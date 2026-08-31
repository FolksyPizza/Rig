package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/FolksyPizza/rig/internal/config"
)

// Labels Rig stamps on every container it creates. Lookups filter on these
// rather than on name prefixes: `docker ps --filter name=rig-foo` is a
// substring match, so it also returns `rig-foobar`, and a destroy or stop
// aimed at one profile would reach into another.
const (
	LabelProfile = "rig.profile"
	LabelRole    = "rig.role"
	RoleSandbox  = "sandbox"
)

// stdinIsTerminal reports whether stdin is an interactive terminal.
//
// Docker only exits an attached session on EOF when no TTY was requested.
// Passing -t unconditionally makes `rig run` and `rig exec` hang forever
// whenever stdin is a pipe or /dev/null — in scripts, CI, and `rig exec ... |
// grep`. The docker CLI makes the same distinction for the same reason.
// A file-mode check is not sufficient here: /dev/null is itself a character
// device, so testing os.ModeCharDevice reports a terminal for the common
// `rig run x < /dev/null` case and reintroduces the hang.
func stdinIsTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// ttyFlags returns the interactive flags to hand docker for this session.
func ttyFlags() []string {
	if stdinIsTerminal() {
		return []string{"-i", "-t"}
	}
	return []string{"-i"}
}

type Runner struct{ bin string }

// NewRunner selects a Docker-compatible engine (Podman preferred, Docker fallback) so Rig
// does not depend on Docker. Apple `container` uses a different create/network surface and
// is driven through internal/provider (lifecycle migration is in progress).
func NewRunner() (*Runner, error) {
	for _, bin := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(bin); err == nil {
			return &Runner{bin: bin}, nil
		}
	}
	return nil, fmt.Errorf("no container engine found in PATH (looked for podman, docker)")
}

func (r *Runner) Close() {}

func (r *Runner) ContainerName(profileName string, instance int) string {
	if instance <= 1 {
		return "rig-" + profileName
	}
	return fmt.Sprintf("rig-%s-%d", profileName, instance)
}

// RunOptions controls how Run picks and starts a sandbox instance.
type RunOptions struct {
	// NewInstance forces a fresh container even when an instance of this
	// profile already exists.
	NewInstance bool
	// Timeout, if non-zero, stops the sandbox after the given duration.
	Timeout time.Duration
}

// Run enters a sandbox for the profile, creating it if necessary.
//
// Persistent sandboxes are created detached around a long-lived init process
// and entered with `docker exec`. That is what makes them re-enterable: a
// container whose main process is an interactive shell exits the moment its
// stdin closes, so the previous approach of `docker start` followed by
// `docker exec` would routinely exec into a container that had already died.
// Ephemeral sandboxes keep the shell as the main process and vanish on exit.
func (r *Runner) Run(ctx context.Context, profile *config.Profile, networkName string, opts RunOptions) error {
	if !opts.NewInstance {
		if existing, ok := r.findReusable(ctx, profile.Name); ok {
			if !existing.Running {
				if out, err := exec.CommandContext(ctx, r.bin, "start", existing.Name).CombinedOutput(); err != nil {
					return fmt.Errorf("start container %s: %s", existing.Name, strings.TrimSpace(string(out)))
				}
			}
			r.armTimeout(ctx, existing.Name, opts.Timeout)
			return r.execInto(ctx, existing.Name)
		}
	}

	containerName := r.ContainerName(profile.Name, r.nextInstance(ctx, profile.Name))
	ephemeral := profile.Persistence == "ephemeral"

	envFile, cleanupEnv, err := writeEnvFile(profile)
	if err != nil {
		return err
	}
	defer cleanupEnv()

	args := r.buildCreateArgs(profile, containerName, networkName, envFile, ephemeral)
	if err := r.create(ctx, args); err != nil {
		return err
	}

	r.armTimeout(ctx, containerName, opts.Timeout)

	if ephemeral {
		// The shell is the container's main process; attach to it directly.
		return r.startAttached(ctx, containerName)
	}

	if out, err := exec.CommandContext(ctx, r.bin, "start", containerName).CombinedOutput(); err != nil {
		return fmt.Errorf("start container %s: %s", containerName, strings.TrimSpace(string(out)))
	}
	return r.execInto(ctx, containerName)
}

// create runs `docker create` and retries without --storage-opt if the host's
// storage driver does not support per-container quotas. Quota support needs
// overlay2 on xfs with pquota (or btrfs/zfs), which is a minority of hosts;
// failing the launch outright over an advisory disk cap is not worth it.
func (r *Runner) create(ctx context.Context, args []string) error {
	out, err := exec.CommandContext(ctx, r.bin, args...).CombinedOutput()
	if err == nil {
		return nil
	}

	msg := string(out)
	if strings.Contains(msg, "storage-opt") || strings.Contains(msg, "storage opt") {
		stripped, dropped := stripStorageOpt(args)
		if dropped {
			fmt.Fprintf(os.Stderr,
				"  Warning: this Docker storage driver does not support per-container size limits; ignoring storage.size.\n")
			if out2, err2 := exec.CommandContext(ctx, r.bin, stripped...).CombinedOutput(); err2 == nil {
				return nil
			} else {
				return fmt.Errorf("create container: %s", strings.TrimSpace(string(out2)))
			}
		}
	}
	return fmt.Errorf("create container: %s", strings.TrimSpace(msg))
}

func stripStorageOpt(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	dropped := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--storage-opt" && i+1 < len(args) {
			i++
			dropped = true
			continue
		}
		out = append(out, args[i])
	}
	return out, dropped
}

// armTimeout schedules a stop for the sandbox after d. It survives the parent
// exiting so `rig run --timeout` behaves the same whether the user stays
// attached or detaches.
func (r *Runner) armTimeout(ctx context.Context, containerName string, d time.Duration) {
	if d <= 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  Sandbox will be stopped automatically after %s.\n", d)
	go func() {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			_ = exec.Command(r.bin, "stop", containerName).Run()
		case <-ctx.Done():
		}
	}()
}

func (r *Runner) Exec(ctx context.Context, containerName string, command []string) error {
	args := append([]string{"exec"}, ttyFlags()...)
	args = append(args, containerName)
	args = append(args, command...)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) Shell(ctx context.Context, containerName string) error {
	return r.execInto(ctx, containerName)
}

func (r *Runner) Stop(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, r.bin, "stop", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) StopAll(ctx context.Context, profileName string) (int, error) {
	containers := r.ListByProfile(ctx, profileName)
	n := 0
	for _, c := range containers {
		if c.Running {
			if err := exec.CommandContext(ctx, r.bin, "stop", c.Name).Run(); err != nil {
				return n, fmt.Errorf("stop %s: %w", c.Name, err)
			}
			n++
		}
	}
	return n, nil
}

func (r *Runner) Destroy(ctx context.Context, name string) error {
	_ = exec.CommandContext(ctx, r.bin, "stop", name).Run()
	cmd := exec.CommandContext(ctx, r.bin, "rm", "-f", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) DestroyAll(ctx context.Context, profileName string) (int, error) {
	containers := r.ListByProfile(ctx, profileName)
	n := 0
	for _, c := range containers {
		_ = exec.CommandContext(ctx, r.bin, "stop", c.Name).Run()
		if err := exec.CommandContext(ctx, r.bin, "rm", "-f", c.Name).Run(); err != nil {
			return n, fmt.Errorf("remove %s: %w", c.Name, err)
		}
		n++
	}
	return n, nil
}

func (r *Runner) Logs(ctx context.Context, containerName string, follow bool, tail string) error {
	args := []string{"logs"}
	if follow {
		args = append(args, "-f")
	}
	if tail != "" {
		args = append(args, "--tail", tail)
	}
	args = append(args, containerName)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) CopyFromContainer(ctx context.Context, containerName, srcPath, dstPath string) error {
	cmd := exec.CommandContext(ctx, r.bin, "cp", containerName+":"+srcPath, dstPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) CopyToContainer(ctx context.Context, containerName, srcPath, dstPath string) error {
	cmd := exec.CommandContext(ctx, r.bin, "cp", srcPath, containerName+":"+dstPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type ContainerInfo struct {
	Name      string
	Profile   string
	Image     string
	Status    string
	Running   bool
	CreatedAt string
	Ports     string
}

// ListSandboxes returns every Rig sandbox container. The proxy sidecars are
// labelled with a different role and are deliberately excluded.
func (r *Runner) ListSandboxes(ctx context.Context) []ContainerInfo {
	return r.list(ctx, LabelRole+"="+RoleSandbox)
}

// ListByProfile returns the sandboxes belonging to exactly one profile.
func (r *Runner) ListByProfile(ctx context.Context, profileName string) []ContainerInfo {
	return r.list(ctx, LabelRole+"="+RoleSandbox, LabelProfile+"="+profileName)
}

func (r *Runner) list(ctx context.Context, labelFilters ...string) []ContainerInfo {
	args := []string{"ps", "-a"}
	for _, f := range labelFilters {
		args = append(args, "--filter", "label="+f)
	}
	args = append(args, "--format",
		`{"name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","state":"{{.State}}","created":"{{.CreatedAt}}","ports":"{{.Ports}}","labels":"{{.Labels}}"}`)

	out, err := exec.CommandContext(ctx, r.bin, args...).Output()
	if err != nil {
		return nil
	}

	var containers []ContainerInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var info struct {
			Name    string `json:"name"`
			Image   string `json:"image"`
			Status  string `json:"status"`
			State   string `json:"state"`
			Created string `json:"created"`
			Ports   string `json:"ports"`
			Labels  string `json:"labels"`
		}
		if err := json.Unmarshal([]byte(line), &info); err != nil {
			continue
		}
		containers = append(containers, ContainerInfo{
			Name:      info.Name,
			Profile:   profileFromLabels(info.Labels),
			Image:     info.Image,
			Status:    info.Status,
			Running:   info.State == "running",
			CreatedAt: info.Created,
			Ports:     info.Ports,
		})
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	return containers
}

func profileFromLabels(labels string) string {
	for _, kv := range strings.Split(labels, ",") {
		if name, ok := strings.CutPrefix(kv, LabelProfile+"="); ok {
			return name
		}
	}
	return ""
}

func (r *Runner) ContainerStats(ctx context.Context, containerName string) (string, error) {
	cmd := exec.CommandContext(ctx, r.bin, "stats", "--no-stream",
		"--format", "CPU: {{.CPUPerc}}  Mem: {{.MemUsage}}  Net: {{.NetIO}}  PIDs: {{.PIDs}}",
		containerName,
	)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Runner) Rename(ctx context.Context, oldName, newName string) error {
	cmd := exec.CommandContext(ctx, r.bin, "rename", oldName, newName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) Pause(ctx context.Context, containerName string) error {
	return exec.CommandContext(ctx, r.bin, "pause", containerName).Run()
}

func (r *Runner) Unpause(ctx context.Context, containerName string) error {
	return exec.CommandContext(ctx, r.bin, "unpause", containerName).Run()
}

func (r *Runner) Commit(ctx context.Context, containerName, tag string) error {
	cmd := exec.CommandContext(ctx, r.bin, "commit", containerName, tag)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) Top(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, r.bin, "top", containerName, "-eo", "pid,ppid,user,%cpu,%mem,etime,comm")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) Diff(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, r.bin, "diff", containerName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// buildCreateArgs assembles the `docker create` invocation for a sandbox.
func (r *Runner) buildCreateArgs(profile *config.Profile, name, networkName, envFile string, ephemeral bool) []string {
	args := []string{
		"create",
		"--name", name,
	}
	args = append(args, ttyFlags()...)
	args = append(args,
		"--init", // reap zombies so the PID limit is not eaten by defunct processes
		"--hostname", "rig-"+profile.Name,
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		fmt.Sprintf("--cpus=%.2f", profile.Resources.CPU),
		fmt.Sprintf("--memory=%dm", profile.Resources.Memory),
		// Without an equal swap limit the memory cap can be exceeded via swap.
		fmt.Sprintf("--memory-swap=%dm", profile.Resources.Memory),
		fmt.Sprintf("--pids-limit=%d", profile.Resources.PIDLimit),
		"--label", LabelProfile+"="+profile.Name,
		"--label", LabelRole+"="+RoleSandbox,
		"--label", "rig.created="+time.Now().UTC().Format(time.RFC3339),
	)

	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}

	switch profile.Network.Mode {
	case "allowlist":
		// networkName is the --internal network; the sandbox has no route out
		// except through the proxy sidecar.
		args = append(args, "--network", networkName)
		args = append(args,
			"-e", "HTTP_PROXY=http://"+ProxyAlias+":3128",
			"-e", "HTTPS_PROXY=http://"+ProxyAlias+":3128",
			"-e", "http_proxy=http://"+ProxyAlias+":3128",
			"-e", "https_proxy=http://"+ProxyAlias+":3128",
			"-e", "NO_PROXY=localhost,127.0.0.1",
			"-e", "no_proxy=localhost,127.0.0.1",
		)
	case "none":
		args = append(args, "--network", "none")
	}

	if profile.Storage.Size != "" {
		args = append(args, "--storage-opt", "size="+profile.Storage.Size)
	}

	for _, v := range profile.Storage.Volumes {
		flag := "rig-" + profile.Name + "-" + v.Name + ":" + v.Target
		if v.ReadOnly {
			flag += ":ro"
		}
		args = append(args, "-v", flag)
	}

	for _, m := range profile.Mounts {
		flag := m.Source + ":" + m.Target
		if m.ReadOnly {
			flag += ":ro"
		}
		args = append(args, "-v", flag)
	}

	if ephemeral {
		args = append(args, "--rm")
	}

	args = append(args, profile.ImageTag())

	if !ephemeral {
		// A persistent sandbox needs a main process that outlives any one
		// shell session, so sessions can come and go via `docker exec`.
		args = append(args, "sleep", "infinity")
	}

	return args
}

// writeEnvFile materialises resolved agent secrets into a 0600 file for
// --env-file. Passing them as -e KEY=value would expose every API key in the
// host's process list to any local user running `ps`.
func writeEnvFile(profile *config.Profile) (string, func(), error) {
	lines := make([]string, 0)
	for _, ac := range profile.Agents {
		for k, v := range config.ResolveEnvVars(ac.Env) {
			if v == "" {
				continue
			}
			if strings.ContainsAny(v, "\n\r\x00") {
				return "", func() {}, fmt.Errorf("value for %s contains a newline, which cannot be passed to the sandbox", k)
			}
			lines = append(lines, k+"="+v)
		}
	}
	if len(lines) == 0 {
		return "", func() {}, nil
	}
	sort.Strings(lines)

	dir, err := os.MkdirTemp("", "rig-env-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("create env dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	path := filepath.Join(dir, "sandbox.env")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("write env file: %w", err)
	}
	return path, cleanup, nil
}

func (r *Runner) execInto(ctx context.Context, containerName string) error {
	args := append([]string{"exec"}, ttyFlags()...)
	args = append(args, containerName, "/bin/bash", "-l")
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) startAttached(ctx context.Context, containerName string) error {
	cmd := exec.CommandContext(ctx, r.bin, "start", "-ai", containerName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ProfileOf returns the profile a container was created from, via its label.
func (r *Runner) ProfileOf(ctx context.Context, containerName string) (string, error) {
	out, err := exec.CommandContext(ctx, r.bin, "inspect",
		"-f", `{{index .Config.Labels "`+LabelProfile+`"}}`, containerName).Output()
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", containerName, err)
	}
	name := strings.TrimSpace(string(out))
	if name == "" || name == "<no value>" {
		return "", fmt.Errorf("container %s has no %s label", containerName, LabelProfile)
	}
	return name, nil
}

func (r *Runner) containerExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, r.bin, "inspect", name).Run() == nil
}

// findReusable returns an existing sandbox for the profile, preferring one
// that is already running.
func (r *Runner) findReusable(ctx context.Context, profileName string) (ContainerInfo, bool) {
	containers := r.ListByProfile(ctx, profileName)
	for _, c := range containers {
		if c.Running {
			return c, true
		}
	}
	if len(containers) > 0 {
		return containers[0], true
	}
	return ContainerInfo{}, false
}

// nextInstance picks the lowest unused instance number for a profile, so a
// destroyed instance's slot is reused instead of the counter climbing forever.
func (r *Runner) nextInstance(ctx context.Context, profileName string) int {
	used := make(map[int]bool)
	prefix := "rig-" + profileName
	for _, c := range r.ListByProfile(ctx, profileName) {
		switch {
		case c.Name == prefix:
			used[1] = true
		case strings.HasPrefix(c.Name, prefix+"-"):
			if n, err := strconv.Atoi(strings.TrimPrefix(c.Name, prefix+"-")); err == nil {
				used[n] = true
			}
		}
	}
	for i := 1; ; i++ {
		if !used[i] {
			return i
		}
	}
}

// ResolveContainerName accepts either a full container name or a profile name
// and returns the matching container.
func ResolveContainerName(ctx context.Context, r *Runner, name string) (string, error) {
	if r.containerExists(ctx, name) {
		return name, nil
	}
	withPrefix := "rig-" + name
	if r.containerExists(ctx, withPrefix) {
		return withPrefix, nil
	}
	return "", fmt.Errorf("container %q not found (tried %q and %q)", name, name, withPrefix)
}
