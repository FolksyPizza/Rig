package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/security"
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

// sudoCaps are the capabilities package managers need when the sandbox user
// has sudo. Docker's defaults minus NET_RAW, MKNOD and SYS_CHROOT.
var sudoCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "NET_BIND_SERVICE", "SETFCAP", "AUDIT_WRITE"}

// stdinIsTerminal reports whether stdin is an interactive terminal.
//
// The engine only exits an attached session on EOF when no TTY was requested.
// Passing -t unconditionally makes `rig run` and `rig exec` hang forever
// whenever stdin is a pipe or /dev/null. A file-mode check is not sufficient:
// /dev/null is itself a character device.
func stdinIsTerminal() bool {
	fd := os.Stdin.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// ttyFlags returns the interactive flags to hand the engine for this session.
func ttyFlags() []string {
	if stdinIsTerminal() {
		return []string{"-i", "-t"}
	}
	return []string{"-i"}
}

// Runner drives a container engine. kind is "" for a Docker-compatible engine
// (docker/podman, identical CLI) or "apple" for Apple's native `container`.
type Runner struct {
	bin  string
	kind string
	name string // docker | podman | apple
}

// NewRunner selects the platform's container engine.
func NewRunner() (*Runner, error) {
	p := provider.Detect()
	if !p.Available() {
		return nil, fmt.Errorf("no container engine found (looked for %s and fallbacks)", p.Name())
	}
	kind := ""
	if p.Name() == "apple" {
		kind = "apple"
	}
	return &Runner{bin: p.Bin(), kind: kind, name: p.Name()}, nil
}

func (r *Runner) Close() {}

// Bin is the engine's command.
func (r *Runner) Bin() string { return r.bin }

// Engine is the engine's name.
func (r *Runner) Engine() string { return r.name }

func (r *Runner) ContainerName(profileName string, instance int) string {
	if instance <= 1 {
		return "rig-" + profileName
	}
	return fmt.Sprintf("rig-%s-%d", profileName, instance)
}

// RunOptions controls how a sandbox instance is picked and started.
type RunOptions struct {
	// NewInstance forces a fresh container even when one exists.
	NewInstance bool
	// Timeout, if non-zero, stops the sandbox after the given duration.
	Timeout time.Duration
	// Command runs instead of an interactive shell.
	Command []string
	// Recreate replaces an existing instance whose image is out of date.
	Recreate bool
	// Container enters this existing instance instead of picking one.
	Container string
	// KeepRunning leaves a persistent sandbox running after the last
	// session ends. Without it, Rig stops the sandbox so nothing runs in it
	// unmonitored.
	KeepRunning bool
	// Detach runs the sandbox in the background, monitored by a background
	// Rig process, instead of opening a shell.
	Detach bool
}

// LaunchSpec is everything needed to create a sandbox container.
type LaunchSpec struct {
	Profile   *config.Profile
	Effective config.Effective
	Isolation Isolation
	Network   *NetworkSetup // nil unless allowlist mode
	Gateway   bool          // a gateway runs for this profile
	// GatewayIP is the gateway's address on the sandbox network. gVisor and
	// VM sandboxes cannot use the engine's DNS, so they get it as a hosts
	// entry.
	GatewayIP string
}

// Prepared is a sandbox ready to be entered.
type Prepared struct {
	Name     string
	Fresh    bool // created by this call
	attached bool // ephemeral: the shell is the main process
	cleanup  func()
}

// Prepare finds or creates the sandbox container. An ephemeral sandbox is
// created but not started: Attach starts it with the shell as its main
// process. A persistent one is started around a long-lived init so sessions
// can come and go.
func (r *Runner) Prepare(ctx context.Context, spec LaunchSpec, opts RunOptions) (*Prepared, error) {
	profile := spec.Profile
	if opts.Container != "" {
		for _, c := range r.ListByProfile(ctx, profile.Name) {
			if c.Name != opts.Container {
				continue
			}
			if !c.Running {
				if out, err := exec.CommandContext(ctx, r.bin, "start", c.Name).CombinedOutput(); err != nil {
					return nil, fmt.Errorf("start container %s: %s", c.Name, strings.TrimSpace(string(out)))
				}
			}
			r.refreshHosts(ctx, spec, c.Name)
			return &Prepared{Name: c.Name}, nil
		}
		return nil, fmt.Errorf("container %s is not an instance of sandbox %s", opts.Container, profile.Name)
	}
	if !opts.NewInstance {
		if existing, ok := r.findReusable(ctx, profile.Name); ok {
			stale := r.imageOutdated(ctx, existing.Name, profile.ImageTag())
			switch {
			case stale && opts.Recreate:
				if err := r.Destroy(ctx, existing.Name); err != nil {
					return nil, err
				}
			case stale:
				fmt.Fprintf(os.Stderr, "  Note: %s was created from an older image. Run with --recreate to apply profile changes (named volumes are kept).\n", existing.Name)
				fallthrough
			default:
				if !existing.Running {
					if out, err := exec.CommandContext(ctx, r.bin, "start", existing.Name).CombinedOutput(); err != nil {
						return nil, fmt.Errorf("start container %s: %s", existing.Name, strings.TrimSpace(string(out)))
					}
				}
				r.refreshHosts(ctx, spec, existing.Name)
				return &Prepared{Name: existing.Name}, nil
			}
		}
	}

	name := r.ContainerName(profile.Name, r.nextInstance(ctx, profile.Name))
	ephemeral := profile.Persistence == "ephemeral"
	// A background sandbox needs a main process that outlives any session,
	// even when it is removed on stop.
	longLived := !ephemeral || opts.Detach

	env, err := SandboxEnv(spec)
	if err != nil {
		return nil, err
	}
	envFile, cleanup, err := writeEnvMap(env)
	if err != nil {
		return nil, err
	}

	home, _ := os.UserHomeDir()
	mounts, err := ResolveMounts(profile, spec.Effective, home)
	if err != nil {
		cleanup()
		return nil, err
	}

	args := r.buildCreateArgs(spec, createOpts{
		name:      name,
		envFile:   envFile,
		ephemeral: ephemeral,
		longLived: longLived,
		mounts:    mounts,
		command:   opts.Command,
	})
	if err := r.create(ctx, args); err != nil {
		cleanup()
		return nil, err
	}
	cleanup()

	if !longLived {
		return &Prepared{Name: name, Fresh: true, attached: true}, nil
	}
	if out, err := exec.CommandContext(ctx, r.bin, "start", name).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("start container %s: %s", name, strings.TrimSpace(string(out)))
	}
	return &Prepared{Name: name, Fresh: true}, nil
}

// Attach enters a prepared sandbox and returns when the session ends.
func (r *Runner) Attach(ctx context.Context, p *Prepared, opts RunOptions) error {
	r.armTimeout(ctx, p.Name, opts.Timeout)
	if p.attached {
		return r.startAttached(ctx, p.Name)
	}
	if len(opts.Command) > 0 {
		return r.Exec(ctx, p.Name, opts.Command)
	}
	return r.execInto(ctx, p.Name)
}

// create runs `create` and retries without --storage-opt if the storage
// driver does not support per-container quotas.
func (r *Runner) create(ctx context.Context, args []string) error {
	out, err := exec.CommandContext(ctx, r.bin, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	msg := string(out)
	if strings.Contains(msg, "storage-opt") || strings.Contains(msg, "storage opt") {
		stripped, dropped := stripStorageOpt(args)
		if dropped {
			fmt.Fprintf(os.Stderr, "  Warning: this storage driver does not support per-container size limits; ignoring storage.size.\n")
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

// armTimeout schedules a stop for the sandbox after d.
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

// Exec runs a command in a running sandbox. It goes through the entrypoint so
// the session gets the same environment cleanup as the main process.
func (r *Runner) Exec(ctx context.Context, containerName string, command []string) error {
	args := append([]string{"exec"}, ttyFlags()...)
	args = append(args, containerName, "/usr/local/bin/rig-entrypoint")
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

// Stop stops a container, keeping its filesystem.
func (r *Runner) Stop(ctx context.Context, name string) error {
	if out, err := exec.CommandContext(ctx, r.bin, "stop", name).CombinedOutput(); err != nil {
		return fmt.Errorf("stop %s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

// Running reports whether a container is running.
func (r *Runner) Running(ctx context.Context, name string) bool {
	if r.kind == "apple" {
		for _, c := range r.ListSandboxes(ctx) {
			if c.Name == name {
				return c.Running
			}
		}
		return false
	}
	return r.containerRunning(ctx, name)
}

// Kill stops a sandbox immediately.
func (r *Runner) Kill(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, r.bin, "kill", name).Run()
}

func (r *Runner) StopAll(ctx context.Context, profileName string) (int, error) {
	n := 0
	for _, c := range r.ListByProfile(ctx, profileName) {
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
	n := 0
	for _, c := range r.ListByProfile(ctx, profileName) {
		_ = exec.CommandContext(ctx, r.bin, "stop", c.Name).Run()
		if err := exec.CommandContext(ctx, r.bin, "rm", "-f", c.Name).Run(); err != nil {
			return n, fmt.Errorf("remove %s: %w", c.Name, err)
		}
		n++
	}
	return n, nil
}

// RemoveVolumes deletes a profile's named volumes (workspace, home, ...).
func (r *Runner) RemoveVolumes(ctx context.Context, profile *config.Profile) {
	names := []string{"rig-" + profile.Name + "-home"}
	for _, v := range profile.Storage.Volumes {
		names = append(names, "rig-"+profile.Name+"-"+v.Name)
	}
	for _, n := range names {
		_ = exec.CommandContext(ctx, r.bin, "volume", "rm", n).Run()
	}
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

// ListSandboxes returns every Rig sandbox container. Proxy and gateway
// containers carry other roles and are excluded.
func (r *Runner) ListSandboxes(ctx context.Context) []ContainerInfo {
	return r.list(ctx, LabelRole+"="+RoleSandbox)
}

// ListByProfile returns the sandboxes belonging to exactly one profile.
func (r *Runner) ListByProfile(ctx context.Context, profileName string) []ContainerInfo {
	return r.list(ctx, LabelRole+"="+RoleSandbox, LabelProfile+"="+profileName)
}

func (r *Runner) list(ctx context.Context, labelFilters ...string) []ContainerInfo {
	if r.kind == "apple" {
		return r.appleList(ctx, labelFilters...)
	}
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

// profileFromLabels reads the profile label from 'ps --format {{.Labels}}',
// which Docker prints as "k=v,k=v" and Podman as "map[k:v k:v]".
func profileFromLabels(labels string) string {
	if inner, ok := strings.CutPrefix(labels, "map["); ok {
		for _, kv := range strings.Fields(strings.TrimSuffix(inner, "]")) {
			if name, ok := strings.CutPrefix(kv, LabelProfile+":"); ok {
				return name
			}
		}
		return ""
	}
	for _, kv := range strings.Split(labels, ",") {
		if name, ok := strings.CutPrefix(kv, LabelProfile+"="); ok {
			return name
		}
	}
	return ""
}

func (r *Runner) ContainerStats(ctx context.Context, containerName string) (string, error) {
	out, err := exec.CommandContext(ctx, r.bin, "stats", "--no-stream",
		"--format", "CPU: {{.CPUPerc}}  Mem: {{.MemUsage}}  Net: {{.NetIO}}  PIDs: {{.PIDs}}",
		containerName,
	).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// WaitGone waits until a container is no longer running, up to d.
func (r *Runner) WaitGone(ctx context.Context, name string, d time.Duration) {
	deadline := time.Now().Add(d)
	for r.containerRunning(ctx, name) && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
}

// UpdateResources changes a container's CPU, memory and process limits in
// place, running or stopped.
func (r *Runner) UpdateResources(ctx context.Context, name string, res config.ResourcesConfig) error {
	if r.kind == "apple" {
		return fmt.Errorf("Apple's container runtime cannot change limits in place")
	}
	out, err := exec.CommandContext(ctx, r.bin, "update",
		fmt.Sprintf("--cpus=%.2f", res.CPU),
		fmt.Sprintf("--memory=%dm", res.Memory),
		fmt.Sprintf("--memory-swap=%dm", res.Memory),
		fmt.Sprintf("--pids-limit=%d", res.PIDLimit),
		name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
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

// Commit snapshots a container as an image. The environment the sandbox was
// started with (API keys among it) would otherwise be copied into the
// image's configuration, so those variables are blanked in the snapshot.
func (r *Runner) Commit(ctx context.Context, containerName, tag string) error {
	args := []string{"commit"}
	for _, k := range r.addedEnv(ctx, containerName) {
		args = append(args, "--change", "ENV "+k+"=")
	}
	args = append(args, containerName, tag)
	if out, err := exec.CommandContext(ctx, r.bin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("commit %s: %s", containerName, strings.TrimSpace(string(out)))
	}
	return nil
}

// addedEnv names the variables a container has that its image does not.
func (r *Runner) addedEnv(ctx context.Context, containerName string) []string {
	out, err := exec.CommandContext(ctx, r.bin, "inspect", "-f", "{{json .Config.Env}}\t{{.Config.Image}}", containerName).Output()
	if err != nil {
		return nil
	}
	envJSON, image, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	var env []string
	if json.Unmarshal([]byte(envJSON), &env) != nil {
		return nil
	}
	base := map[string]bool{}
	if imgOut, err := exec.CommandContext(ctx, r.bin, "image", "inspect", "-f", "{{json .Config.Env}}", image).Output(); err == nil {
		var imgEnv []string
		if json.Unmarshal(imgOut, &imgEnv) == nil {
			for _, kv := range imgEnv {
				base[kv] = true
			}
		}
	}
	var names []string
	for _, kv := range env {
		if base[kv] {
			continue
		}
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
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

type createOpts struct {
	name      string
	envFile   string
	ephemeral bool
	longLived bool // main process is "sleep infinity"; sessions use exec
	mounts    []MountSpec
	command   []string
}

// buildCreateArgs assembles the create invocation for a sandbox.
func (r *Runner) buildCreateArgs(spec LaunchSpec, o createOpts) []string {
	if r.kind == "apple" {
		return appleCreateArgs(spec, o)
	}
	profile, eff := spec.Profile, spec.Effective

	args := []string{"create", "--name", o.name}
	args = append(args, ttyFlags()...)
	args = append(args,
		"--init", // reap zombies so the PID limit is not eaten by defunct processes
		// A generic hostname: the profile name can say more about you than
		// the agent needs to know.
		"--hostname", "sandbox",
		"--cap-drop", "ALL",
		"--cgroupns", "private",
		"--ipc", "private",
		fmt.Sprintf("--cpus=%.2f", profile.Resources.CPU),
		fmt.Sprintf("--memory=%dm", profile.Resources.Memory),
		// Without an equal swap limit the memory cap can be exceeded via swap.
		fmt.Sprintf("--memory-swap=%dm", profile.Resources.Memory),
		fmt.Sprintf("--pids-limit=%d", profile.Resources.PIDLimit),
		"--label", LabelProfile+"="+profile.Name,
		"--label", LabelRole+"="+RoleSandbox,
		"--label", "rig.level="+eff.Level,
		"--label", "rig.isolation="+spec.Isolation.Level,
		"--label", "rig.created="+time.Now().UTC().Format(time.RFC3339),
	)
	if eff.Sudo {
		// sudo is setuid, which no-new-privileges would disable.
		for _, c := range sudoCaps {
			args = append(args, "--cap-add", c)
		}
	} else {
		args = append(args, "--security-opt", "no-new-privileges")
	}
	if spec.Isolation.Runtime != "" {
		args = append(args, "--runtime", spec.Isolation.Runtime)
	}

	if eff.ReadOnlyRoot {
		args = append(args, "--read-only")
		if r.name == "podman" {
			// Podman otherwise mounts writable tmpfs on /var/tmp and /run.
			args = append(args, "--read-only-tmpfs=false")
		}
		tmp := "/tmp:rw,nosuid,nodev,size=1g,mode=1777"
		if eff.NoExecTmp {
			tmp = "/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777"
		}
		args = append(args, "--tmpfs", tmp)

		hasWorkspace := false
		for _, v := range profile.Storage.Volumes {
			if path.Clean(v.Target) == sandboxHome+"/workspace" {
				hasWorkspace = true
			}
		}
		switch {
		case !o.ephemeral:
			// Persistent: home lives in a named volume, seeded from the
			// image the first time.
			args = append(args, "-v", "rig-"+profile.Name+"-home:"+sandboxHome)
		case eff.NoExecHome:
			args = append(args, "--tmpfs", sandboxHome+":rw,nosuid,nodev,noexec,size=1g,mode=0755,"+sandboxOwnedTmpfs(r.name))
			if !hasWorkspace {
				args = append(args, "-v", sandboxHome+"/workspace")
			}
		default:
			// Anonymous volume, seeded from the image and removed with the
			// container.
			args = append(args, "-v", sandboxHome)
		}
	}

	if o.envFile != "" {
		args = append(args, "--env-file", o.envFile)
	}

	switch eff.NetworkMode {
	case "allowlist":
		if spec.Network != nil {
			args = append(args, "--network", spec.Network.Network)
			// gVisor and VM runtimes may not see the engine's embedded DNS,
			// so give them the proxy's address directly.
			if r.needsHostEntries(spec) {
				for _, h := range hostEntries(spec) {
					args = append(args, "--add-host", h[0]+":"+h[1])
				}
			}
		}
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
	for _, m := range o.mounts {
		args = append(args, m.Args()...)
	}

	if o.ephemeral {
		args = append(args, "--rm")
	}
	args = append(args, profile.ImageTag())

	switch {
	case !o.ephemeral || o.longLived:
		// A persistent or background sandbox needs a main process that
		// outlives any one shell session, so sessions can come and go via
		// exec.
		args = append(args, "sleep", "infinity")
	case len(o.command) > 0:
		args = append(args, o.command...)
	}
	return args
}

// SandboxEnv is the sandbox's runtime environment: agent secrets resolved
// from the host, MCP secrets, proxy settings, the git broker rewrite, and the
// level's hardening switches. It goes to the container through a private
// env file, never on a command line.
func SandboxEnv(spec LaunchSpec) (map[string]string, error) {
	p, eff := spec.Profile, spec.Effective
	env := map[string]string{
		"RIG_PROFILE": p.Name,
		"RIG_LEVEL":   eff.Level,
	}
	for _, ac := range p.Agents {
		for k, v := range config.ResolveEnvVars(ac.Env) {
			if v != "" {
				env[k] = v
			}
		}
	}
	plan, err := planMCPForProfile(p, eff)
	if err != nil {
		return nil, err
	}
	for k, v := range plan.sandboxEnv {
		if host, ok := envRef(v); ok {
			v = os.Getenv(host)
		}
		if v != "" {
			env[k] = v
		}
	}

	if eff.QuietAgents {
		for k, v := range quietEnv(p) {
			env[k] = v
		}
	}
	if eff.NpmIgnoreScripts {
		env["NPM_CONFIG_IGNORE_SCRIPTS"] = "true"
	}
	if eff.PipOnlyBinary {
		env["PIP_ONLY_BINARY"] = ":all:"
	}

	noProxy := "localhost,127.0.0.1"
	if spec.Gateway {
		noProxy += "," + GatewayHost
	}
	if eff.NetworkMode == "allowlist" {
		proxyURL := fmt.Sprintf("http://%s:%d", ProxyAlias, ProxyPort)
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env[k] = proxyURL
		}
		env["NO_PROXY"], env["no_proxy"] = noProxy, noProxy
		// Node's built-in fetch ignores proxy variables unless told otherwise.
		// Node then warns on every start that this is experimental; hide
		// that one warning.
		env["NODE_USE_ENV_PROXY"] = "1"
		env["NODE_OPTIONS"] = "--disable-warning=UNDICI-EHPA"
	}

	if len(p.Git.Repos) > 0 {
		base := fmt.Sprintf("http://%s:%d/git/%s/", GatewayHost, config.GatewayPort, p.Git.GitHost())
		key := "url." + base + ".insteadOf"
		values := []string{"https://" + p.Git.GitHost() + "/", "git@" + p.Git.GitHost() + ":", "ssh://git@" + p.Git.GitHost() + "/"}
		env["GIT_CONFIG_COUNT"] = strconv.Itoa(len(values))
		for i, v := range values {
			env[fmt.Sprintf("GIT_CONFIG_KEY_%d", i)] = key
			env[fmt.Sprintf("GIT_CONFIG_VALUE_%d", i)] = v
		}
	}
	return env, nil
}

func planMCPForProfile(p *config.Profile, eff config.Effective) (mcpPlan, error) {
	ids := make([]string, 0, len(p.Agents))
	for _, a := range p.Agents {
		ids = append(ids, a.ID)
	}
	specs, err := resolveAgents(ids)
	if err != nil {
		return mcpPlan{}, err
	}
	return planMCP(p, eff, specs)
}

// MountSpec is one bind or tmpfs mount, already resolved on the host.
type MountSpec struct {
	Source   string // host path; empty for tmpfs
	Target   string
	ReadOnly bool
	Tmpfs    bool // an empty, inaccessible tmpfs (used to hide a directory)
}

// Args renders the mount as engine flags.
func (m MountSpec) Args() []string {
	if m.Tmpfs {
		return []string{"--mount", "type=tmpfs,destination=" + m.Target + ",tmpfs-size=4k,tmpfs-mode=0000"}
	}
	flag := m.Source + ":" + m.Target
	if m.ReadOnly {
		flag += ":ro"
	}
	return []string{"-v", flag}
}

// ResolveMounts turns the profile's mounts into concrete mounts. Host paths
// are resolved through symlinks and re-checked, protected paths inside
// writable mounts are mounted again read-only, and hidden paths are covered
// by an empty file or directory.
func ResolveMounts(p *config.Profile, eff config.Effective, home string) ([]MountSpec, error) {
	var out []MountSpec
	for _, m := range p.Mounts {
		src, err := security.ResolveMountSource(m.Source, home)
		if err != nil {
			return nil, err
		}
		out = append(out, MountSpec{Source: src, Target: m.Target, ReadOnly: m.ReadOnly})

		if !m.ReadOnly {
			protect := append(append([]string{}, m.Protect...), eff.ProtectPaths...)
			seen := map[string]bool{}
			for _, sub := range protect {
				if seen[sub] {
					continue
				}
				seen[sub] = true
				real, ok, err := insideMount(src, sub)
				if err != nil {
					return nil, err
				}
				if ok {
					out = append(out, MountSpec{Source: real, Target: path.Join(m.Target, sub), ReadOnly: true})
				}
			}
		}
		for _, sub := range m.Hide {
			real, ok, err := insideMount(src, sub)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			target := path.Join(m.Target, sub)
			info, err := os.Stat(real)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				out = append(out, MountSpec{Target: target, Tmpfs: true})
			} else {
				out = append(out, MountSpec{Source: "/dev/null", Target: target, ReadOnly: true})
			}
		}
	}
	return out, nil
}

// insideMount resolves src/sub and confirms it stays inside src. A missing
// path is reported as not ok (nothing to protect or hide).
func insideMount(src, sub string) (string, bool, error) {
	if err := security.ValidateSubpath(sub); err != nil {
		return "", false, err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(src, filepath.FromSlash(sub)))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if real != src && !strings.HasPrefix(real, src+string(os.PathSeparator)) {
		return "", false, fmt.Errorf("%s inside %s is a link that points outside the mount", sub, src)
	}
	return real, true, nil
}

func (r *Runner) execInto(ctx context.Context, containerName string) error {
	args := append([]string{"exec"}, ttyFlags()...)
	args = append(args, containerName, "/usr/local/bin/rig-entrypoint", "/bin/bash", "-l")
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

// imageOutdated reports whether a container runs an older build of its image.
func (r *Runner) imageOutdated(ctx context.Context, containerName, tag string) bool {
	if r.kind == "apple" {
		return false
	}
	cur, err := exec.CommandContext(ctx, r.bin, "image", "inspect", "-f", "{{.Id}}", tag).Output()
	if err != nil {
		return false
	}
	used, err := exec.CommandContext(ctx, r.bin, "inspect", "-f", "{{.Image}}", containerName).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(cur)) != strings.TrimSpace(string(used))
}

// ProfileOf returns the profile a container was created from, via its label.
func (r *Runner) ProfileOf(ctx context.Context, containerName string) (string, error) {
	if r.kind == "apple" {
		for _, c := range r.appleList(ctx, LabelRole+"="+RoleSandbox) {
			if c.Name == containerName && c.Profile != "" {
				return c.Profile, nil
			}
		}
		return "", fmt.Errorf("container %s has no %s label", containerName, LabelProfile)
	}
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

// containerExists reports whether a container (not an image, volume or
// network: Podman's plain inspect matches those too) has this name.
func (r *Runner) containerExists(ctx context.Context, name string) bool {
	if r.kind == "apple" {
		return exec.CommandContext(ctx, r.bin, "inspect", name).Run() == nil
	}
	return exec.CommandContext(ctx, r.bin, "inspect", "--type", "container", name).Run() == nil
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

// nextInstance picks the lowest unused instance number for a profile.
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

// hostEntries are the names a gVisor or VM sandbox reaches by address: the
// egress proxy and, when one runs, the gateway.
func hostEntries(spec LaunchSpec) [][2]string {
	var out [][2]string
	if spec.Network != nil && spec.Network.ProxyIP != "" {
		out = append(out, [2]string{ProxyAlias, spec.Network.ProxyIP})
	}
	if spec.Gateway && spec.GatewayIP != "" {
		out = append(out, [2]string{GatewayHost, spec.GatewayIP})
	}
	return out
}

// needsHostEntries reports whether a sandbox reaches the proxy and gateway by
// address rather than through the engine's DNS: gVisor and VM sandboxes cannot
// use that DNS, and Rig turns it off on Podman's internal networks.
func (r *Runner) needsHostEntries(spec LaunchSpec) bool {
	return spec.Isolation.Level != config.IsolationContainer || r.name == "podman"
}

// refreshHosts rewrites the proxy and gateway entries in a reused gVisor or
// VM sandbox's hosts file. The gateway is started anew for each session and
// its address can change; entries given at creation would go stale.
func (r *Runner) refreshHosts(ctx context.Context, spec LaunchSpec, name string) {
	entries := hostEntries(spec)
	if !r.needsHostEntries(spec) || len(entries) == 0 || r.kind == "apple" {
		return
	}
	script := `grep -vE "[[:space:]](` + ProxyAlias + `|` + GatewayHost + `)$" /etc/hosts > /tmp/.rig-hosts; ` +
		`cat /tmp/.rig-hosts > /etc/hosts; rm -f /tmp/.rig-hosts; printf '%s\n' "$@" >> /etc/hosts`
	args := []string{"exec", "-u", "0", name, "sh", "-c", script, "sh"}
	for _, e := range entries {
		args = append(args, e[1]+" "+e[0])
	}
	if out, err := exec.CommandContext(ctx, r.bin, args...).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not update the proxy and gateway addresses in %s: %s\n", name, strings.TrimSpace(string(out)))
	}
}

// ContainerIP is a container's address on a network, or "" if it has none.
func (r *Runner) ContainerIP(ctx context.Context, name, network string) string {
	out, err := exec.CommandContext(ctx, r.bin, "inspect", "-f",
		`{{with index .NetworkSettings.Networks "`+network+`"}}{{.IPAddress}}{{end}}`, name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sandboxOwnedTmpfs is the tmpfs option that makes the mount belong to the
// sandbox user. Podman does not accept Docker's uid= and gid=; its U option
// gives the mount to the container's user, which is the sandbox user.
func sandboxOwnedTmpfs(engine string) string {
	if engine == "podman" {
		return "U"
	}
	return fmt.Sprintf("uid=%d,gid=%d", sandboxUID, sandboxUID)
}
