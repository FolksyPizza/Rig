package container

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/gateway"
	"github.com/FolksyPizza/rig/internal/gitbroker"
	"github.com/FolksyPizza/rig/internal/mcpguard"
	"github.com/FolksyPizza/rig/internal/relay"
)

// GatewayName is the gateway container's name for a profile.
func GatewayName(profileName string) string { return "rig-gw-" + profileName }

// hostTarget is one relayed host port, as the rig process sees it.
type hostTarget struct {
	name string
	port int // port on the host's loopback
}

// GatewayConfig builds the gateway's configuration and the host-side port
// table. The table never leaves the rig process: the gateway can only name a
// port by index, and the index maps to a port chosen here.
func GatewayConfig(p *config.Profile) (gateway.Config, map[uint16]hostTarget) {
	cfg := gateway.Config{Listen: fmt.Sprintf(":%d", config.GatewayPort)}
	targets := map[uint16]hostTarget{}
	var idx uint16
	for _, hp := range p.Host.Ports {
		cfg.Ports = append(cfg.Ports, gateway.PortConfig{Name: hp.Name, Index: idx, Port: hp.Port, Bind: "0.0.0.0"})
		targets[idx] = hostTarget{name: hp.Name, port: hp.Target()}
		idx++
	}
	for i, s := range p.MCP.Servers {
		if s.URL != "" || !s.InGateway() {
			continue
		}
		srv := gateway.ServerConfig{
			Name:    s.Name,
			Command: s.Command,
			Env:     map[string]string{},
			Policy: mcpguard.Policy{
				Server:  s.Name,
				Allow:   s.AllowTools,
				Deny:    s.DenyTools,
				LogArgs: s.LogArgs == nil || *s.LogArgs,
			},
		}
		for k, v := range s.Env {
			if _, ok := envRef(v); ok {
				srv.Env[k] = "${" + mcpEnvName(i, k) + "}"
			} else {
				srv.Env[k] = v
			}
		}
		cfg.Servers = append(cfg.Servers, srv)
		for _, port := range s.HostPorts {
			cfg.Ports = append(cfg.Ports, gateway.PortConfig{Name: s.Name + "-" + strconv.Itoa(port), Index: idx, Port: port, Bind: "127.0.0.1"})
			targets[idx] = hostTarget{name: s.Name, port: port}
			idx++
		}
	}
	if len(p.Git.Repos) > 0 {
		g := &gitbroker.Config{Host: p.Git.GitHost(), TokenEnv: "RIG_GIT_TOKEN"}
		for _, r := range p.Git.Repos {
			g.Repos = append(g.Repos, gitbroker.Repo{
				Name: r.Repo, Access: r.AccessLevel(), Branches: r.Branches, Tags: r.Tags, Delete: r.Delete,
			})
		}
		cfg.Git = g
	}
	return cfg, targets
}

func mcpEnvName(i int, key string) string { return fmt.Sprintf("RIG_MCP_%d_%s", i, key) }

// Gateway is a running gateway owned by this rig process.
type Gateway struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	done   chan struct{}
	Shared bool // another rig process owns it
}

// Stop shuts the gateway down.
func (g *Gateway) Stop() {
	if g == nil || g.Shared || g.cmd == nil {
		return
	}
	_ = g.stdin.Close()
	select {
	case <-g.done:
	case <-time.After(5 * time.Second):
		_ = g.cmd.Process.Kill()
	}
}

// GatewayOptions configures StartGateway.
type GatewayOptions struct {
	Image   string
	Network string
	Token   string // egress proxy credential
	Runtime string // isolation runtime, same as the sandbox
	// OnLog receives each audit line the gateway writes.
	OnLog func(line []byte)
}

// StartGateway runs the profile's gateway container, attached to this
// process. Its stdout and stdin carry the host-port relay; stderr carries its
// audit log. If another rig process already runs the gateway, it is reused.
func (r *Runner) StartGateway(ctx context.Context, p *config.Profile, opts GatewayOptions) (*Gateway, error) {
	name := GatewayName(p.Name)
	if r.containerRunning(ctx, name) {
		return &Gateway{Shared: true}, nil
	}
	_ = exec.CommandContext(ctx, r.bin, "rm", "-f", name).Run()

	cfg, targets := GatewayConfig(p)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dir, err := config.StateDir(p.Name, "gateway")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "gateway.json"), append(data, '\n'), 0o644); err != nil {
		return nil, err
	}

	env := map[string]string{
		"NO_PROXY": "localhost,127.0.0.1," + GatewayHost,
		"no_proxy": "localhost,127.0.0.1," + GatewayHost,
	}
	if opts.Token != "" {
		proxyURL := fmt.Sprintf("http://gateway:%s@%s:%d", opts.Token, ProxyAlias, ProxyPort)
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env[k] = proxyURL
		}
		env["NODE_USE_ENV_PROXY"] = "1"
	}
	if len(p.Git.Repos) > 0 && p.Git.TokenEnv != "" {
		env["RIG_GIT_TOKEN"] = os.Getenv(p.Git.TokenEnv)
	}
	for i, s := range p.MCP.Servers {
		if s.URL != "" || !s.InGateway() {
			continue
		}
		for k, v := range s.Env {
			if host, ok := envRef(v); ok {
				env[mcpEnvName(i, k)] = os.Getenv(host)
			}
		}
	}
	envFile, cleanup, err := writeEnvMap(env)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args := []string{
		"run", "-i", "--rm",
		"--name", name,
		"--network", opts.Network,
		"--network-alias", GatewayHost,
		"--hostname", GatewayHost,
		"--label", LabelProfile + "=" + p.Name,
		"--label", LabelRole + "=gateway",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
		"--tmpfs", fmt.Sprintf("%s:rw,nosuid,nodev,size=512m,uid=%d,gid=%d,mode=0755", sandboxHome, sandboxUID, sandboxUID),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--memory", "1g",
		"--cpus", "1",
		"--env-file", envFile,
		"-v", dir + ":/etc/rig-gw:ro",
	}
	if opts.Runtime != "" {
		args = append(args, "--runtime", opts.Runtime)
	}
	args = append(args, opts.Image, "rig-helper", "gateway", "--config", "/etc/rig-gw/gateway.json")

	cmd := exec.Command(r.bin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start gateway: %w", err)
	}
	g := &Gateway{cmd: cmd, stdin: stdin, done: make(chan struct{})}

	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if opts.OnLog != nil {
				opts.OnLog(append([]byte{}, sc.Bytes()...))
			}
		}
	}()

	// Host side of the relay: connect each stream to the configured port on
	// this machine's loopback.
	var logMu sync.Mutex
	sess := relay.NewSession(stdout, stdin, func(index uint16, st *relay.Stream) {
		t, ok := targets[index]
		if !ok {
			_ = st.Close()
			return
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(t.port)), 5*time.Second)
		if err != nil {
			if opts.OnLog != nil {
				logMu.Lock()
				line, _ := json.Marshal(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "relay", "port": t.name, "phase": "error", "error": "nothing is listening on host port " + strconv.Itoa(t.port)})
				opts.OnLog(line)
				logMu.Unlock()
			}
			_ = st.Close()
			return
		}
		relay.Join(st, c)
	})
	go func() { _ = sess.Run() }()
	go func() {
		_ = cmd.Wait()
		close(g.done)
	}()

	if err := r.waitForGateway(ctx, name, g.done); err != nil {
		g.Stop()
		return nil, err
	}
	return g, nil
}

func (r *Runner) waitForGateway(ctx context.Context, name string, exited <-chan struct{}) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return fmt.Errorf("gateway %s exited during startup (check 'rig audit' for its log)", name)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		probe := exec.CommandContext(ctx, r.bin, "exec", name, "rig-helper", "probe", fmt.Sprintf("127.0.0.1:%d", config.GatewayPort))
		if probe.Run() == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("gateway %s did not become ready within 60s", name)
}

func (r *Runner) containerRunning(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, r.bin, "inspect", "-f", "{{.State.Running}}", name).Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// writeEnvMap writes variables to a private env file for --env-file.
func writeEnvMap(env map[string]string) (string, func(), error) {
	keys := make([]string, 0, len(env))
	for k, v := range env {
		if strings.ContainsAny(v, "\n\r\x00") {
			return "", func() {}, fmt.Errorf("value for %s contains a newline, which cannot be passed to a container", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	dir, err := os.MkdirTemp("", "rig-env-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + env[k] + "\n")
	}
	path := filepath.Join(dir, "container.env")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}
