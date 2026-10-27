package container

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/egress"
	"github.com/FolksyPizza/rig/internal/provider"
)

// ProxyAlias is the name the sandbox reaches the egress proxy by.
const ProxyAlias = "rig-proxy"

// ProxyPort is the egress proxy's port.
const ProxyPort = 3128

// NetworkManager builds and tears down a profile's filtered network.
type NetworkManager struct {
	bin  string
	name string // docker | podman
}

// NewNetworkManager uses the detected container engine. Apple's runtime has
// no internal networks, so allowlist mode is refused there.
func NewNetworkManager() (*NetworkManager, error) {
	p := provider.Detect()
	if !p.Available() {
		return nil, fmt.Errorf("no container engine found (looked for %s and fallbacks)", p.Name())
	}
	if p.Name() == "apple" {
		return nil, fmt.Errorf("the egress allowlist needs internal networks, which Apple's container runtime does not provide yet; install Podman or Docker, or use network mode none")
	}
	return &NetworkManager{bin: p.Bin(), name: p.Name()}, nil
}

func (nm *NetworkManager) Close() {}

// NetworkName is the internal network the sandbox is attached to.
func (nm *NetworkManager) NetworkName(profileName string) string { return "rig-net-" + profileName }

// EgressNetworkName is the ordinary network that gives only the proxy a route out.
func (nm *NetworkManager) EgressNetworkName(profileName string) string {
	return "rig-egress-" + profileName
}

func (nm *NetworkManager) ProxyName(profileName string) string { return "rig-proxy-" + profileName }

// NetworkSetup is what Setup produced.
type NetworkSetup struct {
	Network      string // the sandbox's network
	ProxyIP      string // the proxy's address on it
	GatewayToken string // proxy credential for the gateway, if one is used
}

// Setup builds the egress-filtered network for an allowlist profile.
//
// The topology is what makes the allowlist a boundary rather than a
// suggestion:
//
//	sandbox ── rig-net-<p> (internal: no route out, no host address) ── proxy
//	                                                                     │
//	                                                  rig-egress-<p> ── internet
//
// The sandbox's only network is internal, so it can reach nothing but the
// proxy (and the gateway, when one runs). On Docker the internal network is
// also created without a host-side address, so the sandbox cannot reach
// services listening on the host either. The proxy runs Rig's own filter from
// a minimal image and is the sole path out.
func (nm *NetworkManager) Setup(ctx context.Context, profile *config.Profile, eff config.Effective, helperImage string) (*NetworkSetup, error) {
	if eff.NetworkMode != "allowlist" {
		return nil, nil
	}
	netName := nm.NetworkName(profile.Name)
	egressName := nm.EgressNetworkName(profile.Name)
	proxyName := nm.ProxyName(profile.Name)

	if err := nm.ensureNetwork(ctx, netName, true); err != nil {
		return nil, err
	}
	if err := nm.ensureNetwork(ctx, egressName, false); err != nil {
		return nil, err
	}

	token := ""
	if eff.NeedsGateway {
		t, err := gatewayToken(profile.Name)
		if err != nil {
			return nil, err
		}
		token = t
	}
	confDir, err := nm.writeProxyConfig(profile.Name, eff, token)
	if err != nil {
		return nil, err
	}

	// Reuse a running proxy built from the same helper image: reloading its
	// configuration keeps its address stable for sandboxes already running.
	if nm.containerRunning(ctx, proxyName) && nm.label(ctx, proxyName, "rig.helper-image") == helperImage {
		if out, err := exec.CommandContext(ctx, nm.bin, "kill", "--signal", "HUP", proxyName).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("reload egress proxy: %s", strings.TrimSpace(string(out)))
		}
	} else {
		_ = exec.CommandContext(ctx, nm.bin, "rm", "-f", proxyName).Run()
		args := []string{
			"run", "-d",
			"--name", proxyName,
			"--network", netName,
			"--network-alias", ProxyAlias,
			"--label", LabelProfile + "=" + profile.Name,
			"--label", LabelRole + "=proxy",
			"--label", "rig.helper-image=" + helperImage,
			"--restart", "unless-stopped",
			"--read-only",
			"--cap-drop", "ALL",
			"--security-opt", "no-new-privileges",
			"--pids-limit", "256",
			"--memory", "256m",
			"--cpus", "1",
			"-v", confDir + ":/etc/rig:ro",
			helperImage,
			"proxy", "--config", "/etc/rig/egress.json",
		}
		if out, err := exec.CommandContext(ctx, nm.bin, args...).CombinedOutput(); err != nil {
			nm.Teardown(ctx, profile.Name)
			return nil, fmt.Errorf("start egress proxy: %s", strings.TrimSpace(string(out)))
		}
		// Give the proxy, and only the proxy, a route to the internet.
		if out, err := exec.CommandContext(ctx, nm.bin, "network", "connect", egressName, proxyName).CombinedOutput(); err != nil {
			nm.Teardown(ctx, profile.Name)
			return nil, fmt.Errorf("connect proxy to egress network: %s", strings.TrimSpace(string(out)))
		}
	}

	if err := nm.waitForProxy(ctx, proxyName); err != nil {
		logs, _ := exec.CommandContext(ctx, nm.bin, "logs", "--tail", "20", proxyName).CombinedOutput()
		nm.Teardown(ctx, profile.Name)
		return nil, fmt.Errorf("%w\nproxy logs:\n%s", err, strings.TrimSpace(string(logs)))
	}
	ip := nm.containerIP(ctx, proxyName, netName)
	return &NetworkSetup{Network: netName, ProxyIP: ip, GatewayToken: token}, nil
}

// EgressConfig builds the proxy configuration for a profile.
func EgressConfig(eff config.Effective, gatewayToken string) egress.Config {
	cfg := egress.Config{
		Listen:         fmt.Sprintf(":%d", ProxyPort),
		Allow:          eff.Allowed,
		BlockRisky:     eff.BlockRisky,
		AllowRisky:     eff.AllowRisky,
		HTTPSOnly:      eff.HTTPSOnly,
		RequireSNI:     eff.RequireSNI,
		MaxUploadBytes: eff.MaxUploadBytes,
	}
	if gatewayToken != "" {
		sum := sha256.Sum256([]byte(gatewayToken))
		cfg.Clients = []egress.Client{{
			Name:        "gateway",
			TokenSHA256: hex.EncodeToString(sum[:]),
			Allow:       eff.GatewayAllowed,
		}}
	}
	return cfg
}

// writeProxyConfig stores the proxy configuration where the proxy container
// can read it. It holds the allowlist and a token hash, nothing secret, and
// is world-readable because the proxy runs as an unprivileged user.
func (nm *NetworkManager) writeProxyConfig(profileName string, eff config.Effective, token string) (string, error) {
	dir, err := config.StateDir(profileName, "proxy")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", err
	}
	cfg := EgressConfig(eff, token)
	if _, err := egress.Compile(cfg); err != nil {
		return "", fmt.Errorf("egress policy: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, "egress.json.tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	// Rename keeps the update atomic for a proxy that reloads mid-write.
	if err := os.Rename(tmp, filepath.Join(dir, "egress.json")); err != nil {
		return "", err
	}
	return dir, nil
}

// gatewayToken returns the profile's proxy credential for the gateway,
// creating it once. It is kept private to the user and given only to the
// gateway container.
func gatewayToken(profileName string) (string, error) {
	dir, err := config.StateDir(profileName, "secrets")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "gateway-token")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// ensureNetwork creates a network if it does not already exist. An existing
// network is verified to have the expected internal flag, because a sandbox
// joined to a network that is not internal would have unrestricted egress.
func (nm *NetworkManager) ensureNetwork(ctx context.Context, name string, internal bool) error {
	out, err := exec.CommandContext(ctx, nm.bin, "network", "inspect", name).Output()
	if err == nil {
		var info []struct {
			Internal bool              `json:"Internal"`
			Options  map[string]string `json:"Options"`
			// Podman spells it in lower case.
			InternalLower bool `json:"internal"`
		}
		if json.Unmarshal(out, &info) != nil || len(info) == 0 {
			return fmt.Errorf("could not read network %q", name)
		}
		got := info[0].Internal || info[0].InternalLower
		if got != internal {
			return fmt.Errorf("network %q already exists with internal=%v, expected internal=%v; remove it with '%s network rm %s' and retry", name, got, internal, nm.bin, name)
		}
		if internal && nm.name == "docker" && info[0].Options["com.docker.network.bridge.inhibit_ipv4"] != "true" {
			// Made by an older Rig: the host is reachable from it. Recreate
			// it if nothing is attached; otherwise refuse.
			if rmOut, rmErr := exec.CommandContext(ctx, nm.bin, "network", "rm", name).CombinedOutput(); rmErr != nil {
				return fmt.Errorf("network %q lets sandboxes reach services on your host and is still in use; stop its sandboxes ('rig rm') and retry: %s", name, strings.TrimSpace(string(rmOut)))
			}
		} else {
			return nil
		}
	}

	args := []string{"network", "create"}
	if internal {
		args = append(args, "--internal")
		if nm.name == "docker" {
			// No address for the host on this bridge: without it the sandbox
			// could connect to anything listening on the host's interfaces.
			args = append(args, "-o", "com.docker.network.bridge.inhibit_ipv4=true")
		}
	}
	args = append(args, "--label", "rig.managed=true", name)
	if out, err := exec.CommandContext(ctx, nm.bin, args...).CombinedOutput(); err != nil {
		// A concurrent `rig run` may have won the race.
		if strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("create network %s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

func (nm *NetworkManager) containerRunning(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, nm.bin, "inspect", "-f", "{{.State.Running}}", name).Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func (nm *NetworkManager) label(ctx context.Context, name, label string) string {
	out, err := exec.CommandContext(ctx, nm.bin, "inspect", "-f", `{{index .Config.Labels "`+label+`"}}`, name).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "<no value>" {
		return ""
	}
	return v
}

func (nm *NetworkManager) containerIP(ctx context.Context, name, network string) string {
	out, err := exec.CommandContext(ctx, nm.bin, "inspect", "-f",
		`{{with index .NetworkSettings.Networks "`+network+`"}}{{.IPAddress}}{{end}}`, name).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// waitForProxy blocks until the proxy accepts connections.
func (nm *NetworkManager) waitForProxy(ctx context.Context, proxyName string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !nm.containerRunning(ctx, proxyName) {
			return fmt.Errorf("egress proxy %s exited during startup", proxyName)
		}
		probe := exec.CommandContext(ctx, nm.bin, "exec", proxyName, "/rig-helper", "probe", fmt.Sprintf("127.0.0.1:%d", ProxyPort))
		if probe.Run() == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("egress proxy %s did not become ready within 30s", proxyName)
}

// Teardown removes the proxy, the gateway and both networks for a profile.
// Networks with sandboxes still attached are left alone by the engine, which
// is what we want when other instances are still running.
func (nm *NetworkManager) Teardown(ctx context.Context, profileName string) {
	_ = exec.CommandContext(ctx, nm.bin, "rm", "-f", nm.ProxyName(profileName)).Run()
	_ = exec.CommandContext(ctx, nm.bin, "rm", "-f", GatewayName(profileName)).Run()
	_ = exec.CommandContext(ctx, nm.bin, "network", "rm", nm.NetworkName(profileName)).Run()
	_ = exec.CommandContext(ctx, nm.bin, "network", "rm", nm.EgressNetworkName(profileName)).Run()
}

// ProxyLogs streams the proxy's JSON log from now on. The caller reads
// stdout and must call Wait or kill the command.
func (nm *NetworkManager) ProxyLogs(ctx context.Context, profileName string, since time.Time) *exec.Cmd {
	return exec.CommandContext(ctx, nm.bin, "logs", "-f", "--since", since.UTC().Format(time.RFC3339), nm.ProxyName(profileName))
}
