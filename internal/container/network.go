package container

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/security"
)

// ProxyImage is the Squid image used for allowlist egress filtering. Override
// with RIG_PROXY_IMAGE to pin a digest or use a mirror.
const defaultProxyImage = "ubuntu/squid:latest"

// ProxyAlias is the network alias the sandbox reaches the proxy on. It must
// match the HTTP_PROXY value handed to the sandbox container.
const ProxyAlias = "rig-proxy"

type NetworkManager struct{}

func NewNetworkManager() (*NetworkManager, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}
	return &NetworkManager{}, nil
}

func (nm *NetworkManager) Close() {}

// NetworkName is the internal, routing-less network the sandbox is attached to.
func (nm *NetworkManager) NetworkName(profileName string) string {
	return "rig-net-" + profileName
}

// EgressNetworkName is the ordinary bridge network that gives *only* the proxy
// a route to the internet.
func (nm *NetworkManager) EgressNetworkName(profileName string) string {
	return "rig-egress-" + profileName
}

func (nm *NetworkManager) ProxyName(profileName string) string {
	return "rig-proxy-" + profileName
}

func proxyImage() string {
	if img := os.Getenv("RIG_PROXY_IMAGE"); img != "" {
		return img
	}
	return defaultProxyImage
}

// Setup builds the egress-filtered network for an allowlist profile and
// returns the name of the network the sandbox should join.
//
// The topology is what makes the allowlist an actual boundary rather than a
// suggestion:
//
//	sandbox ── rig-net-<p> (--internal, no route off-host) ── proxy
//	                                                           │
//	                                        rig-egress-<p> ── internet
//
// Because the sandbox's only network is marked --internal, it has no route to
// anything except the proxy. Setting HTTP_PROXY alone would not accomplish
// this: any process can ignore the variable and open a socket directly.
func (nm *NetworkManager) Setup(ctx context.Context, profile *config.Profile) (string, error) {
	if profile.Network.Mode != "allowlist" {
		return "", nil
	}

	squidConf, err := security.GenerateSquidConfig(profile.Network.AllowedDomains)
	if err != nil {
		return "", fmt.Errorf("build allowlist: %w", err)
	}

	netName := nm.NetworkName(profile.Name)
	egressName := nm.EgressNetworkName(profile.Name)

	if err := nm.ensureNetwork(ctx, netName, true); err != nil {
		return "", err
	}
	if err := nm.ensureNetwork(ctx, egressName, false); err != nil {
		return "", err
	}

	confPath, err := nm.writeProxyConfig(profile.Name, squidConf)
	if err != nil {
		return "", err
	}

	proxyName := nm.ProxyName(profile.Name)
	// Remove any proxy left over from a previous run so the container always
	// starts from the current allowlist rather than a stale one.
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", proxyName).Run()

	proxyArgs := []string{
		"run", "-d",
		"--name", proxyName,
		"--network", netName,
		"--network-alias", ProxyAlias,
		"--label", "rig.profile=" + profile.Name,
		"--label", "rig.role=proxy",
		"--restart", "unless-stopped",
		"--security-opt", "no-new-privileges",
		"-v", confPath + ":/etc/squid/squid.conf:ro",
		proxyImage(),
	}
	if out, err := exec.CommandContext(ctx, "docker", proxyArgs...).CombinedOutput(); err != nil {
		// Leave nothing half-built behind: a stray non-internal network would
		// have to be removed by hand before the next launch could succeed.
		nm.Teardown(ctx, profile.Name)
		return "", fmt.Errorf("start allowlist proxy: %s", strings.TrimSpace(string(out)))
	}

	// Give the proxy — and only the proxy — a route to the internet.
	if out, err := exec.CommandContext(ctx, "docker", "network", "connect", egressName, proxyName).CombinedOutput(); err != nil {
		nm.Teardown(ctx, profile.Name)
		return "", fmt.Errorf("connect proxy to egress network: %s", strings.TrimSpace(string(out)))
	}

	if err := nm.waitForProxy(ctx, proxyName); err != nil {
		logs, _ := exec.CommandContext(ctx, "docker", "logs", "--tail", "20", proxyName).CombinedOutput()
		nm.Teardown(ctx, profile.Name)
		return "", fmt.Errorf("%w\nproxy logs:\n%s", err, strings.TrimSpace(string(logs)))
	}

	return netName, nil
}

// ensureNetwork creates a network if it does not already exist. An existing
// network is verified to have the expected internal flag, because a sandbox
// joined to a network that is not internal would have unrestricted egress.
func (nm *NetworkManager) ensureNetwork(ctx context.Context, name string, internal bool) error {
	out, err := exec.CommandContext(ctx, "docker", "network", "inspect", "-f", "{{.Internal}}", name).Output()
	if err == nil {
		got := strings.TrimSpace(string(out)) == "true"
		if got != internal {
			return fmt.Errorf("network %q already exists with internal=%v, expected internal=%v; "+
				"remove it with 'docker network rm %s' and retry", name, got, internal, name)
		}
		return nil
	}

	args := []string{"network", "create"}
	if internal {
		args = append(args, "--internal")
	}
	args = append(args, "--label", "rig.managed=true", name)

	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		// A concurrent `rig run` may have won the race; treat that as success.
		if strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("create network %s: %s", name, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeProxyConfig stores the generated squid.conf under the user's config
// directory. It is world-readable by design: the proxy container drops to an
// unprivileged user and must be able to read its own configuration.
func (nm *NetworkManager) writeProxyConfig(profileName, conf string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "rig", "proxy", profileName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create proxy config dir: %w", err)
	}
	confPath := filepath.Join(dir, "squid.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		return "", fmt.Errorf("write squid config: %w", err)
	}
	return confPath, nil
}

// waitForProxy blocks until the proxy is listening, so the sandbox does not
// start racing a proxy that is still booting and see spurious failures.
func (nm *NetworkManager) waitForProxy(ctx context.Context, proxyName string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		running, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", proxyName).Output()
		if err != nil || strings.TrimSpace(string(running)) != "true" {
			return fmt.Errorf("allowlist proxy %s exited during startup", proxyName)
		}
		// squid rewrites its listening socket last, so a successful connect is
		// a reliable readiness signal.
		check := exec.CommandContext(ctx, "docker", "exec", proxyName,
			"bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/3128")
		if check.Run() == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("allowlist proxy %s did not become ready within 30s", proxyName)
}

// Teardown removes the proxy and both networks for a profile. Networks that
// still have sandboxes attached are left alone by Docker, which is what we
// want when other instances of the profile are still running.
func (nm *NetworkManager) Teardown(ctx context.Context, profileName string) {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", nm.ProxyName(profileName)).Run()
	_ = exec.CommandContext(ctx, "docker", "network", "rm", nm.NetworkName(profileName)).Run()
	_ = exec.CommandContext(ctx, "docker", "network", "rm", nm.EgressNetworkName(profileName)).Run()

	if home, err := os.UserHomeDir(); err == nil {
		_ = os.RemoveAll(filepath.Join(home, ".config", "rig", "proxy", profileName))
	}
}
