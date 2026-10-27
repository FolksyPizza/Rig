package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/provider"
)

// SelfCheck is one result of a self-test.
type SelfCheck struct {
	Name    string
	Passed  bool
	Skipped bool
	Detail  string
}

// NetworkSelfTest checks, on this machine's engine, what the allowlist
// depends on. A container on a Rig internal network must not be able to
// resolve outside names (DNS would let it send data out), connect to services
// on this computer, or reach the cloud metadata address. Engines and versions
// differ here, so Rig tests it rather than assuming it.
func (nm *NetworkManager) NetworkSelfTest(ctx context.Context, helperImage string) []SelfCheck {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	netName := "rig-selftest-" + hex.EncodeToString(buf)
	if err := nm.ensureNetwork(ctx, netName, true); err != nil {
		return []SelfCheck{{Name: "create an internal network", Detail: err.Error()}}
	}
	defer func() { _ = exec.Command(nm.bin, "network", "rm", netName).Run() }()

	var out []SelfCheck

	// DNS.
	dns := SelfCheck{Name: "sandboxes cannot look up outside names (no DNS channel out)"}
	if _, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err != nil {
		dns.Skipped = true
		dns.Detail = "this computer cannot resolve example.com either, so the result would mean nothing"
	} else if res, err := nm.helperRun(ctx, netName, helperImage, "resolve", "example.com"); err == nil {
		dns.Detail = "example.com resolved to " + strings.TrimSpace(res) + " from an internal network; data could be sent out through DNS queries"
	} else {
		dns.Passed = true
	}
	out = append(out, dns)

	// Services on this computer.
	host := SelfCheck{Name: "sandboxes cannot connect to services on this computer"}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		host.Skipped = true
		host.Detail = "could not open a test port: " + err.Error()
		out = append(out, host)
	} else {
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
		targets := nm.hostAddresses(ctx, netName)
		addrs := make([]string, len(targets))
		for i, t := range targets {
			addrs[i] = net.JoinHostPort(t, port)
		}
		res, _ := nm.helperRun(ctx, netName, helperImage, append([]string{"probe"}, addrs...)...)
		if open := openAddrs(res); len(open) > 0 {
			host.Detail = "reached a test port on this computer through " + strings.Join(open, ", ") +
				"; a sandbox could use services listening on this computer's network interfaces"
		} else if !strings.Contains(res, "closed ") {
			host.Detail = "the probe did not run: " + strings.TrimSpace(res)
		} else {
			host.Passed = true
			host.Detail = "tried " + strings.Join(targets, ", ")
		}
		out = append(out, host)
	}

	// Cloud metadata.
	meta := SelfCheck{Name: "sandboxes cannot reach the cloud metadata address"}
	res, _ := nm.helperRun(ctx, netName, helperImage, "probe", "169.254.169.254:80")
	switch {
	case len(openAddrs(res)) > 0:
		meta.Detail = "169.254.169.254 accepted a connection; on a cloud server that can hand out credentials"
	case strings.Contains(res, "closed "):
		meta.Passed = true
	default:
		meta.Detail = "the probe did not run: " + strings.TrimSpace(res)
	}
	out = append(out, meta)
	return out
}

// RuntimeSelfTest starts a container with each strong isolation runtime the
// engine lists, to confirm it works rather than merely being configured.
func (nm *NetworkManager) RuntimeSelfTest(ctx context.Context, helperImage string, info provider.EngineInfo) []SelfCheck {
	var out []SelfCheck
	for _, rt := range info.Runtimes {
		kind := ""
		switch {
		case provider.IsGVisor(rt):
			kind = "gVisor"
		case provider.IsKata(rt):
			kind = "Kata VM"
		default:
			continue
		}
		c := SelfCheck{Name: fmt.Sprintf("%s runtime %q starts sandboxes", kind, rt)}
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res, err := exec.CommandContext(cctx, nm.bin, "run", "--rm", "--runtime", rt, "--network", "none",
			"--label", "rig.selftest=true", helperImage, "help").CombinedOutput()
		cancel()
		if err != nil {
			c.Detail = strings.TrimSpace(string(res))
		} else {
			c.Passed = true
		}
		out = append(out, c)
	}
	return out
}

// helperRun runs the helper image on a network with the sandbox's hardening.
func (nm *NetworkManager) helperRun(ctx context.Context, network, image string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := append([]string{"run", "--rm", "--network", network, "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--label", "rig.selftest=true", image}, args...)
	out, err := exec.CommandContext(cctx, nm.bin, cmd...).CombinedOutput()
	return string(out), err
}

// hostAddresses lists addresses that lead to this computer from a container:
// the test network's and the default network's gateways, this computer's own
// interface addresses, and the engines' special host names.
func (nm *NetworkManager) hostAddresses(ctx context.Context, testNet string) []string {
	set := map[string]bool{}
	defaultNet := "bridge"
	if nm.name == "podman" {
		defaultNet = "podman"
	}
	for _, n := range []string{testNet, defaultNet} {
		for _, gw := range nm.gateways(ctx, n) {
			set[gw] = true
		}
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					set[ipn.IP.String()] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set)+3)
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return append(out, "host.docker.internal", "host.containers.internal", "gateway.docker.internal")
}

// gateways reads a network's gateway addresses (Docker and Podman spell the
// field differently).
func (nm *NetworkManager) gateways(ctx context.Context, network string) []string {
	raw, err := exec.CommandContext(ctx, nm.bin, "network", "inspect", network).Output()
	if err != nil {
		return nil
	}
	var info []struct {
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		Subnets []struct {
			Subnet  string `json:"subnet"`
			Gateway string `json:"gateway"`
		} `json:"subnets"`
	}
	if json.Unmarshal(raw, &info) != nil {
		return nil
	}
	var out []string
	add := func(subnet, gateway string) {
		if ip := net.ParseIP(gateway); ip != nil && ip.To4() != nil {
			out = append(out, gateway)
		}
		// Also the subnet's first address, which engines usually give the
		// host, in case one does so without reporting it.
		if _, n, err := net.ParseCIDR(subnet); err == nil {
			if ip4 := n.IP.To4(); ip4 != nil {
				first := net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+1).String()
				if first != gateway {
					out = append(out, first)
				}
			}
		}
	}
	for _, n := range info {
		for _, c := range n.IPAM.Config {
			add(c.Subnet, c.Gateway)
		}
		for _, s := range n.Subnets {
			add(s.Subnet, s.Gateway)
		}
	}
	return out
}

func openAddrs(probeOutput string) []string {
	var open []string
	for _, line := range strings.Split(probeOutput, "\n") {
		if addr, ok := strings.CutPrefix(strings.TrimSpace(line), "open "); ok {
			open = append(open, addr)
		}
	}
	return open
}
