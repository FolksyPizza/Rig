package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// EngineInfo describes the container engine Rig will use.
type EngineInfo struct {
	Name            string   // docker | podman | apple
	Version         string   // server version, when known
	OS              string   // e.g. "Docker Desktop", "Ubuntu 24.04"
	Runtimes        []string // OCI runtimes the engine can use
	DefaultRuntime  string
	Rootless        bool
	SecurityOptions []string // e.g. seccomp, apparmor, selinux, userns
	DockerDesktop   bool
}

// HasRuntime reports whether a runtime matching pred is available, and its name.
func (e EngineInfo) HasRuntime(pred func(string) bool) (string, bool) {
	for _, r := range e.Runtimes {
		if pred(r) {
			return r, true
		}
	}
	return "", false
}

// IsGVisor matches gVisor runtime names (runsc, runsc-kvm, io.containerd.runsc.v1).
func IsGVisor(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "runsc") || n == "gvisor"
}

// IsKata matches Kata Containers runtime names (kata, kata-qemu, io.containerd.kata.v2).
func IsKata(name string) bool {
	return strings.Contains(strings.ToLower(name), "kata")
}

// Inspect asks the engine about itself.
func Inspect(ctx context.Context, p Provider) (EngineInfo, error) {
	switch p.Name() {
	case "apple":
		return EngineInfo{Name: "apple", OS: "macOS (Apple container: one VM per container)"}, nil
	case "podman":
		return inspectPodman(ctx, p.Bin())
	default:
		return inspectDocker(ctx, p.Bin())
	}
}

func inspectDocker(ctx context.Context, bin string) (EngineInfo, error) {
	out, err := exec.CommandContext(ctx, bin, "info", "--format", "{{json .}}").Output()
	if err != nil {
		return EngineInfo{Name: "docker"}, fmt.Errorf("docker info: %w (is the daemon running?)", err)
	}
	var raw struct {
		ServerVersion   string                     `json:"ServerVersion"`
		OperatingSystem string                     `json:"OperatingSystem"`
		Runtimes        map[string]json.RawMessage `json:"Runtimes"`
		DefaultRuntime  string                     `json:"DefaultRuntime"`
		SecurityOptions []string                   `json:"SecurityOptions"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return EngineInfo{Name: "docker"}, fmt.Errorf("parse docker info: %w", err)
	}
	info := EngineInfo{
		Name:           "docker",
		Version:        raw.ServerVersion,
		OS:             raw.OperatingSystem,
		DefaultRuntime: raw.DefaultRuntime,
		DockerDesktop:  strings.Contains(raw.OperatingSystem, "Docker Desktop"),
	}
	for name := range raw.Runtimes {
		info.Runtimes = append(info.Runtimes, name)
	}
	sort.Strings(info.Runtimes)
	for _, opt := range raw.SecurityOptions {
		name := opt
		for _, kv := range strings.Split(opt, ",") {
			if v, ok := strings.CutPrefix(kv, "name="); ok {
				name = v
			}
		}
		info.SecurityOptions = append(info.SecurityOptions, name)
		if name == "rootless" {
			info.Rootless = true
		}
	}
	return info, nil
}

func inspectPodman(ctx context.Context, bin string) (EngineInfo, error) {
	out, err := exec.CommandContext(ctx, bin, "info", "--format", "json").Output()
	if err != nil {
		return EngineInfo{Name: "podman"}, fmt.Errorf("podman info: %w", err)
	}
	var raw struct {
		Host struct {
			OS         string                                 `json:"os"`
			Distro     struct{ Distribution, Version string } `json:"distribution"`
			OCIRuntime struct {
				Name string `json:"name"`
			} `json:"ociRuntime"`
			Security struct {
				Rootless        bool `json:"rootless"`
				SECCOMPEnabled  bool `json:"seccompEnabled"`
				SELinuxEnabled  bool `json:"selinuxEnabled"`
				AppArmorEnabled bool `json:"apparmorEnabled"`
			} `json:"security"`
		} `json:"host"`
		Version struct {
			Version string `json:"Version"`
		} `json:"version"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return EngineInfo{Name: "podman"}, fmt.Errorf("parse podman info: %w", err)
	}
	info := EngineInfo{
		Name:           "podman",
		Version:        raw.Version.Version,
		OS:             strings.TrimSpace(raw.Host.Distro.Distribution + " " + raw.Host.Distro.Version),
		DefaultRuntime: raw.Host.OCIRuntime.Name,
		Rootless:       raw.Host.Security.Rootless,
	}
	if raw.Host.Security.SECCOMPEnabled {
		info.SecurityOptions = append(info.SecurityOptions, "seccomp")
	}
	if raw.Host.Security.SELinuxEnabled {
		info.SecurityOptions = append(info.SecurityOptions, "selinux")
	}
	if raw.Host.Security.AppArmorEnabled {
		info.SecurityOptions = append(info.SecurityOptions, "apparmor")
	}
	if info.Rootless {
		info.SecurityOptions = append(info.SecurityOptions, "rootless")
	}
	// Podman runs any runtime it can find by name; look for the usual ones.
	seen := map[string]bool{}
	for _, name := range []string{raw.Host.OCIRuntime.Name, "crun", "runc", "runsc", "kata-runtime", "kata"} {
		if name == "" || seen[name] {
			continue
		}
		if name == raw.Host.OCIRuntime.Name {
			seen[name] = true
			info.Runtimes = append(info.Runtimes, name)
			continue
		}
		if _, err := lookPath(name); err == nil {
			seen[name] = true
			info.Runtimes = append(info.Runtimes, name)
		}
	}
	sort.Strings(info.Runtimes)
	return info, nil
}
