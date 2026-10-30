package container

import (
	"fmt"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
)

// Isolation is the boundary a sandbox will run behind.
type Isolation struct {
	Level   string // container | gvisor | vm
	Runtime string // value for --runtime, "" for the engine default
	Note    string // shown to the user when it matters
}

// ResolveIsolation turns the profile's isolation request into a runtime.
//
//   - container: the engine's normal runtime (runc or crun), hardened by Rig.
//     A kernel bug can still escape it.
//   - gvisor: gVisor's runsc. The sandbox talks to a user-space kernel, so a
//     host kernel bug is far harder to reach.
//   - vm: a lightweight virtual machine per sandbox (Kata Containers on
//     Linux; Apple's container runtime on macOS always works this way).
//
// auto picks gVisor, then a VM, then a plain container. When the level
// requires strong isolation and none is installed, this fails rather than
// quietly running with less.
func ResolveIsolation(eff config.Effective, info provider.EngineInfo) (Isolation, error) {
	if info.Name == "apple" {
		if eff.Isolation == config.IsolationGVisor {
			return Isolation{}, fmt.Errorf("gVisor is not available with Apple's container runtime, which already runs each sandbox in its own VM; set security.isolation to vm or auto")
		}
		return Isolation{Level: config.IsolationVM}, nil
	}

	gvisor, hasGVisor := info.HasRuntime(provider.IsGVisor)
	kata, hasKata := info.HasRuntime(provider.IsKata)
	// runsc cannot create containers under rootless Podman (it needs the
	// systemd cgroup manager as root), so it does not count there.
	gvisorBroken := hasGVisor && info.Name == "podman" && info.Rootless
	if gvisorBroken {
		hasGVisor = false
	}

	switch eff.Isolation {
	case config.IsolationContainer:
		return Isolation{Level: config.IsolationContainer}, nil
	case config.IsolationGVisor:
		if gvisorBroken {
			return Isolation{}, fmt.Errorf("security.isolation is gvisor, but gVisor cannot run under rootless Podman; use Docker or rootful Podman with gVisor, or isolation vm")
		}
		if !hasGVisor {
			return Isolation{}, fmt.Errorf("security.isolation is gvisor, but %s has no gVisor runtime (runsc); run 'rig doctor' for setup steps", info.Name)
		}
		return Isolation{Level: config.IsolationGVisor, Runtime: gvisor}, nil
	case config.IsolationVM:
		if !hasKata {
			return Isolation{}, fmt.Errorf("security.isolation is vm, but %s has no VM runtime (Kata Containers); run 'rig doctor' for setup steps", info.Name)
		}
		return Isolation{Level: config.IsolationVM, Runtime: kata}, nil
	}

	// auto
	switch {
	case hasGVisor:
		return Isolation{Level: config.IsolationGVisor, Runtime: gvisor}, nil
	case hasKata:
		return Isolation{Level: config.IsolationVM, Runtime: kata}, nil
	case eff.RequireStrongIsolation:
		return Isolation{}, fmt.Errorf("security level %s needs gVisor or a VM runtime, and %s has neither; install gVisor (runsc) or Kata Containers ('rig doctor' shows how), or choose a lower level", eff.Level, info.Name)
	}
	iso := Isolation{Level: config.IsolationContainer}
	if eff.PreferStrongIsolation {
		iso.Note = "gVisor or a VM runtime would make this sandbox much harder to escape; 'rig doctor' shows how to install one"
	}
	if info.DockerDesktop {
		iso.Note = "running inside Docker Desktop's VM, which shields your computer from a container escape (but not other containers)"
	}
	return iso, nil
}
