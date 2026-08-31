package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/security"
)

type Profile struct {
	Version     int             `yaml:"version"`
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Agents      []AgentConfig   `yaml:"agents"`
	Tools       []string        `yaml:"tools"`
	Network     NetworkConfig   `yaml:"network"`
	Commands    CommandsConfig  `yaml:"commands"`
	Resources   ResourcesConfig `yaml:"resources"`
	Storage     StorageConfig   `yaml:"storage"`
	Persistence string          `yaml:"persistence"`
	GPU         GPUConfig       `yaml:"gpu"`
	Mounts      []MountConfig   `yaml:"mounts,omitempty"`
	Watchdog    WatchdogConfig  `yaml:"watchdog,omitempty"`
	Metadata    Metadata        `yaml:"metadata,omitempty"`
}

// WatchdogConfig configures the in-sandbox monitor. It is optional: an empty or
// "off" mode disables it. Strictness tunes how readily enforce mode kills.
type WatchdogConfig struct {
	Mode       string `yaml:"mode,omitempty"`       // off | observe | enforce
	Strictness string `yaml:"strictness,omitempty"` // low | medium | high
}

type AgentConfig struct {
	ID  string            `yaml:"id"`
	Env map[string]string `yaml:"env,omitempty"`
}

type NetworkConfig struct {
	Mode           string   `yaml:"mode"`
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`
}

// CommandsConfig restricts which commands `rig exec` will run in a sandbox.
//
// This is a convenience guard on Rig's own entry point, not a security
// boundary: an agent with an interactive shell inside the container can run
// anything the image contains regardless of this setting. Use the network and
// resource controls for actual confinement.
type CommandsConfig struct {
	Mode    string   `yaml:"mode"`
	Allowed []string `yaml:"allowed,omitempty"`
}

type ResourcesConfig struct {
	CPU      float64 `yaml:"cpu"`
	Memory   int64   `yaml:"memory"`
	PIDLimit int64   `yaml:"pids_limit"`
}

type StorageConfig struct {
	Size    string        `yaml:"size"`
	Volumes []VolumeMount `yaml:"volumes,omitempty"`
}

type VolumeMount struct {
	Name     string `yaml:"name"`
	Target   string `yaml:"target"`
	Size     string `yaml:"size,omitempty"`
	ReadOnly bool   `yaml:"readonly,omitempty"`
}

type GPUConfig struct {
	Enabled bool     `yaml:"enabled"`
	Devices []string `yaml:"devices,omitempty"`
	Driver  string   `yaml:"driver,omitempty"`
}

type MountConfig struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"readonly"`
}

type Metadata struct {
	CreatedAt time.Time     `yaml:"created_at,omitempty"`
	LastUsed  time.Time     `yaml:"last_used,omitempty"`
	ImageTag  string        `yaml:"image_tag,omitempty"`
	Timeout   time.Duration `yaml:"timeout,omitempty"`
}

// Validate checks every field a profile can carry. Profiles are shareable
// files that arrive via `rig import`, so this runs on load and on save and
// treats the contents as untrusted input.
func (p *Profile) Validate() error {
	if err := security.ValidateProfileName(p.Name); err != nil {
		return err
	}
	if len(p.Agents) == 0 {
		return fmt.Errorf("at least one agent must be selected")
	}
	for _, a := range p.Agents {
		if a.ID == "" {
			return fmt.Errorf("agent entry is missing an id")
		}
		if _, ok := agents.ByID(a.ID); !ok {
			return fmt.Errorf("unknown agent %q (see 'rig agents' for the supported list)", a.ID)
		}
		for k := range a.Env {
			if k == "" || strings.ContainsAny(k, "=\n\r\x00") {
				return fmt.Errorf("invalid environment variable name %q for agent %q", k, a.ID)
			}
		}
	}

	if err := security.ValidatePackageNames(p.Tools); err != nil {
		return err
	}

	switch p.Network.Mode {
	case "unrestricted", "allowlist", "none":
	default:
		return fmt.Errorf("invalid network mode %q (want unrestricted, allowlist or none)", p.Network.Mode)
	}
	if err := security.ValidateDomains(p.Network.AllowedDomains); err != nil {
		return err
	}

	switch p.Commands.Mode {
	case "unrestricted", "allowlist":
	default:
		return fmt.Errorf("invalid commands mode %q (want unrestricted or allowlist)", p.Commands.Mode)
	}

	switch p.Persistence {
	case "ephemeral", "persistent":
	default:
		return fmt.Errorf("invalid persistence mode %q (want ephemeral or persistent)", p.Persistence)
	}

	if p.Resources.CPU < 0.5 {
		return fmt.Errorf("cpu must be at least 0.5 cores")
	}
	if p.Resources.CPU > 1024 {
		return fmt.Errorf("cpu limit %.1f is implausibly large", p.Resources.CPU)
	}
	if p.Resources.Memory < 512 {
		return fmt.Errorf("memory must be at least 512 MB")
	}
	// A PID limit of 0 or -1 means "unlimited" to Docker, which would silently
	// remove the fork-bomb protection the profile appears to configure.
	if p.Resources.PIDLimit < 16 {
		return fmt.Errorf("pids_limit must be at least 16 (0 or negative would disable the limit entirely)")
	}

	if err := security.ValidateSize(p.Storage.Size); err != nil {
		return err
	}
	seenVolume := make(map[string]bool, len(p.Storage.Volumes))
	for _, v := range p.Storage.Volumes {
		if err := security.ValidateVolumeName(v.Name); err != nil {
			return err
		}
		if seenVolume[v.Name] {
			return fmt.Errorf("duplicate volume name %q", v.Name)
		}
		seenVolume[v.Name] = true
		if err := security.ValidateMountTarget(v.Target); err != nil {
			return err
		}
		if err := security.ValidateSize(v.Size); err != nil {
			return err
		}
	}

	for _, m := range p.Mounts {
		if err := security.ValidateMountSource(m.Source); err != nil {
			return err
		}
		if err := security.ValidateMountTarget(m.Target); err != nil {
			return err
		}
	}

	if p.GPU.Enabled {
		return fmt.Errorf("gpu passthrough is not implemented yet; set gpu.enabled to false")
	}

	switch p.Watchdog.Mode {
	case "", "off", "observe", "enforce":
	default:
		return fmt.Errorf("invalid watchdog mode %q (want off, observe or enforce)", p.Watchdog.Mode)
	}
	switch p.Watchdog.Strictness {
	case "", "low", "medium", "high":
	default:
		return fmt.Errorf("invalid watchdog strictness %q (want low, medium or high)", p.Watchdog.Strictness)
	}

	return nil
}

func (p *Profile) ImageTag() string {
	if p.Metadata.ImageTag != "" {
		return p.Metadata.ImageTag
	}
	return fmt.Sprintf("rig/%s:latest", p.Name)
}

// CommandAllowed reports whether `rig exec` should run the given argv in this
// sandbox. See the note on CommandsConfig: this guards Rig's entry point only.
func (p *Profile) CommandAllowed(argv []string) bool {
	if p.Commands.Mode != "allowlist" {
		return true
	}
	if len(argv) == 0 {
		return false
	}
	for _, allowed := range p.Commands.Allowed {
		if allowed == argv[0] {
			return true
		}
	}
	return false
}
