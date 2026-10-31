package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
)

// setting is one value you can change with 'rig set' (and with the matching
// 'rig new' flag). Keeping them in one table means both accept the same
// values and validate them the same way.
type setting struct {
	key, values, help string
	apply             func(p *config.Profile, v string) error
	show              func(p *config.Profile) string
	// resources marks settings an existing container can take without
	// being recreated.
	resources bool
	// rebuild marks settings that change the image or how the container is
	// created, so an existing persistent container needs --recreate.
	rebuild bool
}

func settingsTable() []setting {
	return []setting{
		{key: "agent", rebuild: true, values: "IDs, comma-separated", help: "agents installed in the sandbox ('rig agents')",
			apply: func(p *config.Profile, v string) error {
				ac, err := agentConfigs(splitList(v))
				if err == nil {
					p.Agents = ac
				}
				return err
			},
			show: func(p *config.Profile) string { return agentIDList(p) }},
		{key: "level", rebuild: true, values: "open|standard|strict|lockdown", help: "security level ('rig levels')",
			apply: func(p *config.Profile, v string) error { return applyLevel(p, v, false, false) },
			show:  func(p *config.Profile) string { return p.EffectiveLevel() }},
		{key: "permissions", rebuild: true, values: "ask|edit|full", help: "what agents may do without asking you: ask (their default), edit files, or full (no prompts)",
			apply: func(p *config.Profile, v string) error {
				p.Security.AgentPermissions = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Resolve().AgentPermissions }},
		{key: "cpu", values: "cores, e.g. 2 or 1.5", help: "CPU limit", resources: true,
			apply: func(p *config.Profile, v string) error {
				f, err := strconv.ParseFloat(v, 64)
				if err != nil || f <= 0 {
					return fmt.Errorf("cpu: %q is not a number of cores", v)
				}
				p.Resources.CPU = math.Round(f*100) / 100
				return nil
			},
			show: func(p *config.Profile) string { return strconv.FormatFloat(p.Resources.CPU, 'f', -1, 64) }},
		{key: "memory", values: "e.g. 4g, 512m", help: "memory limit", resources: true,
			apply: func(p *config.Profile, v string) error {
				mb, err := parseMegabytes(v)
				if err == nil {
					p.Resources.Memory = mb
				}
				return err
			},
			show: func(p *config.Profile) string { return formatMegabytes(p.Resources.Memory) }},
		{key: "pids", values: "e.g. 512", help: "process limit", resources: true,
			apply: func(p *config.Profile, v string) error {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return fmt.Errorf("pids: %q is not a number", v)
				}
				p.Resources.PIDLimit = n
				return nil
			},
			show: func(p *config.Profile) string { return strconv.FormatInt(p.Resources.PIDLimit, 10) }},
		{key: "disk", rebuild: true, values: "e.g. 10g", help: "disk space for the sandbox (where the engine supports limits)",
			apply: func(p *config.Profile, v string) error {
				p.Storage.Size = strings.ToLower(v)
				return nil
			},
			show: func(p *config.Profile) string { return p.Storage.Size }},
		{key: "network", rebuild: true, values: "allowlist|none|unrestricted", help: "network mode (unrestricted needs level open)",
			apply: func(p *config.Profile, v string) error {
				p.Network.Mode = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Network.Mode }},
		{key: "isolation", rebuild: true, values: "auto|container|gvisor|vm", help: "boundary between the agent and this computer",
			apply: func(p *config.Profile, v string) error {
				p.Security.Isolation = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Resolve().Isolation }},
		{key: "persistence", rebuild: true, values: "persistent|ephemeral", help: "keep files and installed tools between runs, or start fresh each time",
			apply: func(p *config.Profile, v string) error {
				p.Persistence = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Persistence }},
		{key: "sudo", rebuild: true, values: "yes|no", help: "passwordless sudo for the agent (open and standard only)",
			apply: func(p *config.Profile, v string) error {
				b, err := parseYes(v)
				p.Security.Sudo = b
				return err
			},
			show: func(p *config.Profile) string { return yesNo(p.Security.Sudo) }},
		{key: "monitor", values: "off|observe|enforce", help: "observe records and flags; enforce also stops the sandbox on serious violations",
			apply: func(p *config.Profile, v string) error {
				p.Monitor.Mode = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Resolve().MonitorMode }},
		{key: "strictness", values: "low|medium|high", help: "how readily the monitor acts",
			apply: func(p *config.Profile, v string) error {
				p.Monitor.Strictness = v
				return nil
			},
			show: func(p *config.Profile) string { return p.Resolve().Strictness }},
		{key: "timeout", values: "e.g. 2h, 0 for none", help: "stop the sandbox automatically after this long",
			apply: func(p *config.Profile, v string) error {
				if v == "0" || v == "none" {
					p.Metadata.Timeout = 0
					return nil
				}
				d, err := time.ParseDuration(v)
				if err != nil || d < 0 {
					return fmt.Errorf("timeout: %q is not a duration such as 30m or 2h", v)
				}
				p.Metadata.Timeout = d
				return nil
			},
			show: func(p *config.Profile) string {
				if p.Metadata.Timeout == 0 {
					return "none"
				}
				return p.Metadata.Timeout.String()
			}},
		{key: "commands", values: "all, or names comma-separated", help: "commands 'rig exec' accepts (a guard on that entry point, not a sandbox boundary)",
			apply: func(p *config.Profile, v string) error {
				if v == "all" || v == "unrestricted" {
					p.Commands = config.CommandsConfig{Mode: "unrestricted"}
					return nil
				}
				p.Commands = config.CommandsConfig{Mode: "allowlist", Allowed: splitList(v)}
				return nil
			},
			show: func(p *config.Profile) string {
				if p.Commands.Mode != "allowlist" {
					return "all"
				}
				return strings.Join(p.Commands.Allowed, ",")
			}},
	}
}

func findSetting(key string) (setting, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	aliases := map[string]string{"agents": "agent", "cpus": "cpu", "mem": "memory", "processes": "pids", "pids_limit": "pids",
		"storage": "disk", "size": "disk", "agent_permissions": "permissions", "security": "level"}
	if a, ok := aliases[key]; ok {
		key = a
	}
	for _, s := range settingsTable() {
		if s.key == key {
			return s, true
		}
	}
	return setting{}, false
}

// applyLevel sets the security level and adjusts what the new level does not
// allow, unless you set it explicitly at the same time (keepSudo,
// keepNetwork): then validation reports the conflict instead.
func applyLevel(p *config.Profile, level string, keepSudo, keepNetwork bool) error {
	switch level {
	case config.LevelOpen, config.LevelStandard, config.LevelStrict, config.LevelLockdown:
	default:
		return fmt.Errorf("level: %q is not open, standard, strict or lockdown", level)
	}
	p.Security.Level = level
	rank := config.LevelRank(level)
	if level == config.LevelLockdown {
		p.Persistence = "ephemeral"
		if p.Security.AgentPermissions == config.PermissionsFull {
			p.Security.AgentPermissions = config.PermissionsEdit
		}
		if p.Monitor.Mode == "observe" {
			p.Monitor.Mode = ""
		}
		for i := range p.Mounts {
			p.Mounts[i].ReadOnly = true
		}
	}
	if rank > config.LevelRank(config.LevelStandard) {
		if !keepSudo {
			p.Security.Sudo = false
		}
		if p.Monitor.Mode == "off" {
			p.Monitor.Mode = ""
		}
	}
	if level != config.LevelOpen && p.Network.Mode == "unrestricted" && !keepNetwork {
		p.Network = config.NetworkConfig{Mode: "allowlist", Presets: []string{"github", "npm", "pypi"}}
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func agentIDList(p *config.Profile) string {
	ids := make([]string, len(p.Agents))
	for i, a := range p.Agents {
		ids[i] = a.ID
		if a.Version != "" {
			ids[i] += "@" + a.Version
		}
	}
	return strings.Join(ids, ",")
}

// parseMegabytes reads sizes such as 4g, 4096m, 4096 (megabytes) or 1.5g.
func parseMegabytes(v string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimSuffix(s, "b")
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "g"):
		mult, s = 1024, strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		s = strings.TrimSuffix(s, "m")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return 0, fmt.Errorf("memory: %q is not a size such as 4g or 512m", v)
	}
	return int64(math.Round(f * mult)), nil
}

func formatMegabytes(mb int64) string {
	if mb >= 1024 && mb%1024 == 0 {
		return strconv.FormatInt(mb/1024, 10) + "g"
	}
	return strconv.FormatInt(mb, 10) + "m"
}

func parseYes(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "yes", "y", "true", "on", "1":
		return true, nil
	case "no", "n", "false", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q is not yes or no", v)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
