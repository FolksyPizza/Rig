package config

import "time"

// DefaultProfile is the starting point for `rig new` without a template:
// Claude Code at the standard level, with an egress allowlist and a
// persistent workspace volume.
func DefaultProfile() Profile {
	return Profile{
		Version:  1,
		Security: SecurityConfig{Level: LevelStandard},
		Agents: []AgentConfig{
			{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
		},
		Tools: []string{"git", "curl", "jq", "ripgrep", "fd-find", "make", "python3", "python3-pip", "python3-venv"},
		Network: NetworkConfig{
			Mode:    "allowlist",
			Presets: []string{"github", "npm", "pypi"},
		},
		Commands:    CommandsConfig{Mode: "unrestricted"},
		Resources:   ResourcesConfig{CPU: 2.0, Memory: 4096, PIDLimit: 512},
		Storage:     StorageConfig{Size: "10g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
		Persistence: "persistent",
		Metadata:    Metadata{CreatedAt: time.Now()},
	}
}
