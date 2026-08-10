package config

type Template struct {
	Name        string
	Description string
	Profile     Profile
}

func BuiltinTemplates() []Template {
	return []Template{
		{
			Name:        "claude-dev",
			Description: "Claude Code with full dev tools, unrestricted network",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
				},
				Tools: []string{"git", "curl", "wget", "jq", "ripgrep", "fd-find", "fzf", "neovim", "tmux", "python3", "python3-pip", "make", "build-essential", "unzip"},
				Network: NetworkConfig{
					Mode: "unrestricted",
				},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 4.0, Memory: 8192, PIDLimit: 1024},
				Storage:     StorageConfig{Size: "20g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
				Persistence: "persistent",
			},
		},
		{
			Name:        "claude-secure",
			Description: "Claude Code with network allowlist, locked down",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
				},
				Tools: []string{"git", "curl", "jq", "ripgrep", "fd-find", "neovim"},
				Network: NetworkConfig{
					Mode: "allowlist",
					AllowedDomains: []string{
						"api.anthropic.com",
						"statsig.anthropic.com",
						"registry.npmjs.org",
						"github.com",
						"*.githubusercontent.com",
					},
				},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 2.0, Memory: 4096, PIDLimit: 512},
				Storage:     StorageConfig{Size: "10g"},
				Persistence: "ephemeral",
			},
		},
		{
			Name:        "codex-dev",
			Description: "OpenAI Codex with full dev tools",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "codex", Env: map[string]string{"OPENAI_API_KEY": "${OPENAI_API_KEY}"}},
				},
				Tools: []string{"git", "curl", "wget", "jq", "ripgrep", "fd-find", "fzf", "neovim", "tmux", "python3", "python3-pip", "make", "build-essential"},
				Network: NetworkConfig{
					Mode: "unrestricted",
				},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 4.0, Memory: 8192, PIDLimit: 1024},
				Storage:     StorageConfig{Size: "20g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
				Persistence: "persistent",
			},
		},
		{
			Name:        "multi-agent",
			Description: "Claude Code + Gemini CLI + Codex side by side",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
					{ID: "gemini-cli", Env: map[string]string{"GEMINI_API_KEY": "${GEMINI_API_KEY}"}},
					{ID: "codex", Env: map[string]string{"OPENAI_API_KEY": "${OPENAI_API_KEY}"}},
				},
				Tools: []string{"git", "curl", "wget", "jq", "ripgrep", "fd-find", "fzf", "neovim", "tmux", "python3", "python3-pip", "make", "build-essential", "bat", "htop"},
				Network: NetworkConfig{
					Mode: "unrestricted",
				},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 4.0, Memory: 16384, PIDLimit: 2048},
				Storage:     StorageConfig{Size: "30g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
				Persistence: "persistent",
			},
		},
		{
			Name:        "airgapped",
			Description: "Fully offline sandbox with no network access",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "claude-code"},
				},
				Tools: []string{"git", "curl", "jq", "ripgrep", "fd-find", "fzf", "neovim", "tmux", "python3", "python3-pip"},
				Network: NetworkConfig{
					Mode: "none",
				},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 2.0, Memory: 4096, PIDLimit: 512},
				Storage:     StorageConfig{Size: "10g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
				Persistence: "persistent",
			},
		},
		{
			Name:        "minimal",
			Description: "Lightweight sandbox with minimal tools",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
				},
				Tools:       []string{"git", "curl", "jq"},
				Network:     NetworkConfig{Mode: "unrestricted"},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 1.0, Memory: 2048, PIDLimit: 256},
				Storage:     StorageConfig{Size: "5g"},
				Persistence: "ephemeral",
			},
		},
		{
			Name:        "hermes-research",
			Description: "Hermes Agent for autonomous research tasks",
			Profile: Profile{
				Version: 1,
				Agents: []AgentConfig{
					{ID: "hermes"},
				},
				Tools:       []string{"git", "curl", "wget", "jq", "python3", "python3-pip", "ripgrep"},
				Network:     NetworkConfig{Mode: "unrestricted"},
				Commands:    CommandsConfig{Mode: "unrestricted"},
				Resources:   ResourcesConfig{CPU: 2.0, Memory: 4096, PIDLimit: 512},
				Storage:     StorageConfig{Size: "10g", Volumes: []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}},
				Persistence: "persistent",
			},
		},
	}
}

func GetTemplate(name string) (Template, bool) {
	for _, t := range BuiltinTemplates() {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}
