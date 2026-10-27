package config

// Template is a ready-made starting point for a sandbox.
type Template struct {
	Name        string
	Description string
	Profile     Profile
}

func boolPtr(b bool) *bool { return &b }

var workspace = []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}

func claudeAgent() AgentConfig {
	return AgentConfig{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}}
}

func base(level string) Profile {
	return Profile{
		Version:     1,
		Security:    SecurityConfig{Level: level},
		Tools:       []string{"git", "curl", "jq", "ripgrep", "fd-find", "make", "python3", "python3-pip", "python3-venv"},
		Network:     NetworkConfig{Mode: "allowlist"},
		Commands:    CommandsConfig{Mode: "unrestricted"},
		Resources:   ResourcesConfig{CPU: 2.0, Memory: 4096, PIDLimit: 512},
		Storage:     StorageConfig{Size: "10g", Volumes: workspace},
		Persistence: "persistent",
	}
}

// BuiltinTemplates returns every template. The first is the default for
// `rig new` when no template is named.
func BuiltinTemplates() []Template {
	standard := base(LevelStandard)
	standard.Agents = []AgentConfig{claudeAgent()}
	standard.Network.Presets = []string{"github", "npm", "pypi"}

	strict := base(LevelStrict)
	strict.Agents = []AgentConfig{claudeAgent()}
	strict.Network.Presets = []string{"github"}
	strict.Persistence = "ephemeral"

	lockdown := base(LevelLockdown)
	lockdown.Agents = []AgentConfig{claudeAgent()}
	lockdown.Tools = []string{"git", "curl", "jq", "ripgrep", "fd-find"}
	lockdown.Persistence = "ephemeral"
	lockdown.Security.Isolation = IsolationAuto

	dev := base(LevelOpen)
	dev.Agents = []AgentConfig{claudeAgent()}
	dev.Tools = append(dev.Tools, "neovim", "tmux", "build-essential", "unzip")
	dev.Network = NetworkConfig{Mode: "unrestricted"}
	dev.Security.Sudo = true
	dev.Resources = ResourcesConfig{CPU: 4.0, Memory: 8192, PIDLimit: 1024}
	dev.Storage.Size = "20g"

	codex := base(LevelStandard)
	codex.Agents = []AgentConfig{{ID: "codex", Env: map[string]string{"OPENAI_API_KEY": "${OPENAI_API_KEY}"}}}
	codex.Network.Presets = []string{"github", "npm", "pypi"}

	gemini := base(LevelStandard)
	gemini.Agents = []AgentConfig{{ID: "gemini-cli", Env: map[string]string{"GEMINI_API_KEY": "${GEMINI_API_KEY}"}}}
	gemini.Network.Presets = []string{"github", "npm", "pypi"}

	pi := base(LevelStandard)
	pi.Agents = []AgentConfig{{ID: "pi", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}}}
	pi.Network.Presets = []string{"github", "npm", "pypi"}

	opencode := base(LevelStandard)
	opencode.Agents = []AgentConfig{{ID: "opencode", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}}}
	opencode.Network.Presets = []string{"github", "npm", "pypi"}

	qwen := base(LevelStandard)
	qwen.Agents = []AgentConfig{{ID: "qwen-code", Env: map[string]string{
		"OPENAI_API_KEY":  "${DASHSCOPE_API_KEY}",
		"OPENAI_BASE_URL": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
	}}}
	qwen.Network.Presets = []string{"github", "npm", "pypi"}

	grove := base(LevelStandard)
	grove.Agents = []AgentConfig{{ID: "grove", Env: map[string]string{
		"OPENAI_API_KEY":    "${OPENAI_API_KEY}",
		"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
	}}}
	grove.Network.Presets = []string{"github", "npm", "pypi"}

	// An open-weight model on your own machine, with no internet at all: the
	// agent can reach only Ollama, through the gateway.
	local := base(LevelStrict)
	local.Agents = []AgentConfig{{ID: "qwen-code", Env: map[string]string{
		"OPENAI_API_KEY":  "ollama",
		"OPENAI_BASE_URL": "http://rig-gw:11434/v1",
		"OPENAI_MODEL":    "qwen3-coder",
	}}}
	local.Host = HostConfig{Ports: []HostPort{{Name: "ollama", Port: 11434}}}

	// Blender over MCP. The MCP server runs in the gateway, the only place
	// that can reach Blender's port; the agent gets the tools, not the socket.
	// execute_blender_code runs arbitrary Python inside Blender on your
	// machine, outside the sandbox, so it is blocked unless you allow it.
	blender := base(LevelStandard)
	blender.Agents = []AgentConfig{claudeAgent()}
	blender.Network.Presets = []string{"github", "npm", "pypi"}
	blender.MCP = MCPConfig{Servers: []MCPServer{{
		Name:      "blender",
		Command:   []string{"blender-mcp"},
		Packages:  PackagesConfig{Pip: []string{"blender-mcp"}},
		RunIn:     "gateway",
		HostPorts: []int{9876},
		DenyTools: []string{"execute_blender_code"},
	}}}

	multi := base(LevelStandard)
	multi.Agents = []AgentConfig{
		claudeAgent(),
		{ID: "gemini-cli", Env: map[string]string{"GEMINI_API_KEY": "${GEMINI_API_KEY}"}},
		{ID: "codex", Env: map[string]string{"OPENAI_API_KEY": "${OPENAI_API_KEY}"}},
	}
	multi.Network.Presets = []string{"github", "npm", "pypi"}
	multi.Resources = ResourcesConfig{CPU: 4.0, Memory: 16384, PIDLimit: 2048}
	multi.Storage.Size = "30g"

	airgapped := base(LevelStrict)
	airgapped.Agents = []AgentConfig{{ID: "claude-code"}}
	airgapped.Network = NetworkConfig{Mode: "none"}

	minimal := base(LevelStandard)
	minimal.Agents = []AgentConfig{claudeAgent()}
	minimal.Tools = []string{"git", "curl", "jq"}
	minimal.Resources = ResourcesConfig{CPU: 1.0, Memory: 2048, PIDLimit: 256}
	minimal.Storage = StorageConfig{Size: "5g"}
	minimal.Persistence = "ephemeral"

	research := base(LevelOpen)
	research.Agents = []AgentConfig{{ID: "hermes"}}
	research.Network = NetworkConfig{Mode: "unrestricted", BlockExfil: boolPtr(true)}

	return []Template{
		{"standard", "Claude Code with an egress allowlist (recommended starting point)", standard},
		{"claude-strict", "Claude Code, strict: read-only image, HTTPS only, ephemeral", strict},
		{"lockdown", "Claude Code, lockdown: model API only, gVisor/VM required, ephemeral", lockdown},
		{"claude-dev", "Claude Code, open: unrestricted network and sudo (trusted work only)", dev},
		{"codex", "OpenAI Codex with an egress allowlist", codex},
		{"gemini", "Gemini CLI with an egress allowlist", gemini},
		{"pi", "Pi coding agent with an egress allowlist", pi},
		{"opencode", "OpenCode with an egress allowlist", opencode},
		{"qwen-code", "Qwen Code against Alibaba DashScope", qwen},
		{"grove", "Grove (Codex-based harness) with an egress allowlist", grove},
		{"local-model", "Qwen Code on your local Ollama, no internet access at all", local},
		{"blender", "Claude Code with Blender over MCP, code execution blocked", blender},
		{"multi-agent", "Claude Code, Gemini CLI and Codex side by side", multi},
		{"airgapped", "No network at all", airgapped},
		{"minimal", "Small, ephemeral Claude Code sandbox", minimal},
		{"hermes-research", "Hermes Agent with open web access for research (open level)", research},
	}
}

// templateAliases keeps older template names working.
var templateAliases = map[string]string{
	"claude-secure": "claude-strict",
	"codex-dev":     "codex",
}

// GetTemplate finds a template by name or alias.
func GetTemplate(name string) (Template, bool) {
	if alias, ok := templateAliases[name]; ok {
		name = alias
	}
	for _, t := range BuiltinTemplates() {
		if t.Name == name {
			return t, true
		}
	}
	return Template{}, false
}
