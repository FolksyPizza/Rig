package config

// Template is a ready-made starting point for a sandbox.
type Template struct {
	Name        string
	Description string
	Profile     Profile
}

func boolPtr(b bool) *bool { return &b }

var workspace = []VolumeMount{{Name: "workspace", Target: "/home/sandbox/workspace"}}

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

// BuiltinTemplates returns every template. Most leave the agent open: 'rig
// new' fills it in from --agent, a question, or the API keys it finds. The
// first is the default.
func BuiltinTemplates() []Template {
	standard := base(LevelStandard)
	standard.Network.Presets = []string{"github", "npm", "pypi"}

	strict := base(LevelStrict)
	strict.Network.Presets = []string{"github"}
	strict.Persistence = "ephemeral"

	lockdown := base(LevelLockdown)
	lockdown.Tools = []string{"git", "curl", "jq", "ripgrep", "fd-find"}
	lockdown.Persistence = "ephemeral"
	lockdown.Security.Isolation = IsolationAuto

	dev := base(LevelOpen)
	dev.Tools = append(dev.Tools, "neovim", "tmux", "build-essential", "unzip")
	dev.Network = NetworkConfig{Mode: "unrestricted"}
	dev.Security.Sudo = true
	dev.Security.AgentPermissions = PermissionsFull
	dev.Resources = ResourcesConfig{CPU: 4.0, Memory: 8192, PIDLimit: 1024}
	dev.Storage.Size = "20g"

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
		{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
		{ID: "codex", Env: map[string]string{"OPENAI_API_KEY": "${OPENAI_API_KEY}"}},
		{ID: "gemini-cli", Env: map[string]string{"GEMINI_API_KEY": "${GEMINI_API_KEY}"}},
	}
	multi.Network.Presets = []string{"github", "npm", "pypi"}
	multi.Resources = ResourcesConfig{CPU: 4.0, Memory: 16384, PIDLimit: 2048}
	multi.Storage.Size = "30g"

	airgapped := base(LevelStrict)
	airgapped.Network = NetworkConfig{Mode: "none"}

	minimal := base(LevelStandard)
	minimal.Tools = []string{"git", "curl", "jq"}
	minimal.Resources = ResourcesConfig{CPU: 1.0, Memory: 2048, PIDLimit: 256}
	minimal.Storage = StorageConfig{Size: "5g"}
	minimal.Persistence = "ephemeral"

	research := base(LevelOpen)
	research.Agents = []AgentConfig{{ID: "hermes"}}
	research.Network = NetworkConfig{Mode: "unrestricted", BlockExfil: boolPtr(true)}

	return []Template{
		{"standard", "Egress allowlist, exfiltration sites blocked (recommended)", standard},
		{"strict", "Read-only image, HTTPS only, no sudo, ephemeral", strict},
		{"lockdown", "Model API only, gVisor or VM required, ephemeral", lockdown},
		{"dev", "Open: unrestricted network, sudo, no approval prompts (trusted work only)", dev},
		{"airgapped", "No network at all", airgapped},
		{"minimal", "Small and ephemeral", minimal},
		{"blender", "Blender over MCP, its code-execution tool blocked", blender},
		{"local-model", "Qwen Code on your local Ollama, no internet at all", local},
		{"multi-agent", "Claude Code, Codex and Gemini CLI side by side", multi},
		{"hermes-research", "Hermes Agent with open web access for research (open level)", research},
	}
}

// templateAlias maps an older or agent-named template to a template and the
// agents it implies.
type templateAlias struct {
	template string
	agents   []string
}

var templateAliases = map[string]templateAlias{
	"claude-strict": {"strict", []string{"claude-code"}},
	"claude-secure": {"strict", []string{"claude-code"}},
	"claude-dev":    {"dev", []string{"claude-code"}},
	"codex":         {"standard", []string{"codex"}},
	"codex-dev":     {"standard", []string{"codex"}},
	"gemini":        {"standard", []string{"gemini-cli"}},
	"pi":            {"standard", []string{"pi"}},
	"opencode":      {"standard", []string{"opencode"}},
	"qwen-code":     {"standard", []string{"qwen-code"}},
	"grove":         {"standard", []string{"grove"}},
}

// GetTemplate finds a template by name or alias. For an agent-named alias
// (codex, gemini, claude-strict, ...) the returned template's profile names
// that agent.
func GetTemplate(name string) (Template, bool) {
	var implied []string
	if alias, ok := templateAliases[name]; ok {
		name, implied = alias.template, alias.agents
	}
	for _, t := range BuiltinTemplates() {
		if t.Name == name {
			for _, id := range implied {
				t.Profile.Agents = append(t.Profile.Agents, AgentConfig{ID: id})
			}
			return t, true
		}
	}
	return Template{}, false
}

// NeedsAgent reports whether the template leaves the agent to choose.
func (t Template) NeedsAgent() bool { return len(t.Profile.Agents) == 0 }
