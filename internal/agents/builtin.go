package agents

// GroveRepo is where the Grove harness is built from.
const GroveRepo = "https://github.com/FolksyPizza/grove.git"

// claudeQuiet stops Claude Code's telemetry, error reporting, auto-updater
// and other traffic it does not need to do its job. It also turns off two
// features that would reach past Rig: claude.ai connectors (MCP servers
// configured on your claude.ai account, such as mail or drive access, which
// bypass Rig's MCP guard) and the Artifact tool, which publishes pages to
// claude.ai.
var claudeQuiet = map[string]string{
	"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
	"DISABLE_TELEMETRY":                        "1",
	"DISABLE_ERROR_REPORTING":                  "1",
	"DISABLE_AUTOUPDATER":                      "1",
	"ENABLE_CLAUDEAI_MCP_SERVERS":              "false",
	"CLAUDE_CODE_DISABLE_ARTIFACT":             "1",
}

func builtins() []AgentSpec {
	return []AgentSpec{
		{
			ID:            "claude-code",
			DisplayName:   "Claude Code",
			Description:   "Anthropic's coding agent",
			RequiresNode:  "22",
			Install:       npm("@anthropic-ai/claude-code"),
			Command:       "claude",
			VerifyCommand: "claude --version",
			// platform.claude.com and claude.ai carry sign-in with a Claude
			// subscription or Console account (token exchange and refresh).
			Domains:   []string{"api.anthropic.com", "platform.claude.com", "claude.ai"},
			EnvHints:  []string{"ANTHROPIC_API_KEY"},
			MCPFormat: MCPClaude,
			QuietEnv:  claudeQuiet,
			PermissionArgs: map[string][]string{
				"edit": {"--permission-mode", "acceptEdits"},
				"full": {"--permission-mode", "bypassPermissions"},
			},
		},
		{
			ID:            "codex",
			DisplayName:   "Codex",
			Description:   "OpenAI's coding agent CLI",
			RequiresNode:  "22",
			Install:       npm("@openai/codex"),
			Command:       "codex",
			VerifyCommand: "codex --version",
			// chatgpt.com and auth.openai.com carry ChatGPT sign-in, Codex's
			// default way to authenticate.
			Domains:     []string{"api.openai.com", "chatgpt.com", "auth.openai.com"},
			EnvHints:    []string{"OPENAI_API_KEY"},
			MCPFormat:   MCPCodex,
			LocalModels: true,
			// Codex's own command sandbox (Landlock) does not work under
			// gVisor or in most containers; Rig's sandbox is the boundary.
			PermissionArgs: map[string][]string{
				"edit": {"--ask-for-approval", "untrusted", "--sandbox", "danger-full-access"},
				"full": {"--dangerously-bypass-approvals-and-sandbox"},
			},
		},
		{
			ID:            "gemini-cli",
			DisplayName:   "Gemini CLI",
			Description:   "Google's Gemini CLI agent",
			RequiresNode:  "22",
			Install:       npm("@google/gemini-cli"),
			Command:       "gemini",
			VerifyCommand: "gemini --version",
			Domains:       []string{"generativelanguage.googleapis.com"},
			EnvHints:      []string{"GEMINI_API_KEY"},
			MCPFormat:     MCPGemini,
			PermissionArgs: map[string][]string{
				"edit": {"--approval-mode", "auto_edit"},
				"full": {"--yolo"},
			},
		},
		{
			ID:             "pi",
			DisplayName:    "Pi",
			Description:    "Minimal coding agent (pi-mono) for many providers",
			RequiresNode:   "22",
			Install:        npm("@mariozechner/pi-coding-agent"),
			Command:        "pi",
			VerifyCommand:  "pi --version",
			EnvHints:       []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"},
			LocalModels:    true,
			PermissionNote: "never asks for approval; it always acts directly",
		},
		{
			ID:            "opencode",
			DisplayName:   "OpenCode",
			Description:   "Open-source terminal coding agent for many providers",
			RequiresNode:  "22",
			Install:       npm("opencode-ai"),
			Command:       "opencode",
			VerifyCommand: "opencode --version",
			// models.dev serves OpenCode's model catalog (read-only JSON).
			Domains:        []string{"models.dev"},
			EnvHints:       []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
			MCPFormat:      MCPOpenCode,
			LocalModels:    true,
			QuietEnv:       map[string]string{"OPENCODE_DISABLE_AUTOUPDATE": "1"},
			PermissionNote: "set through its config file (opencode.json permission)",
		},
		{
			ID:            "qwen-code",
			DisplayName:   "Qwen Code",
			Description:   "Qwen's coding agent (OpenAI-compatible endpoints)",
			RequiresNode:  "22",
			Install:       npm("@qwen-code/qwen-code"),
			Command:       "qwen",
			VerifyCommand: "qwen --version",
			EnvHints:      []string{"OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"},
			MCPFormat:     MCPQwen,
			LocalModels:   true,
			PermissionArgs: map[string][]string{
				"edit": {"--approval-mode", "auto-edit"},
				"full": {"--yolo"},
			},
		},
		{
			ID:             "crush",
			DisplayName:    "Crush",
			Description:    "Charm's terminal coding agent for many providers",
			RequiresNode:   "22",
			Install:        npm("@charmland/crush"),
			Command:        "crush",
			VerifyCommand:  "crush --version",
			EnvHints:       []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
			MCPFormat:      MCPCrush,
			LocalModels:    true,
			PermissionArgs: map[string][]string{"full": {"--yolo"}},
			PermissionNote: "has no edit-only mode; it asks until you choose full",
		},
		{
			ID:             "aider",
			DisplayName:    "Aider",
			Description:    "AI pair programming in the terminal, many providers",
			SystemPackages: []string{"python3", "python3-pip", "python3-venv"},
			Install:        pip("aider-chat"),
			Command:        "aider",
			VerifyCommand:  "aider --version",
			EnvHints:       []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"},
			LocalModels:    true,
			QuietEnv:       map[string]string{"AIDER_ANALYTICS": "false", "AIDER_CHECK_UPDATE": "false"},
			PermissionArgs: map[string][]string{"full": {"--yes-always"}},
			PermissionNote: "applies edits without asking already; full also answers yes to its other questions",
		},
		{
			ID:            "copilot",
			DisplayName:   "GitHub Copilot CLI",
			Description:   "GitHub's Copilot coding agent CLI",
			RequiresNode:  "22",
			Install:       npm("@github/copilot"),
			Command:       "copilot",
			VerifyCommand: "copilot --version",
			Domains:       []string{"api.githubcopilot.com", "*.githubcopilot.com", "api.github.com", "github.com"},
			EnvHints:      []string{"GH_TOKEN"},
			PermissionArgs: map[string][]string{
				"edit": {"--allow-tool", "write"},
				"full": {"--allow-all-tools"},
			},
		},
		{
			ID:           "grove",
			DisplayName:  "Grove",
			Description:  "Engineering-focused harness and interface on top of Codex",
			RequiresNode: "22",
			DependsOn:    []string{"codex"},
			Install: func(ref string) []string {
				if ref == "" {
					ref = "main"
				}
				return []string{
					"git clone --depth 1 --branch '" + ref + "' " + GroveRepo + " /opt/grove",
					"cd /opt/grove/ui && npm ci --no-audit --no-fund --loglevel=error && node scripts/build.mjs && rm -rf node_modules",
					`printf '#!/bin/sh\nexec node /opt/grove/ui/dist/grove.mjs "$@"\n' > /usr/local/bin/grove && chmod 0755 /usr/local/bin/grove`,
				}
			},
			Command:       "grove",
			VerifyCommand: "grove --version",
			EnvHints:      []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"},
			MCPFormat:     MCPCodex,
			LocalModels:   true,
		},
		{
			ID:          "grok-build",
			DisplayName: "Grok Build",
			Description: "xAI's build agent CLI",
			InstallSteps: []string{
				"curl -fsSL https://x.ai/cli/install.sh | bash",
			},
			Command:       "grok-build",
			VerifyCommand: "grok-build --version",
			Domains:       []string{"api.x.ai"},
			EnvHints:      []string{"XAI_API_KEY"},
		},
		{
			ID:             "openclaw",
			DisplayName:    "OpenClaw",
			Description:    "Open-source personal AI assistant",
			RequiresNode:   "22",
			SystemPackages: []string{"python3", "python3-pip", "python3-venv"},
			InstallSteps: []string{
				"git clone --depth 1 https://github.com/openclaw/openclaw.git /opt/openclaw",
				"bash -c 'cd /opt/openclaw && (corepack enable && corepack pnpm install && pnpm run build || npm install --ignore-engines && npm run build) && ln -s /opt/openclaw/bin/openclaw /usr/local/bin/openclaw || echo \"OpenClaw: build failed, skipping\"'",
			},
			Command:       "openclaw",
			VerifyCommand: "openclaw --version",
		},
		{
			ID:          "hermes",
			DisplayName: "Hermes Agent",
			Description: "Nous Research's agent with persistent memory",
			InstallSteps: []string{
				`bash -c 'SCRIPT=$(curl -fsSL https://hermes-agent.org/install.sh 2>/dev/null) && echo "$SCRIPT" | head -1 | grep -q "^#!" && echo "$SCRIPT" | bash || echo "Hermes Agent: install script not available, skipping"'`,
			},
			Command:       "hermes",
			VerifyCommand: "hermes --version",
		},
	}
}
