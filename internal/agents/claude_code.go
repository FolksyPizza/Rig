package agents

var ClaudeCode = AgentSpec{
	ID:           "claude-code",
	DisplayName:  "Claude Code",
	Description:  "Anthropic's AI coding agent",
	RequiresNode: "20",
	InstallSteps: []string{
		"npm install -g @anthropic-ai/claude-code",
	},
	VerifyCommand: "claude --version",
	RequiredDomains: []string{
		"api.anthropic.com",
		"statsig.anthropic.com",
		"sentry.io",
		"registry.npmjs.org",
	},
	EnvHints: []string{"ANTHROPIC_API_KEY"},
}
