package agents

var Codex = AgentSpec{
	ID:          "codex",
	DisplayName: "Codex",
	Description: "OpenAI's coding agent CLI",
	InstallSteps: []string{
		"curl -fsSL https://chatgpt.com/codex/install.sh | sh",
	},
	VerifyCommand: "codex --version",
	RequiredDomains: []string{
		"api.openai.com",
		"chatgpt.com",
	},
	EnvHints: []string{"OPENAI_API_KEY"},
}
