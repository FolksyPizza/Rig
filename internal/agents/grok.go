package agents

var GrokBuild = AgentSpec{
	ID:          "grok-build",
	DisplayName: "Grok Build",
	Description: "xAI's build agent CLI",
	InstallSteps: []string{
		"curl -fsSL https://x.ai/cli/install.sh | bash",
	},
	VerifyCommand: "grok-build --version",
	RequiredDomains: []string{
		"api.x.ai",
		"x.ai",
	},
	EnvHints: []string{"XAI_API_KEY"},
}
