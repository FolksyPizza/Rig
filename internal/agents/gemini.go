package agents

var GeminiCLI = AgentSpec{
	ID:           "gemini-cli",
	DisplayName:  "Gemini CLI",
	Description:  "Google's Gemini CLI agent",
	RequiresNode: "20",
	InstallSteps: []string{
		"npm install -g @google/gemini-cli",
	},
	VerifyCommand: "gemini --version",
	RequiredDomains: []string{
		"generativelanguage.googleapis.com",
		"registry.npmjs.org",
	},
	EnvHints: []string{"GEMINI_API_KEY"},
}
