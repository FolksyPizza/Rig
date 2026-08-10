package agents

var HermesAgent = AgentSpec{
	ID:          "hermes",
	DisplayName: "Hermes Agent",
	Description: "Nous Research's AI agent with persistent memory",
	InstallSteps: []string{
		`bash -c 'SCRIPT=$(curl -fsSL https://hermes-agent.org/install.sh 2>/dev/null) && echo "$SCRIPT" | head -1 | grep -q "^#!" && echo "$SCRIPT" | bash || echo "Hermes Agent: install script not available, skipping"'`,
	},
	VerifyCommand: "hermes --version || true",
	RequiredDomains: []string{
		"hermes-agent.org",
		"github.com",
		"*.githubusercontent.com",
	},
}
