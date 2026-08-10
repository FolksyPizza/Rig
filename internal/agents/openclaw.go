package agents

var OpenClaw = AgentSpec{
	ID:             "openclaw",
	DisplayName:    "OpenClaw",
	Description:    "Open-source personal AI assistant",
	RequiresNode:   "22",
	SystemPackages: []string{"python3", "python3-pip", "python3-venv"},
	InstallSteps: []string{
		"git clone --depth 1 https://github.com/openclaw/openclaw.git /opt/openclaw",
		"bash -c 'cd /opt/openclaw && (corepack enable && corepack pnpm install && pnpm run build || npm install --ignore-engines && npm run build) && ln -s /opt/openclaw/bin/openclaw /usr/local/bin/openclaw || echo \"OpenClaw: build failed, skipping\"'",
	},
	VerifyCommand: "openclaw --version || true",
	RequiredDomains: []string{
		"github.com",
		"*.githubusercontent.com",
		"registry.npmjs.org",
	},
}
