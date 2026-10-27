// Package policy explains a profile's effective security in plain language,
// for `rig check`.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/egress"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	return [...]string{"info", "low", "medium", "high"}[s]
}

// ParseSeverity reads a severity name.
func ParseSeverity(s string) (Severity, bool) {
	for i, n := range []string{"info", "low", "medium", "high"} {
		if n == s {
			return Severity(i), true
		}
	}
	return Info, false
}

// Finding is one thing worth knowing about a profile.
type Finding struct {
	Severity Severity
	Area     string // network, filesystem, privileges, isolation, monitoring, mcp, git, host
	Message  string
}

// broadWildcards are domains where anyone can publish a site, so allowing all
// of their subdomains lets an agent send data to a server someone else runs.
var broadWildcards = []string{
	"amazonaws.com", "googleapis.com", "cloudfront.net", "azurewebsites.net", "windows.net",
	"github.io", "herokuapp.com", "vercel.app", "netlify.app", "workers.dev", "pages.dev",
	"firebaseapp.com", "web.app", "appspot.com", "fly.dev", "onrender.com", "replit.dev",
	"glitch.me", "repl.co", "ngrok.io", "railway.app", "deno.dev", "supabase.co",
}

// tokenVars are credentials that, handed straight to the agent, work against
// far more than one repository or account.
var tokenVars = []string{"GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "NPM_TOKEN", "HF_TOKEN", "DOCKER_PASSWORD"}

// Check explains a profile. Findings are sorted most severe first.
func Check(p *config.Profile) []Finding {
	eff := p.Resolve()
	var fs []Finding
	add := func(sev Severity, area, format string, args ...any) {
		fs = append(fs, Finding{sev, area, fmt.Sprintf(format, args...)})
	}

	if p.Security.Level == "" {
		add(Low, "level", "No security level is set; it is treated as %s. Set security.level so it is explicit.", eff.Level)
	}
	if eff.Level == config.LevelOpen {
		add(High, "level", "Level open: the least restrictive setting. Use it only for work you would trust to run on your own machine.")
	}

	// Network.
	switch eff.NetworkMode {
	case "unrestricted":
		add(High, "network", "The agent can reach any address on the internet and send it anything. This is the gap Cohere's report showed; use an allowlist.")
	case "none":
		add(Info, "network", "No network access at all.")
	case "allowlist":
		if len(eff.Allowed) == 0 {
			add(Info, "network", "Allowlist is empty: no internet access (host ports, if any, still work).")
		} else {
			add(Info, "network", "The agent can reach %d domains: %s.", len(eff.Allowed), summarizeList(eff.Allowed, 8))
		}
		for _, d := range eff.Allowed {
			base := strings.TrimPrefix(d, "*.")
			if !strings.HasPrefix(d, "*.") {
				continue
			}
			for _, w := range broadWildcards {
				if base == w || strings.HasSuffix(base, "."+w) {
					add(Medium, "network", "%s covers sites anyone can create, so data could be sent to a server someone else runs. List the exact hosts instead.", d)
				}
			}
		}
		for _, d := range eff.Allowed {
			if cat, ok := egress.RiskCategory(strings.TrimPrefix(d, "*.")); ok {
				add(Low, "network", "%s is a known %s service; it stays blocked unless listed under network.allow_risky.", d, cat)
			}
		}
		if !eff.HTTPSOnly {
			add(Low, "network", "Plain HTTP is allowed to listed domains; its traffic can be read or altered on the way. Set network.https_only.")
		}
	}
	if !eff.BlockRisky {
		add(High, "network", "Known upload, paste, tunnel and IP-lookup services are not blocked (network.block_exfil is off).")
	}
	for _, h := range eff.AllowRisky {
		add(Medium, "network", "%s is exempt from exfiltration blocking (network.allow_risky).", h)
	}

	// Privileges and filesystem.
	if eff.Sudo {
		add(Medium, "privileges", "The agent has passwordless sudo: it can act as root inside the sandbox and install anything the network allows.")
	}
	if eff.ReadOnlyRoot {
		add(Info, "filesystem", "The image is read-only; scratch space and home are separate, and /tmp is %s.", map[bool]string{true: "noexec", false: "executable"}[eff.NoExecTmp])
	}
	for _, m := range p.Mounts {
		if m.ReadOnly {
			add(Low, "filesystem", "The agent can read %s (mounted at %s).", m.Source, m.Target)
			continue
		}
		add(Medium, "filesystem", "The agent can change files in %s on your computer (mounted at %s).", m.Source, m.Target)
		protected := map[string]bool{}
		for _, s := range append(append([]string{}, m.Protect...), eff.ProtectPaths...) {
			protected[s] = true
		}
		if !protected[".git/hooks"] {
			add(Low, "filesystem", "In %s, .git/hooks is writable; hooks run on your computer the next time you use git there. Add it to protect.", m.Source)
		}
		if len(m.Hide) == 0 {
			add(Info, "filesystem", "Nothing in %s is hidden; list secrets such as .env under hide.", m.Source)
		}
	}

	// Isolation.
	switch eff.Isolation {
	case config.IsolationContainer:
		sev := Low
		if eff.PreferStrongIsolation {
			sev = Medium
		}
		add(sev, "isolation", "Plain container isolation shares your kernel; a kernel bug could let code escape. gVisor or a VM runtime closes that ('rig doctor').")
	case config.IsolationAuto:
		if eff.RequireStrongIsolation {
			add(Info, "isolation", "Requires gVisor or a VM runtime and will not start without one.")
		} else {
			add(Info, "isolation", "Uses gVisor or a VM runtime when one is installed, otherwise a hardened container.")
		}
	default:
		add(Info, "isolation", "Runs under %s isolation.", eff.Isolation)
	}

	// Monitoring.
	switch eff.MonitorMode {
	case "off":
		add(Medium, "monitoring", "Monitoring is off: nothing is recorded and nothing is stopped.")
	case "observe":
		add(Low, "monitoring", "Monitoring only records and alerts; it never stops the sandbox.")
	default:
		add(Info, "monitoring", "Monitoring stops the sandbox on %s-strictness violations; everything is recorded in 'rig audit'.", eff.Strictness)
	}
	ai := p.Monitor.AI
	switch {
	case ai.Provider == "":
		add(Info, "monitoring", "No AI monitor. Add monitor.ai to have a second model review activity.")
	case ai.Provider == "ollama":
		add(Info, "monitoring", "AI monitor runs on your local model; events stay on your machine.")
	default:
		add(Info, "monitoring", "AI monitor sends redacted activity to %s for review. Use provider ollama to keep it local.", ai.Provider)
	}

	// Credentials.
	for _, a := range p.Agents {
		for k := range a.Env {
			for _, t := range tokenVars {
				if k == t {
					add(Medium, "credentials", "%s is given to the agent directly; it works against everything that token can reach. For GitHub, use git.repos so the token stays outside the sandbox.", k)
				}
			}
		}
	}

	// MCP.
	for _, s := range p.MCP.Servers {
		switch {
		case s.URL != "":
			add(Medium, "mcp", "MCP server %s is remote (%s): its tool calls are not checked by Rig.", s.Name, s.URL)
		case !s.InGateway():
			add(Low, "mcp", "MCP server %s runs inside the sandbox, so the agent could run it directly and bypass its tool policy. Use run_in: gateway for servers that matter.", s.Name)
			for _, v := range s.Env {
				if strings.HasPrefix(v, "${") {
					add(Low, "mcp", "MCP server %s gets a secret inside the sandbox, where the agent can read it. Gateway servers keep secrets outside.", s.Name)
					break
				}
			}
		default:
			add(Info, "mcp", "MCP server %s runs in the gateway; the agent reaches it only through Rig's tool-call guard.", s.Name)
		}
		if len(s.AllowTools) == 0 && len(s.DenyTools) == 0 {
			add(Low, "mcp", "MCP server %s exposes every tool it has; add allow_tools or deny_tools.", s.Name)
		}
		if strings.Contains(strings.ToLower(s.Name+" "+strings.Join(s.Command, " ")), "blender") && !denies(s, "execute_blender_code") {
			add(High, "mcp", "MCP server %s can call execute_blender_code, which runs any Python inside Blender on your computer, outside the sandbox. Add it to deny_tools.", s.Name)
		}
	}

	// Host access.
	for _, h := range p.Host.Ports {
		add(Medium, "host", "The agent can reach %s on your computer (port %d) through the gateway.", h.Name, h.Target())
	}
	for _, s := range p.MCP.Servers {
		for _, port := range s.HostPorts {
			add(Low, "host", "MCP server %s can reach port %d on your computer; the agent cannot reach it directly.", s.Name, port)
		}
	}

	// Git.
	for _, r := range p.Git.Repos {
		if r.AccessLevel() == "write" {
			if len(r.Branches) == 0 {
				add(Medium, "git", "The agent can push to any branch of %s. Add branch patterns.", r.Repo)
			} else {
				add(Info, "git", "The agent can push to %s on branches %s, without seeing the token.", r.Repo, strings.Join(r.Branches, ", "))
			}
		} else {
			add(Info, "git", "The agent can read %s through the broker.", r.Repo)
		}
	}
	if len(p.Git.Repos) > 0 && p.Git.TokenEnv == "" {
		add(Info, "git", "git.token_env is not set: only public repositories will work through the broker.")
	}

	if eff.Ephemeral {
		add(Info, "lifecycle", "Ephemeral: each run starts clean and the container is removed on exit.")
	}

	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
	return fs
}

func denies(s config.MCPServer, tool string) bool {
	for _, d := range s.DenyTools {
		if d == tool || d == "*" || (strings.HasSuffix(d, "*") && strings.HasPrefix(tool, strings.TrimSuffix(d, "*"))) {
			return true
		}
	}
	if len(s.AllowTools) > 0 {
		for _, a := range s.AllowTools {
			if a == tool || a == "*" {
				return false
			}
		}
		return true // not in the allow list
	}
	return false
}

func summarizeList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
}

// Worst returns the most severe finding's severity.
func Worst(fs []Finding) Severity {
	worst := Info
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}
