// Package agents describes the coding agents (harnesses) Rig can install.
package agents

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// MCP configuration formats Rig knows how to write.
const (
	MCPNone     = ""
	MCPClaude   = "claude"   // ~/.claude.json "mcpServers"
	MCPCodex    = "codex"    // ~/.codex/config.toml [mcp_servers.*]
	MCPGemini   = "gemini"   // ~/.gemini/settings.json "mcpServers"
	MCPQwen     = "qwen"     // ~/.qwen/settings.json "mcpServers" (Gemini format)
	MCPOpenCode = "opencode" // ~/.config/opencode/opencode.json "mcp"
	MCPCrush    = "crush"    // ~/.config/crush/crush.json "mcp"
)

// AgentSpec describes how to install and run one agent.
type AgentSpec struct {
	ID          string
	DisplayName string
	Description string

	// RequiresNode is the Node.js major version the agent needs, if any.
	RequiresNode string
	// SystemPackages are apt packages the agent needs.
	SystemPackages []string
	// InstallSteps are RUN steps executed as root during the image build.
	InstallSteps []string
	// Install, when set, produces install steps for a pinned version.
	// version is already validated; "" means the default.
	Install func(version string) []string
	// DependsOn lists agents that must be installed too.
	DependsOn []string

	Command       string // the binary the user runs
	VerifyCommand string // run after a build to confirm the install

	// Domains are what the agent needs at run time to reach its own model
	// service. Rig allows them automatically unless network.agent_domains is
	// false. Agents that work with many providers list none here; their
	// domains come from the API keys configured (see ProviderDomains).
	Domains []string
	// EnvHints are environment variables the user usually sets.
	EnvHints []string
	// MCPFormat is the agent's MCP configuration format, if Rig can write it.
	MCPFormat string
	// LocalModels reports that the agent can use an OpenAI-compatible local
	// endpoint such as Ollama through a host port.
	LocalModels bool
	// QuietEnv turns off telemetry, error reporting, auto-update and other
	// traffic the agent does not need. Applied at standard level and above.
	QuietEnv map[string]string
	// PermissionArgs are the command-line flags that put the agent in each
	// permission mode Rig offers: "edit" (file edits without asking) and
	// "full" (no approval prompts). "ask" is the agent's own default. Rig
	// installs a wrapper that adds them when the profile asks for a mode.
	PermissionArgs map[string][]string
	// PermissionNote explains how the agent handles permissions when Rig
	// cannot change it (for example, an agent that never asks).
	PermissionNote string
	// Custom marks agents defined by the user in ~/.config/rig/agents.
	Custom bool
}

// PermissionSupport describes what a permission mode means for this agent.
func (a AgentSpec) PermissionSupport(mode string) string {
	if mode == "" || mode == "ask" {
		return "asks before acting (its default)"
	}
	if args, ok := a.PermissionArgs[mode]; ok {
		return "runs with " + strings.Join(args, " ")
	}
	if a.PermissionNote != "" {
		return a.PermissionNote
	}
	return "Rig cannot change its permissions; it keeps its own default"
}

// Steps returns the install steps for a version ("" for the default).
func (a AgentSpec) Steps(version string) []string {
	if a.Install != nil {
		return a.Install(version)
	}
	return a.InstallSteps
}

// Pinnable reports whether the agent accepts a version.
func (a AgentSpec) Pinnable() bool { return a.Install != nil }

var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// ValidVersion reports whether v is safe to use as a package version or git
// ref. It is interpolated into install commands.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// npm returns a versioned global npm install.
func npm(pkg string) func(string) []string {
	return func(version string) []string {
		spec := pkg
		if version != "" {
			spec += "@" + version
		}
		return []string{"npm install -g --no-fund --no-audit --loglevel=error '" + spec + "'"}
	}
}

// pip returns a versioned pip install.
func pip(pkg string) func(string) []string {
	return func(version string) []string {
		spec := pkg
		if version != "" {
			spec += "==" + version
		}
		return []string{"python3 -m pip install --no-cache-dir --break-system-packages '" + spec + "'"}
	}
}

var (
	customOnce sync.Once
	custom     []AgentSpec
	customErrs []error
)

// All returns the built-in agents followed by the user's custom ones.
func All() []AgentSpec {
	customOnce.Do(func() {
		custom, customErrs = LoadCustom(CustomDir())
	})
	out := append([]AgentSpec{}, builtins()...)
	return append(out, custom...)
}

// CustomErrors reports problems loading custom agent definitions.
func CustomErrors() []error {
	All()
	return customErrs
}

// ByID finds an agent.
func ByID(id string) (AgentSpec, bool) {
	for _, a := range All() {
		if a.ID == id {
			return a, true
		}
	}
	return AgentSpec{}, false
}

// Resolve expands a list of agent IDs with their dependencies, dependencies
// first, without duplicates.
func Resolve(ids []string) ([]AgentSpec, error) {
	var out []AgentSpec
	seen := map[string]bool{}
	var visit func(id string, depth int) error
	visit = func(id string, depth int) error {
		if seen[id] {
			return nil
		}
		if depth > 8 {
			return fmt.Errorf("agent dependency cycle at %q", id)
		}
		spec, ok := ByID(id)
		if !ok {
			return fmt.Errorf("unknown agent %q", id)
		}
		for _, d := range spec.DependsOn {
			if err := visit(d, depth+1); err != nil {
				return err
			}
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, spec)
		}
		return nil
	}
	for _, id := range ids {
		if err := visit(id, 0); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MaxNodeVersion returns the highest Node.js major version required.
func MaxNodeVersion(specs []AgentSpec) string {
	max := 0
	for _, s := range specs {
		var v int
		if _, err := fmt.Sscanf(s.RequiresNode, "%d", &v); err == nil && v > max {
			max = v
		}
	}
	if max == 0 {
		return ""
	}
	return fmt.Sprintf("%d", max)
}

// IDs lists every known agent ID, sorted.
func IDs() []string {
	var ids []string
	for _, a := range All() {
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)
	return ids
}

// Describe renders an agent's one-line summary for listings.
func (a AgentSpec) Describe() string {
	parts := []string{a.Description}
	if a.LocalModels {
		parts = append(parts, "local models")
	}
	if a.MCPFormat != "" {
		parts = append(parts, "MCP")
	}
	if a.Custom {
		parts = append(parts, "custom")
	}
	return strings.Join(parts, " · ")
}

// keyAgents maps an API key to the agent it most clearly belongs to, in the
// order Rig offers them.
var keyAgents = []struct{ env, agent string }{
	{"ANTHROPIC_API_KEY", "claude-code"},
	{"OPENAI_API_KEY", "codex"},
	{"GEMINI_API_KEY", "gemini-cli"},
	{"XAI_API_KEY", "grok-build"},
}

// FromEnv lists the agents whose API key is set, by getenv.
func FromEnv(getenv func(string) string) []string {
	var ids []string
	for _, k := range keyAgents {
		if getenv(k.env) != "" {
			ids = append(ids, k.agent)
		}
	}
	return ids
}
