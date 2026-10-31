package container

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/mcpguard"
)

// GatewayHost is the gateway's name on the sandbox network.
const GatewayHost = "rig-gw"

// mcpPlan is the MCP and harness configuration generated for an image.
type mcpPlan struct {
	homeFiles   map[string][]byte // relative to the sandbox user's home
	etcFiles    map[string][]byte // relative to /etc/rig
	claudeMCP   []byte            // merged into ~/.claude.json at start
	sandboxEnv  map[string]string // runtime variables (values may be ${HOSTVAR})
	needsHelper bool              // rig-helper must be in the image
}

type mcpEntry struct {
	name    string
	stdio   bool
	command string
	args    []string
	url     string
	headers map[string]string // values literal or "${VAR}"
}

var envRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// envRefs lists the variables referenced as ${NAME} anywhere in v.
func envRefs(v string) []string {
	var names []string
	for _, m := range envRefRe.FindAllStringSubmatch(v, -1) {
		names = append(names, m[1])
	}
	return names
}

// rewriteEnvRefs replaces each ${NAME} in v using f.
func rewriteEnvRefs(v string, f func(name string) string) string {
	return envRefRe.ReplaceAllStringFunc(v, func(m string) string {
		return f(envRefRe.FindStringSubmatch(m)[1])
	})
}

// envRef returns the variable name in a "${NAME}" value.
func envRef(v string) (string, bool) {
	name, ok := strings.CutPrefix(v, "${")
	if !ok {
		return "", false
	}
	name, ok = strings.CutSuffix(name, "}")
	return name, ok && name != ""
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// planMCP builds MCP client configuration for every agent in the profile.
func planMCP(p *config.Profile, eff config.Effective, specs []agents.AgentSpec) (mcpPlan, error) {
	plan := mcpPlan{
		homeFiles:  map[string][]byte{},
		etcFiles:   map[string][]byte{},
		sandboxEnv: map[string]string{},
	}

	var entries []mcpEntry
	for i, s := range p.MCP.Servers {
		switch {
		case s.URL != "":
			e := mcpEntry{name: s.Name, url: s.URL, headers: map[string]string{}}
			for k, v := range s.Headers {
				e.headers[k] = v
				for _, name := range envRefs(v) {
					plan.sandboxEnv[name] = "${" + name + "}"
				}
			}
			entries = append(entries, e)
		case s.InGateway():
			entries = append(entries, mcpEntry{name: s.Name, url: fmt.Sprintf("http://%s:%d/mcp/%s", GatewayHost, config.GatewayPort, s.Name)})
		default:
			plan.needsHelper = true
			pol := mcpguard.Policy{
				Server:  s.Name,
				Allow:   s.AllowTools,
				Deny:    s.DenyTools,
				LogArgs: s.LogArgs == nil || *s.LogArgs,
				Env:     map[string]string{},
			}
			for k, v := range s.Env {
				if _, ok := envRef(v); ok {
					plan.sandboxEnv[mcpEnvName(i, k)] = v
				} else {
					pol.Env[k] = v
				}
			}
			polJSON, err := json.MarshalIndent(pol, "", "  ")
			if err != nil {
				return plan, err
			}
			plan.etcFiles["mcp/"+s.Name+".json"] = append(polJSON, '\n')
			args := []string{
				"mcp-guard",
				"--policy", "/etc/rig/mcp/" + s.Name + ".json",
				"--env-file", fmt.Sprintf("%s/.rig/mcp-env/%d.env", sandboxHome, i),
				"--",
			}
			args = append(args, s.Command...)
			entries = append(entries, mcpEntry{name: s.Name, stdio: true, command: "rig-helper", args: args})
		}
	}

	formats := map[string]bool{}
	for _, a := range specs {
		if a.MCPFormat != "" {
			formats[a.MCPFormat] = true
		}
	}

	if len(entries) > 0 {
		claude := claudeServers(entries)
		neutral, err := json.MarshalIndent(map[string]any{"mcpServers": claude}, "", "  ")
		if err != nil {
			return plan, err
		}
		plan.etcFiles["mcp.json"] = append(neutral, '\n')
		if formats[agents.MCPClaude] {
			plan.claudeMCP = plan.etcFiles["mcp.json"]
		}
	}

	geminiLike := func(dir string) error {
		settings := map[string]any{}
		if len(entries) > 0 {
			settings["mcpServers"] = geminiServers(entries)
		}
		if eff.QuietAgents {
			settings["privacy"] = map[string]any{"usageStatisticsEnabled": false}
			settings["telemetry"] = map[string]any{"enabled": false}
		}
		if len(settings) == 0 {
			return nil
		}
		b, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return err
		}
		plan.homeFiles[dir+"/settings.json"] = append(b, '\n')
		return nil
	}
	if formats[agents.MCPGemini] {
		if err := geminiLike(".gemini"); err != nil {
			return plan, err
		}
	}
	if formats[agents.MCPQwen] {
		if err := geminiLike(".qwen"); err != nil {
			return plan, err
		}
	}
	if formats[agents.MCPCodex] && len(entries) > 0 {
		plan.homeFiles[".codex/config.toml"] = []byte(codexTOML(entries))
	}
	if formats[agents.MCPOpenCode] {
		cfg := map[string]any{"$schema": "https://opencode.ai/config.json"}
		if eff.QuietAgents {
			cfg["autoupdate"] = false
		}
		if len(entries) > 0 {
			cfg["mcp"] = openCodeServers(entries)
		}
		switch eff.AgentPermissions {
		case config.PermissionsEdit:
			cfg["permission"] = map[string]string{"edit": "allow", "bash": "ask", "webfetch": "ask"}
		case config.PermissionsFull:
			cfg["permission"] = map[string]string{"edit": "allow", "bash": "allow", "webfetch": "allow"}
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return plan, err
		}
		plan.homeFiles[".config/opencode/opencode.json"] = append(b, '\n')
	}
	if formats[agents.MCPCrush] && len(entries) > 0 {
		b, err := json.MarshalIndent(map[string]any{
			"$schema": "https://charm.land/crush.json",
			"mcp":     crushServers(entries),
		}, "", "  ")
		if err != nil {
			return plan, err
		}
		plan.homeFiles[".config/crush/crush.json"] = append(b, '\n')
	}

	if eff.HarnessLockdown {
		addHarnessPolicies(plan.etcFiles, specs)
	}
	return plan, nil
}

func claudeServers(entries []mcpEntry) map[string]any {
	out := map[string]any{}
	for _, e := range entries {
		if e.stdio {
			out[e.name] = map[string]any{"type": "stdio", "command": e.command, "args": e.args}
			continue
		}
		srv := map[string]any{"type": "http", "url": e.url}
		if len(e.headers) > 0 {
			srv["headers"] = e.headers
		}
		out[e.name] = srv
	}
	return out
}

func geminiServers(entries []mcpEntry) map[string]any {
	out := map[string]any{}
	for _, e := range entries {
		if e.stdio {
			out[e.name] = map[string]any{"command": e.command, "args": e.args}
			continue
		}
		srv := map[string]any{"httpUrl": e.url}
		if len(e.headers) > 0 {
			srv["headers"] = e.headers
		}
		out[e.name] = srv
	}
	return out
}

func openCodeServers(entries []mcpEntry) map[string]any {
	out := map[string]any{}
	for _, e := range entries {
		if e.stdio {
			out[e.name] = map[string]any{"type": "local", "command": append([]string{e.command}, e.args...), "enabled": true}
			continue
		}
		srv := map[string]any{"type": "remote", "url": e.url, "enabled": true}
		if len(e.headers) > 0 {
			h := map[string]string{}
			for k, v := range e.headers {
				h[k] = rewriteEnvRefs(v, func(name string) string { return "{env:" + name + "}" })
			}
			srv["headers"] = h
		}
		out[e.name] = srv
	}
	return out
}

func crushServers(entries []mcpEntry) map[string]any {
	out := map[string]any{}
	for _, e := range entries {
		if e.stdio {
			out[e.name] = map[string]any{"type": "stdio", "command": e.command, "args": e.args}
			continue
		}
		srv := map[string]any{"type": "http", "url": e.url}
		if len(e.headers) > 0 {
			h := map[string]string{}
			for k, v := range e.headers {
				h[k] = rewriteEnvRefs(v, func(name string) string { return "$" + name })
			}
			srv["headers"] = h
		}
		out[e.name] = srv
	}
	return out
}

// codexTOML writes Codex's [mcp_servers] tables.
func codexTOML(entries []mcpEntry) string {
	var sb strings.Builder
	sb.WriteString("# Generated by Rig from the sandbox profile; rebuilt with the image.\n")
	for _, e := range entries {
		fmt.Fprintf(&sb, "\n[mcp_servers.%s]\n", e.name)
		if e.stdio {
			fmt.Fprintf(&sb, "command = %s\n", tomlString(e.command))
			quoted := make([]string, len(e.args))
			for i, a := range e.args {
				quoted[i] = tomlString(a)
			}
			fmt.Fprintf(&sb, "args = [%s]\n", strings.Join(quoted, ", "))
			continue
		}
		fmt.Fprintf(&sb, "url = %s\n", tomlString(e.url))
		literal, fromEnv := map[string]string{}, map[string]string{}
		for _, k := range sortedMapKeys(e.headers) {
			v := e.headers[k]
			if strings.EqualFold(k, "Authorization") {
				if name, ok := envRef(strings.TrimPrefix(v, "Bearer ")); ok && strings.HasPrefix(v, "Bearer ") {
					fmt.Fprintf(&sb, "bearer_token_env_var = %s\n", tomlString(name))
					continue
				}
			}
			switch name, ok := envRef(v); {
			case ok:
				fromEnv[k] = name
			case len(envRefs(v)) == 0:
				literal[k] = v
			default:
				// Codex can take a whole header from a variable, but not
				// splice one into a longer value; this header is left out.
				fmt.Fprintf(&sb, "# header %s omitted: Codex cannot build it from %v\n", k, envRefs(v))
			}
		}
		if len(literal) > 0 {
			fmt.Fprintf(&sb, "http_headers = %s\n", tomlInlineTable(literal))
		}
		if len(fromEnv) > 0 {
			fmt.Fprintf(&sb, "env_http_headers = %s\n", tomlInlineTable(fromEnv))
		}
	}
	return sb.String()
}

func tomlInlineTable(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, k := range sortedMapKeys(m) {
		parts = append(parts, tomlString(k)+" = "+tomlString(m[k]))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&sb, `\u%04X`, r)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// addHarnessPolicies writes the agent-level policies used at lockdown: the
// agents' own web tools are turned off (they reach untrusted content, and
// web search runs on the provider's side where the proxy cannot see it), and
// Claude Code's bypass-permissions mode is disabled. They are installed under
// /etc, read-only to the agent, which cannot override managed settings.
func addHarnessPolicies(etc map[string][]byte, specs []agents.AgentSpec) {
	has := map[string]bool{}
	for _, a := range specs {
		has[a.ID] = true
	}
	if has["claude-code"] {
		b, _ := json.MarshalIndent(map[string]any{
			"permissions": map[string]any{
				"deny":                         []string{"WebFetch", "WebSearch"},
				"disableBypassPermissionsMode": "disable",
			},
		}, "", "  ")
		etc["policy/claude-managed-settings.json"] = append(b, '\n')
	}
	if has["gemini-cli"] || has["qwen-code"] {
		b, _ := json.MarshalIndent(map[string]any{
			"tools": map[string]any{"exclude": []string{"web_fetch", "google_web_search"}},
		}, "", "  ")
		etc["policy/gemini-system-settings.json"] = append(b, '\n')
	}
}
