package config

import (
	"reflect"
	"strings"
	"testing"
)

func profileAt(level string) Profile {
	p := validProfile()
	p.Security.Level = level
	p.Network = NetworkConfig{Mode: "allowlist"}
	return p
}

func TestLegacyProfilesInferALevel(t *testing.T) {
	p := validProfile() // no level, unrestricted network
	if got := p.EffectiveLevel(); got != LevelOpen {
		t.Errorf("legacy unrestricted profile level = %s, want open", got)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("existing profiles must keep loading: %v", err)
	}
	p.Network.Mode = "allowlist"
	if got := p.EffectiveLevel(); got != LevelStandard {
		t.Errorf("legacy allowlist profile level = %s, want standard", got)
	}
}

func TestLevelFloors(t *testing.T) {
	no := false
	tests := []struct {
		name   string
		level  string
		mutate func(*Profile)
		want   string // substring of the error; "" means valid
	}{
		{"standard rejects unrestricted", LevelStandard, func(p *Profile) { p.Network.Mode = "unrestricted" }, "unrestricted"},
		{"open allows unrestricted", LevelOpen, func(p *Profile) { p.Network.Mode = "unrestricted" }, ""},
		{"standard keeps exfil blocking", LevelStandard, func(p *Profile) { p.Network.BlockExfil = &no }, "block_exfil"},
		{"open may drop exfil blocking", LevelOpen, func(p *Profile) { p.Network.BlockExfil = &no }, ""},
		{"standard allows sudo", LevelStandard, func(p *Profile) { p.Security.Sudo = true }, ""},
		{"strict rejects sudo", LevelStrict, func(p *Profile) { p.Security.Sudo = true }, "sudo"},
		{"strict requires monitoring", LevelStrict, func(p *Profile) { p.Monitor.Mode = "off" }, "monitor"},
		{"lockdown rejects container isolation", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.Security.Isolation = IsolationContainer
		}, "gVisor or VM"},
		{"lockdown must be ephemeral", LevelLockdown, func(p *Profile) { p.Persistence = "persistent" }, "ephemeral"},
		{"lockdown rejects writable mounts", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.Mounts = []MountConfig{{Source: "/srv/code", Target: "/code"}}
		}, "read-only"},
		{"lockdown accepts read-only mounts", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.Mounts = []MountConfig{{Source: "/srv/code", Target: "/code", ReadOnly: true}}
		}, ""},
		{"lockdown rejects remote MCP", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.MCP.Servers = []MCPServer{{Name: "docs", URL: "https://mcp.example.com/mcp"}}
		}, "remote MCP"},
		{"lockdown requires gateway MCP", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.MCP.Servers = []MCPServer{{Name: "fs", Command: []string{"mcp-fs"}, AllowTools: []string{"read"}}}
		}, "gateway"},
		{"lockdown requires allow_tools", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.MCP.Servers = []MCPServer{{Name: "fs", Command: []string{"mcp-fs"}, RunIn: "gateway"}}
		}, "allow_tools"},
		{"lockdown requires branch patterns for writes", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.Git.Repos = []GitRepo{{Repo: "a/b", Access: "write"}}
		}, "branch patterns"},
		{"valid lockdown", LevelLockdown, func(p *Profile) {
			p.Persistence = "ephemeral"
			p.Git.Repos = []GitRepo{{Repo: "a/b", Access: "write", Branches: []string{"agent/*"}}}
			p.MCP.Servers = []MCPServer{{Name: "fs", Command: []string{"mcp-fs"}, RunIn: "gateway", AllowTools: []string{"read_*"}}}
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := profileAt(tc.level)
			tc.mutate(&p)
			err := p.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("want valid, got %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestResolveAppliesLevelDefaults(t *testing.T) {
	std := profileAt(LevelStandard)
	e := std.Resolve()
	if e.ReadOnlyRoot || e.HTTPSOnly || !e.BlockRisky || e.MonitorMode != "enforce" || e.Strictness != "medium" || e.DenyKillThreshold != 0 {
		t.Errorf("standard defaults wrong: %+v", e)
	}
	if !e.QuietAgents || e.HarnessLockdown {
		t.Errorf("standard quiet/harness flags wrong: %+v", e)
	}

	strict := profileAt(LevelStrict)
	strict.Security.ReadOnlyRoot = false // the level forces it anyway
	e = strict.Resolve()
	if !e.ReadOnlyRoot || !e.HTTPSOnly || !e.NoExecTmp || e.Strictness != "high" || e.DenyKillThreshold != 3 || !e.PreferStrongIsolation {
		t.Errorf("strict defaults wrong: %+v", e)
	}
	if len(e.ProtectPaths) == 0 || !e.NpmIgnoreScripts || !e.KillOnExecFromWritable {
		t.Errorf("strict protections missing: %+v", e)
	}

	lock := profileAt(LevelLockdown)
	lock.Persistence = "ephemeral"
	e = lock.Resolve()
	if !e.RequireStrongIsolation || e.DenyKillThreshold != 1 || !e.AIEnforce || !e.HarnessLockdown || !e.PipOnlyBinary || !e.NoExecHome {
		t.Errorf("lockdown defaults wrong: %+v", e)
	}

	open := validProfile()
	open.Security.Level = LevelOpen
	open.Security.Sudo = true
	e = open.Resolve()
	if e.MonitorMode != "observe" || !e.Sudo {
		t.Errorf("open defaults wrong: %+v", e)
	}
}

func TestSandboxDomainsExpansion(t *testing.T) {
	p := profileAt(LevelStandard)
	p.Agents = []AgentConfig{{ID: "claude-code", Env: map[string]string{
		"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
		"GROQ_API_KEY":      "${GROQ_API_KEY}",
	}}}
	p.Network.AllowedDomains = []string{"Example.com"}
	p.Network.Presets = []string{"npm"}
	p.MCP.Servers = []MCPServer{
		{Name: "docs", URL: "https://mcp.docs.example/mcp"},
		{Name: "local", Command: []string{"x"}, Domains: []string{"api.local-tool.example"}},
		{Name: "gw", Command: []string{"y"}, RunIn: "gateway", Domains: []string{"api.gateway-only.example"}},
	}
	got := p.SandboxDomains()
	want := []string{"api.anthropic.com", "api.groq.com", "api.local-tool.example", "claude.ai", "example.com", "mcp.docs.example", "platform.claude.com", "registry.npmjs.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SandboxDomains = %v\nwant %v", got, want)
	}

	off := false
	p.Network.AgentDomains = &off
	for _, d := range p.SandboxDomains() {
		if d == "api.anthropic.com" || d == "api.groq.com" || d == "platform.claude.com" {
			t.Errorf("agent_domains: false should drop %s", d)
		}
	}
}

func TestGatewayDomainsStaySeparate(t *testing.T) {
	p := profileAt(LevelStandard)
	p.Git.Repos = []GitRepo{{Repo: "FolksyPizza/rig"}}
	p.MCP.Servers = []MCPServer{{Name: "gw", Command: []string{"y"}, RunIn: "gateway", Domains: []string{"api.github.com"}}}
	if got := p.GatewayDomains(); !reflect.DeepEqual(got, []string{"api.github.com", "github.com"}) {
		t.Errorf("GatewayDomains = %v", got)
	}
	for _, d := range p.SandboxDomains() {
		if d == "github.com" || d == "api.github.com" {
			t.Errorf("the broker's host must not leak into the sandbox allowlist: %v", p.SandboxDomains())
		}
	}
	if !p.Resolve().NeedsGateway {
		t.Error("git repos need the gateway")
	}
}

func TestValidateNewSections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"bad level", func(p *Profile) { p.Security.Level = "paranoid" }},
		{"bad isolation", func(p *Profile) { p.Security.Isolation = "chroot" }},
		{"bad agent version", func(p *Profile) { p.Agents[0].Version = "1.0; rm -rf /" }},
		{"unpinnable agent version", func(p *Profile) { p.Agents = []AgentConfig{{ID: "hermes", Version: "1.0"}} }},
		{"duplicate agent", func(p *Profile) { p.Agents = append(p.Agents, p.Agents[0]) }},
		{"bad npm package", func(p *Profile) { p.Packages.NPM = []string{"x;id"} }},
		{"bad pip package", func(p *Profile) { p.Packages.Pip = []string{"-r reqs.txt"} }},
		{"unknown preset", func(p *Profile) { p.Network.Presets = []string{"everything"} }},
		{"wildcard allow_risky", func(p *Profile) { p.Network.AllowRisky = []string{"*.s3.amazonaws.com"} }},
		{"ip in allowlist", func(p *Profile) { p.Network.AllowedDomains = []string{"10.0.0.1"} }},
		{"host port reserved", func(p *Profile) { p.Host.Ports = []HostPort{{Name: "x", Port: GatewayPort}} }},
		{"host port out of range", func(p *Profile) { p.Host.Ports = []HostPort{{Name: "x", Port: 70000}} }},
		{"duplicate host port", func(p *Profile) {
			p.Host.Ports = []HostPort{{Name: "a", Port: 11434}, {Name: "b", Port: 11434}}
		}},
		{"git bad repo", func(p *Profile) { p.Git.Repos = []GitRepo{{Repo: "nope"}} }},
		{"git bad access", func(p *Profile) { p.Git.Repos = []GitRepo{{Repo: "a/b", Access: "admin"}} }},
		{"git bad branch", func(p *Profile) { p.Git.Repos = []GitRepo{{Repo: "a/b", Branches: []string{"x y"}}} }},
		{"git token without repos", func(p *Profile) { p.Git.TokenEnv = "GITHUB_TOKEN" }},
		{"mcp both command and url", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", Command: []string{"a"}, URL: "https://x.example"}}
		}},
		{"mcp http url", func(p *Profile) { p.MCP.Servers = []MCPServer{{Name: "x", URL: "http://x.example/mcp"}} }},
		{"mcp tool rules on a remote server", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", URL: "https://x.example/mcp", DenyTools: []string{"delete"}}}
		}},
		{"mcp url with credentials", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", URL: "https://user:pass@x.example/mcp"}}
		}},
		{"mcp sandbox with host ports", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", Command: []string{"a"}, RunIn: "sandbox", HostPorts: []int{9876}}}
		}},
		{"mcp host port also exposed to sandbox", func(p *Profile) {
			p.Host.Ports = []HostPort{{Name: "b", Port: 9876}}
			p.MCP.Servers = []MCPServer{{Name: "x", Command: []string{"a"}, HostPorts: []int{9876}}}
		}},
		{"mcp bad tool pattern", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", Command: []string{"a"}, DenyTools: []string{"bad["}}}
		}},
		{"mcp newline in command", func(p *Profile) {
			p.MCP.Servers = []MCPServer{{Name: "x", Command: []string{"a\nb"}}}
		}},
		{"monitor bad provider", func(p *Profile) { p.Monitor.AI.Provider = "magic" }},
		{"monitor ai settings without provider", func(p *Profile) { p.Monitor.AI.Model = "x" }},
		{"monitor bad interval", func(p *Profile) {
			p.Monitor.AI = AIConfig{Provider: "ollama", Interval: "1s"}
		}},
		{"monitor endpoint with credentials", func(p *Profile) {
			p.Monitor.AI = AIConfig{Provider: "openai", Endpoint: "https://u:p@api.example.com"}
		}},
		{"mount protect escapes", func(p *Profile) {
			p.Mounts = []MountConfig{{Source: "/srv/code", Target: "/code", Protect: []string{"../etc"}}}
		}},
		{"gateway features need an allowlist", func(p *Profile) {
			p.Host.Ports = []HostPort{{Name: "ollama", Port: 11434}}
		}},
		{"reserved volume name", func(p *Profile) {
			p.Storage.Volumes = []VolumeMount{{Name: "home", Target: "/x"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			tc.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Error("Validate() = nil, want error")
			}
		})
	}
}

func TestNormalizeMigratesWatchdog(t *testing.T) {
	p := validProfile()
	p.Watchdog = WatchdogConfig{Mode: "enforce", Strictness: "high"}
	p.Normalize()
	if p.Monitor.Mode != "enforce" || p.Monitor.Strictness != "high" || p.Watchdog.Mode != "" {
		t.Errorf("watchdog not migrated: %+v / %+v", p.Monitor, p.Watchdog)
	}
}

func TestTemplatesCoverEveryLevel(t *testing.T) {
	levels := map[string]bool{}
	for _, tmpl := range BuiltinTemplates() {
		p := tmpl.Profile
		levels[p.EffectiveLevel()] = true
	}
	for _, l := range []string{LevelOpen, LevelStandard, LevelStrict, LevelLockdown} {
		if !levels[l] {
			t.Errorf("no template uses level %s", l)
		}
	}
	if _, ok := GetTemplate("claude-secure"); !ok {
		t.Error("the old claude-secure name should still work")
	}
}

func TestLocalModelTemplateHasNoInternet(t *testing.T) {
	tmpl, ok := GetTemplate("local-model")
	if !ok {
		t.Fatal("local-model template missing")
	}
	if got := tmpl.Profile.SandboxDomains(); len(got) != 0 {
		t.Errorf("local-model should allow no internet domains, got %v", got)
	}
}
