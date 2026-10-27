package config

import (
	"net/url"
	"sort"
	"strings"

	"github.com/FolksyPizza/rig/internal/agents"
)

// Security levels, from least to most restrictive.
const (
	LevelOpen     = "open"
	LevelStandard = "standard"
	LevelStrict   = "strict"
	LevelLockdown = "lockdown"
)

// Isolation choices.
const (
	IsolationAuto      = "auto"
	IsolationContainer = "container"
	IsolationGVisor    = "gvisor"
	IsolationVM        = "vm"
)

// LevelInfo describes each level for help output.
var LevelInfo = []struct{ Name, Summary string }{
	{LevelOpen, "unrestricted network allowed, sudo allowed, monitor observes"},
	{LevelStandard, "default: egress allowlist, exfiltration sites blocked, monitor stops clear attacks"},
	{LevelStrict, "read-only image, no sudo, HTTPS only, prefers gVisor/VM, monitor stops repeated violations"},
	{LevelLockdown, "only listed domains; gVisor/VM required; read-only mounts; ephemeral; first blocked attempt stops it"},
}

// LevelRank orders levels; unknown levels rank as standard.
func LevelRank(level string) int {
	switch level {
	case LevelOpen:
		return 0
	case LevelStrict:
		return 2
	case LevelLockdown:
		return 3
	default:
		return 1
	}
}

// EffectiveLevel returns the profile's level. Profiles written before levels
// existed have none; they are treated as open if they asked for unrestricted
// network access (as they always had it) and standard otherwise.
func (p *Profile) EffectiveLevel() string {
	if p.Security.Level != "" {
		return p.Security.Level
	}
	if p.Network.Mode == "unrestricted" {
		return LevelOpen
	}
	return LevelStandard
}

// Effective is a profile's resolved policy: what the level forces on top of
// what the profile asks for. Everything that launches or monitors a sandbox
// reads this rather than the raw profile, so a level's floor is applied in
// exactly one place.
type Effective struct {
	Level string

	Isolation              string // auto | container | gvisor | vm
	RequireStrongIsolation bool   // refuse to start without gVisor or a VM
	PreferStrongIsolation  bool   // use gVisor or a VM when installed

	ReadOnlyRoot bool
	NoExecTmp    bool // /tmp mounted noexec
	NoExecHome   bool // home mounted noexec (ephemeral home only)
	Sudo         bool

	NetworkMode    string
	Allowed        []string // the sandbox's expanded allowlist
	GatewayAllowed []string // what the gateway's own servers may reach
	BlockRisky     bool
	AllowRisky     []string
	HTTPSOnly      bool
	RequireSNI     bool
	MaxUploadBytes int64

	MonitorMode string // off | observe | enforce
	Strictness  string // low | medium | high
	// DenyKillThreshold is how many ordinary blocked egress attempts within a
	// minute stop the sandbox. 0 means they are flagged, never fatal.
	// Attempts to reach exfiltration or reconnaissance services are always
	// treated as critical, whatever this says.
	DenyKillThreshold      int
	KillOnExecFromWritable bool
	// ExecOnlyFromImage: running a program from outside the image (a binary
	// built or downloaded into the workspace) stops the sandbox. Lockdown.
	ExecOnlyFromImage bool
	AIEnforce         bool

	HarnessLockdown  bool // agent-level policies (deny web tools, no bypass mode)
	NpmIgnoreScripts bool // no npm install scripts at run time
	PipOnlyBinary    bool // no source builds (setup.py) at run time
	QuietAgents      bool // telemetry, error reporting and auto-update off

	ProtectPaths []string // auto-protected paths inside writable mounts
	Ephemeral    bool
	NeedsGateway bool
}

// AutoProtectPaths are made read-only inside writable mounts at strict and
// above, when they exist: changing them is how an agent would plant code that
// runs later outside the sandbox (git hooks, CI workflows, git config).
var AutoProtectPaths = []string{".git/hooks", ".git/config", ".github", ".gitlab-ci.yml", ".circleci", ".husky"}

// Resolve computes the effective policy.
func (p *Profile) Resolve() Effective {
	level := p.EffectiveLevel()
	r := LevelRank(level)
	e := Effective{Level: level}

	e.Isolation = p.Security.Isolation
	if e.Isolation == "" {
		e.Isolation = IsolationAuto
	}
	e.RequireStrongIsolation = level == LevelLockdown
	e.PreferStrongIsolation = r >= LevelRank(LevelStrict)

	e.ReadOnlyRoot = p.Security.ReadOnlyRoot || r >= LevelRank(LevelStrict)
	e.NoExecTmp = r >= LevelRank(LevelStrict)
	e.NoExecHome = level == LevelLockdown && p.Persistence == "ephemeral"
	e.Sudo = p.Security.Sudo && r <= LevelRank(LevelStandard)

	e.NetworkMode = p.Network.Mode
	e.Allowed = p.SandboxDomains()
	e.GatewayAllowed = p.GatewayDomains()
	e.BlockRisky = r >= LevelRank(LevelStandard) || p.Network.BlockExfil == nil || *p.Network.BlockExfil
	e.AllowRisky = append([]string{}, p.Network.AllowRisky...)
	e.HTTPSOnly = p.Network.HTTPSOnly || r >= LevelRank(LevelStrict)
	e.RequireSNI = true
	switch level {
	case LevelStrict:
		e.MaxUploadBytes = 256 << 20
	case LevelLockdown:
		e.MaxUploadBytes = 64 << 20
	}

	e.MonitorMode = p.Monitor.Mode
	if e.MonitorMode == "" {
		e.MonitorMode = "enforce"
		if level == LevelOpen {
			e.MonitorMode = "observe"
		}
	}
	e.Strictness = p.Monitor.Strictness
	if e.Strictness == "" {
		e.Strictness = "medium"
		if r >= LevelRank(LevelStrict) {
			e.Strictness = "high"
		}
	}
	switch level {
	case LevelStrict:
		e.DenyKillThreshold = 3
	case LevelLockdown:
		e.DenyKillThreshold = 1
	}
	e.KillOnExecFromWritable = r >= LevelRank(LevelStrict)
	e.ExecOnlyFromImage = level == LevelLockdown
	e.AIEnforce = p.Monitor.AI.Enforce || level == LevelLockdown

	e.HarnessLockdown = level == LevelLockdown
	e.NpmIgnoreScripts = r >= LevelRank(LevelStrict)
	e.PipOnlyBinary = level == LevelLockdown
	e.QuietAgents = r >= LevelRank(LevelStandard)
	if r >= LevelRank(LevelStrict) {
		e.ProtectPaths = AutoProtectPaths
	}
	e.Ephemeral = p.Persistence == "ephemeral"

	e.NeedsGateway = len(p.Host.Ports) > 0 || len(p.Git.Repos) > 0
	for _, s := range p.MCP.Servers {
		if s.InGateway() {
			e.NeedsGateway = true
		}
	}
	return e
}

func agentIDs(p *Profile) []string {
	ids := make([]string, 0, len(p.Agents))
	for _, a := range p.Agents {
		ids = append(ids, a.ID)
	}
	return ids
}

// SandboxDomains expands the sandbox's allowlist: explicit domains, presets,
// each agent's own API, model APIs implied by configured keys, and the hosts
// of remote MCP servers and in-sandbox MCP servers' declared domains.
func (p *Profile) SandboxDomains() []string {
	set := map[string]bool{}
	add := func(ds ...string) {
		for _, d := range ds {
			if d != "" {
				set[strings.ToLower(d)] = true
			}
		}
	}
	add(p.Network.AllowedDomains...)
	for _, name := range p.Network.Presets {
		add(Presets[name].Domains...)
	}
	if p.Network.AgentDomains == nil || *p.Network.AgentDomains {
		if specs, err := agents.Resolve(agentIDs(p)); err == nil {
			for _, s := range specs {
				add(s.Domains...)
			}
		}
		for _, a := range p.Agents {
			add(agents.ProviderDomains(a.Env)...)
		}
	}
	for _, s := range p.MCP.Servers {
		if s.URL != "" {
			if u, err := url.Parse(s.URL); err == nil {
				add(u.Hostname())
			}
		} else if !s.InGateway() {
			add(s.Domains...)
		}
	}
	return sortedKeys(set)
}

// GatewayDomains is what the gateway's own MCP servers and git broker may
// reach. It is separate from the sandbox's list so that, for example, giving
// the broker github.com does not give the agent github.com.
func (p *Profile) GatewayDomains() []string {
	set := map[string]bool{}
	for _, s := range p.MCP.Servers {
		if s.InGateway() {
			for _, d := range s.Domains {
				set[strings.ToLower(d)] = true
			}
		}
	}
	if len(p.Git.Repos) > 0 {
		set[p.Git.GitHost()] = true
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
