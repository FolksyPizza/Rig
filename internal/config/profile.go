package config

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/security"
)

// Profile is a saved sandbox definition. Profiles are shareable YAML files,
// so everything in them is treated as untrusted input and validated.
type Profile struct {
	Version     int             `yaml:"version"`
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Security    SecurityConfig  `yaml:"security,omitempty"`
	Agents      []AgentConfig   `yaml:"agents"`
	Tools       []string        `yaml:"tools"`
	Packages    PackagesConfig  `yaml:"packages,omitempty"`
	Network     NetworkConfig   `yaml:"network"`
	Host        HostConfig      `yaml:"host,omitempty"`
	Git         GitConfig       `yaml:"git,omitempty"`
	MCP         MCPConfig       `yaml:"mcp,omitempty"`
	Monitor     MonitorConfig   `yaml:"monitor,omitempty"`
	Commands    CommandsConfig  `yaml:"commands"`
	Resources   ResourcesConfig `yaml:"resources"`
	Storage     StorageConfig   `yaml:"storage"`
	Persistence string          `yaml:"persistence"`
	GPU         GPUConfig       `yaml:"gpu"`
	Mounts      []MountConfig   `yaml:"mounts,omitempty"`
	// Watchdog is the pre-1.0 name for Monitor. It is read for compatibility
	// and folded into Monitor by Normalize.
	Watchdog WatchdogConfig `yaml:"watchdog,omitempty"`
	Metadata Metadata       `yaml:"metadata,omitempty"`
}

// SecurityConfig selects how locked down the sandbox is.
type SecurityConfig struct {
	// Level is open, standard, strict or lockdown. Each level sets defaults
	// and a floor: settings in the profile can be stricter than the level,
	// never looser. See levels.go.
	Level string `yaml:"level,omitempty"`
	// Isolation is auto, container, gvisor or vm. gvisor runs the sandbox on
	// gVisor's user-space kernel; vm runs it in a lightweight virtual machine
	// (Kata Containers, or Apple's per-container VMs on macOS). auto picks the
	// strongest one installed.
	Isolation string `yaml:"isolation,omitempty"`
	// ReadOnlyRoot mounts the image read-only. Forced on at strict and above.
	ReadOnlyRoot bool `yaml:"read_only_root,omitempty"`
	// Sudo gives the sandbox user passwordless sudo, with the minimum
	// capabilities package installs need. Allowed only at open and standard.
	Sudo bool `yaml:"sudo,omitempty"`
}

// AgentConfig selects an agent and its environment.
type AgentConfig struct {
	ID string `yaml:"id"`
	// Version pins the agent (an npm/pip version, or a git ref for Grove).
	Version string            `yaml:"version,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`
}

// PackagesConfig lists language packages installed at build time.
type PackagesConfig struct {
	NPM []string `yaml:"npm,omitempty"`
	Pip []string `yaml:"pip,omitempty"`
}

// NetworkConfig controls the sandbox's network access.
type NetworkConfig struct {
	Mode           string   `yaml:"mode"` // unrestricted | allowlist | none
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`
	// Presets add named groups of domains, such as github or npm.
	Presets []string `yaml:"presets,omitempty"`
	// AgentDomains allows each agent's own model API (default true).
	AgentDomains *bool `yaml:"agent_domains,omitempty"`
	// BlockExfil refuses known upload, paste, tunnel and IP-lookup services
	// even if an allowlist entry covers them (default true; cannot be turned
	// off at standard and above).
	BlockExfil *bool `yaml:"block_exfil,omitempty"`
	// AllowRisky exempts exact hosts from BlockExfil.
	AllowRisky []string `yaml:"allow_risky,omitempty"`
	// HTTPSOnly refuses plain HTTP. Forced on at strict and above.
	HTTPSOnly bool `yaml:"https_only,omitempty"`
}

// HostConfig exposes services on your machine to the sandbox.
type HostConfig struct {
	Ports []HostPort `yaml:"ports,omitempty"`
}

// HostPort relays one port. The sandbox connects to rig-gw:<port>; the rig
// process on the host connects to 127.0.0.1:<host_port>.
type HostPort struct {
	Name     string `yaml:"name"`
	Port     int    `yaml:"port"`
	HostPort int    `yaml:"host_port,omitempty"`
}

// Target is the host-side port.
func (h HostPort) Target() int {
	if h.HostPort > 0 {
		return h.HostPort
	}
	return h.Port
}

// GitConfig grants access to specific repositories through Rig's git broker.
type GitConfig struct {
	// TokenEnv names the host environment variable holding the token. The
	// token stays in the gateway; the sandbox never sees it.
	TokenEnv string    `yaml:"token_env,omitempty"`
	Host     string    `yaml:"host,omitempty"` // default github.com
	Repos    []GitRepo `yaml:"repos,omitempty"`
}

// GitHost is the git host, defaulting to github.com.
func (g GitConfig) GitHost() string {
	if g.Host != "" {
		return strings.ToLower(g.Host)
	}
	return "github.com"
}

// GitRepo is one repository the sandbox may use.
type GitRepo struct {
	Repo     string   `yaml:"repo"`             // owner/name
	Access   string   `yaml:"access,omitempty"` // read (default) | write
	Branches []string `yaml:"branches,omitempty"`
	Tags     bool     `yaml:"tags,omitempty"`
	Delete   bool     `yaml:"delete,omitempty"`
}

// AccessLevel returns read or write.
func (r GitRepo) AccessLevel() string {
	if r.Access == "" {
		return "read"
	}
	return r.Access
}

// MCPConfig lists MCP servers made available to the agents.
type MCPConfig struct {
	Servers []MCPServer `yaml:"servers,omitempty"`
}

// MCPServer is one MCP server. Exactly one of Command (a stdio server Rig
// runs) or URL (a remote server) is set.
type MCPServer struct {
	Name     string            `yaml:"name"`
	Command  []string          `yaml:"command,omitempty"`
	URL      string            `yaml:"url,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Env      map[string]string `yaml:"env,omitempty"`
	Packages PackagesConfig    `yaml:"packages,omitempty"`
	// RunIn is sandbox (default) or gateway. Gateway servers run outside the
	// sandbox and are reachable only through Rig's tool-call guard.
	RunIn string `yaml:"run_in,omitempty"`
	// HostPorts are host ports this server needs (for example Blender's
	// 9876). Only this server can reach them; implies run_in: gateway.
	HostPorts []int `yaml:"host_ports,omitempty"`
	// Domains the server needs to reach on the internet.
	Domains    []string `yaml:"domains,omitempty"`
	AllowTools []string `yaml:"allow_tools,omitempty"`
	DenyTools  []string `yaml:"deny_tools,omitempty"`
	// LogArgs records tool arguments in the audit log (default true).
	LogArgs *bool `yaml:"log_args,omitempty"`
}

// InGateway reports whether the server runs in the gateway.
func (m MCPServer) InGateway() bool {
	return m.RunIn == "gateway" || len(m.HostPorts) > 0
}

// MonitorConfig controls live monitoring while the sandbox runs.
type MonitorConfig struct {
	Mode       string   `yaml:"mode,omitempty"`       // off | observe | enforce
	Strictness string   `yaml:"strictness,omitempty"` // low | medium | high
	AI         AIConfig `yaml:"ai,omitempty"`
}

// AIConfig turns on the AI monitor: a second model that reviews what the
// sandbox does and can raise alarms. It can only make Rig stricter.
type AIConfig struct {
	Provider  string `yaml:"provider,omitempty"` // anthropic | openai | ollama; empty is off
	Model     string `yaml:"model,omitempty"`
	Endpoint  string `yaml:"endpoint,omitempty"`
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	// Enforce lets the AI monitor's verdicts stop the sandbox, not just flag.
	Enforce  bool   `yaml:"enforce,omitempty"`
	Interval string `yaml:"interval,omitempty"` // how often to review, e.g. 30s
}

// WatchdogConfig is the legacy monitor configuration.
type WatchdogConfig struct {
	Mode       string `yaml:"mode,omitempty"`
	Strictness string `yaml:"strictness,omitempty"`
}

// CommandsConfig restricts which commands `rig exec` will run in a sandbox.
//
// This is a convenience guard on Rig's own entry point, not a security
// boundary: an agent with a shell inside the container can run anything the
// image contains regardless of this setting.
type CommandsConfig struct {
	Mode    string   `yaml:"mode"`
	Allowed []string `yaml:"allowed,omitempty"`
}

type ResourcesConfig struct {
	CPU      float64 `yaml:"cpu"`
	Memory   int64   `yaml:"memory"`
	PIDLimit int64   `yaml:"pids_limit"`
}

type StorageConfig struct {
	Size    string        `yaml:"size"`
	Volumes []VolumeMount `yaml:"volumes,omitempty"`
}

type VolumeMount struct {
	Name     string `yaml:"name"`
	Target   string `yaml:"target"`
	Size     string `yaml:"size,omitempty"`
	ReadOnly bool   `yaml:"readonly,omitempty"`
}

type GPUConfig struct {
	Enabled bool     `yaml:"enabled"`
	Devices []string `yaml:"devices,omitempty"`
	Driver  string   `yaml:"driver,omitempty"`
}

// MountConfig bind-mounts a host directory into the sandbox.
type MountConfig struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"readonly"`
	// Protect lists paths inside a writable mount that stay read-only, such
	// as .github or .git/hooks.
	Protect []string `yaml:"protect,omitempty"`
	// Hide lists paths inside the mount that appear empty in the sandbox,
	// such as .env.
	Hide []string `yaml:"hide,omitempty"`
}

type Metadata struct {
	CreatedAt time.Time     `yaml:"created_at,omitempty"`
	LastUsed  time.Time     `yaml:"last_used,omitempty"`
	ImageTag  string        `yaml:"image_tag,omitempty"`
	Timeout   time.Duration `yaml:"timeout,omitempty"`
}

// reservedPorts are used by the gateway itself.
var reservedPorts = map[int]bool{GatewayPort: true}

// GatewayPort is where the gateway serves MCP and git inside the sandbox network.
const GatewayPort = 8800

// Normalize migrates legacy fields. Load and Import call it before Validate.
func (p *Profile) Normalize() {
	if p.Monitor.Mode == "" && p.Watchdog.Mode != "" {
		p.Monitor.Mode = p.Watchdog.Mode
	}
	if p.Monitor.Strictness == "" && p.Watchdog.Strictness != "" {
		p.Monitor.Strictness = p.Watchdog.Strictness
	}
	p.Watchdog = WatchdogConfig{}
}

// Validate checks every field a profile can carry. Profiles are shareable
// files that arrive via `rig import`, so this runs on load and on save and
// treats the contents as untrusted input.
func (p *Profile) Validate() error {
	if err := security.ValidateProfileName(p.Name); err != nil {
		return err
	}
	if err := p.validateSecurity(); err != nil {
		return err
	}
	if err := p.validateAgents(); err != nil {
		return err
	}
	if err := security.ValidatePackageNames(p.Tools); err != nil {
		return err
	}
	if err := validatePackages(p.Packages); err != nil {
		return err
	}
	if err := p.validateNetwork(); err != nil {
		return err
	}
	if err := p.validateHost(); err != nil {
		return err
	}
	if err := p.validateGit(); err != nil {
		return err
	}
	if err := p.validateMCP(); err != nil {
		return err
	}
	if err := p.validateMonitor(); err != nil {
		return err
	}

	switch p.Commands.Mode {
	case "unrestricted", "allowlist":
	default:
		return fmt.Errorf("invalid commands mode %q (want unrestricted or allowlist)", p.Commands.Mode)
	}

	switch p.Persistence {
	case "ephemeral", "persistent":
	default:
		return fmt.Errorf("invalid persistence mode %q (want ephemeral or persistent)", p.Persistence)
	}

	if p.Resources.CPU < 0.5 {
		return fmt.Errorf("cpu must be at least 0.5 cores")
	}
	if p.Resources.CPU > 1024 {
		return fmt.Errorf("cpu limit %.1f is implausibly large", p.Resources.CPU)
	}
	if p.Resources.Memory < 512 {
		return fmt.Errorf("memory must be at least 512 MB")
	}
	// A PID limit of 0 or -1 means "unlimited" to the engine, which would
	// silently remove the fork-bomb protection the profile appears to set.
	if p.Resources.PIDLimit < 16 {
		return fmt.Errorf("pids_limit must be at least 16 (0 or negative would disable the limit entirely)")
	}

	if err := security.ValidateSize(p.Storage.Size); err != nil {
		return err
	}
	seenVolume := make(map[string]bool, len(p.Storage.Volumes))
	for _, v := range p.Storage.Volumes {
		if err := security.ValidateVolumeName(v.Name); err != nil {
			return err
		}
		if v.Name == "home" {
			return fmt.Errorf("volume name \"home\" is reserved")
		}
		if seenVolume[v.Name] {
			return fmt.Errorf("duplicate volume name %q", v.Name)
		}
		seenVolume[v.Name] = true
		if err := security.ValidateMountTarget(v.Target); err != nil {
			return err
		}
		if err := security.ValidateSize(v.Size); err != nil {
			return err
		}
	}

	if err := p.validateMounts(); err != nil {
		return err
	}

	if p.GPU.Enabled {
		return fmt.Errorf("gpu passthrough is not implemented yet; set gpu.enabled to false")
	}
	if p.Resolve().NeedsGateway && p.Network.Mode != "allowlist" {
		return fmt.Errorf("host ports, gateway MCP servers and the git broker need network mode allowlist: they run on the sandbox's private network")
	}
	return p.validateLevelFloor()
}

func (p *Profile) validateSecurity() error {
	switch p.Security.Level {
	case "", LevelOpen, LevelStandard, LevelStrict, LevelLockdown:
	default:
		return fmt.Errorf("invalid security level %q (want open, standard, strict or lockdown)", p.Security.Level)
	}
	switch p.Security.Isolation {
	case "", IsolationAuto, IsolationContainer, IsolationGVisor, IsolationVM:
	default:
		return fmt.Errorf("invalid isolation %q (want auto, container, gvisor or vm)", p.Security.Isolation)
	}
	return nil
}

func (p *Profile) validateAgents() error {
	if len(p.Agents) == 0 {
		return fmt.Errorf("at least one agent must be selected")
	}
	seen := map[string]bool{}
	for _, a := range p.Agents {
		if a.ID == "" {
			return fmt.Errorf("agent entry is missing an id")
		}
		spec, ok := agents.ByID(a.ID)
		if !ok {
			return fmt.Errorf("unknown agent %q (see 'rig agents' for the supported list)", a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("agent %q is listed twice", a.ID)
		}
		seen[a.ID] = true
		if a.Version != "" {
			if !agents.ValidVersion(a.Version) {
				return fmt.Errorf("agent %q: invalid version %q", a.ID, a.Version)
			}
			if !spec.Pinnable() {
				return fmt.Errorf("agent %q does not support pinning a version", a.ID)
			}
		}
		for k, v := range a.Env {
			if err := security.ValidateEnvName(k); err != nil {
				return fmt.Errorf("agent %q: %w", a.ID, err)
			}
			if strings.ContainsAny(v, "\n\r\x00") {
				return fmt.Errorf("agent %q: value of %s contains a newline", a.ID, k)
			}
		}
	}
	return nil
}

func validatePackages(pk PackagesConfig) error {
	for _, n := range pk.NPM {
		if err := security.ValidateNPMPackage(n); err != nil {
			return err
		}
	}
	for _, n := range pk.Pip {
		if err := security.ValidatePipPackage(n); err != nil {
			return err
		}
	}
	return nil
}

func (p *Profile) validateNetwork() error {
	switch p.Network.Mode {
	case "unrestricted", "allowlist", "none":
	default:
		return fmt.Errorf("invalid network mode %q (want unrestricted, allowlist or none)", p.Network.Mode)
	}
	if err := security.ValidateDomains(p.Network.AllowedDomains); err != nil {
		return err
	}
	for _, d := range p.Network.AllowRisky {
		if strings.HasPrefix(d, "*.") {
			return fmt.Errorf("allow_risky takes exact hosts, not wildcards (%q)", d)
		}
		if err := security.ValidateDomain(d); err != nil {
			return err
		}
	}
	for _, name := range p.Network.Presets {
		if _, ok := Presets[name]; !ok {
			return fmt.Errorf("unknown network preset %q (see 'rig presets')", name)
		}
	}
	return nil
}

func (p *Profile) validateHost() error {
	seen := map[int]bool{}
	for _, h := range p.Host.Ports {
		if err := security.ValidateName("host port", h.Name); err != nil {
			return err
		}
		if h.Port < 1 || h.Port > 65535 || h.HostPort < 0 || h.HostPort > 65535 {
			return fmt.Errorf("host port %q: ports must be between 1 and 65535", h.Name)
		}
		if reservedPorts[h.Port] {
			return fmt.Errorf("host port %q: port %d is used by Rig's gateway", h.Name, h.Port)
		}
		if seen[h.Port] {
			return fmt.Errorf("host port %d is listed twice", h.Port)
		}
		seen[h.Port] = true
	}
	return nil
}

func (p *Profile) validateGit() error {
	g := p.Git
	if len(g.Repos) == 0 {
		if g.TokenEnv != "" || g.Host != "" {
			return fmt.Errorf("git: token_env or host is set but no repos are listed")
		}
		return nil
	}
	if g.TokenEnv != "" {
		if err := security.ValidateEnvName(g.TokenEnv); err != nil {
			return fmt.Errorf("git: %w", err)
		}
	}
	if err := security.ValidateDomain(g.GitHost()); err != nil || strings.HasPrefix(g.GitHost(), "*.") {
		return fmt.Errorf("git: invalid host %q", g.Host)
	}
	seen := map[string]bool{}
	for _, r := range g.Repos {
		owner, name, ok := strings.Cut(r.Repo, "/")
		if !ok || security.ValidateRepoPart(owner) != nil || security.ValidateRepoPart(name) != nil {
			return fmt.Errorf("git: invalid repository %q (want owner/name)", r.Repo)
		}
		key := strings.ToLower(r.Repo)
		if seen[key] {
			return fmt.Errorf("git: repository %q is listed twice", r.Repo)
		}
		seen[key] = true
		switch r.Access {
		case "", "read", "write":
		default:
			return fmt.Errorf("git: repository %q: access must be read or write", r.Repo)
		}
		for _, b := range r.Branches {
			if b == "" || strings.ContainsAny(b, " \t\n\r\\:~^?[") || strings.Contains(b, "..") {
				return fmt.Errorf("git: repository %q: invalid branch pattern %q", r.Repo, b)
			}
		}
	}
	return nil
}

func (p *Profile) validateMCP() error {
	seen := map[string]bool{}
	hostPorts := map[int]bool{}
	for _, h := range p.Host.Ports {
		hostPorts[h.Port] = true
	}
	for _, s := range p.MCP.Servers {
		if err := security.ValidateName("MCP server", s.Name); err != nil {
			return err
		}
		if seen[s.Name] {
			return fmt.Errorf("MCP server %q is listed twice", s.Name)
		}
		seen[s.Name] = true

		hasCmd, hasURL := len(s.Command) > 0, s.URL != ""
		if hasCmd == hasURL {
			return fmt.Errorf("MCP server %q needs exactly one of command or url", s.Name)
		}
		for _, a := range s.Command {
			if a == "" || strings.ContainsAny(a, "\n\r\x00") {
				return fmt.Errorf("MCP server %q: command arguments must be non-empty single lines", s.Name)
			}
		}
		if hasURL {
			u, err := url.Parse(s.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return fmt.Errorf("MCP server %q: url must be an https:// URL without credentials", s.Name)
			}
			if err := security.ValidateDomain(strings.ToLower(u.Hostname())); err != nil {
				return fmt.Errorf("MCP server %q: %w", s.Name, err)
			}
			if s.RunIn == "gateway" || len(s.HostPorts) > 0 || len(s.Packages.NPM)+len(s.Packages.Pip) > 0 {
				return fmt.Errorf("MCP server %q: run_in, host_ports and packages apply to command servers only", s.Name)
			}
			// The agent talks to a remote server directly (through the egress
			// proxy), so Rig never sees its tool calls and could not apply
			// these rules. Refuse them rather than imply protection.
			if len(s.AllowTools)+len(s.DenyTools) > 0 {
				return fmt.Errorf("MCP server %q: allow_tools and deny_tools cannot be enforced for a remote server, because Rig does not see its tool calls; remove them, or run the server locally with command: and run_in: gateway", s.Name)
			}
		}
		for k, v := range s.Headers {
			if !hasURL {
				return fmt.Errorf("MCP server %q: headers apply to url servers only", s.Name)
			}
			if err := security.ValidateHeaderName(k); err != nil || strings.ContainsAny(v, "\n\r\x00") {
				return fmt.Errorf("MCP server %q: invalid header %q", s.Name, k)
			}
		}
		for k, v := range s.Env {
			if err := security.ValidateEnvName(k); err != nil {
				return fmt.Errorf("MCP server %q: %w", s.Name, err)
			}
			if strings.ContainsAny(v, "\n\r\x00") {
				return fmt.Errorf("MCP server %q: value of %s contains a newline", s.Name, k)
			}
		}
		if err := validatePackages(s.Packages); err != nil {
			return fmt.Errorf("MCP server %q: %w", s.Name, err)
		}
		switch s.RunIn {
		case "", "sandbox", "gateway":
		default:
			return fmt.Errorf("MCP server %q: run_in must be sandbox or gateway", s.Name)
		}
		if s.RunIn == "sandbox" && len(s.HostPorts) > 0 {
			return fmt.Errorf("MCP server %q: host_ports require run_in: gateway, so the sandbox itself cannot reach them", s.Name)
		}
		for _, hp := range s.HostPorts {
			if hp < 1 || hp > 65535 || reservedPorts[hp] {
				return fmt.Errorf("MCP server %q: invalid host port %d", s.Name, hp)
			}
			if hostPorts[hp] {
				return fmt.Errorf("MCP server %q: host port %d is already exposed to the sandbox under host.ports", s.Name, hp)
			}
		}
		if err := security.ValidateDomains(s.Domains); err != nil {
			return fmt.Errorf("MCP server %q: %w", s.Name, err)
		}
		for _, pat := range append(append([]string{}, s.AllowTools...), s.DenyTools...) {
			if pat == "" || strings.ContainsAny(pat, " \t\n\r") {
				return fmt.Errorf("MCP server %q: invalid tool pattern %q", s.Name, pat)
			}
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("MCP server %q: invalid tool pattern %q", s.Name, pat)
			}
		}
	}
	return nil
}

func (p *Profile) validateMonitor() error {
	switch p.Monitor.Mode {
	case "", "off", "observe", "enforce":
	default:
		return fmt.Errorf("invalid monitor mode %q (want off, observe or enforce)", p.Monitor.Mode)
	}
	switch p.Monitor.Strictness {
	case "", "low", "medium", "high":
	default:
		return fmt.Errorf("invalid monitor strictness %q (want low, medium or high)", p.Monitor.Strictness)
	}
	ai := p.Monitor.AI
	switch ai.Provider {
	case "":
		if ai.Model != "" || ai.Endpoint != "" || ai.APIKeyEnv != "" || ai.Enforce {
			return fmt.Errorf("monitor.ai settings need a provider (anthropic, openai or ollama)")
		}
		return nil
	case "anthropic", "openai", "ollama":
	default:
		return fmt.Errorf("invalid AI monitor provider %q (want anthropic, openai or ollama)", ai.Provider)
	}
	if ai.Endpoint != "" {
		u, err := url.Parse(ai.Endpoint)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return fmt.Errorf("monitor.ai.endpoint must be an http(s) URL without credentials")
		}
	}
	if ai.APIKeyEnv != "" {
		if err := security.ValidateEnvName(ai.APIKeyEnv); err != nil {
			return fmt.Errorf("monitor.ai: %w", err)
		}
	}
	if ai.Model != "" && (len(ai.Model) > 128 || strings.ContainsAny(ai.Model, " \n\r\x00\"")) {
		return fmt.Errorf("monitor.ai.model %q is not a valid model name", ai.Model)
	}
	if ai.Interval != "" {
		d, err := time.ParseDuration(ai.Interval)
		if err != nil || d < 5*time.Second || d > time.Hour {
			return fmt.Errorf("monitor.ai.interval must be a duration between 5s and 1h")
		}
	}
	return nil
}

func (p *Profile) validateMounts() error {
	home, _ := os.UserHomeDir()
	for _, m := range p.Mounts {
		if err := security.ValidateMountSource(m.Source); err != nil {
			return err
		}
		if err := security.CheckCredentialPath(m.Source, home); err != nil {
			return err
		}
		if err := security.ValidateMountTarget(m.Target); err != nil {
			return err
		}
		for _, sub := range append(append([]string{}, m.Protect...), m.Hide...) {
			if err := security.ValidateSubpath(sub); err != nil {
				return fmt.Errorf("mount %s: %w", m.Source, err)
			}
		}
	}
	return nil
}

// validateLevelFloor enforces what each security level does not allow.
func (p *Profile) validateLevelFloor() error {
	level := p.EffectiveLevel()
	rank := LevelRank(level)

	if rank >= LevelRank(LevelStandard) {
		if p.Network.Mode == "unrestricted" {
			return fmt.Errorf("security level %s does not allow unrestricted network access; use network mode allowlist, or set security.level to open", level)
		}
		if p.Network.BlockExfil != nil && !*p.Network.BlockExfil {
			return fmt.Errorf("security level %s does not allow turning off block_exfil; list exact hosts under allow_risky instead", level)
		}
	}
	if rank >= LevelRank(LevelStrict) {
		if p.Security.Sudo {
			return fmt.Errorf("security level %s does not allow sudo; add packages to the profile instead ('rig add')", level)
		}
		if p.Monitor.Mode == "off" {
			return fmt.Errorf("security level %s requires monitoring; set monitor.mode to observe or enforce", level)
		}
	}
	if level == LevelLockdown {
		if p.Security.Isolation == IsolationContainer {
			return fmt.Errorf("lockdown requires gVisor or VM isolation; set security.isolation to auto, gvisor or vm")
		}
		if p.Persistence != "ephemeral" {
			return fmt.Errorf("lockdown sandboxes must be ephemeral (persistence: ephemeral); keep work in a volume or push it through the git broker")
		}
		if p.Monitor.Mode == "observe" {
			return fmt.Errorf("lockdown requires monitor.mode enforce")
		}
		for _, m := range p.Mounts {
			if !m.ReadOnly {
				return fmt.Errorf("lockdown allows read-only host mounts only (%s); have the agent push through the git broker or use 'rig cp'", m.Source)
			}
		}
		for _, s := range p.MCP.Servers {
			if s.URL != "" {
				return fmt.Errorf("lockdown does not allow remote MCP servers (%s): their tool calls cannot be checked", s.Name)
			}
			if !s.InGateway() {
				return fmt.Errorf("lockdown runs MCP servers in the gateway only (%s): set run_in: gateway", s.Name)
			}
			if len(s.AllowTools) == 0 {
				return fmt.Errorf("lockdown requires an allow_tools list for MCP server %s", s.Name)
			}
		}
		for _, r := range p.Git.Repos {
			if r.AccessLevel() == "write" && len(r.Branches) == 0 {
				return fmt.Errorf("lockdown requires branch patterns for writable repository %s", r.Repo)
			}
		}
	}
	return nil
}

// ImageTag is the profile's image name.
func (p *Profile) ImageTag() string {
	if p.Metadata.ImageTag != "" {
		return p.Metadata.ImageTag
	}
	return fmt.Sprintf("rig/%s:latest", p.Name)
}

// CommandAllowed reports whether `rig exec` should run the given argv in this
// sandbox. See the note on CommandsConfig: this guards Rig's entry point only.
func (p *Profile) CommandAllowed(argv []string) bool {
	if p.Commands.Mode != "allowlist" {
		return true
	}
	if len(argv) == 0 {
		return false
	}
	for _, allowed := range p.Commands.Allowed {
		if allowed == argv[0] {
			return true
		}
	}
	return false
}
