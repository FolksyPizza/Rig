package agents

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// customDef is the YAML form of a user-defined agent, kept in
// ~/.config/rig/agents/<id>.yaml.
//
// These files contain shell commands that run as root during an image build,
// so they are trusted local configuration, never part of a shareable profile.
// A profile can only name a custom agent by ID; importing a profile that
// names one you have not defined fails validation instead of running anything.
type customDef struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Node        string   `yaml:"node"`
	Apt         []string `yaml:"apt"`
	Install     []string `yaml:"install"`
	Command     string   `yaml:"command"`
	Verify      string   `yaml:"verify"`
	Domains     []string `yaml:"domains"`
	Env         []string `yaml:"env"`
	MCPFormat   string   `yaml:"mcp_format"`
	LocalModels bool     `yaml:"local_models"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	aptRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]*$`)
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	nodeRe    = regexp.MustCompile(`^[0-9]{2}$`)
	domainRe  = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// CustomDir is where custom agent definitions live.
func CustomDir() string {
	if d := os.Getenv("RIG_AGENTS_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "rig", "agents")
}

// LoadCustom reads every *.yaml definition in dir. Bad files are skipped and
// reported; a missing directory is not an error.
func LoadCustom(dir string) ([]AgentSpec, []error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{err}
	}
	builtin := map[string]bool{}
	for _, b := range builtins() {
		builtin[b.ID] = true
	}

	var specs []AgentSpec
	var errs []error
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	seen := map[string]bool{}
	for _, n := range names {
		path := filepath.Join(dir, n)
		spec, err := loadCustomFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if builtin[spec.ID] || seen[spec.ID] {
			errs = append(errs, fmt.Errorf("%s: agent id %q is already defined", path, spec.ID))
			continue
		}
		seen[spec.ID] = true
		specs = append(specs, spec)
	}
	return specs, errs
}

func loadCustomFile(path string) (AgentSpec, error) {
	info, err := os.Stat(path)
	if err != nil {
		return AgentSpec{}, err
	}
	// Another user able to edit this file could run commands as root in the
	// next image build.
	if info.Mode().Perm()&0o022 != 0 {
		return AgentSpec{}, fmt.Errorf("file is writable by group or others; run chmod 600 on it")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return AgentSpec{}, err
	}
	var d customDef
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return AgentSpec{}, err
	}
	return d.spec()
}

func (d customDef) spec() (AgentSpec, error) {
	if !idRe.MatchString(d.ID) {
		return AgentSpec{}, fmt.Errorf("id %q must be lowercase letters, digits and dashes", d.ID)
	}
	if d.Node != "" && !nodeRe.MatchString(d.Node) {
		return AgentSpec{}, fmt.Errorf("node must be a major version such as 22")
	}
	for _, p := range d.Apt {
		if !aptRe.MatchString(p) {
			return AgentSpec{}, fmt.Errorf("invalid apt package %q", p)
		}
	}
	if len(d.Install) == 0 {
		return AgentSpec{}, fmt.Errorf("install must list at least one command")
	}
	for _, s := range d.Install {
		// Each step becomes one RUN line; a newline would start a new
		// Dockerfile instruction.
		if strings.TrimSpace(s) == "" || strings.ContainsAny(s, "\n\r\x00") {
			return AgentSpec{}, fmt.Errorf("install steps must be single, non-empty lines")
		}
	}
	for _, dom := range d.Domains {
		if !domainRe.MatchString(dom) {
			return AgentSpec{}, fmt.Errorf("invalid domain %q", dom)
		}
	}
	for _, e := range d.Env {
		if !envNameRe.MatchString(e) {
			return AgentSpec{}, fmt.Errorf("invalid environment variable name %q", e)
		}
	}
	switch d.MCPFormat {
	case MCPNone, MCPClaude, MCPCodex, MCPGemini, MCPQwen, MCPOpenCode, MCPCrush:
	default:
		return AgentSpec{}, fmt.Errorf("unknown mcp_format %q", d.MCPFormat)
	}
	if strings.ContainsAny(d.Command+d.Verify, "\n\r\x00") {
		return AgentSpec{}, fmt.Errorf("command and verify must be single lines")
	}
	name := d.Name
	if name == "" {
		name = d.ID
	}
	return AgentSpec{
		ID:             d.ID,
		DisplayName:    name,
		Description:    d.Description,
		RequiresNode:   d.Node,
		SystemPackages: d.Apt,
		InstallSteps:   d.Install,
		Command:        d.Command,
		VerifyCommand:  d.Verify,
		Domains:        d.Domains,
		EnvHints:       d.Env,
		MCPFormat:      d.MCPFormat,
		LocalModels:    d.LocalModels,
		Custom:         true,
	}, nil
}
