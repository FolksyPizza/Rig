package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validProfile() Profile {
	return Profile{
		Version:     1,
		Name:        "test-sandbox",
		Agents:      []AgentConfig{{ID: "claude-code"}},
		Tools:       []string{"git", "ripgrep"},
		Network:     NetworkConfig{Mode: "unrestricted"},
		Commands:    CommandsConfig{Mode: "unrestricted"},
		Resources:   ResourcesConfig{CPU: 2, Memory: 4096, PIDLimit: 512},
		Storage:     StorageConfig{Size: "10g"},
		Persistence: "ephemeral",
	}
}

func TestValidateAcceptsGoodProfile(t *testing.T) {
	p := validProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateRejectsBadProfiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"empty name", func(p *Profile) { p.Name = "" }},
		{"traversing name", func(p *Profile) { p.Name = "../../evil" }},
		{"no agents", func(p *Profile) { p.Agents = nil }},
		{"unknown agent", func(p *Profile) { p.Agents = []AgentConfig{{ID: "not-a-real-agent"}} }},
		{"bad network mode", func(p *Profile) { p.Network.Mode = "wide-open" }},
		{"injected domain", func(p *Profile) {
			p.Network.AllowedDomains = []string{"x.com\nhttp_access allow all"}
		}},
		{"bad commands mode", func(p *Profile) { p.Commands.Mode = "whatever" }},
		{"bad persistence", func(p *Profile) { p.Persistence = "forever" }},
		{"cpu too low", func(p *Profile) { p.Resources.CPU = 0.1 }},
		{"memory too low", func(p *Profile) { p.Resources.Memory = 128 }},
		// 0 and -1 mean "unlimited" to Docker, silently removing the fork-bomb
		// protection the profile appears to configure.
		{"unlimited pids via zero", func(p *Profile) { p.Resources.PIDLimit = 0 }},
		{"unlimited pids via negative", func(p *Profile) { p.Resources.PIDLimit = -1 }},
		{"bad storage size", func(p *Profile) { p.Storage.Size = "lots" }},
		{"injected tool", func(p *Profile) { p.Tools = []string{"git\nRUN evil"} }},
		{"docker socket mount", func(p *Profile) {
			p.Mounts = []MountConfig{{Source: "/var/run/docker.sock", Target: "/docker.sock"}}
		}},
		{"root mount", func(p *Profile) {
			p.Mounts = []MountConfig{{Source: "/", Target: "/host"}}
		}},
		{"relative mount", func(p *Profile) {
			p.Mounts = []MountConfig{{Source: "../..", Target: "/host"}}
		}},
		{"bad volume name", func(p *Profile) {
			p.Storage.Volumes = []VolumeMount{{Name: "../evil", Target: "/data"}}
		}},
		{"duplicate volume", func(p *Profile) {
			p.Storage.Volumes = []VolumeMount{
				{Name: "data", Target: "/data"},
				{Name: "data", Target: "/data2"},
			}
		}},
		{"volume over root", func(p *Profile) {
			p.Storage.Volumes = []VolumeMount{{Name: "data", Target: "/"}}
		}},
		{"gpu not implemented", func(p *Profile) { p.GPU.Enabled = true }},
		{"bad env var name", func(p *Profile) {
			p.Agents = []AgentConfig{{ID: "claude-code", Env: map[string]string{"A=B": "x"}}}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			tc.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}

func TestBuiltinTemplatesAreValid(t *testing.T) {
	for _, tmpl := range BuiltinTemplates() {
		p := tmpl.Profile
		p.Name = tmpl.Name
		if err := p.Validate(); err != nil {
			t.Errorf("template %q is invalid: %v", tmpl.Name, err)
		}
	}
}

func TestImportRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: filepath.Join(dir, "profiles")}
	if err := os.MkdirAll(store.dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A shared profile file is untrusted input. Without name validation this
	// would write outside the profiles directory.
	evil := `version: 1
name: ../../../../tmp/rig-escaped
agents:
  - id: claude-code
tools: [git]
network: {mode: unrestricted}
commands: {mode: unrestricted}
resources: {cpu: 2, memory: 4096, pids_limit: 512}
storage: {size: 10g}
persistence: ephemeral
`
	path := filepath.Join(dir, "evil.yaml")
	if err := os.WriteFile(path, []byte(evil), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Import(path); err == nil {
		t.Fatal("Import() = nil, want error for traversing profile name")
	}
	if _, err := os.Stat("/tmp/rig-escaped.yaml"); err == nil {
		t.Fatal("import wrote a file outside the profiles directory")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir}

	p := validProfile()
	if err := store.Save(&p); err != nil {
		t.Fatalf("Save() = %v", err)
	}

	// Profiles can hold API keys once resolved; the file must not be readable
	// by other users on the machine.
	info, err := os.Stat(filepath.Join(dir, "test-sandbox.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("profile file mode = %o, want 600", perm)
	}

	got, err := store.Load("test-sandbox")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if got.Name != p.Name || got.Resources.CPU != p.Resources.CPU {
		t.Errorf("round trip mismatch: got %+v", got)
	}

	names, err := store.List()
	if err != nil || len(names) != 1 || names[0] != "test-sandbox" {
		t.Errorf("List() = %v, %v", names, err)
	}

	if err := store.Delete("test-sandbox"); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if store.Exists("test-sandbox") {
		t.Error("profile still exists after delete")
	}
}

func TestStoreLoadRejectsTraversal(t *testing.T) {
	store := &Store{dir: t.TempDir()}
	if _, err := store.Load("../../etc/passwd"); err == nil {
		t.Error("Load() = nil, want error for traversing name")
	}
}

func TestExportOmitsResolvedSecrets(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir}

	t.Setenv("ANTHROPIC_API_KEY", "sk-secret-value")
	p := validProfile()
	p.Agents = []AgentConfig{{ID: "claude-code", Env: map[string]string{
		"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
	}}}

	out := filepath.Join(dir, "exported.yaml")
	if err := store.Export(&p, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk-secret-value") {
		t.Error("export wrote the resolved secret value to disk")
	}
	if !strings.Contains(string(data), "${ANTHROPIC_API_KEY}") {
		t.Error("export should keep the ${VAR} reference")
	}
}

func TestResolveEnvVars(t *testing.T) {
	t.Setenv("RIG_TEST_KEY", "resolved")
	got := ResolveEnvVars(map[string]string{
		"A": "${RIG_TEST_KEY}",
		"B": "literal",
		"C": "${RIG_TEST_UNSET}",
		"D": "${incomplete",
		"E": "not${a}ref",
	})
	want := map[string]string{
		"A": "resolved",
		"B": "literal",
		"C": "",
		"D": "${incomplete",
		"E": "not${a}ref",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ResolveEnvVars()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestMissingEnvVars(t *testing.T) {
	t.Setenv("RIG_SET", "yes")
	os.Unsetenv("RIG_UNSET")
	p := validProfile()
	p.Agents = []AgentConfig{{ID: "claude-code", Env: map[string]string{
		"SET":   "${RIG_SET}",
		"UNSET": "${RIG_UNSET}",
	}}}
	missing := MissingEnvVars(&p)
	if len(missing) != 1 || missing[0] != "RIG_UNSET" {
		t.Errorf("MissingEnvVars() = %v, want [RIG_UNSET]", missing)
	}
}

func TestCommandAllowed(t *testing.T) {
	p := validProfile()
	if !p.CommandAllowed([]string{"anything"}) {
		t.Error("unrestricted mode should allow any command")
	}

	p.Commands = CommandsConfig{Mode: "allowlist", Allowed: []string{"ls", "cat"}}
	if !p.CommandAllowed([]string{"ls", "-la"}) {
		t.Error("ls should be allowed")
	}
	if p.CommandAllowed([]string{"rm", "-rf", "/"}) {
		t.Error("rm should not be allowed")
	}
	if p.CommandAllowed(nil) {
		t.Error("empty argv should not be allowed")
	}
}

func TestImageTag(t *testing.T) {
	p := validProfile()
	if got := p.ImageTag(); got != "rig/test-sandbox:latest" {
		t.Errorf("ImageTag() = %q", got)
	}
	p.Metadata.ImageTag = "custom:tag"
	if got := p.ImageTag(); got != "custom:tag" {
		t.Errorf("ImageTag() = %q, want the explicit tag", got)
	}
}
