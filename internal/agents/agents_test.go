package agents

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuiltinsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range builtins() {
		if !idRe.MatchString(a.ID) {
			t.Errorf("agent id %q is not a valid id", a.ID)
		}
		if seen[a.ID] {
			t.Errorf("duplicate agent id %q", a.ID)
		}
		seen[a.ID] = true
		if a.DisplayName == "" || a.Command == "" {
			t.Errorf("agent %s is missing a display name or command", a.ID)
		}
		steps := a.Steps("")
		if len(steps) == 0 {
			t.Errorf("agent %s has no install steps", a.ID)
		}
		for _, s := range steps {
			if strings.ContainsAny(s, "\n\r") {
				t.Errorf("agent %s has a multi-line install step", a.ID)
			}
		}
		for _, d := range a.Domains {
			if !domainRe.MatchString(d) {
				t.Errorf("agent %s lists invalid domain %q", a.ID, d)
			}
		}
		for _, dep := range a.DependsOn {
			if _, ok := ByID(dep); !ok {
				t.Errorf("agent %s depends on unknown agent %q", a.ID, dep)
			}
		}
	}
	for _, want := range []string{"claude-code", "codex", "gemini-cli", "pi", "opencode", "qwen-code", "crush", "aider", "copilot", "grove"} {
		if !seen[want] {
			t.Errorf("expected built-in agent %q", want)
		}
	}
}

func TestVersionedInstall(t *testing.T) {
	claude, _ := ByID("claude-code")
	if got := claude.Steps("2.1.0"); !strings.Contains(got[0], "'@anthropic-ai/claude-code@2.1.0'") {
		t.Errorf("pinned npm install = %q", got[0])
	}
	if got := claude.Steps(""); strings.Contains(got[0], "@anthropic-ai/claude-code@") {
		t.Errorf("unpinned install should not add a version: %q", got[0])
	}
	aider, _ := ByID("aider")
	if got := aider.Steps("0.80.0"); !strings.Contains(got[0], "'aider-chat==0.80.0'") {
		t.Errorf("pinned pip install = %q", got[0])
	}
	grove, _ := ByID("grove")
	if got := grove.Steps("v0.2.0"); !strings.Contains(got[0], "--branch 'v0.2.0'") {
		t.Errorf("grove ref not used: %q", got[0])
	}
	if got := grove.Steps(""); !strings.Contains(got[0], "--branch 'main'") {
		t.Errorf("grove default ref = %q", got[0])
	}
}

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"1.2.3", "v0.2.0", "latest", "2.1.311", "1.0.0-beta.1", "main"} {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false", v)
		}
	}
	for _, v := range []string{"", "-rf", "1.0; rm -rf /", "a b", "$(id)", "x'y", "a\nb", strings.Repeat("a", 65)} {
		if ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true", v)
		}
	}
}

func TestResolveOrdersDependenciesFirst(t *testing.T) {
	specs, err := Resolve([]string{"grove", "claude-code", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range specs {
		ids = append(ids, s.ID)
	}
	if !reflect.DeepEqual(ids, []string{"codex", "grove", "claude-code"}) {
		t.Errorf("Resolve order = %v", ids)
	}
	if _, err := Resolve([]string{"nope"}); err == nil {
		t.Error("unknown agent should fail")
	}
}

func TestMaxNodeVersion(t *testing.T) {
	specs, _ := Resolve([]string{"aider", "pi"})
	if got := MaxNodeVersion(specs); got != "22" {
		t.Errorf("MaxNodeVersion = %q, want 22", got)
	}
	aider, _ := Resolve([]string{"aider"})
	if got := MaxNodeVersion(aider); got != "" {
		t.Errorf("python-only agent needs no node, got %q", got)
	}
}

func TestProviderDomains(t *testing.T) {
	got := ProviderDomains(map[string]string{
		"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
		"OPENAI_BASE_URL":   "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
		"OTHER_BASE_URL":    "http://rig-gw:11434/v1", // plain http: a local endpoint, no domain
		"REF_BASE_URL":      "${SOME_URL}",
		"UNRELATED":         "https://example.com",
	})
	want := []string{"api.anthropic.com", "dashscope-intl.aliyuncs.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ProviderDomains = %v, want %v", got, want)
	}

	// OPENAI_API_KEY pointed at a local endpoint implies no internet domain.
	local := ProviderDomains(map[string]string{
		"OPENAI_API_KEY":  "ollama",
		"OPENAI_BASE_URL": "http://rig-gw:11434/v1",
	})
	if len(local) != 0 {
		t.Errorf("a key redirected to a local endpoint should allow nothing, got %v", local)
	}
}

func writeCustom(t *testing.T, dir, name, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCustom(t *testing.T) {
	dir := t.TempDir()
	writeCustom(t, dir, "good.yaml", `
id: my-agent
name: My Agent
node: "22"
apt: [ripgrep]
install:
  - npm install -g my-agent-cli
command: my-agent
domains: [api.example.com]
env: [MY_API_KEY]
mcp_format: claude
`, 0o600)
	writeCustom(t, dir, "shadow.yaml", "id: claude-code\ninstall: [\"true\"]\n", 0o600)
	writeCustom(t, dir, "multiline.yaml", "id: bad-one\ninstall:\n  - \"echo a\\nRUN evil\"\n", 0o600)
	writeCustom(t, dir, "unknown-field.yaml", "id: bad-two\ninstall: [\"true\"]\nshell: evil\n", 0o600)
	writeCustom(t, dir, "world-writable.yaml", "id: bad-three\ninstall: [\"true\"]\n", 0o666)

	specs, errs := LoadCustom(dir)
	if len(specs) != 1 || specs[0].ID != "my-agent" || !specs[0].Custom {
		t.Fatalf("expected only my-agent to load, got %+v", specs)
	}
	if specs[0].RequiresNode != "22" || specs[0].MCPFormat != MCPClaude {
		t.Errorf("fields not carried over: %+v", specs[0])
	}
	if len(errs) != 4 {
		t.Errorf("expected 4 errors, got %d: %v", len(errs), errs)
	}

	if s, e := LoadCustom(filepath.Join(dir, "missing")); s != nil || e != nil {
		t.Error("a missing directory is not an error")
	}
}
