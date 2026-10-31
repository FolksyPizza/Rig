package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/FolksyPizza/rig/internal/config"
)

func TestMain(m *testing.M) {
	os.Setenv("RIG_AGENTS_DIR", "/nonexistent")
	os.Exit(m.Run())
}

func has(fs []Finding, sev Severity, substr string) bool {
	for _, f := range fs {
		if f.Severity == sev && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

func TestUnrestrictedNetworkIsHigh(t *testing.T) {
	tmpl, _ := config.GetTemplate("claude-dev")
	p := tmpl.Profile
	fs := Check(&p)
	if !has(fs, High, "any address on the internet") {
		t.Errorf("unrestricted network should be a high finding: %+v", fs)
	}
	if !has(fs, Medium, "passwordless sudo") {
		t.Error("sudo should be reported")
	}
	if Worst(fs) != High || fs[0].Severity != High {
		t.Error("findings must be sorted most severe first")
	}
}

func TestStandardTemplateHasNoHighFindings(t *testing.T) {
	tmpl, _ := config.GetTemplate("standard")
	p := tmpl.Profile
	for _, f := range Check(&p) {
		if f.Severity == High {
			t.Errorf("the recommended template should have no high findings: %+v", f)
		}
	}
}

func TestBlenderExecuteCode(t *testing.T) {
	tmpl, _ := config.GetTemplate("blender")
	p := tmpl.Profile
	if has(Check(&p), High, "execute_blender_code") {
		t.Error("the template blocks execute_blender_code and should not be flagged")
	}
	p.MCP.Servers[0].DenyTools = nil
	if !has(Check(&p), High, "execute_blender_code") {
		t.Error("allowing execute_blender_code must be a high finding")
	}
}

func TestBroadWildcardsAndTokens(t *testing.T) {
	p := config.DefaultProfile("claude-code")
	p.Name = "x"
	p.Network.AllowedDomains = []string{"*.amazonaws.com", "pastebin.com"}
	p.Agents[0].Env = map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}
	p.Mounts = []config.MountConfig{{Source: "/srv/code", Target: "/code"}}
	fs := Check(&p)
	for _, want := range []struct {
		sev Severity
		s   string
	}{
		{Medium, "*.amazonaws.com covers sites anyone can create"},
		{Low, "pastebin.com is a known paste service"},
		{Medium, "GITHUB_TOKEN is given to the agent directly"},
		{Medium, "can change files in /srv/code"},
		{Low, ".git/hooks is writable"},
	} {
		if !has(fs, want.sev, want.s) {
			t.Errorf("missing %s finding %q in %+v", want.sev, want.s, fs)
		}
	}
}

func TestLockdownTemplate(t *testing.T) {
	tmpl, _ := config.GetTemplate("lockdown")
	p := tmpl.Profile
	fs := Check(&p)
	if !has(fs, Info, "will not start without one") {
		t.Errorf("lockdown should explain its isolation requirement: %+v", fs)
	}
	for _, f := range fs {
		if f.Severity >= Medium {
			t.Errorf("lockdown template should have nothing above low: %+v", f)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high"} {
		v, ok := ParseSeverity(s)
		if !ok || v.String() != s {
			t.Errorf("round trip %s failed", s)
		}
	}
	if _, ok := ParseSeverity("severe"); ok {
		t.Error("unknown severity accepted")
	}
}
