package main

import (
	"testing"

	"github.com/FolksyPizza/rig/internal/config"
)

func TestParseMegabytes(t *testing.T) {
	for in, want := range map[string]int64{"4g": 4096, "4G": 4096, "512m": 512, "2048": 2048, "1.5g": 1536, "8gb": 8192} {
		got, err := parseMegabytes(in)
		if err != nil || got != want {
			t.Errorf("parseMegabytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "lots", "-1g", "0"} {
		if _, err := parseMegabytes(bad); err == nil {
			t.Errorf("parseMegabytes(%q) should fail", bad)
		}
	}
	if formatMegabytes(4096) != "4g" || formatMegabytes(1536) != "1536m" {
		t.Error("formatMegabytes")
	}
}

func TestSettingsApplyAndValidate(t *testing.T) {
	p := config.DefaultProfile("codex")
	p.Name = "x"
	for kv, check := range map[[2]string]func() bool{
		{"cpu", "3.5"}:          func() bool { return p.Resources.CPU == 3.5 },
		{"memory", "8g"}:        func() bool { return p.Resources.Memory == 8192 },
		{"pids", "1024"}:        func() bool { return p.Resources.PIDLimit == 1024 },
		{"permissions", "full"}: func() bool { return p.Security.AgentPermissions == "full" },
		{"timeout", "2h"}:       func() bool { return p.Metadata.Timeout.Hours() == 2 },
		{"commands", "git,ls"}:  func() bool { return p.Commands.Mode == "allowlist" && len(p.Commands.Allowed) == 2 },
		{"agents", "codex,pi"}:  func() bool { return len(p.Agents) == 2 },
	} {
		s, ok := findSetting(kv[0])
		if !ok {
			t.Fatalf("no setting %s", kv[0])
		}
		if err := s.apply(&p, kv[1]); err != nil || !check() {
			t.Errorf("%s=%s: err %v, profile %+v", kv[0], kv[1], err, p)
		}
	}
	if err := p.Validate(); err != nil {
		t.Errorf("profile should be valid: %v", err)
	}
}

func TestApplyLevelLockdownTightens(t *testing.T) {
	p := config.DefaultProfile("codex")
	p.Name = "x"
	p.Security.Sudo = true
	p.Security.AgentPermissions = config.PermissionsFull
	p.Mounts = []config.MountConfig{{Source: "/srv/code", Target: "/home/sandbox/code"}}
	if err := applyLevel(&p, config.LevelLockdown, false, false); err != nil {
		t.Fatal(err)
	}
	if p.Persistence != "ephemeral" || p.Security.Sudo || p.Security.AgentPermissions != config.PermissionsEdit || !p.Mounts[0].ReadOnly {
		t.Errorf("lockdown left something looser than it allows: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("profile should be valid at lockdown: %v", err)
	}
	if err := applyLevel(&p, "paranoid", false, false); err == nil {
		t.Error("unknown level accepted")
	}
}

func TestRunFromNeutralTemplatePicksAnAgent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "sk-test")
	store, err := config.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	p, err := createFromTemplate(store, "lockdown", "safe")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Agents) != 1 || p.Agents[0].ID != "codex" || p.Agents[0].Env["OPENAI_API_KEY"] != "${OPENAI_API_KEY}" {
		t.Errorf("agents: %+v", p.Agents)
	}
	t.Setenv("OPENAI_API_KEY", "")
	if _, err := createFromTemplate(store, "standard", "none"); err == nil {
		t.Error("without --agent or an API key, creating from a neutral template should ask for an agent")
	}
}
