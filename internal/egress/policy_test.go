package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
)

func mustCompile(t *testing.T, cfg Config) *Policy {
	t.Helper()
	p, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

func TestAllowlistMatching(t *testing.T) {
	p := mustCompile(t, Config{Allow: []string{"api.anthropic.com", "*.githubusercontent.com"}})
	cases := map[string]bool{
		"api.anthropic.com":                  true,
		"API.Anthropic.COM.":                 true, // case and trailing dot are normalized
		"anthropic.com":                      false,
		"evil-api.anthropic.com":             false,
		"githubusercontent.com":              true, // "*." includes the domain itself
		"raw.githubusercontent.com":          true,
		"a.b.githubusercontent.com":          true,
		"githubusercontent.com.evil.example": false,
		"notgithubusercontent.com":           false,
	}
	for host, want := range cases {
		v := p.Check(SandboxClient, host, 443, "connect")
		if v.Allow != want {
			t.Errorf("Check(%q) allow=%v (%s), want %v", host, v.Allow, v.Reason, want)
		}
	}
}

func TestEmptyAllowlistDeniesEverything(t *testing.T) {
	p := mustCompile(t, Config{})
	if v := p.Check(SandboxClient, "api.anthropic.com", 443, "connect"); v.Allow || v.Reason != ReasonNotAllowlisted {
		t.Errorf("empty allowlist must deny, got %+v", v)
	}
}

func TestPortsAndSchemes(t *testing.T) {
	p := mustCompile(t, Config{Allow: []string{"example.com"}})
	if v := p.Check(SandboxClient, "example.com", 22, "connect"); v.Allow || v.Reason != ReasonPort {
		t.Errorf("CONNECT to port 22 must be refused, got %+v", v)
	}
	if v := p.Check(SandboxClient, "example.com", 80, "http"); !v.Allow {
		t.Errorf("plain HTTP on 80 should be allowed by default, got %+v", v)
	}

	strict := mustCompile(t, Config{Allow: []string{"example.com"}, HTTPSOnly: true})
	if v := strict.Check(SandboxClient, "example.com", 80, "http"); v.Allow || v.Reason != ReasonHTTPSOnly {
		t.Errorf("https_only must refuse plain HTTP, got %+v", v)
	}
}

func TestIPLiteralsAreRefused(t *testing.T) {
	p := mustCompile(t, Config{Allow: []string{"example.com"}})
	for _, h := range []string{"1.1.1.1", "169.254.169.254", "127.0.0.1", "::1", "[2606:4700::1111]"} {
		if v := p.Check(SandboxClient, h, 443, "connect"); v.Allow || v.Reason != ReasonIPLiteral {
			t.Errorf("Check(%q) = %+v, want ip_literal denial", h, v)
		}
	}

	lan := mustCompile(t, Config{AllowPrivate: []string{"10.0.0.0/8"}})
	if v := lan.Check(SandboxClient, "10.1.2.3", 443, "connect"); !v.Allow {
		t.Errorf("an explicitly allowed private range should be reachable by address, got %+v", v)
	}
}

func TestAllowlistRejectsIPEntries(t *testing.T) {
	if _, err := Compile(Config{Allow: []string{"10.0.0.1"}}); err == nil {
		t.Error("an IP address in the allowlist must be rejected")
	}
}

func TestRiskyDestinationsBeatTheAllowlist(t *testing.T) {
	p := mustCompile(t, Config{
		Allow:      []string{"*.aliyuncs.com", "*.amazonaws.com", "pastebin.com"},
		BlockRisky: true,
	})
	cases := map[string]string{
		"oss-cn-beijing.aliyuncs.com":              RiskObjectStorage,
		"probe-bucket.oss-cn-beijing.aliyuncs.com": RiskObjectStorage,
		"my-bucket.s3.us-east-1.amazonaws.com":     RiskObjectStorage,
		"s3-us-west-2.amazonaws.com":               RiskObjectStorage,
		"checkip.amazonaws.com":                    RiskRecon,
		"pastebin.com":                             RiskPaste,
	}
	for host, cat := range cases {
		v := p.Check(SandboxClient, host, 443, "connect")
		if v.Allow || v.Reason != ReasonRisky || v.Category != cat {
			t.Errorf("Check(%q) = %+v, want risky %s", host, v, cat)
		}
	}
	// A model API on the same parent domain stays reachable.
	if v := p.Check(SandboxClient, "dashscope.aliyuncs.com", 443, "connect"); !v.Allow {
		t.Errorf("dashscope.aliyuncs.com should not be treated as object storage, got %+v", v)
	}
	if v := p.Check(SandboxClient, "ec2.us-east-1.amazonaws.com", 443, "connect"); !v.Allow {
		t.Errorf("non-S3 AWS endpoints are not object storage, got %+v", v)
	}
}

func TestAllowRiskyExemptsExactHost(t *testing.T) {
	p := mustCompile(t, Config{
		Allow:      []string{"my-bucket.s3.amazonaws.com", "other.s3.amazonaws.com"},
		BlockRisky: true,
		AllowRisky: []string{"my-bucket.s3.amazonaws.com"},
	})
	if v := p.Check(SandboxClient, "my-bucket.s3.amazonaws.com", 443, "connect"); !v.Allow {
		t.Errorf("allow_risky host should be reachable, got %+v", v)
	}
	if v := p.Check(SandboxClient, "other.s3.amazonaws.com", 443, "connect"); v.Allow {
		t.Error("the exemption must not extend to other buckets")
	}
}

func TestRiskCategoryDoesNotOvermatch(t *testing.T) {
	for _, h := range []string{"api.anthropic.com", "github.com", "registry.npmjs.org", "s3cret.example.com", "ossify.aliyuncs.com"} {
		if cat, ok := RiskCategory(h); ok {
			t.Errorf("RiskCategory(%q) = %s, want none", h, cat)
		}
	}
}

func TestIsPublic(t *testing.T) {
	notPublic := []string{
		"127.0.0.1", "10.0.0.5", "172.17.0.1", "192.168.1.1", "169.254.169.254",
		"100.100.100.100", "0.0.0.0", "255.255.255.255", "224.0.0.1",
		"::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1",
	}
	for _, s := range notPublic {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("IsPublic(%s) = true, want false", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "140.82.112.3", "2606:4700::1111"} {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("IsPublic(%s) = false, want true", s)
		}
	}
}

func TestAllowedIP(t *testing.T) {
	p := mustCompile(t, Config{AllowPrivate: []string{"172.30.0.0/16"}})
	if p.AllowedIP(net.ParseIP("127.0.0.1")) {
		t.Error("loopback must not be dialable")
	}
	if p.AllowedIP(net.ParseIP("169.254.169.254")) {
		t.Error("the cloud metadata address must not be dialable")
	}
	if !p.AllowedIP(net.ParseIP("172.30.4.5")) {
		t.Error("an allowed private range should be dialable")
	}
	if !p.AllowedIP(net.ParseIP("8.8.8.8")) {
		t.Error("public addresses should be dialable")
	}
}

func TestClientsHaveTheirOwnAllowlist(t *testing.T) {
	sum := sha256.Sum256([]byte("gateway-secret"))
	p := mustCompile(t, Config{
		Allow: []string{"api.anthropic.com"},
		Clients: []Client{{
			Name:        "gateway",
			TokenSHA256: hex.EncodeToString(sum[:]),
			Allow:       []string{"github.com"},
		}},
	})

	name, ok := p.Authenticate("gateway-secret")
	if !ok || name != "gateway" {
		t.Fatalf("Authenticate(valid) = %q, %v", name, ok)
	}
	if _, ok := p.Authenticate("wrong"); ok {
		t.Error("a wrong token must not authenticate")
	}
	if name, ok := p.Authenticate(""); !ok || name != SandboxClient {
		t.Errorf("no token should mean the sandbox, got %q %v", name, ok)
	}

	if !p.Check("gateway", "github.com", 443, "connect").Allow {
		t.Error("gateway should reach github.com")
	}
	if p.Check(SandboxClient, "github.com", 443, "connect").Allow {
		t.Error("the sandbox must not inherit the gateway's allowlist")
	}
	if p.Check("gateway", "api.anthropic.com", 443, "connect").Allow {
		t.Error("the gateway gets its own list, not the sandbox's")
	}
}

func TestCompileRejectsBadClients(t *testing.T) {
	bad := []Config{
		{Clients: []Client{{Name: "", TokenSHA256: "00"}}},
		{Clients: []Client{{Name: SandboxClient, TokenSHA256: "00"}}},
		{Clients: []Client{{Name: "gw", TokenSHA256: "not-hex"}}},
		{AllowPrivate: []string{"not-a-cidr"}},
	}
	for i, cfg := range bad {
		if _, err := Compile(cfg); err == nil {
			t.Errorf("case %d: Compile succeeded, want error", i)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	good := map[string]string{
		"Example.COM.": "example.com",
		"[::1]":        "::1",
		"10.0.0.1":     "10.0.0.1",
	}
	for in, want := range good {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "exa mple.com", "evil.com\nx", ".leading.com", "a..b.com", "under_score.com"} {
		if _, err := NormalizeHost(in); err == nil {
			t.Errorf("NormalizeHost(%q) should fail", in)
		}
	}
}
