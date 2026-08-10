package security

import (
	"strings"
	"testing"
)

func TestSquidDomainTranslatesWildcard(t *testing.T) {
	// Squid spells "this host and its subdomains" as ".example.com".
	// A literal "*.example.com" is treated as an ordinary hostname and would
	// silently match nothing, quietly breaking the allowlist entry.
	cases := map[string]string{
		"*.githubusercontent.com": ".githubusercontent.com",
		"*.example.com":           ".example.com",
		"api.anthropic.com":       "api.anthropic.com",
		"github.com":              "github.com",
	}
	for in, want := range cases {
		if got := SquidDomain(in); got != want {
			t.Errorf("SquidDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateSquidConfigIsFailClosed(t *testing.T) {
	conf, err := GenerateSquidConfig(nil)
	if err != nil {
		t.Fatalf("GenerateSquidConfig(nil) = %v", err)
	}
	if !strings.Contains(conf, "http_access deny all") {
		t.Error("config must deny all traffic by default")
	}
	if strings.Contains(conf, "http_access allow") {
		t.Error("an empty allowlist must not allow anything")
	}
}

func TestGenerateSquidConfigAllowsListedDomains(t *testing.T) {
	conf, err := GenerateSquidConfig([]string{"api.anthropic.com", "*.githubusercontent.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(conf, "acl allowed_domains dstdomain api.anthropic.com .githubusercontent.com") {
		t.Errorf("unexpected acl line in:\n%s", conf)
	}
	if !strings.Contains(conf, "http_access allow allowed_domains") {
		t.Error("expected an allow rule for the listed domains")
	}

	// The deny-all rule must come last, or it would shadow the allow rule.
	allowIdx := strings.Index(conf, "http_access allow allowed_domains")
	denyIdx := strings.Index(conf, "http_access deny all")
	if allowIdx < 0 || denyIdx < 0 || denyIdx < allowIdx {
		t.Errorf("deny all must follow the allow rule, got allow=%d deny=%d", allowIdx, denyIdx)
	}
}

func TestGenerateSquidConfigRejectsInjection(t *testing.T) {
	_, err := GenerateSquidConfig([]string{"evil.com\nhttp_access allow all"})
	if err == nil {
		t.Fatal("expected an error for a domain containing a newline")
	}
}

func TestGenerateSquidConfigLineCount(t *testing.T) {
	// Every domain must stay on the single acl line; a stray newline would
	// mean an injected directive slipped through validation.
	conf, err := GenerateSquidConfig([]string{"a.com", "b.com", "c.com"})
	if err != nil {
		t.Fatal(err)
	}
	acl := 0
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "acl allowed_domains") {
			acl++
		}
	}
	if acl != 1 {
		t.Errorf("expected exactly 1 allowed_domains line, got %d", acl)
	}
}
