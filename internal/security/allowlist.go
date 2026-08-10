package security

import (
	"fmt"
	"strings"
)

// SquidDomain converts a Rig allowlist entry into Squid dstdomain syntax.
//
// Rig accepts "*.example.com" for "example.com and all subdomains", which is
// how most allowlist UIs spell it. Squid spells the same thing ".example.com";
// a literal "*.example.com" is treated as an ordinary hostname and therefore
// never matches anything. A bare "example.com" stays an exact-host match.
func SquidDomain(domain string) string {
	if rest, ok := strings.CutPrefix(domain, "*."); ok {
		return "." + rest
	}
	return domain
}

// GenerateSquidConfig renders the egress-filtering proxy configuration for a
// sandbox. Every domain must already have passed ValidateDomain; passing an
// invalid one is a programming error and is reported rather than written out,
// because the entries are interpolated into the config file verbatim.
//
// The policy is fail-closed: the final rule is "http_access deny all", so an
// empty allowlist blocks all egress rather than allowing it.
func GenerateSquidConfig(domains []string) (string, error) {
	if err := ValidateDomains(domains); err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("# Rig sandbox egress allowlist — generated file, do not edit.\n")
	sb.WriteString("# Policy is fail-closed: anything not explicitly allowed is denied.\n\n")

	sb.WriteString("acl SSL_ports port 443\n")
	sb.WriteString("acl Safe_ports port 80\n")
	sb.WriteString("acl Safe_ports port 443\n")
	sb.WriteString("acl CONNECT method CONNECT\n\n")

	sb.WriteString("http_access deny !Safe_ports\n")
	sb.WriteString("http_access deny CONNECT !SSL_ports\n\n")

	if len(domains) > 0 {
		sb.WriteString("acl allowed_domains dstdomain")
		for _, d := range domains {
			sb.WriteString(" " + SquidDomain(d))
		}
		sb.WriteString("\n")
		sb.WriteString("http_access allow allowed_domains\n")
	}

	sb.WriteString("http_access deny all\n\n")

	sb.WriteString("http_port 3128\n")
	sb.WriteString("cache deny all\n")
	// Squid in the proxy image cannot open /dev/stdout for access_log and
	// exits at startup if asked to, so only cache_log is redirected; that is
	// enough for `docker logs` to show why a proxy failed to come up.
	sb.WriteString("cache_log stdio:/dev/stderr\n")
	sb.WriteString("coredump_dir /var/spool/squid\n")
	sb.WriteString("forwarded_for delete\n")
	sb.WriteString("via off\n")
	sb.WriteString("httpd_suppress_version_string on\n")

	return sb.String(), nil
}

// DescribeAllowlist renders a short human-readable summary of what a generated
// allowlist actually permits, for display before a sandbox launches.
func DescribeAllowlist(domains []string) string {
	if len(domains) == 0 {
		return "no domains allowed (all egress blocked)"
	}
	return fmt.Sprintf("%d domain(s) allowed, all other egress blocked", len(domains))
}
