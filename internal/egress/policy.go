// Package egress implements Rig's outbound filtering proxy.
//
// The proxy is the only route from a sandbox to the network. It decides each
// request against a domain allowlist, refuses known exfiltration destinations,
// refuses anything that resolves to a private, loopback, link-local or
// metadata address, checks that a TLS client's server name matches the host it
// asked to reach, and writes one JSON line per decision so the host-side
// monitor can react.
//
// The package uses only the standard library: it is compiled into the
// rig-helper binary inside an image build, where third-party modules are not
// available.
package egress

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Config is the proxy's on-disk configuration. Rig generates it from a
// profile; the proxy reloads it on SIGHUP.
type Config struct {
	Listen string `json:"listen,omitempty"`

	// Allow lists the domains the sandbox may reach. "*.example.com" means
	// example.com and every subdomain; anything else is an exact host.
	Allow []string `json:"allow,omitempty"`

	// BlockRisky refuses known exfiltration and reconnaissance destinations
	// even when an allowlist entry matches them.
	BlockRisky bool `json:"block_risky"`
	// AllowRisky exempts exact hosts from BlockRisky.
	AllowRisky []string `json:"allow_risky,omitempty"`

	// HTTPSOnly refuses plain-HTTP requests.
	HTTPSOnly bool `json:"https_only"`
	// RequireSNI refuses a tunnel unless the client opens it with a TLS
	// ClientHello whose server name equals the host it asked to reach. This
	// stops a client from tunnelling to an allowed name and then talking to a
	// different site behind the same address.
	RequireSNI bool `json:"require_sni"`

	// ConnectPorts and HTTPPorts restrict destination ports. Defaults: 443 and 80.
	ConnectPorts []int `json:"connect_ports,omitempty"`
	HTTPPorts    []int `json:"http_ports,omitempty"`

	// AllowPrivate lists CIDR ranges that may be reached even though they are
	// private. Empty by default: the host, the LAN and cloud metadata
	// endpoints are unreachable.
	AllowPrivate []string `json:"allow_private,omitempty"`

	// MaxUploadBytes, if positive, closes any single connection that sends
	// more than this many bytes upstream.
	MaxUploadBytes int64 `json:"max_upload_bytes,omitempty"`

	// MaxConns caps concurrent connections. Default 512.
	MaxConns int `json:"max_conns,omitempty"`

	// Clients are callers that authenticate with a token (Proxy-Authorization)
	// and get their own allowlist instead of the sandbox's. Rig's gateway uses
	// this so the MCP servers and git broker it hosts can reach what they need
	// without widening what the sandbox itself can reach.
	Clients []Client `json:"clients,omitempty"`
}

// Client is a token-authenticated proxy caller.
type Client struct {
	Name string `json:"name"`
	// TokenSHA256 is the hex SHA-256 of the client's token. The token itself
	// never appears in the configuration file.
	TokenSHA256 string   `json:"token_sha256"`
	Allow       []string `json:"allow,omitempty"`
}

// Reasons recorded with each decision. The monitor keys its rules on these
// strings, so they are part of the log format.
const (
	ReasonAllowed        = "allowed"
	ReasonNotAllowlisted = "not_allowlisted"
	ReasonRisky          = "risky_destination"
	ReasonIPLiteral      = "ip_literal"
	ReasonPrivate        = "private_address"
	ReasonPort           = "port_not_allowed"
	ReasonHTTPSOnly      = "https_only"
	ReasonSNIMismatch    = "sni_mismatch"
	ReasonNoSNI          = "no_sni"
	ReasonResolve        = "resolve_failed"
	ReasonUpstream       = "upstream_failed"
	ReasonBadRequest     = "bad_request"
	ReasonUploadLimit    = "upload_limit"
	ReasonAuth           = "auth_failed"
	ReasonBusy           = "too_many_connections"
)

// SandboxClient is the identity of unauthenticated callers.
const SandboxClient = "sandbox"

// Verdict is the policy's answer for one destination.
type Verdict struct {
	Allow    bool
	Reason   string
	Category string // risk category, when Reason is ReasonRisky
}

// Policy is a compiled Config.
type Policy struct {
	cfg          Config
	allow        matcher
	riskExempt   map[string]bool
	privateOK    []netip.Prefix
	connectPorts map[int]bool
	httpPorts    map[int]bool
	clients      []compiledClient
}

type compiledClient struct {
	name  string
	hash  []byte
	allow matcher
}

// Compile validates a configuration and prepares it for lookups.
func Compile(cfg Config) (*Policy, error) {
	p := &Policy{cfg: cfg, riskExempt: map[string]bool{}}

	var err error
	if p.allow, err = newMatcher(cfg.Allow); err != nil {
		return nil, err
	}
	for _, h := range cfg.AllowRisky {
		n, err := NormalizeHost(h)
		if err != nil {
			return nil, fmt.Errorf("allow_risky: %w", err)
		}
		p.riskExempt[n] = true
	}
	for _, c := range cfg.AllowPrivate {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("allow_private: %q is not a CIDR range", c)
		}
		p.privateOK = append(p.privateOK, pfx.Masked())
	}

	p.connectPorts = portSet(cfg.ConnectPorts, 443)
	p.httpPorts = portSet(cfg.HTTPPorts, 80)

	seen := map[string]bool{}
	for _, c := range cfg.Clients {
		if c.Name == "" || c.Name == SandboxClient {
			return nil, fmt.Errorf("client name %q is reserved or empty", c.Name)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("duplicate client %q", c.Name)
		}
		seen[c.Name] = true
		h, err := hex.DecodeString(c.TokenSHA256)
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("client %q: token_sha256 must be 64 hex characters", c.Name)
		}
		m, err := newMatcher(c.Allow)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", c.Name, err)
		}
		p.clients = append(p.clients, compiledClient{name: c.Name, hash: h, allow: m})
	}
	return p, nil
}

func portSet(ports []int, def int) map[int]bool {
	m := map[int]bool{}
	if len(ports) == 0 {
		m[def] = true
	}
	for _, p := range ports {
		m[p] = true
	}
	return m
}

// Config returns the configuration the policy was compiled from.
func (p *Policy) Config() Config { return p.cfg }

// Authenticate maps a presented token to a client name. An empty token is the
// sandbox. ok is false when a token was presented but matches no client.
func (p *Policy) Authenticate(token string) (name string, ok bool) {
	if token == "" {
		return SandboxClient, true
	}
	sum := sha256.Sum256([]byte(token))
	for _, c := range p.clients {
		if subtle.ConstantTimeCompare(sum[:], c.hash) == 1 {
			return c.name, true
		}
	}
	return "", false
}

// Check decides whether client may open a connection to host:port.
// scheme is "connect" for tunnels and "http" for plain proxied requests.
// The host must still be resolved and vetted with AllowedIP before dialing.
func (p *Policy) Check(client, host string, port int, scheme string) Verdict {
	h, err := NormalizeHost(host)
	if err != nil {
		return Verdict{Reason: ReasonBadRequest}
	}

	switch scheme {
	case "connect":
		if !p.connectPorts[port] {
			return Verdict{Reason: ReasonPort}
		}
	case "http":
		if p.cfg.HTTPSOnly {
			return Verdict{Reason: ReasonHTTPSOnly}
		}
		if !p.httpPorts[port] {
			return Verdict{Reason: ReasonPort}
		}
	default:
		return Verdict{Reason: ReasonBadRequest}
	}

	// A literal address bypasses every name-based rule, so it is refused
	// unless it falls in an explicitly allowed private range.
	if addr, err := netip.ParseAddr(h); err == nil {
		if p.privateAllowed(addr) {
			return Verdict{Allow: true, Reason: ReasonAllowed}
		}
		return Verdict{Reason: ReasonIPLiteral}
	}

	if p.cfg.BlockRisky && !p.riskExempt[h] {
		if cat, ok := RiskCategory(h); ok {
			return Verdict{Reason: ReasonRisky, Category: cat}
		}
	}

	if !p.allowlistFor(client).match(h) {
		return Verdict{Reason: ReasonNotAllowlisted}
	}
	return Verdict{Allow: true, Reason: ReasonAllowed}
}

func (p *Policy) allowlistFor(client string) matcher {
	for _, c := range p.clients {
		if c.name == client {
			return c.allow
		}
	}
	return p.allow
}

// AllowedIP reports whether a resolved address may be dialed.
func (p *Policy) AllowedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !IsPublic(addr) {
		return p.privateAllowed(addr)
	}
	return true
}

func (p *Policy) privateAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, pfx := range p.privateOK {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// nonPublic lists ranges that are not reachable public internet addresses.
// Go's IsPrivate/IsLoopback cover the common cases; these cover the rest.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (also Tailscale)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, includes broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: maps onto IPv4, including private space
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4: can embed private IPv4
	netip.MustParsePrefix("2001::/32"),       // Teredo
}

// IsPublic reports whether addr is a globally routable unicast address.
// Loopback, private, link-local (including the 169.254.169.254 cloud metadata
// address), multicast, unspecified and reserved ranges are not.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, pfx := range nonPublic {
		if pfx.Contains(addr) {
			return false
		}
	}
	return true
}

// NormalizeHost lowercases a hostname and strips a trailing dot. It rejects
// anything that could not be a DNS name or an IP literal.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if h == "" || len(h) > 253 {
		return "", fmt.Errorf("invalid host %q", host)
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return h, nil
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return "", fmt.Errorf("invalid host %q", host)
		}
	}
	if strings.HasPrefix(h, ".") || strings.Contains(h, "..") {
		return "", fmt.Errorf("invalid host %q", host)
	}
	return h, nil
}

// matcher implements the allowlist: exact hosts plus "*.domain" entries that
// match the domain and all of its subdomains.
type matcher struct {
	exact  map[string]bool
	suffix []string
}

func newMatcher(entries []string) (matcher, error) {
	m := matcher{exact: map[string]bool{}}
	for _, e := range entries {
		wild := strings.HasPrefix(e, "*.")
		n, err := NormalizeHost(strings.TrimPrefix(e, "*."))
		if err != nil {
			return m, fmt.Errorf("allowlist entry %q: %w", e, err)
		}
		if _, err := netip.ParseAddr(n); err == nil {
			return m, fmt.Errorf("allowlist entry %q is an IP address; list domains instead", e)
		}
		if wild {
			m.suffix = append(m.suffix, n)
		} else {
			m.exact[n] = true
		}
	}
	return m, nil
}

func (m matcher) match(host string) bool {
	if m.exact[host] {
		return true
	}
	for _, s := range m.suffix {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
