package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers from a fixed table.
type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// syncBuffer collects log lines written from server goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) events(t *testing.T) []Event {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	sc := bufio.NewScanner(bytes.NewReader(s.b.Bytes()))
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		out = append(out, e)
	}
	return out
}

// waitFor polls the log until an event matching pred appears.
func (s *syncBuffer) waitFor(t *testing.T, pred func(Event) bool) Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range s.events(t) {
			if pred(e) {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no matching log event; log so far: %+v", s.events(t))
	return Event{}
}

type harness struct {
	proxy    *httptest.Server
	log      *syncBuffer
	upstream *httptest.Server
	port     int
}

// newHarness starts a TLS upstream on loopback that answers as example.com,
// and a proxy whose resolver maps names onto it. Loopback is allowed
// explicitly, the way a real deployment never would, so the tests can stand
// in for the internet.
func newHarness(t *testing.T, cfg Config, names map[string][]string) *harness {
	t.Helper()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "ok %s %d", r.URL.Path, len(body))
	}))
	t.Cleanup(up.Close)
	_, portStr, _ := net.SplitHostPort(up.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg.ConnectPorts = append(cfg.ConnectPorts, port)
	cfg.AllowPrivate = append(cfg.AllowPrivate, "127.0.0.0/8")
	pol := mustCompile(t, cfg)

	log := &syncBuffer{}
	srv := NewServer(pol, log, fakeResolver(names), nil)
	srv.HelloTimeout = 2 * time.Second
	px := httptest.NewServer(srv)
	t.Cleanup(px.Close)
	return &harness{proxy: px, log: log, upstream: up, port: port}
}

func (h *harness) client(t *testing.T, serverName, user, pass string) (*http.Client, *http.Transport) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(h.upstream.Certificate())
	pu, _ := url.Parse(h.proxy.URL)
	if user != "" {
		pu.User = url.UserPassword(user, pass)
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: serverName},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, tr
}

func TestConnectAllowedWithMatchingSNI(t *testing.T) {
	h := newHarness(t, Config{Allow: []string{"example.com"}, RequireSNI: true},
		map[string][]string{"example.com": {"127.0.0.1"}})
	c, tr := h.client(t, "", "", "")

	resp, err := c.Get(fmt.Sprintf("https://example.com:%d/hello", h.port))
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "ok /hello") {
		t.Fatalf("unexpected body %q", body)
	}

	tr.CloseIdleConnections()
	closeEv := h.log.waitFor(t, func(e Event) bool { return e.Phase == "close" })
	if closeEv.Action != "allow" || closeEv.Host != "example.com" || closeEv.SNI != "example.com" {
		t.Errorf("unexpected close event %+v", closeEv)
	}
	if closeEv.BytesUp == 0 || closeEv.BytesDown == 0 {
		t.Errorf("byte counts should be recorded, got up=%d down=%d", closeEv.BytesUp, closeEv.BytesDown)
	}
	if closeEv.IP != "127.0.0.1" {
		t.Errorf("the dialed address should be logged, got %q", closeEv.IP)
	}
}

func TestConnectDeniedForUnlistedHost(t *testing.T) {
	h := newHarness(t, Config{Allow: []string{"example.com"}, RequireSNI: true},
		map[string][]string{"example.com": {"127.0.0.1"}, "unlisted.test": {"127.0.0.1"}})
	c, _ := h.client(t, "", "", "")

	if _, err := c.Get(fmt.Sprintf("https://unlisted.test:%d/", h.port)); err == nil {
		t.Fatal("request to an unlisted host succeeded")
	}
	e := h.log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonNotAllowlisted || e.Host != "unlisted.test" {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func TestConnectDeniedOnSNIMismatch(t *testing.T) {
	// The client asks the proxy for an allowed host, then presents a
	// different server name inside the tunnel.
	h := newHarness(t, Config{Allow: []string{"example.com"}, RequireSNI: true},
		map[string][]string{"example.com": {"127.0.0.1"}})
	c, _ := h.client(t, "elsewhere.test", "", "")

	if _, err := c.Get(fmt.Sprintf("https://example.com:%d/", h.port)); err == nil {
		t.Fatal("request with a mismatched server name succeeded")
	}
	e := h.log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonSNIMismatch || e.SNI != "elsewhere.test" {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func TestConnectDeniedWithoutTLS(t *testing.T) {
	h := newHarness(t, Config{Allow: []string{"example.com"}, RequireSNI: true},
		map[string][]string{"example.com": {"127.0.0.1"}})

	conn, err := net.Dial("tcp", h.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT example.com:%d HTTP/1.1\r\nHost: example.com:%d\r\n\r\n", h.port, h.port)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT not established: %v %v", resp, err)
	}
	// Speak plain text instead of TLS.
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := br.Read(make([]byte, 1)); n != 0 {
		t.Error("a non-TLS tunnel should be closed without reaching upstream")
	}
	e := h.log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonNoSNI {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func TestPrivateResolutionIsRefused(t *testing.T) {
	// An allowlisted name that resolves to the host or LAN must not become a
	// route to it.
	pol := mustCompile(t, Config{Allow: []string{"sneaky.example"}})
	log := &syncBuffer{}
	srv := NewServer(pol, log, fakeResolver{"sneaky.example": {"192.168.1.10", "169.254.169.254"}}, nil)
	px := httptest.NewServer(srv)
	defer px.Close()

	pu, _ := url.Parse(px.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	if _, err := c.Get("https://sneaky.example/"); err == nil {
		t.Fatal("request resolving to a private address succeeded")
	}
	e := log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonPrivate {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func TestRiskyDestinationIsLoggedWithCategory(t *testing.T) {
	pol := mustCompile(t, Config{Allow: []string{"*.aliyuncs.com"}, BlockRisky: true})
	log := &syncBuffer{}
	px := httptest.NewServer(NewServer(pol, log, fakeResolver{}, nil))
	defer px.Close()

	pu, _ := url.Parse(px.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	if _, err := c.Get("https://probe.oss-cn-beijing.aliyuncs.com/upload"); err == nil {
		t.Fatal("request to object storage succeeded")
	}
	e := log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonRisky || e.Category != RiskObjectStorage {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func newPlainHarness(t *testing.T, cfg Config) (*httptest.Server, *syncBuffer, int) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("Proxy-Authorization leaked upstream")
		}
		fmt.Fprintf(w, "plain %s %d", r.URL.Path, len(body))
	}))
	t.Cleanup(up.Close)
	_, portStr, _ := net.SplitHostPort(up.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	cfg.HTTPPorts = append(cfg.HTTPPorts, port)
	cfg.AllowPrivate = append(cfg.AllowPrivate, "127.0.0.0/8")
	log := &syncBuffer{}
	px := httptest.NewServer(NewServer(mustCompile(t, cfg), log, fakeResolver{
		"plain.test": {"127.0.0.1"}, "other.test": {"127.0.0.1"},
	}, nil))
	t.Cleanup(px.Close)
	return px, log, port
}

func TestPlainHTTPForwarding(t *testing.T) {
	px, log, port := newPlainHarness(t, Config{Allow: []string{"plain.test"}})
	pu, _ := url.Parse(px.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}

	resp, err := c.Post(fmt.Sprintf("http://plain.test:%d/p", port), "text/plain", strings.NewReader("12345"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "plain /p 5" {
		t.Fatalf("unexpected body %q", body)
	}
	e := log.waitFor(t, func(e Event) bool { return e.Phase == "close" })
	if e.BytesUp != 5 || e.Method != "POST" {
		t.Errorf("unexpected close event %+v", e)
	}

	resp, err = c.Get(fmt.Sprintf("http://other.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlisted plain-HTTP host returned %d, want 403", resp.StatusCode)
	}
}

func TestPlainHTTPRefusedWhenHTTPSOnly(t *testing.T) {
	px, _, port := newPlainHarness(t, Config{Allow: []string{"plain.test"}, HTTPSOnly: true})
	pu, _ := url.Parse(px.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://plain.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got %d, want 403", resp.StatusCode)
	}
}

func TestUploadLimit(t *testing.T) {
	px, log, port := newPlainHarness(t, Config{Allow: []string{"plain.test"}, MaxUploadBytes: 1024})
	pu, _ := url.Parse(px.URL)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := c.Post(fmt.Sprintf("http://plain.test:%d/", port), "application/octet-stream",
		bytes.NewReader(make([]byte, 64*1024)))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("an upload over the limit was forwarded")
		}
	}
	e := log.waitFor(t, func(e Event) bool { return e.Phase == "deny" })
	if e.Reason != ReasonUploadLimit {
		t.Errorf("unexpected deny event %+v", e)
	}
}

func TestClientTokenSelectsAllowlist(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cr3t"))
	h := newHarness(t, Config{
		Allow:      []string{"sandbox-only.test"},
		RequireSNI: true,
		Clients:    []Client{{Name: "gateway", TokenSHA256: hex.EncodeToString(sum[:]), Allow: []string{"example.com"}}},
	}, map[string][]string{"example.com": {"127.0.0.1"}})

	gw, _ := h.client(t, "", "rig", "s3cr3t")
	resp, err := gw.Get(fmt.Sprintf("https://example.com:%d/", h.port))
	if err != nil {
		t.Fatalf("authenticated client should reach its allowlist: %v", err)
	}
	resp.Body.Close()

	anon, _ := h.client(t, "", "", "")
	if _, err := anon.Get(fmt.Sprintf("https://example.com:%d/", h.port)); err == nil {
		t.Error("the sandbox must not reach the gateway's allowlist")
	}

	bad, _ := h.client(t, "", "rig", "wrong")
	if _, err := bad.Get(fmt.Sprintf("https://example.com:%d/", h.port)); err == nil {
		t.Error("a wrong token must be refused")
	}
	e := h.log.waitFor(t, func(e Event) bool { return e.Reason == ReasonAuth })
	if e.As != "unknown" {
		t.Errorf("unexpected auth event %+v", e)
	}
}

func TestNonProxyRequestsAreRejected(t *testing.T) {
	pol := mustCompile(t, Config{Allow: []string{"example.com"}})
	px := httptest.NewServer(NewServer(pol, &syncBuffer{}, fakeResolver{}, nil))
	defer px.Close()
	resp, err := http.Get(px.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("direct request got %d, want 400", resp.StatusCode)
	}
}
