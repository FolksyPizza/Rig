package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver looks up a host's addresses. net.DefaultResolver satisfies it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Event is one line of the proxy's JSON log.
type Event struct {
	TS        string `json:"ts"`
	Event     string `json:"event"` // always "egress"
	Phase     string `json:"phase"` // open | close | deny
	Client    string `json:"client,omitempty"`
	As        string `json:"as"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"`
	SNI       string `json:"sni,omitempty"`
	IP        string `json:"ip,omitempty"`
	Action    string `json:"action"` // allow | deny
	Reason    string `json:"reason,omitempty"`
	Category  string `json:"category,omitempty"`
	BytesUp   int64  `json:"bytes_up,omitempty"`
	BytesDown int64  `json:"bytes_down,omitempty"`
	MS        int64  `json:"ms,omitempty"`
}

// Server is the filtering proxy. Create one with NewServer.
type Server struct {
	policy   atomic.Pointer[Policy]
	resolver Resolver
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	sem      chan struct{}

	logMu sync.Mutex
	logW  io.Writer

	// Timeouts, overridable in tests.
	ResolveTimeout time.Duration
	DialTimeout    time.Duration
	HelloTimeout   time.Duration
}

// NewServer builds a proxy around a compiled policy. log receives one JSON
// object per line; resolver and dial default to the system's.
func NewServer(p *Policy, log io.Writer, resolver Resolver, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Server {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if dial == nil {
		d := &net.Dialer{KeepAlive: 30 * time.Second}
		dial = d.DialContext
	}
	max := p.Config().MaxConns
	if max <= 0 {
		max = 512
	}
	s := &Server{
		resolver:       resolver,
		dial:           dial,
		sem:            make(chan struct{}, max),
		logW:           log,
		ResolveTimeout: 10 * time.Second,
		DialTimeout:    10 * time.Second,
		HelloTimeout:   10 * time.Second,
	}
	s.policy.Store(p)
	return s
}

// SetPolicy swaps in a new policy for subsequent connections.
func (s *Server) SetPolicy(p *Policy) { s.policy.Store(p) }

// Policy returns the policy currently in force.
func (s *Server) Policy() *Policy { return s.policy.Load() }

func (s *Server) logEvent(e Event) {
	if s.logW == nil {
		return
	}
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	e.Event = "egress"
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	_, _ = s.logW.Write(append(b, '\n'))
}

// ServeHTTP handles both CONNECT tunnels and absolute-URI plain HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.deny(w, Event{Method: r.Method, Host: r.Host, Client: remoteIP(r), As: SandboxClient}, ReasonBusy, "", http.StatusServiceUnavailable)
		return
	}

	pol := s.Policy()
	client, ok := pol.Authenticate(proxyToken(r))
	base := Event{Method: r.Method, Client: remoteIP(r), As: client}
	if !ok {
		base.As = "unknown"
		base.Host = r.Host
		w.Header().Set("Proxy-Authenticate", `Basic realm="rig"`)
		s.deny(w, base, ReasonAuth, "", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, pol, base)
		return
	}
	s.handleHTTP(w, r, pol, base)
}

// deny writes a short refusal and logs it.
func (s *Server) deny(w http.ResponseWriter, e Event, reason, category string, status int) {
	e.Phase, e.Action, e.Reason, e.Category = "deny", "deny", reason, category
	s.logEvent(e)
	msg := "Blocked by Rig egress policy: " + reason
	if category != "" {
		msg += " (" + category + ")"
	}
	http.Error(w, msg, status)
}

// resolve returns the addresses of host that policy allows dialing. When the
// host resolves only to disallowed addresses the reason says so, which is
// worth distinguishing: it is how an allowlisted name pointed at the host or
// the LAN shows up.
func (s *Server) resolve(ctx context.Context, pol *Policy, host string) ([]net.IP, string) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, ReasonBadRequest
	}
	if ip := net.ParseIP(h); ip != nil {
		if pol.AllowedIP(ip) {
			return []net.IP{ip}, ""
		}
		return nil, ReasonIPLiteral
	}
	ctx, cancel := context.WithTimeout(ctx, s.ResolveTimeout)
	defer cancel()
	addrs, err := s.resolver.LookupIPAddr(ctx, h)
	if err != nil || len(addrs) == 0 {
		return nil, ReasonResolve
	}
	var ok []net.IP
	for _, a := range addrs {
		if pol.AllowedIP(a.IP) {
			ok = append(ok, a.IP)
		}
	}
	if len(ok) == 0 {
		return nil, ReasonPrivate
	}
	return ok, ""
}

// dialAny connects to the first reachable vetted address. Dialing the vetted
// address, rather than the name, is what stops a DNS answer that changes
// between the check and the connection from reaching a private address.
func (s *Server) dialAny(ctx context.Context, ips []net.IP, port int) (net.Conn, net.IP, error) {
	var lastErr error
	for _, ip := range ips {
		dctx, cancel := context.WithTimeout(ctx, s.DialTimeout)
		c, err := s.dial(dctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		cancel()
		if err == nil {
			return c, ip, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no address")
	}
	return nil, nil, lastErr
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, pol *Policy, ev Event) {
	host, portStr, err := net.SplitHostPort(r.Host)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || port <= 0 || port > 65535 {
		ev.Host = r.Host
		s.deny(w, ev, ReasonBadRequest, "", http.StatusBadRequest)
		return
	}
	if n, err := NormalizeHost(host); err == nil {
		host = n
	}
	ev.Host, ev.Port = host, port

	v := pol.Check(ev.As, host, port, "connect")
	if !v.Allow {
		s.deny(w, ev, v.Reason, v.Category, http.StatusForbidden)
		return
	}
	ips, reason := s.resolve(r.Context(), pol, host)
	if reason != "" {
		s.deny(w, ev, reason, "", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		s.deny(w, ev, ReasonBadRequest, "", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Everything the client sends before upstream is connected is held here
	// and replayed, so peeking at the ClientHello loses nothing.
	var first []byte
	var reader io.Reader = brw.Reader
	if pol.Config().RequireSNI {
		sni, raw, herr := peekClientHello(conn, brw.Reader, s.HelloTimeout)
		ev.SNI = sni
		first = raw
		switch {
		case herr != nil || sni == "":
			ev.Phase, ev.Action, ev.Reason = "deny", "deny", ReasonNoSNI
			s.logEvent(ev)
			return
		case !strings.EqualFold(strings.TrimSuffix(sni, "."), host):
			ev.Phase, ev.Action, ev.Reason = "deny", "deny", ReasonSNIMismatch
			s.logEvent(ev)
			return
		}
	}

	up, ip, err := s.dialAny(r.Context(), ips, port)
	if err != nil {
		ev.Phase, ev.Action, ev.Reason = "deny", "deny", ReasonUpstream
		s.logEvent(ev)
		return
	}
	defer up.Close()
	ev.IP = ip.String()

	open := ev
	open.Phase, open.Action, open.Reason = "open", "allow", ReasonAllowed
	s.logEvent(open)

	start := time.Now()
	if len(first) > 0 {
		if _, err := up.Write(first); err != nil {
			return
		}
	}
	upBytes, downBytes, limited := pipe(conn, reader, up, pol.Config().MaxUploadBytes)
	ev.Phase, ev.Action = "close", "allow"
	ev.Reason = ReasonAllowed
	if limited {
		ev.Action, ev.Reason = "deny", ReasonUploadLimit
	}
	ev.BytesUp = upBytes + int64(len(first))
	ev.BytesDown = downBytes
	ev.MS = time.Since(start).Milliseconds()
	s.logEvent(ev)
}

// pipe copies client<->upstream until either side closes. It returns the
// bytes sent each way and whether the upload limit cut the connection.
func pipe(client net.Conn, clientR io.Reader, up net.Conn, maxUp int64) (int64, int64, bool) {
	var upN, downN int64
	var limited atomic.Bool
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		src := clientR
		if maxUp > 0 {
			src = io.LimitReader(clientR, maxUp+1)
		}
		n, _ := io.Copy(up, src)
		upN = n
		if maxUp > 0 && n > maxUp {
			limited.Store(true)
		}
		closeWrite(up)
		if limited.Load() {
			// Cut both directions immediately: the limit is a hard stop.
			_ = up.Close()
			_ = client.Close()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(client, up)
		downN = n
		closeWrite(client)
	}()
	<-done
	<-done
	return upN, downN, limited.Load()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// hopHeaders are connection-specific and must not be forwarded.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, k := range strings.Split(f, ",") {
			if k = strings.TrimSpace(k); k != "" {
				h.Del(k)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request, pol *Policy, ev Event) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" {
		ev.Host = r.Host
		s.deny(w, ev, ReasonBadRequest, "", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		ev.Host = r.URL.Hostname()
		s.deny(w, ev, ReasonBadRequest, "", http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	port := 80
	if ps := r.URL.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil {
			ev.Host = host
			s.deny(w, ev, ReasonBadRequest, "", http.StatusBadRequest)
			return
		}
		port = p
	}
	if n, err := NormalizeHost(host); err == nil {
		host = n
	}
	ev.Host, ev.Port = host, port

	v := pol.Check(ev.As, host, port, "http")
	if !v.Allow {
		s.deny(w, ev, v.Reason, v.Category, http.StatusForbidden)
		return
	}
	ips, reason := s.resolve(r.Context(), pol, host)
	if reason != "" {
		s.deny(w, ev, reason, "", http.StatusForbidden)
		return
	}

	var dialed net.IP
	transport := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, ip, err := s.dialAny(ctx, ips, port)
			dialed = ip
			return c, err
		},
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	defer transport.CloseIdleConnections()

	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHop(out.Header)
	var upCount countingReader
	if r.Body != nil && r.Body != http.NoBody {
		upCount.r = r.Body
		if max := pol.Config().MaxUploadBytes; max > 0 {
			upCount.r = io.LimitReader(r.Body, max+1)
			upCount.limit = max
		}
		out.Body = &upCount
	}

	start := time.Now()
	resp, err := transport.RoundTrip(out)
	if err != nil {
		reason := ReasonUpstream
		if upCount.limited() {
			reason = ReasonUploadLimit
		}
		s.deny(w, ev, reason, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if dialed != nil {
		ev.IP = dialed.String()
	}

	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	down, _ := io.Copy(w, resp.Body)

	ev.Phase, ev.Action, ev.Reason = "close", "allow", ReasonAllowed
	ev.BytesUp = upCount.n
	ev.BytesDown = down
	ev.MS = time.Since(start).Milliseconds()
	s.logEvent(ev)
}

type countingReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.limit > 0 && c.n > c.limit {
		return n, fmt.Errorf("upload exceeds %d bytes", c.limit)
	}
	return n, err
}

func (c *countingReader) Close() error  { return nil }
func (c *countingReader) limited() bool { return c.limit > 0 && c.n > c.limit }

// proxyToken extracts the password from a Basic Proxy-Authorization header.
func proxyToken(r *http.Request) string {
	h := r.Header.Get("Proxy-Authorization")
	if h == "" {
		return ""
	}
	scheme, val, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return "\x00invalid"
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val))
	if err != nil {
		return "\x00invalid"
	}
	_, pass, ok := strings.Cut(string(dec), ":")
	if !ok || pass == "" {
		return "\x00invalid"
	}
	return pass
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// peekClientHello reads the client's TLS ClientHello without answering it and
// returns the server name it carries plus every byte read, so the caller can
// replay them upstream. crypto/tls does the parsing, which handles records
// split across reads; its reply alert is discarded so the client sees nothing.
func peekClientHello(conn net.Conn, r io.Reader, timeout time.Duration) (string, []byte, error) {
	cc := &captureConn{Conn: conn, r: r}
	var sni string
	errStop := errors.New("hello captured")
	srv := tls.Server(cc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errStop
		},
	})
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	err := srv.Handshake()
	_ = conn.SetReadDeadline(time.Time{})
	if errors.Is(err, errStop) {
		err = nil
	}
	if sni == "" && err == nil {
		err = errors.New("no server name in ClientHello")
	}
	return sni, cc.buf, err
}

// captureConn records what is read and swallows what is written.
type captureConn struct {
	net.Conn
	r   io.Reader
	buf []byte
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if len(c.buf)+n > 64*1024 {
			return 0, errors.New("ClientHello too large")
		}
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

func (c *captureConn) Write(p []byte) (int, error) { return len(p), nil }

// Listen serves the proxy on addr until ctx is cancelled.
func (s *Server) Listen(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ensure bufio is referenced for Hijack's ReadWriter type.
var _ *bufio.ReadWriter
