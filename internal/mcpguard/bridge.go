package mcpguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// Bridge serves one stdio MCP server over MCP's Streamable HTTP transport,
// with the guard's policy applied. Rig runs bridges in the gateway container,
// outside the sandbox: the agent can reach the server only through this
// endpoint, so it cannot bypass the policy by talking to the server (or the
// application behind it) directly.
//
// Each MCP session gets its own child process. Replies are returned as plain
// JSON; the bridge does not open server-to-client event streams, so server
// notifications are dropped and server-initiated requests are refused.
type Bridge struct {
	Policy  Policy
	Command []string
	Env     []string
	Dir     string
	Log     func(Event)
	// Stderr receives each child's stderr lines, tagged with the server name.
	Stderr func(server string, line []byte)

	IdleTimeout    time.Duration // default 30 minutes
	RequestTimeout time.Duration // default 15 minutes
	MaxSessions    int           // default 8
	MaxBodyBytes   int64         // default 16 MiB

	mu       sync.Mutex
	sessions map[string]*session
	reaper   sync.Once
}

type session struct {
	id      string
	cmd     *exec.Cmd
	filter  *Filter
	writeMu sync.Mutex
	stdin   io.WriteCloser

	mu       sync.Mutex
	waiting  map[string]chan []byte
	lastUsed time.Time
	dead     bool
	done     chan struct{}
}

func (b *Bridge) idle() time.Duration {
	if b.IdleTimeout > 0 {
		return b.IdleTimeout
	}
	return 30 * time.Minute
}

func (b *Bridge) reqTimeout() time.Duration {
	if b.RequestTimeout > 0 {
		return b.RequestTimeout
	}
	return 15 * time.Minute
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Browsers send Origin; the sandbox's MCP clients do not. Refusing it
	// keeps a web page from driving the bridge through DNS rebinding.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "cross-origin requests are not accepted", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPost:
		b.handlePost(w, r)
	case http.MethodDelete:
		b.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this endpoint accepts POST and DELETE only", http.StatusMethodNotAllowed)
	}
}

func (b *Bridge) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("Mcp-Session-Id")
	b.mu.Lock()
	s := b.sessions[id]
	delete(b.sessions, id)
	b.mu.Unlock()
	if s == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	s.kill()
	w.WriteHeader(http.StatusNoContent)
}

func (b *Bridge) handlePost(w http.ResponseWriter, r *http.Request) {
	max := b.MaxBodyBytes
	if max <= 0 {
		max = 16 << 20
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || !json.Valid(body) {
		http.Error(w, "body must be a JSON-RPC message", http.StatusBadRequest)
		return
	}

	sid := r.Header.Get("Mcp-Session-Id")
	var s *session
	created := false
	if sid == "" {
		if !isInitialize(body) {
			http.Error(w, "missing Mcp-Session-Id; start with initialize", http.StatusBadRequest)
			return
		}
		s, err = b.newSession()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		created = true
	} else {
		b.mu.Lock()
		s = b.sessions[sid]
		b.mu.Unlock()
		if s == nil {
			http.Error(w, "unknown or expired session", http.StatusNotFound)
			return
		}
	}

	batch := body[0] == '['
	var items []json.RawMessage
	if batch {
		_ = json.Unmarshal(body, &items)
	} else {
		items = []json.RawMessage{body}
	}

	type pending struct {
		key string
		ch  chan []byte
	}
	var replies []json.RawMessage
	var waits []pending
	for _, raw := range items {
		fwd, reply := s.filter.FromClient(raw)
		if reply != nil {
			replies = append(replies, reply)
			continue
		}
		if fwd == nil {
			continue
		}
		m, err := parseMessage(fwd)
		if err != nil {
			continue // FromClient forwards only messages it could parse
		}
		isRequest := m.Method != "" && len(m.ID) > 0
		if isRequest {
			key := idKey(m.ID)
			ch := make(chan []byte, 1)
			s.mu.Lock()
			s.waiting[key] = ch
			s.mu.Unlock()
			waits = append(waits, pending{key, ch})
		}
		if err := s.send(fwd); err != nil {
			http.Error(w, "MCP server is not running", http.StatusBadGateway)
			return
		}
	}
	s.touch()

	if created {
		w.Header().Set("Mcp-Session-Id", s.id)
	}
	if len(waits) == 0 && len(replies) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), b.reqTimeout())
	defer cancel()
	for _, p := range waits {
		select {
		case resp, ok := <-p.ch:
			if !ok {
				http.Error(w, "MCP server exited", http.StatusBadGateway)
				return
			}
			replies = append(replies, resp)
		case <-ctx.Done():
			s.mu.Lock()
			delete(s.waiting, p.key)
			s.mu.Unlock()
			http.Error(w, "MCP server did not reply in time", http.StatusGatewayTimeout)
			return
		}
	}
	s.touch()

	w.Header().Set("Content-Type", "application/json")
	if batch {
		out, _ := json.Marshal(replies)
		_, _ = w.Write(out)
		return
	}
	_, _ = w.Write(replies[0])
}

func (b *Bridge) newSession() (*session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions == nil {
		b.sessions = map[string]*session{}
	}
	max := b.MaxSessions
	if max <= 0 {
		max = 8
	}
	if len(b.sessions) >= max {
		return nil, errTooManySessions
	}
	b.reaper.Do(func() { go b.reap() })

	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return nil, err
	}
	cmd := exec.Command(b.Command[0], b.Command[1:]...)
	cmd.Env = b.Env
	cmd.Dir = b.Dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	s := &session{
		id:       hex.EncodeToString(idb),
		cmd:      cmd,
		filter:   NewFilter(b.Policy, b.Log),
		stdin:    stdin,
		waiting:  map[string]chan []byte{},
		lastUsed: time.Now(),
		done:     make(chan struct{}),
	}
	b.sessions[s.id] = s

	go func() {
		eachLine(stderr, func(line []byte) bool {
			if b.Stderr != nil {
				b.Stderr(b.Policy.Server, line)
			}
			return true
		})
	}()
	go func() {
		eachLine(stdout, func(line []byte) bool {
			s.fromServer(line)
			return true
		})
		_ = cmd.Wait()
		s.markDead()
		b.mu.Lock()
		if b.sessions[s.id] == s {
			delete(b.sessions, s.id)
		}
		b.mu.Unlock()
	}()
	return s, nil
}

// fromServer routes one line from the child.
func (s *session) fromServer(line []byte) {
	line = s.filter.FromServer(line)
	m, err := parseMessage(line)
	if err != nil {
		return
	}
	switch {
	case m.Method != "" && len(m.ID) > 0:
		// A server-to-client request (sampling, roots, elicitation). There is
		// no client stream to carry it, so refuse it rather than leave the
		// server waiting forever.
		_ = s.send(errorReply(m.ID, -32601, "not supported through the Rig gateway"))
	case m.Method != "":
		// Notification: dropped (no event stream to the client).
	case len(m.ID) > 0:
		key := idKey(m.ID)
		s.mu.Lock()
		ch := s.waiting[key]
		delete(s.waiting, key)
		s.mu.Unlock()
		if ch != nil {
			ch <- append([]byte{}, line...)
		}
	}
}

func (s *session) send(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.stdin.Write(append(append([]byte{}, b...), '\n'))
	return err
}

func (s *session) touch() {
	s.mu.Lock()
	s.lastUsed = time.Now()
	s.mu.Unlock()
}

func (s *session) markDead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return
	}
	s.dead = true
	for k, ch := range s.waiting {
		close(ch)
		delete(s.waiting, k)
	}
	close(s.done)
}

func (s *session) kill() {
	_ = s.stdin.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

// reap stops sessions that have been idle too long.
func (b *Bridge) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-b.idle())
		b.mu.Lock()
		for id, s := range b.sessions {
			s.mu.Lock()
			old := s.lastUsed.Before(cutoff) && len(s.waiting) == 0
			s.mu.Unlock()
			if old {
				delete(b.sessions, id)
				go s.kill()
			}
		}
		b.mu.Unlock()
	}
}

// Close stops every session.
func (b *Bridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.sessions {
		delete(b.sessions, id)
		s.kill()
	}
}

type bridgeError string

func (e bridgeError) Error() string { return string(e) }

const errTooManySessions = bridgeError("too many MCP sessions for this server")
