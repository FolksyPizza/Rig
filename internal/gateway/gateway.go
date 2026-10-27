// Package gateway is the process Rig runs in the gateway container: the one
// place, outside the sandbox, where MCP servers that need host apps or
// credentials run, where the git broker holds repository tokens, and where
// host ports are relayed to the rig process on the host.
//
// The sandbox reaches the gateway over its internal network. The gateway's
// own outbound traffic goes through the egress proxy with a client token, so
// it is filtered and logged like everything else.
//
// Standard library only: compiled into rig-helper inside an image build.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FolksyPizza/rig/internal/gitbroker"
	"github.com/FolksyPizza/rig/internal/mcpguard"
	"github.com/FolksyPizza/rig/internal/relay"
)

// ServerConfig is one MCP server hosted in the gateway.
type ServerConfig struct {
	Name    string   `json:"name"`
	Command []string `json:"command"`
	// Env values of the form "${NAME}" are taken from the gateway's own
	// environment, where Rig placed resolved secrets.
	Env    map[string]string `json:"env,omitempty"`
	Policy mcpguard.Policy   `json:"policy"`
}

// PortConfig is one relayed host port.
type PortConfig struct {
	Name  string `json:"name"`
	Index uint16 `json:"index"`
	Port  int    `json:"port"`
	// Bind is 0.0.0.0 for ports the sandbox may use, or 127.0.0.1 for ports
	// only the gateway's own MCP servers may use.
	Bind string `json:"bind"`
}

// Config is the gateway's configuration file.
type Config struct {
	Listen  string            `json:"listen,omitempty"`
	Servers []ServerConfig    `json:"servers,omitempty"`
	Ports   []PortConfig      `json:"ports,omitempty"`
	Git     *gitbroker.Config `json:"git,omitempty"`
}

// Validate checks the configuration.
func (c Config) Validate() error {
	seen := map[string]bool{}
	for _, s := range c.Servers {
		if s.Name == "" || strings.ContainsAny(s.Name, "/ \t\n") {
			return fmt.Errorf("invalid MCP server name %q", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate MCP server %q", s.Name)
		}
		seen[s.Name] = true
		if len(s.Command) == 0 || s.Command[0] == "" {
			return fmt.Errorf("MCP server %q has no command", s.Name)
		}
		if err := s.Policy.Validate(); err != nil {
			return fmt.Errorf("MCP server %q: %w", s.Name, err)
		}
	}
	ports := map[int]bool{}
	idx := map[uint16]bool{}
	for _, p := range c.Ports {
		if p.Port <= 0 || p.Port > 65535 {
			return fmt.Errorf("port %q: invalid port %d", p.Name, p.Port)
		}
		if p.Bind != "0.0.0.0" && p.Bind != "127.0.0.1" {
			return fmt.Errorf("port %q: bind must be 0.0.0.0 or 127.0.0.1", p.Name)
		}
		if ports[p.Port] || idx[p.Index] {
			return fmt.Errorf("port %q: duplicate port or index", p.Name)
		}
		ports[p.Port], idx[p.Index] = true, true
	}
	return nil
}

// Logger writes JSON audit lines.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger wraps w.
func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

// Log writes v as one JSON line.
func (l *Logger) Log(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

type relayEvent struct {
	TS    string `json:"ts"`
	Event string `json:"event"` // "relay"
	Port  string `json:"port"`
	Phase string `json:"phase"` // open | close | error
	From  string `json:"from,omitempty"`
	Error string `json:"error,omitempty"`
}

type stderrEvent struct {
	TS     string `json:"ts"`
	Event  string `json:"event"` // "mcp_stderr"
	Server string `json:"server"`
	Line   string `json:"line"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// childEnv builds an MCP server's environment: a minimal base, the proxy
// settings, and the server's own variables. The git token is never included.
func childEnv(getenv func(string) string, extra map[string]string) []string {
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "LANG", "LC_ALL", "TERM", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "NODE_USE_ENV_PROXY", "SSL_CERT_FILE"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range extra {
		if name, ok := strings.CutPrefix(v, "${"); ok {
			if name, ok := strings.CutSuffix(name, "}"); ok {
				v = getenv(name)
			}
		}
		env = append(env, k+"="+v)
	}
	return env
}

// Run serves the gateway until ctx ends. When ports are configured, stdin and
// stdout carry the relay to the rig process, and the gateway stops when that
// stream closes.
func Run(ctx context.Context, cfg Config, stdin io.Reader, stdout io.Writer, logw io.Writer, getenv func(string) string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	log := NewLogger(logw)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })

	var bridges []*mcpguard.Bridge
	for _, s := range cfg.Servers {
		b := &mcpguard.Bridge{
			Policy:  s.Policy,
			Command: s.Command,
			Env:     childEnv(getenv, s.Env),
			Log:     func(e mcpguard.Event) { log.Log(e) },
			Stderr: func(server string, line []byte) {
				if len(line) > 2000 {
					line = line[:2000]
				}
				log.Log(stderrEvent{TS: now(), Event: "mcp_stderr", Server: server, Line: string(line)})
			},
		}
		if b.Policy.Server == "" {
			b.Policy.Server = s.Name
		}
		bridges = append(bridges, b)
		mux.Handle("/mcp/"+s.Name, b)
	}
	defer func() {
		for _, b := range bridges {
			b.Close()
		}
	}()

	if cfg.Git != nil {
		token := ""
		if cfg.Git.TokenEnv != "" {
			token = getenv(cfg.Git.TokenEnv)
		}
		broker, err := gitbroker.New(*cfg.Git, token, "https://"+cfg.Git.Host, nil)
		if err != nil {
			return err
		}
		broker.Log = func(e gitbroker.Event) { log.Log(e) }
		mux.Handle("/git/", http.StripPrefix("/git", broker))
	}

	listen := cfg.Listen
	if listen == "" {
		listen = ":8800"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	var relayDone <-chan struct{}
	if len(cfg.Ports) > 0 {
		sess := relay.NewSession(stdin, stdout, nil)
		go func() { _ = sess.Run() }()
		relayDone = sess.Done()
		for _, p := range cfg.Ports {
			pl, err := net.Listen("tcp", net.JoinHostPort(p.Bind, strconv.Itoa(p.Port)))
			if err != nil {
				return fmt.Errorf("listen for port %q: %w", p.Name, err)
			}
			defer pl.Close()
			go acceptPort(ctx, pl, p, sess, log)
		}
	}

	select {
	case <-ctx.Done():
	case <-relayDone:
	}
	return nil
}

func acceptPort(ctx context.Context, ln net.Listener, p PortConfig, sess *relay.Session, log *Logger) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			from := c.RemoteAddr().String()
			st, err := sess.Open(p.Index)
			if err != nil {
				log.Log(relayEvent{TS: now(), Event: "relay", Port: p.Name, Phase: "error", From: from, Error: err.Error()})
				_ = c.Close()
				return
			}
			log.Log(relayEvent{TS: now(), Event: "relay", Port: p.Name, Phase: "open", From: from})
			relay.Join(c, st)
			log.Log(relayEvent{TS: now(), Event: "relay", Port: p.Name, Phase: "close", From: from})
		}()
	}
}
