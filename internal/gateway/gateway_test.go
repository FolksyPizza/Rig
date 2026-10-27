package gateway

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FolksyPizza/rig/internal/mcpguard"
	"github.com/FolksyPizza/rig/internal/relay"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRunRelaysPortsToTheHost(t *testing.T) {
	// The "host" service the sandbox wants to reach.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	toGW_R, toGW_W := io.Pipe()
	fromGW_R, fromGW_W := io.Pipe()
	host := relay.NewSession(fromGW_R, toGW_W, func(index uint16, s *relay.Stream) {
		if index != 0 {
			_ = s.Close()
			return
		}
		c, err := net.Dial("tcp", echo.Addr().String())
		if err != nil {
			_ = s.Close()
			return
		}
		relay.Join(s, c)
	})
	go func() { _ = host.Run() }()

	httpPort, relayPort := freePort(t), freePort(t)
	logs := &lockedBuf{}
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Config{
			Listen: "127.0.0.1:" + strconv.Itoa(httpPort),
			Ports:  []PortConfig{{Name: "echo", Index: 0, Port: relayPort, Bind: "127.0.0.1"}},
		}, toGW_R, fromGW_W, logs, func(string) string { return "" })
	}()

	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(relayPort)); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("gateway port never opened: %v", err)
	}
	if _, err := conn.Write([]byte("hello host")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("hello host"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello host" {
		t.Fatalf("relay round trip = %q, %v", got, err)
	}
	conn.Close()

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(httpPort) + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("health = %d", resp.StatusCode)
	}

	// The rig process going away ends the gateway.
	_ = toGW_W.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway kept running after its relay closed")
	}
	if !strings.Contains(logs.String(), `"event":"relay"`) {
		t.Errorf("relay connections should be logged; got %s", logs.String())
	}
}

func TestValidate(t *testing.T) {
	good := Config{
		Servers: []ServerConfig{{Name: "blender", Command: []string{"blender-mcp"}, Policy: mcpguard.Policy{Deny: []string{"execute_*"}}}},
		Ports:   []PortConfig{{Name: "blender", Index: 0, Port: 9876, Bind: "127.0.0.1"}},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := []Config{
		{Servers: []ServerConfig{{Name: "", Command: []string{"x"}}}},
		{Servers: []ServerConfig{{Name: "a/b", Command: []string{"x"}}}},
		{Servers: []ServerConfig{{Name: "a", Command: nil}}},
		{Servers: []ServerConfig{{Name: "a", Command: []string{"x"}}, {Name: "a", Command: []string{"y"}}}},
		{Servers: []ServerConfig{{Name: "a", Command: []string{"x"}, Policy: mcpguard.Policy{Allow: []string{"["}}}}},
		{Ports: []PortConfig{{Name: "p", Port: 0, Bind: "0.0.0.0"}}},
		{Ports: []PortConfig{{Name: "p", Port: 80, Bind: "10.0.0.1"}}},
		{Ports: []PortConfig{{Name: "p", Index: 0, Port: 80, Bind: "0.0.0.0"}, {Name: "q", Index: 1, Port: 80, Bind: "0.0.0.0"}}},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: Validate succeeded, want error", i)
		}
	}
}

func TestChildEnvExpandsSecretsAndWithholdsTheGitToken(t *testing.T) {
	vars := map[string]string{
		"PATH":          "/usr/bin",
		"HTTPS_PROXY":   "http://gateway:tok@rig-proxy:3128",
		"RIG_GIT_TOKEN": "ghp_secret",
		"BLENDER_KEY":   "k-123",
	}
	env := childEnv(func(k string) string { return vars[k] }, map[string]string{
		"API_KEY": "${BLENDER_KEY}",
		"PORT":    "9876",
	})
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/usr/bin", "API_KEY=k-123", "PORT=9876", "HTTPS_PROXY=http://gateway:tok@rig-proxy:3128"} {
		if !strings.Contains(joined, want) {
			t.Errorf("child env missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "ghp_secret") {
		t.Error("the git token must not reach MCP servers")
	}
}
