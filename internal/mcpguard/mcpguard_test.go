package mcpguard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// TestHelperProcess is not a real test: when GUARD_FAKE_SERVER is set the
// test binary acts as a small stdio MCP server for the tests below.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GUARD_FAKE_SERVER") != "1" {
		return
	}
	fakeServer(os.Stdin, os.Stdout)
	os.Exit(0)
}

func fakeServer(in io.Reader, out io.Writer) {
	enc := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(out, "%s\n", b)
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		var m message
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		switch m.Method {
		case "initialize":
			enc(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fake", "version": "1"},
			}})
		case "tools/list":
			enc(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
				"tools": []map[string]any{{"name": "get_scene"}, {"name": "execute_code"}, {"name": "get_info"}},
			}})
		case "tools/call":
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(m.Params, &p)
			enc(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
				"content": []map[string]string{{"type": "text", "text": "called " + p.Name}},
			}})
		case "ask_client":
			// Issue a server-to-client request, then report what came back.
			enc(map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list"})
			if sc.Scan() {
				enc(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"got": json.RawMessage(sc.Bytes())}})
			}
		}
	}
}

func fakeCommand() []string {
	return []string{os.Args[0], "-test.run=TestHelperProcess"}
}

func fakeEnv() []string {
	return append(os.Environ(), "GUARD_FAKE_SERVER=1")
}

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event{}, l.ev...)
}

func TestPolicyPermits(t *testing.T) {
	p := Policy{Allow: []string{"get_*", "list"}, Deny: []string{"get_secret*"}}
	cases := map[string]bool{
		"get_scene":      true,
		"list":           true,
		"get_secret_key": false, // deny wins over a matching allow
		"execute_code":   false, // not in the allow list
	}
	for tool, want := range cases {
		if got, _ := p.Permits(tool); got != want {
			t.Errorf("Permits(%q) = %v, want %v", tool, got, want)
		}
	}

	open := Policy{Deny: []string{"execute_*"}}
	if ok, _ := open.Permits("anything_else"); !ok {
		t.Error("an empty allow list should permit tools not denied")
	}
	if ok, reason := open.Permits("execute_code"); ok || !strings.Contains(reason, "execute_*") {
		t.Errorf("deny rule not applied: %v %q", ok, reason)
	}

	if err := (Policy{Allow: []string{"bad["}}).Validate(); err == nil {
		t.Error("a malformed pattern should fail validation")
	}

	// Tool names are not paths: a wildcard covers slashes too.
	slash := Policy{Deny: []string{"delete_*"}}
	if ok, _ := slash.Permits("delete_dir/everything"); ok {
		t.Error("delete_* must cover names containing a slash")
	}
}

func TestFilterBlocksCallsAndAnswersItself(t *testing.T) {
	log := &eventLog{}
	f := NewFilter(Policy{Server: "blender", Deny: []string{"execute_code"}, LogArgs: true, MaxArgBytes: 10}, log.add)

	call := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"execute_code","arguments":{"code":"import os; os.system('id')"}}}`)
	fwd, reply := f.FromClient(call)
	if fwd != nil {
		t.Fatal("a blocked call must not be forwarded to the server")
	}
	var r struct {
		ID     int `json:"id"`
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(reply, &r); err != nil {
		t.Fatalf("reply is not JSON: %s", reply)
	}
	if r.ID != 7 || !r.Result.IsError || !strings.Contains(r.Result.Content[0].Text, "execute_code") {
		t.Errorf("unexpected reply %s", reply)
	}

	ok := []byte(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_scene","arguments":{}}}`)
	fwd, reply = f.FromClient(ok)
	if !bytes.Equal(fwd, ok) || reply != nil {
		t.Errorf("an allowed call should pass through unchanged, got fwd=%s reply=%s", fwd, reply)
	}

	ev := log.all()
	if len(ev) != 2 || ev[0].Action != "deny" || ev[0].Tool != "execute_code" || ev[1].Action != "allow" {
		t.Fatalf("unexpected audit events %+v", ev)
	}
	if !strings.HasSuffix(ev[0].Args, "…") || len(ev[0].Args) > 14 {
		t.Errorf("arguments should be truncated, got %q", ev[0].Args)
	}
}

func TestFilterHidesBlockedTools(t *testing.T) {
	f := NewFilter(Policy{Deny: []string{"execute_code"}}, nil)
	f.FromClient([]byte(`{"jsonrpc":"2.0","id":"a","method":"tools/list"}`))
	resp := []byte(`{"jsonrpc":"2.0","id":"a","result":{"tools":[{"name":"get_scene"},{"name":"execute_code"}],"nextCursor":"x"}}`)
	out := f.FromServer(resp)

	var m struct {
		Result struct {
			Tools      []struct{ Name string } `json:"tools"`
			NextCursor string                  `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Result.Tools) != 1 || m.Result.Tools[0].Name != "get_scene" {
		t.Errorf("blocked tool not hidden: %s", out)
	}
	if m.Result.NextCursor != "x" {
		t.Error("other result fields must be preserved")
	}

	// A reply to something other than tools/list is untouched.
	other := []byte(`{"jsonrpc":"2.0","id":"b","result":{"tools":[{"name":"execute_code"}]}}`)
	if got := f.FromServer(other); !bytes.Equal(got, other) {
		t.Error("only tools/list replies should be filtered")
	}
}

func TestFilterBatchesAndPassthrough(t *testing.T) {
	f := NewFilter(Policy{Deny: []string{"bad"}}, nil)
	batch := []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bad"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"good"}}]`)
	fwd, reply := f.FromClient(batch)
	var fwdItems, replyItems []json.RawMessage
	_ = json.Unmarshal(fwd, &fwdItems)
	_ = json.Unmarshal(reply, &replyItems)
	if len(fwdItems) != 1 || len(replyItems) != 1 {
		t.Fatalf("batch split wrong: fwd=%s reply=%s", fwd, reply)
	}
	if !strings.Contains(string(fwdItems[0]), `"good"`) {
		t.Errorf("wrong element forwarded: %s", fwdItems[0])
	}

	junk := []byte("not json at all")
	if fwd, reply := f.FromClient(junk); fwd != nil || !strings.Contains(string(reply), `"error"`) {
		t.Errorf("non-JSON input must be refused, got fwd=%s reply=%s", fwd, reply)
	}
}

// A message that one JSON parser could read differently from another must
// never reach the server: the guard would be checking a different call from
// the one the server runs.
func TestFilterRefusesAmbiguousMessages(t *testing.T) {
	log := &eventLog{}
	f := NewFilter(Policy{Server: "blender", Deny: []string{"execute_code"}}, log.add)
	attacks := map[string]string{
		"name in two cases":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_code","Name":"get_scene"}}`,
		"method in two cases":    `{"jsonrpc":"2.0","id":2,"method":"tools/call","Method":"tools/list","params":{"name":"execute_code"}}`,
		"duplicate name":         `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_code","name":"get_scene"}}`,
		"escaped duplicate name": `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_code","na\u006de":"get_scene"}}`,
		"long s in params":       `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_scene"},"paramſ":{"name":"execute_code"}}`,
		"NaN id":                 `{"jsonrpc":"2.0","id":NaN,"method":"tools/call","params":{"name":"execute_code"}}`,
		"trailing garbage":       `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_scene"}} {"method":"tools/call"}`,
		"comment":                `{"jsonrpc":"2.0","id":7,/*x*/"method":"tools/call","params":{"name":"execute_code"}}`,
		"invalid UTF-8":          "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"get_scene\xff\"}}",
		"name not a string":      `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":["execute_code"]}}`,
		"params not an object":   `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":["execute_code"]}`,
		"method not a string":    `{"jsonrpc":"2.0","id":11,"method":{"x":"tools/call"},"params":{"name":"execute_code"}}`,
	}
	for name, raw := range attacks {
		fwd, reply := f.FromClient([]byte(raw))
		if fwd != nil {
			t.Errorf("%s: forwarded %s", name, fwd)
		}
		if reply == nil {
			t.Errorf("%s: no reply to the agent", name)
		}
	}
	for _, e := range log.all() {
		if e.Action != "deny" {
			t.Errorf("every attempt should be recorded as denied: %+v", e)
		}
	}

	// Ambiguity inside a batch refuses that element only.
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_scene"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_code","Name":"get_scene"}}]`
	fwd, reply := f.FromClient([]byte(batch))
	if !strings.Contains(string(fwd), "get_scene") || strings.Contains(string(fwd), "execute_code") || reply == nil {
		t.Errorf("batch not split safely: fwd=%s reply=%s", fwd, reply)
	}

	// Escaped keys and unknown extra fields are fine when unambiguous.
	okCall := `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"na\u006de":"get_scene","arguments":{},"extra":1}}`
	if fwd, reply := f.FromClient([]byte(okCall)); fwd == nil || reply != nil {
		t.Errorf("an unambiguous call should pass: fwd=%s reply=%s", fwd, reply)
	}
}

func TestRunStdio(t *testing.T) {
	log := &eventLog{}
	f := NewFilter(Policy{Server: "fake", Deny: []string{"execute_code"}}, log.add)
	cmd := exec.Command(fakeCommand()[0], fakeCommand()[1:]...)
	cmd.Env = fakeEnv()
	cmd.Stderr = io.Discard

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_code"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_scene"}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	code, err := RunStdio(f, cmd, strings.NewReader(in), &out)
	if err != nil || code != 0 {
		t.Fatalf("RunStdio = %d, %v", code, err)
	}

	byID := map[string]string{}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var m message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("output line is not JSON: %q", sc.Text())
		}
		byID[string(m.ID)] = sc.Text()
	}
	if len(byID) != 4 {
		t.Fatalf("expected 4 replies, got %d: %v", len(byID), byID)
	}
	if strings.Contains(byID["2"], "execute_code") {
		t.Errorf("tools/list should hide execute_code: %s", byID["2"])
	}
	if !strings.Contains(byID["3"], "Rig blocked") {
		t.Errorf("blocked call should be answered by the guard: %s", byID["3"])
	}
	if !strings.Contains(byID["4"], "called get_scene") {
		t.Errorf("allowed call should reach the server: %s", byID["4"])
	}
}

func postJSON(t *testing.T, url, session, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestBridge(t *testing.T) {
	log := &eventLog{}
	b := &Bridge{
		Policy:  Policy{Server: "fake", Deny: []string{"execute_code"}},
		Command: fakeCommand(),
		Env:     fakeEnv(),
		Log:     log.add,
	}
	defer b.Close()
	srv := httptest.NewServer(b)
	defer srv.Close()

	// No session and not initialize.
	if resp := postJSON(t, srv.URL, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("request without a session got %d, want 400", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}

	resp := postJSON(t, srv.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get("Mcp-Session-Id")
	if body := readBody(t, resp); resp.StatusCode != 200 || sid == "" || !strings.Contains(body, "serverInfo") {
		t.Fatalf("initialize failed: %d sid=%q body=%s", resp.StatusCode, sid, body)
	}

	resp = postJSON(t, srv.URL, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("notification got %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()

	body := readBody(t, postJSON(t, srv.URL, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if strings.Contains(body, "execute_code") || !strings.Contains(body, "get_scene") {
		t.Errorf("tools/list not filtered: %s", body)
	}

	body = readBody(t, postJSON(t, srv.URL, sid, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_code"}}`))
	if !strings.Contains(body, "Rig blocked") {
		t.Errorf("blocked call not refused: %s", body)
	}
	body = readBody(t, postJSON(t, srv.URL, sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_scene"}}`))
	if !strings.Contains(body, "called get_scene") {
		t.Errorf("allowed call failed: %s", body)
	}

	// A server-initiated request is refused by the bridge, not left hanging.
	body = readBody(t, postJSON(t, srv.URL, sid, `{"jsonrpc":"2.0","id":5,"method":"ask_client"}`))
	if !strings.Contains(body, "-32601") {
		t.Errorf("server-to-client request should be refused: %s", body)
	}

	// Batches come back as arrays.
	body = readBody(t, postJSON(t, srv.URL, sid, `[{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_info"}},{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"execute_code"}}]`))
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(body), &arr); err != nil || len(arr) != 2 {
		t.Errorf("batch reply should be a two-element array: %s", body)
	}

	if resp := postJSON(t, srv.URL, "nope", `{"jsonrpc":"2.0","id":8,"method":"tools/list"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session got %d, want 404", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET got %d, want 405", r.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Origin", "http://evil.example")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden {
		t.Errorf("request with Origin got %d, want 403", r.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodDelete, srv.URL, nil)
	req.Header.Set("Mcp-Session-Id", sid)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE got %d, want 204", r.StatusCode)
	}

	var denies int
	for _, e := range log.all() {
		if e.Action == "deny" {
			denies++
		}
	}
	if denies != 2 {
		t.Errorf("expected 2 deny events, got %d: %+v", denies, log.all())
	}
}

func TestBridgeSessionLimit(t *testing.T) {
	b := &Bridge{Policy: Policy{Server: "fake"}, Command: fakeCommand(), Env: fakeEnv(), MaxSessions: 1}
	defer b.Close()
	srv := httptest.NewServer(b)
	defer srv.Close()

	r1 := postJSON(t, srv.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r1.Body.Close()
	r2 := postJSON(t, srv.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r2.Body.Close()
	if r2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second session got %d, want 503", r2.StatusCode)
	}
}
