// Package mcpguard enforces tool-call policy on Model Context Protocol traffic.
//
// It sits between an agent and an MCP server, reads the JSON-RPC stream in
// both directions, records every tools/call, answers calls to blocked tools
// itself instead of forwarding them, and removes blocked tools from tools/list
// replies so the model never sees them. This is the "tool-call layer"
// enforcement point: it acts on what the agent actually asks a server to do,
// not on what the model says it intends.
//
// Standard library only: the package is compiled into rig-helper inside an
// image build.
package mcpguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Policy is the tool policy for one MCP server.
type Policy struct {
	Server string `json:"server"`
	// Allow lists tool-name patterns that may be called. Empty means every
	// tool not matched by Deny. Patterns use shell-style wildcards: "get_*".
	Allow []string `json:"allow,omitempty"`
	// Deny lists tool-name patterns that are always refused. Deny wins.
	Deny []string `json:"deny,omitempty"`
	// LogArgs records each call's arguments (truncated) in the audit log.
	LogArgs bool `json:"log_args"`
	// MaxArgBytes caps logged arguments. Default 2048.
	MaxArgBytes int `json:"max_arg_bytes,omitempty"`
	// Env holds literal environment variables for the server (used by the
	// in-sandbox guard; secrets arrive separately at run time).
	Env map[string]string `json:"env,omitempty"`
}

// Validate checks that every pattern is well formed.
func (p Policy) Validate() error {
	for _, pat := range append(append([]string{}, p.Allow...), p.Deny...) {
		if pat == "" {
			return fmt.Errorf("empty tool pattern")
		}
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("invalid tool pattern %q", pat)
		}
	}
	return nil
}

// Permits reports whether a tool may be called, and why not if it may not.
func (p Policy) Permits(tool string) (bool, string) {
	for _, pat := range p.Deny {
		if matchTool(pat, tool) {
			return false, fmt.Sprintf("matches deny rule %q", pat)
		}
	}
	if len(p.Allow) == 0 {
		return true, ""
	}
	for _, pat := range p.Allow {
		if matchTool(pat, tool) {
			return true, ""
		}
	}
	return false, "not in the allow list"
}

// matchTool is path.Match without its special treatment of "/": tool names
// are not paths, so "delete_*" must also cover "delete_dir/everything".
func matchTool(pat, name string) bool {
	ok, _ := path.Match(strings.ReplaceAll(pat, "/", "\x00"), strings.ReplaceAll(name, "/", "\x00"))
	return ok
}

// Event is one audit record.
type Event struct {
	TS     string `json:"ts"`
	Event  string `json:"event"` // "mcp"
	Server string `json:"server"`
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
	Action string `json:"action"` // allow | deny | filter
	Reason string `json:"reason,omitempty"`
	Args   string `json:"args,omitempty"`
	Hidden int    `json:"hidden,omitempty"` // tools removed from a tools/list reply
}

// Filter applies a Policy to one MCP session's message stream.
type Filter struct {
	Policy Policy
	Log    func(Event)

	mu          sync.Mutex
	pendingList map[string]bool // ids of tools/list requests awaiting replies
}

// NewFilter builds a Filter.
func NewFilter(p Policy, log func(Event)) *Filter {
	return &Filter{Policy: p, Log: log, pendingList: map[string]bool{}}
}

type message struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// errAmbiguous marks a message the guard will not forward because another
// JSON parser might read it differently from the guard.
var errAmbiguous = errors.New("ambiguous or malformed message")

// protocolKeys are the JSON-RPC fields the guard reads; callKeys are the
// fields of tools/call parameters.
var (
	protocolKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}
	callKeys     = []string{"name", "arguments", "_meta"}
)

// parseMessage reads a JSON-RPC message by exact field names and refuses
// anything a server's JSON parser could read differently.
//
// encoding/json matches struct fields regardless of case and lets the last of
// two duplicate keys win. Decoding into a struct, a message carrying both
// "name" and "Name" (or "method" and "Method") could name an allowed tool to
// the guard and a denied one to a server written in another language. Invalid
// JSON is refused for the same reason: Python's json module, for one, accepts
// NaN, so a message Go cannot parse might still run a tool there.
func parseMessage(raw []byte) (message, error) {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return message{}, errAmbiguous
	}
	fields, err := exactObject(raw, protocolKeys)
	if err != nil {
		return message{}, err
	}
	m := message{ID: fields["id"], Params: fields["params"], Result: fields["result"], Error: fields["error"]}
	if v, ok := fields["method"]; ok {
		if json.Unmarshal(v, &m.Method) != nil {
			return message{}, errAmbiguous // method must be a string
		}
	}
	if v, ok := fields["jsonrpc"]; ok {
		_ = json.Unmarshal(v, &m.JSONRPC)
	}
	return m, nil
}

// exactObject returns a JSON object's members by exact key. It refuses
// duplicate keys, and keys that match one of known only when case is ignored
// (including Unicode folds such as the Kelvin sign for k).
func exactObject(raw []byte, known []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errAmbiguous
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errAmbiguous
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errAmbiguous
		}
		if _, dup := out[key]; dup {
			return nil, errAmbiguous
		}
		for _, k := range known {
			if key != k && strings.EqualFold(key, k) {
				return nil, errAmbiguous
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errAmbiguous
		}
		out[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errAmbiguous
	}
	return out, nil
}

// callTarget reads the tool name and arguments of a tools/call.
func callTarget(params json.RawMessage) (string, json.RawMessage, error) {
	fields, err := exactObject(params, callKeys)
	if err != nil {
		return "", nil, err
	}
	var name string
	if json.Unmarshal(fields["name"], &name) != nil || name == "" {
		return "", nil, errAmbiguous
	}
	return name, fields["arguments"], nil
}

func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if err := json.Compact(&b, id); err != nil {
		return string(id)
	}
	return b.String()
}

func (f *Filter) emit(e Event) {
	if f.Log == nil {
		return
	}
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	e.Event = "mcp"
	e.Server = f.Policy.Server
	f.Log(e)
}

// FromClient inspects one message from the agent. It returns the bytes to
// forward to the server (nil to forward nothing) and, when the guard answers
// the agent itself, the reply to send back. Messages the guard cannot read
// unambiguously are never forwarded.
func (f *Filter) FromClient(line []byte) (forward, reply []byte) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if !utf8.Valid(trimmed) || !json.Valid(trimmed) {
			return nil, f.refuse(nil, "")
		}
		return f.batch(trimmed, f.fromClientOne)
	}
	fwd, rep := f.fromClientOne(trimmed)
	return fwd, rep
}

// refuse records and answers a message the guard will not forward.
func (f *Filter) refuse(id json.RawMessage, method string) []byte {
	f.emit(Event{Method: method, Action: "deny", Reason: errAmbiguous.Error()})
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return errorReply(id, -32600, "Rig refused an MCP message it could not read unambiguously")
}

func (f *Filter) fromClientOne(raw []byte) ([]byte, []byte) {
	m, err := parseMessage(raw)
	if err != nil {
		return nil, f.refuse(nil, "")
	}
	switch m.Method {
	case "tools/call":
		name, args, err := callTarget(m.Params)
		if err != nil {
			if len(m.ID) == 0 {
				f.emit(Event{Method: m.Method, Action: "deny", Reason: errAmbiguous.Error()})
				return nil, nil
			}
			return nil, f.refuse(m.ID, m.Method)
		}
		ok, reason := f.Policy.Permits(name)
		ev := Event{Method: m.Method, Tool: name, Action: "allow"}
		if f.Policy.LogArgs && len(args) > 0 {
			ev.Args = truncate(string(args), f.Policy.maxArgs())
		}
		if !ok {
			ev.Action, ev.Reason = "deny", reason
			f.emit(ev)
			if len(m.ID) == 0 {
				return nil, nil // a notification: nothing to answer
			}
			return nil, blockedReply(m.ID, name, reason)
		}
		f.emit(ev)
	case "tools/list":
		if len(m.ID) > 0 {
			f.mu.Lock()
			f.pendingList[idKey(m.ID)] = true
			f.mu.Unlock()
		}
	}
	return raw, nil
}

// FromServer inspects one message from the server and returns what to deliver
// to the agent.
func (f *Filter) FromServer(line []byte) []byte {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		out, _ := f.batch(trimmed, func(raw []byte) ([]byte, []byte) { return f.fromServerOne(raw), nil })
		return out
	}
	return f.fromServerOne(trimmed)
}

func (f *Filter) fromServerOne(raw []byte) []byte {
	m, err := parseMessage(raw)
	if err != nil || len(m.ID) == 0 || m.Method != "" {
		return raw
	}
	key := idKey(m.ID)
	f.mu.Lock()
	pending := f.pendingList[key]
	delete(f.pendingList, key)
	f.mu.Unlock()
	if !pending || len(m.Result) == 0 {
		return raw
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &result); err != nil {
		return raw
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(result["tools"], &tools); err != nil {
		return raw
	}
	kept := make([]json.RawMessage, 0, len(tools))
	hidden := 0
	for _, t := range tools {
		var name string
		if fields, err := exactObject(t, []string{"name"}); err == nil {
			_ = json.Unmarshal(fields["name"], &name)
		}
		if ok, _ := f.Policy.Permits(name); ok && name != "" {
			kept = append(kept, t)
		} else {
			hidden++
		}
	}
	if hidden == 0 {
		return raw
	}
	f.emit(Event{Method: "tools/list", Action: "filter", Hidden: hidden})
	result["tools"], _ = json.Marshal(kept)
	m.Result, _ = json.Marshal(result)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// batch applies fn to each element of a JSON-RPC batch.
func (f *Filter) batch(raw []byte, fn func([]byte) ([]byte, []byte)) ([]byte, []byte) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return raw, nil
	}
	var fwd, rep []json.RawMessage
	for _, it := range items {
		a, b := fn(it)
		if a != nil {
			fwd = append(fwd, a)
		}
		if b != nil {
			rep = append(rep, b)
		}
	}
	var fwdOut, repOut []byte
	if len(fwd) > 0 {
		fwdOut, _ = json.Marshal(fwd)
	}
	if len(rep) > 0 {
		repOut, _ = json.Marshal(rep)
	}
	return fwdOut, repOut
}

// blockedReply answers a refused tools/call the way MCP reports a tool error,
// so the model reads why the call failed instead of seeing a protocol fault.
func blockedReply(id json.RawMessage, tool, reason string) []byte {
	text := fmt.Sprintf("Rig blocked the tool %q: it %s in this sandbox's policy.", tool, reason)
	out, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"content": []map[string]string{{"type": "text", "text": text}},
			"isError": true,
		},
	})
	return out
}

func (p Policy) maxArgs() int {
	if p.MaxArgBytes > 0 {
		return p.MaxArgBytes
	}
	return 2048
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// errorReply builds a JSON-RPC error response.
func errorReply(id json.RawMessage, code int, msg string) []byte {
	out, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
	return out
}

// isInitialize reports whether raw is (or a batch containing) an initialize request.
func isInitialize(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return false
		}
		for _, it := range items {
			if isInitialize(it) {
				return true
			}
		}
		return false
	}
	m, err := parseMessage(raw)
	return err == nil && m.Method == "initialize" && len(m.ID) > 0
}
