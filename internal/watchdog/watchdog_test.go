package watchdog

import (
	"context"
	"testing"
)

func TestPolicyEvaluate(t *testing.T) {
	tests := []struct {
		mode       Mode
		strictness Strictness
		severity   Severity
		want       Action
	}{
		{ModeOff, StrictHigh, SevCritical, ActionAllow},        // off never acts
		{ModeObserve, StrictHigh, SevCritical, ActionFlag},     // observe only flags
		{ModeEnforce, StrictLow, SevHigh, ActionFlag},          // low kills only critical
		{ModeEnforce, StrictLow, SevCritical, ActionKill},      // low kills critical
		{ModeEnforce, StrictMedium, SevMedium, ActionFlag},     // medium kills high+
		{ModeEnforce, StrictMedium, SevHigh, ActionKill},       // medium kills high
		{ModeEnforce, StrictHigh, SevMedium, ActionKill},       // high kills medium+
		{ModeEnforce, StrictHigh, SevLow, ActionFlag},          // high still flags low
	}
	for _, tc := range tests {
		p := Policy{Mode: tc.mode, Strictness: tc.strictness}
		got := p.Evaluate(Observation{Kind: "x", Severity: tc.severity})
		if got != tc.want {
			t.Errorf("Evaluate(mode=%s strict=%s sev=%d) = %s, want %s",
				tc.mode, tc.strictness, tc.severity, got, tc.want)
		}
	}
}

func TestNewPolicyDefaults(t *testing.T) {
	p := NewPolicy("", "")
	if p.Mode != ModeOff || p.Strictness != StrictMedium {
		t.Fatalf("defaults = %+v, want off/medium", p)
	}
}

// fakeObserver emits a fixed list of observations then closes.
type fakeObserver struct{ obs []Observation }

func (f fakeObserver) Observe(ctx context.Context) (<-chan Observation, error) {
	ch := make(chan Observation, len(f.obs))
	for _, o := range f.obs {
		ch <- o
	}
	close(ch)
	return ch, nil
}

type fakeEnforcer struct{ killed []string }

func (f *fakeEnforcer) Kill(ctx context.Context, reason string) error {
	f.killed = append(f.killed, reason)
	return nil
}

func TestMonitorEnforceKills(t *testing.T) {
	enf := &fakeEnforcer{}
	var events []Event
	m := &Monitor{
		Policy:   Policy{Mode: ModeEnforce, Strictness: StrictHigh},
		Observer: fakeObserver{obs: []Observation{
			{Kind: "network_denied", Severity: SevLow},
			{Kind: "banned_process", Severity: SevHigh, Detail: "nc"},
		}},
		Enforcer: enf,
		Report:   func(e Event) { events = append(events, e) },
	}
	cause, err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if cause == nil || cause.Kind != "banned_process" {
		t.Fatalf("expected kill on banned_process, got %+v", cause)
	}
	if len(enf.killed) != 1 {
		t.Fatalf("expected one kill, got %d", len(enf.killed))
	}
	// the low-severity one was flagged, the high one caused the kill
	if len(events) != 2 || events[0].Action != ActionFlag || events[1].Action != ActionKill {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestMonitorObserveDoesNotKill(t *testing.T) {
	enf := &fakeEnforcer{}
	m := &Monitor{
		Policy:   Policy{Mode: ModeObserve, Strictness: StrictHigh},
		Observer: fakeObserver{obs: []Observation{{Kind: "x", Severity: SevCritical}}},
		Enforcer: enf,
	}
	cause, err := m.Run(context.Background())
	if err != nil || cause != nil {
		t.Fatalf("observe mode should not kill; got cause=%+v err=%v", cause, err)
	}
	if len(enf.killed) != 0 {
		t.Fatalf("observe mode killed: %v", enf.killed)
	}
}

func TestMonitorOffIsNoop(t *testing.T) {
	m := &Monitor{Policy: Policy{Mode: ModeOff}, Observer: fakeObserver{obs: []Observation{{Severity: SevCritical}}}}
	cause, err := m.Run(context.Background())
	if err != nil || cause != nil {
		t.Fatalf("off mode should be a noop; got cause=%+v err=%v", cause, err)
	}
}
