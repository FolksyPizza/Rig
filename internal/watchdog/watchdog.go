// Package watchdog monitors a running sandbox and reacts to policy violations.
//
// It is deliberately runtime-agnostic: the policy decides what to do with an
// observation, while getting observations (network attempts, resource
// breaches, suspicious processes, tool calls, AI verdicts) and carrying out a
// kill are behind small interfaces. That keeps the decision logic testable
// without a container engine.
package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Mode controls how forceful the watchdog is. It is optional: "off" disables it.
type Mode string

const (
	ModeOff     Mode = "off"     // no monitoring
	ModeObserve Mode = "observe" // flag violations, never kill
	ModeEnforce Mode = "enforce" // flag and, above the strictness threshold, kill
)

// Strictness tunes how readily enforce mode escalates a flag to a kill.
type Strictness string

const (
	StrictLow    Strictness = "low"    // kill only the most severe violations
	StrictMedium Strictness = "medium" // kill high-severity and worse
	StrictHigh   Strictness = "high"   // kill medium-severity and worse
)

// Severity ranks how dangerous an observed event is.
type Severity int

const (
	// SevInfo is ordinary activity: recorded, never acted on.
	SevInfo Severity = iota - 1
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// ParseSeverity is the inverse of String.
func ParseSeverity(s string) (Severity, bool) {
	for _, v := range []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical} {
		if v.String() == s {
			return v, true
		}
	}
	return SevInfo, false
}

// Action is the watchdog's decision for one observation.
type Action string

const (
	ActionAllow Action = "allow" // recorded only
	ActionFlag  Action = "flag"  // record and alert, let it continue
	ActionKill  Action = "kill"  // stop the sandbox
)

// Observation is a single policy-relevant event seen inside a sandbox.
type Observation struct {
	Kind     string // e.g. "egress_denied", "exfil_attempt", "suspicious_tool"
	Severity Severity
	Detail   string
	// Source names where it came from: egress, process, resource, mcp, git,
	// relay, ai.
	Source string
	// Data is the source's own record, kept for the audit log.
	Data json.RawMessage
	// Advisory observations may be flagged but never kill. AI verdicts are
	// advisory unless the profile lets them enforce.
	Advisory bool
}

// Policy maps an observation to an action given the configured mode/strictness.
type Policy struct {
	Mode       Mode
	Strictness Strictness
}

// NewPolicy builds a policy, defaulting blanks to a safe baseline (off/medium).
func NewPolicy(mode, strictness string) Policy {
	m := Mode(mode)
	if m == "" {
		m = ModeOff
	}
	s := Strictness(strictness)
	if s == "" {
		s = StrictMedium
	}
	return Policy{Mode: m, Strictness: s}
}

// Evaluate decides what to do with an observation.
func (p Policy) Evaluate(o Observation) Action {
	if o.Severity <= SevInfo {
		return ActionAllow
	}
	switch p.Mode {
	case ModeOff:
		return ActionAllow
	case ModeObserve:
		return ActionFlag
	default: // enforce
		if o.Severity >= p.killThreshold() && !o.Advisory {
			return ActionKill
		}
		return ActionFlag
	}
}

// killThreshold is the lowest severity that triggers a kill in enforce mode.
func (p Policy) killThreshold() Severity {
	switch p.Strictness {
	case StrictLow:
		return SevCritical
	case StrictHigh:
		return SevMedium
	default: // medium
		return SevHigh
	}
}

// Observer yields observations for a running sandbox until the context ends.
type Observer interface {
	Observe(ctx context.Context) (<-chan Observation, error)
}

// Enforcer carries out a kill decision (stopping the sandbox).
type Enforcer interface {
	Kill(ctx context.Context, reason string) error
}

// Event is what the monitor reports for each observation and its action.
type Event struct {
	Time        time.Time
	Action      Action
	Observation Observation
}

// Monitor applies a policy to a stream of observations.
type Monitor struct {
	Policy   Policy
	Observer Observer
	Enforcer Enforcer
	Report   func(Event) // optional sink for every observation, with its action
}

// Run consumes observations until the stream closes, the context is cancelled,
// or a kill fires. It returns the observation that caused a kill, if any.
func (m *Monitor) Run(ctx context.Context) (*Observation, error) {
	if m.Policy.Mode == ModeOff {
		return nil, nil
	}
	ch, err := m.Observer.Observe(ctx)
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case o, ok := <-ch:
			if !ok {
				return nil, nil
			}
			action := m.Policy.Evaluate(o)
			m.emit(Event{Time: time.Now(), Action: action, Observation: o})
			if action == ActionKill {
				if m.Enforcer == nil {
					return &o, fmt.Errorf("kill required but no enforcer configured")
				}
				killErr := m.Enforcer.Kill(ctx, o.Kind+": "+o.Detail)
				return &o, killErr
			}
		}
	}
}

func (m *Monitor) emit(e Event) {
	if m.Report != nil {
		m.Report(e)
	}
}

// Merge combines observers into one stream. A source that fails to start is
// skipped; Observe fails only if every source fails.
func Merge(sources ...Observer) Observer { return merged(sources) }

type merged []Observer

func (ms merged) Observe(ctx context.Context) (<-chan Observation, error) {
	out := make(chan Observation, 64)
	var wg sync.WaitGroup
	var firstErr error
	started := 0
	for _, s := range ms {
		ch, err := s.Observe(ctx)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		started++
		wg.Add(1)
		go func(ch <-chan Observation) {
			defer wg.Done()
			for o := range ch {
				select {
				case out <- o:
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}
	if started == 0 && firstErr != nil {
		return nil, firstErr
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}
