// Package watchdog monitors a running sandbox and reacts to policy violations.
//
// It is deliberately runtime-agnostic: the policy decides what to do with an
// observation, while getting observations (network attempts, resource breaches,
// banned processes) and carrying out a kill are behind small interfaces. That
// keeps the decision logic testable without Docker, and lets a Docker- or
// sandbox-exec-backed adapter supply the real observations later.
package watchdog

import (
	"context"
	"fmt"
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

// Severity ranks how dangerous an observed violation is.
type Severity int

const (
	SevLow Severity = iota
	SevMedium
	SevHigh
	SevCritical
)

// Action is the watchdog's decision for one observation.
type Action string

const (
	ActionAllow Action = "allow" // below any threshold, or watchdog off
	ActionFlag  Action = "flag"  // record/alert, let it continue
	ActionKill  Action = "kill"  // stop the sandbox
)

// Observation is a single policy-relevant event seen inside a sandbox.
type Observation struct {
	Kind     string   // e.g. "network_denied", "resource_breach", "banned_process"
	Severity Severity
	Detail   string
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
	switch p.Mode {
	case ModeOff:
		return ActionAllow
	case ModeObserve:
		return ActionFlag
	default: // enforce
		if o.Severity >= p.killThreshold() {
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

// Event is what the monitor reports for each acted-upon observation. Omni reads
// these to fold watchdog activity into its audit log.
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
	Report   func(Event) // optional sink for flag/kill events
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
			if action == ActionAllow {
				continue
			}
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
