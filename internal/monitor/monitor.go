// Package monitor connects the watchdog to a live sandbox.
//
// It gathers observations from the egress proxy, the gateway, the tool-call
// guard, the process table and resource usage, records every one in the
// profile's audit log, alerts on violations, and stops the sandbox when the
// profile's policy says to. An optional AI reviewer sees the same stream.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

const defaultInterval = 2 * time.Second

// EvaluateStats maps a stats sample to a watchdog observation when it breaches
// the memory cap. Pure, so the escalation logic is testable.
func EvaluateStats(s provider.Stats, memLimitBytes int64) (watchdog.Observation, bool) {
	if memLimitBytes > 0 && s.MemBytes > memLimitBytes {
		sev := watchdog.SevHigh
		if s.MemBytes > memLimitBytes*12/10 { // >20% over the cap is critical
			sev = watchdog.SevCritical
		}
		return watchdog.Observation{
			Source:   "resource",
			Kind:     "resource_breach",
			Severity: sev,
			Detail:   fmt.Sprintf("memory %d bytes over limit %d", s.MemBytes, memLimitBytes),
		}, true
	}
	return watchdog.Observation{}, false
}

// EvaluatePIDs flags a sandbox close to its process limit, which is what a
// fork bomb looks like just before the limit stops it.
func EvaluatePIDs(s provider.Stats, pidLimit int64) (watchdog.Observation, bool) {
	if pidLimit > 0 && int64(s.PIDs)*10 >= pidLimit*9 {
		return watchdog.Observation{
			Source:   "resource",
			Kind:     "pid_pressure",
			Severity: watchdog.SevMedium,
			Detail:   fmt.Sprintf("%d processes, close to the limit of %d", s.PIDs, pidLimit),
		}, true
	}
	return watchdog.Observation{}, false
}

// ProviderEnforcer stops a container through its provider.
type ProviderEnforcer struct {
	Provider  provider.Provider
	Container string
}

func (e ProviderEnforcer) Kill(ctx context.Context, reason string) error {
	return e.Provider.Kill(ctx, e.Container)
}

// ResourceObserver polls the provider for stats and emits breach observations.
type ResourceObserver struct {
	Provider      provider.Provider
	Container     string
	MemLimitBytes int64
	PIDLimit      int64
	Interval      time.Duration
}

func (o ResourceObserver) Observe(ctx context.Context) (<-chan watchdog.Observation, error) {
	interval := o.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	ch := make(chan watchdog.Observation)
	go func() {
		defer close(ch)
		t := time.NewTicker(interval)
		defer t.Stop()
		var lastPID time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s, err := o.Provider.Stats(ctx, o.Container)
				if err != nil {
					continue // a transient stats failure is not a policy signal
				}
				var found []watchdog.Observation
				if obs, ok := EvaluateStats(s, o.MemLimitBytes); ok {
					found = append(found, obs)
				}
				if obs, ok := EvaluatePIDs(s, o.PIDLimit); ok && time.Since(lastPID) > time.Minute {
					lastPID = time.Now()
					found = append(found, obs)
				}
				for _, obs := range found {
					select {
					case ch <- obs:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return ch, nil
}

// New builds a resource-only watchdog Monitor for a running container.
func New(p provider.Provider, container string, prof *config.Profile, report func(watchdog.Event)) *watchdog.Monitor {
	mode, strictness := prof.Monitor.Mode, prof.Monitor.Strictness
	if mode == "" {
		mode, strictness = prof.Watchdog.Mode, prof.Watchdog.Strictness // pre-1.0 field name
	}
	return &watchdog.Monitor{
		Policy: watchdog.NewPolicy(mode, strictness),
		Observer: ResourceObserver{
			Provider:      p,
			Container:     container,
			MemLimitBytes: prof.Resources.Memory * 1024 * 1024, // profile memory is MB
			PIDLimit:      prof.Resources.PIDLimit,
		},
		Enforcer: ProviderEnforcer{Provider: p, Container: container},
		Report:   report,
	}
}

// Feeder receives every observation, for the AI reviewer.
type Feeder interface {
	Feed(o watchdog.Observation)
}

// Pipeline is a full monitoring session for one sandbox.
type Pipeline struct {
	Profile   string
	Container string
	Policy    watchdog.Policy
	Sources   []watchdog.Observer
	Enforcer  watchdog.Enforcer
	Audit     *Audit
	// Notify is called for flags and kills, to tell the user.
	Notify func(watchdog.Event)
	// AI, when set, is fed every non-AI observation; its own verdicts arrive
	// as one of the Sources.
	AI Feeder
}

// Run monitors until ctx ends or a kill fires, and returns the observation
// that caused a kill, if any.
func (p *Pipeline) Run(ctx context.Context) (*watchdog.Observation, error) {
	m := &watchdog.Monitor{
		Policy:   p.Policy,
		Observer: watchdog.Merge(p.Sources...),
		Enforcer: p.Enforcer,
		Report: func(e watchdog.Event) {
			if p.Audit != nil {
				_ = p.Audit.Write(Record{
					TS:        e.Time.UTC().Format(time.RFC3339Nano),
					Profile:   p.Profile,
					Container: p.Container,
					Source:    e.Observation.Source,
					Kind:      e.Observation.Kind,
					Severity:  e.Observation.Severity.String(),
					Action:    string(e.Action),
					Detail:    e.Observation.Detail,
					Data:      json.RawMessage(e.Observation.Data),
				})
			}
			if e.Action != watchdog.ActionAllow && p.Notify != nil {
				p.Notify(e)
			}
			if p.AI != nil && e.Observation.Source != "ai" {
				p.AI.Feed(e.Observation)
			}
		},
	}
	return m.Run(ctx)
}
