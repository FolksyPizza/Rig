// Package monitor connects the watchdog to a live container provider.
//
// It samples a running container's stats and turns resource breaches into watchdog
// observations, and enforces kill decisions by asking the provider to stop the container.
// This is what wires the (provider-agnostic) watchdog to Apple `container`, Podman, or Docker.
package monitor

import (
	"context"
	"fmt"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

const defaultInterval = 2 * time.Second

// EvaluateStats maps a stats sample to a watchdog observation when it breaches the memory
// cap. Pure, so the escalation logic is testable without a live container.
func EvaluateStats(s provider.Stats, memLimitBytes int64) (watchdog.Observation, bool) {
	if memLimitBytes > 0 && s.MemBytes > memLimitBytes {
		sev := watchdog.SevHigh
		if s.MemBytes > memLimitBytes*12/10 { // >20% over the cap is critical
			sev = watchdog.SevCritical
		}
		return watchdog.Observation{
			Kind:     "resource_breach",
			Severity: sev,
			Detail:   fmt.Sprintf("memory %d bytes over limit %d", s.MemBytes, memLimitBytes),
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s, err := o.Provider.Stats(ctx, o.Container)
				if err != nil {
					continue // a transient stats failure is not a policy signal
				}
				if obs, ok := EvaluateStats(s, o.MemLimitBytes); ok {
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

// New builds a watchdog Monitor for a running container from its profile's watchdog config.
func New(p provider.Provider, container string, prof *config.Profile, report func(watchdog.Event)) *watchdog.Monitor {
	return &watchdog.Monitor{
		Policy: watchdog.NewPolicy(prof.Watchdog.Mode, prof.Watchdog.Strictness),
		Observer: ResourceObserver{
			Provider:      p,
			Container:     container,
			MemLimitBytes: prof.Resources.Memory * 1024 * 1024, // profile memory is MB
		},
		Enforcer: ProviderEnforcer{Provider: p, Container: container},
		Report:   report,
	}
}
