package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

func TestEvaluateStats(t *testing.T) {
	limit := int64(100 << 20) // 100 MiB
	if _, ok := EvaluateStats(provider.Stats{MemBytes: 50 << 20}, limit); ok {
		t.Error("under limit should not breach")
	}
	obs, ok := EvaluateStats(provider.Stats{MemBytes: 110 << 20}, limit)
	if !ok || obs.Severity != watchdog.SevHigh {
		t.Errorf("just-over should be high breach, got %+v ok=%v", obs, ok)
	}
	obs, ok = EvaluateStats(provider.Stats{MemBytes: 200 << 20}, limit)
	if !ok || obs.Severity != watchdog.SevCritical {
		t.Errorf("far-over should be critical, got %+v", obs)
	}
	if _, ok := EvaluateStats(provider.Stats{MemBytes: 999}, 0); ok {
		t.Error("no limit configured should never breach")
	}
}

// fakeProvider always reports memory over the cap, and records kills.
type fakeProvider struct {
	memBytes int64
	killed   []string
}

func (f *fakeProvider) Name() string    { return "fake" }
func (f *fakeProvider) Bin() string     { return "fake" }
func (f *fakeProvider) Available() bool { return true }
func (f *fakeProvider) Stats(ctx context.Context, name string) (provider.Stats, error) {
	return provider.Stats{MemBytes: f.memBytes}, nil
}
func (f *fakeProvider) Stop(ctx context.Context, name string) error { return nil }
func (f *fakeProvider) Kill(ctx context.Context, name string) error {
	f.killed = append(f.killed, name)
	return nil
}
func (f *fakeProvider) List(ctx context.Context) ([]string, error) { return nil, nil }

func TestMonitorKillsOnBreach(t *testing.T) {
	fp := &fakeProvider{memBytes: 300 << 20} // 300 MiB, well over the 100 MiB cap
	prof := &config.Profile{
		Resources: config.ResourcesConfig{Memory: 100}, // 100 MB
		Watchdog:  config.WatchdogConfig{Mode: "enforce", Strictness: "high"},
	}
	m := New(fp, "rig-test", prof, nil)
	m.Observer = ResourceObserver{Provider: fp, Container: "rig-test", MemLimitBytes: 100 << 20, Interval: time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cause, err := m.Run(ctx)
	if err != nil {
		t.Fatalf("run err: %v", err)
	}
	if cause == nil || cause.Kind != "resource_breach" {
		t.Fatalf("expected resource_breach kill, got %+v", cause)
	}
	if len(fp.killed) != 1 || fp.killed[0] != "rig-test" {
		t.Fatalf("expected one kill of rig-test, got %v", fp.killed)
	}
}

func TestMonitorObserveModeDoesNotKill(t *testing.T) {
	fp := &fakeProvider{memBytes: 300 << 20}
	prof := &config.Profile{
		Resources: config.ResourcesConfig{Memory: 100},
		Watchdog:  config.WatchdogConfig{Mode: "observe"},
	}
	m := New(fp, "rig-test", prof, nil)
	m.Observer = ResourceObserver{Provider: fp, Container: "rig-test", MemLimitBytes: 100 << 20, Interval: time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = m.Run(ctx)
	if len(fp.killed) != 0 {
		t.Fatalf("observe mode must not kill, got %v", fp.killed)
	}
}

func providerStats(pids int) provider.Stats { return provider.Stats{PIDs: pids} }

func TestEngineInitIsNotAScratchProgram(t *testing.T) {
	r := NewRules(0, true)
	if o := r.Process("podman-init", "/run/podman-init -- /usr/local/bin/rig-entrypoint sleep infinity"); o.Kind != "process_started" {
		t.Errorf("Podman's init flagged: %+v", o)
	}
	if o := r.Process("evil", "/run/evil --connect"); o.Kind != "exec_from_temp" {
		t.Errorf("a program under /run should still be flagged: %+v", o)
	}
}
