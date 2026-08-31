//go:build integration

package monitor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// TestLiveWatchdogKills drives the watchdog against a real, running container through the
// detected provider. It needs a running container (default name rig-wd-live) and the
// provider's service up. Run with:  go test -tags integration -run Live -v ./internal/monitor
func TestLiveWatchdogKills(t *testing.T) {
	p := provider.Detect()
	if !p.Available() {
		t.Skipf("provider %s not available", p.Name())
	}
	name := os.Getenv("RIG_LIVE_CONTAINER")
	if name == "" {
		name = "rig-wd-live"
	}
	ctx := context.Background()

	// Real stats must parse from the live provider.
	s, err := p.Stats(ctx, name)
	if err != nil {
		t.Fatalf("live stats for %q failed (is it running?): %v", name, err)
	}
	if s.MemBytes <= 0 {
		t.Fatalf("expected real memory usage, got %d (parser mismatch?)", s.MemBytes)
	}
	t.Logf("live stats via %s: mem=%d limit=%d pids=%d", p.Name(), s.MemBytes, s.MemLimit, s.PIDs)

	// A 1 MiB cap is below any real container's usage, so the watchdog must fire.
	prof := &config.Profile{
		Resources: config.ResourcesConfig{Memory: 1},
		Watchdog:  config.WatchdogConfig{Mode: "enforce", Strictness: "high"},
	}
	m := New(p, name, prof, func(e watchdog.Event) {
		t.Logf("watchdog event: %s %s", e.Action, e.Observation.Detail)
	})
	m.Observer = ResourceObserver{Provider: p, Container: name, MemLimitBytes: 1 << 20, Interval: 200 * time.Millisecond}

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cause, err := m.Run(cctx)
	if err != nil {
		t.Fatalf("monitor run (kill) errored: %v", err)
	}
	if cause == nil || cause.Kind != "resource_breach" {
		t.Fatalf("expected a resource_breach kill, got %+v", cause)
	}
	t.Logf("watchdog killed %q on: %s", name, cause.Detail)
}
