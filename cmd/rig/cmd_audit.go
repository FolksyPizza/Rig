package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/monitor"
	"github.com/FolksyPizza/rig/internal/provider"
)

func auditCmd() *cobra.Command {
	var (
		lines             int
		follow, asJSON    bool
		flagged, showPath bool
		kind              string
		since             time.Duration
	)
	cmd := &cobra.Command{
		Use:   "audit <name>",
		Short: "Show what a sandbox did",
		Long: `Show a sandbox's audit log: connections allowed and blocked, MCP tool calls,
git pushes, processes Rig flagged, resource alarms, AI monitor verdicts, and
anything Rig stopped. The log is kept on this computer, outside every sandbox,
so nothing inside can change it.

  rig audit work                 the last 50 events
  rig audit work --flagged       only what Rig flagged or stopped
  rig audit work --since 1h      the last hour
  rig audit work -f              follow new events as they happen
  rig audit work --json          raw JSON lines, for scripts`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := config.AuditPath(args[0])
			if err != nil {
				return err
			}
			if showPath {
				fmt.Println(path)
				return nil
			}
			keep := func(r monitor.Record) bool {
				if flagged && r.Action == "allow" {
					return false
				}
				if kind != "" && !strings.Contains(r.Kind, kind) {
					return false
				}
				if since > 0 {
					if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil && time.Since(t) > since {
						return false
					}
				}
				return true
			}
			show := func(r monitor.Record) {
				if !keep(r) {
					return
				}
				if asJSON {
					b, _ := json.Marshal(r)
					fmt.Println(string(b))
					return
				}
				printRecord(r)
			}

			n := lines
			if flagged || kind != "" || since > 0 {
				n = 0 // filter the whole log, then trim
			}
			records, err := monitor.ReadAudit(path, n)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			var kept []monitor.Record
			for _, r := range records {
				if keep(r) {
					kept = append(kept, r)
				}
			}
			if lines > 0 && len(kept) > lines {
				kept = kept[len(kept)-lines:]
			}
			if len(kept) == 0 && !follow && !asJSON {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Printf("  No audit log for %s yet; it starts when the sandbox first runs.\n", args[0])
				} else {
					fmt.Println("  No matching events.")
				}
				return nil
			}
			for _, r := range kept {
				show(r)
			}
			if !follow {
				return nil
			}
			ctx, cancel := signalContext()
			defer cancel()
			return followAudit(ctx, path, "", show)
		},
	}
	f := cmd.Flags()
	f.IntVarP(&lines, "lines", "n", 50, "how many recent events to show (0 for all)")
	f.BoolVarP(&follow, "follow", "f", false, "keep showing new events")
	f.BoolVar(&asJSON, "json", false, "print raw JSON lines")
	f.BoolVar(&flagged, "flagged", false, "only events Rig flagged or acted on")
	f.StringVar(&kind, "kind", "", "only events whose kind contains this (e.g. egress, mcp, process)")
	f.DurationVar(&since, "since", 0, "only events newer than this (e.g. 30m, 24h)")
	f.BoolVar(&showPath, "path", false, "print the log file's location and exit")
	return cmd
}

// printRecord prints one audit record as a single readable line.
func printRecord(r monitor.Record) {
	ts := r.TS
	if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil {
		t = t.Local()
		if time.Since(t) < 20*time.Hour {
			ts = t.Format("15:04:05")
		} else {
			ts = t.Format("Jan 02 15:04")
		}
	}
	var action string
	switch r.Action {
	case "kill":
		action = paint("1;31", "STOP")
	case "flag":
		action = paint("1;33", "FLAG")
	default:
		action = paint("2", " ok ")
	}
	sev := ""
	if r.Severity != "" && r.Severity != "info" {
		sev = " " + paint("2", "["+r.Severity+"]")
	}
	fmt.Printf("%s  %s  %-16s %s%s\n", safeText(ts), action, safeText(r.Kind), safeText(r.Detail), safeText(sev))
}

// followAudit prints records appended to the log from now on, following
// rotation, until ctx ends. container, if set, filters by container.
func followAudit(ctx context.Context, path, container string, show func(monitor.Record)) error {
	var f *os.File
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	var reader *bufio.Reader
	var partial []byte
	open := func(fromStart bool) bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		if !fromStart {
			if _, err := nf.Seek(0, io.SeekEnd); err != nil {
				nf.Close()
				return false
			}
		}
		if f != nil {
			f.Close()
		}
		f, reader, partial = nf, bufio.NewReader(nf), nil
		return true
	}
	open(false)

	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		if reader != nil {
			for {
				chunk, err := reader.ReadBytes('\n')
				partial = append(partial, chunk...)
				if err != nil {
					break
				}
				line := bytes.TrimSpace(partial)
				partial = nil
				var r monitor.Record
				if len(line) == 0 || json.Unmarshal(line, &r) != nil {
					continue
				}
				if container == "" || r.Container == "" || r.Container == container {
					show(r)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		// Reopen from the start when the log was created or rotated.
		cur, err := os.Stat(path)
		if err != nil {
			continue
		}
		if f == nil {
			open(true)
			continue
		}
		if info, err := f.Stat(); err != nil || !os.SameFile(info, cur) {
			open(true)
		}
	}
}

func monitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor <name>",
		Short: "Watch a running sandbox live",
		Long: `Show what a running sandbox does as it happens: connections allowed and
blocked, MCP tool calls, processes, resource alarms and AI monitor verdicts.

While a 'rig run' session is open, that session does the monitoring and this
command shows its events. For a sandbox left running with --keep-running, this
command monitors it itself and applies its policy: in enforce mode a serious
violation stops the sandbox.

Press Ctrl-C to stop watching.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, profile, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			eff := profile.Resolve()
			provider.PreferIsolationCapable(needsIsolationEngine(eff))
			r := mustRunner()
			ctx, cancel := signalContext()
			defer cancel()

			target := ""
			for _, c := range r.ListByProfile(ctx, profile.Name) {
				if c.Running {
					target = c.Name
					break
				}
			}
			if target == "" {
				return fmt.Errorf("%s is not running; start it with 'rig run %s' (past events: 'rig audit %s')", profile.Name, profile.Name, profile.Name)
			}
			path, err := config.AuditPath(profile.Name)
			if err != nil {
				return err
			}

			switch pids := otherSessions(profile.Name, target); {
			case len(pids) > 0:
				fmt.Printf("  Watching %s, monitored by the rig session with PID %d. Ctrl-C stops watching.\n\n", target, pids[0])
			case eff.MonitorMode == "off":
				fmt.Printf("  Monitoring is off for %s (monitor.mode: off); nothing new will be recorded.\n", profile.Name)
				return nil
			default:
				fmt.Printf("  No rig session is watching %s; monitoring it from here (%s). Ctrl-C stops.\n\n", target, eff.MonitorMode)
				var setup *container.NetworkSetup
				if eff.NetworkMode == "allowlist" {
					setup = &container.NetworkSetup{Network: "rig-net-" + profile.Name}
				}
				results := startMonitor(ctx, profile, eff, r, provider.Detect(), target, setup, nil, true)
				go func() {
					if cause := <-results; cause != nil {
						fmt.Fprintf(os.Stderr, "\n  %s %s\n", paint("1;31", "Rig stopped the sandbox:"), safeText(cause.Detail))
						cancel()
					}
				}()
			}
			return followAudit(ctx, path, target, printRecord)
		},
	}
	return cmd
}
