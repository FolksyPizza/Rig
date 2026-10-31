package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/monitor"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// A sandbox started with 'rig run -d' (or left with --keep-running) is looked
// after by a background Rig process, the supervisor. It owns the sandbox's
// gateway and monitors it exactly as an interactive session would, applying
// the level's policy, until the sandbox stops. Sessions you open with
// 'rig shell' show its alerts.

// supervisorState is what a supervisor records about itself.
type supervisorState struct {
	PID       int    `json:"pid"`
	Container string `json:"container"`
	Started   string `json:"started"`
}

func supervisorDir(profile string) (string, error) { return config.StateDir(profile, "background") }

func supervisorPath(profile, containerName string) string {
	dir, err := supervisorDir(profile)
	if err != nil {
		return ""
	}
	return filepath.Join(dir, containerName+".json")
}

// supervisorFor returns the PID of the live supervisor of a container, or 0.
func supervisorFor(profile, containerName string) int {
	path := supervisorPath(profile, containerName)
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var st supervisorState
	if json.Unmarshal(data, &st) != nil || st.PID <= 0 {
		return 0
	}
	if st.PID == os.Getpid() || processAlive(st.PID) {
		return st.PID
	}
	_ = os.Remove(path)
	return 0
}

// startBackground starts a sandbox in the background: the image is built here,
// where you can see the progress, then a supervisor takes over.
func startBackground(profile *config.Profile, opts container.RunOptions) error {
	if len(opts.Command) > 0 {
		return fmt.Errorf("--detach starts the sandbox without a command; run commands in it with 'rig exec %s -- <command>'", profile.Name)
	}
	ctx, cancel := signalContext()
	defer cancel()
	eff := profile.Resolve()
	if _, err := engineFor(eff); err != nil {
		return err
	}
	builder, err := container.NewBuilder()
	if err != nil {
		return err
	}
	if err := ensureImage(ctx, builder, profile, false); err != nil {
		return err
	}
	if err := spawnSupervisor(profile, opts); err != nil {
		return err
	}
	fmt.Printf("  %s is running in the background, monitored (%s).\n", paint("1;35", profile.Name), eff.MonitorMode)
	fmt.Printf("  Enter it:  rig shell %s\n  Watch it:  rig monitor %s\n  Stop it:   rig stop %s\n", profile.Name, profile.Name, profile.Name)
	return nil
}

// spawnSupervisor starts the background process and waits until it monitors
// the sandbox, or reports why it could not start.
func spawnSupervisor(profile *config.Profile, opts container.RunOptions) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := supervisorDir(profile.Name)
	if err != nil {
		return err
	}
	logPath := filepath.Join(dir, "supervisor.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	readyPath := filepath.Join(dir, fmt.Sprintf("ready.%d", time.Now().UnixNano()))

	args := []string{"_supervise", profile.Name, "--ready-file", readyPath}
	if opts.Container != "" {
		args = append(args, "--container", opts.Container)
	}
	if opts.NewInstance {
		args = append(args, "--new")
	}
	if opts.Recreate {
		args = append(args, "--recreate")
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", opts.Timeout.String())
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	cmd := exec.Command(self, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logFile, logFile
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	deadline := time.After(10 * time.Minute)
	for {
		if data, err := os.ReadFile(readyPath); err == nil {
			_ = os.Remove(readyPath)
			if msg := strings.TrimSpace(string(data)); msg != "ok" {
				return fmt.Errorf("%s", msg)
			}
			_ = cmd.Process.Release()
			return nil
		}
		select {
		case <-exited:
			_ = os.Remove(readyPath)
			return fmt.Errorf("the background process stopped before the sandbox was ready:\n%s", lastLines(logPath, 12))
		case <-deadline:
			return fmt.Errorf("timed out waiting for the sandbox to start; see %s", logPath)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func lastLines(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i, l := range lines {
		lines[i] = "    " + safeText(l)
	}
	return strings.Join(lines, "\n")
}

func superviseCmd() *cobra.Command {
	var (
		readyFile, containerName string
		newInstance, recreate    bool
		timeout                  time.Duration
	)
	cmd := &cobra.Command{
		Use:    "_supervise <name>",
		Short:  "Monitor a background sandbox (started by 'rig run -d')",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ready := func(msg string) {
				if readyFile != "" {
					_ = os.WriteFile(readyFile, []byte(msg+"\n"), 0o600)
				}
			}
			_, profile, err := loadProfile(args[0])
			if err != nil {
				ready(err.Error())
				return err
			}
			err = supervise(profile, container.RunOptions{
				Container: containerName, NewInstance: newInstance, Recreate: recreate, Timeout: timeout, Detach: true,
			}, ready)
			if err != nil {
				ready(err.Error())
				fmt.Fprintf(os.Stderr, "%s rig: %v\n", time.Now().Format(time.RFC3339), err)
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&readyFile, "ready-file", "", "")
	f.StringVar(&containerName, "container", "", "")
	f.BoolVar(&newInstance, "new", false, "")
	f.BoolVar(&recreate, "recreate", false, "")
	f.DurationVar(&timeout, "timeout", 0, "")
	return cmd
}

// supervise wires the sandbox, monitors it until it stops, then cleans up.
func supervise(profile *config.Profile, opts container.RunOptions, ready func(string)) error {
	ctx, cancel := signalContext()
	defer cancel()

	sr, err := prepareSandbox(ctx, profile, opts, true)
	if err != nil {
		return err
	}
	name := sr.prepared.Name
	if pid := supervisorFor(profile.Name, name); pid > 0 && pid != os.Getpid() {
		sr.gw.Stop()
		ready("ok")
		return nil // another background process already looks after it
	}
	state, _ := json.Marshal(supervisorState{PID: os.Getpid(), Container: name, Started: time.Now().UTC().Format(time.RFC3339)})
	statePath := supervisorPath(profile.Name, name)
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		sr.gw.Stop()
		return err
	}
	defer os.Remove(statePath)

	sess := openSession(profile.Name, name)
	monCtx, monCancel := context.WithCancel(ctx)
	results := sr.monitor(monCtx, nil)
	if sr.eff.MonitorMode == "off" {
		results = nil // nothing to wait for; run until the sandbox stops
	}
	if opts.Timeout > 0 {
		go func() {
			select {
			case <-time.After(opts.Timeout):
				fmt.Printf("%s stopping %s after --timeout %s\n", time.Now().Format(time.RFC3339), name, opts.Timeout)
				_ = sr.runner.Stop(context.Background(), name)
			case <-ctx.Done():
			}
		}()
	}
	fmt.Printf("%s monitoring %s (%s)\n", time.Now().Format(time.RFC3339), name, sr.eff.MonitorMode)
	ready("ok")

	var cause *watchdog.Observation
	stopped := false
wait:
	for {
		select {
		case cause = <-results:
			break wait
		case <-ctx.Done():
			break wait
		case <-time.After(2 * time.Second):
			if !sr.runner.Running(context.Background(), name) {
				stopped = true
				break wait
			}
		}
	}
	monCancel()
	if cause == nil && !stopped {
		select {
		case cause = <-results:
		case <-time.After(5 * time.Second):
		}
	}
	sess.close()
	// Nothing runs unwatched: if this process is told to stop, the sandbox
	// stops with it.
	if !stopped && sr.runner.Running(context.Background(), name) {
		_ = sr.runner.Stop(context.Background(), name)
	}
	if cause != nil {
		fmt.Printf("%s Rig stopped %s: %s\n", time.Now().Format(time.RFC3339), name, cause.Detail)
	} else {
		fmt.Printf("%s %s stopped\n", time.Now().Format(time.RFC3339), name)
	}
	sr.gw.Stop()
	teardownIfIdle(sr.runner, sr.nm, profile.Name)
	return nil
}

// followAlerts shows, in this session, the alerts a background process
// raises for the container, and reports the one that stopped it.
func followAlerts(ctx context.Context, profileName, containerName string, notify func(watchdog.Event)) <-chan *watchdog.Observation {
	results := make(chan *watchdog.Observation, 1)
	path, err := config.AuditPath(profileName)
	if err != nil {
		results <- nil
		return results
	}
	go func() {
		var cause *watchdog.Observation
		_ = followAudit(ctx, path, containerName, func(r monitor.Record) {
			if r.Action == string(watchdog.ActionAllow) || r.Container != containerName {
				return
			}
			o := watchdog.Observation{Kind: r.Kind, Detail: r.Detail, Source: r.Source, Data: r.Data}
			e := watchdog.Event{Action: watchdog.Action(r.Action), Observation: o}
			if notify != nil {
				notify(e)
			}
			if e.Action == watchdog.ActionKill && cause == nil {
				c := o
				cause = &c
			}
		})
		results <- cause
	}()
	return results
}

// backgroundNote describes how a running container is monitored, for 'rig ps'.
func backgroundNote(profile, containerName string) string {
	if pid := supervisorFor(profile, containerName); pid > 0 {
		return "yes (background, PID " + strconv.Itoa(pid) + ")"
	}
	return ""
}
