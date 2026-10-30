package monitor

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// LineSource turns a stream of JSON log lines into observations.
type LineSource struct {
	Rules *Rules
	// Open returns the stream. It is called once; the source ends when the
	// stream does.
	Open func(ctx context.Context) (io.ReadCloser, error)
	// Lines is an alternative to Open for lines delivered by a callback.
	Lines <-chan []byte
	// Accept, if set, drops lines it returns false for (for example proxy
	// lines from other sandboxes sharing the proxy).
	Accept func(raw []byte) bool
}

func (s LineSource) Observe(ctx context.Context) (<-chan watchdog.Observation, error) {
	out := make(chan watchdog.Observation, 32)
	emit := func(raw []byte) bool {
		if s.Accept != nil && !s.Accept(raw) {
			return true
		}
		o, ok := s.Rules.Line(raw)
		if !ok {
			return true
		}
		select {
		case out <- o:
			return true
		case <-ctx.Done():
			return false
		}
	}

	if s.Lines != nil {
		go func() {
			defer close(out)
			for {
				select {
				case <-ctx.Done():
					return
				case raw, ok := <-s.Lines:
					if !ok || !emit(raw) {
						return
					}
				}
			}
		}()
		return out, nil
	}

	rc, err := s.Open(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(out)
		defer rc.Close()
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if !emit(append([]byte{}, sc.Bytes()...)) {
				return
			}
		}
	}()
	return out, nil
}

// CommandStream runs a command and returns its stdout (or stderr), for
// LineSource.Open. The command is killed when ctx ends.
func CommandStream(stderr bool, name string, args ...string) func(ctx context.Context) (io.ReadCloser, error) {
	return func(ctx context.Context) (io.ReadCloser, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		var out io.ReadCloser
		var err error
		if stderr {
			out, err = cmd.StderrPipe()
		} else {
			out, err = cmd.StdoutPipe()
		}
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		go func() { _ = cmd.Wait() }()
		return out, nil
	}
}

// ProcessSource polls the sandbox's process table through the engine and
// reports each new process once. Polling can miss a process that lives for
// less than one interval; the egress proxy, which sees every connection,
// does not have that gap.
type ProcessSource struct {
	Rules     *Rules
	Engine    string // engine binary
	Podman    bool   // podman takes format descriptors instead of ps options
	Container string
	Interval  time.Duration
	// MaxPerMinute caps routine process reports so a busy build cannot flood
	// the audit log. Suspicious processes are always reported.
	MaxPerMinute int
	// Ignore skips processes Rig itself started in the sandbox, such as the
	// monitor's own log reader. It gets the command name and arguments.
	Ignore func(comm, args string) bool
	// InSandbox lists processes by running ps inside the sandbox instead of
	// asking the engine (docker top). Under gVisor or a VM the engine's top
	// looks up the runtime's process IDs on the host, where those processes
	// do not exist, so it cannot see what the sandbox runs.
	InSandbox bool
}

// sandboxPS is the command InSandbox runs; its own process is skipped.
var sandboxPS = []string{"ps", "-eo", "pid=,comm=,args="}

func (s ProcessSource) list(ctx context.Context) ([][2]string, error) {
	args := []string{"top", s.Container, "-eo", "pid,comm,args"}
	switch {
	case s.InSandbox:
		args = append([]string{"exec", s.Container}, sandboxPS...)
	case s.Podman:
		args = []string{"top", s.Container, "pid", "comm", "args"}
	}
	out, err := exec.CommandContext(ctx, s.Engine, args...).Output()
	if err != nil {
		return nil, err
	}
	var procs [][2]string // pid, "comm\x00args"
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i == 0 && !s.InSandbox {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		args := strings.Join(f[2:], " ")
		if args == "" {
			args = f[1]
		}
		procs = append(procs, [2]string{f[0], f[1] + "\x00" + args})
	}
	return procs, nil
}

func (s ProcessSource) Observe(ctx context.Context) (<-chan watchdog.Observation, error) {
	interval := s.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	max := s.MaxPerMinute
	if max <= 0 {
		max = 60
	}
	out := make(chan watchdog.Observation, 32)
	go func() {
		defer close(out)
		seen := map[string]bool{}
		windowStart := time.Now()
		reported := 0
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			procs, err := s.list(ctx)
			if err != nil {
				continue // not running yet, or between restarts
			}
			if time.Since(windowStart) > time.Minute {
				windowStart, reported = time.Now(), 0
			}
			for _, p := range procs {
				key := p[0] + "\x00" + p[1]
				if seen[key] {
					continue
				}
				seen[key] = true
				comm, args, _ := strings.Cut(p[1], "\x00")
				if s.Ignore != nil && s.Ignore(comm, args) {
					continue
				}
				if s.InSandbox && comm == "ps" && args == strings.Join(sandboxPS, " ") {
					continue
				}
				o := s.Rules.Process(comm, args)
				if o.Severity == watchdog.SevInfo {
					if reported >= max {
						continue
					}
					reported++
				}
				select {
				case out <- o:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// IsolatedRuntime reports whether a container runs under gVisor or in a VM,
// where the engine's top cannot list its processes (see InSandbox).
func IsolatedRuntime(ctx context.Context, engine, container string, podman bool) bool {
	format := "{{.HostConfig.Runtime}}"
	if podman {
		format = "{{.OCIRuntime}}"
	}
	out, err := exec.CommandContext(ctx, engine, "inspect", "-f", format, container).Output()
	if err != nil {
		return false
	}
	rt := strings.TrimSpace(string(out))
	return provider.IsGVisor(rt) || provider.IsKata(rt)
}
