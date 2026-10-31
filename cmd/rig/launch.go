package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/FolksyPizza/rig/internal/aimonitor"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/monitor"
	"github.com/FolksyPizza/rig/internal/provider"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// engineFor selects a container engine able to enforce the profile.
func engineFor(eff config.Effective) (provider.Provider, error) {
	provider.PreferIsolationCapable(needsIsolationEngine(eff))
	p := provider.Detect()
	if !p.Available() {
		return nil, fmt.Errorf("no container engine found: install Podman or Docker (on macOS, Docker Desktop, Podman, or Apple's container for open-level sandboxes)")
	}
	if err := container.CheckEngineSupport(p.Name(), eff); err != nil {
		return nil, err
	}
	return p, nil
}

// ensureImage builds the profile's image when it is missing or out of date.
func ensureImage(ctx context.Context, b *container.Builder, profile *config.Profile, noCache bool) error {
	exists, current, err := b.ImageUpToDate(ctx, profile)
	if err != nil {
		return err
	}
	if exists && current && !noCache {
		return nil
	}
	switch {
	case !exists:
		fmt.Printf("  Building image %s (first run takes a few minutes)...\n", profile.ImageTag())
	default:
		fmt.Printf("  The profile changed since the image was built; rebuilding %s...\n", profile.ImageTag())
	}
	if err := b.BuildWithOpts(ctx, profile, noCache, func(e container.BuildEvent) { fmt.Println(e.Stream) }); err != nil {
		return err
	}
	if failed, err := b.VerifyAgents(ctx, profile); err == nil && len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "  %s these agents did not install correctly: %s (check the build output above)\n",
			paint("1;33", "Warning:"), strings.Join(failed, ", "))
	}
	return nil
}

// launch builds, wires and enters a sandbox, then cleans up after it.
func launch(profile *config.Profile, opts container.RunOptions) error {
	ctx, cancel := signalContext()
	defer cancel()

	eff := profile.Resolve()
	prov, err := engineFor(eff)
	if err != nil {
		return err
	}
	info, err := provider.Inspect(ctx, prov)
	if err != nil {
		return err
	}
	iso, err := container.ResolveIsolation(eff, info)
	if err != nil {
		return err
	}
	if iso.Note != "" {
		fmt.Fprintf(os.Stderr, "  Note: %s.\n", iso.Note)
	}
	if missing := config.MissingEnvVars(profile); len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "  Warning: these variables are not set on this machine and will be empty in the sandbox: %s\n", strings.Join(missing, ", "))
	}

	builder, err := container.NewBuilder()
	if err != nil {
		return err
	}
	if err := ensureImage(ctx, builder, profile, false); err != nil {
		return err
	}

	runner, err := container.NewRunner()
	if err != nil {
		return err
	}

	var setup *container.NetworkSetup
	var nm *container.NetworkManager
	if eff.NetworkMode == "allowlist" {
		helperTag, err := builder.EnsureHelperImage(ctx, func(e container.BuildEvent) { fmt.Println(e.Stream) })
		if err != nil {
			return err
		}
		if nm, err = container.NewNetworkManager(); err != nil {
			return err
		}
		if len(opts.Command) == 0 {
			fmt.Printf("  Starting the egress filter (%s)...\n", describeAllowlist(eff))
		}
		setup, err = nm.Setup(ctx, profile, eff, helperTag)
		if err != nil {
			return fmt.Errorf("network setup failed, refusing to launch an unfiltered sandbox: %w", err)
		}
	}

	gwLines := make(chan []byte, 256)
	var gw *container.Gateway
	if eff.NeedsGateway {
		if len(opts.Command) == 0 {
			fmt.Println("  Starting the gateway (MCP, git broker, host ports)...")
		}
		gw, err = runner.StartGateway(ctx, profile, container.GatewayOptions{
			Image:   profile.ImageTag(),
			Network: setup.Network,
			Token:   setup.GatewayToken,
			Runtime: iso.Runtime,
			ProxyIP: setup.ProxyIP,
			OnLog: func(line []byte) {
				select {
				case gwLines <- line:
				default: // never block the gateway on a slow monitor
				}
			},
		})
		if err != nil {
			teardownIfIdle(runner, nm, profile.Name)
			return err
		}
	}

	spec := container.LaunchSpec{Profile: profile, Effective: eff, Isolation: iso, Network: setup, Gateway: eff.NeedsGateway}
	if eff.NeedsGateway && setup != nil {
		spec.GatewayIP = runner.ContainerIP(ctx, container.GatewayName(profile.Name), setup.Network)
	}
	prepared, err := runner.Prepare(ctx, spec, opts)
	if err != nil {
		gw.Stop()
		teardownIfIdle(runner, nm, profile.Name)
		return err
	}

	sess := openSession(profile.Name, prepared.Name)
	if opts.KeepRunning && !eff.Ephemeral {
		setKeepRunning(profile.Name, prepared.Name, true)
	}

	if len(opts.Command) == 0 {
		fmt.Printf("\n  Entering %s %s\n", paint("1;35", profile.Name), paint("2", "("+banner(eff, iso)+")"))
		fmt.Printf("  Type 'exit' to leave.\n\n")
	}

	monCtx, monCancel := context.WithCancel(ctx)
	blocked := &blockedHosts{}
	results := startMonitor(monCtx, profile, eff, runner, prov, prepared.Name, setup, gwLines, false, blocked)
	pushTitle()
	runErr := runner.Attach(ctx, prepared, opts)
	popTitle()
	if eff.MonitorMode != "off" {
		// Let the monitor read events still in flight (the proxy's log is
		// read through the engine) before it stops.
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	monCancel()

	var cause *watchdog.Observation
	select {
	case cause = <-results:
	case <-time.After(5 * time.Second):
	}
	sess.close()
	if !eff.Ephemeral && cause == nil {
		finishSession(runner, profile.Name, prepared.Name, len(opts.Command) > 0)
	}
	if gw != nil && !gw.Shared && cause == nil {
		keepGatewayForOthers(ctx, profile.Name)
	}
	gw.Stop()
	teardownIfIdle(runner, nm, profile.Name)

	blocked.summary(profile.Name)
	if cause != nil {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n  Details: rig audit %s --flagged\n", paint("1;31", "Rig stopped the sandbox:"), safeText(cause.Detail), profile.Name)
		if len(opts.Command) == 0 && opts.Container == "" && interactiveTerminal() {
			if again := afterStop(profile, cause); again {
				return launch(profile, container.RunOptions{})
			}
		}
		return exitError{code: 3}
	}
	// Pass the shell's or command's exit status through without an error
	// message of our own.
	var xe *exec.ExitError
	if errors.As(runErr, &xe) {
		return exitError{code: xe.ExitCode()}
	}
	return runErr
}

// keepGatewayForOthers keeps this process, and the gateway it runs, alive
// while other sessions of the profile still use it: the gateway's host-port
// relay runs through this process, so they would lose MCP servers, the git
// broker and host ports if it exited. Ctrl-C stops waiting.
func keepGatewayForOthers(ctx context.Context, profileName string) {
	announced := false
	for len(profileSessions(profileName)) > 0 {
		if !announced {
			fmt.Printf("  Other sessions of %s still use its gateway; keeping it up until they end (Ctrl-C stops it now).\n", profileName)
			announced = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// finishSession stops a persistent sandbox when the last session leaves it,
// unless it was started with --keep-running. Its files are kept.
func finishSession(runner *container.Runner, profileName, name string, quiet bool) {
	if keepRunning(profileName, name) {
		if !quiet {
			fmt.Printf("  %s keeps running (--keep-running). It is not monitored until you run 'rig monitor %s'; stop it with 'rig stop %s'.\n", name, profileName, profileName)
		}
		return
	}
	if len(otherSessions(profileName, name)) > 0 {
		return
	}
	if err := runner.Stop(context.Background(), name); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: %v\n", err)
		return
	}
	if !quiet {
		fmt.Printf("  Stopped %s; its files are kept. 'rig run %s' picks up where you left off.\n", name, profileName)
	}
}

// teardownIfIdle removes the proxy, gateway and networks once no sandbox of
// the profile is left.
func teardownIfIdle(r *container.Runner, nm *container.NetworkManager, profileName string) {
	if nm == nil {
		return
	}
	if len(r.ListByProfile(context.Background(), profileName)) == 0 {
		nm.Teardown(context.Background(), profileName)
	}
}

func describeAllowlist(eff config.Effective) string {
	if len(eff.Allowed) == 0 {
		return "no internet domains allowed"
	}
	return fmt.Sprintf("%d domains allowed, everything else blocked", len(eff.Allowed))
}

func banner(eff config.Effective, iso container.Isolation) string {
	net := eff.NetworkMode
	if net == "allowlist" {
		net = fmt.Sprintf("allowlist: %d domains", len(eff.Allowed))
	}
	isolation := map[string]string{config.IsolationContainer: "container", config.IsolationGVisor: "gVisor", config.IsolationVM: "VM"}[iso.Level]
	mon := "monitor " + eff.MonitorMode
	return strings.Join([]string{eff.Level, net, isolation, mon}, " · ")
}

// startMonitor runs the monitoring pipeline for one sandbox in the
// background. The channel receives the observation that stopped the sandbox,
// or nil.
func startMonitor(ctx context.Context, profile *config.Profile, eff config.Effective, runner *container.Runner, prov provider.Provider,
	name string, setup *container.NetworkSetup, gwLines <-chan []byte, verbose bool, blocked *blockedHosts) <-chan *watchdog.Observation {

	results := make(chan *watchdog.Observation, 1)
	if eff.MonitorMode == "off" {
		results <- nil
		return results
	}

	var audit *monitor.Audit
	if path, err := config.AuditPath(profile.Name); err == nil {
		if audit, err = monitor.OpenAudit(path); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: audit log unavailable: %v\n", err)
		}
	}

	rules := monitor.NewRules(eff.DenyKillThreshold, eff.KillOnExecFromWritable)
	rules.ExecOnlyFromImage = eff.ExecOnlyFromImage
	bin := runner.Bin()
	// The in-sandbox MCP guard's log, read from the start: a session's first
	// tool calls can land before the reader starts. Lines from earlier
	// sessions are dropped by timestamp.
	const mcpLog = "/home/sandbox/.rig/mcp-audit.jsonl"
	mcpTail := []string{"tail", "-n", "+1", "-F", mcpLog}
	started := time.Now().Add(-2 * time.Second)
	podman := runner.Engine() == "podman"
	sources := []watchdog.Observer{
		monitor.ProcessSource{Rules: rules, Engine: bin, Podman: podman, Container: name,
			InSandbox: monitor.IsolatedRuntime(ctx, bin, name, podman),
			Ignore:    func(comm, args string) bool { return comm == "tail" && args == strings.Join(mcpTail, " ") }},
		monitor.ResourceObserver{Provider: prov, Container: name, MemLimitBytes: profile.Resources.Memory << 20, PIDLimit: profile.Resources.PIDLimit},
	}
	if setup != nil {
		ip := &lazyIP{bin: bin, container: name, network: setup.Network}
		sources = append(sources, monitor.LineSource{
			Rules: rules,
			Open:  monitor.CommandStream(false, bin, "logs", "-f", "--since", time.Now().UTC().Format(time.RFC3339), "rig-proxy-"+profile.Name),
			// The proxy serves every instance of the profile; keep this
			// sandbox's traffic and the gateway's.
			Accept: func(raw []byte) bool {
				var ev struct {
					Client string `json:"client"`
					As     string `json:"as"`
				}
				if json.Unmarshal(raw, &ev) != nil || ev.As == "gateway" {
					return true
				}
				mine := ip.get()
				return mine == "" || ev.Client == "" || ev.Client == mine
			},
		})
	}
	if gwLines != nil && eff.NeedsGateway {
		sources = append(sources, monitor.LineSource{Rules: rules, Lines: gwLines})
	}
	if hasSandboxMCP(profile) {
		sources = append(sources, monitor.LineSource{
			Rules: rules,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				waitRunning(ctx, bin, name)
				return monitor.CommandStream(false, bin, append([]string{"exec", name}, mcpTail...)...)(ctx)
			},
			Accept: func(raw []byte) bool {
				var ev struct {
					TS string `json:"ts"`
				}
				if json.Unmarshal(raw, &ev) != nil {
					return false
				}
				t, err := time.Parse(time.RFC3339Nano, ev.TS)
				return err == nil && t.After(started)
			},
		})
	}

	var ai *aimonitor.Reviewer
	if cfg := profile.Monitor.AI; cfg.Provider != "" {
		r, err := newReviewer(profile, eff)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: AI monitor disabled: %v\n", err)
		} else {
			ai = r
			sources = append(sources, r)
		}
	}

	p := &monitor.Pipeline{
		Profile:   profile.Name,
		Container: name,
		Policy:    watchdog.NewPolicy(eff.MonitorMode, eff.Strictness),
		Sources:   sources,
		Enforcer:  monitor.ProviderEnforcer{Provider: prov, Container: name},
		Audit:     audit,
		Notify:    notifier(verbose, profile.Name, blocked),
	}
	if ai != nil {
		p.AI = ai
	}
	go func() {
		cause, _ := p.Run(ctx)
		audit.Close()
		results <- cause
	}()
	return results
}

func newReviewer(profile *config.Profile, eff config.Effective) (*aimonitor.Reviewer, error) {
	cfg := profile.Monitor.AI
	keyEnv := cfg.APIKeyEnv
	if keyEnv == "" {
		keyEnv = map[string]string{"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}[cfg.Provider]
	}
	key := ""
	if keyEnv != "" {
		key = os.Getenv(keyEnv)
	}
	if key == "" && cfg.Provider == "openai" {
		return nil, fmt.Errorf("%s is not set", keyEnv)
	}
	interval := 30 * time.Second
	if cfg.Interval != "" {
		if d, err := time.ParseDuration(cfg.Interval); err == nil {
			interval = d
		}
	}
	return aimonitor.New(aimonitor.Config{
		Provider: cfg.Provider,
		Model:    cfg.Model,
		Endpoint: cfg.Endpoint,
		APIKey:   key,
		Interval: interval,
		Enforce:  eff.AIEnforce,
		Profile:  profile.Name,
		Level:    eff.Level,
		Allowed:  eff.Allowed,
	})
}

func hasSandboxMCP(p *config.Profile) bool {
	for _, s := range p.MCP.Servers {
		if s.URL == "" && !s.InGateway() {
			return true
		}
	}
	return false
}

// notifier prints alerts in the terminal. In an interactive session the
// terminal may be in raw mode, so lines are framed with explicit carriage
// returns, and the shell or agent is asked to redraw afterwards so its prompt
// comes back instead of leaving the session looking frozen. 'rig monitor'
// (verbose) already prints every event, so it gets none. Blocked sites are
// also collected in blocked, for the summary printed when the session ends.
func notifier(verbose bool, profileName string, blocked *blockedHosts) func(watchdog.Event) {
	if verbose {
		return nil
	}
	var mu sync.Mutex
	last := map[string]time.Time{}
	interactive := stderrTTY && isatty.IsTerminal(os.Stdin.Fd())
	return func(e watchdog.Event) {
		host, denied := deniedHost(e.Observation)
		if denied {
			blocked.add(host)
		}
		key := e.Observation.Kind + "\x00" + e.Observation.Detail
		mu.Lock()
		if t, ok := last[key]; ok && time.Since(t) < 10*time.Second {
			mu.Unlock()
			return
		}
		last[key] = time.Now()
		mu.Unlock()

		label := paint("1;33", "[rig] flagged:")
		detail := safeText(e.Observation.Detail)
		switch {
		case e.Action == watchdog.ActionKill:
			label = paint("1;31", "[rig] stopping the sandbox:")
		case denied:
			label = paint("1;33", "[rig] blocked")
			detail = safeText(host) + paint("2", " (not on the allowlist; to allow it: rig allow "+profileName+" "+safeText(host)+")")
		}
		fmt.Fprintf(os.Stderr, "\r\n%s %s\r\n", label, detail)
		if interactive {
			setTitle("rig " + profileName + ": " + safeText(e.Observation.Detail))
			if e.Action != watchdog.ActionKill {
				go func() {
					mu.Lock()
					defer mu.Unlock()
					redrawTerminal()
				}()
			}
		}
	}
}

// deniedHost returns the host of an ordinary allowlist refusal: the kind of
// block you may want to lift with 'rig allow'.
func deniedHost(o watchdog.Observation) (string, bool) {
	if o.Kind != "egress_denied" || len(o.Data) == 0 {
		return "", false
	}
	var ev struct {
		Host string `json:"host"`
	}
	if json.Unmarshal(o.Data, &ev) != nil || ev.Host == "" {
		return "", false
	}
	return strings.ToLower(ev.Host), true
}

// blockedHosts counts the sites refused during one session.
type blockedHosts struct {
	mu    sync.Mutex
	count map[string]int
	order []string
}

func (b *blockedHosts) add(host string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count == nil {
		b.count = map[string]int{}
	}
	if b.count[host] == 0 {
		b.order = append(b.order, host)
	}
	b.count[host]++
}

// summary prints what was blocked and how to allow it.
func (b *blockedHosts) summary(profileName string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n  %s\n", paint("1", "Blocked during this session (not on the allowlist):"))
	for _, h := range b.order {
		times := ""
		if n := b.count[h]; n > 1 {
			times = fmt.Sprintf(" (%d times)", n)
		}
		fmt.Fprintf(os.Stderr, "    %s%s\n", safeText(h), times)
	}
	fmt.Fprintf(os.Stderr, "  To allow one: rig allow %s %s   (or 'rig blocked %s' to pick)\n", profileName, safeText(b.order[0]), profileName)
}

// lazyIP looks up a container's address on a network once it has one.
type lazyIP struct {
	mu                      sync.Mutex
	bin, container, network string
	ip                      string
	lastTry                 time.Time
}

func (l *lazyIP) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ip != "" || time.Since(l.lastTry) < time.Second {
		return l.ip
	}
	l.lastTry = time.Now()
	out, err := exec.Command(l.bin, "inspect", "-f",
		`{{with index .NetworkSettings.Networks "`+l.network+`"}}{{.IPAddress}}{{end}}`, l.container).Output()
	if err == nil {
		l.ip = strings.TrimSpace(string(out))
	}
	return l.ip
}

// waitRunning blocks until the container is running or ctx ends.
func waitRunning(ctx context.Context, bin, name string) {
	for i := 0; i < 120; i++ {
		out, err := exec.CommandContext(ctx, bin, "inspect", "-f", "{{.State.Running}}", name).Output()
		if err == nil && strings.TrimSpace(string(out)) == "true" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}
