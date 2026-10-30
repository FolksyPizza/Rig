package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/policy"
	"github.com/FolksyPizza/rig/internal/provider"
)

func checkCmd() *cobra.Command {
	var failOn string
	cmd := &cobra.Command{
		Use:   "check <name>",
		Short: "Show what a sandbox can and cannot do",
		Long: `Explain a sandbox's effective security: its level and isolation, what it can
reach on the internet and on this computer, which tools, repositories and files
it can use, and how it is monitored. Risks are listed most serious first.

  rig check work
  rig check work --fail-on medium    exit 1 on any medium or high risk (for CI)

Nothing is started; this reads the saved settings only. 'rig doctor' checks
this computer instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			var threshold policy.Severity
			if failOn != "" {
				var ok bool
				if threshold, ok = policy.ParseSeverity(failOn); !ok {
					return fmt.Errorf("--fail-on must be info, low, medium or high")
				}
			}
			eff := p.Resolve()
			printSummary(p, eff)

			findings := policy.Check(p)
			fmt.Println()
			fmt.Println(paint("1", "  Risks"))
			if len(findings) == 0 {
				fmt.Println("  none found")
			}
			for _, f := range findings {
				fmt.Printf("  %s %-11s %s\n", severityLabel(f.Severity), f.Area, f.Message)
			}
			if failOn != "" {
				for _, f := range findings {
					if f.Severity >= threshold {
						return exitError{code: 1, msg: fmt.Sprintf("\n  %s has risks rated %s or higher.", p.Name, failOn)}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit with status 1 if any risk is at least this severe (info, low, medium, high)")
	return cmd
}

func severityLabel(s policy.Severity) string {
	switch s {
	case policy.High:
		return paint("1;31", "HIGH  ")
	case policy.Medium:
		return paint("1;33", "MEDIUM")
	case policy.Low:
		return paint("33", "low   ")
	}
	return paint("2", "info  ")
}

// printSummary describes a profile's effective policy in plain language.
func printSummary(p *config.Profile, eff config.Effective) {
	fmt.Printf("\n  %s: %s at level %s\n\n", paint("1", p.Name), agentNames(p), paint("1", eff.Level))
	row := func(label, text string) {
		lines := strings.Split(text, "\n")
		fmt.Printf("  %-12s %s\n", label, lines[0])
		for _, l := range lines[1:] {
			fmt.Printf("  %-12s %s\n", "", l)
		}
	}

	row("Isolation", describeIsolation(eff))
	row("Network", describeNetworkLong(eff))
	if eff.NeedsGateway && len(eff.GatewayAllowed) > 0 {
		row("", "MCP servers in the gateway may reach: "+strings.Join(eff.GatewayAllowed, " "))
	}

	var hostLines []string
	for _, hp := range p.Host.Ports {
		hostLines = append(hostLines, fmt.Sprintf("%s: rig-gw:%d inside reaches port %d on this computer", hp.Name, hp.Port, hp.Target()))
	}
	if len(hostLines) == 0 {
		hostLines = []string{"nothing on this computer is reachable"}
	}
	row("This machine", strings.Join(hostLines, "\n"))

	if len(p.MCP.Servers) > 0 {
		var lines []string
		for _, s := range p.MCP.Servers {
			lines = append(lines, describeMCP(s))
		}
		row("MCP", strings.Join(lines, "\n"))
	}

	if len(p.Git.Repos) > 0 {
		var lines []string
		for _, r := range p.Git.Repos {
			l := fmt.Sprintf("%s/%s (%s", p.Git.GitHost(), r.Repo, r.AccessLevel())
			if r.AccessLevel() == "write" && len(r.Branches) > 0 {
				l += ", branches " + strings.Join(r.Branches, " ")
			}
			lines = append(lines, l+")")
		}
		lines = append(lines, fmt.Sprintf("the token in %s stays in the gateway; the sandbox never sees it", p.Git.TokenEnv))
		row("Git", strings.Join(lines, "\n"))
	} else {
		row("Git", "no repository credentials (public repositories only, if the allowlist permits)")
	}

	row("Files", describeFiles(p, eff))
	if eff.Sudo {
		row("Privileges", "passwordless sudo inside the sandbox, with the few capabilities package installs need")
	} else {
		row("Privileges", "unprivileged user, no sudo, no Linux capabilities")
	}
	if eff.HarnessLockdown || eff.NpmIgnoreScripts || eff.PipOnlyBinary || eff.ExecOnlyFromImage {
		var parts []string
		if eff.ExecOnlyFromImage {
			parts = append(parts, "running a program from outside the image stops the sandbox")
		}
		if eff.HarnessLockdown {
			parts = append(parts, "agents' own web tools off and permission bypass disabled")
		}
		if eff.NpmIgnoreScripts {
			parts = append(parts, "npm install scripts off")
		}
		if eff.PipOnlyBinary {
			parts = append(parts, "pip installs prebuilt wheels only")
		}
		row("Code", strings.Join(parts, "; "))
	}
	row("Monitoring", describeMonitoring(p, eff))
	if eff.Ephemeral {
		row("Lifetime", "ephemeral: removed when you exit")
	} else {
		row("Lifetime", "persistent: stopped when you exit, files kept until 'rig rm'")
	}
}

func describeIsolation(eff config.Effective) string {
	switch eff.Isolation {
	case config.IsolationContainer:
		return "hardened container (shares this computer's kernel)"
	case config.IsolationGVisor:
		return "gVisor, required (the sandbox runs on a user-space kernel)"
	case config.IsolationVM:
		return "virtual machine, required (Kata Containers, or Apple's container runtime)"
	}
	switch {
	case eff.RequireStrongIsolation:
		return "gVisor or a VM, required: it will not start without one"
	case eff.PreferStrongIsolation:
		return "gVisor or a VM when installed, otherwise a hardened container"
	}
	return "the strongest installed: gVisor, a VM, or a hardened container"
}

func describeNetworkLong(eff config.Effective) string {
	var flags []string
	if eff.BlockRisky {
		flags = append(flags, "exfiltration sites blocked")
	}
	if eff.HTTPSOnly {
		flags = append(flags, "HTTPS only")
	}
	if eff.MaxUploadBytes > 0 {
		flags = append(flags, fmt.Sprintf("uploads over %d MB refused", eff.MaxUploadBytes>>20))
	}
	suffix := ""
	if len(flags) > 0 {
		suffix = " (" + strings.Join(flags, ", ") + ")"
	}
	switch eff.NetworkMode {
	case "unrestricted":
		return "unrestricted: any address on the internet" + suffix
	case "none":
		return "none: no network at all"
	}
	if len(eff.Allowed) == 0 {
		return "allowlist, empty: no internet access" + suffix
	}
	return fmt.Sprintf("allowlist, %d domains%s\n%s", len(eff.Allowed), suffix, wrapWords(eff.Allowed, 64))
}

func describeMCP(s config.MCPServer) string {
	where := "runs in the sandbox"
	switch {
	case s.URL != "":
		where = "remote at " + s.URL
	case s.InGateway():
		where = "runs in the gateway, outside the sandbox"
	}
	var policyText string
	switch {
	case len(s.AllowTools) > 0:
		policyText = "only " + strings.Join(s.AllowTools, ", ")
	case len(s.DenyTools) > 0:
		policyText = "all tools except " + strings.Join(s.DenyTools, ", ")
	default:
		policyText = "all tools"
	}
	out := fmt.Sprintf("%s: %s; %s", s.Name, where, policyText)
	if len(s.HostPorts) > 0 {
		var ports []string
		for _, p := range s.HostPorts {
			ports = append(ports, fmt.Sprint(p))
		}
		out += "; reaches this computer's port " + strings.Join(ports, ", ")
	}
	return out
}

func describeFiles(p *config.Profile, eff config.Effective) string {
	var lines []string
	var base []string
	if eff.ReadOnlyRoot {
		base = append(base, "read-only image")
	}
	if eff.NoExecTmp {
		base = append(base, "/tmp cannot run programs")
	}
	if eff.NoExecHome {
		base = append(base, "home cannot run programs")
	}
	if len(base) == 0 {
		base = append(base, "writable image")
	}
	lines = append(lines, strings.Join(base, ", "))
	home, _ := os.UserHomeDir()
	for _, m := range p.Mounts {
		src := m.Source
		if home != "" && strings.HasPrefix(src, home) {
			src = "~" + strings.TrimPrefix(src, home)
		}
		mode := "read-only"
		if !m.ReadOnly {
			mode = "read-write"
		}
		l := fmt.Sprintf("%s → %s (%s)", src, m.Target, mode)
		protect := append([]string{}, m.Protect...)
		if !m.ReadOnly {
			protect = append(protect, eff.ProtectPaths...)
		}
		if len(protect) > 0 {
			l += "; read-only inside: " + strings.Join(dedupe(protect), " ")
		}
		if len(m.Hide) > 0 {
			l += "; hidden: " + strings.Join(m.Hide, " ")
		}
		lines = append(lines, l)
	}
	if len(p.Mounts) == 0 {
		lines = append(lines, "no folders from this computer are mounted")
	}
	return strings.Join(lines, "\n")
}

func describeMonitoring(p *config.Profile, eff config.Effective) string {
	var out string
	switch eff.MonitorMode {
	case "off":
		return "off: nothing is watched or recorded"
	case "observe":
		out = "observe: everything is recorded and flagged, nothing is stopped"
	default:
		out = fmt.Sprintf("enforce (%s): serious violations stop the sandbox", eff.Strictness)
		switch {
		case eff.DenyKillThreshold == 1:
			out += "; the first blocked connection stops it"
		case eff.DenyKillThreshold > 1:
			out += fmt.Sprintf("; %d blocked connections in a minute stop it", eff.DenyKillThreshold)
		}
	}
	if ai := p.Monitor.AI; ai.Provider != "" {
		model := ai.Model
		if model == "" && ai.Provider == "anthropic" {
			model = "claude-opus-5-5"
		}
		mode := "advisory"
		if eff.AIEnforce {
			mode = "can stop the sandbox"
		}
		out += fmt.Sprintf("\nAI review: %s %s (%s)", ai.Provider, model, mode)
	}
	return out
}

func wrapWords(words []string, width int) string {
	var lines []string
	line := ""
	for _, w := range words {
		if line != "" && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ── doctor ───────────────────────────────────────────────────────────

type doctorReport struct{ failed bool }

func (d *doctorReport) line(status, text string) {
	label := map[string]string{
		"ok":   paint("1;32", "ok  "),
		"warn": paint("1;33", "warn"),
		"fail": paint("1;31", "FAIL"),
		"skip": paint("2", "skip"),
	}[status]
	if status == "fail" {
		d.failed = true
	}
	lines := strings.Split(text, "\n")
	fmt.Printf("  %s  %s\n", label, lines[0])
	for _, l := range lines[1:] {
		fmt.Printf("        %s\n", l)
	}
}

func doctorCmd() *cobra.Command {
	var deep bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check this computer's setup for running sandboxes safely",
		Long: `Check the container engine, which isolation runtimes are installed (gVisor,
Kata VMs), and your saved sandboxes.

With --deep, Rig also tests this computer's networking: it starts throwaway
containers on an internal network and confirms they cannot look up outside
names, connect to services on this computer, or reach the cloud metadata
address, and that each gVisor or VM runtime starts. Run it once after
installing Rig or changing your container engine.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signalContext()
			defer cancel()
			d := &doctorReport{}

			fmt.Println(paint("1", "\n  Container engine"))
			provider.PreferIsolationCapable(true)
			prov := provider.Detect()
			if !prov.Available() {
				d.line("fail", "No container engine found. Install Podman or Docker"+map[bool]string{true: " (or Apple's container for open-level sandboxes)", false: ""}[isDarwin()]+".")
				return exitError{code: 1}
			}
			info, err := provider.Inspect(ctx, prov)
			if err != nil {
				d.line("fail", err.Error())
				return exitError{code: 1}
			}
			doctorEngine(d, info)

			fmt.Println(paint("1", "\n  Saved sandboxes"))
			doctorProfiles(d, prov.Name(), info)

			if deep {
				fmt.Println(paint("1", "\n  Isolation self-test"))
				doctorDeep(ctx, d, prov.Name(), info)
			} else {
				fmt.Println("\n  Run 'rig doctor --deep' to test network isolation on this computer.")
			}
			if d.failed {
				return exitError{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "also test network isolation and runtimes with throwaway containers")
	return cmd
}

func isDarwin() bool { return runtime.GOOS == "darwin" }

func doctorEngine(d *doctorReport, info provider.EngineInfo) {
	desc := info.Name
	if info.Version != "" {
		desc += " " + info.Version
	}
	if info.OS != "" {
		desc += " on " + info.OS
	}
	if info.Rootless {
		desc += " (rootless: an escape lands in your unprivileged account)"
	}
	d.line("ok", desc)
	if info.Name == "apple" {
		d.line("ok", "Every sandbox runs in its own lightweight VM.")
		d.line("warn", "Apple's runtime cannot enforce the egress allowlist, a read-only image or the gateway yet,\nso only open-level sandboxes run on it. Install Podman or Docker for the other levels;\nRig uses them automatically for those sandboxes.")
		return
	}
	if info.DockerDesktop {
		d.line("ok", "Docker Desktop runs containers inside a VM, which shields this computer from a container escape.")
	}
	has := func(name string) bool {
		for _, o := range info.SecurityOptions {
			if o == name {
				return true
			}
		}
		return false
	}
	if has("seccomp") {
		d.line("ok", "seccomp system call filtering is on")
	} else {
		d.line("warn", "seccomp is not reported: containers may be able to make any system call")
	}
	switch {
	case has("apparmor"):
		d.line("ok", "AppArmor confinement is on")
	case has("selinux"):
		d.line("ok", "SELinux confinement is on")
	}

	gv, hasGV := info.HasRuntime(provider.IsGVisor)
	kata, hasKata := info.HasRuntime(provider.IsKata)
	if hasGV && info.Name == "podman" && info.Rootless {
		d.line("warn", "gVisor is installed, but it cannot run under rootless Podman, so Rig does not use it here.\nUse Docker or rootful Podman for gVisor.")
		hasGV = false
	}
	switch {
	case hasGV && hasKata:
		d.line("ok", fmt.Sprintf("gVisor (%s) and Kata VMs (%s) are installed: strict and lockdown sandboxes use them", gv, kata))
	case hasGV:
		d.line("ok", fmt.Sprintf("gVisor (%s) is installed: strict and lockdown sandboxes use it", gv))
	case hasKata:
		d.line("ok", fmt.Sprintf("Kata Containers (%s) is installed: strict and lockdown sandboxes run in VMs", kata))
	default:
		d.line("warn", "No gVisor or VM runtime: lockdown sandboxes cannot start, and strict ones use a plain container.\n"+
			"Install gVisor: https://gvisor.dev/docs/user_guide/install/ (then 'sudo runsc install' and restart the engine)\n"+
			"or Kata Containers: https://katacontainers.io/docs/")
	}
	if info.Name == "podman" {
		d.line("warn", "Podman's internal networks give the host an address that sandboxes may be able to reach.\nRun 'rig doctor --deep' to test it here, and bind local services to 127.0.0.1.")
	}
}

func doctorProfiles(d *doctorReport, engine string, info provider.EngineInfo) {
	store, err := config.NewStore()
	if err != nil {
		d.line("fail", err.Error())
		return
	}
	names, err := store.List()
	if err != nil {
		d.line("fail", err.Error())
		return
	}
	if len(names) == 0 {
		d.line("ok", "none yet ('rig new <name>' creates one)")
	}
	valid := 0
	for _, name := range names {
		p, err := store.Load(name)
		if err != nil {
			d.line("fail", fmt.Sprintf("%s: %v", name, err))
			continue
		}
		valid++
		eff := p.Resolve()
		if err := container.CheckEngineSupport(engine, eff); err != nil {
			d.line("warn", fmt.Sprintf("%s: %v", name, err))
		}
		if engine != "apple" {
			if _, err := container.ResolveIsolation(eff, info); err != nil {
				d.line("warn", fmt.Sprintf("%s will not start here: %v", name, err))
			}
		}
		if missing := config.MissingEnvVars(p); len(missing) > 0 {
			d.line("warn", fmt.Sprintf("%s: not set on this computer: %s", name, strings.Join(missing, ", ")))
		}
		if len(p.Git.Repos) > 0 && os.Getenv(p.Git.TokenEnv) == "" {
			d.line("warn", fmt.Sprintf("%s: the git broker's token variable %s is not set", name, p.Git.TokenEnv))
		}
		if ai := p.Monitor.AI; ai.Provider == "anthropic" || ai.Provider == "openai" {
			keyEnv := ai.APIKeyEnv
			if keyEnv == "" {
				keyEnv = map[string]string{"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}[ai.Provider]
			}
			if os.Getenv(keyEnv) == "" {
				d.line("warn", fmt.Sprintf("%s: the AI monitor's key %s is not set, so the AI monitor will be off", name, keyEnv))
			}
		}
	}
	if valid > 0 {
		d.line("ok", fmt.Sprintf("%d of %d sandboxes load and validate", valid, len(names)))
	}
	for _, err := range agents.CustomErrors() {
		d.line("warn", "custom agent skipped: "+err.Error())
	}
}

func doctorDeep(ctx context.Context, d *doctorReport, engine string, info provider.EngineInfo) {
	if engine == "apple" {
		d.line("skip", "the network self-test needs Docker or Podman")
		return
	}
	builder, err := container.NewBuilder()
	if err != nil {
		d.line("fail", err.Error())
		return
	}
	fmt.Println("        building the helper image if needed...")
	start := time.Now()
	tag, err := builder.EnsureHelperImage(ctx, func(container.BuildEvent) {})
	if err != nil {
		d.line("fail", "could not build the helper image: "+err.Error())
		return
	}
	if time.Since(start) > 2*time.Second {
		fmt.Printf("        built %s\n", tag)
	}
	nm, err := container.NewNetworkManager()
	if err != nil {
		d.line("fail", err.Error())
		return
	}
	results := nm.NetworkSelfTest(ctx, tag)
	results = append(results, nm.RuntimeSelfTest(ctx, tag, info)...)
	for _, r := range results {
		switch {
		case r.Skipped:
			d.line("skip", r.Name+": "+r.Detail)
		case r.Passed && r.Detail != "":
			d.line("ok", r.Name+"\n"+paint("2", r.Detail))
		case r.Passed:
			d.line("ok", r.Name)
		default:
			d.line("fail", r.Name+"\n"+r.Detail)
		}
	}
}
