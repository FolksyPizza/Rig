// Command rig runs AI coding agents in locked-down sandboxes.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/provider"
)

var version = "dev"

const guide = `Rig runs AI coding agents in locked-down sandboxes.

Start here:
  rig new work                 create a sandbox (Claude Code, standard security)
  rig run work                 build it if needed and open a shell inside
  rig check work               see exactly what it can and cannot reach

Pick an agent or a stricter level:
  rig new work --agent codex --level strict
  rig templates                ready-made setups: lockdown, local-model, blender, ...
  rig agents                   every agent Rig can install

Watch it:
  rig audit work               what the sandbox did: connections, tool calls, processes
  rig monitor work             live view of a running sandbox

Security levels: open < standard (default) < strict < lockdown    (rig levels)
Every command: rig help
`

func main() {
	// List commands in the order they are added: most useful first.
	cobra.EnableCommandSorting = false
	root := &cobra.Command{
		Use:   "rig",
		Short: "Run AI coding agents in locked-down sandboxes",
		Long:  guide,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(guide)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddGroup(
		&cobra.Group{ID: "start", Title: "Getting started:"},
		&cobra.Group{ID: "security", Title: "Security:"},
		&cobra.Group{ID: "config", Title: "Configure a sandbox:"},
		&cobra.Group{ID: "manage", Title: "Manage running sandboxes:"},
	)

	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("start", newCmd(), runCmd(), templatesCmd(), agentsCmd(), levelsCmd())
	add("security", checkCmd(), doctorCmd(), monitorCmd(), auditCmd())
	add("config", editCmd(), allowCmd(), addCmd(), showCmd(), presetsCmd(), exportCmd(), importCmd(), listCmd())
	add("manage", psCmd(), shellCmd(), execCmd(), stopCmd(), rmCmd(), buildCmd(), logsCmd(), cpCmd(),
		statsCmd(), topCmd(), diffCmd(), pauseCmd(), unpauseCmd(), commitCmd(), renameCmd())
	// Older names, kept so scripts keep working.
	root.AddCommand(destroyCmd(), deleteCmd(), inspectCmd(), templateCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		var ec exitError
		if errors.As(err, &ec) {
			if ec.msg != "" {
				fmt.Fprintln(os.Stderr, ec.msg)
			}
			os.Exit(ec.code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// exitError ends the program with a specific status.
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

// signalContext cancels on interrupt, termination or hangup (a closed
// terminal), so Rig tears down what it created and stops a sandbox it was
// monitoring instead of leaving it running unwatched.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

func mustRunner() *container.Runner {
	r, err := container.NewRunner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return r
}

// needsIsolationEngine reports whether a profile needs an engine that can
// enforce network isolation (Docker or Podman rather than Apple's runtime).
func needsIsolationEngine(eff config.Effective) bool {
	return eff.NetworkMode != "unrestricted" || eff.NeedsGateway || eff.ReadOnlyRoot
}

// runnerFor returns the engine holding a sandbox's containers: the one
// 'rig run' picks for its profile. arg is a sandbox or container name. On a
// Mac with both Apple's runtime and Docker or Podman installed, the choice
// depends on the profile, so management commands must make it the same way.
func runnerFor(arg string) *container.Runner {
	if p := profileForArg(arg); p != nil {
		provider.PreferIsolationCapable(needsIsolationEngine(p.Resolve()))
	}
	return mustRunner()
}

// profileForArg finds the saved sandbox named by a sandbox or container name
// (work, rig-work, rig-work-2).
func profileForArg(arg string) *config.Profile {
	store, err := config.NewStore()
	if err != nil {
		return nil
	}
	base := strings.TrimPrefix(arg, "rig-")
	candidates := []string{arg, base}
	if i := strings.LastIndexByte(base, '-'); i > 0 {
		if _, err := strconv.Atoi(base[i+1:]); err == nil {
			candidates = append(candidates, base[:i])
		}
	}
	for _, c := range candidates {
		if store.Exists(c) {
			if p, err := store.Load(c); err == nil {
				return p
			}
		}
	}
	return nil
}

// allRunners returns a runner for each installed engine Rig may have used.
func allRunners() []*container.Runner {
	var out []*container.Runner
	seen := map[string]bool{}
	for _, prefer := range []bool{false, true} {
		provider.PreferIsolationCapable(prefer)
		if r, err := container.NewRunner(); err == nil && !seen[r.Engine()] {
			seen[r.Engine()] = true
			out = append(out, r)
		}
	}
	provider.PreferIsolationCapable(false)
	return out
}

func resolve(ctx context.Context, r *container.Runner, name string) (string, error) {
	return container.ResolveContainerName(ctx, r, name)
}

func loadProfile(name string) (*config.Store, *config.Profile, error) {
	store, err := config.NewStore()
	if err != nil {
		return nil, nil, err
	}
	if !store.Exists(name) {
		return store, nil, fmt.Errorf("sandbox %q not found; create it with 'rig new %s'", name, name)
	}
	p, err := store.Load(name)
	if err != nil {
		return store, nil, err
	}
	return store, p, nil
}

// safeText makes text that came from a sandbox safe to print in a terminal:
// control characters (escape sequences could clear the screen, rewrite earlier
// lines or change the window title) and bidirectional overrides (which can
// make text read differently from what it says) are shown as escapes.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f),
			r >= 0x200e && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			fmt.Fprintf(&b, "\\u%04x", r)
		case r == utf8.RuneError:
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var stderrTTY = isatty.IsTerminal(os.Stderr.Fd())

// paint wraps s in an ANSI style when stderr is a terminal.
func paint(style, s string) string {
	if !stderrTTY {
		return s
	}
	return "\033[" + style + "m" + s + "\033[0m"
}
