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

// quickStart opens the help screen. The command list below it is generated
// from the commands themselves, so 'rig', 'rig help' and 'rig --help' always
// show the same, complete picture.
const quickStart = `Rig runs AI coding agents in locked-down sandboxes.

Quick start:
  rig new                      create a sandbox: pick the agent, security level and resources
  rig run work                 start it and open a shell (-d runs it in the background)
  rig check work               see exactly what it can and cannot reach
  rig blocked work             see what Rig blocked, and allow what you need
`

func main() {
	// List commands in the order they are added: most useful first.
	cobra.EnableCommandSorting = false
	root := &cobra.Command{
		Use:   "rig",
		Short: "Run AI coding agents in locked-down sandboxes",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			printOverview(cmd)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddGroup(
		&cobra.Group{ID: "start", Title: "Use a sandbox"},
		&cobra.Group{ID: "config", Title: "Configure"},
		&cobra.Group{ID: "security", Title: "Watch and check"},
		&cobra.Group{ID: "manage", Title: "Manage"},
	)

	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("start", newCmd(), runCmd(), shellCmd(), execCmd(), stopCmd(), psCmd(), listCmd())
	add("config", setCmd(), allowCmd(), blockedCmd(), addCmd(), editCmd(), showCmd(),
		templatesCmd(), agentsCmd(), levelsCmd(), presetsCmd(), exportCmd(), importCmd())
	add("security", checkCmd(), monitorCmd(), auditCmd(), doctorCmd())
	add("manage", updateCmd(), rmCmd(), buildCmd(), logsCmd(), cpCmd(), statsCmd(), topCmd(), diffCmd(),
		pauseCmd(), unpauseCmd(), commitCmd(), renameCmd(), versionCmd())
	// Older names, kept so scripts keep working, and internals.
	root.AddCommand(destroyCmd(), deleteCmd(), inspectCmd(), templateCmd(), superviseCmd())

	// The root's help is the overview; each command keeps cobra's help.
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd == root {
			printOverview(cmd)
			return
		}
		defaultHelp(cmd, args)
	})
	root.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Explain a command and its options",
		Run: func(cmd *cobra.Command, args []string) {
			target, _, err := root.Find(args)
			if err != nil || target == nil || len(args) == 0 {
				printOverview(root)
				return
			}
			_ = target.Help()
		},
	})

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

// printOverview prints the one help screen: a quick start, then every
// command by group.
func printOverview(root *cobra.Command) {
	fmt.Print(quickStart)
	for _, g := range root.Groups() {
		fmt.Printf("\n%s:\n", g.Title)
		for _, c := range root.Commands() {
			if c.GroupID == g.ID && c.IsAvailableCommand() {
				fmt.Printf("  %-10s %s\n", c.Name(), c.Short)
			}
		}
	}
	fmt.Print(`
Security levels: open < standard (default) < strict < lockdown   ('rig levels')
Agents: Claude Code, Codex, Gemini CLI, Pi, OpenCode, Qwen Code, Crush, Aider, Copilot and more ('rig agents')
'rig help <command>' explains a command and all its options.
`)
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

// newRunnerQuiet returns a runner, or an error instead of exiting.
func newRunnerQuiet() (*container.Runner, error) { return container.NewRunner() }
