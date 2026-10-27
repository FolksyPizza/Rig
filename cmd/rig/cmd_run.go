package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
)

func runCmd() *cobra.Command {
	var (
		from                        string
		timeout                     time.Duration
		newInstance, recreate, keep bool
	)
	cmd := &cobra.Command{
		Use:   "run <name> [-- command...]",
		Short: "Start a sandbox and open a shell in it (builds it if needed)",
		Long: `Start a saved sandbox and open a shell inside it. The image is built on first
use and rebuilt automatically when the sandbox's settings change.

  rig run work                    open a shell
  rig run work -- claude          run a command instead of a shell
  rig run work --from lockdown    create the sandbox from a template first, if needed

While you are inside, Rig filters the network, watches what happens, and
records it in the audit log ('rig audit work'). When you leave a persistent
sandbox it is stopped, with its files kept, so nothing runs in it unmonitored.
Pass --keep-running to leave it up.

A running instance is re-entered and a stopped one restarted; --new starts
another instance alongside it.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			name := args[0]
			var profile *config.Profile
			switch {
			case store.Exists(name):
				if profile, err = store.Load(name); err != nil {
					return fmt.Errorf("sandbox %q could not be loaded: %w", name, err)
				}
			case from != "":
				if profile, err = createFromTemplate(store, from, name); err != nil {
					return err
				}
				fmt.Printf("  Created %s from the %s template.\n", name, from)
			default:
				return fmt.Errorf("sandbox %q not found; create it with 'rig new %s' (or pass --from <template>)", name, name)
			}
			if timeout == 0 {
				timeout = profile.Metadata.Timeout
			}
			return launch(profile, container.RunOptions{
				NewInstance: newInstance,
				Recreate:    recreate,
				Timeout:     timeout,
				Command:     args[1:],
				KeepRunning: keep,
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "create the sandbox from this template if it does not exist")
	f.DurationVar(&timeout, "timeout", 0, "stop the sandbox after this long (e.g. 30m, 2h)")
	f.BoolVar(&newInstance, "new", false, "start another instance instead of reusing the existing one")
	f.BoolVar(&recreate, "recreate", false, "replace an instance created from an older image (named volumes are kept)")
	f.BoolVar(&keep, "keep-running", false, "leave a persistent sandbox running after you exit")
	return cmd
}

func createFromTemplate(store *config.Store, template, name string) (*config.Profile, error) {
	t, ok := config.GetTemplate(template)
	if !ok {
		return nil, fmt.Errorf("template %q not found (see 'rig templates')", template)
	}
	p := t.Profile
	p.Name = name
	p.Metadata.CreatedAt = time.Now().UTC()
	if err := store.Save(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// attachProfile finds the saved sandbox a container belongs to.
func attachProfile(ctx context.Context, r *container.Runner, containerName string) (*config.Profile, error) {
	profileName, err := r.ProfileOf(ctx, containerName)
	if err != nil {
		return nil, err
	}
	_, p, err := loadProfile(profileName)
	return p, err
}

func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell <sandbox|container>",
		Short: "Open another shell in a sandbox",
		Long: `Open another shell in a sandbox, for example in a second terminal. Takes a
sandbox name or a container name from 'rig ps' (such as rig-work-2).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			profile, err := attachProfile(ctx, r, name)
			if err != nil {
				return unmonitoredFallback(err, func() error {
					sctx, cancel := signalContext()
					defer cancel()
					return r.Shell(sctx, name)
				})
			}
			return launch(profile, container.RunOptions{Container: name})
		},
	}
}

func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec <sandbox|container> -- <command...>",
		Short: "Run a command in a sandbox",
		Long: `Run a command inside a sandbox, with the same filtering and monitoring as
'rig run'.

  rig exec work -- git status

If the sandbox sets commands.mode to allowlist, only the listed commands are
accepted here. That guards this entry point only; it does not limit what runs
inside the container.`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] == "-h" || args[0] == "--help" {
				return cmd.Help()
			}
			command := args[1:]
			if len(command) > 0 && command[0] == "--" {
				command = command[1:]
			}
			if len(command) == 0 {
				return fmt.Errorf("no command given; usage: rig exec <sandbox> -- <command...>")
			}
			r := runnerFor(args[0])
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			profile, err := attachProfile(ctx, r, name)
			if err != nil {
				return unmonitoredFallback(err, func() error {
					sctx, cancel := signalContext()
					defer cancel()
					return r.Exec(sctx, name, command)
				})
			}
			if !profile.CommandAllowed(command) {
				return fmt.Errorf("%q is not in %s's command allowlist (%s)", command[0], profile.Name, strings.Join(profile.Commands.Allowed, ", "))
			}
			return launch(profile, container.RunOptions{Container: name, Command: command})
		},
	}
}

// unmonitoredFallback enters a container whose saved sandbox is gone. Rig
// cannot know its policy, so it says so rather than refusing outright.
func unmonitoredFallback(cause error, enter func() error) error {
	fmt.Fprintf(os.Stderr, "  %s %v\n  Entering without monitoring. Remove the container with 'rig rm' if you no longer need it.\n",
		paint("1;33", "Warning:"), cause)
	return enter()
}
