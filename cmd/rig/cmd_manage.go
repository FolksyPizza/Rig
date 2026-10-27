package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/security"
)

func psCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List sandbox containers and whether they are monitored",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			runners := allRunners()
			if len(runners) == 0 {
				return fmt.Errorf("no container engine found")
			}
			var rows [][]string
			for _, r := range runners {
				for _, c := range r.ListSandboxes(ctx) {
					rows = append(rows, []string{c.Name, c.Profile, c.Status, monitoredState(c), r.Engine()})
				}
			}
			if len(rows) == 0 {
				fmt.Println("  No sandbox containers. Start one with 'rig run <name>'.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CONTAINER\tSANDBOX\tSTATUS\tMONITORED\tENGINE")
			for _, row := range rows {
				fmt.Fprintln(w, strings.Join(row, "\t"))
			}
			return w.Flush()
		},
	}
}

func monitoredState(c container.ContainerInfo) string {
	if !c.Running {
		return "-"
	}
	if pids := otherSessions(c.Profile, c.Name); len(pids) > 0 {
		return "yes"
	}
	if keepRunning(c.Profile, c.Name) {
		return "no (kept running; 'rig monitor " + c.Profile + "')"
	}
	return "no ('rig monitor " + c.Profile + "' or 'rig stop " + c.Profile + "')"
}

func stopCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "stop <sandbox|container>",
		Short: "Stop a running sandbox, keeping its files",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			if all {
				n := 0
				for _, c := range r.ListByProfile(ctx, args[0]) {
					setKeepRunning(c.Profile, c.Name, false)
					if c.Running {
						if err := r.Stop(ctx, c.Name); err != nil {
							return err
						}
						n++
					}
				}
				fmt.Printf("  Stopped %d container(s) of %s.\n", n, args[0])
				return nil
			}
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if profileName, err := r.ProfileOf(ctx, name); err == nil {
				setKeepRunning(profileName, name, false)
			}
			if err := r.Stop(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Stopped %s.\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "stop every instance of the sandbox")
	return cmd
}

func rmCmd() *cobra.Command {
	var all, volumes, yes bool
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove"},
		Short:   "Remove a sandbox's containers (--all deletes the sandbox too)",
		Long: `Remove a sandbox's containers. The saved sandbox stays, so the next
'rig run' starts from a fresh container.

  rig rm work              remove work's containers
  rig rm work --volumes    also delete its named volumes (persistent home, workspace)
  rig rm work --all        delete everything: containers, volumes, image, networks,
                           saved settings and audit log`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				return deleteSandbox(args[0], yes)
			}
			r := runnerFor(args[0])
			ctx := context.Background()
			profileName := args[0]
			n, err := r.DestroyAll(ctx, profileName)
			if err != nil {
				return err
			}
			if n == 0 {
				// Maybe a container name rather than a sandbox name.
				if name, rerr := resolve(ctx, r, args[0]); rerr == nil {
					if owner, err := r.ProfileOf(ctx, name); err == nil {
						profileName = owner
					}
					if err := r.Destroy(ctx, name); err != nil {
						return err
					}
					n = 1
				}
			}
			if volumes {
				_, p, err := loadProfile(profileName)
				if err != nil {
					p = &config.Profile{Name: profileName}
				}
				r.RemoveVolumes(ctx, p)
				fmt.Printf("  Removed %d container(s) and the volumes of %s.\n", n, profileName)
			} else {
				fmt.Printf("  Removed %d container(s) of %s.\n", n, profileName)
			}
			if nm, err := container.NewNetworkManager(); err == nil && len(r.ListByProfile(ctx, profileName)) == 0 {
				nm.Teardown(ctx, profileName)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "delete the saved sandbox, its image, volumes, networks and audit log too")
	cmd.Flags().BoolVar(&volumes, "volumes", false, "also delete the sandbox's named volumes")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

// deleteSandbox removes everything a sandbox owns. A saved sandbox whose file
// no longer parses is still removed.
func deleteSandbox(name string, yes bool) error {
	store, err := config.NewStore()
	if err != nil {
		return err
	}
	if !store.Exists(name) {
		return fmt.Errorf("sandbox %q not found", name)
	}
	if !yes {
		if !isatty.IsTerminal(os.Stdin.Fd()) {
			return fmt.Errorf("this deletes %s with its volumes, settings and audit log; pass --yes to confirm", name)
		}
		fmt.Printf("  Delete %s with its containers, volumes, image, settings and audit log? [y/N] ", name)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Println("  Nothing deleted.")
			return nil
		}
	}

	ctx := context.Background()
	p, loadErr := store.Load(name)
	if loadErr != nil {
		p = &config.Profile{Name: name}
	}
	r := runnerFor(name)
	if _, err := r.DestroyAll(ctx, name); err != nil {
		return err
	}
	r.RemoveVolumes(ctx, p)
	if loadErr == nil {
		if b, err := container.NewBuilder(); err == nil {
			if err := b.RemoveImage(ctx, p.ImageTag()); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: %v\n", err)
			}
		}
	}
	if nm, err := container.NewNetworkManager(); err == nil {
		nm.Teardown(ctx, name)
	}
	if err := config.RemoveState(name); err != nil {
		fmt.Fprintf(os.Stderr, "  Warning: could not remove the state of %s: %v\n", name, err)
	}
	if err := store.Delete(name); err != nil {
		return fmt.Errorf("delete sandbox: %w", err)
	}
	fmt.Printf("  Deleted %s.\n", name)
	return nil
}

func buildCmd() *cobra.Command {
	var noCache bool
	cmd := &cobra.Command{
		Use:   "build <name>",
		Short: "Build a sandbox's image without starting it",
		Long: `Build (or rebuild) a sandbox's image. 'rig run' does this automatically when
needed; use this to build ahead of time or to pull in newer agent versions
with --no-cache.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			eff := p.Resolve()
			if _, err := engineFor(eff); err != nil {
				return err
			}
			ctx, cancel := signalContext()
			defer cancel()
			b, err := container.NewBuilder()
			if err != nil {
				return err
			}
			fmt.Printf("  Building %s...\n", p.ImageTag())
			if err := b.BuildWithOpts(ctx, p, noCache, func(e container.BuildEvent) { fmt.Println(e.Stream) }); err != nil {
				return err
			}
			if failed, err := b.VerifyAgents(ctx, p); err == nil && len(failed) > 0 {
				return fmt.Errorf("these agents did not install correctly: %s", strings.Join(failed, ", "))
			}
			if eff.NetworkMode == "allowlist" {
				if _, err := b.EnsureHelperImage(ctx, func(e container.BuildEvent) { fmt.Println(e.Stream) }); err != nil {
					return err
				}
			}
			fmt.Printf("  Built %s.\n", p.ImageTag())
			return nil
		},
	}
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "rebuild every layer (fetches the latest agent versions)")
	return cmd
}

func logsCmd() *cobra.Command {
	var follow bool
	var tail string
	cmd := &cobra.Command{
		Use:   "logs <sandbox|container>",
		Short: "Show a sandbox container's output",
		Long:  "Show the container's console output. For what the sandbox did, see 'rig audit'.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx, cancel := signalContext()
			defer cancel()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			return r.Logs(ctx, name, follow, tail)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new output")
	cmd.Flags().StringVarP(&tail, "tail", "n", "", "number of lines to show from the end")
	return cmd
}

func cpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cp <src> <dst>",
		Short: "Copy files between a sandbox and this computer",
		Long: `Copy files or folders between a sandbox and this computer. Write the
sandbox side as <sandbox>:<absolute path>.

  rig cp work:/home/sandbox/workspace/out.txt ./out.txt
  rig cp ./data.csv work:/home/sandbox/workspace/data.csv

Treat files copied out of a sandbox as untrusted, like any download.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, dst := args[0], args[1]
			srcRef, srcIn := splitContainerRef(src)
			dstRef, dstIn := splitContainerRef(dst)
			ctx, cancel := signalContext()
			defer cancel()
			switch {
			case srcIn && dstIn:
				return fmt.Errorf("cannot copy directly between two sandboxes; copy through this computer")
			case srcIn:
				r := runnerFor(srcRef.container)
				name, err := resolve(ctx, r, srcRef.container)
				if err != nil {
					return err
				}
				fmt.Printf("  %s:%s -> %s\n", name, srcRef.path, dst)
				return r.CopyFromContainer(ctx, name, srcRef.path, dst)
			case dstIn:
				r := runnerFor(dstRef.container)
				name, err := resolve(ctx, r, dstRef.container)
				if err != nil {
					return err
				}
				fmt.Printf("  %s -> %s:%s\n", src, name, dstRef.path)
				return r.CopyToContainer(ctx, name, src, dstRef.path)
			default:
				return fmt.Errorf("write the sandbox side as <sandbox>:<absolute path>")
			}
		},
	}
}

type containerRef struct {
	container string
	path      string
}

// splitContainerRef recognises "name:/path". A host path is never treated as a
// container reference: absolute paths, "./x" and "~/x" have no container part,
// and the path side must be absolute, which is what the engines require anyway.
func splitContainerRef(s string) (containerRef, bool) {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return containerRef{}, false
	}
	name, path, ok := strings.Cut(s, ":")
	if !ok || name == "" || !strings.HasPrefix(path, "/") {
		return containerRef{}, false
	}
	return containerRef{container: name, path: path}, true
}

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats [sandbox|container]",
		Short: "Show resource use of running sandboxes",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if len(args) == 1 {
				r := runnerFor(args[0])
				name, err := resolve(ctx, r, args[0])
				if err != nil {
					return err
				}
				stats, err := r.ContainerStats(ctx, name)
				if err != nil {
					return err
				}
				fmt.Printf("  %s  %s\n", name, stats)
				return nil
			}
			found := false
			for _, r := range allRunners() {
				for _, c := range r.ListSandboxes(ctx) {
					if !c.Running {
						continue
					}
					found = true
					stats, err := r.ContainerStats(ctx, c.Name)
					if err != nil {
						stats = "unavailable: " + err.Error()
					}
					fmt.Printf("  %s  %s\n", c.Name, stats)
				}
			}
			if !found {
				fmt.Println("  No running sandboxes.")
			}
			return nil
		},
	}
}

// simpleCmd builds a command that resolves one sandbox and acts on it.
func simpleCmd(use, short, long string, act func(ctx context.Context, r *container.Runner, name string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			return act(ctx, r, name)
		},
	}
}

func topCmd() *cobra.Command {
	return simpleCmd("top <sandbox|container>", "Show the processes running in a sandbox", "",
		func(ctx context.Context, r *container.Runner, name string) error { return r.Top(ctx, name) })
}

func diffCmd() *cobra.Command {
	return simpleCmd("diff <sandbox|container>", "Show files changed inside a sandbox",
		"List files added (A), changed (C) or deleted (D) relative to the image. Mounted folders and volumes are not included.",
		func(ctx context.Context, r *container.Runner, name string) error { return r.Diff(ctx, name) })
}

func pauseCmd() *cobra.Command {
	return simpleCmd("pause <sandbox|container>", "Freeze every process in a sandbox", "",
		func(ctx context.Context, r *container.Runner, name string) error {
			if err := r.Pause(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Paused %s. Resume it with 'rig unpause %s'.\n", name, name)
			return nil
		})
}

func unpauseCmd() *cobra.Command {
	return simpleCmd("unpause <sandbox|container>", "Resume a paused sandbox", "",
		func(ctx context.Context, r *container.Runner, name string) error {
			if err := r.Unpause(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Resumed %s.\n", name)
			return nil
		})
}

func commitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "commit <sandbox|container> [tag]",
		Short: "Save a sandbox's current state as an image",
		Long: `Save the container's filesystem as an image, for example before a risky
change. Environment variables the sandbox was started with (such as API keys)
are blanked in the image. Files the agent wrote may still hold secrets, so keep
snapshots on this computer.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			tag := name + "-snapshot:" + time.Now().UTC().Format("20060102-150405")
			if len(args) > 1 {
				tag = args[1]
			}
			if err := r.Commit(ctx, name, tag); err != nil {
				return err
			}
			fmt.Printf("  Saved %s as %s.\n", name, tag)
			return nil
		},
	}
}

func renameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <container> <new-name>",
		Short: "Rename a sandbox container",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			newName := strings.TrimPrefix(args[1], "rig-")
			if err := security.ValidateProfileName(newName); err != nil {
				return fmt.Errorf("invalid name: %w", err)
			}
			newName = "rig-" + newName
			if err := r.Rename(ctx, name, newName); err != nil {
				return err
			}
			fmt.Printf("  Renamed %s to %s.\n", name, newName)
			return nil
		},
	}
}

// ── Older names, hidden ──────────────────────────────────────────────

func destroyCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:    "destroy <container|sandbox>",
		Short:  "Deprecated: use 'rig rm'",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := runnerFor(args[0])
			ctx := context.Background()
			if all {
				n, err := r.DestroyAll(ctx, args[0])
				if err != nil {
					return err
				}
				fmt.Printf("  Removed %d container(s) of %s.\n", n, args[0])
				return nil
			}
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if err := r.Destroy(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Removed %s.\n", name)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "every instance of the sandbox")
	return cmd
}

func deleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:    "delete <name>",
		Short:  "Deprecated: use 'rig rm --all'",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteSandbox(args[0], yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "inspect <name>",
		Short:  "Deprecated: use 'rig show --dockerfile'",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			df, err := container.GenerateDockerfile(p)
			if err != nil {
				return err
			}
			fmt.Print(df)
			return nil
		},
	}
}
