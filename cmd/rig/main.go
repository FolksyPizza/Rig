package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/security"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "rig",
		Short: "Containerized AI agent sandbox",
		Long: `Rig creates isolated, containerized sandboxes for AI agents.

Common flow:
  rig new work --from claude-secure   create a sandbox named "work"
  rig run work                        build if needed, then enter it
  rig ls                              list your sandboxes
  rig rm work                         remove its containers (add --all to delete it)`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newCmd(),
		runCmd(),
		listCmd(),
		psCmd(),
		buildCmd(),
		inspectCmd(),
		agentsCmd(),
		shellCmd(),
		execCmd(),
		stopCmd(),
		rmCmd(),
		destroyCmd(),
		deleteCmd(),
		logsCmd(),
		cpCmd(),
		statsCmd(),
		pauseCmd(),
		unpauseCmd(),
		commitCmd(),
		renameCmd(),
		exportCmd(),
		importCmd(),
		templateCmd(),
		topCmd(),
		diffCmd(),
		versionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// signalContext cancels on SIGINT/SIGTERM so an interrupted launch tears down
// the resources it created instead of leaving a proxy and networks behind.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// enterSandbox brings up a profile's network, then its container.
//
// Network setup failures are fatal. Continuing past a failed allowlist setup
// would drop the sandbox onto Docker's default bridge with unrestricted
// internet access — the exact opposite of what the profile asked for, and
// silently so.
func enterSandbox(profile *config.Profile, opts container.RunOptions) error {
	ctx, cancel := signalContext()
	defer cancel()

	if missing := config.MissingEnvVars(profile); len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "  Warning: these environment variables are unset on the host and will be empty in the sandbox: %s\n",
			strings.Join(missing, ", "))
	}

	var networkName string
	if profile.Network.Mode == "allowlist" {
		nm, err := container.NewNetworkManager()
		if err != nil {
			return err
		}
		defer nm.Close()

		fmt.Printf("  Starting egress allowlist (%s)...\n", security.DescribeAllowlist(profile.Network.AllowedDomains))
		networkName, err = nm.Setup(ctx, profile)
		if err != nil {
			return fmt.Errorf("network setup failed, refusing to launch an unfiltered sandbox: %w", err)
		}
	}

	runner, err := container.NewRunner()
	if err != nil {
		return err
	}
	defer runner.Close()

	fmt.Printf("\n  Entering sandbox \033[1;35m%s\033[0m...\n", profile.Name)
	fmt.Printf("  Type 'exit' to leave the sandbox.\n\n")

	runErr := runner.Run(ctx, profile, networkName, opts)

	// Tear the proxy down once the last sandbox for this profile is gone,
	// which is the common case for ephemeral profiles.
	if profile.Network.Mode == "allowlist" {
		if len(runner.ListByProfile(context.Background(), profile.Name)) == 0 {
			if nm, err := container.NewNetworkManager(); err == nil {
				nm.Teardown(context.Background(), profile.Name)
				nm.Close()
			}
		}
	}
	return runErr
}

func mustRunner() *container.Runner {
	r, err := container.NewRunner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return r
}

func resolve(ctx context.Context, r *container.Runner, name string) (string, error) {
	return container.ResolveContainerName(ctx, r, name)
}

// ── Lifecycle commands ───────────────────────────────────────────────

func newCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a sandbox from a template",
		Long: `Create a saved sandbox named <name> from a template.

  rig new work --from claude-secure    create "work" from the claude-secure template
  rig new work --from minimal --run    create it and enter it right away

See 'rig template list' for the available templates.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, _ := cmd.Flags().GetString("from")
			if from == "" {
				return fmt.Errorf("choose a template with --from (see 'rig template list')")
			}
			force, _ := cmd.Flags().GetBool("force")
			launch, _ := cmd.Flags().GetBool("run")

			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profile, err := createFromTemplate(store, from, args[0], force)
			if err != nil {
				return err
			}
			fmt.Printf("  Created sandbox %q from template %q\n", profile.Name, from)
			if launch {
				return buildAndEnter(profile, container.RunOptions{})
			}
			fmt.Printf("  Run 'rig run %s' to launch it.\n", profile.Name)
			return nil
		},
	}
	cmd.Flags().String("from", "", "Template to create the sandbox from (see 'rig template list')")
	cmd.Flags().Bool("run", false, "Launch the sandbox immediately after creating it")
	cmd.Flags().Bool("force", false, "Overwrite an existing sandbox with the same name")
	return cmd
}

// createFromTemplate instantiates a saved sandbox from a built-in template.
func createFromTemplate(store *config.Store, templateName, name string, force bool) (*config.Profile, error) {
	tmpl, ok := config.GetTemplate(templateName)
	if !ok {
		return nil, fmt.Errorf("template %q not found (see 'rig template list')", templateName)
	}
	profile := tmpl.Profile
	profile.Name = tmpl.Name
	if name != "" {
		profile.Name = name
	}
	if store.Exists(profile.Name) && !force {
		return nil, fmt.Errorf("sandbox %q already exists; pass --force to overwrite it", profile.Name)
	}
	profile.Metadata.CreatedAt = time.Now().UTC()
	if err := store.Save(&profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

// buildAndEnter builds a sandbox's image if it is missing, then enters it.
func buildAndEnter(profile *config.Profile, opts container.RunOptions) error {
	ctx, cancel := signalContext()
	defer cancel()

	builder, err := container.NewBuilder()
	if err != nil {
		return err
	}
	defer builder.Close()

	if !builder.ImageExists(ctx, profile.ImageTag()) {
		fmt.Printf("  Building image %s...\n", profile.ImageTag())
		if err := builder.Build(ctx, profile, func(e container.BuildEvent) {
			fmt.Println(e.Stream)
		}); err != nil {
			return err
		}
	}
	return enterSandbox(profile, opts)
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <name>",
		Short: "Build if needed and enter a sandbox",
		Long: `Launch a saved sandbox, building its image on first use.

If the sandbox does not exist yet, pass --from <template> to create it first.
By default an existing instance is reused: a running one is re-entered, a stopped
one is restarted. Pass --new to start an additional instance alongside it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			name := args[0]
			from, _ := cmd.Flags().GetString("from")

			var profile *config.Profile
			switch {
			case store.Exists(name):
				profile, err = store.Load(name)
				if err != nil {
					return fmt.Errorf("sandbox %q could not be loaded: %w", name, err)
				}
			case from != "":
				profile, err = createFromTemplate(store, from, name, false)
				if err != nil {
					return err
				}
				fmt.Printf("  Created sandbox %q from template %q\n", name, from)
			default:
				return fmt.Errorf("sandbox %q not found; create it with 'rig new %s --from <template>' or pass --from here", name, name)
			}

			timeout, _ := cmd.Flags().GetDuration("timeout")
			newInstance, _ := cmd.Flags().GetBool("new")
			return buildAndEnter(profile, container.RunOptions{
				NewInstance: newInstance,
				Timeout:     timeout,
			})
		},
	}
	cmd.Flags().Duration("timeout", 0, "Auto-stop the sandbox after this duration (e.g. 30m, 2h)")
	cmd.Flags().Bool("new", false, "Start an additional instance instead of reusing an existing one")
	cmd.Flags().String("from", "", "If the sandbox doesn't exist, create it from this template first")
	return cmd
}

func buildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build <name>",
		Short: "Build a sandbox image without launching it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profile, err := store.Load(args[0])
			if err != nil {
				return err
			}

			noCache, _ := cmd.Flags().GetBool("no-cache")
			builder, err := container.NewBuilder()
			if err != nil {
				return err
			}
			defer builder.Close()

			ctx, cancel := signalContext()
			defer cancel()

			fmt.Printf("  Building image %s...\n", profile.ImageTag())
			return builder.BuildWithOpts(ctx, profile, noCache, func(e container.BuildEvent) {
				fmt.Println(e.Stream)
			})
		},
	}
	cmd.Flags().Bool("no-cache", false, "Build without using the Docker cache")
	return cmd
}

func stopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop <container|sandbox>",
		Short: "Stop a running sandbox without removing it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()

			if all, _ := cmd.Flags().GetBool("all"); all {
				n, err := r.StopAll(ctx, args[0])
				if err != nil {
					return err
				}
				fmt.Printf("  Stopped %d container(s) for sandbox %q\n", n, args[0])
				return nil
			}

			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if err := r.Stop(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Stopped %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolP("all", "a", false, "Stop every instance of this profile")
	return cmd
}

func destroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "destroy <container|sandbox>",
		Short:  "Deprecated: use 'rig rm <name>'",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()

			if all, _ := cmd.Flags().GetBool("all"); all {
				n, err := r.DestroyAll(ctx, args[0])
				if err != nil {
					return err
				}
				fmt.Printf("  Destroyed %d container(s) for profile %q\n", n, args[0])
				return nil
			}

			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if err := r.Destroy(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Destroyed %s\n", name)
			return nil
		},
	}
	cmd.Flags().BoolP("all", "a", false, "Destroy every instance of this profile")
	return cmd
}

// rmCmd is the single teardown verb: by default it removes a sandbox's
// containers; with --all it also deletes the saved sandbox, its image, and
// network. It replaces the old stop/destroy/delete split.
func rmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a sandbox's containers (with --all, delete the sandbox too)",
		Long: `Remove the containers belonging to a sandbox.

  rig rm work           remove work's containers, keep the saved sandbox
  rig rm work --all     also delete the saved sandbox, its image, and network`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all, _ := cmd.Flags().GetBool("all"); all {
				return deleteSandbox(cmd, args[0])
			}
			r := mustRunner()
			defer r.Close()
			n, err := r.DestroyAll(context.Background(), args[0])
			if err != nil {
				return err
			}
			fmt.Printf("  Removed %d container(s) for sandbox %q\n", n, args[0])
			return nil
		},
	}
	cmd.Flags().BoolP("all", "a", false, "Also delete the saved sandbox, its image, and network")
	cmd.Flags().Bool("yes", false, "Skip the confirmation prompt when using --all")
	return cmd
}

// deleteCmd is retained as a hidden alias for `rm --all`.
func deleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "delete <name>",
		Short:  "Deprecated: use 'rig rm <name> --all'",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteSandbox(cmd, args[0])
		},
	}
	cmd.Flags().Bool("yes", false, "Skip the confirmation prompt")
	return cmd
}

// deleteSandbox tears down every resource a sandbox owns. `cmd` supplies the
// --yes flag. A sandbox whose file no longer parses is still removed.
func deleteSandbox(cmd *cobra.Command, name string) error {
	store, err := config.NewStore()
	if err != nil {
		return err
	}
	if !store.Exists(name) {
		return fmt.Errorf("sandbox %q not found", name)
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		fmt.Printf("  This deletes sandbox %q, its image, and all of its containers.\n", name)
		fmt.Printf("  Re-run with --yes to confirm.\n")
		return nil
	}

	ctx := context.Background()
	if r, err := container.NewRunner(); err == nil {
		defer r.Close()
		if _, err := r.DestroyAll(ctx, name); err != nil {
			return err
		}
	}

	if profile, err := store.Load(name); err == nil {
		if b, err := container.NewBuilder(); err == nil {
			defer b.Close()
			if err := b.RemoveImage(ctx, profile.ImageTag()); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: %v\n", err)
			}
		}
	}

	if nm, err := container.NewNetworkManager(); err == nil {
		nm.Teardown(ctx, name)
		nm.Close()
	}

	if err := store.Delete(name); err != nil {
		return fmt.Errorf("delete sandbox: %w", err)
	}
	fmt.Printf("  Deleted sandbox %q and all associated resources\n", name)
	return nil
}

// ── Interaction commands ─────────────────────────────────────────────

func shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell <container>",
		Short: "Open a new shell in a running sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx, cancel := signalContext()
			defer cancel()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			return r.Shell(ctx, name)
		},
	}
}

func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec <container> -- <command...>",
		Short: "Run a command in a running sandbox",
		Long: `Run a command inside a sandbox.

If the sandbox's profile sets commands.mode to "allowlist", only the listed
commands are accepted here. That check guards this entry point only; it is not
a confinement boundary for processes already running inside the container.`,
		Args:               cobra.MinimumNArgs(2),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx, cancel := signalContext()
			defer cancel()

			cmdArgs := args[1:]
			if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
				cmdArgs = cmdArgs[1:]
			}
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command given")
			}

			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}

			if err := checkCommandAllowed(ctx, r, name, cmdArgs); err != nil {
				return err
			}
			return r.Exec(ctx, name, cmdArgs)
		},
	}
}

// checkCommandAllowed enforces a profile's command allowlist for `rig exec`.
// A container whose profile is missing or unreadable is not blocked; the
// allowlist is a convenience guard, and failing closed here would strand
// users whose profile file was deleted.
func checkCommandAllowed(ctx context.Context, r *container.Runner, containerName string, argv []string) error {
	profileName, err := r.ProfileOf(ctx, containerName)
	if err != nil {
		return nil
	}
	store, err := config.NewStore()
	if err != nil {
		return nil
	}
	profile, err := store.Load(profileName)
	if err != nil {
		return nil
	}
	if !profile.CommandAllowed(argv) {
		return fmt.Errorf("command %q is not in profile %q's allowlist (%s)",
			argv[0], profileName, strings.Join(profile.Commands.Allowed, ", "))
	}
	return nil
}

func logsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs <container>",
		Short: "View logs from a sandbox container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx, cancel := signalContext()
			defer cancel()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			follow, _ := cmd.Flags().GetBool("follow")
			tail, _ := cmd.Flags().GetString("tail")
			return r.Logs(ctx, name, follow, tail)
		},
	}
	cmd.Flags().BoolP("follow", "f", false, "Follow log output")
	cmd.Flags().StringP("tail", "n", "", "Number of lines to show from the end")
	return cmd
}

// ── Data migration ───────────────────────────────────────────────────

func cpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cp <src> <dst>",
		Short: "Copy files between a sandbox and the host",
		Long: `Copy files or directories between a sandbox container and the host.

Use container:path syntax to reference paths inside a container.

Examples:
  rig cp my-sandbox:/home/sandbox/workspace/out.txt ./out.txt
  rig cp ./data.csv my-sandbox:/home/sandbox/workspace/data.csv
  rig cp my-sandbox:/home/sandbox/workspace/ ./backup/`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx, cancel := signalContext()
			defer cancel()

			src, dst := args[0], args[1]
			srcRef, srcIsContainer := splitContainerRef(src)
			dstRef, dstIsContainer := splitContainerRef(dst)

			switch {
			case srcIsContainer && dstIsContainer:
				return fmt.Errorf("cannot copy directly between two containers; copy via the host")
			case srcIsContainer:
				name, err := resolve(ctx, r, srcRef.container)
				if err != nil {
					return err
				}
				fmt.Printf("  %s:%s -> %s\n", name, srcRef.path, dst)
				return r.CopyFromContainer(ctx, name, srcRef.path, dst)
			case dstIsContainer:
				name, err := resolve(ctx, r, dstRef.container)
				if err != nil {
					return err
				}
				fmt.Printf("  %s -> %s:%s\n", src, name, dstRef.path)
				return r.CopyToContainer(ctx, name, src, dstRef.path)
			default:
				return fmt.Errorf("one of src or dst must use container:path syntax")
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
// and the path side must be absolute, which is what Docker requires anyway.
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

// ── Inspection commands ──────────────────────────────────────────────

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "sandboxes"},
		Short:   "List saved sandboxes",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profiles, err := store.List()
			if err != nil {
				return err
			}
			if len(profiles) == 0 {
				fmt.Println("  No sandboxes yet. Create one with 'rig new <name> --from <template>'.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SANDBOX\tAGENTS\tNETWORK\tCPU\tMEMORY\tMODE")
			for _, name := range profiles {
				p, err := store.Load(name)
				if err != nil {
					fmt.Fprintf(w, "%s\t(invalid: %v)\t\t\t\t\n", name, err)
					continue
				}
				ids := make([]string, 0, len(p.Agents))
				for _, a := range p.Agents {
					ids = append(ids, a.ID)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%.1f\t%dMB\t%s\n",
					name, strings.Join(ids, ","), p.Network.Mode,
					p.Resources.CPU, p.Resources.Memory, p.Persistence)
			}
			return w.Flush()
		},
	}
}

func psCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ps",
		Short: "List sandbox containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			containers := r.ListSandboxes(context.Background())
			if len(containers) == 0 {
				fmt.Println("  No sandbox containers found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "CONTAINER\tPROFILE\tSTATUS\tIMAGE\tCREATED")
			for _, c := range containers {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.Name, c.Profile, c.Status, c.Image, c.CreatedAt)
			}
			return w.Flush()
		},
	}
}

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <name>",
		Short: "Show the generated Dockerfile for a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profile, err := store.Load(args[0])
			if err != nil {
				return err
			}
			df, err := container.GenerateDockerfile(profile)
			if err != nil {
				return err
			}
			fmt.Print(df)
			return nil
		},
	}
}

func agentsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "agents",
		Short: "List the agents Rig can install",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tENV VARS")
			for _, a := range agents.All() {
				fmt.Fprintf(w, "%s\t%s\t%s\n", a.ID, a.DisplayName, strings.Join(a.EnvHints, ", "))
			}
			return w.Flush()
		},
	}
}

func statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <container>",
		Short: "Show resource usage of a running sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
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
		},
	}
}

func topCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top <container>",
		Short: "Show running processes inside a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			return r.Top(ctx, name)
		},
	}
}

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <container>",
		Short: "Show filesystem changes made inside a sandbox",
		Long:  "Lists files added, changed, or deleted relative to the base image.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			return r.Diff(ctx, name)
		},
	}
}

// ── State management ─────────────────────────────────────────────────

func pauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pause <container>",
		Short: "Freeze all processes in a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if err := r.Pause(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Paused %s\n", name)
			return nil
		},
	}
}

func unpauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpause <container>",
		Short: "Resume a paused sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}
			if err := r.Unpause(ctx, name); err != nil {
				return err
			}
			fmt.Printf("  Resumed %s\n", name)
			return nil
		},
	}
}

func commitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "commit <container> [tag]",
		Short: "Snapshot a sandbox's current state as a new image",
		Long: `Save the container's filesystem as a Docker image.
Useful for checkpointing agent work before a risky operation.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}

			tag := name + "-snapshot-" + time.Now().UTC().Format("20060102-150405")
			if len(args) > 1 {
				tag = args[1]
			}
			if err := r.Commit(ctx, name, tag); err != nil {
				return err
			}
			fmt.Printf("  Saved snapshot as %s\n", tag)
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
			r := mustRunner()
			defer r.Close()
			ctx := context.Background()
			name, err := resolve(ctx, r, args[0])
			if err != nil {
				return err
			}

			newName := strings.TrimPrefix(args[1], "rig-")
			if err := security.ValidateProfileName(newName); err != nil {
				return fmt.Errorf("invalid container name: %w", err)
			}
			newName = "rig-" + newName

			if err := r.Rename(ctx, name, newName); err != nil {
				return err
			}
			fmt.Printf("  Renamed %s -> %s\n", name, newName)
			return nil
		},
	}
}

// ── Profile portability ──────────────────────────────────────────────

func exportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <name> [file]",
		Short: "Export a sandbox to a YAML file for sharing",
		Long:  "Exports the sandbox with ${VAR} references intact, so no secret value is written.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profile, err := store.Load(args[0])
			if err != nil {
				return err
			}

			outFile := args[0] + ".rig.yaml"
			if len(args) > 1 {
				outFile = args[1]
			}
			if err := store.Export(profile, outFile); err != nil {
				return err
			}
			fmt.Printf("  Exported sandbox to %s\n", outFile)
			return nil
		},
	}
}

func importCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import a sandbox from a YAML file",
		Long: `Import a shared sandbox.

Imported files are treated as untrusted: every field is validated, and a
sandbox that requests a host mount of something like the Docker socket is
rejected rather than imported.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			profile, err := store.Import(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("  Imported sandbox %q\n", profile.Name)
			return nil
		},
	}
}

// ── Templates ────────────────────────────────────────────────────────

func templateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Manage pre-built sandbox templates",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TEMPLATE\tDESCRIPTION\tAGENTS\tNETWORK")
			for _, t := range config.BuiltinTemplates() {
				ids := make([]string, 0, len(t.Profile.Agents))
				for _, a := range t.Profile.Agents {
					ids = append(ids, a.ID)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					t.Name, t.Description, strings.Join(ids, ","), t.Profile.Network.Mode)
			}
			return w.Flush()
		},
	})

	useCmd := &cobra.Command{
		Use:    "use <template> [name]",
		Short:  "Deprecated: use 'rig new <name> --from <template>'",
		Hidden: true,
		Args:   cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			name := ""
			if len(args) > 1 {
				name = args[1]
			}
			force, _ := cmd.Flags().GetBool("force")
			profile, err := createFromTemplate(store, args[0], name, force)
			if err != nil {
				return err
			}
			fmt.Printf("  Created sandbox %q from template %q\n", profile.Name, args[0])
			fmt.Printf("  Run 'rig run %s' to launch it.\n", profile.Name)
			return nil
		},
	}
	useCmd.Flags().Bool("force", false, "Overwrite an existing sandbox with the same name")
	cmd.AddCommand(useCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "inspect <template>",
		Short: "Show details of a template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tmpl, ok := config.GetTemplate(args[0])
			if !ok {
				return fmt.Errorf("template %q not found", args[0])
			}
			profile := tmpl.Profile
			profile.Name = tmpl.Name
			df, err := container.GenerateDockerfile(&profile)
			if err != nil {
				return err
			}
			fmt.Printf("Template: %s\n", tmpl.Name)
			fmt.Printf("Description: %s\n\n", tmpl.Description)
			fmt.Printf("--- Generated Dockerfile ---\n%s", df)
			return nil
		},
	})

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of rig",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("rig %s\n", version)
		},
	}
}
