package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/provider"
)

// agentConfigs builds agent entries, passing through the API keys each agent
// usually needs as ${VAR} references (resolved at launch, never stored).
func agentConfigs(ids []string) ([]config.AgentConfig, error) {
	var out []config.AgentConfig
	for _, raw := range ids {
		id, version, _ := strings.Cut(raw, "@")
		spec, ok := agents.ByID(id)
		if !ok {
			msg := fmt.Sprintf("unknown agent %q (see 'rig agents')", id)
			for _, err := range agents.CustomErrors() {
				msg += fmt.Sprintf("\n  a custom agent definition was skipped: %v", err)
			}
			return nil, fmt.Errorf("%s", msg)
		}
		ac := config.AgentConfig{ID: id, Version: version, Env: map[string]string{}}
		for _, h := range spec.EnvHints {
			secret := strings.HasSuffix(h, "_KEY") || strings.HasSuffix(h, "_TOKEN")
			if secret && os.Getenv(h) != "" {
				ac.Env[h] = "${" + h + "}"
			}
		}
		if len(ac.Env) == 0 && len(spec.EnvHints) > 0 {
			ac.Env[spec.EnvHints[0]] = "${" + spec.EnvHints[0] + "}"
		}
		out = append(out, ac)
	}
	return out, nil
}

func parseMount(s string) (config.MountConfig, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return config.MountConfig{}, fmt.Errorf("mount %q: use SRC:DST or SRC:DST:rw", s)
	}
	src, err := filepath.Abs(parts[0])
	if err != nil {
		return config.MountConfig{}, err
	}
	m := config.MountConfig{Source: src, Target: parts[1], ReadOnly: true}
	if len(parts) == 3 {
		switch parts[2] {
		case "rw":
			m.ReadOnly = false
		case "ro":
		default:
			return config.MountConfig{}, fmt.Errorf("mount %q: mode must be ro or rw", s)
		}
	}
	return m, nil
}

func parsePort(s string) (config.HostPort, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return config.HostPort{}, fmt.Errorf("port %q: use NAME:PORT or NAME:PORT:HOSTPORT", s)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return config.HostPort{}, fmt.Errorf("port %q: %s is not a number", s, parts[1])
	}
	hp := config.HostPort{Name: parts[0], Port: port}
	if len(parts) == 3 {
		if hp.HostPort, err = strconv.Atoi(parts[2]); err != nil {
			return config.HostPort{}, fmt.Errorf("port %q: %s is not a number", s, parts[2])
		}
	}
	return hp, nil
}

func agentNames(p *config.Profile) string {
	var names []string
	for _, a := range p.Agents {
		if spec, ok := agents.ByID(a.ID); ok {
			names = append(names, spec.DisplayName)
		} else {
			names = append(names, a.ID)
		}
	}
	return strings.Join(names, " + ")
}

func describeNetwork(eff config.Effective) string {
	switch eff.NetworkMode {
	case "unrestricted":
		return "unrestricted network"
	case "none":
		return "no network"
	}
	if len(eff.Allowed) == 0 {
		return "no internet domains"
	}
	return fmt.Sprintf("%d allowed domains", len(eff.Allowed))
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit <name>",
		Short: "Edit a sandbox's settings in your editor",
		Long: `Open the sandbox's YAML in $VISUAL or $EDITOR. The file is checked when you
save; an invalid change is not applied. Run 'rig run' afterwards: the image is
rebuilt automatically if needed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			original, err := yaml.Marshal(p)
			if err != nil {
				return err
			}
			dir, err := os.MkdirTemp("", "rig-edit-*")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, p.Name+".yaml")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				return err
			}
			editor := os.Getenv("VISUAL")
			if editor == "" {
				editor = os.Getenv("EDITOR")
			}
			if editor == "" {
				editor = "vi"
			}
			in := bufio.NewReader(os.Stdin)
			for {
				fields := strings.Fields(editor)
				c := exec.Command(fields[0], append(fields[1:], path)...)
				c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := c.Run(); err != nil {
					return fmt.Errorf("editor %q failed: %w", editor, err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				var edited config.Profile
				err = yaml.Unmarshal(data, &edited)
				if err == nil {
					if edited.Name != p.Name {
						err = fmt.Errorf("the name cannot be changed here (it was %q)", p.Name)
					} else {
						edited.Normalize()
						err = edited.Validate()
					}
				}
				if err == nil {
					if err := store.Save(&edited); err != nil {
						return err
					}
					fmt.Printf("  Saved %s.\n", p.Name)
					return nil
				}
				fmt.Fprintf(os.Stderr, "  %s %v\n  Edit again? [Y/n] ", paint("1;31", "Not saved:"), err)
				answer, _ := in.ReadString('\n')
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "n") {
					return fmt.Errorf("no changes saved")
				}
			}
		},
	}
}

func allowCmd() *cobra.Command {
	var remove bool
	cmd := &cobra.Command{
		Use:   "allow <name> <domain>...",
		Short: "Allow (or with --remove, stop allowing) domains",
		Long: `Add domains to a sandbox's egress allowlist. "*.example.com" means
example.com and all of its subdomains.

  rig allow work docs.python.org
  rig allow work --remove docs.python.org
  rig blocked work                 pick from the sites Rig blocked recently

A running sandbox gets the change immediately; otherwise it applies the next
time the sandbox starts.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			p.Network.AllowedDomains = editList(p.Network.AllowedDomains, args[1:], remove)
			if err := store.Save(p); err != nil {
				return err
			}
			if p.Network.Mode != "allowlist" {
				fmt.Fprintf(os.Stderr, "  Note: network mode is %s; the allowlist applies only in allowlist mode.\n", p.Network.Mode)
			}
			fmt.Printf("  %s now allows %d domains in total (see 'rig check %s').\n", p.Name, len(p.Resolve().Allowed), p.Name)
			reloadAllowlist(p)
			return nil
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the domains instead")
	return cmd
}

// reloadAllowlist applies a saved allowlist to the sandbox's running egress
// proxy, so the agent can retry at once.
func reloadAllowlist(p *config.Profile) {
	eff := p.Resolve()
	if eff.NetworkMode != "allowlist" {
		return
	}
	provider.PreferIsolationCapable(needsIsolationEngine(eff))
	nm, err := container.NewNetworkManager()
	if err != nil {
		return
	}
	switch live, err := nm.Reload(context.Background(), p, eff); {
	case err != nil:
		fmt.Fprintf(os.Stderr, "  Note: could not update the running sandbox (%v); the change applies when it next starts.\n", err)
	case live:
		fmt.Println("  Applied to the running sandbox right away.")
	}
}

func addCmd() *cobra.Command {
	var npm, pip, remove bool
	cmd := &cobra.Command{
		Use:   "add <name> <package>...",
		Short: "Install extra software in a sandbox's image",
		Long: `Add packages to the sandbox's image. They are installed when the image is
rebuilt, which happens automatically on the next 'rig run'.

  rig add work ripgrep tmux          apt packages
  rig add work --npm typescript      npm packages
  rig add work --pip requests        pip packages
  rig add work --remove tmux

Inside a running sandbox the agent can also install to its home directory
without root (npm install -g and pip install both work), as far as the
network allowlist permits.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if npm && pip {
				return fmt.Errorf("choose either --npm or --pip")
			}
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			switch {
			case npm:
				p.Packages.NPM = editList(p.Packages.NPM, args[1:], remove)
			case pip:
				p.Packages.Pip = editList(p.Packages.Pip, args[1:], remove)
			default:
				p.Tools = editList(p.Tools, args[1:], remove)
			}
			if err := store.Save(p); err != nil {
				return err
			}
			fmt.Printf("  Updated %s. The image is rebuilt on the next 'rig run %s'.\n", p.Name, p.Name)
			if !p.Resolve().Ephemeral {
				fmt.Printf("  An existing container keeps its old image until you run 'rig run %s --recreate' (home and workspace volumes are kept).\n", p.Name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&npm, "npm", false, "npm packages")
	cmd.Flags().BoolVar(&pip, "pip", false, "pip packages")
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the packages instead")
	return cmd
}

func editList(list, items []string, remove bool) []string {
	if remove {
		drop := map[string]bool{}
		for _, i := range items {
			drop[i] = true
		}
		var out []string
		for _, l := range list {
			if !drop[l] {
				out = append(out, l)
			}
		}
		return out
	}
	seen := map[string]bool{}
	for _, l := range list {
		seen[l] = true
	}
	for _, i := range items {
		if !seen[i] {
			list = append(list, i)
			seen[i] = true
		}
	}
	return list
}

func showCmd() *cobra.Command {
	var dockerfile bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Print a sandbox's settings (or its generated Dockerfile)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			if dockerfile {
				df, err := container.GenerateDockerfile(p)
				if err != nil {
					return err
				}
				fmt.Print(df)
				return nil
			}
			out, err := yaml.Marshal(p)
			if err != nil {
				return err
			}
			fmt.Print(string(out))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dockerfile, "dockerfile", false, "print the Dockerfile Rig generates for it instead")
	return cmd
}

func templatesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "templates",
		Aliases: []string{"tmpl"},
		Short:   "List ready-made sandbox setups",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TEMPLATE\tLEVEL\tAGENTS\tDESCRIPTION")
			for _, t := range config.BuiltinTemplates() {
				p := t.Profile
				names := agentNames(&p)
				if t.NeedsAgent() {
					names = "any"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Name, p.EffectiveLevel(), names, t.Description)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Println("\nUse one with: rig new <name> --from <template> --agent <agent>")
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
			fmt.Fprintln(w, "ID\tNAME\tAPI KEYS\tNOTES")
			for _, a := range agents.All() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, a.DisplayName, strings.Join(a.EnvHints, ", "), a.Describe())
			}
			if err := w.Flush(); err != nil {
				return err
			}
			for _, err := range agents.CustomErrors() {
				fmt.Fprintf(os.Stderr, "  Warning: custom agent skipped: %v\n", err)
			}
			fmt.Printf("\nPin a version with --agent id@version. Define your own agents in %s.\n", agents.CustomDir())
			return nil
		},
	}
}

func levelsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "levels",
		Short: "Explain the security levels",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "LEVEL\tWHAT IT DOES")
			for _, l := range config.LevelInfo {
				fmt.Fprintf(w, "%s\t%s\n", l.Name, l.Summary)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Println(`
Every level runs the agent as an unprivileged user with resource limits, and
blocks known exfiltration sites (at open you may turn that off). Without sudo (never allowed at strict and
lockdown) the agent also has no Linux capabilities and cannot gain privileges.
A level is a floor: a profile can be stricter than its level, never looser.
Set it with 'rig new <name> --level <level>' or security.level in 'rig edit'.`)
			return nil
		},
	}
}

func presetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "presets",
		Short: "List named groups of domains for the allowlist",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PRESET\tDESCRIPTION\tDOMAINS")
			for _, name := range config.PresetNames() {
				ps := config.Presets[name]
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, ps.Description, strings.Join(ps.Domains, " "))
			}
			return w.Flush()
		},
	}
}

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
			names, err := store.List()
			if err != nil {
				return err
			}
			if len(names) == 0 {
				fmt.Println("  No sandboxes yet. Create one with 'rig new <name>'.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SANDBOX\tLEVEL\tAGENTS\tNETWORK\tISOLATION\tMODE")
			for _, name := range names {
				p, err := store.Load(name)
				if err != nil {
					fmt.Fprintf(w, "%s\t(invalid: %v)\t\t\t\t\n", name, err)
					continue
				}
				eff := p.Resolve()
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", name, eff.Level, agentNames(p), describeNetwork(eff), eff.Isolation, p.Persistence)
			}
			return w.Flush()
		},
	}
}

func exportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export <name> [file]",
		Short: "Export a sandbox to a YAML file for sharing",
		Long:  "Exports the sandbox with ${VAR} references intact, so no secret value is written.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			out := args[0] + ".rig.yaml"
			if len(args) > 1 {
				out = args[1]
			}
			if err := store.Export(p, out); err != nil {
				return err
			}
			fmt.Printf("  Exported %s to %s\n", args[0], out)
			return nil
		},
	}
}

func importCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <file>",
		Short: "Import a sandbox from a YAML file",
		Long: `Import a shared sandbox. The file is treated as untrusted: every field is
validated, credential directories and engine sockets cannot be mounted, and it
can only name agents you already have. Run 'rig check' on it before using it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			p, err := store.Import(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("  Imported %s. Review it with 'rig check %s' before running it.\n", p.Name, p.Name)
			return nil
		},
	}
}

// templateCmd keeps the old 'rig template list/use/inspect' working.
func templateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "template", Short: "Deprecated: use 'rig templates' and 'rig new --from'", Hidden: true}
	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List templates",
		RunE: func(c *cobra.Command, args []string) error { return templatesCmd().RunE(c, args) },
	})
	use := &cobra.Command{
		Use: "use <template> [name]", Args: cobra.RangeArgs(1, 2),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			if len(args) > 1 {
				name = args[1]
			}
			n := newCmd()
			force, _ := c.Flags().GetBool("force")
			_ = n.Flags().Set("from", args[0])
			if force {
				_ = n.Flags().Set("force", "true")
			}
			return n.RunE(n, []string{name})
		},
	}
	use.Flags().Bool("force", false, "replace an existing sandbox")
	cmd.AddCommand(use)
	cmd.AddCommand(&cobra.Command{
		Use: "inspect <template>", Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			t, ok := config.GetTemplate(args[0])
			if !ok {
				return fmt.Errorf("template %q not found", args[0])
			}
			p := t.Profile
			p.Name = t.Name
			df, err := container.GenerateDockerfile(&p)
			if err != nil {
				return err
			}
			fmt.Printf("Template: %s\nDescription: %s\n\n--- Generated Dockerfile ---\n%s", t.Name, t.Description, df)
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
