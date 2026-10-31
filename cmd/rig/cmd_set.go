package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
)

func setCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <name> [key=value...]",
		Short: "Change a sandbox's settings (CPU, memory, level, permissions, ...)",
		Long: `Change settings without opening the YAML. With no key=value, show them.

  rig set work                          show every setting and its value
  rig set work cpu=4 memory=8g          more compute
  rig set work permissions=full         let the agents act without asking
  rig set work level=strict             a stricter level
  rig set work timeout=2h disk=20g

CPU, memory and process limits apply to existing containers right away;
other changes apply the next time the sandbox starts. For anything not listed,
use 'rig edit'.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			if len(args) == 1 {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintf(w, "  SETTING\tVALUE\tACCEPTS\n")
				for _, s := range settingsTable() {
					fmt.Fprintf(w, "  %s\t%s\t%s\n", s.key, safeText(s.show(p)), paint("2", s.values))
				}
				w.Flush()
				fmt.Printf("\n  Change one: rig set %s key=value   (more: rig edit %s)\n", p.Name, p.Name)
				return nil
			}
			resources, rebuild := false, false
			var changed []string
			for _, kv := range args[1:] {
				key, value, ok := strings.Cut(kv, "=")
				if !ok || strings.TrimSpace(value) == "" {
					return fmt.Errorf("%q: use key=value (see 'rig set %s')", kv, p.Name)
				}
				s, found := findSetting(key)
				if !found {
					return fmt.Errorf("unknown setting %q (see 'rig set %s' for the list; 'rig edit %s' for everything else)", key, p.Name, p.Name)
				}
				if err := s.apply(p, strings.TrimSpace(value)); err != nil {
					return err
				}
				resources = resources || s.resources
				rebuild = rebuild || s.rebuild
				changed = append(changed, s.key+" "+s.show(p))
			}
			if err := store.Save(p); err != nil {
				return err
			}
			fmt.Printf("  Updated %s: %s.\n", p.Name, strings.Join(changed, ", "))
			if resources {
				updateRunningResources(p)
			}
			switch {
			case rebuild && !p.Resolve().Ephemeral:
				fmt.Printf("  This applies to new containers. Apply it to the existing one with 'rig run %s --recreate' (home and workspace volumes are kept).\n", p.Name)
			case !resources || rebuild:
				fmt.Printf("  Takes effect the next time it starts ('rig run %s').\n", p.Name)
			}
			return nil
		},
	}
}

// updateRunningResources applies new CPU, memory and process limits to the
// sandbox's existing containers.
func updateRunningResources(p *config.Profile) {
	provider.PreferIsolationCapable(needsIsolationEngine(p.Resolve()))
	r, err := newRunnerQuiet()
	if err != nil {
		return
	}
	ctx := context.Background()
	for _, c := range r.ListByProfile(ctx, p.Name) {
		if err := r.UpdateResources(ctx, c.Name, p.Resources); err != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not change %s's limits in place (%v); 'rig run %s --recreate' applies them.\n", c.Name, err, p.Name)
		} else {
			fmt.Printf("  Applied the new limits to %s.\n", c.Name)
		}
	}
}
