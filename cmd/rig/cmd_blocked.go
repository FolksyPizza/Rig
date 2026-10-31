package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/monitor"
)

// blockedSite is one host Rig refused because it was not on the allowlist.
type blockedSite struct {
	Host  string
	Count int
	Last  time.Time
}

func blockedCmd() *cobra.Command {
	var since time.Duration
	cmd := &cobra.Command{
		Use:   "blocked <name>",
		Short: "List sites Rig blocked and choose which to allow",
		Long: `List the sites a sandbox tried to reach that are not on its allowlist, most
recent first. In a terminal, pick the ones to allow; a running sandbox gets
them immediately.

  rig blocked work               the last 24 hours
  rig blocked work --since 1h
  rig blocked work --since 0     everything in the audit log

Known exfiltration services and private addresses are not listed: allowing
them takes an explicit network.allow_risky entry ('rig edit').`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, p, err := loadProfile(args[0])
			if err != nil {
				return err
			}
			sites, err := blockedSites(p.Name, since)
			if err != nil {
				return err
			}
			window := "in the last " + strings.TrimSuffix(strings.TrimSuffix(since.String(), "0s"), "0m")
			if since == 0 {
				window = "in the audit log"
			}
			if len(sites) == 0 {
				fmt.Printf("  Nothing was blocked for %s %s.\n", p.Name, window)
				return nil
			}
			fmt.Printf("  Sites blocked for %s %s (not on the allowlist):\n\n", p.Name, window)
			var options []choice
			for i, s := range sites {
				times := "1 time"
				if s.Count > 1 {
					times = fmt.Sprintf("%d times", s.Count)
				}
				fmt.Printf("  %3d) %-40s %s, last %s\n", i+1, safeText(s.Host), times, s.Last.Local().Format("Jan 02 15:04"))
				options = append(options, choice{key: s.Host})
			}
			if !interactiveTerminal() {
				fmt.Printf("\n  Allow one with: rig allow %s %s\n", p.Name, safeText(sites[0].Host))
				return nil
			}
			fmt.Println()
			answer := newPrompter().line("Allow which? Numbers or names, comma-separated (Enter for none):", "")
			if answer == "" {
				return nil
			}
			var picked []string
			for _, f := range splitList(answer) {
				host := ""
				var n int
				if _, err := fmt.Sscanf(f, "%d", &n); err == nil && n >= 1 && n <= len(sites) {
					host = sites[n-1].Host
				} else {
					for _, s := range sites {
						if strings.EqualFold(s.Host, f) {
							host = s.Host
						}
					}
				}
				if host == "" {
					return fmt.Errorf("%q is not in the list", f)
				}
				picked = append(picked, host)
			}
			p.Network.AllowedDomains = editList(p.Network.AllowedDomains, picked, false)
			if err := store.Save(p); err != nil {
				return err
			}
			fmt.Printf("  Allowed %s.\n", strings.Join(picked, ", "))
			reloadAllowlist(p)
			return nil
		},
	}
	cmd.Flags().DurationVar(&since, "since", 24*time.Hour, "how far back to look (0 for the whole log)")
	return cmd
}

// blockedSites reads the audit log for allowlist refusals, most recent first.
func blockedSites(profileName string, since time.Duration) ([]blockedSite, error) {
	path, err := config.AuditPath(profileName)
	if err != nil {
		return nil, err
	}
	records, err := monitor.ReadAudit(path, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	byHost := map[string]*blockedSite{}
	for _, r := range records {
		if r.Kind != "egress_denied" || len(r.Data) == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, r.TS)
		if err != nil || (since > 0 && time.Since(t) > since) {
			continue
		}
		var ev struct {
			Host   string `json:"host"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(r.Data, &ev) != nil || ev.Host == "" {
			continue
		}
		host := strings.ToLower(ev.Host)
		s := byHost[host]
		if s == nil {
			s = &blockedSite{Host: host}
			byHost[host] = s
		}
		s.Count++
		if t.After(s.Last) {
			s.Last = t
		}
	}
	out := make([]blockedSite, 0, len(byHost))
	for _, s := range byHost {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out, nil
}
