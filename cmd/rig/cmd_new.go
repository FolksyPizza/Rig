package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
)

func newCmd() *cobra.Command {
	var (
		from, level, isolation, network, ai string
		permissions, cpu, memory, disk      string
		monitorMode, timeout                string
		pids                                int64
		agentIDs, allow, presets, mounts    []string
		ports, tools, volumes               []string
		ephemeral, persistent, run, force   bool
		sudo, guided, yes                   bool
	)
	cmd := &cobra.Command{
		Use:   "new [name]",
		Short: "Create a sandbox (guided in a terminal, or with flags)",
		Long: `Create a saved sandbox.

In a terminal, 'rig new' with no options walks you through it: the agent,
the security level, a project folder to share, what the agent may do without
asking, CPU, memory and disk. Press Enter to accept each default.

With options it asks nothing (except which agent, if it cannot tell):

  rig new work --agent codex                        Codex at the standard level
  rig new work --agent claude-code --level strict   stricter
  rig new work --agent gemini-cli --mount .:/home/sandbox/project:rw
  rig new work --agent opencode --cpu 4 --memory 8g --disk 20g
  rig new work --agent claude-code --permissions full   no approval prompts inside
  rig new safe --from lockdown --agent codex        start from a template ('rig templates')
  rig new local --from local-model                  a local model, no internet at all

Without --agent, Rig uses the agent whose API key it finds (ANTHROPIC_API_KEY
for Claude Code, OPENAI_API_KEY for Codex, GEMINI_API_KEY for Gemini CLI).
Mounts are read-only unless you add :rw. Change anything later with
'rig set', 'rig allow', 'rig add' or 'rig edit'.`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := config.NewStore()
			if err != nil {
				return err
			}
			interactive := interactiveTerminal() && !yes
			// No options at all in a terminal: the guided setup.
			if interactive && (guided || cmd.Flags().NFlag() == 0) {
				name := ""
				if len(args) == 1 {
					name = args[0]
				}
				return guidedNew(store, name, force)
			}
			if len(args) == 0 {
				return fmt.Errorf("name the sandbox: rig new <name> (or run 'rig new' in a terminal for the guided setup)")
			}
			name := args[0]
			if store.Exists(name) && !force {
				return fmt.Errorf("sandbox %q already exists; pass --force to replace it", name)
			}
			if from == "" {
				from = "standard"
			}
			tmpl, ok := config.GetTemplate(from)
			if !ok {
				return fmt.Errorf("template %q not found (see 'rig templates')", from)
			}
			p := tmpl.Profile
			p.Name = name
			p.Metadata.CreatedAt = time.Now().UTC()

			switch {
			case len(agentIDs) > 0:
				if p.Agents, err = agentConfigs(agentIDs); err != nil {
					return err
				}
			case !tmpl.NeedsAgent():
				p.Agents = fillAgentEnv(p.Agents)
			default:
				ids, err := pickAgents(interactive)
				if err != nil {
					return err
				}
				if p.Agents, err = agentConfigs(ids); err != nil {
					return err
				}
			}

			if level != "" {
				if err := applyLevel(&p, level, sudo, network != ""); err != nil {
					return err
				}
				if level == config.LevelLockdown && persistent {
					p.Persistence = "persistent" // validation explains why not
				}
			}
			flagSettings := []struct{ key, value string }{
				{"isolation", isolation}, {"network", network}, {"permissions", permissions},
				{"cpu", cpu}, {"memory", memory}, {"disk", disk}, {"monitor", monitorMode}, {"timeout", timeout},
			}
			if pids > 0 {
				flagSettings = append(flagSettings, struct{ key, value string }{"pids", fmt.Sprint(pids)})
			}
			for _, fs := range flagSettings {
				if fs.value == "" {
					continue
				}
				s, _ := findSetting(fs.key)
				if err := s.apply(&p, fs.value); err != nil {
					return err
				}
			}
			if sudo {
				p.Security.Sudo = true
			}
			p.Tools = editList(p.Tools, tools, false)
			p.Network.AllowedDomains = append(p.Network.AllowedDomains, allow...)
			p.Network.Presets = append(p.Network.Presets, presets...)
			for _, m := range mounts {
				mc, err := parseMount(m)
				if err != nil {
					return err
				}
				p.Mounts = append(p.Mounts, mc)
			}
			for _, v := range volumes {
				vm, err := parseVolume(v)
				if err != nil {
					return err
				}
				p.Storage.Volumes = append(p.Storage.Volumes, vm)
			}
			for _, s := range ports {
				hp, err := parsePort(s)
				if err != nil {
					return err
				}
				p.Host.Ports = append(p.Host.Ports, hp)
			}
			if ai != "" {
				provider, model, _ := strings.Cut(ai, ":")
				p.Monitor.AI = config.AIConfig{Provider: provider, Model: model}
			}
			switch {
			case ephemeral && persistent:
				return fmt.Errorf("choose either --ephemeral or --persistent")
			case ephemeral:
				p.Persistence = "ephemeral"
			case persistent:
				p.Persistence = "persistent"
			}
			if err := store.Save(&p); err != nil {
				return err
			}
			created(&p)
			if run {
				return launch(&p, container.RunOptions{})
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&agentIDs, "agent", nil, "agent to install, repeatable (see 'rig agents'; id@version pins one)")
	f.StringVar(&level, "level", "", "security level: open, standard, strict or lockdown")
	f.StringVar(&from, "from", "", "start from a template (default \"standard\"; see 'rig templates')")
	f.StringSliceVar(&mounts, "mount", nil, "share a folder: SRC:DST[:rw] (read-only unless :rw)")
	f.StringVar(&permissions, "permissions", "", "what agents may do without asking: ask (default), edit or full")
	f.StringVar(&cpu, "cpu", "", "CPU cores (default 2)")
	f.StringVar(&memory, "memory", "", "memory, e.g. 8g (default 4g)")
	f.StringVar(&disk, "disk", "", "disk space, e.g. 20g (default 10g)")
	f.Int64Var(&pids, "pids", 0, "process limit (default 512)")
	f.StringSliceVar(&allow, "allow", nil, "allow a domain, repeatable (\"*.example.com\" includes subdomains)")
	f.StringSliceVar(&presets, "preset", nil, "allow a group of domains, repeatable (see 'rig presets')")
	f.StringSliceVar(&tools, "tool", nil, "install an apt package, repeatable (more with 'rig add')")
	f.StringSliceVar(&ports, "port", nil, "let the sandbox reach a service on this computer: NAME:PORT[:HOSTPORT]")
	f.StringSliceVar(&volumes, "volume", nil, "a named volume that keeps its files: NAME:/path")
	f.BoolVar(&sudo, "sudo", false, "give the agent passwordless sudo (open and standard levels only)")
	f.StringVar(&network, "network", "", "allowlist, none, or unrestricted (open level only)")
	f.StringVar(&isolation, "isolation", "", "auto, container, gvisor or vm")
	f.StringVar(&monitorMode, "monitor", "", "off, observe or enforce")
	f.StringVar(&ai, "ai-monitor", "", "add an AI monitor: anthropic, openai:MODEL or ollama:MODEL")
	f.StringVar(&timeout, "timeout", "", "stop the sandbox automatically after this long, e.g. 2h")
	f.BoolVar(&ephemeral, "ephemeral", false, "start fresh every time (remove the container when you leave)")
	f.BoolVar(&persistent, "persistent", false, "keep files and installed tools between runs")
	f.BoolVar(&run, "run", false, "start the sandbox right away")
	f.BoolVar(&force, "force", false, "replace an existing sandbox with the same name")
	f.BoolVarP(&guided, "interactive", "i", false, "ask every question, even with other options given")
	f.BoolVarP(&yes, "yes", "y", false, "ask nothing; use defaults for anything not given")
	return cmd
}

// created reports a new sandbox and what to do next.
func created(p *config.Profile) {
	eff := p.Resolve()
	fmt.Printf("  Created %s: %s, level %s, %s, %s CPU / %s memory.\n", paint("1", p.Name), agentNames(p), eff.Level,
		describeNetwork(eff), strings.TrimSuffix(fmt.Sprintf("%.1f", p.Resources.CPU), ".0"), formatMegabytes(p.Resources.Memory))
	fmt.Printf("  Next: 'rig run %s' to start it ('-d' for the background), 'rig check %s' to see what it can reach.\n", p.Name, p.Name)
}

// pickAgents chooses agents when none were named: from the API keys found,
// or by asking.
func pickAgents(interactive bool) ([]string, error) {
	found := agents.FromEnv(os.Getenv)
	if interactive {
		def := ""
		if len(found) > 0 {
			def = found[0]
		}
		return newPrompter().chooseMany("Which agent should the sandbox have?", agentChoices(found), def, true), nil
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("choose an agent with --agent (see 'rig agents'), for example: --agent claude-code, --agent codex or --agent gemini-cli")
	}
	spec, _ := agents.ByID(found[0])
	fmt.Printf("  Using %s (its API key is set). Pick another with --agent.\n", spec.DisplayName)
	return found[:1], nil
}

func agentChoices(found []string) []choice {
	has := map[string]bool{}
	for _, id := range found {
		has[id] = true
	}
	var out []choice
	for _, a := range agents.All() {
		note := ""
		if has[a.ID] {
			note = "API key found"
		}
		out = append(out, choice{key: a.ID, label: a.DisplayName, note: note})
	}
	return out
}

// fillAgentEnv gives agents named by a template without settings the API key
// references they usually need.
func fillAgentEnv(list []config.AgentConfig) []config.AgentConfig {
	out := make([]config.AgentConfig, len(list))
	for i, a := range list {
		out[i] = a
		if len(a.Env) == 0 {
			if filled, err := agentConfigs([]string{a.ID}); err == nil {
				out[i].Env = filled[0].Env
			}
		}
	}
	return out
}

func parseVolume(s string) (config.VolumeMount, error) {
	name, target, ok := strings.Cut(s, ":")
	if !ok || name == "" || target == "" {
		return config.VolumeMount{}, fmt.Errorf("volume %q: use NAME:/path", s)
	}
	return config.VolumeMount{Name: name, Target: target}, nil
}
