package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/security"
)

// guidedNew creates a sandbox by asking a few questions. Every question has a
// default, so pressing Enter all the way through gives the recommended setup.
func guidedNew(store *config.Store, name string, force bool) error {
	q := newPrompter()
	fmt.Printf("\n  %s  %s\n", paint("1;35", "New sandbox"), paint("2", "(press Enter to accept a default; Ctrl-C to cancel)"))

	for {
		if name == "" {
			name = q.line("Name:", nextFreeName(store, "work"))
		}
		if err := security.ValidateProfileName(name); err != nil {
			fmt.Printf("  %v\n", err)
			name = ""
			continue
		}
		if store.Exists(name) && !force {
			if !q.yes(fmt.Sprintf("A sandbox called %s exists. Replace it?", name), false) {
				name = ""
				continue
			}
		}
		break
	}

	found := agents.FromEnv(os.Getenv)
	def := ""
	if len(found) > 0 {
		def = found[0]
	}
	ids := q.chooseMany("Which agent should the sandbox have?", agentChoices(found), def, true)

	levels := []choice{
		{config.LevelOpen, "any website, sudo allowed", "trusted work only"},
		{config.LevelStandard, "allowlisted sites only, exfiltration sites blocked", "recommended"},
		{config.LevelStrict, "read-only system, HTTPS only, no sudo", ""},
		{config.LevelLockdown, "model API only, gVisor or VM required, fresh every run", ""},
	}
	level := q.choose("Security level?", levels, config.LevelStandard)

	t, _ := config.GetTemplate(map[string]string{config.LevelOpen: "dev", config.LevelStandard: "standard",
		config.LevelStrict: "strict", config.LevelLockdown: "lockdown"}[level])
	p := t.Profile
	p.Name = name
	p.Metadata.CreatedAt = time.Now().UTC()
	p.Security.AgentPermissions = ""
	ac, err := agentConfigs(ids)
	if err != nil {
		return err
	}
	p.Agents = ac

	// A project folder.
	fmt.Println()
	if dir, ok := shareableDir(); ok {
		if q.yes(fmt.Sprintf("Share this folder (%s) with the sandbox?", dir), true) {
			target := "/home/sandbox/" + safeTargetName(filepath.Base(dir))
			readOnly := level == config.LevelLockdown || !q.yes("Let the agent change files in it?", true)
			p.Mounts = append(p.Mounts, config.MountConfig{Source: dir, Target: target, ReadOnly: readOnly})
		}
	} else if path := q.line("A project folder to share (Enter for none):", ""); path != "" {
		if abs, err := filepath.Abs(expandHome(path)); err == nil {
			target := "/home/sandbox/" + safeTargetName(filepath.Base(abs))
			readOnly := level == config.LevelLockdown || !q.yes("Let the agent change files in it?", true)
			p.Mounts = append(p.Mounts, config.MountConfig{Source: abs, Target: target, ReadOnly: readOnly})
		}
	}

	// What the agents may do without asking.
	perms := []choice{
		{config.PermissionsAsk, "ask before acting (each agent's default)", ""},
		{config.PermissionsEdit, "edit files without asking, ask before commands", ""},
	}
	if level != config.LevelLockdown {
		perms = append(perms, choice{config.PermissionsFull, "no approval prompts; the sandbox is the boundary", ""})
	}
	defPerm := config.PermissionsAsk
	if level == config.LevelOpen {
		defPerm = config.PermissionsFull
	}
	p.Security.AgentPermissions = q.choose("What may the agents do without asking you?", perms, defPerm)
	for _, id := range ids {
		if spec, ok := agents.ByID(id); ok && p.Security.AgentPermissions != config.PermissionsAsk {
			fmt.Printf("    %s %s\n", spec.DisplayName, paint("2", spec.PermissionSupport(p.Security.AgentPermissions)))
		}
	}

	// Compute.
	fmt.Printf("\n  %s\n", paint("1", "Resources"))
	cpuNote := ""
	if n := runtime.NumCPU(); n > 0 {
		cpuNote = fmt.Sprintf(" (this computer has %d)", n)
	}
	askSetting(q, &p, "cpu", "CPU cores"+cpuNote+":")
	memNote := ""
	if mb := hostMemoryMB(); mb > 0 {
		memNote = " (this computer has " + formatMegabytes(roundGB(mb)) + ")"
	}
	askSetting(q, &p, "memory", "Memory"+memNote+":")
	askSetting(q, &p, "disk", "Disk space:")

	// Network.
	if p.Network.Mode == "allowlist" {
		fmt.Println()
		presets := "none"
		if len(p.Network.Presets) > 0 {
			presets = strings.Join(p.Network.Presets, ", ")
		}
		fmt.Printf("  The agent can reach its model API and: %s.\n", presets)
		if extra := q.line("Other sites to allow, comma-separated (Enter for none):", ""); extra != "" {
			p.Network.AllowedDomains = append(p.Network.AllowedDomains, splitList(strings.ToLower(extra))...)
		}
	}

	// Lifetime and sudo.
	if level == config.LevelOpen || level == config.LevelStandard {
		p.Security.Sudo = q.yes("Give the agent passwordless sudo (to install software)?", level == config.LevelOpen)
	}
	if level != config.LevelLockdown {
		if q.yes("Keep files and installed tools between runs?", true) {
			p.Persistence = "persistent"
		} else {
			p.Persistence = "ephemeral"
		}
	}

	if err := store.Save(&p); err != nil {
		return err
	}
	fmt.Println()
	created(&p)
	if q.yes("Start it now?", true) {
		return launch(&p, container.RunOptions{})
	}
	return nil
}

// askSetting asks for one setting until it is valid.
func askSetting(q *prompter, p *config.Profile, key, question string) {
	s, _ := findSetting(key)
	for {
		v := q.line(question, s.show(p))
		trial := *p
		if err := s.apply(&trial, v); err != nil {
			fmt.Printf("  %v\n", err)
			continue
		}
		trial.Name = p.Name
		if err := trial.Validate(); err != nil && strings.Contains(err.Error(), key) {
			fmt.Printf("  %v\n", err)
			continue
		}
		*p = trial
		return
	}
}

// shareableDir is the current folder, when Rig would agree to mount it.
func shareableDir() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	home, _ := os.UserHomeDir()
	if dir == "/" || dir == home {
		return "", false
	}
	if err := security.ValidateMountSource(dir); err != nil {
		return "", false
	}
	return dir, true
}

func safeTargetName(base string) string {
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if s := strings.Trim(b.String(), ".-"); s != "" {
		return s
	}
	return "project"
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func nextFreeName(store *config.Store, base string) string {
	if !store.Exists(base) {
		return base
	}
	for i := 2; ; i++ {
		if n := base + strconv.Itoa(i); !store.Exists(n) {
			return n
		}
	}
}

// hostMemoryMB is this computer's memory, or 0 if unknown.
func hostMemoryMB() int64 {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0
		}
		b, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		return b >> 20
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(fields[1], 10, 64)
			return kb >> 10
		}
	}
	return 0
}

func roundGB(mb int64) int64 { return (mb + 512) / 1024 * 1024 }
