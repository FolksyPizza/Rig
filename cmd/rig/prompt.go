package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/monitor"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// interactiveTerminal reports whether Rig can ask questions: both input and
// output are a terminal.
func interactiveTerminal() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

// prompter asks questions on the terminal. Every question has a default, so
// pressing Enter through all of them gives a sensible result.
type prompter struct {
	in *bufio.Reader
}

func newPrompter() *prompter { return &prompter{in: bufio.NewReader(os.Stdin)} }

// line asks a free-form question.
func (p *prompter) line(question, def string) string {
	if def != "" {
		fmt.Printf("  %s %s ", question, paint("2", "["+def+"]"))
	} else {
		fmt.Printf("  %s ", question)
	}
	answer, err := p.in.ReadString('\n')
	answer = strings.TrimSpace(answer)
	if err != nil && answer == "" {
		fmt.Println()
		return def
	}
	if answer == "" {
		return def
	}
	return answer
}

// yes asks a yes/no question.
func (p *prompter) yes(question string, def bool) bool {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Printf("  %s %s ", question, paint("2", "["+hint+"]"))
		answer, err := p.in.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		switch {
		case answer == "" && err != nil:
			fmt.Println()
			return def
		case answer == "":
			return def
		case answer == "y" || answer == "yes":
			return true
		case answer == "n" || answer == "no":
			return false
		}
	}
}

type choice struct {
	key, label, note string
}

// choose asks for one option by number or key. def is the default key.
func (p *prompter) choose(question string, options []choice, def string) string {
	keys := p.chooseMany(question, options, def, false)
	return keys[0]
}

// chooseMany asks for one or more options, separated by commas or spaces.
func (p *prompter) chooseMany(question string, options []choice, def string, many bool) []string {
	fmt.Printf("\n  %s\n", paint("1", question))
	defNum := ""
	for i, o := range options {
		marker := " "
		if o.key == def {
			marker = paint("1;35", ">")
			defNum = strconv.Itoa(i + 1)
		}
		note := ""
		if o.note != "" {
			note = "  " + paint("2", o.note)
		}
		fmt.Printf("  %s %2d) %-14s %s%s\n", marker, i+1, o.key, o.label, note)
	}
	prompt := "Choose"
	if many {
		prompt = "Choose one or more (e.g. 1,3)"
	}
	for {
		answer := p.line(prompt, defNum)
		var picked []string
		ok := answer != ""
		for _, f := range strings.FieldsFunc(answer, func(r rune) bool { return r == ',' || r == ' ' }) {
			key := ""
			if n, err := strconv.Atoi(f); err == nil && n >= 1 && n <= len(options) {
				key = options[n-1].key
			} else {
				for _, o := range options {
					if strings.EqualFold(o.key, f) {
						key = o.key
					}
				}
			}
			if key == "" {
				ok = false
				break
			}
			picked = append(picked, key)
		}
		if ok && (many || len(picked) == 1) {
			return picked
		}
		fmt.Println("  Please pick from the list.")
	}
}

// afterStop is shown when Rig has stopped an interactive sandbox. It lets you
// look at what happened and start again without retyping anything. It
// returns true to restart.
func afterStop(profile *config.Profile, cause *watchdog.Observation) bool {
	p := newPrompter()
	host, canAllow := deniedHost(*cause)
	for {
		opts := "[r] restart   [d] show what happened   [Enter] quit"
		if canAllow {
			opts = "[r] restart   [a] allow " + safeText(host) + " and restart   [d] details   [Enter] quit"
		}
		fmt.Printf("\n  %s ", opts)
		answer, err := p.in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "r":
			return true
		case "a":
			if !canAllow {
				continue
			}
			store, err := config.NewStore()
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %v\n", err)
				return false
			}
			profile.Network.AllowedDomains = editList(profile.Network.AllowedDomains, []string{host}, false)
			if err := store.Save(profile); err != nil {
				fmt.Fprintf(os.Stderr, "  Could not allow %s: %v\n", safeText(host), err)
				return false
			}
			fmt.Printf("  Allowed %s.\n", safeText(host))
			return true
		case "d":
			showFlagged(profile.Name, 10)
		default:
			if err != nil {
				fmt.Println()
			}
			return false
		}
	}
}

// showFlagged prints the most recent events Rig flagged or acted on.
func showFlagged(profileName string, n int) {
	path, err := config.AuditPath(profileName)
	if err != nil {
		return
	}
	records, err := monitor.ReadAudit(path, 0)
	if err != nil {
		fmt.Printf("  No audit log yet.\n")
		return
	}
	var kept []monitor.Record
	for _, r := range records {
		if r.Action != "allow" {
			kept = append(kept, r)
		}
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	fmt.Println()
	for _, r := range kept {
		printRecord(r)
	}
}
