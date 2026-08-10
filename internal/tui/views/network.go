package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/security"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type networkFocus int

const (
	focusMode networkFocus = iota
	focusDomains
	focusInput
)

type NetworkModel struct {
	modes            []string
	modeDescriptions []string
	cursor           int
	domains          []string
	domainCursor     int
	inputBuffer      string
	focus            networkFocus
	agentIDs         []string
	errMsg           string
	width            int
	height           int
}

type NetworkSelectedMsg struct {
	Mode    string
	Domains []string
}

func NewNetwork(agentIDs []string) NetworkModel {
	var domains []string
	seen := make(map[string]bool)
	for _, id := range agentIDs {
		if spec, ok := agents.ByID(id); ok {
			for _, d := range spec.RequiredDomains {
				if !seen[d] {
					seen[d] = true
					domains = append(domains, d)
				}
			}
		}
	}

	return NetworkModel{
		modes:            []string{"unrestricted", "allowlist", "none"},
		modeDescriptions: []string{"Full internet access", "Only specified domains", "Fully offline"},
		domains:          domains,
		agentIDs:         agentIDs,
	}
}

func (m NetworkModel) Init() tea.Cmd {
	return nil
}

func (m NetworkModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.focus == focusInput {
			return m.handleInput(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.focus == focusMode && m.cursor > 0 {
				m.cursor--
			}
			if m.focus == focusDomains && m.domainCursor > 0 {
				m.domainCursor--
			}
		case "down", "j":
			if m.focus == focusMode && m.cursor < len(m.modes)-1 {
				m.cursor++
			}
			if m.focus == focusDomains && m.domainCursor < len(m.domains) {
				m.domainCursor++
			}
		case "tab":
			if m.modes[m.cursor] == "allowlist" {
				if m.focus == focusMode {
					m.focus = focusDomains
				} else {
					m.focus = focusMode
				}
			}
		case " ":
			if m.focus == focusMode {
				// mode selected via cursor position
			}
		case "a":
			if m.focus == focusDomains {
				m.focus = focusInput
				m.inputBuffer = ""
			}
		case "d", "backspace":
			if m.focus == focusDomains && m.domainCursor < len(m.domains) {
				m.domains = append(m.domains[:m.domainCursor], m.domains[m.domainCursor+1:]...)
				if m.domainCursor >= len(m.domains) && m.domainCursor > 0 {
					m.domainCursor--
				}
			}
		case "enter":
			mode := m.modes[m.cursor]
			return m, func() tea.Msg {
				return NetworkSelectedMsg{Mode: mode, Domains: m.domains}
			}
		case "esc":
			if m.focus == focusDomains {
				m.focus = focusMode
			} else {
				return m, func() tea.Msg { return BackMsg{} }
			}
		}
	}
	return m, nil
}

func (m NetworkModel) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		domain := strings.TrimSpace(m.inputBuffer)
		if domain == "" {
			m.focus = focusDomains
			m.inputBuffer = ""
			m.errMsg = ""
			return m, nil
		}
		// Reject bad entries here rather than at save time: these strings end
		// up in a proxy config file, and a clear message at the point of entry
		// beats a cryptic failure three screens later.
		if err := security.ValidateDomain(domain); err != nil {
			m.errMsg = err.Error()
			return m, nil
		}
		m.domains = append(m.domains, domain)
		m.focus = focusDomains
		m.domainCursor = len(m.domains) - 1
		m.inputBuffer = ""
		m.errMsg = ""
	case "esc":
		m.focus = focusDomains
		m.inputBuffer = ""
		m.errMsg = ""
	case "backspace":
		if len(m.inputBuffer) > 0 {
			m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.inputBuffer += msg.String()
		}
	}
	return m, nil
}

func (m NetworkModel) View() string {
	title := styles.StepStyle.Render("[3/8]") + " " + styles.TitleStyle.Render("Network Access")

	var modes string
	for i, mode := range m.modes {
		radio := "○"
		style := styles.UnselectedStyle
		if i == m.cursor {
			radio = styles.SelectedStyle.Render("●")
			style = styles.SelectedStyle
		}
		desc := styles.DimStyle.Render(m.modeDescriptions[i])
		indicator := "  "
		if m.focus == focusMode && i == m.cursor {
			indicator = styles.SelectedStyle.Render("▸ ")
		}
		modes += fmt.Sprintf("%s%s %s  %s\n", indicator, radio, style.Render(mode), desc)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, title, "", modes)

	if m.modes[m.cursor] == "allowlist" {
		domainTitle := "\n" + styles.HighlightStyle.Render("Allowed Domains:")
		var domainList string
		for i, d := range m.domains {
			indicator := "  "
			style := styles.UnselectedStyle
			if m.focus == focusDomains && i == m.domainCursor {
				indicator = styles.SelectedStyle.Render("▸ ")
				style = styles.SelectedStyle
			}
			domainList += fmt.Sprintf("  %s%s\n", indicator, style.Render(d))
		}

		addLine := "    " + styles.DimStyle.Render("+ press 'a' to add domain")
		if m.focus == focusDomains && m.domainCursor == len(m.domains) {
			addLine = "  " + styles.SelectedStyle.Render("▸ ") + styles.DimStyle.Render("+ press 'a' to add domain")
		}

		if m.focus == focusInput {
			addLine = "  " + styles.SelectedStyle.Render("▸ ") + m.inputBuffer + styles.SelectedStyle.Render("█")
		}

		content = lipgloss.JoinVertical(lipgloss.Left, content, domainTitle, domainList, addLine)
	}

	if m.errMsg != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content,
			"  "+styles.ErrorMsgStyle.Render(m.errMsg))
	}

	help := "\n" + styles.HelpStyle.Render("↑/↓ navigate • tab switch • a add • d delete • enter continue • esc back")

	content = lipgloss.JoinVertical(lipgloss.Left, content, help)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}
