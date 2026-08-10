package views

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/tui/styles"
)

const logo = `
 ██████╗ ██╗ ██████╗
 ██╔══██╗██║██╔════╝
 ██████╔╝██║██║  ███╗
 ██╔══██╗██║██║   ██║
 ██║  ██║██║╚██████╔╝
 ╚═╝  ╚═╝╚═╝ ╚═════╝`

type WelcomeModel struct {
	cursor   int
	choices  []string
	profiles []string
	// picking is true while the profile list is shown, after the user chose
	// "Load profile".
	picking    bool
	profCursor int
	width      int
	height     int
}

type WelcomeChoice int

const (
	WelcomeNew WelcomeChoice = iota
	WelcomeLoad
)

type WelcomeChosenMsg struct {
	Choice  WelcomeChoice
	Profile string
}

func NewWelcome(profiles []string) WelcomeModel {
	choices := []string{"Create new sandbox"}
	if len(profiles) > 0 {
		choices = append(choices, "Load profile")
	}
	choices = append(choices, "Quit")
	return WelcomeModel{
		choices:  choices,
		profiles: profiles,
	}
}

func (m WelcomeModel) Init() tea.Cmd {
	return nil
}

func (m WelcomeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.picking {
			return m.updatePicker(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}
		case "enter":
			switch m.choices[m.cursor] {
			case "Quit":
				return m, tea.Quit
			case "Create new sandbox":
				return m, func() tea.Msg { return WelcomeChosenMsg{Choice: WelcomeNew} }
			case "Load profile":
				// Show the profile list rather than reporting a choice: the
				// caller needs to know *which* profile to load.
				m.picking = true
				m.profCursor = 0
			}
		}
	}
	return m, nil
}

func (m WelcomeModel) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.profCursor > 0 {
			m.profCursor--
		}
	case "down", "j":
		if m.profCursor < len(m.profiles)-1 {
			m.profCursor++
		}
	case "esc":
		m.picking = false
	case "enter":
		if len(m.profiles) == 0 {
			m.picking = false
			return m, nil
		}
		name := m.profiles[m.profCursor]
		return m, func() tea.Msg {
			return WelcomeChosenMsg{Choice: WelcomeLoad, Profile: name}
		}
	}
	return m, nil
}

func (m WelcomeModel) View() string {
	logoRendered := styles.LogoStyle.Render(logo)
	tagline := styles.SubtitleStyle.Render("Containerized AI Agent Sandbox")

	var choices string
	if m.picking {
		choices = styles.HighlightStyle.Render("Select a profile") + "\n\n"
		for i, p := range m.profiles {
			cursor := "  "
			style := styles.UnselectedStyle
			if i == m.profCursor {
				cursor = styles.SelectedStyle.Render("▸ ")
				style = styles.SelectedStyle
			}
			choices += fmt.Sprintf("%s%s\n", cursor, style.Render(p))
		}
	} else {
		for i, c := range m.choices {
			cursor := "  "
			style := styles.UnselectedStyle
			if i == m.cursor {
				cursor = styles.SelectedStyle.Render("▸ ")
				style = styles.SelectedStyle
			}
			choices += fmt.Sprintf("%s%s\n", cursor, style.Render(c))
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Center,
		logoRendered,
		"",
		tagline,
		"",
		choices,
	)

	help := styles.HelpStyle.Render("↑/↓ navigate • enter select • q quit")
	if m.picking {
		help = styles.HelpStyle.Render("↑/↓ navigate • enter load • esc back • q quit")
	}

	panel := styles.PanelStyle.Width(50).Render(
		lipgloss.JoinVertical(lipgloss.Center, content, "", help),
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}
