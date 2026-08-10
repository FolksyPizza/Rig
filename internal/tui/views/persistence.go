package views

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type PersistenceModel struct {
	modes  []string
	descs  []string
	cursor int
	width  int
	height int
}

type PersistenceSelectedMsg struct {
	Mode string
}

func NewPersistence() PersistenceModel {
	return PersistenceModel{
		modes: []string{"ephemeral", "persistent"},
		descs: []string{
			"Destroyed on exit — clean slate each session",
			"Kept after exit — re-enter with 'rig run'",
		},
	}
}

func (m PersistenceModel) Init() tea.Cmd {
	return nil
}

func (m PersistenceModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.modes)-1 {
				m.cursor++
			}
		case "enter":
			mode := m.modes[m.cursor]
			return m, func() tea.Msg { return PersistenceSelectedMsg{Mode: mode} }
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		}
	}
	return m, nil
}

func (m PersistenceModel) View() string {
	title := styles.StepStyle.Render("[7/8]") + " " + styles.TitleStyle.Render("Container Persistence")

	var items string
	for i, mode := range m.modes {
		radio := "○"
		style := styles.UnselectedStyle
		indicator := "  "
		if i == m.cursor {
			radio = styles.SelectedStyle.Render("●")
			style = styles.SelectedStyle
			indicator = styles.SelectedStyle.Render("▸ ")
		}
		desc := styles.DimStyle.Render(m.descs[i])
		items += fmt.Sprintf("%s%s %s\n     %s\n\n", indicator, radio, style.Render(mode), desc)
	}

	help := styles.HelpStyle.Render("↑/↓ navigate • enter continue • esc back")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "", items, help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(55).Render(content))
}
