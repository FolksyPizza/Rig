package views

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type AgentSelectModel struct {
	agents   []agents.AgentSpec
	selected map[string]bool
	cursor   int
	width    int
	height   int
}

type AgentsSelectedMsg struct {
	AgentIDs []string
}

func NewAgentSelect() AgentSelectModel {
	return AgentSelectModel{
		agents:   agents.All(),
		selected: make(map[string]bool),
	}
}

func (m AgentSelectModel) Init() tea.Cmd {
	return nil
}

func (m AgentSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			if m.cursor < len(m.agents)-1 {
				m.cursor++
			}
		case " ":
			id := m.agents[m.cursor].ID
			m.selected[id] = !m.selected[id]
			if !m.selected[id] {
				delete(m.selected, id)
			}
		case "enter":
			if len(m.selected) == 0 {
				return m, nil
			}
			// Iterate the registry, not the selection map: map order is
			// random, and an unstable agent order changes the generated
			// Dockerfile and needlessly busts the build cache.
			var ids []string
			for _, a := range m.agents {
				if m.selected[a.ID] {
					ids = append(ids, a.ID)
				}
			}
			return m, func() tea.Msg { return AgentsSelectedMsg{AgentIDs: ids} }
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		}
	}
	return m, nil
}

func (m AgentSelectModel) View() string {
	title := styles.StepStyle.Render("[1/8]") + " " + styles.TitleStyle.Render("Select AI Agents")

	var items string
	for i, a := range m.agents {
		cursor := "  "
		check := "○"
		style := styles.UnselectedStyle
		descStyle := styles.DimStyle

		if m.selected[a.ID] {
			check = styles.CheckedStyle.Render("●")
		}
		if i == m.cursor {
			cursor = styles.SelectedStyle.Render("▸ ")
			style = styles.SelectedStyle
			descStyle = lipgloss.NewStyle().Foreground(styles.TextDim)
		}

		name := style.Render(fmt.Sprintf("%-16s", a.DisplayName))
		desc := descStyle.Render(a.Description)
		items += fmt.Sprintf("%s%s %s %s\n", cursor, check, name, desc)
	}

	count := fmt.Sprintf("\n%s selected", styles.HighlightStyle.Render(fmt.Sprintf("%d", len(m.selected))))
	help := styles.HelpStyle.Render("↑/↓ navigate • space toggle • enter continue • esc back")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "", items, count, "", help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}
