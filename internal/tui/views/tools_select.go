package views

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type flatTool struct {
	tool     config.Tool
	category string
}

type ToolsSelectModel struct {
	items    []flatTool
	selected map[string]bool
	cursor   int
	width    int
	height   int
}

type ToolsSelectedMsg struct {
	Tools []string
}

func NewToolsSelect() ToolsSelectModel {
	var items []flatTool
	selected := make(map[string]bool)

	for _, cat := range config.DefaultTools {
		for _, t := range cat.Tools {
			items = append(items, flatTool{tool: t, category: cat.Name})
			if t.AlwaysIncluded {
				selected[t.ID] = true
			}
		}
	}

	return ToolsSelectModel{
		items:    items,
		selected: selected,
	}
}

func (m ToolsSelectModel) Init() tea.Cmd {
	return nil
}

func (m ToolsSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case " ":
			item := m.items[m.cursor]
			if item.tool.AlwaysIncluded {
				return m, nil
			}
			id := item.tool.ID
			m.selected[id] = !m.selected[id]
			if !m.selected[id] {
				delete(m.selected, id)
			}
		case "enter":
			// Same reason as agent selection: keep a stable, non-random order.
			var tools []string
			for _, item := range m.items {
				if m.selected[item.tool.ID] {
					tools = append(tools, item.tool.ID)
				}
			}
			return m, func() tea.Msg { return ToolsSelectedMsg{Tools: tools} }
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		}
	}
	return m, nil
}

func (m ToolsSelectModel) View() string {
	title := styles.StepStyle.Render("[2/8]") + " " + styles.TitleStyle.Render("Select Tools")

	var items string
	lastCategory := ""
	for i, ft := range m.items {
		if ft.category != lastCategory {
			if lastCategory != "" {
				items += "\n"
			}
			items += styles.HighlightStyle.Render(ft.category) + "\n"
			lastCategory = ft.category
		}

		cursor := "  "
		check := "○"
		style := styles.UnselectedStyle

		if m.selected[ft.tool.ID] {
			check = styles.CheckedStyle.Render("●")
		}
		if ft.tool.AlwaysIncluded {
			check = styles.DimStyle.Render("◉")
		}
		if i == m.cursor {
			cursor = styles.SelectedStyle.Render("▸ ")
			style = styles.SelectedStyle
		}

		lock := ""
		if ft.tool.AlwaysIncluded {
			lock = styles.DimStyle.Render(" (required)")
		}

		items += fmt.Sprintf("%s%s %s%s\n", cursor, check, style.Render(ft.tool.Name), lock)
	}

	help := styles.HelpStyle.Render("↑/↓ navigate • space toggle • enter continue • esc back")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "", items, "", help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(55).Render(content))
}
