package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type commandsFocus int

const (
	cmdFocusMode commandsFocus = iota
	cmdFocusList
	cmdFocusInput
)

type CommandsModel struct {
	modes       []string
	descs       []string
	cursor      int
	commands    []string
	cmdCursor   int
	inputBuffer string
	focus       commandsFocus
	width       int
	height      int
}

type CommandsSelectedMsg struct {
	Mode     string
	Commands []string
}

func NewCommands() CommandsModel {
	return CommandsModel{
		modes: []string{"unrestricted", "allowlist"},
		descs: []string{
			"All commands available",
			"Only specified commands allowed",
		},
		commands: []string{"ls", "cat", "echo", "grep", "find", "cd", "pwd", "mkdir", "cp", "mv", "rm"},
	}
}

func (m CommandsModel) Init() tea.Cmd {
	return nil
}

func (m CommandsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.focus == cmdFocusInput {
			return m.handleInput(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.focus == cmdFocusMode && m.cursor > 0 {
				m.cursor--
			}
			if m.focus == cmdFocusList && m.cmdCursor > 0 {
				m.cmdCursor--
			}
		case "down", "j":
			if m.focus == cmdFocusMode && m.cursor < len(m.modes)-1 {
				m.cursor++
			}
			if m.focus == cmdFocusList && m.cmdCursor < len(m.commands) {
				m.cmdCursor++
			}
		case "tab":
			if m.modes[m.cursor] == "allowlist" {
				if m.focus == cmdFocusMode {
					m.focus = cmdFocusList
				} else {
					m.focus = cmdFocusMode
				}
			}
		case "a":
			if m.focus == cmdFocusList {
				m.focus = cmdFocusInput
				m.inputBuffer = ""
			}
		case "d", "backspace":
			if m.focus == cmdFocusList && m.cmdCursor < len(m.commands) {
				m.commands = append(m.commands[:m.cmdCursor], m.commands[m.cmdCursor+1:]...)
				if m.cmdCursor >= len(m.commands) && m.cmdCursor > 0 {
					m.cmdCursor--
				}
			}
		case "enter":
			mode := m.modes[m.cursor]
			var cmds []string
			if mode == "allowlist" {
				cmds = m.commands
			}
			return m, func() tea.Msg { return CommandsSelectedMsg{Mode: mode, Commands: cmds} }
		case "esc":
			if m.focus == cmdFocusList {
				m.focus = cmdFocusMode
			} else {
				return m, func() tea.Msg { return BackMsg{} }
			}
		}
	}
	return m, nil
}

func (m CommandsModel) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		cmd := strings.TrimSpace(m.inputBuffer)
		if cmd != "" {
			m.commands = append(m.commands, cmd)
		}
		m.focus = cmdFocusList
		m.cmdCursor = len(m.commands) - 1
		m.inputBuffer = ""
	case "esc":
		m.focus = cmdFocusList
		m.inputBuffer = ""
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

func (m CommandsModel) View() string {
	title := styles.StepStyle.Render("[4/8]") + " " + styles.TitleStyle.Render("Command Access")

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
		items += fmt.Sprintf("%s%s %s  %s\n", indicator, radio, style.Render(mode), desc)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, title, "", items)

	if m.modes[m.cursor] == "allowlist" {
		cmdTitle := "\n" + styles.HighlightStyle.Render("Allowed Commands:")
		var cmdList string
		for i, c := range m.commands {
			indicator := "  "
			style := styles.UnselectedStyle
			if m.focus == cmdFocusList && i == m.cmdCursor {
				indicator = styles.SelectedStyle.Render("▸ ")
				style = styles.SelectedStyle
			}
			cmdList += fmt.Sprintf("  %s%s\n", indicator, style.Render(c))
		}

		addLine := "    " + styles.DimStyle.Render("+ press 'a' to add command")
		if m.focus == cmdFocusList && m.cmdCursor == len(m.commands) {
			addLine = "  " + styles.SelectedStyle.Render("▸ ") + styles.DimStyle.Render("+ press 'a' to add command")
		}

		if m.focus == cmdFocusInput {
			addLine = "  " + styles.SelectedStyle.Render("▸ ") + m.inputBuffer + styles.SelectedStyle.Render("█")
		}

		content = lipgloss.JoinVertical(lipgloss.Left, content, cmdTitle, cmdList, addLine)
	}

	help := "\n" + styles.HelpStyle.Render("↑/↓ navigate • tab switch • a add • d delete • enter continue • esc back")

	content = lipgloss.JoinVertical(lipgloss.Left, content, help)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}
