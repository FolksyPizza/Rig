package views

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/container"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type BuildModel struct {
	profile *config.Profile
	logs    []string
	err     error
	done    bool
	width   int
	height  int
	// lines carries build output from the builder goroutine into the Bubble
	// Tea update loop, which is the only place the model may be mutated.
	lines chan string
}

type BuildLogMsg struct {
	Line string
}

type BuildDoneMsg struct{}

type BuildErrorMsg struct {
	Err error
}

type EnterSandboxMsg struct {
	Profile *config.Profile
}

func NewBuild(profile *config.Profile) BuildModel {
	return BuildModel{
		profile: profile,
		logs:    []string{"Starting build..."},
		lines:   make(chan string, 256),
	}
}

func (m BuildModel) Init() tea.Cmd {
	return tea.Batch(m.startBuild(), m.waitForLog())
}

func (m BuildModel) startBuild() tea.Cmd {
	profile := m.profile
	lines := m.lines
	return func() tea.Msg {
		builder, err := container.NewBuilder()
		if err != nil {
			return BuildErrorMsg{Err: err}
		}
		defer builder.Close()

		err = builder.Build(context.Background(), profile, func(event container.BuildEvent) {
			// Drop output rather than block the build if the UI falls behind.
			select {
			case lines <- event.Stream:
			default:
			}
		})
		if err != nil {
			return BuildErrorMsg{Err: err}
		}
		return BuildDoneMsg{}
	}
}

// waitForLog blocks on the next build line and delivers it as a message. It is
// re-issued after each line so output keeps flowing until the build finishes.
func (m BuildModel) waitForLog() tea.Cmd {
	lines := m.lines
	return func() tea.Msg {
		line, ok := <-lines
		if !ok {
			return nil
		}
		return BuildLogMsg{Line: line}
	}
}

func (m BuildModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case BuildLogMsg:
		// Long build lines are truncated: the log box has a fixed width, and
		// letting lipgloss wrap them would push the panel past its height.
		line := truncate(strings.TrimSpace(msg.Line), 51)
		if line != "" {
			m.logs = append(m.logs, line)
			if len(m.logs) > 13 {
				m.logs = m.logs[len(m.logs)-13:]
			}
		}
		return m, m.waitForLog()
	case BuildDoneMsg:
		m.done = true
		m.logs = append(m.logs, "")
		m.logs = append(m.logs, styles.SuccessMsgStyle.Render("✓ Build complete!"))
	case BuildErrorMsg:
		m.err = msg.Err
		m.logs = append(m.logs, styles.ErrorMsgStyle.Render(fmt.Sprintf("✗ Build failed: %v", msg.Err)))
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			if m.done {
				return m, func() tea.Msg {
					return EnterSandboxMsg{Profile: m.profile}
				}
			}
		case "esc":
			if m.err != nil || m.done {
				return m, func() tea.Msg { return BackMsg{} }
			}
		}
	}
	return m, nil
}

func (m BuildModel) View() string {
	title := styles.TitleStyle.Render("Building Sandbox")
	subtitle := styles.DimStyle.Render(fmt.Sprintf("Image: %s", m.profile.ImageTag()))

	logContent := strings.Join(m.logs, "\n")

	logBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.Border).
		Padding(0, 1).
		Width(55).
		Height(15).
		Render(logContent)

	var footer string
	if m.done {
		footer = "\n" + styles.SuccessMsgStyle.Render("Press enter to enter the sandbox")
	} else if m.err != nil {
		footer = "\n" + styles.ErrorMsgStyle.Render("Press esc to go back")
	} else {
		footer = "\n" + styles.DimStyle.Render("Building...")
	}

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, subtitle, "", logBox, footer,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}
