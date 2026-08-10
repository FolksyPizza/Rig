package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/security"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type storageFocus int

const (
	storageFocusSize storageFocus = iota
	storageFocusVolumes
	storageFocusInput
)

type StorageModel struct {
	sizeGB      int
	maxGB       int
	volumes     []config.VolumeMount
	volCursor   int
	focus       storageFocus
	inputStep   int
	inputBuffer string
	inputName   string
	inputTarget string
	errMsg      string
	width       int
	height      int
}

type StorageSelectedMsg struct {
	Size    string
	Volumes []config.VolumeMount
}

func NewStorage() StorageModel {
	return StorageModel{
		sizeGB: 10,
		maxGB:  100,
		volumes: []config.VolumeMount{
			{Name: "workspace", Target: "/home/sandbox/workspace"},
		},
	}
}

func (m StorageModel) Init() tea.Cmd {
	return nil
}

func (m StorageModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.focus == storageFocusInput {
			return m.handleInput(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.focus == storageFocusVolumes && m.volCursor > 0 {
				m.volCursor--
			}
		case "down", "j":
			if m.focus == storageFocusVolumes && m.volCursor < len(m.volumes) {
				m.volCursor++
			}
		case "left", "h":
			if m.focus == storageFocusSize {
				m.sizeGB -= 5
				if m.sizeGB < 1 {
					m.sizeGB = 1
				}
			}
		case "right", "l":
			if m.focus == storageFocusSize {
				m.sizeGB += 5
				if m.sizeGB > m.maxGB {
					m.sizeGB = m.maxGB
				}
			}
		case "tab":
			if m.focus == storageFocusSize {
				m.focus = storageFocusVolumes
			} else {
				m.focus = storageFocusSize
			}
		case "a":
			if m.focus == storageFocusVolumes {
				m.focus = storageFocusInput
				m.inputStep = 0
				m.inputBuffer = ""
				m.inputName = ""
				m.inputTarget = ""
			}
		case "d", "backspace":
			if m.focus == storageFocusVolumes && m.volCursor < len(m.volumes) {
				m.volumes = append(m.volumes[:m.volCursor], m.volumes[m.volCursor+1:]...)
				if m.volCursor >= len(m.volumes) && m.volCursor > 0 {
					m.volCursor--
				}
			}
		case "enter":
			size := fmt.Sprintf("%dg", m.sizeGB)
			return m, func() tea.Msg {
				return StorageSelectedMsg{Size: size, Volumes: m.volumes}
			}
		case "esc":
			if m.focus == storageFocusVolumes {
				m.focus = storageFocusSize
			} else {
				return m, func() tea.Msg { return BackMsg{} }
			}
		}
	}
	return m, nil
}

func (m StorageModel) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		val := strings.TrimSpace(m.inputBuffer)
		if m.inputStep == 0 {
			if val == "" {
				val = "data"
			}
			// Validate as the value is entered; the same rules are enforced
			// again on save, but an inline message is far more usable.
			if err := security.ValidateVolumeName(val); err != nil {
				m.errMsg = err.Error()
				return m, nil
			}
			for _, v := range m.volumes {
				if v.Name == val {
					m.errMsg = "a volume named " + val + " already exists"
					return m, nil
				}
			}
			m.inputName = val
			m.inputStep = 1
			m.inputBuffer = "/home/sandbox/" + val
			m.errMsg = ""
		} else {
			if val == "" {
				val = "/home/sandbox/" + m.inputName
			}
			if err := security.ValidateMountTarget(val); err != nil {
				m.errMsg = err.Error()
				return m, nil
			}
			m.inputTarget = val
			m.volumes = append(m.volumes, config.VolumeMount{
				Name:   m.inputName,
				Target: m.inputTarget,
			})
			m.focus = storageFocusVolumes
			m.volCursor = len(m.volumes) - 1
			m.inputBuffer = ""
			m.errMsg = ""
		}
	case "esc":
		m.focus = storageFocusVolumes
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

func (m StorageModel) View() string {
	title := styles.StepStyle.Render("[6/8]") + " " + styles.TitleStyle.Render("Storage")

	sizeIndicator := "  "
	sizeStyle := styles.UnselectedStyle
	if m.focus == storageFocusSize {
		sizeIndicator = styles.SelectedStyle.Render("▸ ")
		sizeStyle = styles.SelectedStyle
	}
	sizeBar := renderBar(float64(m.sizeGB)/float64(m.maxGB), 30)
	sizeLine := fmt.Sprintf("%s%s  %s  %s",
		sizeIndicator,
		sizeStyle.Render("Container Size"),
		sizeBar,
		styles.DimStyle.Render(fmt.Sprintf("%d GB", m.sizeGB)),
	)

	volTitle := "\n" + styles.HighlightStyle.Render("Persistent Volumes:")
	var volList string
	for i, v := range m.volumes {
		indicator := "  "
		style := styles.UnselectedStyle
		if m.focus == storageFocusVolumes && i == m.volCursor {
			indicator = styles.SelectedStyle.Render("▸ ")
			style = styles.SelectedStyle
		}
		ro := ""
		if v.ReadOnly {
			ro = styles.DimStyle.Render(" (ro)")
		}
		volList += fmt.Sprintf("  %s%s → %s%s\n",
			indicator,
			style.Render(v.Name),
			styles.DimStyle.Render(v.Target),
			ro,
		)
	}

	addLine := "    " + styles.DimStyle.Render("+ press 'a' to add volume")
	if m.focus == storageFocusVolumes && m.volCursor == len(m.volumes) {
		addLine = "  " + styles.SelectedStyle.Render("▸ ") + styles.DimStyle.Render("+ press 'a' to add volume")
	}

	if m.focus == storageFocusInput {
		prompt := "Volume name: "
		if m.inputStep == 1 {
			prompt = "Mount path: "
		}
		addLine = "  " + styles.SelectedStyle.Render("▸ ") + styles.DimStyle.Render(prompt) + m.inputBuffer + styles.SelectedStyle.Render("█")
	}

	errLine := ""
	if m.errMsg != "" {
		errLine = "  " + styles.ErrorMsgStyle.Render(m.errMsg)
	}

	help := "\n" + styles.HelpStyle.Render("←/→ size • tab switch • a add vol • d delete • enter continue • esc back")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "", sizeLine, volTitle, volList, addLine, errLine, help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}
