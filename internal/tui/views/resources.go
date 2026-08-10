package views

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type resourceField int

const (
	fieldCPU resourceField = iota
	fieldMemory
	fieldPIDs
)

type ResourcesModel struct {
	cpu    float64
	maxCPU float64
	memory int64
	maxMem int64
	pids   int64
	field  resourceField
	width  int
	height int
}

type ResourcesSelectedMsg struct {
	CPU      float64
	Memory   int64
	PIDLimit int64
}

func NewResources() ResourcesModel {
	maxCPU := float64(runtime.NumCPU())
	defaultCPU := 2.0
	if defaultCPU > maxCPU {
		defaultCPU = maxCPU
	}

	maxMem := int64(detectMemoryMB())
	defaultMem := int64(4096)
	if defaultMem > maxMem {
		defaultMem = maxMem
	}

	return ResourcesModel{
		cpu:    defaultCPU,
		maxCPU: maxCPU,
		memory: defaultMem,
		maxMem: maxMem,
		pids:   512,
	}
}

func (m ResourcesModel) Init() tea.Cmd {
	return nil
}

func (m ResourcesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.field > 0 {
				m.field--
			}
		case "down", "j", "tab":
			if m.field < fieldPIDs {
				m.field++
			}
		case "left", "h":
			m.adjustField(-1)
		case "right", "l":
			m.adjustField(1)
		case "enter":
			return m, func() tea.Msg {
				return ResourcesSelectedMsg{
					CPU:      m.cpu,
					Memory:   m.memory,
					PIDLimit: m.pids,
				}
			}
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		}
	}
	return m, nil
}

func (m *ResourcesModel) adjustField(dir int) {
	switch m.field {
	case fieldCPU:
		m.cpu += float64(dir) * 0.5
		if m.cpu < 0.5 {
			m.cpu = 0.5
		}
		if m.cpu > m.maxCPU {
			m.cpu = m.maxCPU
		}
	case fieldMemory:
		m.memory += int64(dir) * 256
		if m.memory < 512 {
			m.memory = 512
		}
		if m.memory > m.maxMem {
			m.memory = m.maxMem
		}
	case fieldPIDs:
		m.pids += int64(dir) * 64
		if m.pids < 64 {
			m.pids = 64
		}
		if m.pids > 4096 {
			m.pids = 4096
		}
	}
}

func (m ResourcesModel) View() string {
	title := styles.StepStyle.Render("[5/8]") + " " + styles.TitleStyle.Render("Compute Resources")

	fields := []struct {
		label string
		value string
		bar   string
		field resourceField
	}{
		{
			label: "CPU",
			value: fmt.Sprintf("%.1f / %.0f cores", m.cpu, m.maxCPU),
			bar:   renderBar(m.cpu/m.maxCPU, 30),
			field: fieldCPU,
		},
		{
			label: "Memory",
			value: fmt.Sprintf("%d / %d MB", m.memory, m.maxMem),
			bar:   renderBar(float64(m.memory)/float64(m.maxMem), 30),
			field: fieldMemory,
		},
		{
			label: "PIDs",
			value: fmt.Sprintf("%d", m.pids),
			bar:   renderBar(float64(m.pids)/4096.0, 30),
			field: fieldPIDs,
		},
	}

	var content string
	for _, f := range fields {
		indicator := "  "
		labelStyle := styles.UnselectedStyle
		if f.field == m.field {
			indicator = styles.SelectedStyle.Render("▸ ")
			labelStyle = styles.SelectedStyle
		}
		content += fmt.Sprintf("%s%-8s %s  %s\n\n",
			indicator,
			labelStyle.Render(f.label),
			f.bar,
			styles.DimStyle.Render(f.value),
		)
	}

	help := styles.HelpStyle.Render("↑/↓ select field • ←/→ adjust • enter continue • esc back")

	full := lipgloss.JoinVertical(lipgloss.Left,
		title, "", content, help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(60).Render(full))
}

func renderBar(ratio float64, width int) string {
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * float64(width))
	empty := width - filled
	bar := styles.SliderFillStyle.Render(strings.Repeat("█", filled)) +
		styles.SliderEmptyStyle.Render(strings.Repeat("░", empty))
	return bar
}

func detectMemoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 16384
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb int
				if _, err := fmt.Sscanf(fields[1], "%d", &kb); err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 16384
}
