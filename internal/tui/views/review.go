package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/security"
	"github.com/FolksyPizza/rig/internal/tui/styles"
)

type reviewFocus int

const (
	focusName reviewFocus = iota
	focusBuild
)

type ReviewModel struct {
	profile     *config.Profile
	profileName string
	focus       reviewFocus
	errMsg      string
	width       int
	height      int
}

type BuildRequestedMsg struct {
	Profile *config.Profile
}

func NewReview(profile *config.Profile) ReviewModel {
	return ReviewModel{
		profile:     profile,
		profileName: profile.Name,
	}
}

// NewReviewWithError re-shows the review step after a save failed, so the
// reason is visible instead of the wizard silently dropping the profile.
func NewReviewWithError(profile *config.Profile, msg string) ReviewModel {
	m := NewReview(profile)
	m.errMsg = msg
	m.focus = focusName
	return m
}

func (m ReviewModel) Init() tea.Cmd {
	return nil
}

func (m ReviewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if m.focus == focusName {
			switch msg.String() {
			case "enter":
				m.profile.Name = m.profileName
				m.focus = focusBuild
			case "backspace":
				if len(m.profileName) > 0 {
					m.profileName = m.profileName[:len(m.profileName)-1]
				}
			case "esc":
				return m, func() tea.Msg { return BackMsg{} }
			case "tab":
				m.profile.Name = m.profileName
				m.focus = focusBuild
			default:
				if len(msg.String()) == 1 {
					m.profileName += msg.String()
				}
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			// The name becomes a filename, an image tag and a container name,
			// so reject a bad one here rather than failing at save time.
			if err := security.ValidateProfileName(m.profileName); err != nil {
				m.errMsg = err.Error()
				m.focus = focusName
				return m, nil
			}
			m.profile.Name = m.profileName
			m.errMsg = ""
			return m, func() tea.Msg { return BuildRequestedMsg{Profile: m.profile} }
		case "tab":
			m.focus = focusName
		case "esc":
			return m, func() tea.Msg { return BackMsg{} }
		}
	}
	return m, nil
}

func (m ReviewModel) View() string {
	title := styles.StepStyle.Render("[8/8]") + " " + styles.TitleStyle.Render("Review")

	var agentNames []string
	for _, ac := range m.profile.Agents {
		if spec, ok := agents.ByID(ac.ID); ok {
			agentNames = append(agentNames, spec.DisplayName)
		}
	}

	rows := []struct {
		label string
		value string
	}{
		{"Agents", strings.Join(agentNames, ", ")},
		{"Tools", strings.Join(m.profile.Tools, ", ")},
		{"Network", formatNetworkMode(m.profile)},
		{"Commands", formatCommandsMode(m.profile)},
		{"CPU", fmt.Sprintf("%.1f cores", m.profile.Resources.CPU)},
		{"Memory", fmt.Sprintf("%d MB", m.profile.Resources.Memory)},
		{"PIDs", fmt.Sprintf("%d", m.profile.Resources.PIDLimit)},
		{"Storage", formatStorage(m.profile)},
		{"Persistence", m.profile.Persistence},
	}

	var summary string
	for _, r := range rows {
		summary += fmt.Sprintf("  %s  %s\n",
			styles.HighlightStyle.Render(fmt.Sprintf("%-12s", r.label)),
			styles.UnselectedStyle.Render(r.value),
		)
	}

	nameLabel := "\n  " + styles.HighlightStyle.Render("Profile name: ")
	nameValue := m.profileName
	if m.focus == focusName {
		nameValue += styles.SelectedStyle.Render("█")
	}
	nameLine := nameLabel + nameValue

	var button string
	if m.focus == focusBuild {
		button = "\n  " + styles.ButtonStyle.Render("  Build Sandbox  ")
	} else {
		button = "\n  " + styles.ButtonInactiveStyle.Render("  Build Sandbox  ")
	}

	errLine := ""
	if m.errMsg != "" {
		errLine = "  " + styles.ErrorMsgStyle.Render(m.errMsg)
	}

	help := styles.HelpStyle.Render("tab switch • enter build • esc back")

	content := lipgloss.JoinVertical(lipgloss.Left,
		title, "", summary, nameLine, button, errLine, "", help,
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
		styles.PanelStyle.Width(65).Render(content))
}

func formatNetworkMode(p *config.Profile) string {
	switch p.Network.Mode {
	case "allowlist":
		return fmt.Sprintf("Allowlist (%d domains)", len(p.Network.AllowedDomains))
	case "none":
		return "Offline"
	default:
		return "Unrestricted"
	}
}

func formatCommandsMode(p *config.Profile) string {
	if p.Commands.Mode == "allowlist" {
		return fmt.Sprintf("Allowlist (%d commands)", len(p.Commands.Allowed))
	}
	return "Unrestricted"
}

func formatStorage(p *config.Profile) string {
	parts := []string{p.Storage.Size}
	if len(p.Storage.Volumes) > 0 {
		parts = append(parts, fmt.Sprintf("%d volumes", len(p.Storage.Volumes)))
	}
	return strings.Join(parts, ", ")
}
