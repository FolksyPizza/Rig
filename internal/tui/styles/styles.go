package styles

import "github.com/charmbracelet/lipgloss"

var (
	Primary   = lipgloss.Color("#7C3AED")
	Secondary = lipgloss.Color("#06B6D4")
	Success   = lipgloss.Color("#22C55E")
	Warning   = lipgloss.Color("#F59E0B")
	Error     = lipgloss.Color("#EF4444")
	Muted     = lipgloss.Color("#6B7280")
	Text      = lipgloss.Color("#E5E7EB")
	TextDim   = lipgloss.Color("#9CA3AF")
	BgDark    = lipgloss.Color("#111827")
	BgPanel   = lipgloss.Color("#1F2937")
	Border    = lipgloss.Color("#374151")
)

var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(TextDim).
			MarginBottom(1)

	StepStyle = lipgloss.NewStyle().
			Foreground(Secondary).
			Bold(true)

	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Border).
			Padding(1, 2)

	SelectedStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true)

	UnselectedStyle = lipgloss.NewStyle().
			Foreground(Text)

	CheckedStyle = lipgloss.NewStyle().
			Foreground(Success).
			Bold(true)

	DimStyle = lipgloss.NewStyle().
			Foreground(Muted)

	ErrorMsgStyle = lipgloss.NewStyle().
			Foreground(Error).
			Bold(true)

	SuccessMsgStyle = lipgloss.NewStyle().
			Foreground(Success).
			Bold(true)

	HelpStyle = lipgloss.NewStyle().
			Foreground(Muted).
			MarginTop(1)

	LogoStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true)

	HighlightStyle = lipgloss.NewStyle().
			Foreground(Secondary)

	SliderFillStyle = lipgloss.NewStyle().
			Foreground(Primary)

	SliderEmptyStyle = lipgloss.NewStyle().
				Foreground(Border)

	ButtonStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(Primary).
			Padding(0, 3).
			Bold(true)

	ButtonInactiveStyle = lipgloss.NewStyle().
				Foreground(TextDim).
				Background(Border).
				Padding(0, 3)
)
