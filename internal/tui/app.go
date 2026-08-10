package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/tui/views"
)

type step int

const (
	stepWelcome step = iota
	stepAgents
	stepTools
	stepNetwork
	stepCommands
	stepResources
	stepStorage
	stepPersistence
	stepReview
	stepBuild
)

type App struct {
	step    step
	current tea.Model
	profile *config.Profile
	store   *config.Store
	width   int
	height  int
}

func NewApp(store *config.Store) *App {
	profiles, _ := store.List()
	return &App{
		step:    stepWelcome,
		current: views.NewWelcome(profiles),
		profile: ptrTo(config.DefaultProfile()),
		store:   store,
	}
}

func (a *App) Init() tea.Cmd {
	return a.current.Init()
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		a.width = msg.Width
		a.height = msg.Height
	}

	switch msg := msg.(type) {
	case views.WelcomeChosenMsg:
		if msg.Choice == views.WelcomeLoad && msg.Profile != "" {
			// Load the chosen profile and jump straight to review, rather
			// than restarting the wizard and discarding what was saved.
			p, err := a.store.Load(msg.Profile)
			if err != nil {
				a.current = views.NewWelcome(a.profileNames())
				return a, a.current.Init()
			}
			a.profile = p
			return a.goTo(stepReview)
		}
		return a.goTo(stepAgents)

	case views.AgentsSelectedMsg:
		a.profile.Agents = make([]config.AgentConfig, len(msg.AgentIDs))
		for i, id := range msg.AgentIDs {
			a.profile.Agents[i] = config.AgentConfig{ID: id}
		}
		return a.goTo(stepTools)

	case views.ToolsSelectedMsg:
		a.profile.Tools = msg.Tools
		return a.goTo(stepNetwork)

	case views.NetworkSelectedMsg:
		a.profile.Network.Mode = msg.Mode
		a.profile.Network.AllowedDomains = msg.Domains
		return a.goTo(stepCommands)

	case views.CommandsSelectedMsg:
		a.profile.Commands.Mode = msg.Mode
		a.profile.Commands.Allowed = msg.Commands
		return a.goTo(stepResources)

	case views.ResourcesSelectedMsg:
		a.profile.Resources.CPU = msg.CPU
		a.profile.Resources.Memory = msg.Memory
		a.profile.Resources.PIDLimit = msg.PIDLimit
		return a.goTo(stepStorage)

	case views.StorageSelectedMsg:
		a.profile.Storage.Size = msg.Size
		a.profile.Storage.Volumes = msg.Volumes
		return a.goTo(stepPersistence)

	case views.PersistenceSelectedMsg:
		a.profile.Persistence = msg.Mode
		return a.goTo(stepReview)

	case views.BuildRequestedMsg:
		a.profile = msg.Profile
		if a.profile.Metadata.CreatedAt.IsZero() {
			a.profile.Metadata.CreatedAt = time.Now().UTC()
		}
		if err := a.store.Save(a.profile); err != nil {
			// Never advance to the build step with an unsaved profile: the
			// image would build but `rig run <name>` would not find it.
			a.step = stepReview
			a.current = views.NewReviewWithError(a.profile, err.Error())
			return a, a.current.Init()
		}
		return a.goTo(stepBuild)

	case views.EnterSandboxMsg:
		return a, tea.Quit

	case views.BackMsg:
		return a.goBack()
	}

	var cmd tea.Cmd
	a.current, cmd = a.current.Update(msg)
	return a, cmd
}

func (a *App) View() string {
	return a.current.View()
}

func (a *App) goTo(s step) (*App, tea.Cmd) {
	a.step = s
	a.current = a.viewForStep(s)
	return a, a.current.Init()
}

func (a *App) goBack() (*App, tea.Cmd) {
	prev := a.step - 1
	if prev < stepWelcome {
		prev = stepWelcome
	}
	return a.goTo(prev)
}

func (a *App) viewForStep(s step) tea.Model {
	switch s {
	case stepWelcome:
		return views.NewWelcome(a.profileNames())
	case stepAgents:
		return views.NewAgentSelect()
	case stepTools:
		return views.NewToolsSelect()
	case stepNetwork:
		var ids []string
		for _, ac := range a.profile.Agents {
			ids = append(ids, ac.ID)
		}
		return views.NewNetwork(ids)
	case stepCommands:
		return views.NewCommands()
	case stepResources:
		return views.NewResources()
	case stepStorage:
		return views.NewStorage()
	case stepPersistence:
		return views.NewPersistence()
	case stepReview:
		return views.NewReview(a.profile)
	case stepBuild:
		return views.NewBuild(a.profile)
	default:
		return views.NewWelcome(a.profileNames())
	}
}

func (a *App) profileNames() []string {
	names, _ := a.store.List()
	return names
}

func (a *App) Profile() *config.Profile {
	return a.profile
}

func ptrTo[T any](v T) *T {
	return &v
}
