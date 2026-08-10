package config

import "time"

func DefaultProfile() Profile {
	return Profile{
		Version: 1,
		Network: NetworkConfig{
			Mode: "unrestricted",
		},
		Commands: CommandsConfig{
			Mode: "unrestricted",
		},
		Resources: ResourcesConfig{
			CPU:      2.0,
			Memory:   4096,
			PIDLimit: 512,
		},
		Storage: StorageConfig{
			Size: "10g",
		},
		Persistence: "ephemeral",
		GPU: GPUConfig{
			Enabled: false,
		},
		Tools: []string{"curl", "git", "wget", "jq"},
		Metadata: Metadata{
			CreatedAt: time.Now(),
		},
	}
}

var DefaultTools = []ToolCategory{
	{
		Name: "Development",
		Tools: []Tool{
			{ID: "git", Name: "git", Package: "git", AlwaysIncluded: true},
			{ID: "neovim", Name: "neovim", Package: "neovim"},
			{ID: "tmux", Name: "tmux", Package: "tmux"},
			{ID: "python3", Name: "Python 3", Package: "python3"},
			{ID: "python3-pip", Name: "pip", Package: "python3-pip"},
			{ID: "python3-venv", Name: "venv", Package: "python3-venv"},
			{ID: "make", Name: "make", Package: "make"},
			{ID: "build-essential", Name: "build-essential", Package: "build-essential"},
		},
	},
	{
		Name: "Search & Navigation",
		Tools: []Tool{
			{ID: "ripgrep", Name: "ripgrep", Package: "ripgrep"},
			{ID: "fd-find", Name: "fd", Package: "fd-find"},
			{ID: "fzf", Name: "fzf", Package: "fzf"},
			{ID: "tree", Name: "tree", Package: "tree"},
		},
	},
	{
		Name: "Utilities",
		Tools: []Tool{
			{ID: "curl", Name: "curl", Package: "curl", AlwaysIncluded: true},
			{ID: "wget", Name: "wget", Package: "wget"},
			{ID: "jq", Name: "jq", Package: "jq"},
			{ID: "bat", Name: "bat", Package: "bat"},
			{ID: "htop", Name: "htop", Package: "htop"},
			{ID: "unzip", Name: "unzip", Package: "unzip"},
		},
	},
}

type ToolCategory struct {
	Name  string
	Tools []Tool
}

type Tool struct {
	ID             string
	Name           string
	Package        string
	AlwaysIncluded bool
}
