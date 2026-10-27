package config

import "sort"

// Preset is a named group of domains for network.presets.
type Preset struct {
	Description string
	Domains     []string
}

// Presets are the domain groups a profile can name. Each one is the minimum
// a tool needs, not a whole company's domain.
var Presets = map[string]Preset{
	"github": {
		Description: "GitHub: clone, API, raw files, release downloads",
		Domains:     []string{"github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com"},
	},
	"npm": {
		Description: "npm registry",
		Domains:     []string{"registry.npmjs.org"},
	},
	"pypi": {
		Description: "Python Package Index",
		Domains:     []string{"pypi.org", "files.pythonhosted.org"},
	},
	"go": {
		Description: "Go module proxy and checksum database",
		Domains:     []string{"proxy.golang.org", "sum.golang.org", "index.golang.org"},
	},
	"rust": {
		Description: "crates.io and Rust toolchain downloads",
		Domains:     []string{"crates.io", "index.crates.io", "static.crates.io", "static.rust-lang.org"},
	},
	"ubuntu": {
		Description: "Ubuntu package archives, for sudo apt (plain HTTP, so not usable with https_only)",
		Domains:     []string{"archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"},
	},
	"huggingface": {
		Description: "Hugging Face models and datasets",
		Domains:     []string{"huggingface.co", "*.huggingface.co", "*.hf.co"},
	},
	"anthropic": {
		Description: "Anthropic API",
		Domains:     []string{"api.anthropic.com"},
	},
	"openai": {
		Description: "OpenAI API",
		Domains:     []string{"api.openai.com"},
	},
	"gemini": {
		Description: "Google Gemini API",
		Domains:     []string{"generativelanguage.googleapis.com"},
	},
	"openrouter": {
		Description: "OpenRouter API",
		Domains:     []string{"openrouter.ai"},
	},
	"xai": {
		Description: "xAI API",
		Domains:     []string{"api.x.ai"},
	},
	"dashscope": {
		Description: "Alibaba Cloud DashScope API (Qwen models)",
		Domains:     []string{"dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com"},
	},
}

// PresetNames lists presets in order.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for n := range Presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
