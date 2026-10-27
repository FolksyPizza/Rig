package agents

import (
	"net/url"
	"sort"
	"strings"
)

// providerDomains maps an API key's environment variable to the model API it
// unlocks. When a profile gives an agent one of these keys, Rig allows the
// matching API and nothing else: a sandbox with only ANTHROPIC_API_KEY can
// reach api.anthropic.com but not OpenAI.
var providerDomains = map[string][]string{
	"ANTHROPIC_API_KEY":  {"api.anthropic.com"},
	"OPENAI_API_KEY":     {"api.openai.com"},
	"GEMINI_API_KEY":     {"generativelanguage.googleapis.com"},
	"GOOGLE_API_KEY":     {"generativelanguage.googleapis.com"},
	"XAI_API_KEY":        {"api.x.ai"},
	"OPENROUTER_API_KEY": {"openrouter.ai"},
	"GROQ_API_KEY":       {"api.groq.com"},
	"MISTRAL_API_KEY":    {"api.mistral.ai"},
	"DEEPSEEK_API_KEY":   {"api.deepseek.com"},
	"DASHSCOPE_API_KEY":  {"dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com"},
	"TOGETHER_API_KEY":   {"api.together.xyz"},
	"FIREWORKS_API_KEY":  {"api.fireworks.ai"},
	"CEREBRAS_API_KEY":   {"api.cerebras.ai"},
	"MOONSHOT_API_KEY":   {"api.moonshot.ai"},
	"ZAI_API_KEY":        {"api.z.ai"},
	"HF_TOKEN":           {"huggingface.co", "router.huggingface.co"},
}

// ProviderDomains returns the domains implied by an agent's environment:
// known API keys, plus the host of any literal https URL given in a variable
// whose name ends in _BASE_URL, _API_BASE or _ENDPOINT (for example
// OPENAI_BASE_URL pointing at a compatible provider).
func ProviderDomains(env map[string]string) []string {
	set := map[string]bool{}
	for k, v := range env {
		// A key paired with its own base URL (OPENAI_API_KEY with
		// OPENAI_BASE_URL) is for that endpoint, not the vendor's default API.
		_, redirected := env[strings.TrimSuffix(k, "_API_KEY")+"_BASE_URL"]
		if !redirected || !strings.HasSuffix(k, "_API_KEY") {
			for _, d := range providerDomains[k] {
				set[d] = true
			}
		}
		if strings.HasSuffix(k, "_BASE_URL") || strings.HasSuffix(k, "_API_BASE") || strings.HasSuffix(k, "_ENDPOINT") {
			if strings.HasPrefix(v, "${") {
				continue
			}
			if u, err := url.Parse(v); err == nil && u.Scheme == "https" && u.Hostname() != "" {
				set[strings.ToLower(u.Hostname())] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// KnownKeys lists the API-key variables Rig maps to providers.
func KnownKeys() []string {
	keys := make([]string, 0, len(providerDomains))
	for k := range providerDomains {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
