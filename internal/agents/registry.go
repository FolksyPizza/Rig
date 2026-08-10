package agents

import "fmt"

type AgentSpec struct {
	ID              string
	DisplayName     string
	Description     string
	RequiresNode    string
	SystemPackages  []string
	InstallSteps    []string
	VerifyCommand   string
	RequiredDomains []string
	EnvHints        []string // env var names the user should set
}

func All() []AgentSpec {
	return []AgentSpec{
		ClaudeCode,
		Codex,
		GrokBuild,
		GeminiCLI,
		OpenClaw,
		HermesAgent,
	}
}

func ByID(id string) (AgentSpec, bool) {
	for _, a := range All() {
		if a.ID == id {
			return a, true
		}
	}
	return AgentSpec{}, false
}

func ByIDs(ids []string) []AgentSpec {
	var result []AgentSpec
	for _, id := range ids {
		if a, ok := ByID(id); ok {
			result = append(result, a)
		}
	}
	return result
}

func MaxNodeVersion(specs []AgentSpec) string {
	max := 0
	for _, s := range specs {
		if s.RequiresNode == "" {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(s.RequiresNode, "%d", &v); err == nil && v > max {
			max = v
		}
	}
	if max == 0 {
		return ""
	}
	return fmt.Sprintf("%d", max)
}
