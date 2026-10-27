package container

import (
	"fmt"
	"sort"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
)

func resolveAgents(ids []string) ([]agents.AgentSpec, error) { return agents.Resolve(ids) }

// quietEnv merges the agents' switches for telemetry, error reporting and
// auto-update.
func quietEnv(p *config.Profile) map[string]string {
	ids := make([]string, 0, len(p.Agents))
	for _, a := range p.Agents {
		ids = append(ids, a.ID)
	}
	specs, err := agents.Resolve(ids)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, s := range specs {
		for k, v := range s.QuietEnv {
			out[k] = v
		}
	}
	return out
}

// CheckEngineSupport refuses combinations an engine cannot enforce, instead of
// running a sandbox weaker than its profile says.
func CheckEngineSupport(engine string, eff config.Effective) error {
	if engine != "apple" {
		return nil
	}
	var missing []string
	if eff.NetworkMode != "unrestricted" {
		missing = append(missing, "network mode "+eff.NetworkMode)
	}
	if eff.ReadOnlyRoot {
		missing = append(missing, "a read-only image")
	}
	if eff.NeedsGateway {
		missing = append(missing, "the gateway (MCP, git broker, host ports)")
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("Apple's container runtime cannot enforce %v for security level %s yet; install Podman or Docker (Rig uses them automatically for these profiles) or use level open", missing, eff.Level)
}
