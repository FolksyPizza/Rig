package config

import "time"

// DefaultProfile is the standard template with the given agents.
func DefaultProfile(agentIDs ...string) Profile {
	t, _ := GetTemplate("standard")
	p := t.Profile
	for _, id := range agentIDs {
		p.Agents = append(p.Agents, AgentConfig{ID: id})
	}
	p.Metadata = Metadata{CreatedAt: time.Now()}
	return p
}
