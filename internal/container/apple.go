package container

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
)

// appleCreateArgs builds an Apple `container create` invocation. Apple's CLI is largely
// Docker-compatible but omits a few flags (--pids-limit, --memory-swap, --security-opt,
// --storage-opt); resource limits it does support (cpus, memory) and cap-drop are applied.
// Mounts use --mount rather than -v. Network allowlist mode is not yet mapped and is left
// on the default network (handled/guarded by the caller).
func appleCreateArgs(profile *config.Profile, name, networkName, envFile string, ephemeral bool) []string {
	args := []string{"create", "--name", name}
	args = append(args, ttyFlags()...)
	args = append(args,
		"--init",
		"--cap-drop", "ALL",
		"-c", fmt.Sprintf("%.2f", profile.Resources.CPU),
		"-m", fmt.Sprintf("%dM", profile.Resources.Memory),
		"--label", LabelProfile+"="+profile.Name,
		"--label", LabelRole+"="+RoleSandbox,
		"--label", "rig.created="+time.Now().UTC().Format(time.RFC3339),
	)

	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	if profile.Network.Mode == "none" {
		args = append(args, "--no-dns")
	}

	for _, v := range profile.Storage.Volumes {
		vol := "rig-" + profile.Name + "-" + v.Name
		spec := fmt.Sprintf("type=volume,source=%s,target=%s", vol, v.Target)
		if v.ReadOnly {
			spec += ",readonly"
		}
		args = append(args, "--mount", spec)
	}
	for _, m := range profile.Mounts {
		spec := fmt.Sprintf("type=bind,source=%s,target=%s", m.Source, m.Target)
		if m.ReadOnly {
			spec += ",readonly"
		}
		args = append(args, "--mount", spec)
	}

	if ephemeral {
		args = append(args, "--rm")
	}

	args = append(args, profile.ImageTag())
	if !ephemeral {
		args = append(args, "sleep", "infinity")
	}
	return args
}

// appleContainer mirrors the fields Rig needs from `container ls --format json`.
// `status` is an object (state + networks), not a string.
type appleContainer struct {
	Status struct {
		State string `json:"state"`
	} `json:"status"`
	Configuration struct {
		ID    string `json:"id"`
		Image struct {
			Reference string `json:"reference"`
		} `json:"image"`
		Labels map[string]string `json:"labels"`
	} `json:"configuration"`
}

// appleList lists Rig sandboxes, filtering client-side by label (Apple's ls has no
// server-side label filter).
func (r *Runner) appleList(ctx context.Context, labelFilters ...string) []ContainerInfo {
	out, err := exec.CommandContext(ctx, r.bin, "ls", "--all", "--format", "json").Output()
	if err != nil {
		return nil
	}
	var items []appleContainer
	if json.Unmarshal(out, &items) != nil {
		return nil
	}

	var containers []ContainerInfo
	for _, it := range items {
		if !matchesLabels(it.Configuration.Labels, labelFilters) {
			continue
		}
		containers = append(containers, ContainerInfo{
			Name:      it.Configuration.ID,
			Profile:   it.Configuration.Labels[LabelProfile],
			Image:     it.Configuration.Image.Reference,
			Status:    it.Status.State,
			Running:   it.Status.State == "running",
		})
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	return containers
}

// matchesLabels reports whether a container's labels satisfy every "key=value" filter.
func matchesLabels(labels map[string]string, filters []string) bool {
	for _, f := range filters {
		key, val, ok := cutLabel(f)
		if !ok {
			continue
		}
		if labels[key] != val {
			return false
		}
	}
	return true
}

func cutLabel(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
