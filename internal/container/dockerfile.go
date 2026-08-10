package container

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/security"
)

// baseImage is pinned to an LTS tag so images are reproducible across hosts.
const baseImage = "ubuntu:24.04"

// basePackages are installed in every sandbox and therefore filtered out of a
// profile's tool list to avoid a duplicate apt line.
var basePackages = []string{
	"ca-certificates", "curl", "git", "wget", "jq",
	"openssh-client", "locales", "less", "file",
}

type DockerfileData struct {
	ProfileName    string
	BaseImage      string
	NodeVersion    string
	SystemPackages []string
	AgentBlocks    []AgentBlock
	BashrcCommand  string
}

type AgentBlock struct {
	Name  string
	Steps []string
}

// The image deliberately has no sudo. The sandbox user is unprivileged and
// stays that way: the container already runs with --cap-drop ALL and
// no-new-privileges, so a setuid sudo binary could not escalate anyway, and
// shipping one only widens the attack surface inside the sandbox.
var dockerfileTmpl = template.Must(template.New("Dockerfile").Parse(`FROM {{ .BaseImage }}

LABEL maintainer="rig" \
      rig.profile="{{ .ProfileName }}"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TERM=xterm-256color

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    wget \
    jq \
    openssh-client \
    locales \
    less \
    file \
{{- range .SystemPackages }}
    {{ . }} \
{{- end }}
    && locale-gen en_US.UTF-8 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
{{ if .NodeVersion }}
RUN curl -fsSL https://deb.nodesource.com/setup_{{ .NodeVersion }}.x -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -f /tmp/nodesource_setup.sh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
{{ end }}
{{- range .AgentBlocks }}
# -- {{ .Name }} --
{{- range .Steps }}
RUN {{ . }}
{{- end }}
{{ end }}
RUN useradd -m -s /bin/bash sandbox \
    && mkdir -p /home/sandbox/workspace \
    && chown -R sandbox:sandbox /home/sandbox

RUN {{ .BashrcCommand }} \
    && chown sandbox:sandbox /home/sandbox/.bashrc \
    && chmod 0644 /home/sandbox/.bashrc

USER sandbox
WORKDIR /home/sandbox/workspace

CMD ["/bin/bash", "-l"]
`))

// GenerateDockerfile renders the image definition for a profile.
//
// Every interpolated value is validated first. Profiles are shareable files,
// so a tool name or agent id is untrusted input, and an unchecked value
// containing a newline could append its own instructions to the build.
func GenerateDockerfile(profile *config.Profile) (string, error) {
	if err := security.ValidateProfileName(profile.Name); err != nil {
		return "", err
	}
	if err := security.ValidatePackageNames(profile.Tools); err != nil {
		return "", err
	}

	selectedAgents := make([]agents.AgentSpec, 0, len(profile.Agents))
	for _, ac := range profile.Agents {
		spec, ok := agents.ByID(ac.ID)
		if !ok {
			return "", fmt.Errorf("unknown agent %q", ac.ID)
		}
		selectedAgents = append(selectedAgents, spec)
	}
	if len(selectedAgents) == 0 {
		return "", fmt.Errorf("profile %q selects no agents", profile.Name)
	}

	pkgSet := make(map[string]bool)
	for _, t := range profile.Tools {
		pkgSet[t] = true
	}
	for _, a := range selectedAgents {
		for _, p := range a.SystemPackages {
			if err := security.ValidatePackageName(p); err != nil {
				return "", fmt.Errorf("agent %s: %w", a.ID, err)
			}
			pkgSet[p] = true
		}
	}
	for _, base := range basePackages {
		delete(pkgSet, base)
	}

	packages := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		packages = append(packages, p)
	}
	sort.Strings(packages)

	agentBlocks := make([]AgentBlock, 0, len(selectedAgents))
	agentNames := make([]string, 0, len(selectedAgents))
	for _, a := range selectedAgents {
		for _, step := range a.InstallSteps {
			if strings.ContainsAny(step, "\n\r") {
				return "", fmt.Errorf("agent %s has a multi-line install step", a.ID)
			}
		}
		agentBlocks = append(agentBlocks, AgentBlock{Name: a.DisplayName, Steps: a.InstallSteps})
		agentNames = append(agentNames, a.DisplayName)
	}

	data := DockerfileData{
		ProfileName:    profile.Name,
		BaseImage:      baseImage,
		NodeVersion:    agents.MaxNodeVersion(selectedAgents),
		SystemPackages: packages,
		AgentBlocks:    agentBlocks,
		BashrcCommand:  bashrcCommand(profile.Name, agentNames),
	}

	var buf bytes.Buffer
	if err := dockerfileTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()) + "\n", nil
}

// bashrcCommand builds a single-line shell command that writes the sandbox
// .bashrc. Using printf rather than a Dockerfile heredoc keeps the build
// working on daemons without the BuildKit heredoc frontend.
func bashrcCommand(profileName string, agentNames []string) string {
	lines := []string{
		"# Rig sandbox shell",
		`export PS1='\[\033[1;35m\]rig\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]\$ '`,
		`export PATH="$HOME/.local/bin:$PATH"`,
		`alias ll='ls -alF --color=auto'`,
		`alias la='ls -A --color=auto'`,
		``,
		`if [ -z "$RIG_GREETED" ]; then`,
		`    export RIG_GREETED=1`,
		`    echo ""`,
		`    echo -e "  \033[1;35mRig Sandbox\033[0m - ` + profileName + `"`,
	}
	for _, name := range agentNames {
		lines = append(lines, `    echo -e "  \033[0;36m*\033[0m `+name+`"`)
	}
	lines = append(lines, `    echo ""`, `fi`)

	quoted := make([]string, 0, len(lines))
	for _, l := range lines {
		quoted = append(quoted, shellQuote(l))
	}
	return "printf '%s\\n' " + strings.Join(quoted, " ") + " > /home/sandbox/.bashrc"
}

// shellQuote wraps a string in single quotes, escaping any it contains.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
