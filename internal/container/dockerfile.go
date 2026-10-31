package container

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/template"

	rig "github.com/FolksyPizza/rig"
	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/security"
)

const (
	// defaultBaseImage is pinned to an LTS tag so images are reproducible.
	defaultBaseImage = "ubuntu:24.04"
	// defaultGoImage builds rig-helper inside the image build.
	defaultGoImage = "golang:1.25-alpine"

	sandboxHome = "/home/sandbox"
	// sandboxUID matches the first regular user on most Linux hosts, so files
	// the agent writes into a bind mount are owned by you.
	sandboxUID = 1000
)

// basePackages are installed in every sandbox and therefore filtered out of a
// profile's tool list to avoid a duplicate apt line.
var basePackages = []string{
	"ca-certificates", "curl", "git", "wget", "jq",
	"openssh-client", "locales", "less", "file", "procps",
}

// imageRefRe accepts registry/name[:tag][@digest] references, so an override
// cannot inject anything into a FROM line.
var imageRefRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// imageOverride reads an image reference from the environment, falling back
// to def. RIG_BASE_IMAGE, RIG_GO_IMAGE and RIG_NODE_IMAGE let you use a mirror
// or pin a digest.
func imageOverride(env, def string) (string, error) {
	v := os.Getenv(env)
	if v == "" {
		return def, nil
	}
	if !imageRefRe.MatchString(v) {
		return "", fmt.Errorf("%s=%q is not a valid image reference", env, v)
	}
	return v, nil
}

// BuildContext is everything sent to the image builder. It is generated in
// full; nothing is copied from the user's filesystem.
type BuildContext struct {
	Dockerfile string
	Files      map[string][]byte
	// Hash identifies the context. It is stored as the image label
	// rig.build-hash, so Rig can tell when a profile change needs a rebuild.
	Hash string
}

type dockerfileData struct {
	ProfileName    string
	Hash           string
	BaseImage      string
	GoImage        string
	Helper         bool
	NodeImage      string
	SystemPackages []string
	PipPackages    string
	NPMPackages    string
	AgentBlocks    []agentBlock
	UID            int
	Sudo           bool
	ClaudePolicy   bool
	GeminiPolicy   bool
	AgentBin       bool // /etc/rig/bin holds permission-mode wrappers
}

type agentBlock struct {
	Name  string
	Steps []string
}

var dockerfileTmpl = template.Must(template.New("Dockerfile").Parse(`{{ if .Helper -}}
FROM {{ .GoImage }} AS rig-helper
WORKDIR /src
COPY rig-helper-src/ ./
RUN CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/rig-helper ./cmd/rig-helper

{{ end -}}
{{ if .NodeImage -}}
FROM {{ .NodeImage }} AS node

{{ end -}}
FROM {{ .BaseImage }}

LABEL rig.profile="{{ .ProfileName }}" \
      rig.build-hash="{{ .Hash }}"

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
    procps \
{{- range .SystemPackages }}
    {{ . }} \
{{- end }}
    && locale-gen en_US.UTF-8 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
{{ if .NodeImage }}
# Node.js comes from the official image, so no install script is downloaded
# and run as root.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version && npm --version
{{ end -}}
{{ if .PipPackages }}
RUN python3 -m pip install --no-cache-dir --break-system-packages {{ .PipPackages }}
{{ end -}}
{{ if .NPMPackages }}
RUN npm install -g --no-fund --no-audit --loglevel=error {{ .NPMPackages }}
{{ end -}}
{{ range .AgentBlocks }}
# -- {{ .Name }} --
{{- range .Steps }}
RUN {{ . }}
{{- end }}
{{ end -}}
{{ if .Helper }}
COPY --from=rig-helper /out/rig-helper /usr/local/bin/rig-helper
{{ end }}
RUN if getent passwd {{ .UID }} >/dev/null; then userdel -r "$(getent passwd {{ .UID }} | cut -d: -f1)" 2>/dev/null || true; fi \
    && useradd -m -s /bin/bash -u {{ .UID }} sandbox \
    && mkdir -p /home/sandbox/workspace /home/sandbox/.rig \
    && chown -R sandbox:sandbox /home/sandbox
{{ if .Sudo }}
RUN printf '%s\n' 'sandbox ALL=(ALL) NOPASSWD:ALL' 'Defaults env_keep += "HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy NODE_USE_ENV_PROXY NODE_OPTIONS"' > /etc/sudoers.d/90-rig-sandbox \
    && chmod 0440 /etc/sudoers.d/90-rig-sandbox \
    && visudo -cf /etc/sudoers.d/90-rig-sandbox
{{ end }}
COPY rig/ /etc/rig/
RUN install -m 0755 /etc/rig/rig-entrypoint /usr/local/bin/rig-entrypoint \
    && cp -a /etc/rig/home/. /home/sandbox/ \
    && chown -R sandbox:sandbox /home/sandbox \
    && mkdir -p /etc/rig/skel \
    && cp -a /home/sandbox/. /etc/rig/skel/ \
    && chown -R sandbox:sandbox /etc/rig/skel \
{{- if .ClaudePolicy }}
    && install -D -m 0644 /etc/rig/policy/claude-managed-settings.json /etc/claude-code/managed-settings.json \
{{- end }}
{{- if .GeminiPolicy }}
    && install -D -m 0644 /etc/rig/policy/gemini-system-settings.json /etc/gemini-cli/settings.json \
    && install -D -m 0644 /etc/rig/policy/gemini-system-settings.json /etc/qwen-code/settings.json \
{{- end }}
{{- if .AgentBin }}
    && chmod 0755 /etc/rig/bin/* \
{{- end }}
    && chmod -R a+rX /etc/rig

ENV PATH=/etc/rig/bin:/home/sandbox/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NPM_CONFIG_PREFIX=/home/sandbox/.local \
    PIP_BREAK_SYSTEM_PACKAGES=1

USER sandbox
WORKDIR /home/sandbox/workspace

ENTRYPOINT ["/usr/local/bin/rig-entrypoint"]
CMD ["/bin/bash", "-l"]
`))

// shellQuote wraps a string in single quotes, escaping any it contains.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoteAll(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = shellQuote(s)
	}
	return strings.Join(q, " ")
}

func dedupeSorted(items []string) []string {
	set := map[string]bool{}
	for _, s := range items {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// GenerateContext renders the build context for a profile.
//
// Every interpolated value is validated first. Profiles are shareable files,
// so a tool name or agent id is untrusted input, and an unchecked value
// containing a newline could append its own instructions to the build.
func GenerateContext(profile *config.Profile) (*BuildContext, error) {
	if err := security.ValidateProfileName(profile.Name); err != nil {
		return nil, err
	}
	if err := security.ValidatePackageNames(profile.Tools); err != nil {
		return nil, err
	}
	baseImage, err := imageOverride("RIG_BASE_IMAGE", defaultBaseImage)
	if err != nil {
		return nil, err
	}
	goImage, err := imageOverride("RIG_GO_IMAGE", defaultGoImage)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(profile.Agents))
	versions := map[string]string{}
	for _, ac := range profile.Agents {
		ids = append(ids, ac.ID)
		if ac.Version != "" {
			if !agents.ValidVersion(ac.Version) {
				return nil, fmt.Errorf("agent %s: invalid version %q", ac.ID, ac.Version)
			}
			versions[ac.ID] = ac.Version
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("profile %q selects no agents", profile.Name)
	}
	specs, err := agents.Resolve(ids)
	if err != nil {
		return nil, err
	}
	eff := profile.Resolve()

	npm := append([]string{}, profile.Packages.NPM...)
	pip := append([]string{}, profile.Packages.Pip...)
	for _, s := range profile.MCP.Servers {
		npm = append(npm, s.Packages.NPM...)
		pip = append(pip, s.Packages.Pip...)
	}
	for _, n := range npm {
		if err := security.ValidateNPMPackage(n); err != nil {
			return nil, err
		}
	}
	for _, n := range pip {
		if err := security.ValidatePipPackage(n); err != nil {
			return nil, err
		}
	}
	npm, pip = dedupeSorted(npm), dedupeSorted(pip)

	pkgSet := make(map[string]bool)
	for _, t := range profile.Tools {
		pkgSet[t] = true
	}
	for _, a := range specs {
		for _, p := range a.SystemPackages {
			if err := security.ValidatePackageName(p); err != nil {
				return nil, fmt.Errorf("agent %s: %w", a.ID, err)
			}
			pkgSet[p] = true
		}
	}
	if len(pip) > 0 {
		pkgSet["python3"], pkgSet["python3-pip"] = true, true
	}
	if eff.Sudo {
		pkgSet["sudo"] = true
	}
	for _, b := range basePackages {
		delete(pkgSet, b)
	}
	packages := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		packages = append(packages, p)
	}
	sort.Strings(packages)

	blocks := make([]agentBlock, 0, len(specs))
	names := make([]string, 0, len(specs))
	for _, a := range specs {
		steps := a.Steps(versions[a.ID])
		for _, step := range steps {
			if strings.ContainsAny(step, "\n\r") {
				return nil, fmt.Errorf("agent %s has a multi-line install step", a.ID)
			}
		}
		blocks = append(blocks, agentBlock{Name: a.DisplayName, Steps: steps})
		names = append(names, a.DisplayName)
	}

	nodeVersion := agents.MaxNodeVersion(specs)
	if nodeVersion == "" && len(npm) > 0 {
		nodeVersion = "22"
	}
	nodeImage := ""
	if nodeVersion != "" {
		if nodeImage, err = imageOverride("RIG_NODE_IMAGE", "node:"+nodeVersion+"-bookworm-slim"); err != nil {
			return nil, err
		}
	}

	plan, err := planMCP(profile, eff, specs)
	if err != nil {
		return nil, err
	}
	helper := plan.needsHelper || eff.NeedsGateway

	files := map[string][]byte{
		"rig/rig-entrypoint": []byte(entrypointScript),
		"rig/home/.bashrc":   []byte(bashrc(profile.Name, eff.Level, names)),
	}
	agentBin := false
	if mode := eff.AgentPermissions; mode == config.PermissionsEdit || mode == config.PermissionsFull {
		for _, a := range specs {
			if args := a.PermissionArgs[mode]; len(args) > 0 && commandNameRe.MatchString(a.Command) {
				files["rig/bin/"+a.Command] = []byte(permissionWrapper(a.Command, mode, args))
				agentBin = true
			}
		}
	}
	for p, b := range plan.homeFiles {
		files["rig/home/"+p] = b
	}
	// COPY rig/ /etc/rig/ puts these at /etc/rig/<path>, where the MCP
	// guard and the policy install steps look for them.
	for p, b := range plan.etcFiles {
		files["rig/"+p] = b
	}
	if plan.claudeMCP != nil {
		files["rig/claude-mcp.json"] = plan.claudeMCP
	}
	if helper {
		if err := addHelperSource(files, "rig-helper-src/"); err != nil {
			return nil, err
		}
	}

	data := dockerfileData{
		ProfileName:    profile.Name,
		BaseImage:      baseImage,
		GoImage:        goImage,
		Helper:         helper,
		NodeImage:      nodeImage,
		SystemPackages: packages,
		PipPackages:    quoteAll(pip),
		NPMPackages:    quoteAll(npm),
		AgentBlocks:    blocks,
		UID:            sandboxUID,
		Sudo:           eff.Sudo,
		ClaudePolicy:   plan.etcFiles["policy/claude-managed-settings.json"] != nil,
		GeminiPolicy:   plan.etcFiles["policy/gemini-system-settings.json"] != nil,
		AgentBin:       agentBin,
	}

	// The hash covers the Dockerfile (rendered without it) and every file.
	unlabeled, err := renderDockerfile(data)
	if err != nil {
		return nil, err
	}
	hash := contextHash(unlabeled, files)
	data.Hash = hash
	df, err := renderDockerfile(data)
	if err != nil {
		return nil, err
	}
	files["rig/version"] = []byte(hash + "\n")
	return &BuildContext{Dockerfile: df, Files: files, Hash: hash}, nil
}

var commandNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// permissionWrapper runs an agent with the flags for a permission mode. It
// lives in /etc/rig/bin, first on PATH and read-only to the agent, and finds
// the real program further along PATH.
func permissionWrapper(command, mode string, args []string) string {
	return `#!/bin/sh
# Rig: run ` + command + ` with agent_permissions: ` + mode + `. Generated by rig.
real=$(PATH=$(printf '%s' "$PATH" | tr ':' '\n' | grep -vx /etc/rig/bin | paste -sd: -) command -v ` + command + `) || {
  echo "rig: ` + command + ` is not installed" >&2
  exit 127
}
exec "$real" ` + quoteAll(args) + ` "$@"
`
}

func renderDockerfile(d dockerfileData) (string, error) {
	var buf bytes.Buffer
	if err := dockerfileTmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()) + "\n", nil
}

func contextHash(dockerfile string, files map[string][]byte) string {
	h := sha256.New()
	h.Write([]byte(dockerfile))
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		h.Write([]byte{0})
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(files[p])
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// addHelperSource copies rig-helper's embedded source into the context under
// prefix, with a minimal go.mod. Tests are left out.
func addHelperSource(files map[string][]byte, prefix string) error {
	files[prefix+"go.mod"] = []byte("module " + rig.ModulePath + "\n\ngo 1.25\n")
	return fs.WalkDir(rig.HelperSource, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := rig.HelperSource.ReadFile(path)
		if err != nil {
			return err
		}
		files[prefix+path] = b
		return nil
	})
}

// GenerateDockerfile renders just the Dockerfile, for `rig inspect`.
func GenerateDockerfile(profile *config.Profile) (string, error) {
	ctx, err := GenerateContext(profile)
	if err != nil {
		return "", err
	}
	return ctx.Dockerfile, nil
}
