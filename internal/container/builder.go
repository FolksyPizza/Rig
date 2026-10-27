package container

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/FolksyPizza/rig/internal/agents"
	"github.com/FolksyPizza/rig/internal/config"
	"github.com/FolksyPizza/rig/internal/provider"
)

type BuildEvent struct {
	Stream string
}

type Builder struct {
	bin  string
	kind string
}

func NewBuilder() (*Builder, error) {
	p := provider.Detect()
	if !p.Available() {
		return nil, fmt.Errorf("no container engine found (looked for %s and fallbacks)", p.Name())
	}
	kind := ""
	if p.Name() == "apple" {
		kind = "apple"
	}
	return &Builder{bin: p.Bin(), kind: kind}, nil
}

func (b *Builder) Close() {}

// Build builds the image for a profile, streaming progress to onEvent.
func (b *Builder) Build(ctx context.Context, profile *config.Profile, onEvent func(BuildEvent)) error {
	return b.BuildWithOpts(ctx, profile, false, onEvent)
}

// writeContext materializes a build context in a fresh private directory.
func writeContext(dockerfile string, files map[string][]byte) (string, error) {
	dir, err := os.MkdirTemp("", "rig-build-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	for p, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if !strings.HasPrefix(full, dir+string(os.PathSeparator)) {
			os.RemoveAll(dir)
			return "", fmt.Errorf("build context path %q escapes the context", p)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, "rig-entrypoint") {
			mode = 0o755
		}
		if err := os.WriteFile(full, data, mode); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// BuildWithOpts builds the image for a profile.
//
// The build context is generated in full: it holds the Dockerfile, Rig's
// generated configuration, and (when needed) rig-helper's source. Nothing is
// copied from the user's files.
func (b *Builder) BuildWithOpts(ctx context.Context, profile *config.Profile, noCache bool, onEvent func(BuildEvent)) error {
	bc, err := GenerateContext(profile)
	if err != nil {
		return fmt.Errorf("generate build context: %w", err)
	}
	return b.buildDir(ctx, profile.ImageTag(), bc.Dockerfile, bc.Files, noCache, onEvent)
}

func (b *Builder) buildDir(ctx context.Context, tag, dockerfile string, files map[string][]byte, noCache bool, onEvent func(BuildEvent)) error {
	dir, err := writeContext(dockerfile, files)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	args := []string{"build", "-t", tag, "-f", filepath.Join(dir, "Dockerfile")}
	if noCache {
		args = append(args, "--no-cache")
	}
	if b.kind != "apple" {
		// Plain progress is line-oriented and readable once captured.
		args = append(args, "--progress=plain")
	}
	args = append(args, dir)

	cmd := exec.CommandContext(ctx, b.bin, args...)
	pipeRead, pipeWrite := io.Pipe()
	cmd.Stdout = pipeWrite
	cmd.Stderr = pipeWrite
	if err := cmd.Start(); err != nil {
		_ = pipeWrite.Close()
		return fmt.Errorf("start build: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(pipeRead)
		// Build logs can contain very long lines (npm output, base64 blobs).
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			if onEvent != nil {
				onEvent(BuildEvent{Stream: scanner.Text()})
			}
		}
	}()

	waitErr := cmd.Wait()
	_ = pipeWrite.Close()
	<-done
	_ = pipeRead.Close()
	if waitErr != nil {
		return fmt.Errorf("build failed: %w", waitErr)
	}
	return nil
}

// imageLabel reads one label from a local image, or "" if it is missing.
func (b *Builder) imageLabel(ctx context.Context, tag, label string) string {
	out, err := exec.CommandContext(ctx, b.bin, "image", "inspect", tag).Output()
	if err != nil {
		return ""
	}
	// Docker and Podman put labels in Config.Labels (Podman also at the top
	// level); Apple nests them differently, so all are tried.
	var items []map[string]json.RawMessage
	if json.Unmarshal(out, &items) != nil || len(items) == 0 {
		return ""
	}
	var cfg struct {
		Labels map[string]string `json:"Labels"`
	}
	if raw, ok := items[0]["Config"]; ok && json.Unmarshal(raw, &cfg) == nil && cfg.Labels[label] != "" {
		return cfg.Labels[label]
	}
	var top map[string]string
	if raw, ok := items[0]["Labels"]; ok && json.Unmarshal(raw, &top) == nil {
		return top[label]
	}
	return ""
}

// ImageUpToDate reports whether the profile's image exists and was built from
// the current profile. A missing or stale image needs a build.
func (b *Builder) ImageUpToDate(ctx context.Context, profile *config.Profile) (exists, current bool, err error) {
	if !b.ImageExists(ctx, profile.ImageTag()) {
		return false, false, nil
	}
	bc, err := GenerateContext(profile)
	if err != nil {
		return true, false, err
	}
	return true, b.imageLabel(ctx, profile.ImageTag(), "rig.build-hash") == bc.Hash, nil
}

func (b *Builder) ImageExists(ctx context.Context, tag string) bool {
	return exec.CommandContext(ctx, b.bin, "image", "inspect", tag).Run() == nil
}

// RemoveImage deletes a profile's image. A missing image is not an error.
func (b *Builder) RemoveImage(ctx context.Context, tag string) error {
	if !b.ImageExists(ctx, tag) {
		return nil
	}
	rm := exec.CommandContext(ctx, b.bin, "rmi", "-f", tag)
	if b.kind == "apple" {
		rm = exec.CommandContext(ctx, b.bin, "image", "rm", tag)
	}
	if out, err := rm.CombinedOutput(); err != nil {
		return fmt.Errorf("remove image %s: %s", tag, out)
	}
	return nil
}

// helperDockerfile builds rig-helper into an image that contains nothing else:
// no shell, no package manager, just the static binary and CA certificates.
// The egress proxy runs from it.
const helperDockerfileTmpl = `FROM %s AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/rig-helper ./cmd/rig-helper

FROM scratch
LABEL rig.role="helper"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/rig-helper /rig-helper
USER 65532:65532
ENTRYPOINT ["/rig-helper"]
`

// HelperContext returns the helper image's tag and build context. The tag is
// derived from the helper's source, so each rig version gets matching helpers.
func HelperContext() (string, string, map[string][]byte, error) {
	goImage, err := imageOverride("RIG_GO_IMAGE", defaultGoImage)
	if err != nil {
		return "", "", nil, err
	}
	files := map[string][]byte{}
	if err := addHelperSource(files, ""); err != nil {
		return "", "", nil, err
	}
	df := fmt.Sprintf(helperDockerfileTmpl, goImage)
	h := sha256.New()
	h.Write([]byte(df))
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(files[p])
	}
	tag := "rig/helper:" + hex.EncodeToString(h.Sum(nil))[:16]
	return tag, df, files, nil
}

// EnsureHelperImage builds the helper image if this version's is missing.
func (b *Builder) EnsureHelperImage(ctx context.Context, onEvent func(BuildEvent)) (string, error) {
	tag, df, files, err := HelperContext()
	if err != nil {
		return "", err
	}
	if b.ImageExists(ctx, tag) {
		return tag, nil
	}
	if onEvent != nil {
		onEvent(BuildEvent{Stream: "Building Rig helper image " + tag})
	}
	if err := b.buildDir(ctx, tag, df, files, false, onEvent); err != nil {
		return "", fmt.Errorf("build helper image: %w", err)
	}
	return tag, nil
}

// VerifyAgents runs each agent's verify command in the built image, offline,
// and returns the agents whose check failed.
func (b *Builder) VerifyAgents(ctx context.Context, profile *config.Profile) ([]string, error) {
	ids := make([]string, 0, len(profile.Agents))
	for _, a := range profile.Agents {
		ids = append(ids, a.ID)
	}
	specs, err := agents.Resolve(ids)
	if err != nil {
		return nil, err
	}
	var script []string
	for _, s := range specs {
		if s.VerifyCommand == "" {
			continue
		}
		script = append(script, fmt.Sprintf("(%s) >/dev/null 2>&1 || echo %s", s.VerifyCommand, shellQuote(s.ID)))
	}
	if len(script) == 0 {
		return nil, nil
	}
	args := []string{"run", "--rm", "--network", "none", "--cap-drop", "ALL", "--entrypoint", "/bin/sh"}
	if b.kind == "apple" {
		args = []string{"run", "--rm", "--entrypoint", "/bin/sh"}
	}
	args = append(args, profile.ImageTag(), "-c", strings.Join(script, "; "))
	out, err := exec.CommandContext(ctx, b.bin, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("verify agents: %w", err)
	}
	var failed []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			failed = append(failed, line)
		}
	}
	return failed, nil
}
