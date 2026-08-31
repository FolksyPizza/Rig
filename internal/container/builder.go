package container

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

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

// BuildWithOpts builds the image for a profile.
//
// The build context is an empty temporary directory: the Dockerfile is fully
// generated and copies nothing from the host, so there is no reason to hand
// the daemon any of the user's files.
func (b *Builder) BuildWithOpts(ctx context.Context, profile *config.Profile, noCache bool, onEvent func(BuildEvent)) error {
	dockerfile, err := GenerateDockerfile(profile)
	if err != nil {
		return fmt.Errorf("generate dockerfile: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "rig-build-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dfPath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dfPath, []byte(dockerfile), 0o600); err != nil {
		return fmt.Errorf("write dockerfile: %w", err)
	}

	args := []string{"build", "-t", profile.ImageTag(), "-f", dfPath}
	if noCache {
		args = append(args, "--no-cache")
	}
	// BuildKit reports progress on stderr in a TTY-oriented format that is
	// unreadable once captured; plain progress gives line-oriented output.
	args = append(args, "--progress=plain", tmpDir)

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
		// Build logs can contain very long lines (npm output, base64 blobs);
		// the default 64 KiB limit would abort the scan partway through.
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

func (b *Builder) ImageExists(ctx context.Context, tag string) bool {
	// `image inspect` is supported by docker, podman, and Apple `container` alike.
	return exec.CommandContext(ctx, b.bin, "image", "inspect", tag).Run() == nil
}

// RemoveImage deletes a profile's image. A missing image is not an error.
func (b *Builder) RemoveImage(ctx context.Context, tag string) error {
	if !b.ImageExists(ctx, tag) {
		return nil
	}
	// Apple uses `image rm`; docker/podman use `rmi -f`.
	rm := exec.CommandContext(ctx, b.bin, "rmi", "-f", tag)
	if b.kind == "apple" {
		rm = exec.CommandContext(ctx, b.bin, "image", "rm", tag)
	}
	if out, err := rm.CombinedOutput(); err != nil {
		return fmt.Errorf("remove image %s: %s", tag, out)
	}
	return nil
}
