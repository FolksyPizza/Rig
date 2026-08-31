// Package provider abstracts the container runtime so Rig is not tied to Docker.
//
// macOS uses Apple's native `container`; Linux and Windows use Podman (both daemonless),
// with Docker as a compatible fallback. The interface exposes just what lifecycle and the
// watchdog need; Podman and Docker share Docker's CLI, so one implementation covers both.
package provider

import (
	"context"
	"os/exec"
	goruntime "runtime"
	"strings"
)

// Stats is a point-in-time resource sample for one container.
type Stats struct {
	CPUPercent float64
	MemBytes   int64
	MemLimit   int64
	PIDs       int
}

type Provider interface {
	Name() string
	Bin() string
	Available() bool
	Stats(ctx context.Context, name string) (Stats, error)
	Stop(ctx context.Context, name string) error
	Kill(ctx context.Context, name string) error
	List(ctx context.Context) ([]string, error)
}

// lookPath is overridable in tests.
var lookPath = exec.LookPath

func Docker() Provider { return &dockerCLI{name: "docker", bin: "docker"} }
func Podman() Provider { return &dockerCLI{name: "podman", bin: "podman"} }
func Apple() Provider  { return &appleCLI{} }

// Detect chooses a provider for this OS, preferring the native/daemonless option.
func Detect() Provider {
	return detect(goruntime.GOOS, func(bin string) bool {
		_, err := lookPath(bin)
		return err == nil
	})
}

func detect(goos string, has func(string) bool) Provider {
	var order []Provider
	switch goos {
	case "darwin":
		order = []Provider{Apple(), Podman(), Docker()}
	default: // linux, windows, and anything else
		order = []Provider{Podman(), Docker()}
	}
	for _, p := range order {
		if has(p.Bin()) {
			return p
		}
	}
	return order[len(order)-1] // report the preferred one even if absent
}

// --- Docker / Podman (shared CLI) ------------------------------------------

type dockerCLI struct{ name, bin string }

func (c *dockerCLI) Name() string { return c.name }
func (c *dockerCLI) Bin() string  { return c.bin }
func (c *dockerCLI) Available() bool {
	_, err := lookPath(c.bin)
	return err == nil
}

func (c *dockerCLI) Stop(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, c.bin, "stop", name).Run()
}

func (c *dockerCLI) Kill(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, c.bin, "kill", name).Run()
}

func (c *dockerCLI) List(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, c.bin, "ps", "-a", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil, err
	}
	return nonEmptyLines(string(out)), nil
}

func (c *dockerCLI) Stats(ctx context.Context, name string) (Stats, error) {
	out, err := exec.CommandContext(ctx, c.bin, "stats", "--no-stream",
		"--format", "{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}", name).Output()
	if err != nil {
		return Stats{}, err
	}
	return parseCLIStats(string(out))
}

// --- Apple `container` ------------------------------------------------------

type appleCLI struct{}

func (a *appleCLI) Name() string { return "apple" }
func (a *appleCLI) Bin() string  { return "container" }
func (a *appleCLI) Available() bool {
	_, err := lookPath("container")
	return err == nil
}

func (a *appleCLI) Stop(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "container", "stop", name).Run()
}

func (a *appleCLI) Kill(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "container", "kill", name).Run()
}

func (a *appleCLI) List(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "container", "ls", "--all", "--format", "json").Output()
	if err != nil {
		return nil, err
	}
	return parseAppleNames(out), nil
}

func (a *appleCLI) Stats(ctx context.Context, name string) (Stats, error) {
	out, err := exec.CommandContext(ctx, "container", "stats", "--no-stream", "--format", "json", name).Output()
	if err != nil {
		return Stats{}, err
	}
	return parseAppleStats(out)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
