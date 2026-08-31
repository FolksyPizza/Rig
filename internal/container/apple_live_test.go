//go:build integration

package container

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestLiveAppleLifecycle exercises the Apple `container` lifecycle paths (list-by-label,
// ProfileOf, exec) against a real running container. Needs the container service up.
// Run with:  go test -tags integration -run LiveApple -v ./internal/container
func TestLiveAppleLifecycle(t *testing.T) {
	r, err := NewRunner()
	if err != nil || r.kind != "apple" {
		t.Skipf("apple container runner not selected (err=%v kind=%q)", err, r.kind)
	}
	ctx := context.Background()
	const name = "rig-lifetest"
	const profileName = "lifetest"

	_ = exec.Command("container", "stop", name).Run()
	_ = exec.Command("container", "rm", name).Run()

	create := exec.CommandContext(ctx, "container", "create", "--name", name,
		"--label", LabelProfile+"="+profileName,
		"--label", LabelRole+"="+RoleSandbox,
		"docker.io/library/alpine:latest", "sleep", "3600")
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create failed: %s (%v)", out, err)
	}
	if out, err := exec.CommandContext(ctx, "container", "start", name).CombinedOutput(); err != nil {
		t.Fatalf("start failed: %s (%v)", out, err)
	}
	defer func() {
		_ = exec.Command("container", "stop", name).Run()
		_ = exec.Command("container", "rm", name).Run()
	}()
	time.Sleep(2 * time.Second)

	// appleList + client-side label filter must find the running sandbox.
	found := r.ListByProfile(ctx, profileName)
	if len(found) == 0 || found[0].Name != name {
		t.Fatalf("ListByProfile(%q) did not find the container: %+v", profileName, found)
	}
	if !found[0].Running {
		t.Errorf("expected running, got status %q", found[0].Status)
	}
	t.Logf("listed: name=%s image=%s status=%s", found[0].Name, found[0].Image, found[0].Status)

	// ProfileOf resolves the label back to the profile.
	if p, err := r.ProfileOf(ctx, name); err != nil || p != profileName {
		t.Fatalf("ProfileOf = %q, err = %v; want %q", p, err, profileName)
	}

	// Exec into the running sandbox.
	if err := r.Exec(ctx, name, []string{"/bin/sh", "-c", "echo lifecheck-ok"}); err != nil {
		t.Fatalf("exec failed: %v", err)
	}
}
