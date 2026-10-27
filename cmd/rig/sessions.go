package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FolksyPizza/rig/internal/config"
)

// Rig records each process attached to a sandbox (rig run, shell, exec) in
// the profile's state directory. Monitoring runs inside those processes, so
// when the last one leaves a persistent sandbox Rig stops it: nothing keeps
// running in a sandbox that no Rig process is watching, unless you asked for
// that with --keep-running.

type session struct {
	path string
	stop chan struct{}
}

// Sessions refresh their record's timestamp while they run, so a record left
// behind by a process that died (or a PID reused after a reboot) stops
// counting once the heartbeat is stale.
const (
	sessionHeartbeat = 30 * time.Second
	sessionStale     = 2 * time.Minute
)

func sessionDir(profile string) (string, error) { return config.StateDir(profile, "sessions") }

// openSession registers this process as attached to a container.
func openSession(profile, container string) *session {
	dir, err := sessionDir(profile)
	if err != nil {
		return nil
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.%d", container, os.Getpid()))
	if os.WriteFile(path, nil, 0o600) != nil {
		return nil
	}
	s := &session{path: path, stop: make(chan struct{})}
	go func() {
		t := time.NewTicker(sessionHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case now := <-t.C:
				_ = os.Chtimes(path, now, now)
			}
		}
	}()
	return s
}

func (s *session) close() {
	if s != nil {
		close(s.stop)
		_ = os.Remove(s.path)
	}
}

// otherSessions returns the PIDs of other live Rig processes attached to a
// container, removing records left by processes that have exited.
func otherSessions(profile, container string) []int {
	dir, err := sessionDir(profile)
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		name := e.Name()
		i := strings.LastIndexByte(name, '.')
		if i <= 0 || name[:i] != container {
			continue
		}
		pid, err := strconv.Atoi(name[i+1:])
		if err != nil || pid == os.Getpid() {
			continue
		}
		fresh := false
		if info, err := e.Info(); err == nil {
			fresh = time.Since(info.ModTime()) < sessionStale
		}
		if fresh && processAlive(pid) {
			pids = append(pids, pid)
		} else {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	return pids
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	// EPERM means it exists but belongs to someone else.
	return err == nil || errors.Is(err, syscall.EPERM)
}

func keepPath(profile, container string) string {
	dir, err := sessionDir(profile)
	if err != nil {
		return ""
	}
	return filepath.Join(dir, container+".keep")
}

// setKeepRunning marks (or unmarks) a container to stay up between sessions.
func setKeepRunning(profile, container string, keep bool) {
	path := keepPath(profile, container)
	if path == "" {
		return
	}
	if keep {
		_ = os.WriteFile(path, nil, 0o600)
	} else {
		_ = os.Remove(path)
	}
}

func keepRunning(profile, container string) bool {
	path := keepPath(profile, container)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
