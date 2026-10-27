package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/FolksyPizza/rig/internal/security"
)

// StateRoot is where Rig keeps runtime state: proxy and gateway configuration
// and audit logs. It honors XDG_STATE_HOME.
func StateRoot() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "rig"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".local", "state", "rig"), nil
}

// StateDir returns (creating it) a per-profile state subdirectory such as
// "proxy" or "gateway". Directories are private to the user.
func StateDir(profile, sub string) (string, error) {
	if err := security.ValidateProfileName(profile); err != nil {
		return "", err
	}
	root, err := StateRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "profiles", profile, sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// AuditPath is the profile's audit log.
func AuditPath(profile string) (string, error) {
	dir, err := StateDir(profile, "audit")
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}

// RemoveState deletes a profile's runtime state.
func RemoveState(profile string) error {
	if err := security.ValidateProfileName(profile); err != nil {
		return err
	}
	root, err := StateRoot()
	if err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(root, "profiles", profile))
}
