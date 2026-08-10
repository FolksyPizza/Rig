package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/FolksyPizza/rig/internal/security"
)

type Store struct {
	dir string
}

func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "rig", "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create profiles dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the directory profiles are stored in.
func (s *Store) Dir() string { return s.dir }

// path builds the on-disk path for a profile. The name is validated first:
// without that check a name like "../../../.ssh/authorized_keys" would let an
// imported profile read or write files anywhere the user can.
func (s *Store) path(name string) (string, error) {
	if err := security.ValidateProfileName(name); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, name+".yaml"), nil
}

func (s *Store) Save(p *Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	path, err := s.path(p.Name)
	if err != nil {
		return err
	}
	p.Metadata.ImageTag = p.ImageTag()
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

func (s *Store) Load(name string) (*Profile, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	// A profile on disk may have been hand-edited or written by an older
	// version, so it is validated on the way in as well as on the way out.
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile %q is invalid: %w", name, err)
	}
	return &p, nil
}

func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return names, nil
}

func (s *Store) Delete(name string) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func (s *Store) Exists(name string) bool {
	path, err := s.path(name)
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr == nil
}

// Export writes a profile to an arbitrary path for sharing. Metadata is
// stripped; env values keep their ${VAR} references so no secret is written.
func (s *Store) Export(p *Profile, path string) error {
	clean := *p
	clean.Metadata = Metadata{}
	data, err := yaml.Marshal(&clean)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// Import reads a shared profile file and saves it. The file is untrusted
// input: Save validates every field, including the name used as a filename.
func (s *Store) Import(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if err := s.Save(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ResolveEnvVars expands "${VAR}" values against the host environment. Values
// that do not use the reference form are passed through unchanged.
func ResolveEnvVars(env map[string]string) map[string]string {
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		if name, ok := strings.CutPrefix(v, "${"); ok {
			if name, ok := strings.CutSuffix(name, "}"); ok {
				resolved[k] = os.Getenv(name)
				continue
			}
		}
		resolved[k] = v
	}
	return resolved
}

// MissingEnvVars returns the names of ${VAR} references in a profile that are
// unset or empty in the host environment, so the CLI can warn before launch
// instead of starting an agent that will fail to authenticate.
func MissingEnvVars(p *Profile) []string {
	var missing []string
	seen := make(map[string]bool)
	for _, a := range p.Agents {
		for key, v := range a.Env {
			name, ok := strings.CutPrefix(v, "${")
			if !ok {
				continue
			}
			name, ok = strings.CutSuffix(name, "}")
			if !ok {
				continue
			}
			if os.Getenv(name) == "" && !seen[key] {
				seen[key] = true
				missing = append(missing, name)
			}
		}
	}
	return missing
}
