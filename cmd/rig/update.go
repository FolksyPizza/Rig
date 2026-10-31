package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FolksyPizza/rig/internal/container"
)

// Releases are published by .github/workflows/release.yml: one binary per
// platform, named rig-<os>-<arch>, and a SHA256SUMS file covering them.
const (
	releaseRepo = "FolksyPizza/Rig"
	releaseAPI  = "https://api.github.com/repos/" + releaseRepo + "/releases/latest"
	installURL  = "https://raw.githubusercontent.com/" + releaseRepo + "/main/install.sh"
)

func updateCmd() *cobra.Command {
	var check, force bool
	cmd := &cobra.Command{
		Use:   "update [name]",
		Short: "Update Rig itself, or a sandbox's agents to their latest versions",
		Long: `Update Rig, or the agents in a sandbox.

  rig update              install the latest Rig release (checksum verified)
  rig update --check      only say whether a newer release exists
  rig update work         rebuild the work sandbox with the latest agent versions

Updating Rig replaces this program in place; if it lives somewhere you cannot
write, run the install script again with the access it needs:
  curl -fsSL ` + installURL + ` | sh`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return updateSandbox(args[0])
			}
			return selfUpdate(check, force)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only check for a newer release")
	cmd.Flags().BoolVar(&force, "force", false, "reinstall even if this version is current")
	return cmd
}

// updateSandbox rebuilds a sandbox's image without the cache, which installs
// the newest version of each agent that is not pinned.
func updateSandbox(name string) error {
	_, p, err := loadProfile(name)
	if err != nil {
		return err
	}
	eff := p.Resolve()
	if _, err := engineFor(eff); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	b, err := container.NewBuilder()
	if err != nil {
		return err
	}
	fmt.Printf("  Rebuilding %s with the latest agent versions...\n", p.ImageTag())
	if err := b.BuildWithOpts(ctx, p, true, func(e container.BuildEvent) { fmt.Println(e.Stream) }); err != nil {
		return err
	}
	if failed, err := b.VerifyAgents(ctx, p); err == nil && len(failed) > 0 {
		return fmt.Errorf("these agents did not install correctly: %s", strings.Join(failed, ", "))
	}
	fmt.Printf("  Updated %s's agents.\n", p.Name)
	if !eff.Ephemeral {
		fmt.Printf("  An existing container keeps the old versions until you run 'rig run %s --recreate' (home and workspace volumes are kept).\n", p.Name)
	}
	return nil
}

type release struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (r release) asset(name string) string {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

// selfUpdate replaces this program with the latest release for this
// platform, after checking it against the release's SHA256SUMS.
func selfUpdate(checkOnly, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rel, err := latestRelease(ctx)
	if err != nil {
		return err
	}
	current := version
	if rel.Tag == current && !force {
		fmt.Printf("  rig %s is the latest release.\n", current)
		return nil
	}
	fmt.Printf("  Installed: %s   Latest release: %s\n", current, rel.Tag)
	if checkOnly {
		fmt.Println("  Install it with: rig update")
		return nil
	}

	assetName := fmt.Sprintf("rig-%s-%s", runtime.GOOS, runtime.GOARCH)
	binURL, sumsURL := rel.asset(assetName), rel.asset("SHA256SUMS")
	if binURL == "" || sumsURL == "" {
		return fmt.Errorf("release %s has no build for %s/%s; build from source instead (see the README)", rel.Tag, runtime.GOOS, runtime.GOARCH)
	}
	sums, err := fetch(ctx, sumsURL, 1<<20)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	want := checksumFor(string(sums), assetName)
	if want == "" {
		return fmt.Errorf("SHA256SUMS in release %s does not list %s", rel.Tag, assetName)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	tmp, err := os.CreateTemp(filepath.Dir(self), ".rig-update-*")
	if err != nil {
		return fmt.Errorf("cannot write next to %s (%v); run the install script instead:\n  curl -fsSL %s | sh", self, err, installURL)
	}
	defer os.Remove(tmp.Name())
	fmt.Printf("  Downloading %s...\n", assetName)
	if err := download(ctx, binURL, tmp, 256<<20); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, tmp); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s (got %s, want %s); nothing was changed", assetName, got, want)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), self); err != nil {
		return fmt.Errorf("replace %s: %w", self, err)
	}
	fmt.Printf("  Updated rig to %s (checksum verified).\n", rel.Tag)
	return nil
}

func latestRelease(ctx context.Context) (release, error) {
	data, err := fetch(ctx, releaseAPI, 4<<20)
	if err != nil {
		var nf errNotFound
		if errors.As(err, &nf) {
			return release{}, fmt.Errorf("no Rig release has been published yet; update from source:\n  curl -fsSL %s | sh", installURL)
		}
		return release{}, fmt.Errorf("check for updates: %w", err)
	}
	var rel release
	if err := json.Unmarshal(data, &rel); err != nil || rel.Tag == "" {
		return release{}, fmt.Errorf("could not read the latest release from GitHub")
	}
	return rel, nil
}

// checksumFor finds a file's hash in SHA256SUMS ("<hash>  <name>" lines).
func checksumFor(sums, name string) string {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

type errNotFound struct{ url string }

func (e errNotFound) Error() string { return e.url + ": not found" }

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rig/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, errNotFound{url}
	case resp.StatusCode != http.StatusOK:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp, nil
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func download(ctx context.Context, url string, w io.Writer, limit int64) error {
	resp, err := get(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("%s is larger than expected", url)
	}
	return nil
}
