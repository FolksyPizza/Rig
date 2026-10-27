package gitbroker

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type recorded struct {
	method, path, query, auth string
	body                      []byte
}

type fakeUpstream struct {
	mu   sync.Mutex
	reqs []recorded
	srv  *httptest.Server
}

func newFakeUpstream(t *testing.T, status int) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body})
		f.mu.Unlock()
		if status != http.StatusOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(status)
		fmt.Fprint(w, "upstream-response")
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpstream) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded{}, f.reqs...)
}

func newBroker(t *testing.T, up *fakeUpstream) *httptest.Server {
	t.Helper()
	b, err := New(Config{
		Host: "github.com",
		Repos: []Repo{
			{Name: "FolksyPizza/rig", Access: "write", Branches: []string{"claude/*", "feature/**"}},
			{Name: "FolksyPizza/docs", Access: "read"},
			{Name: "FolksyPizza/tags-ok", Access: "write", Tags: true, Delete: true},
		},
	}, "secret-token", up.srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	return srv
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	oidA = "1111111111111111111111111111111111111111"
	oidB = "2222222222222222222222222222222222222222"
	zero = "0000000000000000000000000000000000000000"
)

func pushBody(updates ...string) string {
	var sb strings.Builder
	for i, u := range updates {
		if i == 0 {
			u += "\x00report-status side-band-64k"
		}
		sb.WriteString(pkt(u + "\n"))
	}
	sb.WriteString("0000")
	sb.WriteString("PACK-DATA-FOLLOWS")
	return sb.String()
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/x-git-receive-pack-request", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestFetchFromListedRepoAddsToken(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)

	resp, err := http.Get(srv.URL + "/github.com/FolksyPizza/docs.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-response" {
		t.Fatalf("fetch discovery failed: %d %q", resp.StatusCode, body)
	}
	reqs := up.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected one upstream request, got %d", len(reqs))
	}
	if reqs[0].path != "/FolksyPizza/docs.git/info/refs" || reqs[0].query != "service=git-upload-pack" {
		t.Errorf("unexpected upstream path %q?%q", reqs[0].path, reqs[0].query)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:secret-token"))
	if reqs[0].auth != want {
		t.Errorf("token not attached upstream: %q", reqs[0].auth)
	}
	if strings.Contains(string(body), "secret-token") {
		t.Error("token leaked into the response")
	}
}

func TestRepoMatchingIsCaseInsensitive(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	resp, _ := http.Get(srv.URL + "/GitHub.com/folksypizza/DOCS/info/refs?service=git-upload-pack")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("case-insensitive repo match failed: %d", resp.StatusCode)
	}
}

func TestUnlistedRepoIsRefused(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	resp, _ := http.Get(srv.URL + "/github.com/someone/else.git/info/refs?service=git-upload-pack")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlisted repo got %d, want 403", resp.StatusCode)
	}
	if len(up.requests()) != 0 {
		t.Error("a refused request must not reach upstream")
	}
}

func TestReadOnlyRepoRefusesPush(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	resp, _ := http.Get(srv.URL + "/github.com/FolksyPizza/docs.git/info/refs?service=git-receive-pack")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("push discovery on read-only repo got %d, want 403", resp.StatusCode)
	}
	resp = post(t, srv.URL+"/github.com/FolksyPizza/docs.git/git-receive-pack", pushBody(oidA+" "+oidB+" refs/heads/main"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("push to read-only repo got %d, want 403", resp.StatusCode)
	}
	if len(up.requests()) != 0 {
		t.Error("refused pushes must not reach upstream")
	}
}

func TestPushToAllowedBranchIsForwardedVerbatim(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	body := pushBody(oidA+" "+oidB+" refs/heads/claude/fix-bug", oidA+" "+oidB+" refs/heads/feature/a/b")
	resp := post(t, srv.URL+"/github.com/FolksyPizza/rig.git/git-receive-pack", body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("allowed push got %d", resp.StatusCode)
	}
	reqs := up.requests()
	if len(reqs) != 1 || !bytes.Equal(reqs[0].body, []byte(body)) {
		t.Fatalf("push body was not forwarded verbatim: %+v", reqs)
	}
}

func TestPushRefusals(t *testing.T) {
	cases := []struct {
		name, repo, update string
	}{
		{"branch outside patterns", "rig", oidA + " " + oidB + " refs/heads/main"},
		{"single star does not cross slashes", "rig", oidA + " " + oidB + " refs/heads/claude/a/b"},
		{"deleting a branch", "rig", oidA + " " + zero + " refs/heads/claude/old"},
		{"pushing a tag", "rig", zero + " " + oidB + " refs/tags/v1.0"},
		{"pushing a non-branch ref", "tags-ok", zero + " " + oidB + " refs/notes/commits"},
		{"dot-dot in a ref name", "tags-ok", oidA + " " + oidB + " refs/heads/claude/../main"},
		{"lock suffix", "tags-ok", oidA + " " + oidB + " refs/heads/claude/x.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := newFakeUpstream(t, http.StatusOK)
			srv := newBroker(t, up)
			resp := post(t, srv.URL+"/github.com/FolksyPizza/"+tc.repo+".git/git-receive-pack", pushBody(tc.update))
			msg, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("got %d (%s), want 403", resp.StatusCode, msg)
			}
			if len(up.requests()) != 0 {
				t.Error("a refused push reached upstream")
			}
		})
	}
}

func TestTagsAndDeletesWhenEnabled(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	resp := post(t, srv.URL+"/github.com/FolksyPizza/tags-ok.git/git-receive-pack",
		pushBody(zero+" "+oidB+" refs/tags/v1.0", oidA+" "+zero+" refs/heads/old"))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("enabled tag push and delete got %d", resp.StatusCode)
	}
}

func TestOneBadRefRefusesTheWholePush(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)
	resp := post(t, srv.URL+"/github.com/FolksyPizza/rig.git/git-receive-pack",
		pushBody(oidA+" "+oidB+" refs/heads/claude/ok", oidA+" "+oidB+" refs/heads/main"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(up.requests()) != 0 {
		t.Errorf("a push touching a forbidden ref must be refused entirely: %d", resp.StatusCode)
	}
}

func TestMalformedAndUnsupportedRequests(t *testing.T) {
	up := newFakeUpstream(t, http.StatusOK)
	srv := newBroker(t, up)

	resp := post(t, srv.URL+"/github.com/FolksyPizza/rig.git/git-receive-pack", "zzzz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed push got %d, want 400", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github.com/FolksyPizza/rig.git/git-receive-pack",
		strings.NewReader(pushBody(oidA+" "+oidB+" refs/heads/claude/x")))
	req.Header.Set("Content-Encoding", "gzip")
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("compressed push got %d, want 415", r2.StatusCode)
	}

	for _, p := range []string{
		"/github.com/FolksyPizza/rig.git/objects/info/packs", // dumb protocol
		"/github.com/FolksyPizza/rig.git/info/refs",          // no service
		"/gitlab.com/FolksyPizza/rig.git/info/refs?service=git-upload-pack",
		"/github.com/FolksyPizza/../x.git/info/refs?service=git-upload-pack",
	} {
		r, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden && r.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %s got %d, want 400 or 403", p, r.StatusCode)
		}
	}
	if len(up.requests()) != 0 {
		t.Error("none of these requests should reach upstream")
	}
}

func TestUpstreamAuthChallengeIsNotPassedOn(t *testing.T) {
	up := newFakeUpstream(t, http.StatusUnauthorized)
	srv := newBroker(t, up)
	resp, _ := http.Get(srv.URL + "/github.com/FolksyPizza/docs.git/info/refs?service=git-upload-pack")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want the upstream 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Error("WWW-Authenticate must be dropped so git does not prompt for credentials")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	bad := []Config{
		{Host: "", Repos: nil},
		{Host: "github.com", Repos: []Repo{{Name: "noslash", Access: "read"}}},
		{Host: "github.com", Repos: []Repo{{Name: "a/b", Access: "admin"}}},
		{Host: "github.com", Repos: []Repo{{Name: "a/..", Access: "read"}}},
		{Host: "github.com", Repos: []Repo{{Name: "a/b", Access: "write", Branches: []string{"bad pattern"}}}},
	}
	for i, cfg := range bad {
		if _, err := New(cfg, "", "https://github.com", nil); err == nil {
			t.Errorf("case %d: New succeeded, want error", i)
		}
	}
}

func TestGlobRegexp(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"claude/*", "claude/x", true},
		{"claude/*", "claude/x/y", false},
		{"claude/**", "claude/x/y", true},
		{"release-?", "release-1", true},
		{"release-?", "release-10", false},
		{"a.b", "aXb", false}, // dots are literal
	}
	for _, tc := range cases {
		re, err := globRegexp(tc.pat)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.MatchString(tc.name); got != tc.want {
			t.Errorf("glob %q vs %q = %v, want %v", tc.pat, tc.name, got, tc.want)
		}
	}
}
