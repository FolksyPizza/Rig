// Package gitbroker gives a sandbox git access to specific repositories
// without giving it a credential.
//
// The broker runs in Rig's gateway container. The sandbox's git is pointed at
// it (url.<broker>.insteadOf https://github.com/), and the broker forwards
// smart-HTTP git traffic to the real host only for repositories on its list,
// adding the token itself. The token lives in the gateway's environment and
// never enters the sandbox, so an agent cannot copy it, use it against other
// repositories, or call the host's API with it. Pushes are refused unless the
// repository is writable and every updated ref matches an allowed branch
// pattern; deleting refs and pushing tags are refused unless enabled.
//
// Standard library only: compiled into rig-helper inside an image build.
package gitbroker

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Repo is one repository the sandbox may use.
type Repo struct {
	Name   string `json:"repo"`   // owner/name
	Access string `json:"access"` // read | write
	// Branches restricts pushes to branches matching these patterns.
	// "*" matches within one path segment, "**" across segments. Empty allows
	// every branch.
	Branches []string `json:"branches,omitempty"`
	Tags     bool     `json:"tags,omitempty"`   // allow pushing tags
	Delete   bool     `json:"delete,omitempty"` // allow deleting refs
}

// Config configures the broker.
type Config struct {
	Host     string `json:"host"` // e.g. github.com
	Repos    []Repo `json:"repos"`
	TokenEnv string `json:"token_env,omitempty"`
}

// Event is one audit record.
type Event struct {
	TS     string   `json:"ts"`
	Event  string   `json:"event"` // "git"
	Repo   string   `json:"repo"`
	Op     string   `json:"op"` // fetch | push
	Action string   `json:"action"`
	Reason string   `json:"reason,omitempty"`
	Refs   []string `json:"refs,omitempty"`
}

// Broker is an http.Handler mounted at a prefix such as /git.
type Broker struct {
	host     string
	repos    map[string]compiledRepo
	token    string
	upstream *url.URL
	client   *http.Client
	Log      func(Event)
}

type compiledRepo struct {
	Repo
	patterns []*regexp.Regexp
}

var namePart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ValidRepoName reports whether s is an owner/name pair.
func ValidRepoName(s string) bool {
	owner, name, ok := strings.Cut(s, "/")
	return ok && validPart(owner) && validPart(strings.TrimSuffix(name, ".git"))
}

func validPart(s string) bool {
	return namePart.MatchString(s) && s != "." && s != ".."
}

// New builds a broker. upstream is the base URL of the git host, normally
// "https://" + cfg.Host. rt carries upstream requests; nil uses a transport
// that honors HTTPS_PROXY.
func New(cfg Config, token, upstream string, rt http.RoundTripper) (*Broker, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("git broker: host is required")
	}
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("git broker: invalid upstream %q", upstream)
	}
	if rt == nil {
		rt = &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 5 * time.Minute}
	}
	b := &Broker{
		host:     strings.ToLower(cfg.Host),
		repos:    map[string]compiledRepo{},
		token:    token,
		upstream: u,
		client:   &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	for _, r := range cfg.Repos {
		if !ValidRepoName(r.Name) {
			return nil, fmt.Errorf("git broker: invalid repository %q (want owner/name)", r.Name)
		}
		if r.Access != "read" && r.Access != "write" {
			return nil, fmt.Errorf("git broker: repository %q: access must be read or write", r.Name)
		}
		cr := compiledRepo{Repo: r}
		for _, pat := range r.Branches {
			re, err := globRegexp(pat)
			if err != nil {
				return nil, fmt.Errorf("git broker: repository %q: %w", r.Name, err)
			}
			cr.patterns = append(cr.patterns, re)
		}
		b.repos[strings.ToLower(strings.TrimSuffix(r.Name, ".git"))] = cr
	}
	return b, nil
}

// globRegexp converts a branch pattern to an anchored regexp.
func globRegexp(pat string) (*regexp.Regexp, error) {
	if pat == "" || strings.ContainsAny(pat, " \t\n\\") {
		return nil, fmt.Errorf("invalid branch pattern %q", pat)
	}
	var sb strings.Builder
	sb.WriteString("^")
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				sb.WriteString(".*")
				i++
			} else {
				sb.WriteString("[^/]*")
			}
		case '?':
			sb.WriteString("[^/]")
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

func (b *Broker) emit(e Event) {
	if b.Log == nil {
		return
	}
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	e.Event = "git"
	b.Log(e)
}

func (b *Broker) refuse(w http.ResponseWriter, e Event, status int, msg string) {
	e.Action, e.Reason = "deny", msg
	b.emit(e)
	http.Error(w, "Rig git broker: "+msg, status)
}

// ServeHTTP handles /<host>/<owner>/<repo>[.git]/<endpoint>.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 4 || !strings.EqualFold(parts[0], b.host) || !validPart(parts[1]) || !validPart(strings.TrimSuffix(parts[2], ".git")) {
		http.Error(w, "Rig git broker: unrecognized repository path", http.StatusBadRequest)
		return
	}
	owner, name := parts[1], strings.TrimSuffix(parts[2], ".git")
	full := owner + "/" + name
	endpoint := strings.Join(parts[3:], "/")
	ev := Event{Repo: full}

	repo, ok := b.repos[strings.ToLower(full)]
	if !ok {
		ev.Op = "fetch"
		b.refuse(w, ev, http.StatusForbidden, "repository "+full+" is not on this sandbox's list")
		return
	}

	var op string
	switch {
	case r.Method == http.MethodGet && endpoint == "info/refs":
		switch r.URL.Query().Get("service") {
		case "git-upload-pack":
			op = "fetch"
		case "git-receive-pack":
			op = "push"
		default:
			ev.Op = "fetch"
			b.refuse(w, ev, http.StatusForbidden, "only the smart HTTP protocol is supported")
			return
		}
	case r.Method == http.MethodPost && endpoint == "git-upload-pack":
		op = "fetch"
	case r.Method == http.MethodPost && endpoint == "git-receive-pack":
		op = "push"
	default:
		ev.Op = "fetch"
		b.refuse(w, ev, http.StatusForbidden, "unsupported git endpoint "+endpoint)
		return
	}
	ev.Op = op

	if op == "push" && repo.Access != "write" {
		b.refuse(w, ev, http.StatusForbidden, "repository "+full+" is read-only for this sandbox")
		return
	}

	body := io.Reader(r.Body)
	if op == "push" && r.Method == http.MethodPost {
		if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
			b.refuse(w, ev, http.StatusUnsupportedMediaType, "compressed push requests are not supported")
			return
		}
		br := bufio.NewReaderSize(r.Body, 64*1024)
		cmds, consumed, err := readCommands(br, 1<<20)
		if err != nil {
			b.refuse(w, ev, http.StatusBadRequest, "malformed push request: "+err.Error())
			return
		}
		for _, c := range cmds {
			ev.Refs = append(ev.Refs, c.ref)
			if err := repo.allow(c); err != nil {
				b.refuse(w, ev, http.StatusForbidden, err.Error())
				return
			}
		}
		body = io.MultiReader(bytes.NewReader(consumed), br)
	}

	target := *b.upstream
	target.Path = strings.TrimSuffix(b.upstream.Path, "/") + "/" + owner + "/" + name + ".git/" + endpoint
	target.RawQuery = r.URL.RawQuery

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		http.Error(w, "Rig git broker: bad request", http.StatusBadRequest)
		return
	}
	out.ContentLength = r.ContentLength
	for _, h := range []string{"Content-Type", "Accept", "Git-Protocol", "User-Agent", "Content-Encoding"} {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	if b.token != "" {
		out.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+b.token)))
	}

	resp, err := b.client.Do(out)
	if err != nil {
		b.refuse(w, ev, http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer resp.Body.Close()

	for _, h := range []string{"Content-Type", "Content-Encoding", "Cache-Control", "Expires", "Pragma"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	// WWW-Authenticate is dropped: a sandbox git that sees it would prompt for
	// credentials it does not have, instead of failing with a clear status.
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	ev.Action = "allow"
	if resp.StatusCode >= 400 {
		ev.Reason = "upstream status " + strconv.Itoa(resp.StatusCode)
	}
	b.emit(ev)
}

type refUpdate struct {
	old, new, ref string
}

var zeroOID = regexp.MustCompile(`^0+$`)

// validRefName applies git's check-ref-format rules that matter here, so a
// name like refs/heads/rig/../main cannot satisfy a branch pattern and then
// mean something else. The git host enforces them too.
func validRefName(ref string) bool {
	if ref == "" || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, ".lock") {
		return false
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.Contains(ref, "@{") || strings.Contains(ref, "/.") {
		return false
	}
	for _, c := range ref {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(" ~^:?*[\\", c) {
			return false
		}
	}
	return true
}

func (r compiledRepo) allow(c refUpdate) error {
	if !validRefName(c.ref) {
		return fmt.Errorf("invalid ref name %q", c.ref)
	}
	deleting := zeroOID.MatchString(c.new)
	switch {
	case strings.HasPrefix(c.ref, "refs/heads/"):
		branch := strings.TrimPrefix(c.ref, "refs/heads/")
		if len(r.patterns) > 0 {
			matched := false
			for _, re := range r.patterns {
				if re.MatchString(branch) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("pushing to branch %q is not allowed (allowed: %s)", branch, strings.Join(r.Branches, ", "))
			}
		}
	case strings.HasPrefix(c.ref, "refs/tags/"):
		if !r.Tags {
			return fmt.Errorf("pushing tags is not allowed (%s)", c.ref)
		}
	default:
		return fmt.Errorf("only branches can be pushed, not %s", c.ref)
	}
	if deleting && !r.Delete {
		return fmt.Errorf("deleting %s is not allowed", c.ref)
	}
	return nil
}

// readCommands parses the ref-update commands at the start of a receive-pack
// request: pkt-lines up to the first flush packet. It returns the commands and
// the exact bytes consumed, which the caller forwards ahead of the rest.
func readCommands(r *bufio.Reader, limit int) ([]refUpdate, []byte, error) {
	var consumed []byte
	var cmds []refUpdate
	for {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return nil, nil, fmt.Errorf("truncated command list")
		}
		consumed = append(consumed, hdr...)
		n, err := strconv.ParseUint(string(hdr), 16, 16)
		if err != nil {
			return nil, nil, fmt.Errorf("bad pkt-line length %q", hdr)
		}
		if n == 0 {
			break // flush: end of commands
		}
		if n < 4 {
			return nil, nil, fmt.Errorf("unexpected special packet")
		}
		if len(consumed)+int(n) > limit {
			return nil, nil, fmt.Errorf("command list too large")
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, fmt.Errorf("truncated command")
		}
		consumed = append(consumed, payload...)

		line := strings.TrimSuffix(string(payload), "\n")
		if strings.HasPrefix(line, "shallow ") {
			continue
		}
		if strings.HasPrefix(line, "push-cert") {
			return nil, nil, fmt.Errorf("signed pushes are not supported")
		}
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i] // drop capabilities
		}
		f := strings.Fields(line)
		if len(f) != 3 || !isOID(f[0]) || !isOID(f[1]) || f[2] == "" {
			return nil, nil, fmt.Errorf("unrecognized command %q", line)
		}
		cmds = append(cmds, refUpdate{old: f[0], new: f[1], ref: f[2]})
	}
	if len(cmds) == 0 {
		return nil, nil, fmt.Errorf("no ref updates")
	}
	return cmds, consumed, nil
}

func isOID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
