package monitor

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/FolksyPizza/rig/internal/egress"
	"github.com/FolksyPizza/rig/internal/watchdog"
)

// Rules turn raw events from the proxy, the gateway, the tool-call guard and
// the process table into observations with a severity. The watchdog policy
// then decides, from the profile's level, whether each one is recorded,
// flagged or fatal.
type Rules struct {
	// DenyKillThreshold: ordinary blocked egress attempts within a minute that
	// count as a violation worth stopping for. 0 means never.
	DenyKillThreshold int
	// ExecFromTempIsSevere raises running a program from /tmp and similar
	// scratch locations from medium to high.
	ExecFromTempIsSevere bool
	// ExecOnlyFromImage (lockdown) treats running a program from anywhere
	// but the image's system directories, such as a binary the agent built
	// or downloaded into its workspace, as a high-severity violation.
	ExecOnlyFromImage bool
	// LargeUpload flags a single connection that sends more than this.
	LargeUpload int64

	mu     sync.Mutex
	denies []time.Time
	now    func() time.Time
}

// NewRules builds rules with defaults filled in.
func NewRules(denyKillThreshold int, execFromTempIsSevere bool) *Rules {
	return &Rules{
		DenyKillThreshold:    denyKillThreshold,
		ExecFromTempIsSevere: execFromTempIsSevere,
		LargeUpload:          64 << 20,
		now:                  time.Now,
	}
}

func obs(source, kind string, sev watchdog.Severity, raw []byte, format string, args ...any) watchdog.Observation {
	return watchdog.Observation{
		Source:   source,
		Kind:     kind,
		Severity: sev,
		Detail:   fmt.Sprintf(format, args...),
		Data:     json.RawMessage(append([]byte{}, raw...)),
	}
}

// Line classifies one JSON log line from the proxy, gateway or guard.
func (r *Rules) Line(raw []byte) (watchdog.Observation, bool) {
	var head struct {
		Event string `json:"event"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return watchdog.Observation{}, false
	}
	switch head.Event {
	case "egress":
		var ev egress.Event
		if json.Unmarshal(raw, &ev) != nil {
			return watchdog.Observation{}, false
		}
		return r.Egress(ev, raw), true
	case "mcp":
		return r.mcp(raw), true
	case "git":
		return r.git(raw), true
	case "relay":
		return r.relay(raw), true
	case "mcp_stderr":
		var ev struct {
			Server string `json:"server"`
			Line   string `json:"line"`
		}
		_ = json.Unmarshal(raw, &ev)
		return obs("mcp", "mcp_stderr", watchdog.SevInfo, raw, "%s: %s", ev.Server, clip(ev.Line, 200)), true
	case "config":
		return obs("egress", "proxy_config", watchdog.SevInfo, raw, "egress policy reloaded"), true
	}
	return watchdog.Observation{}, false
}

// Egress classifies one proxy decision.
func (r *Rules) Egress(ev egress.Event, raw []byte) watchdog.Observation {
	target := ev.Host
	if ev.Port != 0 && ev.Port != 443 && ev.Port != 80 {
		target = fmt.Sprintf("%s:%d", ev.Host, ev.Port)
	}
	who := ""
	if ev.As != "" && ev.As != egress.SandboxClient {
		who = " (via " + ev.As + ")"
	}
	switch ev.Phase {
	case "open":
		return obs("egress", "egress_open", watchdog.SevInfo, raw, "connected to %s%s", target, who)
	case "close":
		if ev.Reason == egress.ReasonUploadLimit {
			return obs("egress", "upload_limit", watchdog.SevHigh, raw, "cut a connection to %s after it tried to upload more than the limit%s", target, who)
		}
		if r.LargeUpload > 0 && ev.BytesUp > r.LargeUpload {
			return obs("egress", "large_upload", watchdog.SevMedium, raw, "sent %s to %s%s", humanBytes(ev.BytesUp), target, who)
		}
		return obs("egress", "egress_close", watchdog.SevInfo, raw, "closed %s (sent %s, received %s)", target, humanBytes(ev.BytesUp), humanBytes(ev.BytesDown))
	}

	switch ev.Reason {
	case egress.ReasonRisky:
		if ev.Category == egress.RiskRecon {
			return obs("egress", "recon_attempt", watchdog.SevHigh, raw, "blocked a public-IP lookup at %s%s", target, who)
		}
		return obs("egress", "exfil_attempt", watchdog.SevCritical, raw, "blocked a connection to %s, a known %s service used to move data out%s", target, ev.Category, who)
	case egress.ReasonPrivate, egress.ReasonIPLiteral:
		return obs("egress", "internal_access_attempt", watchdog.SevHigh, raw, "blocked an attempt to reach %s, a private or raw address%s", target, who)
	case egress.ReasonSNIMismatch:
		return obs("egress", "domain_fronting_attempt", watchdog.SevHigh, raw, "blocked a tunnel to %s that presented a different server name (%s)%s", target, ev.SNI, who)
	case egress.ReasonNoSNI:
		return obs("egress", "non_tls_tunnel", watchdog.SevMedium, raw, "blocked a non-TLS tunnel to %s%s", target, who)
	case egress.ReasonPort:
		return obs("egress", "port_blocked", watchdog.SevMedium, raw, "blocked a connection to %s on a port that is not allowed%s", target, who)
	case egress.ReasonAuth:
		return obs("egress", "proxy_auth_failed", watchdog.SevHigh, raw, "something presented a wrong gateway credential to the proxy")
	case egress.ReasonUploadLimit:
		return obs("egress", "upload_limit", watchdog.SevHigh, raw, "blocked an upload to %s over the size limit%s", target, who)
	case egress.ReasonBusy:
		return obs("egress", "connection_flood", watchdog.SevMedium, raw, "refused connections: too many open at once")
	case egress.ReasonNotAllowlisted, egress.ReasonHTTPSOnly:
		n := r.countDeny()
		if r.DenyKillThreshold > 0 && n >= r.DenyKillThreshold {
			return obs("egress", "egress_denied", watchdog.SevMedium, raw, "blocked %s, which is not on the allowlist (%d blocked attempts in the last minute)%s", target, n, who)
		}
		return obs("egress", "egress_denied", watchdog.SevLow, raw, "blocked %s, which is not on the allowlist%s", target, who)
	}
	return obs("egress", "egress_error", watchdog.SevInfo, raw, "%s to %s: %s", ev.Method, target, ev.Reason)
}

func (r *Rules) countDeny() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cutoff := now.Add(-time.Minute)
	kept := r.denies[:0]
	for _, t := range r.denies {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.denies = append(kept, now)
	return len(r.denies)
}

func (r *Rules) mcp(raw []byte) watchdog.Observation {
	var ev struct {
		Server string `json:"server"`
		Method string `json:"method"`
		Tool   string `json:"tool"`
		Action string `json:"action"`
		Reason string `json:"reason"`
		Hidden int    `json:"hidden"`
	}
	_ = json.Unmarshal(raw, &ev)
	switch ev.Action {
	case "deny":
		return obs("mcp", "mcp_tool_blocked", watchdog.SevMedium, raw, "blocked MCP tool %s/%s (%s)", ev.Server, ev.Tool, ev.Reason)
	case "filter":
		return obs("mcp", "mcp_tools_hidden", watchdog.SevInfo, raw, "hid %d blocked tools from %s", ev.Hidden, ev.Server)
	}
	return obs("mcp", "mcp_tool_call", watchdog.SevInfo, raw, "called MCP tool %s/%s", ev.Server, ev.Tool)
}

func (r *Rules) git(raw []byte) watchdog.Observation {
	var ev struct {
		Repo   string   `json:"repo"`
		Op     string   `json:"op"`
		Action string   `json:"action"`
		Reason string   `json:"reason"`
		Refs   []string `json:"refs"`
	}
	_ = json.Unmarshal(raw, &ev)
	if ev.Action == "deny" {
		if ev.Op == "push" {
			return obs("git", "git_push_refused", watchdog.SevHigh, raw, "refused a push to %s: %s", ev.Repo, ev.Reason)
		}
		return obs("git", "git_repo_refused", watchdog.SevMedium, raw, "refused git access to %s: %s", ev.Repo, ev.Reason)
	}
	return obs("git", "git_"+ev.Op, watchdog.SevInfo, raw, "git %s %s %s", ev.Op, ev.Repo, strings.Join(ev.Refs, " "))
}

func (r *Rules) relay(raw []byte) watchdog.Observation {
	var ev struct {
		Port  string `json:"port"`
		Phase string `json:"phase"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &ev)
	if ev.Phase == "error" {
		return obs("relay", "host_port_unavailable", watchdog.SevLow, raw, "host port %s: %s", ev.Port, ev.Error)
	}
	return obs("relay", "host_port_"+ev.Phase, watchdog.SevInfo, raw, "host port %s %s", ev.Port, ev.Phase)
}

// suspiciousTools are programs a coding agent has little reason to run and
// that are staples of scanning, tunnelling, credential cracking and mining.
var suspiciousTools = map[string]bool{
	"nc": true, "ncat": true, "netcat": true, "socat": true, "nmap": true, "masscan": true,
	"zmap": true, "rustscan": true, "tcpdump": true, "tshark": true, "hydra": true,
	"medusa": true, "john": true, "hashcat": true, "xmrig": true, "minerd": true,
	"cpuminer": true, "chisel": true, "frpc": true, "ngrok": true, "cloudflared": true,
	"ligolo": true, "sshuttle": true, "proxychains": true, "proxychains4": true,
	"mitmproxy": true, "responder": true, "bore": true,
}

// engineInits are the init programs engines run as a container's first
// process. Podman's lives under /run but is mounted read-only by the engine.
var engineInits = map[string]bool{"/run/podman-init": true, "/dev/init": true, "/sbin/docker-init": true}

// tempDirs are scratch locations a program should not normally run from.
var tempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/"}

// imageDirs hold the programs installed in the image, which is read-only at
// strict and above.
var imageDirs = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/etc/rig/"}

// fromImage reports whether a process's first argument names a program in
// the image. A bare name was found on PATH and cannot be judged from here.
func fromImage(first string) bool {
	if !strings.Contains(first, "/") {
		return true
	}
	for _, d := range imageDirs {
		if strings.HasPrefix(first, d) {
			return true
		}
	}
	return false
}

// Process classifies a newly seen process.
func (r *Rules) Process(comm, args string) watchdog.Observation {
	exe := strings.Fields(args)
	first := comm
	if len(exe) > 0 {
		first = exe[0]
	}
	base := first[strings.LastIndex(first, "/")+1:]
	raw, _ := json.Marshal(map[string]string{"comm": comm, "args": clip(args, 500)})
	if suspiciousTools[comm] || suspiciousTools[base] {
		return obs("process", "suspicious_tool", watchdog.SevHigh, raw, "started %s, a scanning/tunnelling/cracking tool: %s", base, clip(args, 160))
	}
	for _, d := range tempDirs {
		if strings.HasPrefix(first, d) && !engineInits[first] {
			sev := watchdog.SevMedium
			if r.ExecFromTempIsSevere {
				sev = watchdog.SevHigh
			}
			return obs("process", "exec_from_temp", sev, raw, "ran a program from a scratch directory: %s", clip(args, 160))
		}
	}
	if r.ExecOnlyFromImage && !fromImage(first) {
		return obs("process", "exec_outside_image", watchdog.SevHigh, raw, "ran a program that is not part of the image: %s", clip(args, 160))
	}
	return obs("process", "process_started", watchdog.SevInfo, raw, "%s", clip(args, 200))
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
