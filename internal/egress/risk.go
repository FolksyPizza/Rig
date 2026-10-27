package egress

import (
	"regexp"
	"strings"
)

// Risk categories name the kinds of destination that an agent has almost no
// legitimate reason to contact and that are routinely used to move data out of
// a machine: anonymous file drops, paste sites, request-capture endpoints,
// reverse tunnels, out-of-band testing domains, chat webhooks, raw object
// storage, and "what is my IP" services used to fingerprint a host.
//
// The proxy refuses these even when an allowlist entry would otherwise match
// (for example "*.amazonaws.com"), unless the exact host is listed in
// allow_risky. A denied attempt to reach one is reported with its category so
// the monitor can treat it as a likely exfiltration attempt rather than an
// ordinary blocked request.
const (
	RiskPaste          = "paste"
	RiskFileSharing    = "file-sharing"
	RiskRequestCapture = "request-capture"
	RiskTunnel         = "tunnel"
	RiskOAST           = "oast"
	RiskMessaging      = "messaging"
	RiskRecon          = "recon"
	RiskObjectStorage  = "object-storage"
)

// riskDomains maps a domain to its category. An entry matches the domain
// itself and every subdomain of it.
var riskDomains = map[string]string{
	// Paste sites.
	"pastebin.com":   RiskPaste,
	"paste.ee":       RiskPaste,
	"hastebin.com":   RiskPaste,
	"dpaste.org":     RiskPaste,
	"dpaste.com":     RiskPaste,
	"rentry.co":      RiskPaste,
	"paste.rs":       RiskPaste,
	"termbin.com":    RiskPaste,
	"ix.io":          RiskPaste,
	"sprunge.us":     RiskPaste,
	"controlc.com":   RiskPaste,
	"justpaste.it":   RiskPaste,
	"privatebin.net": RiskPaste,

	// Anonymous file drops.
	"transfer.sh":    RiskFileSharing,
	"file.io":        RiskFileSharing,
	"0x0.st":         RiskFileSharing,
	"temp.sh":        RiskFileSharing,
	"catbox.moe":     RiskFileSharing,
	"gofile.io":      RiskFileSharing,
	"wetransfer.com": RiskFileSharing,
	"we.tl":          RiskFileSharing,
	"sendspace.com":  RiskFileSharing,
	"mediafire.com":  RiskFileSharing,
	"mega.nz":        RiskFileSharing,
	"mega.io":        RiskFileSharing,
	"anonfiles.com":  RiskFileSharing,
	"bashupload.com": RiskFileSharing,
	"oshi.at":        RiskFileSharing,
	"filebin.net":    RiskFileSharing,
	"uguu.se":        RiskFileSharing,
	"pixeldrain.com": RiskFileSharing,
	"tmpfiles.org":   RiskFileSharing,
	"keep.sh":        RiskFileSharing,
	"ufile.io":       RiskFileSharing,

	// Request capture and webhook inspection.
	"webhook.site":       RiskRequestCapture,
	"requestbin.net":     RiskRequestCapture,
	"requestbin.com":     RiskRequestCapture,
	"pipedream.net":      RiskRequestCapture,
	"hookbin.com":        RiskRequestCapture,
	"beeceptor.com":      RiskRequestCapture,
	"requestcatcher.com": RiskRequestCapture,
	"mockbin.org":        RiskRequestCapture,
	"postb.in":           RiskRequestCapture,
	"smee.io":            RiskRequestCapture,

	// Reverse tunnels that expose or relay arbitrary traffic.
	"ngrok.io":          RiskTunnel,
	"ngrok.app":         RiskTunnel,
	"ngrok.dev":         RiskTunnel,
	"ngrok-free.app":    RiskTunnel,
	"ngrok-free.dev":    RiskTunnel,
	"trycloudflare.com": RiskTunnel,
	"loca.lt":           RiskTunnel,
	"localtunnel.me":    RiskTunnel,
	"serveo.net":        RiskTunnel,
	"localhost.run":     RiskTunnel,
	"lhr.life":          RiskTunnel,
	"pinggy.io":         RiskTunnel,
	"pinggy.link":       RiskTunnel,
	"bore.pub":          RiskTunnel,
	"localxpose.io":     RiskTunnel,
	"playit.gg":         RiskTunnel,
	"tunnelto.dev":      RiskTunnel,
	"devtunnels.ms":     RiskTunnel,

	// Out-of-band interaction testing (callbacks that prove code ran).
	"interact.sh":          RiskOAST,
	"oast.pro":             RiskOAST,
	"oast.live":            RiskOAST,
	"oast.site":            RiskOAST,
	"oast.online":          RiskOAST,
	"oast.fun":             RiskOAST,
	"oast.me":              RiskOAST,
	"burpcollaborator.net": RiskOAST,
	"oastify.com":          RiskOAST,
	"canarytokens.com":     RiskOAST,
	"dnslog.cn":            RiskOAST,
	"ceye.io":              RiskOAST,
	"requestrepo.com":      RiskOAST,

	// Chat bots and webhooks used as drop boxes.
	"api.telegram.org": RiskMessaging,
	"discord.com":      RiskMessaging,
	"discordapp.com":   RiskMessaging,
	"hooks.slack.com":  RiskMessaging,

	// Public-IP and geolocation lookups, used to fingerprint the host.
	"ipinfo.io":             RiskRecon,
	"ifconfig.me":           RiskRecon,
	"ifconfig.co":           RiskRecon,
	"icanhazip.com":         RiskRecon,
	"ipify.org":             RiskRecon,
	"ip-api.com":            RiskRecon,
	"ipapi.co":              RiskRecon,
	"ipecho.net":            RiskRecon,
	"wtfismyip.com":         RiskRecon,
	"checkip.amazonaws.com": RiskRecon,
	"checkip.dyndns.org":    RiskRecon,
	"ident.me":              RiskRecon,
	"ipgeolocation.io":      RiskRecon,
	"whatismyipaddress.com": RiskRecon,
	"ip.sb":                 RiskRecon,
	"myexternalip.com":      RiskRecon,
	"ipwho.is":              RiskRecon,
	"ipwhois.app":           RiskRecon,
	"seeip.org":             RiskRecon,

	// Object storage endpoints that accept uploads to any bucket.
	"storage.googleapis.com":   RiskObjectStorage,
	"blob.core.windows.net":    RiskObjectStorage,
	"r2.cloudflarestorage.com": RiskObjectStorage,
	"r2.dev":                   RiskObjectStorage,
	"backblazeb2.com":          RiskObjectStorage,
	"wasabisys.com":            RiskObjectStorage,
	"digitaloceanspaces.com":   RiskObjectStorage,
	"linodeobjects.com":        RiskObjectStorage,
}

// riskPatterns cover object storage whose hostnames embed a region or bucket
// in the middle of the name, which a suffix match cannot express.
var riskPatterns = []struct {
	re       *regexp.Regexp
	category string
}{
	// Alibaba Cloud OSS: oss-cn-beijing.aliyuncs.com, bucket.oss-cn-beijing.aliyuncs.com,
	// oss-accelerate.aliyuncs.com. Other aliyuncs.com services (such as the
	// DashScope model API) are deliberately not matched.
	{regexp.MustCompile(`(^|\.)oss(-[a-z0-9-]+)?\.aliyuncs\.com$`), RiskObjectStorage},
	// Amazon S3: s3.amazonaws.com, bucket.s3.us-east-1.amazonaws.com,
	// s3-us-west-2.amazonaws.com, s3.dualstack.eu-west-1.amazonaws.com.
	{regexp.MustCompile(`(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com(\.cn)?$`), RiskObjectStorage},
	// Tencent Cloud COS.
	{regexp.MustCompile(`(^|\.)cos\.[a-z0-9-]+\.myqcloud\.com$`), RiskObjectStorage},
	// Huawei Cloud OBS.
	{regexp.MustCompile(`(^|\.)obs\.[a-z0-9-]+\.myhuaweicloud\.com$`), RiskObjectStorage},
}

// RiskCategory reports whether host is a known exfiltration or reconnaissance
// destination, and if so which kind. host must already be normalized
// (lowercase, no trailing dot).
func RiskCategory(host string) (string, bool) {
	// Walk the host and each parent domain: a.b.example.com, b.example.com, example.com.
	for h := host; h != ""; {
		if cat, ok := riskDomains[h]; ok {
			return cat, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	for _, p := range riskPatterns {
		if p.re.MatchString(host) {
			return p.category, true
		}
	}
	return "", false
}
