// Package security provides input validation for sandbox profiles.
// Everything a profile can influence — domains, names, packages, mount paths,
// volume targets — passes through here before it reaches the container engine,
// a generated Dockerfile, or the egress proxy configuration.
package security

import (
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// A domain label, optionally preceded by a single "*." wildcard.
	domainRegex = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	nameRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
	sizeRegex   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[kmgtKMGT]?$`)
	// Debian package names: lowercase alphanumerics plus + . - and _.
	packageRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]*$`)
	// npm: optional @scope/, a name, and an optional @version or tag.
	npmRegex = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*(@[A-Za-z0-9._^~-]+)?$`)
	// pip: a project name, optional [extras], and at most one version clause.
	pipRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?((==|>=|<=|~=|!=|>|<)[A-Za-z0-9.*+!_-]+)?$`)
	envRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ValidatePackageName checks an apt package name. Tool names come from profile
// YAML and are written straight into the generated Dockerfile, where a name
// containing a newline or a backslash-continuation could append arbitrary
// build instructions.
func ValidatePackageName(pkg string) error {
	if pkg == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(pkg) > 100 {
		return fmt.Errorf("package name too long: %q", pkg)
	}
	if !packageRegex.MatchString(pkg) {
		return fmt.Errorf("invalid package name %q (expected a lowercase apt package name)", pkg)
	}
	return nil
}

// ValidatePackageNames validates a whole tool list.
func ValidatePackageNames(pkgs []string) error {
	for _, p := range pkgs {
		if err := ValidatePackageName(p); err != nil {
			return err
		}
	}
	return nil
}

// ValidateNPMPackage checks an npm package spec such as "typescript" or
// "@scope/tool@1.2.3". Specs are quoted in the Dockerfile as well, but the
// character set is kept tight so nothing reaches the shell that needs quoting.
func ValidateNPMPackage(spec string) error {
	if spec == "" || len(spec) > 214 || !npmRegex.MatchString(spec) {
		return fmt.Errorf("invalid npm package %q", spec)
	}
	return nil
}

// ValidatePipPackage checks a pip requirement such as "requests" or
// "httpx[http2]>=0.27".
func ValidatePipPackage(spec string) error {
	if spec == "" || len(spec) > 200 || !pipRegex.MatchString(spec) {
		return fmt.Errorf("invalid pip package %q", spec)
	}
	return nil
}

// ValidateEnvName checks an environment variable name.
func ValidateEnvName(name string) error {
	if !envRegex.MatchString(name) {
		return fmt.Errorf("invalid environment variable name %q", name)
	}
	return nil
}

// ValidateDomain checks a single allowlist entry. Entries end up in the egress
// proxy's configuration and in log lines, so anything that is not a plain DNS
// name is refused.
func ValidateDomain(domain string) error {
	if strings.TrimSpace(domain) != domain {
		return fmt.Errorf("domain %q has leading or trailing whitespace", domain)
	}
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long (max 253 chars): %q", domain)
	}
	for _, r := range domain {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("domain %q contains a control character", domain)
		}
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %q", domain)
	}
	if net.ParseIP(strings.TrimPrefix(domain, "*.")) != nil {
		return fmt.Errorf("%q is an IP address; the allowlist takes domain names (use host.ports for services on your machine)", domain)
	}
	for _, label := range strings.Split(strings.TrimPrefix(domain, "*."), ".") {
		if len(label) > 63 {
			return fmt.Errorf("domain %q has a label longer than 63 chars", domain)
		}
	}
	return nil
}

// ValidateDomains validates every entry in an allowlist.
func ValidateDomains(domains []string) error {
	for _, d := range domains {
		if err := ValidateDomain(d); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProfileName checks a profile name. Profile names become filenames
// under ~/.config/rig/profiles, container names, network names and image
// tags, so they must be restrictive enough for all four.
func ValidateProfileName(name string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("profile name too long (max 64 chars)")
	}
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("profile name %q must start with a letter or digit and contain only letters, digits, dashes and underscores", name)
	}
	return nil
}

// ValidateVolumeName checks a named-volume identifier. It is concatenated into
// a volume name, so it carries the same constraints as a profile name.
func ValidateVolumeName(name string) error {
	if name == "" {
		return fmt.Errorf("volume name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("volume name too long (max 64 chars)")
	}
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("volume name %q must start with a letter or digit and contain only letters, digits, dashes and underscores", name)
	}
	return nil
}

// ValidateName checks a short identifier such as an MCP server or port name.
func ValidateName(kind, name string) error {
	if name == "" || len(name) > 64 || !nameRegex.MatchString(name) {
		return fmt.Errorf("%s name %q must start with a letter or digit and contain only letters, digits, dashes and underscores", kind, name)
	}
	return nil
}

// ValidateSize checks a size string such as "10g" or "512m".
func ValidateSize(size string) error {
	if size == "" {
		return nil
	}
	if !sizeRegex.MatchString(size) {
		return fmt.Errorf("invalid size %q (expected a number with an optional k/m/g/t suffix, e.g. \"10g\")", size)
	}
	return nil
}

// forbiddenSources are host paths that would hand the sandbox control of the
// host if they were bind-mounted in. Anything at or below these is refused.
var forbiddenSources = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/docker",
	"/run/containerd",
	"/var/run/containerd",
	"/run/podman",
	"/var/run/podman",
	"/run/user", // rootless docker and podman sockets live here
	"/run/crio",
	"/var/run/crio",
	"/proc",
	"/sys",
	"/dev",
	"/boot",
	"/etc",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/containers",
	"/private/var/run", // macOS: /var/run is a symlink here
}

// credentialDirs, relative to the home directory, hold keys and tokens that
// would let an agent act as you elsewhere.
var credentialDirs = []string{
	".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".config/gcloud",
	".config/gh", ".config/rig", ".config/containers", ".local/share/containers",
	".netrc", ".git-credentials", ".npmrc", ".pypirc", ".cargo/credentials",
	".cargo/credentials.toml", ".terraform.d", ".vault-token", "Library/Keychains",
	".password-store", ".config/op",
	// Coding agents' own sign-in tokens. Sign in inside the sandbox instead;
	// a persistent sandbox keeps the login in its home volume.
	".claude", ".codex", ".gemini", ".qwen", ".config/opencode", ".local/share/opencode",
}

// ValidateMountTarget checks the in-container side of a bind mount or volume.
func ValidateMountTarget(target string) error {
	if target == "" {
		return fmt.Errorf("mount target cannot be empty")
	}
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("mount target %q must be an absolute path", target)
	}
	if strings.ContainsAny(target, "\x00:,\n\r") {
		return fmt.Errorf("mount target %q contains an invalid character", target)
	}
	if path.Clean(target) == "/" {
		return fmt.Errorf("refusing to mount over the container root")
	}
	return nil
}

// ValidateMountSource checks the host side of a bind mount. Mounting a
// container-engine socket, or the host directories the engine and kernel rely
// on, is a trivial container escape, so those are rejected outright.
func ValidateMountSource(source string) error {
	if source == "" {
		return fmt.Errorf("mount source cannot be empty")
	}
	if !strings.HasPrefix(source, "/") {
		return fmt.Errorf("mount source %q must be an absolute host path", source)
	}
	if strings.ContainsAny(source, "\x00:,\n\r") {
		return fmt.Errorf("mount source %q contains an invalid character", source)
	}

	clean := path.Clean(source)
	if clean == "/" {
		return fmt.Errorf("refusing to mount the host root filesystem into a sandbox")
	}
	for _, forbidden := range forbiddenSources {
		if clean == forbidden || strings.HasPrefix(clean, forbidden+"/") {
			return fmt.Errorf("refusing to mount %q: %s grants control of the host", source, forbidden)
		}
	}
	return nil
}

// CheckCredentialPath refuses a mount source that is the home directory, a
// parent of it, or inside one of the places keys and tokens are kept.
func CheckCredentialPath(source, home string) error {
	if home == "" {
		return nil
	}
	src := path.Clean(source)
	home = path.Clean(home)
	if src == home || strings.HasPrefix(home, src+"/") {
		return fmt.Errorf("refusing to mount %q: it contains your whole home directory, including SSH keys and tokens; mount a project directory instead", source)
	}
	for _, d := range credentialDirs {
		p := path.Join(home, d)
		if src == p || strings.HasPrefix(src, p+"/") {
			return fmt.Errorf("refusing to mount %q: it holds credentials (%s)", source, "~/"+d)
		}
	}
	return nil
}

// ResolveMountSource follows symlinks on the host side of a bind mount and
// re-checks the real path, so a link inside a project cannot smuggle in a
// forbidden directory.
func ResolveMountSource(source, home string) (string, error) {
	real, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", fmt.Errorf("mount source %q: %w", source, err)
	}
	if err := ValidateMountSource(real); err != nil {
		return "", err
	}
	if err := CheckCredentialPath(real, home); err != nil {
		return "", err
	}
	return real, nil
}

// ValidateSubpath checks a path relative to a mount, as used by protect and
// hide. It must stay inside the mount.
func ValidateSubpath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00:,\n\r") {
		return fmt.Errorf("invalid path %q (must be relative to the mount)", p)
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path %q must stay inside the mount", p)
	}
	return nil
}

var (
	repoPartRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// An HTTP header field name (an RFC 9110 token).
	headerRegex = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
)

// ValidateRepoPart checks one half of an owner/name repository reference.
func ValidateRepoPart(s string) error {
	if !repoPartRegex.MatchString(s) || s == "." || s == ".." || len(s) > 100 {
		return fmt.Errorf("invalid repository name part %q", s)
	}
	return nil
}

// ValidateHeaderName checks an HTTP header name.
func ValidateHeaderName(s string) error {
	if !headerRegex.MatchString(s) {
		return fmt.Errorf("invalid header name %q", s)
	}
	return nil
}
