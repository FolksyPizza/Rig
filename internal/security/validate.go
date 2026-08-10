// Package security provides input validation and policy generation for
// sandbox profiles. Everything a profile can influence — domains, names,
// mount paths, volume targets — passes through here before it reaches
// Docker or a proxy config file.
package security

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	// A domain label, optionally preceded by a single "*." wildcard.
	domainRegex = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	nameRegex   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
	sizeRegex   = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[kmgtKMGT]?$`)
	// Debian package names: lowercase alphanumerics plus - + . , and the
	// optional "=version" or ":arch" suffixes apt accepts.
	packageRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]*$`)
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

// ValidateDomain checks a single allowlist entry. Entries are interpolated
// verbatim into a Squid configuration file, so anything that could terminate
// the ACL line and inject a new directive must be rejected here.
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
// under ~/.config/rig/profiles, Docker container names, Docker network names
// and image tags, so they must be restrictive enough for all four.
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
// a Docker volume name, so it carries the same constraints as a profile name.
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

// ValidateSize checks a Docker-style size string such as "10g" or "512m".
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
	"/proc",
	"/sys",
	"/dev",
	"/boot",
	"/etc",
	"/var/lib/docker",
	"/var/lib/containerd",
}

// ValidateMountTarget checks the in-container side of a bind mount or volume.
func ValidateMountTarget(target string) error {
	if target == "" {
		return fmt.Errorf("mount target cannot be empty")
	}
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("mount target %q must be an absolute path", target)
	}
	if strings.ContainsAny(target, "\x00:") {
		return fmt.Errorf("mount target %q contains an invalid character", target)
	}
	if path.Clean(target) == "/" {
		return fmt.Errorf("refusing to mount over the container root")
	}
	return nil
}

// ValidateMountSource checks the host side of a bind mount. Mounting the Docker
// socket, or the host directories Docker and the kernel rely on, is a trivial
// container escape, so those are rejected outright.
func ValidateMountSource(source string) error {
	if source == "" {
		return fmt.Errorf("mount source cannot be empty")
	}
	if !strings.HasPrefix(source, "/") {
		return fmt.Errorf("mount source %q must be an absolute host path", source)
	}
	if strings.ContainsAny(source, "\x00:") {
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
