#!/bin/sh
# Install Rig, no clone needed:
#
#   curl -fsSL https://raw.githubusercontent.com/FolksyPizza/Rig/main/install.sh | sh
#
# It downloads the latest release for this computer, checks it against the
# release's SHA256SUMS and installs it in ~/.local/bin. When no release build
# is available it builds Rig from source instead (needs git and Go 1.25+).
#
# Settings (environment variables):
#   RIG_VERSION=v0.3.0        install that release instead of the latest
#   RIG_INSTALL_DIR=/usr/local/bin
#   RIG_FROM_SOURCE=1         always build from source
set -eu

repo="FolksyPizza/Rig"
dir="${RIG_INSTALL_DIR:-$HOME/.local/bin}"
version="${RIG_VERSION:-latest}"

say() { printf '  %s\n' "$*"; }
fail() { printf '  rig install: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "Rig runs on Linux and macOS (on Windows, use WSL2)." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no build for $(uname -m); build from source (see the README)." ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "curl or wget is needed."
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

from_release() {
  asset="rig-$os-$arch"
  if [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
  else
    base="https://github.com/$repo/releases/download/$version"
  fi
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null || return 1
  say "Downloading $asset ($version)..."
  fetch "$base/$asset" "$tmp/rig" || fail "download of $asset failed."
  want="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
  [ -n "$want" ] || fail "SHA256SUMS does not list $asset."
  got="$(sha256 "$tmp/rig")"
  [ "$got" = "$want" ] || fail "checksum mismatch for $asset (got $got, want $want); nothing was installed."
  say "Checksum verified."
}

from_source() {
  command -v git >/dev/null 2>&1 || fail "no release build is available and git is not installed to build from source."
  command -v go >/dev/null 2>&1 || fail "no release build is available; install Go 1.25 or later (https://go.dev/dl/) to build from source."
  ref=main
  [ "$version" = latest ] || ref="$version"
  say "Building Rig from source ($ref)..."
  git clone --quiet --depth 1 --branch "$ref" "https://github.com/$repo.git" "$tmp/src"
  v="$(git -C "$tmp/src" describe --tags --always 2>/dev/null || echo dev)"
  (cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$v" -o "$tmp/rig" ./cmd/rig)
}

if [ "${RIG_FROM_SOURCE:-}" = 1 ] || ! from_release; then
  from_source
fi

mkdir -p "$dir"
chmod 0755 "$tmp/rig"
mv "$tmp/rig" "$dir/rig"
say "Installed $("$dir/rig" version) to $dir/rig"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "Add $dir to your PATH, for example:  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
esac
say "Next: 'rig doctor' checks your container engine, then 'rig new' creates a sandbox."
command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1 || \
  say "Rig needs Docker or Podman to run sandboxes; neither was found."
