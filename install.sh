#!/usr/bin/env bash
# Install a prebuilt cloud-tools binary, and register it with Claude Code.
#
# This used to run `cargo build --release`, which made a Rust toolchain a
# prerequisite for every user of a project that publishes six ready binaries.
# It now downloads the release asset for this machine and verifies it against
# the SHA256SUMS published beside it — the same contract npm/bin/resolve.js and
# the Dockerfile follow.
#
# `uname` and the asset names disagree, and the disagreement is the whole bug
# class this file has to avoid: `uname -s` prints Darwin where the asset says
# macos, and Apple Silicon prints arm64 where the asset says aarch64. The
# mapping below is asserted against the release matrix by npm/test_platform.sh.
#
#   curl -sSL https://raw.githubusercontent.com/munhq/cloud-tools/main/install.sh | bash
#
# INSTALL_DIR overrides where it lands. VERSION pins a release; the default is
# the newest one.
set -euo pipefail

REPO="munhq/cloud-tools"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-}"

artifact() {
    local machine system arch plat ext=""
    machine="$(uname -m)"
    system="$(uname -s)"

    case "$machine" in
        x86_64 | amd64) arch="x86_64" ;;
        aarch64 | arm64) arch="aarch64" ;;
        *) echo "unsupported architecture: $machine" >&2; return 1 ;;
    esac

    case "$system" in
        Linux) plat="linux" ;;
        Darwin) plat="macos" ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT) plat="windows"; ext=".exe" ;;
        *) echo "unsupported system: $system" >&2; return 1 ;;
    esac

    printf 'cloud-tools-%s-%s%s\n' "$arch" "$plat" "$ext"
}

# npm/test_platform.sh drives this against the release matrix, so the names this
# script asks for cannot drift from the names the release publishes.
if [ "${1:-}" = "--print-artifact" ]; then
    artifact
    exit $?
fi

ASSET="$(artifact)"

if [ -n "$VERSION" ]; then
    BASE="https://github.com/$REPO/releases/download/v${VERSION#v}"
else
    BASE="https://github.com/$REPO/releases/latest/download"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $ASSET"
# A bare `curl -f` failure here prints "The requested URL returned error: 404"
# and nothing about why. The likely cause is knowable: releases before v0.2.0
# published .tar.gz archives named by Rust target triple, and this script asks
# for the bare binaries that replaced them. Say which release was looked at and
# what it actually holds.
if ! curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"; then
    echo "" >&2
    echo "$ASSET is not in that release." >&2
    if command -v curl >/dev/null; then
        latest="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
                  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
        [ -n "$latest" ] && echo "The newest release is ${latest}." >&2
    fi
    echo "" >&2
    echo "Releases from v0.2.0 publish bare binaries named cloud-tools-<arch>-<platform>" >&2
    echo "with one SHA256SUMS. Earlier ones published .tar.gz archives under a different" >&2
    echo "name, which this script cannot use. Options:" >&2
    echo "  - install from npm:  npx -y @munhq/cloud-tools" >&2
    echo "  - build from source: cargo build --release" >&2
    echo "  - pin a release:     VERSION=0.2.0 ./install.sh" >&2
    exit 1
fi
if ! curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"; then
    echo "That release publishes no SHA256SUMS, so the download cannot be verified." >&2
    exit 1
fi

# The checksum sits beside the binary, so it is not proof against someone who can
# replace both. It catches a truncated download and a release that never uploaded
# this asset, which are the failures that actually happen.
WANT="$(awk -v a="$ASSET" '$2 == a || $2 == "*" a { print $1 }' "$TMP/SHA256SUMS")"
if [ -z "$WANT" ]; then
    echo "SHA256SUMS does not list $ASSET — the release is incomplete" >&2
    exit 1
fi
GOT="$(cd "$TMP" && sha256sum "$ASSET" | cut -d' ' -f1)"
if [ "$WANT" != "$GOT" ]; then
    echo "checksum mismatch for $ASSET: want $WANT, got $GOT" >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$TMP/$ASSET" "$INSTALL_DIR/cloud-tools"
echo "Installed $INSTALL_DIR/cloud-tools"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Warning: $INSTALL_DIR is not on your PATH." >&2 ;;
esac

if command -v claude &>/dev/null; then
    claude mcp add cloud-tools "$INSTALL_DIR/cloud-tools"
    echo "Registered with Claude Code"
else
    echo "Claude Code not found — register manually:"
    echo "  claude mcp add cloud-tools $INSTALL_DIR/cloud-tools"
fi
