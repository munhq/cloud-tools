#!/usr/bin/env bash
set -euo pipefail

BINARY="cloud-tools"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

mkdir -p "$INSTALL_DIR"

if ! command -v cargo &>/dev/null; then
    echo "Error: cargo not found. Install Rust: https://rustup.rs" >&2
    exit 1
fi

echo "Building from source..."
cargo build --release
cp "target/release/$BINARY" "$INSTALL_DIR/$BINARY"
echo "Installed to $INSTALL_DIR/$BINARY"

if command -v claude &>/dev/null; then
    claude mcp add cloud-tools "$INSTALL_DIR/$BINARY"
    echo "Registered with Claude Code"
else
    echo "Claude Code not found — register manually:"
    echo "  claude mcp add cloud-tools $INSTALL_DIR/$BINARY"
fi
