#!/usr/bin/env bash
# ==============================================================================
# Kaizo DevSec Framework (K-SEF) - One-Line Global Installer for Linux / macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/kizo-88/Kaizo-DevSec-Framework-K-SEF-/main/install.sh | bash
# ==============================================================================

set -euo pipefail

echo "🛡️ Installing Kaizo DevSec CLI (k-sef)..."

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

TMP_DIR=$(mktemp -d)
git clone --depth 1 https://github.com/kizo-88/Kaizo-DevSec-Framework-K-SEF-.git "$TMP_DIR/k-sef"

cp "$TMP_DIR/k-sef/bin/k-sef.js" "$INSTALL_DIR/k-sef"
chmod +x "$INSTALL_DIR/k-sef"

rm -rf "$TMP_DIR"

echo "✅ Kaizo DevSec CLI installed successfully to $INSTALL_DIR/k-sef!"
echo "👉 Run: k-sef init (in any project to apply security guardrails)"
