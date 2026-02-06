#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
curl -fsSL -o "$INSTALL_DIR/mytool" "https://github.com/example/mytool/releases/latest/download/mytool-linux-amd64"
chmod +x "$INSTALL_DIR/mytool"
echo "mytool installed to $INSTALL_DIR/mytool"
