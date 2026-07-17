#!/usr/bin/env bash
# Inert fixture: a realistic, benign install script. sanitycheck only reads it;
# the test never executes it. Represents the normal-for-installers patterns the
# installer mode is expected NOT to call DANGEROUS.
set -euo pipefail

APP=exampletool
PREFIX="${PREFIX:-$HOME/.local}"

detect_os() { uname -s; }

echo "installing $APP into $PREFIX ..."
mkdir -p "$PREFIX/bin"

# download the release binary from the project's own domain
curl -fsSL "https://dl.exampletool.dev/${APP}-$(uname -m)" -o "$PREFIX/bin/$APP"
chmod +x "$PREFIX/bin/$APP"

# add a vendor apt repo + GPG key (normal for installers)
if command -v apt-get >/dev/null 2>&1; then
  sudo install -m0755 -d /etc/apt/keyrings
  curl -fsSL https://dl.exampletool.dev/gpg | sudo tee /etc/apt/keyrings/exampletool.asc >/dev/null
fi

# put it on PATH via the shell rc
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "export PATH=\"$PREFIX/bin:\$PATH\"" >> "$HOME/.bashrc" ;;
esac

echo "done. run '$APP --help' to get started."
