#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://raw.githubusercontent.com/BusesCanFly/sanitycheck/main"
INSTALL_DIR="${SANITYCHECK_DIR:-$HOME/.local/share/sanitycheck}"
BIN_DIR="${SANITYCHECK_BIN_DIR:-$HOME/.local/bin}"

# Read a y/n answer from the terminal (works even when stdin is a pipe).
# Defaults to yes when fully non-interactive (no tty at all).
ask() {
  local prompt="$1" answer=""
  if [[ -t 0 ]]; then
    printf '%s ' "$prompt"
    read -r answer
  elif (exec < /dev/tty) 2>/dev/null; then
    printf '%s ' "$prompt" > /dev/tty
    read -r answer < /dev/tty
  fi
  [[ "$answer" =~ ^[Yy]$ || -z "$answer" ]]
}

# Append a line to a file if it isn't already present.
inject_line() {
  local file="$1" marker="$2" line="$3"
  if [[ -f "$file" ]] && grep -qF "$marker" "$file"; then
    return 1  # already present
  fi
  printf '\n%s\n' "$line" >> "$file"
  return 0
}

main() {
  # --- Locate source files ------------------------------------------------
  # Use BASH_SOURCE to find the real script location; when piped via
  # curl|bash, BASH_SOURCE is empty so we fall back to downloading.
  local self="${BASH_SOURCE[0]:-}"
  local src_dir=""

  if [[ -n "$self" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "$self")" && pwd)"
    if [[ -f "$script_dir/sanitycheck.sh" && -d "$script_dir/hooks" ]]; then
      src_dir="$script_dir"
    fi
  fi

  if [[ -z "$src_dir" ]]; then
    src_dir="$(mktemp -d "${TMPDIR:-/tmp}/sanitycheck-install.XXXXXXXXXX")"
    trap 'rm -rf "$src_dir"' EXIT
    printf 'downloading sanitycheck...\n'
    curl -fsSL -o "$src_dir/sanitycheck.sh" "$REPO_URL/sanitycheck.sh"
    mkdir -p "$src_dir/hooks"
    curl -fsSL -o "$src_dir/hooks/sanitycheck.zsh" "$REPO_URL/hooks/sanitycheck.zsh"
  fi

  # --- Install files ------------------------------------------------------
  mkdir -p "$INSTALL_DIR/hooks" "$BIN_DIR"
  cp "$src_dir/sanitycheck.sh"            "$INSTALL_DIR/sanitycheck.sh"
  cp "$src_dir/hooks/sanitycheck.zsh"     "$INSTALL_DIR/hooks/sanitycheck.zsh"
  chmod +x "$INSTALL_DIR/sanitycheck.sh"
  ln -sf "$INSTALL_DIR/sanitycheck.sh" "$BIN_DIR/sanitycheck"

  printf '\n  installed: %s/sanitycheck\n\n' "$BIN_DIR"

  # --- Shell config -------------------------------------------------------
  local source_line="source \"$INSTALL_DIR/hooks/sanitycheck.zsh\""
  local path_line="export PATH=\"$BIN_DIR:\$PATH\""
  local rc_file=""
  local did_modify=0

  # Pick the right rc file
  case "${SHELL:-}" in
    */zsh)  rc_file="$HOME/.zshrc" ;;
    */bash) rc_file="$HOME/.bashrc" ;;
  esac
  # Also accept .zshrc if it exists regardless of $SHELL
  if [[ -z "$rc_file" && -f "$HOME/.zshrc" ]]; then
    rc_file="$HOME/.zshrc"
  fi

  # PATH — offer to add if ~/.local/bin isn't in PATH
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
      if [[ -n "$rc_file" ]]; then
        if ask "Add $BIN_DIR to PATH in $rc_file? [Y/n]"; then
          if inject_line "$rc_file" "$BIN_DIR" "$path_line"; then
            printf '  added PATH entry to %s\n' "$rc_file"
            did_modify=1
          else
            printf '  PATH entry already in %s\n' "$rc_file"
          fi
        fi
      else
        printf '  note: add to your shell profile:\n\n'
        printf '    %s\n\n' "$path_line"
      fi
      ;;
  esac

  # Zsh hook — offer to add if shell is zsh (or .zshrc exists)
  local zshrc="$HOME/.zshrc"
  if [[ -f "$zshrc" || "${SHELL:-}" == */zsh ]]; then
    if grep -qF "sanitycheck.zsh" "$zshrc" 2>/dev/null; then
      printf '  zsh hook already in %s\n' "$zshrc"
    elif ask "Enable zsh hook (auto-intercept curl|bash)? [Y/n]"; then
      inject_line "$zshrc" "sanitycheck.zsh" "$source_line"
      printf '  added zsh hook to %s\n' "$zshrc"
      did_modify=1
    fi
  fi

  if (( did_modify )); then
    printf '\n  restart your shell or: source %s\n' "${rc_file:-$zshrc}"
  fi

  # claude check (warn last so the actionable output stays visible)
  if ! command -v claude >/dev/null 2>&1; then
    printf '\n  note: the claude CLI is required at runtime\n'
    printf '    https://docs.anthropic.com/en/docs/claude-cli\n'
  fi

  printf '\n'
}

main
