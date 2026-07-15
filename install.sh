#!/usr/bin/env bash
set -euo pipefail

# sanitycheck installer. Works locally (./install.sh) or piped (curl|bash).
# Installs the tool, its Python deep-pass helper, the IOC database, and the
# combined shell hook; offers to add PATH and the hook to your shell rc.

REPO_URL="https://raw.githubusercontent.com/BusesCanFly/sanitycheck/main"
INSTALL_DIR="${SANITYCHECK_DIR:-$HOME/.local/share/sanitycheck}"
BIN_DIR="${SANITYCHECK_BIN_DIR:-$HOME/.local/bin}"

ask() {
  local prompt="$1" answer=""
  if [[ -t 0 ]]; then printf '%s ' "$prompt"; read -r answer
  elif (exec < /dev/tty) 2>/dev/null; then printf '%s ' "$prompt" > /dev/tty; read -r answer < /dev/tty; fi
  [[ "$answer" =~ ^[Yy]$ || -z "$answer" ]]
}

inject_line() {
  local file="$1" marker="$2" line="$3"
  if [[ -f "$file" ]] && grep -qF "$marker" "$file"; then return 1; fi
  printf '\n%s\n' "$line" >> "$file"; return 0
}

main() {
  # --- locate source (local checkout, else download) ----------------------
  local self="${BASH_SOURCE[0]:-}" src_dir=""
  if [[ -n "$self" ]]; then
    local d; d="$(cd "$(dirname "$self")" && pwd)"
    [[ -f "$d/sanitycheck.sh" && -f "$d/sanitycheck_deep.py" ]] && src_dir="$d"
  fi
  if [[ -z "$src_dir" ]]; then
    src_dir="$(mktemp -d "${TMPDIR:-/tmp}/sanitycheck-install.XXXXXX")"
    trap 'rm -rf "$src_dir"' EXIT
    printf 'downloading sanitycheck...\n'
    mkdir -p "$src_dir/hooks" "$src_dir/iocs"
    curl -fsSL -o "$src_dir/sanitycheck.sh"          "$REPO_URL/sanitycheck.sh"
    curl -fsSL -o "$src_dir/sanitycheck_deep.py"     "$REPO_URL/sanitycheck_deep.py"
    curl -fsSL -o "$src_dir/hooks/sanitycheck.zsh"   "$REPO_URL/hooks/sanitycheck.zsh"
    curl -fsSL -o "$src_dir/iocs/chocopoc.txt"       "$REPO_URL/iocs/chocopoc.txt"
  fi

  # --- install files ------------------------------------------------------
  mkdir -p "$INSTALL_DIR/hooks" "$INSTALL_DIR/iocs" "$BIN_DIR"
  cp "$src_dir/sanitycheck.sh"        "$INSTALL_DIR/sanitycheck.sh"
  cp "$src_dir/sanitycheck_deep.py"   "$INSTALL_DIR/sanitycheck_deep.py"
  cp "$src_dir/hooks/sanitycheck.zsh" "$INSTALL_DIR/hooks/sanitycheck.zsh"
  cp "$src_dir/iocs/chocopoc.txt"     "$INSTALL_DIR/iocs/chocopoc.txt"
  chmod +x "$INSTALL_DIR/sanitycheck.sh" "$INSTALL_DIR/sanitycheck_deep.py"
  ln -sf "$INSTALL_DIR/sanitycheck.sh" "$BIN_DIR/sanitycheck"
  printf '\n  installed: %s/sanitycheck\n' "$BIN_DIR"
  printf '  helper:    %s/sanitycheck_deep.py\n' "$INSTALL_DIR"
  printf '  iocs:      %s/iocs/chocopoc.txt\n\n' "$INSTALL_DIR"

  # --- shell config -------------------------------------------------------
  local source_line="source \"$INSTALL_DIR/hooks/sanitycheck.zsh\""
  local path_line="export PATH=\"$BIN_DIR:\$PATH\""
  local rc_file="" did_modify=0
  case "${SHELL:-}" in */zsh) rc_file="$HOME/.zshrc" ;; */bash) rc_file="$HOME/.bashrc" ;; esac
  [[ -z "$rc_file" && -f "$HOME/.zshrc" ]] && rc_file="$HOME/.zshrc"

  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) if [[ -n "$rc_file" ]] && ask "Add $BIN_DIR to PATH in $rc_file? [Y/n]"; then
         inject_line "$rc_file" "$BIN_DIR" "$path_line" && { printf '  added PATH entry to %s\n' "$rc_file"; did_modify=1; }
       else printf '  note: add to your shell profile:\n    %s\n' "$path_line"; fi ;;
  esac

  if [[ -n "$rc_file" ]]; then
    if grep -qF "sanitycheck.zsh" "$rc_file" 2>/dev/null; then
      printf '  hook already in %s\n' "$rc_file"
    elif ask "Enable shell hook (auto-audit curl|bash, git clone, pip/npm install)? [Y/n]"; then
      inject_line "$rc_file" "sanitycheck.zsh" "$source_line"
      printf '  added hook to %s\n' "$rc_file"; did_modify=1
    fi
  fi
  (( did_modify )) && printf '\n  restart your shell or: source %s\n' "$rc_file"

  # --- optional dependency notes (never fatal) ----------------------------
  command -v python3 >/dev/null 2>&1 || printf '\n  note: python3 not found. Core checks still run; the AST/typosquat\n        deep-pass, transitive resolve, and JSON output are skipped without it.\n'
  if ! command -v ollama >/dev/null 2>&1 && [[ -z "${ANTHROPIC_API_KEY:-}" ]] \
     && [[ -z "${OPENAI_API_KEY:-}" ]] && ! command -v claude >/dev/null 2>&1; then
    printf '\n  note: no LLM provider found - the optional second opinion is skipped.\n'
    printf '        static analysis is always on. To enable it: ollama, claude CLI,\n'
    printf '        or OPENAI_API_KEY / ANTHROPIC_API_KEY.\n'
  fi
  printf '\n  try:  sanitycheck ./some-cloned-poc\n\n'
}

main
