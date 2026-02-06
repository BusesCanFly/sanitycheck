# sanitycheck.zsh — intercept curl|bash commands and offer to audit them first.
# Source in .zshrc:  source /path/to/sanitycheck/hooks/sanitycheck.zsh

SANITYCHECK_BIN="${SANITYCHECK_BIN:-sanitycheck}"

_sanitycheck_match() {
  local cmd="$1"
  # curl/wget piped to a shell:  curl ... | bash,  curl ... | sudo sh
  [[ "$cmd" =~ "(curl|wget)\s.*\|\s*(sudo\s+)?(bash|sh)" ]] && return 0
  # bash -c "$(curl ...)":  bash -c "$(curl -fsSL ...)"
  [[ "$cmd" =~ "(bash|sh)\s+-c\s.*\\\$\(.*\s*(curl|wget)" ]] && return 0
  # bash <(curl ...):  process substitution
  [[ "$cmd" =~ "(bash|sh)\s+<\(.*\s*(curl|wget)" ]] && return 0
  # source <(curl ...):  source or . with process substitution
  [[ "$cmd" =~ "(source|\.)\s+<\(.*\s*(curl|wget)" ]] && return 0
  return 1
}

_sanitycheck_accept_line() {
  if command -v "$SANITYCHECK_BIN" >/dev/null 2>&1 && _sanitycheck_match "$BUFFER"; then
    local orig="$BUFFER"
    echo ""
    printf '\033[33msanitycheck:\033[0m audit this before running? [Y/n] '
    read -rk1 answer
    echo ""
    case "$answer" in
      [Nn]) BUFFER="$orig" ;;
      *)    BUFFER="${SANITYCHECK_BIN} -r $(printf '%q' "$orig")" ;;
    esac
  fi
  zle .accept-line
}

zle -N accept-line _sanitycheck_accept_line
