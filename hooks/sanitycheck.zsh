# sanitycheck shell hook  (zsh + bash)
#
# Auto-audits untrusted code at the moments you get burned:
#   1. running a  curl|bash  installer   (zsh only, via the zle line editor)
#   2. right after  git clone <url>      -> FAST static scan of the checkout
#   3. right before installing deps      -> DEEP scan (with dependency resolution):
#        pip, pip3, npm, yarn, pnpm, poetry, uv
#
# clone=fast, install=deep: a fresh clone hasn't pulled dependencies yet, and a
# malicious build script (Makefile, build.rs, setup.py, ...) is already caught by
# the static scan - so cloning stays instant. Dependency resolution (the network
# layer that catches trojaned *transitive* deps) is saved for the install step,
# where deps are actually fetched and the install latency hides the scan.
# Build commands that run every few seconds (make, cargo build, go build, gradle)
# are intentionally NOT hooked - they'd add latency to every build for signal the
# clone scan already has.
#
# Enable:   echo 'source /path/to/hooks/sanitycheck.zsh' >> ~/.zshrc   # or ~/.bashrc
# Disable:  comment that line out, or:  export SANITYCHECK_HOOK=0
# Bypass once:  SANITYCHECK_HOOK=0 <cmd>   or   command git/pip/npm ...
#
# On DANGEROUS, the install wrappers abort and ask to confirm (set
# SANITYCHECK_HOOK_STRICT=1 to hard-abort with no prompt). Exit code 1 == DANGEROUS.
# For instant, offline install scans set SANITYCHECK_HOOK_FAST=1 (passes --fast:
# static only, no network resolve). Resolution is already wall-clock bounded (~12s).

SANITYCHECK_HOOK="${SANITYCHECK_HOOK:-1}"
SANITYCHECK_BIN="${SANITYCHECK_BIN:-sanitycheck}"

_sanitycheck_bin() { command -v "$SANITYCHECK_BIN" 2>/dev/null || echo ""; }
# expands to "--fast" when SANITYCHECK_HOOK_FAST is set, otherwise nothing
_sc_fast() { [[ -n "${SANITYCHECK_HOOK_FAST:-}" ]] && printf -- '--fast'; }

# --- 1. curl|bash interception (zsh only; needs the zle line editor) ----------
if [[ -n "${ZSH_VERSION:-}" ]]; then
  _sanitycheck_match() {
    local cmd="$1"
    [[ "$cmd" =~ "(curl|wget)\s.*\|\s*(sudo\s+)?(bash|sh)" ]] && return 0
    [[ "$cmd" =~ "(bash|sh)\s+-c\s.*\\\$\(.*\s*(curl|wget)" ]] && return 0
    [[ "$cmd" =~ "(bash|sh)\s+<\(.*\s*(curl|wget)" ]] && return 0
    [[ "$cmd" =~ "(source|\.)\s+<\(.*\s*(curl|wget)" ]] && return 0
    return 1
  }
  _sanitycheck_accept_line() {
    if [[ "$SANITYCHECK_HOOK" == "1" ]] && command -v "$SANITYCHECK_BIN" >/dev/null 2>&1 \
       && _sanitycheck_match "$BUFFER"; then
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
fi

# --- 2. git clone wrapper: fast static scan of the fresh checkout ------------
git() {
  local bin; bin="$(_sanitycheck_bin)"
  if [[ "$SANITYCHECK_HOOK" != "1" || -z "$bin" || "${1:-}" != "clone" ]]; then
    command git "$@"; return $?
  fi
  command git "$@" || return $?
  local args=("$@") dest="" a
  for a in "${args[@]:1}"; do [[ "$a" == -* ]] || dest="$a"; done
  if [[ "$dest" == *://* || "$dest" == *@*:* || "$dest" == *.git ]]; then
    dest="$(basename "${dest%.git}")"
  fi
  [[ -d "$dest" ]] || return 0
  echo "sanitycheck: scanning freshly cloned '$dest'..." >&2
  "$bin" --fast "$dest" || true      # clone=fast: dependencies aren't pulled yet
  return 0
}

# --- 3. dependency-install wrappers: deep scan before deps are pulled --------
# One guard for every "install this project's dependencies" command. Registry
# packages are fetched by the tool itself (their install scripts can't be seen
# until download), so we vet the local project/target - its manifests (for the
# transitive resolve) and its own lifecycle scripts - up front.
_sc_install_guard() {  # display-cmd  trigger-subcommand-ere  installs-cwd-project(0|1)  args...
  local bin; bin="$(_sanitycheck_bin)"
  local cmd="$1" trig="$2" project="$3"; shift 3
  [[ "$SANITYCHECK_HOOK" == "1" && -n "$bin" ]] || { command "$cmd" "$@"; return $?; }
  local sub="" a
  for a in "$@"; do [[ "$a" == -* ]] || { sub="$a"; break; }; done   # first non-flag arg
  local scan=0
  printf '%s' "$sub" | grep -qE "^(${trig})$" && scan=1
  [[ -z "$sub" && "$project" == 1 ]] && scan=1                        # bare `npm`/`yarn` installs cwd
  [[ "$scan" == 1 ]] || { command "$cmd" "$@"; return $?; }
  # target: the cwd project (for project installers) and/or an explicit local path
  local target="" prev=""
  [[ "$project" == 1 ]] && target="."
  for a in "$@"; do
    case "$prev" in -r|--requirement) [[ -f "$a" ]] && target="$(dirname "$a")" ;; -e|--editable) [[ -e "$a" ]] && target="$a" ;; esac
    case "$a" in .|./*|/*|../*) [[ -e "$a" ]] && target="$a" ;; esac
    prev="$a"
  done
  [[ -n "$target" && -e "$target" ]] || { command "$cmd" "$@"; return $?; }
  local what="$cmd${sub:+ $sub}"
  echo "sanitycheck: scanning '$target' before $what..." >&2
  "$bin" $(_sc_fast) "$target"; local rc=$?      # install=deep unless SANITYCHECK_HOOK_FAST
  if [[ $rc -eq 1 ]]; then                        # exit 1 == DANGEROUS
    if [[ "${SANITYCHECK_HOOK_STRICT:-0}" == "1" ]]; then
      echo "sanitycheck: DANGEROUS - $what aborted." >&2; return 1
    fi
    printf 'sanitycheck: DANGEROUS verdict. Run %s anyway? [y/N] ' "$what" >&2
    local ans; read -r ans
    [[ "$ans" == [yY]* ]] || { echo "aborted." >&2; return 1; }
  fi
  command "$cmd" "$@"
}
pip()    { _sc_install_guard pip    'install'          0 "$@"; }
pip3()   { _sc_install_guard pip3   'install'          0 "$@"; }
npm()    { _sc_install_guard npm    'install|i|ci|add' 1 "$@"; }
yarn()   { _sc_install_guard yarn   'install|add'      1 "$@"; }
pnpm()   { _sc_install_guard pnpm   'install|i|add'    1 "$@"; }
poetry() { _sc_install_guard poetry 'install|add|sync' 1 "$@"; }
uv()     { _sc_install_guard uv     'sync|add|pip'     1 "$@"; }
# add another manager in one line, e.g.:
# bundle() { _sc_install_guard bundle 'install' 1 "$@"; }
# composer() { _sc_install_guard composer 'install|require|update' 1 "$@"; }
