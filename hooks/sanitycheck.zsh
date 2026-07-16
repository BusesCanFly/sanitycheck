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
    # NB: zsh's =~ uses POSIX ERE (no \s / \d), so use [[:space:]] classes -
    # \s silently never matches here (notably on macOS).
    local cmd="$1"
    [[ "$cmd" =~ "(curl|wget)[[:space:]].*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh)" ]] && return 0
    [[ "$cmd" =~ "(bash|sh)[[:space:]]+-c[[:space:]].*\\\$\(.*[[:space:]]*(curl|wget)" ]] && return 0
    [[ "$cmd" =~ "(bash|sh)[[:space:]]+<\(.*[[:space:]]*(curl|wget)" ]] && return 0
    [[ "$cmd" =~ "(source|\.)[[:space:]]+<\(.*[[:space:]]*(curl|wget)" ]] && return 0
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

# --- 2 & 3. command wrappers (git clone, and the dependency installers) ------
# The wrapper functions shadow real command names, so they are defined together
# at the bottom of this file with alias expansion disabled (see the note there).

# shared guard for every "install this project's dependencies" command:
# One guard for every "install this project's dependencies" command. Registry
# packages are fetched by the tool itself (their install scripts can't be seen
# until download), so we vet the local project/target - its manifests (for the
# transitive resolve) and its own lifecycle scripts - up front.
_sc_install_guard() {  # display-cmd  trigger-subcommand-ere  installs-cwd-project(0|1)  args...
  local bin; bin="$(_sanitycheck_bin)"
  local cmd="$1" trig="$2" project="$3"; shift 3
  [[ "$SANITYCHECK_HOOK" == "1" && -n "$bin" ]] || { command "$cmd" "$@"; return $?; }
  # walk the args once: the subcommand (first non-flag), an explicit local target
  # (a path, `-r <reqfile>`, or `-e <path>`), and whether a *named* registry
  # package was requested.
  local sub="" target="" prev="" seen=0 a
  local -a pkgs; pkgs=()
  for a in "$@"; do
    if [[ "$a" == -* ]]; then prev="$a"; continue; fi
    case "$prev" in
      -r|--requirement) [[ -f "$a" ]] && target="$(dirname "$a")"; prev="$a"; continue ;;
      -e|--editable)    [[ -e "$a" ]] && target="$a"; prev="$a"; continue ;;
    esac
    if [[ "$seen" == 0 ]]; then
      sub="$a"; seen=1
    else
      case "$a" in
        .|./*|../*|/*) [[ -e "$a" ]] && target="$a" ;;   # a local path
        *) pkgs+=("$a") ;;                                # a registry package name
      esac
    fi
    prev="$a"
  done

  # trigger only on an install-like subcommand (or a bare project installer)
  local trigger=0
  printf '%s' "$sub" | grep -qE "^(${trig})$" && trigger=1
  [[ -z "$sub" && "$project" == 1 ]] && trigger=1
  [[ "$trigger" == 1 ]] || { command "$cmd" "$@"; return $?; }

  # bare project install (no path, no named pkg) audits the cwd project
  [[ -z "$target" && "$project" == 1 && ${#pkgs[@]} -eq 0 ]] && target="."

  local rc=0 what="$cmd${sub:+ $sub}"
  if [[ -n "$target" && -e "$target" ]]; then
    # a local project/path -> full scan
    echo "sanitycheck: scanning '$target' before $what..." >&2
    "$bin" $(_sc_fast) "$target"; rc=$?          # deep unless SANITYCHECK_HOOK_FAST
  elif [[ ${#pkgs[@]} -gt 0 ]]; then
    # named registry package(s) -> vet the NAME(s) against IOCs and, when online,
    # download+scan the actual package contents (no cwd scan). Silent unless
    # something is flagged.
    local eco=""
    case "$cmd" in pip|pip3|poetry|uv) eco="pypi" ;; npm|yarn|pnpm) eco="npm" ;; esac
    local -a cka; cka=(--check-pkg)
    [[ -n "$eco" ]] && cka+=(--ecosystem "$eco")
    [[ -n "${SANITYCHECK_HOOK_FAST:-}" ]] && cka+=(--fast)
    "$bin" "${cka[@]}" "${pkgs[@]}"; rc=$?
  else
    command "$cmd" "$@"; return $?
  fi

  if [[ $rc -eq 1 ]]; then                         # exit 1 == DANGEROUS
    if [[ "${SANITYCHECK_HOOK_STRICT:-0}" == "1" ]]; then
      echo "sanitycheck: DANGEROUS - $what aborted." >&2; return 1
    fi
    printf 'sanitycheck: DANGEROUS verdict. Run %s anyway? [y/N] ' "$what" >&2
    local ans; read -r ans
    [[ "$ans" == [yY]* ]] || { echo "aborted." >&2; return 1; }
  fi
  command "$cmd" "$@"
}
# These wrappers shadow real command names. zsh expands aliases at parse time,
# so a matching `alias pip=...` would break a bare `pip() { ... }` definition and
# abort the hook while it is being sourced. Turn alias expansion off just while
# we define them, then restore it. (Your aliases are untouched; note that a
# command you have aliased still uses your alias, not this wrapper.)
if [[ -n "${ZSH_VERSION:-}" ]] && [[ -o aliases ]]; then
  _sc_realias=1; unsetopt aliases
else
  _sc_realias=0
fi

git() {
  local bin; bin="$(_sanitycheck_bin)"
  if [[ "$SANITYCHECK_HOOK" != "1" || -z "$bin" || "${1:-}" != "clone" ]]; then
    command git "$@"; return $?
  fi
  command git "$@" || return $?
  # destination = last non-flag arg after `clone` (or the repo's basename)
  local dest="" a first=1
  for a in "$@"; do
    [[ "$first" == "1" ]] && { first=0; continue; }
    [[ "$a" == -* ]] || dest="$a"
  done
  if [[ "$dest" == *://* || "$dest" == *@*:* || "$dest" == *.git ]]; then
    dest="$(basename "${dest%.git}")"
  fi
  [[ -d "$dest" ]] || return 0
  echo "sanitycheck: scanning freshly cloned '$dest'..." >&2
  "$bin" --fast "$dest" || true      # clone=fast: dependencies aren't pulled yet
  return 0
}

pip()    { _sc_install_guard pip    'install'          0 "$@"; }
pip3()   { _sc_install_guard pip3   'install'          0 "$@"; }
npm()    { _sc_install_guard npm    'install|i|ci|add' 1 "$@"; }
yarn()   { _sc_install_guard yarn   'install|add'      1 "$@"; }
pnpm()   { _sc_install_guard pnpm   'install|i|add'    1 "$@"; }
poetry() { _sc_install_guard poetry 'install|add|sync' 1 "$@"; }
uv()     { _sc_install_guard uv     'sync|add|pip'     1 "$@"; }
# add another manager in one line, e.g.:
# bundle()   { _sc_install_guard bundle 'install' 1 "$@"; }
# composer() { _sc_install_guard composer 'install|require|update' 1 "$@"; }

[[ "${_sc_realias:-0}" == "1" ]] && setopt aliases
unset _sc_realias
