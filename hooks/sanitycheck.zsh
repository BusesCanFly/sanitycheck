# sanitycheck shell hook  (zsh + bash)
#
# Auto-audits untrusted code at the moments you get burned:
#   1. running a  curl|bash  installer   (zsh only, via the zle line editor)
#   2. right after  git clone <url>      -> FAST static scan of the checkout
#   3. right before installing deps      -> DEEP scan (with dependency resolution):
#        pip, pip3, pipx, npm, yarn, pnpm, poetry, uv, go
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

# One "sanitycheck:" label for every message, so wording and color match across
# the curl|bash, git-clone, and install-guard paths. Yellow on a color terminal;
# plain when NO_COLOR is set or stderr is not a tty.
_sc_label() {
  if [[ -z "${NO_COLOR:-}" && -t 2 ]]; then printf '\033[33msanitycheck:\033[0m'
  else printf 'sanitycheck:'; fi
}
# a status/aborted line: "sanitycheck: <msg>" on its own line
_sc_say() { printf '%s %s\n' "$(_sc_label)" "$1" >&2; }

# Read a single keypress from the terminal without echoing it, then print one
# newline ourselves. Silent read (-s) is what makes spacing deterministic: the
# terminal no longer echoes the key (which happened or not depending on tty
# mode), so every path prints exactly one line break after the prompt.
_sc_readkey() {  # -> echoes the key
  local ans=""
  if [[ -n "${ZSH_VERSION:-}" ]]; then read -rsk1 ans </dev/tty 2>/dev/null || ans=""
  else read -rsn1 ans </dev/tty 2>/dev/null || ans=""; fi
  printf '\n' >&2
  printf '%s' "$ans"
}
# Ask a yes-default question, same style everywhere: "sanitycheck: <q> [Y/n] ".
# Enter (or anything but n) proceeds. No terminal -> nobody to ask, so proceed
# with the automatic scan (scripts stay covered and never hang on a read).
_sc_ask() {  # question -> 0 = yes/proceed, 1 = no/skip
  [[ -t 0 && -t 2 ]] || return 0
  printf '%s %s [Y/n] ' "$(_sc_label)" "$1" >&2
  [[ "$(_sc_readkey)" != [Nn] ]]
}
# Ask a no-default question (for the "run it anyway?" confirm after DANGEROUS).
# Any args after the question are a command that reprints the audit in full - the
# user presses `v` to see it, since under the hook the tool can't be re-run with
# -v by hand. Loops on `v`, otherwise y = proceed, anything else = abort.
_sc_ask_risky() {  # question [detail-cmd...] -> 0 = yes/proceed, 1 = no/abort
  [[ -t 0 && -t 2 ]] || return 1        # non-interactive: refuse by default
  local q="$1"; shift
  local vk=""; (( $# )) && vk="/v"
  while :; do
    printf '%s %s [y/N%s] ' "$(_sc_label)" "$q" "$vk" >&2
    local k; k="$(_sc_readkey)"
    if [[ -n "$vk" && "$k" == [Vv] ]]; then "$@"; continue; fi
    [[ "$k" == [Yy] ]] && return 0 || return 1
  done
}

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
      local orig="$BUFFER" answer
      # We are about to write to the terminal from inside a widget: invalidate
      # zle's display first, or the next redraw lands at a stale cursor
      # position and smears across the [Y/n] line.
      zle -I
      echo ""
      printf '%s audit this before running? [Y/n] ' "$(_sc_label)"
      read -rsk1 answer; echo ""
      if [[ "$answer" != [Nn] ]]; then
        # Run the audit right here instead of rewriting BUFFER: zle displays
        # whatever buffer it accepts, and echoing a `sanitycheck -r '...'`
        # one-liner (plus a redrawn prompt) reads as clutter. History keeps the
        # command the user actually typed.
        print -s -- "$orig"
        BUFFER=""
        "$SANITYCHECK_BIN" -r "$orig" </dev/tty
      fi
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
_sc_install_guard() {  # display-cmd  trigger-ere  project(0|1)  skip-lead  args...
  local bin; bin="$(_sanitycheck_bin)"
  local cmd="$1" trig="$2" project="$3" skip="$4"; shift 4
  [[ "$SANITYCHECK_HOOK" == "1" && -n "$bin" ]] || { command "$cmd" "$@"; return $?; }
  # walk the args once: skip `skip` leading non-flag tokens that are part of the
  # command itself (e.g. the "pip" in `uv pip install`), then read the subcommand
  # (next non-flag), an explicit local target (a path, `-r <reqfile>`, or
  # `-e <path>`), and any *named* registry packages.
  # `cmd` stays the real executable (for `command "$cmd" ...`); `disp` is the
  # human name, which grows to include skipped tokens like "uv pip".
  local sub="" target="" prev="" seen=0 skipped=0 a base disp="$cmd"
  local -a pkgs; pkgs=()
  for a in "$@"; do
    if [[ "$a" == -* ]]; then prev="$a"; continue; fi
    case "$prev" in
      -r|--requirement) [[ -f "$a" ]] && target="$(dirname "$a")"; prev="$a"; continue ;;
      -e|--editable)    [[ -e "$a" ]] && target="$a"; prev="$a"; continue ;;
    esac
    if (( skipped < skip )); then disp="$disp $a"; skipped=$((skipped+1)); prev="$a"; continue; fi
    if [[ "$seen" == 0 ]]; then
      sub="$a"; seen=1
    else
      case "$a" in
        .|./*|../*|/*)
          if [[ -e "$a" ]]; then target="$a"              # a local path
          else
            # Go package patterns (./... , ./cmd/...) are not paths on disk;
            # the directory above the wildcard is what to scan.
            base="${a%/...}"
            [[ "$base" != "$a" && -e "$base" ]] && target="$base"
          fi ;;
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

  # A registry redirect given on the command line (pip --index-url,
  # npm --registry) aims installs at a non-official host with no config file for
  # detect_registry_redirect to catch. Surface it - the same MED-level signal,
  # noted at the moment it matters.
  local ra rprev="" rhost=""
  for ra in "$@"; do
    case "$rprev" in --index-url|--extra-index-url|-i|--registry) rhost="$ra" ;; esac
    case "$ra" in --index-url=*|--extra-index-url=*|--registry=*) rhost="${ra#*=}" ;; esac
    rprev="$ra"
  done
  if [[ "$rhost" == *://* ]]; then
    local rh="${rhost#*://}"; rh="${rh%%/*}"; rh="${rh##*@}"; rh="${rh%%:*}"
    case "$rh" in
      registry.npmjs.org|registry.yarnpkg.com|npm.pkg.github.com|\
      pypi.org|files.pythonhosted.org|pypi.python.org|test.pypi.org) ;;
      '') ;;
      *) _sc_say "note: installs are being redirected to '$rh' (not the official registry)" ;;
    esac
  fi

  # bare project install (no path, no named pkg) audits the cwd project
  [[ -z "$target" && "$project" == 1 && ${#pkgs[@]} -eq 0 ]] && target="."

  local rc=0 what="$disp${sub:+ $sub}"
  local -a dtl; dtl=()                            # command `v` re-runs for detail
  if [[ -n "$target" && -e "$target" ]]; then
    # a local project/path -> full scan
    _sc_ask "audit '$target' before $what?" || { command "$cmd" "$@"; return $?; }
    "$bin" $(_sc_fast) "$target"; rc=$?          # deep unless SANITYCHECK_HOOK_FAST
    dtl=("$bin" -v); [[ -n "${SANITYCHECK_HOOK_FAST:-}" ]] && dtl+=(--fast); dtl+=("$target")
  elif [[ ${#pkgs[@]} -gt 0 ]]; then
    # named registry package(s) -> check the NAME(s) against IOCs and, when
    # online, download+scan the actual package contents (no cwd scan). Silent
    # unless something is flagged.
    _sc_ask "audit ${pkgs[*]} before $what?" || { command "$cmd" "$@"; return $?; }
    local eco=""
    case "$cmd" in
      pip|pip3|pipx|poetry|uv) eco="pypi" ;;
      npm|yarn|pnpm)           eco="npm" ;;
      go)                      eco="go" ;;
      cargo)                   eco="crates" ;;
      # gem/bundle have no fetch support, so they get the offline name check
      # against the IOC list and nothing else.
    esac
    local -a cka; cka=(--check-pkg)
    [[ -n "$eco" ]] && cka+=(--ecosystem "$eco")
    [[ -n "${SANITYCHECK_HOOK_FAST:-}" ]] && cka+=(--fast)
    "$bin" "${cka[@]}" "${pkgs[@]}"; rc=$?
    dtl=("$bin" -v "${cka[@]}" "${pkgs[@]}")
  else
    command "$cmd" "$@"; return $?
  fi

  if [[ $rc -eq 1 ]]; then                         # exit 1 == DANGEROUS
    if [[ "${SANITYCHECK_HOOK_STRICT:-0}" == "1" ]]; then
      _sc_say "$what aborted (DANGEROUS)."; return 1
    fi
    _sc_ask_risky "DANGEROUS - run $what anyway?" "${dtl[@]}" || { _sc_say "$what aborted."; return 1; }
  fi
  command "$cmd" "$@"
}

# Guard for the download-and-RUN commands: npx / yarn dlx / pnpm dlx / bunx / uvx
# / uv tool run. These fetch a package and execute it immediately - strictly more
# dangerous than installing it - and unlike an install there is no subcommand:
# the package to run is the first non-flag token (after `skip` leading tokens,
# e.g. the `dlx` in `yarn dlx`). Routes to the same --check-pkg name+content vet.
_sc_runner_guard() {  # display  real-cmd  ecosystem  skip  args...
  local disp="$1" cmd="$2" eco="$3" skip="$4"; shift 4
  local bin; bin="$(_sanitycheck_bin)"
  [[ "$SANITYCHECK_HOOK" == "1" && -n "$bin" ]] || { command "$cmd" "$@"; return $?; }
  local a prev="" skipped=0 pkg=""
  for a in "$@"; do
    # an explicit -p/--package <pkg> names the package directly
    case "$prev" in -p|--package) pkg="$a"; break ;; esac
    if [[ "$a" == -* ]]; then prev="$a"; continue; fi
    if (( skipped < skip )); then skipped=$((skipped+1)); prev="$a"; continue; fi
    pkg="$a"; break
  done
  [[ -n "$pkg" ]] || { command "$cmd" "$@"; return $?; }
  _sc_ask "audit '$pkg' before $disp runs it?" || { command "$cmd" "$@"; return $?; }
  local -a cka; cka=(--check-pkg --ecosystem "$eco")
  [[ -n "${SANITYCHECK_HOOK_FAST:-}" ]] && cka+=(--fast)
  "$bin" "${cka[@]}" "$pkg"; local rc=$?
  if [[ $rc -eq 1 ]]; then
    if [[ "${SANITYCHECK_HOOK_STRICT:-0}" == "1" ]]; then _sc_say "$disp aborted (DANGEROUS)."; return 1; fi
    _sc_ask_risky "DANGEROUS - run $disp anyway?" "$bin" -v "${cka[@]}" "$pkg" \
      || { _sc_say "$disp aborted."; return 1; }
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
  # Fail open: a function shadowing git must never break git. If the helper did
  # not travel with this wrapper (e.g. only the function body was captured),
  # fall straight through to the real command.
  typeset -f _sanitycheck_bin >/dev/null 2>&1 || { command git "$@"; return $?; }
  local bin; bin="$(_sanitycheck_bin)"
  if [[ "$SANITYCHECK_HOOK" != "1" || -z "$bin" ]]; then
    command git "$@"; return $?
  fi

  # Find the subcommand, skipping leading global options and any value they take
  # (`git -C <dir> clone`, `git -c k=v clone`), so those forms still hook rather
  # than bypassing. Everything after the subcommand is collected for parsing.
  local a sub="" seen_sub=0 want_val=0
  local -a rest=()
  for a in "$@"; do
    if [[ "$seen_sub" == 1 ]]; then rest+=("$a"); continue; fi
    if (( want_val )); then want_val=0; continue; fi
    case "$a" in
      -C|-c|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix) want_val=1 ;;
      --git-dir=*|--work-tree=*|--namespace=*|--exec-path=*|--super-prefix=*|-*) : ;;
      *) sub="$a"; seen_sub=1 ;;
    esac
  done
  [[ "$sub" == "clone" ]] || { command git "$@"; return $?; }

  command git "$@" || return $?

  # Parse clone's positional args, skipping value-taking options so a branch,
  # depth or origin value is never mistaken for the destination directory:
  #   git clone [options] <repo> [<dir>]
  local repo="" dest="" np=0
  want_val=0
  for a in "${rest[@]}"; do
    if (( want_val )); then want_val=0; continue; fi
    case "$a" in
      -b|--branch|-o|--origin|-u|--upload-pack|-c|--config|--depth|--reference|\
      --reference-if-able|-j|--jobs|--template|--separate-git-dir|--filter|\
      --shallow-since|--shallow-exclude|--server-option|--bundle-uri) want_val=1 ;;
      -*) : ;;
      *) np=$((np+1)); if (( np == 1 )); then repo="$a"; elif (( np == 2 )); then dest="$a"; fi ;;
    esac
  done
  # No explicit target dir: git derives it from the repo's basename.
  [[ -z "$dest" ]] && dest="$(basename "${repo%.git}")"
  [[ -d "$dest" ]] || return 0
  _sc_ask "audit '$dest'?" || return 0
  "$bin" --fast "$dest" || true      # clone=fast: dependencies aren't pulled yet
  return 0
}

# Every wrapper fails open the same way: if _sc_install_guard did not travel with
# the function body, delegate to the real command rather than break it. The check
# is `typeset` (a builtin, always present) inline in each body, so a missing
# helper never even prints a "command not found" - it just falls through.
pip()    { typeset -f _sc_install_guard >/dev/null 2>&1 || { command pip    "$@"; return $?; }; _sc_install_guard pip    'install'             0 0 "$@"; }
pip3()   { typeset -f _sc_install_guard >/dev/null 2>&1 || { command pip3   "$@"; return $?; }; _sc_install_guard pip3   'install'             0 0 "$@"; }
pipx()   { typeset -f _sc_install_guard >/dev/null 2>&1 || { command pipx   "$@"; return $?; }; _sc_install_guard pipx   'install|inject|run'  0 0 "$@"; }
npm()    { typeset -f _sc_install_guard >/dev/null 2>&1 || { command npm    "$@"; return $?; }; _sc_install_guard npm    'install|i|ci|add' 1 0 "$@"; }
yarn()   {
  typeset -f _sc_install_guard >/dev/null 2>&1 || { command yarn "$@"; return $?; }
  if [[ "${1:-}" == dlx ]]; then _sc_runner_guard 'yarn dlx' yarn npm 1 "$@"
  else _sc_install_guard yarn 'install|add' 1 0 "$@"; fi
}
pnpm()   {
  typeset -f _sc_install_guard >/dev/null 2>&1 || { command pnpm "$@"; return $?; }
  if [[ "${1:-}" == dlx ]]; then _sc_runner_guard 'pnpm dlx' pnpm npm 1 "$@"
  else _sc_install_guard pnpm 'install|i|add' 1 0 "$@"; fi
}
# The download-and-run commands. npx/bunx run npm packages; uvx runs a PyPI tool.
npx()    { typeset -f _sc_runner_guard >/dev/null 2>&1 || { command npx  "$@"; return $?; }; _sc_runner_guard npx  npx  npm  0 "$@"; }
bunx()   { typeset -f _sc_runner_guard >/dev/null 2>&1 || { command bunx "$@"; return $?; }; _sc_runner_guard bunx bunx npm  0 "$@"; }
uvx()    { typeset -f _sc_runner_guard >/dev/null 2>&1 || { command uvx  "$@"; return $?; }; _sc_runner_guard uvx  uvx  pypi 0 "$@"; }
poetry() { typeset -f _sc_install_guard >/dev/null 2>&1 || { command poetry "$@"; return $?; }; _sc_install_guard poetry 'install|add|sync' 1 0 "$@"; }
uv() {
  typeset -f _sc_install_guard >/dev/null 2>&1 || { command uv "$@"; return $?; }
  # uv has two shapes: native (`uv add|sync|lock`) and a pip passthrough
  # (`uv pip install|sync ...`). For the latter, skip the leading "pip" token so
  # the subcommand and package names parse correctly.
  if [[ "${1:-}" == pip ]]; then _sc_install_guard uv 'install|sync' 0 1 "$@"
  elif [[ "${1:-}" == tool && "${2:-}" == run ]]; then _sc_runner_guard 'uv tool run' uv pypi 2 "$@"
  else _sc_install_guard uv 'sync|add|lock' 1 0 "$@"; fi
}
# `go install pkg@version` fetches a module and compiles it; `go get` fetches
# without building. Both pull down code you did not write.
#
# Not hooked: `go build` and `go run`. Those are the inner loop of working on a
# Go project, and prompting on every one of them is how a check gets switched
# off. `go run pkg@version` does execute a remote module and is a genuine gap -
# but the clone and install scans are what cover that path.
go() {
  typeset -f _sc_install_guard >/dev/null 2>&1 || { command go "$@"; return $?; }
  # With a subcommand, project=1 so that a bare `go install` (no package, no
  # path) audits the current module. Without one, project=0 keeps plain `go`
  # from being treated as an install of the working directory.
  case "${1:-}" in
    install|get) _sc_install_guard go 'install|get' 1 0 "$@" ;;
    *)           _sc_install_guard go 'install|get' 0 0 "$@" ;;
  esac
}
# `cargo install` downloads a crate and compiles it, and a build.rs runs during
# that compile - the same install-time execution as setup.py or a postinstall
# script, on a toolchain nobody thinks of as one. `cargo build`/`test`/`run` are
# deliberately not hooked, for the same reason `go build` is not: they are the
# inner loop, and a check that fires every few seconds gets switched off.
cargo()  { typeset -f _sc_install_guard >/dev/null 2>&1 || { command cargo  "$@"; return $?; }; _sc_install_guard cargo  'install|add'     1 0 "$@"; }
# No registry fetch for these two, so they get the offline name check only.
gem()    { typeset -f _sc_install_guard >/dev/null 2>&1 || { command gem    "$@"; return $?; }; _sc_install_guard gem    'install'         0 0 "$@"; }
bundle() { typeset -f _sc_install_guard >/dev/null 2>&1 || { command bundle "$@"; return $?; }; _sc_install_guard bundle 'install|add'     1 0 "$@"; }
# add another manager in one line, e.g.:
# composer() { _sc_install_guard composer 'install|require|update' 1 0 "$@"; }

[[ "${_sc_realias:-0}" == "1" ]] && setopt aliases
unset _sc_realias
