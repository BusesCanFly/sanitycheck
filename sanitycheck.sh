#!/usr/bin/env bash
set -euo pipefail

# sanitycheck — audit a curl|bash installer before running it.
#
# Usage:
#   sanitycheck "curl -fsSL https://example.com/install.sh | bash"
#   sanitycheck https://example.com/install.sh
#   sanitycheck "wget -qO- https://example.com/install.sh | sh"

readonly VERSION="0.2.0"
readonly PROG="$(basename "$0")"

# ---------------------------------------------------------------------------
# Colors & symbols
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
  R='\033[31m' G='\033[32m' Y='\033[33m' D='\033[2m' B='\033[1m' Z='\033[0m'
else
  R='' G='' Y='' D='' B='' Z=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die()  { printf "${R}error:${Z} %s\n" "$1" >&2; exit 1; }
info() { printf "${D}%s${Z}\n" "$1"; }

usage() {
  cat <<EOF
${PROG} v${VERSION} — audit curl|bash installers before running them

Usage:
  ${PROG} "curl -fsSL https://example.com/install.sh | bash"
  ${PROG} https://example.com/install.sh
  ${PROG} "wget -qO- https://example.com/install.sh | sh"

Flags:
  -r, --run         Prompt to run the script after audit (off by default)
  -k, --keep        Keep downloaded script and full report after exit
  -o, --output DIR  Save files to DIR instead of a tmpdir
  -h, --help        Show this help
EOF
  exit 0
}

cleanup() {
  if [[ "${KEEP:-0}" == "0" && -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ---------------------------------------------------------------------------
# Parse a curl/wget command or bare URL into just the URL
# ---------------------------------------------------------------------------

extract_url() {
  local input="$1"

  # Pull the first URL out of whatever command string was given.
  # Handles:  bare URL, curl ... | bash, bash -c "$(curl URL)", bash <(curl URL)
  local url
  url=$(printf '%s' "$input" | grep -oE 'https?://[^ "'"'"')]+' | head -1 || true)

  if [[ -n "$url" ]]; then
    printf '%s' "$url"
    return 0
  fi

  return 1
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

INPUT=""
RUN_AFTER=0
KEEP=0
OUT_DIR=""
SCRIPT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    -r|--run)     RUN_AFTER=1; shift ;;
    -k|--keep)    KEEP=1; shift ;;
    -o|--output)  OUT_DIR="$2"; shift 2 ;;
    --)           shift; SCRIPT_ARGS=("$@"); break ;;
    -*)           die "unknown flag: $1 (see --help)" ;;
    *)
      if [[ -z "$INPUT" ]]; then
        INPUT="$1"
      else
        # Multiple unquoted words — join them (handles unquoted curl commands)
        INPUT="$INPUT $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$INPUT" ]] || die "no URL or command provided (see --help)"

URL=$(extract_url "$INPUT") || die "could not find a URL in: $INPUT"

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

require_cmd curl
require_cmd claude

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

if [[ -n "$OUT_DIR" ]]; then
  mkdir -p "$OUT_DIR"
  WORK_DIR="$OUT_DIR"
else
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sanitycheck.XXXXXXXXXX")"
fi

SCRIPT_FILE="$WORK_DIR/downloaded_script.sh"
REPORT_FILE="$WORK_DIR/audit_report.md"

info "fetching $URL"
http_code=$(curl -fsSL -w '%{http_code}' -o "$SCRIPT_FILE" "$URL" 2>/dev/null) \
  || die "download failed (HTTP ${http_code:-?})"

file_size=$(wc -c < "$SCRIPT_FILE")
info "downloaded $(( file_size )) bytes"

if (( file_size > 1048576 )); then
  die "file is ${file_size} bytes — too large for a typical install script"
fi
if (( file_size == 0 )); then
  die "downloaded file is empty"
fi

# ---------------------------------------------------------------------------
# Claude Code audit
# ---------------------------------------------------------------------------

AUDIT_PROMPT='You are a security auditor. A user is about to run the following
shell script via curl|bash. Respond with ONLY valid JSON — no markdown fences,
no commentary outside the JSON object.

{
  "verdict": "SAFE" | "CAUTION" | "DANGEROUS",
  "summary": "One sentence: what the script does.",
  "warnings": ["Short string per finding worth warning about (omit if none)"]
}

Verdict rules:
- SAFE: nothing unusual for an installer script. Return empty warnings[].
- CAUTION: something genuinely unusual that is not a standard installer pattern.
- DANGEROUS: clear malicious or highly suspicious behaviour.

The following are NORMAL for installers and must NOT generate warnings:
- Using sudo/root for package managers (apt, yum, dnf, brew, pacman, etc.)
- Adding apt/yum/dnf repositories and GPG keys from the project vendor
- Writing to /usr/local, ~/.local, /opt, or ~/bin
- Modifying shell rc files (.bashrc, .zshrc, .profile) to add PATH entries
- Creating symlinks, setting chmod +x
- Detecting OS/arch via uname, /etc/os-release, etc.
- Downloading binaries from GitHub releases or the project official domain
- Enabling/starting a systemd service for the thing being installed
- Creating config directories and files for the tool being installed

Only warn about things that are UNEXPECTED for a legitimate installer:
1. Data exfiltration (POSTing data out, piping env/secrets to a server)
2. Backdoors (unauthorized_keys edits, cron jobs unrelated to the tool)
3. Credential harvesting (~/.ssh private keys, browser profiles, wallets)
4. Obfuscation (base64 payloads executed, eval of constructed strings)
5. Destructive ops (rm -rf on broad paths unrelated to the tool)
6. Suspicious network calls (hardcoded IPs, domains unrelated to the project)
7. Download-and-execute of secondary payloads from unrelated domains

Respond with raw JSON only.'

info "auditing with claude …"

RAW_RESPONSE=$(claude -p "$AUDIT_PROMPT

--- BEGIN SCRIPT ---
$(cat "$SCRIPT_FILE")
--- END SCRIPT ---" 2>/dev/null) \
  || die "claude analysis failed"

# Save full report
printf '%s\n' "$RAW_RESPONSE" > "$REPORT_FILE"

# ---------------------------------------------------------------------------
# Parse JSON response and display clean output
# ---------------------------------------------------------------------------

# Extract fields — use python if available, else basic grep/sed
parse_json() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
except Exception:
    print('PARSE_ERROR')
    sys.exit(0)
print(d.get('verdict', 'UNKNOWN'))
print(d.get('summary', ''))
for w in d.get('warnings', []):
    print('W:' + str(w))
"
  else
    local v
    v=$(grep -oE '"verdict"\s*:\s*"(SAFE|CAUTION|DANGEROUS)"' | head -1 \
      | grep -oE '(SAFE|CAUTION|DANGEROUS)' || echo "UNKNOWN")
    echo "$v"
    echo ""
  fi
}

PARSED=$(printf '%s' "$RAW_RESPONSE" | parse_json)
VERDICT=$(echo "$PARSED" | head -1)
SUMMARY=$(echo "$PARSED" | sed -n '2p')
WARNINGS=$(echo "$PARSED" | grep '^W:' | sed 's/^W://' || true)

if [[ "$VERDICT" == "PARSE_ERROR" || "$VERDICT" == "" ]]; then
  VERDICT="UNKNOWN"
fi

printf '\n'

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------

case "$VERDICT" in
  SAFE)
    printf "  ${G}[+]${Z} %s\n" "$SUMMARY"
    ;;
  CAUTION)
    printf "  ${Y}[~]${Z} %s\n" "$SUMMARY"
    while IFS= read -r line; do
      [[ -n "$line" ]] && printf "  ${Y}[~]${Z} %s\n" "$line"
    done <<< "$WARNINGS"
    ;;
  DANGEROUS)
    printf "  ${R}[!]${Z} %s\n" "$SUMMARY"
    while IFS= read -r line; do
      [[ -n "$line" ]] && printf "  ${R}[!]${Z} %s\n" "$line"
    done <<< "$WARNINGS"
    ;;
  *)
    printf "  ${Y}[?]${Z} could not determine verdict — review manually\n"
    printf "      full report: %s\n" "$REPORT_FILE"
    KEEP=1
    ;;
esac

printf '\n'

# ---------------------------------------------------------------------------
# Keep / run
# ---------------------------------------------------------------------------

if [[ "$KEEP" == "1" ]]; then
  info "script: $SCRIPT_FILE"
  info "report: $REPORT_FILE"
fi

if [[ "$RUN_AFTER" == "1" ]]; then
  case "$VERDICT" in
    SAFE)
      printf 'Run the script? [Y/n] '
      read -r answer
      case "$answer" in
        [Nn]*) printf 'Aborted.\n'; KEEP=1 ;;
        *)     printf '\n'; bash "$SCRIPT_FILE" "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}" ;;
      esac
      ;;
    CAUTION)
      printf 'Run the script? [y/N] '
      read -r answer
      case "$answer" in
        [Yy]) printf '\n'; bash "$SCRIPT_FILE" "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}" ;;
        *)    printf 'Aborted.\n'; KEEP=1 ;;
      esac
      ;;
    DANGEROUS)
      printf "${R}Run despite warnings?${Z} [y/N] "
      read -r answer
      case "$answer" in
        [Yy]) printf '\n'; bash "$SCRIPT_FILE" "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}" ;;
        *)    printf 'Aborted.\n'; KEEP=1 ;;
      esac
      ;;
    *)
      printf 'Run the script? [y/N] '
      read -r answer
      case "$answer" in
        [Yy]) printf '\n'; bash "$SCRIPT_FILE" "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}" ;;
        *)    printf 'Aborted.\n'; KEEP=1 ;;
      esac
      ;;
  esac
elif [[ "$VERDICT" == "DANGEROUS" ]]; then
  printf "${R}Execution blocked.${Z} Review: %s\n" "$SCRIPT_FILE"
  KEEP=1
  exit 1
fi
