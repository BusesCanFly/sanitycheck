#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass() { PASS=$((PASS + 1)); printf '  \033[32mpass\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    pass "$label"
  else
    fail "$label (expected '$expected', got '$actual')"
  fi
}

assert_exit() {
  local label="$1" expected="$2"; shift 2
  local rc=0
  "$@" >/dev/null 2>&1 || rc=$?
  assert_eq "$label" "$expected" "$rc"
}

# ---------------------------------------------------------------------------
# Source just the functions we need (without running main script)
# ---------------------------------------------------------------------------

# extract_url
eval "$(sed -n '/^extract_url()/,/^}/p' "$SCRIPT_DIR/sanitycheck.sh")"

# parse_json
eval "$(sed -n '/^parse_json()/,/^}/p' "$SCRIPT_DIR/sanitycheck.sh")"

# ---------------------------------------------------------------------------
printf 'extract_url\n'
# ---------------------------------------------------------------------------

assert_eq "bare https URL" \
  "https://example.com/install.sh" \
  "$(extract_url "https://example.com/install.sh")"

assert_eq "bare http URL" \
  "http://example.com/install.sh" \
  "$(extract_url "http://example.com/install.sh")"

assert_eq "curl pipe bash" \
  "https://example.com/install.sh" \
  "$(extract_url "curl -fsSL https://example.com/install.sh | bash")"

assert_eq "curl pipe sh" \
  "https://example.com/install.sh" \
  "$(extract_url "curl -fsSL https://example.com/install.sh | sh")"

assert_eq "wget pipe bash" \
  "https://example.com/install.sh" \
  "$(extract_url "wget -qO- https://example.com/install.sh | bash")"

assert_eq "curl pipe sudo bash" \
  "https://example.com/install.sh" \
  "$(extract_url "curl -fsSL https://example.com/install.sh | sudo bash")"

assert_eq "bash -c \$(curl)" \
  "https://example.com/install.sh" \
  "$(extract_url 'bash -c "$(curl -fsSL https://example.com/install.sh)"')"

assert_eq "bash process substitution" \
  "https://example.com/install.sh" \
  "$(extract_url "bash <(curl -fsSL https://example.com/install.sh)")"

assert_eq "URL with path and query" \
  "https://raw.githubusercontent.com/user/repo/main/install.sh?token=abc" \
  "$(extract_url "curl -fsSL https://raw.githubusercontent.com/user/repo/main/install.sh?token=abc | bash")"

assert_exit "no URL returns 1" 1 extract_url "no url here"
assert_exit "empty string returns 1" 1 extract_url ""

# ---------------------------------------------------------------------------
printf '\nparse_json\n'
# ---------------------------------------------------------------------------

PARSED=$(printf '{"verdict":"SAFE","summary":"Installs foo.","warnings":[]}' | parse_json)
assert_eq "SAFE verdict" "SAFE" "$(echo "$PARSED" | head -1)"
assert_eq "SAFE summary" "Installs foo." "$(echo "$PARSED" | sed -n '2p')"
assert_eq "SAFE no warnings" "" "$(echo "$PARSED" | grep '^W:' || true)"

PARSED=$(printf '{"verdict":"CAUTION","summary":"Installs bar.","warnings":["telemetry","modifies cron"]}' | parse_json)
assert_eq "CAUTION verdict" "CAUTION" "$(echo "$PARSED" | head -1)"
assert_eq "CAUTION summary" "Installs bar." "$(echo "$PARSED" | sed -n '2p')"
assert_eq "CAUTION warning count" "2" "$(echo "$PARSED" | grep -c '^W:' || true)"
assert_eq "CAUTION warning 1" "W:telemetry" "$(echo "$PARSED" | grep '^W:' | head -1)"

PARSED=$(printf '{"verdict":"DANGEROUS","summary":"Malware.","warnings":["steals keys","backdoor"]}' | parse_json)
assert_eq "DANGEROUS verdict" "DANGEROUS" "$(echo "$PARSED" | head -1)"
assert_eq "DANGEROUS warning count" "2" "$(echo "$PARSED" | grep -c '^W:' || true)"

PARSED=$(printf 'this is not json' | parse_json)
assert_eq "invalid JSON returns PARSE_ERROR" "PARSE_ERROR" "$(echo "$PARSED" | head -1)"

PARSED=$(printf '{"summary":"no verdict field"}' | parse_json)
assert_eq "missing verdict returns UNKNOWN" "UNKNOWN" "$(echo "$PARSED" | head -1)"

# ---------------------------------------------------------------------------
printf '\nCLI flags\n'
# ---------------------------------------------------------------------------

assert_exit "--help exits 0" 0 bash "$SCRIPT_DIR/sanitycheck.sh" --help
assert_exit "-h exits 0" 0 bash "$SCRIPT_DIR/sanitycheck.sh" -h
assert_exit "no args exits 1" 1 bash "$SCRIPT_DIR/sanitycheck.sh"
assert_exit "unknown flag exits 1" 1 bash "$SCRIPT_DIR/sanitycheck.sh" --bogus
assert_exit "no URL in input exits 1" 1 bash "$SCRIPT_DIR/sanitycheck.sh" "just words"

# ---------------------------------------------------------------------------
printf '\ncolors\n'
# ---------------------------------------------------------------------------

# When not a tty, colors should be empty
OUTPUT=$(bash "$SCRIPT_DIR/sanitycheck.sh" --help 2>&1 | cat -v)
if [[ "$OUTPUT" != *$'\033'* ]]; then
  pass "no escape codes when piped"
else
  fail "escape codes present when piped"
fi

# ---------------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
