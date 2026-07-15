#!/usr/bin/env bash
# sanitycheck test suite. Unit-tests pure functions (sourced individually, the
# main script is not run) plus integration tests over inert fixtures. Offline and
# deterministic: no network, no LLM, fixtures never execute (dangerous lines are
# quoted strings or behind SystemExit guards).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SC="$HERE/sanitycheck.sh"
FIX="$HERE/tests"
if [[ -t 1 ]]; then G=$'\033[32m' R=$'\033[31m' Z=$'\033[0m'; else G='' R='' Z=''; fi
fails=0
pass() { printf '  %sPASS%s  %s\n' "$G" "$Z" "$1"; }
fail() { printf '  %sFAIL%s  %s\n' "$R" "$Z" "$1"; fails=$((fails+1)); }
eq()   { [[ "$2" == "$3" ]] && pass "$1" || fail "$1 (want '$3' got '$2')"; }

# --- unit: source individual functions without running main -------------------
eval "$(sed -n '/^extract_url()/,/^}/p'         "$SC")"
eval "$(sed -n '/^classify_input()/,/^}/p'      "$SC")"
eval "$(sed -n '/^sev_rank()/,/^}/p'            "$SC")"
eval "$(sed -n '/^more_severe()/,/^}/p'         "$SC")"
eval "$(sed -n '/^demote_for_installer()/,/^}/p' "$SC")"
eval "$(sed -n '/^parse_llm()/,/^}/p' "$SC")"

echo "unit: parse_llm (LLM response parsing)"
parse_llm 'sure: {"verdict":"dangerous","summary":"drops a RAT","warnings":["revshell"]} done'
eq "verdict parsed" "$LLM_VERDICT" "DANGEROUS"
eq "summary parsed" "$LLM_SUMMARY" "drops a RAT"

eval "$(sed -n '/^extract_fetch_urls()/,/^}/p' "$SC")"
echo "unit: extract_fetch_urls (staged-download URL extraction)"
utf=$(mktemp)
printf 'curl -fsSL https://a.example/s2.sh -o /tmp/x\nwget http://b.example/p.bin\necho see https://not-fetched.example/docs\n' > "$utf"
uurls="$(extract_fetch_urls "$utf")"
[[ "$uurls" == *"https://a.example/s2.sh"* ]] && pass "extracts curl download URL" || fail "curl url"
[[ "$uurls" == *"http://b.example/p.bin"* ]] && pass "extracts wget download URL" || fail "wget url"
[[ "$uurls" != *"not-fetched"* ]] && pass "ignores non-download URL" || fail "over-extracts"
rm -f "$utf"

echo "unit: classify_input"
eq "dir -> repo"                "$(classify_input "$FIX/benign-poc")" "repo"
eq ".py file -> file"           "$(classify_input "$FIX/caution-poc/poc.py")" "file"
eq "curl|bash cmd -> installer" "$(classify_input 'curl -fsSL https://x.io/i.sh | bash')" "installer"
eq "script URL -> installer"    "$(classify_input 'https://x.io/install.sh')" "installer"
eq "git URL -> repo"            "$(classify_input 'https://github.com/u/repo.git')" "repo"
eq "github repo URL -> repo"    "$(classify_input 'https://github.com/u/repo')" "repo"
eq "raw .sh URL -> installer"   "$(classify_input 'https://raw.githubusercontent.com/u/r/main/install.sh')" "installer"

echo "unit: extract_url"
eq "url from curl cmd" "$(extract_url 'curl -fsSL https://x.io/i.sh | bash')" "https://x.io/i.sh"

echo "unit: more_severe"
eq "DANGEROUS beats CAUTION" "$(more_severe CAUTION DANGEROUS)" "DANGEROUS"
eq "CAUTION beats SAFE"      "$(more_severe SAFE CAUTION)" "CAUTION"

echo "unit: demote_for_installer (anti-cry-wolf)"
MODE=installer
eq "persistence demoted to LOW"   "$(demote_for_installer persistence MED)" "LOW"
eq "download-exec HIGH -> MED"    "$(demote_for_installer download-exec HIGH)" "MED"
eq "reverse-shell stays HIGH"     "$(demote_for_installer reverse-shell HIGH)" "HIGH"
MODE=repo
eq "no demotion in repo mode"     "$(demote_for_installer persistence MED)" "MED"

# --- integration: fixtures (offline, no LLM) ---------------------------------
scan() { # dir [flags...]
  local dir="$1"; shift
  local json; json="$("$SC" --offline "$@" --json "$FIX/$dir" 2>/dev/null)"
  "$SC" --offline "$@" "$FIX/$dir" >/dev/null 2>&1; EXIT=$?
  VERDICT="$(printf '%s' "$json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
  TAGS=" $(printf '%s' "$json" | python3 -c 'import json,sys;print(" ".join(sorted({f["tag"] for f in json.load(sys.stdin)["findings"]})))' 2>/dev/null) "
}
has() { [[ "$TAGS" == *" $1 "* ]] && pass "detects $1" || fail "missing tag $1"; }

echo "integration: benign-poc -> SAFE"
scan benign-poc;   eq "verdict" "$VERDICT" "SAFE"; eq "exit" "$EXIT" "0"

echo "integration: benign-npm -> not DANGEROUS (legit node-gyp postinstall = MED, not a dropper)"
scan benign-npm
[[ "$VERDICT" != "DANGEROUS" ]] && pass "benign npm is not DANGEROUS ($VERDICT)" || fail "benign npm FP: DANGEROUS"
expect_no_tag() { [[ "$TAGS" != *" $1 "* ]] && pass "no $1" || fail "unexpected $1"; }
expect_no_tag npm-script-exec

echo "integration: chocopoc-lookalike -> DANGEROUS"
scan chocopoc-lookalike; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in import-shadow ioc-pkg ioc-str native-load env-gating pth-exec harvest sni-front doh; do has "$t"; done

echo "integration: generic-malware -> DANGEROUS"
scan generic-malware; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in reverse-shell download-exec destructive win-lolbin exfil-channel; do has "$t"; done

echo "integration: deep-triggers -> DANGEROUS (Python deep-pass)"
scan deep-triggers; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in typosquat ast-install-exec ast-decode-exec entropy-blob; do has "$t"; done

echo "integration: dev-targeting -> DANGEROUS (editor/IDE/CI autorun + Trojan Source)"
scan dev-targeting; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in ide-autorun direnv conftest-exec py-startup-hook npm-install-script npm-script-exec trojan-source; do has "$t"; done

echo "integration: evasion -> DANGEROUS (obfuscation/normalization variants still caught)"
scan evasion; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in reverse-shell ioc-pkg typosquat import-shadow trojan-source win-lolbin; do has "$t"; done

echo "hook: git/pip/npm wrappers"
htmp=$(mktemp -d); fbin=$(mktemp -d); wrapd=$(mktemp -d)
# offline wrapper so the hook scans stay fast/deterministic in the test (real
# hooks run with network resolve on)
printf '#!/bin/sh\nexec "%s" --offline "$@"\n' "$SC" > "$wrapd/sc"; chmod +x "$wrapd/sc"
cp "$FIX/dev-targeting/package.json" "$htmp/package.json"   # known-DANGEROUS npm project
printf '#!/bin/sh\necho REAL_RAN\n' > "$fbin/npm"; cp "$fbin/npm" "$fbin/pip3"; chmod +x "$fbin/npm" "$fbin/pip3"
henv=(SANITYCHECK_BIN="$wrapd/sc" SANITYCHECK_HOOK=1 SANITYCHECK_HOOK_STRICT=1)
nout=$(cd "$htmp" && PATH="$fbin:$PATH" env "${henv[@]}" bash -c "source '$HERE/hooks/sanitycheck.zsh'; npm install 2>&1" </dev/null)
[[ "$nout" == *"npm install aborted"* && "$nout" != *REAL_RAN* ]] && pass "npm install aborts + blocks real npm" || fail "npm wrapper"
pout=$(PATH="$fbin:$PATH" env "${henv[@]}" bash -c "source '$HERE/hooks/sanitycheck.zsh'; pip3 install '$FIX/chocopoc-lookalike' 2>&1" </dev/null)
[[ "$pout" == *"install aborted"* && "$pout" != *REAL_RAN* ]] && pass "pip3 install aborts + blocks real pip" || fail "pip wrapper"
gsrc=$(mktemp -d); gdstp=$(mktemp -d); cp -R "$FIX/chocopoc-lookalike/." "$gsrc/"
( cd "$gsrc" && git init -q && git add -A && git -c commit.gpgsign=false \
    -c user.email=a@b -c user.name=a commit -qm x --no-verify ) >/dev/null 2>&1
gout=$(env SANITYCHECK_BIN="$wrapd/sc" SANITYCHECK_HOOK=1 bash -c "source '$HERE/hooks/sanitycheck.zsh'; git clone -q '$gsrc' '$gdstp/c' 2>&1" </dev/null)
[[ "$gout" == *"scanning freshly cloned"* && "$gout" == *DANGEROUS* ]] && pass "git clone scans the checkout" || fail "git clone wrapper"
rm -rf "$htmp" "$fbin" "$wrapd" "$gsrc" "$gdstp"

if command -v zsh >/dev/null 2>&1; then
  echo "hook: curl|bash matcher (zsh POSIX-ERE)"
  zmatch() { CMD="$1" zsh -c "source '$HERE/hooks/sanitycheck.zsh'; _sanitycheck_match \"\$CMD\""; }
  zmatch 'curl -fsSL https://x.io/i.sh | bash' && pass "matches curl|bash" || fail "curl|bash not matched"
  zmatch 'wget -qO- https://x.io/i.sh | sudo sh' && pass "matches wget|sudo sh" || fail "wget|sudo sh not matched"
  zmatch 'bash <(curl -fsSL https://x.io/i.sh)' && pass "matches bash <(curl)" || fail "process-sub not matched"
  zmatch 'curl -fsSL https://x.io/f.tgz -o f.tgz' && fail "false-matched a plain curl download" || pass "ignores plain curl download"
else
  echo "hook: (zsh unavailable — skipping curl|bash matcher test)"
fi

echo "integration: caution-poc -> CAUTION + --strict exit codes"
scan caution-poc; eq "verdict" "$VERDICT" "CAUTION"; eq "exit (default)" "$EXIT" "0"
scan caution-poc --strict; eq "exit (--strict)" "$EXIT" "1"

echo
if (( fails )); then printf '%sFAIL%s: %d check(s) failed\n' "$R" "$Z" "$fails"; exit 1; fi
printf '%sPASS%s: all checks passed\n' "$G" "$Z"
