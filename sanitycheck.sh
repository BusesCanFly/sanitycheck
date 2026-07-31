#!/usr/bin/env bash
#
# sanitycheck - audit untrusted code before you run it.
#
# One command, auto-detected input:
#   * a `curl | bash` installer (URL or command)   -> installer audit
#   * a cloned PoC repo (dir / archive / git URL)   -> repo + dependency audit
#   * a single source file                          -> file audit
#
# It flags the ChocoPoC class of supply-chain trojan (malware hidden in a PoC's
# transitive dependencies, compiled extensions that shadow .py files on import,
# install-time setup.py hooks, DoH/SNI-fronted C2, credential harvesting) AND
# general malware (reverse shells, download-and-exec, destructive ops, encoded
# PowerShell, exfil, miners, persistence, keylogging, wallet/credential theft).
#
# Design: static-first and effectiveness-first. Every check the environment
# supports runs automatically; flags only ever SUBTRACT work. The core runs
# offline with zero required dependencies. python3 (optional) adds an AST /
# typosquat deep-pass, safe transitive dependency resolution, and JSON. An LLM
# (optional) adds a second opinion when a provider is available.
#
# It NEVER installs, imports, builds, or executes the target.
#
set -euo pipefail

VERSION="1.0.0"
SELF="$(basename "$0")"

# --- config / flags ----------------------------------------------------------
JSON=0
STRICT=0            # --strict : CAUTION also exits nonzero (CI gate)
KEEP=0
RUN_AFTER=0         # -r       : offer to run an installer after the audit
FAST=0              # --fast   : static only (skip network resolve + LLM)
OFFLINE=0           # --offline: no network at all (implies no resolve, no LLM)
NO_LLM=0            # --no-llm : skip the LLM second opinion
FOLLOW=1            # --no-follow : don't fetch staged payloads an installer downloads
VERBOSE=0
NO_COLOR=0
OUT_DIR=""
PROVIDER="${SANITYCHECK_PROVIDER:-auto}"
MODEL="${SANITYCHECK_MODEL:-}"
EXTRA_IOCS=()
TARGET=""
MODE=""             # installer | repo | file | pkgcheck  (auto-detected)
ASAR_PASS=0          # scanning inside an unpacked .asar (see demote_for_mode)
CHECK_PKG=0         # --check-pkg : vet named packages (name IOC + fetch/scan)
ECOSYSTEM=""        # --ecosystem : pypi | npm  (registry to fetch --check-pkg from)
PKG_NAMES=()

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IOC_DB="${SANITYCHECK_IOCS:-}"
if [[ -z "$IOC_DB" ]]; then
  for c in "$_HERE/iocs/chocopoc.txt" \
           "$_HERE/../share/sanitycheck/iocs/chocopoc.txt" \
           "${XDG_CONFIG_HOME:-$HOME/.config}/sanitycheck/iocs/chocopoc.txt"; do
    [[ -f "$c" ]] && { IOC_DB="$c"; break; }
  done
fi

HELPER="${SANITYCHECK_DEEP:-}"
if [[ -z "$HELPER" ]]; then
  for c in "$_HERE/sanitycheck_deep.py" \
           "$_HERE/../share/sanitycheck/sanitycheck_deep.py" \
           "$_HERE/../libexec/sanitycheck/sanitycheck_deep.py" \
           "${XDG_DATA_HOME:-$HOME/.local/share}/sanitycheck/sanitycheck_deep.py"; do
    [[ -f "$c" ]] && { HELPER="$c"; break; }
  done
fi

# --- colors ------------------------------------------------------------------
setup_colors() {
  if [[ "$NO_COLOR" == "1" || ! -t 1 ]]; then
    R='' G='' Y='' C='' D='' B='' Z=''
  else
    R=$'\033[31m' G=$'\033[32m' Y=$'\033[33m' C=$'\033[36m' D=$'\033[2m' B=$'\033[1m' Z=$'\033[0m'
  fi
}

die()  { printf '%s%s error:%s %s\n' "$R" "$SELF" "$Z" "$*" >&2; exit 2; }
info() { [[ "$VERBOSE" == "1" ]] && printf '%s[*]%s %s\n' "$D" "$Z" "$*" >&2 || true; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
${B}sanitycheck${Z} v$VERSION - audit untrusted code before you run it.

Auto-detects what you give it: a curl|bash installer, a cloned PoC repo (dir,
archive, or git URL), or a single source file. Runs every applicable check.

${B}USAGE${Z}
  $SELF [options] <curl|bash cmd | url | path | archive | git-url>

${B}OPTIONS${Z}  (defaults run every applicable check; flags turn parts off)
  -r, --run             Offer to run an installer script after the audit
  --fast                Static checks only (skip network resolve + LLM)
  --offline             No network at all (implies --fast for network layers)
  --no-llm              Skip the LLM second opinion
  --no-follow           Don't fetch staged payloads the installer would download
  --provider <name>     LLM provider: auto|ollama|claude-api|openai|claude-cli
  --model <name>        Override the LLM model
  --ioc <file>          Additional IOC database (repeatable)
  --strict              Exit nonzero on CAUTION as well as DANGEROUS (CI)
  --json                Machine-readable JSON report
  -o, --output <dir>    Keep downloads/extractions in <dir>
  -k, --keep            Keep the temp workdir
  --no-color            Disable ANSI color
  -v, --verbose         Show LOW findings and progress
  -h, --help            This help
  --version             Print version

${B}EXAMPLES${Z}
  $SELF "curl -fsSL https://example.com/install.sh | bash"
  $SELF ./CVE-2026-12345-poc
  $SELF https://github.com/x/poc.git
  $SELF exploit.py

${B}EXIT CODES${Z}
  0  SAFE / CAUTION      1  DANGEROUS      2  error
  (with --strict, CAUTION exits 1 too)
EOF
  exit 0
}

# --- findings store ----------------------------------------------------------
F_SEV=(); F_TAG=(); F_FILE=(); F_LINE=(); F_MSG=()
N_CRIT=0; N_HIGH=0; N_MED=0; N_LOW=0

# In installer mode, patterns that are normal for legitimate installers are
# demoted so the tool doesn't cry wolf. Unambiguous malware tags keep full
# severity. (Effectiveness includes staying trusted enough to be read.)
demote_for_mode() { # tag sev  ->  echoes a possibly-lowered severity
  local tag="$1" sev="$2"
  # Inside an unpacked .asar the subject is a built application, not a source
  # tree about to be installed - the same situation as an installed dependency,
  # so it uses the same policy.
  if [[ "$ASAR_PASS" == "1" ]] && is_context_tag "$tag"; then printf 'LOW'; return; fi
  if [[ "$MODE" == "installer" ]]; then
    # normal-for-installers patterns
    case "$tag" in
      persistence|dep-links|net-exec|build-ext|shell-exec) printf 'LOW'; return ;;
      download-exec) [[ "$sev" == "HIGH" ]] && { printf 'MED'; return; } ;;
    esac
  elif [[ "$MODE" == "pkgcheck" ]]; then
    # a published package legitimately ships compiled extensions, uses ctypes/
    # cffi, calls exec for py2/3 compat, makes network calls, pickles, etc.
    # Demote those dual-use signals; the unambiguous install-time-exec and
    # malware signals (install-hook, *-decode-exec, reverse-shell, exfil,
    # import-shadow, IOC hits, ...) keep full severity.
    case "$tag" in
      native-load|native-vendored|dyn-exec|shell-exec|net-exec|build-ext|\
      pickle-exec|pickle-reduce|hex-blob|decode|blob|self-inspect|sandbox-check|\
      anti-debug|timestomp|lib-inject|screencap|mapbox-c2) printf 'LOW'; return ;;
    esac
  fi
  printf '%s' "$sev"
}

SEP=$'\x1f'
SEEN_KEYS="$SEP"
add_finding() { # sev tag file line msg
  # De-duplicate identical findings: the same rule hitting the same file with
  # the same message (e.g. a benign string matched on several lines) is counted
  # ONCE, so a single file can never multiply a verdict. Distinct messages
  # (e.g. two different malicious package names) are kept.
  local key="$2$SEP$3$SEP$5"
  case "$SEEN_KEYS" in *"$SEP$key$SEP"*) return 0 ;; esac
  SEEN_KEYS="$SEEN_KEYS$key$SEP"
  local sev; sev="$(demote_for_mode "$2" "$1")"
  # Installed or built code is scanned like anything else, but a dual-use pattern
  # in someone else's dependency is not a finding about this project.
  if [[ "$sev" != "LOW" ]]; then
    if [[ "$IS_APP_BUNDLE" == "1" ]]; then
      is_bundle_keep "$2" || sev=LOW
    elif is_context_tag "$2" && is_vendored_path "$3"; then
      sev=LOW
    fi
  fi
  local tag="$2" file="$3" line="$4" msg="$5"
  F_SEV+=("$sev"); F_TAG+=("$tag"); F_FILE+=("$file"); F_LINE+=("$line"); F_MSG+=("$msg")
  case "$sev" in
    CRIT) N_CRIT=$((N_CRIT+1)) ;;
    HIGH) N_HIGH=$((N_HIGH+1)) ;;
    MED)  N_MED=$((N_MED+1)) ;;
    *)    N_LOW=$((N_LOW+1)) ;;
  esac
}

# Display path for a finding. Files unpacked from an .asar live in the workdir,
# which means nothing to the user, so they are reported against the archive they
# came from: "Contents/Resources/app.asar!/index.js".
ASAR_DIR=(); ASAR_LABEL=()
rel() {
  local p="$1" i
  for ((i=0; i<${#ASAR_DIR[@]}; i++)); do
    case "$p" in
      "${ASAR_DIR[$i]}"/*) printf '%s!/%s' "${ASAR_LABEL[$i]}" "${p#"${ASAR_DIR[$i]}"/}"; return ;;
    esac
  done
  printf '%s' "${p#"$ROOT"/}"
}

# --- content-rule engine -----------------------------------------------------
RULE_SEV=(); RULE_TAG=(); RULE_GLOB=(); RULE_ERE=(); RULE_MSG=()
rule() { RULE_SEV+=("$1"); RULE_TAG+=("$2"); RULE_GLOB+=("$3"); RULE_ERE+=("$4"); RULE_MSG+=("$5"); }

SH="*.sh *.bash *.zsh *.command Makefile *.mk"
ANY="*.py *.pyx *.sh *.bash *.command *.rb *.pl *.php *.js *.mjs *.cjs *.ts *.go *.c *.ps1"
JS="*.js *.mjs *.cjs *.ts"
# ANY plus build-system files that execute on build/install (gradle=Groovy,
# build.rs=cargo, Rakefile/extconf.rb/Gemfile=ruby, build.sbt=scala).
ANYPLUS="$ANY *.gradle build.rs Rakefile Gemfile extconf.rb build.sbt *.groovy Dockerfile"
# The ONLY things skipped outright, because neither can hide runnable code that
# the scan would otherwise miss: .git holds compressed VCS objects, and
# __pycache__ holds byte-compiled copies of .py files already being read.
#
# Everything else is scanned - node_modules, site-packages, virtualenvs, build
# output, vendor. Skipping those is how a trojanned dependency goes unnoticed,
# and a trojanned dependency is the single most likely thing this tool will ever
# catch. Installed code is not excluded, it is judged in context: see
# CONTEXT_TAGS below.
EXCLUDE_NAMES=(.git __pycache__)
GREP_EXCLUDES=(); FIND_PRUNE=()
rebuild_excludes() {
  GREP_EXCLUDES=(); FIND_PRUNE=()
  local d first=1
  for d in "${EXCLUDE_NAMES[@]}"; do
    GREP_EXCLUDES+=(--exclude-dir="$d")
    if (( first )); then FIND_PRUNE+=(-name "$d"); first=0
    else FIND_PRUNE+=(-o -name "$d"); fi
  done
}
rebuild_excludes

# Code that was installed rather than written. Still scanned; only weighted
# differently. Virtualenvs are found by their pyvenv.cfg rather than by name,
# since venv, env, .env and virtualenv are all in common use.
VENDOR_DIRS=()
discover_venvs() {
  local cfg n
  while IFS= read -r cfg; do
    [[ -n "$cfg" ]] || continue
    n="$(basename "$(dirname "$cfg")")"
    case " ${VENDOR_DIRS[*]:-} " in *" $n "*) continue ;; esac
    VENDOR_DIRS+=("$n")
    info "treating '$n/' as an installed virtualenv"
  done < <(find "$ROOT" -maxdepth 6 -type f -name pyvenv.cfg 2>/dev/null || true)
  return 0
}

# A prebuilt application is a different question from a source checkout. You are
# not reviewing code someone is about to install into your interpreter; you are
# asking whether a finished program is hostile. Almost every capability a rule
# looks for is one a real application plausibly has for its own reasons: VS Code
# reads the keychain and talks to the GitHub API, RStudio captures the screen and
# JITs executable memory, GIMP ships Python plugins, an AI editor contains the
# literal text "ignore previous instructions" as data, and any app with
# translations contains bidi characters. Scored like source, all three of those
# came back DANGEROUS.
#
# So for a bundle only the patterns no legitimate application has any reason to
# contain still count. Everything else drops to LOW - still in --json and -v,
# just not pretending to be evidence. Source trees are unaffected.
BUNDLE_KEEP=(ioc-pkg ioc-str ioc-hash reverse-shell macos-inmem gatekeeper
  tunnel-c2 multi-decode miner backdoor-acct js-fetch-exec py-fetch-exec)
is_bundle_keep() { [[ " ${BUNDLE_KEEP[*]} " == *" $1 "* ]]; }

IS_APP_BUNDLE=0
detect_app_bundle() {
  case "$ROOT" in *.app|*.app/) IS_APP_BUNDLE=1; return 0 ;; esac
  [[ -d "$ROOT/Contents/MacOS" || -f "$ROOT/Contents/Info.plist" ]] && IS_APP_BUNDLE=1
  return 0
}

is_vendored_path() { # path -> 0 if this is installed/built code, not the author's
  case "$1" in
    */node_modules/*|*/site-packages/*|*/dist-packages/*|*/.tox/*|*/.eggs/*|\
    */build/*|*/dist/*|*/.mypy_cache/*|*/.pytest_cache/*) return 0 ;;
  esac
  local d
  for d in "${VENDOR_DIRS[@]:-}"; do
    [[ -n "$d" ]] && case "$1" in */"$d"/*) return 0 ;; esac
  done
  return 1
}

# Tags that only carry meaning when the code is the author's own. In an installed
# dependency, a built app bundle or a build directory they are unremarkable:
# urllib3 sets server_hostname, setuptools ships _distutils_hack, an AWS client
# names .aws/credentials. Reporting those at full severity produced 71 findings
# on one real checkout, none of them about that project.
#
# The unambiguous malware tags are deliberately absent, so they keep full
# severity wherever they appear: import-shadow, the ioc-* family, reverse-shell,
# download-exec, *-fetch-exec, multi-decode, macos-inmem, gatekeeper, repo-exfil,
# devtool-theft, tunnel-c2, llm-evasion, trojan-source, npm-script-exec, miner,
# keylog, shellcode, exfil-channel, env-gating, pth-exec.
#
# An array, not a string: as a multi-line string every tag that happened to sit
# at the end of a line was followed by a newline rather than a space, so the
# " $tag " match silently never fired for it. "${CONTEXT_TAGS[*]}" joins on a
# space regardless of how the source is wrapped.
CONTEXT_TAGS=(secret-scrape harvest wallet keychain-cli histfiles persistence
  screencap sandbox-check self-inspect anti-debug timestomp str-obf lib-inject
  native-vendored native-load js-shell-exec shell-exec dyn-exec decode hex-blob
  install-hook gyp-exec dep-links build-ext registry-redirect sni-front doh
  mapbox-c2 persist-pth pth-file npm-install-script conftest-exec direnv
  py-startup-hook
  # A compiled module beside a same-named .py is the ChocoPoC trick, and stays
  # CRIT in a source tree - which is what the pip/clone hooks actually scan.
  # Inside an already-installed dependency it is also just how lxml and friends
  # ship a C accelerator next to its pure-Python fallback, and Debian's
  # python3-lxml alone produced five of them.
  import-shadow)
is_context_tag() { [[ " ${CONTEXT_TAGS[*]} " == *" $1 "* ]]; }

load_rules() {
  # install-time code execution (pip/npm runs this; the #1 supply-chain vector)
  rule HIGH install-hook "setup.py"        'cmdclass\s*=|class .{0,60}\(.{0,40}install.{0,20}\):|PostInstall|def run\(self\)' \
       'setup.py defines an install-time hook (cmdclass/custom install) - runs code on "pip install"'
  rule MED  dep-links    "setup.py"        'dependency_links\s*=|--extra-index-url|--index-url' \
       'Custom package index / dependency_links - can pull attacker-controlled packages'
  # node-gyp runs binding.gyp during `npm install`. After preinstall/postinstall
  # hooks became the thing everyone watches, weaponised binding.gyp became the
  # way to get the same install-time execution without a lifecycle script.
  rule MED  gyp-exec     "binding.gyp *.gyp *.gypi" '<!@?\(|"action"\s*:\s*\[' \
       'binding.gyp shells out at build time - node-gyp runs it during "npm install", with no lifecycle script to notice'

  # native-extension import shadowing (the core ChocoPoC trick; loaders here)
  rule HIGH native-load  "*.py *.pyx"      'ctypes\.(CDLL|WinDLL|cdll|windll)|cffi|LoadLibrary' \
       'Loads a native library directly (ctypes/cffi/LoadLibrary) - the loaded code is not visible to source review'

  # environmental gating / anti-analysis
  rule HIGH env-gating   "*.py *.pyx"      'EXPLOIT_POC|0xF4835C9C' \
       'Gates behaviour on a specific filename/constant - runs only in the intended target, not under review'
  rule MED  self-inspect "*.py *.pyx"      'hash\([^)]*(__file__|basename)|__file__.{0,40}==.{0,20}0x|for\s+\w+\s+in\s+(list\()?sys\.modules' \
       'Hashes its own filename or inspects loaded modules - fingerprints its runtime to run only in a specific environment'
  rule MED  anti-debug   "*.py *.pyx *.c"  'CheckRemoteDebuggerPresent|IsDebuggerPresent|GetThreadContext|ptrace\(' \
       'Anti-debugging check (IsDebuggerPresent/ptrace) - detects or blocks a debugger'
  # Was: any platform.node()/getpass.getuser() call, which honest code does all
  # the time. Only the comparison against known analysis environments is a
  # malware behaviour.
  rule MED  sandbox-check "$ANY"           '(hostname|platform\.node\(\)|getuser\(\)).{0,60}(sandbox|vmware|virtualbox|qemu|cuckoo|analyst|malware)|/sys/class/dmi.{0,40}(vendor|product)' \
       'Compares the hostname/machine against sandbox and VM names - refuses to run where it would be watched'
  # Malware now ships text aimed at the analyst's tooling rather than the
  # analyst: macOS.Gaslight embedded dozens of fake system messages to talk an
  # AI triage step into calling it clean. This scanner has an LLM pass, so this
  # is both a detection and a defence of that pass.
  rule HIGH llm-evasion  "$ANYPLUS *.md *.txt" \
       '([Ii]gnore|[Dd]isregard|[Ff]orget)\s+(all\s+)?(your\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|[Aa]s\s+an?\s+AI.{0,60}(safe|benign|harmless|no\s+threat)|[Tt]h(is|e)\s+(file|package|code|script|program)\s+is\s+(completely\s+)?(safe|benign|harmless).{0,60}(do\s+not|don.t|no\s+need\s+to)\s+(flag|report|analyz|review)|<\|im_(start|end)\|>|\[/INST\]|^\s*###\s*(System|Assistant)\s*:' \
       'Text addressed to an automated reviewer, telling it to ignore its instructions or declare the file safe - present only to defeat AI-assisted analysis'

  # obfuscation / dynamic execution
  rule HIGH pack-exec    "*.py *.pyx"      '(marshal\.loads|zlib\.decompress|lzma\.decompress|codecs\.decode).{0,80}(exec|eval)|exec\(.{0,80}decompress|exec\(.{0,80}b64decode' \
       'Decodes or decompresses data and then executes it'
  # Decoding, and dynamic execution, are each ordinary on their own - honest code
  # base64s things and calls exec() constantly. Only the combination, and code
  # pulled in at runtime, say anything about intent. The bare primitives stay as
  # LOW: hidden from the default report so they cannot drive a verdict, still on
  # record for someone reading with -v or --json.
  rule LOW  dyn-exec     "*.py *.pyx"      'exec\(|eval\(|__import__\(|compile\(.{0,60}exec' \
       'Dynamic code execution (exec/eval/compile/__import__)'
  rule LOW  decode       "*.py *.pyx"      'base64\.b(64|85|32)decode|bytes\.fromhex|codecs\.decode.{0,40}rot' \
       'Decodes encoded data (base64/hex/rot13)'
  rule HIGH py-fetch-exec "*.py *.pyx" \
       '(exec|eval)\(\s*[^)]{0,80}(requests\.(get|post)|urlopen|httpx\.(get|post)|urlretrieve)\(' \
       'Executes code downloaded at runtime - what runs is chosen by a server, after any review'
  rule HIGH multi-decode "$ANY" \
       'b64decode\(.{0,60}b64decode\(|atob\(.{0,60}atob\(|base64\s+(-d|-D|--decode).{0,60}\|.{0,40}base64\s+(-d|-D|--decode)' \
       'Nested base64 layers - encoding applied repeatedly to get a payload past scanners'
  rule MED  str-obf      "$ANY" \
       '\[::-1\].{0,60}(http|urlopen|connect|requests|exec)|(https?|urlopen|exec).{0,30}\[::-1\]|String\.fromCharCode\([^)]{60,}|"?"\.join\(chr\(.{0,60}(\^|-|\+)\s*\w' \
       'Builds a string by reversal or character arithmetic - hides a URL or command from anyone searching the file'
  rule MED  hex-blob     "*.py *.pyx"      '(\\x[0-9a-fA-F]{2}){40,}' \
       'Long \\xNN byte string - possible shellcode/obfuscated data'

  # shell / command execution
  rule LOW  shell-exec   "*.py *.pyx"      'os\.system\(|os\.popen\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|pty\.spawn|commands\.getoutput' \
       'Executes shell commands (os.system / subprocess shell=True / pty.spawn)'

  # credential / data harvesting
  rule HIGH harvest      "*.py *.pyx"      'Login Data|cookies\.sqlite|key4\.db|logins\.json|os_crypt|Local State|Keychain' \
       'Reads browser credential/cookie stores (Login Data / key4.db / cookies)'
  rule HIGH keychain-cli "$ANY"            'security\s+find-generic-password|login\.keychain|secretstorage' \
       'Reads the OS keychain / secret store (macOS Keychain / libsecret)'
  rule HIGH wallet       "$ANY"            'wallet\.dat|MetaMask|Electrum|Exodus|Ethereum/keystore|\.config/solana' \
       'Reads cryptocurrency wallet files (wallet.dat / MetaMask / Electrum)'
  rule MED  histfiles    "*.py *.pyx"      '\.bash_history|\.zsh_history|\.ssh/id_[rd]sa|\.aws/credentials|\bid_rsa\b' \
       'Reads shell history / SSH keys / cloud credential files'

  # surveillance
  rule HIGH keylog       "$ANY"            'pynput\.keyboard|GetAsyncKeyState|SetWindowsHookEx|keyboard\.on_press|CGEventTap' \
       'Keylogging / input-hooking API (pynput / SetWindowsHookEx / CGEventTap)'
  rule MED  screencap    "$ANY"            'ImageGrab\.grab|\bmss\(\)|screencapture\b|\bscrot\b' \
       'Screen capture - confirm captures are not exfiltrated'

  # persistence / tampering
  rule HIGH persist-pth  "*.py *.pyx"      '_distutils_hack|add_shim|site-packages.{0,60}\.pth|\.pth.{0,60}__import__' \
       'Writes a .pth / _distutils_hack shim - auto-executes on every interpreter start'
  rule LOW  timestomp    "*.py *.pyx *.c"  'os\.utime\(|SetFileTime|st_mtime\s*=' \
       'Timestomps files - forensic evasion (weak signal on its own)'

  # C2 evasion (DoH tunneling, SNI/host-header fronting, Mapbox abuse)
  rule HIGH doh          "*.py *.pyx"      'dns-query|application/dns-json|dns\.google/resolve|cloudflare-dns\.com|/resolve\?name=' \
       'DNS-over-HTTPS resolution - hides C2 lookup from network monitoring'
  rule HIGH sni-front    "*.py *.pyx"      'assert_hostname|server_hostname|HostHeaderSSLAdapter|set_ciphers.{0,60}ServerName|TLS.{0,40}SNI' \
       'SNI / Host-header fronting - disguises C2 traffic as a trusted service'
  rule MED  mapbox-c2    "*.py *.pyx"      'api\.mapbox\.com|mapbox.{0,60}(dataset|feature)' \
       'Uses Mapbox datasets/features - abused for C2 tasking in ChocoPoC'

  # general malicious code (polyglot)
  rule HIGH reverse-shell "$ANYPLUS" \
       '/dev/tcp/|nc\s+-e|ncat\s+-e|mkfifo.{0,60}(/bin/sh|nc )|bash\s+-i\s*>&|pty\.spawn\(.{0,12}/bin/(sh|bash)|socket.{0,80}(dup2|SOCK_STREAM).{0,80}(/bin/sh|exec)' \
       'Reverse-shell pattern - hands an interactive shell to a remote host'
  rule HIGH download-exec "$ANYPLUS Makefile *.dockerfile" \
       '(curl|wget)\s+[^|;]*\|\s*(sudo\s+)?((ba)?sh|node|python[0-9.]*|perl|ruby)|(curl|wget)[^;|]*;[^;]*chmod\s+\+x|urlretrieve\(|certutil\s+-urlcache|bitsadmin\s+/transfer|Invoke-WebRequest.*\|\s*iex' \
       'Downloads a remote file and executes it'
  rule HIGH destructive  "$ANYPLUS Makefile" \
       'rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+["]?(--no-preserve-root|/(\s|$|\*|["])|~(\s|/|$)|\$\{?HOME|\*(\s|$))|\bmkfs\.|dd\s+if=/dev/(zero|u?random)\s+of=/dev|:\(\)\s*\{\s*:\s*\|\s*:&?|shutil\.rmtree\(\s*["]?(/(["]|\s*\))|~|\$HOME)' \
       'Destructive filesystem/disk wipe or fork bomb'
  rule HIGH win-lolbin   "*.ps1 *.psm1 *.bat *.cmd *.hta *.vbs" \
       'powershell.{0,40}-e(nc(odedcommand)?)?\b|-EncodedCommand|IEX\s*\(|Invoke-Expression|New-Object\s+Net\.WebClient|FromBase64String|\bmshta\b|regsvr32.{0,40}scrobj|DownloadString' \
       'Encoded PowerShell / living-off-the-land binary execution'
  rule HIGH miner        "$ANY *.yml *.yaml *.json *.conf" \
       'stratum\+tcp://|\bxmrig\b|cpuminer|coinhive|supportxmr|nicehash|nanopool' \
       'Cryptocurrency miner reference'
  rule HIGH backdoor-acct "$ANY Makefile" \
       'useradd\b.{0,60}(-o\s+-u\s*0|-G\s+(sudo|wheel))|net\s+user\b.{0,40}/add|net\s+localgroup\b.{0,40}/add' \
       'Creates a new user account with uid 0 or sudo/wheel/admin group'
  rule MED  exfil-channel "$ANYPLUS" \
       'discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/(api|raw)|api\.telegram\.org/bot|https?://t\.me/|transfer\.sh|0x0\.st|termbin\.com' \
       'Exfiltration channel (webhook / paste / telegram / anonymous upload)'
  rule MED  persistence  "$ANY" \
       'crontab\s+-|/etc/cron|authorized_keys|~/\.(bashrc|zshrc|profile)|LaunchAgents|LaunchDaemons|/etc/systemd/system|\.config/systemd/user|\.config/autostart|/etc/ld\.so\.preload|reg\s+add.{0,60}\\Run|schtasks\s+/create|New-Service' \
       'Installs a persistence mechanism (cron / autostart / service / SSH key)'
  rule MED  secret-scrape "$ANY" \
       '/proc/self/environ|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|NPM_TOKEN|VAULT_TOKEN|\.aws/credentials|\.docker/config\.json|\.kube/config|\.git-credentials|\.config/gh/hosts\.yml|_authToken' \
       'Reads cloud keys / access tokens / credential files'
  # The current stealer target list: the developer's own publishing tokens, and
  # the config files of local AI coding tools, which now hold API keys.
  rule HIGH devtool-theft "$ANY" \
       '\.claude(\.json|/\.credentials)|\.codeium/|\.cursor/.{0,30}(config|state|mcp)|\.continue/config|Bitwarden.{0,20}(data\.json|vault)|1[Pp]assword.{0,20}(sqlite|vault)|\.mozilla.{0,30}logins\.json|\.config/solana/id\.json' \
       'Reads local AI-tool, password-manager or wallet credential stores - the 2026 infostealer target set'
  # Disposable tunnel endpoints: how malware gets a reachable C2 address without
  # registering a domain that could be blocked or attributed.
  rule MED  tunnel-c2    "$ANYPLUS" \
       '[a-z0-9-]{4,}\.ngrok(-free)?\.(io|app|dev)|[a-z0-9-]{4,}\.trycloudflare\.com|\.loca\.lt\b|[a-z0-9-]{4,}\.serveo\.net|\.localtunnel\.me|\.pagekite\.me|\.telebit\.io' \
       'Talks to a disposable tunnel endpoint (ngrok / trycloudflare / localtunnel) - a C2 address that needs no domain registration'
  # Shai-Hulud-class worms exfiltrate into repositories they create under the
  # victim's own account, and persist by committing a workflow.
  rule HIGH repo-exfil   "$ANY" \
       'api\.github\.com/user/repos|/actions/secrets/|\.github/workflows/.{0,60}(writeFile|open\(|fs\.write)|(execSync|exec|spawn(Sync)?)\(.{0,40}npm\s+publish|npm\s+publish.{0,60}(NODE_AUTH_TOKEN|NPM_TOKEN|_authToken)' \
       'Creates a remote repo, reads Actions secrets, writes a CI workflow or republishes a package from inside the code - the npm worm exfiltration and self-propagation path'
  rule MED  shell-obf    "$SH" \
       'eval\s+"?\$\(|base64\s+-d\s*\|\s*(ba)?sh|\$\{IFS\}|`.{0,60}\$\(.{0,60}`|xxd\s+-r\s+-p' \
       'Obfuscated or dynamically-evaluated shell'
  # macOS stealers are overwhelmingly fileless: fetch, decompress and hand
  # straight to an interpreter, so nothing lands on disk to be hashed or
  # quarantined.
  rule HIGH macos-inmem  "$ANYPLUS" \
       '(curl|wget)[^|]{0,160}\|\s*(sudo\s+)?osascript|(curl|wget)[^|]{0,160}\|\s*(gunzip|zcat|funzip|base64\s+(-d|-D|--decode)).{0,60}\|\s*(ba|z)?sh' \
       'Pipes downloaded content straight into osascript or through a decompressor into a shell - runs in memory, nothing written to disk'
  rule HIGH gatekeeper   "$ANYPLUS" \
       'xattr\s+.{0,30}-d\s+com\.apple\.quarantine|xattr\s+-c[r]?\s|spctl\s+--(master|global)-disable|csrutil\s+disable|SetFile\s+-a\s+V' \
       'Strips macOS quarantine or disables Gatekeeper/SIP - removes the check that would have warned you before this code ran'

  # ===== JavaScript / Node, i.e. what is inside an Electron .asar =============
  # The execution primitives above are mostly Python-shaped. Unpacking an asar
  # and then having no rule that reads JavaScript would be pointless, so these
  # mirror dyn-exec / shell-exec / pack-exec for Node.
  # Deliberately NOT "uses eval" or "requires child_process". Every bundled app
  # trips those: webpack emits a stub table naming every Node builtin, and bare
  # eval( matches comments and regex literals in stock dependencies. Neither
  # tells a reader anything about what the program will do to them. What matters
  # is where the executed code comes from, and whether a command is built from
  # data at runtime.
  rule HIGH js-fetch-exec "$JS" \
       '(eval|new\s+Function)\(\s*[^)]{0,80}(await\s+)?(fetch|axios|https?\.get|request)\(' \
       'Executes code fetched over the network - what runs is decided by a server, after any review'
  rule MED  js-shell-exec "$JS" \
       '\b(exec|execSync)\(\s*[`"'"'"'][^`"'"'"'\n]{0,80}\$\{|\b(exec|execSync)\(\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*\+|\bspawn(Sync)?\(\s*["'"'"'`](sh|bash|zsh|cmd(\.exe)?|powershell(\.exe)?|osascript)["'"'"'`]' \
       'Builds an OS command string at runtime or spawns a shell - what actually runs depends on data, not on this file'
  rule HIGH js-decode-exec "$JS" \
       '(eval|new\s+Function|execSync)\(.{0,100}Buffer\.from\(.{0,60}["'"'"'`](base64|hex)|Buffer\.from\(.{0,60}["'"'"'`](base64|hex)["'"'"'`]\).{0,80}\.(toString\(\)\s*\))?.{0,20}(eval|new\s+Function)\(' \
       'Decodes a base64/hex blob and executes it - the code that actually runs is not in the file'

  # Not "this workflow is injectable" - that is the author's vulnerability, and
  # not something the person cloning the repo can act on. This is a workflow that
  # takes the repository's secrets and sends them somewhere, which is credential
  # theft that runs on every build. toJSON(secrets) dumps all of them at once.
  rule HIGH ci-secret-exfil "*.yml *.yaml" \
       'toJSON\(\s*secrets\s*\)|\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}.{0,100}(curl|wget|nc |https?://)|(curl|wget).{0,140}\$\{\{\s*secrets\.' \
       'CI workflow sends repository secrets to a network destination - credential theft on every build'

  # Deliberately no rule for webSecurity:false / nodeIntegration:true. Those are
  # weak configuration, not malicious behaviour - honest apps ship them by the
  # thousand, and a scanner that reports them is describing a vulnerability
  # nobody asked it about while burying the findings that mean something.

  # ===== dev/researcher-workstation targeting (editor, IDE, CI autorun) ========
  # These fire when merely OPENING/cloning a repo runs code - the vector behind
  # Lazarus "Contagious Interview" and trojanised research projects.
  rule HIGH ide-autorun  "tasks.json"      'folderOpen' \
       'VS Code task set to auto-run on folder open - zero-click code execution when the repo is opened in the editor'
  rule HIGH vs-buildevent "*.vcxproj *.csproj *.vbproj *.targets *.props" \
       'PreBuildEvent|PostBuildEvent|<Exec\s|Command>[^<]*(cmd|powershell|pwsh|bash|curl|wget|mshta)' \
       'Visual Studio project runs a command at build time (PreBuildEvent/PostBuildEvent/Exec) - runs when the project is built'
  rule HIGH shellcode    "*.py *.pyx *.c *.cs *.go *.js" \
       'VirtualAllocEx?|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|mmap\([^)]*PROT_EXEC|PROT_EXEC[^)]*PROT_WRITE|ctypes\.cast\([^)]*CFUNCTYPE' \
       'Allocates executable memory or writes into another process (VirtualAlloc/mmap PROT_EXEC/WriteProcessMemory)'
  rule MED  lib-inject   "$ANY" \
       'LD_PRELOAD|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH' \
       'Library injection via LD_PRELOAD / DYLD_INSERT_LIBRARIES'
}

# --- search backend ----------------------------------------------------------
# ripgrep is used when it is installed, purely because it is much faster over the
# large binaries in an application bundle. It is not required and no check
# depends on it; SANITYCHECK_SEARCH=grep forces the fallback, and test.sh asserts
# both engines produce identical findings on the fixtures.
#
# Two ripgrep defaults have to be turned off. It skips hidden files and obeys
# .gitignore - and a dotfile is often the finding (.npmrc, .envrc, .pth), while a
# repo that gitignores its payload is the oldest trick there is. --hidden and
# --no-ignore restore grep's plain view of the tree.
SEARCH_BIN="${SANITYCHECK_SEARCH:-}"
if [[ -z "$SEARCH_BIN" ]]; then
  if have rg; then SEARCH_BIN="rg"; else SEARCH_BIN="grep"; fi
fi

rg_excludes() { # GREP_EXCLUDES -> ripgrep's negated-glob form
  local e; for e in "${GREP_EXCLUDES[@]}"; do printf '%s\n' "!${e#--exclude-dir=}/"; done
}

search_rules() { # ere glob... -> file:line:match
  local ere="$1"; shift
  local g args=()
  if [[ "$SEARCH_BIN" == "rg" ]]; then
    args=(--no-ignore --hidden --no-messages --with-filename --line-number)
    while IFS= read -r g; do args+=(-g "$g"); done < <(rg_excludes)
    for g in "$@"; do args+=(-g "$g"); done
    rg "${args[@]}" -e "$ere" -- "$ROOT" 2>/dev/null || true
  else
    args=(-rInE "${GREP_EXCLUDES[@]}")
    for g in "$@"; do args+=(--include="$g"); done
    grep "${args[@]}" -- "$ere" "$ROOT" 2>/dev/null || true
  fi
}

search_iocs() { # ere -> file:line:match  (binaries read as text, size-capped)
  local ere="$1" g args=()
  if [[ "$SEARCH_BIN" == "rg" ]]; then
    args=(--no-ignore --hidden --no-messages --with-filename --line-number
          --text --only-matching --max-filesize "$IOC_SCAN_MAX_BYTES")
    while IFS= read -r g; do args+=(-g "$g"); done < <(rg_excludes)
    rg "${args[@]}" -e "$ere" -- "$ROOT" 2>/dev/null || true
  else
    ioc_scan_files | xargs -0 grep -HInaoE -- "$ere" 2>/dev/null || true
  fi
}

# Per-rule cap on recorded matches. Raised from 40 once dependency trees stopped
# being skipped: a rule can now legitimately match many vendored files, and a low
# cap let those crowd out the project's own code.
RULE_HIT_CAP="${SANITYCHECK_RULE_HIT_CAP:-200}"

run_content_rules() {
  local i n=${#RULE_SEV[@]}
  for ((i=0; i<n; i++)); do
    local sev="${RULE_SEV[$i]}" tag="${RULE_TAG[$i]}" glob="${RULE_GLOB[$i]}" ere="${RULE_ERE[$i]}" msg="${RULE_MSG[$i]}"
    local gl; read -ra gl <<< "$glob"
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      local file="${hit%%:*}"; local rest="${hit#*:}"; local line="${rest%%:*}"
      add_finding "$sev" "$tag" "$file" "$line" "$msg"
    done < <(search_rules "$ere" "${gl[@]}" | head -n "$RULE_HIT_CAP" || true)
  done
}

# --- structural checks (repo/file mode) --------------------------------------
detect_native_shadowing() {
  local so
  while IFS= read -r so; do
    [[ -z "$so" ]] && continue
    local dir stem base
    dir="$(dirname "$so")"; base="$(basename "$so")"
    stem="${base%.*}"; stem="${stem%%.*}"
    if [[ -f "$dir/$stem.py" ]]; then
      add_finding CRIT import-shadow "$so" 0 \
        "Compiled '$base' shadows '$stem.py' in the same package - the binary imports instead of the source you can read"
    else
      # Not a shadowing pair, just a compiled blob. This is an unreviewability
      # note, not evidence of malice: every prebuilt app bundle, wheel and
      # node-gyp module ships these. MED so it warns and reads, rather than
      # blocking anything with a dylib in it. import-shadow above is the signal
      # that actually indicts a binary.
      # No filename in the message - the location line underneath already shows
      # it, and keeping the text identical lets the report collapse the six
      # stock dylibs every Electron app ships into one line.
      add_finding MED native-vendored "$so" 0 \
        "Vendored compiled extension - binary, not reviewable as source; verify it by hash"
    fi
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' -o -name '*.node' \) -print 2>/dev/null || true)
}

# --- Electron .asar archives -------------------------------------------------
# An Electron app keeps its actual program in Contents/Resources/app.asar - a
# concatenated blob behind a JSON header. A plain tree walk cannot see into it,
# so scanning an .app bundle without unpacking reviews the GPU libraries and
# misses the code. Unpack into the workdir; the engine then runs over the result.
#
# The archive is untrusted input, so the reader is deliberately narrow: entry
# names with a separator or a ".." component are dropped rather than sanitised,
# "link" entries are never materialised, and both the file count and the total
# extracted size are capped.
ASAR_MAX_BYTES="${SANITYCHECK_ASAR_MAX_BYTES:-67108864}"   # 64 MiB per archive
ASAR_MAX_FILES="${SANITYCHECK_ASAR_MAX_FILES:-4000}"

read -r -d '' ASAR_PY <<'PY' || true
import json, os, struct, sys

src, dest = sys.argv[1], sys.argv[2]
max_bytes, max_files = int(sys.argv[3]), int(sys.argv[4])

with open(src, 'rb') as fh:
    head = fh.read(16)
    if len(head) < 16:
        sys.exit(1)
    # Chromium Pickle framing: [4][header_size][payload_size][json_len][json...]
    # and the file data begins at 8 + header_size.
    _, header_size, _, json_len = struct.unpack('<4I', head)
    if not (0 < json_len <= header_size <= 1 << 28):
        sys.exit(1)
    try:
        tree = json.loads(fh.read(json_len).decode('utf-8', 'replace'))
    except ValueError:
        sys.exit(1)
    base = 8 + header_size
    count = total = 0

    def walk(node, parts):
        global count, total
        for name, ent in (node.get('files') or {}).items():
            if name in ('', '.', '..') or '/' in name or '\\' in name or '\0' in name:
                continue
            sub = parts + [name]
            if 'files' in ent:
                walk(ent, sub)
                continue
            if 'link' in ent:        # symlink entry - never materialise it
                continue
            if ent.get('unpacked'):  # content sits in <archive>.unpacked/, already on disk
                continue
            try:
                off, size = int(ent['offset']), int(ent['size'])
            except (KeyError, TypeError, ValueError):
                continue
            if off < 0 or size < 0 or count >= max_files or total + size > max_bytes:
                continue
            fh.seek(base + off)
            data = fh.read(size)
            if len(data) != size:
                continue
            out = os.path.join(dest, *sub)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, 'wb') as w:
                w.write(data)
            count += 1
            total += size

    walk(tree, [])
print(count)
PY

extract_asars() {
  local a n dest i=0
  while IFS= read -r a; do
    [[ -z "$a" ]] && continue
    if ! have python3; then
      add_finding MED asar-unread "$a" 0 \
        'Electron .asar archive found, but python3 is not available to unpack it - the application code inside was NOT scanned'
      continue
    fi
    [[ -n "$WORK_DIR" ]] || make_workdir
    i=$((i+1)); dest="$WORK_DIR/asar/$i"
    mkdir -p "$dest"
    n="$(python3 -c "$ASAR_PY" "$a" "$dest" "$ASAR_MAX_BYTES" "$ASAR_MAX_FILES" 2>/dev/null || true)"
    if [[ -z "$n" || "$n" == "0" ]]; then
      add_finding MED asar-unread "$a" 0 \
        'Electron .asar archive could not be unpacked (corrupt or unsupported) - the application code inside was NOT scanned'
      rm -rf "$dest"; continue
    fi
    ASAR_DIR+=("$dest"); ASAR_LABEL+=("$(rel "$a")")
    info "asar: unpacked $n files from $(rel "$a")"
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f -name '*.asar' -print 2>/dev/null | head -n 8 || true)
}

# Run the engine over each unpacked archive. node_modules is excluded from the
# normal tree walk because in a source repo those are third-party files you have
# not installed yet - but inside an asar the bundled dependencies ARE the shipped
# program, and are where a trojanised build hides. So the exclusion is lifted.
#
# detect_npm_scripts / detect_registry_redirect / detect_autorun_files are
# deliberately NOT run here. They all answer "what happens when you install
# this", and nobody installs an asar - it is the built output. Running them
# anyway is what made a stock Amazon Chime build score DANGEROUS off its own
# bundled lifecycle scripts.
audit_asar_payloads() {
  (( ${#ASAR_DIR[@]} )) || return 0
  local outer_root="$ROOT" outer_ex=("${EXCLUDE_NAMES[@]}") d
  EXCLUDE_NAMES=(.git); rebuild_excludes
  ASAR_PASS=1
  for d in "${ASAR_DIR[@]}"; do
    ROOT="$d"
    run_content_rules
    detect_native_shadowing
    detect_iocs
  done
  ASAR_PASS=0
  ROOT="$outer_root"; EXCLUDE_NAMES=("${outer_ex[@]}"); rebuild_excludes
}

# A committed registry token is the author leaking their own credential - not a
# threat to you. A committed registry *redirect* is: the next `npm install` or
# `pip install` you run in this directory fetches its packages from that host
# instead of the official index, which is the whole dependency-confusion play.
# So this checks where installs are pointed, and official hosts are skipped -
# it fires on redirection, not on the presence of a config file.
detect_registry_redirect() {
  local f hit ln text url host
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      ln="${hit%%:*}"; text="${hit#*:}"
      url="$(printf '%s' "$text" | grep -oE 'https?://[^[:space:]"'"'"']+' | head -1)"
      [[ -n "$url" ]] || continue
      host="${url#*://}"; host="${host%%/*}"; host="${host##*@}"; host="${host%%:*}"
      case "$host" in
        registry.npmjs.org|registry.yarnpkg.com|npm.pkg.github.com|\
        pypi.org|files.pythonhosted.org|pypi.python.org|test.pypi.org) continue ;;
      esac
      add_finding MED registry-redirect "$f" "$ln" \
        "Package installs are redirected to '$host' - an install run in this directory fetches code from there rather than the official index"
    done < <(grep -nE '^[^#]*(registry|index-url|extra-index-url)[[:space:]]*=' "$f" 2>/dev/null | head -n 5 || true)
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f \( -name '.npmrc' -o -name '.yarnrc' -o -name '.yarnrc.yml' \
             -o -name 'pip.conf' -o -name '.pypirc' -o -name 'poetry.toml' \) -print 2>/dev/null | head -n 20 || true)
}

detect_pth_files() {
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    local pb; pb="$(basename "$p")"
    # Two stock .pth files legitimately carry an import line and appear in
    # essentially every Python environment: setuptools' distutils shim, and the
    # finder pip writes for `pip install -e`. Matched on their exact content, not
    # just their name, so a .pth an attacker dropped under the same name still
    # scores CRIT - which is the point of the check.
    if [[ "$pb" == "distutils-precedence.pth" ]] \
       && grep -qE "^import os; *var *= *'SETUPTOOLS_USE_DISTUTILS'" "$p" 2>/dev/null; then
      add_finding LOW pth-file "$p" 0 "setuptools' stock distutils shim - present in every environment"
    elif [[ "$pb" == __editable__*.pth ]] \
       && grep -qE '^(import __editable___|/)' "$p" 2>/dev/null; then
      add_finding LOW pth-file "$p" 0 "pip editable-install finder - written by 'pip install -e'"
    elif [[ "$pb" == *-nspkg.pth ]] \
       && grep -qE "^import sys, types, os;.*_getframe\(1\)\.f_locals\['sitedir'\]" "$p" 2>/dev/null; then
      # setuptools generates one of these for every namespace package - protobuf,
      # ruamel.yaml, zope, the google.* family. Same generated body every time.
      add_finding LOW pth-file "$p" 0 "setuptools namespace-package shim - generated for any package using namespace packages"
    elif grep -qE 'import|exec|eval' "$p" 2>/dev/null; then
      add_finding CRIT pth-exec "$p" 1 \
        ".pth file contains executable 'import' line - runs automatically on every interpreter startup"
    else
      add_finding MED pth-file "$p" 0 ".pth file present - can inject import paths"
    fi
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f -name '*.pth' -print 2>/dev/null || true)
}

detect_npm_scripts() {
  local f ln
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    # any lifecycle script that runs automatically on `npm install`
    if grep -qE '"(preinstall|install|postinstall|prepare|prepublish|preprepare|postprepare)"\s*:' "$f" 2>/dev/null; then
      ln="$(grep -nE '"(preinstall|install|postinstall|prepare|prepublish)"\s*:' "$f" | head -1 | cut -d: -f1)"
      add_finding MED npm-install-script "$f" "${ln:-0}" \
        'package.json lifecycle script runs automatically on "npm install" (preinstall/postinstall/prepare) - review it (legitimate for node-gyp/husky, abused for droppers)'
    fi
    # unambiguously-malicious content in a script value: download-and-run, an
    # inline node/JS payload, decode-and-run, eval, or a raw-IP callback. In an
    # install script there is no legitimate reason for these, so it is CRIT (a
    # legit build postinstall like `node-gyp rebuild` stays MED above).
    if grep -qE '"[A-Za-z_]+"\s*:\s*"[^"]*((curl|wget)[^"]*\|[^"]*(sh|node)|node\s+-e|base64\s+(-d|--decode)[^"]*\|[^"]*(sh|node)|eval\s*\(|https?://[0-9]{1,3}(\.[0-9]{1,3}){3})' "$f" 2>/dev/null; then
      ln="$(grep -nE '(curl|wget)[^"]*\||node\s+-e|base64\s+(-d|--decode)|eval\s*\(' "$f" | head -1 | cut -d: -f1)"
      add_finding CRIT npm-script-exec "$f" "${ln:-0}" \
        'package.json install script downloads/executes remote code, decodes-and-runs a blob, or calls a raw IP - infostealer install vector (Contagious Interview)'
    fi
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f -name 'package.json' -print 2>/dev/null || true)
}

# --- structural: dev-workstation autorun files -------------------------------
# Files that execute merely by cloning + opening a repo, or by running the
# tests / interpreter in it. The Lazarus/Contagious-Interview class of trap.
detect_autorun_files() {
  local f
  # .envrc - direnv runs it automatically when you cd into the directory
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    add_finding LOW direnv "$f" 0 \
      'direnv .envrc runs when you cd in (after `direnv allow`) - read it before allowing'
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f -name '.envrc' -print 2>/dev/null || true)
  # conftest.py - pytest imports & executes it on test collection. Importing
  # subprocess/requests is completely normal in a test suite, so we only flag a
  # conftest that contains high-signal execution/exfil patterns (not the mere
  # presence of those modules) to avoid crying wolf on legitimate tests.
  local danger='os\.system\(|os\.popen\(|\bexec\(|\beval\(|marshal\.loads|b64decode|/dev/tcp|(curl|wget)[^|]*\||urlopen\(|urlretrieve\(|socket\.socket\(|shell\s*=\s*True|Popen\([^)]*/bin/(sh|bash)'
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if grep -qE "$danger" "$f" 2>/dev/null; then
      add_finding HIGH conftest-exec "$f" 0 \
        'conftest.py runs code when pytest collects tests, and here contains shell/exec/download patterns'
    fi
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f -name 'conftest.py' -print 2>/dev/null || true)
  # sitecustomize.py / usercustomize.py - auto-imported at interpreter startup.
  # Some legitimate tooling (e.g. coverage's subprocess trick) ships one, so a
  # plain hook is MED; only escalate to HIGH on dangerous content.
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    # Split by content, the same way .pth files are, so the dangerous case has
    # its own tag. A plain startup hook is ordinary enough to be context inside
    # an installed environment, but one that shells out is a persistence
    # technique precisely because site-packages is where you would plant it -
    # and a single shared tag meant the vendored-path rule demoted both.
    if grep -qE "$danger" "$f" 2>/dev/null; then
      add_finding HIGH py-startup-exec "$f" 0 \
        "$(basename "$f") runs shell/exec/download code at every Python startup - a persistence vector wherever it lands on sys.path"
    else
      add_finding MED py-startup-hook "$f" 0 \
        "$(basename "$f") is auto-imported at Python startup - an exec/persistence vector when it lands on sys.path"
    fi
  done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f \( -name 'sitecustomize.py' -o -name 'usercustomize.py' \) -print 2>/dev/null || true)
}

# --- dependency manifests + IOC matching -------------------------------------
DECLARED_PKGS=()
collect_python_deps() {
  local f
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    while IFS= read -r name; do
      [[ -n "$name" ]] && DECLARED_PKGS+=("$name")
    done < <(grep -vE '^\s*(#|-|$)' "$f" 2>/dev/null | sed -E 's/[[:space:]]*([A-Za-z0-9._-]+).*/\1/' | tr -d ' ' || true)
  done < <(find "$ROOT" -maxdepth 3 -type f -iname 'requirements*.txt' 2>/dev/null || true)
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    while IFS= read -r name; do
      [[ -n "$name" ]] && DECLARED_PKGS+=("$name")
    done < <(grep -oE '"[A-Za-z0-9._-]+"|'"'"'[A-Za-z0-9._-]+'"'"'' "$f" 2>/dev/null \
             | tr -d "\"'" | grep -vE '^(python|3|2)' | head -n 60 || true)
  done < <(find "$ROOT" -maxdepth 3 -type f \( -iname 'pyproject.toml' -o -iname 'setup.cfg' -o -iname 'setup.py' \) 2>/dev/null || true)
}

sha256_file() {
  if have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}';
  elif have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}';
  else return 1; fi
}

# What a flagged file contributes to the LLM prompt. A compiled binary cannot be
# pasted in as-is: command substitution strips its null bytes (noisily) and the
# model gets byte soup regardless. Send an identity the user can act on - type,
# size, sha256 - plus the printable strings, which is what a reviewer would
# actually look at.
llm_excerpt() { # file -> prompt text
  local f="$1"
  if grep -qI . "$f" 2>/dev/null; then
    head -c 8000 "$f" 2>/dev/null || true
    return 0
  fi
  printf '(binary: %s, %s bytes, sha256 %s)\nprintable strings:\n%s\n' \
    "$(file -b "$f" 2>/dev/null || echo unknown)" \
    "$(wc -c <"$f" 2>/dev/null | tr -d ' ')" \
    "$(sha256_file "$f" 2>/dev/null || echo unavailable)" \
    "$(strings -n 6 "$f" 2>/dev/null | head -n 150 | tr -d '\0' || true)"
}

IOC_PKG=(); IOC_SHA=(); IOC_ENV=(); IOC_STR=(); IOC_HOST=()
IOC_PKG_NOTE=(); IOC_SHA_NOTE=(); IOC_PKG_NORM=()
load_iocs() {
  local files=("$IOC_DB" "${EXTRA_IOCS[@]}")
  local f k
  for f in "${files[@]}"; do
    [[ -n "$f" && -f "$f" ]] || continue
    while IFS=$'\t' read -r type value note; do
      [[ -z "${type:-}" || "$type" == \#* ]] && continue
      case "$type" in
        pkg)    IOC_PKG+=("$value"); IOC_PKG_NOTE+=("${note:-}") ;;
        sha256) IOC_SHA+=("$value"); IOC_SHA_NOTE+=("${note:-}") ;;
        env)    IOC_ENV+=("$value") ;;
        str)    IOC_STR+=("$value") ;;
        host)   IOC_HOST+=("$value") ;;
      esac
    done < "$f"
  done
  # pre-normalize IOC package names once, so the match loops don't fork norm_pkg
  # per (declared-dep x ioc) pair.
  for k in "${IOC_PKG[@]:-}"; do IOC_PKG_NORM+=("$(norm_pkg "$k")"); done
}

# Normalize a package name for IOC matching: lowercase and drop all . _ -
# separators, so a known-bad "skytext" also catches "sky-text" / "sky_text".
norm_pkg() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '._-'; }

# Files the IOC string pass will read. That pass uses grep -a, deliberately: a
# C2 host or env marker embedded in a compiled payload is exactly what we want to
# catch. But with no size bound it also reads every byte of the stock frameworks
# in an application bundle, which was the single largest cost in a scan - about
# three of the four minutes a 450 MB .app used to take. Files over the cap are
# still hash-checked against the IOC database, which is the right tool for a
# large binary anyway.
IOC_SCAN_MAX_BYTES="${SANITYCHECK_IOC_SCAN_MAX_BYTES:-4194304}"
# The prune list is derived from GREP_EXCLUDES rather than repeated, so the grep
# and ripgrep paths see exactly the same tree - including during the asar pass,
# where GREP_EXCLUDES is narrowed to keep bundled node_modules in scope.
ioc_scan_files() {
  find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o \
       -type f -size -"${IOC_SCAN_MAX_BYTES}"c -print0 2>/dev/null || true
}

detect_iocs() {
  local d k
  for d in "${DECLARED_PKGS[@]:-}"; do
    [[ -z "$d" ]] && continue
    local dl; dl="$(norm_pkg "$d")"
    local i=0
    for k in "${IOC_PKG_NORM[@]:-}"; do
      [[ -z "$k" ]] && { i=$((i+1)); continue; }
      if [[ "$dl" == "$k" ]]; then
        add_finding CRIT ioc-pkg "declared-dependencies" 0 \
          "Depends on known-malicious package '$d' - ${IOC_PKG_NOTE[$i]:-ChocoPoC IOC}"
      fi
      i=$((i+1))
    done
  done
  local pat=()
  for k in "${IOC_ENV[@]:-}" "${IOC_STR[@]:-}" "${IOC_HOST[@]:-}"; do
    [[ -n "$k" ]] && pat+=("$k")
  done
  if [[ ${#pat[@]} -gt 0 ]]; then
    local joined; joined="$(printf '%s|' "${pat[@]}")"; joined="${joined%|}"
    # -o prints the matched IOC itself, so the finding can name it (file:line:match)
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      local file="${hit%%:*}"; local rest="${hit#*:}"; local line="${rest%%:*}"; local match="${rest#*:}"
      add_finding CRIT ioc-str "$file" "$line" "Contains known IOC marker '$match' (from the IOC database)"
    done < <(search_iocs "$joined" | head -n 20 || true)
  fi
  if [[ ${#IOC_SHA[@]} -gt 0 ]]; then
    local art
    while IFS= read -r art; do
      [[ -z "$art" ]] && continue
      local h; h="$(sha256_file "$art" 2>/dev/null || true)"
      [[ -z "$h" ]] && continue
      local i=0 s
      for s in "${IOC_SHA[@]}"; do
        if [[ "$h" == "$s" ]]; then
          add_finding CRIT ioc-hash "$art" 0 "File hash matches a known malicious payload - ${IOC_SHA_NOTE[$i]:-IOC}"
        fi
        i=$((i+1))
      done
    done < <(find "$ROOT" -type d \( "${FIND_PRUNE[@]}" \) -prune -o -type f \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' -o -name '*.node' -o -name '*.whl' -o -name '*.tar.gz' -o -name '*.zip' -o -name '*.asar' \) -print 2>/dev/null || true)
  fi
}

# --- python deep-pass (AST + typosquat + entropy) and safe resolver ----------
run_deep_pass() {
  have python3 || { info "deep: python3 not found, skipping"; return 0; }
  [[ -n "$HELPER" && -f "$HELPER" ]] || { info "deep: helper not found, skipping"; return 0; }
  local args=("$HELPER")
  # transitive PyPI resolution is default-on, but only when network is allowed
  if [[ "$OFFLINE" != "1" && "$FAST" != "1" ]]; then
    args+=(--resolve --iocs "$IOC_DB")
    info "deep: AST + typosquat + entropy + transitive resolve"
  else
    info "deep: AST + typosquat + entropy (offline)"
  fi
  args+=("$ROOT")
  local sev tag file line msg
  while IFS=$'\t' read -r sev tag file line msg; do
    [[ -z "$sev" ]] && continue
    local f="$file"; [[ "$file" == "declared-dependencies" ]] || f="$ROOT/$file"
    add_finding "$sev" "$tag" "$f" "${line:-0}" "$msg"
  done < <(python3 "${args[@]}" 2>/dev/null || true)
}

# --- verdict -----------------------------------------------------------------
sev_rank() { case "$1" in DANGEROUS) echo 3;; CAUTION) echo 2;; SAFE) echo 1;; *) echo 0;; esac; }
more_severe() { # a b -> the more severe verdict
  [[ "$(sev_rank "$1")" -ge "$(sev_rank "$2")" ]] && printf '%s' "$1" || printf '%s' "$2"
}

# Counts that decide the verdict, as opposed to N_* which report what was found.
# Every finding is still listed, but one signal repeated across many files is
# still one signal: a tag counts at most twice toward the verdict at a given
# severity. Without this a bundle shipping six copies of the same unreviewable
# dylib escalates itself on volume alone, while two genuinely independent HIGH
# findings still escalate as before.
verdict_counts() { # -> "crit high med"
  local i sev tag key c=0 h=0 m=0 seen="$SEP"
  for ((i=0; i<${#F_SEV[@]}; i++)); do
    sev="${F_SEV[$i]}"; tag="${F_TAG[$i]}"
    case "$sev" in CRIT|HIGH|MED) ;; *) continue ;; esac
    key="$sev$SEP$tag"
    case "$seen" in
      *"$SEP${key}#2$SEP"*) continue ;;
      *"$SEP${key}#1$SEP"*) seen="$seen${key}#2$SEP" ;;
      *)                    seen="$seen${key}#1$SEP" ;;
    esac
    case "$sev" in CRIT) c=$((c+1)) ;; HIGH) h=$((h+1)) ;; MED) m=$((m+1)) ;; esac
  done
  printf '%s %s %s' "$c" "$h" "$m"
}

static_verdict() {
  local c h m
  read -r c h m <<<"$(verdict_counts)"
  if (( c >= 1 || h >= 2 )); then echo DANGEROUS
  elif (( h == 1 || m >= 1 )); then echo CAUTION
  else echo SAFE; fi
}

# --- LLM providers (shared) --------------------------------------------------
detect_provider() {
  case "$PROVIDER" in
    anthropic) PROVIDER=claude-api ;;
    claude)    PROVIDER=claude-cli ;;
  esac
  [[ "$PROVIDER" != "auto" ]] && { printf '%s' "$PROVIDER"; return; }
  if have ollama; then printf 'ollama';
  elif have claude; then printf 'claude-cli';
  elif [[ -n "${OPENAI_API_KEY:-}" ]]; then printf 'openai';
  elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then printf 'claude-api';
  else printf ''; fi
}

llm_call() { # provider prompt -> raw text
  local prov="$1" prompt="$2"
  case "$prov" in
    ollama)
      local model="${MODEL:-llama3.1}" host="${OLLAMA_HOST:-http://localhost:11434}"
      local body; body="$(python3 -c 'import json,sys;print(json.dumps({"model":sys.argv[1],"prompt":sys.stdin.read(),"stream":False}))' "$model" <<<"$prompt")"
      curl -sS --max-time 120 "$host/api/generate" -H 'content-type: application/json' -d "$body" 2>/dev/null \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("response",""))' 2>/dev/null || true ;;
    claude-cli)
      printf '%s' "$prompt" | claude -p 'Return only the JSON object requested.' 2>/dev/null || true ;;
    claude-api)
      local model="${MODEL:-claude-sonnet-4-5-20250929}"
      local body; body="$(python3 -c 'import json,sys;print(json.dumps({"model":sys.argv[1],"max_tokens":1024,"messages":[{"role":"user","content":sys.stdin.read()}]}))' "$model" <<<"$prompt")"
      curl -sS --max-time 60 https://api.anthropic.com/v1/messages \
        -H "x-api-key: ${ANTHROPIC_API_KEY:-}" -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' -d "$body" 2>/dev/null \
        | python3 -c 'import json,sys;d=json.load(sys.stdin);print("".join(b.get("text","") for b in d.get("content",[])))' 2>/dev/null || true ;;
    openai)
      local base="${OPENAI_BASE_URL:-https://api.openai.com/v1}" model="${MODEL:-gpt-4o}"
      local body; body="$(python3 -c 'import json,sys;print(json.dumps({"model":sys.argv[1],"messages":[{"role":"user","content":sys.stdin.read()}]}))' "$model" <<<"$prompt")"
      curl -sS --max-time 60 "$base/chat/completions" \
        -H "Authorization: Bearer ${OPENAI_API_KEY:-}" -H 'content-type: application/json' -d "$body" 2>/dev/null \
        | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["choices"][0]["message"]["content"])' 2>/dev/null || true ;;
  esac
}

LLM_VERDICT=""; LLM_SUMMARY=""; LLM_WARNINGS=""
parse_llm() { # raw -> sets LLM_VERDICT/SUMMARY/WARNINGS
  # program via -c so the piped LLM response is what reaches python's stdin
  # (a `python3 - <<HEREDOC` would make the heredoc stdin and swallow the pipe).
  local parsed
  parsed="$(printf '%s' "$1" | python3 -c '
import json, sys, re
raw = sys.stdin.read()
m = re.search(r"\{.*\}", raw, re.S)
if not m:
    sys.exit(0)
try:
    d = json.loads(m.group(0))
except Exception:
    sys.exit(0)
print((d.get("verdict") or "").upper())
print((d.get("summary") or "").replace("\n", " "))
for w in d.get("warnings", []) or []:
    print("W:" + str(w).replace("\n", " "))
' 2>/dev/null || true)"
  LLM_VERDICT="$(printf '%s' "$parsed" | sed -n '1p')"
  LLM_SUMMARY="$(printf '%s' "$parsed" | sed -n '2p')"
  LLM_WARNINGS="$(printf '%s' "$parsed" | grep '^W:' | sed 's/^W://' || true)"
}

installer_prompt() {
  cat <<'EOF'
You are a security auditor. A user is about to run the following shell script via
curl|bash. Respond with ONLY valid JSON, no markdown fences:
{"verdict":"SAFE|CAUTION|DANGEROUS","summary":"one sentence","warnings":["..."]}

NORMAL for installers (do NOT warn): sudo for package managers; adding vendor
apt/yum repos and GPG keys; writing to /usr/local, ~/.local, /opt, ~/bin; editing
shell rc files for PATH; symlinks/chmod +x; uname/OS detection; downloading
binaries from the project's official domain or GitHub releases; enabling a
systemd service for the installed tool.

WARN only about: data exfiltration; backdoors (authorized_keys, unrelated cron);
credential harvesting (ssh keys, browser profiles, wallets); obfuscation (base64
piped to a shell, eval of built strings); destructive ops on broad paths;
hardcoded IPs / unrelated domains; download-and-exec of secondary payloads from
unrelated domains.
EOF
}

malware_prompt() {
  # The summary is read by someone deciding whether to run a download, not by an
  # analyst. Asking plainly for that stops it coming back as "stock ANGLE and
  # SwiftShader libraries whose strings contain expected GL/EGL entry points",
  # which is accurate and tells that reader nothing. Caveats still have somewhere
  # to go - warnings render as notes, behind -v.
  cat <<'EOF'
You are reviewing files that a static scanner flagged in something the user is
about to install or run, looking for supply-chain trojans and general malware.

Respond with ONLY a JSON object:
{"verdict":"SAFE|CAUTION|DANGEROUS","summary":"one sentence","warnings":["..."]}

The summary is shown to a normal technical user asking "is this safe to run?".
Write it for them: one plain sentence saying whether you found anything harmful
and, if so, what it would do to them. No library names, API inventories, file
format details, or lists of what looked normal - if nothing is wrong, saying so
briefly is the whole summary. Put anything you could not check, or that you want
verified by hand, in warnings instead.
EOF
}

run_llm() {
  [[ "$NO_LLM" == "1" || "$FAST" == "1" || "$OFFLINE" == "1" ]] && return 0
  have python3 || return 0
  local prov; prov="$(detect_provider)"
  [[ -z "$prov" ]] && { info "llm: no provider available"; return 0; }
  info "llm: provider=$prov"

  local payload
  if [[ "$MODE" == "installer" ]]; then
    payload="$(installer_prompt)"$'\n\n--- BEGIN SCRIPT ---\n'"$(cat "$SCRIPT_FILE" 2>/dev/null)"$'\n--- END SCRIPT ---'
  else
    # send only flagged files, capped
    payload="$(malware_prompt)"
    local seen=() i f budget=48000
    for ((i=0; i<${#F_FILE[@]}; i++)); do
      [[ "${F_SEV[$i]}" == "LOW" ]] && continue
      f="${F_FILE[$i]}"; [[ -f "$f" ]] || continue
      case " ${seen[*]:-} " in *" $f "*) continue ;; esac
      seen+=("$f")
      (( ${#payload} > budget )) && break
      payload+=$'\n\n----- '"$(rel "$f")"$' -----\n'"$(llm_excerpt "$f")"
    done
    [[ ${#seen[@]} -eq 0 ]] && { info "llm: nothing flagged to review"; return 0; }
  fi

  # Static status line while the model runs (the LLM call can take several
  # seconds with nothing else on screen). Deliberately NOT the animated spinner:
  # the claude CLI must not share the terminal with it.
  local llm_line=0
  if [[ -t 2 && "$JSON" != "1" ]]; then
    printf '  %sllm review%s (%s)...' "$C" "$Z" "$prov" >&2; llm_line=1
  fi
  local raw; raw="$(llm_call "$prov" "$payload")"
  [[ "$llm_line" == "1" ]] && printf '\r\033[K' >&2
  [[ -z "$raw" ]] && { info "llm: no response from $prov"; return 0; }
  parse_llm "$raw"
  LLM_PROVIDER="$prov"
  # fold LLM warnings into the findings list so they appear in the report
  if [[ -n "$LLM_VERDICT" ]]; then
    local wsev=INFO
    case "$LLM_VERDICT" in DANGEROUS) wsev=HIGH;; CAUTION) wsev=MED;; esac
    local w
    while IFS= read -r w; do
      [[ -n "$w" ]] || continue
      F_SEV+=("$wsev"); F_TAG+=("llm"); F_FILE+=("(llm)"); F_LINE+=("0"); F_MSG+=("$w")
    done <<< "$LLM_WARNINGS"
  fi
}

# --- reporting ---------------------------------------------------------------
sev_color() { case "$1" in CRIT|HIGH) printf '%s' "$R";; MED) printf '%s' "$Y";; *) printf '%s' "$D";; esac; }

report_human() {
  local n=${#F_SEV[@]}
  printf '\n%s== sanitycheck (%s) ==%s  %s\n' "$B" "$MODE" "$Z" "$D$TARGET$Z"
  local hdr=0
  if [[ "$VERDICT" != "SAFE" ]]; then
    printf '%sfindings:%s %sCRIT %d%s  %sHIGH %d%s  %sMED %d%s  %sLOW %d%s\n' \
      "$B" "$Z" "$R" "$N_CRIT" "$Z" "$R" "$N_HIGH" "$Z" "$Y" "$N_MED" "$Z" "$D" "$N_LOW" "$Z"
    hdr=1
  fi
  [[ -n "$LLM_SUMMARY" ]] && { printf '%sllm (%s):%s %s\n' "$B" "${LLM_PROVIDER:-?}" "$Z" "$LLM_SUMMARY"; hdr=1; }
  [[ "$hdr" == "1" ]] && printf '\n'

  # What the default report answers is "is this safe to run". LOW findings are
  # dual-use context that cannot drive a verdict, and INFO is the LLM's own
  # methodology caveats - what it did not check, what to verify by hand. Both are
  # worth keeping and neither belongs in front of someone deciding whether to
  # double-click a download, so both live behind -v.
  local order=(CRIT HIGH MED LOW INFO) want i j hidden=0
  for want in "${order[@]}"; do
    if [[ "$VERBOSE" != "1" ]] && [[ "$want" == "LOW" || "$want" == "INFO" ]]; then
      for ((i=0; i<n; i++)); do [[ "${F_SEV[$i]}" == "$want" ]] && hidden=$((hidden+1)); done
      continue
    fi
    for ((i=0; i<n; i++)); do
      [[ "${F_SEV[$i]}" == "$want" ]] || continue
      local more=0 dup=0
      # The same finding across many files is one fact. Printing it once per file
      # buries everything else - six stock Electron dylibs pushed the actual
      # summary off the top of the screen. -v still lists them individually.
      if [[ "$VERBOSE" != "1" ]]; then
        for ((j=0; j<i; j++)); do
          [[ "${F_SEV[$j]}" == "$want" && "${F_TAG[$j]}" == "${F_TAG[$i]}" \
             && "${F_MSG[$j]}" == "${F_MSG[$i]}" ]] && { dup=1; break; }
        done
        (( dup )) && { hidden=$((hidden+1)); continue; }
        for ((j=i+1; j<n; j++)); do
          [[ "${F_SEV[$j]}" == "$want" && "${F_TAG[$j]}" == "${F_TAG[$i]}" \
             && "${F_MSG[$j]}" == "${F_MSG[$i]}" ]] && more=$((more+1))
        done
      fi
      local col; col="$(sev_color "$want")"
      local loc; loc="$(rel "${F_FILE[$i]}")"
      [[ "${F_LINE[$i]}" != "0" ]] && loc="$loc:${F_LINE[$i]}"
      (( more > 0 )) && loc="$loc  (+$more more files)"
      printf '%s[%s]%s %s%-16s%s %s\n      %s%s%s\n' \
        "$col" "$want" "$Z" "$C" "${F_TAG[$i]}" "$Z" "${F_MSG[$i]}" "$D" "$loc" "$Z"
    done
  done
  # Not on a SAFE result: there the answer is the whole report, and a dangling
  # "6 things hidden" line only invites a hunt through material that was filed as
  # unimportant precisely because it is.
  (( hidden > 0 )) && [[ "$VERDICT" != "SAFE" ]] && \
    printf '%s  (+%d hidden: LOW findings, notes, repeated files; -v to show)%s\n' "$D" "$hidden" "$Z"

  local vc vsym
  case "$VERDICT" in
    DANGEROUS) vc="$R"; vsym="[!]" ;;
    CAUTION)   vc="$Y"; vsym="[~]" ;;
    *)         vc="$G"; vsym="[+]" ;;
  esac
  printf '\n%s%s VERDICT: %s %s\n' "$vc$B" "$vsym" "$VERDICT" "$Z"
  # One line each. Nobody reads every flagged file, so telling them to was advice
  # that got ignored and made the rest look ignorable too.
  case "$VERDICT" in
    DANGEROUS) printf '%s  Known-malicious patterns found!%s\n' "$R" "$Z" ;;
    CAUTION)   printf '%s  Potential risk - review findings above.%s\n' "$Y" "$Z" ;;
    *)         printf '%s  No known-malicious patterns found.%s\n' "$G" "$Z" ;;
  esac
  echo
}

# Emit the whole report in ONE python3 call: stream findings as TSV on stdin and
# pass the scalars as argv. (Escaping per-field in the shell would spawn a python
# process per finding - slow on a large tree.)
report_json() {
  local i n=${#F_SEV[@]}
  for ((i=0; i<n; i++)); do
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "${F_SEV[$i]}" "${F_TAG[$i]}" "$(rel "${F_FILE[$i]}")" "${F_LINE[$i]}" "${F_MSG[$i]}"
  done | python3 -c '
import json, sys
_, version, mode, target, verdict, crit, high, med, low, llm = sys.argv
findings = []
for line in sys.stdin:
    p = line.rstrip("\n").split("\t", 4)
    if len(p) == 5:
        findings.append({"severity": p[0], "tag": p[1], "file": p[2],
                         "line": int(p[3]) if p[3].isdigit() else 0, "message": p[4]})
out = {"tool": "sanitycheck", "version": version, "mode": mode, "target": target,
       "verdict": verdict,
       "counts": {"crit": int(crit), "high": int(high), "med": int(med), "low": int(low)},
       "findings": findings}
if llm:
    out["llm_verdict"] = llm
print(json.dumps(out, indent=2))
' "$VERSION" "$MODE" "$TARGET" "$VERDICT" "$N_CRIT" "$N_HIGH" "$N_MED" "$N_LOW" "${LLM_VERDICT:-}"
}

# --- input classification & acquisition --------------------------------------
extract_url() { printf '%s' "$1" | grep -oE 'https?://[^ "'"'"')]+' | head -1 || true; }

classify_input() {
  local t="$1"
  if [[ -d "$t" ]]; then echo repo; return; fi
  if [[ -f "$t" ]]; then
    case "$t" in *.tar.gz|*.tgz|*.tar|*.zip) echo repo ;; *) echo file ;; esac
    return
  fi
  if printf '%s' "$t" | grep -qE '(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh|(bash|sh)\s+-c|<\(\s*(curl|wget)'; then
    echo installer; return
  fi
  if [[ "$t" =~ ^(https?|git|ssh)://|^git@|\.git$ ]]; then
    case "$t" in
      *.sh|*.bash) echo installer; return ;;
    esac
    if [[ "$t" =~ \.git($|/)|^git@|github\.com/[^/]+/[^/]+|gitlab\.com/[^/]+/[^/]+|bitbucket\.org/[^/]+/[^/]+ ]]; then
      echo repo; return
    fi
    echo installer; return
  fi
  echo unknown
}

WORK_DIR=""; ROOT=""; SCRIPT_FILE=""
# --- progress spinner (knight-rider) -----------------------------------------
# Shown on stderr while the audit runs so a slow scan (e.g. network dependency
# resolution) doesn't look like the terminal hung. Only on a TTY, not for --json.
SPIN_PID=""
start_spinner() {
  [[ -t 2 && "$JSON" != "1" ]] || return 0
  ( set +e                    # subshell inherits set -e, and ((pos+=dir))
                              # returns 1 whenever the result is 0 - that
                              # killed the spinner one full sweep in (~1.4s)
    w=10; pos=0; dir=1        # subshell: no `local` (invalid outside a function)
    while :; do
      bar=""
      for ((i=0; i<w; i++)); do [[ "$i" == "$pos" ]] && bar+="*" || bar+="."; done
      printf '\r  %sauditing%s [%s]' "$C" "$Z" "$bar" >&2
      (( pos+=dir )); (( pos<=0 )) && dir=1; (( pos>=w-1 )) && dir=-1
      sleep "${SANITYCHECK_SPIN_INTERVAL:-0.08}"   # env override is a test hook
    done ) &
  SPIN_PID=$!
}
stop_spinner() {
  [[ -n "$SPIN_PID" ]] || return 0
  # `|| true` on the kill too: if the spinner is already gone (bash reaps
  # background children), a bare failing kill takes the whole script - and the
  # report - down with it under set -e.
  kill "$SPIN_PID" 2>/dev/null || true; wait "$SPIN_PID" 2>/dev/null || true
  printf '\r\033[K' >&2
  SPIN_PID=""
}

cleanup() {
  stop_spinner
  [[ "$KEEP" != "1" && -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR" || true
}
trap cleanup EXIT

make_workdir() {
  if [[ -n "$OUT_DIR" ]]; then mkdir -p "$OUT_DIR"; WORK_DIR="$OUT_DIR";
  else WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sanitycheck.XXXXXX")"; fi
}

acquire_installer() {
  have curl || die "curl required for installer audit"
  local url; url="$(extract_url "$1")"
  [[ -n "$url" ]] || die "could not find a URL in: $1"
  make_workdir
  SCRIPT_FILE="$WORK_DIR/downloaded_script.sh"
  info "fetching $url"
  local code; code="$(curl -fsSL -w '%{http_code}' -o "$SCRIPT_FILE" "$url" 2>/dev/null)" || die "download failed (HTTP ${code:-?})"
  local size; size="$(wc -c < "$SCRIPT_FILE")"
  (( size == 0 )) && die "downloaded file is empty"
  (( size > 1048576 )) && die "file is ${size} bytes - too large for a typical install script"
  ROOT="$WORK_DIR"
}

acquire_repo() {
  local t="$1"
  if [[ "$t" =~ ^(https?|git|ssh)://|\.git$|^git@ ]]; then
    have git || die "git required to clone $t"
    make_workdir
    git clone --depth 1 -q "$t" "$WORK_DIR/repo" 2>/dev/null || die "clone failed: $t"
    ROOT="$WORK_DIR/repo"
  elif [[ -d "$t" ]]; then
    ROOT="$(cd "$t" && pwd)"
  elif [[ -f "$t" ]]; then
    make_workdir
    case "$t" in
      *.tar.gz|*.tgz|*.tar) have tar || die "tar required"; tar -xf "$t" -C "$WORK_DIR" 2>/dev/null || die "extract failed" ; ROOT="$WORK_DIR" ;;
      *.zip) have unzip || die "unzip required"; unzip -q "$t" -d "$WORK_DIR" 2>/dev/null || die "extract failed"; ROOT="$WORK_DIR" ;;
    esac
  fi
}

acquire_file() { # single source file
  make_workdir
  cp "$1" "$WORK_DIR/" && ROOT="$WORK_DIR"
}

# --- pipelines ---------------------------------------------------------------
# Installer "resolve": most droppers are staged - a small clean-looking stage-1
# fetches stage-2 (the real payload) from a remote host. We statically extract the
# URLs the script downloads (via curl/wget/fetch/...), pull each into the workdir
# (bounded; never executed), and recurse, so the normal engine then scans every
# stage. Caveat: a server can detect `curl|bash` and serve benign content to a
# plain fetch, so a clean stage-resolve is NOT proof of safety.
STAGE_MAX=8         # max total files fetched
STAGE_DEPTH=3       # max chain depth (stage-2 -> stage-3 -> ...)
STAGE_MAXSIZE=1048576
STAGE_SEEN="|"

# Extract the URLs a script actually downloads: those appearing as the argument
# of a fetch command (curl/wget/fetch/urlretrieve/Invoke-WebRequest/Download*).
extract_fetch_urls() { # file
  grep -oiE '(curl|wget|fetch|urlretrieve|Invoke-WebRequest|DownloadString|DownloadFile)[^|;&<>]*https?://[^ "'"'"')]+' "$1" 2>/dev/null \
    | grep -oE 'https?://[^ "'"'"')]+' \
    | sed 's/[]"'"'"');].*$//' \
    | sort -u
}

resolve_installer_stages() {
  [[ "$MODE" == "installer" && "$FOLLOW" == "1" && "$FAST" != "1" && "$OFFLINE" != "1" ]] || return 0
  have curl || return 0
  local fetched=0 depth=0
  local scan_list=("$SCRIPT_FILE")
  while (( depth < STAGE_DEPTH && fetched < STAGE_MAX )); do
    local newfiles=() f url
    for f in "${scan_list[@]}"; do
      [[ -f "$f" ]] || continue
      while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        # never fetch cloud-metadata / link-local endpoints (SSRF side effects)
        case "$url" in *://169.254.*|*://metadata*|*://[fF][eE]80:*) continue ;; esac
        case "$STAGE_SEEN" in *"|$url|"*) continue ;; esac
        STAGE_SEEN="$STAGE_SEEN$url|"
        (( fetched >= STAGE_MAX )) && break
        # give the stage a scannable extension (the content rules match on globs);
        # default to .sh since staged installer payloads are usually shell
        local ext="sh"
        case "$url" in
          *.py) ext="py" ;; *.ps1) ext="ps1" ;; *.rb) ext="rb" ;;
          *.js) ext="js" ;; *.pl) ext="pl" ;; *.php) ext="php" ;;
        esac
        local out="$WORK_DIR/stage_$fetched.$ext"
        if curl -fsSL --max-time 6 --max-filesize "$STAGE_MAXSIZE" -o "$out" "$url" 2>/dev/null; then
          fetched=$((fetched+1)); newfiles+=("$out")
          info "stage: fetched $url"
        fi
      done < <(extract_fetch_urls "$f" | head -n 20)
    done
    (( ${#newfiles[@]} == 0 )) && break
    scan_list=("${newfiles[@]}")
    depth=$((depth+1))
  done
  if (( fetched > 0 )); then
    add_finding LOW stage-resolved "$(rel "$SCRIPT_FILE")" 0 \
      "Fetched and scanned $fetched staged download(s) referenced by the installer. Note: a server can serve benign content to a non-piped fetch, so a clean result here is not proof of safety."
  fi
}

# Vet package NAMES (from `pip/npm install <name>`) against the known-malicious
# IOC list. No directory is scanned - the package's own code isn't on disk yet -
# so this is instant and cannot false-positive on your existing files. Catches
# e.g. `pip install frint` / `npm install skytext`.
audit_pkgcheck() {
  load_iocs
  # 1. instant, offline name check against the known-malicious IOC list.
  local name norm k i
  for name in "${PKG_NAMES[@]:-}"; do
    [[ -z "$name" ]] && continue
    norm="$(norm_pkg "$name")"
    i=0
    for k in "${IOC_PKG_NORM[@]:-}"; do
      [[ -z "$k" ]] && { i=$((i+1)); continue; }
      [[ "$norm" == "$k" ]] && add_finding CRIT ioc-pkg "$name" 0 \
        "Installing known-malicious package '$name' - ${IOC_PKG_NOTE[$i]:-known IOC}"
      i=$((i+1))
    done
  done

  # 2. content inspection: download each package's artifact from the registry
  # and scan the REAL code (never executed - just untar/unzip). Online + a
  # known ecosystem only; --fast/--offline stay at the name check above.
  [[ "$FAST" != "1" && "$OFFLINE" != "1" && -n "$ECOSYSTEM" ]] || return 0
  have python3 || return 0
  [[ -n "$HELPER" && -f "$HELPER" ]] || return 0
  ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sanitycheck-pkg.XXXXXX")"
  WORK_DIR="$ROOT"
  local sev tag file line msg f
  # fetch+extract (helper reports missing / too-large packages as findings)
  while IFS=$'\t' read -r sev tag file line msg; do
    [[ -z "$sev" ]] && continue
    add_finding "$sev" "$tag" "$file" "${line:-0}" "$msg"
  done < <(python3 "$HELPER" --fetch "$ECOSYSTEM" --dest "$ROOT" "${PKG_NAMES[@]}" 2>/dev/null || true)
  # scan the extracted contents with the full static engine (offline)
  if find "$ROOT" -type f 2>/dev/null | head -1 | grep -q .; then
    load_rules; collect_python_deps
    run_content_rules
    detect_native_shadowing
    detect_pth_files
    detect_npm_scripts
    detect_autorun_files
    detect_iocs
    while IFS=$'\t' read -r sev tag file line msg; do
      [[ -z "$sev" ]] && continue
      f="$file"; [[ "$file" == "declared-dependencies" ]] || f="$ROOT/$file"
      add_finding "$sev" "$tag" "$f" "${line:-0}" "$msg"
    done < <(python3 "$HELPER" "$ROOT" 2>/dev/null || true)
  fi
}

audit_installer() {
  acquire_installer "$TARGET"
  resolve_installer_stages   # pull staged payloads into the workdir first...
  load_rules; load_iocs
  run_content_rules          # ...so the engine scans stage-1 AND every fetched stage
  detect_iocs
  run_deep_pass
}

audit_repo_or_file() {
  [[ "$MODE" == "repo" ]] && acquire_repo "$TARGET" || acquire_file "$TARGET"
  [[ -n "$ROOT" ]] || die "could not acquire target: $TARGET"
  load_rules; load_iocs
  discover_venvs
  detect_app_bundle
  collect_python_deps
  extract_asars
  run_content_rules
  detect_native_shadowing
  detect_pth_files
  detect_npm_scripts
  detect_registry_redirect
  detect_autorun_files
  detect_iocs
  run_deep_pass
  # after the deep pass: it is a Python AST/typosquat pass, and asar payloads are
  # JavaScript, so it has nothing to say about them and they can be large.
  audit_asar_payloads
}

# --- run-after (installer only) ----------------------------------------------
maybe_run_installer() {
  [[ "$RUN_AFTER" == "1" && "$MODE" == "installer" ]] || return 0
  local prompt ans
  case "$VERDICT" in
    SAFE)      prompt='Run the script? [Y/n] ' ;;
    DANGEROUS) prompt="${R}Run despite DANGEROUS verdict?${Z} [y/N] " ;;
    *)         prompt='Run the script? [y/N] ' ;;
  esac
  printf '%s' "$prompt"; read -r ans
  case "$VERDICT" in
    SAFE) [[ "$ans" == [Nn]* ]] && { echo "Aborted."; KEEP=1; } || bash "$SCRIPT_FILE" ;;
    *)    [[ "$ans" == [Yy]* ]] && bash "$SCRIPT_FILE" || { echo "Aborted."; KEEP=1; } ;;
  esac
}

# --- main --------------------------------------------------------------------
main() {
  setup_colors   # usage/die can fire mid-parse; re-run after, once --no-color is known
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--run)     RUN_AFTER=1; shift ;;
      --fast)       FAST=1; shift ;;
      --offline)    OFFLINE=1; shift ;;
      --no-llm)     NO_LLM=1; shift ;;
      --no-follow)  FOLLOW=0; shift ;;
      --check-pkg)  CHECK_PKG=1; shift ;;
      --ecosystem)  ECOSYSTEM="${2:-}"; shift 2 ;;
      --provider)   PROVIDER="${2:-}"; shift 2 ;;
      --model)      MODEL="${2:-}"; shift 2 ;;
      --ioc)        EXTRA_IOCS+=("${2:-}"); shift 2 ;;
      --strict)     STRICT=1; shift ;;
      --json)       JSON=1; shift ;;
      -o|--output)  OUT_DIR="${2:-}"; shift 2 ;;
      -k|--keep)    KEEP=1; shift ;;
      --no-color)   NO_COLOR=1; shift ;;
      -v|--verbose) VERBOSE=1; shift ;;
      --version)    echo "sanitycheck $VERSION"; exit 0 ;;
      -h|--help)    usage ;;
      --)           shift; [[ -z "$TARGET" && $# -gt 0 ]] && TARGET="$1"; break ;;
      -*)           die "unknown option: $1 (see --help)" ;;
      *)            if [[ "$CHECK_PKG" == "1" ]]; then PKG_NAMES+=("$1")
                    elif [[ -z "$TARGET" ]]; then TARGET="$1"; else TARGET="$TARGET $1"; fi; shift ;;
    esac
  done
  setup_colors
  have grep || die "grep required"

  # --check-pkg: vet package names, then exit. Stays silent when clean so it can
  # run on every `install <name>` from the hook without adding noise.
  if [[ "$CHECK_PKG" == "1" ]]; then
    MODE="pkgcheck"; TARGET="${PKG_NAMES[*]:-}"
    start_spinner
    audit_pkgcheck
    stop_spinner
    VERDICT="$(static_verdict)"
    if [[ "$VERDICT" != "SAFE" ]]; then
      if [[ "$JSON" == "1" ]]; then report_json; else report_human; fi
    elif [[ "$JSON" != "1" && -t 1 ]]; then
      # SAFE + interactive: close the loop with a one-line confirmation. Stays
      # silent when output is piped/redirected (the automatic non-tty hook scan),
      # so it adds no noise to scripts or CI.
      printf '%s[+] %s — SAFE%s\n' "$G" "$TARGET" "$Z"
    fi
    case "$VERDICT" in
      DANGEROUS) exit 1 ;;
      CAUTION)   [[ "$STRICT" == "1" ]] && exit 1 || exit 0 ;;
      *)         exit 0 ;;
    esac
  fi

  [[ -n "$TARGET" ]] || usage
  MODE="$(classify_input "$TARGET")"
  [[ "$MODE" == "unknown" ]] && die "could not tell what '$TARGET' is (not a path, URL, or curl|bash command)"
  info "mode=$MODE"

  start_spinner
  if [[ "$MODE" == "installer" ]]; then
    audit_installer
  else
    audit_repo_or_file
  fi

  stop_spinner   # clear the spinner before the (optional) LLM step, which has
                 # its own UI and must not share the terminal with the spinner
  VERDICT="$(static_verdict)"
  run_llm
  [[ -n "$LLM_VERDICT" ]] && VERDICT="$(more_severe "$VERDICT" "$LLM_VERDICT")"

  if [[ "$JSON" == "1" ]]; then report_json; else report_human; fi

  maybe_run_installer

  case "$VERDICT" in
    DANGEROUS) exit 1 ;;
    CAUTION)   [[ "$STRICT" == "1" ]] && exit 1 || exit 0 ;;
    *)         exit 0 ;;
  esac
}

LLM_PROVIDER=""
main "$@"
