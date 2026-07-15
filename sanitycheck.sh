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
MODE=""             # installer | repo | file  (auto-detected)

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

${B}OPTIONS${Z}  (flags only subtract work; defaults do the most)
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

Never run untrusted code you have not read. Run PoCs in a throwaway VM.
EOF
  exit 0
}

# --- findings store ----------------------------------------------------------
F_SEV=(); F_TAG=(); F_FILE=(); F_LINE=(); F_MSG=()
N_CRIT=0; N_HIGH=0; N_MED=0; N_LOW=0

# In installer mode, patterns that are normal for legitimate installers are
# demoted so the tool doesn't cry wolf. Unambiguous malware tags keep full
# severity. (Effectiveness includes staying trusted enough to be read.)
demote_for_installer() { # tag sev  ->  echoes possibly-lowered sev
  local tag="$1" sev="$2"
  [[ "$MODE" == "installer" ]] || { printf '%s' "$sev"; return; }
  case "$tag" in
    persistence|dep-links|net-exec|build-ext|shell-exec) printf 'LOW' ;;
    download-exec) [[ "$sev" == "HIGH" ]] && printf 'MED' || printf '%s' "$sev" ;;
    *) printf '%s' "$sev" ;;
  esac
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
  local sev; sev="$(demote_for_installer "$2" "$1")"
  local tag="$2" file="$3" line="$4" msg="$5"
  F_SEV+=("$sev"); F_TAG+=("$tag"); F_FILE+=("$file"); F_LINE+=("$line"); F_MSG+=("$msg")
  case "$sev" in
    CRIT) N_CRIT=$((N_CRIT+1)) ;;
    HIGH) N_HIGH=$((N_HIGH+1)) ;;
    MED)  N_MED=$((N_MED+1)) ;;
    *)    N_LOW=$((N_LOW+1)) ;;
  esac
}

rel() { local p="$1"; printf '%s' "${p#"$ROOT"/}"; }

# --- content-rule engine -----------------------------------------------------
RULE_SEV=(); RULE_TAG=(); RULE_GLOB=(); RULE_ERE=(); RULE_MSG=()
rule() { RULE_SEV+=("$1"); RULE_TAG+=("$2"); RULE_GLOB+=("$3"); RULE_ERE+=("$4"); RULE_MSG+=("$5"); }

SH="*.sh *.bash *.zsh *.command Makefile *.mk"
ANY="*.py *.pyx *.sh *.bash *.rb *.pl *.php *.js *.ts *.go *.c *.ps1"
# ANY plus build-system files that execute on build/install (gradle=Groovy,
# build.rs=cargo, Rakefile/extconf.rb/Gemfile=ruby, build.sbt=scala).
ANYPLUS="$ANY *.gradle build.rs Rakefile Gemfile extconf.rb build.sbt *.groovy Dockerfile"

load_rules() {
  # install-time code execution (pip/npm runs this; the #1 supply-chain vector)
  rule HIGH install-hook "setup.py"        'cmdclass\s*=|class .*\(.*install.*\):|PostInstall|def run\(self\)' \
       'setup.py defines an install-time hook (cmdclass/custom install) - runs code on "pip install"'
  rule MED  dep-links    "setup.py"        'dependency_links\s*=|--extra-index-url|--index-url' \
       'Custom package index / dependency_links - can pull attacker-controlled packages'
  rule LOW  build-ext    "setup.py"        'build_ext|Extension\(|ext_modules' \
       'Builds a native extension at install time'

  # native-extension import shadowing (the core ChocoPoC trick; loaders here)
  rule HIGH native-load  "*.py *.pyx"      'ctypes\.(CDLL|WinDLL|cdll|windll)|cffi|LoadLibrary' \
       'Loads a native library directly - compiled payloads evade source review'

  # environmental gating / anti-analysis
  rule HIGH env-gating   "*.py *.pyx"      'EXPLOIT_POC|0xF4835C9C' \
       'Gates behaviour on a specific PoC filename - classic sandbox-evasion detonation trigger'
  rule MED  self-inspect "*.py *.pyx"      'hash\([^)]*(__file__|basename)|__file__[^\n]{0,40}==[^\n]{0,20}0x|for\s+\w+\s+in\s+(list\()?sys\.modules' \
       'Hashes its own filename or iterates loaded modules - used to detonate only for real victims'
  rule MED  anti-debug   "*.py *.pyx *.c"  'CheckRemoteDebuggerPresent|IsDebuggerPresent|GetThreadContext|ptrace\(' \
       'Anti-debugging check - hallmark of malware, not of a PoC'
  rule MED  sandbox-check "*.py *.pyx"     'platform\.node|getpass\.getuser|hostname.*(sandbox|vmware|virtualbox)' \
       'Environment fingerprinting - may refuse to run under analysis'

  # obfuscation / dynamic execution
  rule HIGH pack-exec    "*.py *.pyx"      '(marshal\.loads|zlib\.decompress|lzma\.decompress|codecs\.decode).*(exec|eval)|exec\(.*decompress|exec\(.*b64decode' \
       'Decodes/decompresses then executes a blob - packed payload'
  rule MED  dyn-exec     "*.py *.pyx"      'exec\(|eval\(|__import__\(|compile\(.*exec' \
       'Dynamic code execution'
  rule MED  decode       "*.py *.pyx"      'base64\.b(64|85|32)decode|bytes\.fromhex|codecs\.decode.*rot' \
       'Decodes encoded data (base64/hex/rot13) - common payload wrapper'
  rule LOW  blob         "*.py *.pyx *.txt" '[A-Za-z0-9+/]{220,}={0,2}' \
       'Very long encoded literal - possible embedded payload'
  rule MED  hex-blob     "*.py *.pyx"      '(\\x[0-9a-fA-F]{2}){40,}' \
       'Long \\xNN byte string - possible shellcode/obfuscated data'

  # shell / command execution
  rule MED  shell-exec   "*.py *.pyx"      'os\.system\(|os\.popen\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True|pty\.spawn|commands\.getoutput' \
       'Executes shell commands'
  rule LOW  net-exec     "*.py *.pyx"      'urllib.*urlopen|requests\.(get|post)|socket\.socket|http\.client' \
       'Makes network connections'

  # credential / data harvesting
  rule HIGH harvest      "*.py *.pyx"      'Login Data|cookies\.sqlite|key4\.db|logins\.json|os_crypt|Local State|Keychain|_distutils' \
       'Reads browser credential/cookie stores - data theft'
  rule HIGH keychain-cli "$ANY"            'security\s+find-generic-password|login\.keychain|secretstorage' \
       'Extracts OS keychain / secret-store credentials'
  rule HIGH wallet       "$ANY"            'wallet\.dat|MetaMask|Electrum|Exodus|Ethereum/keystore|\.config/solana' \
       'Accesses cryptocurrency wallet files - wallet stealer behaviour'
  rule MED  histfiles    "*.py *.pyx"      '\.bash_history|\.zsh_history|\.ssh/id_[rd]sa|\.aws/credentials|\bid_rsa\b' \
       'Reads shell history / SSH / cloud credential files'

  # surveillance
  rule HIGH keylog       "$ANY"            'pynput\.keyboard|GetAsyncKeyState|SetWindowsHookEx|keyboard\.on_press|CGEventTap' \
       'Keylogging / input-hooking API - surveillance, not exploitation'
  rule MED  screencap    "$ANY"            'ImageGrab\.grab|\bmss\(\)|screencapture\b|\bscrot\b' \
       'Screen capture - confirm captures are not exfiltrated'

  # persistence / tampering
  rule HIGH persist-pth  "*.py *.pyx"      '_distutils_hack|add_shim|site-packages.*\.pth|\.pth.*__import__' \
       'Writes a .pth / _distutils_hack shim - auto-executes on every interpreter start'
  rule LOW  timestomp    "*.py *.pyx *.c"  'os\.utime\(|SetFileTime|st_mtime\s*=' \
       'Timestomps files - forensic evasion (weak signal on its own)'

  # C2 evasion (DoH tunneling, SNI/host-header fronting, Mapbox abuse)
  rule HIGH doh          "*.py *.pyx"      'dns-query|application/dns-json|dns\.google/resolve|cloudflare-dns\.com|/resolve\?name=' \
       'DNS-over-HTTPS resolution - hides C2 lookup from network monitoring'
  rule HIGH sni-front    "*.py *.pyx"      'assert_hostname|server_hostname|HostHeaderSSLAdapter|set_ciphers.*ServerName|TLS.*SNI' \
       'SNI / Host-header fronting - disguises C2 traffic as a trusted service'
  rule MED  mapbox-c2    "*.py *.pyx"      'api\.mapbox\.com|mapbox.*(dataset|feature)' \
       'Uses Mapbox datasets/features - abused for C2 tasking in ChocoPoC'

  # general malicious code (polyglot)
  rule HIGH reverse-shell "$ANYPLUS" \
       '/dev/tcp/|nc\s+-e|ncat\s+-e|mkfifo.*(/bin/sh|nc )|bash\s+-i\s*>&|pty\.spawn\(.{0,12}/bin/(sh|bash)|socket.*(dup2|SOCK_STREAM).*(/bin/sh|exec)' \
       'Reverse-shell pattern - hands an interactive shell to a remote host'
  rule HIGH download-exec "$ANYPLUS Makefile *.dockerfile" \
       '(curl|wget)\s+[^|;]*\|\s*(sudo\s+)?((ba)?sh|node|python[0-9.]*|perl|ruby)|(curl|wget)[^;|]*;[^;]*chmod\s+\+x|urlretrieve\(|certutil\s+-urlcache|bitsadmin\s+/transfer|Invoke-WebRequest[^\n]*\|\s*iex' \
       'Downloads a remote file and executes it'
  rule HIGH destructive  "$ANYPLUS Makefile" \
       'rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+["]?(--no-preserve-root|/(\s|$|\*|["])|~(\s|/|$)|\$\{?HOME|\*(\s|$))|\bmkfs\.|dd\s+if=/dev/(zero|u?random)\s+of=/dev|:\(\)\s*\{\s*:\s*\|\s*:&?|shutil\.rmtree\(\s*["]?(/(["]|\s*\))|~|\$HOME)' \
       'Destructive filesystem/disk wipe or fork bomb'
  rule HIGH win-lolbin   "*.ps1 *.psm1 *.bat *.cmd *.hta *.vbs" \
       'powershell.*-e(nc(odedcommand)?)?\b|-EncodedCommand|IEX\s*\(|Invoke-Expression|New-Object\s+Net\.WebClient|FromBase64String|\bmshta\b|regsvr32.*scrobj|DownloadString' \
       'Encoded PowerShell / living-off-the-land binary execution'
  rule HIGH miner        "$ANY *.yml *.yaml *.json *.conf" \
       'stratum\+tcp://|\bxmrig\b|\bminerd\b|cpuminer|coinhive|supportxmr|nicehash|nanopool' \
       'Cryptocurrency miner reference'
  rule HIGH backdoor-acct "$ANY Makefile" \
       'useradd\b[^\n]{0,60}(-o\s+-u\s*0|-G\s+(sudo|wheel))|net\s+user\b[^\n]{0,40}/add|net\s+localgroup\b[^\n]{0,40}/add' \
       'Creates a new (possibly privileged) user account - backdoor'
  rule MED  exfil-channel "$ANYPLUS" \
       'discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/(api|raw)|api\.telegram\.org/bot|https?://t\.me/|transfer\.sh|0x0\.st|termbin\.com' \
       'Exfiltration channel (webhook / paste / telegram / anonymous upload)'
  rule MED  persistence  "$ANY" \
       'crontab\s+-|/etc/cron|authorized_keys|~/\.(bashrc|zshrc|profile)|LaunchAgents|LaunchDaemons|/etc/systemd/system|reg\s+add.*\\Run|schtasks\s+/create|New-Service' \
       'Installs a persistence mechanism (cron / autostart / service / SSH key)'
  rule MED  secret-scrape "$ANY" \
       '/proc/self/environ|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|\.aws/credentials|\.docker/config\.json|\.kube/config' \
       'Reads cloud keys / access tokens / credential files'
  rule MED  shell-obf    "$SH" \
       'eval\s+"?\$\(|base64\s+-d\s*\|\s*(ba)?sh|\$\{IFS\}|`.*\$\(.*`|xxd\s+-r\s+-p' \
       'Obfuscated or dynamically-evaluated shell'

  # ===== dev/researcher-workstation targeting (editor, IDE, CI autorun) ========
  # These fire when merely OPENING/cloning a repo runs code - the vector behind
  # Lazarus "Contagious Interview" and trojanised research projects.
  rule HIGH ide-autorun  "tasks.json"      'folderOpen' \
       'VS Code task set to auto-run on folder open - zero-click code execution when the repo is opened in the editor'
  rule HIGH vs-buildevent "*.vcxproj *.csproj *.vbproj *.targets *.props" \
       'PreBuildEvent|PostBuildEvent|<Exec\s|Command>[^<]*(cmd|powershell|pwsh|bash|curl|wget|mshta)' \
       'Visual Studio project runs a command at build time (Lazarus researcher-targeting vector - malicious .vcxproj/DLL)'
  rule HIGH shellcode    "*.py *.pyx *.c *.cs *.go *.js" \
       'VirtualAllocEx?|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|mmap\([^)]*PROT_EXEC|PROT_EXEC[^)]*PROT_WRITE|ctypes\.cast\([^)]*CFUNCTYPE' \
       'Allocates executable memory / injects into a process - shellcode runner'
  rule LOW  pickle-exec  "*.py *.pyx" \
       'pickle\.loads|cPickle\.loads|jsonpickle\.decode' \
       'Unpickling untrusted data can execute code - verify the source is trusted'
  rule MED  pickle-reduce "*.py *.pyx" \
       'def __reduce__\s*\(' \
       'Custom __reduce__ - controls what runs when the object is unpickled (a pickle RCE primitive)'
  rule MED  lib-inject   "$ANY" \
       'LD_PRELOAD|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH' \
       'Library injection via LD_PRELOAD / DYLD_INSERT_LIBRARIES'
  rule MED  ci-exec      "*.yml *.yaml" \
       '\$\{\{\s*github\.event\.[^}]*(\.body|\.title|\.message|head_ref|head\.ref)|(curl|wget)\s+[^|]*\|\s*(ba)?sh' \
       'CI workflow interpolates an injectable untrusted field (issue/PR body/title, head ref) into a step, or pipes a download into a shell'
  rule MED  pkg-registry ".npmrc pip.conf .pypirc" \
       '_authToken\s*=|//[^/]+/:_auth|_password\s*=|extra-index-url\s*=\s*https?' \
       'Embedded registry token or extra package index - credential exposure / dependency-confusion vector'
}

run_content_rules() {
  local i n=${#RULE_SEV[@]}
  for ((i=0; i<n; i++)); do
    local sev="${RULE_SEV[$i]}" tag="${RULE_TAG[$i]}" glob="${RULE_GLOB[$i]}" ere="${RULE_ERE[$i]}" msg="${RULE_MSG[$i]}"
    local inc=() g gl
    read -ra gl <<< "$glob"
    for g in "${gl[@]}"; do inc+=(--include="$g"); done
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      local file="${hit%%:*}"; local rest="${hit#*:}"; local line="${rest%%:*}"
      add_finding "$sev" "$tag" "$file" "$line" "$msg"
    done < <(grep -rInE "${inc[@]}" -- "$ere" "$ROOT" 2>/dev/null | head -n 40 || true)
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
      add_finding HIGH native-vendored "$so" 0 \
        "Vendored compiled extension '$base' - review or hash-check; ChocoPoC hid its payload in one"
    fi
  done < <(find "$ROOT" -type f \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' \) 2>/dev/null || true)
}

detect_pth_files() {
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if grep -qE 'import|exec|eval' "$p" 2>/dev/null; then
      add_finding CRIT pth-exec "$p" 1 \
        ".pth file contains executable 'import' line - runs automatically on every interpreter startup"
    else
      add_finding MED pth-file "$p" 0 ".pth file present - can inject import paths"
    fi
  done < <(find "$ROOT" -type f -name '*.pth' 2>/dev/null || true)
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
  done < <(find "$ROOT" -maxdepth 4 -type f -name 'package.json' 2>/dev/null || true)
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
  done < <(find "$ROOT" -maxdepth 3 -type f -name '.envrc' 2>/dev/null || true)
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
  done < <(find "$ROOT" -maxdepth 4 -type f -name 'conftest.py' 2>/dev/null || true)
  # sitecustomize.py / usercustomize.py - auto-imported at interpreter startup.
  # Some legitimate tooling (e.g. coverage's subprocess trick) ships one, so a
  # plain hook is MED; only escalate to HIGH on dangerous content.
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    local sev=MED
    grep -qE "$danger" "$f" 2>/dev/null && sev=HIGH
    add_finding "$sev" py-startup-hook "$f" 0 \
      "$(basename "$f") is auto-imported at Python startup - an exec/persistence vector when it lands on sys.path"
  done < <(find "$ROOT" -maxdepth 4 -type f \( -name 'sitecustomize.py' -o -name 'usercustomize.py' \) 2>/dev/null || true)
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

IOC_PKG=(); IOC_SHA=(); IOC_ENV=(); IOC_STR=(); IOC_HOST=()
IOC_PKG_NOTE=(); IOC_SHA_NOTE=()
load_iocs() {
  local files=("$IOC_DB" "${EXTRA_IOCS[@]}")
  local f
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
}

# Normalize a package name for IOC matching: lowercase and drop all . _ -
# separators, so a known-bad "skytext" also catches "sky-text" / "sky_text".
norm_pkg() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '._-'; }

detect_iocs() {
  local d k
  for d in "${DECLARED_PKGS[@]:-}"; do
    [[ -z "$d" ]] && continue
    local dl; dl="$(norm_pkg "$d")"
    local i=0
    for k in "${IOC_PKG[@]:-}"; do
      [[ -z "$k" ]] && { i=$((i+1)); continue; }
      if [[ "$dl" == "$(norm_pkg "$k")" ]]; then
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
    while IFS= read -r hit; do
      [[ -z "$hit" ]] && continue
      local file="${hit%%:*}"; local rest="${hit#*:}"; local line="${rest%%:*}"
      add_finding CRIT ioc-str "$file" "$line" "Contains ChocoPoC IOC string (env marker / magic constant / C2 host)"
    done < <(grep -rInaE -- "$joined" "$ROOT" 2>/dev/null | head -n 20 || true)
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
          add_finding CRIT ioc-hash "$art" 0 "File hash matches known ChocoPoC payload - ${IOC_SHA_NOTE[$i]:-IOC}"
        fi
        i=$((i+1))
      done
    done < <(find "$ROOT" -type f \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' -o -name '*.whl' -o -name '*.tar.gz' -o -name '*.zip' \) 2>/dev/null || true)
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

static_verdict() {
  if (( N_CRIT >= 1 || N_HIGH >= 2 )); then echo DANGEROUS
  elif (( N_HIGH == 1 || N_MED >= 1 )); then echo CAUTION
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
  cat <<'EOF'
You are a malware analyst reviewing a proof-of-concept exploit and its
dependencies for supply-chain trojans (the "ChocoPoC" class) and general malware.
Below are the files a static scanner flagged. Respond with ONLY a JSON object:
{"verdict":"SAFE|CAUTION|DANGEROUS","summary":"one sentence","warnings":["..."]}
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
      payload+=$'\n\n----- '"$(rel "$f")"$' -----\n'"$(head -c 8000 "$f" 2>/dev/null || true)"
    done
    [[ ${#seen[@]} -eq 0 ]] && { info "llm: nothing flagged to review"; return 0; }
  fi

  local raw; raw="$(llm_call "$prov" "$payload")"
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
  printf '%sfindings:%s %sCRIT %d%s  %sHIGH %d%s  %sMED %d%s  %sLOW %d%s\n' \
    "$B" "$Z" "$R" "$N_CRIT" "$Z" "$R" "$N_HIGH" "$Z" "$Y" "$N_MED" "$Z" "$D" "$N_LOW" "$Z"
  [[ -n "$LLM_SUMMARY" ]] && printf '%sllm (%s):%s %s\n' "$B" "${LLM_PROVIDER:-?}" "$Z" "$LLM_SUMMARY"
  printf '\n'

  local order=(CRIT HIGH MED LOW INFO) want i
  for want in "${order[@]}"; do
    [[ "$want" == "LOW" && "$VERBOSE" != "1" ]] && continue
    for ((i=0; i<n; i++)); do
      [[ "${F_SEV[$i]}" == "$want" ]] || continue
      local col; col="$(sev_color "$want")"
      local loc; loc="$(rel "${F_FILE[$i]}")"
      [[ "${F_LINE[$i]}" != "0" ]] && loc="$loc:${F_LINE[$i]}"
      printf '%s[%s]%s %s%-16s%s %s\n      %s%s%s\n' \
        "$col" "$want" "$Z" "$C" "${F_TAG[$i]}" "$Z" "${F_MSG[$i]}" "$D" "$loc" "$Z"
    done
  done
  (( N_LOW > 0 && VERBOSE != 1 )) && printf '%s  (+%d LOW findings; -v to show)%s\n' "$D" "$N_LOW" "$Z"

  local vc vsym
  case "$VERDICT" in
    DANGEROUS) vc="$R"; vsym="[!]" ;;
    CAUTION)   vc="$Y"; vsym="[~]" ;;
    *)         vc="$G"; vsym="[+]" ;;
  esac
  printf '\n%s%s VERDICT: %s %s\n' "$vc$B" "$vsym" "$VERDICT" "$Z"
  case "$VERDICT" in
    DANGEROUS) printf '%s  Do not install or run this. Treat it as hostile.%s\n' "$R" "$Z" ;;
    CAUTION)   printf '%s  Read every flagged file before you install or run anything.%s\n' "$Y" "$Z" ;;
    *)         printf '%s  Nothing suspicious found by static checks. Still read the code before running.%s\n' "$G" "$Z" ;;
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
cleanup() { [[ "$KEEP" != "1" && -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR" || true; }
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
  collect_python_deps
  run_content_rules
  detect_native_shadowing
  detect_pth_files
  detect_npm_scripts
  detect_autorun_files
  detect_iocs
  run_deep_pass
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
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--run)     RUN_AFTER=1; shift ;;
      --fast)       FAST=1; shift ;;
      --offline)    OFFLINE=1; shift ;;
      --no-llm)     NO_LLM=1; shift ;;
      --no-follow)  FOLLOW=0; shift ;;
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
      *)            [[ -z "$TARGET" ]] && TARGET="$1" || TARGET="$TARGET $1"; shift ;;
    esac
  done
  [[ -n "$TARGET" ]] || usage
  setup_colors
  have grep || die "grep required"

  MODE="$(classify_input "$TARGET")"
  [[ "$MODE" == "unknown" ]] && die "could not tell what '$TARGET' is (not a path, URL, or curl|bash command)"
  info "mode=$MODE"

  if [[ "$MODE" == "installer" ]]; then
    audit_installer
  else
    audit_repo_or_file
  fi

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
