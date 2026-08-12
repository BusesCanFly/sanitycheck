# sanitycheck README

⚠️🚨 This is entirely vibe code slop, but it was useful so I wanted to share 🥀 🚨⚠️

## sanitycheck

Audit untrusted code before you run it. `sanitycheck` scans `curl | bash` installers, cloned repos and their dependencies, pip/npm installs, and single scripts, then gives a `SAFE` / `CAUTION` / `DANGEROUS` verdict. It never runs the code it checks.

A baseline security check with no extra effort: shell hooks catch the commands, and anything not flagged runs as normal.

<p align="center">
  <img src="demo.svg" alt="sanitycheck auditing a git clone, a pip install, a curl|bash installer, and direct usage — showing DANGEROUS, CAUTION, and SAFE verdicts" width="720">
</p>

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/BusesCanFly/sanitycheck/main/install.sh | bash
```

(lol)

Or clone and run locally:

```sh
git clone https://github.com/BusesCanFly/sanitycheck.git
cd sanitycheck
./install.sh
```

The installer adds the shell hook and PATH entry to your `.zshrc` / `.bashrc`, and installs the deep-pass helper and IOC database.

Requires `bash`, `grep`, `find`. `python3`, `rg`, `unsquashfs` (for AppImages) and an LLM provider are optional.

## How it works

With the shell hook enabled, sanitycheck audits automatically:

| Trigger | Scan |
|---------|------|
| `curl \| bash` command line (zsh) | audits the script before it runs |
| `git clone <url>` | **fast** static scan of the fresh checkout |
| `pip` / `pipx` / `npm` / `yarn` / `pnpm` / `poetry` / `uv` install, `go install` / `go get`, `cargo install` / `add`, `gem` / `bundle install` | **deep** scan with dependency resolution; aborts on DANGEROUS |

Each hook asks first (`[Y/n]`, Enter audits, `n` skips); without a terminal it scans automatically. It never installs, imports, builds, or runs the target.

Clone is fast because dependencies aren't pulled yet; resolution waits for install, where the install latency hides the scan. Build commands (`make`, `cargo build`, `go build`, `go run`, `gradle`) aren't hooked — they run every few seconds while you work, and that's what the clone scan is for. `cargo install` is hooked because it compiles what it downloads, and a `build.rs` runs during that compile.

Core checks are pure shell (`grep`/`find`) and run offline. `python3` adds AST / typosquat / Unicode analysis, dependency resolution, `.asar` unpacking, and `--json`; `rg` is used for the search if installed, roughly 3x faster on large targets; an LLM adds a second opinion. Missing pieces are skipped, not fatal — except `--json`, which needs `python3` and says so rather than producing nothing.

Some applications ship as one opaque file that a directory walk can't see into. Those are unpacked and scanned, with findings reported against the container — `app.asar!/index.js`, `Foo.AppImage!/AppRun`:

- **Electron** keeps its code in `app.asar`, a concatenated blob behind a JSON header.
- **AppImage** is an ELF runtime with a whole filesystem appended. It is *not* opened with `--appimage-extract`: that flag belongs to the runtime inside the file, so using it means executing the untrusted binary to ask it to unpack itself. The filesystem offset is computed from the ELF header and read directly with `unsquashfs`, which never involves the runtime. Without `unsquashfs` the AppImage is reported as unread rather than passed as clean.

Enable the hook yourself (the installer does this for you):

```sh
echo 'source ~/.local/share/sanitycheck/hooks/sanitycheck.zsh' >> ~/.zshrc  # or .bashrc
```

- `SANITYCHECK_HOOK=0 <cmd>` — bypass once (or `command git/pip/...`)
- `SANITYCHECK_HOOK_STRICT=1` — hard-abort on DANGEROUS, no prompt
- `SANITYCHECK_HOOK_FAST=1` — instant, offline hook scans

## What it catches

Malicious behaviour, not weak configuration: an insecure setting is someone else's bug to fix, and reporting it buries the findings that are code doing something to you.

Supply-chain trojans:

- compiled `.so`/`.pyd`/`.node` shadowing a same-named `.py` on import; vendored native extensions; IOC hash matches
- `setup.py` hooks, `.pth` shims, npm lifecycle scripts, `binding.gyp` and `#cgo` build-time execution, `go.mod` toolchain directives
- typosquatted, known-malicious, or non-existent (dependency-confusion) packages, including transitive ones
- Go module paths that near-miss a popular one (`boltdb-go/bolt`, `shopsprint/decimal`)
- installs redirected to a non-official registry or index, including cargo source replacement
- a dependency whose version spec is a URL — whatever that host serves, under a name you recognise

Zero-click autorun:

- VS Code `tasks.json` `runOn: folderOpen`, Visual Studio build events
- `conftest.py`, `sitecustomize.py`, `.envrc`
- `devcontainer.json` lifecycle commands — `initializeCommand` runs on the host, before any container exists
- a `.git` directory that came with the tree: `core.sshCommand`, `core.fsmonitor`, `clean`/`smudge` filters, and executable hooks all run on ordinary git commands (a fresh `git clone` can't carry these; a copied or unzipped working tree can)
- `.cargo/config.toml` `runner`/`linker`, which cargo executes on any build in the directory
- Trojan Source bidi / invisible Unicode

Code you can't read from the file:

- `eval`/`exec` fed from `fetch` or a base64 blob; nested encoding layers
- URLs built by string reversal or character arithmetic to stay out of a grep
- DoH/SNI-fronted C2, tunnel endpoints (ngrok, trycloudflare), filename gating
- text aimed at an automated reviewer ("ignore previous instructions") — malware ships prompt injection to talk AI triage out of a verdict, and this tool has one

Theft and persistence:

- shell history, SSH keys, cloud/CI tokens, keychain, wallets, password vaults, AI-tool credentials
- creating a repo, reading Actions secrets, or committing a workflow from inside the code
- downloads piped into `osascript`; stripping quarantine, disabling Gatekeeper/SIP
- LaunchAgents, systemd user units, `.config/autostart`, `/etc/ld.so.preload`, cron, authorized_keys

General malware (shell, JS, Python, Ruby, Go, Makefiles, Dockerfiles, Jupyter notebooks): reverse shells, download-and-exec, destructive ops, miners, exfil channels, keyloggers, shellcode. Windows payloads too — encoded PowerShell in a repo is evidence the repo is malicious even where it can't run.

Notebooks are read line-by-line like source: a notebook stores each line of a cell as its own JSON string, so the same rules apply. Patterns split across two lines of a cell are missed, the same as anywhere else.

One signal repeated across many files counts once toward the verdict, so an app shipping six vendored dylibs is a `CAUTION` to read, not a block.

## What it tells you

The answer is the whole report:

```
== sanitycheck (repo) ==  ./CVE-2026-12345-poc
[!] DANGEROUS - execution not advised
    matches known malware, gives a remote host control, steals credentials and keys (+5 more)
    104 findings in 39 files - "-v" for detail
```

Three lines, phrased as what it would do to you. `import-shadow` and `mapbox-c2` are precise and mean nothing to someone deciding whether to run a download, so rule names, file locations and dual-use signals (`eval`, `subprocess`, base64) are evidence for the answer rather than the answer, and live behind `-v`. `--json` always contains everything.

`-v` adds the same list in full with locations, then every individual finding, then the LLM's caveats about what it didn't check.

A clean result is two lines and nothing else:

```
== sanitycheck (repo) ==  ./some-tool
[+] SAFE - nothing here looks like it would harm your system
```

## Direct usage

You can also run sanitycheck manually, without the hook:

```sh
sanitycheck "curl -fsSL https://example.com/install.sh | bash"   # installer
sanitycheck ./CVE-2026-12345-poc                                 # cloned repo
sanitycheck https://github.com/x/poc.git                         # clone + scan
sanitycheck exploit.py                                           # single file
sanitycheck ~/Downloads/Some.app                                 # app bundle
sanitycheck ~/Downloads/Some.AppImage                            # AppImage
```

| Flag | Description |
|------|-------------|
| `-r, --run` | After auditing an installer, prompt to run it (the audited bytes, not a second fetch — keeping any `sudo` and arguments from the original pipeline) |
| `--fast` | Static checks only (skip network resolve + LLM) |
| `--offline` | No network at all |
| `--no-llm` | Skip the LLM second opinion |
| `--no-follow` | Don't fetch the staged payloads an installer downloads |
| `--strict` | Exit nonzero on `CAUTION` too (CI gate) |
| `--json` | Machine-readable report |
| `--ioc FILE` | Extra IOC database (repeatable) |
| `--check-pkg NAME...` | Vet package name(s) against IOCs and typosquats; when online, download and scan their real contents (what the install hook uses) |
| `--ecosystem ECO` | Registry for `--check-pkg`: `pypi`, `npm`, `go`, or `crates` |
| `--provider P` | LLM provider (`auto`, `ollama`, `claude-api`, `openai`, `claude-cli`) |
| `--model NAME` | Model name |
| `-o, --output DIR` | Keep files in DIR instead of a tmpdir |
| `-k, --keep` | Keep downloaded/extracted files |
| `--no-color` | Disable color |
| `-v, --verbose` | Show LOW findings and progress |
| `-h, --help`, `--version` | Help / version |

Exit codes: `0` SAFE/CAUTION, `1` DANGEROUS, `2` error. `--strict` makes CAUTION exit `1`.

## Dependency & staged-payload resolution

Named installs are fetched from PyPI, npm, crates.io or the Go module proxy and their real source is scanned; a name that does not exist there is flagged as possible dependency confusion. A pinned version is what gets fetched, so what you scanned is what you are about to install.

sanitycheck walks each dependency's PyPI metadata graph — never building or installing, which would run `setup.py` — and flags malicious, typosquatted, or non-existent transitive deps. This catches `frint → skytext` even when the bad package isn't in your manifest, and on `pip install frint` as well as on a repo that lists it.

On an installer, it extracts the URLs the script downloads, fetches each into a scratch dir (bounded, never executed, skipping cloud-metadata and link-local hosts), and scans those too, following stage-2 to stage-3. A server can serve benign content to a plain fetch and the real payload to `curl|bash`, so a clean result here is not proof of safety.

Capped at ~12s (`SANITYCHECK_RESOLVE_BUDGET`); `--fast`/`--offline`/`--no-follow` turn the network layers off.

## LLM providers

Auto-detected in order; static analysis runs with or without one.

| Provider | Needs | Default model |
|----------|-------|---------------|
| `ollama` | [Ollama](https://ollama.com) installed | `llama3.1` |
| `claude-cli` | [Claude CLI](https://docs.anthropic.com/en/docs/claude-cli) | *(CLI default)* |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `claude-api` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5-20250929` |

Override with `--provider`/`--model` or `SANITYCHECK_PROVIDER`/`SANITYCHECK_MODEL`. The `openai` provider honors `OPENAI_BASE_URL` for any OpenAI-compatible API (LM Studio, vLLM, etc.); `ollama` honors `OLLAMA_HOST`.

## IOC database

`iocs/chocopoc.txt` is a tab-separated file of known-malicious package names, file hashes, env markers, C2 strings, and hosts. Add your own with `--ioc <file>` or `SANITYCHECK_IOCS`.

## Testing

```sh
./test.sh
```

A few seconds, offline and deterministic. Unit tests source individual shell functions; integration tests scan the inert fixtures in `tests/` and assert on verdict, exit code, and which detections fire. Fixtures never execute — dangerous lines are quoted strings or behind a `raise SystemExit`.

`tests/false-positives/` is the other half, and the one that decides whether this is usable: ordinary shapes from real projects — a stdlib `urlretrieve` call, tqdm's Telegram progress bar inside a virtualenv, a Cloudflare deploy hook, a zero-width space in a minified bundle, a Hebrew Qt translation, an embedded `cargo` runner. It has to come back `SAFE`. Together those used to score `DANGEROUS`.

## Limitations

Heuristic and text-based — it reads code, it doesn't sandbox it. A `SAFE` verdict isn't proof of safety and a flagged one isn't proof of malice; read the findings, and run untrusted code in a throwaway VM.

macOS and Linux only. A 450 MB `.app` bundle takes ~15s with `rg` installed, ~45s without — mostly reading framework binaries for IOC strings.

A prebuilt application — an `.app`, an AppImage — is scored differently from a source tree: almost every capability a rule looks for is one a real application plausibly has, so only the patterns no legitimate program has any reason to contain still count toward the verdict. Everything else drops to `LOW`.

## Uninstall

```sh
rm -f ~/.local/bin/sanitycheck
rm -rf ~/.local/share/sanitycheck
```

Then remove the `source "...sanitycheck.zsh"` line from your `.zshrc`.

## License

MIT
