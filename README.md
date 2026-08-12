# sanitycheck README

⚠️🚨 This is entirely vibe code slop, but it was useful so I wanted to share 🥀 🚨⚠️

## sanitycheck

Audit untrusted code before you run it. Scans `curl | bash` installers, cloned repos and their dependencies, pip/npm/etc. installs, and single scripts, then gives a `SAFE` / `CAUTION` / `DANGEROUS` verdict — without ever running, installing, importing, or building what it checks. Shell hooks catch the commands; anything not flagged runs as normal.

<p align="center">
  <img src="demo.svg" alt="sanitycheck auditing a git clone, a pip install, a curl|bash installer, and direct usage" width="720">
</p>

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/BusesCanFly/sanitycheck/main/install.sh | bash
```

(lol)

Or clone and run `./install.sh`. It adds the hook to your `.zshrc`/`.bashrc` and installs the deep-pass helper and IOC database.

Requires `bash`, `grep`, `find`. Optional, skipped if missing: `python3` (AST / typosquat / Unicode analysis, dependency resolution, `.asar`, `--json`), `rg` (~3× faster search), `unsquashfs` (AppImages), an LLM provider (second opinion).

## Hook

Enabled by the installer, or:

```sh
echo 'source ~/.local/share/sanitycheck/hooks/sanitycheck.zsh' >> ~/.zshrc  # or .bashrc
```

Commands are audited automatically. Each asks first (`[Y/n]`, Enter audits); without a terminal it scans anyway.

| Trigger | Scan |
|---------|------|
| `curl \| bash` command (zsh) | the script, before it runs |
| `git clone <url>` | fast static scan of the checkout |
| `pip` / `pipx` / `npm` / `yarn` / `pnpm` / `poetry` / `uv` install, `go install` / `get`, `cargo install` / `add`, `gem` / `bundle install` | deep scan + dependency resolution; aborts on DANGEROUS |

Clone is fast because deps aren't pulled yet; resolution waits for install. Build commands (`make`, `cargo build`, `go build`, `go run`) aren't hooked — the clone scan covers them. `cargo install` is, because it compiles (and runs `build.rs`) as it fetches.

- `SANITYCHECK_HOOK=0 <cmd>` — bypass once (or `command git/pip/...`)
- `SANITYCHECK_HOOK_STRICT=1` — hard-abort on DANGEROUS, no prompt
- `SANITYCHECK_HOOK_FAST=1` — instant, offline scans

## Usage

```sh
sanitycheck "curl -fsSL https://example.com/install.sh | bash"   # installer
sanitycheck ./poc                                                # repo or directory
sanitycheck https://github.com/x/poc.git                         # clone + scan
sanitycheck exploit.py                                           # single file
sanitycheck ~/Downloads/Some.app                                 # .app / AppImage / .pkg / .dmg
```

Output is the verdict and one line on what it would do; `-v` adds every finding with locations, `--json` has everything.

```
== sanitycheck (repo) ==  ./CVE-2026-12345-poc
[!] DANGEROUS - execution not advised
    matches known malware, gives a remote host control, steals credentials and keys (+5 more)
    104 findings in 39 files
```

| Flag | Description |
|------|-------------|
| `-r, --run` | Prompt to run an installer after auditing (the audited bytes, not a re-fetch; keeps any `sudo`/args) |
| `--fast` | Static checks only (skip network resolve + LLM) |
| `--offline` | No network at all |
| `--no-llm` | Skip the LLM second opinion |
| `--no-follow` | Don't fetch the staged payloads an installer downloads |
| `--strict` | Exit nonzero on `CAUTION` too (CI gate) |
| `--json` | Machine-readable report |
| `--ioc FILE` | Extra IOC database (repeatable) |
| `--check-pkg NAME...` | Vet package name(s) against IOCs and typosquats; when online, fetch and scan their real contents |
| `--ecosystem ECO` | Registry for `--check-pkg`: `pypi`, `npm`, `go`, `crates` |
| `--provider P` | LLM provider (`auto`, `ollama`, `claude-api`, `openai`, `claude-cli`) |
| `--model NAME` | Model name |
| `-o, --output DIR` | Keep files in DIR instead of a tmpdir |
| `-k, --keep` | Keep downloaded/extracted files |
| `--no-color` | Disable color |
| `-v, --verbose` | Show LOW findings and progress |
| `-h, --help`, `--version` | Help / version |

Exit codes: `0` SAFE/CAUTION, `1` DANGEROUS, `2` error. `--strict` makes CAUTION exit `1`.

## What it catches

Malicious behaviour, not weak configuration.

- **Supply chain** — typosquatted / known-malicious / non-existent (dependency-confusion) packages, including transitive ones and Go path near-misses; installs redirected to an unofficial registry; version specs that are URLs; install/build-time execution (`setup.py`, `.pth`, npm lifecycle scripts, `binding.gyp`, `#cgo`, `build.rs`, `go.mod` toolchain); compiled `.so`/`.pyd`/`.node` shadowing a same-named module; IOC hashes.
- **Autorun** — editor, devcontainer, and `.git`-config hooks that fire on folder-open or ordinary git commands; `conftest.py` / `sitecustomize.py` / `.envrc`; `.cargo/config.toml` runners.
- **Hidden code** — `eval`/`exec` fed from `fetch` or base64, nested / reversed encodings; DoH/SNI-fronted C2 and tunnels (ngrok, trycloudflare); Trojan-Source Unicode; prompt injection aimed at an AI reviewer.
- **Theft & persistence** — SSH keys, cloud/CI tokens, keychain, wallets, password / AI-tool credentials; LaunchAgents, systemd units, cron, `authorized_keys`; Gatekeeper/SIP tampering, quarantine stripping.
- **General malware** across shell, JS, Python, Ruby, Go, Makefiles, Dockerfiles, notebooks — reverse shells, download-and-exec, miners, keyloggers, shellcode, encoded PowerShell.

Named installs are fetched (never built) and their real source scanned; the transitive dependency graph is walked too, catching a bad package your manifest never named. On an installer, the URLs it would download are fetched into a scratch dir and scanned, stage by stage — a server can still serve a plain fetch something different, so a clean result isn't proof. Network layers cap at ~12s and are off under `--fast`/`--offline`/`--no-follow`.

Opaque single-file apps (Electron `.asar`, AppImage, `.pkg`, `.dmg`) are unpacked without executing them, findings reported against the container (`app.asar!/index.js`). AppImages are read via `unsquashfs` at the ELF offset, never `--appimage-extract` — that flag would run the untrusted binary. A prebuilt app is scored more leniently than source: capabilities any real program plausibly has drop to `LOW`, so only patterns with no legitimate reason to exist still count.

## LLM providers

Auto-detected in order; static analysis runs with or without one.

| Provider | Needs | Default model |
|----------|-------|---------------|
| `ollama` | [Ollama](https://ollama.com) installed | `llama3.1` |
| `claude-cli` | [Claude CLI](https://docs.anthropic.com/en/docs/claude-cli) | *(CLI default)* |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `claude-api` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5-20250929` |

Override with `--provider`/`--model` or `SANITYCHECK_PROVIDER`/`SANITYCHECK_MODEL`. `openai` honors `OPENAI_BASE_URL` (LM Studio, vLLM, …); `ollama` honors `OLLAMA_HOST`.

## Notes

- `./test.sh` — offline, deterministic. `tests/false-positives/` is the guard: ordinary shapes from real projects that must come back `SAFE`.
- IOCs live in `iocs/chocopoc.txt` (packages, hashes, env markers, C2 strings, hosts); add your own with `--ioc <file>` or `SANITYCHECK_IOCS`.
- Heuristic and text-based — it reads code, it doesn't sandbox it. A `SAFE` verdict isn't proof of safety; run untrusted code in a throwaway VM. macOS and Linux only.

## Uninstall

```sh
rm -f ~/.local/bin/sanitycheck
rm -rf ~/.local/share/sanitycheck
```

Then remove the `source "...sanitycheck.zsh"` line from your `.zshrc`.

## License

MIT
