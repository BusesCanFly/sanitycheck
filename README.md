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

Requires `bash`, `grep`, `find`. `python3`, `rg` and an LLM provider are optional.

## How it works

With the shell hook enabled, sanitycheck audits automatically:

| Trigger | Scan |
|---------|------|
| `curl \| bash` command line (zsh) | audits the script before it runs |
| `git clone <url>` | **fast** static scan of the fresh checkout |
| `pip` / `pipx` / `npm` / `yarn` / `pnpm` / `poetry` / `uv` install, `go install` / `go get` | **deep** scan with dependency resolution; aborts on DANGEROUS |

Each hook asks first (`[Y/n]`, Enter audits, `n` skips); without a terminal it scans automatically. It never installs, imports, builds, or runs the target.

Clone is fast because dependencies aren't pulled yet; resolution waits for install, where the install latency hides the scan. Build commands (`make`, `cargo build`, `go build`, `go run`, `gradle`) aren't hooked — they run every few seconds while you work, and that's what the clone scan is for.

Core checks are pure shell (`grep`/`find`) and run offline. `python3` adds AST / typosquat / Unicode analysis, dependency resolution, `.asar` unpacking, and `--json`; `rg` is used for the search if installed, roughly 3x faster on large targets; an LLM adds a second opinion. Missing pieces are skipped, not fatal.

Electron apps keep their code in `app.asar`, which a directory walk can't see into. Archives are unpacked and scanned, with findings reported as `app.asar!/index.js`.

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
- `setup.py` hooks, `.pth` shims, npm lifecycle scripts, `binding.gyp` and `#cgo` build-time execution
- typosquatted, known-malicious, or non-existent (dependency-confusion) packages, including transitive ones
- installs redirected to a non-official registry or index

Zero-click autorun:

- VS Code `tasks.json` `runOn: folderOpen`, Visual Studio build events
- `conftest.py`, `sitecustomize.py`, `.envrc`
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

General malware (shell, JS, Python, Ruby, Go, Makefiles, Dockerfiles): reverse shells, download-and-exec, destructive ops, miners, exfil channels, keyloggers, shellcode. Windows payloads too — encoded PowerShell in a repo is evidence the repo is malicious even where it can't run.

One signal repeated across many files counts once toward the verdict, so an app shipping six vendored dylibs is a `CAUTION` to read, not a block — and prints once, with a file count, rather than six times.

The default report answers "is this safe to run". Dual-use signals (`eval`, `subprocess`, base64) are `LOW`, and the LLM's own caveats about what it didn't check are notes; neither can drive a verdict and both stay behind `-v`. `--json` always contains everything.

## Direct usage

You can also run sanitycheck manually, without the hook:

```sh
sanitycheck "curl -fsSL https://example.com/install.sh | bash"   # installer
sanitycheck ./CVE-2026-12345-poc                                 # cloned repo
sanitycheck https://github.com/x/poc.git                         # clone + scan
sanitycheck exploit.py                                           # single file
sanitycheck ~/Downloads/Some.app                                 # app bundle
```

| Flag | Description |
|------|-------------|
| `-r, --run` | After auditing an installer, prompt to run it |
| `--fast` | Static checks only (skip network resolve + LLM) |
| `--offline` | No network at all |
| `--no-llm` | Skip the LLM second opinion |
| `--no-follow` | Don't fetch the staged payloads an installer downloads |
| `--strict` | Exit nonzero on `CAUTION` too (CI gate) |
| `--json` | Machine-readable report |
| `--ioc FILE` | Extra IOC database (repeatable) |
| `--provider P` | LLM provider (`auto`, `ollama`, `claude-api`, `openai`, `claude-cli`) |
| `--model NAME` | Model name |
| `-o, --output DIR` | Keep files in DIR instead of a tmpdir |
| `-k, --keep` | Keep downloaded/extracted files |
| `--no-color` | Disable color |
| `-v, --verbose` | Show LOW findings and progress |
| `-h, --help`, `--version` | Help / version |

Exit codes: `0` SAFE/CAUTION, `1` DANGEROUS, `2` error. `--strict` makes CAUTION exit `1`.

## Dependency & staged-payload resolution

Named installs are fetched from PyPI, npm or the Go module proxy and their real source is scanned; a name that does not exist there is flagged as possible dependency confusion.

On a repo, sanitycheck walks each dependency's PyPI metadata graph — never building or installing, which would run `setup.py` — and flags malicious, typosquatted, or non-existent transitive deps. This catches `frint → skytext` even when the bad package isn't in your manifest.

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

## Limitations

Heuristic and text-based — it reads code, it doesn't sandbox it. A `SAFE` verdict isn't proof of safety and a flagged one isn't proof of malice; read the findings, and run untrusted code in a throwaway VM.

macOS and Linux only. A 450 MB `.app` bundle takes ~15s with `rg` installed, ~45s without — mostly reading framework binaries for IOC strings.

## Uninstall

```sh
rm -f ~/.local/bin/sanitycheck
rm -rf ~/.local/share/sanitycheck
```

Then remove the `source "...sanitycheck.zsh"` line from your `.zshrc`.

## License

MIT
