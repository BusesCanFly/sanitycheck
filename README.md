⚠️🚨 This is entirely vibe code slop, but it was useful so I wanted to share 🥀 🚨⚠️
# sanitycheck

Audit `curl | bash` type installers before running them

## How it works

With the zsh hook enabled, sanitycheck automatically intercepts `curl | bash`-like commands when you press enter, downloads the script, sends it to an LLM for analysis, and gives you a verdict:

<p align="center">
  <img src="demo.svg" alt="sanitycheck demo showing SAFE, CAUTION, and DANGEROUS verdicts" width="680">
</p>

The hook catches common patterns like:

- `curl ... | bash`, `curl ... | sh`, `curl ... | sudo bash`
- `wget ... | bash`, `wget ... | sh`, `wget ... | sudo sh`
- `bash -c "$(curl ...)"`, `sh -c "$(wget ...)"`
- `bash <(curl ...)`, `sh <(wget ...)`
- `source <(curl ...)`, `. <(wget ...)`

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/BusesCanFly/sanitycheck/main/install.sh | bash
```

> lol

Or clone and run locally:

```sh
git clone https://github.com/BusesCanFly/sanitycheck.git
cd sanitycheck
./install.sh
```

The installer will offer to add the zsh hook and PATH entry to your `.zshrc` automatically.

Requires: `bash`, `curl`, and an LLM provider (see below).

## Direct usage

You can also run sanitycheck manually without the hook:

```sh
sanitycheck https://example.com/install.sh                       # bare URL
sanitycheck "curl -fsSL https://example.com/install.sh | bash"   # paste the command you were about to run
sanitycheck -r "wget -qO- https://example.com/setup.sh | sh"     # audit, then prompt to run
sanitycheck -k https://example.com/install.sh                    # keep script + report
```

| Flag | Description |
|------|-------------|
| `-r, --run` | Prompt to run the script after audit |
| `-k, --keep` | Keep downloaded script and report |
| `-o, --output DIR` | Save files to DIR instead of a tmpdir |
| `-p, --provider P` | LLM provider (`auto`, `ollama`, `claude-api`, `openai`, `claude-cli`) |
| `-m, --model NAME` | Model name (default depends on provider) |
| `-h, --help` | Show help |

## LLM providers

sanitycheck auto-detects the first available provider in this order:

| Provider | Needs | Default model |
|----------|-------|---------------|
| `ollama` | [Ollama](https://ollama.com) installed | `llama3.1` |
| `claude-cli` | [Claude CLI](https://docs.anthropic.com/en/docs/claude-cli) | *(CLI default)* |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` |
| `claude-api` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5-20250929` |

Override with `--provider` / `--model` flags or env vars:

```sh
export SANITYCHECK_PROVIDER=ollama
export SANITYCHECK_MODEL=llama3.1
```

The `openai` provider also supports `OPENAI_BASE_URL` for any OpenAI-compatible API (LM Studio, vLLM, etc.).

## Uninstall

```sh
rm -f ~/.local/bin/sanitycheck
rm -rf ~/.local/share/sanitycheck
```

Then remove the `source "...sanitycheck.zsh"` line from your `.zshrc`.

## License

MIT
