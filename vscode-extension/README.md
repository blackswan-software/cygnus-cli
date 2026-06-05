# Cygnus VS Code Extension

Inline verification status for library imports across 14 ecosystems.

## Install

The extension ships from the cygnus-cli GitHub release page — no Microsoft
Marketplace or Open VSX account needed.

```sh
# install the CLI (skip if you already have it)
curl -fsSL https://install.blackswan-software.ai | sh

# install the extension into VS Code (also works for cursor, codium)
cygnus extension install vscode
```

The extension reads `~/.cygnus/config.json` on activation, so a one-time
`cygnus auth login` covers both the CLI and the extension. No manual paste
into VS Code settings required.

For a private build, point the installer at a local file:

```sh
cygnus extension install vscode --vsix-file ./cygnus-0.1.0.vsix
```

Or grab a `.vsix` directly from
[the releases page](https://github.com/blackswan-software/cygnus-cli/releases)
and use `code --install-extension <path>`.

## Features

- **Import verification** — green ✓ on verified imports, red ✗ on unverified
- **Auto-compilation** — missing libraries automatically queued for verification
- **Token count** — see how many functions are verified per library
- **Status bar** — `Cygnus: 23/25 ✓` shows project coverage
- **Hover details** — signature, confidence level, signing key
- **Command palette** — verify, search, compose token graphs

## What you see

```python
import requests  # ✓ 176 tokens
import flask     # ✓ 258 tokens
import my_lib    # ✗ unverified — queuing...
```

The missing library is automatically sent for compilation. Within 5 minutes
it appears as verified (if it's a public package).

## Authentication precedence

The extension picks up your API key from, in order:

1. `cygnus.apiKey` VS Code setting (explicit override)
2. `CYGNUS_API_KEY` environment variable
3. `~/.cygnus/config.json` `api_key` field — written by `cygnus auth login`
4. Free tier (no key) — 100 lookups/day

## Supported Ecosystems

Python, Node/TypeScript, Go, Rust, Java, C#, Ruby, PHP, Kotlin, Scala,
Swift, Dart, Elixir, C++

## Commands

| Command | Description |
|---------|-------------|
| `Cygnus: Verify Current File` | Check all imports in active file |
| `Cygnus: Verify Library...` | Manual lookup for any library |
| `Cygnus: Show Function Tokens` | Deep-dive on selected function |
| `Cygnus: Compose Token Graph` | Build verified API chain from description |

## Building from source

```sh
cd vscode-extension
npm install
npm run compile      # tsc → out/
npm test             # @vscode/test-electron, 4 e2e tests
npm run package      # vsce package → cygnus-0.1.0.vsix
```

The release workflow (`.github/workflows/build-vscode-extension.yml`)
runs compile + e2e tests on every PR touching `vscode-extension/**`,
and builds + attaches the `.vsix` to a GitHub Release on tags matching
`vscode-v*`.
