# Cygnus CLI

Verified function signatures for every library in your stack. Pre-compiled, signed, graded.

```
$ cygnus verify flask
  ✓ flask@3.1.0 — FULLY_VERIFIED (47 functions, signed)
```

[![Cygnus](https://blackswan-software.ai/badge/python/flask)](https://blackswan-software.ai)

---

## Use in GitHub Actions

Add four lines to your workflow to verify your dependencies on every CI run:

```yaml
- uses: blackswan-software/cygnus-cli/.github/actions/verify@v0.1.2
  with:
    ecosystem: npm   # or python, ruby, go, java, csharp, rust, etc. (omit to auto-detect)
```

Fails the build on `SECURITY_ISSUE_DETECTED`. Pulls the CLI from the public CDN, verifies its SHA-256 against the published checksum, then runs `cygnus verify --ci` against your lockfile. No auth required for the free tier.

Pin to `@latest` for rolling updates, or pin to a specific tag (`@v0.1.2`) for reproducible runs.

Full action spec: [`.github/actions/verify/action.yml`](.github/actions/verify/action.yml).

---

## Install

Pick one. All three install the same binary; they differ in how much you trust the install path.

### 1. Quick (one-liner)

**macOS / Linux:**
```bash
curl -fsSL https://install.blackswan-software.ai | sh
```

**Windows (PowerShell):**
```powershell
irm https://install.blackswan-software.ai/win | iex
```

The script prints a preamble before doing anything — what it'll do, what it won't, how to reverse it, and a 3-second abort window.

### 2. Review first (recommended for security-aware setups)

```bash
curl -fsSL https://install.blackswan-software.ai > install.sh
less install.sh        # ~140 lines of bash, read it
sh install.sh
```

The install script is plain bash with no obfuscation. [View on GitHub](https://github.com/blackswan-software/cygnus-cli/blob/master/install.sh).

### 3. Direct binary download

Same binaries the script downloads. Verify SHA-256 before running.

| Platform | Binary | Checksum |
|---|---|---|
| Linux x86_64 | [cygnus-linux-x86_64](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-linux-x86_64) | [.sha256](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-linux-x86_64.sha256) |
| Linux arm64 | [cygnus-linux-arm64](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-linux-arm64) | [.sha256](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-linux-arm64.sha256) |
| macOS Apple Silicon | [cygnus-darwin-arm64](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-darwin-arm64) | [.sha256](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-darwin-arm64.sha256) |
| Windows x86_64 | [cygnus-windows-x86_64.exe](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-windows-x86_64.exe) | [.sha256](https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli/latest/cygnus-windows-x86_64.exe.sha256) |

Pin a specific version by swapping `latest` for `0.2.1`, etc. in the URL.

Then:

```bash
chmod +x cygnus-linux-x86_64
mv cygnus-linux-x86_64 ~/.local/bin/cygnus
cygnus verify flask
```

### 4. Build from source

Cygnus CLI is MIT-licensed Python. Build locally if you want a custom build:

```bash
git clone https://github.com/blackswan-software/cygnus-cli
cd cygnus-cli
pip install -e .
```

---

## What the install does

- Downloads ~8 MB binary from `cygnus-registry.sfo3.cdn.digitaloceanspaces.com`
- Verifies SHA-256 against the published checksum
- Installs to `~/.local/bin/cygnus` (no `sudo`, no system changes)
- Does NOT modify `~/.bashrc`, `~/.zshrc`, or any shell startup file (prints PATH hint instead)
- Sends no telemetry. Runs nothing on startup. Installs no daemons.
- Works alongside pip / npm / cargo / brew — never replaces or modifies your package managers.

To uninstall: `rm ~/.local/bin/cygnus`

---

## Usage

5 commands. Auth happens inline — first command that needs it prompts for your email.

```bash
# Verify one library
cygnus verify flask
  ✓ flask@3.1.0 — FULLY_VERIFIED (47 functions, signed)

# Verify all project dependencies (auto-detects lockfile)
cygnus verify
  47/50 deps verified. 3 not in corpus — queued.

# CVE scan (free, no account needed)
cygnus check

# Download pre-compiled, verified artifact
cygnus add flask

# Request verification for a library
cygnus request spdlog

# Auth state, tier, balance, usage
cygnus status
```

Full command reference: `cygnus help`

---

## Supported Ecosystems

Python, Node.js, Go, Rust, Java, C#, Ruby, PHP, Kotlin, Scala, Swift, Dart, Elixir, C++.

---

## Pricing

Free during launch. Daily quota + grace credits if you hit the cap. [Details](https://blackswan-software.ai).

---

## Trust

Cygnus is the certificate authority for software libraries. The same standard applies to the CLI itself:

- All releases are built reproducibly via [GitHub Actions](https://github.com/blackswan-software/cygnus-cli/actions) from this repo.
- Every binary has a published SHA-256 checksum (verified by the install script).
- Source-from-Git path is always supported.
- Security disclosures: [security.txt](https://blackswan-software.ai/.well-known/security.txt).

---

## Legal

- [Terms of Service](https://blackswan-software.ai/terms)
- [Privacy Policy](https://blackswan-software.ai/privacy)
- [Data Processing Addendum](https://blackswan-software.ai/dpa)

---

## Issues

[github.com/blackswan-software/cygnus-cli/issues](https://github.com/blackswan-software/cygnus-cli/issues)

Or from inside the CLI: `cygnus issue`

---

## License

MIT. See [LICENSE](LICENSE).
