# Cygnus CLI

Verified function signatures for every library. Pre-compiled, signed, graded.

## Install

```bash
curl -fsSL https://install.blackswan-software.ai | sh
```

No Python required — standalone binary for Linux and macOS.

## Usage

```bash
# Verify a library
cygnus verify flask
  ✓ flask@3.1.0 — FULLY_VERIFIED (47 functions, signed)

# Scan all project dependencies
cygnus verify
  47/50 deps verified. 3 not in corpus — queued.

# Check for CVEs
cygnus check

# Generate CycloneDX SBOM
cygnus sbom -o sbom.json

# Download signed artifact
cygnus install flask
```

## Supported Ecosystems

Python, Node.js, Go, Rust, Java, C#, Ruby, PHP, Kotlin, Scala, Swift, Dart, Elixir, C++, Erlang

## Pricing

- **Free:** Grade + CVE for the daily quota. No payment required.
- **Verified:** see pricing page. Pay-as-you-go, balance never expires.
- **Enterprise:** platform fee. Attestations, audit docs, priority support.

[blackswan-software.ai](https://blackswan-software.ai)

## License

MIT
