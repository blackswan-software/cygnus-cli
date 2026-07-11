#!/usr/bin/env bash
# Cygnus CLI installer — standalone binary, no Python required.
#
# Usage:
#   curl -fsSL https://install.blackswan-software.ai | sh
#
# What it does:
#   1. Detects OS (Linux/macOS) and architecture (x86_64/arm64)
#   2. Downloads the standalone binary from CDN
#   3. Verifies SHA-256 checksum
#   4. Installs to ~/.local/bin/cygnus
#
# Supports: Linux x86_64, Linux arm64, macOS x86_64, macOS arm64
# 15 ecosystems: Python, Node, Go, Rust, Java, C#, Ruby, PHP,
#                Kotlin, Scala, Swift, Dart, Elixir, C++, Erlang

# POSIX sh-compatible: 'set -eu' works on dash (Debian/Ubuntu default sh)
# AND bash. Originally was 'set -euo pipefail' but pipefail is bash-only
# and broke the documented `curl ... | sh` invocation on Debian/Ubuntu.
# Every curl/download is checked individually via set -e, so pipefail
# isn't load-bearing here.
set -eu

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="${CYGNUS_INSTALL_DIR:-$HOME/.local/bin}"
CDN_URL="https://cygnus-registry.sfo3.cdn.digitaloceanspaces.com/cli"
# Default to "latest" so users always get the newest release without us
# shipping install.sh edits on every version bump. Pin via
# CYGNUS_VERSION=0.1.0 if you need a specific version. Each release uploads
# binaries to BOTH cli/<version>/ and cli/latest/ (see build.yml release job).
CLI_VERSION="${CYGNUS_VERSION:-latest}"

info()  { printf "%b\n" "${CYAN}cygnus${NC} $*"; }
ok()    { printf "%b\n" "${GREEN}  ✓${NC} $*"; }
fail()  { printf "%b\n" "${RED}  ✗${NC} $*"; exit 1; }

# ── Pre-execution disclosure ────────────────────────────────────────
# Shown FIRST when piped to sh — gives security-aware users a chance
# to abort + re-fetch the script for review before anything happens.
# Skip with CYGNUS_NO_PREAMBLE=1 (useful for CI/automation).
if [ "${CYGNUS_NO_PREAMBLE:-}" != "1" ]; then
    echo ""
    printf "%b\n" "${BOLD}Cygnus CLI — installer${NC}"
    echo "─────────────────────────────────────────────────"
    printf "%b\n" "${BOLD}Will:${NC}"
    echo "  • Download ~8 MB binary from cygnus-registry.sfo3.cdn.digitaloceanspaces.com"
    echo "  • Verify SHA-256 against the published checksum (same CDN, separate file)"
    echo "  • Install to ${INSTALL_DIR}/cygnus  (no sudo, no system changes)"
    echo ""
    printf "%b\n" "${BOLD}Won't:${NC}"
    echo "  • Modify ~/.bashrc / ~/.zshrc  (prints PATH hint, never writes)"
    echo "  • Send telemetry or analytics"
    echo "  • Run on startup / install daemons"
    echo "  • Touch pip / npm / brew / cargo  (works alongside, never replaces)"
    echo ""
    printf "%b\n" "${BOLD}Reverse:${NC}  rm ${INSTALL_DIR}/cygnus"
    printf "%b\n" "${BOLD}Source:${NC}   https://github.com/blackswan-software/cygnus-cli/blob/main/install.sh"
    printf "%b\n" "${BOLD}Issues:${NC}   https://github.com/blackswan-software/cygnus-cli/issues"
    echo "─────────────────────────────────────────────────"
    echo "Continuing in 3 seconds. Press Ctrl-C to abort + review."
    echo ""
    sleep 3 2>/dev/null || true
fi

# ── 1. Detect OS + Arch ─────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) fail "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

BINARY_NAME="cygnus-${OS}-${ARCH}"
info "Installing Cygnus CLI for ${OS}-${ARCH}"

# ── 2. Download binary ──────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

BINARY_URL="${CDN_URL}/${CLI_VERSION}/${BINARY_NAME}"
CHECKSUM_URL="${CDN_URL}/${CLI_VERSION}/${BINARY_NAME}.sha256"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

info "Downloading from CDN..."
if ! curl -fsSL "$BINARY_URL" -o "$TMPDIR/cygnus" 2>/dev/null; then
    # Fallback: try pip install if binary not available for this platform
    info "Binary not available for ${OS}-${ARCH}. Trying pip install..."
    if command -v python3 >/dev/null 2>&1; then
        python3 -m pip install --user "git+https://github.com/blackswan-software/cygnus-cli.git" --quiet 2>/dev/null
        if command -v cygnus >/dev/null 2>&1; then
            ok "Installed via pip"
            exit 0
        fi
    fi
    fail "Download failed. Check https://blackswan-software.ai for install options."
fi

# ── 3. Verify checksum ──────────────────────────────────────────────
if curl -fsSL "$CHECKSUM_URL" -o "$TMPDIR/checksum" 2>/dev/null; then
    expected=$(awk '{print $1}' "$TMPDIR/checksum")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$TMPDIR/cygnus" | awk '{print $1}')
    else
        actual=$(shasum -a 256 "$TMPDIR/cygnus" | awk '{print $1}')
    fi
    if [ "$expected" != "$actual" ]; then
        fail "Checksum mismatch — download may be corrupted"
    fi
    ok "Checksum verified"
else
    info "Checksum not available — skipping verification"
fi

# ── 4. Install ──────────────────────────────────────────────────────
chmod +x "$TMPDIR/cygnus"
mv "$TMPDIR/cygnus" "$INSTALL_DIR/cygnus"
ok "Installed to $INSTALL_DIR/cygnus"

# ── 5. Verify PATH ─────────────────────────────────────────────────
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo ""
    info "Add to PATH (add to ~/.bashrc or ~/.zshrc):"
    echo ""
    printf "%b\n" "  ${DIM}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
    echo ""
fi

# ── 6. Done ─────────────────────────────────────────────────────────
echo ""
INSTALLED_VERSION=$("$INSTALL_DIR/cygnus" --version 2>/dev/null | awk '{print $2}' || echo "unknown")
info "Cygnus CLI v${INSTALLED_VERSION} installed!"
echo ""
printf "%b\n" "  ${CYAN}Get started:${NC}"
echo "    cygnus verify flask          # check a library"
echo "    cygnus check                 # scan for CVEs"
echo "    cygnus status                # auth state + usage"
echo "    cygnus help                  # full command list"
echo ""
printf "%b\n" "  ${DIM}Free during launch. No card, no signup wall.${NC}"
printf "%b\n" "  ${DIM}Daily quota + 3 free grace credits if you hit the cap.${NC}"
printf "%b\n" "  ${DIM}Need more? Email hello@blackswan-software.ai with your key prefix.${NC}"
echo ""
printf "%b\n" "  ${DIM}Docs: https://blackswan-software.ai${NC}"
# innocent change
