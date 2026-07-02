#!/usr/bin/env bash
# Build standalone Cygnus CLI binary using PyInstaller.
# Output: dist/cygnus-{os}-{arch} (single file, no Python required)
#
# Usage:
#   bash build.sh           # build for current platform
#
# The CLI is pure Python stdlib — no external deps. PyInstaller bundles
# the Python interpreter + cli.py into a single executable.

set -euo pipefail

CLI_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CLI_DIR"

VERSION=$(python3 -c "from cygnus import __version__; print(__version__)")

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Building Cygnus CLI v${VERSION} for ${OS}-${ARCH}"

if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller..."
    pip install pyinstaller --quiet
fi

rm -rf build dist *.spec

python3 -m PyInstaller \
    --onefile \
    --name "cygnus-${OS}-${ARCH}" \
    --strip \
    --noupx \
    --clean \
    --noconfirm \
    --log-level WARN \
    cygnus/__main__.py

if [ -f "dist/cygnus-${OS}-${ARCH}" ]; then
    cp "dist/cygnus-${OS}-${ARCH}" "dist/cygnus"
    echo "Built: dist/cygnus-${OS}-${ARCH} ($(du -sh dist/cygnus-${OS}-${ARCH} | cut -f1))"

    cd dist
    sha256sum "cygnus-${OS}-${ARCH}" > "cygnus-${OS}-${ARCH}.sha256" 2>/dev/null || \
        shasum -a 256 "cygnus-${OS}-${ARCH}" > "cygnus-${OS}-${ARCH}.sha256"
    echo "Checksum: $(cat cygnus-${OS}-${ARCH}.sha256)"
    cd ..
else
    echo "ERROR: Build failed"
    exit 1
fi

echo ""
echo "Build complete. To install locally:"
echo "  cp dist/cygnus-${OS}-${ARCH} ~/.local/bin/cygnus"
