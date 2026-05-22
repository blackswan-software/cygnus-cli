#!/usr/bin/env bash
# Build standalone Cygnus CLI binary using PyInstaller.
# Output: dist/cygnus (single file, no Python required)
#
# Usage:
#   bash cli/build.sh                    # build for current platform
#   bash cli/build.sh --all              # build linux + mac (needs Docker for cross-compile)
#
# The CLI is pure Python stdlib — no external deps. PyInstaller bundles
# the Python interpreter + cli.py into a single executable.
#
# After build:
#   1. Test locally: ./dist/cygnus --help
#   2. Upload + publish: see private deploy docs

set -euo pipefail

CLI_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CLI_DIR"

VERSION=$(python3 -c "
import re
text = open('pyproject.toml').read()
m = re.search(r'version = \"([^\"]+)\"', text)
print(m.group(1) if m else '0.1.0')
")

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Building Cygnus CLI v${VERSION} for ${OS}-${ARCH}"

# Ensure PyInstaller is installed
if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller..."
    pip install pyinstaller --quiet
fi

# Clean previous builds
rm -rf build dist *.spec

# Build single-file executable
# --onefile: single binary (slower startup but clean install)
# --name: output binary name
# --strip: strip debug symbols (smaller binary)
# --noupx: skip UPX compression (more compatible)
# --hidden-import: none needed (pure stdlib)
python3 -m PyInstaller \
    --onefile \
    --name "cygnus-${OS}-${ARCH}" \
    --strip \
    --noupx \
    --clean \
    --noconfirm \
    --log-level WARN \
    cygnus/__main__.py

# Also create a generic name symlink
if [ -f "dist/cygnus-${OS}-${ARCH}" ]; then
    cp "dist/cygnus-${OS}-${ARCH}" "dist/cygnus"
    echo "Built: dist/cygnus-${OS}-${ARCH} ($(du -sh dist/cygnus-${OS}-${ARCH} | cut -f1))"

    # Generate checksum
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
echo ""
echo "To upload to CDN, see the private deploy docs."
