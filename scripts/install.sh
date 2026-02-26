#!/bin/sh
# ShellGate Installer
# Usage: curl -sL https://raw.githubusercontent.com/cc1a2b/shellgate/main/scripts/install.sh | bash
set -e

REPO="cc1a2b/shellgate"
BINARY="shellgate"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Detected: ${OS}/${ARCH}"

# Get latest release tag
echo "Fetching latest release..."
LATEST=$(curl -sI "https://github.com/${REPO}/releases/latest" | grep -i "^location:" | sed 's#.*/tag/##' | tr -d '\r\n')

if [ -z "$LATEST" ]; then
    echo "Error: Could not determine latest release"
    exit 1
fi

echo "Latest version: ${LATEST}"

# Download
ARCHIVE="${BINARY}_${LATEST#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${URL}..."
curl -sL "$URL" -o "${TMPDIR}/${ARCHIVE}"
curl -sL "$CHECKSUM_URL" -o "${TMPDIR}/checksums.txt"

# Verify checksum
echo "Verifying checksum..."
cd "$TMPDIR"
EXPECTED=$(grep "$ARCHIVE" checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum "$ARCHIVE" | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Checksum verification failed!"
    echo "  Expected: $EXPECTED"
    echo "  Got:      $ACTUAL"
    exit 1
fi

echo "Checksum verified."

# Extract
tar xzf "$ARCHIVE"

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY" "${INSTALL_DIR}/${BINARY}"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$BINARY" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "ShellGate ${LATEST} installed successfully!"
echo "  Binary: ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Quick start:"
echo "  shellgate                     # Start with auto-generated token"
echo "  shellgate --auth password     # Start with password auth"
echo "  shellgate --tls               # Start with self-signed TLS"
