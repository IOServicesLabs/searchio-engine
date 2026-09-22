#!/usr/bin/env sh
# Install the se-serve engine binary to ~/.searchio/bin (where the searchio
# package discovers it). Usage:
#   curl -fsSL https://raw.githubusercontent.com/IOServicesLabs/searchio-engine/main/scripts/install.sh | sh
# Env overrides: VERSION (default: latest release), INSTALL_DIR,
#                GITHUB_TOKEN (required while the repo is private: the release
#                API and the asset URLs 404 anonymously).
set -eu

REPO="IOServicesLabs/searchio-engine"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.searchio/bin}"

if [ "${VERSION:-}" = "" ]; then
  api="https://api.github.com/repos/$REPO/releases/latest"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    VERSION=$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$api" \
      | grep tag_name | head -1 | cut -d '"' -f 4)
  else
    VERSION=$(curl -fsSL "$api" \
      | grep tag_name | head -1 | cut -d '"' -f 4)
  fi
fi
[ -n "$VERSION" ] || { echo "install.sh: could not resolve latest release" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  target="x86_64-unknown-linux-gnu";  ext="tar.gz"; bin="se-serve" ;;
  Linux-aarch64) target="aarch64-unknown-linux-gnu"; ext="tar.gz"; bin="se-serve" ;;
  Darwin-arm64)  target="aarch64-apple-darwin";      ext="tar.gz"; bin="se-serve" ;;
  Darwin-x86_64) target="x86_64-apple-darwin";       ext="tar.gz"; bin="se-serve" ;;
  # Git Bash / MSYS2 / Cygwin on 64-bit Windows. (WSL reports Linux-* and
  # takes the glibc build above.)
  MINGW64_NT-*-x86_64|MSYS_NT-*-x86_64|CYGWIN_NT-*-x86_64)
                 target="x86_64-pc-windows-msvc";    ext="zip";    bin="se-serve.exe" ;;
  *) echo "install.sh: no prebuilt binary for $(uname -s)-$(uname -m); build from source:" >&2
     echo "  git clone https://github.com/$REPO && cd searchio-engine && cargo build --release" >&2
     exit 1 ;;
esac

archive="se-serve-${VERSION}-${target}.${ext}"
url="https://github.com/$REPO/releases/download/${VERSION}/${archive}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $url"
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$url" -o "$tmp/$archive"
else
  curl -fsSL "$url" -o "$tmp/$archive"
fi
if [ "$ext" = "zip" ]; then
  unzip -q -o "$tmp/$archive" -d "$tmp"
else
  tar xzf "$tmp/$archive" -C "$tmp"
fi

mkdir -p "$INSTALL_DIR"
cp "$tmp/se-serve-${VERSION}-${target}/$bin" "$INSTALL_DIR/$bin"
chmod +x "$INSTALL_DIR/$bin" 2>/dev/null || true
echo "se-serve $VERSION installed to $INSTALL_DIR/$bin"
echo "The searchio package picks it up automatically (engine tier)."
