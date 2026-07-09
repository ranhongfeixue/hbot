#!/bin/sh
set -eu

# Put hbot-linux-amd64 and hbot-linux-arm64 in GitHub Releases.
# You can also override it at runtime:
#   HBOT_BASE_URL=https://github.com/ranhongfeixue/hbot/releases/download/v1.0.0 sh install-hbot.sh
HBOT_BASE_URL="${HBOT_BASE_URL:-https://github.com/ranhongfeixue/hbot/releases/latest/download}"
if [ -z "${HBOT_BIN_DIR:-}" ]; then
  case ":${PATH:-}:" in
    *:/usr/local/bin:*)
      HBOT_BIN_DIR="/usr/local/bin"
      ;;
    *)
      HBOT_BIN_DIR="/usr/bin"
      ;;
  esac
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)
    file="hbot-linux-amd64"
    ;;
  aarch64|arm64)
    file="hbot-linux-arm64"
    ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

url="${HBOT_BASE_URL%/}/$file"
tmp="/tmp/hbot.$$"

echo "Downloading $url"
if command -v curl >/dev/null 2>&1; then
  curl -fL "$url" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$tmp" "$url"
else
  echo "curl or wget is required to download hbot" >&2
  exit 1
fi

chmod 0755 "$tmp"

if [ ! -d "$HBOT_BIN_DIR" ]; then
  mkdir -p "$HBOT_BIN_DIR"
fi

mv "$tmp" "$HBOT_BIN_DIR/hbot"
chmod 0755 "$HBOT_BIN_DIR/hbot"

echo "Installed: $HBOT_BIN_DIR/hbot"
echo "Run: hbot"
