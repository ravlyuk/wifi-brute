#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/common_passwords.yaml"
APP_PKG="$ROOT/WifiConnect.app/Contents/Resources/venv/lib/python3.13/site-packages/wifi_connector/common_passwords.yaml"

if [[ ! -f "$SOURCE" ]]; then
  echo "Missing shared config: $SOURCE" >&2
  exit 1
fi

mkdir -p "$(dirname "$APP_PKG")"
cp "$SOURCE" "$APP_PKG"

echo "Synced common_passwords.yaml to macOS app bundle."
