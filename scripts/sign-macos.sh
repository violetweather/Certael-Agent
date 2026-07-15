#!/usr/bin/env bash
set -euo pipefail
: "${MACOS_CERTIFICATE_BASE64:?Stable macOS releases require a Developer ID certificate}"
: "${MACOS_CERTIFICATE_PASSWORD:?Missing macOS certificate password}"
: "${MACOS_KEYCHAIN_PASSWORD:?Missing temporary keychain password}"
: "${MACOS_APPLICATION_IDENTITY:?Missing Developer ID Application identity}"

certificate="$RUNNER_TEMP/certael-developer-id.p12"
keychain="$RUNNER_TEMP/certael-signing.keychain-db"
printf '%s' "$MACOS_CERTIFICATE_BASE64" | base64 --decode > "$certificate"
security create-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$keychain"
trap 'security delete-keychain "$keychain" >/dev/null 2>&1 || true; rm -f "$certificate"' EXIT
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$keychain"
security import "$certificate" -k "$keychain" -P "$MACOS_CERTIFICATE_PASSWORD" -A -t cert -f pkcs12
security set-key-partition-list -S apple-tool:,apple: -s -k "$MACOS_KEYCHAIN_PASSWORD" "$keychain"
security list-keychains -d user -s "$keychain"

for file in "$@"; do
  codesign --force --timestamp --options runtime --sign "$MACOS_APPLICATION_IDENTITY" "$file"
  codesign --verify --strict --verbose=2 "$file"
done
