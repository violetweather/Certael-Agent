#!/usr/bin/env bash
set -euo pipefail
prefix=/usr/local
purge=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:-}"; shift 2 ;;
    --purge) purge=true; shift ;;
    *) echo "Usage: sudo ./uninstall.sh [--prefix /usr/local] [--purge]" >&2; exit 2 ;;
  esac
done
rm -f "$prefix/bin/certael-agent" "$prefix/lib/certael-agent/certael-agent-launcher" \
  "$prefix/lib/certael-agent/activation.json"
rm -rf "$prefix/lib/certael-agent/versions"
if [[ "$purge" == true ]]; then rm -rf "${CERTAEL_CONFIG_DIR:-$prefix/etc/certael}"; fi
echo "Removed Certael Agent binaries. Public trust configuration was $([[ "$purge" == true ]] && echo removed || echo preserved)."
