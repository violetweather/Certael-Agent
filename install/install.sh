#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo ./install.sh --trust-store /path/to/trust-store.json [--prefix /usr/local] [--version 0.1.0]" >&2
}

replace_link() {
  local source=$1 destination=$2
  if [[ "$(uname -s)" == Darwin ]]; then mv -fh "$source" "$destination"
  else mv -Tf "$source" "$destination"
  fi
}

prefix=/usr/local
version=0.1.0
trust_store=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --trust-store) trust_store="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z "$trust_store" || -L "$trust_store" || ! -f "$trust_store" ]]; then
  echo "A regular, non-symlink public trust-store file is required." >&2
  exit 2
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "The install version is invalid." >&2
  exit 2
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -x "$source_dir/certael-agent" ]]; then
  echo "certael-agent is missing from the extracted release directory." >&2
  exit 1
fi
if [[ ! -x "$source_dir/certael-agent-launcher" ]]; then
  echo "certael-agent-launcher is missing from the extracted release directory." >&2
  exit 1
fi
"$source_dir/certael-agent" validate-trust-store --trust-store "$trust_store" >/dev/null

base="$prefix/lib/certael-agent"
destination="$base/versions/$version"
configuration="${CERTAEL_CONFIG_DIR:-$prefix/etc/certael}"
binary_dir="$prefix/bin"
umask 022
mkdir -p "$base/versions" "$configuration" "$binary_dir"
temporary="$(mktemp -d "$base/versions/.install.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

install -m 0755 "$source_dir/certael-agent" "$temporary/certael-agent"
for file in libcertael_agent_probe.so libcertael_agent_probe.dylib \
  certael_agent_probe.h compatibility-v1.json LICENSE README.md; do
  if [[ -f "$source_dir/$file" ]]; then install -m 0644 "$source_dir/$file" "$temporary/$file"; fi
done
"$temporary/certael-agent" --help >/dev/null

if [[ -e "$destination" ]]; then
  echo "Certael Agent $version is already installed." >&2
  exit 1
fi
mv "$temporary" "$destination"
trap - EXIT
"$destination/certael-agent" register-installed-version \
  --install-root "$base" --version "$version" --installed-name certael-agent --activate
install -m 0644 "$trust_store" "$configuration/trust-store.json.new"
mv -f "$configuration/trust-store.json.new" "$configuration/trust-store.json"

launcher_new="$base/.certael-agent-launcher.$$"
install -m 0755 "$source_dir/certael-agent-launcher" "$launcher_new"
replace_link "$launcher_new" "$base/certael-agent-launcher"
command_link="$binary_dir/.certael-agent.$$"
ln -s "$base/certael-agent-launcher" "$command_link"
replace_link "$command_link" "$binary_dir/certael-agent"

echo "Installed Certael Agent $version."
echo "Public trust store: $configuration/trust-store.json"
echo "Launcher: $binary_dir/certael-agent"
