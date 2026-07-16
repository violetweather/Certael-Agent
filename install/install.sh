#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo ./install.sh [--prefix /usr/local] [--version 0.3.0-alpha.1] [--registration FILE --publisher-trust-store FILE --update-root FILE --game-root DIR]" >&2
}

replace_link() {
  local source=$1 destination=$2
  if [[ "$(uname -s)" == Darwin ]]; then mv -fh "$source" "$destination"
  else mv -Tf "$source" "$destination"
  fi
}

prefix=/usr/local
version=0.3.0-alpha.1
registration= publisher_trust_store= update_root= game_root=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --registration) registration="${2:-}"; shift 2 ;;
    --publisher-trust-store) publisher_trust_store="${2:-}"; shift 2 ;;
    --update-root) update_root="${2:-}"; shift 2 ;;
    --game-root) game_root="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

provided=0
for value in "$registration" "$publisher_trust_store" "$update_root" "$game_root"; do
  [[ -n "$value" ]] && provided=$((provided + 1))
done
if [[ $provided -ne 0 && $provided -ne 4 ]]; then
  echo "Registration, publisher trust store, update root, and game root must be supplied together." >&2
  exit 2
fi
if [[ $provided -eq 4 ]]; then
  for file in "$registration" "$publisher_trust_store" "$update_root"; do
    [[ -f "$file" && ! -L "$file" ]] || { echo "$file must be a regular, non-symlink file." >&2; exit 2; }
  done
  [[ -d "$game_root" && ! -L "$game_root" ]] || { echo "Game root must be a non-symlink directory." >&2; exit 2; }
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

base="$prefix/lib/certael-agent"
destination="$base/versions/$version"
binary_dir="$prefix/bin"
umask 022
mkdir -p "$base/versions" "$binary_dir"
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

launcher_new="$base/.certael-agent-launcher.$$"
install -m 0755 "$source_dir/certael-agent-launcher" "$launcher_new"
replace_link "$launcher_new" "$base/certael-agent-launcher"
command_link="$binary_dir/.certael-agent.$$"
ln -s "$base/certael-agent-launcher" "$command_link"
replace_link "$command_link" "$binary_dir/certael-agent"

if [[ $provided -eq 4 ]]; then
  "$binary_dir/certael-agent" register-game --registration "$registration" \
    --publisher-trust-store "$publisher_trust_store" --update-root "$update_root" \
    --game-root "$game_root"
fi

echo "Installed Certael Agent $version."
echo "Launcher: $binary_dir/certael-agent"
