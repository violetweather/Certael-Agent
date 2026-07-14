#!/usr/bin/env bash
set -euo pipefail

output=${1:?"usage: package-sbom.sh <output.tar.gz>"}
mkdir -p "$(dirname "$output")"

cargo cyclonedx --format json --spec-version 1.5 --target all
sbom_list=$(mktemp)
trap 'rm -f "$sbom_list"' EXIT
find . -path '*/target' -prune -o -type f -name '*.cdx.json' -print0 >"$sbom_list"
if [[ ! -s "$sbom_list" ]]; then
  echo "cargo-cyclonedx produced no *.cdx.json files" >&2
  exit 1
fi

while IFS= read -r -d '' sbom; do
  jq -e '.bomFormat == "CycloneDX" and .metadata.component.name != null' "$sbom" >/dev/null
done <"$sbom_list"

tar --null -czf "$output" --files-from="$sbom_list"
test "$(wc -c <"$output")" -gt 100
tar -tzf "$output" | grep -q '\.cdx\.json$'
