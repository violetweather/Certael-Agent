#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked

if [[ "$(uname -s)" == Linux || "$(uname -s)" == Darwin ]]; then
  sandbox=$(mktemp -d)
  trap 'rm -rf "$sandbox"' EXIT
  package="$sandbox/package"
  prefix="$sandbox/prefix"
  mkdir -p "$package/install"
  cp target/release/certael-agent "$package/certael-agent"
  cp target/release/certael-agent-launcher "$package/certael-agent-launcher"
  cp install/install.sh "$package/install/install.sh"
  cp examples/trust-store.example.json "$sandbox/trust-store.json"
  chmod 0755 "$package/certael-agent" "$package/certael-agent-launcher" \
    "$package/install/install.sh"
  "$package/install/install.sh" --prefix "$prefix" --version 0.0.0-local \
    --trust-store "$sandbox/trust-store.json"
  "$prefix/bin/certael-agent" update-status \
    --install-root "$prefix/lib/certael-agent" >/dev/null
  "$prefix/bin/certael-agent" validate-trust-store \
    --trust-store "$prefix/etc/certael/trust-store.json" >/dev/null
fi

echo "Certael Agent local verification passed."
