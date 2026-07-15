# Certael Agent

Certael Agent is the optional user-mode integrity companion for [Certael](https://github.com/violetweather/Certael). It launches approved game builds, establishes a private inherited channel with the game, and produces nonce-bound, signed integrity reports for the authoritative server.

The Agent is pre-1.0. It has no kernel driver, does not make a client trustworthy, and never authorizes gameplay state. Its evidence is advisory and must be combined with server-authoritative validation.

## Install a prebuilt release

Normal players and game developers do not need Rust or a native compiler.
Extract the archive and run the included installer as an administrator. The
Agent installs once; each game is added with a publisher-signed registration.

```powershell
.\install\install.ps1
```

```bash
sudo ./install/install.sh
```

See [the complete installation guide](docs/INSTALLING.md), including installed
paths, launch commands, upgrades, and uninstall behavior. Verified staged
updates and rollback are documented in [the secure update guide](docs/UPDATES.md).

## Build from source

```bash
cargo test --workspace
cargo run -p certael-agent -- inspect --game /path/to/game
cargo run -p certael-agent -- launch --game /path/to/game \
  --trust-store /path/to/certael-agent-trust.json -- --game-argument
```

Run the complete local format, lint, test, release-build, installer, launcher,
and trust-store smoke suite with `./scripts/verify-local.sh` on macOS or Linux.

For source-only development, the legacy explicit `launch` command accepts one
trust store. Production installs use `register-game` and `launch-game`, which
isolate trust and update roots per game. A trust store pins the game operator's
Ed25519 Agent signing roots. Start from
[`examples/trust-store.example.json`](examples/trust-store.example.json), replace
the example public key and validity window, and install it outside the
game-writable directory. It must not be group- or world-writable on Unix:

```json
{
  "keys": [{
    "key_id": "production-agent-2026-01",
    "public_key_hex": "64 lowercase hexadecimal characters",
    "not_before_unix": 1782864000,
    "not_after_unix": 1814400000,
    "revoked": false
  }]
}
```

The launched game receives a private inherited socket descriptor in `CERTAEL_AGENT_FD` on Unix. Windows receives separate restricted inherited anonymous-pipe handles. These are local process handles, not network listeners.

After `AgentHelloV1`, the game obtains a signed policy, short-lived launch
grant, and signed whole-build manifest from its authoritative server. It sends
all three in `AgentLaunchBundleV1`, relays fresh server challenges, forwards
signed reports, and can relay a signed revocation. Missing trust roots, altered
files, wrong builds, expired state, missed deadlines, changed process identity,
and malformed frames fail closed.

## Privacy boundary

The Agent reports approved build-file hashes, executable identity, its own/game process relationship, loaded image basenames, debugger observation, probe health, and timestamps. It does not collect keystrokes, screenshots, window titles, unrelated processes, network history, raw memory, usernames, email addresses, or full command lines.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
