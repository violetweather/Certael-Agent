# Certael Agent

Certael Agent is the optional user-mode integrity companion for [Certael](https://github.com/violetweather/Certael). It launches approved game builds, establishes a private inherited channel with the game, and produces nonce-bound, signed integrity reports for the authoritative server.

The Agent is pre-1.0. It has no kernel driver, does not make a client trustworthy, and never authorizes gameplay state. Its evidence is advisory and must be combined with server-authoritative validation.

## Current developer build

```bash
cargo test --workspace
cargo run -p certael-agent -- inspect --game /path/to/game
cargo run -p certael-agent -- launch --game /path/to/game \
  --trust-store /path/to/certael-agent-trust.json -- --game-argument
```

The trust store pins the game operator's Ed25519 Agent signing roots. It is installed outside the game-writable directory and must not be group- or world-writable on Unix:

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

After `AgentHelloV1`, the game obtains a signed policy and short-lived launch grant from its authoritative server, sends both in `AgentLaunchBundleV1`, relays fresh server challenges, and forwards the Agent's signed reports. Missing trust roots, altered bundles, wrong builds, expired grants, invalid challenges, changed executables, and malformed frames fail closed.

## Privacy boundary

The Agent reports approved build-file hashes, executable identity, its own/game process relationship, loaded image basenames, debugger observation, probe health, and timestamps. It does not collect keystrokes, screenshots, window titles, unrelated processes, network history, raw memory, usernames, email addresses, or full command lines.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
