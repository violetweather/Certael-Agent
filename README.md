# Certael Agent

Certael Agent is the optional user-mode integrity companion for [Certael](https://github.com/violetweather/Certael). It launches approved game builds, establishes a private inherited channel with the game, and produces nonce-bound, signed integrity reports for the authoritative server.

The Agent is pre-1.0. It has no kernel driver, does not make a client trustworthy, and never authorizes gameplay state. Its evidence is advisory and must be combined with server-authoritative validation.

## Current developer build

```bash
cargo test --workspace
cargo run -p certael-agent -- inspect --game /path/to/game
cargo run -p certael-agent -- launch --game /path/to/game -- --game-argument
```

The launched game receives a private inherited channel descriptor in `CERTAEL_AGENT_FD` on Unix. Windows uses the same protocol over a restricted inherited named-pipe handle in release builds.

## Privacy boundary

The Agent reports approved build-file hashes, executable identity, its own/game process relationship, loaded image basenames, debugger observation, probe health, and timestamps. It does not collect keystrokes, screenshots, window titles, unrelated processes, network history, raw memory, usernames, email addresses, or full command lines.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

