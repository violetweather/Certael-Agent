# Compatibility and required updates

Certael Agent evaluates two independent, signed controls before protected play:

1. Core's short-lived Agent policy states the minimum Agent version for the
   requested game/environment.
2. Certael's offline-signed compatibility manifest records supported,
   deprecated, required-update, withdrawn, unknown, and indeterminate product
   states.

The authoritative Core deployment refuses to mint a new protected launch when
its signed compatibility policy does not allow the component stack. The Agent
independently checks the signed launch policy and the version/ABI declarations
inside the signed whole-build manifest.

## Player-visible states

| Agent state | Meaning | Action |
|---|---|---|
| `update_required` | Installed Agent is below the signed minimum | Wait while the trusted update is checked |
| `updating` | TUF metadata and target are being verified | Do not copy or replace Agent files |
| `update_ready` | Verified immutable version is staged | Close and relaunch to activate |
| `update_failed` | No safe update could be staged | Use **Check trusted update** or run repair as administrator |

For a signed registered game, `launch-game` derives the HTTPS repository,
channel, target platform, update root, and state directory from that
registration. On `agent_update_required`, it automatically verifies and stages
the matching TUF target. It never executes an unverified download and never
overwrites the running process.

The GUI reads live status and offers trusted update, activation, interrupted
update recovery, and last-known-good rollback actions. Its update action uses
the platform's administrator approval UI for a system-wide installation; the
registration ID is passed as a separate bounded argument. Offline games and modes
whose server policy disables Agent remain available without this flow.

## Operator check

The Agent CLI can independently verify the Core-compatible binary manifest:

```bash
certael-agent compatibility-check \
  --manifest compatibility.pb \
  --trust-store compatibility-trust-store.json \
  --product agent --version 0.3.0-alpha.1 --protocol 1
```

The compatibility key is a dedicated offline release key. A game publisher's
Agent policy key, per-game trust store, and TUF root do not replace it.

## Breaking change in 0.3 alpha

Whole-build manifests now contain the Core SDK version, engine adapter and
version, Core C ABI, action protocol, Agent protocol, and probe ABI. Earlier
alpha Agents drop those fields during Protobuf decoding, causing canonical
encoding verification to fail safely. Upgrade Core and Agent together,
regenerate the protected build manifest, and start a fresh Agent session.
