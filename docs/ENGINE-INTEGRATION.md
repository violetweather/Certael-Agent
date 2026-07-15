# Engine integration

Games should normally be started by Certael Agent. On Unix, the Agent passes an inherited socket descriptor through `CERTAEL_AGENT_FD`; the descriptor is not a network listener. Windows passes separate read/write anonymous-pipe handles and restricts child inheritance to only those handles.

The engine adapter must:

1. Connect only to the inherited channel.
2. Reject messages over 64 KiB and unsupported protocol versions.
3. Send the signed policy, server-issued launch grant, and signed whole-build manifest together as a canonical `AgentLaunchBundleV1`.
4. Never provide a signing root over this channel; trusted public keys come from the separately installed Agent trust store.
5. Relay fresh server nonce challenges and forward only complete signed reports.
6. Consume health heartbeats and surface `ready`, `protected`, `degraded`, `expired`, `revoked`, `lost`, and `update_required` states.
7. Relay Core's signed revocation during match exit, account switch, server migration, or logout.
8. Send an empty typed shutdown frame during ordinary process exit.

The stable probe C ABI exposes `certael_agent_channel_open`,
`certael_agent_channel_read`, `certael_agent_channel_write`, and
`certael_agent_channel_destroy`. A buffer-too-small
read reports the required length without consuming the pending frame. Every other
language binding must preserve this ownership and retry behavior.

The expected exchange is:

```text
Agent -> game: AgentHelloV1
game -> Agent: AgentLaunchBundleV1 (policy + grant + build manifest)
Agent -> game: AgentHealthV1 (protected)
game -> Agent: AgentReportChallengeV1
Agent -> game: AgentIntegrityReportV1
... repeat fresh challenge/report ...
game -> Agent: SignedAgentRevocationV1 (when server revokes)
Agent -> game: AgentHealthV1 (revoked)
game -> Agent: empty Shutdown frame
```

The launch bundle must come from the authenticated authoritative-server API. A
client script cannot mint it, substitute its Agent key, alter a manifest file, extend
its lifetime, or lower the minimum Agent version without invalidating the
operator signature.
The grant also binds the authoritative server ID, so migration to another
server requires a new Agent session and launch bundle.

Godot receives this through a prebuilt GDExtension and autoload, Unity through a UPM runtime service with IL2CPP bindings, and Unreal through a GameInstance subsystem with typed Blueprint nodes. Security-sensitive messages are binary and typed; gameplay scripts never construct JSON security envelopes.
