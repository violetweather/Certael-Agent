# Engine integration

Games should normally be started by Certael Agent. On Unix, the Agent passes an inherited socket descriptor through `CERTAEL_AGENT_FD`; the descriptor is not a network listener. Windows release packages use an inherited restricted named-pipe handle.

The engine adapter must:

1. Connect only to the inherited channel.
2. Reject messages over 64 KiB and unsupported protocol versions.
3. Bind the server-issued launch grant to the Agent session public key.
4. Start the in-process probe and answer fresh nonce challenges.
5. Surface `ready`, `degraded`, `lost`, and `update_required` states.
6. Dispose the channel during logout, account switch, or process exit.

The stable probe C ABI exposes `certael_agent_channel_open`,
`certael_agent_channel_read`, and `certael_agent_channel_destroy`. A buffer-too-small
read reports the required length without consuming the pending frame. Every other
language binding must preserve this ownership and retry behavior.

Godot receives this through a prebuilt GDExtension and autoload, Unity through a UPM runtime service with IL2CPP bindings, and Unreal through a GameInstance subsystem with typed Blueprint nodes. Security-sensitive messages are binary and typed; gameplay scripts never construct JSON security envelopes.
