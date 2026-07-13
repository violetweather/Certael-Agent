# Agent protocol v1

The normative schema is mirrored by `certael.agent.v1` in Certael Core. Production messages use deterministic Protobuf encoding with a 64 KiB limit. JSON is diagnostic only.

Signature domains are:

```text
certael.agent.policy.v1\0
certael.agent.launch.v1\0
certael.agent.report.v1\0
certael.agent.update.v1\0
```

Reports are signed over the report with its signature field omitted. Servers verify the session ID, build ID, fresh challenge, exact next sequence, previous report digest, expiry, and Ed25519 signature before storing evidence. Protocol v1 becomes immutable at the 1.0 release.

Local engine communication uses a typed frame with `CTAL` magic, protocol version, message type, and a network-byte-order payload length. Unknown types, unsupported versions, truncated frames, and payloads over 64 KiB are rejected. The first message is `AgentHelloV1`; a hello is bootstrap identity, not an integrity report and not proof of trust.

The second message must be `AgentLaunchBundleV1`. Its nested signed policy and
launch grant are themselves canonically encoded and verified against a pinned,
time-bounded, non-revoked trust-store key. Admission binds the policy digest,
ephemeral Agent public key, executable build, game, environment, grant expiry,
and minimum Agent version. Trust roots are never accepted from the game channel.

After admission, only fresh `AgentReportChallengeV1` messages and an empty
shutdown frame are accepted from the game. Each response advances an exact
sequence and SHA-256 report chain. Closing the channel ends evidence production;
the server then classifies the session according to its signed grace policy.
