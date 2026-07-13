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

