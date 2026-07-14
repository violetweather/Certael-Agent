# 1.0 evidence gates

This repository remains pre-1.0 until every gate has published evidence.

- [x] Separate repository and license boundary
- [x] Canonical v1 report model and Ed25519 proof
- [x] Strict size, session, nonce, sequence, and digest-chain verification
- [x] Panic-contained probe C ABI
- [x] Private inherited Unix launch channel
- [x] Bounded typed IPC framing with malformed/oversized-frame tests
- [x] Revocable signing-key ring and canonical signed policy verification
- [x] Short-lived launch-grant verification bound to Agent key and policy digest
- [x] Fresh one-time challenge handling and chained signed report state
- [x] TUF metadata rotation, expiration, rollback, and target verification library
- [x] Restricted inherited Windows anonymous-pipe implementation
- [x] Live signed policy/grant, challenge, report, and shutdown channel loop
- [x] Permission-checked operator trust store with overlapping/revoked keys
- [x] Core-backed launch-grant, one-time challenge, report, health, and revocation transport
- [x] Core-owned signed immutable policy lifecycle with durable approvals and tenant isolation
- [x] Atomic versioned platform installer, verified launcher, activation, recovery, and rollback
- [ ] Exercised offline 2-of-3 TUF root ceremony
- [x] Windows child-process mitigations and Agent process mitigations
- [ ] Windows Authenticode signing and validation evidence
- [ ] macOS Developer ID, notarization, hardened-runtime, and Mach-O checks
- [x] Linux ELF build-ID reporting and pidfd liveness checks
- [x] Prebuilt-package automation for Godot, Unity, and Unreal Agent probes
- [ ] Pinned editor/player execution evidence for all three engines and four platforms
- [x] Native minimal UI and telemetry disclosure screen
- [x] Core-enforced configurable raw Agent report retention capped at 24 hours
- [x] Core-enforced 30-day maximum for evidence containing advisory Agent findings
- [x] Core tenant/environment-scoped raw and derived evidence deletion exercise
- [ ] 100,000-session load and 24-hour soak evidence
- [x] Nonempty SBOM, checksums, keyless signature, provenance, and verification automation
- [ ] Authenticode, Developer ID, notarization, and independently verified release evidence
- [ ] External security, cryptographic, and privacy review with no open high findings

Unchecked items are not implemented claims.
