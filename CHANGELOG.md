# Changelog

All notable changes to Certael Agent are documented here.

## [0.4.0-alpha.1] - 2026-07-18

### Added

- A signed, publisher-branded launch splash with verified local PNG icon and optional cinematic hero artwork, plain-language progress, responsive layouts, and accessible large-text behavior.
- Truthful protected-launch milestones covering launcher verification, registration loading, registered-file hashing, game startup, secure-server admission, signed launch verification, and protected-session readiness.
- A versioned runtime-status contract with per-attempt correlation so stale status files cannot advance or complete a newer launch.
- Signed registration controls for registered game-file hashes, a bounded repair executable and arguments, and an explicit offline-play allowance.
- Actionable failure views that expose only the repair, offline, and close actions permitted by the signed registration.
- Debug-only splash preview controls for milestone, failure, viewport, zoom, and screenshot QA.

### Security

- Branding assets are constrained to safe registration-relative paths and verified for signature binding, SHA-256 digest, PNG type, animation, file size, decoded dimensions, and decoded memory before display.
- Repair launches only a signed, registered, hash-matched executable directly without a command shell.
- Offline launch never receives the private Agent channel and cannot weaken modes whose signed policy requires protected play.
- The splash reports `Protected session ready` only after authoritative server admission, signed bundle verification, matching build verification, and ready health.

### Changed

- `RuntimeStatus` advances to schema version 2 and records a launch-attempt identifier plus the current launch milestone.
- The native launcher uses AccessKit-backed accessibility integration and a wide publisher-launcher composition across normal, narrow, failure, and large-text states.

### Compatibility

- Probe ABI v1 and Agent protocol v1 remain current.
- This release is the recommended Agent for Core `v0.4.0-alpha.1` and remains compatible with existing action protocol v1 integrations.

## [0.3.0-alpha.3] - 2026-07-16

### Added

- Canonical rejection health responses for admission timeout, channel failure, frame mismatch, bundle rejection, registration mismatch, manifest verification, build mismatch, and required updates.
- Privacy-bounded cross-process correlation for Agent PID, game PID, build ID, payload length, and accepted session ID.

### Fixed

- Engine integrations can distinguish an Agent rejection from a missing or malformed health response while the return channel remains available.
- Protected-launch failures no longer depend exclusively on a terminal failure after session closure.

### Compatibility

- Probe ABI v1 and Agent protocol v1 remain current.
- This release is the recommended Agent for Core `v0.4.0-alpha.1`; no Agent update is required when upgrading from Core `v0.3.0-alpha.2`.

[0.4.0-alpha.1]: https://github.com/violetweather/Certael-Agent/compare/v0.3.0-alpha.3...v0.4.0-alpha.1
[0.3.0-alpha.3]: https://github.com/violetweather/Certael-Agent/compare/v0.3.0-alpha.2...v0.3.0-alpha.3
