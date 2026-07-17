# Changelog

All notable changes to Certael Agent are documented here.

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

[0.3.0-alpha.3]: https://github.com/violetweather/Certael-Agent/compare/v0.3.0-alpha.2...v0.3.0-alpha.3
