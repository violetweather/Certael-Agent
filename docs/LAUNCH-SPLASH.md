# Publisher launch splash

Certael Agent `v0.4.0-alpha.1` can present a signed, game-branded launcher while
protected play is being established. The window is intentionally a launch
surface—not a security dashboard—and reports only milestones the Agent has
actually completed.

## Publisher inputs

The publisher signs canonical `BrandingManifestClaimsV1` bytes with the same
publisher trust domain used by the game registration. The claims bind:

- `registration_id` and `game_id`;
- a display name and optional publisher name;
- a registration-relative icon PNG path and SHA-256 digest;
- an optional registration-relative cinematic hero PNG path and SHA-256 digest;
- a validity window.

Pass the signed Protobuf manifest and the asset root together when installing or
updating a registration:

```powershell
certael-agent register-game `
  --registration C:\Game\Certael\registration.pb `
  --publisher-trust-store C:\Game\Certael\publisher-trust-store.json `
  --update-root C:\Game\Certael\update-root.json `
  --game-root C:\Game `
  --branding-manifest C:\Game\Certael\branding.pb `
  --branding-root C:\Game\Certael\branding
```

Both branding arguments are optional, but one cannot be supplied without the
other. The Agent verifies the signature, registration binding, validity, safe
relative paths, SHA-256 digests, PNG type, absence of animation, file limits,
dimensions, and decoded memory bounds before copying the assets into the
isolated registration. The launcher never downloads artwork at launch time.

## Registered files and recovery actions

`GameRegistrationClaimsV1.registered_files` is the signed allowlist of protected
files. Each entry binds a relative path, byte length, and SHA-256 digest. Before
starting protected mode, the Agent verifies every entry.

The optional `repair_executable_relative_path` must name one of those registered
files. Its signed arguments are bounded and the Agent starts it directly without
a command shell. `offline_play_allowed` and `offline_arguments` are also signed;
offline launch receives no private Agent channel and is never offered when the
registration does not permit it.

## Truthful progress

The splash advances through launcher verification, registration loading,
registered-file checking, game startup, server admission, signed launch-bundle
verification, and protected readiness. `Protected session ready` is shown only
after authoritative admission, a matching signed build, and ready health. A
stale status file from another launch attempt cannot advance the UI.

Failures retain the last trustworthy milestone and show a bounded public reason.
Repair and offline actions appear only when permitted by the signed registration.
