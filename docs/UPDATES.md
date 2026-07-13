# Secure updates

The updater uses the audited `tough` implementation of The Update Framework. It always enables safe expiration enforcement, persists metadata for rollback detection, follows signed root rotation, applies strict metadata size/update limits, requires HTTPS repositories, and stages targets only after their signed length and hash verify.

The trusted root is shipped out of band with the Agent. Stable releases require an exercised offline 2-of-3 root-key ceremony and separate online timestamp, snapshot, and targets roles. Private keys are never placed in this repository or ordinary workflow configuration.

Staging does not replace a running executable. Platform-specific atomic installation, Authenticode/Developer ID signing, rollback testing, and interrupted-update recovery remain release gates in `ROADMAP.md`.
