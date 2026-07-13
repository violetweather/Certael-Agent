# Secure updates

The updater uses the audited `tough` implementation of The Update Framework. It always enables safe expiration enforcement, persists metadata for rollback detection, follows signed root rotation, applies strict metadata size/update limits, requires HTTPS repositories, and stages targets only after their signed length and hash verify.

The trusted root is shipped out of band with the Agent. Stable releases require an exercised offline 2-of-3 root-key ceremony and separate online timestamp, snapshot, and targets roles. Private keys are never placed in this repository or ordinary workflow configuration.

Staging does not replace a running executable. After TUF verification, the
installer copies the target into an immutable version directory, verifies its
SHA-256 digest again while copying, fsyncs it, and records a pending slot. A
single bounded `activation.json` state file selects the active, previous, and
pending slots. Unix uses atomic rename; Windows uses write-through
`MoveFileExW` replacement. Activation, rollback, and interrupted-update
recovery never execute bytes whose recorded digest no longer matches.

The running Agent is never overwritten. A launcher or platform service reads
the active slot on the next start. Incomplete temporary directories are not
eligible slots, invalid pending versions are discarded during recovery, and an
invalid active version can only fall back to a still-valid previous slot.

Authenticode/Developer ID signing, packaged platform installers, upgrade chaos
tests, and the exercised offline 2-of-3 TUF root ceremony remain release gates
in `ROADMAP.md`.
