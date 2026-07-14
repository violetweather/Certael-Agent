# Secure updates

The updater uses the audited `tough` implementation of The Update Framework. It always enables safe expiration enforcement, persists metadata for rollback detection, follows signed root rotation, applies strict metadata size/update limits, requires HTTPS repositories, and stages targets only after their signed length and hash verify.

The trusted root is shipped out of band with the Agent. Stable releases require an exercised offline 2-of-3 root-key ceremony and separate online timestamp, snapshot, and targets roles. Private keys are never placed in this repository or ordinary workflow configuration.
The exact custody, rotation, negative-test, and public-evidence procedure is in
[TUF-CEREMONY.md](TUF-CEREMONY.md).

Staging does not replace a running executable. After TUF verification, the
installer copies the target into an immutable version directory, verifies its
SHA-256 digest again while copying, fsyncs it, and records a pending slot. A
single bounded `activation.json` state file selects the active, previous, and
pending slots. Unix uses atomic rename; Windows uses write-through
`MoveFileExW` replacement. Activation, rollback, and interrupted-update
recovery never execute bytes whose recorded digest no longer matches.

The running Agent is never overwritten. The installed `certael-agent-launcher`
re-verifies the selected slot and its complete SHA-256 digest on every start,
then executes that immutable version. Incomplete temporary directories are not
eligible slots, invalid pending versions are discarded during recovery, and an
invalid active version can only fall back to a still-valid previous slot.

Use `certael-agent update` with the separately distributed TUF root and HTTPS
metadata/target endpoints to verify and stage a pending version. Inspect it with
`update-status`, then use `activate-update` for the next launch. If operational
checks fail, `rollback-update` atomically selects the prior verified slot.

Authenticode/Developer ID signing, packaged platform installers, upgrade chaos
tests, and the exercised offline 2-of-3 TUF root ceremony remain release gates
in `ROADMAP.md`.
