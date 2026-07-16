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

Normal users run `update-registered-game --registration-id ID --activate` or
use the GUI. The Agent derives the HTTPS endpoints, channel, target, and TUF
root from the signed game registration and rejects cross-channel targets. The
lower-level `update` command remains for release engineering. Inspect an install
with `update-status`, then use `activate-update` for the next launch. If operational
checks fail, `rollback-update` atomically selects the prior verified slot.

During protected launch, a signed `agent_update_required` decision triggers the
same TUF verification and immutable staging automatically for registered games.
The live state progresses through `update_required`, `updating`, and
`update_ready` (or `update_failed`). Activation remains a relaunch boundary so
the running executable is never replaced. System-wide installations use the
GUI's OS-native administrator approval flow (Windows UAC, macOS administrator
authorization, or Linux PolicyKit) before writing the immutable install slot.
See [COMPATIBILITY.md](COMPATIBILITY.md).

Stable `v1.*` workflows fail unless Windows Authenticode and macOS Developer ID
signing/notarization credentials are available. Archives are checksummed,
SBOM-attached, provenance-attested, and keyless-signed. The offline 2-of-3 TUF
root ceremony remains an operator release gate.
