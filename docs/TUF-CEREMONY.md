# TUF root ceremony and release evidence

Stable 1.0 updates require a witnessed offline root ceremony. This document is
a runbook; checking the roadmap gate requires carrying it out with real
operator-controlled keys and publishing the non-secret evidence.

## Roles and custody

- Root: three offline Ed25519 keys held by three distinct custodians; threshold 2.
- Targets: online release signer, threshold 1, short rotation interval.
- Snapshot: separate online signer, threshold 1.
- Timestamp: separate online signer, threshold 1, shortest expiry.
- No root private key may exist on a CI runner, network service, source tree,
  engine project, release archive, or shared password manager entry.

Each custodian generates their root key on a freshly prepared offline device,
records the public key fingerprint by two independent channels, and keeps an
encrypted offline backup under separate physical control. Ceremony workstations
must have synchronized clocks before disconnection and must not be reconnected
until secret material has been removed.

## Initial ceremony

1. Record date, location, participants, tool binary digest, OS image digest,
   and the intended root metadata version and expiry.
2. Verify all three public-key fingerprints aloud and in the written record.
3. Construct root metadata with exactly the roles and thresholds above.
4. Have two custodians independently sign the exact canonical root bytes.
5. On a separate clean machine, verify both signatures, threshold, expiry,
   version, and role separation from the resulting public root.
6. Copy only the signed public `root.json` and ceremony record out through
   write-once media. Hash them before and after transfer.
7. Destroy temporary plaintext secret material and record the disposition.
8. Install the public root in release packages and test an update, an expired
   timestamp, a tampered target, and a rollback attempt.

## Rotation and emergency recovery

Every root rotation is signed by the threshold of both the old root and the new
root. Versions increase by exactly one. Test sequential rotation through every
intermediate root because clients reject skipped trust transitions. A suspected
online-role compromise rotates that role with the offline root; a suspected
root compromise triggers the documented incident process and must not be
handled by silently replacing the shipped root.

## Evidence bundle

Publish no secrets. Retain:

- signed public root metadata and SHA-256 digest;
- redacted ceremony minutes and custodian attestations;
- tool and clean-OS provenance;
- independent verification output;
- successful update/rotation test output;
- negative-test output for tampering, expiration, rollback, and missing target;
- issue references for every deviation.

The checkbox in `ROADMAP.md` stays unchecked until this evidence exists and a
second trusted maintainer has reviewed it.
