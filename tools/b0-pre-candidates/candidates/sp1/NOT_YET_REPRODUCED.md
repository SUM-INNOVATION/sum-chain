# NOT_YET_REPRODUCED — SP1 candidate

No authoritative `Cargo.lock`, `candidate_dep_lock_hash`, container digest, or
verifier material exists for the SP1 candidate.

- Direct pins (exact): `sp1-sdk = 6.3.1`, `sp1-zkvm = 6.3.1`, `sp1-build = 6.3.1`,
  `sp1-verifier = 6.3.1`.
- Authoritative lock: **absent** — to be generated inside the container venue
  (native Linux, Rust 1.88.0) per [`../../VENUE.md`](../../VENUE.md).
- `candidate_dep_lock_hash`: **not computed** (must not be computed off-venue).
- Any `Cargo.lock` present in this directory is an error and must be deleted; it
  was not produced by the authoritative venue.

This marker is intentionally outside any lockfile path so scripts can assert the
candidate is unresolved without a fabricated lock existing.
