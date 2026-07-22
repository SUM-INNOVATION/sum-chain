# NOT_YET_REPRODUCED — RISC Zero candidate

No authoritative `Cargo.lock`, `candidate_dep_lock_hash`, container digest, or
verifier material exists for the RISC Zero candidate.

- Direct pins (exact): `risc0-zkvm = 3.0.5`, `risc0-build = 3.0.5`,
  `risc0-groth16 = 3.0.4`, `risc0-zkvm-platform = 2.2.2`.
- Authoritative lock: **absent** — to be generated inside the container venue
  (native Linux **x86_64**, Rust 1.88.0) per
  [`docs/b0-pre/venue/VENUE.md`](../../../../docs/b0-pre/venue/VENUE.md).
- `candidate_dep_lock_hash`: **not computed** (must not be computed off-venue).
- Groth16 receipt generation + verifier-material extraction must run **natively
  on x86_64**; emulated results are ineligible.
- Any `Cargo.lock` present in this directory is an error and must be deleted; it
  was not produced by the authoritative venue.

This marker is intentionally outside any lockfile path so scripts can assert the
candidate is unresolved without a fabricated lock existing.
