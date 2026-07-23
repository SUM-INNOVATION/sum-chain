# NOT_YET_REPRODUCED — SP1 candidate

The SP1 candidate now carries **official guest SOURCE** (`guest/src/main.rs`
routing through the candidate-neutral `b0-pre-guest-core`). What is still absent
is any **venue-built artifact or measurement** — this marker records that.

No authoritative `Cargo.lock`, `candidate_dep_lock_hash`, container digest,
verifier material, guest program id / verifying key, proof/receipt, or measured
cost exists for the SP1 candidate.

- Direct pins (exact): `sp1-zkvm = 6.3.1` (guest), `sp1-sdk = 6.3.1`,
  `sp1-verifier = 6.3.1`, `sp1-build = 6.3.1` (host).
- Official guest source: **present** (`guest/src/main.rs` →
  `b0_pre_guest_core::run`); its semantics are locally verified by the
  `b0-pre-guest-core` tests (no prover toolchain needed). See
  [`docs/b0-pre/GUEST_SOURCE.md`](../../../../docs/b0-pre/GUEST_SOURCE.md).
- Guest ELF / program id / verifying key: **not built** — produced only by the
  pinned SP1 6.3.1 guest toolchain inside the container venue per
  [`docs/b0-pre/venue/VENUE.md`](../../../../docs/b0-pre/venue/VENUE.md). The
  guest identity does NOT enter the normative artifact (Stage-1 rule); any venue
  proof stays `NON_SELECTION / NOT_AN_OFFICIAL_GUEST`.
- Authoritative lock: **absent** — to be generated inside the container venue
  (native Linux, Rust 1.88.0).
- `candidate_dep_lock_hash`: **not computed** (must not be computed off-venue).
- Any `Cargo.lock` present in this directory is an error and must be deleted; it
  was not produced by the authoritative venue.

This marker is intentionally outside any lockfile path so scripts can assert the
candidate is unreproduced without a fabricated lock existing.
