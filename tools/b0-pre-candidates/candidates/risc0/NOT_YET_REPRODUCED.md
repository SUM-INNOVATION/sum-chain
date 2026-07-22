# NOT_YET_REPRODUCED — RISC Zero candidate

The RISC Zero candidate now carries **official guest SOURCE**
(`guest/src/main.rs` routing through the candidate-neutral `b0-pre-guest-core`).
What is still absent is any **venue-built artifact or measurement** — this marker
records that.

No authoritative `Cargo.lock`, `candidate_dep_lock_hash`, container digest,
verifier material, guest image id, proof/receipt, or measured cost exists for the
RISC Zero candidate.

- Direct pins (exact): `risc0-zkvm = 3.0.5` (guest env + host), `risc0-groth16 =
  3.0.4`, `risc0-build = 3.0.5` (host). The guest-side platform crate
  (`risc0-zkvm-platform = 2.2.2`) resolves transitively from `risc0-zkvm 3.0.5`.
- Official guest source: **present** (`guest/src/main.rs` →
  `b0_pre_guest_core::run`); its semantics are locally verified by the
  `b0-pre-guest-core` tests (no prover toolchain needed). See
  [`docs/b0-pre/GUEST_SOURCE.md`](../../../../docs/b0-pre/GUEST_SOURCE.md).
- Guest ELF / image id: **not built** — produced only by the pinned RISC Zero
  3.0.5 toolchain inside the **native x86_64** container venue per
  [`docs/b0-pre/venue/VENUE.md`](../../../../docs/b0-pre/venue/VENUE.md). The
  guest identity does NOT enter the normative artifact (Stage-1 rule); any venue
  proof stays `NON_SELECTION / NOT_AN_OFFICIAL_GUEST`.
- Authoritative lock: **absent** — to be generated inside the container venue
  (native Linux **x86_64**, Rust 1.88.0).
- `candidate_dep_lock_hash`: **not computed** (must not be computed off-venue).
- Groth16 receipt generation + verifier-material extraction must run **natively
  on x86_64**; emulated results are ineligible.
- Any `Cargo.lock` present in this directory is an error and must be deleted; it
  was not produced by the authoritative venue.

This marker is intentionally outside any lockfile path so scripts can assert the
candidate is unreproduced without a fabricated lock existing.
