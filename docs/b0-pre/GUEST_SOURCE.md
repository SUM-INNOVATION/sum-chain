# B0-PRE official guest source (#123)

This document describes the **official guest source** for the two frozen B0-PRE
statements — `TransformerLayerGroup` and `SelectToken` — and, crucially, what is
*locally verifiable* versus what is a *venue-built artifact* that does not exist
yet.

It preserves three deliberately separate layers:

1. **Locally reviewable guest semantics** — the candidate-neutral source in
   `tools/b0-pre-candidates/guest-core` plus the two thin candidate wrappers.
   Fully testable on any host, with no prover toolchain.
2. **Venue-built SP1 / RISC Zero artifacts** — the compiled guest ELF, its
   program id / verifying key / image id, the in-container `Cargo.lock`, and the
   Groth16 proof/receipt. Produced only inside the pinned container venue.
3. **Authoritative measured results** — cycle counts, proof bytes, verify times,
   RSS. Produced only by the two-architecture R0 run under a merged B0-PRE
   protocol hash. **Out of scope here** and not attempted.

Nothing in layer 1 fabricates anything from layers 2 or 3.

## What the official guest is

- `guest-core` (`b0-pre-guest-core`) is the single, shared, candidate-neutral
  source of the guest-side statement contract. It contains:
  - the frozen **integer transformer** (`transformer.rs`) and fixed-point
    arithmetic (`fixed.rs`), byte-identical to the frozen reference
    `b0-pre-validator`;
  - the certified **Q16 exp-table values** baked in as a constant
    (`exp_table.rs`), bound to the committed
    `docs/b0-pre/exp/exp_table_q16.json` (+ `.hash`) by a test;
  - the strict **witness→statement contract** (`verify.rs`) — the byte-driven
    counterpart of the reference's `verify_tlg` / `verify_select`, which that
    reference explicitly documents as "the guest-side contract";
  - the **guest-input envelope** decoder (`input.rs`, see below);
  - `run(input) -> [u8; 32]`, the entrypoint that decodes the envelope, verifies
    the contract for the statement's `unit_kind`, and returns the single
    committed journal.
- The SP1 and RISC Zero guests (`candidates/{sp1,risc0}/guest/src/main.rs`) are
  **thin wrappers**: they own only the zkVM I/O (read the input blob, call
  `b0_pre_guest_core::run`, commit the 32-byte journal). They re-implement no
  semantics, so both candidates prove **logically identical** statement fixtures.

### It adopts the frozen wire types directly (no mirror)

`guest-core` depends on the production crate `sumchain-wire` (path dependency)
and decodes every statement / object commitment / manifest / derived-input
through the frozen `sumchain-wire::b0` types. There is **no hand-written mirror**
of those types — the guest enforces exactly the merged production wire formats,
byte-for-byte.

### The committed output (journal)

The guest commits **only** `computation_statement_hash` — `BLAKE3` over the
re-canonicalized 996-byte statement (§17). No host-only field, synthetic value,
program id, or verifier key is exposed as guest output. The guest is
**spec-hash-agnostic**: it commits the hash of whatever canonical statement it is
given, so no `b0_pre_spec_hash` is invented.

## The guest-input envelope is guest-LOCAL, not consensus

The frozen wire family freezes the *statement* and each *witness object*, and
freezes the guest's *output*. It does **not** freeze an outer container that
concatenates a statement with its witnesses for `stdin.write` — the prover just
hands the guest one opaque blob. That outer framing is therefore an **UNFROZEN,
guest-local I/O concern**. It is defined explicitly in `input.rs` (self-domained
tag `SUMCHAIN/R0/GUESTIN/v1`, strict, length-checked) rather than left implicit.

It never enters the committed journal (which is derived only from the
re-canonicalized statement), so a different framing changes no consensus value.
**This is the one semantic this work chose rather than found frozen; it is
isolated here and does not touch any consensus value.** If the owner prefers a
different or frozen input framing, only `input.rs` and the two wrappers change.

## What is locally verifiable (no prover toolchain)

Run from `tools/b0-pre-candidates/guest-core`:

```
cargo test          # unit + golden + malformed + exp-table binding
cargo clippy --all-targets
cargo fmt --check
```

The tests establish:

- **Reference agreement** (`tests/reference_agreement.rs`): the frozen official
  workload fixture `docs/b0-pre/fixtures/workload/official.json` (produced by the
  reference transformer) is ACCEPTED by the guest core for both statements, and
  the journal equals `computation_statement_hash` of the frozen statement
  template. Because the guest recomputes every output commitment, any drift in
  the baked transformer/exp/fixed logic would make a recomputed commitment
  mismatch and the guest reject — so acceptance is byte-for-byte agreement with
  the frozen reference.
- **Deterministic rejection** (`tests/malformed.rs`): every tampered witness
  byte, tampered public-statement byte, wrong statement kind, missing/extra
  witness, corrupted envelope, and trailing byte is rejected.
- **Exp-table binding** (`tests/exp_table_binding.rs`): the baked table
  reproduces the committed single-domain hash and every committed value.
- Unit tests for the transformer, fixed-point arithmetic, exp lookup, and the
  input envelope's strict decode.

The venue can also emit the exact input blobs the prover consumes, with a
built-in acceptance self-check:

```
cargo run --example emit_official_guest_input -- \
  ../../../docs/b0-pre/fixtures/workload/official.json <out_dir>
# writes <out_dir>/tlg.guestin.bin and <out_dir>/select.guestin.bin (INPUT bytes only)
```

## What is NOT done here (venue-built / measured)

- **No guest ELF is built.** Compiling the SP1/RISC Zero guests needs the pinned
  guest toolchains (`cargo prove build` for SP1 6.3.1; `cargo risczero build`
  for RISC Zero 3.0.5, native x86_64). Off-venue the build fails closed. This is
  **implemented but UNEXECUTED**.
- **No program id / verifying key / image id.** The guest identity is derived
  from the compiled ELF; it is a venue artifact. Per the Stage-1 rule it does not
  enter the normative protocol artifact, and no allowlist / `r0_guest_set_hash`
  is populated.
- **No proof / receipt.** Generated only by proving the built guest in the venue.
- **No measured cost.** Cycle counts, proof bytes, verify times, and RSS are the
  authoritative R0 results (layer 3) and are not produced here.

The guest must not be reported as reproducibly frozen until native venue outputs
exist for both architectures.

## Venue packaging (IMPLEMENTED — container context staging)

Because the official guest depends on the shared `b0-pre-guest-core`, which in
turn depends on `sumchain-wire`, the in-container build must have those two crates
present at the paths the manifests reference:

- `candidates/<cand>/guest` → `../../../guest-core` (`b0-pre-guest-core`)
- `guest-core` → `../../../crates/sumchain-wire` (`sumchain-wire`)

and `sumchain-wire` is a **workspace member** that inherits `.workspace = true`
keys from the repo-root `Cargo.toml`, so the workspace root must also be present.

This is now **implemented** by an authoritative container-context staging step
(`scripts/stage_context.sh`, shared with `build_container.sh`). It builds a
**curated, minimal** Docker build context that reproduces the **exact
repo-relative layout of ONLY the guest dep graph** — nothing else from the
production workspace (isolation):

```
<staged context> = reproduced repo root mapped to /work
├─ Cargo.toml                              curated minimal workspace root: ONLY the
│                                          [workspace] / [workspace.package] /
│                                          [workspace.dependencies] sections
│                                          sumchain-wire inherits, and ONLY
│                                          sumchain-wire as a member (tools excluded)
├─ crates/sumchain-wire/                   frozen wire leaf (workspace member)
├─ tools/b0-pre-candidates/
│  ├─ guest-core/                          candidate-neutral shared guest core
│  └─ candidates/<cand>/                   this candidate workspace (host + guest)
└─ docs/b0-pre/{fixtures/workload,exp}/    frozen guest fixtures the guest-core uses
```

The path deps (`../../../guest-core`, `../../../crates/sumchain-wire`) and
`sumchain-wire`'s `.workspace` inheritance therefore resolve in-container, and the
candidate `Cargo.lock` is generated in-container **from the COMPLETE staged graph**
(guest + guest-core + sumchain-wire + transitive), not just the candidate crate.
No production workspace or unrelated crate is copied; the staged context carries
**no `Cargo.lock`** (host locks are refused; the venue generates the authoritative
lock and binds it).

This does **not** weaken the #154-sealed container reproducibility machinery: the
container digest is still recomputed from the actual built image, and the staged
context's exact byte identity (`staged_context_blake3`) is additionally bound into
the builder command log that is already BLAKE3-hashed into the container evidence —
an added binding, not a relaxed one. The `packaging` is implemented and
structurally verified off-venue
(`tools/b0-pre-validator/tests/container_context_staging.rs`, no Docker / prover);
the guest **ELF build + prove** remains **VENUE-UNEXECUTED**. Off-venue,
`prove_fixture.sh` still locates the official guest and fails closed (a missing
toolchain / container / native builder is a hard error, never a synthetic proof).

### Fresh in-container lock vs a yanked transitive version

The graph transitively pulls `lazy_static 1.5.0`, whose optional `spin_no_std`
feature requires `spin = ^0.9.8`; **`spin 0.9.8` is yanked** on crates.io. Because
the authoritative path rejects any pre-existing lock and generates a **fresh** one
in-container, and the v2 resolver refuses a yanked version for a fresh lock, this
could have been a hard blocker. It is not: `^0.9.8` is **also satisfied by the
non-yanked `spin 0.9.9`**, which the resolver selects. A fresh
`cargo generate-lockfile` over BOTH staged candidate graphs was confirmed to resolve
`spin 0.9.9` from the authoritative registry (sp1 = 532 packages, risc0 = 359). **No
host lock, un-yank, invented version, or vendored source is used.** This is guarded
by `tools/b0-pre-validator/tests/candidate_lock_yanked_spin.rs` (deterministic index
check + a fresh-lock resolution over the exact edge; the network resolution is
labelled venue-unexecuted when the host is air-gapped). Note that an **`--offline`**
resolve on a dev host that has only `spin-0.9.8.crate` cached fails *spuriously* —
offline mode restricts candidates to already-downloaded crates — which is an
offline-mode artifact, not a venue failure.

## Exact venue commands (implemented, UNEXECUTED)

On the pinned native builder, inside the venue (see
[`venue/VENUE.md`](venue/VENUE.md) and [`venue/RUNBOOK.md`](venue/RUNBOOK.md)):

```
# 1. Produce the deterministic guest-input blob for a statement (host side):
cargo run --manifest-path tools/b0-pre-candidates/guest-core/Cargo.toml \
  --example emit_official_guest_input -- \
  docs/b0-pre/fixtures/workload/official.json <work>/guestin

# 2. Prove the OFFICIAL guest to a genuine (still NON_SELECTION-stamped) fixture,
#    inside the pinned container, with the bound prover tool identity:
VERIFIER_REF=<pinned-builder-image> CMD_LOG=<work>/cmd.log SCHEMA_ARCH=X86_64 \
  TOOL_BINDING=<work>/Sp1.tool-binding.json \
  PROVER_GUEST_INPUT=<work>/guestin/tlg.guestin.bin \
  bash tools/b0-pre-candidates/scripts/prove_fixture.sh sp1 x86_64 <work>/fixture.json

# (RISC Zero is native x86_64 only; use SCHEMA_ARCH=X86_64, candidate risc0.)
```

The Stage-5 harness (`verifier_fixtures.sh`, driven by `run_authoritative.sh`)
calls the same `prove_fixture.sh` and now passes `PROVER_GUEST_INPUT` through.

## Guarantees preserved

- Fail-closed off-venue (no toolchain / container / native builder → hard stop).
- The dry/test path (`SUMCHAIN_B0PRE_DRYRUN=1`) is refused by both fixture
  scripts, so no synthetic input/proof can reach authoritative Stage-5 ingestion.
- Any venue-proved fixture stays self-labeled
  `TEST_ONLY / NON_SELECTION / INVALID_FOR_R0 / NOT_AN_OFFICIAL_GUEST` (four
  stamps): the guest identity never enters the normative artifact.
- The sealed evidence bindings from #154 are unchanged (no fixture/lock/hash
  binding was weakened).
- The protocol artifact stays `not_finalizable`; no `b0-pre-protocol-v1.json.hash`
  is written.
