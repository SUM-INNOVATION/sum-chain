# ArchRunProvenanceV1 DVFS-v2 transition — TEST_ONLY fixture regeneration provenance

The `ArchRunProvenanceV1` record advanced to a **provenance-local** schema version 2
(`consts::ARCH_RUN_PROVENANCE_SCHEMA_VERSION`) for the `DvfsProvenance` sum-type transition
(the explicit hypervisor-managed-unobservable DVFS state). The global `consts::SCHEMA_VERSION`
stays **1**: no other record's layout changed, so the finalized R0 protocol / B0-PRE / R5
canonical bytes and hashes are untouched.

## Regeneration set — exactly four TEST_ONLY fixtures (+ two `.blake3` sidecars)

Each of the four **directly embeds or hashes `ArchRunProvenanceV1`**, so the provenance-local
v2 byte change forces their regeneration. No finalized artifact is regenerated.

| fixture | SHA-256 old → new | BLAKE3 old → new |
|---|---|---|
| `closure-golden/vectors.json` | `3a2a6893…dee248` → `7518440f…9b68e640` | `85026475…c757f78` → `5d993fcc…dd87a86` |
| `evidence-harness/spec.json` | `4f6c777f…2d91e9` → `cca8c255…dfe349` | `40cce9b0…d0a2d3` → `fda119d5…0954f49` |
| `measurement-vector/real-orchestrator-vector.bin` | `5d6e53c4…2b5aa5` → `d2ccd28b…5c4ee219` | `f40c4a88…c68fb0` → `38023d04…dd01dfa6` |
| `producer-selftest/producer-dry-run-testonly.bin` | `0bd27a94…d5098c` → `cc18c31f…14a9e291` | `61fa17fd…bea5243` → `bf325f49…f6dbb785` |

Sidecars `real-orchestrator-vector.bin.blake3` and `producer-dry-run-testonly.bin.blake3` carry the
new BLAKE3 values above. In-code evidence-harness fingerprints (validator `harness.rs`) also moved:
SP1 `9992d256…325d8aa1d`, RISC0 `d767ec6e…4572520e`.

## Finalized artifacts — byte-identical (guarded by tests, not regenerated)

- `encoding-golden/vectors.json`: **byte-identical** to `origin/main` — `tests/golden.rs`
  (`reference_pipeline_matches_committed_golden`) re-derives and pins the finalized R0
  `statement_final.computation_statement_hash`, `derived_input.identity`, the manifests, and the
  object commitment. This is the standing regression lock that finalized R0 bytes do not drift.
- Finalized R0 statement and derived-input identities: unchanged.
- Finalized B0-PRE / R5 artifacts: unchanged.
- Scan invariant: `ArchRunProvenanceV1` is the ONLY record that emits schema version 2
  (`consts::ARCH_RUN_PROVENANCE_SCHEMA_VERSION`, sole writer at `schema/provenance.rs`).

Cross-implementation agreement on the unobservable evidence hash is pinned to the shared golden
`6aa1924a…892b7c6` in both the reference validator (`schema/provenance.rs` tests) and the
independent verifier (`b0-pre-independent/tests/dvfs_unobservable_cross_impl.rs`).
