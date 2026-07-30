# S1-v2 native-x86 real-candidate smoke (pre-R5 gate)

**Purpose.** Before R5, prove on a **native x86_64** venue that the S1-v2 Stage-5 verifier
identity is causal end-to-end for **both** SP1 and RISC Zero with the **real** pinned
verifier SDKs — through Stage-5 execution, exact-set assembly, seal, and import — and that
the authoritative importer rejects a TEST_ONLY (and a v1) result. This is the heavy tier
the lightweight CI E2E (`scripts/tests/e2e_v2_produce_chain.test.sh`) deliberately does
NOT cover: CI runs on arm64/ubuntu with itoa fixtures; RISC Zero is x86_64-only
(VENUE.md §2), and a genuine SP1/RISC Zero proof needs the x86 prover toolchain.

**This smoke is TEST_ONLY / NON_SELECTION. It must NOT:** satisfy authoritative Stage 0
(no `RATIFIED_SOURCE_COMMIT` reuse), write the protocol hash, aggregate into normative
state, select, prove for selection, or deploy. It runs on the **exact PR-head SHA**, never
a ratified source commit, and all outputs stay **outside** authoritative evidence dirs.

## Preconditions

- Native **x86_64 Linux** + a reachable Docker daemon with BuildKit/buildx ≥ 0.11.
- Checkout at the **exact PR-head SHA** under review; record it:
  `PRHEAD=$(git rev-parse HEAD)` and confirm it matches the PR head on GitHub.
- The two pinned builder images buildable per the PR-head Dockerfiles (SP1 + RISC Zero).
- A working directory OUTSIDE any authoritative evidence path, e.g.
  `SMOKE=$HOME/b0-s1v2-smoke.$PRHEAD` (never `docs/b0-pre/...`, never the venue evidence dir).

## What to run

Run the single first-class command — the separate public TEST_ONLY entry point that drives the
complete continuous path (real build → capability preflight → Stage-1 lock → Stage-2 audit →
material → causal Stage-5 → real `SmokeExecutionAttestation` → verified explicit synthetic
substitution → TEST_ONLY assembly → seal → import → the three rejection proofs → terminal marker):

```sh
# On the native x86_64 Linux venue, at the EXACT clean PR-head, with the proposed pins +
# TEST_ONLY toolchain provisioning available to build_container.sh (BASE_IMAGE / APT_* /
# RUSTUP_INIT_* / the in-image cargo-audit + advisory-DB + prover toolchain), plus:
#   ADVISORY_DB_CHECKOUT               read-only pinned RustSec advisory-db checkout
#   CARGO_AUDIT_PIN_VERSION            ratified cargo-audit version (e.g. 0.22.2)
#   CARGO_AUDIT_EXPECTED_EXE_SHA256    venue-recorded cargo-audit executable sha256 (reproduced)
export SMOKE=$HOME/b0-s1v2-smoke.$(git rev-parse HEAD)   # OUTSIDE docs/ and the authoritative dirs
bash tools/b0-pre-candidates/scripts/smoke.sh "$SMOKE"
```

On success it prints the terminal marker `X86_REAL_CANDIDATE_SMOKE_PASS` — and ONLY after every
stage and every rejection proof passed. It refuses to run with `RATIFIED_SOURCE_COMMIT` set or any
bypass variable, on a dirty tree, or with an output path under the repository / `docs/`. A missing
provisioned pin or tool value fails closed with its exact name; nothing is fabricated. The smoke
uses the SHARED production cores (`lib.sh` / `extract_material.sh`: `gen_lock_in_container`,
`run_stage2_locked`, `run_stage2_audit_locked`, `extract_material_core`,
`causal_build_hash_exec_runner`, `preflight_builder_capability`) via `build_container.sh smoke`
(the distinct `b0pre-smoke-runnable-ref-v1` sidecar the authoritative resolver rejects) — it never
duplicates production logic and never touches the authoritative dispatch.

The continuous path, per candidate `c ∈ {sp1, risc0}` (SP1 on eligible arches; RISC Zero
`arch=x86_64` only) — this is exactly what the command above executes:

1. **Builder image + Stage-1 lock.** Build the pinned builder; `resolve_lock.sh c $SMOKE`
   generates the candidate lock in-container; confirm `require_stage1_lock` accepts it.
2. **Stage-2 (D1).** Run the real `produce_stage2` path: `cargo metadata/audit --locked`
   with the Stage-1 lock **read-only bind-mounted** at `$cdir/Cargo.lock`; confirm success
   and that the host lock is byte-unchanged.
3. **Material (D2).** `extract_material.sh c $SMOKE` inside the verified builder over the
   curated harness+`b0-pre-vmat` context; confirm the material JSON + unchanged proofs.
4. **Stage-5 (v2 causal).** The real `verifier_fixtures.sh` for candidate `c`: generate +
   validate the runner lock, **build** the real verifier runner (`sp1-verifier` 6.3.1 /
   `risc0-zkvm` 3.0.5), **hash the exact binary**, **exec that file directly** over the
   genuine fixture, run all five mutation cases (each rejected), and
   `vv stage5-generate` a **schema-v2** `Stage5Result`. Confirm
   `verifier_sdk_lock_blake3` == `vv lock-hash <candidate>.stage5-runner.lock`.
5. **Assemble → seal → import.** Assemble the exact-set x86_64 bundle (both candidates),
   `vv seal-bundle $SMOKE/evidence x86_64 $PRHEAD`, then `vv import-bundle $SMOKE/evidence`.
   Import must recompute every hash — including the sealed runner locks' domain-separated
   BLAKE3 — and structurally confirm each pins its SDK (sp1-verifier 6.3.1 / risc0-zkvm
   3.0.5) from a registry source with a checksum.
6. **Rejection proofs (must FAIL closed).** The command runs these three automatically
   (`smoke_rejection_proofs`), each of which MUST be refused, before it emits the marker:
   - **P1** — the authoritative `resolve_runnable_ref` rejects the smoke `b0pre-smoke-runnable-ref-v1`
     sidecar (distinct schema); a smoke image can never be consumed on the authoritative path.
   - **P2** — authoritative `stage1-ingest` rejects the smoke `SmokeSourceBinding` (it is not a
     stage1-result-bundle, and `SmokeClass` has no authoritative variant).
   - **P3** — authoritative `stage1-ingest` refuses the sealed TEST_ONLY per-arch evidence
     (non-`AUTHORITATIVE_STAGE1` classification; never finalizable).
   Additional manual deep checks (recommended alongside): downgrade one `Stage5Result` to v1 and
   re-import (must refuse as inadequate); alter a sealed runner lock / its SDK version/source and
   re-import (must refuse).

## Sealed-artifact lineage (every substantive record is the REAL producer output)

The smoke assembles the sealed bundle from the **real** producer outputs via the shared real
assembler (`assemble_evidence`); the **one** synthetic substitution is the Stage-5b tool binding.
`emit-test-only-bundle` / `write_test_only_bundle_dir` are **never** used. Every equality below is
asserted by the Rust lineage test
`evidence_bundle_tests::smoke_bundle_lineage_only_stage5b_synthetic_every_file_is_producer_output`
(sealed-file hash == producer-output hash for every file; no synthetic sentinel in any real record).

| Sealed artifact | Producing function (real) | Source (work) path | Classification | Hash-equality asserted |
|---|---|---|---|---|
| `<Cand>.container.json` / `.native.json` | `build_container.sh smoke` (two clean builds) | `$work/<cand>.<arch>.container.json` / `.native.json` | real | ✅ |
| `<Cand>.Cargo.lock` / `.lock-provenance.json` | `resolve_lock.sh` (`gen_lock_in_container`) | `$work/<Cand>.Cargo.lock` / `.lock-provenance.json` | real | ✅ |
| `<Cand>.stage2-audit.json` | `produce_stage2` (`run_stage2_audit_locked` + `venue-verify stage2-generate`) | `$work/<Cand>.stage2-audit.json` | real | ✅ |
| `<material>.json` | `extract_material.sh` (`extract_material_core`) | `$work/<material>.json` | real | ✅ |
| `<Cand>.stage5-result.json` | `produce_stage5` (`causal_build_hash_exec_runner` + `stage5-generate`) | `$work/<Cand>.stage5-result.json` | real | ✅ |
| `<Cand>.stage5-runner.lock` | `produce_stage5` (`verifier_fixtures.sh`) | `$work/<Cand>.stage5/runner-cargo.lock` | real | ✅ |
| `<Cand>.tool-binding.json` | `smoke_write_synthetic_tool_binding` | `$work/<Cand>.tool-binding.json` | **SYNTHETIC (the one)** | ✅ |
| `smoke-source-binding.json` | `smoke_write_source_binding` | `$SMOKE/smoke-source-binding.json` | TEST_ONLY classification | ✅ |
| `<Cand>.smoke-attestation.json` | `smoke_build_attestation_and_substitution` | `$work/<Cand>.smoke-attestation.json` | real-execution attestation | ✅ |
| `<Cand>.substitution-log.json` | `venue-verify smoke-substitute` | `$work/<Cand>.substitution-log.json` | explicit logged substitution | ✅ |

The importer additionally cross-binds these: the attestation's point-of-use SHA-256 == the Stage-5
result's `verifier_executed_binary_sha256` (causal), the substitution log's `attestation_hash` == the
attestation's hash, and the substitution's `synthetic_sentinel` == the sealed tool-binding identity.

## Evidence checklist (capture into `$SMOKE`, outside authoritative dirs)

- [ ] `PRHEAD` recorded; matches the PR head on GitHub; **not** `RATIFIED_SOURCE_COMMIT`.
- [ ] Host `uname -m` = `x86_64`; Docker + buildx versions.
- [ ] Per candidate: builder OCI digest, Stage-1 lock BLAKE3, Stage-2 `--locked` success.
- [ ] Per candidate: material JSON identity; runner-lock domain-sep BLAKE3; the **exact
      executed verifier binary sha256**; the SDK name/version parsed from the sealed lock.
- [ ] The two `Stage5Result` records are `schema_version = 2`, `overall_pass` derived true,
      each `verifier_sdk_lock_blake3` == recomputed sealed-lock hash.
- [ ] `import-bundle` succeeds; bundle content hash recorded.
- [ ] All three rejection proofs failed closed (finalization rejects TEST_ONLY; import
      rejects v1; import rejects altered lock), with the exact error each produced.
- [ ] Every output labeled `TEST_ONLY / NON_SELECTION`; nothing written under
      `docs/b0-pre/**` or the authoritative venue evidence directory; no protocol hash
      written; no aggregation into normative state.
- [ ] **Independent second operator** repeats steps 1–5 and reproduces the verifier
      identities (runner-lock domain-sep hashes + parsed SDKs) and the bundle content hash;
      any disagreement is a FAIL.

## Pass criteria (all required before R5)

Both candidates reach a v2 `Stage5Result` and a sealed bundle that **import-verifies**;
all three rejection proofs fail closed; the executed-binary + runner-lock bindings are
recorded; a second operator reproduces the identities and bundle hash. Only after this
smoke passes on the exact PR head — **and** the reviewed head is merged, the pins
re-verify, and the new merge SHA is explicitly re-ratified — may R5 (authoritative x86)
begin. This smoke never establishes authoritative readiness by itself.
