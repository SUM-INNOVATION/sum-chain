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

The smoke drives the **actual production seam functions** (sourced; the Q6 guard prevents
authoritative dispatch) against the **real** candidate builder images + the real
`harness/{sp1,risc0}-verifier-material` and `verifier_fixtures.sh` runners, with a
genuine/externally-supplied Groth16 fixture per candidate (`SP1_G16_FIXTURE`,
`RISC0_G16_FIXTURE`). For each candidate `c ∈ {sp1, risc0}` and `arch=x86_64`:

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
6. **Rejection proofs (must FAIL closed).**
   - Feed the sealed TEST_ONLY aggregate to authoritative finalization
     (`stage6-assemble` → `stage1-ingest`): it MUST refuse (non-`AUTHORITATIVE_STAGE1`
     classification / non-ratified source commit).
   - Downgrade one `Stage5Result` to v1 (drop `schema_version` + the causal fields,
     reinstate `tool_identity_hex`), reseal, re-import: import MUST refuse it as inadequate.
   - Alter a sealed runner lock (or its SDK version/source), reseal, re-import: MUST refuse.

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
