# B0-PRE / B0-FINAL measurement-tooling RETIREMENT (#196)

The B0 measurement phase is **closed**. RISC0 was selected and the official evidence sealed (see
`docs/b0-final/B0-FINAL-CLOSURE.md`). This record retires the measurement tooling on `main`:
**current `main` is deliberately unable to produce a new official B0 measurement.** This is an
ordinary reviewed retirement — **not** an A/B ratification pair, and the historical B15 authority is
**not** re-ratified.

## Historical authority (preserved for the record; NOT live)

These are the historical, now-retired values. They are preserved here for verification of the
already-sealed evidence and **must not** be used to authorize a measurement on current `main`.

| Field | Value |
|---|---|
| Measurement head (where the authority was bound) | `9cccaa5ee6e038fb9dcb45af44ecb3cbdc2f48c6` |
| Measured-source commit | `507281e21e95a6a98e3480e25e12d1baab586e07` |
| Tooling authority (Commit A) | `be3a5cb151b42689b31574691ec1641bb1278bbf` |
| Tooling path-set BLAKE3 | `e17877e38b5ada83f7d84b81bd25be0c3e1cd53e6a1a94fb555140371397a856` |
| B0-PRE spec hash | `e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2` |
| Official deterministic seal (BLAKE3) | `60ace32cc2775fd38c3a4b9ea81f49686121cdd25a38db7a5ca5a0f4580bd600` |
| Durable evidence release (immutable) | `b0-final-evidence-60ace32c` |

The same values are mirrored, non-authoritatively, as `HISTORICAL_*` constants in
`tools/b0-pre-validator/src/tooling_authority.rs`.

## What retirement changed on `main`

1. **Live tooling authority set to `UNBOUND`.** `RATIFIED_MEASUREMENT_TOOLING_COMMIT` and
   `RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3` are both `UNBOUND`, so every consumer that requires a
   bound authority (`verify_tooling_authority`) **fails closed**.
2. **Explicit retirement marker.** `pub const B0_PRE_RETIRED: bool = true;` plus `b0_pre_retired()`
   and `assert_not_retired()` in `tooling_authority.rs`. This is distinct from the pre-binding
   Commit-A `UNBOUND` state — it is terminal.
3. **Production-measurement producers refuse fail-closed.** The shared shell gate
   `require_two_roots` (used by `measure_fragment.sh`, `derive_guest_set.sh`,
   `produce_canonical_sp1_guest.sh`, `produce_measurement_input_authority.sh`) and
   `make_validation_bundle.sh` both refuse with `B0_PRE_RETIRED` on a retired tooling tree.
4. **Whole-tree B15 guard removed.** The `git diff <CommitA>..HEAD == tooling_authority.rs` freeze
   check in `make_validation_bundle.sh` is deleted (it was the guard tracked in #196; it is also
   unreachable once the live authority is `UNBOUND`).
5. **Production-measurement CI workflow disabled.** `.github/workflows/b0-pre.yml` no longer runs the
   venue-script selftest, the real-container seal→import E2E, or the heavyweight provisioning/
   real-backend build steps; it now asserts the retirement marker + fail-closed refusal and keeps the
   frozen tool crates compiling with their unit suites green.

## Verifying the historical measurement (do NOT use current `main`)

Historical B0 evidence is verified from the **tagged historical commit/release**, where the authority
was bound and the whole-tree guard held:

```
git checkout b0-final-evidence-60ace32c    # tag → commit 9cccaa5e
# recompute the seal from the release members and confirm 60ace32c…; run the from-scratch
# independent verifier against the release's real-orchestrator-vector.bin. See B0-FINAL-CLOSURE.md
# and the release assets (manifest + CHECKSUMS + tar).
```

Current `main` will refuse every production-measurement path by design.

## Re-enablement (future)

There is no re-ratification here; `main` stays retired. If a *new* measurement phase is ever needed,
it must stand up its own fresh two-root authority + guard from scratch under a new ratification — it
must not reuse or silently re-bind this retired authority. The historical whole-tree guard's full
retire/retarget for any future b0-pre tooling work is tracked in #196.
