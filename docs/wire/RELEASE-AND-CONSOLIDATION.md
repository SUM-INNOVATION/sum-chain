# Shared-wire consolidation, versioning & release (#117 → pre-#125)

Operational companion to the #117 CONSOLIDATE decision. `crates/sumchain-wire` is the **single
source of truth** for every wire/primitive byte-format; `crates/primitives` (`sumchain-primitives`)
is a re-export hub for above-leaf semantic types (block/receipt/attestation). This document is the
enforced versioning + publish policy and the version-convergence ordering that gates #125.

## Leaf invariant (CI-enforced)

`sumchain-wire` must stay a **pure leaf**: it may depend on external crates only, never on a
workspace-internal crate. Enforced in `rust-ci.yml` (the `sumchain-wire leaf-dependency guard (#117)`
step): `cargo metadata` fails the required `build-test-clippy` check if `sumchain-wire` acquires any
`path` (workspace-internal) dependency.

## Versioning policy (strict semver)

- Previously `sumchain-wire` (`0.3.0`) was versioned ahead of the rest of the workspace
  (`[workspace.package] version = 0.2.0`). As of this change the whole workspace converges on a single
  `0.3.0` line, which simplifies the publish story.
- Any change to enum-variant order, struct field order/width, or the bincode config of a wire type is
  a **breaking** change: it requires a new golden fixture **and** a version bump.
- Byte-freeze guarantees that must be re-run on every wire change (they are the freeze contract):
  - sum-chain `crates/sumchain-wire/tests/{wire_0_2_0_golden,b0_corroboration_0_2_2,tx_strict_decode_0_2_2,beacon_wire_golden}.rs`
  - SNIP `crates/sum-store/tests/{assignment_v2_conformance,wire_equivalence,object_manifest_golden}.rs`

## Publish process (tagged, reviewed)

Formalized in `.github/workflows/publish-wire.yml`:

1. Bump `crates/sumchain-wire/Cargo.toml` version (and, for a coordinated release, `[workspace.package] version`).
2. Merge the bump via normal review.
3. Push a `wire-vX.Y.Z` tag matching the `sumchain-wire` crate version. The workflow verifies
   (`cargo publish --dry-run`) always, and — on a `wire-v*` tag **and** with the owner-provided
   `CARGO_REGISTRY_TOKEN` secret present — publishes to crates.io in dependency order
   (`sumchain-wire`, then `sumchain-primitives`). Publishing remains an **owner** action (the secret).

## Version state + convergence ordering (open risks R1/R2)

Current pins (audit at `main`): in-repo `sumchain-wire`/workspace = **0.3.0** (this change); SNIP
`sum-types`/`sum-store`/`sum-node` pin `sumchain-wire "=0.2.2"`; OmniNode `tools/r0-zkvm-bench` pins
`"=0.2.1"`; OmniNode **production** consumes the pre-split monolith `sumchain-primitives 0.2.0`.

**This change (pre-#125, in-repo only, no publish):**
- Bumps `[workspace.package] version` `0.2.0 → 0.3.0` so a **post-split** `sumchain-primitives` can be
  published as `0.3.0` (resolves R2's semver collision — the pre-split `0.2.0` on crates.io is a
  different, monolithic crate and can never be re-published under the same number).
- Adds the CI leaf-guard and the tagged publish workflow.

**Convergence sequence (after this merges — the publish is owner-run):**
1. Owner publishes `sumchain-wire 0.3.0` (+ post-split `sumchain-primitives 0.3.0`) via the tagged
   workflow.
2. SNIP bumps `sumchain-wire "=0.2.2" → "=0.3.0"`, regenerates its lockfile, and re-runs its
   cross-validation goldens against the published bytes.
3. OmniNode `tools/r0-zkvm-bench` bumps `"=0.2.1" → "=0.3.0"` + lock regen + goldens.
4. OmniNode **production** migrates onto post-split `sumchain-primitives 0.3.0` (the biggest item;
   only possible once step 1 has published a `0.3.0` primitives).

Once steps 1–3 land, the wire source-of-truth is single, leaf-enforced, and exact-pinned across all
three repos — the pre-#125 precondition for the wire-types work.
