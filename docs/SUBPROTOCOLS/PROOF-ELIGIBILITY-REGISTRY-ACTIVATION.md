# Proof Eligibility Registry — Activation Readiness (DRAFT, dormant)

Mirrors [`INFERENCE-ATTESTATION-ACTIVATION.md`](./INFERENCE-ATTESTATION-ACTIVATION.md)
and [`EDUCATION-ACTIVATION.md`](./EDUCATION-ACTIVATION.md).
This document **does not set or propose an activation height for any
environment.** The mechanism is specified to ship **dormant**
(`proof_eligibility_enabled_from_height: None`) with **no active registry
records**. For the design/contract, see
[`PROOF-ELIGIBILITY-REGISTRY.md`](./PROOF-ELIGIBILITY-REGISTRY.md).

## Current status (2026-06-24)

- Mechanism: **implemented, dormant, ZERO records.**
  [`crates/primitives/src/proof_eligibility.rs`](../../crates/primitives/src/proof_eligibility.rs)
  (types + resolution helpers + empty `REGISTRY`), gate
  `proof_eligibility_enabled_from_height` in
  [`crates/genesis/src/lib.rs`](../../crates/genesis/src/lib.rs) (default
  `None`), read RPC `sum_getProofEligibilityRegistry` (returns `[]`).
- `Stage11dProductionFixedPointMlp` mainnet eligibility: **REJECTED** at this
  time; no record shipped (see design doc, Decision of record + §deferred).
- Blockers before any record is drafted:
  1. OmniNode delivers the Stage 11d / Stage 14 evidence bundle (real `halo2_version`).
  2. A concrete governance issue + finalized `chain_team_review_ref` exist.
- Production / mainnet default: `proof_eligibility_enabled_from_height: None`
  (dormant). No environment has an activation height set by this PR. The gate has
  **no runtime consumer** in v1 — forward plumbing for a future `Active` path.
- **v1 position:** SUM Chain admits by exact proof-profile identity match only.
  SUM Chain does not verify proof correctness for this profile; OmniNode owns
  proof generation and verification correctness (design doc, O-1 = register-only).

## Explicit non-goals

- No mainnet (or any) activation height is proposed here.
- No active registry record is added.
- No `Stage11dProductionFixedPointMlp` enum variant, verifier, executor,
  mempool, or RPC change is made.

## Pre-activation checklist

No box may be checked until O-1 is answered and the evidence bundle is in hand.

- [ ] **Ownership split confirmed (O-1).** v1 is register-only: the chain admits
      by exact proof-profile identity match and does **not** verify proof
      correctness. Confirm OmniNode agrees in writing that it owns proof
      generation and verification correctness.
- [ ] **Evidence bundle received.** OmniNode Stage 11d / Stage 14 evidence
      delivered to the chain team and attached to the review ref.
- [ ] **Audit bar met.** Register-only (v1): internal review complete *and* the
      record states plainly that the chain does not verify the proof. (The
      verify branch — third-party cryptographer review — applies only to a
      future on-chain-verifier version, out of v1 scope.)
- [ ] **Tuple provenance recorded.** Each hash is either independently
      reproduced by the chain team, or marked
      `accepted by OmniNode attestation, not independently reproduced`.
- [ ] **`chain_team_review_ref` populated.** Non-empty, full-trail
      (`sum-chain#<PR>; governance#<ISSUE>; commit:<SHA>`), covering
      proof-family review + circuit identity + evidence/audit + registry record +
      activation height.
- [ ] **Dormant-default guarded.** Production/testnet genesis files do NOT set
      `proof_eligibility_enabled_from_height` (it stays `None`). An integration
      test enforces this (mirror the Education genesis guard).
- [ ] **Dry-run first.** The tuple's first record is `CandidateRefused`; a
      separate later PR appends an `Active` record superseding it (append-only,
      not an in-place flip).
- [ ] **Regeneration policy wired.** Changing `params.bin`, VK hash, circuit ID,
      Halo2 version, circuit code, backend ID, model format, or model hash
      invalidates the record and requires a fresh registry PR + review ref.

## Activation procedure

Generic template — no environment-specific values filled in. Assumes the
mechanism is implemented and a record is `Active`-ready.

1. Build and deploy the validator binary from the candidate `main` commit to
   every validator in the target environment; verify all report the same commit.
2. Confirm every validator reports the expected pre-activation
   `proof_eligibility_enabled_from_height` (`null`) via `chain_getChainParams`.
3. Choose a future activation height `H`, strictly greater than every
   validator's head, with lead time for params propagation and client updates
   (governance step; not chosen here).
4. Apply the params overlay setting `proof_eligibility_enabled_from_height: Some(H)`
   to every validator before `H`, so all validators agree on the gate state at
   every height (consensus-safe). Confirm via `chain_getChainParams`.
5. From block `H` onward, monitor the metrics below.

## Rollback / abort guidance

Two cases, mirroring the InferenceAttestation readiness package.

**Case A — before height `H`, or before any proof referencing an active record
is admitted.** Remove `proof_eligibility_enabled_from_height` from the overlay
(or set it to a later height) and propagate. No proof has been admitted, so the
abort is effectively free.

**Case B — after the first proof referencing an active record has been admitted.**
As with InferenceAttestation, the current activation gate enables but is not
necessarily consulted after activation by every code path; verify the target
binary's runtime behavior before relying on a "set to far-future height"
rollback. A clean deactivation gate (or per-height "deny new" semantic) would be
a new protocol change, not covered here. For a severe incident, the immediate
lever is operational (validator-side rate-limit, RPC-layer drop, coordinated
downgrade), not protocol.

**Registry-level rollback is append-only.** Withdrawing an active tuple is done
by appending a new superseding record — `Active → CandidateRefused` (re-arm the
dry-run refusal) or `Active → Revoked` — each with its own `state_reason` and
`chain_team_review_ref`. Records are never edited or deleted, so the rollback
itself is part of the auditable history. Appending a `CandidateRefused`/`Revoked`
superseding record is the first lever (it refuses the tuple by construction)
before touching the height gate, which is environment-wide.

## Post-activation monitoring

Recommended starting points; tune against baseline.

- Counts of proofs **refused** for referencing a `CandidateRefused` record —
  expected non-zero during dry-run, expected zero for `Active` records.
- Counts of proofs **admitted** per active record.
- Hash-mismatch refusals (a referenced tuple not matching any active record) —
  spikes usually mean submitter-side drift or a stale OmniNode build.
- `chain_getChainParams.proof_eligibility_enabled_from_height` reachable and
  reporting the expected value from each validator.

## Handoff to OmniNode

After the chain has a `CandidateRefused` registry record and review trail,
OmniNode Stage 11d.3C may mirror or consume that record locally.

## References

- Design / contract: [`PROOF-ELIGIBILITY-REGISTRY.md`](./PROOF-ELIGIBILITY-REGISTRY.md)
- Activation-gate precedent: [`crates/genesis/src/lib.rs:151`](../../crates/genesis/src/lib.rs#L151)
- Readiness-doc precedents: [`INFERENCE-ATTESTATION-ACTIVATION.md`](./INFERENCE-ATTESTATION-ACTIVATION.md),
  [`EDUCATION-ACTIVATION.md`](./EDUCATION-ACTIVATION.md)
- Draft `ProofSystem` enum (doc-only, not chain code):
  [`docs/SRC-80X-81X-DocClass.md`](../SRC-80X-81X-DocClass.md)
