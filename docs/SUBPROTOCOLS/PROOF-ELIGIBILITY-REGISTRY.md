# Proof Eligibility Registry — Design (DRAFT, dormant)

**Status: DRAFT design. No mechanism is implemented in chain code, and no
registry record is approved.** This document specifies a *dormant* Proof
Eligibility Registry so that adding a proof system to mainnet is a reviewable,
governed, append-only act rather than an ad-hoc code change. It exists because
OmniNode requested chain-team/governance sign-off for
`ProofSystem::Stage11dProductionFixedPointMlp`, which the chain cannot grant
today: there is no registry, no such proof system, no verification path, and no
`chain_team_review_ref` convention in this repo. (The only existing `ProofSystem`
reference is a draft enum in [`docs/SRC-80X-81X-DocClass.md`](../SRC-80X-81X-DocClass.md),
not chain code.)

This is the *contract/design* doc. Operational activation lives in
[`PROOF-ELIGIBILITY-REGISTRY-ACTIVATION.md`](./PROOF-ELIGIBILITY-REGISTRY-ACTIVATION.md).
It mirrors the dormant-by-default discipline of the
[`InferenceAttestation`](./INFERENCE-ATTESTATION.md) subprotocol and the
Education-LMS suite.

## Decision of record (2026-06-23)

Mainnet eligibility for `Stage11dProductionFixedPointMlp` is **REJECTED at this
time.** Reason: nothing enforceable exists in chain code. What is approved is
*building this dormant registry mechanism* — with **no active records** — and
revisiting the specific proof system only after two blockers clear:

1. OmniNode delivers the Stage 11d / Stage 14 evidence bundle (it lives in the
   OmniNode repo, not here).
2. OmniNode confirms the **ownership split**: does SUM Chain *verify* proofs, or
   does it only *register identity hashes* and leave verification to OmniNode?
   This single answer determines the size of the audit bar and the verification
   code path (see [Open question O-1](#open-question-o-1--verify-vs-register)).

## What the mechanism is

A small, governed Proof Eligibility Registry of proof systems that are eligible
to be referenced on mainnet. Each record is added by an explicit registry PR
carrying a review trail. The registry is **append-only and dormant by default**:
shipping the mechanism with zero records changes no runtime behavior. Eligibility
is never changed by editing or deleting a record — every transition is a new
superseding record (see [§state model](#state-model)).

### Registry record schema (proposed)

One record per governance act. All fields required and non-empty unless typed
`Option`. The registry is **append-only**: a record is never edited or deleted.
A proof system's *current* eligibility is the latest (highest `entry_id`,
equivalently the non-superseded) record for its identity tuple.

| Field | Type | Notes |
|---|---|---|
| `entry_id` | monotonic id | unique per record; identifies this record for superseding |
| `supersedes_entry_id` | `Option<id>` | `Some(prev)` when this record replaces an earlier one for the same tuple; `None` for the first record |
| `proof_system` | enum variant | e.g. `Stage11dProductionFixedPointMlp` (the variant does not exist yet) |
| `backend_id` | string | e.g. `production-fixedpoint-mlp-v1` |
| `model_format` | string | e.g. `ProductionFixedPointMlp` |
| `circuit_id_hex` | 32-byte hex | circuit identity |
| `model_hash` | 32-byte hex | model identity |
| `verification_key_hash_hex` | 32-byte hex | VK identity |
| `halo2_version` | string | pinned; part of the identity per [§regeneration](#regeneration-policy-q8) |
| `eligibility_state` | enum | `CandidateRefused` (dry-run) \| `Active` \| `Revoked`; see [§state model](#state-model) |
| `state_reason` | string | human-readable reason for this record's state (e.g. "dry-run", "activation", "rollback: incident #…") |
| `chain_team_review_ref` | string, non-empty | full review trail for *this record*, see [§review-ref](#review-ref-scope-q7) |

(`entry_id` / `supersedes_entry_id` are the record identifiers — "entry" here is
the record id, not a separate concept.) The exact Rust placement (likely a
`proof_eligibility` module in `crates/primitives`, mirroring
`inference_attestation.rs`) is deferred to implementation, pending O-1.

### State model

The registry is append-only; **eligibility never changes by mutating or
deleting a record.** Every transition is a *new* record that supersedes the
prior one for the same identity tuple, carries its own
`chain_team_review_ref`, and sets `supersedes_entry_id` to the record it
replaces. Three states:

- `CandidateRefused` — dry-run. The tuple is observable as a candidate but
  proofs referencing it are **refused**. This is the first record for any tuple.
- `Active` — proofs referencing the tuple are admitted (subject to O-1).
- `Revoked` — eligibility withdrawn; proofs referencing the tuple are refused.
  Terminal for that tuple unless a later record re-establishes it (which is a
  fresh review).

Allowed transitions (each = one superseding record + its own review PR):
`CandidateRefused → Active`, `Active → CandidateRefused`,
`Active → Revoked`, `CandidateRefused → Revoked`. There is no in-place edit and
no deletion, so the full governance history of a tuple is reconstructable from
the record chain.

## Per-question design positions

These map 1:1 to OmniNode's nine sign-off questions.

### 1. Mainnet eligibility
**Rejected now.** Approve the dormant mechanism only; the live record is blocked
on the two items above.

### 2. Tuple sign-off
Do **not** sign off the cited hashes blindly. Each record must note one of:
- **independently reproduced** by the chain team (preferred if chain verifies), or
- **`accepted by OmniNode attestation, not independently reproduced`** — stated
  in plain text in the record and the review ref.

The cited tuple (recorded here for the future review, **not approved**):
- `proof_system`: `Stage11dProductionFixedPointMlp`
- `backend_id`: `production-fixedpoint-mlp-v1`
- `model_format`: `ProductionFixedPointMlp`
- `circuit_id_hex`: `593d027df3778bc582f9ec40bf453e757a1be6a9b6961243f2dfdf38fb4ea95d`
- `model_hash`: `1c95eea59ab7fe811f1a3c668798221577225c917846888a803b939f9cbda741`
- `verification_key_hash_hex`: `2ec18faed223a28a23155492459c507a2672b9ff495c1df566103a19638655a9`

### 3. `chain_team_review_ref`
Canonical format: `sum-chain#<PR>; governance#<ISSUE>; commit:<SHA>`. A signed
review artifact may be appended later; the GitHub PR + issue trail is the
lowest-friction auditable baseline.

### 4. Evidence / audit bar
Require the OmniNode Stage 11d/14 evidence bundle first. Then:
- if **chain verifies proofs** → third-party cryptographer review required
  before mainnet;
- if **chain only registers identity hashes** → internal review may suffice,
  but the record and review ref must state plainly that *the chain does not
  verify the proof*.

### 5. Activation semantics
Reuse the genesis height-gate pattern: `proof_eligibility_enabled_from_height:
Option<u64>`, `#[serde(default)]` = `None` (dormant forever until set). This
mirrors `omninode_enabled_from_height` and `education_enabled_from_height`
([`crates/genesis/src/lib.rs:151`](../../crates/genesis/src/lib.rs#L151)).
**Not** "merge = active."

### 6. Emergency rollback
Required, committed with the activating PR. Rollback is **append-only**: it adds
a new superseding record (`Active → CandidateRefused` or `Active → Revoked`)
with its own `state_reason` and `chain_team_review_ref` — never a deletion or
in-place edit. See
[`PROOF-ELIGIBILITY-REGISTRY-ACTIVATION.md`](./PROOF-ELIGIBILITY-REGISTRY-ACTIVATION.md).

### 7. Review-ref scope (Q7)
**Full trail**, not activation-only. `chain_team_review_ref` must cover:
proof-family review · circuit-identity tuple sign-off · evidence/audit result ·
the registry record · the activation height.

### 8. Regeneration policy (Q8)
Any change invalidates the record. A change to `params.bin`,
`verification_key_hash_hex`, `circuit_id_hex`, `halo2_version`, circuit code,
`backend_id`, `model_format`, or `model_hash` makes the current record
automatically invalid. Because a regenerated artifact is a *different identity
tuple*, re-eligibility is a brand-new record (a fresh registry PR and a fresh
`chain_team_review_ref`) — not a superseding record of the old tuple, and never
an in-place edit.

### 9. Dry-run / observability (Q9)
Yes. The first record for a tuple is `eligibility_state: CandidateRefused`: the
tuple is logged as a candidate and observable, but proofs referencing it are
still **refused**. Activation is a later, separate PR that appends a new
`Active` record superseding the dry-run one (not an in-place flip). This follows
the repo's dormant-by-default pattern and yields monitoring data before real
activation.

## Open question O-1 — verify vs. register

**Blocking, owned by OmniNode.** Until answered, the verification code path is
unspecified:
- **Verify:** chain links a verifier for the proof system; record hashes gate a
  real on-chain verification. Heavy; needs third-party crypto audit.
- **Register-only:** chain stores the identity tuple and refuses/admits by hash
  match only; OmniNode owns verification. Light; internal review may suffice.

The schema above supports both; the executor/verifier wiring does not exist and
will be designed once O-1 is answered.

## Non-goals

- No active registry record in this PR.
- No `Stage11dProductionFixedPointMlp` enum variant or verifier in this PR.
- No genesis code change in this PR (the gate field is *specified* here for
  reviewer approval, added in the implementation PR).
- No change to existing subprotocols, executor, mempool, or RPC.
