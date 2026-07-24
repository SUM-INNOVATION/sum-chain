//! # SUM Chain BR1 Beacon Runtime (issue #127) — GATE-CLOSED, NOT ACTIVATED
//!
//! The **gate-closed BR1 randomness-beacon runtime / state machine**: the epoch
//! DKG + chained threshold-BLS lifecycle from `BR1-BEACON-SECURITY-SPEC-DRAFT.md`,
//! built as a self-contained workspace **leaf** over the
//! [`sumchain_beacon_crypto`] adapter (which confines `blstrs`/`blst`) and the
//! merged `sumchain_wire::beacon_wire` carriers. It is the validation + transition
//! logic the beacon executor seam will invoke **once the beacon gate opens**; under
//! the default configuration it activates nothing.
//!
//! ## What it implements
//!
//! * **Validated parameters** ([`params::BeaconParams`]): injected from authoritative
//!   config, with the ratified §7.4 inequalities enforced on construction; the
//!   proposed profile is a test fixture only, never frozen behavior.
//! * **Authenticated context** ([`context`]): every transition takes an
//!   [`context::ExecContext`] (signer identity, epoch membership snapshot, phase,
//!   cutoffs) and enforces the actor bindings #164 deferred (registrant ↔ `j`,
//!   dealer ↔ `i`, complainant ↔ `j`, partial signer ↔ `j`, indices `< n`, cutoffs).
//! * **Setup** ([`dkg`]): `RegisterBeaconKeyV1` (PoP verify §2.3; replay vs
//!   equivocation distinguished with retained evidence), `DkgDealV1` (count `== T`,
//!   membership, identical-commitments-across-recipients, §8.4 replay/conflict with
//!   retained evidence), and `DkgComplaintV1`.
//! * **Objective complaint adjudication** ([`dkg::DkgEpoch::adjudicate`]): the four
//!   deterministic verdicts of draft §6.1 via the DLEQ (§5) ⇒ ECIES-open (§8) ⇒
//!   Feldman (§6.2) pipeline, idempotent per §6.6.
//! * **QUAL determination** ([`dkg::DkgEpoch::finalize`]): the carrier-free
//!   deterministic state transition of §4.2 — success iff `|QUAL| ≥ Q_dkg`, else
//!   **safe-halt**; on success `PK_E = Σ C_{i,0}`.
//! * **Signing** ([`signing`]): derive `vk_j` (§2.4), verify partials, exactly-`T`
//!   sorted Lagrange combine to `Σ_r` (§4.3), verify `BeaconFinalizeV1`.
//! * **Chained-round state machine** ([`rounds::BeaconChain`]): GENESIS/ROUND/OUT
//!   domains + chained `Σ_prev` (§12.1), monotonic round progression, partial
//!   replay/conflict, output verification + replay separation, and reorg restoration
//!   of prior rounds / finalized signatures (§10).
//!
//! ## GATE-CLOSED — no activation, and activation additionally requires AUDIT
//!
//! This crate performs **no state mutation** on chain and requires **no activation**
//! under the default config:
//!
//! * It is a workspace **leaf** — **no production crate depends on it** (proven by
//!   `cargo metadata`; the same stance as [`sumchain_beacon_crypto`]). It cannot be
//!   on any consensus, mempool, or block-application path.
//! * It defines **no activation height**, invents **no** `beacon_enabled_from_height`
//!   value, registers **no** `TxType`/`TxPayload`, and flips **no** genesis gate. The
//!   beacon activation gate remains `None` (dormant) — see
//!   `crates/state/src/beacon_executor.rs` in the #125 seam.
//! * Its methods mutate only a caller-held in-memory epoch object ([`dkg::DkgEpoch`]);
//!   they are pure functions of already-accepted on-chain data plus the crypto
//!   adapter. There is no clock and no RNG.
//!
//! ### Activation additionally requires an INDEPENDENT CRYPTOGRAPHIC AUDIT
//!
//! Per the security-design draft (status header, §13, §17), the on-chain DKG,
//! complaint adjudication, and threshold combine are BR1-original compositions and
//! are an **activation blocker**: *an independent cryptographic audit must pass
//! before any implementation is activated* (`beacon_enabled_from_height = None` until
//! then). **This runtime being complete does NOT authorize activation.** Completeness
//! and audit are separate gates; only the owner, after an independent audit, may set
//! an activation height — and that decision lives in genesis/params, never here.
//! Additionally, the parameter set, DKG/ECIES/DLEQ/beacon layouts, and ciphersuite
//! choices this runtime exercises are (except `G_enc = G1` and K-rotate) **PROPOSED —
//! OWNER DECISION, not ratified** (draft §16.3); their ratification is a further
//! prerequisite.
//!
//! ## Executor integration (vertically connected — finding 7)
//!
//! The beacon executor seam (`crates/state/src/beacon_executor.rs`) reaches this
//! runtime on the gate-open path: after the crypto-free semantic precheck it invokes
//! [`validate_operation`] (this crate) to run the §2.2 subgroup/infinity, PoP, DLEQ,
//! AEAD, and pairing validation the seam documented as deferred. Because the beacon
//! activation gate is `None` by default (dormant, fail-closed in
//! `ChainParams::validate`), the runtime is never reached in production and every
//! beacon tx still rejects with the generic `Failed(0)` and mutates no state —
//! byte/state-identical to before. The persisted epoch/round state
//! (`crates/state/src/beacon_store.rs`) follows the #163 C1 pattern: a domain-versioned
//! `state_digest` folded into `compute_block_state_root` **only** when the gate is
//! open (no-op under `None`), and a `stage_block_revert` composed into the unified
//! atomic reorg batch (`revert_block_state_diffs`). Full live per-block epoch-state
//! mutation additionally needs a genesis `BeaconParams` + membership-snapshot source,
//! which do not exist yet (the gate stays closed until they — and an audit — do).
//!
//! ## Boundary invariants
//!
//! * The only curve/pairing dependency edge is [`sumchain_beacon_crypto`]; raw
//!   `blstrs`/`blst` types never appear here.
//! * Wire-decode success means only "well-framed bytes"; this runtime performs the
//!   full §2.2 subgroup/infinity, PoP, DLEQ, AEAD, and pairing validation the wire
//!   layer defers (the layer-boundary caveat) **before** any transition is derived.

#![forbid(unsafe_code)]

pub mod context;
pub mod dkg;
pub mod params;
pub mod rounds;
pub mod signing;
pub mod validate;
pub mod wire;

pub use context::{BeaconPhase, EpochMembership, ExecContext, ValidatorId};
pub use params::BeaconParams;
pub use validate::{validate_operation, ValidationError};

#[cfg(test)]
mod tests;
