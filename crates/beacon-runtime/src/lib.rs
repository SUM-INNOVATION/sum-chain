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
//! * **Setup** ([`dkg`]): process `RegisterBeaconKeyV1` (PoP verify, §2.3),
//!   `DkgDealV1` (commitment/carrier validation + §8.4 replay/conflicting-deal
//!   rules), and `DkgComplaintV1`.
//! * **Objective complaint adjudication** ([`dkg::DkgEpoch::adjudicate`]): the four
//!   deterministic verdicts of draft §6.1 — `REJECT_COMPLAINT_MALFORMED`,
//!   `DISQUALIFY(i)`, `SLASH_FALSE_ACCUSER(j)`, `DISQUALIFY_AND_SLASH(i)` — via the
//!   DLEQ (§5) ⇒ ECIES-open (§8) ⇒ Feldman (§6.2) pipeline, idempotent per §6.6.
//! * **QUAL determination** ([`dkg::DkgEpoch::finalize`]): the carrier-free
//!   deterministic state transition of §4.2 — `QUAL` = non-disqualified dealers,
//!   success iff `|QUAL| ≥ Q_dkg`, else **safe-halt**; on success `PK_E = Σ C_{i,0}`.
//! * **Signing** ([`signing`]): derive `vk_j` (§2.4), verify `BeaconPartialV1`
//!   partials, exactly-`T` sorted Lagrange combine to `Sigma_r` (§4.3), verify
//!   `BeaconFinalizeV1`; plus the §12.1 beacon chaining messages ([`wire`]).
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
//! ## Executor integration point (documented, NOT wired — the #164 seam)
//!
//! The #125/#164 beacon executor seam (`crates/state/src/beacon_executor.rs`) is
//! today **fail-closed**: gate-open it runs the crypto-free semantic precheck, then
//! returns `Failed(BEACON_CRYPTO_UNAVAILABLE_127)` because "the #127 crypto +
//! threshold/membership validation that MUST pass before accepting beacon state is
//! not built yet." **This crate is that validation.** When the owner wires it (after
//! audit + ratification), `execute`, on the gate-open path and after the semantic
//! precheck, dispatches the decoded `BeaconOperation` to this runtime, keyed by the
//! epoch's `BeaconParams` + membership snapshot:
//!
//! | `BeaconOperation` variant | Runtime call |
//! |---|---|
//! | `RegisterBeaconKey(k)` | [`dkg::DkgEpoch::register_key`] (signer index, `k`) |
//! | `DkgDeal(d)` | [`dkg::DkgEpoch::submit_deal`] |
//! | `DkgComplaint(c)` | [`dkg::DkgEpoch::apply_complaint`] |
//! | DKG finalization (no carrier) | [`dkg::DkgEpoch::finalize`] at the cutoff height |
//! | `BeaconPartial(p)` | [`signing::QualifiedEpoch::verify_partial_carrier`] |
//! | `BeaconFinalize(f)` | [`signing::QualifiedEpoch::verify_finalize`] |
//!
//! Only on a fully-validating result may the executor mutate beacon state; any error
//! keeps the current fail-closed behaviour (reject, no state, no fee). The seam's
//! `BeaconParams` type and the epoch membership snapshot are the missing runtime
//! inputs the executor must supply — they do not exist in `main` yet, which is the
//! one thing that genuinely needs #164 (the #125 seam) merged before wiring. This
//! crate provides the logic; it deliberately does **not** edit the executor.
//!
//! ## Boundary invariants
//!
//! * The only curve/pairing dependency edge is [`sumchain_beacon_crypto`]; raw
//!   `blstrs`/`blst` types never appear here.
//! * Wire-decode success means only "well-framed bytes"; this runtime performs the
//!   full §2.2 subgroup/infinity, PoP, DLEQ, AEAD, and pairing validation the wire
//!   layer defers (the layer-boundary caveat) **before** any transition is derived.

#![forbid(unsafe_code)]

pub mod dkg;
pub mod params;
pub mod signing;
pub mod wire;

pub use params::BeaconParams;

#[cfg(test)]
mod tests;
