//! BR1 randomness-beacon (#125) execution seam — GATE-CLOSED, FAIL-CLOSED to #127.
//!
//! Owner OPTION B (2026-07) registered the beacon families in the canonical
//! `TxType`/`TxPayload` (`TxType::BeaconSetup` = 28, `TxType::BeaconSigning` = 29;
//! payload = [`sumchain_primitives::BeaconTxData`] wrapping a frozen
//! [`BeaconOperation`] encoding). **Registration authorizes DECODING, not
//! EXECUTION.** This module is the block-application acceptance seam and it is
//! deliberately closed:
//!
//! 1. **Gate-closed (the default) → deterministic free rejection.** The
//!    `beacon_enabled_from_height` activation gate is `None` by default and is
//!    fail-closed in `ChainParams::validate` (it can only be `Some(_)` for an
//!    isolated in-memory `ChainParams`, never through the authoritative genesis
//!    loader, until `BeaconParams`/#127 exists). While closed, [`execute`] returns
//!    the executor's **generic** failure receipt (`Failed(0)`, reused — see
//!    [`BEACON_GENERIC_FAILURE`]) with `fee_paid: 0` and mutates **no** state —
//!    exactly the dormant-deploy semantics of the other `*_enabled_from_height`
//!    gates (Supply, contracts, V2, …). The specific reason is the TYPED
//!    [`BeaconReject`], never a frozen receipt number.
//!
//! 2. **Gate-open → pure semantic precheck, then FAIL CLOSED for #127.** If a test
//!    (or a future activated chain) opens the gate, [`execute`] runs the pure,
//!    crypto-free semantic checks that are available now — payload decode, the
//!    phase↔variant consistency, the `chain_id` binding, and the finalize
//!    witness's structural canonicality (strictly ascending ⇒ sorted + distinct) —
//!    and then **fails closed** (still the generic `Failed(0)`,
//!    [`BeaconReject::CryptoUnavailablePending127`]) because the crypto and
//!    threshold/membership validation that MUST pass before any beacon state is
//!    accepted is not built yet. It never accepts unvalidated state. **No
//!    beacon-specific consensus receipt code is invented or frozen** (Option B
//!    ratified carrier schemas + tx ordinals, not receipt codes).
//!
//! ## Validation deferred to #127 (documented seam — MUST run before acceptance)
//!
//! The following are **NOT** performed here and are the reason the gate-open path
//! fails closed. They require the #127 crypto adapter (`blst`/`arkworks`) and/or a
//! `BeaconParams` + membership-snapshot runtime that do not exist:
//!
//! * BLS12-381 prime-order-subgroup + infinity membership for every G1/G2 field;
//! * `PopVerify` for `RegisterBeaconKeyV1.pop`;
//! * DLEQ (`DkgComplaintV1`) and AEAD/KDF open (`DkgDealV1.ct_ij`) adjudication;
//! * partial-signature and combined-signature pairing verification;
//! * the finalize witness being **exactly the active threshold `T`** and every
//!   index being a **valid membership index** for the epoch (needs `BeaconParams.T`
//!   + the epoch membership snapshot);
//! * key-registration binding to the registered validator identity / epoch window.
//!
//! When #127 lands, its adapter is invoked here (after the pure precheck) and only
//! on full success may beacon state be mutated; until then this seam rejects.

use sumchain_beacon_runtime::{validate_operation, BeaconParams};
use sumchain_genesis::ChainParams;
use sumchain_primitives::beacon_wire::BeaconOperation;
use sumchain_primitives::{BeaconTxData, Hash, TxStatus};

use crate::executor::TxExecutionResult;

// ── Rejection reasons: TYPED, never invented wire receipt codes ────────────────
//
// Option B ratified the carrier schemas + tx ordinals, **not** a beacon
// receipt-code range. Following the C1/#130 precedent (`crate::compute_pool`,
// "Errors (typed; never receipt-code integers) ... the numeric code is a
// frozen-wire concern and is deliberately not encoded here"), beacon rejection
// reasons are a TYPED enum used only internally (logging/testing). At the execution
// boundary EVERY beacon rejection maps to the executor's EXISTING generic failure
// receipt — no beacon-specific consensus number is invented or frozen.

/// The generic executor failure receipt reused for every beacon rejection: the same
/// `TxStatus::Failed(0)` the executor already emits for any otherwise-unmapped
/// failure (`crates/state/src/executor.rs`, the `_ => TxStatus::Failed(0)` arm in
/// `execute_tx`). It renders as the generic `"failed"` (`TxStatus::description`) and
/// freezes NO beacon-specific meaning. **Reused, not invented** — when a
/// receipt-code owner later allocates a beacon range, this single mapping is the
/// only place to refine.
const BEACON_GENERIC_FAILURE: u32 = 0;

/// Typed, crypto-free reason a beacon tx is rejected. **Internal only** — never a
/// wire receipt code (see the note above); all reasons map to
/// [`BEACON_GENERIC_FAILURE`] at the receipt boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconReject {
    /// Activation gate closed (the default) — the subprotocol is dormant.
    GateClosed,
    /// The carried `BeaconOperation` bytes are undecodable/malformed.
    MalformedPayload,
    /// The op's phase does not match the enclosing `TxPayload` variant.
    PhaseMismatch,
    /// The op's `chain_id` does not equal the transaction's.
    ChainIdMismatch,
    /// A `BeaconFinalizeV1` witness is not strictly ascending (unsorted/duplicate).
    WitnessNonCanonical,
    /// Gate open, the pure precheck passed, and the #127 runtime's **stateless**
    /// crypto/structural validation ([`validate_operation`]) REJECTED the carrier
    /// (bad subgroup/infinity point, failing PoP, non-canonical scalar, or an
    /// invalid finalize witness). The runtime is genuinely reached here.
    RuntimeValidationFailed,
    /// Gate open, the pure precheck AND the #127 runtime's stateless validation
    /// passed, but the full STATEFUL adjudication (DLEQ/AEAD vs the on-chain deal,
    /// QUAL, pairing-under-`PK_E`) + persisted epoch/round state are not wired to
    /// live execution yet — FAIL CLOSED (needs a genesis `BeaconParams` + membership
    /// snapshot, which do not exist while the gate is `None`).
    CryptoUnavailablePending127,
}

/// BR1 beacon activation gate. Dormant by default (`None` → never open). Fail-closed
/// in `ChainParams::validate` (blocked on `BeaconParams`/#127); mirrors the other
/// `*_enabled_from_height` gates. When open, execution still fails closed pending
/// #127 (see module docs). No activation height is defined here.
#[inline]
pub fn beacon_gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(params.beacon_enabled_from_height, Some(h) if block_height >= h)
}

/// `true` iff `v` is strictly ascending — which simultaneously proves it is sorted
/// and duplicate-free. The pure structural canonicality check for a
/// `BeaconFinalizeV1` selected-contributor witness (draft §4.1/§4.3 canonical
/// ascending order). The *exactly-`T`* and *membership-valid* parts are deferred to
/// #127 (they need `BeaconParams.T` + the epoch membership snapshot).
fn is_strictly_ascending(v: &[u32]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

/// The pure, crypto-free semantic precheck. Decodes the payload and enforces every
/// rule that needs no external runtime: decode, phase↔variant consistency, the
/// `chain_id` binding, and the finalize witness's structural canonicality. Returns
/// the decoded `BeaconOperation` on success, or the typed [`BeaconReject`] reason.
///
/// This runs only on the gate-open path; the crypto/threshold/membership validation
/// that follows is #127's and currently absent (the caller then fails closed).
pub fn semantic_precheck(
    expected_phase_ordinal: u8,
    tx_chain_id: u64,
    data: &BeaconTxData,
) -> Result<BeaconOperation, BeaconReject> {
    // Decode by magic/op-tag (rejects trailing / malformed).
    let op = data
        .decode_operation()
        .map_err(|_| BeaconReject::MalformedPayload)?;

    // Phase↔variant consistency: the op's phase ordinal (28/29, via
    // `top_level_txtype`) MUST equal the enclosing `TxPayload` variant's ordinal.
    if op.top_level_txtype() != expected_phase_ordinal {
        return Err(BeaconReject::PhaseMismatch);
    }

    // Replay binding: the op's `chain_id` MUST equal the transaction's.
    if op.chain_id() != tx_chain_id {
        return Err(BeaconReject::ChainIdMismatch);
    }

    // Finalize witness structural canonicality (pure): strictly ascending.
    if let BeaconOperation::BeaconFinalize(f) = &op {
        if !is_strictly_ascending(&f.witness) {
            return Err(BeaconReject::WitnessNonCanonical);
        }
    }

    Ok(op)
}

/// Classify WHY a beacon tx is rejected — it always is, until #127. Returns the
/// TYPED [`BeaconReject`]; the wire receipt is always the generic failure. Gate
/// closed (the default) → [`BeaconReject::GateClosed`]. Gate open → the pure
/// [`semantic_precheck`] reason, or [`BeaconReject::CryptoUnavailablePending127`]
/// (fail closed) when the pure checks pass but #127 validation is unavailable.
pub fn classify_reject(
    params: &ChainParams,
    block_height: u64,
    tx_chain_id: u64,
    expected_phase_ordinal: u8,
    data: &BeaconTxData,
) -> BeaconReject {
    if !beacon_gate_open(params, block_height) {
        return BeaconReject::GateClosed;
    }
    // Gate open (only reachable via an in-memory ChainParams; the authoritative
    // genesis loader forbids it until #127).
    match semantic_precheck(expected_phase_ordinal, tx_chain_id, data) {
        Err(reason) => reason,
        // Pure checks pass → REACH the #127 runtime for the stateless crypto/
        // structural validation (real §2.2 subgroup/infinity, PoP pairing, canonical
        // scalars, exactly-T/ascending/membership-bounded witness). This is the
        // vertical connection: the runtime is genuinely invoked here.
        //
        // `BeaconParams::proposed_default()` is a FIXTURE — the authoritative genesis
        // `BeaconParams` surface does not exist yet, and the gate can only be open via
        // an in-memory `ChainParams` (the genesis loader forbids `Some(_)`), so this
        // never runs in production. If/when a genesis surface lands, thread it here.
        Ok(op) => match validate_operation(&BeaconParams::proposed_default(), &op) {
            Err(_) => BeaconReject::RuntimeValidationFailed,
            // Stateless crypto passed; still FAIL CLOSED because the full stateful
            // adjudication + persisted epoch/round state are not wired to live
            // execution yet. Never accept unvalidated beacon state.
            Ok(()) => BeaconReject::CryptoUnavailablePending127,
        },
    }
}

/// Execute (accept/reject) a beacon transaction. GATE-CLOSED + FAIL-CLOSED.
///
/// Every branch REJECTS with the executor's GENERIC failure receipt
/// ([`BEACON_GENERIC_FAILURE`] = `Failed(0)`), `fee_paid: 0`, and **mutates no
/// state**. The specific reason ([`classify_reject`]) is typed and internal — no
/// beacon receipt code is frozen. Side-effect-free until #127 wires a validated
/// acceptance path.
pub fn execute(
    params: &ChainParams,
    block_height: u64,
    tx_hash: Hash,
    tx_chain_id: u64,
    expected_phase_ordinal: u8,
    data: &BeaconTxData,
) -> TxExecutionResult {
    // Classify for diagnostics (typed, internal); the receipt is the generic
    // failure regardless of reason — no invented consensus number.
    let _reason = classify_reject(
        params,
        block_height,
        tx_chain_id,
        expected_phase_ordinal,
        data,
    );
    TxExecutionResult {
        tx_hash,
        status: TxStatus::Failed(BEACON_GENERIC_FAILURE),
        fee_paid: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::beacon_wire::{
        BeaconFinalizeV1, BeaconPartialV1, RegisterBeaconKeyV1, G1_LEN, G2_LEN, POP_LEN,
    };

    fn g1(b: u8) -> [u8; G1_LEN] {
        let mut p = [b; G1_LEN];
        p[0] = 0x80; // compression set, infinity clear
        p
    }
    fn g2(b: u8) -> [u8; G2_LEN] {
        let mut p = [b; G2_LEN];
        p[0] = 0x80;
        p
    }

    fn closed_params() -> ChainParams {
        // Default = beacon gate None (closed).
        ChainParams::default()
    }
    fn open_params() -> ChainParams {
        // In-memory only; the genesis loader would reject this via
        // ChainParams::validate. Used to exercise the gate-open FAIL-CLOSED path.
        ChainParams {
            beacon_enabled_from_height: Some(0),
            ..ChainParams::default()
        }
    }

    fn setup_data(chain_id: u64) -> BeaconTxData {
        let op = BeaconOperation::RegisterBeaconKey(RegisterBeaconKeyV1 {
            chain_id,
            epoch: 1,
            ek_j: g1(0x11),
            pop: [0x22; POP_LEN],
        });
        BeaconTxData::from_operation(&op).unwrap()
    }

    fn signing_partial_data(chain_id: u64) -> BeaconTxData {
        let op = BeaconOperation::BeaconPartial(BeaconPartialV1 {
            chain_id,
            epoch: 1,
            round: 2,
            j: 0,
            sigma_j: g2(0x81),
        });
        BeaconTxData::from_operation(&op).unwrap()
    }

    fn finalize_data(chain_id: u64, witness: Vec<u32>) -> BeaconTxData {
        let op = BeaconOperation::BeaconFinalize(BeaconFinalizeV1 {
            chain_id,
            epoch: 1,
            round: 2,
            sigma_r: g2(0x82),
            witness,
        });
        BeaconTxData::from_operation(&op).unwrap()
    }

    // Every beacon rejection surfaces the SAME generic receipt Failed(0); the
    // TYPED reason is asserted via `classify_reject`/`semantic_precheck`. No beacon
    // receipt code is frozen anywhere.
    const GENERIC: TxStatus = TxStatus::Failed(0);

    #[test]
    fn gate_closed_rejects_free_generic_no_state() {
        let p = closed_params();
        let r = execute(&p, 100, Hash::hash(b"tx"), 7, 28, &setup_data(7));
        assert_eq!(r.status, GENERIC); // reused generic Failed(0), not an invented code
        assert_eq!(r.fee_paid, 0);
        assert_eq!(
            classify_reject(&p, 100, 7, 28, &setup_data(7)),
            BeaconReject::GateClosed
        );
        // Signing phase likewise.
        let r2 = execute(&p, 100, Hash::hash(b"tx2"), 7, 29, &signing_partial_data(7));
        assert_eq!(r2.status, GENERIC);
        assert_eq!(r2.fee_paid, 0);
    }

    #[test]
    fn gate_open_reaches_runtime_and_rejects_fake_points() {
        // Well-framed setup op, phase + chain_id correct → pure precheck PASSES →
        // the #127 runtime is REACHED and rejects the structurally-OK-but-not-a-real-
        // curve-point fixture (`ek_j = g1(0x11)`). Still generic receipt, no state.
        let p = open_params();
        let r = execute(&p, 0, Hash::hash(b"tx"), 7, 28, &setup_data(7));
        assert_eq!(r.status, GENERIC);
        assert_eq!(r.fee_paid, 0);
        assert!(!r.status.is_success());
        assert_eq!(
            classify_reject(&p, 0, 7, 28, &setup_data(7)),
            BeaconReject::RuntimeValidationFailed
        );
        assert!(semantic_precheck(28, 7, &setup_data(7)).is_ok());
    }

    #[test]
    fn gate_open_rejects_phase_mismatch() {
        // A setup op carried under the signing variant (29) → phase mismatch.
        let p = open_params();
        assert_eq!(
            execute(&p, 0, Hash::hash(b"tx"), 7, 29, &setup_data(7)).status,
            GENERIC
        );
        assert_eq!(
            classify_reject(&p, 0, 7, 29, &setup_data(7)),
            BeaconReject::PhaseMismatch
        );
        assert_eq!(
            semantic_precheck(29, 7, &setup_data(7)).unwrap_err(),
            BeaconReject::PhaseMismatch
        );
    }

    #[test]
    fn gate_open_rejects_chain_id_mismatch() {
        let p = open_params();
        // op chain_id = 7, tx chain_id = 9.
        assert_eq!(
            execute(&p, 0, Hash::hash(b"tx"), 9, 28, &setup_data(7)).status,
            GENERIC
        );
        assert_eq!(
            semantic_precheck(28, 9, &setup_data(7)).unwrap_err(),
            BeaconReject::ChainIdMismatch
        );
    }

    #[test]
    fn gate_open_rejects_malformed_payload() {
        let p = open_params();
        let bad = BeaconTxData {
            op_bytes: vec![0xAA, 0xBB, 0xCC],
        };
        assert_eq!(
            execute(&p, 0, Hash::hash(b"tx"), 7, 28, &bad).status,
            GENERIC
        );
        assert_eq!(
            semantic_precheck(28, 7, &bad).unwrap_err(),
            BeaconReject::MalformedPayload
        );
    }

    #[test]
    fn gate_open_rejects_noncanonical_witness() {
        // Non-ascending witness (duplicate / unsorted) → typed WitnessNonCanonical.
        let dup = finalize_data(7, vec![2, 2]);
        assert_eq!(
            semantic_precheck(29, 7, &dup).unwrap_err(),
            BeaconReject::WitnessNonCanonical
        );
        let unsorted = finalize_data(7, vec![3, 1]);
        assert_eq!(
            semantic_precheck(29, 7, &unsorted).unwrap_err(),
            BeaconReject::WitnessNonCanonical
        );
        // A strictly-ascending witness passes the pure precheck; the #127 runtime is
        // then reached and rejects it (fixture `sigma_r`/witness are not real, and
        // len 3 != fixture T=2), still with the generic receipt.
        let ok = finalize_data(7, vec![0, 1, 2]);
        assert!(semantic_precheck(29, 7, &ok).is_ok());
        let p = open_params();
        assert_eq!(execute(&p, 0, Hash::hash(b"c"), 7, 29, &ok).status, GENERIC);
        assert_eq!(
            classify_reject(&p, 0, 7, 29, &ok),
            BeaconReject::RuntimeValidationFailed
        );
    }

    #[test]
    fn gate_open_reaches_runtime_and_fails_closed_on_valid_carrier() {
        // Build a REAL registration (valid EK_j = g1^{ek}, valid PoP) with the #127
        // crypto adapter, so the runtime's stateless validation PASSES — proving the
        // seam is vertically connected to the runtime. The seam then STILL fails
        // closed (stateful adjudication + persistence not wired), with the generic
        // receipt and no state.
        use sumchain_beacon_crypto::SecretScalar;
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 7; // a small canonical scalar (< r)
        let sk = SecretScalar::from_bytes_le(&sk_bytes).unwrap();
        let reg = RegisterBeaconKeyV1 {
            chain_id: 7,
            epoch: 1,
            ek_j: sk.public_g1().to_compressed(),
            pop: sk.pop_prove().to_compressed(),
        };
        let data = BeaconTxData::from_operation(&BeaconOperation::RegisterBeaconKey(reg)).unwrap();

        let p = open_params();
        // The runtime validated the real crypto OK, yet the seam fails closed pending
        // the stateful path — the vertical connection is exercised, state stays dormant.
        assert_eq!(
            classify_reject(&p, 0, 7, 28, &data),
            BeaconReject::CryptoUnavailablePending127
        );
        let r = execute(&p, 0, Hash::hash(b"tx"), 7, 28, &data);
        assert_eq!(r.status, GENERIC);
        assert_eq!(r.fee_paid, 0);
        assert!(!r.status.is_success());
    }

    #[test]
    fn no_beacon_specific_receipt_code_is_frozen() {
        // Reuse assertion: the generic failure code is the executor's existing
        // Failed(0), which renders as the generic "failed" — never a beacon number.
        assert_eq!(BEACON_GENERIC_FAILURE, 0);
        assert_eq!(
            TxStatus::Failed(BEACON_GENERIC_FAILURE).description(),
            "failed"
        );
    }
}
