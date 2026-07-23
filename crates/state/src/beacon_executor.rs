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
//!    `Failed(BEACON_GATE_CLOSED)` with `fee_paid: 0` and mutates **no** state —
//!    exactly the dormant-deploy semantics of the other `*_enabled_from_height`
//!    gates (Supply, contracts, V2, …).
//!
//! 2. **Gate-open → pure semantic precheck, then FAIL CLOSED for #127.** If a test
//!    (or a future activated chain) opens the gate, [`execute`] runs the pure,
//!    crypto-free semantic checks that are available now — payload decode, the
//!    phase↔variant consistency, the `chain_id` binding, and the finalize
//!    witness's structural canonicality (strictly ascending ⇒ sorted + distinct) —
//!    and then **fails closed** (`Failed(BEACON_CRYPTO_UNAVAILABLE_127)`) because
//!    the crypto and threshold/membership validation that MUST pass before any
//!    beacon state is accepted is not built yet. It never accepts unvalidated
//!    state.
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

use sumchain_genesis::ChainParams;
use sumchain_primitives::beacon_wire::BeaconOperation;
use sumchain_primitives::{BeaconTxData, Hash, TxStatus};

use crate::executor::TxExecutionResult;

// ── Beacon `TxStatus::Failed` reason codes (kept in sync with executor dispatch).
/// Gate closed: `beacon_enabled_from_height` is `None`/in the future. Free reject.
pub const BEACON_GATE_CLOSED: u32 = 400;
/// The carried `BeaconOperation` bytes are undecodable/malformed. Free reject.
pub const BEACON_MALFORMED_PAYLOAD: u32 = 401;
/// The carried op's phase does not match the enclosing `TxPayload` variant
/// (e.g. a signing op inside `BeaconSetup`). Free reject.
pub const BEACON_PHASE_MISMATCH: u32 = 402;
/// The op's `chain_id` does not equal the transaction's `chain_id`. Free reject.
pub const BEACON_CHAIN_ID_MISMATCH: u32 = 403;
/// A `BeaconFinalizeV1` witness is not strictly ascending (⇒ unsorted or has a
/// duplicate). Pure structural canonicality failure. Free reject.
pub const BEACON_WITNESS_NONCANONICAL: u32 = 404;
/// Gate open but the #127 crypto / threshold / membership validation that MUST
/// pass before accepting beacon state is unavailable — FAIL CLOSED. Free reject.
pub const BEACON_CRYPTO_UNAVAILABLE_127: u32 = 405;

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
/// the decoded `BeaconOperation` on success, or a `Failed` reason code.
///
/// This runs only on the gate-open path; the crypto/threshold/membership validation
/// that follows is #127's and currently absent (the caller then fails closed).
pub fn semantic_precheck(
    expected_phase_ordinal: u8,
    tx_chain_id: u64,
    data: &BeaconTxData,
) -> Result<BeaconOperation, u32> {
    // Decode by magic/op-tag (rejects trailing / malformed).
    let op = data
        .decode_operation()
        .map_err(|_| BEACON_MALFORMED_PAYLOAD)?;

    // Phase↔variant consistency: the op's phase ordinal (28/29, via
    // `top_level_txtype`) MUST equal the enclosing `TxPayload` variant's ordinal.
    if op.top_level_txtype() != expected_phase_ordinal {
        return Err(BEACON_PHASE_MISMATCH);
    }

    // Replay binding: the op's `chain_id` MUST equal the transaction's.
    if op.chain_id() != tx_chain_id {
        return Err(BEACON_CHAIN_ID_MISMATCH);
    }

    // Finalize witness structural canonicality (pure): strictly ascending.
    if let BeaconOperation::BeaconFinalize(f) = &op {
        if !is_strictly_ascending(&f.witness) {
            return Err(BEACON_WITNESS_NONCANONICAL);
        }
    }

    Ok(op)
}

/// Execute (accept/reject) a beacon transaction. GATE-CLOSED + FAIL-CLOSED.
///
/// * Gate closed (default) → `Failed(BEACON_GATE_CLOSED)`, `fee_paid: 0`, no state.
/// * Gate open → pure semantic precheck; on failure, the specific `Failed(code)`
///   (free); on success, `Failed(BEACON_CRYPTO_UNAVAILABLE_127)` (free) because the
///   #127 crypto/threshold/membership validation required before accepting state is
///   not available — never accept unvalidated beacon state.
///
/// In all branches `fee_paid` is `0` and **no beacon state is mutated**, so this is
/// side-effect-free until #127 wires the validated acceptance path.
pub fn execute(
    params: &ChainParams,
    block_height: u64,
    tx_hash: Hash,
    tx_chain_id: u64,
    expected_phase_ordinal: u8,
    data: &BeaconTxData,
) -> TxExecutionResult {
    if !beacon_gate_open(params, block_height) {
        return TxExecutionResult {
            tx_hash,
            status: TxStatus::Failed(BEACON_GATE_CLOSED),
            fee_paid: 0,
        };
    }

    // Gate open (only reachable via an in-memory ChainParams; the authoritative
    // genesis loader forbids it until #127). Run the pure semantic precheck.
    if let Err(code) = semantic_precheck(expected_phase_ordinal, tx_chain_id, data) {
        return TxExecutionResult {
            tx_hash,
            status: TxStatus::Failed(code),
            fee_paid: 0,
        };
    }

    // FAIL CLOSED: the #127 crypto + threshold/membership validation that MUST pass
    // before accepting beacon state is not built yet. Reject rather than accept
    // unvalidated state; charge no fee and mutate nothing.
    TxExecutionResult {
        tx_hash,
        status: TxStatus::Failed(BEACON_CRYPTO_UNAVAILABLE_127),
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

    #[test]
    fn gate_closed_rejects_free_no_state() {
        let p = closed_params();
        let r = execute(&p, 100, Hash::hash(b"tx"), 7, 28, &setup_data(7));
        assert_eq!(r.status, TxStatus::Failed(BEACON_GATE_CLOSED));
        assert_eq!(r.fee_paid, 0);
        // Signing phase likewise.
        let r2 = execute(&p, 100, Hash::hash(b"tx2"), 7, 29, &signing_partial_data(7));
        assert_eq!(r2.status, TxStatus::Failed(BEACON_GATE_CLOSED));
        assert_eq!(r2.fee_paid, 0);
    }

    #[test]
    fn gate_open_fails_closed_after_pure_precheck_passes() {
        // Well-formed setup op, phase + chain_id correct → pure precheck PASSES,
        // then FAIL CLOSED on the missing #127 validation. Never Success.
        let p = open_params();
        let r = execute(&p, 0, Hash::hash(b"tx"), 7, 28, &setup_data(7));
        assert_eq!(r.status, TxStatus::Failed(BEACON_CRYPTO_UNAVAILABLE_127));
        assert_eq!(r.fee_paid, 0);
        assert!(!r.status.is_success());
    }

    #[test]
    fn gate_open_rejects_phase_mismatch() {
        // A setup op carried under the signing variant (29) → phase mismatch.
        let p = open_params();
        let r = execute(&p, 0, Hash::hash(b"tx"), 7, 29, &setup_data(7));
        assert_eq!(r.status, TxStatus::Failed(BEACON_PHASE_MISMATCH));
        assert_eq!(r.fee_paid, 0);
    }

    #[test]
    fn gate_open_rejects_chain_id_mismatch() {
        let p = open_params();
        // op chain_id = 7, tx chain_id = 9.
        let r = execute(&p, 0, Hash::hash(b"tx"), 9, 28, &setup_data(7));
        assert_eq!(r.status, TxStatus::Failed(BEACON_CHAIN_ID_MISMATCH));
    }

    #[test]
    fn gate_open_rejects_malformed_payload() {
        let p = open_params();
        let bad = BeaconTxData {
            op_bytes: vec![0xAA, 0xBB, 0xCC],
        };
        let r = execute(&p, 0, Hash::hash(b"tx"), 7, 28, &bad);
        assert_eq!(r.status, TxStatus::Failed(BEACON_MALFORMED_PAYLOAD));
    }

    #[test]
    fn gate_open_rejects_noncanonical_witness() {
        let p = open_params();
        // Non-ascending witness (duplicate / unsorted).
        let dup = finalize_data(7, vec![2, 2]);
        assert_eq!(
            execute(&p, 0, Hash::hash(b"a"), 7, 29, &dup).status,
            TxStatus::Failed(BEACON_WITNESS_NONCANONICAL)
        );
        let unsorted = finalize_data(7, vec![3, 1]);
        assert_eq!(
            execute(&p, 0, Hash::hash(b"b"), 7, 29, &unsorted).status,
            TxStatus::Failed(BEACON_WITNESS_NONCANONICAL)
        );
        // A strictly-ascending witness passes the pure check, then FAIL CLOSED.
        let ok = finalize_data(7, vec![0, 1, 2]);
        assert_eq!(
            execute(&p, 0, Hash::hash(b"c"), 7, 29, &ok).status,
            TxStatus::Failed(BEACON_CRYPTO_UNAVAILABLE_127)
        );
    }
}
