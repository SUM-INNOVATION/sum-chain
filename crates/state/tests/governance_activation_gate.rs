//! Issue #50, Phase 1: governance is dormant behind `governance_enabled_from_height`.
//! Below the gate, `TxPayload::Governance` is rejected free (Failed(80), no fee,
//! no nonce, no state). Phase 1 has no lifecycle, so at/above the gate it is a
//! fail-closed stub (Failed(81)) — still no fee and no state — but it is
//! distinctly NOT the gate rejection. Mirrors the #25 contracts gate tests.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload, TxStatus};

fn signed(kp: &KeyPair, fee: u128, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn gov_payload() -> TxPayload {
    TxPayload::Governance(GovernanceTxData {
        operation: GovernanceOperation::CreateProposal,
        data: vec![],
    })
}

#[test]
fn governance_rejected_free_when_gate_closed() {
    // v2 enabled but governance dormant (None).
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, gov_payload());
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(80)), "gate-closed code, got {:?}", res.status);
    assert_eq!(res.fee_paid, 0, "no fee below the gate");
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10_000, "balance unchanged");
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0, "nonce unchanged");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), 0, "proposer not credited");
}

#[test]
fn governance_gate_open_is_not_the_gate_rejection() {
    // Governance activated from genesis: Phase 1 has no lifecycle yet, so the
    // tx still fails closed (Failed(81)) with no fee/state — but it is NOT the
    // gate rejection Failed(80). This proves the gate opens.
    let mut params = ChainParams::with_v2_enabled();
    params.governance_enabled_from_height = Some(0);
    let (state, _db, _dir, executor) = setup_with_params(params);
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, gov_payload());
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(81)), "gate-open P1 stub, got {:?}", res.status);
    assert!(!matches!(res.status, TxStatus::Failed(80)), "gate should be open");
    // Phase 1 never mutates state, regardless of gate.
    assert_eq!(res.fee_paid, 0);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10_000, "balance unchanged");
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0, "nonce unchanged");
}

#[test]
fn governance_default_params_leave_gate_closed() {
    // Production default: governance_enabled_from_height is None.
    assert_eq!(ChainParams::default().governance_enabled_from_height, None);
}
