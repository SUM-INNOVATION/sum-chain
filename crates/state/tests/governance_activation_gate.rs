//! Issue #50, Phase 3a: governance dispatch skeleton behind the P1 gate.
//! Governance is dormant (`governance_enabled_from_height`) and unconfigured
//! (`governance: None`) by default. Every path here is pre-semantic: no fee,
//! no nonce, no state. Governance failure codes are the isolated 300-block.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{GovernanceOperation, GovernanceParams, GovernanceTxData};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};

fn signed(kp: &KeyPair, fee: u128, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn gov_payload(op: GovernanceOperation) -> TxPayload {
    TxPayload::Governance(GovernanceTxData { operation: op, data: vec![] })
}

fn test_gov_params() -> GovernanceParams {
    // Fixture values only — no mainnet defaults.
    GovernanceParams {
        validator_authority_threshold_bps: 6_667,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 0,
    }
}

fn assert_no_mutation(state: &sumchain_state::StateManager, sender: &Address, proposer: &Address) {
    assert_eq!(state.get_balance(sender).unwrap(), 10_000, "balance unchanged");
    assert_eq!(state.get_nonce(sender).unwrap(), 0, "nonce unchanged");
    assert_eq!(state.get_balance(proposer).unwrap(), 0, "proposer not credited");
}

#[test]
fn gate_closed_rejects_300_no_mutation() {
    // v2 enabled but governance dormant (None) and unconfigured.
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, gov_payload(GovernanceOperation::CreateProposal));
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(300)), "gate closed, got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_no_mutation(&state, &sender.address(), &proposer.address());
}

#[test]
fn gate_open_but_params_absent_rejects_301() {
    // Gate open, but no GovernanceParams configured.
    let mut params = ChainParams::with_v2_enabled();
    params.governance_enabled_from_height = Some(0);
    // params.governance stays None.
    let (state, _db, _dir, executor) = setup_with_params(params);
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, gov_payload(GovernanceOperation::CreateProposal));
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(301)), "params absent, got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_no_mutation(&state, &sender.address(), &proposer.address());
}

#[test]
fn gate_open_and_configured_op_unsupported_in_p3a_302() {
    // Gate open AND params configured: P3a implements no lifecycle, so every
    // recognized operation is unsupported (302).
    let mut params = ChainParams::with_v2_enabled();
    params.governance_enabled_from_height = Some(0);
    params.governance = Some(test_gov_params());
    let (state, _db, _dir, executor) = setup_with_params(params);
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    for op in [
        GovernanceOperation::RegisterAsset,
        GovernanceOperation::CreateProposal,
        GovernanceOperation::CastVote,
        GovernanceOperation::ExecuteProposal,
        GovernanceOperation::CancelProposal,
    ] {
        let tx = signed(&sender, 1_000, 0, gov_payload(op));
        let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();
        assert!(matches!(res.status, TxStatus::Failed(302)), "op {:?} => {:?}", op, res.status);
        assert_eq!(res.fee_paid, 0);
    }
    // No path mutated state.
    assert_no_mutation(&state, &sender.address(), &proposer.address());
}

#[test]
fn defaults_leave_governance_dormant_and_unconfigured() {
    let p = ChainParams::default();
    assert_eq!(p.governance_enabled_from_height, None);
    assert!(p.governance.is_none());
}
