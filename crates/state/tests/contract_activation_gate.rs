//! Issue #25, Set 1: contracts are dormant behind `contracts_enabled_from_height`.
//! Below the gate, `ContractDeploy`/`ContractCall` are rejected free (no fee,
//! no nonce, no state). At/above the gate they are not gate-rejected.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};

fn signed(kp: &KeyPair, fee: u128, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn deploy_payload() -> TxPayload {
    TxPayload::ContractDeploy(ContractDeployData {
        code: vec![0, 1, 2, 3],
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    })
}

fn call_payload() -> TxPayload {
    TxPayload::ContractCall(ContractCallData {
        contract: Address::new([9u8; 20]),
        method: "foo".to_string(),
        args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    })
}

#[test]
fn deploy_rejected_free_when_gate_closed() {
    // v2 enabled but contracts dormant (None).
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, deploy_payload());
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(60)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0, "no fee below the gate");
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10_000, "balance unchanged");
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0, "nonce unchanged");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), 0, "proposer not credited");
}

#[test]
fn call_rejected_free_when_gate_closed() {
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, call_payload());
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();

    assert!(matches!(res.status, TxStatus::Failed(60)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0);
}

#[test]
fn execute_tx_v2_path_also_gated() {
    // Defensive: the (currently unreached) public execute_tx_v2 path must also
    // reject contract txs free when the gate is closed.
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: sender.address(),
        fee: 1_000,
        nonce: 0,
        payload: deploy_payload(),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), sender.private_key());
    let res = executor
        .execute_tx_v2(
            &tx,
            sig.as_bytes(),
            sender.public_key().as_bytes(),
            &proposer.address(),
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(60)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0);
}

#[test]
fn not_gate_rejected_when_enabled() {
    // With the gate open, the contract path runs; the outcome may be success or
    // an execution failure, but it must NOT be the gate rejection Failed(60).
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000);

    let tx = signed(&sender, 1_000, 0, deploy_payload());
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();
    assert!(!matches!(res.status, TxStatus::Failed(60)), "gate should be open");
}
