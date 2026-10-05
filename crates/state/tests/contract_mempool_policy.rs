//! #279 interim mitigation: the node-local contract refusal. Off by default;
//! when on, contract deploys and calls are refused at admission, removed if
//! already held, and never selected for a block. Other transactions are
//! unaffected.

use sumchain_crypto::{sign, KeyPair};
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::{Mempool, MempoolConfig, StateError};

fn signed(kp: &KeyPair, nonce: u64, fee: u128, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: 1,
        from: kp.address(),
        fee,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn deploy() -> TxPayload {
    TxPayload::ContractDeploy(ContractDeployData {
        code: vec![0, 97, 115, 109],
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 21_000,
    })
}

fn call() -> TxPayload {
    TxPayload::ContractCall(ContractCallData {
        contract: Address::new([9u8; 20]),
        method: "m".to_string(),
        args: vec![],
        value: 0,
        gas_limit: 21_000,
    })
}

fn transfer() -> TxPayload {
    TxPayload::Transfer {
        to: Address::new([3u8; 20]),
        amount: 1,
    }
}

#[test]
fn off_by_default_contract_transactions_are_admitted_and_selected() {
    let pool = Mempool::new(MempoolConfig::default());
    assert!(!pool.refuses_contract_transactions());
    let kp = KeyPair::generate();
    pool.add(signed(&kp, 0, 1_000, deploy())).unwrap();
    pool.add(signed(&kp, 1, 1_000, call())).unwrap();
    assert_eq!(pool.select_for_block(10).len(), 2);
}

#[test]
fn on_refuses_contract_transactions_at_admission_and_nothing_else() {
    let pool = Mempool::new(MempoolConfig::default());
    pool.set_refuse_contract_transactions(true);
    let kp = KeyPair::generate();
    for p in [deploy(), call()] {
        assert!(matches!(
            pool.add(signed(&kp, 0, 1_000, p)),
            Err(StateError::ContractTransactionsRefused)
        ));
    }
    let t = signed(&kp, 0, 1_000, transfer());
    pool.add(t.clone()).unwrap();
    assert_eq!(pool.len(), 1);
    let picked = pool.select_for_block(10);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].hash(), t.hash());
}

#[test]
fn enabling_removes_contract_transactions_already_held() {
    let pool = Mempool::new(MempoolConfig::default());
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    pool.add(signed(&a, 0, 5_000, deploy())).unwrap();
    pool.add(signed(&a, 1, 5_000, call())).unwrap();
    let t = signed(&b, 0, 1_000, transfer());
    pool.add(t.clone()).unwrap();

    let removed = pool.set_refuse_contract_transactions(true);
    assert_eq!(removed, 2);
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&t.hash()));
    assert!(
        pool.get_by_sender(&a.address()).is_empty(),
        "sender index cleared"
    );
    let picked = pool.select_for_block(10);
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].hash(), t.hash());
}

#[test]
fn selection_fills_the_block_with_ordinary_transactions() {
    // `max_count` counts transactions actually returned.
    let pool = Mempool::new(MempoolConfig::default());
    let kp = KeyPair::generate();
    for n in 0..5 {
        pool.add(signed(&kp, n, 1_000 + n as u128, transfer()))
            .unwrap();
    }
    pool.set_refuse_contract_transactions(true);
    assert_eq!(pool.select_for_block(3).len(), 3);
}

#[test]
fn disabling_restores_admission() {
    let pool = Mempool::new(MempoolConfig::default());
    pool.set_refuse_contract_transactions(true);
    assert_eq!(pool.set_refuse_contract_transactions(false), 0);
    let kp = KeyPair::generate();
    assert!(pool.add(signed(&kp, 0, 1_000, deploy())).is_ok());
}
