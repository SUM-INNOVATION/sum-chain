//! #279: a contract `abort` inside block execution is an ordinary failed
//! transaction, with exactly the receipt, fee, nonce and storage effects of a
//! trapping one — and below the contracts gate it never reaches the runtime.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_storage::{contract_cf_kind, ContractStateDiff};

const WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (import "env" "abort"         (func $abort  (param i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "new_abort") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (call $abort (i32.const 0) (i32.const 1))
    (i32.const 0))
  (func (export "new_unreachable") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (unreachable))
  (func (export "write_then_abort") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (call $abort (i32.const 0) (i32.const 1))
    (i32.const 0))
  (func (export "write_then_unreachable") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (unreachable))
)
"#;

const FEE: u128 = 1_000;
const FUNDS: u128 = 10_000_000;

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn deploy_tx(kp: &KeyPair, nonce: u64, init: &str) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractDeploy(ContractDeployData {
            code: wat::parse_str(WAT).unwrap(),
            init_method: init.to_string(),
            init_args: vec![],
            value: 0,
            gas_limit: 1_000_000,
        }),
    )
}

fn call_tx(kp: &KeyPair, nonce: u64, contract: Address, method: &str) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractCall(ContractCallData {
            contract,
            method: method.to_string(),
            args: vec![],
            value: 0,
            gas_limit: 1_000_000,
        }),
    )
}

fn block(height: u64, proposer: &KeyPair, txs: Vec<SignedTransaction>) -> Block {
    let header = BlockHeader::new(
        Hash::ZERO,
        height,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer.public_key().as_bytes(),
    );
    Block::new(header, txs)
}

fn deployed_address(cd: &ContractStateDiff) -> Address {
    let key = &cd
        .records
        .iter()
        .find(|r| r.cf_kind == contract_cf_kind::CODE)
        .expect("deploy writes code")
        .key;
    let mut a = [0u8; 20];
    a.copy_from_slice(&key[..20]);
    Address::new(a)
}

/// Fixed keys, so independent runs build identical blocks.
fn keys() -> (KeyPair, KeyPair) {
    (
        KeyPair::from_bytes([0x21; 32]),
        KeyPair::from_bytes([0x22; 32]),
    )
}

struct Outcome {
    statuses: Vec<TxStatus>,
    root: Hash,
    storage_records: usize,
    sender_balance: u128,
    sender_nonce: u64,
    proposer_balance: u128,
}

/// Deploy, then call `method`, in one block on a fresh chain with `params`.
fn deploy_and_call(params: ChainParams, method: &str) -> Outcome {
    let (deployer, proposer) = keys();
    let addr = {
        let (_s, db, _d, ex) = setup_with_params(ChainParams::with_contracts_enabled());
        fund(&db, &deployer, FUNDS);
        let exec = ex
            .execute_block(
                &block(1, &proposer, vec![deploy_tx(&deployer, 0, "new")]),
                Hash::ZERO,
                &[],
            )
            .unwrap();
        deployed_address(&exec.into_parts().2)
    };
    run(
        params,
        vec![
            deploy_tx(&deployer, 0, "new"),
            call_tx(&deployer, 1, addr, method),
        ],
    )
}

fn run(params: ChainParams, txs: Vec<SignedTransaction>) -> Outcome {
    let (deployer, proposer) = keys();
    let (state, db, _d, ex) = setup_with_params(params);
    fund(&db, &deployer, FUNDS);
    let mut blk = block(1, &proposer, txs);
    let exec = ex.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let root = exec.computed_root();
    blk.header.state_root = root;
    let (executed, _sd, cd) = exec.into_parts();
    let statuses = executed.receipts().iter().map(|r| r.status).collect();
    let storage_records = cd
        .records
        .iter()
        .filter(|r| r.cf_kind == contract_cf_kind::STORAGE)
        .count();
    executed.accept_produced(&blk).unwrap().publish().unwrap();
    Outcome {
        statuses,
        root,
        storage_records,
        sender_balance: state.get_balance(&deployer.address()).unwrap(),
        sender_nonce: state.get_nonce(&deployer.address()).unwrap(),
        proposer_balance: state.get_balance(&proposer.address()).unwrap(),
    }
}

#[test]
fn an_aborting_call_in_a_block_is_a_failed_transaction_like_a_trap() {
    let aborted = deploy_and_call(ChainParams::with_contracts_enabled(), "write_then_abort");
    let trapped = deploy_and_call(
        ChainParams::with_contracts_enabled(),
        "write_then_unreachable",
    );

    assert_eq!(
        aborted.statuses,
        vec![TxStatus::Success, TxStatus::Failed(5)]
    );
    assert_eq!(aborted.statuses, trapped.statuses);
    assert_eq!(
        aborted.storage_records, 0,
        "the write before abort does not survive"
    );
    // A failed call is still charged: fee to the proposer, nonce advanced.
    assert_eq!(aborted.sender_balance, FUNDS - 2 * FEE);
    assert_eq!(aborted.sender_nonce, 2);
    assert_eq!(aborted.proposer_balance, 2 * FEE);
    // Roots are not compared across the two: the blocks carry different
    // transactions. Every account and contract effect is.
    assert_eq!(
        (
            aborted.sender_balance,
            aborted.sender_nonce,
            aborted.proposer_balance,
            aborted.storage_records
        ),
        (
            trapped.sender_balance,
            trapped.sender_nonce,
            trapped.proposer_balance,
            trapped.storage_records
        ),
        "identical effects to a trapping call"
    );
}

#[test]
fn a_deploy_whose_init_aborts_in_a_block_matches_a_trapping_init() {
    let (deployer, _) = keys();
    let aborted = run(
        ChainParams::with_contracts_enabled(),
        vec![deploy_tx(&deployer, 0, "new_abort")],
    );
    let trapped = run(
        ChainParams::with_contracts_enabled(),
        vec![deploy_tx(&deployer, 0, "new_unreachable")],
    );
    assert_eq!(aborted.statuses, vec![TxStatus::Failed(4)]);
    assert_eq!(aborted.statuses, trapped.statuses);
    assert_eq!(aborted.storage_records, 0);
    assert_eq!(
        (aborted.sender_balance, aborted.sender_nonce),
        (FUNDS - FEE, 1)
    );
    assert_eq!(
        (
            aborted.sender_balance,
            aborted.sender_nonce,
            aborted.proposer_balance
        ),
        (
            trapped.sender_balance,
            trapped.sender_nonce,
            trapped.proposer_balance
        ),
        "identical effects to a trapping init"
    );
}

#[test]
fn an_aborting_block_is_deterministic_across_independent_nodes() {
    let a = deploy_and_call(ChainParams::with_contracts_enabled(), "write_then_abort");
    let b = deploy_and_call(ChainParams::with_contracts_enabled(), "write_then_abort");
    assert_eq!((a.statuses, a.root), (b.statuses, b.root));
}

/// Below the gate the runtime is never entered: the same transactions are
/// rejected free before any WASM runs. This holds with or without the abort
/// fix, which is the point — gate-closed block execution cannot reach abort.
#[test]
fn below_the_contracts_gate_abort_is_unreachable_in_block_execution() {
    let (deployer, _) = keys();
    let closed = ChainParams::with_v2_enabled();
    assert_eq!(closed.contracts_enabled_from_height, None);
    let deploy = run(closed.clone(), vec![deploy_tx(&deployer, 0, "new_abort")]);
    assert_eq!(deploy.statuses, vec![TxStatus::Failed(60)]);
    // Free rejection leaves the nonce at 0, so the call reuses it.
    let call = run(
        closed,
        vec![call_tx(
            &deployer,
            0,
            Address::new([9u8; 20]),
            "write_then_abort",
        )],
    );
    assert_eq!(call.statuses, vec![TxStatus::Failed(60)]);
    assert_eq!(
        (
            call.sender_balance,
            call.sender_nonce,
            call.proposer_balance
        ),
        (FUNDS, 0, 0),
        "rejected free"
    );
}
