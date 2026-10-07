//! #279: a contract call that returns an error inside block execution.
//!
//! Such a call is a failed transaction (`Failed(5)`, fee charged, nonce
//! advanced). Before `contract_error_rollback_enabled_from_height` its staged
//! storage writes stay in the runtime's write cache and the next successful
//! contract call or deploy of the block commits them: they reach contract
//! storage and the state root. At and above the gate they are rolled back.
//!
//! Below the gate (or unset) every outcome here is byte-identical to the
//! unfixed tree: `MAIN` was produced on 8744d861 by this file's ungated half.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_storage::{contract_cf_kind, ContractStateDiff};

/// `write_then_bad_return` stages k -> VAL, then returns a pointer whose
/// length prefix (256) runs past the single page: the runtime returns `Err`.
const WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (data (i32.const 65520) "\00\01\00\00")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "noop") (param i32 i32) (result i32) (i32.const 0))
  (func (export "write_then_bad_return") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 65520))
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
        KeyPair::from_bytes([0x31; 32]),
        KeyPair::from_bytes([0x32; 32]),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    statuses: Vec<TxStatus>,
    root: Hash,
    storage_records: usize,
    sender_balance: u128,
    sender_nonce: u64,
    proposer_balance: u128,
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


/// The contract's address, from a throwaway chain that deploys it first.
fn contract_address() -> Address {
    let (deployer, proposer) = keys();
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
}

/// Deploy; the erroring call; then a successful call.
fn erroring_then_successful_call(params: ChainParams) -> Outcome {
    let (deployer, _) = keys();
    let addr = contract_address();
    run(
        params,
        vec![
            deploy_tx(&deployer, 0, "new"),
            call_tx(&deployer, 1, addr, "write_then_bad_return"),
            call_tx(&deployer, 2, addr, "noop"),
        ],
    )
}

/// Deploy; the erroring call; then a second deploy.
fn erroring_call_then_deploy(params: ChainParams) -> Outcome {
    let (deployer, _) = keys();
    let addr = contract_address();
    run(
        params,
        vec![
            deploy_tx(&deployer, 0, "new"),
            call_tx(&deployer, 1, addr, "write_then_bad_return"),
            deploy_tx(&deployer, 2, "new"),
        ],
    )
}

fn with_gate(gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_contracts_enabled();
    p.contract_error_rollback_enabled_from_height = gate;
    p
}

fn summary(o: &Outcome) -> String {
    format!(
        "statuses={:?} root={} storage_records={} sender_balance={} sender_nonce={} proposer_balance={}",
        o.statuses, o.root, o.storage_records, o.sender_balance, o.sender_nonce, o.proposer_balance
    )
}

/// Produced on 8744d861 (unfixed) by the ungated test below, which prints them.
const MAIN: &[(&str, &str)] = &[
    ("erroring_then_successful_call", "statuses=[Success, Failed(5), Success] root=0x8094e150820fc78ef62de6e6f6cea9ca98cd693aba438ce36bd293c0d2a422e2 storage_records=1 sender_balance=9997000 sender_nonce=3 proposer_balance=3000"),
    ("erroring_call_then_deploy", "statuses=[Success, Failed(5), Success] root=0x3ee7a169985fc47ca615372a872f9e0c6dfcc12a7aab224733ed29ac0e77b884 storage_records=1 sender_balance=9997000 sender_nonce=3 proposer_balance=3000"),
];

#[test]
fn ungated_outcomes_are_byte_identical_to_main() {
    let got = [
        ("erroring_then_successful_call", summary(&erroring_then_successful_call(with_gate(None)))),
        ("erroring_call_then_deploy", summary(&erroring_call_then_deploy(with_gate(None)))),
    ];
    for (name, s) in &got {
        println!("    ({name:?}, {s:?}),");
    }
    for ((name, s), (pname, want)) in got.iter().zip(MAIN) {
        assert_eq!(name, pname);
        assert_eq!(s, want, "{name}");
    }
}

/// The issue, as block execution sees it: the erroring call fails and pays,
/// yet its write reaches contract storage through the next transaction.
#[test]
fn below_the_gate_the_erroring_calls_write_is_committed_by_the_next_one() {
    for o in [
        erroring_then_successful_call(with_gate(None)),
        erroring_call_then_deploy(with_gate(None)),
    ] {
        assert_eq!(o.statuses[1], TxStatus::Failed(5));
        assert_eq!(o.storage_records, 1, "k -> VAL leaked into the block");
    }
}

#[test]
fn at_and_above_the_gate_nothing_of_the_erroring_call_survives() {
    for params in [with_gate(Some(0)), with_gate(Some(1))] {
        let a = erroring_then_successful_call(params.clone());
        let b = erroring_call_then_deploy(params);
        assert_eq!(a.storage_records, 0);
        assert_eq!(b.storage_records, 0);
        // Receipt, fee and nonce of every transaction are unchanged.
        let la = erroring_then_successful_call(with_gate(None));
        let lb = erroring_call_then_deploy(with_gate(None));
        for (fixed, legacy) in [(&a, &la), (&b, &lb)] {
            assert_eq!(fixed.statuses, legacy.statuses);
            assert_eq!(
                (fixed.sender_balance, fixed.sender_nonce, fixed.proposer_balance),
                (legacy.sender_balance, legacy.sender_nonce, legacy.proposer_balance)
            );
            assert_ne!(fixed.root, legacy.root, "the leaked row was in the root");
        }
    }
}

/// The block is at height 1: a gate at 2 has not opened, and the block is
/// executed exactly as with no gate.
#[test]
fn one_block_below_the_gate_is_the_ungated_block() {
    assert_eq!(
        erroring_then_successful_call(with_gate(Some(2))),
        erroring_then_successful_call(with_gate(None))
    );
    assert_eq!(
        erroring_call_then_deploy(with_gate(Some(2))),
        erroring_call_then_deploy(with_gate(None))
    );
}

#[test]
fn the_gated_block_is_deterministic_across_independent_nodes() {
    assert_eq!(
        erroring_then_successful_call(with_gate(Some(1))),
        erroring_then_successful_call(with_gate(Some(1)))
    );
}

#[test]
fn the_gate_is_dormant_by_default() {
    assert_eq!(ChainParams::default().contract_error_rollback_enabled_from_height, None);
    assert_eq!(
        ChainParams::with_contracts_enabled().contract_error_rollback_enabled_from_height,
        None
    );
}
