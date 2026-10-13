//! #279: `max_contract_deploy_gas` at the block-execution boundary.
//!
//! Dormant. Below the metering gate, or with the ceiling unset, a deploy is
//! bounded by `max_contract_gas` exactly as before the field existed. At and
//! above the gate, with the ceiling set, a deploy may declare up to the
//! ceiling. Calls stay bounded by `max_contract_gas` at every height.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumc_runtime::ContractExecutor;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::contract_deploy_gas_ceiling;

const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "get") (param i32 i32) (result i32) (i32.const 0))
)
"#;

const FEE: u128 = 1_000;
const FUNDS: u128 = 10_000_000;

/// TEST_ONLY: a deploy ceiling twice the default per-transaction ceiling. Not a
/// proposed value.
fn ceiling() -> u64 {
    2 * ChainParams::default().max_contract_gas
}

fn params(gate: Option<u64>, deploy: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_contracts_enabled();
    p.contract_metering_enabled_from_height = gate;
    p.max_contract_deploy_gas = deploy;
    p.validate().expect("fixture is a valid configuration");
    p
}

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

fn deploy_tx(kp: &KeyPair, nonce: u64, gas_limit: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractDeploy(ContractDeployData {
            code: wat::parse_str(WAT).unwrap(),
            init_method: "new".to_string(),
            init_args: vec![],
            value: 0,
            gas_limit,
        }),
    )
}

fn call_tx(kp: &KeyPair, nonce: u64, contract: Address, gas_limit: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractCall(ContractCallData {
            contract,
            method: "get".to_string(),
            args: vec![],
            value: 0,
            gas_limit,
        }),
    )
}

fn deployer() -> KeyPair {
    KeyPair::from_bytes([0x41; 32])
}

/// Execute one block at height 1 on a fresh chain; its receipts' statuses and
/// state root.
fn run(params: ChainParams, txs: Vec<SignedTransaction>) -> (Vec<TxStatus>, Hash) {
    let proposer = KeyPair::from_bytes([0x42; 32]);
    let (_state, db, _d, ex) = setup_with_params(params);
    fund(&db, &deployer(), FUNDS);
    let header = BlockHeader::new(
        Hash::ZERO,
        1,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer.public_key().as_bytes(),
    );
    let blk = Block::new(header, txs);
    let exec = ex.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    (executed.receipts().iter().map(|r| r.status).collect(), root)
}

#[test]
fn the_ceiling_applies_only_where_the_gate_is_open_and_it_is_set() {
    let tx = ChainParams::default().max_contract_gas;
    let p = params(Some(5), Some(ceiling()));
    assert_eq!(contract_deploy_gas_ceiling(&p, 4), tx);
    assert_eq!(contract_deploy_gas_ceiling(&p, 5), ceiling());
    assert_eq!(contract_deploy_gas_ceiling(&p, u64::MAX), ceiling());
    // Gate open, no ceiling: the bound a deploy always had.
    assert_eq!(contract_deploy_gas_ceiling(&params(Some(1), None), 5), tx);
    // No gate at all.
    assert_eq!(contract_deploy_gas_ceiling(&params(None, None), 5), tx);
}

#[test]
fn below_the_gate_a_deploy_is_bounded_as_before() {
    let over = ChainParams::default().max_contract_gas + 1;
    // The gate opens at 5; the block is at 1. The ceiling changes nothing.
    let with_ceiling = run(
        params(Some(5), Some(ceiling())),
        vec![deploy_tx(&deployer(), 0, over)],
    );
    let without = run(params(None, None), vec![deploy_tx(&deployer(), 0, over)]);
    assert_eq!(with_ceiling, without);
    assert_ne!(with_ceiling.0[0], TxStatus::Success);
}

#[test]
fn above_the_gate_a_deploy_may_declare_up_to_the_ceiling() {
    let tx = ChainParams::default().max_contract_gas;
    for gas in [tx + 1, ceiling()] {
        let (statuses, _) = run(
            params(Some(1), Some(ceiling())),
            vec![deploy_tx(&deployer(), 0, gas)],
        );
        assert_eq!(statuses, vec![TxStatus::Success], "declared {gas}");
    }
    // Above the ceiling: refused, as above max_contract_gas before.
    let (statuses, _) = run(
        params(Some(1), Some(ceiling())),
        vec![deploy_tx(&deployer(), 0, ceiling() + 1)],
    );
    assert_ne!(statuses[0], TxStatus::Success);
    // Gate open, no ceiling: max_contract_gas still bounds the deploy.
    let (statuses, _) = run(
        params(Some(1), None),
        vec![deploy_tx(&deployer(), 0, tx + 1)],
    );
    assert_ne!(statuses[0], TxStatus::Success);
}

#[test]
fn a_call_stays_bounded_by_the_per_transaction_ceiling() {
    let tx = ChainParams::default().max_contract_gas;
    let contract = ContractExecutor::compute_address(&deployer().address(), 0);
    let (statuses, _) = run(
        params(Some(1), Some(ceiling())),
        vec![
            deploy_tx(&deployer(), 0, tx),
            call_tx(&deployer(), 1, contract, tx),
            call_tx(&deployer(), 2, contract, tx + 1),
        ],
    );
    assert_eq!(statuses[0], TxStatus::Success);
    assert_eq!(statuses[1], TxStatus::Success);
    assert_ne!(
        statuses[2],
        TxStatus::Success,
        "a call above max_contract_gas"
    );
}
