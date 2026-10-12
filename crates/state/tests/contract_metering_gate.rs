//! #279: `contract_metering_enabled_from_height` and `max_block_contract_gas`
//! at the block-execution boundary.
//!
//! Below the gate (or with it unset) a block executes exactly as it did before
//! the gate existed — same receipts, same root, same effects. At the gate the
//! same block runs on the metered engine: a non-terminating init or call fails
//! with today's failure semantics (Failed(4)/Failed(5), fee charged, nonce
//! advanced, staged writes rolled back). The block budget is checked over
//! declared limits only.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumc_runtime::{metering, ContractExecutor, ExecutionMode, LocalExecutionLimits};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, GenesisError};
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload,
    TxStatus,
};
use sumchain_state::{
    block_contract_gas_budget, check_block_contract_gas, contract_execution_mode,
    select_within_block_contract_gas, ContractExecutorState,
};
use sumchain_storage::contract_cf_kind;

const WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
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
  (func (export "new_forever") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0))
  (func (export "put") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 0))
  (func (export "put_then_forever") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (loop $l (br $l))
    (i32.const 0))
  (func (export "forever") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0))
  ;; ten million iterations: finite, so it can be run below the gate, where
  ;; nothing bounds it, under the smallest admissible gas limit
  (func (export "spin_10m") (param i32 i32) (result i32)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 10000000))))
    (i32.const 0))
)
"#;

const FEE: u128 = 1_000;
const FUNDS: u128 = 10_000_000;

fn params(gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_contracts_enabled();
    p.contract_metering_enabled_from_height = gate;
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

fn deploy_tx(kp: &KeyPair, nonce: u64, init: &str, gas_limit: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractDeploy(ContractDeployData {
            code: wat::parse_str(WAT).unwrap(),
            init_method: init.to_string(),
            init_args: vec![],
            value: 0,
            gas_limit,
        }),
    )
}

fn call_tx(kp: &KeyPair, nonce: u64, contract: Address, method: &str, gas_limit: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractCall(ContractCallData {
            contract,
            method: method.to_string(),
            args: vec![],
            value: 0,
            gas_limit,
        }),
    )
}

fn keys() -> (KeyPair, KeyPair) {
    (KeyPair::from_bytes([0x31; 32]), KeyPair::from_bytes([0x32; 32]))
}

/// The address the deployer's nonce-0 deploy lands at.
fn first_contract(deployer: &KeyPair) -> Address {
    ContractExecutor::compute_address(&deployer.address(), 0)
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    receipts: Vec<Receipt>,
    root: Hash,
    code_records: usize,
    storage_records: usize,
    sender_balance: u128,
    sender_nonce: u64,
    proposer_balance: u128,
}

impl Outcome {
    fn statuses(&self) -> Vec<TxStatus> {
        self.receipts.iter().map(|r| r.status).collect()
    }
}

/// Execute and publish one block at height 1 on a fresh chain.
fn run(params: ChainParams, txs: Vec<SignedTransaction>) -> Outcome {
    let (deployer, proposer) = keys();
    let (state, db, _d, ex) = setup_with_params(params);
    fund(&db, &deployer, FUNDS);
    let header = BlockHeader::new(
        Hash::ZERO,
        1,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer.public_key().as_bytes(),
    );
    let mut blk = Block::new(header, txs);
    let exec = ex.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let root = exec.computed_root();
    blk.header.state_root = root;
    let (executed, _sd, cd) = exec.into_parts();
    let receipts = executed.receipts().to_vec();
    let count = |kind| cd.records.iter().filter(|r| r.cf_kind == kind).count();
    let (code_records, storage_records) =
        (count(contract_cf_kind::CODE), count(contract_cf_kind::STORAGE));
    executed.accept_produced(&blk).unwrap().publish().unwrap();
    Outcome {
        receipts,
        root,
        code_records,
        storage_records,
        sender_balance: state.get_balance(&deployer.address()).unwrap(),
        sender_nonce: state.get_nonce(&deployer.address()).unwrap(),
        proposer_balance: state.get_balance(&proposer.address()).unwrap(),
    }
}

/// Deploy, write, then ten million iterations under the smallest admissible
/// gas limit.
fn mixed_block() -> Vec<SignedTransaction> {
    let (deployer, _) = keys();
    let addr = first_contract(&deployer);
    let min = ChainParams::default().min_contract_gas;
    vec![
        deploy_tx(&deployer, 0, "new", 1_000_000),
        call_tx(&deployer, 1, addr, "put", 1_000_000),
        call_tx(&deployer, 2, addr, "spin_10m", min),
    ]
}

#[test]
fn below_the_gate_a_block_executes_exactly_as_with_no_gate() {
    let today = run(params(None), mixed_block());
    // The unbounded baseline, unchanged: ten million iterations under the
    // minimum gas limit succeed, because instructions are not charged.
    assert_eq!(
        today.statuses(),
        vec![TxStatus::Success, TxStatus::Success, TxStatus::Success]
    );
    assert_eq!(today.storage_records, 1);
    for gate in [Some(2), Some(1_000_000), Some(u64::MAX)] {
        assert_eq!(run(params(gate), mixed_block()), today, "gate {gate:?}");
    }
}

#[test]
fn at_the_gate_height_the_same_block_is_metered() {
    // Height 1 is h-1 for a gate at 2, and h for a gate at 1.
    let below = run(params(Some(2)), mixed_block());
    let at = run(params(Some(1)), mixed_block());
    assert_eq!(
        below.statuses(),
        vec![TxStatus::Success, TxStatus::Success, TxStatus::Success]
    );
    assert_eq!(
        at.statuses(),
        vec![TxStatus::Success, TxStatus::Success, TxStatus::Failed(5)],
        "the unbounded loop runs out of gas once metered"
    );
    assert_ne!(below.root, at.root);
    // Fees and nonces are unchanged by metering: every transaction pays.
    assert_eq!((at.sender_balance, at.sender_nonce), (FUNDS - 3 * FEE, 3));
    assert_eq!(at.proposer_balance, 3 * FEE);
    assert_eq!(at.storage_records, 1, "the successful write still lands");

    assert_eq!(contract_execution_mode(&params(Some(2)), 1), sumc_runtime::ExecutionMode::Unmetered);
    assert_eq!(
        contract_execution_mode(&params(Some(1)), 1),
        sumc_runtime::ExecutionMode::MeteredV1Provisional
    );
    assert_eq!(contract_execution_mode(&params(None), u64::MAX), sumc_runtime::ExecutionMode::Unmetered);
}

#[test]
fn a_non_terminating_init_fails_the_deploy_with_todays_failure_semantics() {
    let (deployer, _) = keys();
    let block = || vec![deploy_tx(&deployer, 0, "new_forever", 1_000_000)];
    let a = run(params(Some(1)), block());
    assert_eq!(a.statuses(), vec![TxStatus::Failed(4)]);
    assert_eq!(a.code_records, 0, "no code row for a failed deploy");
    assert_eq!((a.sender_balance, a.sender_nonce), (FUNDS - FEE, 1));
    assert_eq!(a.proposer_balance, FEE);
    assert_eq!(a, run(params(Some(1)), block()), "deterministic");
}

#[test]
fn a_non_terminating_call_fails_and_rolls_its_writes_back() {
    let (deployer, _) = keys();
    let addr = first_contract(&deployer);
    let block = |method: &str| {
        vec![
            deploy_tx(&deployer, 0, "new", 1_000_000),
            call_tx(&deployer, 1, addr, method, 1_000_000),
        ]
    };
    for method in ["forever", "put_then_forever"] {
        let a = run(params(Some(1)), block(method));
        assert_eq!(a.statuses(), vec![TxStatus::Success, TxStatus::Failed(5)], "{method}");
        assert_eq!(a.storage_records, 0, "{method}: staged write rolled back");
        assert_eq!((a.sender_balance, a.sender_nonce), (FUNDS - 2 * FEE, 2));
        assert_eq!(a, run(params(Some(1)), block(method)), "{method}: deterministic");
    }
}

// ── block budget over declared limits ───────────────────────────────────────

/// A budget fixture that is a VALID configuration: the per-transaction
/// ceiling is lowered to the budget where the budget is below the default.
fn budget_params(gate: Option<u64>, budget: Option<u64>) -> ChainParams {
    let mut p = params(gate);
    p.max_block_contract_gas = budget;
    if let Some(b) = budget {
        p.max_contract_gas = p.max_contract_gas.min(b);
    }
    p.validate().expect("fixture is a valid configuration");
    p
}

fn declared(kp: &KeyPair, nonce: u64, gas_limit: u64) -> SignedTransaction {
    call_tx(kp, nonce, Address::new([9u8; 20]), "m", gas_limit)
}

fn transfer(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::Transfer {
            to: Address::new([8u8; 20]),
            amount: 1,
        },
    )
}

#[test]
fn the_block_budget_applies_only_where_the_gate_is_open() {
    let (a, _) = keys();
    let over = vec![declared(&a, 0, 1_000_000), declared(&a, 1, 1_000_000)];
    let p = budget_params(Some(5), Some(1_500_000));
    assert_eq!(block_contract_gas_budget(&p, 4), None);
    assert_eq!(block_contract_gas_budget(&p, 5), Some(1_500_000));
    assert!(check_block_contract_gas(&p, 4, &over).is_ok(), "h-1: no budget");
    assert!(check_block_contract_gas(&p, 5, &over).is_err(), "h: refused");
    assert!(check_block_contract_gas(&p, 5, &over[..1]).is_ok());
    // No budget configured: no limit even with the gate open.
    assert!(check_block_contract_gas(&budget_params(Some(1), None), 5, &over).is_ok());
    // A budget with the gate unset is refused at load; were it ever reached,
    // execution would still ignore it.
    let mut inert = params(None);
    inert.max_block_contract_gas = Some(1);
    inert.max_contract_gas = 1;
    assert!(matches!(
        inert.validate(),
        Err(GenesisError::BlockContractGasWithoutMetering { budget: 1 })
    ));
    assert_eq!(block_contract_gas_budget(&inert, 5), None);
    assert!(check_block_contract_gas(&inert, 5, &over).is_ok());
}

#[test]
fn the_declared_sum_is_checked_arithmetic() {
    let (a, b) = keys();
    let p = budget_params(Some(1), Some(u64::MAX));
    let half = u64::MAX / 2 + 1;
    let txs = vec![declared(&a, 0, half), declared(&b, 0, half)];
    let err = check_block_contract_gas(&p, 1, &txs).unwrap_err();
    assert!(err.contains("overflows"), "{err}");
    // Exactly at the budget is within it; transfers do not count.
    let p = budget_params(Some(1), Some(2_000_000));
    let txs = vec![declared(&a, 0, 1_000_000), transfer(&a, 1), declared(&a, 2, 1_000_000)];
    assert!(check_block_contract_gas(&p, 1, &txs).is_ok());
}

#[test]
fn the_proposer_skips_what_does_not_fit_and_keeps_the_rest() {
    let (a, b) = keys();
    let c = KeyPair::from_bytes([0x33; 32]);
    let p = budget_params(Some(1), Some(2_500_000));
    let txs = vec![
        declared(&a, 0, 2_000_000), // fits: 500_000 left
        declared(&b, 0, 1_000_000), // does not fit: skipped
        transfer(&b, 1),            // b's later nonce: skipped with it
        transfer(&c, 0),            // not contract gas: kept
        declared(&c, 1, 400_000),   // fits: 100_000 left
        declared(&a, 1, u64::MAX),  // never fits; no overflow
    ];
    let hashes = |v: &[SignedTransaction]| v.iter().map(|t| t.hash()).collect::<Vec<_>>();
    let kept = select_within_block_contract_gas(&p, 1, txs.clone());
    assert_eq!(hashes(&kept), hashes(&[txs[0].clone(), txs[3].clone(), txs[4].clone()]));
    assert!(check_block_contract_gas(&p, 1, &kept).is_ok());
    // Below the gate the selection is untouched.
    assert_eq!(hashes(&select_within_block_contract_gas(&p, 0, txs.clone())), hashes(&txs));
}

#[test]
fn the_budget_boundaries_are_exact_and_overflow_is_refused() {
    let (a, b) = keys();
    let c = KeyPair::from_bytes([0x33; 32]);
    let ceiling = ChainParams::default().max_contract_gas;

    // budget = u64::MAX: a sum of exactly u64::MAX is within it; one more
    // unit overflows and is refused, never wrapped.
    let p = budget_params(Some(1), Some(u64::MAX));
    let half = u64::MAX / 2;
    let exact = vec![declared(&a, 0, half), declared(&b, 0, half + 1)];
    assert!(check_block_contract_gas(&p, 1, &exact).is_ok());
    let mut over = exact.clone();
    over.push(declared(&c, 0, 1));
    assert!(check_block_contract_gas(&p, 1, &over).unwrap_err().contains("overflows"));
    // The proposer never overflows either: the third does not fit and is skipped.
    let kept = select_within_block_contract_gas(&p, 1, over.clone());
    assert_eq!(kept.len(), 2);

    // budget = ceiling exactly: one transaction at the ceiling fits, nothing
    // more does.
    let p = budget_params(Some(1), Some(ceiling));
    let at = vec![declared(&a, 0, ceiling)];
    assert!(check_block_contract_gas(&p, 1, &at).is_ok());
    let plus_one = vec![declared(&a, 0, ceiling), declared(&b, 0, 1)];
    assert!(check_block_contract_gas(&p, 1, &plus_one).is_err());
    let kept = select_within_block_contract_gas(&p, 1, plus_one.clone());
    assert_eq!(kept.iter().map(|t| t.hash()).collect::<Vec<_>>(), vec![plus_one[0].hash()]);
    // A second ceiling transaction alone is selected first if offered first.
    let reordered = vec![declared(&b, 0, 1), declared(&a, 0, ceiling)];
    let kept = select_within_block_contract_gas(&p, 1, reordered.clone());
    assert_eq!(kept.iter().map(|t| t.hash()).collect::<Vec<_>>(), vec![reordered[0].hash()]);

    // budget = ceiling + 1: the ceiling and one more unit fit, two more do not.
    let p = budget_params(Some(1), Some(ceiling + 1));
    let fits = vec![declared(&a, 0, ceiling), declared(&b, 0, 1)];
    assert!(check_block_contract_gas(&p, 1, &fits).is_ok());
    let over = vec![declared(&a, 0, ceiling), declared(&b, 0, 2)];
    assert!(check_block_contract_gas(&p, 1, &over).is_err());
    assert_eq!(select_within_block_contract_gas(&p, 1, over).len(), 1);
}

// ── the RPC executor follows the next block's engine ────────────────────────

/// A view or an estimate is served from the latest block, for a call that can
/// execute at the next one at the earliest: it runs on that block's engine.
/// So from the last block before the gate it is already metered, and its gas
/// is the metered gas a block would charge, not the unmetered figure.
#[test]
fn rpc_views_and_estimates_run_on_the_engine_of_the_next_block() {
    let gate = 100;
    let mode = |p: &ChainParams, tip| ContractExecutorState::local_execution_mode(p, tip);
    assert_eq!(mode(&params(Some(gate)), gate - 2), ExecutionMode::Unmetered);
    assert_eq!(mode(&params(Some(gate)), gate - 1), ExecutionMode::MeteredV1Provisional);
    assert_eq!(mode(&params(Some(gate)), gate), ExecutionMode::MeteredV1Provisional);
    assert_eq!(mode(&params(None), u64::MAX), ExecutionMode::Unmetered);

    // Deploy below the gate; ask local (RPC) executors on the published state.
    let (deployer, proposer) = keys();
    let (_state, db, _d, ex) = setup_with_params(params(Some(gate)));
    fund(&db, &deployer, FUNDS);
    let header = BlockHeader::new(
        Hash::ZERO,
        1,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer.public_key().as_bytes(),
    );
    let mut blk = Block::new(header, vec![deploy_tx(&deployer, 0, "new", 1_000_000)]);
    let exec = ex.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    blk.header.state_root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    assert_eq!(executed.receipts()[0].status, TxStatus::Success);
    executed.accept_produced(&blk).unwrap().publish().unwrap();

    let addr = first_contract(&deployer);
    let local = |gate| {
        ContractExecutorState::new_local(db.clone(), params(gate), LocalExecutionLimits::DEFAULT)
    };
    let estimate = |e: &ContractExecutorState, tip| {
        e.estimate_gas(&addr, "put", vec![], None, tip, 1000, CHAIN_ID)
    };
    let gated = local(Some(gate));
    let ungated = local(None);

    // Next block below the gate: today's estimate, unchanged.
    let today = estimate(&ungated, gate).unwrap();
    assert_eq!(estimate(&gated, gate - 2).unwrap(), today);
    // Next block at the gate: the metered charge (instantiation and fuel too).
    let metered = estimate(&gated, gate - 1).unwrap();
    assert!(metered > today, "metered {metered} vs unmetered {today}");
    assert_eq!(estimate(&gated, gate).unwrap(), metered);

    // A non-terminating view: stopped by the node-local fuel budget below the
    // gate, and out of gas (deterministically) from the block before it.
    let view = |e: &ContractExecutorState, tip| {
        e.view_call(&addr, "forever", vec![], None, tip, 1000, CHAIN_ID)
            .unwrap_err()
            .to_string()
    };
    assert!(!view(&gated, gate - 2).contains(metering::OUT_OF_GAS_MESSAGE));
    let err = view(&gated, gate - 1);
    assert!(err.contains(metering::OUT_OF_GAS_MESSAGE), "{err}");
}

