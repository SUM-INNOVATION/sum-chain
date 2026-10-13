//! #279, D8: the per-block loaded-code cap.
//!
//! Compiling a contract on a metered-cache miss is outside gas accounting, so
//! gas never depends on cache state. What bounds a block's compilation work is
//! the code it makes a node load: its deployed code plus the code of every
//! distinct contract it calls, measured in the parent state. The cap is decided
//! before anything executes, applies only above the metering gate, and never
//! depends on what a node's cache holds.

mod common;
use common::{fund, publish_block, setup_with_params, CHAIN_ID};

use std::collections::HashMap;
use sumc_runtime::{metering, ContractExecutor};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{
    block_loaded_code_cap, check_block_loaded_code, loaded_code_bytes,
    select_within_block_loaded_code, StateError,
};

const FEE: u128 = 1_000;
const FUNDS: u128 = 100_000_000;
/// Data bytes per test contract: five of them load more than the 256 KiB cap,
/// four fit under it.
const DATA: usize = 60 * 1024;

fn cap() -> u64 {
    u64::from(metering::METERED_COST_SCHEDULE.max_block_loaded_code_bytes)
}

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

/// A contract whose code carries `fill` bytes of data, so its length is known.
fn code(fill: u8) -> Vec<u8> {
    let data: String = std::iter::repeat_n(char::from(b'a' + fill % 26), DATA).collect();
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{data}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "get") (param i32 i32) (result i32) (i32.const 0)))"#
    );
    wat::parse_str(wat).unwrap()
}

fn deploy_tx(kp: &KeyPair, nonce: u64, code: Vec<u8>) -> SignedTransaction {
    deploy_tx_with_init(kp, nonce, code, "new")
}

fn deploy_tx_with_init(kp: &KeyPair, nonce: u64, code: Vec<u8>, init: &str) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractDeploy(ContractDeployData {
            code,
            init_method: init.to_string(),
            init_args: vec![],
            value: 0,
            gas_limit: ChainParams::default().max_contract_gas,
        }),
    )
}

fn call_tx(kp: &KeyPair, nonce: u64, contract: Address) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractCall(ContractCallData {
            contract,
            method: "get".to_string(),
            args: vec![],
            value: 0,
            gas_limit: 1_000_000,
        }),
    )
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

fn deployer() -> KeyPair {
    KeyPair::from_bytes([0x51; 32])
}

fn caller() -> KeyPair {
    KeyPair::from_bytes([0x52; 32])
}

fn proposer() -> KeyPair {
    KeyPair::from_bytes([0x53; 32])
}

/// A fake parent-state lookup.
fn lookup(map: &HashMap<Address, u64>) -> impl FnMut(&Address) -> Result<Option<u64>, String> + '_ {
    move |a| Ok(map.get(a).copied())
}

// ── the rule, over a fake parent state ─────────────────────────────────────

#[test]
fn the_cap_applies_only_where_the_gate_is_open() {
    assert_eq!(cap(), 256 * 1024);
    let p = params(Some(5));
    assert_eq!(block_loaded_code_cap(&p, 4), None);
    assert_eq!(block_loaded_code_cap(&p, 5), Some(cap()));
    assert_eq!(block_loaded_code_cap(&params(None), u64::MAX), None);
    // Below the gate nothing is checked, however much code a block loads.
    let a = Address::new([1u8; 20]);
    let huge = HashMap::from([(a, u64::MAX)]);
    assert!(check_block_loaded_code(&p, 4, &[call_tx(&caller(), 0, a)], lookup(&huge)).is_ok());
}

#[test]
fn deploys_and_distinct_called_contracts_are_counted_once() {
    let (a, b) = (Address::new([1u8; 20]), Address::new([2u8; 20]));
    let parent = HashMap::from([(a, 100), (b, 40)]);
    let k = caller();
    let txs = vec![
        call_tx(&k, 0, a),
        call_tx(&k, 1, a), // the same contract again: nothing more
        call_tx(&k, 2, b),
        deploy_tx(&k, 3, vec![0u8; 7]),
        transfer(&k, 4), // not contract code
    ];
    assert_eq!(
        loaded_code_bytes(&txs, lookup(&parent)).unwrap(),
        100 + 40 + 7
    );
}

#[test]
fn a_contract_absent_from_the_parent_state_adds_nothing() {
    // Deployed earlier in the same block (its deploy was counted), or nowhere.
    let fresh = Address::new([9u8; 20]);
    let txs = vec![
        deploy_tx(&deployer(), 0, vec![0u8; 11]),
        call_tx(&caller(), 0, fresh),
    ];
    assert_eq!(
        loaded_code_bytes(&txs, lookup(&HashMap::new())).unwrap(),
        11
    );
}

#[test]
fn the_cap_is_exact_and_the_sum_is_checked_arithmetic() {
    let p = params(Some(1));
    let (a, b) = (Address::new([1u8; 20]), Address::new([2u8; 20]));
    let k = caller();
    let at = HashMap::from([(a, cap())]);
    assert!(check_block_loaded_code(&p, 1, &[call_tx(&k, 0, a)], lookup(&at)).is_ok());
    let over = HashMap::from([(a, cap()), (b, 1)]);
    let err = check_block_loaded_code(
        &p,
        1,
        &[call_tx(&k, 0, a), call_tx(&k, 1, b)],
        lookup(&over),
    )
    .unwrap_err();
    assert!(err.contains("cap"), "{err}");
    let overflow = HashMap::from([(a, u64::MAX), (b, 1)]);
    let err =
        loaded_code_bytes(&[call_tx(&k, 0, a), call_tx(&k, 1, b)], lookup(&overflow)).unwrap_err();
    assert!(err.contains("overflows"), "{err}");
}

#[test]
fn the_proposer_skips_what_does_not_fit_and_keeps_the_rest() {
    let p = params(Some(1));
    let (a, b, c) = (
        Address::new([1u8; 20]),
        Address::new([2u8; 20]),
        Address::new([3u8; 20]),
    );
    let parent = HashMap::from([(a, cap() - 10), (b, 20), (c, 5)]);
    let (x, y, z) = (caller(), deployer(), proposer());
    let txs = vec![
        call_tx(&x, 0, a), // fits: 10 left
        call_tx(&y, 0, b), // 20 does not fit: skipped
        transfer(&y, 1),   // y's later nonce: skipped with it
        transfer(&z, 0),   // not contract code: kept
        call_tx(&z, 1, c), // fits: 5 left
        call_tx(&x, 1, a), // already loaded: free
    ];
    let hashes = |v: &[SignedTransaction]| v.iter().map(|t| t.hash()).collect::<Vec<_>>();
    let kept = select_within_block_loaded_code(&p, 1, txs.clone(), lookup(&parent));
    assert_eq!(
        hashes(&kept),
        hashes(&[
            txs[0].clone(),
            txs[3].clone(),
            txs[4].clone(),
            txs[5].clone()
        ])
    );
    assert!(check_block_loaded_code(&p, 1, &kept, lookup(&parent)).is_ok());
    // Below the gate the selection is untouched.
    assert_eq!(
        hashes(&select_within_block_loaded_code(
            &p,
            0,
            txs.clone(),
            lookup(&parent)
        )),
        hashes(&txs)
    );
}

// ── the rule in block execution ────────────────────────────────────────────

/// A chain with five deployed DATA-sized contracts (deployed across two blocks,
/// so no single block loads more than the cap), returning their addresses.
fn chain_with_five_contracts(
    gate: Option<u64>,
) -> (
    std::sync::Arc<sumchain_state::state::StateManager>,
    sumchain_state::BlockExecutor,
    tempfile::TempDir,
    Vec<Address>,
) {
    let (state, _db, ex, dir, addrs) = chain_with_five_contracts_and_db(gate);
    (state, ex, dir, addrs)
}

/// [`chain_with_five_contracts`], also returning its database.
fn chain_with_five_contracts_and_db(
    gate: Option<u64>,
) -> (
    std::sync::Arc<sumchain_state::state::StateManager>,
    std::sync::Arc<sumchain_storage::Database>,
    sumchain_state::BlockExecutor,
    tempfile::TempDir,
    Vec<Address>,
) {
    let (state, db, dir, ex) = setup_with_params(params(gate));
    fund(&db, &deployer(), FUNDS);
    fund(&db, &caller(), FUNDS);
    let pk = *proposer().public_key().as_bytes();
    let d = deployer();
    let receipts = publish_block(
        &state,
        &ex,
        1,
        &pk,
        (0..3).map(|n| deploy_tx(&d, n, code(n as u8))).collect(),
        &[],
    );
    assert!(
        receipts.iter().all(|r| r.status == TxStatus::Success),
        "{receipts:?}"
    );
    let receipts = publish_block(
        &state,
        &ex,
        2,
        &pk,
        (3..5).map(|n| deploy_tx(&d, n, code(n as u8))).collect(),
        &[],
    );
    assert!(
        receipts.iter().all(|r| r.status == TxStatus::Success),
        "{receipts:?}"
    );
    let addrs = (0..5)
        .map(|n| ContractExecutor::compute_address(&d.address(), n))
        .collect();
    (state, db, ex, dir, addrs)
}

fn block(height: u64, txs: Vec<SignedTransaction>) -> Block {
    let header = BlockHeader::new(
        Hash::ZERO,
        height,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer().public_key().as_bytes(),
    );
    Block::new(header, txs)
}

fn calls(addrs: &[Address]) -> Vec<SignedTransaction> {
    let k = caller();
    addrs
        .iter()
        .enumerate()
        .map(|(i, a)| call_tx(&k, i as u64, *a))
        .collect()
}

#[test]
fn an_importer_refuses_an_over_cap_block_before_executing_it() {
    let (state, ex, _dir, addrs) = chain_with_five_contracts(Some(1));
    let one = code(0).len() as u64;
    assert!(4 * one <= cap() && 5 * one > cap(), "fixture sizes: {one}");
    let root = state.state_root();
    let nonce = state.get_nonce(&caller().address()).unwrap();

    match ex.execute_block(&block(3, calls(&addrs)), root, &[]) {
        Err(StateError::BlockValidation(m)) => assert!(m.contains("cap"), "{m}"),
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("an over-cap block executed"),
    }
    // Refused before anything ran: no state moved.
    assert_eq!(state.state_root(), root);
    assert_eq!(state.get_nonce(&caller().address()).unwrap(), nonce);

    // Four distinct contracts fit, and repeating one costs nothing more.
    let mut four = addrs[..4].to_vec();
    four.push(addrs[0]);
    let exec = ex
        .execute_block(&block(3, calls(&four)), root, &[])
        .expect("within the cap");
    assert!(exec
        .into_parts()
        .0
        .receipts()
        .iter()
        .all(|r| r.status == TxStatus::Success));
}

#[test]
fn below_the_gate_the_same_block_executes_as_before() {
    // The gate opens far above: the five-contract block is not capped.
    let (state, ex, _dir, addrs) = chain_with_five_contracts(Some(1_000_000));
    let exec = ex
        .execute_block(&block(3, calls(&addrs)), state.state_root(), &[])
        .expect("no cap below the gate");
    assert!(exec
        .into_parts()
        .0
        .receipts()
        .iter()
        .all(|r| r.status == TxStatus::Success));
}

#[test]
fn the_verdict_does_not_depend_on_the_cache() {
    // Node A has executed calls to every contract (warm cache); node B has not.
    let (state_a, ex_a, _da, addrs) = chain_with_five_contracts(Some(1));
    let pk = *proposer().public_key().as_bytes();
    let k = caller();
    let warm: Vec<_> = addrs[..4]
        .iter()
        .enumerate()
        .map(|(i, a)| call_tx(&k, i as u64, *a))
        .collect();
    publish_block(&state_a, &ex_a, 3, &pk, warm, &[]);
    let warm: Vec<_> = vec![call_tx(&k, 4, addrs[4])];
    publish_block(&state_a, &ex_a, 4, &pk, warm, &[]);

    let (state_b, ex_b, _db, addrs_b) = chain_with_five_contracts(Some(1));
    assert_eq!(addrs, addrs_b);
    let over = |n: u64| {
        let k = caller();
        addrs
            .iter()
            .enumerate()
            .map(|(i, a)| call_tx(&k, n + i as u64, *a))
            .collect::<Vec<_>>()
    };
    let verdict_a = ex_a
        .execute_block(&block(5, over(5)), state_a.state_root(), &[])
        .is_ok();
    let verdict_b = ex_b
        .execute_block(&block(3, over(0)), state_b.state_root(), &[])
        .is_ok();
    assert!(
        !verdict_a && !verdict_b,
        "both refuse: warm {verdict_a}, cold {verdict_b}"
    );
}

#[test]
fn the_proposer_reads_code_lengths_from_canonical_state() {
    let (_state, db, _dir, ex) = setup_with_params(params(Some(1)));
    drop(ex);
    let missing = Address::new([7u8; 20]);
    assert_eq!(
        sumchain_state::committed_contract_code_len(&db, &missing).unwrap(),
        None
    );
    let (state, ex, dir, addrs) = chain_with_five_contracts(Some(1));
    drop((state, ex));
    let db = std::sync::Arc::new(sumchain_storage::Database::open_default(dir.path()).unwrap());
    for (n, a) in addrs.iter().enumerate() {
        assert_eq!(
            sumchain_state::committed_contract_code_len(&db, a).unwrap(),
            Some(code(n as u8).len() as u64)
        );
    }
}

// ── the bound itself: what a node compiles never exceeds the measure ───────
//
// Agreeing verdicts on warm and cold nodes do not by themselves bound anything.
// These count the bytes a node actually compiles while executing a block and
// hold them to the block's loaded-code measure. The cold node is a fresh
// executor over the same database, as after a restart, so every load misses.

/// Executes `txs` as block `height` on `ex` (without committing it) and returns
/// the bytes it compiled, the block's loaded-code measure over the committed
/// parent state, and each transaction's status.
fn compiled_against_measure(
    state: &std::sync::Arc<sumchain_state::state::StateManager>,
    db: &std::sync::Arc<sumchain_storage::Database>,
    ex: &sumchain_state::BlockExecutor,
    height: u64,
    txs: Vec<SignedTransaction>,
) -> (u64, u64, Vec<TxStatus>) {
    let measure =
        loaded_code_bytes(&txs, |a| sumchain_state::committed_contract_code_len(db, a)).unwrap();
    let before = ex.contract_metered_compiled_bytes();
    let exec = ex
        .execute_block(&block(height, txs), state.state_root(), &[])
        .expect("within the cap");
    let statuses = exec
        .into_parts()
        .0
        .receipts()
        .iter()
        .map(|r| r.status.clone())
        .collect();
    (
        ex.contract_metered_compiled_bytes() - before,
        measure,
        statuses,
    )
}

#[test]
fn repeated_calls_and_a_deploy_with_its_init_compile_no_more_than_the_measure() {
    let (state, db, warm, _dir, addrs) = chain_with_five_contracts_and_db(Some(1));
    let cold = sumchain_state::BlockExecutor::new(state.clone(), db.clone(), params(Some(1)));
    let d = deployer();
    let next = state.get_nonce(&d.address()).unwrap();
    let fresh = ContractExecutor::compute_address(&d.address(), next);
    let k = caller();
    let txs = || {
        vec![
            call_tx(&k, 0, addrs[0]),
            call_tx(&k, 1, addrs[1]),
            call_tx(&k, 2, addrs[0]),
            call_tx(&k, 3, addrs[1]),
            deploy_tx(&d, next, code(9)), // compiled once; its init reuses it
            call_tx(&k, 4, fresh),        // deployed in this block: nothing more
            call_tx(&k, 5, addrs[0]),
        ]
    };
    let one = code(0).len() as u64;

    let (compiled, measure, statuses) = compiled_against_measure(&state, &db, &cold, 3, txs());
    assert!(
        statuses.iter().all(|s| *s == TxStatus::Success),
        "{statuses:?}"
    );
    assert_eq!(measure, 3 * one);
    assert_eq!(
        compiled, measure,
        "a cold node compiles each load exactly once"
    );

    // A warm node compiles only the deploy.
    let (compiled, measure_warm, _) = compiled_against_measure(&state, &db, &warm, 3, txs());
    assert_eq!(measure_warm, measure);
    assert_eq!(compiled, one);
}

#[test]
fn a_failed_deploy_does_not_make_counted_code_compile_again() {
    // Contract 0's code is deployed again, twice, with an init that does not
    // exist, so each deploy compiles and then fails. Calls to contract 0 come
    // before, between and after. Each failed deploy is counted; the calls after
    // it must find the code still compiled.
    let (state, db, _warm, _dir, addrs) = chain_with_five_contracts_and_db(Some(1));
    let cold = sumchain_state::BlockExecutor::new(state.clone(), db.clone(), params(Some(1)));
    let d = deployer();
    let next = state.get_nonce(&d.address()).unwrap();
    let k = caller();
    let txs = vec![
        call_tx(&k, 0, addrs[0]),
        deploy_tx_with_init(&d, next, code(0), "absent"),
        call_tx(&k, 1, addrs[0]),
        deploy_tx_with_init(&d, next + 1, code(0), "absent"),
        call_tx(&k, 2, addrs[0]),
    ];
    let one = code(0).len() as u64;

    let (compiled, measure, statuses) = compiled_against_measure(&state, &db, &cold, 3, txs);
    assert_eq!(statuses[1], statuses[3]);
    assert_ne!(statuses[1], TxStatus::Success, "{statuses:?}");
    assert!(
        [0, 2, 4].iter().all(|&i| statuses[i] == TxStatus::Success),
        "{statuses:?}"
    );
    assert_eq!(measure, 3 * one);
    assert_eq!(
        compiled, measure,
        "compiled {compiled} of a {measure}-byte measure"
    );
}
