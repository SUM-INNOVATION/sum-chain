//! Issue #25, Set 3: contract-state diff capture, root commitment (gated), and
//! reorg revert (deploy / call-overwrite / delete).

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::ContractDeployData;
use sumchain_primitives::{Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_storage::schema::AccountState;
use sumchain_storage::{cf, contract_cf_kind, ContractMutation, ContractStateDiff, StateDiff};

/// `new` (init) writes storage key "k" -> "VAL", so a deploy yields a diff with
/// STORAGE + CODE + METADATA records.
const WAT_INIT_WRITES: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (func (export "alloc") (param i32) (result i32)
    (local $p i32) (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get 0))) (local.get $p))
  (func (export "new") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 0)))
"#;

/// Init traps -> deploy fails.
const WAT_INIT_TRAPS: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (unreachable)))
"#;

fn deploy_tx(kp: &KeyPair, nonce: u64, code: Vec<u8>) -> SignedTransaction {
    let payload = TxPayload::ContractDeploy(ContractDeployData {
        code,
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    });
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee: 1_000, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
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

#[test]
fn deploy_diff_captured_and_reverted() {
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &deployer, 10_000_000);

    let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap())]);
    let (receipts, _root, state_diff, contract_diff) = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    assert!(matches!(receipts[0].status, TxStatus::Success), "deploy should succeed: {:?}", receipts[0].status);

    // Diff has code + metadata + the init storage write. Clone the keys we
    // need before moving the diff into the store.
    assert!(contract_diff.records.iter().any(|r| r.cf_kind == contract_cf_kind::METADATA));
    let storage_rec = contract_diff.records.iter().find(|r| r.cf_kind == contract_cf_kind::STORAGE).expect("storage record");
    assert_eq!(storage_rec.new.as_deref(), Some(b"VAL".as_ref()));
    let storage_key = storage_rec.key.clone();
    let code_key = contract_diff.records.iter().find(|r| r.cf_kind == contract_cf_kind::CODE).expect("code record").key.clone();

    // Verify persistence on the CFs.
    assert!(db.get(cf::CONTRACT_CODE, &code_key).unwrap().is_some(), "code persisted");
    assert!(db.get(cf::CONTRACT_STORAGE, &storage_key).unwrap().is_some(), "storage persisted");

    // Persist BOTH diffs, then revert them together (simulated reorg) via the
    // coordinated path.
    state.save_state_diff(1, state_diff).unwrap();
    state.save_contract_state_diff(1, contract_diff).unwrap();
    state.revert_block_state_diffs(1).unwrap();

    // Deploy fully undone: code, storage, metadata all gone.
    assert!(db.get(cf::CONTRACT_CODE, &code_key).unwrap().is_none(), "code reverted");
    assert!(db.get(cf::CONTRACT_STORAGE, &storage_key).unwrap().is_none(), "storage reverted");
    assert!(db.get(cf::CONTRACT_METADATA, &code_key).unwrap().is_none(), "metadata reverted");
    // Account state restored, and BOTH diff records deleted.
    assert_eq!(state.get_balance(&deployer.address()).unwrap(), 10_000_000, "account restored");
    assert!(state.revert_block_state_diffs(1).is_ok(), "diffs already consumed -> no-op");
}

#[test]
fn root_committed_above_gate_only() {
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    let code = wat::parse_str(WAT_INIT_WRITES).unwrap();

    // Gate OPEN: deploy succeeds, contract diff non-empty, digest folded.
    let (s1, _d1, _dir1, ex1) = setup_with_params(ChainParams::with_contracts_enabled());
    fund(&s1, &deployer, 10_000_000);
    let (r1, root_open, _sd1, cd1) = ex1
        .execute_block(&block(1, &proposer, vec![deploy_tx(&deployer, 0, code.clone())]), Hash::ZERO, &[])
        .unwrap();
    assert!(matches!(r1[0].status, TxStatus::Success));
    assert!(!cd1.records.is_empty());

    // Gate CLOSED: same block, contract tx rejected free, empty diff, no digest.
    let (s2, _d2, _dir2, ex2) = setup_with_params(ChainParams::with_v2_enabled());
    fund(&s2, &deployer, 10_000_000);
    let (r2, root_closed, _sd2, cd2) = ex2
        .execute_block(&block(1, &proposer, vec![deploy_tx(&deployer, 0, code)]), Hash::ZERO, &[])
        .unwrap();
    assert!(matches!(r2[0].status, TxStatus::Failed(60)), "rejected below gate: {:?}", r2[0].status);
    assert!(cd2.records.is_empty(), "no contract diff below gate");

    assert_ne!(root_open, root_closed, "contract activation must change the state root");
}

#[test]
fn failed_deploy_leaves_no_diff_or_state() {
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &deployer, 10_000_000);

    let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_TRAPS).unwrap())]);
    let (receipts, _root, _sd, contract_diff) = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    assert!(!matches!(receipts[0].status, TxStatus::Success), "trapping init must fail");
    assert!(contract_diff.records.is_empty(), "failed deploy must produce no diff");
    // No contract CFs written.
    assert_eq!(db.full_iter(cf::CONTRACT_CODE).unwrap().count(), 0);
    assert_eq!(db.full_iter(cf::CONTRACT_STORAGE).unwrap().count(), 0);
}

#[test]
fn call_overwrite_and_delete_revert_at_state_level() {
    // Directly exercise revert_contract_state_diff for a call that overwrites
    // one slot and deletes another (the runtime tests prove the journal is
    // produced; this proves the revert restores pre-block values exactly).
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_contracts_enabled());
    let over_key = b"contractA:slot".to_vec();
    let del_key = b"contractA:gone".to_vec();

    // Post-block CF state: overwritten slot holds "new"; deleted slot absent.
    db.put(cf::CONTRACT_STORAGE, &over_key, b"new").unwrap();

    let mut diff = ContractStateDiff::new();
    diff.push(ContractMutation {
        cf_kind: contract_cf_kind::STORAGE,
        key: over_key.clone(),
        old: Some(b"old".to_vec()),
        new: Some(b"new".to_vec()),
    });
    diff.push(ContractMutation {
        cf_kind: contract_cf_kind::STORAGE,
        key: del_key.clone(),
        old: Some(b"prior".to_vec()),
        new: None,
    });
    diff.sort();

    state.save_contract_state_diff(7, diff).unwrap();
    state.revert_block_state_diffs(7).unwrap();

    // Overwrite reverted to "old"; delete reverted to restore "prior".
    assert_eq!(db.get(cf::CONTRACT_STORAGE, &over_key).unwrap().as_deref(), Some(b"old".as_ref()));
    assert_eq!(db.get(cf::CONTRACT_STORAGE, &del_key).unwrap().as_deref(), Some(b"prior".as_ref()));
    // Diff consumed.
    assert!(state.revert_block_state_diffs(7).is_ok());
}

#[test]
fn unknown_cf_kind_aborts_revert_atomically() {
    // A malformed contract diff (unknown cf_kind) must abort the WHOLE
    // coordinated revert: account state is NOT partially reverted and neither
    // diff record is deleted, leaving a clean retry path.
    let (state, _db, _dir, _ex) = setup_with_params(ChainParams::with_contracts_enabled());
    let addr = KeyPair::generate().address();

    // Current account state is the post-block value (balance 50).
    state.put_account(&addr, &AccountState { balance: 50, nonce: 1 }).unwrap();
    let mut sd = StateDiff::new();
    sd.add_change(
        addr,
        Some(AccountState { balance: 100, nonce: 0 }),
        AccountState { balance: 50, nonce: 1 },
    );
    state.save_state_diff(9, sd).unwrap();

    let mut cd = ContractStateDiff::new();
    cd.push(ContractMutation { cf_kind: 99, key: b"x".to_vec(), old: Some(b"o".to_vec()), new: None });
    state.save_contract_state_diff(9, cd).unwrap();

    // Revert must fail and apply NOTHING.
    assert!(state.revert_block_state_diffs(9).is_err());
    // Account NOT reverted (still post-block value).
    assert_eq!(state.get_balance(&addr).unwrap(), 50, "account must not be partially reverted");
    // Both diffs intact -> a retry still hits the same error (proves not deleted).
    assert!(state.revert_block_state_diffs(9).is_err(), "diffs must be preserved for retry");
}
