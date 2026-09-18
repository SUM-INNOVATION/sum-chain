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
    fund(&db, &deployer, 10_000_000);

    let mut blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap())]);
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    blk.header.state_root = exec.computed_root();
    let (executed, state_diff, contract_diff) = exec.into_parts();
    let receipts = executed.receipts().to_vec();

    // PUBLISH before asserting the rows are committed. A deploy stages its
    // code, storage and metadata into the block's candidate now; it does not
    // commit them as it executes. This test's subject is the reorg revert of
    // COMMITTED rows, so it has to make them committed first — and asserting
    // `db.get(...).is_some()` straight after `execute_block` was, before this
    // package, a test of the defect.
    let accepted = executed.accept_produced(&blk).expect("accept_produced");
    accepted.publish().expect("publish");
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
    state.save_state_diff(1, &Hash::ZERO, state_diff).unwrap();
    state.save_contract_state_diff(1, &Hash::ZERO, contract_diff).unwrap();
    state.revert_block_state_diffs(1, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).unwrap();

    // Deploy fully undone: code, storage, metadata all gone.
    assert!(db.get(cf::CONTRACT_CODE, &code_key).unwrap().is_none(), "code reverted");
    assert!(db.get(cf::CONTRACT_STORAGE, &storage_key).unwrap().is_none(), "storage reverted");
    assert!(db.get(cf::CONTRACT_METADATA, &code_key).unwrap().is_none(), "metadata reverted");
    // Account state restored, and BOTH diff records deleted.
    assert_eq!(state.get_balance(&deployer.address()).unwrap(), 10_000_000, "account restored");
    assert!(state.revert_block_state_diffs(1, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).is_ok(), "diffs already consumed -> no-op");
}

#[test]
fn root_committed_above_gate_only() {
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    let code = wat::parse_str(WAT_INIT_WRITES).unwrap();

    // Gate OPEN: deploy succeeds, contract diff non-empty, digest folded.
    let (s1, d1, _dir1, ex1) = setup_with_params(ChainParams::with_contracts_enabled());
    fund(&d1, &deployer, 10_000_000);
    let exec1 = ex1
        .execute_block(&block(1, &proposer, vec![deploy_tx(&deployer, 0, code.clone())]), Hash::ZERO, &[])
        .unwrap();
    // The root is read from the candidate it was bound to, not from a tuple
    // element a caller could have swapped.
    let root_open = exec1.computed_root();
    let (executed1, _sd1, cd1) = exec1.into_parts();
    let r1 = executed1.receipts().to_vec();
    assert!(matches!(r1[0].status, TxStatus::Success));
    assert!(!cd1.records.is_empty());

    // Gate CLOSED: same block, contract tx rejected free, empty diff, no digest.
    let (s2, d2, _dir2, ex2) = setup_with_params(ChainParams::with_v2_enabled());
    fund(&d2, &deployer, 10_000_000);
    let exec2 = ex2
        .execute_block(&block(1, &proposer, vec![deploy_tx(&deployer, 0, code)]), Hash::ZERO, &[])
        .unwrap();
    let root_closed = exec2.computed_root();
    let (executed2, _sd2, cd2) = exec2.into_parts();
    let r2 = executed2.receipts().to_vec();
    assert!(matches!(r2[0].status, TxStatus::Failed(60)), "rejected below gate: {:?}", r2[0].status);
    assert!(cd2.records.is_empty(), "no contract diff below gate");

    assert_ne!(root_open, root_closed, "contract activation must change the state root");
}

#[test]
fn failed_deploy_leaves_no_diff_or_state() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_TRAPS).unwrap())]);
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let (executed, _sd, contract_diff) = exec.into_parts();
    let receipts = executed.receipts().to_vec();
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

    state.save_contract_state_diff(7, &Hash::ZERO, diff).unwrap();
    state.revert_block_state_diffs(7, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).unwrap();

    // Overwrite reverted to "old"; delete reverted to restore "prior".
    assert_eq!(db.get(cf::CONTRACT_STORAGE, &over_key).unwrap().as_deref(), Some(b"old".as_ref()));
    assert_eq!(db.get(cf::CONTRACT_STORAGE, &del_key).unwrap().as_deref(), Some(b"prior".as_ref()));
    // Diff consumed.
    assert!(state.revert_block_state_diffs(7, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).is_ok());
}

#[test]
fn unknown_cf_kind_aborts_revert_atomically() {
    // A malformed contract diff (unknown cf_kind) must abort the WHOLE
    // coordinated revert: account state is NOT partially reverted and neither
    // diff record is deleted, leaving a clean retry path.
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_contracts_enabled());
    let addr = KeyPair::generate().address();

    // Current account state is the post-block value (balance 50).
    sumchain_storage::StateStore::new(&db).put_account(&addr, &AccountState { balance: 50, nonce: 1 }).unwrap();
    let mut sd = StateDiff::new();
    sd.add_change(
        addr,
        Some(AccountState { balance: 100, nonce: 0 }),
        AccountState { balance: 50, nonce: 1 },
    );
    state.save_state_diff(9, &Hash::ZERO, sd).unwrap();

    let mut cd = ContractStateDiff::new();
    cd.push(ContractMutation { cf_kind: 99, key: b"x".to_vec(), old: Some(b"o".to_vec()), new: None });
    state.save_contract_state_diff(9, &Hash::ZERO, cd).unwrap();

    // Revert must fail and apply NOTHING.
    assert!(state.revert_block_state_diffs(9, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).is_err());
    // Account NOT reverted (still post-block value).
    assert_eq!(state.get_balance(&addr).unwrap(), 50, "account must not be partially reverted");
    // Both diffs intact -> a retry still hits the same error (proves not deleted).
    assert!(state.revert_block_state_diffs(9, &Hash::ZERO, sumchain_storage::journal::JournalRequirement::PreActivation).is_err(), "diffs must be preserved for retry");
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// Every contract family this package moved.
const CONTRACT_CFS: &[&str] = &[cf::CONTRACT_CODE, cf::CONTRACT_STORAGE, cf::CONTRACT_METADATA];

fn contract_rows(db: &sumchain_storage::Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in CONTRACT_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// A deploy in a block that is never published leaves no contract row behind.
///
/// This is the property the package exists for, and the one the closure ledger
/// cannot check: contract writes come from `sumc-runtime`, which the ledger
/// classifies `Library` by location, so they were never manifest rows and their
/// removal is invisible to it.
///
/// Before this change the deploy committed as it executed — and worse than the
/// other subsystems, because `store_code` and `store_metadata` wrote straight
/// through with no buffer at all. An abandoned block left the contract's code
/// in `cf::CONTRACT_CODE` permanently.
///
/// The block is executed and then DROPPED, never accepted, never published.
#[test]
fn an_abandoned_deploy_leaves_no_contract_rows() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let before = contract_rows(&db);
    assert!(before.is_empty(), "no contract rows before the block");

    {
        let blk = block(
            1,
            &proposer,
            vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap())],
        );
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (executed, _state_diff, contract_diff) = exec.into_parts();
        assert!(
            matches!(executed.receipts()[0].status, TxStatus::Success),
            "the deploy must succeed, or this proves nothing"
        );

        // It really did write — code, metadata and the init storage row are all
        // in the journal, so the rollback below is not vacuous.
        for kind in [
            contract_cf_kind::CODE,
            contract_cf_kind::METADATA,
            contract_cf_kind::STORAGE,
        ] {
            assert!(
                contract_diff.records.iter().any(|r| r.cf_kind == kind),
                "the deploy must have produced a {kind:?} mutation"
            );
        }
        // `executed` is dropped here: not accepted, not published.
    }

    assert_eq!(
        contract_rows(&db),
        before,
        "an abandoned deploy must leave every contract row as it found it — \
         code included, which used to be written straight through"
    );
}

/// The code of an abandoned deploy is specifically absent.
///
/// Stated on its own because `store_code` was the worst case: unbuffered, so it
/// did not even have the mid-execution batch the other subsystems had.
#[test]
fn an_abandoned_deploy_leaves_no_code() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    let code_key = {
        let blk = block(
            1,
            &proposer,
            vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap())],
        );
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (_executed, _state_diff, contract_diff) = exec.into_parts();
        contract_diff
            .records
            .iter()
            .find(|r| r.cf_kind == contract_cf_kind::CODE)
            .expect("a deploy writes code")
            .key
            .clone()
    };

    assert!(
        db.get(cf::CONTRACT_CODE, &code_key).unwrap().is_none(),
        "the code of an abandoned deploy must not be durable"
    );
    assert!(
        db.get(cf::CONTRACT_METADATA, &code_key).unwrap().is_none(),
        "nor its metadata"
    );
}

/// A contract with callable `set`/`get`, for visibility and isolation tests.
/// Same shape as the runtime's persistence fixture, whose host signatures are
/// known good.
const WAT_GET: &str = r#"
(module
  (import "env" "storage_read"   (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write"  (func $swrite (param i32 i32 i32 i32)))
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
  (func (export "set") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 0))
  (func (export "get") (param i32 i32) (result i32)
    (call $sread (i32.const 0) (i32.const 1)))
)
"#;

fn call_tx(kp: &KeyPair, nonce: u64, contract: sumchain_primitives::Address, method: &str) -> SignedTransaction {
    let payload = TxPayload::ContractCall(sumchain_primitives::transaction::ContractCallData {
        contract,
        method: method.to_string(),
        args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    });
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee: 1_000, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// The address a deploy produced, from its journal.
fn deployed_address(cd: &ContractStateDiff) -> sumchain_primitives::Address {
    let key = cd
        .records
        .iter()
        .find(|r| r.cf_kind == contract_cf_kind::CODE)
        .expect("a deploy writes code")
        .key
        .clone();
    let mut a = [0u8; 20];
    a.copy_from_slice(&key[..20]);
    sumchain_primitives::Address::new(a)
}

// ── Candidate isolation ──────────────────────────────────────────────────────

/// A LATER candidate must not see an abandoned one's contract, through the
/// same executor.
///
/// This is the bug the first version of this package shipped. The runtime is
/// built once, for the node, and caches per-candidate state so a later
/// transaction can read an earlier one's writes. Nothing cleared it. An
/// abandoned block's contract rows stayed in a cache that `read` consults
/// BEFORE the database, and the next block read state the chain never accepted.
///
/// Nobody signals the end of a block that is thrown away, so the fix cannot be
/// "clear at the end". The candidate carries an identity and the runtime drops
/// what it holds when that identity changes.
#[test]
fn a_later_candidate_does_not_see_an_abandoned_ones_contract() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    // Candidate 1: deploy, then abandon.
    let addr = {
        let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap())]);
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (executed, _sd, cd) = exec.into_parts();
        assert!(matches!(executed.receipts()[0].status, TxStatus::Success), "deploy must succeed");
        deployed_address(&cd)
    };
    assert!(
        db.get(cf::CONTRACT_CODE, addr.as_bytes()).unwrap().is_none(),
        "the abandoned deploy committed nothing"
    );

    // Candidate 2, SAME executor: calling that contract must fail. The deploy
    // was thrown away, so nothing about it may be visible here.
    // Nonce 0, not 1: block 1 was abandoned, so it consumed nothing. Using 1
    // made an earlier version of this test pass on InvalidNonce — a failure
    // that has nothing to do with whether the contract is visible.
    let blk2 = block(2, &proposer, vec![call_tx(&deployer, 0, addr, "get")]);
    let exec2 = executor.execute_block(&blk2, Hash::ZERO, &[]).unwrap();
    let (executed2, _sd2, cd2) = exec2.into_parts();
    // The REASON, exactly. Failed(5) is "contract call failed" — the call
    // reached the contract executor and found nothing to call. Excluding
    // Success and InvalidNonce left every other rejection able to stand in for
    // isolation: an insufficient balance, a closed gate, a malformed payload.
    let status = executed2.receipts()[0].status;
    assert_eq!(
        status,
        TxStatus::Failed(5),
        "the call must fail because the contract is not there, not for any \
         other reason: {status:?}"
    );
    assert!(
        cd2.records.is_empty(),
        "and it must journal nothing: {:?}",
        cd2.records.len()
    );
}

/// A finished block leaves nothing in the contract runtime.
///
/// The runtime is built once for the node and caches per-candidate state so a
/// later transaction can read an earlier one's writes. Candidate identity makes
/// that state UNREADABLE by the next block, but on its own it does not release
/// it: it clears at the start of the next candidate's first contract operation,
/// so a finished block's staged rows, code, metadata, queued writes and journal
/// stay resident until some later block happens to deploy or call something.
/// For an abandoned block that interval has no end at all, and what it holds is
/// block-sized — a deployed contract's code is in there.
///
/// `execute_block` therefore clears in a scope guard, which runs on the normal
/// exit and on every `?`. This is the normal exit;
/// `a_block_scope_clears_when_its_scope_exits_with_an_error` in the executor's
/// own tests is the other one.
#[test]
fn a_finished_block_leaves_nothing_in_the_runtime() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    // Deploy AND call in one block, so the block is known to have put contract
    // state into the runtime. Without the call this test would pass against a
    // runtime that never caches anything.
    let addr = {
        let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap())]);
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (_e, _sd, cd) = exec.into_parts();
        deployed_address(&cd)
    };
    let blk = block(
        1,
        &proposer,
        vec![
            deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap()),
            call_tx(&deployer, 1, addr, "set"),
        ],
    );
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let (executed, _sd, cd) = exec.into_parts();
    assert!(
        matches!(executed.receipts()[0].status, TxStatus::Success)
            && matches!(executed.receipts()[1].status, TxStatus::Success),
        "the block must reach the contract executor twice: {:?}",
        executed.receipts().iter().map(|r| r.status).collect::<Vec<_>>()
    );
    assert!(
        cd.records
            .iter()
            .any(|r| r.cf_kind == contract_cf_kind::STORAGE),
        "and the call must have written, so there was something to hold"
    );

    // The block is over. Nothing about it may still be held — and this is true
    // before anything else runs, not once the next candidate arrives.
    assert!(
        !executor.contract_exists_in_runtime(&addr),
        "a finished block's code must not still be staged in the runtime"
    );
    assert!(
        !executor.contract_metadata_in_runtime(&addr),
        "nor its metadata"
    );
    assert!(
        !executor.contract_queue_is_non_empty(),
        "nor may queued writes outlive the block that queued them"
    );
    // Never published, so nothing is durable either.
    assert!(
        db.get(cf::CONTRACT_CODE, addr.as_bytes()).unwrap().is_none(),
        "the abandoned block committed nothing"
    );
}

// ── Same-block visibility ────────────────────────────────────────────────────

/// A contract deployed earlier in the block is callable later in it.
///
/// The positive control for the isolation test above: without it, that test
/// would pass if calls to this contract failed for any reason at all.
#[test]
fn a_contract_deployed_earlier_in_the_block_is_callable_later_in_it() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    // Deploy alone, to learn the address the same inputs produce.
    let addr = {
        let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap())]);
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (_e, _sd, cd) = exec.into_parts();
        deployed_address(&cd)
    };

    // Deploy AND call, in one block.
    let blk = block(
        1,
        &proposer,
        vec![
            deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap()),
            call_tx(&deployer, 1, addr, "set"),
        ],
    );
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let (executed, _sd, _cd) = exec.into_parts();
    assert!(matches!(executed.receipts()[0].status, TxStatus::Success), "deploy");
    assert!(
        matches!(executed.receipts()[1].status, TxStatus::Success),
        "a call must see the contract deployed earlier in the SAME block: {:?}",
        executed.receipts()[1].status
    );
}

/// A call sees a previous call's storage write, same block.
#[test]
fn a_call_sees_an_earlier_calls_write_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);

    let addr = {
        let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap())]);
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (_e, _sd, cd) = exec.into_parts();
        deployed_address(&cd)
    };

    let blk = block(
        1,
        &proposer,
        vec![
            deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap()),
            call_tx(&deployer, 1, addr, "set"),
            call_tx(&deployer, 2, addr, "get"),
        ],
    );
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    let (executed, _sd, cd) = exec.into_parts();
    for (i, r) in executed.receipts().iter().enumerate() {
        assert!(matches!(r.status, TxStatus::Success), "tx {i}: {:?}", r.status);
    }
    // The write from `set` is journalled once, not twice: `get` reads it from
    // the block's staged cache rather than re-writing.
    let writes = cd
        .records
        .iter()
        .filter(|r| r.cf_kind == contract_cf_kind::STORAGE)
        .count();
    assert_eq!(writes, 1, "one storage mutation, from `set`");
}

/// A transaction that fails AFTER an earlier one succeeded does not undo it.
///
/// The earlier write is checked by VALUE, at its own key, on both sides of the
/// question: the journal record the block produced, and the committed bytes
/// after publication. A journal record on its own says a mutation was recorded,
/// not that the right bytes ended up in the right row — which is the thing a
/// later failure could plausibly damage.
#[test]
fn a_later_failure_does_not_undo_an_earlier_success_or_leak_it() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let before = contract_rows(&db);

    let addr = {
        let blk = block(1, &proposer, vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap())]);
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (_e, _sd, cd) = exec.into_parts();
        deployed_address(&cd)
    };

    // Abandoned: nothing of it commits, successes included.
    {
        let blk = block(
            1,
            &proposer,
            vec![
                deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap()),
                call_tx(&deployer, 1, addr, "set"),
                // No such method: this transaction fails.
                call_tx(&deployer, 2, addr, "nope"),
            ],
        );
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        let (executed, _sd, cd) = exec.into_parts();
        assert!(matches!(executed.receipts()[1].status, TxStatus::Success), "set succeeds");
        assert_eq!(
            executed.receipts()[2].status,
            TxStatus::Failed(5),
            "the unknown method must fail in the contract, not elsewhere"
        );
        assert!(
            cd.records
                .iter()
                .any(|r| r.cf_kind == contract_cf_kind::STORAGE),
            "the earlier success is still journalled"
        );
        // dropped
    }
    assert_eq!(
        contract_rows(&db),
        before,
        "and the whole block, successes included, commits nothing when abandoned"
    );

    // Kept: the earlier write is intact, byte for byte, at its own key.
    let mut blk = block(
        1,
        &proposer,
        vec![
            deploy_tx(&deployer, 0, wat::parse_str(WAT_GET).unwrap()),
            call_tx(&deployer, 1, addr, "set"),
            call_tx(&deployer, 2, addr, "nope"),
        ],
    );
    let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
    blk.header.state_root = exec.computed_root();
    let (executed, _sd, cd) = exec.into_parts();
    assert!(matches!(executed.receipts()[1].status, TxStatus::Success));
    assert_eq!(executed.receipts()[2].status, TxStatus::Failed(5));

    // `set` writes "k" -> "VAL". The record must carry that value, not merely
    // exist.
    let rec = cd
        .records
        .iter()
        .find(|r| r.cf_kind == contract_cf_kind::STORAGE)
        .expect("the earlier call journalled a storage mutation")
        .clone();
    assert_eq!(
        rec.new.as_deref(),
        Some(&b"VAL"[..]),
        "the journal must carry the value the earlier call wrote"
    );
    assert_eq!(
        rec.old, None,
        "and record that the row did not exist before it"
    );

    let accepted = executed.accept_produced(&blk).expect("accept_produced");
    accepted.publish().expect("publish");
    assert_eq!(
        db.get(cf::CONTRACT_STORAGE, &rec.key).unwrap().as_deref(),
        Some(&b"VAL"[..]),
        "the earlier success must be committed at its own key, unchanged by the \
         transaction that failed after it"
    );
}

// ── Limit refusal, and what a refusal must not lose ──────────────────────────

/// A deploy refused by the candidate's ceiling leaves no contract row, and the
/// refusal covers all three families.
///
/// A deploy writes code, metadata AND an init storage row. The ceiling is
/// measured from a completed run and then lowered, so staging is refused
/// part-way: some of those families land in the candidate and the rest cannot.
/// Dropping it must leave every one of them as it was.
#[test]
fn a_deploy_refused_by_the_ceiling_leaves_no_contract_row() {
    use sumchain_storage::overlay::ApplicationOverlay;
    use sumchain_storage::exec_view::ExecutionView;

    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let before = contract_rows(&db);
    // WAT_INIT_WRITES, not WAT_GET: its `new` writes a storage row, so the
    // deploy touches all three contract families rather than two.
    let tx = deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap());

    // What the whole transaction costs.
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            let _ = executor.execute_tx(&mut view, &tx, &sumchain_primitives::Address::new([9; 20]), 1, 1000);
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "a deploy must cost something");

    // The three families it writes, so the refusal below is known to be
    // cutting across a multi-family write rather than a single row.
    {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut scratch);
        executor
            .execute_tx(&mut view, &tx, &sumchain_primitives::Address::new([9; 20]), 1, 1000)
            .unwrap();
        for family in [cf::CONTRACT_CODE, cf::CONTRACT_METADATA, cf::CONTRACT_STORAGE] {
            assert!(
                view.prefix_iter(family, &[]).unwrap().next().is_some(),
                "a deploy must write {family}"
            );
        }
    }

    {
        let mut overlay = ApplicationOverlay::new(&db, full - 1);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &sumchain_primitives::Address::new([9; 20]), 1, 1000);
        assert!(
            outcome.is_err(),
            "one byte under the measured cost must refuse a write"
        );
        let err = outcome.unwrap_err().to_string();
        assert!(
            err.contains("limit"),
            "it must fail because a WRITE was refused, not before writing: {err}"
        );
    }

    assert_eq!(
        contract_rows(&db),
        before,
        "a deploy refused part-way must leave every contract row as it found it"
    );
    let _ = state;
}

/// A refusal mid-staging does not silently lose the writes that followed it.
///
/// `stage_contract_writes` used to DRAIN the runtime's queue and then stage, so
/// a refusal part-way left the queue empty with some of its contents never
/// written. It stages from a copy now and clears only once every write lands.
///
/// This covers the outcome — a transaction refused anywhere leaves no contract
/// row. `a_refusal_inside_staging_leaves_the_queue_intact` below covers the
/// queue itself, and `sumc-runtime`'s
/// `staging_clears_the_queue_only_when_every_write_lands` the mechanism.
#[test]
fn a_transaction_refused_anywhere_leaves_no_contract_row() {
    use sumchain_storage::exec_view::ExecutionView;
    use sumchain_storage::overlay::ApplicationOverlay;

    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let before = contract_rows(&db);
    let tx = deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap());

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            let _ = executor.execute_tx(
                &mut view,
                &tx,
                &sumchain_primitives::Address::new([9; 20]),
                1,
                1000,
            );
        }
        scratch.logical_bytes()
    };

    // Every ceiling from "almost nothing" to "one byte short" must refuse, and
    // none of them may leave a contract row behind. Sweeping rather than
    // picking one point is what makes this independent of exactly which write
    // the ceiling happens to cut.
    for ceiling in [1u64, full / 4, full / 2, full - 1] {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(
            &mut view,
            &tx,
            &sumchain_primitives::Address::new([9; 20]),
            1,
            1000,
        );
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert_eq!(
            contract_rows(&db),
            before,
            "a refusal at ceiling {ceiling} must leave every contract row as it \
             found it"
        );
    }
}

/// Each contract family is charged separately, and the refusal moves with the
/// boundary between them.
///
/// The ceiling sweep above proves a refused transaction leaves no row. It does
/// NOT prove that code, metadata and storage are each charged: one large code
/// write would refuse at every ceiling in that sweep and produce the same
/// result. This walks the three boundaries instead, and asserts exactly which
/// families are staged on each side of each one.
///
/// The thresholds are computed, not guessed. Contract staging runs in queue
/// order — code, then metadata, then the storage the init wrote — and on a
/// fresh database every row is new, so the candidate charges `2*key + value`
/// for each (key and value once, key and the absent pre-image once). The test
/// asserts its own arithmetic: if that formula were wrong, the boundary cases
/// below would not land where they are asserted to land.
#[test]
fn each_contract_family_is_charged_separately_by_the_ceiling() {
    use sumchain_state::contract_executor::ContractExecutorState;
    use sumchain_storage::exec_view::ExecutionView;
    use sumchain_storage::overlay::ApplicationOverlay;

    let (state, db, _dir, _executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let contracts =
        ContractExecutorState::new(db.clone(), ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let data = ContractDeployData {
        code: wat::parse_str(WAT_INIT_WRITES).unwrap(),
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    };
    let proposer = sumchain_primitives::Address::new([9; 20]);

    // One unconstrained run, to measure what each family actually writes.
    let charges: Vec<(&str, u64)> = {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let result = contracts
            .deploy(&mut view, &deployer.address(), &data, &state, &proposer, 1_000, 1, 1000)
            .expect("an unconstrained deploy must succeed");
        assert!(result.success, "{:?}", result.error);
        // Queue order: code, metadata, storage.
        [cf::CONTRACT_CODE, cf::CONTRACT_METADATA, cf::CONTRACT_STORAGE]
            .into_iter()
            .map(|family| {
                let charge: u64 = view
                    .prefix_iter(family, &[])
                    .unwrap()
                    .map(|r| { let (k, v) = r.unwrap(); 2 * k.len() as u64 + v.len() as u64 })
                    .sum();
                assert!(charge > 0, "a deploy must write {family}");
                (family, charge)
            })
            .collect()
    };

    // The three families must cost visibly different amounts, or "the refusal
    // moved with the boundary" would be indistinguishable from coincidence.
    assert!(
        charges[0].1 != charges[1].1
            && charges[1].1 != charges[2].1
            && charges[0].1 != charges[2].1,
        "the three families must have distinct charges for this test to \
         discriminate between them: {charges:?}"
    );

    // Walk the boundaries. At `cumulative - 1` the family is refused; at
    // `cumulative` it fits and the NEXT one is refused.
    let mut cumulative = 0u64;
    for (idx, (family, charge)) in charges.iter().enumerate() {
        let staged_before: Vec<&str> = charges[..idx].iter().map(|(f, _)| *f).collect();

        // One byte short of this family: everything before it is staged, it is
        // not, and the queue still holds every write.
        {
            let mut overlay = ApplicationOverlay::new(&db, cumulative + charge - 1);
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = contracts
                .deploy(&mut view, &deployer.address(), &data, &state, &proposer, 1_000, 1, 1000);
            let err = outcome
                .expect_err("one byte short of {family} must refuse")
                .to_string();
            assert!(
                err.contains("limit"),
                "it must fail because a WRITE was refused: {err}"
            );
            for earlier in &staged_before {
                assert!(
                    view.prefix_iter(earlier, &[]).unwrap().next().is_some(),
                    "{earlier} fits under this ceiling and must be staged"
                );
            }
            assert!(
                view.prefix_iter(family, &[]).unwrap().next().is_none(),
                "{family} does not fit and must not be staged"
            );
            assert!(
                contracts.queue_is_non_empty(),
                "a refusal at {family} must leave the queue intact"
            );
        }

        cumulative += charge;

        // Exactly enough for this family: it IS staged now. The boundary moved
        // by this family's own charge, which is what "charged separately"
        // means.
        {
            let mut overlay = ApplicationOverlay::new(&db, cumulative);
            let mut view = ExecutionView::new(&mut overlay);
            let _ = contracts
                .deploy(&mut view, &deployer.address(), &data, &state, &proposer, 1_000, 1, 1000);
            assert!(
                view.prefix_iter(family, &[]).unwrap().next().is_some(),
                "{family} fits exactly at {cumulative} and must be staged"
            );
        }
    }
}

/// A refusal PART-WAY through staging leaves the queue holding all of it.
///
/// `stage_contract_writes` used to call `take_pending_writes`, which drains.
/// A put refused part-way then left the queue empty with the rest of its
/// contents written nowhere — the writes were not rolled back, they were lost.
/// Staging borrows the entries now and clears only after the last one lands.
///
/// Genuinely partial: the ceiling is measured so that the code row is staged
/// and the metadata row that follows it is refused. A ceiling that refuses the
/// FIRST write exercises the empty-queue case, which is not the one that was
/// broken.
#[test]
fn a_refusal_inside_staging_leaves_the_queue_intact() {
    use sumchain_state::contract_executor::ContractExecutorState;
    use sumchain_storage::exec_view::ExecutionView;
    use sumchain_storage::overlay::ApplicationOverlay;

    let (state, db, _dir, _executor) = setup_with_params(ChainParams::with_contracts_enabled());
    let contracts =
        ContractExecutorState::new(db.clone(), ChainParams::with_contracts_enabled());
    let deployer = KeyPair::generate();
    fund(&db, &deployer, 10_000_000);
    let data = ContractDeployData {
        code: wat::parse_str(WAT_INIT_WRITES).unwrap(),
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    };
    let proposer = sumchain_primitives::Address::new([9; 20]);

    // Measure: the code row's charge, and how many writes a complete staging
    // performs.
    let (code_charge, queued) = {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        contracts
            .deploy(&mut view, &deployer.address(), &data, &state, &proposer, 1_000, 1, 1000)
            .expect("an unconstrained deploy must succeed");
        let code: u64 = view
            .prefix_iter(cf::CONTRACT_CODE, &[])
            .unwrap()
            .map(|r| { let (k, v) = r.unwrap(); 2 * k.len() as u64 + v.len() as u64 })
            .sum();
        let rows: usize = [cf::CONTRACT_CODE, cf::CONTRACT_METADATA, cf::CONTRACT_STORAGE]
            .into_iter()
            .map(|f| view.prefix_iter(f, &[]).unwrap().count())
            .sum();
        (code, rows)
    };
    assert_eq!(queued, 3, "one row per family for this contract");

    // Room for the code row and not a byte more: the metadata write that
    // follows it is refused.
    let mut overlay = ApplicationOverlay::new(&db, code_charge);
    let mut view = ExecutionView::new(&mut overlay);
    let outcome = contracts
        .deploy(&mut view, &deployer.address(), &data, &state, &proposer, 1_000, 1, 1000);

    let err = outcome.expect_err("the metadata write must be refused");
    assert!(
        err.to_string().contains("limit"),
        "it must fail because a WRITE was refused, not before writing: {err}"
    );
    // Partial, which is the case that matters: one row in, the next refused.
    assert!(
        view.prefix_iter(cf::CONTRACT_CODE, &[]).unwrap().next().is_some(),
        "the code row must already be staged when the refusal happens"
    );
    assert!(
        view.prefix_iter(cf::CONTRACT_METADATA, &[]).unwrap().next().is_none(),
        "and the metadata row must not be"
    );
    // The queue still holds EVERY write, including the one that landed and the
    // ones after the refusal. Draining first lost the tail.
    assert_eq!(
        contracts.queued_write_count(),
        queued,
        "a refusal part-way must leave the whole queue, not what was left of it"
    );
}

// ── Committed-byte and restart parity ────────────────────────────────────────

/// A PUBLISHED deploy writes the same contract bytes the runtime produced, and
/// they survive a restart.
///
/// The other direction of the abandonment tests. Those prove nothing is
/// committed when a block is dropped; this proves the right thing is committed
/// when one is kept — same keys, same bytes, still there when the database is
/// reopened. Without it, "commits nothing" would be satisfiable by a change
/// that simply never writes.
#[test]
fn a_published_deploy_commits_the_expected_bytes_and_survives_a_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let deployer = KeyPair::generate();
    let proposer = KeyPair::generate();

    let expected = {
        let db = std::sync::Arc::new(
            sumchain_storage::Database::open_default(dir.path()).unwrap(),
        );
        let state = std::sync::Arc::new(sumchain_state::state::StateManager::new(db.clone(), CHAIN_ID));
        let executor = sumchain_state::executor::BlockExecutor::new(
            state.clone(),
            db.clone(),
            ChainParams::with_contracts_enabled(),
        );
        fund(&db, &deployer, 10_000_000);

        let mut blk = block(
            1,
            &proposer,
            vec![deploy_tx(&deployer, 0, wat::parse_str(WAT_INIT_WRITES).unwrap())],
        );
        let exec = executor.execute_block(&blk, Hash::ZERO, &[]).unwrap();
        blk.header.state_root = exec.computed_root();
        let (executed, _sd, cd) = exec.into_parts();
        assert!(matches!(executed.receipts()[0].status, TxStatus::Success));

        let code_rec = cd
            .records
            .iter()
            .find(|r| r.cf_kind == contract_cf_kind::CODE)
            .expect("code record")
            .clone();
        let storage_rec = cd
            .records
            .iter()
            .find(|r| r.cf_kind == contract_cf_kind::STORAGE)
            .expect("storage record")
            .clone();
        let meta_rec = cd
            .records
            .iter()
            .find(|r| r.cf_kind == contract_cf_kind::METADATA)
            .expect("metadata record")
            .clone();

        let accepted = executed.accept_produced(&blk).expect("accept_produced");
        accepted.publish().expect("publish");

        // Guard against a vacuous pass: None == None would satisfy the
        // comparisons below without a single byte being written.
        assert!(code_rec.new.is_some(), "journal must record the deployed code");
        assert!(storage_rec.new.is_some(), "journal must record the init write");
        assert!(meta_rec.new.is_some(), "journal must record the metadata");

        // The bytes on disk are the bytes the journal says were written — the
        // journal and the staged row cannot disagree, because both are built
        // from the same key builder and the same value.
        assert_eq!(
            db.get(cf::CONTRACT_CODE, &code_rec.key).unwrap(),
            code_rec.new,
            "published code bytes must equal what the journal recorded"
        );
        assert_eq!(
            db.get(cf::CONTRACT_STORAGE, &storage_rec.key).unwrap(),
            storage_rec.new,
            "published storage bytes must equal what the journal recorded"
        );
        assert_eq!(
            db.get(cf::CONTRACT_METADATA, &meta_rec.key).unwrap(),
            meta_rec.new,
            "published metadata bytes must equal what the journal recorded"
        );
        vec![
            (cf::CONTRACT_CODE, code_rec.key.clone(), code_rec.new.clone()),
            (cf::CONTRACT_STORAGE, storage_rec.key.clone(), storage_rec.new.clone()),
            (cf::CONTRACT_METADATA, meta_rec.key.clone(), meta_rec.new.clone()),
        ]
    };

    // Reopen the same path: contract state is durable, not merely cached.
    let db = std::sync::Arc::new(sumchain_storage::Database::open_default(dir.path()).unwrap());
    for (family, key, bytes) in &expected {
        assert_eq!(
            db.get(family, key).unwrap(),
            *bytes,
            "{family} must survive a restart"
        );
    }
}
