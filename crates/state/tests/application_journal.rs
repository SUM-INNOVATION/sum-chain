//! The application journal under a REAL block, published the way a proposer
//! publishes one.
//!
//! `crates/storage/tests/application_journal.rs` drives the machinery directly:
//! it stages known rows through an `ExecutionView` so the assertions can name
//! the exact bytes. This file answers the different question — does a block that
//! went through `BlockExecutor::execute_block`, with real transactions, real fee
//! debits and a real accumulator, leave a journal that restores what it changed.
//!
//! Publication is `common::publish_block`, which is the producer's own path:
//! execute, fill in the computed root, `accept_produced`, `publish`. Nothing
//! here hand-writes a row or hand-builds a batch.

mod common;

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_storage::db::cf;
use sumchain_storage::journal::{
    ActivationSource, ApplicationJournal, JournalActivation, JournalRequirement, Preimage,
};
use sumchain_storage::schema::journal_key;
use sumchain_storage::Database;

const FEE: u128 = 10;

fn setup() -> (
    Arc<StateManager>,
    Arc<Database>,
    tempfile::TempDir,
    BlockExecutor,
) {
    common::setup_with_params(sumchain_genesis::ChainParams::with_v2_enabled())
}

fn transfer(sender: &KeyPair, to: Address, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: common::CHAIN_ID,
        from: sender.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Transfer { to, amount },
    };
    let h = tx.signing_hash();
    let s = sign(h.as_bytes(), sender.private_key());
    SignedTransaction::new_v2(tx, *s.as_bytes(), *sender.public_key().as_bytes())
}

/// Every account row, as raw bytes.
///
/// Bytes rather than decoded balances: the claim is that undo restores the
/// column family, and a decoded comparison would pass over a row rewritten to an
/// equal value — which is still a write, and a row that was absent before must
/// come back absent, not as a zero-balance row that reads the same.
fn account_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = db
        .prefix_iter(cf::STATE, b"acct")
        .unwrap()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    out.sort();
    out
}

/// A real block leaves a journal that walks its account rows back exactly.
///
/// The recipient and the proposer have no row before the block, so their entries
/// must be absent-before and undo must DELETE them. Writing a default row
/// instead would read identically through `get_account`, which returns the
/// default for a missing key — the two are indistinguishable through the API and
/// different on disk, and the difference becomes a fork the moment anything
/// hashes stored rows.
#[test]
fn a_published_block_leaves_a_journal_that_restores_its_account_rows() {
    let (state, db, _dir, executor) = setup();
    let sender = KeyPair::generate();
    let recipient = Address::new([0x5A; 20]);
    let proposer = KeyPair::generate();
    common::fund(&db, &sender, 1_000);

    let before = account_rows(&db);
    assert_eq!(before.len(), 1, "only the funded sender exists yet");

    common::publish_block(
        &state,
        &executor,
        1,
        proposer.public_key().as_bytes(),
        vec![transfer(&sender, recipient, 100, 0)],
        &[],
    );

    let after = account_rows(&db);
    assert_ne!(after, before, "the block must have moved balances");
    assert!(
        after.len() > before.len(),
        "the recipient and the proposer are new rows"
    );

    // One journal, under this block's own (height, hash).
    let hash = sumchain_storage::schema::BlockStore::new(&db)
        .get_by_height(1)
        .unwrap()
        .expect("the block was published")
        .hash();
    let bytes = db
        .get(cf::APPLICATION_JOURNAL, &journal_key(1, &hash))
        .unwrap()
        .expect("a published block leaves a journal");
    let journal = ApplicationJournal::decode_for(&bytes, 1, &hash).expect("decode");

    assert!(
        journal.column_families().contains(cf::STATE),
        "a transfer writes account rows, so cf::STATE must be journalled: {:?}",
        journal.column_families()
    );
    // The sender existed; the recipient and proposer did not.
    let kinds: Vec<&Preimage> = journal
        .entries()
        .iter()
        .filter(|e| e.cf() == cf::STATE)
        .map(|e| e.before())
        .collect();
    assert!(
        kinds.iter().any(|p| matches!(p, Preimage::Value(_))),
        "the funded sender had a row before the block"
    );
    assert!(
        kinds.iter().any(|p| matches!(p, Preimage::Absent)),
        "the recipient and the proposer did not"
    );

    // The rows are still what the block left, and undo walks them back exactly.
    journal
        .check_current_matches_after(&db)
        .expect("nothing has moved since");
    journal.undo_batch(&db).unwrap().commit().unwrap();
    assert_eq!(
        account_rows(&db),
        before,
        "undo must restore cf::STATE byte for byte, deleting the rows the block \
         created rather than zeroing them"
    );
}

/// Two published blocks each get their own journal, and unwinding them in
/// reverse order walks the chain back block by block.
#[test]
fn consecutive_blocks_unwind_in_reverse_through_their_own_journals() {
    let (state, db, _dir, executor) = setup();
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    common::fund(&db, &sender, 10_000);

    let at_zero = account_rows(&db);
    common::publish_block(
        &state,
        &executor,
        1,
        proposer.public_key().as_bytes(),
        vec![transfer(&sender, Address::new([1; 20]), 100, 0)],
        &[],
    );
    let after_one = account_rows(&db);
    common::publish_block(
        &state,
        &executor,
        2,
        proposer.public_key().as_bytes(),
        vec![transfer(&sender, Address::new([2; 20]), 200, 1)],
        &[],
    );
    let after_two = account_rows(&db);
    assert_ne!(at_zero, after_one);
    assert_ne!(after_one, after_two);

    let store = sumchain_storage::schema::BlockStore::new(&db);
    let load = |h: u64| {
        let hash = store.get_by_height(h).unwrap().unwrap().hash();
        let bytes = db
            .get(cf::APPLICATION_JOURNAL, &journal_key(h, &hash))
            .unwrap()
            .unwrap();
        ApplicationJournal::decode_for(&bytes, h, &hash).unwrap()
    };
    let j1 = load(1);
    let j2 = load(2);
    assert_ne!(j1.block_hash(), j2.block_hash());

    j2.check_current_matches_after(&db).expect("head first");
    j2.undo_batch(&db).unwrap().commit().unwrap();
    assert_eq!(
        account_rows(&db),
        after_one,
        "undoing block 2 lands on block 1"
    );

    j1.check_current_matches_after(&db)
        .expect("then its parent");
    j1.undo_batch(&db).unwrap().commit().unwrap();
    assert_eq!(account_rows(&db), at_zero, "and then on the parent state");
}

/// The activation boundary a real chain establishes is the first height it
/// published, and a missing journal at or above it halts.
#[test]
fn the_boundary_a_real_chain_establishes_is_the_first_height_it_published() {
    let (state, db, _dir, executor) = setup();
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    common::fund(&db, &sender, 10_000);

    // Nothing published yet: no boundary, so nothing is required.
    let none_yet = JournalActivation::resolve(&db, ActivationSource::ObservedFromChain).unwrap();
    assert_eq!(none_yet.boundary(), None);
    assert_eq!(
        none_yet.requirement_at(1),
        JournalRequirement::PreActivation
    );

    for (height, nonce) in [(3u64, 0u64), (4, 1)] {
        common::publish_block(
            &state,
            &executor,
            height,
            proposer.public_key().as_bytes(),
            vec![transfer(&sender, Address::new([7; 20]), 1, nonce)],
            &[],
        );
    }

    let act = JournalActivation::resolve(&db, ActivationSource::ObservedFromChain).unwrap();
    assert_eq!(
        act.boundary(),
        Some(3),
        "the first height this node published"
    );
    assert_eq!(act.requirement_at(2), JournalRequirement::PreActivation);
    assert_eq!(act.requirement_at(3), JournalRequirement::Required);

    // A block at a post-boundary height whose journal was never written halts,
    // rather than being reverted with no undo data.
    let phantom = sumchain_primitives::Hash::hash(b"a block this node never published");
    let err = act
        .load_for_revert(&db, 5, &phantom)
        .expect_err("a missing post-activation journal must halt");
    assert!(err.to_string().contains("refusing to revert"), "{err}");

    // And the block it did publish loads.
    let hash = sumchain_storage::schema::BlockStore::new(&db)
        .get_by_height(3)
        .unwrap()
        .unwrap()
        .hash();
    assert!(act.load_for_revert(&db, 3, &hash).unwrap().is_some());
}

/// The legacy revert path refuses a block at or above the activation boundary,
/// and its `Ok(())` over an absent journal survives only below it.
///
/// `StateManager::revert_block_state_diffs` reverts from the four per-subsystem
/// diffs. Those cover strictly fewer families than a block writes — `cf::SUPPLY`
/// most visibly — so at and above the boundary reverting from them would report
/// success while leaving rows the block wrote in place. That is the silent-skip
/// the contract forbids post-activation, and it is closed by the signature: the
/// caller must pass its classification, and `Required` is refused before
/// anything is read.
///
/// Below the boundary the old behaviour is intact, including the `Ok(())` for a
/// block with no diffs at all — which is correct there, because a block
/// published by a binary that wrote no journal for a family it did not touch is
/// indistinguishable from one whose record was lost, and there is no third thing
/// to consult.
#[test]
fn the_legacy_revert_path_refuses_a_post_activation_block() {
    let (state, db, _dir, executor) = setup();
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    common::fund(&db, &sender, 10_000);

    common::publish_block(
        &state,
        &executor,
        1,
        proposer.public_key().as_bytes(),
        vec![transfer(&sender, Address::new([7; 20]), 1, 0)],
        &[],
    );
    let hash = sumchain_storage::schema::BlockStore::new(&db)
        .get_by_height(1)
        .unwrap()
        .unwrap()
        .hash();

    let err = state
        .revert_block_state_diffs(1, &hash, JournalRequirement::Required)
        .expect_err("the legacy path must refuse a post-activation block");
    let msg = err.to_string();
    assert!(
        msg.contains("generic journal is authoritative and mandatory"),
        "the refusal must say which record governs and why: {msg}"
    );
    assert!(
        msg.contains("ActivatedJournal"),
        "and must name the path that does govern it: {msg}"
    );

    // The refusal read nothing and wrote nothing: the diffs are still there for
    // the correct path to consume.
    assert!(db
        .get(cf::STATE_DIFFS, &journal_key(1, &hash))
        .unwrap()
        .is_some());

    // Below the boundary the same call is the old behaviour, and an absence is
    // the tolerated silence.
    let absent = sumchain_primitives::Hash::hash(b"a block with no diffs at all");
    state
        .revert_block_state_diffs(9, &absent, JournalRequirement::PreActivation)
        .expect("pre-activation absence is Ok(()), which is the only place it is");

    // And the real revert below the boundary still works.
    state
        .revert_block_state_diffs(1, &hash, JournalRequirement::PreActivation)
        .expect("pre-activation revert from the legacy diffs is unchanged");
    assert!(db
        .get(cf::STATE_DIFFS, &journal_key(1, &hash))
        .unwrap()
        .is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Release blocker 5: is `StateManager::revert_block_state_diffs` reached from
// production, or is it dead?
// ─────────────────────────────────────────────────────────────────────────────

/// `StateManager::revert_block_state_diffs` has NO production caller anywhere in
/// the workspace, and this checks it rather than asserting it.
///
/// # Why this is a test and not a note
///
/// The function carries a post-activation REFUSAL: at or above the journal
/// activation boundary it returns `Err` without reading anything, because the
/// four legacy per-subsystem journals cover fewer families than a block writes
/// and reverting from them there would report success over rows nothing
/// restored. A refusal is only as good as the path it guards, and the honest
/// finding is that today it guards no live path: the production reorg path is
/// `sumchain_state::reorg_undo::ActivatedJournal`, driven from
/// `PoAEngine::import_reorg` through `execute_reorg`.
///
/// So the status is DEAD IN PRODUCTION, deliberately, and the guard is a
/// contract on a public API rather than protection for a live caller. That is a
/// decision, and a decision that is only written down drifts. This makes it
/// fail if the situation changes in either direction — a new production caller
/// appears, or the function is removed and this test stops finding it.
///
/// # What this does NOT say
///
/// It does not say nothing unwinds application state outside consensus.
/// `sum-node rollback` (`crates/node/src/main.rs`) does, and it does so with its
/// own open-coded loop that reads `cf::STATE_DIFFS` directly: it reverts account
/// rows only, consults neither the contract diff nor the generic application
/// journal, and never asks where the activation boundary is. Post-activation it
/// therefore under-reverts in exactly the way this function's guard exists to
/// prevent. That is a finding about an operator tool, recorded in §11.1 of
/// `docs/lane-a/JOURNAL-CONTRACT.md`; it is NOT fixed here, and this test pins
/// its shape so the claim can be rechecked.
#[test]
fn the_legacy_revert_path_has_no_production_caller_and_the_rollback_cli_has_its_own() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();
    let crates = workspace.join("crates");
    assert!(crates.is_dir(), "expected {}", crates.display());

    /// Every `.rs` under `<crate>/src`, recursively.
    fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                sources(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    let mut files = Vec::new();
    for e in std::fs::read_dir(&crates).expect("read crates/").flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            sources(&src, &mut files);
        }
    }
    assert!(
        files.len() > 50,
        "the scan must actually have found the workspace sources: {}",
        files.len()
    );

    let mut production_callers = Vec::new();
    let mut saw_definition = false;
    for path in &files {
        let text = std::fs::read_to_string(path).expect("read source");
        if text.contains("pub fn revert_block_state_diffs(") {
            saw_definition = true;
        }
        // Everything from the first column-zero `#[cfg(test)]` onward is a test
        // module, not production. Nothing above it in any of these files is.
        let production = match text.find("\n#[cfg(test)]") {
            Some(at) => &text[..at],
            None => &text[..],
        };
        // A CALL, not the definition and not a doc-comment mention: the method
        // is only reachable as `.revert_block_state_diffs(`.
        for (n, line) in production.lines().enumerate() {
            if line.contains(".revert_block_state_diffs(") {
                production_callers.push(format!(
                    "{}:{}",
                    path.strip_prefix(&workspace).unwrap_or(path).display(),
                    n + 1
                ));
            }
        }
    }

    assert!(
        saw_definition,
        "the scan did not find the definition, so a clean result would mean nothing"
    );
    assert!(
        production_callers.is_empty(),
        "`StateManager::revert_block_state_diffs` now HAS a production caller. That is \
         not a failure — it is the situation this test exists to notice. Its \
         post-activation refusal is no longer a contract on an unused API but a guard on \
         a live path, and the caller must be checked for whether it classifies the \
         height before calling. Callers found: {production_callers:?}"
    );

    // And the operator tool that DOES unwind application state outside consensus
    // still has its own loop, which is the other half of the finding.
    let main_rs = crates.join("node/src/main.rs");
    let main = std::fs::read_to_string(&main_rs).expect("read the node CLI");
    assert!(
        main.contains("Commands::Rollback"),
        "the rollback subcommand must still exist for this claim to be about anything"
    );
    assert!(
        !main.contains(".revert_block_state_diffs("),
        "the rollback CLI now routes through the guarded function; update §11.1 of \
         docs/lane-a/JOURNAL-CONTRACT.md, which records that it does not"
    );
    assert!(
        main.contains("get_state_diff"),
        "the rollback CLI still reads the legacy account diff directly, which is what \
         makes it a third unwind implementation"
    );
}
