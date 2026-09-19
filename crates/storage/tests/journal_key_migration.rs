//! The undo-journal re-keying, in both directions.
//!
//! ACTIVATION-AUDIT row JR-1. The per-block undo journal key changed shape from
//! height alone to `height ‖ block_hash` (`crates/storage/src/schema.rs`), with
//! no activation height, and the audit's finding is that it needs none: the
//! journals are node-local undo data in `cf::STATE_DIFFS` and
//! `cf::CONTRACT_STATE_DIFFS`, neither of which reaches
//! `compute_block_state_root`, so no transaction's validity turns on the key.
//!
//! What the row leaves behind is an OPERATIONAL asymmetry, and these tests pin
//! it as an asymmetry rather than asserting only the comfortable half:
//!
//!   * **Upgrade works.** A journal written by an older binary under the
//!     height-only key is still read, because the reader falls back to it, and
//!     still deleted, because the delete removes both forms. A node upgraded
//!     mid-chain can revert a block it executed before the upgrade.
//!   * **Downgrade does not, and cannot.** A journal written under the new key
//!     is invisible to a binary that knows only the old one. There is no code
//!     that can fix this from the new side — the old binary is the thing doing
//!     the looking — so the remedy is operational and lives in
//!     `docs/operations/production-checklist.md`, not in an activation height.
//!
//! The second test is the one that matters. It asserts a NEGATIVE that the
//! tree's own comments only assert in prose, and it is what makes the checklist
//! entry a claim about this code rather than a guess about it.

use sumchain_primitives::Hash;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::{AccountState, StateDiff, StateStore};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

/// The key an old binary writes and looks under: the height, big-endian, alone.
///
/// Transcribed here on purpose. `legacy_journal_key` is private to `schema`,
/// and the point of this file is to stand where the OLD binary stands, which
/// is outside this crate's private helpers.
fn old_binary_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

fn a_diff(balance: u128) -> StateDiff {
    let mut diff = StateDiff::new();
    diff.add_change(
        sumchain_primitives::Address::new([0x7a; 20]),
        None,
        AccountState { balance, nonce: 3 },
    );
    diff
}

/// JR-1, the upgrade direction: what the old binary wrote, the new one reads
/// and removes.
#[test]
fn a_journal_written_under_the_old_key_is_still_read_and_still_deleted() {
    let (database, _dir) = db();
    let store = StateStore::new(&database);
    let height = 41u64;
    let block_hash = Hash::hash(b"the block the old binary executed");

    // Exactly what the pre-#253 binary did: height alone, no hash.
    database
        .put(
            cf::STATE_DIFFS,
            &old_binary_key(height),
            &bincode::serialize(&a_diff(900)).expect("serialize"),
        )
        .expect("stage a legacy journal");

    let read = store
        .get_state_diff(height, &block_hash)
        .expect("read")
        .expect("the reader falls back to the legacy key, so the old journal is found");
    assert_eq!(
        read.changes.len(),
        1,
        "JR-1: the upgrade direction is handled -- a journal the old binary \
         wrote is readable by this one, which is what lets an upgraded node \
         revert a block it executed before the upgrade"
    );
    assert_eq!(
        read.changes[0].2.balance, 900,
        "and it is the right journal"
    );

    store
        .delete_state_diff(height, &block_hash)
        .expect("delete removes both key forms");
    assert!(
        database
            .get(cf::STATE_DIFFS, &old_binary_key(height))
            .expect("probe")
            .is_none(),
        "JR-1: the delete removes the LEGACY form too, so legacy rows drain as \
         blocks are reverted or pruned and nothing re-creates them"
    );
}

/// JR-1, the downgrade direction: what this binary writes, the old one cannot
/// see — which is why the remedy is a checklist entry and not a gate.
#[test]
fn a_journal_written_under_the_new_key_is_invisible_to_the_old_one() {
    let (database, _dir) = db();
    let store = StateStore::new(&database);
    let height = 41u64;
    let block_hash = Hash::hash(b"the block the new binary executed");

    store
        .put_state_diff(height, &block_hash, &a_diff(1_200))
        .expect("write a journal the way this binary writes one");

    // The new binary can see it, keyed by height AND hash.
    assert!(
        store
            .get_state_diff(height, &block_hash)
            .expect("read")
            .is_some(),
        "the writing binary reads back its own journal"
    );

    // The old binary looks under eight bytes and finds nothing. This is the
    // whole of the hazard: the rollback is silent. There is no error, no
    // missing column family and no decode failure -- the journal simply is not
    // where the old binary looks, so the block's undo record is lost and the
    // reorg that would have used it cannot run.
    assert!(
        database
            .get(cf::STATE_DIFFS, &old_binary_key(height))
            .expect("probe")
            .is_none(),
        "JR-1: a journal written under `height ‖ block_hash` is NOT visible \
         under the height-only key, so rolling a validator back to a binary \
         that knows only that key loses the undo record of every block the new \
         binary executed. Nothing on this side can repair that -- the old \
         binary is the one doing the looking -- which is why the remedy is the \
         rollback-coordination entry in docs/operations/production-checklist.md \
         and not an activation height"
    );

    // And the same asymmetry on the contract journal, which shares the key
    // builder and is the other family the row names.
    let contract = sumchain_storage::schema::ContractStateDiff::new();
    store
        .put_contract_state_diff(height, &block_hash, &contract)
        .expect("write a contract journal");
    assert!(
        database
            .get(cf::CONTRACT_STATE_DIFFS, &old_binary_key(height))
            .expect("probe")
            .is_none(),
        "JR-1: `cf::CONTRACT_STATE_DIFFS` is re-keyed by the same builder and \
         is invisible to the old binary for the same reason"
    );
}
