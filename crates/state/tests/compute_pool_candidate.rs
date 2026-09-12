//! The compute-pool subsystem reads and writes the block's candidate.
//!
//! C1 rows are folded into the block state root once the gate is open, which
//! makes this more than a storage concern. If `stage_transition` buffers rows
//! into the candidate while `state_digest` still reads committed state, the root
//! commits to the PARENT's compute-pool state while the block publishes the
//! child's rows — every validator computes a root that disagrees with the state
//! it stores. Reads and writes have to move together, and these tests pin that.
//!
//! They drive the store directly, without a block or an executor, so they assert
//! the property rather than the pipeline around it.

use std::sync::Arc;

use sumchain_primitives::{Address, Hash};
use sumchain_state::compute_pool::{
    ComputePoolModel, ExposureInputs, JobId, UnitId, UnitSizing, UnitState, WorkUnit,
};
use sumchain_state::compute_pool_store::{ComputePoolStateDiff, ComputePoolStore};
use sumchain_storage::candidate::JournalRecord;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database};

const LIMIT: u64 = 1 << 20;
const HEIGHT: u64 = 5;

fn open_db() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

fn block_hash(variant: u8) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&HEIGHT.to_be_bytes());
    b[31] = variant;
    Hash::new(b)
}

/// A model holding one job with one unit, seeded by `seed`.
fn model_with_job(seed: u8) -> ComputePoolModel {
    let mut m = ComputePoolModel::new();
    let job = JobId::from_bytes([seed; 32]);
    let unit = UnitId::from_bytes([seed.wrapping_add(1); 32]);
    m.create_job(
        job,
        Address::new([9; 20]),
        1,
        vec![WorkUnit {
            job_id: job,
            unit_id: unit,
            predecessors: vec![],
            required_inputs: vec![],
            generation: 0,
            state: UnitState::Blocked,
        }],
        &[UnitSizing { slots: 0 }],
        1,
        0,
        1_000,
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0,
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        },
        1_000_000,
    )
    .unwrap();
    m
}

/// Publish what a candidate staged: the journal's rows, and the journal itself
/// under the publisher's `(height, block_hash)` key. Stands in for
/// `AcceptedCandidate::publish`, whose overlay-to-batch seam is private to
/// `sumchain-storage`.
fn publish(db: &Database, journal: &JournalRecord, height: u64, hash: &Hash) {
    let JournalRecord::Recorded(bytes) = journal else {
        return;
    };
    let diff = ComputePoolStateDiff::decode(bytes).unwrap();
    let mut batch = db.batch();
    for r in &diff.records {
        match &r.new {
            Some(v) => batch.put(cf::COMPUTE_POOL_STATE, &r.key, v).unwrap(),
            None => batch.delete(cf::COMPUTE_POOL_STATE, &r.key).unwrap(),
        }
    }
    batch
        .put(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &sumchain_storage::schema::journal_key(height, hash),
            bytes,
        )
        .unwrap();
    batch.commit().unwrap();
}

#[test]
fn staged_rows_are_visible_to_the_same_block_and_to_nobody_else() {
    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let after = model_with_job(1);

    let (mutated, journal) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &after).unwrap()
    };
    assert!(mutated > 0);
    assert!(matches!(journal, JournalRecord::Recorded(_)));

    let view = ExecutionView::new(&mut overlay);

    // The block sees its own rows, and they are exactly the model's canonical
    // materialization.
    assert_eq!(
        ComputePoolStore::v_load_state_map(&view).unwrap(),
        ComputePoolStore::materialize(&after).unwrap(),
    );

    // Nobody else does. Committed state is untouched: the rows are buffered.
    let store = ComputePoolStore::new(&db);
    assert!(
        store.load_state_map().unwrap().is_empty(),
        "staging must not reach canonical storage"
    );

    // And the journal was RETURNED, not written. Writing it here is what keyed
    // it by height alone, before the block hash was final.
    assert!(
        db.get(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &HEIGHT.to_be_bytes()
        )
        .unwrap()
        .is_none(),
        "the journal must travel as an artifact, not as a row written during execution"
    );
}

#[test]
fn the_candidate_digest_is_the_digest_of_what_gets_published() {
    // The consensus property. A proposer folds the digest computed over its
    // candidate; a validator that stores the block recomputes it over committed
    // state. If those two differ by a byte, the network splits.
    let (_d, db) = open_db();
    let after = model_with_job(2);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let (candidate_digest, journal) = {
        let mut view = ExecutionView::new(&mut overlay);
        let (_, journal) = ComputePoolStore::stage_transition(&mut view, None, &after).unwrap();
        (ComputePoolStore::v_state_digest(&view).unwrap(), journal)
    };

    let store = ComputePoolStore::new(&db);
    let empty_digest = store.state_digest().unwrap();
    assert_ne!(
        candidate_digest, empty_digest,
        "a candidate that staged rows must not digest like the empty parent; if \
         these are equal the digest is reading committed state"
    );

    drop(overlay);
    publish(&db, &journal, HEIGHT, &block_hash(0));

    assert_eq!(
        store.state_digest().unwrap(),
        candidate_digest,
        "the published digest must equal the one the block folded into its root"
    );
}

#[test]
fn a_second_transition_in_one_block_is_rejected_with_the_candidate_intact() {
    let (_d, db) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let first = model_with_job(3);

    let staged = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &first).unwrap();
        ComputePoolStore::v_load_state_map(&view).unwrap()
    };

    let mut view = ExecutionView::new(&mut overlay);
    let err = ComputePoolStore::stage_transition(&mut view, Some(&first), &model_with_job(4))
        .unwrap_err();
    assert!(
        format!("{err}").contains("already staged"),
        "expected a duplicate-transition rejection, got {err}"
    );

    assert_eq!(
        ComputePoolStore::v_load_state_map(&view).unwrap(),
        staged,
        "a rejected second transition must leave the candidate byte-identical"
    );
}

#[test]
fn a_stale_predecessor_is_rejected_against_the_candidate() {
    // The predecessor check reads the candidate, not the chain. Claiming an
    // empty predecessor against a database that already holds rows is refused.
    let (_d, db) = open_db();
    let live = model_with_job(5);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let (_, journal) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &live).unwrap()
    };
    drop(overlay);
    publish(&db, &journal, HEIGHT, &block_hash(0));

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let err =
        ComputePoolStore::stage_transition(&mut view, None, &model_with_job(6)).unwrap_err();
    assert!(
        format!("{err}").contains("stale `before` snapshot"),
        "got {err}"
    );
}

#[test]
fn a_dropped_candidate_leaves_storage_byte_identical() {
    let (_d, db) = open_db();
    let store = ComputePoolStore::new(&db);
    let before_rows = store.load_state_map().unwrap();
    let before_digest = store.state_digest().unwrap();

    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let (mutated, journal) =
            ComputePoolStore::stage_transition(&mut view, None, &model_with_job(7)).unwrap();
        assert!(mutated > 0);
        assert!(matches!(journal, JournalRecord::Recorded(_)));
        // The candidate is dropped here, journal and all.
    }

    assert_eq!(store.load_state_map().unwrap(), before_rows);
    assert_eq!(store.state_digest().unwrap(), before_digest);
    assert!(
        !store.has_journal(HEIGHT, &block_hash(0)).unwrap(),
        "a dropped candidate must leave no journal"
    );
}

#[test]
fn two_blocks_at_one_height_keep_separate_journals() {
    // The old journal key was the height alone, which two competing blocks
    // share: the side branch's journal overwrote the canonical one, and the
    // guard meant to prevent that instead refused the side branch outright.
    let (_d, db) = open_db();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let (_, canonical) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &model_with_job(8)).unwrap()
    };
    drop(overlay);
    publish(&db, &canonical, HEIGHT, &block_hash(0));

    // A competing block at the same height, executed against the same parent.
    // Its own candidate, its own journal.
    let (_d2, db2) = open_db();
    let mut overlay = ApplicationOverlay::new(&db2, LIMIT);
    let (_, side) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &model_with_job(9)).unwrap()
    };
    drop(overlay);
    publish(&db, &side, HEIGHT, &block_hash(1));

    let store = ComputePoolStore::new(&db);
    assert!(store.has_journal(HEIGHT, &block_hash(0)).unwrap());
    assert!(store.has_journal(HEIGHT, &block_hash(1)).unwrap());
    assert_ne!(
        store.load_journal(HEIGHT, &block_hash(0)).unwrap(),
        store.load_journal(HEIGHT, &block_hash(1)).unwrap(),
        "each block's journal must describe its own transition"
    );
}

#[test]
fn a_height_only_journal_refuses_rather_than_guessing_which_block_it_undoes() {
    // The account and contract families fall back to the pre-#253 height-only
    // key so an upgrading node can still revert blocks an older binary wrote.
    // C1 must not: the gate is `None` in production, so no compute-pool journal
    // has ever been written at any height by any binary. A height-only row here
    // cannot be a legitimate legacy journal, and it names a height and nothing
    // else — where two blocks competed there, applying it would write a
    // predecessor that never existed into canonical state, silently, because
    // every mutation in it decodes cleanly.
    let (_d, db) = open_db();
    let store = ComputePoolStore::new(&db);

    // A well-formed journal, written under the height alone.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let (_, journal) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &model_with_job(10)).unwrap()
    };
    drop(overlay);
    let JournalRecord::Recorded(bytes) = &journal else {
        panic!("expected a journal");
    };
    db.put(
        cf::COMPUTE_POOL_STATE_DIFFS,
        &HEIGHT.to_be_bytes(),
        bytes,
    )
    .unwrap();

    for (label, result) in [
        ("has_journal", store.has_journal(HEIGHT, &block_hash(0)).err()),
        ("load_journal", store.load_journal(HEIGHT, &block_hash(0)).err()),
        (
            "revert_block",
            store.revert_block(HEIGHT, &block_hash(0)).err(),
        ),
    ] {
        let err = result.unwrap_or_else(|| panic!("{label} must refuse a height-only journal"));
        assert!(
            format!("{err}").contains("keyed by height alone"),
            "{label}: {err}"
        );
    }

    // The row is still there. Deleting it would destroy the evidence an operator
    // needs to work out which block it belonged to.
    assert!(db
        .get(cf::COMPUTE_POOL_STATE_DIFFS, &HEIGHT.to_be_bytes())
        .unwrap()
        .is_some());
}

#[test]
fn a_stray_height_only_row_refuses_even_beside_a_valid_journal() {
    let (_d, db) = open_db();
    let store = ComputePoolStore::new(&db);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let (_, journal) = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &model_with_job(11)).unwrap()
    };
    drop(overlay);
    publish(&db, &journal, HEIGHT, &block_hash(0));
    assert!(store.has_journal(HEIGHT, &block_hash(0)).unwrap());

    // Now a stray legacy row appears beside the correct one. Reverting past it
    // would leave it behind to mislead the next reader.
    db.put(cf::COMPUTE_POOL_STATE_DIFFS, &HEIGHT.to_be_bytes(), b"x")
        .unwrap();
    assert!(
        store.has_journal(HEIGHT, &block_hash(0)).is_err(),
        "a stray height-only row is an anomaly even when this block's journal is present"
    );
}
