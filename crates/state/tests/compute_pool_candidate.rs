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

/// Seed a PARENT that already holds `rows`, before any candidate exists.
///
/// Not a publisher: nothing here reads a candidate. It writes the rows a prior
/// block would have left behind, which is the starting state these tests need.
/// The compute-pool gate is `None` and there is no live operation source yet
/// (#125), so a real block cannot carry a C1 transition — publication
/// integration stays deferred until it can, and until then a parent is seeded
/// rather than produced.
fn seed_parent(db: &Database, rows: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>) {
    let mut batch = db.batch();
    for (k, v) in rows {
        batch.put(cf::COMPUTE_POOL_STATE, k, v).unwrap();
    }
    batch.commit().unwrap();
}

/// Seed a journal row verbatim, before any candidate exists.
fn seed_journal(db: &Database, height: u64, hash: &Hash, bytes: &[u8]) {
    db.put(
        cf::COMPUTE_POOL_STATE_DIFFS,
        &sumchain_storage::schema::journal_key(height, hash),
        bytes,
    )
    .unwrap();
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

    let store = ComputePoolStore::new(&db);
    let empty_digest = store.state_digest().unwrap();

    // The digest a block would fold, over rows it staged and has not published.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let candidate_digest = {
        let mut view = ExecutionView::new(&mut overlay);
        ComputePoolStore::stage_transition(&mut view, None, &after).unwrap();
        ComputePoolStore::v_state_digest(&view).unwrap()
    };
    assert_ne!(
        candidate_digest, empty_digest,
        "a candidate that staged rows must not digest like the empty parent; if \
         these are equal the digest is reading committed state"
    );
    drop(overlay);

    // Nothing was published, so the committed digest is still the parent's.
    assert_eq!(store.state_digest().unwrap(), empty_digest);

    // Now a SECOND database whose parent already holds exactly those rows, seeded
    // before any candidate exists. Its committed digest must equal the one the
    // candidate folded: same rows, same encoding, whichever side computes it.
    // That is the parity a proposer and a validator depend on, and it is what
    // `digest_of` being shared guarantees.
    let (_d2, db2) = open_db();
    seed_parent(&db2, &ComputePoolStore::materialize(&after).unwrap());
    assert_eq!(
        ComputePoolStore::new(&db2).state_digest().unwrap(),
        candidate_digest,
        "the committed digest over identical rows must equal the candidate's"
    );

    // And a candidate opened over that parent — the validator's own
    // recomputation — agrees with both.
    let mut ov2 = ApplicationOverlay::new(&db2, LIMIT);
    let view2 = ExecutionView::new(&mut ov2);
    assert_eq!(
        ComputePoolStore::v_state_digest(&view2).unwrap(),
        candidate_digest
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
    // A parent that already holds rows, seeded before any candidate exists.
    seed_parent(&db, &ComputePoolStore::materialize(&live).unwrap());

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
    // The subject is the KEYING, so the journal bytes are seeded verbatim: two
    // blocks at one height, two distinct rows, neither overwriting the other.
    // What each journal decodes to is `multi_record_apply_revert_reapply_is_exact`'s
    // subject, not this one.
    let (_d, db) = open_db();
    seed_journal(&db, HEIGHT, &block_hash(0), b"canonical-journal");
    seed_journal(&db, HEIGHT, &block_hash(1), b"side-branch-journal");

    let store = ComputePoolStore::new(&db);
    assert!(store.has_journal(HEIGHT, &block_hash(0)).unwrap());
    assert!(store.has_journal(HEIGHT, &block_hash(1)).unwrap());
    assert_ne!(
        db.get(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &sumchain_storage::schema::journal_key(HEIGHT, &block_hash(0)),
        )
        .unwrap(),
        db.get(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &sumchain_storage::schema::journal_key(HEIGHT, &block_hash(1)),
        )
        .unwrap(),
        "each block's journal row must survive the other's"
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

    // A row under the height alone. The reader refuses on the KEY, before it
    // decodes anything, so the bytes need only be present — and seeding them
    // keeps this test free of a candidate it would then have to publish.
    db.put(
        cf::COMPUTE_POOL_STATE_DIFFS,
        &HEIGHT.to_be_bytes(),
        b"a-journal-under-the-height-alone",
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

    // This block's journal, seeded under the publisher's key. The reader never
    // decodes it here — it refuses on the stray row below first, which is the
    // whole point — so the bytes need only be present.
    seed_journal(&db, HEIGHT, &block_hash(0), b"this-blocks-journal");
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
