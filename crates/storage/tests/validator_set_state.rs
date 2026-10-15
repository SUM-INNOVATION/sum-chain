//! The dormant validator-set state rows (#266), end to end.
//!
//! Every row here is written the way a block's state is: through the
//! `ExecutionView` of a candidate, published by `AcceptedCandidate::publish`,
//! undone from the generic application journal that publication leaves, and
//! switched by the one adoption batch of a replacement branch. The layout is a
//! test layout in an existing family: no production layout exists.

use std::collections::BTreeSet;
use std::sync::Arc;

use sumchain_primitives::{Block, BlockHeader, Hash};
use sumchain_storage::branch::BranchState;
use sumchain_storage::candidate::{
    build_adoption_batch, BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
    SpeculativeBlock,
};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::journal::{ApplicationJournal, Preimage};
use sumchain_storage::schema::journal_key;
use sumchain_storage::validator_set_record::{ValidatorSetRecord, ValidatorSetRecordError};
use sumchain_storage::validator_set_state::{
    read, stage_insert, stage_replace, Presence, StateError, ValidatorSetLayout,
};
use tempfile::TempDir;

const LIMIT: u64 = 1 << 22;

/// Above the legacy root-compatibility window, so a root mismatch is refused
/// rather than force-adopted.
const VERIFIED_HEIGHT: u64 = 1_000_000;

const PREFIX: &[u8] = b"test/validator-set/";

struct TestLayout;

impl ValidatorSetLayout for TestLayout {
    fn row_location(&self, key: u64) -> (&'static str, Vec<u8>) {
        (cf::STATE, row_key(key))
    }
}

fn row_key(key: u64) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(&key.to_be_bytes());
    k
}

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

fn member(b: u8) -> [u8; 32] {
    [b; 32]
}

fn set(key: u64, members: &[u8]) -> ValidatorSetRecord {
    ValidatorSetRecord::new(key, members.iter().copied().map(member).collect()).unwrap()
}

/// A block with no transactions. `tag` reaches the timestamp and transaction
/// root, so two blocks at one height with different tags have different hashes.
fn block(parent: Hash, height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        parent,
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    Block::new(header, Vec::new())
}

fn journals() -> BlockJournals {
    BlockJournals {
        account: JournalRecord::NothingToUndo,
        contract: JournalRecord::NothingToUndo,
        compute_pool: JournalRecord::NothingToUndo,
        beacon: JournalRecord::NothingToUndo,
    }
}

type Writes<'f> = Box<dyn FnOnce(&mut ExecutionView<'_, '_>) -> Result<(), StateError> + 'f>;

/// Execute `writes` into a candidate for `block` and publish it. A refused
/// write fails the attempt; it never produces a block that wrote less.
fn publish(d: &Database, block: &Block, writes: Writes<'_>) -> Result<(), String> {
    let mut cand = CandidateExecution::new(d, LIMIT);
    {
        let mut view = cand.view();
        writes(&mut view).map_err(|e| e.to_string())?;
    }
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        block.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(block)
    .map_err(|e| e.to_string())?
    .publish()
    .map_err(|e| e.to_string())
}

fn insert(record: ValidatorSetRecord) -> Writes<'static> {
    Box::new(move |view| stage_insert(view, &TestLayout, &record))
}

fn replace(record: ValidatorSetRecord) -> Writes<'static> {
    Box::new(move |view| stage_replace(view, &TestLayout, &record).map(|_| ()))
}

fn journal_of(d: &Database, block: &Block) -> ApplicationJournal {
    let bytes = d
        .get(
            cf::APPLICATION_JOURNAL,
            &journal_key(block.height(), &block.hash()),
        )
        .unwrap()
        .expect("a published block leaves a journal");
    ApplicationJournal::decode_for(&bytes, block.height(), &block.hash()).unwrap()
}

/// Revert `block` the way a rollback does: from its own journal, after
/// checking the rows still hold what it left.
fn undo(d: &Database, block: &Block) {
    let j = journal_of(d, block);
    j.check_current_matches_after(d).unwrap();
    j.undo_batch(d).unwrap().commit().unwrap();
}

fn stored(d: &Database, key: u64) -> Option<Vec<u8>> {
    d.get(cf::STATE, &row_key(key)).unwrap()
}

/// Every membership row.
fn membership(d: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    d.iter(cf::STATE)
        .unwrap()
        .filter(|(k, _)| k.starts_with(PREFIX))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

/// Every row of every family, for proving a refusal touched nothing.
fn whole_db(d: &Database) -> BTreeSet<(String, Vec<u8>, Vec<u8>)> {
    let mut out = BTreeSet::new();
    for name in ALL_CFS {
        if let Ok(it) = d.iter(name) {
            for (k, v) in it {
                out.insert((name.to_string(), k.to_vec(), v.to_vec()));
            }
        }
    }
    out
}

fn published(d: &Database, block: &Block) -> bool {
    d.get(cf::BLOCK_HEIGHT, &block.height().to_be_bytes())
        .unwrap()
        .is_some()
}

fn committed(d: &Database, key: u64) -> ValidatorSetRecord {
    read(d, &TestLayout, key, Presence::Required)
        .unwrap()
        .expect("required")
}

// ── S1: a row lands only with its block ────────────────────────────────────

#[test]
fn s1_a_row_lands_only_when_its_block_is_published_and_with_it() {
    let (d, _g) = db();
    let b = block(Hash::hash(b"genesis"), 1, 1);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    {
        let mut view = cand.view();
        stage_insert(&mut view, &TestLayout, &set(1, &[3, 1, 2])).unwrap();
        // Execution reads its own write.
        assert_eq!(
            read(&view, &TestLayout, 1, Presence::Required).unwrap(),
            Some(set(1, &[3, 1, 2]))
        );
    }
    // Executed, not yet published: neither the row nor the block is stored.
    assert_eq!(stored(&d, 1), None);
    assert!(!published(&d, &b));
    read(&d, &TestLayout, 1, Presence::Absent).unwrap();

    cand.finish_execution(
        ExecutionSubject::of(&b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(&b)
    .unwrap()
    .publish()
    .unwrap();
    assert!(published(&d, &b));
    assert_eq!(committed(&d, 1), set(1, &[3, 1, 2]));
}

#[test]
fn s1_an_abandoned_candidate_writes_nothing() {
    let (d, _g) = db();
    let before = whole_db(&d);
    {
        let mut cand = CandidateExecution::new(&d, LIMIT);
        let mut view = cand.view();
        stage_insert(&mut view, &TestLayout, &set(1, &[1])).unwrap();
    }
    assert_eq!(whole_db(&d), before);
}

#[test]
fn s1_a_block_refused_at_acceptance_writes_nothing() {
    let (d, _g) = db();
    let before = whole_db(&d);
    let b = block(Hash::hash(b"parent"), VERIFIED_HEIGHT, 1);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    {
        let mut view = cand.view();
        stage_insert(&mut view, &TestLayout, &set(1, &[1])).unwrap();
    }
    let err = cand
        .finish_execution(
            ExecutionSubject::of(&b).unwrap(),
            Hash::hash(b"some other root"),
            Vec::new(),
            journals(),
        )
        .accept_imported(&b)
        .expect_err("a root mismatch above the legacy window is refused");
    assert!(err.to_string().contains("state root mismatch"), "{err}");
    assert_eq!(whole_db(&d), before);
}

#[test]
fn s1_a_write_over_the_block_ceiling_fails_the_attempt_and_writes_nothing() {
    let (d, _g) = db();
    let before = whole_db(&d);
    {
        let mut cand = CandidateExecution::new(&d, 64);
        let mut view = cand.view();
        let err = stage_insert(&mut view, &TestLayout, &set(1, &[1, 2, 3, 4]))
            .expect_err("a row larger than the ceiling is refused");
        assert!(matches!(err, StateError::Storage(_)), "{err}");
    }
    assert_eq!(whole_db(&d), before);
}

#[test]
fn s1_the_stored_bytes_are_exactly_the_row_encoding() {
    let (d, _g) = db();
    let r = set(9, &[5, 4]);
    publish(&d, &block(Hash::hash(b"g"), 1, 1), insert(r.clone())).unwrap();
    assert_eq!(stored(&d, 9), Some(r.encode()));
    assert_eq!(membership(&d).len(), 1);
}

// ── S2: rollback is the generic journal ────────────────────────────────────

#[test]
fn s2_the_journal_records_the_row_with_no_membership_specific_code() {
    let (d, _g) = db();
    let b1 = block(Hash::hash(b"g"), 1, 1);
    publish(&d, &b1, insert(set(1, &[1, 2]))).unwrap();
    let b2 = block(b1.hash(), 2, 2);
    publish(&d, &b2, replace(set(1, &[3]))).unwrap();

    let e1 = journal_of(&d, &b1);
    let e1 = e1
        .entries()
        .iter()
        .find(|e| e.cf() == cf::STATE && e.key() == row_key(1).as_slice())
        .expect("the inserting block's journal covers the row")
        .before()
        .clone();
    assert_eq!(e1, Preimage::Absent);

    let e2 = journal_of(&d, &b2);
    let e2 = e2
        .entries()
        .iter()
        .find(|e| e.cf() == cf::STATE && e.key() == row_key(1).as_slice())
        .expect("the replacing block's journal covers the row")
        .before()
        .clone();
    assert_eq!(e2, Preimage::Value(set(1, &[1, 2]).encode()));
}

#[test]
fn s2_undoing_blocks_restores_each_prior_row_exactly() {
    let (d, _g) = db();
    let b1 = block(Hash::hash(b"g"), 1, 1);
    publish(&d, &b1, insert(set(1, &[1, 2]))).unwrap();
    let b2 = block(b1.hash(), 2, 2);
    publish(&d, &b2, replace(set(1, &[3]))).unwrap();
    assert_eq!(committed(&d, 1), set(1, &[3]));

    undo(&d, &b2);
    assert_eq!(committed(&d, 1), set(1, &[1, 2]));
    assert_eq!(stored(&d, 1), Some(set(1, &[1, 2]).encode()));

    undo(&d, &b1);
    assert_eq!(
        stored(&d, 1),
        None,
        "an inserted row is deleted, not emptied"
    );
    read(&d, &TestLayout, 1, Presence::Absent).unwrap();
}

#[test]
fn s2_apply_a_undo_a_apply_b_leaves_the_state_b_alone_leaves() {
    let parent = Hash::hash(b"g");
    let a = block(parent, 1, 1);
    let b = block(parent, 1, 2);
    let writes_b = || -> Writes<'static> {
        Box::new(|view| {
            stage_insert(view, &TestLayout, &set(1, &[7, 8]))?;
            stage_insert(view, &TestLayout, &set(2, &[9]))
        })
    };

    let (alone, _g1) = db();
    publish(&alone, &b, writes_b()).unwrap();

    let (d, _g2) = db();
    publish(
        &d,
        &a,
        Box::new(|view| {
            stage_insert(view, &TestLayout, &set(1, &[1, 2]))?;
            stage_insert(view, &TestLayout, &set(3, &[4]))
        }),
    )
    .unwrap();
    undo(&d, &a);
    publish(&d, &b, writes_b()).unwrap();

    let state = |d: &Database| -> Vec<(Vec<u8>, Vec<u8>)> {
        d.iter(cf::STATE)
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    };
    assert_eq!(state(&d), state(&alone));
    assert_eq!(membership(&d), membership(&alone));
}

#[test]
fn s2_a_row_moved_on_since_the_block_refuses_the_whole_undo() {
    let (d, _g) = db();
    let b1 = block(Hash::hash(b"g"), 1, 1);
    publish(&d, &b1, insert(set(1, &[1]))).unwrap();
    let b2 = block(b1.hash(), 2, 2);
    publish(&d, &b2, replace(set(1, &[2]))).unwrap();
    // b1's journal says it left [1]; the row now holds b2's [2].
    let err = journal_of(&d, &b1)
        .check_current_matches_after(&d)
        .expect_err("undoing out of order is refused");
    assert!(
        err.to_string().contains("refusing to apply any preimage"),
        "{err}"
    );
    assert_eq!(committed(&d, 1), set(1, &[2]));
}

// ── S3: competing blocks and a branch switch ───────────────────────────────

#[test]
fn s3_competing_blocks_hold_separate_sets_and_adoption_switches_them_in_one_batch() {
    let (d, _g) = db();
    let p = block(Hash::hash(b"g"), 1, 1);
    publish(&d, &p, insert(set(1, &[1, 2, 3]))).unwrap();

    // Canonical child: replaces the set.
    let a = block(p.hash(), 2, 10);
    publish(&d, &a, replace(set(1, &[4, 5]))).unwrap();
    assert_eq!(committed(&d, 1), set(1, &[4, 5]));

    // A sibling at the same height, executed on the fork parent rebuilt from
    // the canonical child's journal.
    let b = block(p.hash(), 2, 20);
    assert_ne!(a.hash(), b.hash());
    let mut layer = BranchState::new(LIMIT);
    layer.restore_parent(&d, &journal_of(&d, &a)).unwrap();
    let layer = Arc::new(layer);

    let spec: SpeculativeBlock = {
        let mut cand = CandidateExecution::on_branch(&d, layer.clone(), LIMIT);
        {
            let mut view = cand.view();
            // The sibling reads the parent's set, not the canonical child's.
            assert_eq!(
                read(&view, &TestLayout, 1, Presence::Required).unwrap(),
                Some(set(1, &[1, 2, 3]))
            );
            let replaced = stage_replace(&mut view, &TestLayout, &set(1, &[6])).unwrap();
            assert_eq!(replaced, set(1, &[1, 2, 3]));
        }
        cand.finish_execution(
            ExecutionSubject::of(&b).unwrap(),
            b.header.state_root,
            Vec::new(),
            journals(),
        )
        .accept_imported(&b)
        .unwrap()
        .into_speculative()
        .unwrap()
    };
    // Executing the sibling wrote nothing canonical.
    assert_eq!(committed(&d, 1), set(1, &[4, 5]));

    let mut layer = Arc::try_unwrap(layer).expect("the candidate released the layer");
    layer.absorb_net_writes(spec.net_writes()).unwrap();
    let before_commit = whole_db(&d);
    let (batch, _report) = build_adoption_batch(
        &d,
        std::slice::from_ref(&a),
        &[(
            cf::APPLICATION_JOURNAL.to_string(),
            journal_key(a.height(), &a.hash()).to_vec(),
        )],
        &layer,
        std::slice::from_ref(&spec),
        LIMIT,
    )
    .unwrap();
    assert_eq!(
        whole_db(&d),
        before_commit,
        "nothing lands before the commit"
    );
    batch.commit().unwrap();

    assert_eq!(committed(&d, 1), set(1, &[6]));
    assert_eq!(membership(&d).len(), 1);
    assert_eq!(
        d.get(cf::APPLICATION_JOURNAL, &journal_key(a.height(), &a.hash()))
            .unwrap(),
        None,
        "the abandoned block's journal is gone with it"
    );

    // The adopted block is undone from its own journal, back to the parent's set.
    undo(&d, &b);
    assert_eq!(committed(&d, 1), set(1, &[1, 2, 3]));
}

// ── S4: every read fails closed ────────────────────────────────────────────

#[test]
fn s4_every_read_fails_closed() {
    let (d, _g) = db();
    // Missing when required.
    assert!(matches!(
        read(&d, &TestLayout, 1, Presence::Required),
        Err(StateError::Missing { key: 1 })
    ));

    publish(&d, &block(Hash::hash(b"g"), 1, 1), insert(set(1, &[1]))).unwrap();
    // Present when absent.
    assert!(matches!(
        read(&d, &TestLayout, 1, Presence::Absent),
        Err(StateError::Unexpected { key: 1 })
    ));

    let raw = |bytes: &[u8]| {
        d.put(cf::STATE, &row_key(2), bytes).unwrap();
        read(&d, &TestLayout, 2, Presence::Required).unwrap_err()
    };
    // Another key's row copied here.
    assert!(matches!(
        raw(&set(1, &[1]).encode()),
        StateError::Record {
            key: 2,
            source: ValidatorSetRecordError::KeyMismatch {
                expected: 2,
                found: 1
            }
        }
    ));
    // Corrupt, truncated, another version, foreign.
    let mut wrong_version = set(2, &[1]).encode();
    wrong_version[4..6].copy_from_slice(&1u16.to_be_bytes());
    assert!(matches!(
        raw(&wrong_version),
        StateError::Record {
            source: ValidatorSetRecordError::UnsupportedVersion { found: 1 },
            ..
        }
    ));
    assert!(matches!(
        raw(&set(2, &[1]).encode()[..20]),
        StateError::Record {
            source: ValidatorSetRecordError::LengthMismatch { .. },
            ..
        }
    ));
    assert!(matches!(
        raw(b"not a row"),
        StateError::Record {
            source: ValidatorSetRecordError::Truncated { .. },
            ..
        }
    ));
    assert!(matches!(raw(b""), StateError::Record { .. }));
}

// ── S5: a write states what it replaces ────────────────────────────────────

#[test]
fn s5_insert_refuses_an_occupied_key_even_with_the_identical_row() {
    let (d, _g) = db();
    publish(&d, &block(Hash::hash(b"g"), 1, 1), insert(set(1, &[1]))).unwrap();
    let before = whole_db(&d);
    for r in [set(1, &[1]), set(1, &[2])] {
        let err = publish(&d, &block(Hash::hash(b"g"), 2, 2), insert(r)).unwrap_err();
        assert!(err.contains("already stored under key 1"), "{err}");
    }
    assert_eq!(whole_db(&d), before);
}

#[test]
fn s5_replace_refuses_a_missing_key() {
    let (d, _g) = db();
    let before = whole_db(&d);
    let err = publish(&d, &block(Hash::hash(b"g"), 1, 1), replace(set(1, &[1]))).unwrap_err();
    assert!(err.contains("required under key 1"), "{err}");
    assert_eq!(whole_db(&d), before);
}

#[test]
fn s5_an_undecodable_row_is_reported_not_overwritten() {
    let (d, _g) = db();
    d.put(cf::STATE, &row_key(1), b"garbage").unwrap();
    let before = whole_db(&d);
    for writes in [insert(set(1, &[1])), replace(set(1, &[1]))] {
        let err = publish(&d, &block(Hash::hash(b"g"), 1, 1), writes).unwrap_err();
        assert!(err.contains("is refused"), "{err}");
    }
    assert_eq!(whole_db(&d), before);
    assert_eq!(stored(&d, 1).as_deref(), Some(&b"garbage"[..]));
}

#[test]
fn s5_a_replace_within_one_block_reads_the_blocks_own_insert() {
    let (d, _g) = db();
    let b = block(Hash::hash(b"g"), 1, 1);
    publish(
        &d,
        &b,
        Box::new(|view| {
            stage_insert(view, &TestLayout, &set(1, &[1]))?;
            let replaced = stage_replace(view, &TestLayout, &set(1, &[2]))?;
            assert_eq!(replaced, set(1, &[1]));
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(committed(&d, 1), set(1, &[2]));
    // The journal records the value the block started from: absent.
    undo(&d, &b);
    assert_eq!(stored(&d, 1), None);
}
