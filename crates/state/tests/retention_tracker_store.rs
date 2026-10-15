//! Stored retention trackers (#129), end to end.
//!
//! Every row here is written the way a block's state is: through the
//! `ExecutionView` of a candidate, published by `AcceptedCandidate::publish`,
//! undone from the generic application journal publication leaves, and moved
//! by the one adoption batch of a replacement branch. The layout is a test
//! layout in an existing family; no production layout exists. The limits are
//! test values, not proposals.

use std::collections::BTreeSet;
use std::sync::Arc;

use sumchain_primitives::{Address, Block, BlockHeader, Hash};
use sumchain_state::compute_pool::{
    JobId, PoolError, RecomputeCursor, RetentionReverseIndex, ReverseIndexLimits,
    TrackerIndexRecord, TrackerKey,
};
use sumchain_state::retention_tracker_store::{
    self as store, Namespaces, Presence, RecordError, RetentionLayout, RowKind, TrackerState,
    TrackerStoreError,
};
use sumchain_storage::branch::BranchState;
use sumchain_storage::candidate::{
    build_adoption_batch, BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
    SpeculativeBlock,
};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::journal::ApplicationJournal;
use sumchain_storage::schema::{journal_key, AccountState, StateStore};
use tempfile::TempDir;

const LIMIT: u64 = 1 << 22;

/// Above the legacy root-compatibility window, so a root mismatch is refused.
const VERIFIED_HEIGHT: u64 = 1_000_000;

const PREFIX: &[u8] = b"rt/";

struct TestLayout;

impl RetentionLayout for TestLayout {
    fn namespace(&self, kind: RowKind) -> (&'static str, Vec<u8>) {
        let tag: &[u8] = match kind {
            RowKind::TrackerState => b"rt/s/",
            RowKind::IndexRecord => b"rt/i/",
            RowKind::ArchiveMember => b"rt/a/",
            RowKind::FileMember => b"rt/f/",
            RowKind::JobMember => b"rt/j/",
            RowKind::JobEntries => b"rt/n/",
            RowKind::Cursor => b"rt/c",
        };
        (cf::STATE, tag.to_vec())
    }
}

fn ns() -> Namespaces {
    Namespaces::check(&TestLayout).unwrap()
}

fn limits() -> ReverseIndexLimits {
    ReverseIndexLimits {
        max_entries_per_job: 1_000,
        r_max: 8,
        retention_chunk_cap: 64,
        max_indexed_epochs: 4,
    }
}

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    (Database::open_default(dir.path()).unwrap(), dir)
}

fn tk(b: u8) -> TrackerKey {
    TrackerKey::from_bytes([b; 32])
}

fn job(b: u8) -> JobId {
    JobId::from_bytes([b; 32])
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

fn file(b: u8) -> Hash {
    Hash::new([b; 32])
}

fn record(j: u8, f: u8, epochs: &[u64], archives: &[u8]) -> TrackerIndexRecord {
    TrackerIndexRecord {
        job_id: job(j),
        file_root: file(f),
        r_job: 2,
        interval_version: 1,
        chunk_count: 4,
        epochs: epochs.iter().copied().collect(),
        archives: archives.iter().copied().map(addr).collect(),
    }
}

fn fresh_state(key: TrackerKey) -> TrackerState {
    TrackerState::new(key, 2, 4, vec![], None, None).unwrap()
}

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

type Writes<'f> = Box<dyn FnOnce(&mut ExecutionView<'_, '_>) -> Result<(), TrackerStoreError> + 'f>;

fn publish(d: &Database, b: &Block, writes: Writes<'_>) -> Result<(), String> {
    let mut cand = CandidateExecution::new(d, LIMIT);
    {
        let mut view = cand.view();
        writes(&mut view).map_err(|e| e.to_string())?;
    }
    cand.finish_execution(
        ExecutionSubject::of(b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(b)
    .map_err(|e| e.to_string())?
    .publish()
    .map_err(|e| e.to_string())
}

fn start(key: u8, rec: TrackerIndexRecord) -> Writes<'static> {
    Box::new(move |v| store::start_tracking(v, &ns(), &fresh_state(tk(key)), &rec, &limits()))
}

fn journal_of(d: &Database, b: &Block) -> ApplicationJournal {
    let bytes = d
        .get(cf::APPLICATION_JOURNAL, &journal_key(b.height(), &b.hash()))
        .unwrap()
        .expect("a published block leaves a journal");
    ApplicationJournal::decode_for(&bytes, b.height(), &b.hash()).unwrap()
}

fn undo(d: &Database, b: &Block) {
    let j = journal_of(d, b);
    j.check_current_matches_after(d).unwrap();
    j.undo_batch(d).unwrap().commit().unwrap();
}

/// Every retention row, in key order.
fn rows(d: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    d.iter(cf::STATE)
        .unwrap()
        .filter(|(k, _)| k.starts_with(PREFIX))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

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

/// Everything the store answers about the given trackers, jobs, files and
/// archives, read from `rows`.
fn answers(
    rows: &(impl store::RowSource + ?Sized),
    keys: &[u8],
    jobs: &[u8],
    files: &[u8],
    archives: &[u8],
) -> String {
    let ns = ns();
    let mut out = String::new();
    for &k in keys {
        out += &format!(
            "{k}: {:?} {:?}\n",
            store::index_record(rows, &ns, &tk(k), Presence::Required).ok(),
            store::tracker_state(rows, &ns, &tk(k), Presence::Required).ok()
        );
    }
    for &j in jobs {
        out += &format!(
            "job {j}: {:?} {}\n",
            store::trackers_for_job(rows, &ns, &job(j)).unwrap(),
            store::job_entry_count(rows, &ns, &job(j)).unwrap()
        );
    }
    for &f in files {
        out += &format!(
            "file {f}: {:?}\n",
            store::file_entries(rows, &ns, &file(f)).unwrap()
        );
    }
    for &a in archives {
        out += &format!(
            "archive {a}: {:?}\n",
            store::trackers_for_archive(rows, &ns, &addr(a)).unwrap()
        );
    }
    out += &format!("cursor {:?}\n", store::recompute_cursor(rows, &ns).unwrap());
    out
}

// ── R1: rows land only with their block ────────────────────────────────────

#[test]
fn r1_rows_land_only_when_their_block_is_published() {
    let (d, _g) = db();
    let b = block(Hash::hash(b"g"), 1, 1);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    {
        let mut view = cand.view();
        store::start_tracking(
            &mut view,
            &ns(),
            &fresh_state(tk(1)),
            &record(1, 1, &[5], &[1, 2]),
            &limits(),
        )
        .unwrap();
        // Execution reads its own writes.
        assert_eq!(
            store::trackers_for_archive(&view, &ns(), &addr(2)).unwrap(),
            vec![tk(1)]
        );
    }
    assert!(rows(&d).is_empty(), "nothing lands before publication");
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
    assert_eq!(store::job_entry_count(&d, &ns(), &job(1)).unwrap(), 4);
    assert_eq!(
        store::index_record(&d, &ns(), &tk(1), Presence::Required).unwrap(),
        Some(record(1, 1, &[5], &[1, 2]))
    );
}

#[test]
fn r1_failed_publication_writes_nothing() {
    let (d, _g) = db();
    let before = whole_db(&d);

    // An abandoned candidate.
    {
        let mut cand = CandidateExecution::new(&d, LIMIT);
        let mut view = cand.view();
        store::start_tracking(
            &mut view,
            &ns(),
            &fresh_state(tk(1)),
            &record(1, 1, &[5], &[1]),
            &limits(),
        )
        .unwrap();
    }
    assert_eq!(whole_db(&d), before, "abandoned");

    // A root mismatch above the legacy window.
    let b = block(Hash::hash(b"p"), VERIFIED_HEIGHT, 1);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    {
        let mut view = cand.view();
        store::start_tracking(
            &mut view,
            &ns(),
            &fresh_state(tk(1)),
            &record(1, 1, &[5], &[1]),
            &limits(),
        )
        .unwrap();
    }
    let err = cand
        .finish_execution(
            ExecutionSubject::of(&b).unwrap(),
            Hash::hash(b"another root"),
            Vec::new(),
            journals(),
        )
        .accept_imported(&b)
        .expect_err("refused");
    assert!(err.to_string().contains("state root mismatch"), "{err}");
    assert_eq!(whole_db(&d), before, "root mismatch");

    // A write over the block's ceiling.
    {
        let mut cand = CandidateExecution::new(&d, 128);
        let mut view = cand.view();
        let err = store::start_tracking(
            &mut view,
            &ns(),
            &fresh_state(tk(1)),
            &record(1, 1, &[5, 6], &[1, 2, 3]),
            &limits(),
        )
        .expect_err("over the ceiling");
        assert!(matches!(err, TrackerStoreError::Storage(_)), "{err}");
    }
    assert_eq!(whole_db(&d), before, "over the ceiling");
}

// ── R2: undo is the generic journal ────────────────────────────────────────

#[test]
fn r2_undo_restores_every_row_exactly() {
    let (d, _g) = db();
    let b1 = block(Hash::hash(b"g"), 1, 1);
    publish(
        &d,
        &b1,
        Box::new(|v| {
            store::start_tracking(
                v,
                &ns(),
                &fresh_state(tk(1)),
                &record(1, 1, &[5], &[1, 2]),
                &limits(),
            )?;
            store::start_tracking(
                v,
                &ns(),
                &fresh_state(tk(2)),
                &record(1, 2, &[5, 6], &[2]),
                &limits(),
            )
        }),
    )
    .unwrap();
    let after_b1 = rows(&d);

    let b2 = block(b1.hash(), 2, 2);
    publish(
        &d,
        &b2,
        Box::new(|v| {
            store::replace_dependencies(
                v,
                &ns(),
                &tk(1),
                [6u64, 7].into_iter().collect(),
                [addr(3)].into_iter().collect(),
                &limits(),
            )?;
            store::update_state(
                v,
                &ns(),
                &TrackerState::new(tk(1), 2, 4, vec![(addr(3), 1)], Some(2), Some(2)).unwrap(),
            )?;
            store::stop_tracking(v, &ns(), &tk(2))?;
            store::store_cursor(v, &ns(), &RecomputeCursor::after(tk(1)))
        }),
    )
    .unwrap();
    assert_ne!(rows(&d), after_b1);
    assert!(store::trackers_for_archive(&d, &ns(), &addr(2))
        .unwrap()
        .is_empty());

    undo(&d, &b2);
    assert_eq!(
        rows(&d),
        after_b1,
        "back to the state b1 left, byte for byte"
    );
    undo(&d, &b1);
    assert!(
        rows(&d).is_empty(),
        "every inserted row is deleted, not emptied"
    );
}

#[test]
fn r2_apply_a_undo_a_apply_b_equals_b_alone() {
    let parent = Hash::hash(b"g");
    let a = block(parent, 1, 1);
    let b = block(parent, 1, 2);
    let writes_b = || start(9, record(4, 4, &[1, 2], &[7, 8]));

    let (alone, _g1) = db();
    publish(&alone, &b, writes_b()).unwrap();

    let (d, _g2) = db();
    publish(&d, &a, start(1, record(1, 1, &[5], &[1, 2]))).unwrap();
    undo(&d, &a);
    publish(&d, &b, writes_b()).unwrap();
    assert_eq!(rows(&d), rows(&alone));
}

// ── R3: competing branches ─────────────────────────────────────────────────

#[test]
fn r3_competing_blocks_hold_separate_trackers_and_adoption_switches_them() {
    let (d, _g) = db();
    let p = block(Hash::hash(b"g"), 1, 1);
    publish(&d, &p, start(1, record(1, 1, &[5], &[1, 2]))).unwrap();
    let parent_rows = rows(&d);

    // Canonical child: reassigns tracker 1 and starts tracker 2.
    let a = block(p.hash(), 2, 10);
    publish(
        &d,
        &a,
        Box::new(|v| {
            store::replace_dependencies(
                v,
                &ns(),
                &tk(1),
                [5u64].into_iter().collect(),
                [addr(3)].into_iter().collect(),
                &limits(),
            )?;
            store::start_tracking(
                v,
                &ns(),
                &fresh_state(tk(2)),
                &record(1, 2, &[5], &[3]),
                &limits(),
            )
        }),
    )
    .unwrap();

    // A sibling over the fork parent rebuilt from the child's journal.
    let b = block(p.hash(), 2, 20);
    let mut layer = BranchState::new(LIMIT);
    layer.restore_parent(&d, &journal_of(&d, &a)).unwrap();
    let layer = Arc::new(layer);
    let spec: SpeculativeBlock = {
        let mut cand = CandidateExecution::on_branch(&d, layer.clone(), LIMIT);
        {
            let mut view = cand.view();
            // The sibling sees the parent's trackers, not the child's.
            assert_eq!(
                store::trackers_for_archive(&view, &ns(), &addr(1)).unwrap(),
                vec![tk(1)]
            );
            assert!(store::trackers_for_archive(&view, &ns(), &addr(3))
                .unwrap()
                .is_empty());
            assert_eq!(store::job_entry_count(&view, &ns(), &job(1)).unwrap(), 4);
            store::stop_tracking(&mut view, &ns(), &tk(1)).unwrap();
            store::start_tracking(
                &mut view,
                &ns(),
                &fresh_state(tk(3)),
                &record(2, 1, &[6], &[4]),
                &limits(),
            )
            .unwrap();
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
    assert!(store::index_record(&d, &ns(), &tk(2), Presence::Required).is_ok());

    let mut layer = Arc::try_unwrap(layer).expect("released");
    layer.absorb_net_writes(spec.net_writes()).unwrap();
    let (batch, _) = build_adoption_batch(
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
    batch.commit().unwrap();

    // The sibling's view is canonical: tracker 1 and 2 gone, 3 tracked.
    assert!(store::index_record(&d, &ns(), &tk(1), Presence::Absent).is_ok());
    assert!(store::index_record(&d, &ns(), &tk(2), Presence::Absent).is_ok());
    assert_eq!(
        store::trackers_for_job(&d, &ns(), &job(2)).unwrap(),
        vec![tk(3)]
    );
    assert_eq!(store::job_entry_count(&d, &ns(), &job(1)).unwrap(), 0);

    // And the adopted block is undone from its own journal.
    undo(&d, &b);
    assert_eq!(rows(&d), parent_rows);
}

// ── Reopen ─────────────────────────────────────────────────────────────────

#[test]
fn reopen_reads_back_identical_state() {
    let dir = TempDir::new().unwrap();
    let (before_rows, before_answers) = {
        let d = Database::open_default(dir.path()).unwrap();
        let b1 = block(Hash::hash(b"g"), 1, 1);
        publish(&d, &b1, start(1, record(1, 1, &[5, 6], &[1, 2]))).unwrap();
        let b2 = block(b1.hash(), 2, 2);
        publish(
            &d,
            &b2,
            Box::new(|v| {
                store::update_state(
                    v,
                    &ns(),
                    &TrackerState::new(
                        tk(1),
                        2,
                        4,
                        vec![(addr(1), 3), (addr(2), 4)],
                        Some(2),
                        Some(2),
                    )
                    .unwrap(),
                )?;
                store::store_cursor(v, &ns(), &RecomputeCursor::after(tk(1)))
            }),
        )
        .unwrap();
        (rows(&d), answers(&d, &[1, 2], &[1], &[1], &[1, 2]))
    };
    let d = Database::open_default(dir.path()).unwrap();
    assert_eq!(rows(&d), before_rows);
    assert_eq!(answers(&d, &[1, 2], &[1], &[1], &[1, 2]), before_answers);
    assert_eq!(
        store::tracker_state(&d, &ns(), &tk(1), Presence::Required)
            .unwrap()
            .unwrap()
            .coverage_satisfied_since_height(),
        Some(2)
    );
}

// ── Absent versus empty ────────────────────────────────────────────────────

#[test]
fn absent_and_empty_are_distinct_and_both_survive() {
    let dir = TempDir::new().unwrap();
    let d = Database::open_default(dir.path()).unwrap();
    // Nothing stored: absent everywhere.
    assert!(matches!(
        store::tracker_state(&d, &ns(), &tk(1), Presence::Required),
        Err(TrackerStoreError::Missing {
            kind: RowKind::TrackerState
        })
    ));
    assert_eq!(
        store::tracker_state(&d, &ns(), &tk(1), Presence::Absent).unwrap(),
        None
    );
    assert_eq!(store::job_entry_count(&d, &ns(), &job(1)).unwrap(), 0);
    assert_eq!(store::recompute_cursor(&d, &ns()).unwrap(), None);

    // A tracker with no dependencies, no archives and no since: empty, not
    // absent. A cursor stored at the start: present, not absent.
    let b = block(Hash::hash(b"g"), 1, 1);
    publish(
        &d,
        &b,
        Box::new(|v| {
            store::start_tracking(
                v,
                &ns(),
                &fresh_state(tk(1)),
                &record(1, 1, &[5], &[]),
                &limits(),
            )?;
            store::store_cursor(v, &ns(), &RecomputeCursor::start())
        }),
    )
    .unwrap();
    drop(d);
    let d = Database::open_default(dir.path()).unwrap();
    let s = store::tracker_state(&d, &ns(), &tk(1), Presence::Required)
        .unwrap()
        .unwrap();
    assert!(s.dependency_generations().is_empty());
    assert_eq!(s.coverage_satisfied_since_height(), None);
    assert!(matches!(
        store::tracker_state(&d, &ns(), &tk(1), Presence::Absent),
        Err(TrackerStoreError::Unexpected { .. })
    ));
    assert!(store::index_record(&d, &ns(), &tk(1), Presence::Required)
        .unwrap()
        .unwrap()
        .archives
        .is_empty());
    assert_eq!(store::job_entry_count(&d, &ns(), &job(1)).unwrap(), 2);
    assert_eq!(
        store::recompute_cursor(&d, &ns()).unwrap(),
        Some(RecomputeCursor::start())
    );

    // Stopping the last tracker prunes every row it owned, including the
    // job's count: the namespace holds only the cursor.
    let b2 = block(b.hash(), 2, 2);
    publish(
        &d,
        &b2,
        Box::new(|v| store::stop_tracking(v, &ns(), &tk(1)).map(|_| ())),
    )
    .unwrap();
    let left = rows(&d);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].0, b"rt/c".to_vec());
}

// ── R4: malformed rows fail closed ─────────────────────────────────────────

#[test]
fn r4_malformed_rows_are_refused_on_read_and_never_overwritten() {
    let (d, _g) = db();
    publish(
        &d,
        &block(Hash::hash(b"g"), 1, 1),
        start(1, record(1, 1, &[5], &[1])),
    )
    .unwrap();
    let mut state_key = b"rt/s/".to_vec();
    state_key.extend_from_slice(&[1; 32]);
    let mut index_key = b"rt/i/".to_vec();
    index_key.extend_from_slice(&[1; 32]);
    let good_index = d.get(cf::STATE, &index_key).unwrap().unwrap();

    let read_index = |d: &Database| store::index_record(d, &ns(), &tk(1), Presence::Required);

    // Truncated, extended, another version, another key.
    for (what, bytes) in [
        ("truncated", good_index[..good_index.len() - 1].to_vec()),
        ("extended", [good_index.clone(), vec![0]].concat()),
        ("version", {
            let mut b = good_index.clone();
            b[5] = 9;
            b
        }),
        ("foreign key", {
            let mut b = good_index.clone();
            b[6] ^= 1;
            b
        }),
        ("bad count", {
            let mut b = good_index.clone();
            let at = 6 + 32 * 3 + 12;
            b[at..at + 4].copy_from_slice(&7u32.to_be_bytes());
            b
        }),
    ] {
        d.put(cf::STATE, &index_key, &bytes).unwrap();
        assert!(
            matches!(
                read_index(&d),
                Err(TrackerStoreError::Record {
                    kind: RowKind::IndexRecord,
                    ..
                })
            ),
            "{what}"
        );
        // Every write that would touch it refuses and stages nothing.
        let before = whole_db(&d);
        for writes in [
            start(1, record(1, 1, &[5], &[1])),
            Box::new(|v: &mut ExecutionView<'_, '_>| {
                store::replace_dependencies(
                    v,
                    &ns(),
                    &tk(1),
                    [5u64].into_iter().collect(),
                    BTreeSet::new(),
                    &limits(),
                )
            }) as Writes<'static>,
            Box::new(|v: &mut ExecutionView<'_, '_>| {
                store::stop_tracking(v, &ns(), &tk(1)).map(|_| ())
            }),
        ] {
            let err = publish(&d, &block(Hash::hash(b"g"), 2, 2), writes).unwrap_err();
            assert!(err.contains("IndexRecord row is refused"), "{what}: {err}");
        }
        assert_eq!(whole_db(&d), before, "{what}");
    }
    d.put(cf::STATE, &index_key, &good_index).unwrap();

    // A state row copied under another tracker's key.
    let good_state = d.get(cf::STATE, &state_key).unwrap().unwrap();
    let mut other_key = b"rt/s/".to_vec();
    other_key.extend_from_slice(&[2; 32]);
    d.put(cf::STATE, &other_key, &good_state).unwrap();
    assert!(matches!(
        store::tracker_state(&d, &ns(), &tk(2), Presence::Required),
        Err(TrackerStoreError::Record {
            source: RecordError::KeyMismatch,
            ..
        })
    ));
    d.delete(cf::STATE, &other_key).unwrap();

    // A member row whose value names another tracker, and a member key of the
    // wrong length, in a bucket.
    let mut member = b"rt/a/".to_vec();
    member.extend_from_slice(&[1; 20]);
    member.extend_from_slice(&[1; 32]);
    let good_member = d.get(cf::STATE, &member).unwrap().unwrap();
    let mut forged = good_member.clone();
    forged[6 + 20] ^= 1;
    d.put(cf::STATE, &member, &forged).unwrap();
    assert!(matches!(
        store::trackers_for_archive(&d, &ns(), &addr(1)),
        Err(TrackerStoreError::Record {
            kind: RowKind::ArchiveMember,
            source: RecordError::KeyMismatch
        })
    ));
    d.put(cf::STATE, &member, &good_member).unwrap();
    let mut short = member.clone();
    short.pop();
    d.put(cf::STATE, &short, &good_member).unwrap();
    assert!(matches!(
        store::trackers_for_archive(&d, &ns(), &addr(1)),
        Err(TrackerStoreError::MalformedKey { .. })
    ));
    d.delete(cf::STATE, &short).unwrap();

    // A job count of zero is never written, so it is never read.
    let mut count_key = b"rt/n/".to_vec();
    count_key.extend_from_slice(&[1; 32]);
    let mut zero = d.get(cf::STATE, &count_key).unwrap().unwrap();
    let n = zero.len();
    zero[n - 8..].copy_from_slice(&0u64.to_be_bytes());
    d.put(cf::STATE, &count_key, &zero).unwrap();
    assert!(matches!(
        store::job_entry_count(&d, &ns(), &job(1)),
        Err(TrackerStoreError::Record {
            source: RecordError::Zero { .. },
            ..
        })
    ));
}

// ── R5: every write states what it expects ─────────────────────────────────

#[test]
fn r5_refused_writes_stage_nothing() {
    let (d, _g) = db();
    publish(
        &d,
        &block(Hash::hash(b"g"), 1, 1),
        start(1, record(1, 1, &[5], &[1])),
    )
    .unwrap();
    let before = whole_db(&d);
    let next = || block(Hash::hash(b"g"), 2, 2);

    let cases: Vec<(&str, Writes<'static>, &str)> = vec![
        (
            "tracked key",
            start(1, record(1, 1, &[5], &[1])),
            "already indexed",
        ),
        (
            "unknown key",
            Box::new(|v| {
                store::replace_dependencies(
                    v,
                    &ns(),
                    &tk(9),
                    [5u64].into_iter().collect(),
                    BTreeSet::new(),
                    &limits(),
                )
            }),
            "unknown",
        ),
        (
            "stop unknown",
            Box::new(|v| store::stop_tracking(v, &ns(), &tk(9)).map(|_| ())),
            "unknown",
        ),
        (
            "state for another r_job",
            Box::new(|v| {
                store::update_state(
                    v,
                    &ns(),
                    &TrackerState::new(tk(1), 3, 4, vec![], None, None).unwrap(),
                )
                .map(|_| ())
            }),
            "r_job",
        ),
        ("no epoch", start(2, record(1, 2, &[], &[1])), "epoch"),
    ];
    for (what, writes, needle) in cases {
        let err = publish(&d, &next(), writes).unwrap_err();
        assert!(err.to_lowercase().contains(needle), "{what}: {err}");
        assert_eq!(whole_db(&d), before, "{what}");
    }

    // A state row stored without an index row refuses a start for its key.
    let mut state_key = b"rt/s/".to_vec();
    state_key.extend_from_slice(&[5; 32]);
    d.put(cf::STATE, &state_key, &fresh_state(tk(5)).encode())
        .unwrap();
    let before = whole_db(&d);
    let err = publish(&d, &next(), start(5, record(1, 5, &[5], &[1]))).unwrap_err();
    assert!(err.contains("TrackerState row is expected"), "{err}");
    assert_eq!(whole_db(&d), before);
}

// ── R6: the stored indexes answer as the kernel does ───────────────────────

#[test]
fn r6_the_stored_indexes_match_the_kernel_through_a_long_sequence() {
    let (d, _g) = db();
    let tight = ReverseIndexLimits {
        max_entries_per_job: 12,
        r_max: 2,
        retention_chunk_cap: 4,
        max_indexed_epochs: 3,
    };
    let mut kernel = RetentionReverseIndex::new();
    let mut seed: u64 = 0x5EED;
    let mut rand = |n: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let mut parent = Hash::hash(b"g");
    let (mut refused, mut applied) = (0, 0);
    for step in 0..240u64 {
        let key = (rand(6) + 1) as u8;
        let epochs: BTreeSet<u64> = (0..rand(4)).map(|_| rand(5)).collect();
        let archives: BTreeSet<Address> = (0..rand(6)).map(|_| addr((rand(5) + 1) as u8)).collect();
        let op = rand(3);
        let rec = TrackerIndexRecord {
            job_id: job(key % 2 + 1),
            file_root: file(key % 3 + 1),
            r_job: rand(3) as u32,
            interval_version: 1,
            chunk_count: (rand(3) + 1) as u32,
            epochs: epochs.clone(),
            archives: archives.clone(),
        };
        let expected: Result<(), PoolError> = match op {
            0 => kernel.insert_tracker(tk(key), rec.clone(), &tight),
            1 => kernel.replace_dependencies(&tk(key), epochs.clone(), archives.clone(), &tight),
            _ => kernel.remove_tracker(&tk(key)).map(|_| ()),
        };
        let b = block(parent, step + 1, step);
        let got = publish(
            &d,
            &b,
            Box::new(move |v| match op {
                0 => {
                    let state =
                        TrackerState::new(tk(key), rec.r_job, rec.chunk_count, vec![], None, None)
                            .unwrap();
                    store::start_tracking(v, &ns(), &state, &rec, &tight)
                }
                1 => store::replace_dependencies(v, &ns(), &tk(key), epochs, archives, &tight),
                _ => store::stop_tracking(v, &ns(), &tk(key)).map(|_| ()),
            }),
        );
        match (&expected, &got) {
            (Ok(()), Ok(())) => {
                applied += 1;
                parent = b.hash();
            }
            (Err(e), Err(g)) => {
                refused += 1;
                assert!(
                    g.contains(&e.to_string()),
                    "step {step}: kernel {e}, store {g}"
                );
            }
            _ => panic!("step {step}: kernel {expected:?}, store {got:?}"),
        }
        // Every answer agrees.
        for k in 1..=6u8 {
            let stored = match store::index_record(&d, &ns(), &tk(k), Presence::Absent) {
                Ok(_) => None,
                Err(TrackerStoreError::Unexpected { .. }) => {
                    store::index_record(&d, &ns(), &tk(k), Presence::Required).unwrap()
                }
                Err(e) => panic!("step {step}: tracker {k}: {e}"),
            };
            assert_eq!(
                stored,
                kernel.tracker(&tk(k)).cloned(),
                "step {step}: tracker {k}"
            );
        }
        for j in 1..=2u8 {
            assert_eq!(
                store::trackers_for_job(&d, &ns(), &job(j)).unwrap(),
                kernel
                    .trackers_for_job(&job(j))
                    .copied()
                    .collect::<Vec<_>>(),
                "step {step}: job {j}"
            );
            assert_eq!(
                store::job_entry_count(&d, &ns(), &job(j)).unwrap(),
                kernel.job_entry_count(&job(j)),
                "step {step}: job {j} count"
            );
        }
        for f in 1..=3u8 {
            assert_eq!(
                store::file_entries(&d, &ns(), &file(f)).unwrap(),
                kernel.file_entries(&file(f)).copied().collect::<Vec<_>>(),
                "step {step}: file {f}"
            );
        }
        for a in 1..=5u8 {
            assert_eq!(
                store::trackers_for_archive(&d, &ns(), &addr(a)).unwrap(),
                kernel
                    .trackers_for_archive(&addr(a))
                    .copied()
                    .collect::<Vec<_>>(),
                "step {step}: archive {a}"
            );
        }
        let changed_a = [addr(1), addr(3)];
        let changed_f = [file(2)];
        assert_eq!(
            store::affected_trackers(&d, &ns(), &changed_a, &changed_f).unwrap(),
            kernel.affected_trackers(&changed_a, &changed_f),
            "step {step}: affected"
        );
    }
    assert!(
        applied > 40 && refused > 40,
        "both sides exercised: {applied} applied, {refused} refused"
    );
}

// ── R7: namespaces ─────────────────────────────────────────────────────────

struct Bad(
    &'static str,
    &'static [u8],
    Option<(RowKind, &'static [u8])>,
);

impl RetentionLayout for Bad {
    fn namespace(&self, kind: RowKind) -> (&'static str, Vec<u8>) {
        if let Some((k, p)) = self.2 {
            if k == kind {
                return (self.0, p.to_vec());
            }
        }
        let (_, base) = TestLayout.namespace(kind);
        let mut prefix = self.1.to_vec();
        prefix.extend_from_slice(&base);
        (self.0, prefix)
    }
}

#[test]
fn r7_layouts_that_reach_other_namespaces_are_refused() {
    let refused = |layout: Bad, needle: &str| {
        let err = Namespaces::check(&layout).unwrap_err().to_string();
        assert!(err.contains(needle), "{err}");
    };
    refused(Bad(cf::COMPUTE_POOL_STATE, b"x", None), "folded in full");
    refused(Bad(cf::BEACON_STATE, b"x", None), "folded in full");
    refused(
        Bad("no_such_family", b"x", None),
        "not one the database opens",
    );
    refused(Bad(cf::STATE, b"", Some((RowKind::Cursor, b""))), "empty");
    refused(
        Bad(cf::STATE, b"", Some((RowKind::Cursor, b"acct"))),
        "account range",
    );
    refused(
        Bad(cf::STATE, b"", Some((RowKind::Cursor, b"ac"))),
        "account range",
    );
    refused(Bad(cf::STATE, b"acct", None), "account range");
    refused(
        Bad(cf::STATE, b"", Some((RowKind::Cursor, b"rt/s/x"))),
        "overlaps",
    );
    Namespaces::check(&TestLayout).unwrap();
}

#[test]
fn r7_tracker_rows_beside_accounts_leave_the_account_digest_unchanged() {
    let (d, _g) = db();
    let accounts = StateStore::new(&d);
    for b in [0x01u8, 0x7F, 0xFE] {
        accounts
            .put_account(
                &Address::new([b; 20]),
                &AccountState {
                    balance: u128::from(b),
                    nonce: 1,
                },
            )
            .unwrap();
    }
    let mut cand = CandidateExecution::new(&d, LIMIT);
    let mut view = cand.view();
    let before = sumchain_state::account_root::v_account_state_digest(&view).unwrap();
    store::start_tracking(
        &mut view,
        &ns(),
        &fresh_state(tk(1)),
        &record(1, 1, &[5, 6], &[1, 2, 3]),
        &limits(),
    )
    .unwrap();
    store::store_cursor(&mut view, &ns(), &RecomputeCursor::after(tk(1))).unwrap();
    let after = sumchain_state::account_root::v_account_state_digest(&view).unwrap();
    assert_eq!(before, after);
}
