//! The generic application journal, end to end through publication.
//!
//! Every test here publishes through `AcceptedCandidate::publish` — the one
//! publication function — and reads the journal back out of RocksDB. Nothing
//! reaches into the overlay to inspect what would have been written, because
//! what would have been written is not the claim.

use std::collections::BTreeSet;

use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, Receipt, SignedTransaction, Transaction, TxStatus,
};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::journal::{
    ActivationSource, AfterImage, ApplicationJournal, JournalActivation, JournalRequirement,
    Preimage,
};
use sumchain_storage::schema::journal_key;
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 22;

/// What a staging closure returns. A refused write is the attempt's failure, not
/// a smaller block.
type StagingResult = sumchain_storage::Result<()>;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

fn empty_journals() -> BlockJournals {
    BlockJournals {
        account: JournalRecord::NothingToUndo,
        contract: JournalRecord::NothingToUndo,
        compute_pool: JournalRecord::NothingToUndo,
        beacon: JournalRecord::NothingToUndo,
    }
}

/// A block with no transactions, distinguished from its siblings by `tag`.
///
/// `tag` reaches the timestamp and the transaction root, so two blocks at one
/// height with different tags have different hashes — which is the whole point
/// of the #253 regression below.
fn block_at(height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    Block::new(header, Vec::new())
}

fn tx_with(seed: u8, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(
        1,
        Address::new([seed; 20]),
        Address::new([seed.wrapping_add(1); 20]),
        100,
        7,
        nonce,
    );
    SignedTransaction::new(tx, [seed; 64], [seed; 32])
}

fn block_with_txs(height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    Block::new(header, vec![tx_with(1, 0), tx_with(3, 1)])
}

fn receipts_for(block: &Block) -> Vec<Receipt> {
    block
        .transactions
        .iter()
        .map(|tx| Receipt {
            tx_hash: tx.hash(),
            status: TxStatus::Success,
            fee_paid: 7,
            block_height: block.height(),
            tx_index: 0,
        })
        .collect()
}

/// Execute `writes` into a candidate for `block` and publish it.
///
/// `writes` runs against the `ExecutionView`, which is the only handle block
/// execution ever has, so everything this test causes to be journalled got there
/// the way a real block's writes do.
fn publish_with(
    d: &Database,
    block: &Block,
    limit: u64,
    writes: impl FnOnce(&mut sumchain_storage::exec_view::ExecutionView<'_, '_>) -> StagingResult,
) -> Result<(), String> {
    let mut cand = CandidateExecution::new(d, limit);
    {
        let mut view = cand.view();
        // Propagated, never swallowed. A ceiling that refuses an execution write
        // must fail the attempt, not quietly produce a block that wrote less and
        // therefore fits.
        writes(&mut view).map_err(|e| e.to_string())?;
    }
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        block.header.state_root,
        receipts_for(block),
        empty_journals(),
    )
    .accept_imported(block)
    .map_err(|e| e.to_string())?
    .publish()
    .map_err(|e| e.to_string())
}

/// The journal a published block left, decoded under its own key.
fn journal_of(d: &Database, block: &Block) -> ApplicationJournal {
    let key = journal_key(block.height(), &block.hash());
    let bytes = d
        .get(cf::APPLICATION_JOURNAL, &key)
        .expect("read")
        .expect("a published block must leave a journal");
    ApplicationJournal::decode_for(&bytes, block.height(), &block.hash()).expect("decode")
}

fn journal_rows(d: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    d.iter(cf::APPLICATION_JOURNAL)
        .expect("iter")
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

// ── Coverage, derived rather than listed ───────────────────────────────────

/// EVERY column family the database opens is journalled when a block writes it.
///
/// The set comes from `ALL_CFS` — the registry the database itself is opened
/// from — not from a list maintained beside the journal. Nothing in this test
/// names a family, so a family added to the schema tomorrow is covered by this
/// test on the day it is added, and a journal that stopped covering one would
/// fail here without anyone remembering to update a list.
///
/// This is the property a hand-maintained per-subsystem diff cannot have, and
/// the reason the four existing journals were the wrong shape.
#[test]
fn every_column_family_the_database_opens_is_journalled_when_a_block_writes_it() {
    assert!(
        ALL_CFS.len() > 100,
        "the registry must be substantial for this to prove anything, not {}",
        ALL_CFS.len()
    );

    let (d, _g) = db();
    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        for name in ALL_CFS {
            view.put(name, b"coverage-probe", b"v")?;
        }
        Ok(())
    })
    .expect("publish");

    let journal = journal_of(&d, &block);
    let covered = journal.column_families();
    let expected: BTreeSet<&str> = ALL_CFS.iter().copied().collect();
    let missing: Vec<_> = expected.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "these families were written through the execution view and did not \
         reach the journal: {missing:?}. Coverage is derived from the overlay's \
         pre-images, so a gap here means the derivation dropped them."
    );
    assert_eq!(
        covered, expected,
        "the journal must cover exactly what the block wrote"
    );
}

/// The journal covers EXECUTION's writes, not the block's own canonical rows.
///
/// It is derived before publication stages anything, so the block, its
/// transactions, its receipts, its indexes and the head metadata are not in it —
/// those are chain storage, not application state, and reverting them is the
/// reorg path's separate business.
#[test]
fn the_journal_carries_execution_writes_only_not_the_blocks_canonical_rows() {
    let (d, _g) = db();
    let block = block_with_txs(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"acct:alice", b"100")
    })
    .expect("publish");

    let j = journal_of(&d, &block);
    assert_eq!(
        j.column_families(),
        BTreeSet::from([cf::STATE]),
        "only the family execution wrote belongs in the journal"
    );
    // Guard against the assertion above passing because publication wrote
    // nothing: it did write all of these.
    for (name, key) in [
        (cf::BLOCKS, block.hash().as_bytes().to_vec()),
        (cf::BLOCK_HEIGHT, block.height().to_be_bytes().to_vec()),
        (
            cf::TRANSACTIONS,
            block.transactions[0].hash().as_bytes().to_vec(),
        ),
        (
            cf::RECEIPTS,
            receipts_for(&block)[0].tx_hash.as_bytes().to_vec(),
        ),
        (
            cf::META,
            sumchain_storage::schema::meta_keys::LATEST_BLOCK_HASH.to_vec(),
        ),
    ] {
        assert!(
            d.get(name, &key).unwrap().is_some(),
            "publication must still write {name}"
        );
    }
}

// ── Determinism ────────────────────────────────────────────────────────────

/// Identical block content produces byte-identical journals, however the writes
/// were ordered.
///
/// Two independent databases, two independent candidates, the same content
/// staged in opposite orders. If anything about `HashMap` iteration, insertion
/// order or allocation reached the serialization, these bytes would differ.
#[test]
fn identical_block_content_produces_identical_journal_bytes() {
    let content: Vec<(&str, &[u8], &[u8])> = vec![
        (cf::STATE, b"acct:alice", b"100"),
        (cf::STATE, b"acct:bob", b""),
        (cf::TOKENS, b"tok:1", b"aaaa"),
        (cf::VALIDATORS, b"val:1", b"bbbb"),
        (cf::NFT_TOKENS, b"nft:1", b"cccc"),
        (cf::MESSAGING_EVENTS, b"msg:1", b"dddd"),
        (cf::CONTRACT_STORAGE, b"c:1", b"eeee"),
        (cf::GOV_VOTES, b"gv:1", b"ffff"),
    ];
    let seed: Vec<(&str, &[u8], &[u8])> = vec![
        (cf::STATE, b"acct:alice", b"prior"),
        (cf::TOKENS, b"tok:1", b""),
        (cf::GOV_VOTES, b"gv:1", b"prior-gov"),
    ];
    let block = block_at(9, 1);

    let run = |forward: bool| -> Vec<u8> {
        let (d, g) = db();
        for (name, k, v) in &seed {
            d.put(name, k, v).unwrap();
        }
        publish_with(&d, &block, TEST_LIMIT, |view| {
            let mut ops = content.clone();
            if !forward {
                ops.reverse();
            }
            for (name, k, v) in ops {
                view.put(name, k, v)?;
            }
            Ok(())
        })
        .expect("publish");
        let bytes = d
            .get(
                cf::APPLICATION_JOURNAL,
                &journal_key(block.height(), &block.hash()),
            )
            .unwrap()
            .unwrap();
        drop(g);
        bytes
    };

    let a = run(true);
    let b = run(false);
    assert_eq!(a, b, "journal bytes must not depend on write order");
    assert!(!a.is_empty());

    // And the order the bytes encode is strictly increasing, which is what makes
    // the sort total rather than merely applied.
    let j = ApplicationJournal::decode_for(&a, block.height(), &block.hash()).unwrap();
    let keys: Vec<(&str, &[u8])> = j.entries().iter().map(|e| (e.cf(), e.key())).collect();
    assert_eq!(keys.len(), content.len());
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "entries must be strictly increasing by (family, key): {keys:?}"
    );
}

// ── Pre-image semantics ────────────────────────────────────────────────────

/// "Absent before" and "had value V before" are different records, and undo does
/// the different thing for each.
///
/// This is the distinction a `Vec<u8>` cannot carry. Several families here store
/// empty values meaningfully, so "no bytes" cannot stand in for "no row": undoing
/// a block that CREATED a key has to DELETE it, and writing zero bytes instead
/// leaves a row that was never supposed to exist.
#[test]
fn absent_before_and_value_before_are_distinguished_and_each_undoes_exactly() {
    let (d, _g) = db();
    d.put(cf::STATE, b"existing", b"original").unwrap();
    d.put(cf::TOKENS, b"empty-valued", b"").unwrap();

    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"existing", b"changed")?;
        view.put(cf::STATE, b"created", b"brand new")?;
        view.put(cf::TOKENS, b"empty-valued", b"now set")?;
        view.delete(cf::STATE, b"never-existed")
    })
    .expect("publish");

    let j = journal_of(&d, &block);
    let find = |name: &str, key: &[u8]| {
        j.entries()
            .iter()
            .find(|e| e.cf() == name && e.key() == key)
            .unwrap_or_else(|| panic!("no journal entry for {name}/{key:?}"))
            .before()
            .clone()
    };
    assert_eq!(
        find(cf::STATE, b"existing"),
        Preimage::Value(b"original".to_vec())
    );
    assert_eq!(find(cf::STATE, b"created"), Preimage::Absent);
    assert_eq!(find(cf::STATE, b"never-existed"), Preimage::Absent);
    assert_eq!(
        find(cf::TOKENS, b"empty-valued"),
        Preimage::Value(Vec::new()),
        "an empty stored value is a VALUE, not an absent key"
    );

    // The block did happen.
    assert_eq!(
        d.get(cf::STATE, b"existing").unwrap().as_deref(),
        Some(&b"changed"[..])
    );
    assert!(d.get(cf::STATE, b"created").unwrap().is_some());

    // Undo restores each case exactly.
    j.check_current_matches_after(&d)
        .expect("the rows must still be what the block left");
    j.undo_batch(&d).unwrap().commit().unwrap();

    assert_eq!(
        d.get(cf::STATE, b"existing").unwrap().as_deref(),
        Some(&b"original"[..]),
        "a value-before key must come back with its exact prior bytes"
    );
    assert_eq!(
        d.get(cf::STATE, b"created").unwrap(),
        None,
        "an absent-before key must be DELETED, not zeroed"
    );
    assert_eq!(
        d.get(cf::TOKENS, b"empty-valued").unwrap().as_deref(),
        Some(&b""[..]),
        "an empty-valued row must come back empty, not missing"
    );
    assert_eq!(d.get(cf::STATE, b"never-existed").unwrap(), None);
}

/// The after tag notices state that has moved on since the block.
///
/// A consumer about to revert checks that the rows it is overwriting are still
/// the ones this block wrote. When they are not, the answer is to refuse the
/// whole unwind — not to apply the entries that still match.
#[test]
fn a_row_that_moved_on_since_the_block_refuses_the_whole_unwind() {
    let (d, _g) = db();
    d.put(cf::STATE, b"a", b"original").unwrap();
    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"a", b"by the block")?;
        view.put(cf::STATE, b"b", b"also by the block")
    })
    .expect("publish");

    let j = journal_of(&d, &block);
    j.check_current_matches_after(&d).expect("untouched");

    // Something else wrote over one of the block's rows.
    d.put(cf::STATE, b"a", b"somebody else").unwrap();
    let err = j
        .check_current_matches_after(&d)
        .expect_err("a moved row must be reported");
    assert!(
        err.to_string()
            .contains("no longer holds what the block left"),
        "{err}"
    );
    assert!(
        err.to_string().contains("refusing to apply any preimage"),
        "{err}"
    );

    // A deleted row is caught too, in the other direction.
    d.put(cf::STATE, b"a", b"by the block").unwrap();
    d.delete(cf::STATE, b"b").unwrap();
    assert!(j.check_current_matches_after(&d).is_err());
}

// ── Issue #253: competing blocks at one height ─────────────────────────────

/// Two blocks at the SAME height leave two distinct journals.
///
/// This is issue #253 as a regression test. `ComputePoolStateDiff` and
/// `BeaconStateDiff` key by `height.to_be_bytes()` alone, so the second block at
/// a height overwrites the first's undo record and a later revert of the first
/// block replays the second block's mutations — deleting rows that should have
/// been restored. Here the key carries the 32-byte block hash, so the two
/// records cannot name the same row, and the record repeats its own
/// `(height, hash)` so reading one under the other's key is refused rather than
/// silently accepted.
#[test]
fn competing_blocks_at_one_height_leave_distinct_non_colliding_journals() {
    let (d, _g) = db();
    d.put(cf::STATE, b"contested", b"parent value").unwrap();

    let a = block_at(9, 1);
    let b = block_at(9, 2);
    assert_eq!(a.height(), b.height(), "same height");
    assert_ne!(a.hash(), b.hash(), "different blocks");

    publish_with(&d, &a, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"contested", b"from A")
    })
    .expect("publish A");
    publish_with(&d, &b, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"contested", b"from B")
    })
    .expect("publish B");

    let rows = journal_rows(&d);
    assert_eq!(
        rows.len(),
        2,
        "two blocks at one height must leave two journal rows; one row is #253"
    );
    let key_a = journal_key(9, &a.hash());
    let key_b = journal_key(9, &b.hash());
    assert_ne!(key_a, key_b);
    let bytes_a = d.get(cf::APPLICATION_JOURNAL, &key_a).unwrap().unwrap();
    let bytes_b = d.get(cf::APPLICATION_JOURNAL, &key_b).unwrap().unwrap();
    assert_ne!(bytes_a, bytes_b, "the two records must differ");

    // The height prefix the pruner parses is still the first eight bytes.
    assert_eq!(&key_a[..8], &9u64.to_be_bytes());
    assert_eq!(&key_b[..8], &9u64.to_be_bytes());

    // A record refuses to be read as the other block's.
    assert!(ApplicationJournal::decode_for(&bytes_a, 9, &a.hash()).is_ok());
    let crossed = ApplicationJournal::decode_for(&bytes_a, 9, &b.hash())
        .expect_err("A's record must not decode as B's");
    assert!(
        crossed.to_string().contains("another block's undo record"),
        "{crossed}"
    );

    // And A's undo record still says what A overwrote, which is the value the
    // #253 collision destroys.
    let ja = ApplicationJournal::decode_for(&bytes_a, 9, &a.hash()).unwrap();
    assert_eq!(
        *ja.entries()[0].before(),
        Preimage::Value(b"parent value".to_vec())
    );
    let jb = ApplicationJournal::decode_for(&bytes_b, 9, &b.hash()).unwrap();
    assert_eq!(
        *jb.entries()[0].before(),
        Preimage::Value(b"from A".to_vec()),
        "B executed on top of A, so B's pre-image is A's value"
    );

    // Unwinding in reverse order walks the state back through both.
    jb.undo_batch(&d).unwrap().commit().unwrap();
    assert_eq!(
        d.get(cf::STATE, b"contested").unwrap().as_deref(),
        Some(&b"from A"[..])
    );
    ja.undo_batch(&d).unwrap().commit().unwrap();
    assert_eq!(
        d.get(cf::STATE, b"contested").unwrap().as_deref(),
        Some(&b"parent value"[..])
    );
}

// ── Charging ───────────────────────────────────────────────────────────────

/// The smallest ceiling at which this block publishes.
///
/// Monotone in the limit — a larger ceiling only relaxes checks — so a bisection
/// finds the exact total the candidate is charged.
fn minimum_publishing_limit(prior_len: usize) -> u64 {
    let block = block_at(9, 1);
    let prior = vec![b'p'; prior_len];
    let attempt = |limit: u64| -> bool {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", &prior).unwrap();
        publish_with(&d, &block, limit, |view| view.put(cf::STATE, b"k", b"new")).is_ok()
    };

    let (mut lo, mut hi) = (0u64, TEST_LIMIT);
    assert!(attempt(hi), "the generous ceiling must publish");
    assert!(!attempt(lo), "a zero ceiling must not");
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if attempt(mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    hi
}

/// Journal bytes are charged against the candidate's ceiling.
///
/// The discriminating measurement: grow the PRE-IMAGE by `DELTA` bytes and the
/// minimum publishing ceiling grows by exactly `2 * DELTA` — once for the
/// pre-image the overlay captured, once for the copy of it inside the journal.
/// If the journal were staged outside the accounting, as an earlier generation
/// of side-buffer would have been, the ceiling would grow by `DELTA` alone.
///
/// Equality, not an inequality: the encoding is fixed-width-prefixed, so a
/// pre-image `DELTA` bytes longer makes the record exactly `DELTA` bytes longer
/// and nothing else moves.
#[test]
fn journal_bytes_are_charged_against_the_candidate_ceiling() {
    const SMALL: usize = 64;
    const DELTA: usize = 4_096;

    let base = minimum_publishing_limit(SMALL);
    let grown = minimum_publishing_limit(SMALL + DELTA);
    assert_eq!(
        grown - base,
        2 * DELTA as u64,
        "a pre-image {DELTA} bytes larger must cost {DELTA} for the overlay's \
         capture AND {DELTA} for the journal's copy of it; {} says the journal \
         is not being charged",
        grown - base
    );
}

/// A block whose journal does not fit is refused, and touches nothing.
#[test]
fn a_block_whose_journal_exceeds_the_ceiling_publishes_nothing() {
    const PRIOR: usize = 4_096;
    let exact = minimum_publishing_limit(PRIOR);

    let (d, _g) = db();
    d.put(cf::STATE, b"k", &vec![b'p'; PRIOR]).unwrap();
    let before = whole_db(&d);
    let block = block_at(9, 1);

    let err = publish_with(&d, &block, exact - 1, |view| {
        view.put(cf::STATE, b"k", b"new")
    })
    .expect_err("one byte under the exact total must be refused");
    assert!(err.contains("limit"), "{err}");

    assert_eq!(
        whole_db(&d),
        before,
        "a refused publication must leave RocksDB byte-identical: no canonical \
         row, and no journal row either"
    );
    assert!(journal_rows(&d).is_empty());

    // And at the exact total it publishes, so the refusal above is about the
    // ceiling and not about the fixture being broken.
    let (d2, _g2) = db();
    d2.put(cf::STATE, b"k", &vec![b'p'; PRIOR]).unwrap();
    publish_with(&d2, &block, exact, |view| view.put(cf::STATE, b"k", b"new"))
        .expect("the exact total publishes");
    assert_eq!(journal_rows(&d2).len(), 1);
}

// ── Abandonment ────────────────────────────────────────────────────────────

/// An abandoned candidate writes no journal at all.
///
/// Both ways a candidate can be abandoned: dropped after execution, and refused
/// at acceptance. The journal is derived inside `publish`, so a candidate that
/// never publishes never produces one — there is no window in which undo data
/// exists for a block that did not happen.
#[test]
fn an_abandoned_candidate_writes_no_journal() {
    // (a) executed, then dropped.
    let (d, _g) = db();
    d.put(cf::STATE, b"k", b"original").unwrap();
    let block = block_at(9, 1);
    {
        let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
        {
            let mut view = cand.view();
            view.put(cf::STATE, b"k", b"candidate value").unwrap();
        }
        let executed = cand.finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            block.header.state_root,
            Vec::new(),
            empty_journals(),
        );
        drop(executed);
    }
    assert!(
        journal_rows(&d).is_empty(),
        "a dropped candidate must leave no undo record"
    );
    assert_eq!(
        d.get(cf::STATE, b"k").unwrap().as_deref(),
        Some(&b"original"[..])
    );

    // (b) refused at acceptance: the root disagrees, above the compatibility
    // cutoff, so the candidate is consumed rather than published.
    let high = block_at(
        sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1,
        2,
    );
    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"k", b"rejected value").unwrap();
    }
    let err = cand
        .finish_execution(
            ExecutionSubject::of(&high).unwrap(),
            Hash::hash(b"a different root"),
            Vec::new(),
            empty_journals(),
        )
        .accept_imported(&high)
        .err()
        .expect("a root mismatch above the cutoff must be refused");
    assert!(err.to_string().contains("state root mismatch"), "{err}");
    assert!(
        journal_rows(&d).is_empty(),
        "a refused candidate must leave no undo record"
    );
}

/// A block that wrote nothing still leaves a journal, and it is empty.
///
/// A missing row and "nothing to undo" are different claims, and a consumer that
/// cannot tell them apart has to guess whether the producer wrote journals at
/// all.
#[test]
fn a_block_that_wrote_nothing_leaves_an_empty_journal_rather_than_no_row() {
    let (d, _g) = db();
    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |_| Ok(())).expect("publish");

    let j = journal_of(&d, &block);
    assert!(j.is_empty(), "no application write means no entries");
    assert_eq!(j.entries().len(), 0);
    assert_eq!(j.height(), 9);
    assert_eq!(j.block_hash(), block.hash());
    assert_eq!(j.column_families(), BTreeSet::new());
}

/// A block that DELETED a key records the deletion on both sides.
#[test]
fn a_deleted_key_records_its_prior_value_and_an_absent_after_image() {
    let (d, _g) = db();
    d.put(cf::STATE, b"doomed", b"still here").unwrap();
    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.delete(cf::STATE, b"doomed")
    })
    .expect("publish");

    assert_eq!(d.get(cf::STATE, b"doomed").unwrap(), None);
    let j = journal_of(&d, &block);
    let e = &j.entries()[0];
    assert_eq!(*e.before(), Preimage::Value(b"still here".to_vec()));
    assert_eq!(*e.after(), AfterImage::Absent);

    j.check_current_matches_after(&d)
        .expect("deleted, as recorded");
    j.undo_batch(&d).unwrap().commit().unwrap();
    assert_eq!(
        d.get(cf::STATE, b"doomed").unwrap().as_deref(),
        Some(&b"still here"[..])
    );
}

/// The pre-image is the value at the START of the block, not an intermediate.
#[test]
fn repeated_writes_to_one_key_journal_the_value_the_block_started_from() {
    let (d, _g) = db();
    d.put(cf::STATE, b"k", b"parent").unwrap();
    let block = block_at(9, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"first")?;
        view.put(cf::STATE, b"k", b"second")?;
        view.delete(cf::STATE, b"k")?;
        view.put(cf::STATE, b"k", b"final")
    })
    .expect("publish");

    let j = journal_of(&d, &block);
    assert_eq!(j.entries().len(), 1, "one key, one entry");
    assert_eq!(
        *j.entries()[0].before(),
        Preimage::Value(b"parent".to_vec()),
        "undo must restore what the PARENT held, not an intermediate"
    );
    j.undo_batch(&d).unwrap().commit().unwrap();
    assert_eq!(
        d.get(cf::STATE, b"k").unwrap().as_deref(),
        Some(&b"parent"[..])
    );
}

// ── Activation ─────────────────────────────────────────────────────────────

/// The WRITE side has no gate to leave unset.
///
/// This is the answer to the defect the census found in the other two journals:
/// `compute_pool_enabled_from_height` and `beacon_enabled_from_height` are
/// `None` in production, so neither journal is ever written and every test that
/// exercises them seeds rows by hand. There is no equivalent here to leave
/// `None` — `publish` writes a record for every block it publishes, and this
/// test publishes through the ordinary path with no parameter set anywhere.
#[test]
fn the_write_side_is_ungated_so_no_configuration_can_leave_it_unwritten() {
    let (d, _g) = db();
    for tag in 0..4u64 {
        let block = block_at(100 + tag, tag);
        publish_with(&d, &block, TEST_LIMIT, |view| {
            view.put(cf::STATE, b"k", &tag.to_be_bytes())
        })
        .expect("publish");
    }
    assert_eq!(
        journal_rows(&d).len(),
        4,
        "every published block must leave a record, with nothing to switch on"
    );
}

/// The boundary is observed from the chain, so an upgrade needs no number.
///
/// A node that starts publishing journals at height H has journal history from H
/// upward and none below it. The lowest stored height IS that boundary, so a
/// revert below it meets the compatibility case and a revert above it requires
/// a record.
#[test]
fn the_activation_boundary_is_observed_from_the_chains_own_journals() {
    let (d, _g) = db();

    // Before any block publishes: no boundary, so every height is pre-journal
    // history. An observation about the database, not a gate left unset.
    let empty = JournalActivation::resolve(&d, ActivationSource::ObservedFromChain).unwrap();
    assert_eq!(empty.boundary(), None);
    assert_eq!(empty.requirement_at(0), JournalRequirement::PreActivation);
    assert_eq!(
        empty.requirement_at(u64::MAX),
        JournalRequirement::PreActivation
    );

    // This node starts publishing at height 500.
    for h in [500u64, 501, 502] {
        let block = block_at(h, h);
        publish_with(&d, &block, TEST_LIMIT, |view| {
            view.put(cf::STATE, b"k", b"v")
        })
        .expect("publish");
    }

    let act = JournalActivation::resolve(&d, ActivationSource::ObservedFromChain).unwrap();
    assert_eq!(act.boundary(), Some(500));
    assert_eq!(act.requirement_at(499), JournalRequirement::PreActivation);
    assert_eq!(act.requirement_at(500), JournalRequirement::Required);
    assert_eq!(act.requirement_at(502), JournalRequirement::Required);
}

/// A boundary can be pinned instead, for a deployment that wants one answer
/// across every node rather than each observing its own.
#[test]
fn a_pinned_boundary_overrides_the_observed_one() {
    let (d, _g) = db();
    let block = block_at(500, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");

    let pinned = JournalActivation::resolve(&d, ActivationSource::Pinned(400)).unwrap();
    assert_eq!(pinned.boundary(), Some(400));
    assert_eq!(pinned.requirement_at(400), JournalRequirement::Required);
    assert_eq!(
        pinned.requirement_at(399),
        JournalRequirement::PreActivation
    );
}

/// A journal missing AT OR ABOVE the boundary halts. Below it, absence is the
/// explicit compatibility case.
///
/// This is the case `state.rs` currently answers with `return Ok(())` when all
/// four legacy journals are absent — a silent skip, which the contract forbids
/// post-activation. The decision lives in one function so both sides give the
/// same answer.
#[test]
fn a_missing_post_activation_journal_halts_and_a_pre_activation_one_does_not() {
    let (d, _g) = db();
    let published = block_at(500, 1);
    publish_with(&d, &published, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");

    let act = JournalActivation::resolve(&d, ActivationSource::ObservedFromChain).unwrap();
    assert_eq!(act.boundary(), Some(500));

    // Present: decoded and validated.
    let found = act
        .load_for_revert(&d, 500, &published.hash())
        .expect("a published block's journal loads")
        .expect("and is present");
    assert_eq!(found.block_hash(), published.hash());

    // Absent BELOW the boundary: the compatibility case, stated rather than
    // stumbled into.
    let old = block_at(499, 2);
    assert!(act
        .load_for_revert(&d, 499, &old.hash())
        .expect("pre-activation absence is defined")
        .is_none());

    // Absent AT OR ABOVE it: a halt, naming the block and the boundary.
    let phantom = block_at(501, 3);
    let err = act
        .load_for_revert(&d, 501, &phantom.hash())
        .expect_err("a missing post-activation journal must halt");
    assert!(err.to_string().contains("refusing to revert"), "{err}");
    assert!(err.to_string().contains("501"), "{err}");

    // A sibling at a height that DOES have journal history, but whose own record
    // was never written, halts too — the boundary is a height, not a block.
    let sibling = block_at(500, 4);
    assert_ne!(sibling.hash(), published.hash());
    assert!(act.load_for_revert(&d, 500, &sibling.hash()).is_err());
}

/// A corrupt record at or above the boundary halts; it does not read as absent.
#[test]
fn a_corrupt_journal_halts_rather_than_reading_as_no_journal() {
    let (d, _g) = db();
    let block = block_at(500, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");

    let key = journal_key(500, &block.hash());
    let mut bytes = d.get(cf::APPLICATION_JOURNAL, &key).unwrap().unwrap();
    bytes.truncate(bytes.len() - 3);
    d.put(cf::APPLICATION_JOURNAL, &key, &bytes).unwrap();

    let act = JournalActivation::resolve(&d, ActivationSource::ObservedFromChain).unwrap();
    let err = act
        .load_for_revert(&d, 500, &block.hash())
        .expect_err("a truncated record must halt");
    assert!(err.to_string().contains("truncated"), "{err}");
}

/// A binary refuses to run against journal history it cannot read.
///
/// The downgrade check. Discovering an unreadable record during a reorg is
/// discovering it with the chain already committed to unwinding; this turns it
/// into a refusal to start.
#[test]
fn a_binary_refuses_to_start_against_a_newer_record_format() {
    let (d, _g) = db();
    let block = block_at(500, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");

    assert_eq!(
        sumchain_storage::journal::highest_stored_format_version(&d).unwrap(),
        Some(sumchain_storage::journal::FORMAT_VERSION_V1)
    );
    sumchain_storage::journal::refuse_downgrade(&d).expect("its own records are readable");

    // A record written by a future binary.
    let key = journal_key(500, &block.hash());
    let mut bytes = d.get(cf::APPLICATION_JOURNAL, &key).unwrap().unwrap();
    bytes[5..7].copy_from_slice(&7u16.to_be_bytes());
    d.put(cf::APPLICATION_JOURNAL, &key, &bytes).unwrap();

    assert_eq!(
        sumchain_storage::journal::highest_stored_format_version(&d).unwrap(),
        Some(7)
    );
    let err = sumchain_storage::journal::refuse_downgrade(&d)
        .expect_err("post-activation history in a newer format must refuse the downgrade");
    assert!(err.to_string().contains("refuses to start"), "{err}");
}

/// The format watermark is STAMPED, so it survives pruning away every record.
///
/// # Why the stamp exists
///
/// `highest_stored_format_version` derives the watermark from the records
/// themselves, which is exact while the records are there. Pruning removes them
/// — that is its job — and a pruned database can reach a state where the family
/// is empty. At that point the scan says "nothing", and a downgrade the records
/// would have refused becomes silently permitted: an older binary starts, runs,
/// and discovers during a reorg that it cannot read the history it already
/// committed to unwinding.
///
/// So `publish` stamps a `META` row in the same batch as the block, the row is
/// not pruned, and `validate_startup` takes the HIGHER of the two watermarks.
#[test]
fn the_format_watermark_survives_pruning_away_every_record() {
    let (d, _g) = db();
    let block = block_at(500, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");

    let state = sumchain_storage::journal::validate_startup(&d).expect("this binary's own record");
    assert_eq!(
        state.persisted,
        Some(sumchain_storage::journal::FORMAT_VERSION_V1),
        "publish must stamp the format watermark"
    );
    assert_eq!(
        state.scanned,
        Some(sumchain_storage::journal::FORMAT_VERSION_V1)
    );
    assert_eq!(state.observed_boundary, Some(500));

    // Raise the STAMP alone, as a newer binary would have, and then remove every
    // record as pruning would.
    d.put(
        cf::META,
        sumchain_storage::journal::FORMAT_HIGH_WATER_META_KEY,
        &9u16.to_be_bytes(),
    )
    .unwrap();
    d.delete(cf::APPLICATION_JOURNAL, &journal_key(500, &block.hash()))
        .unwrap();

    assert_eq!(
        sumchain_storage::journal::highest_stored_format_version(&d).unwrap(),
        None,
        "the fixture must really have pruned every record, or this proves nothing"
    );
    let err = sumchain_storage::journal::validate_startup(&d).expect_err(
        "a database whose newer records have been pruned must still refuse the downgrade",
    );
    assert!(err.to_string().contains("refuses to start"), "{err}");
    assert!(
        err.to_string().contains("Downgrading a node"),
        "the refusal must state the operational rule and the recovery, not only \
         that it refused: {err}"
    );
}

/// The startup gate accepts a database with no journal history at all.
///
/// A fresh database has no records and no stamp. That is not a downgrade, it is
/// a node that has published nothing, and refusing it would refuse every cold
/// start. The boundary is `None`, which the consumer reads as "nothing is
/// required yet" — and it stops being `None` the moment the first block
/// publishes, because the write side has no gate to leave unset.
#[test]
fn a_database_with_no_journal_history_starts_and_requires_nothing() {
    let (d, _g) = db();
    let state = sumchain_storage::journal::validate_startup(&d).expect("a cold start is fine");
    assert_eq!(state.persisted, None);
    assert_eq!(state.scanned, None);
    assert_eq!(state.observed_boundary, None);
    assert_eq!(state.effective_high_water(), None);

    let block = block_at(1, 1);
    publish_with(&d, &block, TEST_LIMIT, |view| {
        view.put(cf::STATE, b"k", b"v")
    })
    .expect("publish");
    let state = sumchain_storage::journal::validate_startup(&d).expect("still fine");
    assert_eq!(state.observed_boundary, Some(1));
    assert_eq!(
        state.effective_high_water(),
        Some(sumchain_storage::journal::FORMAT_VERSION_V1)
    );
}
