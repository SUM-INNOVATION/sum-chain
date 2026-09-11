//! A canonical transition publishes completely and coherently, or not at all.
//!
//! The previous design recorded which builder *methods* had been called, so
//! `with_journals(&[])` and `with_head(&[])` satisfied it while supplying
//! nothing, and the accumulator could be written to any column family and key a
//! caller chose. These tests exist against that class of mistake: the type must
//! make the forged transition unconstructible, not merely unlikely.

use sumchain_primitives::{Block, BlockHeader, Hash};
use sumchain_storage::candidate::{
    CandidateExecution, CanonicalTransition, JournalRecord, ACCUMULATOR_KEY,
    ACTIVATION_VERSION_KEY,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::{journal_key, meta_keys};
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;
const VERSION: u32 = 7;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

fn block_with_root(root: Hash, height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        root,
        [0u8; 32],
    );
    Block::new(header, Vec::new())
}

/// A candidate that wrote one state row, verified against `block`.
fn verified<'a>(
    d: &'a Database,
    block: &Block,
) -> sumchain_storage::candidate::VerifiedCandidate<'a> {
    let mut cand = CandidateExecution::new(d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    cand.verify_for_block(block, block.header.state_root)
        .expect("roots match")
}

fn transition(block: &Block, accumulator: Hash, version: u32) -> CanonicalTransition {
    CanonicalTransition::new(
        block,
        b"block-bytes".to_vec(),
        accumulator,
        version,
        JournalRecord::Recorded(b"account-undo".to_vec()),
        JournalRecord::Recorded(b"contract-undo".to_vec()),
        JournalRecord::NothingToUndo,
        JournalRecord::NothingToUndo,
    )
}

#[test]
fn a_complete_transition_publishes_every_component_in_one_batch() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    verified(&d, &block)
        .publish(transition(&block, root, VERSION))
        .unwrap();

    let jkey = journal_key(9, &block.hash());
    assert_eq!(
        d.get(cf::STATE, b"acct:alice").unwrap().as_deref(),
        Some(&b"100"[..])
    );
    assert_eq!(
        d.get(cf::STATE_DIFFS, &jkey).unwrap().as_deref(),
        Some(&b"account-undo"[..])
    );
    assert_eq!(
        d.get(cf::CONTRACT_STATE_DIFFS, &jkey).unwrap().as_deref(),
        Some(&b"contract-undo"[..])
    );
    assert_eq!(
        d.get(cf::COMPUTE_POOL_STATE_DIFFS, &jkey).unwrap(),
        None,
        "NothingToUndo writes no row"
    );
    assert_eq!(
        d.get(cf::META, ACCUMULATOR_KEY).unwrap().as_deref(),
        Some(&root.as_bytes()[..])
    );
    assert_eq!(
        d.get(cf::META, ACTIVATION_VERSION_KEY).unwrap().as_deref(),
        Some(&VERSION.to_be_bytes()[..])
    );
    assert_eq!(
        d.get(cf::META, meta_keys::LATEST_BLOCK_HASH).unwrap().as_deref(),
        Some(&block.hash().as_bytes()[..])
    );
    assert_eq!(
        d.get(cf::BLOCKS, block.hash().as_bytes()).unwrap().as_deref(),
        Some(&b"block-bytes"[..])
    );
}

#[test]
fn a_transition_for_a_different_block_is_refused() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);
    let other = block_with_root(root, 9, 2); // same height and root, different block
    assert_ne!(block.hash(), other.hash());

    let err = verified(&d, &block)
        .publish(transition(&other, root, VERSION))
        .expect_err("must refuse a transition describing another block");
    assert!(err.to_string().contains("describes block"), "{err}");
    assert_eq!(d.get(cf::STATE, b"acct:alice").unwrap(), None);
}

#[test]
fn a_transition_at_a_different_height_is_refused() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    // Same block contents, different height -> different hash AND height.
    let wrong = block_with_root(root, 10, 1);
    let err = verified(&d, &block)
        .publish(transition(&wrong, root, VERSION))
        .expect_err("must refuse");
    let msg = err.to_string();
    assert!(msg.contains("describes block") || msg.contains("height"), "{msg}");
    assert_eq!(d.get(cf::STATE, b"acct:alice").unwrap(), None);
}

#[test]
fn an_accumulator_that_is_not_the_verified_root_is_refused() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    let err = verified(&d, &block)
        .publish(transition(&block, Hash::hash(b"something-else"), VERSION))
        .expect_err("must refuse an accumulator that is not the verified root");
    assert!(err.to_string().contains("does not match the verified root"), "{err}");
    assert_eq!(d.get(cf::STATE, b"acct:alice").unwrap(), None);
    assert_eq!(d.get(cf::META, ACCUMULATOR_KEY).unwrap(), None);
}

#[test]
fn the_accumulator_and_activation_keys_are_fixed_not_caller_chosen() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);
    verified(&d, &block)
        .publish(transition(&block, root, VERSION))
        .unwrap();

    // There is no API to write these anywhere else: `publish` derives both keys
    // internally. This pins the locations so a later change has to be deliberate.
    assert_eq!(ACCUMULATOR_KEY, b"state_accumulator");
    assert_eq!(ACTIVATION_VERSION_KEY, b"activation_version");
    assert!(d.get(cf::META, b"arbitrary-key").unwrap().is_none());
}

#[test]
fn an_absent_journal_is_a_statement_not_an_omission() {
    // `JournalRecord` has no empty-slice form. A family that changed nothing is
    // `NothingToUndo`, which is a value the author had to write. There is no way
    // to construct a transition that simply fails to mention a family — the
    // constructor requires all four.
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    let t = CanonicalTransition::new(
        &block,
        b"bytes".to_vec(),
        root,
        VERSION,
        JournalRecord::NothingToUndo,
        JournalRecord::NothingToUndo,
        JournalRecord::NothingToUndo,
        JournalRecord::NothingToUndo,
    );
    verified(&d, &block).publish(t).unwrap();

    let jkey = journal_key(9, &block.hash());
    for family in [
        cf::STATE_DIFFS,
        cf::CONTRACT_STATE_DIFFS,
        cf::COMPUTE_POOL_STATE_DIFFS,
        cf::BEACON_STATE_DIFFS,
    ] {
        assert_eq!(d.get(family, &jkey).unwrap(), None);
    }
    // The state row and head still published: "nothing to undo" is valid.
    assert_eq!(
        d.get(cf::STATE, b"acct:alice").unwrap().as_deref(),
        Some(&b"100"[..])
    );
}

#[test]
fn journals_are_written_under_the_key_a_reorg_will_look_for() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 42, 5);
    verified(&d, &block)
        .publish(transition(&block, root, VERSION))
        .unwrap();

    // Derived internally from (height, block hash) — a caller cannot write an
    // undo record under a key nothing will look for.
    let expected = journal_key(42, &block.hash());
    assert_eq!(
        d.get(cf::STATE_DIFFS, &expected).unwrap().as_deref(),
        Some(&b"account-undo"[..])
    );
    assert_eq!(
        d.get(cf::STATE_DIFFS, &42u64.to_be_bytes()).unwrap(),
        None,
        "not under the pre-#253 height-only key"
    );
}
