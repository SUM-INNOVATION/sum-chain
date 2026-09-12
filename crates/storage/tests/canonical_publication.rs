//! Acceptance semantics: which candidates may publish, and on what evidence.
//!
//! The canonical WRITE SET is covered byte-for-byte in `publication_parity.rs`.

use sumchain_primitives::{Block, BlockHeader, Hash, Receipt};
use sumchain_storage::candidate::{
    Acceptance, CandidateExecution, BlockJournals, ExecutionSubject, JournalRecord, LEGACY_ROOT_COMPATIBILITY_HEIGHT,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::journal_key;
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

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

/// Execute one state row, bind artifacts, and return the executed candidate.
fn executed<'d>(
    d: &'d Database,
    block: &Block,
    computed: Hash,
) -> sumchain_storage::candidate::ExecutedCandidate<'d> {
    executed_with(
        d,
        block,
        computed,
        Vec::new(),
        JournalRecord::Recorded(b"account-undo".to_vec()),
    )
}

fn executed_with<'d>(
    d: &'d Database,
    block: &Block,
    computed: Hash,
    receipts: Vec<Receipt>,
    account: JournalRecord,
) -> sumchain_storage::candidate::ExecutedCandidate<'d> {
    let mut cand = CandidateExecution::new(d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        computed,
        receipts,
        BlockJournals {
            account,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
}

// ── Acceptance evidence ────────────────────────────────────────────────────

#[test]
fn a_produced_block_is_accepted_by_construction_not_by_comparison() {
    let (d, _g) = db();
    let root = Hash::hash(b"computed");
    let block = block_with_root(root, 9, 1);
    let a = executed(&d, &block, root).accept_produced(&block).expect("produced");

    assert_eq!(*a.acceptance(), Acceptance::Produced);
    assert!(
        !a.acceptance().is_verified(),
        "acceptance by construction must not report as a verified root"
    );
    assert_eq!(a.accumulator(), root);
}

#[test]
fn a_producer_whose_header_disagrees_with_its_own_execution_is_refused() {
    let (d, _g) = db();
    let block = block_with_root(Hash::hash(b"header"), 9, 1);
    let err = executed(&d, &block, Hash::hash(b"different"))
        .accept_produced(&block)
        .expect_err("a producer bug must not publish");
    assert!(err.to_string().contains("producer bug"), "{err}");
}

#[test]
fn an_exact_imported_root_reports_as_verified() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);
    let a = executed(&d, &block, root).accept_imported(&block).expect("exact");

    assert_eq!(*a.acceptance(), Acceptance::ExactRoot);
    assert!(a.acceptance().is_verified());
    assert_eq!(a.accumulator(), root);
}

#[test]
fn a_mismatch_above_the_cutoff_publishes_nothing() {
    let (d, _g) = db();
    d.put(cf::STATE, b"existing", b"original").unwrap();
    let block = block_with_root(Hash::hash(b"header"), LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1, 1);

    let err = executed(&d, &block, Hash::hash(b"computed"))
        .accept_imported(&block)
        .expect_err("must reject above the cutoff");
    assert!(err.to_string().contains("state root mismatch"), "{err}");
    assert_eq!(
        d.get(cf::STATE, b"existing").unwrap().as_deref(),
        Some(&b"original"[..])
    );
}

#[test]
fn a_mismatch_at_the_cutoff_adopts_the_header_root_and_says_so() {
    let (d, _g) = db();
    let header = Hash::hash(b"header");
    let computed = Hash::hash(b"computed");
    let block = block_with_root(header, LEGACY_ROOT_COMPATIBILITY_HEIGHT, 1);

    let a = executed(&d, &block, computed)
        .accept_imported(&block)
        .expect("the legacy allowance applies at the cutoff");

    assert_eq!(
        *a.acceptance(),
        Acceptance::LegacyCompatibility { computed, header }
    );
    assert!(!a.acceptance().is_verified());
    assert_eq!(
        a.accumulator(),
        header,
        "the HEADER's root is published, exactly as PoA does today"
    );
}

#[test]
fn the_cutoff_boundary_is_inclusive_below_and_exclusive_above() {
    let (d, _g) = db();
    for (height, ok) in [
        (LEGACY_ROOT_COMPATIBILITY_HEIGHT - 1, true),
        (LEGACY_ROOT_COMPATIBILITY_HEIGHT, true),
        (LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1, false),
    ] {
        let block = block_with_root(Hash::hash(b"header"), height, 1);
        let got = executed(&d, &block, Hash::hash(b"computed"))
            .accept_imported(&block)
            .is_ok();
        assert_eq!(got, ok, "height {height} acceptance should be {ok}");
    }
}

// ── Journals ───────────────────────────────────────────────────────────────

#[test]
fn journals_land_under_the_key_a_reorg_will_look_for() {
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 42, 5);
    executed(&d, &block, root)
        .accept_imported(&block)
        .unwrap()
        .publish()
        .unwrap();

    assert_eq!(
        d.get(cf::STATE_DIFFS, &journal_key(42, &block.hash()))
            .unwrap()
            .as_deref(),
        Some(&b"account-undo"[..])
    );
    assert_eq!(
        d.get(cf::STATE_DIFFS, &42u64.to_be_bytes()).unwrap(),
        None,
        "not under the pre-#253 height-only key"
    );
}

#[test]
fn an_absent_journal_is_a_statement_not_an_omission() {
    // `JournalRecord` has no empty form, and all four are parameters of
    // `finish_execution`, so a candidate cannot simply fail to mention one.
    let (d, _g) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    executed_with(&d, &block, root, Vec::new(), JournalRecord::NothingToUndo)
        .accept_imported(&block)
        .unwrap()
        .publish()
        .unwrap();

    let jkey = journal_key(9, &block.hash());
    for family in [
        cf::STATE_DIFFS,
        cf::CONTRACT_STATE_DIFFS,
        cf::COMPUTE_POOL_STATE_DIFFS,
        cf::BEACON_STATE_DIFFS,
    ] {
        assert_eq!(d.get(family, &jkey).unwrap(), None);
    }
    assert_eq!(
        d.get(cf::STATE, b"acct:alice").unwrap().as_deref(),
        Some(&b"100"[..]),
        "\"nothing to undo\" is valid: state and head still publish"
    );
}

#[test]
fn both_acceptance_paths_reach_the_same_publisher() {
    let (d1, _g1) = db();
    let (d2, _g2) = db();
    let root = Hash::hash(b"root");
    let block = block_with_root(root, 9, 1);

    for (d, produced) in [(&d1, true), (&d2, false)] {
        let e = executed(d, &block, root);
        let a = if produced {
            e.accept_produced(&block).unwrap()
        } else {
            e.accept_imported(&block).unwrap()
        };
        a.publish().unwrap();

        assert_eq!(
            d.get(cf::STATE, b"acct:alice").unwrap().as_deref(),
            Some(&b"100"[..])
        );
        assert_eq!(
            d.get(cf::BLOCK_HEIGHT, &9u64.to_be_bytes())
                .unwrap()
                .as_deref(),
            Some(&block.hash().as_bytes()[..])
        );
    }
}
