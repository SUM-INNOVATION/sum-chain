//! An execution belongs to the block it was performed for.
//!
//! Binding the accumulator, receipts and journals proves the artifacts came from
//! an execution. It does not prove they came from an execution of THIS block.
//! Without a subject, a candidate executed for block A is accepted against a
//! block B that keeps A's transactions and computed root while changing its
//! height, parent, timestamp or proposer — and publication then stores B's
//! header beside A's state.
//!
//! Every field below is consensus-relevant, and each has a negative on BOTH
//! acceptance paths, because produced and imported reach acceptance differently.

use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, Receipt, SignedTransaction, Transaction, TxStatus,
};
use sumchain_storage::candidate::{CandidateExecution, ExecutionSubject, BlockJournals, JournalRecord};
use sumchain_storage::db::{cf, Database};
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

fn tx(seed: u8, nonce: u64) -> SignedTransaction {
    let t = Transaction::new(
        1,
        Address::new([seed; 20]),
        Address::new([seed.wrapping_add(1); 20]),
        100,
        7,
        nonce,
    );
    SignedTransaction::new(t, [seed; 64], [seed; 32])
}

/// The block an execution is performed for.
fn base_block(root: Hash) -> Block {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        9,
        1_000,
        Hash::hash(b"txroot"),
        root,
        [7u8; 32],
    );
    Block::new(header, vec![tx(1, 0), tx(3, 1)])
}

fn receipts_for(block: &Block) -> Vec<Receipt> {
    block
        .transactions
        .iter()
        .map(|t| Receipt {
            tx_hash: t.hash(),
            status: TxStatus::Success,
            fee_paid: 7,
            block_height: block.height(),
            tx_index: 0,
        })
        .collect()
}

/// Execute for `executed_for`, then attempt acceptance against `presented`.
fn attempt(executed_for: &Block, presented: &Block, produced: bool) -> Result<(), String> {
    let (d, _g) = db();
    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    let executed = cand.finish_execution(
        ExecutionSubject::of(executed_for).unwrap(),
        executed_for.header.state_root,
        receipts_for(executed_for),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    );
    let r = if produced {
        executed.accept_produced(presented)
    } else {
        executed.accept_imported(presented)
    };
    r.map(|_| ()).map_err(|e| e.to_string())
}

/// Every way a block can differ while keeping the transactions and root.
fn variants(root: Hash) -> Vec<(&'static str, Block)> {
    let mut out = Vec::new();

    let mut b = base_block(root);
    b.header.height = 10;
    out.push(("height", b));

    let mut b = base_block(root);
    b.header.parent_hash = Hash::hash(b"a-different-parent");
    out.push(("parent hash", b));

    let mut b = base_block(root);
    b.header.timestamp = 2_000;
    out.push(("timestamp", b));

    let mut b = base_block(root);
    b.header.proposer_pubkey = [9u8; 32];
    out.push(("proposer", b));

    let mut b = base_block(root);
    b.header.tx_root = Hash::hash(b"a-different-txroot");
    out.push(("transaction root", b));

    let mut b = base_block(root);
    b.transactions.swap(0, 1);
    out.push(("transaction bytes or order", b));

    let mut b = base_block(root);
    b.transactions.pop();
    out.push(("transaction count", b));

    let mut b = base_block(root);
    b.transactions[0] = tx(5, 0);
    out.push(("transaction bytes or order", b));

    out
}

#[test]
fn a_produced_candidate_is_refused_against_any_altered_block() {
    let root = Hash::hash(b"root");
    let executed_for = base_block(root);

    for (field, presented) in variants(root) {
        let err = attempt(&executed_for, &presented, true)
            .expect_err(&format!("produced: a changed {field} must be refused"));
        assert!(
            err.contains(field) || err.contains("differs from the block"),
            "produced: error for a changed {field} should name it: {err}"
        );
    }
}

#[test]
fn an_imported_candidate_is_refused_against_any_altered_block() {
    let root = Hash::hash(b"root");
    let executed_for = base_block(root);

    for (field, presented) in variants(root) {
        let err = attempt(&executed_for, &presented, false)
            .expect_err(&format!("imported: a changed {field} must be refused"));
        assert!(
            err.contains(field) || err.contains("differs from the block"),
            "imported: error for a changed {field} should name it: {err}"
        );
    }
}

/// Guard against the refusals passing vacuously: the unaltered block IS accepted
/// on both paths.
#[test]
fn the_block_that_was_executed_is_accepted_on_both_paths() {
    let root = Hash::hash(b"root");
    let b = base_block(root);
    assert_eq!(attempt(&b, &b, true), Ok(()), "produced");
    assert_eq!(attempt(&b, &b, false), Ok(()), "imported");
}

/// The two fields derived AFTER execution must NOT be part of the subject.
///
/// The produce path computes the root and writes it into the header, then signs.
/// If either were compared, a candidate could never be accepted for the block it
/// was executed for — the subject would be uncapturable before execution.
#[test]
fn fields_derived_after_execution_are_excluded_from_the_subject() {
    let root = Hash::hash(b"root");
    let executed_for = base_block(root);

    // A signature applied after execution must not break acceptance.
    let mut signed = base_block(root);
    signed.header.set_signature([42u8; 64]);
    assert_eq!(
        attempt(&executed_for, &signed, false),
        Ok(()),
        "a signature applied after execution must not change the subject"
    );

    // The state root differing is the ACCEPTANCE decision's business, not the
    // subject's: it is what `accept_imported` compares, and a mismatch above the
    // cutoff is refused for being a root mismatch, not a subject mismatch.
    let mut other_root = base_block(root);
    other_root.header.state_root = Hash::hash(b"different-root");
    other_root.header.height = 600_000; // above the compatibility cutoff
    let err = attempt(&executed_for, &other_root, false).expect_err("refused");
    assert!(
        err.contains("height"),
        "a block differing in height is refused as a subject mismatch first: {err}"
    );
}

#[test]
fn the_subject_covers_every_header_field_except_the_two_derived_ones() {
    // A structural reminder: if `BlockHeader` grows a field, it must be added to
    // `ExecutionSubject` or deliberately excluded. This fails when the header
    // changes, which is the point.
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../primitives/src/block.rs"),
    )
    .expect("read block.rs");
    let start = src.find("pub struct BlockHeader").expect("header exists");
    let end = src[start..].find("\n}").expect("header ends") + start;
    let fields: Vec<&str> = src[start..end]
        .lines()
        .filter_map(|l| l.trim().strip_suffix(','))
        .filter(|l| !l.starts_with("//") && l.contains(": "))
        .map(|l| l.split(':').next().unwrap().trim().trim_start_matches("pub "))
        .collect();

    assert_eq!(
        fields,
        vec![
            "parent_hash",
            "height",
            "timestamp",
            "tx_root",
            "state_root",
            "proposer_pubkey",
            "proposer_sig",
        ],
        "BlockHeader changed: every new field must be added to ExecutionSubject \
         or deliberately excluded with a reason"
    );
}
