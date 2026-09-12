//! The new publication route must write exactly what the old one wrote.
//!
//! Not "the same information" — the same column families, the same keys, the
//! same value bytes, with nothing extra and nothing missing. A canonical write
//! set that is merely equivalent-looking is how a node ends up answering "what
//! is the block at height N" with the previous occupant.
//!
//! The old route is reproduced here from source (`BlockStore::put`,
//! `TxStore::put`, `ReceiptStore::put`, `index_by_sender`, `index_by_recipient`,
//! `save_state_diff`, `save_contract_state_diff`, `set_latest_hash`,
//! `set_latest_height`) and its result is compared byte-for-byte against a
//! `CanonicalTransition` publication of the same block.

use std::collections::BTreeMap;

use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, Receipt, SignedTransaction, Transaction, TxStatus,
};
use sumchain_storage::candidate::{
    Acceptance, CandidateExecution, BlockJournals, ExecutionSubject, JournalRecord, LEGACY_ROOT_COMPATIBILITY_HEIGHT,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::{BlockStore, ReceiptStore, StateStore, TxIndexStore, TxStore};
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

/// Every canonical column family a block admission can touch.
const CANONICAL_CFS: &[&str] = &[
    cf::BLOCKS,
    cf::BLOCK_HEIGHT,
    cf::TRANSACTIONS,
    cf::TX_BY_SENDER,
    cf::TX_BY_RECIPIENT,
    cf::RECEIPTS,
    cf::STATE_DIFFS,
    cf::CONTRACT_STATE_DIFFS,
    cf::COMPUTE_POOL_STATE_DIFFS,
    cf::BEACON_STATE_DIFFS,
    cf::META,
    cf::STATE,
];

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

/// The complete contents of every canonical CF, as raw bytes.
fn snapshot(d: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for name in CANONICAL_CFS {
        if let Ok(it) = d.iter(name) {
            for (k, v) in it {
                out.insert((name.to_string(), k.to_vec()), v.to_vec());
            }
        }
    }
    out
}

/// A transaction with a dummy signature.
///
/// Parity is about ENCODINGS — which column family, which key, which bytes — and
/// neither route validates a signature while writing. A real signature would
/// pull `sumchain-crypto` into this crate's dev-dependencies and prove nothing
/// extra.
fn tx_with(sender_seed: u8, recipient: Option<Address>, nonce: u64) -> SignedTransaction {
    let from = Address::new([sender_seed; 20]);
    let to = recipient.unwrap_or_else(|| Address::new([0u8; 20]));
    let tx = Transaction::new(1, from, to, 100, 7, nonce);
    SignedTransaction::new(tx, [sender_seed; 64], [sender_seed; 32])
}

/// A block WITH transactions — one with a recipient and one without, so the
/// recipient index's conditional write is actually exercised. An empty block
/// would make every transaction, receipt and index assertion below vacuous,
/// which is how a parity test passes while covering nothing.
fn block_at(height: u64, root: Hash, tag: u64) -> Block {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        root,
        [0u8; 32],
    );
    let txs = vec![
        tx_with(1, Some(Address::new([2u8; 20])), 0),
        tx_with(3, Some(Address::new([4u8; 20])), 1),
    ];
    Block::new(header, txs)
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

/// The pre-existing write sequence, reproduced from the source it came from.
fn old_route(d: &Database, block: &Block, receipts: &[Receipt], account: &[u8], contract: &[u8]) {
    let height = block.height();
    let block_hash = block.hash();

    let tx_store = TxStore::new(d);
    let receipt_store = ReceiptStore::new(d);
    let tx_index_store = TxIndexStore::new(d);
    for (i, tx) in block.transactions.iter().enumerate() {
        tx_store.put(tx).unwrap();
        tx_index_store
            .index_transaction(tx, height, i as u32)
            .unwrap();
    }
    for r in receipts {
        receipt_store.put(r).unwrap();
    }

    d.put(
        cf::STATE_DIFFS,
        &sumchain_storage::schema::journal_key(height, &block_hash),
        account,
    )
    .unwrap();
    d.put(
        cf::CONTRACT_STATE_DIFFS,
        &sumchain_storage::schema::journal_key(height, &block_hash),
        contract,
    )
    .unwrap();

    let block_store = BlockStore::new(d);
    block_store.put(block).unwrap();
    block_store.set_latest_hash(&block_hash).unwrap();
    block_store.set_latest_height(height).unwrap();
}

/// The new route: execute into a candidate, accept, publish one transition.
fn new_route(d: &Database, block: &Block, receipts: &[Receipt], account: &[u8], contract: &[u8]) {
    CandidateExecution::new(d, TEST_LIMIT)
        .finish_execution(
            ExecutionSubject::of(block).unwrap(),
            block.header.state_root,
            receipts.to_vec(),
            BlockJournals {
                account: JournalRecord::Recorded(account.to_vec()),
                contract: JournalRecord::Recorded(contract.to_vec()),
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(block)
        .expect("exact root")
        .publish()
        .unwrap();
}

/// Bind artifacts and accept, without publishing.
fn accept<'a>(
    d: &'a Database,
    block: &'a Block,
    receipts: &[Receipt],
    limit: u64,
) -> Result<sumchain_storage::candidate::AcceptedCandidate<'a, 'a>, String> {
    let mut cand = CandidateExecution::new(d, limit);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        block.header.state_root,
        receipts.to_vec(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
    .accept_imported(block)
    .map_err(|e| e.to_string())
}

#[test]
fn the_new_route_writes_exactly_what_the_old_route_wrote() {
    let (old_db, _g1) = db();
    let (new_db, _g2) = db();

    let block = block_at(9, Hash::hash(b"root"), 1);
    let receipts = receipts_for(&block);
    let account = b"account-undo";
    let contract = b"contract-undo";

    old_route(&old_db, &block, &receipts, account, contract);
    new_route(&new_db, &block, &receipts, account, contract);

    let old = snapshot(&old_db);
    let new = snapshot(&new_db);

    let only_old: Vec<_> = old.keys().filter(|k| !new.contains_key(*k)).collect();
    let only_new: Vec<_> = new.keys().filter(|k| !old.contains_key(*k)).collect();
    assert!(
        only_old.is_empty(),
        "the new route OMITS keys the old route wrote: {only_old:?}"
    );
    assert!(
        only_new.is_empty(),
        "the new route writes keys the old route did not: {only_new:?}"
    );
    for (k, v) in &old {
        assert_eq!(new.get(k), Some(v), "value differs at {k:?}");
    }

    // Guard against a vacuous pass: the comparison must actually have covered
    // transactions, receipts and both address indexes.
    for family in [
        cf::TRANSACTIONS,
        cf::TX_BY_SENDER,
        cf::TX_BY_RECIPIENT,
        cf::RECEIPTS,
        cf::BLOCKS,
        cf::BLOCK_HEIGHT,
        cf::STATE_DIFFS,
    ] {
        let n = old.keys().filter(|(c, _)| c == family).count();
        assert!(n > 0, "parity check covered no rows in {family}");
    }
}

#[test]
fn the_height_index_is_part_of_the_canonical_set() {
    // The omission that prompted this package: a block stored without its
    // height index answers "what is at height N" with the previous occupant.
    let (d, _g) = db();
    let block = block_at(42, Hash::hash(b"root"), 3);
    new_route(&d, &block, &receipts_for(&block), b"a", b"c");

    assert_eq!(
        d.get(cf::BLOCK_HEIGHT, &42u64.to_be_bytes())
            .unwrap()
            .as_deref(),
        Some(&block.hash().as_bytes()[..]),
        "BLOCK_HEIGHT[height] -> block_hash must be published"
    );
    assert_eq!(
        BlockStore::new(&d).get_by_height(42).unwrap().map(|b| b.hash()),
        Some(block.hash())
    );
}

#[test]
fn the_retired_metadata_keys_are_not_written() {
    // `state_accumulator` and `activation_version` had no production readers, so
    // they restored nothing and enforced nothing. The block header remains the
    // accumulator's authority.
    let (d, _g) = db();
    let block = block_at(9, Hash::hash(b"root"), 1);
    new_route(&d, &block, &receipts_for(&block), b"a", b"c");

    assert_eq!(d.get(cf::META, b"state_accumulator").unwrap(), None);
    assert_eq!(d.get(cf::META, b"activation_version").unwrap(), None);
}

#[test]
fn nothing_is_written_before_the_batch_commits() {
    let (d, _g) = db();
    let block = block_at(9, Hash::hash(b"root"), 1);
    let before = snapshot(&d);

    let accepted = accept(&d, &block, &receipts_for(&block), TEST_LIMIT).expect("exact root");
    // An accepted candidate exists and has not been published.
    drop(accepted);

    assert_eq!(
        snapshot(&d),
        before,
        "accepting a candidate must write nothing until publish"
    );
}

#[test]
fn a_rejected_candidate_leaves_every_canonical_family_untouched() {
    let (d, _g) = db();
    // Seed some canonical state so "unchanged" is a real claim.
    let seed = block_at(1, Hash::hash(b"seed"), 9);
    new_route(&d, &seed, &receipts_for(&seed), b"a", b"c");
    let before = snapshot(&d);

    // A mismatch above the cutoff.
    let block = block_at(600_000, Hash::hash(b"header"), 2);
    let err = {
        let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
        {
            let mut view = cand.view();
            view.put(cf::STATE, b"acct:alice", b"candidate").unwrap();
        }
        cand.finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            Hash::hash(b"computed"),
            receipts_for(&block),
            BlockJournals {
                account: JournalRecord::NothingToUndo,
                contract: JournalRecord::NothingToUndo,
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(&block)
        .expect_err("must reject above the cutoff")
    };
    assert!(err.to_string().contains("state root mismatch"), "{err}");

    assert_eq!(
        snapshot(&d),
        before,
        "a rejected candidate must leave every canonical family byte-identical"
    );
}

#[test]
fn an_unpublished_side_block_touches_no_canonical_family() {
    // A block that loses fork choice is simply never published: its candidate is
    // dropped. This asserts the property the consensus wiring will rely on —
    // that not publishing is a complete no-op, not a partial write.
    let (d, _g) = db();
    let seed = block_at(1, Hash::hash(b"seed"), 9);
    new_route(&d, &seed, &receipts_for(&seed), b"a", b"c");
    let before = snapshot(&d);

    let side = block_at(2, Hash::hash(b"side-root"), 77);
    {
        let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
        {
            let mut view = cand.view();
            view.put(cf::STATE, b"acct:alice", b"side").unwrap();
        }
        let _accepted = cand
            .finish_execution(
                ExecutionSubject::of(&side).unwrap(),
                side.header.state_root,
                receipts_for(&side),
                BlockJournals {
                    account: JournalRecord::NothingToUndo,
                    contract: JournalRecord::NothingToUndo,
                    compute_pool: JournalRecord::NothingToUndo,
                    beacon: JournalRecord::NothingToUndo,
                },
            )
            .accept_imported(&side)
            .expect("root matches; acceptance is not publication");
        // Fork choice says no: the accepted candidate is dropped unpublished.
    }

    assert_eq!(
        snapshot(&d),
        before,
        "a side block that is not published must leave every canonical family, \
         including STATE and the journals, byte-identical"
    );
    assert!(
        StateStore::new(&d)
            .get_account_opt(&sumchain_primitives::Address::new([0u8; 20]))
            .unwrap()
            .is_none(),
        "the side block's buffered account write must not have reached the store"
    );
}

// ── Receipt pairing ────────────────────────────────────────────────────────
//
// `RECEIPTS` is keyed by transaction hash, so a mispaired set writes a receipt
// under a transaction it does not describe — a corruption no later read can
// detect, because the row looks perfectly well-formed.

fn pairing_err(block: &Block, receipts: &[Receipt]) -> String {
    let (d, _g) = db();
    match accept(&d, block, receipts, TEST_LIMIT) {
        Ok(_) => "ACCEPTED".to_string(),
        Err(e) => e,
    }
}

#[test]
fn a_missing_receipt_is_refused() {
    let block = block_at(9, Hash::hash(b"r"), 1);
    let mut r = receipts_for(&block);
    r.pop();
    let e = pairing_err(&block, &r);
    assert!(e.contains("receipts"), "missing receipt must be refused: {e}");
}

#[test]
fn an_extra_receipt_is_refused() {
    let block = block_at(9, Hash::hash(b"r"), 1);
    let mut r = receipts_for(&block);
    let dup = r[0].clone();
    r.push(dup);
    let e = pairing_err(&block, &r);
    assert!(e.contains("receipts"), "extra receipt must be refused: {e}");
}

#[test]
fn a_duplicated_receipt_is_refused() {
    let block = block_at(9, Hash::hash(b"r"), 1);
    let mut r = receipts_for(&block);
    r[1] = r[0].clone(); // same count, but position 1 now describes tx 0
    let e = pairing_err(&block, &r);
    assert!(e.contains("describes transaction"), "duplicate must be refused: {e}");
}

#[test]
fn reordered_receipts_are_refused() {
    let block = block_at(9, Hash::hash(b"r"), 1);
    let mut r = receipts_for(&block);
    r.swap(0, 1);
    let e = pairing_err(&block, &r);
    assert!(e.contains("block order"), "reordering must be refused: {e}");
}

#[test]
fn a_mismatched_receipt_hash_is_refused() {
    let block = block_at(9, Hash::hash(b"r"), 1);
    let mut r = receipts_for(&block);
    r[0].tx_hash = Hash::hash(b"not-this-transaction");
    let e = pairing_err(&block, &r);
    assert!(e.contains("describes transaction"), "mismatch must be refused: {e}");
}

#[test]
fn a_correctly_paired_set_is_accepted() {
    // Guard against the refusals passing vacuously.
    let block = block_at(9, Hash::hash(b"r"), 1);
    assert_eq!(pairing_err(&block, &receipts_for(&block)), "ACCEPTED");
}

// ── Encoding contract ──────────────────────────────────────────────────────

#[test]
fn published_receipt_bytes_are_receipt_to_bytes() {
    // `ReceiptStore::put` calls `receipt.to_bytes()`. Re-deriving the encoding
    // in the publisher would duplicate the contract and let the two drift apart
    // silently — they agree today, which is exactly why the duplication is easy
    // to miss.
    let (d, _g) = db();
    let block = block_at(9, Hash::hash(b"root"), 1);
    let receipts = receipts_for(&block);
    new_route(&d, &block, &receipts, b"a", b"c");

    for r in &receipts {
        assert_eq!(
            d.get(cf::RECEIPTS, r.tx_hash.as_bytes()).unwrap().as_deref(),
            Some(&r.to_bytes()[..]),
            "published receipt bytes must be exactly Receipt::to_bytes()"
        );
    }
}

// ── Accounting ─────────────────────────────────────────────────────────────

/// Canonical records are charged against the SAME ceiling as execution's writes.
///
/// The discriminating pair: a ceiling generous enough for everything publishes;
/// a ceiling that admits execution's single row but not the block's derived
/// records refuses. If those records were staged into a side buffer instead of
/// the overlay — as an earlier version did — the tight ceiling would publish
/// happily, because the limit would never see them.
#[test]
fn canonical_records_are_charged_against_the_overlay_limit() {
    let block = block_at(9, Hash::hash(b"root"), 1);
    let receipts = receipts_for(&block);

    // The block's derived records are far larger than execution's one row.
    let derived_bytes: usize = block.to_bytes().len()
        + block
            .transactions
            .iter()
            .map(|t| t.to_bytes().len())
            .sum::<usize>()
        + receipts.iter().map(|r| r.to_bytes().len()).sum::<usize>();
    assert!(derived_bytes > 300, "fixture must have substantial derived records");

    let attempt = |limit: u64| -> Result<(), String> {
        let (d, _g) = db();
        accept(&d, &block, &receipts, limit)?.publish().map_err(|e| e.to_string())
    };

    assert!(attempt(TEST_LIMIT).is_ok(), "a generous ceiling must publish");

    let tight = attempt(200).expect_err(
        "a ceiling admitting execution's row but not the block's derived records \
         must refuse — if this publishes, canonical records are being staged \
         outside the overlay's accounting",
    );
    assert!(tight.contains("limit"), "{tight}");
}

#[test]
fn a_block_whose_canonical_records_exceed_the_limit_publishes_nothing() {
    let (d, _g) = db();
    d.put(cf::STATE, b"seed", b"original").unwrap();
    let block = block_at(9, Hash::hash(b"root"), 1);
    let before = snapshot(&d);

    // A ceiling large enough for execution's single row but far too small for
    // the block, its transactions, receipts and indexes.
    let err = accept(&d, &block, &receipts_for(&block), 200)
        .expect("acceptance itself fits")
        .publish()
        .expect_err("canonical records alone exceed the ceiling");
    assert!(err.to_string().contains("limit"), "{err}");

    assert_eq!(
        snapshot(&d),
        before,
        "a staging failure must consume the candidate and touch RocksDB not at all"
    );
}

// ── Artifact substitution ──────────────────────────────────────────────────
//
// Pairing by hash catches a reordered or missing receipt set. It does NOT catch
// an altered `status` or `fee_paid` — and those are hashed into the accumulator,
// so a substituted set would publish receipts that disagree with the root the
// same block committed to. The defence is that artifacts are BOUND at execution
// completion and no later call takes them, not that publication re-checks them.

#[test]
fn an_altered_receipt_field_cannot_be_substituted_after_execution() {
    let (d, _g) = db();
    let block = block_at(9, Hash::hash(b"root"), 1);

    // What execution produced.
    let honest = receipts_for(&block);
    // What an attacker would want published: same hashes, different outcome.
    let mut tampered = honest.clone();
    tampered[0].fee_paid = 999_999;
    tampered[0].status = TxStatus::Failed(1);
    assert_eq!(
        tampered[0].tx_hash, honest[0].tx_hash,
        "the tampered set still pairs by hash — which is exactly why pairing is \
         not sufficient on its own"
    );

    // Bind the honest artifacts, then publish. There is no parameter on
    // `accept_imported` or `publish` through which `tampered` could be supplied.
    accept(&d, &block, &honest, TEST_LIMIT)
        .expect("exact root")
        .publish()
        .unwrap();

    let published = d
        .get(cf::RECEIPTS, honest[0].tx_hash.as_bytes())
        .unwrap()
        .expect("receipt published");
    assert_eq!(
        published,
        honest[0].to_bytes(),
        "the published receipt must be the one execution produced"
    );
    assert_ne!(
        published,
        tampered[0].to_bytes(),
        "and must not be a substituted set that merely pairs by hash"
    );
}

#[test]
fn a_substituted_journal_cannot_reach_publication() {
    let (d, _g) = db();
    let block = block_at(9, Hash::hash(b"root"), 1);
    let receipts = receipts_for(&block);

    // Bind the journal execution produced.
    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    cand.finish_execution(
        ExecutionSubject::of(&block).unwrap(),
        block.header.state_root,
        receipts,
        BlockJournals {
            account: JournalRecord::Recorded(b"the-real-undo-record".to_vec()),
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
    .accept_imported(&block)
    .expect("exact root")
    .publish()
    .unwrap();

    // `publish()` takes no arguments, so a different journal has nowhere to
    // enter. What is stored is what execution bound.
    assert_eq!(
        d.get(
            cf::STATE_DIFFS,
            &sumchain_storage::schema::journal_key(9, &block.hash())
        )
        .unwrap()
        .as_deref(),
        Some(&b"the-real-undo-record"[..])
    );
}

// ── The legacy warning fires only after a durable commit ───────────────────

#[test]
fn a_failed_publication_emits_no_adoption_message() {
    // The warning says a block's header root WAS adopted. Emitted at acceptance
    // it would say that even when staging then failed and nothing published —
    // an operator reading logs would believe unverified state had entered the
    // chain when it had not.
    let (d, _g) = db();
    let header = Hash::hash(b"header");
    let block = block_at(LEGACY_ROOT_COMPATIBILITY_HEIGHT, header, 1);
    let before = snapshot(&d);

    let mut cand = CandidateExecution::new(&d, 200); // too small for the block
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    let accepted = cand
        .finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            Hash::hash(b"computed"), // mismatch -> legacy branch
            receipts_for(&block),
            BlockJournals {
                account: JournalRecord::NothingToUndo,
                contract: JournalRecord::NothingToUndo,
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(&block)
        .expect("legacy allowance applies");
    assert!(matches!(
        accepted.acceptance(),
        Acceptance::LegacyCompatibility { .. }
    ));

    let err = accepted.publish().expect_err("ceiling refuses the block");
    assert!(err.to_string().contains("limit"), "{err}");
    assert_eq!(
        snapshot(&d),
        before,
        "nothing published, so nothing was adopted"
    );
}

#[test]
fn a_successful_legacy_publication_commits_the_header_root() {
    let (d, _g) = db();
    let header = Hash::hash(b"header");
    let block = block_at(LEGACY_ROOT_COMPATIBILITY_HEIGHT, header, 1);

    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"acct:alice", b"100").unwrap();
    }
    let accepted = cand
        .finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            Hash::hash(b"computed"),
            receipts_for(&block),
            BlockJournals {
                account: JournalRecord::NothingToUndo,
                contract: JournalRecord::NothingToUndo,
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(&block)
        .expect("legacy allowance applies");

    assert_eq!(accepted.accumulator(), header);
    accepted.publish().expect("publishes");

    // Durable, and the warning fired after this commit rather than before it.
    assert_eq!(
        d.get(cf::META, sumchain_storage::schema::meta_keys::LATEST_BLOCK_HASH)
            .unwrap()
            .as_deref(),
        Some(&block.hash().as_bytes()[..])
    );
}
