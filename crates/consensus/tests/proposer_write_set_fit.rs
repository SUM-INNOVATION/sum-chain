//! A proposer must not sign a block that execution would then reject, AND must
//! still produce one.
//!
//! # The half that was already right, and the half that was not
//!
//! `PoAEngine::create_block` has always executed a block before signing it:
//! `execute_block` runs, and only then is `sign(...)` reached. So a proposer
//! never signed a block that its own execution refused. That much was never the
//! gap.
//!
//! The gap is what happened INSTEAD of a block. `create_block` returned the
//! error, `run_block_producer` logged "Failed to create block", and — this is
//! the part that turns a slot into a halt — `mempool.remove_batch` is only
//! reached on the success path, while `Mempool::select_for_block` is
//! non-destructive and ordered by FEE. So the transaction that made the block
//! unexecutable stayed in the mempool, sorted to the front, and was selected
//! first on the next tick, and the tick after that. One transaction, for one
//! `min_fee`, stopped that validator producing blocks for good.
//!
//! What this file asserts is the remedy: the crossing transaction is identified
//! by index, dropped from the proposal, and the proposal is retried — so a
//! block is produced out of the transactions that do fit.
//!
//! Whether the dropped transaction is also EVICTED from the mempool depends on
//! which of two things happened, and the distinction is the difference between
//! ending the halt and ending it by destroying honest traffic:
//!
//!   * it crossed at an index ABOVE ZERO, meaning the transactions ahead of it
//!     had spent the budget. It did nothing an emptier block would refuse, and
//!     `select_for_block` is fee-ordered, so leaving it in the mempool puts it
//!     EARLIER in the next selection — which is exactly where it fits. Nothing
//!     is evicted, and the test below proves the next block carries it.
//!   * it crossed at index ZERO, or it alone left no room to publish. No
//!     emptier block exists, so no block can carry it. That one is evicted —
//!     not to end a halt in block production, which nothing here threatens, but
//!     to end the starvation of every smaller transaction behind it in the fee
//!     order.
//!
//! # And why the per-transaction bound does not subsume this
//!
//! `MAX_TX_WRITE_SET_BYTES x max_txs_per_block` is two orders of magnitude past
//! `MAX_BLOCK_WRITE_SET_BYTES`, deliberately — the per-transaction bound has to
//! admit the largest honest transaction, and a thousand of those do not have to
//! fit in one block. So a block every one of whose transactions is inside its
//! own bound can still cross the block's, and only the proposer can decide
//! which of them not to include. The two mechanisms compose; neither replaces
//! the other, and the last test here runs them together.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Address, DocClassOperation, DocClassTxData, DocSubcode, IdentityKey, IdentityRoot,
    IdentityStatus, KeyPurpose, KeyType, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager, TX_WRITE_SET_BOUND_RECEIPT_CODE};
use sumchain_storage::{cf, Database, DocClassStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

/// Rows of this size, rewritten one per transaction, cross
/// `MAX_BLOCK_WRITE_SET_BYTES` in a few hundred transactions — the same shape
/// `crates/state/tests/block_write_set_ceiling.rs` uses to cross a 256 MiB
/// ceiling inside a few hundred megabytes of resident memory rather than the
/// gigabyte one row at the ceiling would need.
const ROW_BYTES: usize = 1 << 20;

/// A row whose single rewrite crosses `MAX_TX_WRITE_SET_BYTES`, for the
/// composed test at the end.
const OVERSIZED_ROW: usize = 9 << 20;

/// A row whose single rewrite executes inside `MAX_BLOCK_WRITE_SET_BYTES` and
/// then leaves no room to PUBLISH beneath it.
///
/// The publication budget is `MAX_BLOCK_WRITE_SET_BYTES /
/// PROPOSAL_EXECUTION_SHARE_DIVISOR` = 128 MiB, and a rewrite charges twice the
/// row (the new value and the captured pre-image), so 68 MiB charges about
/// 136 MiB: over the publication budget, comfortably under the 256 MiB
/// execution ceiling. Sized from that arithmetic rather than picked, so that a
/// change to either constant fails this loudly instead of quietly making the
/// test measure nothing.
const UNPUBLISHABLE_ROW: usize = 68 << 20;

fn params(tx_bound_from: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p.subsystem_tx_write_set_bound_enabled_from_height = tx_bound_from;
    // Opening any remediation gate obliges the operator to set the peer
    // protocol declaration deadline at or below it — `Genesis::validate`
    // refuses otherwise, because above an open gate a peer that declares no
    // protocol digest is indistinguishable from one running the unremediated
    // binary. The fixture has to satisfy that, and the fact that it DOES have
    // to is itself evidence the new gate is properly enrolled in
    // `REMEDIATION_GATES`.
    if tx_bound_from.is_some() {
        p.peer_protocol_declaration_required_from_height = Some(0);
    }
    p
}

struct Node {
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    _dir: TempDir,
}

impl Node {
    fn new(genesis: &Genesis, key: [u8; 32]) -> Self {
        Self::with_mempool(genesis, key, MempoolConfig::default())
    }

    /// `max_per_sender` defaults to 100, and the eviction fixture needs every
    /// one of its transactions actually IN the mempool — otherwise "the
    /// offender was evicted" and "the offender was never admitted" look the
    /// same from outside.
    fn with_mempool(genesis: &Genesis, key: [u8; 32], config: MempoolConfig) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(config));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                genesis,
                Some(KeyPair::from_bytes(key)),
            )
            .expect("engine"),
        );
        consensus.init_genesis(genesis).expect("init genesis");
        Self {
            db,
            mempool,
            consensus,
            _dir: dir,
        }
    }
}

fn key_with_id(id: String) -> IdentityKey {
    IdentityKey {
        key_id: id,
        key_type: KeyType::Ed25519,
        public_key: [7u8; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn ident(n: usize) -> [u8; 32] {
    let mut id = [0xE0u8; 32];
    id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

fn seed_row(db: &Database, n: usize, controller: Address, bytes: usize) {
    let root = IdentityRoot {
        identity_id: ident(n),
        subject_commitment: [0x40; 32],
        controller,
        additional_controllers: vec![],
        keys: vec![key_with_id("x".repeat(bytes))],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    };
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

fn add_key_tx(kp: &KeyPair, nonce: u64, n: usize, fee: u128) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation: DocClassOperation::AddKey,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(&AddKeyData {
                identity_id: ident(n),
                key: key_with_id(format!("k{n}")),
            })
            .unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

struct Fixture {
    genesis: Genesis,
    key: [u8; 32],
    actor: KeyPair,
}

fn fixture(tx_bound_from: Option<u64>) -> Fixture {
    let validator = KeyPair::generate();
    let actor = KeyPair::generate();
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (validator.address().to_base58(), 100_000_000u128),
            (actor.address().to_base58(), 1_000_000_000_000u128),
        ]),
        params(tx_bound_from),
    );
    Fixture {
        genesis,
        key: *validator.private_key().as_bytes(),
        actor,
    }
}

/// How many rewrites of `ROW_BYTES` rows it takes to cross the block ceiling,
/// with margin so the test does not depend on the per-row constant factor.
fn rows_past_the_block_ceiling() -> usize {
    (sumchain_state::MAX_BLOCK_WRITE_SET_BYTES as usize / ROW_BYTES) + 16
}

// ── 1. The proposer produces a block instead of nothing ─────────────────────

/// A set of transactions that together cross the block ceiling yields a BLOCK,
/// not an error.
///
/// Signed, published, and strictly shorter than what was handed in. The
/// alternative — the behaviour before the fitting loop — is no block at all,
/// and no block at all is how one cheap transaction halts a validator.
#[tokio::test]
async fn a_proposal_past_the_block_ceiling_yields_a_shorter_block_rather_than_no_block() {
    let f = fixture(None);
    let node = Node::new(&f.genesis, f.key);
    let rows = rows_past_the_block_ceiling();
    for n in 0..rows {
        seed_row(&node.db, n, f.actor.address(), ROW_BYTES);
    }
    let txs: Vec<SignedTransaction> = (0..rows)
        .map(|n| add_key_tx(&f.actor, n as u64, n, 1_000))
        .collect();

    let block = node.consensus.propose_block(txs.clone()).await.expect(
        "a proposal whose transactions together cross the block ceiling must \
             still produce a block out of the ones that fit. An Err here is the \
             permanent halt this file is about: no block is produced, the \
             mempool is not cleared, and the next tick selects the same \
             transactions again",
    );

    println!(
        "PROPOSER: {rows} transactions handed in, {} included, block {} at height {}",
        block.tx_count(),
        block.hash(),
        block.height()
    );
    assert!(
        block.tx_count() < rows,
        "the block must be SHORTER than the proposal: the whole point is that \
         the transactions which do not fit are left out"
    );
    assert!(
        block.tx_count() > 0,
        "and it must not be empty: the transactions before the crossing point \
         executed, so they fit"
    );
    assert_ne!(
        block.header.proposer_sig, [0u8; 64],
        "the block that is produced is SIGNED — the half that was always right, \
         asserted so a refactor cannot lose it while keeping the fitting loop"
    );
    assert!(
        node.db
            .get(cf::BLOCKS, block.hash().as_bytes())
            .unwrap()
            .is_some(),
        "and published"
    );
}

// ── 2. The offender is quarantined, not destroyed ───────────────────────────

/// A transaction that crosses the ceiling BECAUSE OF THE PREFIX is not evicted.
///
/// This assertion is the inverse of the one that stood here before, and the
/// inversion is the point. The transaction at index k crossed
/// `MAX_BLOCK_WRITE_SET_BYTES` because the k transactions ahead of it had
/// already spent the budget — it did nothing a smaller block would refuse, and
/// at the head of an emptier block it fits. Evicting it ends the halt by
/// destroying a transaction whose only fault is the company it was selected
/// with, which is the second half of the property this whole track is about:
/// "a temporarily ineligible transaction is not incorrectly destroyed".
///
/// The halt argument that justified eviction does not apply to this class.
/// `select_for_block` is fee-ordered, so a transaction left in the mempool is
/// selected EARLIER next time, not later — and earlier is exactly where it
/// fits. The test proves that rather than asserting it: the second proposal
/// carries the transaction the first one shed.
///
/// The transaction that IS evicted for crossing the ceiling is the one at index
/// ZERO, where no emptier block exists. That case has its own test below.
#[tokio::test]
async fn a_transaction_that_only_overflows_a_full_block_stays_eligible_for_the_next_one() {
    let f = fixture(None);
    let deep = MempoolConfig {
        max_per_sender: 10_000,
        ..MempoolConfig::default()
    };
    let node = Node::with_mempool(&f.genesis, f.key, deep);
    let rows = rows_past_the_block_ceiling();
    for n in 0..rows {
        seed_row(&node.db, n, f.actor.address(), ROW_BYTES);
    }
    // A high fee on every transaction, so the shed ones are at the front of the
    // next fee-ordered selection — which is where they fit.
    let txs: Vec<SignedTransaction> = (0..rows)
        .map(|n| add_key_tx(&f.actor, n as u64, n, 1_000_000))
        .collect();
    for tx in &txs {
        node.mempool.add(tx.clone()).expect("admitted");
    }
    assert_eq!(
        node.mempool.len(),
        rows,
        "every transaction must be IN the mempool, or 'evicted' and 'never \
         admitted' are indistinguishable from outside"
    );

    let block = node
        .consensus
        .propose_block(txs.clone())
        .await
        .expect("a block is produced");

    let included: std::collections::HashSet<_> =
        block.transactions.iter().map(|t| t.hash()).collect();
    let pending: std::collections::HashSet<_> = node
        .mempool
        .get_all()
        .into_iter()
        .map(|t| t.hash())
        .collect();
    let destroyed: Vec<usize> = (0..rows)
        .filter(|&n| !included.contains(&txs[n].hash()) && !pending.contains(&txs[n].hash()))
        .collect();

    println!(
        "QUARANTINE: {rows} in the mempool, {} included, {} still pending, \
         destroyed {destroyed:?}",
        block.tx_count(),
        pending.len()
    );

    assert!(
        destroyed.is_empty(),
        "NOTHING may be destroyed. Every transaction the proposal shed — the \
         one that crossed the ceiling and the ones truncated behind it alike — \
         did so because of the block it was selected into, not because of \
         anything it contains. Evicting any of them throws away honest traffic"
    );
    assert_eq!(
        included.len() + pending.len(),
        rows,
        "every transaction is accounted for: carried, or still waiting"
    );
    assert!(
        block.tx_count() > 0 && block.tx_count() < rows,
        "and it fit"
    );

    // The proof that quarantine is enough: the transaction the first block shed
    // is carried by the second. Handed over in NONCE order, which is what the
    // sender's own sequence requires and what a fee-ordered selection of
    // equal-fee transactions does not guarantee.
    let consumed = block.tx_count();
    let shed = txs[consumed].hash();
    assert!(
        pending.contains(&shed),
        "the crossing transaction is waiting"
    );
    let second = node
        .consensus
        .propose_block(txs[consumed..].to_vec())
        .await
        .expect("second proposal");
    println!(
        "CARRIED LATER: height {} carried {} transactions, including the one \
         height {} could not fit",
        second.height(),
        second.tx_count(),
        block.height()
    );
    assert!(
        second.transactions.iter().any(|t| t.hash() == shed),
        "and the next block CARRIES it. This is what makes quarantine the right \
         answer rather than eviction: the transaction was never at fault, and \
         at the head of an emptier block it fits"
    );
}

/// The one crossing that IS permanent: the FIRST transaction in the proposal.
///
/// Nothing preceded it, so no emptier block exists. A transaction that cannot
/// be carried by an empty block cannot be carried at all, and leaving it costs
/// more than a slot: it sits at the top of the fee order and empties every
/// future block while the smaller transactions behind it never confirm.
///
/// Reached here through the PUBLICATION headroom rather than the execution
/// ceiling, because that budget is half the size and so the fixture is half the
/// size: one rewrite charging about `2 x UNPUBLISHABLE_ROW` executes inside
/// `MAX_BLOCK_WRITE_SET_BYTES` and then leaves nothing underneath it to publish
/// with. Same verdict, same code path for the eviction.
#[tokio::test]
async fn a_transaction_no_block_could_ever_publish_is_evicted() {
    let f = fixture(None);
    let node = Node::new(&f.genesis, f.key);
    seed_row(&node.db, 0, f.actor.address(), UNPUBLISHABLE_ROW);

    let poison = add_key_tx(&f.actor, 0, 0, 1_000_000);
    node.mempool.add(poison.clone()).expect("admitted");

    let block = node
        .consensus
        .propose_block(vec![poison.clone()])
        .await
        .expect(
            "a block is still produced — an empty one, because the only \
             transaction offered could not be published",
        );
    println!(
        "UNPUBLISHABLE: block {} at height {} carried {} tx; still pending: {}",
        block.hash(),
        block.height(),
        block.tx_count(),
        node.mempool.contains(&poison.hash())
    );
    assert_eq!(block.tx_count(), 0, "it could not be carried");
    assert!(
        !node.mempool.contains(&poison.hash()),
        "and it must be EVICTED. Left in the mempool at this fee it is selected \
         first on every subsequent tick, and every one of those blocks comes \
         out empty: the chain advances while no transaction ever confirms, \
         which is the starvation half of the halt"
    );
}

// ── 3. The next slot is not poisoned ────────────────────────────────────────

/// Two proposals in a row both succeed.
///
/// This is the property the whole fitting loop exists for, and it is the one
/// that distinguishes a slot that is lost from a validator that is stopped. A
/// proposer that produced one block and then failed forever would pass the
/// first test in this file and still be halted.
#[tokio::test]
async fn a_second_proposal_after_a_crossing_still_produces_a_block() {
    let f = fixture(None);
    let node = Node::new(&f.genesis, f.key);
    let rows = rows_past_the_block_ceiling();
    for n in 0..rows {
        seed_row(&node.db, n, f.actor.address(), ROW_BYTES);
    }
    let txs: Vec<SignedTransaction> = (0..rows)
        .map(|n| add_key_tx(&f.actor, n as u64, n, 1_000))
        .collect();

    let first = node
        .consensus
        .propose_block(txs.clone())
        .await
        .expect("first proposal");
    let consumed = first.tx_count();

    // The remainder, at the nonces the first block left the sender on.
    let rest: Vec<SignedTransaction> = txs[consumed..].to_vec();
    let second = node.consensus.propose_block(rest).await.expect(
        "the slot after a crossing must also produce a block. A proposer \
             that produces one block and then fails forever is still halted, \
             and would pass every other test in this file",
    );

    println!(
        "LIVENESS: height {} carried {consumed} transactions, height {} carried {}",
        first.height(),
        second.height(),
        second.tx_count()
    );
    assert_eq!(second.height(), first.height() + 1, "the chain advanced");
    assert!(second.tx_count() > 0, "and carried work");
}

// ── 4. The two mechanisms composed ──────────────────────────────────────────

/// With the per-transaction gate OPEN, a single oversized rewrite does not even
/// reach the fitting loop: it is a failed receipt inside a block the proposer
/// signs normally.
///
/// The two rules do different jobs and this shows both doing theirs. The
/// per-transaction bound attributes the refusal to the transaction that earned
/// it, so the block is built, signed and published with a `Failed(400)` receipt
/// in it and the sender charged. The fitting loop never runs, because there is
/// nothing left for it to do.
#[tokio::test]
async fn with_the_per_transaction_gate_open_an_oversized_rewrite_is_a_failed_receipt() {
    let f = fixture(Some(0));
    let node = Node::new(&f.genesis, f.key);
    seed_row(&node.db, 0, f.actor.address(), OVERSIZED_ROW);
    seed_row(&node.db, 1, f.actor.address(), ROW_BYTES);

    let txs = vec![
        add_key_tx(&f.actor, 0, 0, 1_000),
        add_key_tx(&f.actor, 1, 1, 1_000),
    ];
    let block = node
        .consensus
        .propose_block(txs.clone())
        .await
        .expect("the block is produced normally");

    assert_eq!(
        block.tx_count(),
        2,
        "BOTH transactions are included: the oversized one is not dropped from \
         the block, it is executed and fails. Dropping it would be the fitting \
         loop doing a job the per-transaction bound has already done, and would \
         cost the sender nothing"
    );

    let receipts = ReceiptStore::new(&node.db);
    let refused = receipts
        .get(&txs[0].hash())
        .expect("read receipt")
        .expect("the refused transaction has a receipt");
    let ordinary = receipts
        .get(&txs[1].hash())
        .expect("read receipt")
        .expect("the ordinary transaction has a receipt");
    println!(
        "COMPOSED: oversized rewrite -> {:?} fee {}, ordinary rewrite -> {:?} fee {}",
        refused.status, refused.fee_paid, ordinary.status, ordinary.fee_paid
    );
    assert_eq!(
        refused.status,
        TxStatus::Failed(TX_WRITE_SET_BOUND_RECEIPT_CODE)
    );
    assert_eq!(refused.fee_paid, 1_000, "and it paid");
    assert_eq!(ordinary.status, TxStatus::Success);
}
