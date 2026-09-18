//! Admission classification, side-branch archival, and publication ordering.
//!
//! Fork choice is decided BEFORE a block is executed, so a block that loses it
//! never reaches the canonical publisher. What a losing block may leave behind
//! is deliberately narrow, and every exclusion below has a reason: a key without
//! branch identity would let an abandoned block overwrite canonical data.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusEvent, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;
use tokio::sync::broadcast::error::TryRecvError;

const CHAIN_ID: u64 = 1;

struct Node {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    _dir: TempDir,
}

impl Node {
    fn new(genesis: &Genesis, key: [u8; 32]) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
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
        Self { db, state, mempool, consensus, _dir: dir }
    }

    async fn produce(&self) -> Block {
        let txs = self.mempool.select_for_block(100);
        assert!(!txs.is_empty(), "need a non-empty block");
        self.consensus.propose_block(txs).await.expect("propose")
    }

    fn rows(&self, family: &str) -> usize {
        self.db.iter(family).map(|it| it.count()).unwrap_or(0)
    }

    fn head_hash(&self) -> Option<Vec<u8>> {
        self.db
            .get(cf::META, b"latest_block_hash")
            .unwrap()
            .map(|v| v.to_vec())
    }
}

fn transfer(from: &KeyPair, to: Address, amount: u128, fee: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, fee, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

struct Fixture {
    genesis: Genesis,
    key: [u8; 32],
    alice: KeyPair,
    bob: KeyPair,
}

fn fixture() -> Fixture {
    let validator = KeyPair::generate();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (validator.address().to_base58(), 100_000_000u128),
            (alice.address().to_base58(), 10_000_000u128),
            (bob.address().to_base58(), 10_000_000u128),
        ]),
        ChainParams::default(),
    );
    Fixture { genesis, key: *validator.private_key().as_bytes(), alice, bob }
}

/// Build two sibling blocks at height 1 on independent nodes, and return them
/// ordered so that `(winner, loser)` matches what fork choice will decide.
///
/// `LongestChainForkChoice::should_switch` at equal height is
/// `candidate.hash() < head.hash()`, so the lower hash wins.
async fn siblings(f: &Fixture) -> (Block, Block) {
    let a = Node::new(&f.genesis, f.key);
    let b = Node::new(&f.genesis, f.key);
    a.mempool
        .add(transfer(&f.alice, f.bob.address(), 1_000, 10, 0))
        .unwrap();
    b.mempool
        .add(transfer(&f.bob, f.alice.address(), 2_000, 20, 0))
        .unwrap();
    let ba = a.produce().await;
    let bb = b.produce().await;
    assert_ne!(ba.hash(), bb.hash(), "siblings must differ");
    if bb.hash() < ba.hash() {
        (bb, ba)
    } else {
        (ba, bb)
    }
}

// ── Admission classification ───────────────────────────────────────────────

#[tokio::test]
async fn a_block_extending_the_head_is_admitted_and_published() {
    let f = fixture();
    let producer = Node::new(&f.genesis, f.key);
    producer
        .mempool
        .add(transfer(&f.alice, f.bob.address(), 1_000, 10, 0))
        .unwrap();
    let block = producer.produce().await;

    let importer = Node::new(&f.genesis, f.key);
    importer.consensus.import_block(block.clone()).await.expect("import");

    assert_eq!(
        importer.head_hash().as_deref(),
        Some(&block.hash().as_bytes()[..]),
        "a direct extension must become the canonical head"
    );
    assert_eq!(
        importer
            .db
            .get(cf::BLOCK_HEIGHT, &1u64.to_be_bytes())
            .unwrap()
            .as_deref(),
        Some(&block.hash().as_bytes()[..]),
        "and must publish the height index"
    );
}

#[tokio::test]
async fn a_block_losing_fork_choice_is_not_published() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus.import_block(winner.clone()).await.expect("winner imports");

    let head_before = node.head_hash();
    let diffs_before = node.rows(cf::STATE_DIFFS);
    let receipts_before = node.rows(cf::RECEIPTS);
    let by_sender_before = node.rows(cf::TX_BY_SENDER);
    let by_recipient_before = node.rows(cf::TX_BY_RECIPIENT);
    let height_index_before = node
        .db
        .get(cf::BLOCK_HEIGHT, &1u64.to_be_bytes())
        .unwrap()
        .map(|v| v.to_vec());

    // The loser has a higher hash, so fork choice declines it.
    node.consensus.import_block(loser.clone()).await.expect("loser is accepted but not published");

    assert_eq!(node.head_hash(), head_before, "head must not move");
    assert_eq!(
        node.db
            .get(cf::BLOCK_HEIGHT, &1u64.to_be_bytes())
            .unwrap()
            .map(|v| v.to_vec()),
        height_index_before,
        "BLOCK_HEIGHT is keyed by height alone and must not be repointed"
    );
    assert_eq!(node.rows(cf::STATE_DIFFS), diffs_before, "no journal");
    assert_eq!(node.rows(cf::RECEIPTS), receipts_before, "no receipts");
    assert_eq!(node.rows(cf::TX_BY_SENDER), by_sender_before, "no sender index");
    assert_eq!(
        node.rows(cf::TX_BY_RECIPIENT),
        by_recipient_before,
        "no recipient index"
    );
}

// ── Archival: only branch-safe rows ────────────────────────────────────────

#[tokio::test]
async fn a_losing_block_is_archived_by_hash_only() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus.import_block(winner).await.expect("winner");
    node.consensus.import_block(loser.clone()).await.expect("loser");

    // Keyed by its own hash: retrievable, and unable to collide.
    assert_eq!(
        node.db
            .get(cf::BLOCKS, loser.hash().as_bytes())
            .unwrap()
            .as_deref(),
        Some(&loser.to_bytes()[..]),
        "the losing block itself is archived"
    );
    // Its transactions likewise, keyed by transaction hash.
    for tx in &loser.transactions {
        assert!(
            node.db
                .get(cf::TRANSACTIONS, tx.hash().as_bytes())
                .unwrap()
                .is_some(),
            "the losing block's transactions are archived"
        );
    }
}

// ── Publication precedes memory and events ─────────────────────────────────

#[tokio::test]
async fn a_refused_import_updates_neither_memory_nor_events() {
    let f = fixture();
    let producer = Node::new(&f.genesis, f.key);
    producer
        .mempool
        .add(transfer(&f.alice, f.bob.address(), 1_000, 10, 0))
        .unwrap();
    let mut block = producer.produce().await;

    // Corrupt the declared root, above the compatibility cutoff, so acceptance
    // refuses it. Height 1 is below the cutoff, so raise it out of the window.
    block.header.height = 600_001;
    block.header.state_root = Hash::hash(b"not-the-computed-root");

    let importer = Node::new(&f.genesis, f.key);
    let mut events = importer.consensus.subscribe();
    let head_before = importer.head_hash();
    let root_before = importer.state.state_root();

    let _ = importer.consensus.import_block(block).await;

    assert_eq!(importer.head_hash(), head_before, "head unchanged");
    assert_eq!(
        importer.state.state_root(),
        root_before,
        "the in-memory accumulator must not move for a block that did not publish"
    );
    assert!(
        matches!(events.try_recv(), Err(TryRecvError::Empty)),
        "a block that did not publish must not be announced"
    );
}

#[tokio::test]
async fn a_published_block_updates_memory_and_announces() {
    let f = fixture();
    let producer = Node::new(&f.genesis, f.key);
    producer
        .mempool
        .add(transfer(&f.alice, f.bob.address(), 1_000, 10, 0))
        .unwrap();
    let block = producer.produce().await;

    let importer = Node::new(&f.genesis, f.key);
    let mut events = importer.consensus.subscribe();
    importer.consensus.import_block(block.clone()).await.expect("import");

    // Durable first, then memory, then the event — all three present here.
    assert_eq!(
        importer.head_hash().as_deref(),
        Some(&block.hash().as_bytes()[..])
    );
    assert_eq!(importer.state.state_root(), block.header.state_root);
    assert!(
        matches!(events.try_recv(), Ok(ConsensusEvent::BlockImported(b)) if b.hash() == block.hash()),
        "a published block is announced"
    );
}

/// A collision during archival must leave NOTHING written.
///
/// `TRANSACTIONS` is keyed by transaction hash, so differing bytes under the
/// same key cannot arise naturally — it would mean a hash collision or an
/// encoding change. The row is corrupted deliberately here, because the property
/// being tested is what archival does when it finds one: refuse, and write
/// nothing at all. A partial archive is not a smaller archive, it is a store
/// whose contents nothing describes.
#[tokio::test]
async fn an_archival_collision_writes_nothing() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus.import_block(winner).await.expect("winner");

    // Corrupt the stored bytes for one of the loser's transactions.
    let victim = loser.transactions[0].hash();
    node.db
        .put(cf::TRANSACTIONS, victim.as_bytes(), b"different-bytes")
        .unwrap();

    let blocks_before = node.rows(cf::BLOCKS);
    let txs_before = node.rows(cf::TRANSACTIONS);

    let err = node
        .consensus
        .import_block(loser.clone())
        .await
        .expect_err("a collision must refuse the archival");
    assert!(
        err.to_string().contains("already stored with different bytes"),
        "{err}"
    );

    assert_eq!(
        node.rows(cf::BLOCKS),
        blocks_before,
        "the losing block must NOT be archived when one of its transactions collides"
    );
    assert_eq!(
        node.rows(cf::TRANSACTIONS),
        txs_before,
        "and no transaction may be archived either"
    );
    assert_eq!(
        node.db
            .get(cf::TRANSACTIONS, victim.as_bytes())
            .unwrap()
            .as_deref(),
        Some(&b"different-bytes"[..]),
        "the pre-existing row must be left exactly as it was"
    );
}

/// A corrupted block row makes import SKIP the block entirely — a pre-existing
/// gap this archival change does not close.
///
/// `do_import_block` dedups with `BlockStore::contains`, which asks only whether
/// a key is present. Any bytes under a block's hash therefore satisfy it, so a
/// corrupted or planted row causes the real block to be treated as already
/// imported and silently skipped. The archival preflight never runs, because the
/// function returns before reaching it.
///
/// The block-row preflight in `archive_noncanonical` is correct and stays —
/// `BLOCKS` is content-addressed like `TRANSACTIONS`, and a future caller could
/// reach it another way — but through `import_block` it is unreachable, and a
/// test claiming otherwise would be asserting a guarantee the dedup check
/// prevents from ever being exercised.
///
/// Fixing the dedup to compare bytes rather than presence is its own change: it
/// would turn a silent skip into an error on every node holding a corrupt row,
/// which is a behaviour change needing its own decision.
#[tokio::test]
async fn a_corrupted_block_row_causes_import_to_skip_rather_than_refuse() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus.import_block(winner).await.expect("winner");

    node.db
        .put(cf::BLOCKS, loser.hash().as_bytes(), b"not-this-block")
        .unwrap();
    let txs_before = node.rows(cf::TRANSACTIONS);

    // Not an error: the presence check short-circuits.
    node.consensus
        .import_block(loser.clone())
        .await
        .expect("dedup treats any bytes under the hash as the block itself");

    assert_eq!(
        node.db
            .get(cf::BLOCKS, loser.hash().as_bytes())
            .unwrap()
            .as_deref(),
        Some(&b"not-this-block"[..]),
        "the corrupt row survives untouched — the block was skipped, not archived"
    );
    assert_eq!(
        node.rows(cf::TRANSACTIONS),
        txs_before,
        "and nothing from the skipped block was written"
    );
}

/// Re-archiving the same losing block is a no-op, not a refusal.
///
/// Pass 2 writes every row rather than only the missing ones — that is what lets
/// pass 1 retain nothing — so the second attempt overwrites byte-identical
/// content-addressed rows, which is safe by construction.
#[tokio::test]
async fn archiving_the_same_block_twice_is_idempotent() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus.import_block(winner).await.expect("winner");
    node.consensus.import_block(loser.clone()).await.expect("first archive");

    let blocks = node.rows(cf::BLOCKS);
    let txs = node.rows(cf::TRANSACTIONS);

    node.consensus
        .import_block(loser.clone())
        .await
        .expect("re-archiving byte-identical rows is safe");

    assert_eq!(node.rows(cf::BLOCKS), blocks, "no new block rows");
    assert_eq!(node.rows(cf::TRANSACTIONS), txs, "no new transaction rows");
    assert_eq!(
        node.db
            .get(cf::BLOCKS, loser.hash().as_bytes())
            .unwrap()
            .as_deref(),
        Some(&loser.to_bytes()[..]),
        "and the content is unchanged"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Archival touches two families, and the canonical height index is not one.
//
// `a_block_losing_fork_choice_is_not_published` pins `BLOCK_HEIGHT[1]` at the
// winner, which is the specific row the old bug repointed. That is one row at
// one height, and the guarantee is wider: a block that lost fork choice must
// leave NOTHING outside the two content-addressed families, because every other
// family in this schema is keyed without branch identity and an abandoned
// block's row there shadows the canonical one.
// ─────────────────────────────────────────────────────────────────────────────

/// Every row of every family.
fn whole_db(db: &Database) -> std::collections::BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    for family in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.iter(family).expect("iterate") {
            out.insert((family.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

/// Archiving a losing block writes `BLOCKS` and `TRANSACTIONS` and nothing else
/// — the canonical height index included.
#[tokio::test]
async fn archival_writes_only_the_branch_safe_families_and_never_the_height_index() {
    let f = fixture();
    let (winner, loser) = siblings(&f).await;

    let node = Node::new(&f.genesis, f.key);
    node.consensus
        .import_block(winner.clone())
        .await
        .expect("winner");

    // The canonical database, immediately before a losing sibling arrives.
    let before = whole_db(&node.db);
    let height_index_before: std::collections::BTreeMap<_, _> = before
        .iter()
        .filter(|((family, _), _)| family == cf::BLOCK_HEIGHT)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert!(
        !height_index_before.is_empty(),
        "the fixture must have a canonical height index to protect"
    );

    node.consensus
        .import_block(loser.clone())
        .await
        .expect("loser");
    let after = whole_db(&node.db);

    // What changed, as (family, key) pairs — additions and modifications alike.
    let changed: std::collections::BTreeSet<&String> = after
        .iter()
        .filter(|(k, v)| before.get(*k) != Some(*v))
        .map(|((family, _), _)| family)
        .collect();
    let removed: std::collections::BTreeSet<&String> = before
        .keys()
        .filter(|k| !after.contains_key(*k))
        .map(|(family, _)| family)
        .collect();

    assert!(
        removed.is_empty(),
        "archiving a side branch must delete nothing: {removed:?}"
    );
    let allowed: std::collections::BTreeSet<String> =
        [cf::BLOCKS.to_string(), cf::TRANSACTIONS.to_string()]
            .into_iter()
            .collect();
    let disallowed: Vec<&&String> = changed.iter().filter(|c| !allowed.contains(**c)).collect();
    assert!(
        disallowed.is_empty(),
        "a block that lost fork choice wrote outside the two content-addressed \
         families: {disallowed:?}. Every other family in this schema is keyed \
         without branch identity, so a side branch's row there shadows the \
         canonical one — BLOCK_HEIGHT points the chain at a block nobody adopted, \
         RECEIPTS overwrites a canonical receipt for the same transaction hash, and \
         the address indexes are keyed by (address, height, tx_index) with no \
         branch in the key at all"
    );
    assert!(
        changed.contains(&cf::BLOCKS.to_string()),
        "the losing block must actually have been archived, or this proves nothing"
    );

    // Said again directly, because it is the row the old bug moved.
    let height_index_after: std::collections::BTreeMap<_, _> = after
        .iter()
        .filter(|((family, _), _)| family == cf::BLOCK_HEIGHT)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    assert_eq!(
        height_index_after, height_index_before,
        "archive_noncanonical must never touch the canonical height index"
    );
    assert_ne!(winner.hash(), loser.hash(), "the siblings must differ");
}
