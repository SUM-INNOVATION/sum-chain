//! Local-depth finality is persisted atomically on the live path (#350).
//!
//! `PoAEngine::check_finality` writes the finality record, height and hash
//! together in one batch, before memory or events move; `load_chain` restores
//! it only when it is whole and names the canonical block at its height. On
//! real on-disk databases, through block production, block import, restart
//! and the operator rollback:
//!
//! * the record is one pair, and a normal restart restores it unchanged;
//! * a failed finality write fail-stops the engine, on production and on
//!   import, and the in-memory finalized height stays at the record;
//! * a restart over a record that cannot be read, is half present, is above
//!   the head or names another block refuses, and changes nothing;
//! * a restart with no record at all starts with nothing finalized, as before,
//!   and the next block derives finality again;
//! * a rollback below the record moves it as a pair; above it, leaves it;
//! * a catch-up over many heights writes the record once, for the highest
//!   height with a canonical block, then announces each height in order, and
//!   a failed write announces nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sumchain_consensus::branch_switch::failpoints::{arm, Failpoint};
use sumchain_consensus::reorg::{execute_rollback, plan_rollback};
use sumchain_consensus::{ConsensusEngine, ConsensusEvent, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Block, Hash};
use sumchain_state::reorg_undo::ActivatedJournal;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::journal::ActivationSource;
use sumchain_storage::schema::meta_keys;
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;
use tokio::sync::broadcast::{self, error::TryRecvError};

const CHAIN_ID: u64 = 1;
/// Small, so a handful of blocks finalizes some.
const DEPTH: u64 = 2;

fn validator() -> KeyPair {
    KeyPair::from_bytes([5u8; 32])
}

fn genesis() -> Genesis {
    let params = ChainParams {
        finality_depth: DEPTH,
        application_journal_enabled_from_height: Some(1),
        ..ChainParams::default()
    };
    Genesis::new(
        CHAIN_ID,
        0,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        params,
    )
}

/// A real engine on a real on-disk database, which can be closed and opened
/// again on the same directory.
struct Node {
    dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    engine: PoAEngine,
}

impl Node {
    /// A fresh directory with the genesis block. `validating` gives the engine
    /// the single validator's key, so it can produce.
    fn new(validating: bool) -> Self {
        let n = Self::open(TempDir::new().unwrap(), validating);
        n.engine.init_genesis(&genesis()).unwrap();
        n
    }

    /// An engine over `dir`, with nothing loaded yet.
    fn open(dir: TempDir, validating: bool) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            &genesis(),
            validating.then(validator),
        )
        .unwrap();
        Self {
            dir,
            db,
            state,
            engine,
        }
    }

    /// Close every handle, keeping the directory.
    fn close(self) -> TempDir {
        let Node {
            dir,
            db,
            state,
            engine,
        } = self;
        drop(engine);
        drop(state);
        assert_eq!(Arc::strong_count(&db), 1, "every handle must be closed");
        drop(db);
        dir
    }

    /// Close and open again, then load the chain the way a start does.
    fn restart(self, validating: bool) -> (Self, sumchain_consensus::Result<Option<Block>>) {
        let n = Self::open(self.close(), validating);
        let loaded = n.engine.load_chain();
        (n, loaded)
    }

    async fn produce(&self) -> sumchain_consensus::Result<Block> {
        self.engine.propose_block(Vec::new()).await
    }

    async fn produce_n(&self, n: usize) -> Vec<Block> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(self.produce().await.unwrap());
        }
        out
    }

    fn record(&self) -> Option<(u64, Hash)> {
        BlockStore::new(&self.db)
            .checked_finality_record()
            .expect("the record must be whole")
    }

    fn head(&self) -> Block {
        BlockStore::new(&self.db).get_latest().unwrap().unwrap()
    }

    fn hash_at(&self, height: u64) -> Hash {
        BlockStore::new(&self.db)
            .get_hash_by_height(height)
            .unwrap()
            .unwrap()
    }
}

fn rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Writing, and a normal restart
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn finality_is_written_as_one_record_and_restored_on_restart() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(5).await;
    assert_eq!(n.engine.finalized_height(), 5 - DEPTH);
    assert_eq!(n.engine.finalized_hash(), n.hash_at(3));
    assert_eq!(n.record(), Some((3, n.hash_at(3))));

    let (n, loaded) = n.restart(true);
    assert_eq!(loaded.unwrap().unwrap().height(), 5);
    assert_eq!(n.engine.finalized_height(), 3, "restored, not reset");
    assert_eq!(n.engine.finalized_hash(), n.hash_at(3));

    n.produce().await.unwrap();
    assert_eq!(n.engine.finalized_height(), 4);
    assert_eq!(n.record(), Some((4, n.hash_at(4))));
}

#[tokio::test]
async fn finality_advances_on_import_and_on_production_alike() {
    arm(None);
    let p = Node::new(true);
    let blocks = p.produce_n(4).await;
    let f = Node::new(false);
    for b in &blocks {
        f.engine.import_block(b.clone()).await.unwrap();
    }
    assert_eq!(f.engine.finalized_height(), 2);
    assert_eq!(f.record(), p.record());
}

// ─────────────────────────────────────────────────────────────────────────────
// A failed write fail-stops
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_failed_finality_write_fail_stops_production_and_memory_stays_at_the_record() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(3).await;
    assert_eq!(n.record(), Some((1, n.hash_at(1))));

    arm(Some(Failpoint::FinalityWriteFails));
    let err = n.produce().await.expect_err("must fail-stop").to_string();
    arm(None);
    assert!(
        err.contains("fail-stopped")
            && err.contains("could not persist local finality at height 2"),
        "{err}"
    );
    assert!(n.engine.halted_reason().is_some());
    assert_eq!(
        n.engine.finalized_height(),
        1,
        "memory must not run ahead of the record"
    );
    assert_eq!(n.engine.finalized_hash(), n.hash_at(1));
    assert_eq!(n.record(), Some((1, n.hash_at(1))), "the record is whole");
    assert_eq!(n.head().height(), 4, "the block itself was committed");

    // Halted: nothing more is produced until restart.
    let again = n.produce().await.expect_err("halted").to_string();
    assert!(again.contains("fail-stopped"), "{again}");
    assert_eq!(n.head().height(), 4);

    // A restart reloads the committed chain and the last record, and the next
    // block derives finality again.
    let (n, loaded) = n.restart(true);
    loaded.unwrap();
    assert_eq!(n.engine.finalized_height(), 1);
    n.produce().await.unwrap();
    assert_eq!(n.engine.finalized_height(), 3);
    assert_eq!(n.record(), Some((3, n.hash_at(3))));
}

#[tokio::test]
async fn a_failed_finality_write_fail_stops_import() {
    arm(None);
    let p = Node::new(true);
    let blocks = p.produce_n(5).await;
    let f = Node::new(false);
    for b in &blocks[..3] {
        f.engine.import_block(b.clone()).await.unwrap();
    }
    assert_eq!(f.record(), Some((1, f.hash_at(1))));

    arm(Some(Failpoint::FinalityWriteFails));
    let err = f
        .engine
        .import_block(blocks[3].clone())
        .await
        .expect_err("must fail-stop")
        .to_string();
    arm(None);
    assert!(err.contains("fail-stopped"), "{err}");
    assert!(f.engine.halted_reason().is_some());
    assert_eq!(f.engine.finalized_height(), 1);
    assert_eq!(f.record(), Some((1, f.hash_at(1))));
    assert_eq!(f.head().height(), 4, "the imported block was committed");
    assert!(f.engine.import_block(blocks[4].clone()).await.is_err());
    assert_eq!(f.head().height(), 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart over a damaged record
// ─────────────────────────────────────────────────────────────────────────────

/// Finalize up to 3, damage the record with `damage`, restart: refused with
/// `needle` in the message, and nothing in the database changes.
async fn restart_refused(damage: impl FnOnce(&Database, &Node), needle: &str) {
    arm(None);
    let n = Node::new(true);
    n.produce_n(5).await;
    assert_eq!(n.record(), Some((3, n.hash_at(3))));
    damage(&n.db, &n);
    let before = rows(&n.db);

    let (n, loaded) = n.restart(true);
    let err = loaded
        .expect_err("a damaged record must refuse start")
        .to_string();
    assert!(
        err.contains("refusing to start") && err.contains(needle),
        "{needle}: {err}"
    );
    assert!(err.contains("not reset to zero"), "{err}");
    assert_eq!(rows(&n.db), before, "a refused start changed the database");

    // And again: nothing was repaired behind the operator's back.
    let (_n, loaded) = n.restart(true);
    assert!(loaded.is_err());
}

#[tokio::test]
async fn a_restart_refuses_a_height_without_its_hash() {
    restart_refused(
        |db, _| db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap(),
        "finalized_hash is absent",
    )
    .await;
}

#[tokio::test]
async fn a_restart_refuses_a_hash_without_its_height() {
    restart_refused(
        |db, _| db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap(),
        "finalized_height is absent",
    )
    .await;
}

#[tokio::test]
async fn a_restart_refuses_an_undecodable_height() {
    restart_refused(
        |db, _| {
            db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &[3u8; 7])
                .unwrap()
        },
        "cannot be read",
    )
    .await;
}

#[tokio::test]
async fn a_restart_refuses_an_undecodable_hash() {
    restart_refused(
        |db, _| {
            db.put(cf::META, meta_keys::FINALIZED_HASH, &[3u8; 31])
                .unwrap()
        },
        "cannot be read",
    )
    .await;
}

/// What two separate writes left when the second was lost: the new height
/// with the previous height's hash.
#[tokio::test]
async fn a_restart_refuses_a_hash_that_is_not_the_block_at_the_height() {
    restart_refused(
        |db, n| {
            db.put(cf::META, meta_keys::FINALIZED_HASH, n.hash_at(2).as_bytes())
                .unwrap()
        },
        "the canonical block at that height",
    )
    .await;
}

#[tokio::test]
async fn a_restart_refuses_a_record_above_the_head() {
    restart_refused(
        |db, _| {
            db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &9u64.to_be_bytes())
                .unwrap()
        },
        "above the recorded head",
    )
    .await;
}

/// Neither key: nothing finalized was recorded. Unchanged from before: the
/// node starts with nothing finalized, and the next block derives finality from
/// the head again and records it.
#[tokio::test]
async fn a_restart_with_no_record_at_all_starts_with_nothing_finalized_as_before() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(5).await;
    n.db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
    n.db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap();

    let (n, loaded) = n.restart(true);
    assert_eq!(loaded.unwrap().unwrap().height(), 5);
    assert_eq!(n.engine.finalized_height(), 0);
    n.produce().await.unwrap();
    assert_eq!(n.engine.finalized_height(), 4);
    assert_eq!(n.record(), Some((4, n.hash_at(4))));
}

// ─────────────────────────────────────────────────────────────────────────────
// Catch-up: one write, then one event per height
// ─────────────────────────────────────────────────────────────────────────────

/// Every `BlockFinalized` event sent since the last call, in order, as
/// (height, hash).
fn finalized_events(rx: &mut broadcast::Receiver<ConsensusEvent>) -> Vec<(u64, Hash)> {
    let mut out = Vec::new();
    loop {
        match rx.try_recv() {
            Ok(ConsensusEvent::BlockFinalized(hash, height)) => out.push((height, hash)),
            Ok(_) => {}
            Err(TryRecvError::Empty) => return out,
            Err(e) => panic!("event stream: {e:?}"),
        }
    }
}

/// With no record and a chain well above the depth, the next block finalizes
/// every height up to head minus depth at once: the record is written once,
/// for the highest, and each height is announced once, in order.
#[tokio::test]
async fn a_catch_up_records_the_highest_height_and_announces_each_height_in_order() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(12).await;
    n.db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
    n.db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap();
    let (n, loaded) = n.restart(true);
    loaded.unwrap();
    assert_eq!(n.engine.finalized_height(), 0);

    let mut rx = n.engine.subscribe();
    n.produce().await.unwrap();
    let expected: Vec<(u64, Hash)> = (1..=11).map(|h| (h, n.hash_at(h))).collect();
    assert_eq!(finalized_events(&mut rx), expected);
    assert_eq!(n.record(), Some((11, n.hash_at(11))));
    assert_eq!(n.engine.finalized_height(), 11);

    // The next block finalizes exactly one more height.
    n.produce().await.unwrap();
    assert_eq!(finalized_events(&mut rx), vec![(12, n.hash_at(12))]);
}

/// A height with no block on the canonical index is skipped, as before: no
/// event for it, and the record names the highest height that has one.
#[tokio::test]
async fn a_catch_up_skips_heights_without_a_canonical_block() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(8).await;
    let hashes: Vec<Hash> = (0..=8).map(|h| n.hash_at(h)).collect();
    n.db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
    n.db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap();
    for gap in [3u64, 7] {
        n.db.delete(cf::BLOCK_HEIGHT, &gap.to_be_bytes()).unwrap();
    }
    let (n, loaded) = n.restart(true);
    loaded.unwrap();

    // Head 9 makes 1..=7 final; 3 and 7 have no canonical block.
    let mut rx = n.engine.subscribe();
    n.produce().await.unwrap();
    let expected: Vec<(u64, Hash)> = [1u64, 2, 4, 5, 6]
        .into_iter()
        .map(|h| (h, hashes[h as usize]))
        .collect();
    assert_eq!(finalized_events(&mut rx), expected);
    assert_eq!(n.record(), Some((6, hashes[6])));
}

/// A failed write announces nothing: events follow the write.
#[tokio::test]
async fn a_failed_finality_write_announces_nothing() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(3).await;
    let mut rx = n.engine.subscribe();
    arm(Some(Failpoint::FinalityWriteFails));
    let failed = n.produce().await;
    arm(None);
    assert!(failed.is_err());
    assert_eq!(finalized_events(&mut rx), Vec::new());
    assert_eq!(n.record(), Some((1, n.hash_at(1))));
}

// ─────────────────────────────────────────────────────────────────────────────
// The operator rollback
// ─────────────────────────────────────────────────────────────────────────────

fn roll_back(n: &Node, to: u64) {
    let journals = ActivatedJournal::resolve(
        &n.db,
        ActivationSource::from_configured_height(Some(1)),
        SubsystemGates::DORMANT,
    )
    .unwrap();
    let plan = plan_rollback(&BlockStore::new(&n.db), to, 10, &journals.activation()).unwrap();
    execute_rollback(&n.db, &n.state, &plan, &journals, journals.policy()).unwrap();
}

#[tokio::test]
async fn a_rollback_below_the_record_moves_it_as_a_pair_and_the_node_restarts() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(6).await;
    assert_eq!(n.record(), Some((4, n.hash_at(4))));
    let target = n.hash_at(2);

    roll_back(&n, 2);
    assert_eq!(n.record(), Some((2, target)), "height and hash together");

    let (n, loaded) = n.restart(true);
    assert_eq!(loaded.unwrap().unwrap().hash(), target);
    assert_eq!(n.engine.finalized_height(), 2);
    assert_eq!(n.engine.finalized_hash(), target);
}

#[tokio::test]
async fn a_rollback_above_the_record_leaves_it() {
    arm(None);
    let n = Node::new(true);
    n.produce_n(6).await;
    let record = n.record();
    assert_eq!(record, Some((4, n.hash_at(4))));
    roll_back(&n, 5);
    assert_eq!(n.record(), record);
    let (n, loaded) = n.restart(true);
    loaded.unwrap();
    assert_eq!(n.engine.finalized_height(), 4);
}
