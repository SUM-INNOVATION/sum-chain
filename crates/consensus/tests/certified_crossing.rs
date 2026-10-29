//! The certified-crossing guard (#341) through the engine and the operator
//! rollback (#350).
//!
//! `PoAEngine::import_reorg` consults `sumchain_storage::certified_guard` after
//! a switch is planned and before the replacement branch is executed, and
//! `reorg::execute_rollback` consults it before staging anything. These drive
//! both on real on-disk databases, with SYNTHETIC certified records written into
//! `META`: a pointer and a placeholder certificate row. No production path
//! writes either, and this binary verifies no certificate.
//!
//! * a switch forking below the certified block is refused through
//!   `import_block`: the database, head, accumulator and mempool are exactly as
//!   they were, and the engine is not fail-stopped;
//! * a switch forking at or above the certified block is adopted;
//! * a pointer that does not decode, or certificate rows without a pointer,
//!   fail-stop the switch and change nothing;
//! * with no certified record, the switch is adopted exactly as before;
//! * a rollback below the certified block, or onto another block at its
//!   height, is refused and writes nothing; to the certified block it runs; with
//!   no certified record it runs as before, including the legacy local-depth
//!   `finalized_height` pull-back.
//!
//! Under G2-a the pointer is always the canonical head (S8), and
//! `certified_meta::recover_v1` refuses anything else; the pointers below the
//! head written here exist only to place the boundary. All keys are synthetic.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::reorg::{execute_rollback, plan_rollback};
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, BlockHeader, Hash, SignedTransaction, Transaction};
use sumchain_state::reorg_undo::ActivatedJournal;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_guard::{certified_block, CertifiedBlock, CrossingRefusal};
use sumchain_storage::certified_meta::{certificate_key, FINALIZED_POINTER_KEY};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::journal::ActivationSource;
use sumchain_storage::schema::meta_keys;
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

/// Two validators, static membership, journals required from height 1, and
/// local-depth finality out of reach, so only certified finality can refuse.
fn genesis(validators: &[KeyPair], funded: &[&KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_contracts_enabled()
    };
    let mut alloc = HashMap::new();
    for k in validators.iter().chain(funded.iter().copied()) {
        alloc.insert(k.address().to_base58(), 1_000_000_000u128);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    )
}

fn transfer(from: &KeyPair, to: Address, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, 10, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), pk(from))
}

// ─────────────────────────────────────────────────────────────────────────────
// A block builder off the node under test: its own database, real execution.
// ─────────────────────────────────────────────────────────────────────────────

struct Builder {
    _dir: TempDir,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    keys: Vec<KeyPair>,
    validators: Vec<[u8; 32]>,
    head: Block,
    /// Added to every timestamp, so two builders on one parent differ.
    salt: u64,
}

impl Builder {
    fn new(g: &Genesis, keys: &[KeyPair], salt: u64) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            g,
            None,
        )
        .unwrap();
        let head = engine.init_genesis(g).unwrap();
        drop(engine);
        let executor = BlockExecutor::new(state.clone(), db.clone(), g.params.clone());
        Self {
            _dir: dir,
            state,
            executor,
            keys: keys
                .iter()
                .map(|k| KeyPair::from_bytes(*k.private_key().as_bytes()))
                .collect(),
            validators: g.validator_pubkeys().unwrap(),
            head,
            salt,
        }
    }

    fn proposer(&self, height: u64) -> &KeyPair {
        let want = self.validators[(height % self.validators.len() as u64) as usize];
        self.keys.iter().find(|k| pk(k) == want).unwrap()
    }

    /// Follow a block produced elsewhere.
    fn follow(&mut self, b: &Block) {
        let exec = self
            .executor
            .execute_block(b, self.state.state_root(), &self.validators)
            .unwrap();
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_imported(b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
    }

    /// Produce, publish and return the next block, signed by its rightful
    /// proposer.
    fn produce(&mut self, txs: Vec<SignedTransaction>) -> Block {
        let height = self.head.height() + 1;
        let proposer = KeyPair::from_bytes(*self.proposer(height).private_key().as_bytes());
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10 + self.salt,
                Hash::ZERO,
                Hash::ZERO,
                pk(&proposer),
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &self.validators)
            .unwrap();
        b.header.state_root = exec.computed_root();
        let s = sign(b.header.signing_hash().as_bytes(), proposer.private_key());
        b.header.set_signature(*s.as_bytes());
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The node under test: a real engine on a real on-disk database.
// ─────────────────────────────────────────────────────────────────────────────

struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine =
            Arc::new(PoAEngine::new(db.clone(), state.clone(), mempool.clone(), g, None).unwrap());
        engine.init_genesis(g).unwrap();
        Self {
            _dir: dir,
            db,
            state,
            mempool,
            engine,
        }
    }

    async fn import(&self, b: &Block) -> sumchain_consensus::Result<()> {
        self.engine.import_block(b.clone()).await
    }

    fn db_head(&self) -> Block {
        BlockStore::new(&self.db).get_latest().unwrap().unwrap()
    }

    fn journal(&self) -> ActivatedJournal<'_> {
        ActivatedJournal::resolve(
            &self.db,
            ActivationSource::from_configured_height(Some(1)),
            SubsystemGates::DORMANT,
        )
        .unwrap()
    }
}

/// Every row of every column family.
type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

fn rows(db: &Database) -> Rows {
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

/// The archive keys a block contributes: `BLOCKS[hash]`, `TRANSACTIONS[tx]`.
fn archive_keys(blocks: &[Block]) -> BTreeSet<(String, Vec<u8>)> {
    let mut out = BTreeSet::new();
    for b in blocks {
        out.insert((cf::BLOCKS.to_string(), b.hash().as_bytes().to_vec()));
        for tx in &b.transactions {
            out.insert((cf::TRANSACTIONS.to_string(), tx.hash().as_bytes().to_vec()));
        }
    }
    out
}

/// Every row, except the content-addressed archive rows of `archived`, which
/// a node keeps for any block it has seen.
fn digest_excluding(db: &Database, archived: &[Block]) -> Rows {
    let mut r = rows(db);
    for k in archive_keys(archived) {
        r.remove(&k);
    }
    r
}

/// What `archive_noncanonical` writes for a side block.
fn archive(db: &Database, b: &Block) {
    db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
        .unwrap();
    for tx in &b.transactions {
        db.put(cf::TRANSACTIONS, tx.hash().as_bytes(), &tx.to_bytes())
            .unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Synthetic certified records, in `certified_meta`'s v1 layout.
// ─────────────────────────────────────────────────────────────────────────────

/// Record `(height, hash)` as certified: the 40-byte pointer (height u64 LE ‖
/// block hash) and a placeholder certificate row. The guard's own decoder reads
/// it back, so the encoding here is checked rather than assumed.
fn certify_as(db: &Database, height: u64, hash: Hash) {
    let mut pointer = height.to_le_bytes().to_vec();
    pointer.extend_from_slice(hash.as_bytes());
    db.put(cf::META, FINALIZED_POINTER_KEY, &pointer).unwrap();
    db.put(
        cf::META,
        &certificate_key(height, &hash),
        b"synthetic certificate",
    )
    .unwrap();
    assert_eq!(
        certified_block(db).unwrap(),
        Some(CertifiedBlock { height, hash }),
        "the guard must read exactly the record written"
    );
}

fn certify(db: &Database, b: &Block) {
    certify_as(db, b.height(), b.hash());
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture: a shared prefix, then a canonical suffix and a longer replacement.
// ─────────────────────────────────────────────────────────────────────────────

struct World {
    g: Genesis,
    prefix: Vec<Block>,
    canonical: Vec<Block>,
    branch: Vec<Block>,
}

/// Heights 1..=prefix shared; `old` canonical blocks above them on one side and
/// `new` replacement blocks on the other, each carrying a transfer so the two
/// branches write different state.
fn world(prefix: u64, old: u64, new: u64) -> World {
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let bob = key(0x62);
    let carol = key(0x63);
    let g = genesis(&keys, &[&alice, &bob, &carol]);
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    let mut prefix_blocks = Vec::new();
    for i in 0..prefix {
        let blk = a.produce(vec![transfer(&alice, bob.address(), 1 + i as u128, i)]);
        b.follow(&blk);
        prefix_blocks.push(blk);
    }
    let canonical = (0..old)
        .map(|i| {
            a.produce(vec![transfer(
                &alice,
                bob.address(),
                100 + i as u128,
                prefix + i,
            )])
        })
        .collect();
    let branch = (0..new)
        .map(|i| {
            b.produce(vec![transfer(
                &alice,
                carol.address(),
                500 + i as u128,
                prefix + i,
            )])
        })
        .collect();
    World {
        g,
        prefix: prefix_blocks,
        canonical,
        branch,
    }
}

impl World {
    /// A node holding prefix + canonical.
    async fn canonical_node(&self) -> Node {
        let n = Node::new(&self.g);
        for b in self.prefix.iter().chain(&self.canonical) {
            n.import(b).await.unwrap();
        }
        n
    }

    /// A node that followed prefix + branch only.
    async fn winner_only_node(&self) -> Node {
        let n = Node::new(&self.g);
        for b in self.prefix.iter().chain(&self.branch) {
            n.import(b).await.unwrap();
        }
        n
    }

    /// Feed the replacement branch to `n`: every block but the tip archived as
    /// a side block that lost fork choice is, then the tip, which wins fork
    /// choice and takes the engine's reorg arm.
    async fn feed_branch(&self, n: &Node) -> sumchain_consensus::Result<()> {
        let (tip, interior) = self.branch.split_last().unwrap();
        for b in interior {
            archive(&n.db, b);
        }
        n.import(tip).await
    }

    fn fork_height(&self) -> u64 {
        self.prefix.len() as u64
    }

    /// The canonical block at `height`, on the node holding prefix + canonical.
    fn canonical_at(&self, height: u64) -> &Block {
        self.prefix
            .iter()
            .chain(&self.canonical)
            .find(|b| b.height() == height)
            .unwrap()
    }
}

/// Feed the branch, expect `import_block` to fail, and prove the database
/// (archive rows aside), head, accumulator and mempool are exactly as before.
/// Returns the error text.
async fn refused_and_untouched(w: &World, x: &Node) -> String {
    let before = digest_excluding(&x.db, &w.branch);
    let head = x.engine.best_block_hash();
    let height = x.engine.current_height();
    let root = x.state.state_root();
    let pool = x.mempool.len();
    let err = w
        .feed_branch(x)
        .await
        .expect_err("the switch must be refused")
        .to_string();
    assert_eq!(
        digest_excluding(&x.db, &w.branch),
        before,
        "a refused switch moved the database: {err}"
    );
    assert_eq!(x.db_head().hash(), head, "the recorded head moved");
    assert_eq!(x.engine.best_block_hash(), head, "the in-memory head moved");
    assert_eq!(x.engine.current_height(), height);
    assert_eq!(x.state.state_root(), root, "the accumulator moved");
    assert_eq!(x.mempool.len(), pool, "the mempool changed");
    for b in &w.canonical {
        assert_eq!(
            BlockStore::new(&x.db)
                .get_hash_by_height(b.height())
                .unwrap(),
            Some(b.hash()),
            "the canonical height index must still name the node's own block"
        );
    }
    err
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain switches through `import_block`
// ─────────────────────────────────────────────────────────────────────────────

/// Fork at height 2; the canonical branch is heights 3..=5 and the replacement
/// 3..=6. Certified at 3, 4 or 5 (5 is the head, the only state G2-a's S8
/// allows), the switch would abandon the certified block: refused, as a verdict
/// on the branch, not a fail-stop, with nothing moved.
#[tokio::test]
async fn a_switch_forking_below_the_certified_block_is_refused_through_import_block() {
    let w = world(2, 3, 4);
    assert_eq!(w.fork_height(), 2);
    for certified in 3..=5u64 {
        let x = w.canonical_node().await;
        assert_eq!(x.engine.current_height(), 5);
        certify(&x.db, w.canonical_at(certified));
        let err = refused_and_untouched(&w, &x).await;
        assert!(
            err.contains("crosses certified finality")
                && err.contains(&format!(
                    "forks at block 2, below the certified block {certified}"
                )),
            "the refusal must name the fork and the certified block: {err}"
        );
        assert!(
            x.engine.halted_reason().is_none(),
            "a crossing branch is rejected, not a reason to stop: {err}"
        );
        // Offered again, the tip is already archived, so the import is a no-op
        // and the node stays on its branch; the record is untouched.
        let _ = w.feed_branch(&x).await;
        assert_eq!(x.db_head().hash(), w.canonical.last().unwrap().hash());
        assert_eq!(
            certified_block(&x.db).unwrap().map(|c| c.height),
            Some(certified)
        );
    }
}

/// Certified at or below the fork point, the same switch crosses nothing and
/// is adopted.
#[tokio::test]
async fn a_switch_forking_at_or_above_the_certified_block_is_adopted() {
    let w = world(2, 3, 4);
    for certified in [1u64, 2] {
        let x = w.canonical_node().await;
        certify(&x.db, w.canonical_at(certified));
        w.feed_branch(&x)
            .await
            .unwrap_or_else(|e| panic!("certified at {certified}: {e}"));
        let tip = w.branch.last().unwrap();
        assert_eq!(x.db_head().hash(), tip.hash());
        assert_eq!(x.engine.best_block_hash(), tip.hash());
        assert!(x.engine.halted_reason().is_none());
        assert_eq!(
            certified_block(&x.db).unwrap().map(|c| c.height),
            Some(certified),
            "a switch never writes the certified record"
        );
    }
}

/// With no certified record (every database today) the switch is adopted, and
/// the node ends byte-for-byte where a node that only ever saw the winning
/// branch is: exactly the behaviour before the guard was consulted.
#[tokio::test]
async fn with_no_certified_record_the_switch_is_adopted_exactly_as_before() {
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    assert_eq!(certified_block(&x.db).unwrap(), None);
    w.feed_branch(&x)
        .await
        .expect("the longer branch is adopted");
    let winner = w.winner_only_node().await;
    assert_eq!(
        digest_excluding(&x.db, &w.canonical),
        rows(&winner.db),
        "after adoption the node must hold exactly the winning chain"
    );
    assert_eq!(x.engine.best_block_hash(), w.branch.last().unwrap().hash());
    assert_eq!(
        x.state.state_root(),
        w.branch.last().unwrap().header.state_root
    );
    assert!(x.engine.halted_reason().is_none());
}

/// A pointer that does not decode means this node cannot say what is
/// certified. That is a statement about the node, not the branch: the engine
/// fail-stops, and nothing moves.
#[tokio::test]
async fn an_undecodable_certified_pointer_fail_stops_the_switch_and_moves_nothing() {
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    x.db.put(cf::META, FINALIZED_POINTER_KEY, &[0xAB; 39])
        .unwrap();
    assert!(matches!(
        certified_block(&x.db),
        Err(CrossingRefusal::UnreadablePointer(_))
    ));
    let err = refused_and_untouched(&w, &x).await;
    assert!(
        err.contains("fail-stopped") && err.contains("cannot be read"),
        "{err}"
    );
    assert!(x.engine.halted_reason().is_some());
    // Halted: the next import is refused until restart.
    assert!(x.import(&w.branch[0]).await.is_err());
}

/// Certificate rows without a pointer mean the pointer was lost, never
/// "nothing certified": the switch fail-stops and nothing moves.
#[tokio::test]
async fn certificate_rows_without_a_pointer_fail_stop_the_switch_and_move_nothing() {
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let c = w.canonical_at(4);
    x.db.put(cf::META, &certificate_key(4, &c.hash()), b"orphan")
        .unwrap();
    let err = refused_and_untouched(&w, &x).await;
    assert!(
        err.contains("fail-stopped") && err.contains("pointer is absent"),
        "{err}"
    );
    assert!(x.engine.halted_reason().is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// The operator rollback
// ─────────────────────────────────────────────────────────────────────────────

/// Plan and execute a rollback of the canonical node to `to`.
fn roll_back(x: &Node, to: u64) -> sumchain_consensus::Result<()> {
    let journals = x.journal();
    let plan = plan_rollback(&BlockStore::new(&x.db), to, 10, &journals.activation())?;
    execute_rollback(&x.db, &x.state, &plan, &journals, journals.policy()).map(drop)
}

/// Below the certified block, the rollback is refused before anything is
/// staged: every row of every family is as it was.
#[tokio::test]
async fn a_rollback_below_the_certified_block_is_refused_and_writes_nothing() {
    let w = world(2, 3, 0);
    for (certified, target) in [(5u64, 3u64), (4, 3), (5, 1)] {
        let x = w.canonical_node().await;
        certify(&x.db, w.canonical_at(certified));
        let before = rows(&x.db);
        let err = roll_back(&x, target)
            .expect_err("a rollback below the certified block must be refused")
            .to_string();
        assert!(
            err.contains(&format!("refusing to roll back to height {target}"))
                && err.contains(&format!("below the certified block {certified}")),
            "{err}"
        );
        assert_eq!(rows(&x.db), before, "a refused rollback wrote: {err}");
    }
}

/// To the certified block itself the rollback runs; the certified record is
/// not touched.
#[tokio::test]
async fn a_rollback_to_the_certified_block_runs() {
    let w = world(2, 3, 0);
    let x = w.canonical_node().await;
    let c = w.canonical_at(4);
    certify(&x.db, c);
    roll_back(&x, 4).expect("rolling back to the certified block crosses nothing");
    assert_eq!(x.db_head().hash(), c.hash());
    assert_eq!(
        certified_block(&x.db).unwrap(),
        Some(CertifiedBlock {
            height: 4,
            hash: c.hash()
        })
    );
}

/// A target at the certified height that is not the certified block is
/// refused, and nothing is written.
#[tokio::test]
async fn a_rollback_onto_another_block_at_the_certified_height_is_refused() {
    let w = world(2, 3, 0);
    let x = w.canonical_node().await;
    certify_as(&x.db, 4, Hash::new([0xF0; 32]));
    let before = rows(&x.db);
    let err = roll_back(&x, 4).expect_err("must refuse").to_string();
    assert!(
        err.contains("rollback target at height 4 is not the certified block"),
        "{err}"
    );
    assert_eq!(rows(&x.db), before);
}

/// A pointer that does not decode refuses the rollback, and nothing is written.
#[tokio::test]
async fn an_undecodable_certified_pointer_refuses_the_rollback() {
    let w = world(2, 3, 0);
    let x = w.canonical_node().await;
    x.db.put(cf::META, FINALIZED_POINTER_KEY, b"short").unwrap();
    let before = rows(&x.db);
    let err = roll_back(&x, 4).expect_err("must refuse").to_string();
    assert!(err.contains("cannot be read"), "{err}");
    assert_eq!(rows(&x.db), before);
}

/// With no certified record the rollback runs exactly as before, including
/// the legacy local-depth pull-back: a recorded `finalized_height` above the
/// target comes down to the target, hash and height together.
#[tokio::test]
async fn with_no_certified_record_a_rollback_runs_as_before_and_pulls_local_finality_back() {
    let w = world(2, 3, 0);
    let x = w.canonical_node().await;
    let four = w.canonical_at(4);
    let three = w.canonical_at(3);
    x.db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &4u64.to_be_bytes())
        .unwrap();
    x.db.put(cf::META, meta_keys::FINALIZED_HASH, four.hash().as_bytes())
        .unwrap();
    assert_eq!(certified_block(&x.db).unwrap(), None);

    roll_back(&x, 3).expect("no certified record: the rollback runs");
    assert_eq!(x.db_head().hash(), three.hash());
    let store = BlockStore::new(&x.db);
    assert_eq!(store.get_finalized_height().unwrap(), Some(3));
    assert_eq!(store.get_finalized_hash().unwrap(), Some(three.hash()));
    assert_eq!(store.get_by_height(4).unwrap(), None);
}
