//! The local-depth finality record (#350) across a chain switch and a restart.
//!
//! The reorg suites keep `finality_depth` out of reach, so no record exists
//! while they switch. Here the depth is 2, so every node holds a record when a
//! competing branch arrives through `import_block`:
//!
//! * a switch that forks exactly at the recorded height keeps the recorded
//!   block, is adopted, moves the record onto the new branch, and the node
//!   restarts on it (closed and reopened): the start check does not refuse a
//!   database a legitimate switch produced;
//! * a switch that forks below the recorded height is refused, the record is
//!   unchanged, and the node restarts on its own chain.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::branch_switch::failpoints::arm;
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, BlockHeader, Hash, SignedTransaction, Transaction};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// Small, so a handful of blocks finalizes some.
const DEPTH: u64 = 2;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

/// Two validators, static membership, journals from height 1, depth 2.
fn genesis(validators: &[KeyPair], funded: &[&KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: DEPTH,
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

/// The node under test: a real engine on a real on-disk database, which can be
/// closed and opened again on the same directory.
struct Node {
    dir: TempDir,
    db: Arc<Database>,
    engine: PoAEngine,
}

impl Node {
    fn open(dir: TempDir, g: &Genesis) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let engine = PoAEngine::new(
            db.clone(),
            Arc::new(StateManager::new(db.clone(), CHAIN_ID)),
            Arc::new(Mempool::new(MempoolConfig::default())),
            g,
            None,
        )
        .unwrap();
        Self { dir, db, engine }
    }

    /// Close every handle and open the directory again, then load the chain
    /// the way a start does.
    fn restart(self, g: &Genesis) -> (Self, sumchain_consensus::Result<Option<Block>>) {
        let Node { dir, db, engine } = self;
        drop(engine);
        assert_eq!(Arc::strong_count(&db), 1, "every handle must be closed");
        drop(db);
        let n = Self::open(dir, g);
        let loaded = n.engine.load_chain();
        (n, loaded)
    }

    fn record(&self) -> Option<(u64, Hash)> {
        BlockStore::new(&self.db)
            .checked_finality_record()
            .expect("the record must be whole")
    }
}

impl World {
    /// A node holding prefix + canonical, with its finality record.
    async fn canonical_node(&self) -> Node {
        let n = Node::open(TempDir::new().unwrap(), &self.g);
        n.engine.init_genesis(&self.g).unwrap();
        for b in self.prefix.iter().chain(&self.canonical) {
            n.engine.import_block(b.clone()).await.unwrap();
        }
        n
    }

    /// Feed the replacement branch: every block but the tip archived as a side
    /// block that lost fork choice is, then the tip, which wins fork choice and
    /// takes the engine's reorg arm.
    async fn feed_branch(&self, n: &Node) -> sumchain_consensus::Result<()> {
        let (tip, interior) = self.branch.split_last().unwrap();
        for b in interior {
            n.db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
                .unwrap();
            for tx in &b.transactions {
                n.db.put(cf::TRANSACTIONS, tx.hash().as_bytes(), &tx.to_bytes())
                    .unwrap();
            }
        }
        n.engine.import_block(tip.clone()).await
    }
}

#[tokio::test]
async fn a_switch_forking_at_the_record_moves_it_to_the_new_branch_and_the_node_restarts() {
    arm(None);
    // Shared 1..=5, canonical 6..=7, replacement 6..=8. Depth 2: before the
    // switch the record is at 5, the fork point itself.
    let w = world(5, 2, 3);
    let x = w.canonical_node().await;
    assert_eq!(x.engine.current_height(), 7);
    assert_eq!(x.record(), Some((5, w.prefix[4].hash())));

    w.feed_branch(&x)
        .await
        .expect("a switch forking at the finalized height keeps the finalized block");
    let tip = w.branch.last().unwrap();
    assert_eq!(x.engine.best_block_hash(), tip.hash());
    assert!(x.engine.halted_reason().is_none());
    // Finality was checked after the switch: the record names the new branch.
    assert_eq!(x.record(), Some((6, w.branch[0].hash())));
    assert_eq!(x.engine.finalized_height(), 6);

    let (x, loaded) = x.restart(&w.g);
    let head = loaded
        .expect("a restart after a legitimate switch must not be refused")
        .expect("a head");
    assert_eq!(head.hash(), tip.hash());
    assert_eq!(x.engine.finalized_height(), 6);
    assert_eq!(x.engine.finalized_hash(), w.branch[0].hash());
}

#[tokio::test]
async fn a_switch_forking_below_the_record_is_refused_and_the_node_restarts_on_its_chain() {
    arm(None);
    // Shared 1..=4, canonical 5..=7, replacement 5..=8. The record is at 5,
    // above the fork at 4.
    let w = world(4, 3, 4);
    let x = w.canonical_node().await;
    let record = Some((5, w.canonical[0].hash()));
    assert_eq!(x.record(), record);

    let err = w
        .feed_branch(&x)
        .await
        .expect_err("a switch below the finalized height must be refused")
        .to_string();
    assert!(err.contains("finalized"), "{err}");
    assert_eq!(x.record(), record, "a refused switch moved the record");

    let (x, loaded) = x.restart(&w.g);
    let head = loaded
        .expect("the node restarts on its own chain")
        .expect("a head");
    assert_eq!(head.hash(), w.canonical.last().unwrap().hash());
    assert_eq!(x.engine.finalized_height(), 5);
}
