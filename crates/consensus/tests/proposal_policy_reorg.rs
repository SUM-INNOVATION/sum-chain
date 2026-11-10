//! The node-local inclusion policy across a chain switch, on a real engine.
//!
//! "Already included" means included on the CANONICAL chain as this node
//! records it. A transaction carried only by a block that lost fork choice is
//! archived (`BLOCKS`, `TRANSACTIONS`) and nothing more: it has no receipt, so
//! it is not counted as included. A transaction a chain switch unwinds loses
//! its receipt and becomes includable again; one the adopted branch carries
//! gains a receipt and is refused. The engine's own mempool reconciliation
//! after a committed switch (`reconcile_mempool_after_switch`) offers the
//! unwound transactions back through `Mempool::add`, so this is the policy
//! judging them against the chain the switch just committed.
//!
//! Two off-node builders, each on its own database over the same genesis,
//! produce the competing branches; the node under test only imports. Same
//! shape as `branch_state_reorg.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, BlockHeader, Hash, SignedTransaction, Transaction};
use sumchain_state::mempool::InclusionPolicy;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, ReceiptStore, TxStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

/// Two validators, static membership, journals required from height 1,
/// finality out of reach.
fn genesis(validators: &[KeyPair], funded: &[&KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::default()
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

/// A block builder off the node under test: its own database, real execution.
struct Builder {
    _dir: TempDir,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    keys: Vec<KeyPair>,
    validators: Vec<[u8; 32]>,
    head: Block,
    /// Added to every timestamp, so two builders on the same parent produce
    /// different blocks.
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

/// The node under test: a follower on a real database, its pool wired with
/// the inclusion policy over that database, exactly as `Node::new` wires it.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(
            Mempool::new(MempoolConfig::default())
                .with_inclusion_policy(InclusionPolicy { db: db.clone() }),
        );
        let engine = Arc::new(PoAEngine::new(db.clone(), state, mempool.clone(), g, None).unwrap());
        engine.init_genesis(g).unwrap();
        Self {
            _dir: dir,
            db,
            mempool,
            engine,
        }
    }

    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.unwrap();
    }

    fn has_receipt(&self, tx: &SignedTransaction) -> bool {
        ReceiptStore::new(&self.db).contains(&tx.hash()).unwrap()
    }

    fn archived(&self, tx: &SignedTransaction) -> bool {
        TxStore::new(&self.db).contains(&tx.hash()).unwrap()
    }
}

fn already_included(r: Result<Hash, StateError>) -> bool {
    matches!(r, Err(StateError::TransactionAlreadyIncluded))
}

/// Blocks 1 and 2 (branch A) make T canonical; the node imports them, so T is
/// included and refused. Block 1' (branch B) carries S and is strictly shorter
/// than the head, so it loses fork choice: it is archived without a receipt, S
/// is NOT counted as included and is admitted. Blocks 2' and 3' then win (3' is
/// strictly longer; 2' may or may not win its same-height tie by hash, which
/// changes nothing below): the switch unwinds T, whose receipt goes with it, and
/// adopts S, which gains one. Afterwards T is held and offered, S is removed and
/// refused. Then branch A grows past B and the two trade places again.
#[tokio::test]
async fn a_chain_switch_releases_unwound_transactions_and_claims_adopted_ones() {
    let validators = [key(1), key(2)];
    let alice = key(10);
    let bob = key(11);
    let g = genesis(&validators, &[&alice, &bob]);

    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators, 0);
    let mut b = Builder::new(&g, &validators, 1);
    assert_eq!(a.head.hash(), b.head.hash(), "one genesis");

    // ── branch A: T is canonical ────────────────────────────────────────────
    let t = transfer(&alice, bob.address(), 5, 0);
    let a1 = a.produce(vec![t.clone()]);
    let a2 = a.produce(Vec::new());
    node.import(&a1).await;
    node.import(&a2).await;
    assert_eq!(node.engine.best_block_hash(), a2.hash());
    assert!(node.has_receipt(&t));
    assert!(already_included(node.mempool.add(t.clone())));
    assert!(node.mempool.is_empty());

    // ── branch B, block 1': S on a block that loses fork choice ─────────────
    let s = transfer(&bob, alice.address(), 7, 0);
    let b1 = b.produce(vec![s.clone()]);
    let b2 = b.produce(Vec::new());
    let b3 = b.produce(Vec::new());
    node.import(&b1).await;
    assert_eq!(node.engine.best_block_hash(), a2.hash(), "a side branch");
    assert!(node.archived(&s), "the losing block's rows are kept");
    assert!(!node.has_receipt(&s), "but it has no receipt");
    node.mempool
        .add(s.clone())
        .expect("a transaction seen only on a side branch is not included");
    assert_eq!(selected(&node), vec![s.hash()]);

    // ── blocks 2' and 3': the switch ────────────────────────────────────────
    node.import(&b2).await;
    node.import(&b3).await;
    assert_eq!(node.engine.best_block_hash(), b3.hash(), "switched");
    assert_eq!(node.engine.current_height(), 3);

    // T was unwound: no receipt, offered back by the engine, admitted by the
    // policy, and selected.
    assert!(!node.has_receipt(&t));
    assert!(node.archived(&t), "the abandoned block's rows are kept");
    assert!(
        node.mempool.contains(&t.hash()),
        "offered back and admitted"
    );
    // S was adopted: a receipt, removed from the pool, refused again.
    assert!(node.has_receipt(&s));
    assert!(!node.mempool.contains(&s.hash()));
    assert!(already_included(node.mempool.add(s.clone())));
    assert_eq!(selected(&node), vec![t.hash()]);

    // ── and back: branch A grows past B ─────────────────────────────────────
    let a3 = a.produce(Vec::new());
    let a4 = a.produce(Vec::new());
    node.import(&a3).await;
    node.import(&a4).await;
    assert_eq!(node.engine.best_block_hash(), a4.hash());
    assert!(node.has_receipt(&t));
    assert!(!node.has_receipt(&s));
    assert!(!node.mempool.contains(&t.hash()), "adopted: removed");
    assert!(node.mempool.contains(&s.hash()), "unwound: offered back");
    assert!(already_included(node.mempool.add(t)));
    assert_eq!(selected(&node), vec![s.hash()]);
}

/// What the node's pool would carry in its next block.
fn selected(node: &Node) -> Vec<Hash> {
    node.mempool
        .select_for_block(10)
        .iter()
        .map(|x| x.hash())
        .collect()
}
