//! Branch-state execution for chain switches (#269), on real on-disk RocksDB.
//!
//! A replacement branch is executed in full against its OWN parent state —
//! reconstructed from the abandoned blocks' journals — and adopted in one atomic
//! batch, or refused with the canonical chain byte-for-byte unchanged.
//!
//! Every comparison here is over the WHOLE database — every column family the
//! database opens — not over a reported root. The one deliberate exclusion is
//! the content-addressed archive of blocks a node has merely SEEN
//! (`BLOCKS[hash]`, `TRANSACTIONS[hash]` for blocks on no canonical chain): a
//! node that saw a branch keeps those rows by design, so a follower that never
//! saw it lacks them. They are checked separately, exactly.
//!
//! All keys are synthetic.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::branch_switch::failpoints::{arm, Failpoint};
use sumchain_consensus::branch_switch::BranchLimits;
use sumchain_consensus::{ConsensusEngine, ConsensusEvent, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::transaction::ContractDeployData;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, Transaction, TransactionV2, TxPayload,
};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

/// Two validators, static membership, journals required from height 1,
/// finality out of reach, contracts enabled.
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

/// `new` writes storage "k" -> `value` (3 bytes).
fn contract_code(value: &str) -> Vec<u8> {
    assert_eq!(value.len(), 3);
    wat::parse_str(format!(
        r#"(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "{value}")
  (func (export "alloc") (param i32) (result i32)
    (local $p i32) (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get 0))) (local.get $p))
  (func (export "new") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 0)))"#
    ))
    .unwrap()
}

fn deploy(from: &KeyPair, nonce: u64, code: Vec<u8>) -> SignedTransaction {
    let payload = TxPayload::ContractDeploy(ContractDeployData {
        code,
        init_method: "new".to_string(),
        init_args: vec![],
        value: 0,
        gas_limit: 1_000_000,
    });
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: from.address(),
        fee: 1_000,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(from))
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

/// Re-sign `b` after editing it, by `signer`.
fn resign(b: &mut Block, signer: &KeyPair) {
    b.header.proposer_pubkey = pk(signer);
    let s = sign(b.header.signing_hash().as_bytes(), signer.private_key());
    b.header.set_signature(*s.as_bytes());
}

/// A structurally valid, never-executed block on `parent`, signed by the
/// rightful proposer: what follows an invalid block in a forged branch.
fn unexecuted_child(parent: &Block, keys: &[KeyPair], validators: &[[u8; 32]]) -> Block {
    let height = parent.height() + 1;
    let want = validators[(height % validators.len() as u64) as usize];
    let signer = keys.iter().find(|k| pk(k) == want).unwrap();
    let mut b = Block::new(
        BlockHeader::new(
            parent.hash(),
            height,
            parent.header.timestamp + 10,
            Hash::ZERO,
            Hash::new([7u8; 32]),
            pk(signer),
        ),
        Vec::new(),
    );
    b.header.tx_root = b.compute_tx_root();
    resign(&mut b, signer);
    b
}

// ─────────────────────────────────────────────────────────────────────────────
// The node under test: a real engine on a real on-disk database, reopenable.
// ─────────────────────────────────────────────────────────────────────────────

struct Node {
    dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        let dir = TempDir::new().unwrap();
        let n = Self::open(dir, g);
        n.engine.init_genesis(g).unwrap();
        n
    }

    fn open(dir: TempDir, g: &Genesis) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine =
            Arc::new(PoAEngine::new(db.clone(), state.clone(), mempool.clone(), g, None).unwrap());
        Self {
            dir,
            db,
            state,
            mempool,
            engine,
        }
    }

    /// Close every handle and reopen the same directory: a restart.
    fn restart(self, g: &Genesis) -> Self {
        let Node {
            dir,
            db,
            state,
            mempool,
            engine,
        } = self;
        drop(engine);
        drop(mempool);
        drop(state);
        assert_eq!(
            Arc::strong_count(&db),
            1,
            "every database handle must be closed"
        );
        drop(db);
        let n = Self::open(dir, g);
        n.engine.load_chain().unwrap();
        n
    }

    async fn import(&self, b: &Block) -> sumchain_consensus::Result<()> {
        self.engine.import_block(b.clone()).await
    }

    fn db_head(&self) -> Block {
        BlockStore::new(&self.db).get_latest().unwrap().unwrap()
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

fn without(mut r: Rows, keys: &BTreeSet<(String, Vec<u8>)>) -> Rows {
    for k in keys {
        r.remove(k);
    }
    r
}

/// The whole database is equal, except for archive rows of blocks only
/// `left` has seen; those are exactly `left_only`.
fn assert_same_database(left: &Database, right: &Database, left_only: &[Block], what: &str) {
    let l = rows(left);
    let r = rows(right);
    let extra = archive_keys(left_only);
    let shared_extra: BTreeSet<_> = extra
        .iter()
        .filter(|k| r.contains_key(*k))
        .cloned()
        .collect();
    let only: BTreeSet<_> = extra.difference(&shared_extra).cloned().collect();
    for k in &only {
        assert!(l.contains_key(k), "{what}: expected archive row {k:?}");
    }
    let l = without(l, &only);
    if l != r {
        let lk: BTreeSet<_> = l.keys().collect();
        let rk: BTreeSet<_> = r.keys().collect();
        let first_l: Vec<_> = lk.difference(&rk).take(3).collect();
        let first_r: Vec<_> = rk.difference(&lk).take(3).collect();
        let differ: Vec<_> = lk
            .intersection(&rk)
            .filter(|k| l[**k] != r[**k])
            .take(3)
            .collect();
        panic!(
            "{what}: databases differ. only left: {first_l:?}; only right: {first_r:?}; \
             values differ: {differ:?}"
        );
    }
}

fn digest_excluding(db: &Database, archived: &[Block]) -> Rows {
    without(rows(db), &archive_keys(archived))
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture: a canonical chain and a competing branch from a common fork parent.
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct World {
    g: Genesis,
    keys: Vec<KeyPair>,
    alice: KeyPair,
    bob: KeyPair,
    carol: KeyPair,
    prefix: Vec<Block>,
    canonical: Vec<Block>,
    branch: Vec<Block>,
}

/// `prefix` blocks shared by both chains, then `old` canonical blocks on one
/// side and `new` replacement blocks on the other, each block carrying a
/// transfer so the two branches write different state.
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
    let base = prefix;
    let canonical = (0..old)
        .map(|i| {
            a.produce(vec![transfer(
                &alice,
                bob.address(),
                100 + i as u128,
                base + i,
            )])
        })
        .collect();
    let branch = (0..new)
        .map(|i| a_or_b_branch(&mut b, &alice, &carol, base, i))
        .collect();
    World {
        g,
        keys,
        alice,
        bob,
        carol,
        prefix: prefix_blocks,
        canonical,
        branch,
    }
}

fn a_or_b_branch(b: &mut Builder, alice: &KeyPair, carol: &KeyPair, base: u64, i: u64) -> Block {
    b.produce(vec![transfer(
        alice,
        carol.address(),
        500 + i as u128,
        base + i,
    )])
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

    /// A node that followed prefix + branch only, never seeing the canonical
    /// suffix.
    async fn winner_only_node(&self) -> Node {
        let n = Node::new(&self.g);
        for b in self.prefix.iter().chain(&self.branch) {
            n.import(b).await.unwrap();
        }
        n
    }

    /// Feed the replacement branch to `n`: every block but the tip is archived
    /// exactly as a side block that lost fork choice is, and the tip triggers
    /// the switch. Archived directly rather than imported because the interior
    /// block at the canonical head's height can win the equal-height hash
    /// tiebreak on arrival, which would make the switch happen one block early;
    /// that path has its own test.
    async fn feed_branch(&self, n: &Node, branch: &[Block]) -> sumchain_consensus::Result<()> {
        let (tip, interior) = branch.split_last().unwrap();
        for b in interior {
            archive(&n.db, b);
        }
        n.import(tip).await
    }
}

/// What `archive_noncanonical` writes for a side block: its content-addressed
/// `BLOCKS` and `TRANSACTIONS` rows, nothing else.
fn archive(db: &Database, b: &Block) {
    db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
        .unwrap();
    for tx in &b.transactions {
        db.put(cf::TRANSACTIONS, tx.hash().as_bytes(), &tx.to_bytes())
            .unwrap();
    }
}

fn reset_hooks() {
    arm(None);
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(None);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1–3, 15, 16, 20: valid replacements match a winner-only node exactly.
// ─────────────────────────────────────────────────────────────────────────────

async fn valid_replacement(old: u64, new: u64) {
    reset_hooks();
    let w = world(2, old, new);
    let x = w.canonical_node().await;
    assert_eq!(x.engine.current_height(), 2 + old);
    w.feed_branch(&x, &w.branch)
        .await
        .expect("the longer valid branch is adopted");
    assert_eq!(x.db_head().hash(), w.branch.last().unwrap().hash());
    assert_eq!(x.engine.current_height(), 2 + new);
    assert!(x.engine.halted_reason().is_none());

    let winner = w.winner_only_node().await;
    assert_same_database(&x.db, &winner.db, &w.canonical, "after adoption");
    // State root accumulator and in-memory head agree with the database.
    assert_eq!(
        x.state.state_root(),
        w.branch.last().unwrap().header.state_root
    );
    assert_eq!(x.engine.best_block_hash(), w.branch.last().unwrap().hash());

    // 20: static membership and the proposer sequence are unchanged.
    let validators = w.g.validator_pubkeys().unwrap();
    for h in 0..20u64 {
        assert_eq!(x.engine.get_proposer(h), validators[(h % 2) as usize]);
    }
}

#[tokio::test]
async fn a_valid_one_block_replacement_is_adopted() {
    valid_replacement(1, 2).await;
}

#[tokio::test]
async fn a_valid_six_block_replacement_is_adopted() {
    valid_replacement(6, 7).await;
}

#[tokio::test]
async fn a_valid_sixty_four_block_replacement_is_adopted() {
    valid_replacement(64, 65).await;
}

/// Equal height, lower hash: the tiebreak switch is a one-for-one replacement.
#[tokio::test]
async fn an_equal_length_replacement_wins_on_the_tiebreak() {
    reset_hooks();
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let bob = key(0x62);
    let g = genesis(&keys, &[&alice, &bob]);
    let mut a = Builder::new(&g, &keys, 0);
    let first = a.produce(vec![]);
    // Search salts for a sibling with a lower hash than `first`.
    let sibling = (1..200)
        .map(|salt| {
            let mut b = Builder::new(&g, &keys, salt);
            b.produce(vec![transfer(&alice, bob.address(), 9, 0)])
        })
        .find(|s| s.hash() < first.hash())
        .expect("some salt yields a lower hash");
    let x = Node::new(&g);
    x.import(&first).await.unwrap();
    x.import(&sibling)
        .await
        .expect("the lower-hash sibling wins");
    assert_eq!(x.db_head().hash(), sibling.hash());
    let winner = Node::new(&g);
    winner.import(&sibling).await.unwrap();
    assert_same_database(&x.db, &winner.db, &[first], "after the tiebreak switch");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4–10, 14: invalid branches are refused with nothing changed.
// ─────────────────────────────────────────────────────────────────────────────

/// Feed `branch` (interior blocks written raw into BLOCKS, as an archived side
/// branch would be), expect refusal, and prove the database, head, accumulator
/// and mempool are exactly as before.
async fn assert_refused(x: &Node, branch: &[Block], needle: &str) {
    let before = digest_excluding(&x.db, branch);
    let head = x.engine.best_block_hash();
    let root = x.state.state_root();
    let pool = x.mempool.len();
    let (tip, interior) = branch.split_last().unwrap();
    for b in interior {
        archive(&x.db, b);
    }
    let err = x
        .import(tip)
        .await
        .expect_err("an invalid branch must be refused")
        .to_string();
    assert!(
        err.contains(needle),
        "refusal should mention {needle:?}: {err}"
    );
    assert!(
        x.engine.halted_reason().is_none(),
        "a rejection is not a fail-stop"
    );
    assert_eq!(
        digest_excluding(&x.db, branch),
        before,
        "the canonical chain moved"
    );
    assert_eq!(x.engine.best_block_hash(), head);
    assert_eq!(x.state.state_root(), root);
    assert_eq!(x.mempool.len(), pool);
}

/// A branch whose block at `bad` carries a wrong state root, re-signed; every
/// later block structurally valid but never executable.
fn branch_with_bad_root(w: &World, bad: usize) -> Vec<Block> {
    let validators = w.g.validator_pubkeys().unwrap();
    let mut out: Vec<Block> = w.branch[..bad].to_vec();
    let mut b = w.branch[bad].clone();
    b.header.state_root = Hash::new([0xEE; 32]);
    let signer = w
        .keys
        .iter()
        .find(|k| pk(k) == b.header.proposer_pubkey)
        .unwrap();
    resign(&mut b, signer);
    out.push(b);
    while out.len() < w.branch.len() {
        let next = unexecuted_child(out.last().unwrap(), &w.keys, &validators);
        out.push(next);
    }
    out
}

async fn refused_at(bad: usize) {
    reset_hooks();
    // Heights here are far below the legacy window; refuse mismatches anyway.
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(Some(0));
    let w = world(2, 4, 5);
    let x = w.canonical_node().await;
    let forged = branch_with_bad_root(&w, bad);
    assert_refused(&x, &forged, "state root mismatch").await;
    reset_hooks();
}

#[tokio::test]
async fn an_invalid_first_replacement_block_is_refused() {
    refused_at(0).await;
}

#[tokio::test]
async fn an_invalid_middle_replacement_block_is_refused() {
    refused_at(2).await;
}

#[tokio::test]
async fn an_invalid_final_replacement_block_is_refused() {
    refused_at(4).await;
}

#[tokio::test]
async fn a_wrong_proposer_is_refused_before_anything_is_reconstructed() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let mut forged = w.branch.clone();
    let wrong = w
        .keys
        .iter()
        .find(|k| pk(k) != forged[1].header.proposer_pubkey)
        .unwrap();
    resign(&mut forged[1], wrong);
    // Re-link the rest onto the re-signed block.
    let validators = w.g.validator_pubkeys().unwrap();
    for i in 2..forged.len() {
        forged[i] = unexecuted_child(&forged[i - 1].clone(), &w.keys, &validators);
    }
    assert_refused(&x, &forged, "Invalid proposer").await;
}

#[tokio::test]
async fn a_wrong_parent_hash_is_refused() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let before = digest_excluding(&x.db, &w.branch);
    // A tip whose parent this node has never seen.
    let mut orphan = w.branch.last().unwrap().clone();
    orphan.header.parent_hash = Hash::new([0xAB; 32]);
    let signer = w
        .keys
        .iter()
        .find(|k| pk(k) == orphan.header.proposer_pubkey)
        .unwrap();
    resign(&mut orphan, signer);
    assert!(x.import(&orphan).await.is_err());
    // A tip whose height does not follow its parent's.
    let mut skipped = w.branch[1].clone();
    skipped.header.parent_hash = w.prefix.last().unwrap().hash();
    resign(&mut skipped, signer);
    let err = x.import(&skipped).await.unwrap_err().to_string();
    assert!(err.contains("height") || err.contains("proposer"), "{err}");
    assert_eq!(digest_excluding(&x.db, &w.branch), before);
}

/// A transaction the header root does not account for, several blocks deep.
#[tokio::test]
async fn an_invalid_transaction_after_several_valid_blocks_is_refused() {
    reset_hooks();
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(Some(0));
    let w = world(2, 4, 5);
    let x = w.canonical_node().await;
    let validators = w.g.validator_pubkeys().unwrap();
    let mut forged: Vec<Block> = w.branch[..3].to_vec();
    let mut b = w.branch[3].clone();
    b.transactions = vec![transfer(&w.alice, w.bob.address(), 777_777, 2 + 3)];
    b.header.tx_root = b.compute_tx_root();
    let signer = w
        .keys
        .iter()
        .find(|k| pk(k) == b.header.proposer_pubkey)
        .unwrap();
    resign(&mut b, signer);
    forged.push(b);
    forged.push(unexecuted_child(
        forged.last().unwrap(),
        &w.keys,
        &validators,
    ));
    assert_refused(&x, &forged, "state root mismatch").await;
    reset_hooks();
}

// ─────────────────────────────────────────────────────────────────────────────
// 11, 12: each branch reads its own parent; contract state is isolated.
// ─────────────────────────────────────────────────────────────────────────────

/// Both chains spend alice's SAME nonce from the fork parent, and both deploy
/// a contract from the same deployer nonce — so the same contract address —
/// with different code. On the canonical head the replacement's transactions
/// would fail (nonce used, contract already exists); against the fork parent
/// they succeed. Equality with a winner-only node proves every read, including
/// the contract runtime's, came from the fork parent.
#[tokio::test]
async fn competing_branches_read_their_own_fork_parent_including_contracts() {
    reset_hooks();
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let bob = key(0x62);
    let carol = key(0x63);
    let g = genesis(&keys, &[&alice, &bob, &carol]);
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    let shared = a.produce(vec![]);
    b.follow(&shared);
    let canonical = vec![
        a.produce(vec![
            transfer(&alice, bob.address(), 5, 0),
            deploy(&carol, 0, contract_code("AAA")),
        ]),
        a.produce(vec![]),
    ];
    let branch = vec![
        b.produce(vec![
            transfer(&alice, carol.address(), 6, 0),
            deploy(&carol, 0, contract_code("BBB")),
        ]),
        b.produce(vec![]),
        b.produce(vec![]),
    ];
    let x = Node::new(&g);
    for blk in std::iter::once(&shared).chain(&canonical) {
        x.import(blk).await.unwrap();
    }
    let before_code = rows(&x.db)
        .into_iter()
        .filter(|((c, _), _)| c == cf::CONTRACT_STORAGE)
        .count();
    assert!(
        before_code > 0,
        "the canonical deploy wrote contract storage"
    );
    let (tip, interior) = branch.split_last().unwrap();
    for blk in interior {
        x.import(blk).await.unwrap();
    }
    x.import(tip)
        .await
        .expect("the replacement is valid on its own parent");

    let winner = Node::new(&g);
    for blk in std::iter::once(&shared).chain(&branch) {
        winner.import(blk).await.unwrap();
    }
    assert_same_database(&x.db, &winner.db, &canonical, "contracts and accounts");
    let storage: Vec<_> = rows(&x.db)
        .into_iter()
        .filter(|((c, _), _)| c == cf::CONTRACT_STORAGE)
        .map(|(_, v)| v)
        .collect();
    assert!(storage.contains(&b"BBB".to_vec()) && !storage.contains(&b"AAA".to_vec()));
}

/// A refused branch carrying contract and account writes leaves every family —
/// contract, account, and the dormant compute-pool and beacon families —
/// exactly as it was.
#[tokio::test]
async fn a_refused_branch_leaves_contract_account_and_dormant_state_untouched() {
    reset_hooks();
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(Some(0));
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let carol = key(0x63);
    let g = genesis(&keys, &[&alice, &carol]);
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    let canonical = vec![a.produce(vec![]), a.produce(vec![])];
    let mut branch = vec![
        b.produce(vec![
            transfer(&alice, carol.address(), 6, 0),
            deploy(&carol, 0, contract_code("BBB")),
        ]),
        b.produce(vec![]),
    ];
    let mut last = b.produce(vec![]);
    last.header.state_root = Hash::new([1; 32]);
    let signer = keys
        .iter()
        .find(|k| pk(k) == last.header.proposer_pubkey)
        .unwrap();
    resign(&mut last, signer);
    branch.push(last);
    let x = Node::new(&g);
    for blk in &canonical {
        x.import(blk).await.unwrap();
    }
    let dormant_before: Vec<_> = rows(&x.db)
        .into_iter()
        .filter(|((c, _), _)| {
            c == cf::COMPUTE_POOL_STATE || c == cf::BEACON_STATE || c.starts_with("contract")
        })
        .collect();
    assert_refused(&x, &branch, "state root mismatch").await;
    let dormant_after: Vec<_> = rows(&x.db)
        .into_iter()
        .filter(|((c, _), _)| {
            c == cf::COMPUTE_POOL_STATE || c == cf::BEACON_STATE || c.starts_with("contract")
        })
        .collect();
    assert_eq!(dormant_before, dormant_after);
    reset_hooks();
}

// ─────────────────────────────────────────────────────────────────────────────
// 17, 18: restart and every injected failure.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn restart_before_and_after_adoption_keeps_the_committed_chain() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let (tip, interior) = w.branch.split_last().unwrap();
    for b in interior {
        archive(&x.db, b);
    }
    // Restart with the side branch archived but not adopted.
    let x = x.restart(&w.g);
    assert_eq!(
        x.engine.best_block_hash(),
        w.canonical.last().unwrap().hash()
    );
    x.import(tip).await.expect("adopted after a restart");
    // Restart after adoption.
    let x = x.restart(&w.g);
    assert_eq!(x.engine.best_block_hash(), tip.hash());
    assert_eq!(x.state.state_root(), tip.header.state_root);
    let winner = w.winner_only_node().await;
    assert_same_database(&x.db, &winner.db, &w.canonical, "after restarts");
}

struct Injected {
    w: World,
    x: Node,
    before: Rows,
}

async fn inject(fp: Failpoint) -> (Injected, sumchain_consensus::Result<()>) {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let before = digest_excluding(&x.db, &w.branch);
    let (tip, interior) = w.branch.split_last().unwrap();
    for b in interior {
        archive(&x.db, b);
    }
    arm(Some(fp));
    let r = x.import(tip).await;
    arm(None);
    (Injected { w, x, before }, r)
}

async fn assert_old_chain_after_restart(i: Injected) {
    let x = i.x.restart(&i.w.g);
    assert_eq!(
        x.engine.best_block_hash(),
        i.w.canonical.last().unwrap().hash()
    );
    assert_eq!(digest_excluding(&x.db, &i.w.branch), i.before);
    assert_eq!(
        x.state.state_root(),
        i.w.canonical.last().unwrap().header.state_root
    );
}

async fn assert_new_chain_after_restart(i: Injected) {
    let tip = i.w.branch.last().unwrap().clone();
    let winner = i.w.winner_only_node().await;
    let x = i.x.restart(&i.w.g);
    assert_eq!(x.engine.best_block_hash(), tip.hash());
    assert_eq!(x.state.state_root(), tip.header.state_root);
    assert_same_database(
        &x.db,
        &winner.db,
        &i.w.canonical,
        "after a post-commit failure",
    );
}

#[tokio::test]
async fn f1_a_speculative_execution_error_changes_nothing() {
    let (i, r) = inject(Failpoint::SpeculativeExecution(2)).await;
    assert!(r.is_err());
    assert!(i.x.engine.halted_reason().is_none());
    assert_eq!(digest_excluding(&i.x.db, &i.w.branch), i.before);
    assert_old_chain_after_restart(i).await;
}

#[tokio::test]
async fn f2_a_replacement_root_mismatch_changes_nothing() {
    reset_hooks();
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(Some(0));
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let forged = branch_with_bad_root(&w, 1);
    assert_refused(&x, &forged, "state root mismatch").await;
    let before = digest_excluding(&x.db, &forged);
    let x = x.restart(&w.g);
    assert_eq!(
        x.engine.best_block_hash(),
        w.canonical.last().unwrap().hash()
    );
    assert_eq!(digest_excluding(&x.db, &forged), before);
    reset_hooks();
}

#[tokio::test]
async fn f3_a_local_resource_limit_fail_stops_and_changes_nothing() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let before = digest_excluding(&x.db, &w.branch);
    x.engine.set_branch_limits_for_tests(BranchLimits {
        max_branch_state_bytes: 64,
        ..BranchLimits::PRODUCTION
    });
    let err = w.feed_branch(&x, &w.branch).await.unwrap_err().to_string();
    assert!(err.contains("fail-stopped"), "{err}");
    assert!(x.engine.halted_reason().is_some());
    // Halted: nothing further is accepted until restart.
    assert!(x.import(&w.branch[0]).await.is_err() || x.engine.halted_reason().is_some());
    assert_eq!(digest_excluding(&x.db, &w.branch), before);
    let i = Injected { w, x, before };
    assert_old_chain_after_restart(i).await;
}

#[tokio::test]
async fn f4_a_database_failure_before_commit_changes_nothing() {
    let (i, r) = inject(Failpoint::BeforeCommit).await;
    assert!(r.is_err());
    assert_eq!(digest_excluding(&i.x.db, &i.w.branch), i.before);
    assert_eq!(
        i.x.engine.best_block_hash(),
        i.w.canonical.last().unwrap().hash()
    );
    assert_old_chain_after_restart(i).await;
}

#[tokio::test]
async fn f5_a_failed_commit_changes_nothing() {
    let (i, r) = inject(Failpoint::CommitFails).await;
    assert!(r.is_err());
    assert_eq!(digest_excluding(&i.x.db, &i.w.branch), i.before);
    assert_eq!(
        i.x.engine.best_block_hash(),
        i.w.canonical.last().unwrap().hash()
    );
    assert_old_chain_after_restart(i).await;
}

#[tokio::test]
async fn f6_a_crash_before_commit_recovers_the_old_chain() {
    let (i, r) = inject(Failpoint::CrashBeforeCommit).await;
    assert!(r.unwrap_err().to_string().contains("fail-stopped"));
    assert_eq!(
        i.x.engine.best_block_hash(),
        i.w.canonical.last().unwrap().hash()
    );
    assert_old_chain_after_restart(i).await;
}

#[tokio::test]
async fn f7_a_crash_after_commit_recovers_the_new_chain() {
    let (i, r) = inject(Failpoint::CrashAfterCommit).await;
    assert!(r.unwrap_err().to_string().contains("fail-stopped"));
    // The database already holds the new chain; the stopped engine refuses
    // everything rather than act on its stale memory.
    assert_eq!(i.x.db_head().hash(), i.w.branch.last().unwrap().hash());
    assert!(i.x.import(&i.w.canonical[0]).await.is_err());
    assert_new_chain_after_restart(i).await;
}

/// After a post-commit reconciliation failure, memory is rebuilt from the
/// committed database before the engine stops: the head and accumulator name
/// the new tip, and the mempool no longer holds a transaction the new branch
/// included (it was valid at the old head, and is spent on the new chain).
async fn assert_memory_rebuilt(fp: Failpoint) {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let included = w.branch[3].transactions[0].clone();
    x.mempool.add(included.clone()).unwrap();
    let (tip, interior) = w.branch.split_last().unwrap();
    for b in interior {
        archive(&x.db, b);
    }
    arm(Some(fp));
    let r = x.import(tip).await;
    arm(None);
    assert!(r.unwrap_err().to_string().contains("fail-stopped"));
    assert_eq!(x.engine.best_block_hash(), tip.hash());
    assert_eq!(x.state.state_root(), tip.header.state_root);
    assert!(
        !x.mempool.contains(&included.hash()),
        "memory reconstruction revalidates the mempool against the committed chain"
    );
    let before = digest_excluding(&x.db, &w.branch);
    let i = Injected { w, x, before };
    assert_new_chain_after_restart(i).await;
}

#[tokio::test]
async fn f8_a_mempool_reconciliation_failure_rebuilds_memory_and_stops() {
    assert_memory_rebuilt(Failpoint::MempoolReconcile).await;
}

#[tokio::test]
async fn f9_an_event_emission_failure_rebuilds_memory_and_stops() {
    assert_memory_rebuilt(Failpoint::EventEmission).await;
}

#[tokio::test]
async fn f10_a_corrupt_or_missing_old_journal_fail_stops_and_changes_nothing() {
    for corrupt in [true, false] {
        reset_hooks();
        let w = world(2, 3, 4);
        let x = w.canonical_node().await;
        let victim = &w.canonical[1];
        let jkey = sumchain_storage::schema::journal_key(victim.height(), &victim.hash());
        if corrupt {
            x.db.put(cf::APPLICATION_JOURNAL, &jkey, b"SUMAJ garbage")
                .unwrap();
        } else {
            x.db.delete(cf::APPLICATION_JOURNAL, &jkey).unwrap();
        }
        let before = digest_excluding(&x.db, &w.branch);
        let err = w.feed_branch(&x, &w.branch).await.unwrap_err().to_string();
        assert!(err.contains("fail-stopped"), "{err}");
        assert_eq!(digest_excluding(&x.db, &w.branch), before);
        let i = Injected { w, x, before };
        assert_old_chain_after_restart(i).await;
    }
}

/// The journal of an abandoned block is checked against the state it unwinds:
/// a well-formed record whose after-image no longer matches is refused.
#[tokio::test]
async fn a_journal_that_does_not_describe_the_current_state_is_refused() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    // Move a row every canonical block wrote — alice's account — behind its
    // journals' back.
    let alice = w.alice.address();
    let alice_row = rows(&x.db)
        .into_iter()
        .find(|((c, k), _)| {
            c == cf::STATE
                && k.windows(alice.as_bytes().len())
                    .any(|w| w == alice.as_bytes())
        })
        .map(|((_, k), _)| k)
        .expect("alice's account row");
    x.db.put(cf::STATE, &alice_row, b"tampered").unwrap();
    let err = w.feed_branch(&x, &w.branch).await.unwrap_err().to_string();
    assert!(err.contains("fail-stopped"), "{err}");
}

// ─────────────────────────────────────────────────────────────────────────────
// 19: mempool reconciliation and events, only after a committed switch.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_mempool_is_reconciled_only_after_a_committed_switch() {
    reset_hooks();
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let bob = key(0x62);
    let carol = key(0x63);
    let dave = key(0x64);
    let g = genesis(&keys, &[&alice, &bob, &carol, &dave]);
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    // Canonical: alice→bob (alice nonce 0), carol→bob (carol nonce 0).
    let alice_canon = transfer(&alice, bob.address(), 5, 0);
    let carol_canon = transfer(&carol, bob.address(), 7, 0);
    let canonical = vec![a.produce(vec![alice_canon.clone(), carol_canon.clone()])];
    // Replacement: alice→dave (alice nonce 0) and dave→alice, which X holds
    // in its mempool beforehand.
    let dave_pending = transfer(&dave, alice.address(), 3, 0);
    let branch = vec![
        b.produce(vec![transfer(&alice, dave.address(), 9, 0)]),
        b.produce(vec![dave_pending.clone()]),
    ];
    let x = Node::new(&g);
    x.import(&canonical[0]).await.unwrap();
    x.mempool.add(dave_pending.clone()).unwrap();
    let mut events = x.engine.subscribe();

    // A refused attempt first: the mempool and events are untouched.
    sumchain_storage::candidate::set_legacy_cutoff_for_tests(Some(0));
    let mut bad = branch.clone();
    bad[1].header.state_root = Hash::new([3; 32]);
    let signer = keys
        .iter()
        .find(|k| pk(k) == bad[1].header.proposer_pubkey)
        .unwrap();
    resign(&mut bad[1], signer);
    let pool_before: BTreeSet<Hash> = x.mempool.get_all().iter().map(|t| t.hash()).collect();
    assert_refused(&x, &bad, "state root mismatch").await;
    assert_eq!(
        x.mempool
            .get_all()
            .iter()
            .map(|t| t.hash())
            .collect::<BTreeSet<_>>(),
        pool_before
    );
    assert!(events.try_recv().is_err(), "no event for a refused switch");
    reset_hooks();

    w_feed(&x, &branch).await;
    let pool: BTreeSet<Hash> = x.mempool.get_all().iter().map(|t| t.hash()).collect();
    assert!(
        pool.contains(&carol_canon.hash()),
        "an abandoned tx still valid is offered back"
    );
    assert!(
        !pool.contains(&alice_canon.hash()),
        "an abandoned tx the new branch spent is dropped"
    );
    assert!(
        !pool.contains(&dave_pending.hash()),
        "a tx the new branch includes is removed"
    );
    let mut saw_reorg = false;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev, ConsensusEvent::Reorg { .. }) {
            saw_reorg = true;
        }
    }
    assert!(saw_reorg, "the committed switch is announced");
}

async fn w_feed(x: &Node, branch: &[Block]) {
    let (tip, interior) = branch.split_last().unwrap();
    for b in interior {
        archive(&x.db, b);
    }
    x.import(tip).await.expect("adopted");
}

// ─────────────────────────────────────────────────────────────────────────────
// After a switch the node keeps going on the new chain.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn after_a_switch_the_next_block_extends_the_new_chain() {
    reset_hooks();
    let keys = vec![key(1), key(2)];
    let alice = key(0x61);
    let carol = key(0x63);
    let g = genesis(&keys, &[&alice, &carol]);
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    let canonical = vec![a.produce(vec![]), a.produce(vec![])];
    let branch: Vec<Block> = (0..3)
        .map(|i| b.produce(vec![transfer(&alice, carol.address(), 1, i)]))
        .collect();
    let x = Node::new(&g);
    for blk in &canonical {
        x.import(blk).await.unwrap();
    }
    w_feed(&x, &branch).await;
    let next = b.produce(vec![transfer(&alice, carol.address(), 1, 3)]);
    x.import(&next)
        .await
        .expect("a direct extension of the adopted chain");
    assert_eq!(x.db_head().hash(), next.hash());
    let winner = Node::new(&g);
    for blk in branch.iter().chain(std::iter::once(&next)) {
        winner.import(blk).await.unwrap();
    }
    assert_same_database(
        &x.db,
        &winner.db,
        &canonical,
        "after extending the new chain",
    );
}

/// A journal is bound to its block: an otherwise genuine record whose embedded
/// `(height, hash)` names a different block is refused, even though its entries
/// would reconstruct the right state.
#[tokio::test]
async fn a_journal_bound_to_another_block_is_refused() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let victim = &w.canonical[2];
    let other = &w.canonical[1];
    let jkey = sumchain_storage::schema::journal_key(victim.height(), &victim.hash());
    let mut bytes = x.db.get(cf::APPLICATION_JOURNAL, &jkey).unwrap().unwrap();
    // Header: magic (5) | version (2) | height (8, BE) | block hash (32).
    bytes[7..15].copy_from_slice(&other.height().to_be_bytes());
    bytes[15..47].copy_from_slice(other.hash().as_bytes());
    x.db.put(cf::APPLICATION_JOURNAL, &jkey, &bytes).unwrap();
    let before = digest_excluding(&x.db, &w.branch);
    let err = w.feed_branch(&x, &w.branch).await.unwrap_err().to_string();
    assert!(err.contains("fail-stopped"), "{err}");
    assert!(
        err.contains("describes"),
        "the refusal names the identity mismatch: {err}"
    );
    assert_eq!(digest_excluding(&x.db, &w.branch), before);
}

/// The whole-database comparison these tests rely on notices one changed row.
#[tokio::test]
async fn the_database_comparison_detects_a_single_changed_row() {
    reset_hooks();
    let w = world(1, 0, 1);
    let a = w.winner_only_node().await;
    let b = w.winner_only_node().await;
    assert_same_database(&a.db, &b.db, &[], "identical histories");
    b.db.put(cf::STATE, b"stray", b"row").unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_same_database(&a.db, &b.db, &[], "one stray row")
    }));
    assert!(caught.is_err(), "a single extra row must be detected");
}

/// An interior block from the rightful proposer whose signature does not
/// verify is refused before anything is reconstructed or executed.
#[tokio::test]
async fn a_bad_signature_is_refused() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let validators = w.g.validator_pubkeys().unwrap();
    let mut forged = w.branch.clone();
    let mut sig = forged[1].header.proposer_sig;
    sig[0] ^= 0x01;
    forged[1].header.set_signature(sig);
    for i in 2..forged.len() {
        forged[i] = unexecuted_child(&forged[i - 1].clone(), &w.keys, &validators);
    }
    assert_refused(&x, &forged, "signature").await;
}

// ═════════════════════════════════════════════════════════════════════════════
// Execution-time scan isolation and historical-view equivalence (staking).
//
// `WithdrawUnbonded` is a real transaction path whose execution PREFIX-SCANS
// `UNBONDING_DELEGATIONS` by delegator and deletes every completed entry it
// finds (`StakingExecutor::v_get_unbondings_by_delegator`). `Undelegate`
// inserts entries keyed `delegator ‖ completion height ‖ validator`, so two in
// one block for one validator OVERWRITE the same key. Unbonding period 0: every
// entry is complete from the block that made it.
// ═════════════════════════════════════════════════════════════════════════════

use sumchain_primitives::staking::{
    CreateValidatorData, DelegateData, StakingOperation, StakingParams, StakingTxData,
    UndelegateData, WithdrawUnbondedData,
};

fn staking_tx(
    from: &KeyPair,
    nonce: u64,
    operation: StakingOperation,
    data: Vec<u8>,
) -> SignedTransaction {
    let tx = TransactionV2::staking(
        CHAIN_ID,
        from.address(),
        1_000,
        nonce,
        StakingTxData { operation, data },
    );
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(from))
}

/// The staking executor's key for an address-registered validator.
fn staking_validator_key(k: &KeyPair) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(k.address().as_bytes());
    out
}

fn create_validator(v: &KeyPair, nonce: u64) -> SignedTransaction {
    let data = bincode::serialize(&CreateValidatorData {
        stake: 10_000,
        commission_bps: 0,
        metadata: vec![],
    })
    .unwrap();
    staking_tx(v, nonce, StakingOperation::CreateValidator, data)
}

fn delegate(d: &KeyPair, nonce: u64, v: &KeyPair, amount: u128) -> SignedTransaction {
    let data = bincode::serialize(&DelegateData {
        validator_pubkey: staking_validator_key(v),
        amount,
    })
    .unwrap();
    staking_tx(d, nonce, StakingOperation::Delegate, data)
}

fn undelegate(d: &KeyPair, nonce: u64, v: &KeyPair, amount: u128) -> SignedTransaction {
    let data = bincode::serialize(&UndelegateData {
        validator_pubkey: staking_validator_key(v),
        amount,
    })
    .unwrap();
    staking_tx(d, nonce, StakingOperation::Undelegate, data)
}

fn withdraw(d: &KeyPair, nonce: u64) -> SignedTransaction {
    let data = bincode::serialize(&WithdrawUnbondedData {
        validator_pubkey: None,
    })
    .unwrap();
    staking_tx(d, nonce, StakingOperation::WithdrawUnbonded, data)
}

struct StakingWorld {
    g: Genesis,
    prefix: Vec<Block>,
    canonical: Vec<Block>,
    branch: Vec<Block>,
    d: KeyPair,
    d2: KeyPair,
}

/// Fork parent F = height 4:
///
/// * prefix: V registers; D and D2 delegate; D undelegates 10 (u_a, h3) and 20
///   (u_b, h4); D2 undelegates 5 (a neighbouring delegator's row, at h3).
/// * canonical suffix (abandoned): D withdraws (DELETES u_a, u_b), then
///   undelegates 30 (u_c, h6: a canonical-only row).
/// * replacement: D undelegates 40 (u_d, h5); undelegates 50 and 60 in one block
///   (u_e, h6: one key OVERWRITTEN within the block); WITHDRAWS — which must see
///   exactly u_a, u_b (restored), u_d, u_e (speculative) and not u_c; undelegates
///   70 (u_f, h8); WITHDRAWS again — which must see only u_f, the earlier
///   speculative deletions hidden.
fn staking_world() -> StakingWorld {
    let keys = vec![key(1), key(2)];
    let v = key(0x71);
    let d = key(0x72);
    let d2 = key(0x73);
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        staking: Some(StakingParams {
            min_validator_stake: 1_000,
            unbonding_period: 0,
            ..StakingParams::default()
        }),
        ..ChainParams::with_contracts_enabled()
    };
    let mut alloc = HashMap::new();
    for k in keys.iter().chain([&v, &d, &d2]) {
        alloc.insert(k.address().to_base58(), 1_000_000_000u128);
    }
    let g = Genesis::new(
        CHAIN_ID,
        0,
        keys.iter().map(|k| k.public_key().to_base58()).collect(),
        alloc,
        params,
    );
    let mut a = Builder::new(&g, &keys, 0);
    let mut b = Builder::new(&g, &keys, 1);
    let prefix = vec![
        a.produce(vec![create_validator(&v, 0)]),
        a.produce(vec![delegate(&d, 0, &v, 1_000), delegate(&d2, 0, &v, 500)]),
        a.produce(vec![undelegate(&d, 1, &v, 10), undelegate(&d2, 1, &v, 5)]),
        a.produce(vec![undelegate(&d, 2, &v, 20)]),
    ];
    for blk in &prefix {
        b.follow(blk);
    }
    let canonical = vec![
        a.produce(vec![withdraw(&d, 3)]),
        a.produce(vec![undelegate(&d, 4, &v, 30)]),
    ];
    let branch = vec![
        b.produce(vec![undelegate(&d, 3, &v, 40)]),
        b.produce(vec![undelegate(&d, 4, &v, 50), undelegate(&d, 5, &v, 60)]),
        b.produce(vec![withdraw(&d, 6)]),
        b.produce(vec![undelegate(&d, 7, &v, 70)]),
        b.produce(vec![withdraw(&d, 8)]),
    ];
    StakingWorld {
        g,
        prefix,
        canonical,
        branch,
        d,
        d2,
    }
}

fn unbonding_keys(db: &Database) -> BTreeSet<Vec<u8>> {
    db.iter_checked_from(cf::UNBONDING_DELEGATIONS, None)
        .unwrap()
        .map(|e| e.unwrap().0.into_vec())
        .collect()
}

fn unbonding_key(delegator: &KeyPair, height: u64, validator: &KeyPair) -> Vec<u8> {
    let mut k = Vec::with_capacity(72);
    let mut d = [0u8; 32];
    d[..20].copy_from_slice(delegator.address().as_bytes());
    k.extend_from_slice(&d);
    k.extend_from_slice(&height.to_be_bytes());
    k.extend_from_slice(&staking_validator_key(validator));
    k
}

#[tokio::test]
async fn an_execution_time_scan_sees_exactly_the_fork_parent_plus_earlier_replacement_blocks() {
    reset_hooks();
    let w = staking_world();
    let v = key(0x71);
    let x = Node::new(&w.g);
    for blk in w.prefix.iter().chain(&w.canonical) {
        x.import(blk).await.unwrap();
    }
    // The canonical head: u_a, u_b withdrawn; u_c present; D2's row present.
    let at_head = unbonding_keys(&x.db);
    assert!(
        at_head.contains(&unbonding_key(&w.d, 6, &v)),
        "u_c exists on the canonical head"
    );
    assert!(
        !at_head.contains(&unbonding_key(&w.d, 3, &v)),
        "u_a was withdrawn on the canonical head"
    );

    for b in &w.branch[..w.branch.len() - 1] {
        archive(&x.db, b);
    }
    x.import(w.branch.last().unwrap())
        .await
        .expect("the replacement is adopted");

    // A node that followed the winner from genesis.
    let winner = Node::new(&w.g);
    for blk in w.prefix.iter().chain(&w.branch) {
        winner.import(blk).await.unwrap();
    }
    assert_same_database(&x.db, &winner.db, &w.canonical, "staking fork");
    // Both withdrawals succeeded, which they do only if the first scan found
    // the restored and speculative rows and the second found u_f.
    let receipts = sumchain_storage::ReceiptStore::new(&winner.db);
    for idx in [2usize, 4] {
        let tx = &w.branch[idx].transactions[0];
        let r = receipts.get(&tx.hash()).unwrap().unwrap();
        assert!(
            r.is_success(),
            "replacement withdrawal {idx} must succeed: {:?}",
            r.status
        );
    }
    // And they deleted exactly what they should: every D entry is gone, u_c
    // never reappears, and D2's neighbouring row is untouched.
    assert_eq!(
        unbonding_keys(&x.db),
        BTreeSet::from([unbonding_key(&w.d2, 3, &v)]),
        "only the neighbouring delegator's row remains"
    );
}

/// The consensus-readable state families: everything a block's execution can
/// read. The rest are block, index, receipt and journal records written at
/// publication, which execution never reads.
fn state_families() -> Vec<&'static str> {
    let publication = [
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
        cf::APPLICATION_JOURNAL,
    ];
    ALL_CFS
        .iter()
        .copied()
        .filter(|c| !publication.contains(c))
        .collect()
}

/// `META` keys written by publication or startup rather than by execution.
fn publication_meta(key: &[u8]) -> bool {
    use sumchain_storage::schema::meta_keys;
    [
        meta_keys::LATEST_BLOCK_HASH,
        meta_keys::LATEST_BLOCK_HEIGHT,
        meta_keys::GENESIS_HASH,
        meta_keys::CHAIN_ID,
        meta_keys::FINALIZED_HEIGHT,
        meta_keys::FINALIZED_HASH,
        sumchain_storage::journal::FORMAT_HIGH_WATER_META_KEY,
        sumchain_storage::journal::UNDO_HISTORY_FLOOR_META_KEY,
    ]
    .contains(&key)
}

fn reference_rows(db: &Database, cf_name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.iter_checked_from(cf_name, None)
        .unwrap()
        .map(|e| {
            let (k, v) = e.unwrap();
            (k.into_vec(), v.into_vec())
        })
        .filter(|(k, _)| cf_name != cf::META || !publication_meta(k))
        .collect()
}

/// The branch view over `db` presents exactly `reference` for every state
/// family: every point read (keys from either side and from the layer, so
/// absent, deleted and overwritten keys are all probed), a full scan, and a
/// scan from every reference key.
fn assert_view_equals(
    layer: &sumchain_storage::branch::BranchState,
    db: &Database,
    reference: &Database,
    what: &str,
) {
    for cf_name in state_families() {
        let expect = reference_rows(reference, cf_name);
        let mut keys: BTreeSet<Vec<u8>> = expect.iter().map(|(k, _)| k.clone()).collect();
        for (k, _) in reference_rows(db, cf_name) {
            keys.insert(k);
        }
        for (c, k, _) in layer.entries() {
            if c == cf_name {
                keys.insert(k.to_vec());
            }
        }
        for k in &keys {
            if cf_name == cf::META && publication_meta(k) {
                continue;
            }
            assert_eq!(
                layer.get(db, cf_name, k).unwrap(),
                reference.get(cf_name, k).unwrap(),
                "{what}: point read {cf_name} {}",
                hex::encode(k)
            );
        }
        let scanned = |start: Option<&[u8]>| -> Vec<(Vec<u8>, Vec<u8>)> {
            layer
                .iter_checked_from(db, cf_name, start)
                .unwrap()
                .map(|e| {
                    let (k, v) = e.unwrap();
                    (k.into_vec(), v.into_vec())
                })
                .filter(|(k, _)| cf_name != cf::META || !publication_meta(k))
                .collect()
        };
        assert_eq!(scanned(None), expect, "{what}: full scan of {cf_name}");
        for (i, (start, _)) in expect.iter().enumerate().step_by(3) {
            assert_eq!(
                scanned(Some(start)),
                expect[i..].to_vec(),
                "{what}: scan of {cf_name} from a key"
            );
        }
    }
}

fn reconstruct(db: &Database, abandoned: &[Block]) -> sumchain_storage::branch::BranchState {
    use sumchain_storage::journal::{ActivationSource, JournalActivation};
    let act =
        JournalActivation::resolve(db, ActivationSource::from_configured_height(Some(1))).unwrap();
    let mut layer = sumchain_storage::branch::BranchState::new(1 << 30);
    for b in abandoned.iter().rev() {
        let j = act
            .load_for_revert(db, b.height(), &b.hash())
            .unwrap()
            .unwrap();
        layer.restore_parent(db, &j).unwrap();
    }
    layer
}

/// The reconstructed fork parent equals an INDEPENDENT database that never went
/// past the fork parent — every state family, point reads and scans, including
/// rows the canonical suffix created, deleted and overwrote — and still does
/// after the database is reopened. Then, block by block, the view after each
/// speculative replacement block equals a node that executed the same blocks
/// for real.
#[tokio::test]
async fn the_historical_view_equals_an_independent_reference_database() {
    reset_hooks();
    let w = staking_world();
    let x = Node::new(&w.g);
    let reference = Node::new(&w.g);
    for blk in &w.prefix {
        x.import(blk).await.unwrap();
        reference.import(blk).await.unwrap();
    }
    for blk in &w.canonical {
        x.import(blk).await.unwrap();
    }
    let layer = reconstruct(&x.db, &w.canonical);
    assert!(layer.restored_blocks() == 2 && !layer.is_empty());
    assert_view_equals(&layer, &x.db, &reference.db, "fork parent");

    // Reopen the canonical node's database and reconstruct again.
    let x = x.restart(&w.g);
    let layer = reconstruct(&x.db, &w.canonical);
    assert_view_equals(&layer, &x.db, &reference.db, "fork parent after reopen");

    // Each speculative block against a node that executed it for real.
    let validators = w.g.validator_pubkeys().unwrap();
    let executor = BlockExecutor::new(x.state.clone(), x.db.clone(), w.g.params.clone());
    let mut layer = Arc::new(layer);
    let mut accumulator = w.prefix.last().unwrap().header.state_root;
    for (i, b) in w.branch.iter().enumerate() {
        let spec = {
            let exec = executor
                .execute_block_on_branch(b, accumulator, &validators, layer.clone())
                .unwrap();
            let (executed, _, _) = exec.into_parts();
            executed
                .accept_imported(b)
                .unwrap()
                .into_speculative()
                .unwrap()
        };
        Arc::get_mut(&mut layer)
            .expect("no reference to the layer survives a block")
            .absorb_net_writes(spec.net_writes())
            .unwrap();
        accumulator = spec.accumulator();
        reference.import(b).await.unwrap();
        assert_view_equals(
            &layer,
            &x.db,
            &reference.db,
            &format!("after replacement block {i}"),
        );
    }
    // Nothing of this reached the canonical node's database.
    assert_eq!(x.db_head().hash(), w.canonical.last().unwrap().hash());
}

/// The commit is pinned to the canonical head the branch was validated
/// against: if the head moved meanwhile, nothing is applied and the refusal is
/// a retry, not a rejection of the branch and not a fail-stop.
#[tokio::test]
async fn a_switch_validated_against_a_moved_head_is_not_applied() {
    reset_hooks();
    let w = world(2, 3, 4);
    let x = w.canonical_node().await;
    let head = x.db_head();
    let before = digest_excluding(&x.db, &w.branch);
    for b in &w.branch[..w.branch.len() - 1] {
        archive(&x.db, b);
    }
    let db = x.db.clone();
    let ancestor = w.prefix.last().unwrap().hash();
    sumchain_consensus::branch_switch::failpoints::set_before_head_pin(Some(Box::new(move || {
        BlockStore::new(&db).set_latest_hash(&ancestor).unwrap();
    })));
    let err = x
        .import(w.branch.last().unwrap())
        .await
        .unwrap_err()
        .to_string();
    sumchain_consensus::branch_switch::failpoints::set_before_head_pin(None);
    assert!(err.contains("canonical head moved"), "{err}");
    assert!(
        x.engine.halted_reason().is_none(),
        "a moved head is not a fail-stop"
    );
    // Undo the simulated foreign write, then nothing else changed.
    BlockStore::new(&x.db)
        .set_latest_hash(&head.hash())
        .unwrap();
    assert_eq!(digest_excluding(&x.db, &w.branch), before);
    assert_eq!(x.engine.best_block_hash(), head.hash());
}
