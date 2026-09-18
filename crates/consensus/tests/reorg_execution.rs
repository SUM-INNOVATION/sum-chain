//! Executing a reorg: ancestor-based unwind, branch apply, activation
//! boundaries, interruption, and the refusal that keeps an undo off state it was
//! not derived from.
//!
//! # What these tests drive
//!
//! `sumchain_consensus::reorg::execute_reorg` and the machinery under it —
//! `sumchain_state::reorg_undo` for the journal-driven unwind,
//! `sumchain_storage::candidate::stage_deindex` for the publication rows the
//! journal does not cover.
//!
//! Every block reaches canonical state through the REAL publication path:
//! `execute_block` → fill in the computed root → `accept_produced`/
//! `accept_imported` → `publish`. There is no hand-written commit anywhere in
//! this file, and there could not be: `ApplicationOverlay::into_batch` is
//! crate-private to `sumchain-storage`, so the only route from a candidate to
//! canonical state is through acceptance.
//!
//! # The two-node shape
//!
//! A competing branch cannot be built on the node that is going to reorg to it —
//! the node would have to be on that branch to execute it. So these tests stand
//! up two independent databases over the same genesis, let each build its own
//! branch, and then copy the loser's BLOCKS rows into the winner, which is
//! exactly what `archive_noncanonical` does when a side branch arrives over the
//! network. `plan_reorg` then has a real fork to resolve.
//!
//! Genesis is identical across the two by construction: the same header fields
//! and the same (empty) transaction set produce the same computed root, which is
//! asserted rather than assumed.

use std::collections::BTreeMap;
use std::sync::Arc;

use sumchain_consensus::reorg::{
    accumulator_of, apply_branch, execute_reorg, plan_reorg, recorded_head, resume, ReorgPlan,
};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Block, BlockHeader, Hash, SignedTransaction, Transaction};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::reorg_undo::{
    stage_branch_unwind, BranchJournal, JournalLookup, SubsystemJournals, UndoRecord, UndoRefusal,
};
use sumchain_state::state::StateManager;
use sumchain_storage::schema::BlockStore;
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const NO_FINALITY: u64 = 0;
const DEEP: u64 = 1024;
const NO_VALIDATORS: &[[u8; 32]] = &[];

/// Fixed timestamp, so two independently-built genesis blocks are byte-equal.
const GENESIS_TS: u64 = 1_000;

/// The column families a reorg must NOT be compared on.
///
/// Both are keyed by the hash of their own contents, so an abandoned branch's
/// rows there cannot shadow the adopted branch's, and keeping them is what makes
/// reorging BACK possible at all — `plan_reorg` walks parents out of `BLOCKS`,
/// and a branch deleted on abandonment can never be re-adopted. This mirrors
/// `archive_noncanonical`.
const BRANCH_SAFE_CFS: &[&str] = &[cf::BLOCKS, cf::TRANSACTIONS];

/// Everything else. Derived from `ALL_CFS` rather than listed, so a column
/// family added to the database is covered by these tests the day it appears
/// instead of the day someone remembers to add it here.
fn convergent_cfs() -> Vec<&'static str> {
    sumchain_storage::db::ALL_CFS
        .iter()
        .copied()
        .filter(|c| !BRANCH_SAFE_CFS.contains(c))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Column families the JOURNAL does not own, because the reorg handles them
/// another way.
///
/// `BLOCKS` and `TRANSACTIONS` are branch-safe and kept. `BLOCK_HEIGHT`,
/// `RECEIPTS` and the two address indexes are removed by `stage_deindex` and
/// rewritten by `publish`. `META` carries the head, which the unwind moves
/// explicitly. The four `*_state_diffs` families ARE the journals.
///
/// Everything not listed here is state, and a journal that does not cover it
/// cannot undo a block that wrote it.
const NOT_JOURNALLED: &[&str] = &[
    cf::BLOCKS,
    cf::TRANSACTIONS,
    cf::BLOCK_HEIGHT,
    cf::RECEIPTS,
    cf::TX_BY_SENDER,
    cf::TX_BY_RECIPIENT,
    cf::META,
    cf::STATE_DIFFS,
    cf::CONTRACT_STATE_DIFFS,
    cf::COMPUTE_POOL_STATE_DIFFS,
    cf::BEACON_STATE_DIFFS,
];

fn state_cfs() -> Vec<&'static str> {
    sumchain_storage::db::ALL_CFS
        .iter()
        .copied()
        .filter(|c| !NOT_JOURNALLED.contains(c))
        .collect()
}

/// A journal that satisfies the contract in full, built by OBSERVATION.
///
/// # Why this exists, and what it is not
///
/// The four per-subsystem journals that exist today cover account, contract,
/// compute-pool and beacon rows. They do not cover every column family a block
/// writes — see
/// [`the_subsystem_journals_do_not_cover_every_family_a_block_writes`], which
/// measures the gap rather than asserting it. Testing the consumer against them
/// would therefore be testing the producer's omissions, and every convergence
/// assertion below would fail for a reason that has nothing to do with the
/// unwind.
///
/// So this is a REFERENCE ORACLE, not an encoding. It snapshots every state
/// column family immediately before and immediately after a block is published
/// and takes the difference. That difference is ground truth — it is by
/// definition what the block did — and it is expressed in exactly the
/// `(cf, key, before, after)` shape the contract specifies, addressed by
/// `(height, block hash)`. Nothing here invents a wire format, a tag, or a
/// version: those are the producer's, and the consumer never sees them.
///
/// A generic application journal built from `ApplicationOverlay` pre-images is
/// the production answer to the same thing, and it is being built elsewhere.
/// When it lands it replaces this type and nothing else.
///
/// Record order is capture order within a family and families in a fixed order,
/// which is stable but NOT the order the block applied them. That is enough here
/// because a snapshot diff has at most one record per key, so within one block
/// no two records can interact. A real journal has more than one record per key
/// and must preserve application order; see the contract note on ordering.
#[derive(Default)]
struct ObservedJournal {
    per_block: BTreeMap<(u64, Hash), Vec<UndoRecord>>,
}

impl ObservedJournal {
    fn snapshot(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
        let mut out = BTreeMap::new();
        for family in state_cfs() {
            for (k, v) in db.iter(family).expect("iterate column family") {
                out.insert((family.to_string(), k.into_vec()), v.into_vec());
            }
        }
        out
    }

    fn record(
        &mut self,
        height: u64,
        hash: Hash,
        before: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
        after: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
    ) {
        let mut keys: Vec<&(String, Vec<u8>)> = before.keys().chain(after.keys()).collect();
        keys.sort();
        keys.dedup();
        let records = keys
            .into_iter()
            .filter(|k| before.get(*k) != after.get(*k))
            .map(|k| UndoRecord {
                cf: k.0.clone(),
                key: k.1.clone(),
                before: before.get(k).cloned(),
                after: after.get(k).cloned(),
            })
            .collect();
        self.per_block.insert((height, hash), records);
    }
}

impl BranchJournal for ObservedJournal {
    fn lookup(&self, height: u64, block_hash: &Hash) -> JournalLookup {
        match self.per_block.get(&(height, *block_hash)) {
            Some(r) => JournalLookup::Present(r.clone()),
            None => JournalLookup::Absent,
        }
    }
    fn rows(&self, height: u64, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
        // The oracle itself lives in memory, but the rows the PUBLISHER wrote
        // are on disk and must still be consumed: a journal row that outlives
        // the block it describes is an undo record for a block on no chain.
        sumchain_state::reorg_undo::subsystem_journal_rows(height, block_hash)
    }
}

struct Node {
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    dir: TempDir,
    /// Contract-conformant journal for every block this node published.
    ///
    /// A `RefCell` because `produce` takes `&self` like every other helper here
    /// and the alternative — threading `&mut` through the whole harness — would
    /// obscure the tests for no gain in a single-threaded fixture.
    observed: std::cell::RefCell<ObservedJournal>,
}

impl Node {
    fn new(params: ChainParams) -> Self {
        let dir = TempDir::new().expect("temp dir");
        Self::open_at(dir, params)
    }

    fn open_at(dir: TempDir, params: ChainParams) -> Self {
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor = BlockExecutor::new(state.clone(), db.clone(), params);
        Node {
            db,
            state,
            executor,
            dir,
            observed: std::cell::RefCell::new(ObservedJournal::default()),
        }
    }

    /// Close and reopen the database, keeping the directory.
    ///
    /// This is the crash: every handle is dropped, RocksDB is reopened from what
    /// is on disk, and the in-memory accumulator is gone. A test that "restarts"
    /// without dropping the `Database` is testing nothing — it still holds the
    /// memtable and the `StateManager`'s cached root.
    fn restart(self, params: ChainParams) -> Node {
        let Node {
            db,
            state,
            executor,
            dir,
            observed,
        } = self;
        // Every handle, explicitly and in order. The executor holds its own
        // `Arc<Database>`, and RocksDB refuses to reopen a directory whose lock
        // is still held — a "restart" that left one alive would be testing a
        // warm process, which is the opposite of the point.
        drop(executor);
        drop(state);
        drop(db);
        let reopened = Node::open_at(dir, params);
        // The journal survives the restart, because a real one is on disk. The
        // node's in-memory accumulator does not, which is the thing under test.
        *reopened.observed.borrow_mut() = observed.into_inner();
        reopened
    }

    fn seed(&self, kp: &KeyPair, balance: u128) {
        sumchain_storage::StateStore::new(&self.db)
            .put_account(
                &kp.address(),
                &sumchain_storage::schema::AccountState { balance, nonce: 0 },
            )
            .expect("seed account");
    }

    /// Produce and PUBLISH one block on top of `parent`, the way a proposer
    /// does. The producer's own order: execute, then write the computed root
    /// into the header it is about to sign, then accept, then publish.
    fn produce(
        &self,
        parent: Option<&Block>,
        proposer: &KeyPair,
        txs: Vec<SignedTransaction>,
    ) -> Block {
        let (parent_hash, height) = match parent {
            Some(p) => (p.hash(), p.height() + 1),
            None => (Hash::ZERO, 0),
        };
        let header = BlockHeader::new(
            parent_hash,
            height,
            GENESIS_TS + height,
            Hash::ZERO,
            Hash::ZERO,
            *proposer.public_key().as_bytes(),
        );
        let mut block = Block::new(header, txs);

        let before = ObservedJournal::snapshot(&self.db);
        let execution = self
            .executor
            .execute_block(&block, self.state.state_root(), NO_VALIDATORS)
            .expect("execute_block");
        block.header.state_root = execution.computed_root();

        let (executed, _account_diff, _contract_diff) = execution.into_parts();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        let after = ObservedJournal::snapshot(&self.db);
        self.observed
            .borrow_mut()
            .record(height, block.hash(), &before, &after);
        block
    }

    /// Adopt the journals another node recorded for the blocks it published.
    ///
    /// A node that receives a branch over the network does not have its undo
    /// journals — the producer wrote them into its own database. In production
    /// the adopting node derives them by EXECUTING the branch, which it does
    /// anyway, and the publisher writes them. Here the oracle is copied across,
    /// which models the same thing without pretending the copy is the mechanism.
    fn adopt_journals_from(&self, other: &Node) {
        let src = other.observed.borrow();
        let mut dst = self.observed.borrow_mut();
        for (k, v) in &src.per_block {
            dst.per_block.insert(*k, v.clone());
        }
    }

    /// Retain a block built elsewhere, without touching canonical state.
    ///
    /// Only `BLOCKS[block_hash]`, which is keyed by the block's own hash and so
    /// cannot shadow anything. This is what an arriving side branch looks like
    /// before fork choice has said anything about it, and it is what
    /// `plan_reorg` walks.
    fn retain(&self, block: &Block) {
        BlockStore::new(&self.db).put(block).expect("retain block");
    }

    fn head(&self) -> Option<Block> {
        recorded_head(&BlockStore::new(&self.db)).expect("read head")
    }

    /// Every row in the families a reorg must converge on.
    fn snapshot(&self) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
        let mut out = BTreeMap::new();
        for family in convergent_cfs() {
            for (k, v) in self.db.iter(family).expect("iterate column family") {
                out.insert((family.to_string(), k.into_vec()), v.into_vec());
            }
        }
        out
    }

    fn balance(&self, addr: &Address) -> u128 {
        self.state.get_balance(addr).unwrap_or(0)
    }

    /// The contract-conformant journal for the blocks this node published.
    ///
    /// Returns a borrow guard, so a call site passes `&*node.journals()`.
    fn journals(&self) -> std::cell::Ref<'_, ObservedJournal> {
        self.observed.borrow()
    }

    /// The adapter over the four per-subsystem journals that exist today.
    ///
    /// Used where the SUBJECT is that adapter — its corruption reporting, its
    /// per-hash addressing, and the measured gap between what it covers and what
    /// a block writes. Not used for convergence, because it does not cover
    /// everything a block writes and the convergence tests would then be
    /// measuring the producer instead of the unwind.
    fn subsystem_journals(&self) -> SubsystemJournals<'_> {
        SubsystemJournals::new(&self.db)
    }
}

fn transfer(
    from: &KeyPair,
    to: &Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), *to, amount, fee, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// Report the first few differing rows, so a failure names what diverged rather
/// than only that something did.
fn describe_divergence(
    left: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
    right: &BTreeMap<(String, Vec<u8>), Vec<u8>>,
) -> String {
    let mut keys: Vec<&(String, Vec<u8>)> = left.keys().collect();
    keys.extend(right.keys());
    keys.sort();
    keys.dedup();
    let mut lines = Vec::new();
    for k in keys {
        if left.get(k) != right.get(k) {
            lines.push(format!(
                "  {} / {}: {:?} vs {:?}",
                k.0,
                hex::encode(&k.1),
                left.get(k).map(hex::encode),
                right.get(k).map(hex::encode),
            ));
        }
    }
    if lines.len() > 12 {
        lines.truncate(12);
        lines.push("  …".to_string());
    }
    lines.join("\n")
}

/// Deterministic keys, so a failing run reproduces.
fn key(n: u8) -> KeyPair {
    KeyPair::from_bytes([n; 32])
}

/// Two nodes on an identical genesis, with identical seeded balances.
///
/// Returns `(node_a, node_b, genesis)`. The genesis blocks are asserted equal:
/// without that these tests would be comparing two different chains and every
/// later assertion would be meaningless.
fn two_nodes(params: ChainParams, seeds: &[(&KeyPair, u128)]) -> (Node, Node, Block) {
    let a = Node::new(params.clone());
    let b = Node::new(params);
    let proposer = key(9);
    for (kp, bal) in seeds {
        a.seed(kp, *bal);
        b.seed(kp, *bal);
    }
    let ga = a.produce(None, &proposer, Vec::new());
    let gb = b.produce(None, &proposer, Vec::new());
    assert_eq!(
        ga.hash(),
        gb.hash(),
        "the two nodes must share a genesis byte-for-byte, or there is no common ancestor"
    );
    (a, b, ga)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Ancestor-based reorg across multiple blocks
// ─────────────────────────────────────────────────────────────────────────────

/// Three blocks abandoned, two adopted, and the node ends byte-identical to the
/// node that built the branch it adopted.
///
/// The convergence assertion is the strong form. Checking a few balances would
/// pass with stale receipts, a height index still pointing at an abandoned
/// block, or an undo journal left behind for a block on no chain — all of which
/// are wrong, and none of which a balance check can see.
#[test]
fn a_multi_block_reorg_converges_with_the_branch_it_adopted() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    // Branch A: three blocks, alice paying carol.
    let mut branch_a = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..3u64 {
        let blk = a.produce(
            Some(&parent),
            &proposer,
            vec![transfer(
                &alice,
                &carol.address(),
                1_000 + n as u128,
                500,
                n,
            )],
        );
        parent = blk.clone();
        branch_a.push(blk);
    }

    // Branch B: two blocks, bob paying carol. Disjoint senders, so no
    // transaction is on both branches and the receipt sets cannot alias.
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..2u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 7_000 + n as u128, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }

    // B's branch arrives at A.
    for blk in &branch_b {
        a.retain(blk);
    }

    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        DEEP,
    )
    .expect("plan");
    assert_eq!(plan.ancestor_hash, genesis.hash());
    assert_eq!(plan.depth(), 3, "three blocks abandoned");
    assert_eq!(plan.new_branch.len(), 2, "two blocks adopted");

    let outcome = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &*a.journals(),
    )
    .expect("execute_reorg");

    assert_eq!(outcome.unwound.blocks, 3);
    assert!(outcome.unwound.records > 0, "the unwind replayed nothing");
    assert_eq!(
        outcome.unwound.checks, outcome.unwound.records,
        "every replayed record must have been validated against current state"
    );
    assert_eq!(outcome.applied, 2);
    assert_eq!(
        outcome.force_adopted, 0,
        "the adopted branch's roots must be REPRODUCED by replay, not force-adopted \
         under the historical compatibility window; a force-adopted reorg proves nothing \
         about the state it left behind"
    );
    assert_eq!(outcome.verified, 2);

    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(
        left,
        right,
        "the reorged node did not converge with the branch it adopted:\n{}",
        describe_divergence(&left, &right)
    );
    assert_eq!(a.head().map(|h| h.hash()), Some(branch_b[1].hash()));
    assert_eq!(a.state.state_root(), accumulator_of(&branch_b[1]));
    assert_eq!(a.balance(&carol.address()), b.balance(&carol.address()));
}

/// The unwind alone, with nothing applied, restores the fork point EXACTLY.
///
/// Separated from the test above because convergence with another node could in
/// principle be reached by a wrong unwind followed by a compensating apply. This
/// one stops halfway and compares against a snapshot taken at the fork point on
/// the same database — no second node, no second chain, no room for the two
/// errors to cancel.
#[test]
fn unwinding_a_branch_restores_the_fork_point_byte_for_byte() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let at_fork = node.snapshot();

    let mut branch = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..4u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }
    assert_ne!(
        node.snapshot(),
        at_fork,
        "the branch must have changed state"
    );

    // The unwind, as `execute_reorg` composes it: one batch carrying the state
    // restore, the de-indexing and the head reset.
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(&node.db, &mut batch, &branch, &*node.journals())
        .expect("unwind must be accepted");
    for blk in &branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head reset");
    batch.commit().expect("commit");

    assert_eq!(report.blocks, 4);
    let after = node.snapshot();
    assert_eq!(
        after,
        at_fork,
        "unwinding did not restore the fork point:\n{}",
        describe_divergence(&after, &at_fork)
    );
}

/// Unwinding must run NEWEST-first.
///
/// Four blocks all move the same account, so each block's pre-image is the
/// previous block's post-image. Unwound oldest-first, the last record written
/// would be the OLDEST block's pre-image applied on top of state the newer
/// blocks had already restored — the account would land on an intermediate
/// value, not the fork point.
///
/// Rather than assert the direction by reading the source, this reproduces the
/// wrong order explicitly and shows it lands somewhere else, then shows the real
/// unwind lands on the fork point.
#[test]
fn unwinding_oldest_first_would_land_on_an_intermediate_value() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let at_fork = node.balance(&alice.address());

    let mut branch = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..4u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }

    // The WRONG order: blocks oldest-first, records forward within each block.
    // Written out here rather than exercised through the real API, which has no
    // way to express it — that is the point.
    let journals = node.journals();
    let mut batch = node.db.batch();
    for blk in &branch {
        let JournalLookup::Present(records) = journals.lookup(blk.height(), &blk.hash()) else {
            panic!("every published block must have a journal");
        };
        for r in &records {
            match &r.before {
                Some(v) => batch.put(&r.cf, &r.key, v).unwrap(),
                None => batch.delete(&r.cf, &r.key).unwrap(),
            }
        }
    }
    batch.commit().unwrap();

    assert_ne!(
        node.balance(&alice.address()),
        at_fork,
        "if oldest-first happened to land on the fork point, this test is not \
         exercising the ordering it claims to"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Competing branches at the same height — the issue #253 shape
// ─────────────────────────────────────────────────────────────────────────────

/// Two siblings at one height, reorged to and away from, with no cross
/// contamination.
///
/// This is the shape issue #253 is about. Both blocks are at height 1 over the
/// same genesis, so a journal keyed by height alone gives them ONE undo row: the
/// second import overwrites the first's, and the reorg then reverts the block it
/// is adopting while leaving the abandoned one applied forever. Keyed by block
/// hash, each keeps its own, and switching back and forth is lossless.
///
/// Asserted by round trip rather than by inspecting the journal rows: A → B → A
/// must return the node to a state byte-identical to where it started, and then
/// A → B again must reproduce B exactly.
#[test]
fn two_siblings_at_one_height_reorg_to_and_from_without_contamination() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    let block_a = a.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 4_321, 500, 0)],
    );
    let block_b = b.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&bob, &carol.address(), 8_765, 500, 0)],
    );
    assert_eq!(block_a.height(), block_b.height(), "must be siblings");
    assert_ne!(block_a.hash(), block_b.hash(), "must be distinct siblings");

    let on_a = a.snapshot();
    let on_b = b.snapshot();
    assert_ne!(on_a, on_b);

    // Each node retains the other's block, so both can plan either way — and
    // each takes the other's undo journal with it. A node that receives a
    // branch derives its journals by executing it, which it does anyway, and its
    // publisher writes them; copying the oracle across models the same thing
    // without pretending the copy is the mechanism. The two agree because the
    // fork point is byte-identical on both nodes, which the first switch below
    // asserts before any of it is relied on.
    a.retain(&block_b);
    b.retain(&block_a);
    a.adopt_journals_from(&b);
    b.adopt_journals_from(&a);

    let switch = |node: &Node, from: &Block, to: &Block| {
        let store = BlockStore::new(&node.db);
        let plan = plan_reorg(&store, from, to, NO_FINALITY, DEEP).expect("plan");
        assert_eq!(plan.ancestor_hash, genesis.hash());
        assert_eq!(plan.depth(), 1);
        let outcome = execute_reorg(
            &node.db,
            &node.state,
            &node.executor,
            &plan,
            NO_VALIDATORS,
            &*node.journals(),
        )
        .expect("execute_reorg");
        assert_eq!(
            outcome.force_adopted, 0,
            "roots must be reproduced, not forgiven"
        );
        outcome
    };

    // A → B.
    switch(&a, &block_a, &block_b);
    let a_on_b = a.snapshot();
    assert_eq!(
        a_on_b,
        on_b,
        "after switching to B, A must hold exactly B's state:\n{}",
        describe_divergence(&a_on_b, &on_b)
    );

    // B → A, on the OTHER node, from the other direction.
    switch(&b, &block_b, &block_a);
    let b_on_a = b.snapshot();
    assert_eq!(
        b_on_a,
        on_a,
        "after switching to A, B must hold exactly A's state:\n{}",
        describe_divergence(&b_on_a, &on_a)
    );

    // And back again on A: B → A must return A to where it began.
    switch(&a, &block_b, &block_a);
    let a_home = a.snapshot();
    assert_eq!(
        a_home,
        on_a,
        "reorging away and back did not return A to its own branch:\n{}",
        describe_divergence(&a_home, &on_a)
    );
    assert_eq!(a.head().map(|h| h.hash()), Some(block_a.hash()));
}

/// The sibling journals are addressed separately, which is what makes the round
/// trip above possible.
///
/// The round trip is the behavioural proof; this is the mechanism, asserted
/// directly so a regression names the cause rather than only the symptom.
#[test]
fn siblings_at_one_height_do_not_share_an_undo_journal() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    let block_a = a.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 4_321, 500, 0)],
    );
    let block_b = b.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&bob, &carol.address(), 8_765, 500, 0)],
    );

    // Both journals, read from the node that published each. Keyed by hash, the
    // two rows are distinct addresses; keyed by height they would be one.
    let ja = match a.subsystem_journals().lookup(1, &block_a.hash()) {
        JournalLookup::Present(r) => r,
        other => panic!("A's journal missing: {other:?}"),
    };
    let jb = match b.subsystem_journals().lookup(1, &block_b.hash()) {
        JournalLookup::Present(r) => r,
        other => panic!("B's journal missing: {other:?}"),
    };
    assert_ne!(ja, jb, "the two siblings must journal different mutations");

    // Asking A for B's journal must find nothing — not A's journal under
    // another name.
    assert!(
        matches!(
            a.subsystem_journals().lookup(1, &block_b.hash()),
            JournalLookup::Absent
        ),
        "a journal lookup keyed by block hash must not answer with a sibling's record"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Current-value validation
// ─────────────────────────────────────────────────────────────────────────────

/// A journal whose post-image disagrees with what is actually stored is REFUSED,
/// and nothing is written.
///
/// The undo would otherwise be applied to state it was not derived from: the
/// pre-image describes a transition out of a value the row does not hold, so
/// writing it back produces a state no block ever produced. Refusing leaves the
/// node on a chain it can still reason about; "restoring" leaves it on one
/// nobody can.
///
/// Driven through a journal shim rather than by corrupting a real journal row,
/// so the test is about the CHECK and not about any encoding's failure modes.
#[test]
fn a_preimage_that_does_not_match_current_state_is_refused_loudly() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let before = node.snapshot();

    /// A journal that reports a post-image nothing wrote.
    struct Lying(Vec<UndoRecord>);
    impl BranchJournal for Lying {
        fn lookup(&self, _h: u64, _b: &Hash) -> JournalLookup {
            JournalLookup::Present(self.0.clone())
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let truthful = match node.journals().lookup(1, &block.hash()) {
        JournalLookup::Present(r) => r,
        other => panic!("expected a journal: {other:?}"),
    };
    let mut lying = truthful.clone();
    // One record's post-image is replaced with a value the block never wrote.
    lying[0].after = Some(b"this row never held these bytes".to_vec());
    let target_cf = lying[0].cf.clone();
    let target_key = lying[0].key.clone();

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &[block.clone()], &Lying(lying))
        .expect_err("a mismatching pre-image must be refused");
    drop(batch);

    match &err {
        UndoRefusal::CurrentValueMismatch { cf, key, .. } => {
            assert_eq!(*cf, target_cf);
            assert_eq!(*key, hex::encode(&target_key));
        }
        other => panic!("wrong refusal: {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("was not derived from the state it is being applied to"),
        "the refusal must say WHY, not only that it refused: {msg}"
    );
    assert!(
        msg.contains(&target_cf),
        "the refusal must name the family: {msg}"
    );

    assert_eq!(
        node.snapshot(),
        before,
        "a refused unwind must write nothing at all"
    );

    // And the truthful journal over the same state is accepted, so the refusal
    // above is the check firing rather than the fixture being unusable.
    let mut batch = node.db.batch();
    stage_branch_unwind(&node.db, &mut batch, &[block], &*node.journals())
        .expect("the real journal must still be accepted");
    drop(batch);
}

/// A refusal partway through a MULTI-block unwind writes nothing either.
///
/// The first block unwinds cleanly and the second does not. Because everything
/// is staged into one batch that the caller drops on refusal, the accepted part
/// never reaches the database — the alternative would be a half-unwound branch,
/// which is the torn state this design exists to make unreachable.
#[test]
fn a_refusal_partway_through_a_branch_leaves_the_whole_branch_applied() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    let mut branch = Vec::new();
    let mut parent = genesis;
    for n in 0..3u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }
    let before = node.snapshot();

    /// Truthful for the newest block, lying for the one below it. The unwind
    /// runs newest-first, so it accepts the first and refuses the second.
    struct LyingBelow<'a> {
        inner: &'a ObservedJournal,
        lie_at: u64,
    }
    impl BranchJournal for LyingBelow<'_> {
        fn lookup(&self, h: u64, b: &Hash) -> JournalLookup {
            match self.inner.lookup(h, b) {
                JournalLookup::Present(mut r) if h == self.lie_at => {
                    r[0].after = Some(b"never written".to_vec());
                    JournalLookup::Present(r)
                }
                other => other,
            }
        }
        fn rows(&self, h: u64, b: &Hash) -> Vec<(String, Vec<u8>)> {
            self.inner.rows(h, b)
        }
    }

    let truth = node.journals();
    let journal = LyingBelow {
        inner: &truth,
        lie_at: 2,
    };
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &branch, &journal)
        .expect_err("the mismatch at height 2 must refuse the whole branch");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::CurrentValueMismatch { height: 2, .. }),
        "{err}"
    );
    assert_eq!(
        node.snapshot(),
        before,
        "the block above the refusal must not have been unwound"
    );
}

/// A block on the abandoned branch with NO journal is refused, not skipped.
///
/// Skipping would leave that block's effects applied under a chain that no
/// longer contains it, and nothing downstream would ever notice.
#[test]
fn a_block_with_no_journal_refuses_the_unwind() {
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(Some(&genesis), &proposer, Vec::new());

    struct NoJournal;
    impl BranchJournal for NoJournal {
        fn lookup(&self, _h: u64, _b: &Hash) -> JournalLookup {
            JournalLookup::Absent
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &[block], &NoJournal)
        .expect_err("a block with no journal cannot be unwound");
    drop(batch);
    assert!(matches!(err, UndoRefusal::MissingJournal { .. }), "{err}");
    assert!(err.to_string().contains("cannot be reversed"), "{err}");
}

/// An unreadable journal is refused as unreadable, and is NOT confused with an
/// absent one.
///
/// The two are different node conditions with different responses — a block that
/// mutated nothing has no journal, while a journal that will not decode is a
/// damaged node — and collapsing them silently skips an undo that was required.
#[test]
fn an_unreadable_journal_is_refused_as_unreadable_not_as_absent() {
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(Some(&genesis), &proposer, Vec::new());

    struct Truncated;
    impl BranchJournal for Truncated {
        fn lookup(&self, _h: u64, _b: &Hash) -> JournalLookup {
            JournalLookup::Unreadable("record 3 of 7 ends mid-key".to_string())
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &[block], &Truncated)
        .expect_err("an unreadable journal cannot be unwound");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::UnreadableJournal { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("ends mid-key"),
        "the producer's reason must survive into the refusal: {err}"
    );
}

/// A corrupt journal ROW in the real store reaches the same refusal.
///
/// The shims above prove the consumer's behaviour for each `JournalLookup`
/// case. This proves the adapter over the journals that exist today actually
/// produces `Unreadable` for a damaged row, rather than panicking or reporting
/// absence.
#[test]
fn a_corrupt_journal_row_is_reported_as_unreadable() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );

    node.db
        .put(
            cf::STATE_DIFFS,
            &sumchain_storage::schema::journal_key(1, &block.hash()),
            b"\xff\xff\xff not a journal",
        )
        .expect("overwrite the journal row");

    match node.subsystem_journals().lookup(1, &block.hash()) {
        JournalLookup::Unreadable(reason) => {
            assert!(reason.contains("account journal"), "{reason}")
        }
        other => panic!("a corrupt row must read as Unreadable, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Activation boundaries
// ─────────────────────────────────────────────────────────────────────────────

/// Params with the contracts gate opening at `h`.
fn gate_at(h: u64) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.contracts_enabled_from_height = Some(h);
    p
}

/// A reorg wholly BELOW an activation height, wholly ABOVE it, and ACROSS it in
/// both directions, each converging on the branch it adopted.
///
/// The gate that matters here is `contracts_enabled_from_height`, because it
/// changes the state-root FORMULA — above it `compute_block_state_root` folds
/// the contract diff digest, below it does not. So a reorg that crosses the
/// boundary is replaying blocks whose roots were computed under two different
/// rules, and the accumulator is chained, so getting the boundary wrong makes
/// every later root wrong too.
///
/// `force_adopted == 0` is the assertion that carries this. Without it the
/// historical compatibility window would forgive exactly the mismatch the test
/// is looking for.
#[test]
fn a_reorg_crossing_an_activation_boundary_reproduces_both_sides() {
    for (name, gate, branch_len) in [
        ("entirely below the gate", 100u64, 3usize),
        ("entirely above the gate", 0u64, 3usize),
        ("across the gate", 2u64, 3usize),
    ] {
        let alice = key(1);
        let bob = key(2);
        let carol = key(3);
        let proposer = key(9);
        let (a, b, genesis) = two_nodes(gate_at(gate), &[(&alice, 10_000_000), (&bob, 10_000_000)]);

        let mut branch_a = Vec::new();
        let mut parent = genesis.clone();
        for n in 0..branch_len as u64 {
            let blk = a.produce(
                Some(&parent),
                &proposer,
                vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
            );
            parent = blk.clone();
            branch_a.push(blk);
        }

        let mut branch_b = Vec::new();
        let mut parent = genesis.clone();
        for n in 0..branch_len as u64 {
            let blk = b.produce(
                Some(&parent),
                &proposer,
                vec![transfer(&bob, &carol.address(), 3_000, 500, n)],
            );
            parent = blk.clone();
            branch_b.push(blk);
        }
        for blk in &branch_b {
            a.retain(blk);
        }

        let store = BlockStore::new(&a.db);
        let plan = plan_reorg(
            &store,
            branch_a.last().unwrap(),
            branch_b.last().unwrap(),
            NO_FINALITY,
            DEEP,
        )
        .expect("plan");
        let outcome = execute_reorg(
            &a.db,
            &a.state,
            &a.executor,
            &plan,
            NO_VALIDATORS,
            &*a.journals(),
        )
        .unwrap_or_else(|e| panic!("reorg {name} failed: {e}"));

        assert_eq!(
            outcome.force_adopted, 0,
            "reorg {name}: the replayed roots must EQUAL the adopted branch's headers; \
             a force-adopted root would hide exactly the boundary error this checks for"
        );
        let (left, right) = (a.snapshot(), b.snapshot());
        assert_eq!(
            left,
            right,
            "reorg {name} did not converge:\n{}",
            describe_divergence(&left, &right)
        );
    }
}

/// A DOWNGRADE — unwinding from above an activation height to below it — leaves
/// no row the activated rules wrote.
///
/// The gate is opened at height 2, so the abandoned branch straddles it: its
/// blocks below the gate ran under the old rules and its blocks at and above
/// ran under the new ones. Unwinding to the fork point must remove both, and
/// the snapshot comparison is over every convergent family including the
/// contract ones.
///
/// The accumulator has to come back too. It is a chained value, not a function
/// of stored rows, so no amount of row restoration recovers it; it is restored
/// from the ancestor's own header, and this asserts that it lands on exactly the
/// value the fork point published.
#[test]
fn a_downgrade_across_an_activation_boundary_leaves_nothing_behind() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(gate_at(2));
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    // One block BELOW the gate, which becomes the fork point.
    let below = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let at_fork = node.snapshot();
    let fork_accumulator = node.state.state_root();
    assert_eq!(fork_accumulator, accumulator_of(&below));

    // Two blocks AT and ABOVE the gate.
    let mut branch = Vec::new();
    let mut parent = below.clone();
    for n in 1..3u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }
    assert!(branch[0].height() >= 2, "the branch must reach the gate");

    let mut batch = node.db.batch();
    stage_branch_unwind(&node.db, &mut batch, &branch, &*node.journals()).expect("unwind");
    for blk in &branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &below).expect("head reset");
    batch.commit().expect("commit");
    node.state.set_state_root(accumulator_of(&below));

    let after = node.snapshot();
    assert_eq!(
        after,
        at_fork,
        "downgrading past the gate left rows behind:\n{}",
        describe_divergence(&after, &at_fork)
    );
    assert_eq!(
        node.state.state_root(),
        fork_accumulator,
        "the accumulator must return to the fork point's, or every block replayed \
         afterwards chains from a value no chain ever held"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Crash recovery
// ─────────────────────────────────────────────────────────────────────────────

/// An unwind interrupted before its commit leaves the node exactly where it was,
/// and a retry after restart reaches the same place an uninterrupted unwind
/// would.
///
/// The interruption point is defined: the batch is fully staged and then
/// DROPPED, which is what a process death between staging and `commit` looks
/// like from the database's side. The node is then closed and reopened, so
/// nothing in memory carries over.
#[test]
fn an_unwind_interrupted_before_commit_reopens_on_the_old_branch_and_retries_cleanly() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let (a, b, genesis) = two_nodes(params.clone(), &[(&alice, 10_000_000), (&bob, 10_000_000)]);

    let mut branch_a = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..3u64 {
        let blk = a.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch_a.push(blk);
    }
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..2u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 3_000, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    for blk in &branch_b {
        a.retain(blk);
    }

    let on_old_branch = a.snapshot();

    // ── the interruption ────────────────────────────────────────────────────
    {
        let mut batch = a.db.batch();
        stage_branch_unwind(&a.db, &mut batch, &branch_a, &*a.journals()).expect("stage");
        for blk in &branch_a {
            sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
        }
        sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
        drop(batch); // process death, one instruction before `commit`
    }

    let a = a.restart(params);
    assert_eq!(
        a.snapshot(),
        on_old_branch,
        "a batch that was never committed must have changed nothing"
    );
    let head = a.head().expect("head survives");
    assert_eq!(
        head.hash(),
        branch_a[2].hash(),
        "the head must still name the old tip: the unwind never became durable"
    );

    // ── recovery: the head says which state machine the node is in ──────────
    a.state.set_state_root(accumulator_of(&head));
    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(&store, &head, branch_b.last().unwrap(), NO_FINALITY, DEEP)
        .expect("re-plan from the recorded head");
    let outcome = resume(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &*a.journals(),
    )
    .expect("resume");
    assert_eq!(outcome.force_adopted, 0);

    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(
        left,
        right,
        "the retry after an interrupted unwind did not reach the uninterrupted result:\n{}",
        describe_divergence(&left, &right)
    );
}

/// An apply interrupted between blocks reopens on a COMPLETE prefix of the new
/// branch, and resuming finishes it.
///
/// The head pointer is written by `publish`, in the same batch as the block's
/// state, so it can only ever name a block whose state is entirely applied. That
/// is the whole recovery protocol: no crash marker, no separate journal, because
/// the head IS the marker.
///
/// The interruption here is real rather than simulated: the first block of the
/// new branch is applied and committed, the node is then closed and reopened,
/// and the second is applied afterwards. The result must be byte-identical to
/// applying both without a restart.
#[test]
fn an_apply_interrupted_between_blocks_resumes_on_the_committed_prefix() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let seeds = [(&alice, 10_000_000u128), (&bob, 10_000_000u128)];

    // Reference: the same switch performed without any interruption.
    let reference = {
        let (a, b, genesis) = two_nodes(params.clone(), &seeds);
        let (branch_a, branch_b) = build_forks(&a, &b, &genesis, &alice, &bob, &carol, &proposer);
        for blk in &branch_b {
            a.retain(blk);
        }
        let store = BlockStore::new(&a.db);
        let plan = plan_reorg(
            &store,
            branch_a.last().unwrap(),
            branch_b.last().unwrap(),
            NO_FINALITY,
            DEEP,
        )
        .expect("plan");
        execute_reorg(
            &a.db,
            &a.state,
            &a.executor,
            &plan,
            NO_VALIDATORS,
            &*a.journals(),
        )
        .expect("reference reorg");
        a.snapshot()
    };

    // The interrupted run.
    let (a, b, genesis) = two_nodes(params.clone(), &seeds);
    let (branch_a, branch_b) = build_forks(&a, &b, &genesis, &alice, &bob, &carol, &proposer);
    for blk in &branch_b {
        a.retain(blk);
    }
    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        DEEP,
    )
    .expect("plan");

    // Unwind, then apply only the FIRST block of the new branch, then die.
    {
        let mut batch = a.db.batch();
        stage_branch_unwind(&a.db, &mut batch, &plan.old_branch, &*a.journals()).expect("stage");
        for blk in &plan.old_branch {
            sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
        }
        sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
        batch.commit().expect("commit the unwind");
    }
    a.state.set_state_root(accumulator_of(&genesis));
    let partial = apply_branch(
        &a.db,
        &a.state,
        &a.executor,
        &plan.new_branch[..1],
        NO_VALIDATORS,
    )
    .expect("apply the first block only");
    assert_eq!(partial.applied, 1);

    let a = a.restart(params);
    let head = a.head().expect("head survives the restart");
    assert_eq!(
        head.hash(),
        plan.new_branch[0].hash(),
        "the head must name the last block whose publication committed"
    );

    // Recovery: accumulator from the head's header, then finish.
    let finished = resume(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &*a.journals(),
    )
    .expect("resume the apply");
    assert_eq!(
        finished.applied,
        (plan.new_branch.len() - 1) as u64,
        "resume must apply only what the interruption left, not replay the committed prefix"
    );
    assert_eq!(finished.force_adopted, 0);

    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(
        left,
        right,
        "the resumed node did not converge with the branch it adopted:\n{}",
        describe_divergence(&left, &right)
    );
    assert_eq!(
        a.snapshot(),
        reference,
        "an interrupted-and-resumed reorg must be indistinguishable from an \
         uninterrupted one"
    );
}

/// Shared fork construction for the crash tests.
#[allow(clippy::too_many_arguments)]
fn build_forks(
    a: &Node,
    b: &Node,
    genesis: &Block,
    alice: &KeyPair,
    bob: &KeyPair,
    carol: &KeyPair,
    proposer: &KeyPair,
) -> (Vec<Block>, Vec<Block>) {
    let mut branch_a = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..2u64 {
        let blk = a.produce(
            Some(&parent),
            proposer,
            vec![transfer(alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch_a.push(blk);
    }
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..3u64 {
        let blk = b.produce(
            Some(&parent),
            proposer,
            vec![transfer(bob, &carol.address(), 3_000, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    (branch_a, branch_b)
}

/// Applying a branch is idempotent against an already-applied prefix.
///
/// Re-running the whole apply after it has already finished must be a no-op, not
/// a second execution of every block against its own output. This is the
/// property that makes "retry on restart" safe to do unconditionally.
#[test]
fn re_applying_a_finished_branch_does_nothing() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let mut branch = Vec::new();
    let mut parent = genesis;
    for n in 0..2u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }

    let before = node.snapshot();
    let again = apply_branch(
        &node.db,
        &node.state,
        &node.executor,
        &branch,
        NO_VALIDATORS,
    )
    .expect("re-apply");
    assert_eq!(
        again.applied, 0,
        "an already-applied branch must apply nothing"
    );
    assert_eq!(node.snapshot(), before);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Account state and the authoritative commitment
// ─────────────────────────────────────────────────────────────────────────────

/// Account rows do NOT participate in the authoritative state commitment.
///
/// `compute_block_state_root` folds header fields, receipt outcomes, the gated
/// contract/supply/compute-pool/beacon digests and the previous root. It reads
/// `cf::STATE` nowhere. So two nodes can hold different balances and publish
/// identical roots, and the chain cannot tell.
///
/// This is demonstrated rather than asserted from the source: a balance is
/// altered behind the executor's back, a block is then published, and its root
/// is compared with the root the same block produces on an untouched node. Equal
/// roots is the finding.
///
/// It matters here because it is the reason a reorg's correctness cannot be
/// delegated to root comparison. `accept_imported` agreeing tells you the
/// receipts and the chained accumulator line up; it tells you nothing about
/// whether the account rows were restored. That is why these tests compare rows
/// byte-for-byte instead of trusting the root.
#[test]
fn account_rows_do_not_participate_in_the_state_root() {
    let alice = key(1);
    let carol = key(3);
    let mallory = key(4);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();

    let honest = Node::new(params.clone());
    let tampered = Node::new(params);
    for n in [&honest, &tampered] {
        n.seed(&alice, 10_000_000);
    }
    let g1 = honest.produce(None, &proposer, Vec::new());
    let g2 = tampered.produce(None, &proposer, Vec::new());
    assert_eq!(g1.hash(), g2.hash());

    // A balance that no transaction created, written straight into `cf::STATE`.
    tampered.seed(&mallory, 999_999_999);
    assert_eq!(honest.balance(&mallory.address()), 0);
    assert_eq!(tampered.balance(&mallory.address()), 999_999_999);

    let tx = transfer(&alice, &carol.address(), 1_000, 500, 0);
    let b1 = honest.produce(Some(&g1), &proposer, vec![tx.clone()]);
    let b2 = tampered.produce(Some(&g2), &proposer, vec![tx]);

    assert_eq!(
        b1.header.state_root, b2.header.state_root,
        "if these ever differ, account rows HAVE entered the commitment and the reorg \
         tests may rely on root equality instead of row equality"
    );
    assert_eq!(b1.hash(), b2.hash());
    assert_ne!(
        honest.balance(&mallory.address()),
        tampered.balance(&mallory.address()),
        "the two nodes hold different account state under one identical block hash"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Refusals that protect the switch
// ─────────────────────────────────────────────────────────────────────────────

/// A plan naming an ancestor the store does not have is refused before anything
/// is unwound.
#[test]
fn a_plan_whose_ancestor_is_missing_is_refused_before_any_write() {
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(Some(&genesis), &proposer, Vec::new());
    let before = node.snapshot();

    let plan = ReorgPlan {
        ancestor_hash: Hash::hash(b"an ancestor nobody stored"),
        ancestor_height: 0,
        old_branch: vec![block],
        new_branch: Vec::new(),
    };
    let err = execute_reorg(
        &node.db,
        &node.state,
        &node.executor,
        &plan,
        NO_VALIDATORS,
        &*node.journals(),
    )
    .expect_err("a missing ancestor must be refused");
    assert!(
        err.to_string()
            .contains("not \n                 in the block store")
            || err.to_string().contains("is not"),
        "{err}"
    );
    assert_eq!(node.snapshot(), before, "a refused plan must write nothing");
}

/// A pure extension — nothing abandoned — applies without unwinding.
#[test]
fn an_extension_applies_without_unwinding_anything() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(ChainParams::with_v2_enabled(), &[(&alice, 10_000_000)]);

    // B builds two blocks; A has none of them.
    let mut branch = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..2u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }
    for blk in &branch {
        a.retain(blk);
    }

    let store = BlockStore::new(&a.db);
    let plan =
        plan_reorg(&store, &genesis, branch.last().unwrap(), NO_FINALITY, DEEP).expect("plan");
    assert!(plan.is_extension());

    let outcome = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &*a.journals(),
    )
    .expect("extension");
    assert_eq!(outcome.unwound.blocks, 0);
    assert_eq!(outcome.applied, 2);
    assert_eq!(outcome.force_adopted, 0);

    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(left, right, "{}", describe_divergence(&left, &right));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. What today's journals do NOT cover
// ─────────────────────────────────────────────────────────────────────────────

/// The four per-subsystem journals do not cover every column family a block
/// writes, and the shortfall reaches the authoritative commitment.
///
/// # Why this is a test and not a note
///
/// Every convergence test above is driven by `ObservedJournal`, a journal built
/// by observation that satisfies the contract in full. That is deliberate: it
/// isolates the CONSUMER — the ancestor walk, the newest-first unwind, the
/// current-value check, the atomic batch, the resume — from whether any
/// particular producer is complete. But it would be dishonest to leave the
/// reader believing the journals that exist today would do.
///
/// So this measures the difference directly. It publishes one ordinary block,
/// takes the ground-truth diff of every state column family, and subtracts what
/// `SubsystemJournals` reports. What is left is the set of rows a reorg driven
/// by today's journals would fail to restore.
///
/// # What the shortfall is, and why it matters
///
/// `cf::SUPPLY`. The supply ledger, the protocol reserve and the per-address
/// service-grant rows are written by block execution and have no undo journal of
/// any kind. They are not inert: `SupplyStore::v_state_digest` is folded into
/// `compute_block_state_root` once the correction marker is set, so these rows
/// are part of the authoritative commitment. A reorg that cannot restore them
/// replays the adopted branch against supply state the abandoned branch left
/// behind, computes a different root for every adopted block, and — below
/// `LEGACY_ROOT_COMPATIBILITY_HEIGHT` — has that mismatch forgiven and
/// published.
///
/// This is a PRODUCER-side obligation. A generic application journal built from
/// `ApplicationOverlay` pre-images covers it without knowing it exists, because
/// the overlay captures a pre-image for every key written through it regardless
/// of family. The four hand-written journals cover four families by name.
///
/// The assertion is two-sided on purpose. It pins the families that ARE covered,
/// so a regression that drops one fails here; and it pins the shortfall, so
/// closing it fails here too and the entry is removed deliberately rather than
/// drifting out of the record.
#[test]
fn the_subsystem_journals_do_not_cover_every_family_a_block_writes() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );

    // Ground truth: what the block actually changed.
    let truth = match node.journals().lookup(1, &block.hash()) {
        JournalLookup::Present(r) => r,
        other => panic!("the oracle must have recorded the block: {other:?}"),
    };
    assert!(!truth.is_empty(), "the block must have changed something");

    // What the journals the publisher wrote can account for.
    let claimed = match node.subsystem_journals().lookup(1, &block.hash()) {
        JournalLookup::Present(r) => r,
        other => panic!("the publisher must have written journals: {other:?}"),
    };

    let mut covered: std::collections::BTreeSet<&str> = Default::default();
    for r in &claimed {
        covered.insert(Box::leak(r.cf.clone().into_boxed_str()));
    }
    let mut touched: std::collections::BTreeSet<String> = Default::default();
    for r in &truth {
        touched.insert(r.cf.clone());
    }
    let uncovered: Vec<&String> = touched
        .iter()
        .filter(|c| !covered.contains(c.as_str()))
        .collect();

    assert!(
        covered.contains(cf::STATE),
        "the account journal must still cover cf::STATE; if this fails the \
         publisher stopped writing it and every reorg is silently broken"
    );
    assert_eq!(
        uncovered.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec![cf::SUPPLY],
        "the set of families a block writes and no journal records has changed. \
         Adding one is a reorg-correctness regression: those rows cannot be \
         restored. Removing `supply` is the fix this entry is waiting for — \
         delete this assertion when a journal covers every family, and say so."
    );

    // And the consequence, demonstrated rather than asserted from the shape: an
    // unwind driven by the incomplete journals leaves the supply rows the block
    // wrote exactly where the block left them.
    let supply_after_block: BTreeMap<Vec<u8>, Vec<u8>> = node
        .db
        .iter(cf::SUPPLY)
        .unwrap()
        .map(|(k, v)| (k.into_vec(), v.into_vec()))
        .collect();

    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.subsystem_journals(),
    )
    .expect("the incomplete journal still unwinds what it covers");
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).unwrap();
    batch.commit().unwrap();

    let supply_after_unwind: BTreeMap<Vec<u8>, Vec<u8>> = node
        .db
        .iter(cf::SUPPLY)
        .unwrap()
        .map(|(k, v)| (k.into_vec(), v.into_vec()))
        .collect();
    assert_eq!(
        supply_after_unwind, supply_after_block,
        "if the supply rows moved, something now journals them and the entry \
         above is stale"
    );
}

/// A reorg driven by the incomplete journals cannot reproduce the adopted
/// branch's roots, and below the compatibility height that failure is FORGIVEN
/// rather than reported.
///
/// The companion to the test above: that one measures the gap, this one shows
/// what the gap does to a switch. It is the argument for why `force_adopted` is
/// reported by `ReorgOutcome` at all — without it this reorg looks successful.
#[test]
fn a_reorg_driven_by_the_incomplete_journals_force_adopts_its_roots() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    let block_a = a.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let block_b = b.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&bob, &carol.address(), 3_000, 500, 0)],
    );
    a.retain(&block_b);

    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(&store, &block_a, &block_b, NO_FINALITY, DEEP).expect("plan");
    let outcome = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &a.subsystem_journals(),
    )
    .expect("the switch itself is not refused");

    assert_eq!(outcome.applied, 1);
    assert_eq!(
        outcome.force_adopted, 1,
        "with the supply rows unrestored, the replayed root cannot equal the \
         adopted header's; this block is published under the historical \
         compatibility window, NOT verified. If this ever reads 0, a journal now \
         covers every family and `the_subsystem_journals_do_not_cover_every_\
         family_a_block_writes` should have failed first."
    );
    assert_eq!(outcome.verified, 0);

    // The same switch, driven by a contract-conformant journal, verifies.
    a.adopt_journals_from(&b);
    let (a2, b2, genesis2) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );
    let a2_block = a2.produce(
        Some(&genesis2),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let b2_block = b2.produce(
        Some(&genesis2),
        &proposer,
        vec![transfer(&bob, &carol.address(), 3_000, 500, 0)],
    );
    a2.retain(&b2_block);
    a2.adopt_journals_from(&b2);
    let store2 = BlockStore::new(&a2.db);
    let plan2 = plan_reorg(&store2, &a2_block, &b2_block, NO_FINALITY, DEEP).expect("plan");
    let good = execute_reorg(
        &a2.db,
        &a2.state,
        &a2.executor,
        &plan2,
        NO_VALIDATORS,
        &*a2.journals(),
    )
    .expect("switch");
    assert_eq!(
        (good.verified, good.force_adopted),
        (1, 0),
        "a complete journal is the whole difference between a reorg whose result \
         is checked and one whose result is forgiven"
    );
}
