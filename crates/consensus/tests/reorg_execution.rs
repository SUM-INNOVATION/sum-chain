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
    stage_branch_unwind, ActivatedJournal, BranchJournal, EntryOrdering, ExpectedAfter,
    JournalHeader, JournalLookup, MissingJournalPolicy, SubsystemJournals, UndoRecord, UndoRefusal,
};
use sumchain_state::state::StateManager;
use sumchain_storage::journal::{ActivationSource, JournalActivation, JournalRequirement};
use sumchain_storage::schema::BlockStore;
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const NO_FINALITY: u64 = 0;
const DEEP: u64 = 1024;
const NO_VALIDATORS: &[[u8; 32]] = &[];

/// The strict missing-journal policy: a journal is required at every height.
///
/// Correct for the fixtures below because every block they publish goes through
/// `publish`, which writes an application-journal envelope unconditionally —
/// including a zero-entry one for a block that wrote nothing. So absence carries
/// information at every height here, and requiring a record refuses nothing
/// legitimate. It is the same policy `ActivatedJournal::policy` derives for a
/// chain whose observed boundary is height 0, which is every chain these
/// fixtures build. Tests whose subject is the tolerant policy name it
/// explicitly.
const JOURNAL_REQUIRED: MissingJournalPolicy = MissingJournalPolicy::RequiredFrom(0);

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
/// explicitly, and the journal format watermark, which is not per-block state.
/// The four `*_state_diffs` families ARE the legacy journals, and
/// `APPLICATION_JOURNAL` is the generic one.
///
/// # Why `APPLICATION_JOURNAL` belongs on this list
///
/// It is UNDO DATA, in the same class as the four `*_state_diffs` families
/// already here, and it is node-local by the contract's own §0: never hashed
/// into a block, never folded into a state root, never sent over the wire,
/// never read by consensus. It is not application state that a reorg must
/// restore; it is the record that says how to restore application state, and a
/// reorg consumes it — `BranchJournal::rows` deletes each block's row in the
/// same batch that applies its restores.
///
/// Listing it here is not a widening to make a red assertion go green. It puts
/// a new family in the class its four siblings were already in, and the
/// consequence is visible in the assertion below: with it excluded, the set of
/// families a block writes and no LEGACY journal records is `[supply]` again —
/// the same real, still-open shortfall the entry has always measured.
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
    cf::APPLICATION_JOURNAL,
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
/// Record order is ascending `(cf, key)`, and a snapshot diff holds at most one
/// record per key by construction — so this oracle satisfies
/// [`EntryOrdering::NetByKey`] exactly as the real journal does, and declares
/// it, and `stage_branch_unwind` validates the declaration for both.
///
/// It is kept as a COMPARATOR rather than as the thing under test.
/// [`Node::real_journal`] drives the acceptance path; `assert_oracle_agrees`
/// checks the real decoded journal against this ground truth, so a producer bug
/// that made both wrong in the same way is not what the convergence tests would
/// be measuring.
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
                after: ExpectedAfter::Exact(after.get(k).cloned()),
            })
            .collect();
        self.per_block.insert((height, hash), records);
    }
}

impl BranchJournal for ObservedJournal {
    fn lookup(&self, height: u64, block_hash: &Hash) -> JournalLookup {
        match self.per_block.get(&(height, *block_hash)) {
            Some(r) => JournalLookup::Present {
                header: JournalHeader {
                    height,
                    block_hash: *block_hash,
                    version: 0,
                    // A snapshot diff holds at most one record per key by
                    // construction, so this oracle really is `NetByKey` and
                    // `stage_branch_unwind` is entitled to check it.
                    ordering: EntryOrdering::NetByKey,
                },
                records: r.clone(),
            },
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

    /// Execute and ACCEPT a block, then die before `publish` commits.
    ///
    /// Returns the block that was never published. Nothing is written: the
    /// overlay buffers every write, `into_batch` is crate-private to
    /// `sumchain-storage`, and dropping an `AcceptedCandidate` drops the
    /// overlay with it. This is the crash-before-publication state.
    fn execute_and_abandon(
        &self,
        parent: &Block,
        proposer: &KeyPair,
        txs: Vec<SignedTransaction>,
    ) -> Block {
        let header = BlockHeader::new(
            parent.hash(),
            parent.height() + 1,
            GENESIS_TS + parent.height() + 1,
            Hash::ZERO,
            Hash::ZERO,
            *proposer.public_key().as_bytes(),
        );
        let mut block = Block::new(header, txs);
        let execution = self
            .executor
            .execute_block(&block, self.state.state_root(), NO_VALIDATORS)
            .expect("execute_block");
        block.header.state_root = execution.computed_root();
        let (executed, _account_diff, _contract_diff) = execution.into_parts();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        drop(accepted); // process death, one instruction before `publish`
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

    /// The REAL journal: the encoded records this node's publisher wrote, read
    /// back off disk, decoded and validated.
    ///
    /// This is what the acceptance path below runs on. `ActivatedJournal`
    /// resolves the boundary from the node's own journal history and then
    /// dispatches per block — the generic application journal at and above it,
    /// the legacy per-subsystem diffs below it, never both. Every block these
    /// fixtures publish goes through `publish`, which writes a record
    /// unconditionally, so the observed boundary is height 0 and every block is
    /// in the required region.
    ///
    /// Nothing here is an oracle. `ApplicationJournalReader` reads
    /// `cf::APPLICATION_JOURNAL`, `ApplicationJournal::decode_for` checks magic,
    /// format version, `(height, block hash)` identity, canonical `(cf, key)`
    /// order and framing, and the after-images are 8-byte tags recomputed
    /// against committed rows rather than values copied from a snapshot.
    fn real_journal(&self) -> ActivatedJournal<'_> {
        ActivatedJournal::resolve(&self.db, ActivationSource::ObservedFromChain)
            .expect("resolve the journal activation boundary")
    }
}

/// The real journal and the snapshot-diff oracle must describe the same block.
///
/// The oracle stays in this file as a COMPARATOR. It is ground truth by
/// construction — it is the difference between the database before publication
/// and the database after — so checking the decoded record against it is a check
/// on the producer that does not depend on the producer being right.
///
/// Two directions:
///
/// * every row the block actually changed must have an entry in the journal,
///   with the same pre-image;
/// * any extra entry the journal carries must be a NO-OP write — a key written
///   with the value it already held, which the overlay journals (it captured a
///   pre-image on the write) and a snapshot diff cannot see. Verified through
///   the entry's own after-tag: recomputing the tag over the PRE-image and
///   finding it matches is exactly the statement "the block left what it found".
fn assert_oracle_agrees(node: &Node, block: &Block) {
    let height = block.height();
    let hash = block.hash();

    let JournalLookup::Present { records: real, .. } = node.real_journal().lookup(height, &hash)
    else {
        panic!("the real journal must hold a record for every published block");
    };
    let JournalLookup::Present {
        records: oracle, ..
    } = node.journals().lookup(height, &hash)
    else {
        panic!("the oracle must have recorded the block");
    };

    let real_by_key: BTreeMap<(String, Vec<u8>), &UndoRecord> = real
        .iter()
        .map(|r| ((r.cf.clone(), r.key.clone()), r))
        .collect();
    assert_eq!(
        real_by_key.len(),
        real.len(),
        "the real journal must hold one net entry per (cf, key)"
    );

    for o in &oracle {
        let found = real_by_key
            .get(&(o.cf.clone(), o.key.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "block {hash} at height {height} changed {} / {} and the real journal                      has no entry for it",
                    o.cf,
                    hex::encode(&o.key)
                )
            });
        assert_eq!(
            found.before, o.before,
            "pre-image disagreement at {} / {}: the journal says {:?}, the block's own              before/after snapshot says {:?}",
            o.cf,
            hex::encode(&o.key),
            found.before,
            o.before
        );
    }

    let oracle_keys: BTreeMap<(String, Vec<u8>), ()> = oracle
        .iter()
        .map(|r| ((r.cf.clone(), r.key.clone()), ()))
        .collect();
    for ((cf_name, key), r) in &real_by_key {
        if oracle_keys.contains_key(&(cf_name.clone(), key.clone())) {
            continue;
        }
        assert!(
            r.after.matches(cf_name, key, r.before.as_deref()),
            "the journal carries an entry for {} / {} that the block's before/after              snapshot does not show as changed, and its after-tag does not match its              pre-image either — so it is neither a no-op write nor a real change",
            cf_name,
            hex::encode(key)
        );
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
        &a.real_journal(),
        JOURNAL_REQUIRED,
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
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
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
    let journals = node.real_journal();
    let mut batch = node.db.batch();
    for blk in &branch {
        let JournalLookup::Present { records, .. } = journals.lookup(blk.height(), &blk.hash())
        else {
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
            &node.real_journal(),
            JOURNAL_REQUIRED,
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
        JournalLookup::Present { records, .. } => records,
        other => panic!("A's journal missing: {other:?}"),
    };
    let jb = match b.subsystem_journals().lookup(1, &block_b.hash()) {
        JournalLookup::Present { records, .. } => records,
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
        fn lookup(&self, h: u64, b: &Hash) -> JournalLookup {
            JournalLookup::Present {
                header: JournalHeader {
                    height: h,
                    block_hash: *b,
                    version: 0,
                    ordering: EntryOrdering::NetByKey,
                },
                records: self.0.clone(),
            }
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let truthful = match node.journals().lookup(1, &block.hash()) {
        JournalLookup::Present { records, .. } => records,
        other => panic!("expected a journal: {other:?}"),
    };
    let mut lying = truthful.clone();
    // One record's post-image is replaced with a value the block never wrote.
    lying[0].after = ExpectedAfter::Exact(Some(b"this row never held these bytes".to_vec()));
    let target_cf = lying[0].cf.clone();
    let target_key = lying[0].key.clone();

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &Lying(lying),
        JOURNAL_REQUIRED,
    )
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
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
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
                JournalLookup::Present {
                    header,
                    mut records,
                } if h == self.lie_at => {
                    records[0].after = ExpectedAfter::Exact(Some(b"never written".to_vec()));
                    JournalLookup::Present { header, records }
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
    let err = stage_branch_unwind(&node.db, &mut batch, &branch, &journal, JOURNAL_REQUIRED)
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
    let err = stage_branch_unwind(&node.db, &mut batch, &[block], &NoJournal, JOURNAL_REQUIRED)
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
    let err = stage_branch_unwind(&node.db, &mut batch, &[block], &Truncated, JOURNAL_REQUIRED)
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
            &a.real_journal(),
            JOURNAL_REQUIRED,
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
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("unwind");
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
        stage_branch_unwind(
            &a.db,
            &mut batch,
            &branch_a,
            &a.real_journal(),
            JOURNAL_REQUIRED,
        )
        .expect("stage");
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
        &a.real_journal(),
        JOURNAL_REQUIRED,
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
            &a.real_journal(),
            JOURNAL_REQUIRED,
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
        stage_branch_unwind(
            &a.db,
            &mut batch,
            &plan.old_branch,
            &a.real_journal(),
            JOURNAL_REQUIRED,
        )
        .expect("stage");
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
        &a.real_journal(),
        JOURNAL_REQUIRED,
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
        &node.real_journal(),
        JOURNAL_REQUIRED,
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
        &a.real_journal(),
        JOURNAL_REQUIRED,
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
/// # What this measures, now that the generic journal exists
///
/// It measures the LEGACY shortfall, which is why the activation boundary is
/// not a formality. It publishes one ordinary block, takes the ground-truth diff
/// of every state column family, and subtracts what `SubsystemJournals` reports.
/// What is left is the set of rows a reorg driven by today's per-subsystem
/// journals would fail to restore — and therefore the set of rows that a
/// PRE-ACTIVATION reorg still cannot restore, because below the boundary those
/// four journals are all there is.
///
/// # The shortfall
///
/// `cf::SUPPLY`. The supply ledger, the protocol reserve and the per-address
/// service-grant rows are written by block execution and have no hand-written
/// undo journal of any kind. They are not inert: `SupplyStore::v_state_digest`
/// is folded into `compute_block_state_root` once the correction marker is set,
/// so these rows are part of the authoritative commitment. A reorg that cannot
/// restore them replays the adopted branch against supply state the abandoned
/// branch left behind, computes a different root for every adopted block, and —
/// below `LEGACY_ROOT_COMPATIBILITY_HEIGHT` — has that mismatch forgiven and
/// published.
///
/// # Why the assertion stays, and what changed about it
///
/// Its old message said to delete it "when a journal covers every family". A
/// journal now does: the generic application journal is derived from
/// `ApplicationOverlay` pre-images, so it covers `cf::SUPPLY` without knowing
/// the family exists, and the third block of assertions below proves that on the
/// same fixture rather than asserting it from the shape. What it does NOT do is
/// make the four legacy journals complete — nothing can, short of rewriting
/// them — and those four are still the only record below the activation
/// boundary. So the entry is not deleted. It is what the boundary is FOR, and
/// deleting it would delete the measurement of the gap the boundary exists to
/// close.
///
/// # A note on `application_journal` itself
///
/// The generic journal's own column family is written by every block, and it is
/// covered by none of the four legacy journals — so a naive reading of "families
/// a block writes and no journal records" now includes it. It is excluded, by
/// `NOT_JOURNALLED`, because it is node-local UNDO DATA rather than application
/// state: the same class as the four `*_state_diffs` families that were always
/// on that list, never hashed into a block or folded into a state root, and
/// consumed by the reorg rather than restored by it. That exclusion is a
/// classification, not a widening — see `NOT_JOURNALLED`'s own note — and the
/// assertion below is unchanged in what it measures.
///
/// The assertion is three-sided. It pins the families that ARE covered by the
/// legacy journals, so a regression that drops one fails here; it pins the
/// legacy shortfall, so a change to it is deliberate; and it pins that the
/// generic journal closes that shortfall, so a regression there fails here too.
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
        JournalLookup::Present { records, .. } => records,
        other => panic!("the oracle must have recorded the block: {other:?}"),
    };
    assert!(!truth.is_empty(), "the block must have changed something");

    // What the journals the publisher wrote can account for.
    let claimed = match node.subsystem_journals().lookup(1, &block.hash()) {
        JournalLookup::Present { records, .. } => records,
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
        "the set of families a block writes and the four LEGACY journals do not \
         record has changed. Adding one widens the gap a pre-activation reorg \
         cannot close. Removing `supply` would mean the legacy journals \
         themselves were completed, which is a different change from the generic \
         journal covering it — that is asserted separately below, and it is why \
         this entry is not deleted: below the activation boundary these four are \
         still the only undo record a block has."
    );

    // ── and the generic journal covers what they do not ─────────────────────
    //
    // Same fixture, same block. The generic journal is derived from the
    // overlay's pre-image map, so it covers `cf::SUPPLY` without naming it —
    // there is no allowlist for a family to be missing from.
    let generic = match node.real_journal().lookup(1, &block.hash()) {
        JournalLookup::Present { records, .. } => records,
        other => panic!("the generic journal must have recorded the block: {other:?}"),
    };
    let generic_families: std::collections::BTreeSet<&str> =
        generic.iter().map(|r| r.cf.as_str()).collect();
    for c in &touched {
        assert!(
            generic_families.contains(c.as_str()),
            "the generic journal must cover {c}, which a block wrote; it is derived \
             from the overlay's pre-images, so a family missing from it would mean \
             the write did not go through the overlay at all"
        );
    }
    assert!(
        generic_families.contains(cf::SUPPLY),
        "in particular it must cover `supply` — the family the four hand-written \
         journals have never recorded, and the one whose absence reaches the state \
         root"
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
        JOURNAL_REQUIRED,
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
        // The subsystem journals have no record for an empty block; the
        // fixture's blocks are not empty, but the strict policy is what makes
        // the force-adoption below attributable to the SUPPLY gap and not to a
        // tolerated absence.
        JOURNAL_REQUIRED,
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
        &a2.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("switch");
    assert_eq!(
        (good.verified, good.force_adopted),
        (1, 0),
        "a complete journal is the whole difference between a reorg whose result \
         is checked and one whose result is forgiven"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. The journal must agree with the block it was filed under
// ─────────────────────────────────────────────────────────────────────────────

/// A journal that decodes cleanly but names a DIFFERENT block is refused.
///
/// Addressing by `(height, block hash)` is what fixes issue #253, and it is not
/// sufficient on its own: addressing is a key, and a key can be wrong — a
/// producer bug, a half-migrated store, a row copied between databases. Nothing
/// about a correctly-decoding record proves it belongs on the shelf it was found
/// on unless the record says so itself.
///
/// So the record carries its own `(height, block hash)` and the reader checks
/// them. This is the check firing: same height, wrong block. There is no way to
/// tell which of the key and the record is right, so neither is trusted.
#[test]
fn a_journal_that_names_a_different_block_is_refused() {
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

    /// Reports a truthful record set under a header naming a sibling.
    struct Misfiled {
        records: Vec<UndoRecord>,
        claims: Hash,
    }
    impl BranchJournal for Misfiled {
        fn lookup(&self, h: u64, _b: &Hash) -> JournalLookup {
            JournalLookup::Present {
                header: JournalHeader {
                    height: h,
                    block_hash: self.claims,
                    version: 0,
                    ordering: EntryOrdering::NetByKey,
                },
                records: self.records.clone(),
            }
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let records = match node.journals().lookup(1, &block.hash()) {
        JournalLookup::Present { records, .. } => records,
        other => panic!("expected a journal: {other:?}"),
    };
    let sibling = Hash::hash(b"a block at the same height that is not this one");
    assert_ne!(sibling, block.hash());

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block],
        &Misfiled {
            records,
            claims: sibling,
        },
        JOURNAL_REQUIRED,
    )
    .expect_err("a journal naming another block must be refused");
    drop(batch);

    assert!(
        matches!(err, UndoRefusal::JournalIdentityMismatch { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("cannot be applied to either"),
        "the refusal must say that neither side is trusted: {err}"
    );
    assert_eq!(
        node.snapshot(),
        before,
        "a refused unwind must write nothing, even when its records were correct"
    );
}

/// A journal at a format version this reader does not understand is REFUSED,
/// never partially decoded.
///
/// This is downgrade safety, and it is the reason the version field is in the
/// contract at all. Once a store holds journals written above a reader's
/// version — which is what an activation that changes the format produces — an
/// older binary must stop rather than apply the parts it recognises. A
/// partially-understood undo record applied to state is worse than no undo,
/// because it looks like it worked.
///
/// The complement is asserted too: a version the reader DOES know is accepted,
/// so this is a version check and not a blanket refusal.
#[test]
fn a_journal_at_an_unknown_format_version_is_refused() {
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

    struct AtVersion {
        records: Vec<UndoRecord>,
        version: u32,
    }
    impl BranchJournal for AtVersion {
        fn lookup(&self, h: u64, b: &Hash) -> JournalLookup {
            JournalLookup::Present {
                header: JournalHeader {
                    height: h,
                    block_hash: *b,
                    version: self.version,
                    ordering: EntryOrdering::NetByKey,
                },
                records: self.records.clone(),
            }
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let records = match node.journals().lookup(1, &block.hash()) {
        JournalLookup::Present { records, .. } => records,
        other => panic!("expected a journal: {other:?}"),
    };

    // A version from beyond this reader's knowledge.
    let future = sumchain_state::reorg_undo::SUPPORTED_JOURNAL_VERSIONS
        .iter()
        .max()
        .copied()
        .expect("at least one supported version")
        + 1;

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &AtVersion {
            records: records.clone(),
            version: future,
        },
        JOURNAL_REQUIRED,
    )
    .expect_err("an unknown journal version must be refused");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::UnsupportedJournalVersion { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("looks like it worked"),
        "the refusal must say why partial decoding is worse than stopping: {err}"
    );
    assert_eq!(node.snapshot(), before, "a refused unwind writes nothing");

    // Every version the reader declares is accepted, so the refusal above is a
    // version check and not a blanket one.
    for known in sumchain_state::reorg_undo::SUPPORTED_JOURNAL_VERSIONS {
        let mut batch = node.db.batch();
        stage_branch_unwind(
            &node.db,
            &mut batch,
            &[block.clone()],
            &AtVersion {
                records: records.clone(),
                version: *known,
            },
            JOURNAL_REQUIRED,
        )
        .unwrap_or_else(|e| panic!("declared version {known} must be accepted: {e}"));
        drop(batch);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Missing journals: halting, and the compatibility rule
// ─────────────────────────────────────────────────────────────────────────────

/// A missing journal HALTS at or above the height the journal is required from,
/// and is tolerated below it — counted, never silent.
///
/// The two are different node conditions. On history that predates the journal
/// format a block legitimately has none, and there is nothing the node could
/// have recorded. Once the format is active, absence is a damaged database, and
/// unwinding past it leaves that block's effects applied under a chain that no
/// longer contains it.
///
/// Tolerating is therefore not "fine". It is reported as
/// `UnwindReport::tolerated_absences`, because a switch with a non-zero count
/// has not fully unwound its abandoned branch, and a caller that treats it as
/// though it had is asserting something nobody checked.
#[test]
fn a_missing_journal_halts_at_or_above_the_height_it_is_required_from() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    let mut branch = Vec::new();
    let mut parent = genesis.clone();
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

    /// The real oracle, with the journal for one height withheld.
    struct Withholding<'a> {
        inner: &'a ObservedJournal,
        withhold: u64,
    }
    impl BranchJournal for Withholding<'_> {
        fn lookup(&self, h: u64, b: &Hash) -> JournalLookup {
            if h == self.withhold {
                JournalLookup::Absent
            } else {
                self.inner.lookup(h, b)
            }
        }
        fn rows(&self, h: u64, b: &Hash) -> Vec<(String, Vec<u8>)> {
            self.inner.rows(h, b)
        }
    }

    let truth = node.journals();
    // Withheld at the OLDEST block on the branch, which is the only position
    // where tolerating one is coherent: the unwind runs newest-first, so an
    // absence at the bottom is the last thing it reaches and no later record
    // depends on it having been applied. An absence in the MIDDLE is a different
    // story, and has its own test below.
    let journal = Withholding {
        inner: &truth,
        withhold: 1,
    };

    // Required from height 1: the absence at 1 halts.
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &journal,
        MissingJournalPolicy::RequiredFrom(1),
    )
    .expect_err("a journal required at this height and absent must halt");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::MissingJournal { height: 1, .. }),
        "{err}"
    );
    assert_eq!(node.snapshot(), before, "a halt writes nothing");

    // Required only from height 2: the absence at 1 is below the line, so it is
    // tolerated — and counted.
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &journal,
        MissingJournalPolicy::RequiredFrom(2),
    )
    .expect("below the required height, absence is tolerated");
    drop(batch);
    assert_eq!(
        report.tolerated_absences, 1,
        "a tolerated absence must be REPORTED: the block's effects were not reverted"
    );
    assert_eq!(
        report.blocks, 2,
        "only two of the three blocks were unwound"
    );

    // And the tolerant-everywhere policy tolerates the same absence.
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &journal,
        MissingJournalPolicy::ToleratedEverywhere,
    )
    .expect("tolerated everywhere");
    drop(batch);
    assert_eq!(report.tolerated_absences, 1);
}

/// Tolerating an absence in the MIDDLE of a branch makes every block below it
/// fail current-value validation — and that is the check working, not a
/// conflict between two rules.
///
/// Skipping a block leaves its mutations applied. The next block down journalled
/// pre-images taken from a state where those mutations had not happened yet, so
/// its post-images no longer describe what is in the rows. Applying them anyway
/// would write values from a state the node is not in and never will be.
///
/// The refusal names the row, which is what makes it actionable. Worth pinning
/// because it bounds what the compatibility rule can mean: an absence is only
/// tolerable at the OLDEST end of a branch, where nothing below it depends on
/// the skipped block having been reverted. Anywhere else, tolerating it and
/// continuing is not a weaker guarantee — it is a refusal, deliberately.
#[test]
fn a_tolerated_absence_in_the_middle_of_a_branch_refuses_the_blocks_below_it() {
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

    struct Withholding<'a> {
        inner: &'a ObservedJournal,
        withhold: u64,
    }
    impl BranchJournal for Withholding<'_> {
        fn lookup(&self, h: u64, b: &Hash) -> JournalLookup {
            if h == self.withhold {
                JournalLookup::Absent
            } else {
                self.inner.lookup(h, b)
            }
        }
        fn rows(&self, h: u64, b: &Hash) -> Vec<(String, Vec<u8>)> {
            self.inner.rows(h, b)
        }
    }

    let truth = node.journals();
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &Withholding {
            inner: &truth,
            withhold: 2,
        },
        MissingJournalPolicy::ToleratedEverywhere,
    )
    .expect_err(
        "skipping height 2 leaves its mutations applied, so height 1's journal no longer \
         describes the rows and must be refused",
    );
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::CurrentValueMismatch { height: 1, .. }),
        "the refusal must land on the block BELOW the skipped one: {err}"
    );
    assert_eq!(node.snapshot(), before, "a refused unwind writes nothing");
}

/// Tolerating a missing journal leaves that block's state APPLIED. Demonstrated,
/// so the cost of the compatibility rule is on the record and not only in a
/// doc comment.
#[test]
fn a_tolerated_absence_leaves_the_block_it_skipped_applied() {
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
    let at_fork_balance = 10_000_000u128;
    assert_ne!(node.balance(&alice.address()), at_fork_balance);

    struct Nothing;
    impl BranchJournal for Nothing {
        fn lookup(&self, _h: u64, _b: &Hash) -> JournalLookup {
            JournalLookup::Absent
        }
        fn rows(&self, _h: u64, _b: &Hash) -> Vec<(String, Vec<u8>)> {
            Vec::new()
        }
    }

    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &Nothing,
        MissingJournalPolicy::ToleratedEverywhere,
    )
    .expect("tolerated");
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).unwrap();
    batch.commit().unwrap();

    assert_eq!(report.tolerated_absences, 1);
    assert_eq!(report.records, 0, "nothing was reverted");
    assert_eq!(
        node.head().map(|h| h.hash()),
        Some(genesis.hash()),
        "the head moved back to the fork point"
    );
    assert_ne!(
        node.balance(&alice.address()),
        at_fork_balance,
        "the head says the fork point and the state says otherwise; this is what \
         `tolerated_absences` is reporting, and why a caller must not read a switch \
         with a non-zero count as a completed unwind"
    );
}

/// An empty block has no LEGACY journal row, and a positive GENERIC one.
///
/// # What changed, and why this test was rewritten rather than deleted
///
/// It used to assert only the first half, and its note said the live path could
/// not require a journal until a producer wrote a positive nothing-to-undo
/// record — because `JournalRecord::NothingToUndo` makes `publish` write NO row,
/// so on disk "this block mutated nothing" and "this block's undo record is
/// lost" are the same zero bytes, and requiring one would refuse every reorg
/// over an empty block.
///
/// That producer now exists. `publish` writes an application-journal envelope
/// for every block unconditionally, including a zero-entry one, so the two
/// conditions are no longer the same bytes: "mutated nothing" is a record whose
/// `entry_count` is 0, and "record lost" is no row. The test keeps the original
/// assertion — the legacy journals really do still write nothing, which is why
/// they cannot be the post-activation record — and adds the half that closes it.
#[test]
fn an_empty_block_has_no_legacy_journal_row_and_a_positive_generic_one() {
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    let genesis = node.produce(None, &proposer, Vec::new());
    let empty = node.produce(Some(&genesis), &proposer, Vec::new());

    assert!(
        matches!(
            node.subsystem_journals().lookup(1, &empty.hash()),
            JournalLookup::Absent
        ),
        "if an empty block now has a journal row, the publisher writes a positive \
         nothing-to-undo record and the live path can require one"
    );

    // The consequence: under the strict policy the switch halts.
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[empty.clone()],
        &node.subsystem_journals(),
        JOURNAL_REQUIRED,
    )
    .expect_err("strict policy halts on an empty block today");
    drop(batch);
    assert!(matches!(err, UndoRefusal::MissingJournal { .. }), "{err}");

    // And under the pre-activation policy — which is what a database with no
    // generic journal history would resolve to — it is tolerated.
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[empty.clone()],
        &node.subsystem_journals(),
        MissingJournalPolicy::ToleratedEverywhere,
    )
    .expect("the pre-activation policy tolerates it");
    drop(batch);
    assert_eq!(report.tolerated_absences, 1);
    assert_eq!(report.records, 0);

    // ── the half that closes it ──────────────────────────────────────────────
    //
    // The generic journal has a row for the same block, and it is a POSITIVE
    // zero-entry record rather than an absence.
    let row = node
        .db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(1, &empty.hash()),
        )
        .expect("read the journal row")
        .expect("an empty block must still leave a journal envelope");
    let decoded = sumchain_storage::journal::ApplicationJournal::decode_for(&row, 1, &empty.hash())
        .expect("the envelope must decode");
    assert!(
        decoded.is_empty(),
        "a block that wrote nothing must leave a record with no entries, not no record"
    );
    assert_eq!(decoded.height(), 1);
    assert_eq!(decoded.block_hash(), empty.hash());

    // So the STRICT policy — the one the live path now runs — accepts it, with
    // no tolerated absence. "Mutated nothing" and "record lost" are different
    // bytes, so requiring a record no longer refuses an empty block.
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[empty.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("the strict policy accepts an empty block through the generic journal");
    drop(batch);
    assert_eq!(report.blocks, 1, "the block's record was consumed");
    assert_eq!(report.records, 0, "and it had nothing to restore");
    assert_eq!(
        report.tolerated_absences, 0,
        "no absence was tolerated: the record was there"
    );

    // And with the row removed, the same policy HALTS. That is the whole point
    // of the positive record: the two conditions are now distinguishable.
    node.db
        .delete(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(1, &empty.hash()),
        )
        .expect("delete the journal row");
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[empty],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a missing post-activation record must halt");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::UnreadableJournal { .. }),
        "the producer's own load_for_revert refusal must surface, not a silent \
         Absent that a tolerant policy could swallow: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. The generic application journal, driving the acceptance path
//
// Everything below runs on the REAL encoded record: written by `publish`, read
// back off disk through `ApplicationJournalReader`, decoded and validated by
// `ApplicationJournal::decode_for`. The snapshot-diff oracle appears only as a
// comparator, through `assert_oracle_agrees`.
// ─────────────────────────────────────────────────────────────────────────────

/// The row on disk that holds one block's generic journal.
fn journal_row(node: &Node, block: &Block) -> Vec<u8> {
    node.db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
        )
        .expect("read the journal row")
        .expect("every published block leaves a journal row")
}

fn put_journal_row(node: &Node, block: &Block, bytes: &[u8]) {
    node.db
        .put(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
            bytes,
        )
        .expect("overwrite the journal row");
}

/// Every row of one column family, for a byte-level comparison.
fn family(node: &Node, cf_name: &str) -> BTreeMap<Vec<u8>, Vec<u8>> {
    node.db
        .iter(cf_name)
        .expect("iterate")
        .map(|(k, v)| (k.into_vec(), v.into_vec()))
        .collect()
}

/// A block that writes one key several times leaves ONE net entry for it, whose
/// pre-image is the value at the START of the block.
///
/// Three transfers from one sender in one block rewrite that sender's account
/// row three times. The overlay captures the pre-image on the FIRST write and
/// never overwrites it, so the journal holds one entry carrying the balance the
/// block started from — not the intermediate value after the second transfer,
/// which was never a value the chain committed to.
///
/// This is also the invariant that settles the ordering contract. With one entry
/// per key, no two entries of a block can interact, so a deterministic
/// `(cf, key)` order is sufficient and "application order" is a question the
/// consumer does not have to ask.
#[test]
fn multiple_writes_to_one_key_produce_one_correct_net_undo_entry() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    let at_fork = family(&node, cf::STATE);
    let alice_key = sumchain_storage::StateStore::account_key(&alice.address());
    let alice_before = at_fork.get(&alice_key).cloned();

    let block = node.produce(
        Some(&genesis),
        &proposer,
        vec![
            transfer(&alice, &carol.address(), 1_000, 500, 0),
            transfer(&alice, &carol.address(), 2_000, 500, 1),
            transfer(&alice, &carol.address(), 3_000, 500, 2),
        ],
    );
    assert_eq!(block.transactions.len(), 3);

    let JournalLookup::Present { records, header } = node.real_journal().lookup(1, &block.hash())
    else {
        panic!("the published block must have a real journal");
    };
    assert_eq!(header.ordering, EntryOrdering::NetByKey);

    let for_alice: Vec<&UndoRecord> = records
        .iter()
        .filter(|r| r.cf == cf::STATE && r.key == alice_key)
        .collect();
    assert_eq!(
        for_alice.len(),
        1,
        "three writes to one key must journal ONE net entry, not three"
    );
    assert_eq!(
        for_alice[0].before, alice_before,
        "the entry's pre-image must be the value at the START of the block, not \
         an intermediate one"
    );

    assert_oracle_agrees(&node, &block);

    // And it undoes exactly: the account row returns to the fork point.
    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("unwind");
    sumchain_storage::candidate::stage_deindex(&mut batch, &block).expect("deindex");
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
    batch.commit().expect("commit");

    assert_eq!(
        family(&node, cf::STATE),
        at_fork,
        "one net entry per key must restore the whole family to the fork point"
    );
}

/// The current-value check compares against each entry's FINAL value, and a row
/// that has moved on refuses the WHOLE unwind.
///
/// The journal's after-image is an 8-byte domain-separated tag over
/// `(family, key, value)`. This recomputes it from what is committed right now
/// and compares. The interesting case is the one the tag has to get right: a key
/// the block wrote MORE THAN ONCE, where "what the block left" is the final
/// value and not the intermediate one. So the fixture writes three times, then
/// puts the INTERMEDIATE value back — a value the key genuinely held during the
/// block — and requires that to be refused too. A check against anything but the
/// final value would accept it.
#[test]
fn current_value_validation_compares_against_each_entrys_final_value() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    // One block that writes alice's row twice, and one that writes it once more,
    // so an intermediate value for the two-write block is observable.
    let first = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let alice_key = sumchain_storage::StateStore::account_key(&alice.address());
    let intermediate = node
        .db
        .get(cf::STATE, &alice_key)
        .expect("read")
        .expect("alice has a row");

    let second = node.produce(
        Some(&first),
        &proposer,
        vec![
            transfer(&alice, &carol.address(), 2_000, 500, 1),
            transfer(&alice, &carol.address(), 3_000, 500, 2),
        ],
    );
    let after_second = node
        .db
        .get(cf::STATE, &alice_key)
        .expect("read")
        .expect("alice has a row");
    assert_ne!(intermediate, after_second);

    let before_any_write = node.snapshot();

    // ── the row still holds what the block left: accepted ───────────────────
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[second.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("an untouched row must validate");
    drop(batch);
    assert!(report.checks >= report.records);
    assert!(report.records > 0);

    // ── the row holds a value the key really held DURING the block: refused ──
    node.db
        .put(cf::STATE, &alice_key, &intermediate)
        .expect("plant the intermediate value");
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[second.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a row holding an intermediate value is not a row the block left");
    drop(batch);
    match &err {
        UndoRefusal::CurrentValueMismatch { cf: c, key: k, .. } => {
            assert_eq!(*c, cf::STATE);
            assert_eq!(*k, hex::encode(&alice_key));
        }
        other => panic!("wrong refusal: {other:?}"),
    }
    node.db
        .put(cf::STATE, &alice_key, &after_second)
        .expect("restore");

    // ── a row deleted since the block: refused, and nothing is written ───────
    node.db.delete(cf::STATE, &alice_key).expect("delete");
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[second.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("an absent row where the block left a value must be refused");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::CurrentValueMismatch { .. }),
        "{err}"
    );
    node.db
        .put(cf::STATE, &alice_key, &after_second)
        .expect("restore");

    assert_eq!(
        node.snapshot(),
        before_any_write,
        "every refusal above must have written nothing at all"
    );
}

/// The unwind is atomic: a refusal partway through a branch driven by the REAL
/// journal leaves the entire branch applied.
///
/// The counterpart for the oracle already exists. This one matters separately
/// because the real journal's refusal can come from the DECODER — a corrupt
/// record for the second block down — which is a path the oracle cannot reach at
/// all. Everything is staged into one borrowed batch that the caller drops, so
/// the blocks already unwound never reach the database.
#[test]
fn a_refusal_partway_through_a_real_journal_branch_writes_nothing() {
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
    // Truncate the MIDDLE block's record. The unwind runs newest-first, so it
    // stages the newest block and then meets a record that will not decode.
    // Truncation rather than a flipped byte: a flipped after-TAG still decodes
    // and is caught later by the current-value check, which is a different
    // refusal on a different code path — this one is about the decoder.
    let mut bytes = journal_row(&node, &branch[1]);
    bytes.truncate(bytes.len() - 1);
    put_journal_row(&node, &branch[1], &bytes);

    // Taken AFTER the corruption, so what is compared is the effect of the
    // refused unwind and not the effect of the fixture damaging a row.
    let before = node.snapshot();

    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a corrupt record partway down the branch must refuse the whole unwind");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::UnreadableJournal { .. }),
        "{err}"
    );

    assert_eq!(
        node.snapshot(),
        before,
        "the newest block was already staged when the refusal came; dropping the \
         batch must leave the whole branch applied rather than half of it"
    );
}

/// Supply state converges through the real journal, and the legacy journals
/// cannot make it converge.
///
/// `cf::SUPPLY` — the supply ledger, the protocol reserve, the per-address
/// service-grant rows — is written by block execution, folded into
/// `compute_block_state_root` through `SupplyStore::v_state_digest`, and covered
/// by NO hand-written journal. `the_subsystem_journals_do_not_cover_every_family_a_block_writes`
/// measures exactly that gap. The generic journal closes it without knowing the
/// family exists, because it is derived from overlay pre-images rather than from
/// a list.
///
/// Two halves, so this is a demonstration rather than an assertion about shape:
/// the legacy journals leave the abandoned branch's supply rows in place, and
/// the real journal restores them byte for byte. `force_adopted == 0` is what
/// makes the second half mean something — without it the historical
/// compatibility window would forgive the very root mismatch a stale supply row
/// causes.
#[test]
fn supply_state_converges_through_the_real_journal() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let (a, b, genesis) = two_nodes(params, &[(&alice, 10_000_000), (&bob, 10_000_000)]);

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
            vec![transfer(&bob, &carol.address(), 4_000, 700, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }

    // The two branches really do disagree about supply, or this proves nothing.
    assert_ne!(
        family(&a, cf::SUPPLY),
        family(&b, cf::SUPPLY),
        "the fixture must make the two branches disagree about the supply family"
    );

    // ── half one: the legacy journals cannot restore it ──────────────────────
    {
        let mut batch = a.db.batch();
        stage_branch_unwind(
            &a.db,
            &mut batch,
            &branch_a,
            &a.subsystem_journals(),
            MissingJournalPolicy::ToleratedEverywhere,
        )
        .expect("the incomplete journals unwind what they cover");
        let supply_before = family(&a, cf::SUPPLY);
        batch.commit().expect("commit");
        assert_eq!(
            family(&a, cf::SUPPLY),
            supply_before,
            "the four per-subsystem journals record no supply row, so an unwind \
             driven by them leaves every one of them exactly where the abandoned \
             branch left it"
        );
    }

    // That database is now half-unwound, so the second half runs on a fresh pair
    // built the same way rather than on top of it.
    let params = ChainParams::with_v2_enabled();
    let (a, b, genesis) = two_nodes(params, &[(&alice, 10_000_000), (&bob, 10_000_000)]);
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
            vec![transfer(&bob, &carol.address(), 4_000, 700, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    for blk in &branch_b {
        a.retain(blk);
    }
    for blk in &branch_a {
        assert_oracle_agrees(&a, blk);
    }

    // ── half two: the real journal restores it, and the roots verify ─────────
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
        &a.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("the reorg must succeed through the real journal");

    assert_eq!(outcome.unwound.blocks, 3);
    assert_eq!(outcome.unwound.tolerated_absences, 0);
    assert_eq!(outcome.applied, 2);
    assert_eq!(
        outcome.force_adopted, 0,
        "every adopted block's replayed root must EQUAL its header root; a \
         force-adopted block would mean the supply rows were still wrong and the \
         compatibility window forgave it"
    );

    assert_eq!(
        family(&a, cf::SUPPLY),
        family(&b, cf::SUPPLY),
        "the supply family must be byte-identical to the node that built the \
         branch that was adopted"
    );
    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(left, right, "{}", describe_divergence(&left, &right));
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Post-activation refusals, through the real record
// ─────────────────────────────────────────────────────────────────────────────

/// Every way a post-activation record can be wrong HALTS the reorg.
///
/// Five conditions, all against the same block, each restoring the good record
/// afterwards so the next one is measured in isolation:
///
/// * **missing** — the row deleted;
/// * **corrupt** — a byte flipped;
/// * **mis-keyed** — a sibling's record filed under this block's key;
/// * **duplicate-key** — a record holding two entries for one `(cf, key)`;
/// * **identity-mismatched** — a record whose own header names another block.
///
/// The last two are refused by the DECODER — the canonical-order check catches a
/// repeated key, and the `(height, block hash)` check catches a transplanted
/// record — which is why they reach the unwind as `UnreadableJournal` rather
/// than as `DuplicateJournalKey` or `JournalIdentityMismatch`. Both of those
/// variants remain reachable for a producer that does not validate on the way
/// in; here the producer refuses first, which is strictly earlier and strictly
/// louder, and the test asserts that rather than pretending otherwise.
#[test]
fn every_post_activation_record_fault_halts_the_reorg() {
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
    let good = journal_row(&node, &block);
    let before = node.snapshot();

    // A genuine sibling, built on a SECOND node over the same genesis. It has to
    // be built elsewhere: producing it here would apply its state on top of
    // `block`'s, and then `block`'s own record would no longer match the rows it
    // describes — which is a different failure from the one under test.
    let other = Node::new(ChainParams::with_v2_enabled());
    other.seed(&alice, 10_000_000);
    let other_genesis = other.produce(None, &proposer, Vec::new());
    assert_eq!(
        other_genesis.hash(),
        genesis.hash(),
        "the two nodes must share a genesis, or the sibling is not a sibling"
    );
    let sibling = other.produce(
        Some(&other_genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 2_000, 500, 0)],
    );
    assert_eq!(sibling.height(), 1);
    assert_ne!(sibling.hash(), block.hash());

    // ── missing ──────────────────────────────────────────────────────────────
    node.db
        .delete(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(1, &block.hash()),
        )
        .expect("delete");
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a missing post-activation record must halt");
    drop(batch);
    assert!(
        err.to_string().contains("no application journal for block"),
        "the halt must name the block and the boundary: {err}"
    );
    put_journal_row(&node, &block, &good);

    // ── corrupt ──────────────────────────────────────────────────────────────
    let mut corrupt = good.clone();
    corrupt[0] ^= 0xff;
    put_journal_row(&node, &block, &corrupt);
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a corrupt record must halt");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::UnreadableJournal { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("magic"), "{err}");
    put_journal_row(&node, &block, &good);

    // ── mis-keyed: the sibling's record, filed under this block ──────────────
    let siblings_record = journal_row(&other, &sibling);
    assert_ne!(siblings_record, good);
    put_journal_row(&node, &block, &siblings_record);
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a record filed under the wrong block must halt");
    drop(batch);
    assert!(
        err.to_string().contains("another block's undo record"),
        "the record carries its own identity, so this is caught by comparing it \
         with the key it was read under rather than by luck: {err}"
    );
    put_journal_row(&node, &block, &good);

    // ── duplicate key inside one record ──────────────────────────────────────
    //
    // Built by hand: `bind` refuses to construct one, which is the producer-side
    // half of the same invariant. The entry list is the good record's first
    // entry repeated, so the bytes are well-formed in every other respect and
    // the only thing wrong with them is the repetition.
    let dup = record_with_first_entry_repeated(&good);
    put_journal_row(&node, &block, &dup);
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a record with two entries for one key must halt");
    drop(batch);
    assert!(
        err.to_string().contains("canonical order"),
        "a repeated (cf, key) is not strictly increasing, so the decoder refuses \
         it before the unwind ever sees the entries: {err}"
    );
    put_journal_row(&node, &block, &good);

    // ── identity mismatch: the record's own header names another block ───────
    let mut transplanted = good.clone();
    // The header is magic(5) || version(2) || height(8) || block_hash(32).
    transplanted[15..47].copy_from_slice(sibling.hash().as_bytes());
    put_journal_row(&node, &block, &transplanted);
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block.clone()],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect_err("a record whose header names another block must halt");
    drop(batch);
    assert!(
        err.to_string().contains("another block's undo record"),
        "{err}"
    );
    put_journal_row(&node, &block, &good);

    // Nothing above wrote a thing.
    assert_eq!(
        node.snapshot(),
        before,
        "every refusal must leave the database exactly as it was"
    );

    // And the good record still unwinds, so the five refusals above are the
    // checks firing rather than the fixture being unusable.
    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("the untouched record must still be accepted");
    drop(batch);
}

/// Re-encode a record with its FIRST entry repeated, leaving everything else
/// byte-identical.
///
/// Hand-built because no constructor will make one: `ApplicationJournal::bind`
/// refuses a duplicate `(cf, key)` on the way in. Parsing here is deliberately
/// minimal — it reads the header, copies the first entry's bytes, and bumps
/// `entry_count` — so the fixture depends on the wire format's framing and not
/// on any helper that could hide a mistake.
fn record_with_first_entry_repeated(good: &[u8]) -> Vec<u8> {
    const HEADER: usize = 5 + 2 + 8 + 32 + 8; // magic, version, height, hash, count
    let count = u64::from_be_bytes(good[47..55].try_into().unwrap());
    assert!(
        count >= 1,
        "the fixture block must have journalled something"
    );

    // Walk exactly one entry to find its length.
    let mut at = HEADER;
    let take_u64 = |bytes: &[u8], at: &mut usize| -> usize {
        let v = u64::from_be_bytes(bytes[*at..*at + 8].try_into().unwrap()) as usize;
        *at += 8;
        v
    };
    let cf_len = take_u64(good, &mut at);
    at += cf_len;
    let key_len = take_u64(good, &mut at);
    at += key_len;
    match good[at] {
        0 => at += 1,
        1 => {
            at += 1;
            let value_len = take_u64(good, &mut at);
            at += value_len;
        }
        other => panic!("unexpected before_tag {other}"),
    }
    match good[at] {
        0 => at += 1,
        1 => at += 1 + 8,
        other => panic!("unexpected after_tag {other}"),
    }
    let first_entry = good[HEADER..at].to_vec();

    let mut out = good[..47].to_vec();
    out.extend_from_slice(&(count + 1).to_be_bytes());
    out.extend_from_slice(&first_entry);
    out.extend_from_slice(&good[HEADER..]);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Activation: the journal's own gate, and reorgs across its boundary
// ─────────────────────────────────────────────────────────────────────────────

/// The journal's activation gate is its own, and opening it leaves the two
/// dormant subsystem gates exactly where they were.
///
/// `compute_pool_enabled_from_height` and `beacon_enabled_from_height` gate
/// dormant CONSENSUS subsystems: opening either changes which state a block
/// commits, and `Genesis::validate` rejects any `Some(_)` for them. Reusing one
/// of them to switch on undo-journal enforcement would have tied a node-local
/// storage decision to a coordinated consensus activation. So the journal has
/// `application_journal_enabled_from_height`, and this pins that they are three
/// independent fields.
#[test]
fn the_journal_activation_gate_is_its_own_and_leaves_the_dormant_gates_closed() {
    let default = ChainParams::default();
    assert_eq!(
        default.application_journal_enabled_from_height, None,
        "the production default is None: the boundary is OBSERVED from the chain's \
         own journal history, which is not an off position — the write side is \
         ungated, so the first published block establishes it"
    );
    assert_eq!(default.compute_pool_enabled_from_height, None);
    assert_eq!(default.beacon_enabled_from_height, None);

    let mut pinned = ChainParams::default();
    pinned.application_journal_enabled_from_height = Some(1_000);
    assert_eq!(
        pinned.compute_pool_enabled_from_height, None,
        "pinning the journal boundary must not open the compute-pool gate"
    );
    assert_eq!(
        pinned.beacon_enabled_from_height, None,
        "pinning the journal boundary must not open the beacon gate"
    );

    // And the translation into the storage-side rule is the one-site mapping.
    assert_eq!(
        ActivationSource::from_configured_height(None),
        ActivationSource::ObservedFromChain
    );
    assert_eq!(
        ActivationSource::from_configured_height(Some(1_000)),
        ActivationSource::Pinned(1_000)
    );
}

/// A reorg whose range spans the activation boundary decides PER BLOCK: the
/// generic journal at and above it, the legacy journals below it, never both.
///
/// The boundary is pinned partway up the abandoned branch. Below it the generic
/// records are DELETED from disk, so any block that still consulted them would
/// halt; above it the legacy rows are deleted, so any block that fell back would
/// find nothing. Passing therefore means each block was classified correctly and
/// only one record was consulted for it.
///
/// The unwind runs head-first, so it walks from the required region into the
/// fallback region — never the reverse, which is the direction that would need a
/// re-classification mid-range.
#[test]
fn a_reorg_across_the_journal_activation_boundary_decides_per_block() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

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

    const BOUNDARY: u64 = 3;
    let activation =
        JournalActivation::resolve(&node.db, ActivationSource::Pinned(BOUNDARY)).expect("resolve");
    assert_eq!(activation.boundary(), Some(BOUNDARY));
    let journal = ActivatedJournal::new(&node.db, activation);
    assert_eq!(
        journal.policy(),
        MissingJournalPolicy::RequiredFrom(BOUNDARY),
        "the policy must be derived from the same activation the journal holds"
    );

    // Remove the record each side is NOT supposed to consult.
    for blk in &branch {
        if blk.height() < BOUNDARY {
            node.db
                .delete(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(blk.height(), &blk.hash()),
                )
                .expect("delete the generic record below the boundary");
        } else {
            for (cf_name, key) in
                sumchain_state::reorg_undo::subsystem_journal_rows(blk.height(), &blk.hash())
            {
                node.db.delete(&cf_name, &key).expect("delete a legacy row");
            }
        }
    }

    let mut batch = node.db.batch();
    let report = stage_branch_unwind(&node.db, &mut batch, &branch, &journal, journal.policy())
        .expect("a branch spanning the boundary must unwind, each block from its own record");
    for blk in &branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
    batch.commit().expect("commit");

    assert_eq!(
        report.blocks, 4,
        "every block on the branch was accounted for"
    );
    assert_eq!(
        report.tolerated_absences, 0,
        "no block's record was missing: below the boundary the legacy rows are \
         there, at and above it the generic ones are"
    );

    // Account state returns to the fork point. The families the legacy journals
    // never covered are only restored for the blocks at and above the boundary —
    // which is exactly the shortfall the pre-activation region is stuck with,
    // and why the boundary exists rather than being a formality.
    assert_eq!(
        node.head().map(|h| h.hash()),
        Some(genesis.hash()),
        "the head moved back to the fork point"
    );

    // Classification is per height and nothing else.
    assert_eq!(journal.governing(0), JournalRequirement::PreActivation);
    assert_eq!(
        journal.governing(BOUNDARY - 1),
        JournalRequirement::PreActivation
    );
    assert_eq!(journal.governing(BOUNDARY), JournalRequirement::Required);
    assert_eq!(
        journal.governing(BOUNDARY + 100),
        JournalRequirement::Required
    );
}

/// Below the boundary a missing record is tolerated; at and above it, the same
/// absence halts. One branch, one policy, two answers decided by height.
#[test]
fn the_activation_boundary_decides_whether_an_absence_halts() {
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

    // Strip EVERY undo record from the whole branch, so absence is the only
    // condition under test.
    for blk in &branch {
        node.db
            .delete(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(blk.height(), &blk.hash()),
            )
            .expect("delete");
        for (cf_name, key) in
            sumchain_state::reorg_undo::subsystem_journal_rows(blk.height(), &blk.hash())
        {
            node.db.delete(&cf_name, &key).expect("delete");
        }
    }

    // Boundary above the branch: every block is pre-activation, every absence is
    // tolerated and counted.
    let below = ActivatedJournal::new(
        &node.db,
        JournalActivation::resolve(&node.db, ActivationSource::Pinned(100)).expect("resolve"),
    );
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(&node.db, &mut batch, &branch, &below, below.policy())
        .expect("pre-activation absence is tolerated");
    drop(batch);
    assert_eq!(report.tolerated_absences, 3);
    assert_eq!(report.records, 0);

    // Boundary at the foot of the branch: the same absence halts.
    let at = ActivatedJournal::new(
        &node.db,
        JournalActivation::resolve(&node.db, ActivationSource::Pinned(1)).expect("resolve"),
    );
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &branch, &at, at.policy())
        .expect_err("post-activation absence must halt");
    drop(batch);
    assert!(
        err.to_string().contains("no application journal for block"),
        "{err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. Retention: pruning must not outrun the reorg horizon
// ─────────────────────────────────────────────────────────────────────────────

/// The undo-retention floor is the deepest reorg this engine will plan.
///
/// `sumchain_storage::pruner::UNDO_RETENTION_FLOOR` is a duplicate of
/// `sumchain_consensus::poa::MAX_REORG_WALK`, because the pruner sits below
/// consensus and cannot import it. This is the consensus-side half of the pin;
/// `pruner.rs` asserts the same equality from its own side, so the two cannot
/// drift apart without one of them failing.
///
/// If the floor were lower, `plan_reorg` would still be willing to name a block
/// whose journal pruning had already removed — and post-activation that block's
/// unwind HALTS, correctly and uselessly, because the node deleted the record it
/// now needs.
#[test]
fn the_pruning_floor_covers_every_reorg_this_engine_will_plan() {
    assert_eq!(
        sumchain_storage::pruner::UNDO_RETENTION_FLOOR,
        sumchain_consensus::poa::MAX_REORG_WALK,
        "pruning must never remove undo data for a block a reorg can still name"
    );
}

/// Pruning keeps every journal inside the reorg horizon, and a branch that deep
/// still unwinds afterwards.
///
/// The end-to-end version of the pruner's own unit test: publish a branch, run
/// the pruner at a head far above it, and require the branch to unwind through
/// the records that survived. Written against a configuration that ASKS for a
/// short retention, so what is being tested is the floor overriding it rather
/// than a generous default doing the work.
#[test]
fn a_branch_inside_the_reorg_horizon_still_unwinds_after_pruning() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let at_fork = node.snapshot();

    let mut branch = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..3u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }

    // A head just inside the horizon, and a configuration asking to keep almost
    // nothing. The floor is what must save the records.
    let head_height = sumchain_storage::pruner::UNDO_RETENTION_FLOOR;
    let pruner = sumchain_storage::pruner::Pruner::new(
        node.db.clone(),
        sumchain_storage::pruner::PrunerConfig {
            enabled: true,
            blocks_to_keep: 0,
            state_diffs_to_keep: 1,
            compact_after_prune: false,
            ..Default::default()
        },
    );
    pruner.prune(head_height).expect("prune");

    for blk in &branch {
        assert!(
            node.db
                .get(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(blk.height(), &blk.hash()),
                )
                .expect("read")
                .is_some(),
            "block {} is within {} of the head and must keep its journal",
            blk.height(),
            head_height
        );
    }

    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("a revertible branch must still unwind after pruning");
    for blk in &branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
    batch.commit().expect("commit");

    assert_eq!(
        node.snapshot(),
        at_fork,
        "{}",
        describe_divergence(&node.snapshot(), &at_fork)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. Crash recovery across the whole state machine
//
// Four points, because those are the four places a crash can land relative to
// the three durable transitions a switch makes: the journal's publication, the
// canonical state it describes, and the head that names it.
//
// The apply side has only ONE resting state per block, and that is the whole of
// its recovery argument: `publish` stages the journal, the block's state rows,
// the block row, the transactions, the receipts, the indexes and the head into
// one `WriteBatch` and commits it once, and a `WriteBatch` has no interior. So
// "crashed before publication" and "crashed after the journal write" are not two
// windows around one block — they are the two sides of a single instruction, and
// the tests below prove exactly that rather than asserting it from the shape.
// ─────────────────────────────────────────────────────────────────────────────

/// **Crash BEFORE publication.** Neither state nor journal, and the head has not
/// moved.
///
/// The block is executed and ACCEPTED — everything short of the commit — and
/// then dropped. The database must be byte-identical across every column family
/// afterwards, and identical again after a real restart, so what is being
/// measured is durable emptiness rather than an unflushed memtable.
#[test]
fn a_crash_before_publication_leaves_neither_state_nor_journal() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let node = Node::new(params.clone());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let head_before = node.head().map(|h| h.hash());

    let everything_before: BTreeMap<(String, Vec<u8>), Vec<u8>> = convergent_cfs()
        .into_iter()
        .flat_map(|f| {
            node.db
                .iter(f)
                .expect("iterate")
                .map(move |(k, v)| ((f.to_string(), k.into_vec()), v.into_vec()))
        })
        .collect();

    let abandoned = node.execute_and_abandon(
        &genesis,
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );

    let node = node.restart(params);
    let everything_after: BTreeMap<(String, Vec<u8>), Vec<u8>> = convergent_cfs()
        .into_iter()
        .flat_map(|f| {
            node.db
                .iter(f)
                .expect("iterate")
                .map(move |(k, v)| ((f.to_string(), k.into_vec()), v.into_vec()))
        })
        .collect();

    assert_eq!(
        everything_after,
        everything_before,
        "a candidate abandoned before publication must leave the database \
         byte-identical:\n{}",
        describe_divergence(&everything_before, &everything_after)
    );
    assert!(
        node.db
            .get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(1, &abandoned.hash()),
            )
            .expect("read")
            .is_none(),
        "no journal may exist for a block that was never published: an undo record \
         for a block that did not happen is worse than none, because a reader \
         cannot tell it from one that did"
    );
    assert_eq!(node.head().map(|h| h.hash()), head_before);
}

/// **Crash AFTER the journal write.** The journal and the state it describes are
/// the same commit, so a restart finds both or neither — never one.
///
/// This is the property the apply side rests on, and it is checkable rather than
/// merely argued: the record is read back after a real reopen, decoded, and
/// required to identify the block whose rows are also there and whose hash the
/// head names. The negative half is the test above.
#[test]
fn a_crash_after_the_journal_write_finds_the_block_and_its_journal_together() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let node = Node::new(params.clone());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let block = node.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let balance_after = node.balance(&alice.address());

    let node = node.restart(params);

    // The head names the block.
    assert_eq!(node.head().map(|h| h.hash()), Some(block.hash()));
    // The state it wrote is there.
    assert_eq!(node.balance(&alice.address()), balance_after);
    // And so is the journal, identifying that same block.
    let record = node
        .db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(1, &block.hash()),
        )
        .expect("read")
        .expect("the journal is in the same commit as the state it describes");
    let decoded =
        sumchain_storage::journal::ApplicationJournal::decode_for(&record, 1, &block.hash())
            .expect("decode");
    assert_eq!(decoded.block_hash(), block.hash());
    assert_eq!(decoded.height(), 1);
    assert!(
        !decoded.is_empty(),
        "the block wrote rows, so it journalled them"
    );

    // The record still describes the state on disk, which is what makes the
    // reopened node able to revert it. Checked through the unwind's own
    // validation rather than by inspection.
    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &[block],
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("the surviving record must still validate against the surviving state");
    drop(batch);
}

/// **Crash DURING reversal**, before the unwind batch commits.
///
/// The batch is dropped one instruction before `commit`. What must survive is
/// not only the old branch's state but every JOURNAL the interrupted unwind was
/// consuming: restores and the journal's own deletion are in the SAME batch, so
/// dropping it leaves the undo data intact and the retry has everything it had
/// the first time. A design that deleted journals in an earlier batch would
/// leave this state unrecoverable — rows unrestored, and the record saying how
/// already gone.
#[test]
fn a_crash_during_reversal_leaves_every_journal_it_was_consuming() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let params = ChainParams::with_v2_enabled();
    let node = Node::new(params.clone());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    let mut branch = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..3u64 {
        let blk = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch.push(blk);
    }
    let on_old_branch = node.snapshot();
    let records: Vec<Vec<u8>> = branch.iter().map(|b| journal_row(&node, b)).collect();

    {
        let mut batch = node.db.batch();
        stage_branch_unwind(
            &node.db,
            &mut batch,
            &branch,
            &node.real_journal(),
            JOURNAL_REQUIRED,
        )
        .expect("stage");
        for blk in &branch {
            sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
        }
        sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
        drop(batch); // process death, one instruction before `commit`
    }

    let node = node.restart(params);
    assert_eq!(
        node.snapshot(),
        on_old_branch,
        "an uncommitted batch must have changed nothing"
    );
    assert_eq!(
        node.head().map(|h| h.hash()),
        Some(branch[2].hash()),
        "the head still names the old tip, which is how the node knows the unwind \
         never became durable"
    );
    for (blk, expected) in branch.iter().zip(&records) {
        assert_eq!(
            &journal_row(&node, blk),
            expected,
            "block {}'s journal must survive byte-for-byte: it is deleted in the \
             same batch that applies its restores, so an interrupted unwind keeps \
             both or neither",
            blk.height()
        );
    }

    // And the retry works, from exactly the state the crash left.
    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &node.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("the retry must succeed with no manual repair");
    for blk in &branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
    batch.commit().expect("commit");
    assert_eq!(node.head().map(|h| h.hash()), Some(genesis.hash()));
    for blk in &branch {
        assert!(
            node.db
                .get(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(blk.height(), &blk.hash()),
                )
                .expect("read")
                .is_none(),
            "a consumed journal must be gone in the same commit that consumed it"
        );
    }
}

/// **Crash BEFORE the new head is committed**: the unwind is durable, no block
/// of the adopted branch has been published, and the head names the ancestor.
///
/// This is the resting state the previous test's retry lands in, and it is the
/// one with no marker of its own — the head IS the marker. `resume` reads it,
/// restores the accumulator from that block's header, and applies the whole new
/// branch. Nothing re-runs the unwind, because the head says it is done.
#[test]
fn a_crash_before_the_new_head_is_committed_resumes_from_the_ancestor() {
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

    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        DEEP,
    )
    .expect("plan");

    // The unwind commits — and then the process dies before `apply_branch` has
    // published anything.
    {
        let mut batch = a.db.batch();
        stage_branch_unwind(
            &a.db,
            &mut batch,
            &plan.old_branch,
            &a.real_journal(),
            JOURNAL_REQUIRED,
        )
        .expect("stage");
        for blk in &plan.old_branch {
            sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
        }
        sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
        batch.commit().expect("commit");
    }

    let a = a.restart(params);
    assert_eq!(
        a.head().map(|h| h.hash()),
        Some(genesis.hash()),
        "the head must name the ancestor: that is the marker, and it moved in the \
         same batch as the state it names"
    );

    // Recovery. The accumulator is gone with the process and comes back from the
    // head block's own header, which is the only place it is recoverable from.
    let head = a.head().expect("head");
    a.state.set_state_root(accumulator_of(&head));
    let outcome = resume(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &a.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("resume from the ancestor");

    assert_eq!(
        outcome.unwound,
        Default::default(),
        "resume must NOT unwind again: the head already said the unwind was durable"
    );
    assert_eq!(outcome.applied, 2, "the whole new branch is applied");
    assert_eq!(outcome.force_adopted, 0);

    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(left, right, "{}", describe_divergence(&left, &right));
}
