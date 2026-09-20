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
    accumulator_of, apply_branch, execute_reorg, plan_reorg, recorded_head, resume, ReorgOutcome,
    ReorgPlan,
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

    /// `produce`, without the file-local snapshot-diff ORACLE.
    ///
    /// Byte for byte the same publication path — execute, fill in the computed
    /// root, accept, publish, advance the accumulator. The only thing skipped is
    /// `ObservedJournal::snapshot`, which walks every row of the database and is
    /// taken twice per block; that is fine for a fixture publishing three blocks
    /// and quadratic for one publishing thousands.
    ///
    /// Nothing that reads a journal is affected: the oracle is a comparator this
    /// file uses to check the producer against a snapshot diff, and the tests
    /// that use this helper read the REAL records back off disk through
    /// `real_journal()`.
    fn produce_bulk(
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
    ///
    /// Written straight into the family rather than through `BlockStore::put`.
    /// `put` writes `BLOCK_HEIGHT[height] = hash` beside the content-addressed
    /// row, and that key carries no branch identity — so retaining a side branch
    /// through it points the CANONICAL height index at blocks nobody has
    /// adopted. `PoAEngine::import_reorg` had exactly that bug and no longer
    /// does; this fixture modelled the bug rather than the fix, which is why
    /// nothing here ever caught it.
    fn retain(&self, block: &Block) {
        self.db
            .put(cf::BLOCKS, block.hash().as_bytes(), &block.to_bytes())
            .expect("retain block");
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

    // Required only from height 2: the branch (heights 1..=3) now reaches BELOW
    // the boundary while holding blocks above it, so the unwind is refused as a
    // CHECKPOINT CROSSING before the absence at height 1 is ever reached.
    //
    // CHANGED DELIBERATELY. This block used to assert that the absence at
    // height 1 was tolerated and counted, and that two of the three blocks
    // unwound. That was the per-block fallback rule, and it is no longer the
    // policy: the four legacy journals do not cover every family a block wrote,
    // so unwinding the lower part of a crossing branch from them leaves rows
    // applied under a chain that no longer contains the blocks that wrote them,
    // and reports success. The activation height is an irreversible checkpoint
    // instead. The old assertion encoded an assumption that is now false; it is
    // replaced rather than deleted, so the change is visible.
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(
        &node.db,
        &mut batch,
        &branch,
        &journal,
        MissingJournalPolicy::RequiredFrom(2),
    )
    .expect_err("a branch reaching below the boundary must be refused whole");
    drop(batch);
    assert!(
        matches!(
            err,
            UndoRefusal::CrossesActivationCheckpoint {
                boundary: 2,
                lowest: 1,
                highest: 3
            }
        ),
        "{err}"
    );
    assert_eq!(node.snapshot(), before, "a refused unwind writes nothing");

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

    let pinned = ChainParams {
        application_journal_enabled_from_height: Some(1_000),
        ..Default::default()
    };
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

/// A reorg whose range CROSSES the activation boundary is refused whole, and
/// the same branch unwinds cleanly once it stops crossing.
///
/// # This test was rewritten, and the claim it makes is the opposite of the one
/// it used to make
///
/// It was `a_reorg_across_the_journal_activation_boundary_decides_per_block`,
/// and it asserted that a branch spanning the boundary unwound completely, each
/// block from its own record. Choosing the record per block is still exactly
/// what `ActivatedJournal` does, and the classification assertions below are
/// kept unchanged because they are still true. What was false is the conclusion
/// drawn from them: that per-block selection made a crossing unwind CORRECT.
///
/// It does not. Selecting the record answers "which record governs this block".
/// It cannot answer "what restores the families no record covers". Below the
/// boundary the only records are the four legacy per-subsystem journals, and
/// `the_subsystem_journals_do_not_cover_every_family_a_block_writes` measures
/// precisely how incomplete they are — `cf::SUPPLY` is restorable from none of
/// them. So the old behaviour reverted the upper blocks completely and the lower
/// blocks partially, committed both in one batch, moved the head, and returned
/// `Ok`. The abandoned rows stayed applied, silently.
///
/// The policy is now that the activation height is an IRREVERSIBLE CHECKPOINT.
/// A branch reaching below it while holding blocks at or above it is refused
/// before a single row is staged.
#[test]
fn a_reorg_crossing_the_journal_activation_boundary_is_refused_whole() {
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

    // Remove the record each side is NOT supposed to consult. Unchanged from the
    // original test: it is what makes the per-block classification observable
    // rather than asserted.
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

    // The classification is still per block, and still correct. Every block
    // finds a record through the journal it is supposed to consult — which is
    // exactly why the old test passed, and exactly why passing was not evidence
    // of safety.
    for blk in &branch {
        assert!(
            matches!(
                journal.lookup(blk.height(), &blk.hash()),
                sumchain_state::reorg_undo::JournalLookup::Present { .. }
            ),
            "height {} must resolve through its own record",
            blk.height()
        );
    }
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

    // And the crossing unwind is refused anyway, naming the span and the
    // boundary, with nothing staged.
    let before = node.snapshot();
    let head_before = node.head().map(|h| h.hash());
    let mut batch = node.db.batch();
    let err = stage_branch_unwind(&node.db, &mut batch, &branch, &journal, journal.policy())
        .expect_err("a branch crossing the checkpoint must be refused");
    drop(batch);
    assert!(
        matches!(
            err,
            UndoRefusal::CrossesActivationCheckpoint {
                boundary: BOUNDARY,
                lowest: 1,
                highest: 4
            }
        ),
        "{err}"
    );
    assert_eq!(node.snapshot(), before, "a refusal writes nothing");
    assert_eq!(
        node.head().map(|h| h.hash()),
        head_before,
        "and does not move the head"
    );

    // The same branch, truncated to the blocks at and above the boundary, is not
    // a crossing and unwinds completely from generic records alone — the legacy
    // rows for these heights were deleted above, so nothing else could have done
    // it. This is the region the checkpoint keeps reversible.
    let above: Vec<_> = branch
        .iter()
        .filter(|b| b.height() >= BOUNDARY)
        .cloned()
        .collect();
    assert_eq!(above.len(), 2);
    let fork_point = branch[BOUNDARY as usize - 2].clone();
    assert_eq!(fork_point.height(), BOUNDARY - 1);
    let mut batch = node.db.batch();
    let report = stage_branch_unwind(&node.db, &mut batch, &above, &journal, journal.policy())
        .expect("a branch wholly at or above the boundary unwinds from generic records");
    for blk in &above {
        sumchain_storage::candidate::stage_deindex(&mut batch, blk).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &fork_point).expect("head");
    batch.commit().expect("commit");
    assert_eq!(report.blocks, 2);
    assert_eq!(
        report.tolerated_absences, 0,
        "no absence is tolerated at or above the boundary"
    );
    assert_eq!(
        node.head().map(|h| h.hash()),
        Some(fork_point.hash()),
        "the head moved back to the last block the checkpoint allows reverting to"
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

// ─────────────────────────────────────────────────────────────────────────────
// 13. The activation boundary is an irreversible checkpoint
//
// Release blocker 1. Below the boundary the only undo records are the four
// legacy per-subsystem journals, and
// `the_subsystem_journals_do_not_cover_every_family_a_block_writes` measures how
// incomplete they are. Selecting the record per block answers "which record
// governs this block"; it cannot answer "what restores the families no record
// covers". So a reorg that crosses the boundary is refused whole.
// ─────────────────────────────────────────────────────────────────────────────

/// The REAL reorg driver refuses a crossing switch, writes nothing, and leaves
/// the head where it was.
///
/// Not `stage_branch_unwind` in isolation: `execute_reorg` is the function
/// `PoAEngine::import_reorg` calls, over a plan `plan_reorg` built, with the
/// `ActivatedJournal` a pinned `ChainParams` gate produces. The refusal has to
/// hold there or it holds nowhere.
#[test]
fn a_reorg_crossing_the_checkpoint_is_refused_by_the_real_reorg_driver() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

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
    assert_eq!(plan.depth(), 3, "the abandoned branch spans heights 1..=3");

    // The boundary sits INSIDE the abandoned branch: heights 1 and 2 are
    // pre-activation, height 3 is required. This is the configuration the
    // per-block rule used to accept.
    const BOUNDARY: u64 = 3;
    let journal = ActivatedJournal::new(
        &a.db,
        JournalActivation::resolve(&a.db, ActivationSource::Pinned(BOUNDARY)).expect("resolve"),
    );
    assert_eq!(
        journal.policy(),
        MissingJournalPolicy::RequiredFrom(BOUNDARY)
    );

    let before = a.snapshot();
    let head_before = a.head().map(|h| h.hash());
    let err = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &journal,
        journal.policy(),
    )
    .expect_err("a switch whose abandoned branch crosses the checkpoint must be refused");
    let rendered = err.to_string();
    assert!(
        rendered.contains("crosses this chain's application-journal activation boundary")
            && rendered.contains("irreversible checkpoint"),
        "the refusal must name the boundary and the policy: {rendered}"
    );
    assert_eq!(
        a.snapshot(),
        before,
        "a refused switch writes nothing at all"
    );
    assert_eq!(
        a.head().map(|h| h.hash()),
        head_before,
        "and leaves the node on the branch it was already on"
    );

    // The same switch, with the boundary at the FOOT of the abandoned branch,
    // is not a crossing and succeeds — so what was refused above is the
    // crossing and not the switch.
    let journal = ActivatedJournal::new(
        &a.db,
        JournalActivation::resolve(&a.db, ActivationSource::Pinned(1)).expect("resolve"),
    );
    let outcome = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &journal,
        journal.policy(),
    )
    .expect("a switch wholly at or above the boundary is unaffected");
    assert_eq!(outcome.unwound.blocks, 3);
    assert_eq!(outcome.applied, 2);
    assert_eq!(outcome.force_adopted, 0);
    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(
        left,
        right,
        "the reorged node did not converge:\n{}",
        describe_divergence(&left, &right)
    );
}

/// A reorg wholly BELOW the boundary is NOT a crossing and is left alone.
///
/// This is the shape an operator gets by pinning a boundary above the current
/// head: the chain has not activated over that range at all, every block in it
/// is pre-journal history, and §7.1 says the legacy behaviour is unchanged.
/// Refusing here would refuse every reorg on such a chain, which is a different
/// and much larger claim than the one the checkpoint makes.
#[test]
fn a_reorg_wholly_below_the_boundary_is_not_a_crossing() {
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

    // Boundary far above the branch. Every block is pre-activation, and the
    // legacy journals — incomplete as they are — are what unwinds it, exactly as
    // before this work.
    let journal = ActivatedJournal::new(
        &node.db,
        JournalActivation::resolve(&node.db, ActivationSource::Pinned(100)).expect("resolve"),
    );
    assert!(
        sumchain_state::reorg_undo::crosses_activation_checkpoint(&branch, journal.policy())
            .is_none(),
        "a branch wholly below the boundary does not cross it"
    );
    let mut batch = node.db.batch();
    stage_branch_unwind(&node.db, &mut batch, &branch, &journal, journal.policy())
        .expect("a wholly pre-activation branch still unwinds from the legacy journals");
    drop(batch);
}

/// The checkpoint is SELF-EXTINGUISHING, and this is the arithmetic that says
/// when it stops binding.
///
/// `plan_reorg` never walks further than `MAX_REORG_WALK` blocks back from the
/// head, so once the head is `MAX_REORG_WALK` blocks above the boundary, no plan
/// the engine will ever build can name a block below it — and the checkpoint
/// cannot refuse anything. The availability cost of blocker 1's policy is
/// therefore bounded to the first `MAX_REORG_WALK` blocks after activation, and
/// this pins that rather than leaving it as a claim in a doc comment.
#[test]
fn the_checkpoint_stops_binding_once_the_head_outruns_the_engine_walk_limit() {
    const BOUNDARY: u64 = 10_000;
    let walk = sumchain_consensus::poa::MAX_REORG_WALK;

    // `plan_reorg` refuses once either walk exceeds `max_depth`, and the walk
    // vector carries the ancestor as its last element, so the deepest abandoned
    // branch it will ever return is exactly `walk` blocks long — pinned by
    // `reorg::tests::an_excessively_deep_reorg_is_refused`. The lowest height
    // such a branch can contain is therefore `head - walk + 1`.
    let lowest_reachable = |head: u64| head.saturating_sub(walk) + 1;

    // The last head at which a crossing is still expressible.
    let head = BOUNDARY + walk - 2;
    assert!(
        lowest_reachable(head) < BOUNDARY,
        "at head {head} the engine can still name a block below {BOUNDARY}"
    );

    // From `BOUNDARY + walk - 1` onward it cannot, ever again.
    for head in [BOUNDARY + walk - 1, BOUNDARY + walk, BOUNDARY + 1_000_000] {
        assert!(
            lowest_reachable(head) >= BOUNDARY,
            "at head {head} no plan can reach below {BOUNDARY}, so the checkpoint is inert"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. What a node may honestly claim it can revert
//
// The journal is node-local: never committed, never in a root, never
// transmitted. A node that arrives by snapshot restore or fast sync holds
// canonical state and NO undo history, so `UNDO_RETENTION_FLOOR` — a promise not
// to DISCARD undo data — says nothing about how much it HAS.
// ─────────────────────────────────────────────────────────────────────────────

/// The depth a node advertises is exactly the depth the checkpoint lets it
/// unwind. One number, two readings, and they are pinned to each other.
///
/// A node restored from a snapshot at height 5,000 holds canonical state and no
/// journals at all — journals are node-local and are not transmitted, and a
/// pre-image cannot be derived from a post-state. Its first published block is
/// 5,001, which becomes its observed boundary. `UNDO_RETENTION_FLOOR = 4_096` is
/// irrelevant to it: retention is a promise not to DISCARD undo history, never a
/// claim to HAVE it.
#[test]
fn the_advertised_reorg_depth_is_the_depth_the_checkpoint_actually_allows() {
    let node = Node::new(ChainParams::with_v2_enabled());
    let walk = sumchain_consensus::poa::MAX_REORG_WALK;

    const RESTORE: u64 = 5_000;
    const BOUNDARY: u64 = RESTORE + 1;
    let activation =
        JournalActivation::resolve(&node.db, ActivationSource::Pinned(BOUNDARY)).expect("resolve");

    for published in [0u64, 1, 200, walk - 1, walk, walk + 1, 100_000] {
        let head = RESTORE + published;
        assert_eq!(
            activation.advertisable_reorg_depth(head, walk),
            published.min(walk),
            "after {published} published block(s) the node may claim {} and no more",
            published.min(walk)
        );
        assert_eq!(activation.restorable_depth(head), published);
    }

    // The claim is not separately maintained. A branch of exactly the advertised
    // depth stays at or above the boundary and does not cross the checkpoint; one
    // block deeper reaches below it and does.
    let policy = MissingJournalPolicy::RequiredFrom(BOUNDARY);
    let head = RESTORE + 200;
    let depth = activation.advertisable_reorg_depth(head, walk);
    assert_eq!(depth, 200);
    let fake = |lowest: u64, highest: u64| (lowest..=highest).collect::<Vec<_>>();
    // Expressed over heights rather than blocks, because what the checkpoint
    // reads off a branch is exactly its lowest and highest height.
    for (lowest, crossing) in [
        (head + 1 - depth, false), // the advertised depth, to the block
        (head - depth, true),      // one block deeper
    ] {
        let span = fake(lowest, head);
        let crosses = *span.iter().min().unwrap() < BOUNDARY;
        assert_eq!(
            crosses, crossing,
            "a branch spanning {lowest}..={head} against boundary {BOUNDARY}"
        );
    }
    let _ = policy;

    // Immediately after the restore, before the node has published anything, the
    // honest depth is ZERO — not 4_096, and not the engine limit.
    assert_eq!(activation.advertisable_reorg_depth(RESTORE, walk), 0);
    assert_eq!(activation.restorable_depth(RESTORE), 0);
}

/// The observed boundary a restored node establishes is the first height it
/// publishes, measured on a real database rather than asserted.
#[test]
fn a_node_with_no_journal_history_advertises_zero_until_it_publishes() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let walk = sumchain_consensus::poa::MAX_REORG_WALK;

    // Before any block: no journal history, nothing revertible.
    let empty =
        JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain).expect("resolve");
    assert_eq!(empty.boundary(), None);
    assert_eq!(empty.advertisable_reorg_depth(0, walk), 0);

    let genesis = node.produce(None, &proposer, Vec::new());
    let mut parent = genesis;
    for n in 0..3u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    let head = parent.height();
    let act =
        JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain).expect("resolve");
    assert_eq!(
        act.boundary(),
        Some(0),
        "this fixture publishes genesis through `publish` too, so its history starts at 0"
    );
    assert_eq!(
        act.advertisable_reorg_depth(head, walk),
        head + 1,
        "every block this node published is revertible, and nothing below that is"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Resource sizing: what the journal costs on disk and in memory
//
// Release blocker 7. With pruning disabled (`PrunerConfig::enabled` is `false`
// by default and nothing in `crates/node` constructs a `Pruner`), the journal
// column family grows without bound, so the growth rate is an operational
// number somebody has to have. These tests MEASURE it against real published
// blocks rather than estimating it from the record layout, and the figures they
// print are the ones `docs/lane-a/JOURNAL-CONTRACT.md` §12 quotes.
// ─────────────────────────────────────────────────────────────────────────────

/// Journal bytes per published block, measured, with a fixed cost and a
/// per-transaction marginal cost separated.
///
/// The marginal cost is the interesting one: it is what multiplies by the
/// transaction rate, and it is what a capacity plan is a function of. Asserted
/// with bounds rather than exact equality — the record layout is pinned by the
/// producer's own tests, and pinning byte totals here would make this test fail
/// for reasons that have nothing to do with resource sizing.
#[test]
fn journal_bytes_per_block_are_measured_against_real_published_blocks() {
    let proposer = key(9);
    let mut measured: Vec<(usize, usize)> = Vec::new();

    for tx_count in [0usize, 1, 8, 32] {
        let node = Node::new(ChainParams::with_v2_enabled());
        let senders: Vec<_> = (0..tx_count).map(|i| key(20 + i as u8)).collect();
        for s in &senders {
            node.seed(s, 10_000_000);
        }
        let recipient = key(3);
        let genesis = node.produce(None, &proposer, Vec::new());
        let txs: Vec<_> = senders
            .iter()
            .map(|s| transfer(s, &recipient.address(), 1_000, 500, 0))
            .collect();
        let block = node.produce(Some(&genesis), &proposer, txs);

        let raw = node
            .db
            .get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
            )
            .expect("read")
            .expect("every published block has a record");
        let decoded = sumchain_storage::journal::ApplicationJournal::decode_for(
            &raw,
            block.height(),
            &block.hash(),
        )
        .expect("decode");
        println!(
            "journal sizing: {tx_count:>3} tx -> {:>6} bytes, {} entries ({} families)",
            raw.len(),
            decoded.entries().len(),
            decoded.column_families().len()
        );
        measured.push((tx_count, raw.len()));
    }

    // Fixed cost: the header is 55 bytes, and a block's non-transaction writes
    // (the proposer's fee credit, the supply rows) are the rest. The zero-tx
    // measurement IS the fixed cost, which is why it is taken.
    let (_, zero) = measured[0];
    let (_, one) = measured[1];
    let (_, eight) = measured[2];
    let (_, thirty_two) = measured[3];
    assert!(
        zero >= 55,
        "a record cannot be smaller than its own header: {zero}"
    );
    println!("journal sizing: fixed cost (0 tx) = {zero} bytes");

    // Marginal cost per transaction, taken across the widest span measured so
    // the fixed cost cancels.
    let marginal = (thirty_two - one) as f64 / 31.0;
    assert!(
        one > zero,
        "a transaction must journal something: {zero}, {one}"
    );
    println!("journal sizing: marginal cost ~{marginal:.0} bytes per transaction");
    assert!(
        (40.0..400.0).contains(&marginal),
        "the per-transaction marginal journal cost is {marginal:.0} bytes, outside the \
         range this capacity plan was written against; the sizing in \
         docs/lane-a/JOURNAL-CONTRACT.md §12 needs revisiting"
    );
    assert!(
        eight > one && thirty_two > eight,
        "journal size must grow with the write set: {one}, {eight}, {thirty_two}"
    );

    // A full block at the chain's own ceiling, extrapolated from the marginal
    // cost, against the 1 GiB logical candidate ceiling the tree carries.
    let max_txs = ChainParams::default().max_txs_per_block as f64;
    let full_block = one as f64 + marginal * (max_txs - 1.0);
    println!("journal sizing: a full {max_txs:.0}-tx block journals ~{full_block:.0} bytes");
    assert!(
        full_block < sumchain_state::MAX_BLOCK_WRITE_SET_BYTES as f64,
        "a full block's journal must fit inside MAX_BLOCK_WRITE_SET_BYTES with room to \
         spare, or the ceiling is the binding constraint rather than the block limit"
    );
}

/// A pre-image is charged TWICE against the candidate ceiling — once by the
/// overlay that captured it, once by the journal's copy of it — and this
/// measures the factor rather than restating §9 of the contract.
///
/// This is the memory overhead the journal adds to a candidate in flight. It is
/// not a disk figure: it is what a node must have headroom for while executing
/// a block, and it is the reason the effective publishing ceiling for a block
/// near the limit is tighter than the limit says.
#[test]
fn a_preimage_is_charged_twice_and_the_factor_is_measured() {
    let proposer = key(9);

    // Two blocks whose write sets differ only in size, so the difference in
    // charged bytes is attributable to the pre-images alone.
    let mut charged = Vec::new();
    for tx_count in [1usize, 16] {
        let node = Node::new(ChainParams::with_v2_enabled());
        let senders: Vec<_> = (0..tx_count).map(|i| key(40 + i as u8)).collect();
        for s in &senders {
            node.seed(s, 10_000_000);
        }
        let recipient = key(3);
        let genesis = node.produce(None, &proposer, Vec::new());
        let txs: Vec<_> = senders
            .iter()
            .map(|s| transfer(s, &recipient.address(), 1_000, 500, 0))
            .collect();
        let block = node.produce(Some(&genesis), &proposer, txs);

        let raw = node
            .db
            .get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(block.height(), &block.hash()),
            )
            .expect("read")
            .expect("record");
        let decoded = sumchain_storage::journal::ApplicationJournal::decode_for(
            &raw,
            block.height(),
            &block.hash(),
        )
        .expect("decode");

        // The pre-image bytes the overlay captured, as the journal reports them.
        let preimage_bytes: usize = decoded
            .entries()
            .iter()
            .map(|e| match e.before() {
                sumchain_storage::journal::Preimage::Value(v) => v.len(),
                sumchain_storage::journal::Preimage::Absent => 0,
            })
            .sum();
        println!(
            "journal memory: {tx_count:>3} tx -> {} pre-image bytes, {} journal bytes \
             (framing {} bytes)",
            preimage_bytes,
            raw.len(),
            raw.len() - preimage_bytes
        );
        charged.push((preimage_bytes, raw.len()));
    }

    // The journal is a SECOND copy of every pre-image, plus framing. So the
    // total a candidate must have headroom for is the overlay's capture plus
    // the journal's copy: 2N + framing, not N.
    for (preimage_bytes, journal_bytes) in &charged {
        assert!(
            journal_bytes >= preimage_bytes,
            "the journal carries every pre-image, so it cannot be smaller than they are"
        );
        let total_charged = preimage_bytes + journal_bytes;
        assert!(
            total_charged >= 2 * preimage_bytes,
            "a pre-image is charged twice: {total_charged} against {preimage_bytes}"
        );
    }

    // Growing the pre-image set raises the charge by twice the growth, plus
    // framing — the exact statement §9 of the contract makes about the ceiling.
    let (p1, j1) = charged[0];
    let (p16, j16) = charged[1];
    let preimage_growth = p16 - p1;
    let charge_growth = (p16 + j16) - (p1 + j1);
    println!(
        "journal memory: pre-images grew {preimage_growth} bytes, charged bytes grew \
         {charge_growth} ({:.2}x)",
        charge_growth as f64 / preimage_growth.max(1) as f64
    );
    assert!(
        charge_growth >= 2 * preimage_growth,
        "growing pre-images by N must raise the charge by at least 2N: {charge_growth} \
         against {preimage_growth}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. Depth: a real reorg at a reduced horizon, and capacity at the real one
//
// Release blocker 3. The retention floor was pinned to `MAX_REORG_WALK` by
// constant equality on both sides and exercised against seeded rows; the
// deepest REAL reorg anywhere was three blocks. Two tests close that, by the
// second of the two routes the blocker allows:
//
//   * this one — a real multi-block reorg through the IDENTICAL production
//     algorithm (`plan_reorg` -> `execute_reorg` -> `stage_branch_unwind`),
//     with only the horizon reduced, and with the real `Pruner` run at the real
//     `UNDO_RETENTION_FLOOR` in between so the floor is what preserved the
//     records the unwind then consumes;
//   * `the_retained_undo_set_at_the_real_floor_is_bounded_and_complete`, a
//     storage/capacity test at the real constant.
//
// Why this route and not a real 4,096-block reorg: the two branches would be
// ~8,200 real block executions plus a 4,096-block unwind and re-apply, and the
// publication path here runs at a few blocks per second. A test that takes tens
// of minutes is a test that gets disabled. What a deeper run would exercise
// that this one does not is LOOP COUNT — the code is the same code, the batch
// is the same single batch, and the per-block work does not change with depth.
// The one thing depth changes that a short test cannot see is the SIZE of the
// single unwind batch, and that is what the capacity test measures at 4,096.
// ─────────────────────────────────────────────────────────────────────────────

/// A REAL reorg at the engine's full production depth — 4,096 abandoned blocks
/// — over a chain long enough for the real pruner at the real
/// `UNDO_RETENTION_FLOOR` to have deleted something, with every record read back
/// off disk.
///
/// # Why this is route A and not route B
///
/// Publishing a real block through this fixture costs about two milliseconds, so
/// the 8,300 blocks this needs cost seconds rather than the tens of minutes that
/// would have forced a reduced horizon. Nothing here is reduced: `MAX_REORG_WALK`
/// is passed to `plan_reorg` unchanged, `UNDO_RETENTION_FLOOR` is the real
/// constant, the pruner is asked to keep far LESS than the floor so that what
/// preserves the branch is the floor overriding the configuration, and the
/// abandoned branch is exactly as deep as the engine will ever plan.
///
/// The fork is arranged by determinism rather than by copying: both nodes build
/// the same prefix from the same transactions, and `produce_bulk` derives every
/// header field from the height, so the prefix blocks are byte-identical and the
/// fork point is a real common ancestor.
///
/// What this leaves unmeasured: nothing about depth. The single unwind batch
/// here holds every one of the 4,096 blocks' restores, which is the one property
/// a shallow test cannot reach.
#[test]
fn a_real_reorg_at_the_full_production_depth_survives_the_real_retention_floor() {
    let walk = sumchain_consensus::poa::MAX_REORG_WALK;
    const PREFIX: u64 = 64;

    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, u128::MAX / 4), (&bob, u128::MAX / 4)],
    );

    // The shared prefix, built independently and identically on both nodes.
    let started = std::time::Instant::now();
    let mut fork_point_a = genesis.clone();
    let mut fork_point_b = genesis.clone();
    for n in 0..PREFIX {
        let tx = transfer(&alice, &carol.address(), 1_000, 500, n);
        fork_point_a = a.produce_bulk(Some(&fork_point_a), &proposer, vec![tx.clone()]);
        fork_point_b = b.produce_bulk(Some(&fork_point_b), &proposer, vec![tx]);
    }
    assert_eq!(
        fork_point_a.hash(),
        fork_point_b.hash(),
        "the shared prefix must be byte-identical, or the fork has no common ancestor"
    );
    assert_eq!(fork_point_a.height(), PREFIX);

    // A's branch: `MAX_REORG_WALK - 1` blocks above the fork point.
    //
    // CORRECTED from an earlier revision of this comment, which said the walk
    // vectors' ancestor element made the maximum `max_depth - 1`. That is not
    // the rule. `plan_reorg` refuses when EITHER branch exceeds `max_depth`
    // blocks, so the abandoned branch may be up to `max_depth` on its own. What
    // binds here is the OTHER branch: the adopted one has to be longer for fork
    // choice to want it, so an abandoned branch of `MAX_REORG_WALK` implies an
    // adopted branch of `MAX_REORG_WALK + 1`, and that is what is refused. The
    // assertion below measures both directions rather than restating either.
    //
    // Either way the consequence is the same and is the safe direction:
    // `UNDO_RETENTION_FLOOR = 4_096` covers every branch a longest-chain switch
    // can abandon.
    let mut branch_a = Vec::new();
    let mut parent = fork_point_a.clone();
    for n in 0..walk - 1 {
        parent = a.produce_bulk(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, PREFIX + n)],
        );
        branch_a.push(parent.clone());
    }
    // B's branch: one longer, from a disjoint sender so no transaction is on
    // both branches.
    let mut branch_b = Vec::new();
    let mut parent = fork_point_b.clone();
    for n in 0..walk {
        parent = b.produce_bulk(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 2_000, 500, n)],
        );
        branch_b.push(parent.clone());
    }
    let head_height = branch_a.last().unwrap().height();
    println!(
        "depth evidence: published {} real blocks in {:?}; A's head is {}",
        4 * PREFIX + 2 * walk - 1,
        started.elapsed(),
        head_height
    );
    assert_eq!(head_height, PREFIX + walk - 1);

    for blk in &branch_b {
        a.retain(blk);
    }

    // ── the real pruner, at the real head, at the real floor ────────────────
    //
    // Asked to keep 8 blocks of undo data on a chain whose head is above the
    // floor. The floor raises that to 4,096, so the prune line lands at
    // `head - 4_096`, which is BELOW the fork point and therefore below every
    // record the unwind needs. Something is deleted — that is the point; an
    // unfloored pruner at this head would have deleted the whole branch.
    let pruner = sumchain_storage::pruner::Pruner::new(
        a.db.clone(),
        sumchain_storage::pruner::PrunerConfig {
            blocks_to_keep: 0,
            state_diffs_to_keep: 8,
            max_db_size_bytes: 0,
            compact_after_prune: false,
            enabled: true,
        },
    );
    assert_eq!(
        pruner.undo_retention(),
        sumchain_storage::pruner::UNDO_RETENTION_FLOOR
    );
    let stats = pruner.prune(head_height).expect("prune");
    println!(
        "depth evidence: the pruner removed {} journal(s) and {} state diff(s) at head \
         {head_height} (line at {})",
        stats.application_journals_pruned,
        stats.state_diffs_pruned,
        head_height - sumchain_storage::pruner::UNDO_RETENTION_FLOOR
    );
    assert!(
        stats.application_journals_pruned > 0,
        "the pruner must actually have run and deleted something, or this proves nothing \
         about the floor"
    );

    // Every record inside the horizon survived, decodes, and identifies itself.
    let retained_bytes: usize = branch_a
        .iter()
        .map(|blk| {
            let raw =
                a.db.get(
                    cf::APPLICATION_JOURNAL,
                    &sumchain_storage::schema::journal_key(blk.height(), &blk.hash()),
                )
                .expect("read")
                .unwrap_or_else(|| {
                    panic!(
                        "the floor deleted the record for height {} that a reorg can still \
                         name",
                        blk.height()
                    )
                });
            sumchain_storage::journal::ApplicationJournal::decode_for(
                &raw,
                blk.height(),
                &blk.hash(),
            )
            .expect("a surviving record must still decode");
            raw.len()
        })
        .sum();
    println!(
        "depth evidence: {} retained journal records total {} bytes ({:.1} MiB)",
        branch_a.len(),
        retained_bytes,
        retained_bytes as f64 / (1024.0 * 1024.0)
    );

    // ── the reorg, at full depth, through the production algorithm ───────────
    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        walk,
    )
    .expect("the deepest branch the engine will plan must be plannable");
    assert_eq!(plan.ancestor_hash, fork_point_a.hash());
    assert_eq!(
        plan.depth(),
        walk - 1,
        "the abandoned branch must be exactly as deep as the engine will ever plan"
    );

    // One block deeper is refused, which is what makes the line above a
    // MAXIMUM rather than an arbitrary large number. The refusal names the
    // ADOPTED branch, at 4,096 against a budget of 4,095 — the abandoned branch
    // is 4,095 and would have fitted.
    let deeper = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        walk - 1,
    );
    assert!(
        deeper.is_err(),
        "a walk budget one below the engine's must refuse this very plan"
    );
    assert!(
        sumchain_storage::pruner::UNDO_RETENTION_FLOOR >= plan.depth(),
        "the retention floor must cover the deepest branch the engine will plan"
    );

    let switching = std::time::Instant::now();
    let outcome = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &a.real_journal(),
        JOURNAL_REQUIRED,
    )
    .expect("execute_reorg at full depth");
    println!(
        "depth evidence: unwound {} blocks ({} records, {} checks) and applied {} in {:?}",
        outcome.unwound.blocks,
        outcome.unwound.records,
        outcome.unwound.checks,
        outcome.applied,
        switching.elapsed()
    );

    assert_eq!(outcome.unwound.blocks, walk - 1);
    assert_eq!(
        outcome.unwound.tolerated_absences, 0,
        "no record inside the horizon may have been missing"
    );
    assert_eq!(outcome.unwound.checks, outcome.unwound.records);
    assert_eq!(outcome.applied, walk);
    assert_eq!(
        outcome.force_adopted, 0,
        "every adopted root must be REPRODUCED by replay at this depth too"
    );

    // Convergence, minus the two families the PRUNER deliberately emptied on A
    // and not on B. They are node-local undo metadata, not application state: A
    // ran a pruner and B did not, so they are expected to differ, and comparing
    // them would be comparing the pruner's effect rather than the reorg's. Every
    // other family — including `cf::SUPPLY`, which no legacy journal covers — is
    // compared in full.
    let pruned_families = [cf::APPLICATION_JOURNAL, cf::STATE_DIFFS];
    let without_undo = |snap: BTreeMap<(String, Vec<u8>), Vec<u8>>| {
        snap.into_iter()
            .filter(|((family, _), _)| !pruned_families.contains(&family.as_str()))
            .collect::<BTreeMap<_, _>>()
    };
    let left = without_undo(a.snapshot());
    let right = without_undo(b.snapshot());
    let compared: std::collections::BTreeSet<&str> =
        left.keys().map(|(family, _)| family.as_str()).collect();
    assert!(
        compared.contains(cf::STATE) && compared.len() >= 2,
        "the comparison must still cover real application state: {compared:?}"
    );
    assert_eq!(
        left,
        right,
        "a {}-block reorg did not converge with the branch it adopted:\n{}",
        walk - 1,
        describe_divergence(&left, &right)
    );
    assert_eq!(
        a.head().map(|h| h.hash()),
        Some(branch_b.last().unwrap().hash())
    );
    assert_eq!(
        a.state.state_root(),
        accumulator_of(branch_b.last().unwrap())
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. The canonical height index, in BOTH directions
//
// Release blocker 11. `import_reorg` used to retain the arriving block through
// `BlockStore::put`, which writes `BLOCK_HEIGHT[height] = hash` beside the
// content-addressed `BLOCKS` row; a refused switch then left the canonical
// height index naming a block that had not been adopted. That is fixed. Only
// ONE of the two directions was ever wrong, so both are pinned here: a future
// change that "fixes" the refusal by never writing the index would break
// adoption, and nothing would have noticed.
// ─────────────────────────────────────────────────────────────────────────────

/// Every `BLOCK_HEIGHT` row, as height -> hash.
fn height_index(node: &Node) -> BTreeMap<u64, Hash> {
    node.db
        .iter(cf::BLOCK_HEIGHT)
        .expect("iterate the height index")
        .filter_map(|(k, v)| {
            (k.len() == 8 && v.len() == 32).then(|| {
                (
                    u64::from_be_bytes(k[..8].try_into().unwrap()),
                    Hash::from_slice(&v).expect("32-byte hash"),
                )
            })
        })
        .collect()
}

/// A REFUSED switch leaves the height index byte-for-byte unchanged, and a
/// SUCCESSFUL one moves it to the adopted branch — never before the commit that
/// adopts each block.
#[test]
fn the_height_index_survives_a_refusal_and_follows_an_adoption() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

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
    for blk in &branch_b {
        a.retain(blk);
    }

    // The index names A's branch, and retaining B's blocks did not touch it.
    let canonical = height_index(&a);
    assert_eq!(canonical.get(&0), Some(&genesis.hash()));
    for blk in &branch_a {
        assert_eq!(
            canonical.get(&blk.height()),
            Some(&blk.hash()),
            "height {} must name A's block before anything is switched",
            blk.height()
        );
    }
    assert_eq!(canonical.len(), 4, "genesis plus three blocks");

    let store = BlockStore::new(&a.db);
    let plan = plan_reorg(
        &store,
        branch_a.last().unwrap(),
        branch_b.last().unwrap(),
        NO_FINALITY,
        DEEP,
    )
    .expect("plan");

    // ── direction 1: a REFUSED switch changes nothing ───────────────────────
    //
    // Refused for a reason that has nothing to do with the height index — a
    // withheld journal — so what is being measured is the index's behaviour
    // under refusal and not the refusal's own subject.
    struct Withholding<'a> {
        inner: &'a ActivatedJournal<'a>,
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
    let real = a.real_journal();
    let refused = execute_reorg(
        &a.db,
        &a.state,
        &a.executor,
        &plan,
        NO_VALIDATORS,
        &Withholding {
            inner: &real,
            withhold: 3,
        },
        JOURNAL_REQUIRED,
    );
    assert!(refused.is_err(), "the withheld journal must refuse");
    assert_eq!(
        height_index(&a),
        canonical,
        "a refused switch must leave the canonical height index exactly as it was"
    );

    // ── direction 2: the index moves with the COMMIT, not before it ─────────
    //
    // The switch is run in its two halves so the intermediate state is
    // observable. The unwind batch de-indexes every abandoned height; until the
    // apply commits a block, that height has NO row — absent, not stale. A
    // stale row would name a block on no chain, which is the defect this whole
    // section is about, and an absent one cannot.
    let journal = a.real_journal();
    let mut batch = a.db.batch();
    stage_branch_unwind(
        &a.db,
        &mut batch,
        &plan.old_branch,
        &journal,
        JOURNAL_REQUIRED,
    )
    .expect("unwind");
    for abandoned in &plan.old_branch {
        sumchain_storage::candidate::stage_deindex(&mut batch, abandoned).expect("deindex");
    }
    sumchain_state::reorg_undo::stage_head_reset(&mut batch, &genesis).expect("head");
    batch.commit().expect("commit the unwind");
    a.state.set_state_root(accumulator_of(&genesis));

    let after_unwind = height_index(&a);
    assert_eq!(
        after_unwind.keys().copied().collect::<Vec<_>>(),
        vec![0],
        "after the unwind commits, only genesis is indexed: every abandoned height is \
         ABSENT rather than stale"
    );

    // Apply one block and check the index gained exactly that one height.
    let applied = apply_branch(&a.db, &a.state, &a.executor, &branch_b[..1], NO_VALIDATORS)
        .expect("apply the first adopted block");
    assert_eq!(applied.applied, 1);
    let after_one = height_index(&a);
    assert_eq!(
        after_one.get(&1),
        Some(&branch_b[0].hash()),
        "a committed adoption must index its own block"
    );
    assert_eq!(
        after_one.get(&2),
        None,
        "and must not index a block it has not committed yet"
    );

    // Finish, and require the index to name the adopted branch and nothing else.
    apply_branch(&a.db, &a.state, &a.executor, &branch_b, NO_VALIDATORS).expect("apply the rest");
    let finished = height_index(&a);
    assert_eq!(finished.get(&0), Some(&genesis.hash()));
    assert_eq!(finished.get(&1), Some(&branch_b[0].hash()));
    assert_eq!(finished.get(&2), Some(&branch_b[1].hash()));
    assert_eq!(
        finished.get(&3),
        None,
        "the abandoned branch's extra height must be de-indexed, not left naming A's block"
    );
    assert_eq!(finished.len(), 3);
    assert_eq!(
        height_index(&b),
        finished,
        "and the reorged node's index must equal the index of the node it adopted from"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. Usable undo depth is enforced at PLAN time
//
// Release blocker 10. A node restored from a snapshot or fast sync holds
// canonical state and no journals — they are node-local and are not
// transmitted, and a pre-image is not derivable from a post-state. Its usable
// reorg depth on arrival is ZERO; it REBUILDS one block per publish; and it must
// never accept a switch deeper than it can reverse.
// ─────────────────────────────────────────────────────────────────────────────

/// The plan-time check: a switch deeper than the undo history this node holds is
/// refused before the plan is acted on, and one exactly at the limit is not.
///
/// Driven through `plan_reorg_within_undo_history`, the function
/// `PoAEngine::import_reorg` now calls — not through the standalone predicate —
/// so what is exercised is the entry point rather than a helper beside it.
#[test]
fn a_switch_deeper_than_this_nodes_undo_history_is_refused_at_plan_time() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    let mut branch_a = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..4u64 {
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
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..5u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 7_000 + n as u128, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    for blk in &branch_b {
        a.retain(blk);
    }
    let store = BlockStore::new(&a.db);
    let head = branch_a.last().unwrap();
    let new_head = branch_b.last().unwrap();
    assert_eq!(head.height(), 4);

    // A node "restored at height 2": its journal history begins at 3, so it can
    // reverse heights 3 and 4 and nothing below. The abandoned branch here is
    // four blocks, which is deeper.
    let restored = JournalActivation::pinned(3);
    assert_eq!(restored.advertisable_reorg_depth(4, DEEP), 2);
    let err = sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &store,
        head,
        new_head,
        NO_FINALITY,
        DEEP,
        &restored,
    )
    .expect_err("a switch deeper than the undo history must be refused");
    let rendered = err.to_string();
    assert!(
        rendered.contains("refusing a 4-block switch")
            && rendered.contains("only 2 block(s)")
            && rendered.contains("node-local"),
        "the refusal must name both depths and why the shortfall exists: {rendered}"
    );

    // Nothing was written by the refusal — planning never writes, and this
    // refuses inside planning.
    assert_eq!(
        a.head().map(|h| h.hash()),
        Some(head.hash()),
        "a refused plan leaves the node where it was"
    );

    // Exactly at the limit is accepted: a boundary at 1 makes all four blocks
    // reversible.
    let full = JournalActivation::pinned(1);
    assert_eq!(full.advertisable_reorg_depth(4, DEEP), 4);
    let plan = sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &store,
        head,
        new_head,
        NO_FINALITY,
        DEEP,
        &full,
    )
    .expect("a switch exactly at the usable depth is not deeper than it");
    assert_eq!(plan.depth(), 4);

    // And one block of undo history short of that is refused, so the acceptance
    // above is a boundary and not a large allowance.
    let one_short = JournalActivation::pinned(2);
    assert_eq!(one_short.advertisable_reorg_depth(4, DEEP), 3);
    assert!(sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &store,
        head,
        new_head,
        NO_FINALITY,
        DEEP,
        &one_short,
    )
    .is_err());

    // The plan-time refusal and the unwind-time checkpoint agree by
    // construction: a branch deeper than `head - boundary + 1` is exactly a
    // branch reaching below `boundary`. Shown rather than argued.
    let journal = ActivatedJournal::new(&a.db, restored);
    let plan = plan_reorg(&store, head, new_head, NO_FINALITY, DEEP).expect("plan");
    let mut batch = a.db.batch();
    let err = stage_branch_unwind(
        &a.db,
        &mut batch,
        &plan.old_branch,
        &journal,
        journal.policy(),
    )
    .expect_err("the same branch must also be refused by the checkpoint");
    drop(batch);
    assert!(
        matches!(err, UndoRefusal::CrossesActivationCheckpoint { .. }),
        "{err}"
    );
}

/// A node that adopts a branch whose ADOPTED side is long but whose abandoned
/// side is short is NOT refused.
///
/// This is why the usable depth is checked against the abandoned branch rather
/// than passed as `max_depth`: `max_depth` bounds both walks, and a node catching
/// up after being offline legitimately adopts far more than it reverses.
#[test]
fn a_long_catch_up_over_a_shallow_fork_is_not_refused() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    // A's chain, and B's: they share the genesis only, but A abandons ONE block
    // while B offers twelve.
    let only = a.produce(
        Some(&genesis),
        &proposer,
        vec![transfer(&alice, &carol.address(), 1_000, 500, 0)],
    );
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..12u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 7_000 + n as u128, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    for blk in &branch_b {
        a.retain(blk);
    }

    // Undo history for exactly the one block it has to reverse, and no more.
    let activation = JournalActivation::pinned(1);
    assert_eq!(activation.advertisable_reorg_depth(1, DEEP), 1);
    let plan = sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &BlockStore::new(&a.db),
        &only,
        branch_b.last().unwrap(),
        NO_FINALITY,
        DEEP,
        &activation,
    )
    .expect("adopting twelve while abandoning one is within a one-block undo history");
    assert_eq!(plan.depth(), 1);
    assert_eq!(plan.new_branch.len(), 12);
}

/// The usable depth REBUILDS as the node publishes, measured on a real database
/// rather than asserted about the formula.
///
/// A restored node cannot import undo history — journals are not transmitted —
/// so the only thing that raises this number is publishing blocks. After
/// `MAX_REORG_WALK` of them it has reached the engine's horizon and stops
/// growing.
#[test]
fn a_restored_nodes_usable_depth_rebuilds_one_block_at_a_time() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let walk = sumchain_consensus::poa::MAX_REORG_WALK;

    // The restore: canonical state present, no journal history at all. That is
    // the state a snapshot leaves, and the observed boundary is unestablished.
    let restored =
        JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain).expect("resolve");
    assert_eq!(restored.boundary(), None);
    assert_eq!(
        restored.advertisable_reorg_depth(5_000, walk),
        0,
        "a node that has published nothing can reverse nothing, whatever its head"
    );

    // Publishing is the only thing that rebuilds it.
    let genesis = node.produce(None, &proposer, Vec::new());
    let mut parent = genesis;
    for n in 0..4u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        let observed = JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain)
            .expect("resolve");
        assert_eq!(
            observed.advertisable_reorg_depth(parent.height(), walk),
            parent.height() + 1,
            "after publishing height {} the node can reverse every block it published",
            parent.height()
        );
    }

    // And a node restored at a height ABOVE genesis counts from its own first
    // published block, not from the bottom of the chain it was handed.
    const RESTORE: u64 = 900_000;
    let after_restore = JournalActivation::pinned(RESTORE + 1);
    for published in [0u64, 1, 200, walk, walk + 5_000] {
        assert_eq!(
            after_restore.advertisable_reorg_depth(RESTORE + published, walk),
            published.min(walk),
            "after {published} published block(s)"
        );
    }
}

/// A node that was RESTORED from a snapshot refuses a switch reaching below the
/// restore point, on a real database, through the planner the engine uses.
///
/// The restore is expressed the way a restore expresses itself: canonical state
/// present, blocks present, and `record_undo_history_floor` stamped at the
/// height it arrived at. Nothing else distinguishes it — the journal family is
/// empty either way, which is why the row exists.
///
/// `crates/state/src/snapshot.rs` belongs to another workstream and is not
/// touched here. What this pins is the seam: whatever writes that row gets this
/// behaviour, and until something does, a restored node is indistinguishable
/// from a pre-journal chain and is treated as one.
#[test]
fn a_snapshot_restored_node_refuses_a_switch_below_its_restore_point() {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);
    let (a, b, genesis) = two_nodes(
        ChainParams::with_v2_enabled(),
        &[(&alice, 10_000_000), (&bob, 10_000_000)],
    );

    let mut branch_a = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..4u64 {
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
    let mut branch_b = Vec::new();
    let mut parent = genesis.clone();
    for n in 0..5u64 {
        let blk = b.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&bob, &carol.address(), 7_000 + n as u128, 500, n)],
        );
        parent = blk.clone();
        branch_b.push(blk);
    }
    for blk in &branch_b {
        a.retain(blk);
    }
    let store = BlockStore::new(&a.db);
    let head = branch_a.last().unwrap();
    let new_head = branch_b.last().unwrap();

    // Before the restore is recorded, this chain's own journal history says the
    // whole branch is reversible — which it is, because this node published it.
    let native =
        JournalActivation::resolve(&a.db, ActivationSource::ObservedFromChain).expect("resolve");
    assert_eq!(native.boundary(), Some(0));
    sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &store,
        head,
        new_head,
        NO_FINALITY,
        DEEP,
        &native,
    )
    .expect("a node holding its own journals may reverse its own blocks");

    // Now say it arrived at height 2 by snapshot. Everything at or below 2 is
    // unreversible by any record this database holds, however many blocks are
    // sitting in `BLOCKS`.
    sumchain_storage::journal::record_undo_history_floor(&a.db, 2).expect("record the floor");
    let restored =
        JournalActivation::resolve(&a.db, ActivationSource::ObservedFromChain).expect("resolve");
    assert_eq!(
        restored.boundary(),
        Some(3),
        "the floor raises the boundary even though the journal family is full"
    );
    assert_eq!(restored.advertisable_reorg_depth(4, DEEP), 2);

    let err = sumchain_consensus::reorg::plan_reorg_within_undo_history(
        &store,
        head,
        new_head,
        NO_FINALITY,
        DEEP,
        &restored,
    )
    .expect_err("a restored node must refuse a switch below its restore point");
    assert!(
        err.to_string().contains("refusing a 4-block switch")
            && err.to_string().contains("only 2 block(s)"),
        "{err}"
    );

    // And the unwind layer refuses the same branch independently, so the two
    // guards agree on a restored node exactly as they do on an activating one.
    let journal = ActivatedJournal::new(&a.db, restored);
    let plan = plan_reorg(&store, head, new_head, NO_FINALITY, DEEP).expect("plan");
    let mut batch = a.db.batch();
    let refusal = stage_branch_unwind(
        &a.db,
        &mut batch,
        &plan.old_branch,
        &journal,
        journal.policy(),
    )
    .expect_err("the checkpoint must refuse a branch below the restore point too");
    drop(batch);
    assert!(
        matches!(
            refusal,
            UndoRefusal::CrossesActivationCheckpoint { boundary: 3, .. }
        ),
        "{refusal}"
    );

    // A shallower switch, wholly above the restore point, is still allowed —
    // the restriction is a floor, not a freeze.
    let shallow = plan_reorg(&store, head, &branch_b[3], NO_FINALITY, DEEP).expect("plan");
    assert_eq!(shallow.depth(), 4);
    let fork_at_3 = plan_reorg(&store, head, new_head, NO_FINALITY, DEEP).expect("plan");
    assert_eq!(fork_at_3.depth(), 4);
    let shallow_plan = ReorgPlanShim::two_block_suffix(&branch_a);
    sumchain_consensus::reorg::refuse_beyond_undo_history(&shallow_plan, &restored, 4, DEEP)
        .expect("a two-block switch is within a two-block undo history");
}

/// A `ReorgPlan` built by hand, so the depth predicate can be exercised at
/// depths this fixture's forks do not happen to produce.
struct ReorgPlanShim;

impl ReorgPlanShim {
    fn two_block_suffix(branch: &[Block]) -> sumchain_consensus::reorg::ReorgPlan {
        let ancestor = &branch[branch.len() - 3];
        sumchain_consensus::reorg::ReorgPlan {
            ancestor_hash: ancestor.hash(),
            ancestor_height: ancestor.height(),
            old_branch: branch[branch.len() - 2..].to_vec(),
            new_branch: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. The operator rollback
//
// Release blocker 7. `sum-node rollback` reverted ACCOUNT rows out of
// `cf::STATE_DIFFS` with its own loop and nothing else — no contract diff, no
// compute-pool or beacon journal, no generic application journal, and no
// question about the activation boundary. Past activation that under-reverts.
// It is now `plan_rollback` + `execute_rollback`, which is the reorg path's own
// unwind, and these drive those directly.
// ─────────────────────────────────────────────────────────────────────────────

/// A rollback returns EVERY family to the target, byte for byte — including the
/// families the four legacy per-subsystem journals never covered, which is the
/// whole of what the old loop got wrong.
#[test]
fn a_rollback_restores_every_family_the_legacy_diffs_never_covered() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());

    // Two blocks above the target, then the target snapshot, then two more.
    let mut parent = genesis;
    for n in 0..2u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    let target = parent.clone();
    let at_target = node.snapshot();
    for n in 2..4u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    assert_ne!(node.snapshot(), at_target, "the fixture must have moved on");

    let store = BlockStore::new(&node.db);
    let journals = node.real_journal();
    let plan = sumchain_consensus::reorg::plan_rollback(
        &store,
        target.height(),
        10,
        &journals.activation(),
    )
    .expect("plan a two-block rollback");
    assert_eq!(plan.depth(), 2);
    assert_eq!(plan.target.hash(), target.hash());

    let report = sumchain_consensus::reorg::execute_rollback(
        &node.db,
        &node.state,
        &plan,
        &journals,
        journals.policy(),
    )
    .expect("execute");

    assert_eq!(report.blocks, 2);
    assert_eq!(report.tolerated_absences, 0);
    assert_eq!(report.checks, report.records);
    assert!(report.records > 0);

    // Every convergent family, not only `cf::STATE`. The old loop would have
    // left everything outside `cf::STATE` exactly where the rolled-back blocks
    // put it.
    let after = node.snapshot();
    let mut expected = at_target.clone();
    // The rolled-back blocks' rows are gone from BLOCKS too — a rollback is not
    // a fork choice, and the tool deletes them, as it always did.
    expected.retain(|(family, _), _| family != cf::BLOCKS);
    let mut after_cmp = after.clone();
    after_cmp.retain(|(family, _), _| family != cf::BLOCKS);
    assert_eq!(
        after_cmp,
        expected,
        "a rollback must return every family to the target:\n{}",
        describe_divergence(&after_cmp, &expected)
    );
    assert_eq!(node.head().map(|h| h.hash()), Some(target.hash()));
    assert_eq!(node.state.state_root(), accumulator_of(&target));

    // And the rolled-back blocks are gone from the store, which is what the
    // operator asked for.
    assert!(store.get_by_height(target.height() + 1).unwrap().is_none());
}

/// A rollback that would cross the activation checkpoint is REFUSED, at plan
/// time, and writes nothing.
///
/// This is the case the old loop executed happily: below the boundary it would
/// have reverted account rows from the legacy diffs and left every other family
/// applied, on a chain that no longer contained the blocks that wrote them.
#[test]
fn a_rollback_across_the_activation_checkpoint_is_refused() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let mut parent = genesis.clone();
    for n in 0..4u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    let before = node.snapshot();
    let store = BlockStore::new(&node.db);

    // The chain's boundary is at 3: heights 1 and 2 are pre-journal history.
    let activation = JournalActivation::pinned(3);
    let err = sumchain_consensus::reorg::plan_rollback(&store, 1, 10, &activation)
        .expect_err("a rollback reaching below the boundary must be refused");
    assert!(
        err.to_string().contains("refusing a 3-block switch")
            && err.to_string().contains("only 2 block(s)"),
        "{err}"
    );
    assert_eq!(node.snapshot(), before, "planning writes nothing");

    // Down to the boundary itself is allowed — the restriction is a floor.
    let plan = sumchain_consensus::reorg::plan_rollback(&store, 2, 10, &activation)
        .expect("a rollback to the boundary's own predecessor is within the undo history");
    assert_eq!(plan.depth(), 2);

    // And the unwind layer refuses the crossing branch independently, so the
    // tool is not the only thing standing between an operator and it.
    let journals = ActivatedJournal::new(&node.db, activation);
    let crossing: Vec<Block> = (1..=4)
        .map(|h| store.get_by_height(h).unwrap().unwrap())
        .collect();
    let mut batch = node.db.batch();
    let refusal = stage_branch_unwind(
        &node.db,
        &mut batch,
        &crossing,
        &journals,
        journals.policy(),
    )
    .expect_err("the checkpoint must refuse it too");
    drop(batch);
    assert!(
        matches!(
            refusal,
            UndoRefusal::CrossesActivationCheckpoint { boundary: 3, .. }
        ),
        "{refusal}"
    );
    assert_eq!(node.snapshot(), before);
}

/// The operator-facing refusals: a target at or above the tip, a range past the
/// caller's own limit, and a gap in the range. All before anything is written.
#[test]
fn a_rollback_refuses_a_bad_target_a_deep_range_and_a_gap() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let mut parent = genesis;
    for n in 0..4u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    let before = node.snapshot();
    let store = BlockStore::new(&node.db);
    let activation =
        JournalActivation::resolve(&node.db, ActivationSource::ObservedFromChain).expect("resolve");

    for (target, limit, expect) in [
        (4u64, 10u64, "strictly below the current tip"),
        (5, 10, "strictly below the current tip"),
        (0, 2, "the limit for this invocation is 2"),
    ] {
        let err = sumchain_consensus::reorg::plan_rollback(&store, target, limit, &activation)
            .expect_err("must refuse");
        assert!(
            err.to_string().contains(expect),
            "target {target} limit {limit}: {err}"
        );
    }

    // A gap: the height index no longer names a block in the range. Refused
    // rather than unwound around, because unwinding around it would leave the
    // missing block's rows applied.
    assert_eq!(
        node.snapshot(),
        before,
        "no refusal so far has written anything"
    );
    node.db
        .delete(cf::BLOCK_HEIGHT, &3u64.to_be_bytes())
        .expect("create a gap");
    let with_gap = node.snapshot();
    let err = sumchain_consensus::reorg::plan_rollback(&store, 1, 10, &activation)
        .expect_err("a gap must refuse");
    assert!(err.to_string().contains("has a gap"), "{err}");
    assert_eq!(
        node.snapshot(),
        with_gap,
        "the gap refusal writes nothing either"
    );
}

/// A rollback is ONE batch, so an interruption leaves the old tip or the target
/// and never a chain half-way between them.
#[test]
fn an_interrupted_rollback_leaves_the_old_tip_untouched() {
    let alice = key(1);
    let carol = key(3);
    let proposer = key(9);
    let node = Node::new(ChainParams::with_v2_enabled());
    node.seed(&alice, 10_000_000);
    let genesis = node.produce(None, &proposer, Vec::new());
    let mut parent = genesis;
    for n in 0..3u64 {
        parent = node.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
    }
    let head = parent.clone();
    let before = node.snapshot();
    let store = BlockStore::new(&node.db);
    let journals = node.real_journal();
    let plan =
        sumchain_consensus::reorg::plan_rollback(&store, 1, 10, &journals.activation()).unwrap();

    // The interruption: everything staged, nothing committed. `stage_branch_unwind`
    // is what `execute_rollback` calls, and a dropped `WriteBatch` writes
    // nothing — which is the whole of the crash argument, since the rollback has
    // no second batch for a crash to land between.
    let mut batch = node.db.batch();
    stage_branch_unwind(
        &node.db,
        &mut batch,
        &plan.abandoned,
        &journals,
        journals.policy(),
    )
    .expect("stage");
    drop(batch);

    assert_eq!(
        node.snapshot(),
        before,
        "an interrupted rollback leaves the database exactly as it was"
    );
    assert_eq!(node.head().map(|h| h.hash()), Some(head.hash()));

    // And the retry succeeds, because nothing was consumed.
    let journals = node.real_journal();
    let report = sumchain_consensus::reorg::execute_rollback(
        &node.db,
        &node.state,
        &plan,
        &journals,
        journals.policy(),
    )
    .expect("a clean retry");
    assert_eq!(report.blocks, 2);
}

// 14. The activated account commitment, through a reorg
// ─────────────────────────────────────────────────────────────────────────────

/// The height these fixtures fork above.
///
/// Above `LEGACY_ROOT_COMPATIBILITY_HEIGHT`, and that is the whole point of
/// paying for it. Below that cutoff a replayed block whose root disagrees with
/// its header is FORCE-ADOPTED — `ReorgOutcome::force_adopted` counts it and the
/// reorg still "succeeds". A convergence test run down there proves only that
/// nobody noticed. Above it, a single wrong account row halts the reorg, so
/// "the reorg completed" is itself part of the claim.
const ACTIVATED: u64 = sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;

/// Params with the account commitment ACTIVE from the fork height, paired with
/// a journal boundary a full reorg horizon below it — the pair
/// `sumchain_state::account_root::validate_account_root_activation` accepts.
fn activated_params() -> ChainParams {
    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(ACTIVATED);
    params.application_journal_enabled_from_height =
        Some(ACTIVATED - sumchain_storage::pruner::UNDO_RETENTION_FLOOR);
    params
}

/// A fork point at `ACTIVATED - 1`, retained on every node that will build on
/// it.
///
/// The fixtures elsewhere in this file start at height 0, which is inside the
/// legacy window. This one cannot, so the chain begins at a block that is put
/// into the store rather than produced: `plan_reorg` walks parents out of
/// `BLOCKS` and needs the common ancestor to be there, and nothing else about
/// the ancestor is read.
fn forked_root(proposer: &KeyPair) -> Block {
    let header = BlockHeader::new(
        Hash::ZERO,
        ACTIVATED - 1,
        GENESIS_TS + ACTIVATED - 1,
        Hash::ZERO,
        Hash::ZERO,
        *proposer.public_key().as_bytes(),
    );
    Block::new(header, Vec::new())
}

/// The account family, by itself.
fn account_rows(node: &Node) -> BTreeMap<Vec<u8>, Vec<u8>> {
    family(node, cf::STATE)
        .into_iter()
        .filter(|(k, _)| k.starts_with(sumchain_storage::schema::ACCOUNT_KEY_PREFIX))
        .collect()
}

/// Build the two branches on a pair of nodes under `params` and reorg `a` onto
/// `b`'s. Returns the two nodes, the outcome, and `a`'s head root.
///
/// Extracted so the test below can run the SAME fixture twice — once with the
/// commitment active and once dormant — and compare the roots. Without that
/// control, "the root converged" would be a statement about three families and
/// the previous root, and would hold identically whether or not the account
/// digest was in the formula at all.
fn build_and_reorg(params: ChainParams) -> (Node, Node, ReorgOutcome, Hash) {
    let alice = key(1);
    let bob = key(2);
    let carol = key(3);
    let proposer = key(9);

    let a = Node::new(params.clone());
    let b = Node::new(params);
    for n in [&a, &b] {
        n.seed(&alice, 10_000_000);
        n.seed(&bob, 10_000_000);
        // An account no transaction on either branch ever touches. It is folded
        // by the commitment and by nothing else, which is what makes the
        // commitment's participation observable at all.
        n.seed(&key(7), 4_242);
    }
    let root = forked_root(&proposer);
    for n in [&a, &b] {
        n.retain(&root);
    }

    // The abandoned branch: three blocks, alice paying carol.
    let mut branch_a = Vec::new();
    let mut parent = root.clone();
    for n in 0..3u64 {
        let blk = a.produce(
            Some(&parent),
            &proposer,
            vec![transfer(&alice, &carol.address(), 1_000, 500, n)],
        );
        parent = blk.clone();
        branch_a.push(blk);
    }

    // The adopted branch: two blocks, bob paying carol. Different sender,
    // different amounts, different length — so every one of the four things
    // below really does have to move.
    let mut branch_b = Vec::new();
    let mut parent = root.clone();
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

    let head_root = a.state.state_root();
    (a, b, outcome, head_root)
}

/// After a reorg, account rows, supply rows, journal consumption and the
/// ACTIVATED state root converge together.
///
/// One fixture, four claims, and the point is that they are one claim. Each of
/// the four has been established separately elsewhere in this file and in
/// `crates/state/tests/account_state_root.rs`, on separate fixtures, with the
/// commitment dormant. A clean cherry-pick of two branches proves they compile
/// together; it proves nothing about whether the unwind restores exactly what
/// the commitment now reads. This is the first test where a failure of the
/// journal to restore one untouched account row is a failure of the STATE ROOT,
/// and therefore a chain that can neither revert nor agree.
///
/// Run above `LEGACY_ROOT_COMPATIBILITY_HEIGHT`, so `force_adopted` cannot
/// absorb a disagreement — see [`ACTIVATED`].
///
/// # The control
///
/// The same fixture is built twice, with the commitment active and dormant, and
/// the two head roots must DIFFER. Without that, "the root converged" is a
/// statement about the supply digest, the receipts and the previous root, true
/// whether or not account state was ever folded — the reorg equivalent of
/// `the_finding_account_rows_are_absent_from_todays_commitment`.
#[test]
fn a_reorg_converges_account_rows_supply_rows_journals_and_the_activated_root() {
    let (a, b, outcome, activated_root) = build_and_reorg(activated_params());

    assert_eq!(outcome.unwound.blocks, 3);
    assert_eq!(outcome.unwound.tolerated_absences, 0);
    assert_eq!(outcome.applied, 2);
    assert_eq!(
        outcome.force_adopted, 0,
        "above the compatibility cutoff a mismatch halts, so this must be zero \
         by construction; asserting it makes the reliance explicit"
    );
    assert_eq!(outcome.verified, 2, "every adopted block was CHECKED");

    // ── 1. account rows ──────────────────────────────────────────────────────
    assert_eq!(
        account_rows(&a),
        account_rows(&b),
        "every account row must equal the node that built the adopted branch"
    );
    assert_eq!(
        sumchain_state::account_root::account_state_digest(&a.db).unwrap(),
        sumchain_state::account_root::account_state_digest(&b.db).unwrap(),
        "and so must the commitment over them — the row comparison above is the \
         same claim expressed as bytes, and this is it expressed as the value \
         consensus actually folds"
    );
    // Named balances, so a failure says which direction the state went rather
    // than only that two maps differ.
    assert_eq!(
        a.balance(&key(3).address()),
        8_000,
        "carol must hold the ADOPTED branch's two payments, not the abandoned \
         branch's three"
    );
    assert_eq!(a.balance(&key(1).address()), 10_000_000, "alice untouched");
    assert_eq!(
        a.balance(&key(7).address()),
        4_242,
        "the bystander no transaction touched must be exactly where it started; \
         it reaches the root through the commitment and through nothing else"
    );

    // ── 2. supply rows ───────────────────────────────────────────────────────
    assert_eq!(
        family(&a, cf::SUPPLY),
        family(&b, cf::SUPPLY),
        "the supply family is covered by no per-subsystem journal and folded \
         into the root by `SupplyStore::v_state_digest`"
    );

    // ── 3. journal consumption ───────────────────────────────────────────────
    //
    // A reorg CONSUMES the records it replays: `BranchJournal::rows` deletes
    // each block's row in the same batch that applies its restores. So the
    // abandoned branch's records must be gone — a record left behind for a block
    // on no chain would be replayed again by the next reorg that walked through
    // it — and the adopted branch's must be present, because those blocks are
    // now canonical and must remain revertible.
    let journals = family(&a, cf::APPLICATION_JOURNAL);
    assert_eq!(
        journals.len(),
        2,
        "exactly the adopted branch's two records remain: three consumed, two \
         written by the apply"
    );
    assert_eq!(
        journals,
        family(&b, cf::APPLICATION_JOURNAL),
        "and they are byte-identical to the records the node that built that \
         branch wrote"
    );

    // ── 4. the activated state root ──────────────────────────────────────────
    assert_eq!(
        activated_root,
        b.state.state_root(),
        "the accumulator a reorged node holds must be the accumulator the node \
         that built the branch holds"
    );
    assert_eq!(
        a.head().map(|h| h.header.state_root),
        b.head().map(|h| h.header.state_root),
        "and the head block they name must be the same block"
    );

    // ── the control: the root really does depend on the account rows here ────
    let (_, _, dormant_outcome, dormant_root) = build_and_reorg(ChainParams::with_v2_enabled());
    assert_eq!(
        dormant_outcome.applied, 2,
        "the control must be the same fixture, not a different one"
    );
    assert_ne!(
        activated_root, dormant_root,
        "with the gate closed the same blocks produce a different accumulator. \
         If these were equal, every assertion above about `the root` would be a \
         statement about the supply digest and the receipts, and account state \
         would be converging beside the commitment rather than inside it."
    );

    // The strong form last, so a failure above names the family and this one
    // catches anything the four did not think to look at.
    let (left, right) = (a.snapshot(), b.snapshot());
    assert_eq!(left, right, "{}", describe_divergence(&left, &right));
}

// ─────────────────────────────────────────────────────────────────────────────
// 19b. The operator rollback, family by family.
//
// `a_rollback_restores_every_family_the_legacy_diffs_never_covered` compares
// whole-database snapshots, which is the strongest shape of assertion available
// — and exactly as strong as the fixture that feeds it. Its blocks carry plain
// transfers, so the families they move are `state` and `supply`, and its claim
// about CONTRACTS and the application subsystems is true but vacuous: nothing
// in that fixture ever wrote one.
//
// This drives the same `plan_rollback` + `execute_rollback` over blocks that
// really do write a contract's code and storage, a supply row, and one INDEXED
// application subsystem — a primary row plus the secondary index that points at
// it, which is the shape that breaks worst under a partial unwind, because an
// index left pointing at a row that is gone is a lookup that returns nothing
// while the subsystem still believes the record exists.
//
// It publishes through `CandidateExecution` rather than through `BlockExecutor`
// because the point is the FAMILIES, and driving a wasm deploy and a messaging
// registration through the executor would make the fixture about transaction
// admission instead. The publication path is the real one either way: the
// generic journal is derived from the overlay's pre-image map, so what it
// records is what the block wrote, whatever wrote it.
// ─────────────────────────────────────────────────────────────────────────────

/// Publish `block` through the real publication path, staging `writes`.
fn publish_staging(
    db: &Database,
    block: &Block,
    writes: impl FnOnce(
        &mut sumchain_storage::exec_view::ExecutionView<'_, '_>,
    ) -> sumchain_storage::Result<()>,
) {
    use sumchain_storage::candidate::{
        BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
    };

    let mut cand = CandidateExecution::new(db, 1 << 22);
    {
        let mut view = cand.view();
        writes(&mut view).expect("stage the block's writes");
    }
    cand.finish_execution(
        ExecutionSubject::of(block).expect("subject"),
        block.header.state_root,
        Vec::new(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
    .accept_imported(block)
    .expect("accept")
    .publish()
    .expect("publish");
}

/// A `sum-node rollback` returns accounts, contracts, supply and an indexed
/// application subsystem to the target — all four, in one atomic batch.
///
/// The bug this is the regression for: the old command reverted ACCOUNT rows out
/// of `cf::STATE_DIFFS` with a loop of its own and then printed "Rollback
/// complete." A contract's code and storage, the supply row, and every
/// application subsystem's rows and indexes stayed exactly where the
/// rolled-back blocks left them, on a chain that no longer contained the blocks
/// that wrote them — and the operator was told it had worked.
#[test]
fn a_rollback_restores_accounts_contracts_supply_and_an_indexed_subsystem() {
    // The four families under test, named so a failure says which one leaked.
    // `MESSAGING_PUBLIC_KEYS` is the primary row of an application subsystem and
    // `MESSAGING_SENDER_EVENTS` is a secondary index into it: an unwind that
    // restores one and not the other leaves a lookup that disagrees with the
    // record it points at.
    const ACCOUNT: &[u8] = b"account-row";
    const CODE: &[u8] = b"contract-code";
    const SLOT: &[u8] = b"contract-slot";
    const SUPPLY_KEY: &[u8] = b"total";
    const SUBJECT: &[u8] = b"messaging-subject";
    const INDEX_KEY: &[u8] = b"messaging-subject/event-0";

    let dir = TempDir::new().expect("temp dir");
    let db = Arc::new(Database::open_default(dir.path()).expect("open"));
    let state = StateManager::new(db.clone(), CHAIN_ID);

    // Heights 0..=2 build the state the rollback must return to; 3 and 4 move
    // every one of the four families away from it.
    let mut parent = Hash::ZERO;
    let mut blocks = Vec::new();
    for height in 0..=4u64 {
        let header = BlockHeader::new(
            parent,
            height,
            GENESIS_TS + height,
            Hash::hash(&height.to_be_bytes()),
            Hash::ZERO,
            [0u8; 32],
        );
        let block = Block::new(header, Vec::new());
        publish_staging(&db, &block, |view| {
            let v = |tag: &str| format!("{tag}@{height}").into_bytes();
            view.put(cf::STATE, ACCOUNT, &v("balance"))?;
            view.put(cf::CONTRACT_CODE, CODE, &v("wasm"))?;
            view.put(cf::CONTRACT_STORAGE, SLOT, &v("slot"))?;
            view.put(cf::SUPPLY, SUPPLY_KEY, &v("supply"))?;
            view.put(cf::MESSAGING_PUBLIC_KEYS, SUBJECT, &v("pubkey"))?;
            // The index row appears only at and above the target, so the
            // rollback has to DELETE it rather than merely rewrite it — a
            // restore that only ever overwrites would pass without proving the
            // absent-before case.
            if height >= 3 {
                view.put(cf::MESSAGING_SENDER_EVENTS, INDEX_KEY, &v("event"))?;
            }
            Ok(())
        });
        parent = block.hash();
        blocks.push(block);
    }

    let target = blocks[2].clone();
    let read = |family: &str, key: &[u8]| db.get(family, key).expect("read");
    let four_families = || {
        vec![
            (cf::STATE, ACCOUNT, read(cf::STATE, ACCOUNT)),
            (cf::CONTRACT_CODE, CODE, read(cf::CONTRACT_CODE, CODE)),
            (cf::CONTRACT_STORAGE, SLOT, read(cf::CONTRACT_STORAGE, SLOT)),
            (cf::SUPPLY, SUPPLY_KEY, read(cf::SUPPLY, SUPPLY_KEY)),
            (
                cf::MESSAGING_PUBLIC_KEYS,
                SUBJECT,
                read(cf::MESSAGING_PUBLIC_KEYS, SUBJECT),
            ),
            (
                cf::MESSAGING_SENDER_EVENTS,
                INDEX_KEY,
                read(cf::MESSAGING_SENDER_EVENTS, INDEX_KEY),
            ),
        ]
    };

    // What the target looked like, read at height 4 and reconstructed from the
    // fixture's own rule rather than snapshotted — the snapshot is taken below,
    // but this asserts the fixture really moved all six rows.
    let at_head = four_families();
    for (family, _, value) in &at_head {
        assert_eq!(
            value.as_deref(),
            Some(format!("{}@4", tag_for(family)).as_bytes()),
            "the fixture must leave {family} at height 4 before the rollback"
        );
    }

    let store = BlockStore::new(&db);
    assert_eq!(store.get_latest_height().unwrap(), Some(4));

    let journals = ActivatedJournal::resolve(&db, ActivationSource::ObservedFromChain)
        .expect("resolve the real journal");
    assert_eq!(
        journals.activation().boundary(),
        Some(0),
        "every block here published a generic journal, so a missing record is an \
         error at every height and the rollback is a post-activation one"
    );

    let plan = sumchain_consensus::reorg::plan_rollback(&store, 2, 10, &journals.activation())
        .expect("plan");
    assert_eq!(plan.depth(), 2);

    let report = sumchain_consensus::reorg::execute_rollback(
        &db,
        &state,
        &plan,
        &journals,
        journals.policy(),
    )
    .expect("execute");
    assert_eq!(report.blocks, 2);
    assert_eq!(
        report.tolerated_absences, 0,
        "a post-activation rollback that tolerated an absence would be the old \
         bug wearing the new API"
    );

    // ── every family, by name ───────────────────────────────────────────────
    for (family, _key, value) in four_families() {
        if family == cf::MESSAGING_SENDER_EVENTS {
            assert_eq!(
                value, None,
                "the secondary index row was written by an abandoned block and must \
                 be GONE: an index that outlives the block that wrote it points at a \
                 record the chain no longer contains"
            );
            continue;
        }
        assert_eq!(
            value.as_deref(),
            Some(format!("{}@2", tag_for(family)).as_bytes()),
            "{family} must be back at the target's value; the old rollback restored \
             cf::STATE alone and reported success"
        );
    }

    // ── and the tip, and the blocks ─────────────────────────────────────────
    assert_eq!(
        store.get_latest_height().unwrap(),
        Some(2),
        "the canonical height index follows the rollback"
    );
    assert_eq!(store.get_by_height(3).unwrap(), None);
    assert!(store.get_by_hash(&blocks[3].hash()).unwrap().is_none());
    assert_eq!(
        store.get_by_height(2).unwrap().map(|b| b.hash()),
        Some(target.hash())
    );

    // The consumed journals are gone with the blocks they described, and the
    // target's is not.
    for b in &blocks[3..] {
        assert_eq!(
            db.get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(b.height(), &b.hash())
            )
            .unwrap(),
            None,
            "a rolled-back block's undo record is consumed in the same batch"
        );
    }
    assert!(db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(target.height(), &target.hash())
        )
        .unwrap()
        .is_some());
}

/// The value tag this fixture writes into `family`.
fn tag_for(family: &str) -> &'static str {
    match family {
        f if f == cf::STATE => "balance",
        f if f == cf::CONTRACT_CODE => "wasm",
        f if f == cf::CONTRACT_STORAGE => "slot",
        f if f == cf::SUPPLY => "supply",
        f if f == cf::MESSAGING_PUBLIC_KEYS => "pubkey",
        f if f == cf::MESSAGING_SENDER_EVENTS => "event",
        other => panic!("unexpected family {other}"),
    }
}
