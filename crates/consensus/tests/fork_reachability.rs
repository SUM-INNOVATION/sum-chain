//! Fork-reachability probe for issue #253 (Lane 5).
//!
//! TEST-ONLY. This file adds no production behaviour and no production hook: it
//! observes through the public engine API, the existing `ConsensusEvent`
//! broadcast, and direct reads of the database column families.
//!
//! # What this probe answers
//!
//! Issue #253 asks whether the depth-1 fork path in `PoAEngine` is reachable,
//! and what it does to state when it runs.
//!
//! The probe builds a genuine depth-1 fork: two fully independent nodes on one
//! genesis with a single validator (so `is_proposer` is true at every height and
//! both may legitimately produce at height 1), disjoint transaction sets, one
//! block each at height 1 over the same genesis parent. It then arranges — by
//! varying a fee and retrying — that `LongestChainForkChoice::should_switch`
//! (`crates/consensus/src/engine.rs`) genuinely wants to switch, which at equal
//! height means `candidate.hash() < head.hash()`, and imports B's block into A.
//!
//! # Outcome: (2) `Ok`, and the reorg path actually runs
//!
//! This is *not* the outcome the issue's first hypothesis predicted. A depth-1
//! sibling was expected to die on the state-root check in
//! `PoAEngine::do_import_block`, because `BlockExecutor::compute_block_state_root`
//! mixes the node's *current* state root into a chained accumulator: A computes
//! B's block on top of A's already-applied height-1 state, so the computed root
//! cannot equal the root B derived from the genesis state.
//!
//! It does mismatch. It is then **forgiven**: acceptance carries a
//! `height <= 496720` historical-exception branch that downgrades a state-root
//! mismatch to a warning and force-adopts the header's root. Height 1 is inside
//! that window, so the block is accepted, fork choice switches, and the reorg
//! path runs. [`depth1_sibling_import_reaches_the_reorg_path`] pins that
//! classification.
//!
//! # What the reorg then does
//!
//! It converges. [`reorged_node_must_converge_with_the_chain_it_adopted_issue_253`]
//! asserts the property the issue is about — after adopting a chain, a node
//! holds that chain's account state — and it passes. That test's own
//! documentation records the two defects that had to be fixed to get there, and
//! the one gap that remains outside what it measures.
//!
//! # How to run
//!
//! ```text
//! cargo test -p sumchain-consensus --test fork_reachability -- --nocapture
//! ```
//!
//! Both tests are ordinary tests. Neither is `#[ignore]`d any more: the second
//! was, for as long as it described a defect rather than a property.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusError, ConsensusEvent, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database, StateStore};
use tempfile::TempDir;
use tokio::sync::broadcast::error::TryRecvError;

const CHAIN_ID: u64 = 1;

/// Bounded retry budget for arranging `hash(B) < hash(A)`. Each attempt is an
/// independent coin flip over a 32-byte hash, so exhausting 24 attempts has
/// probability ~6e-8. A bounded loop keeps the probe from hanging.
const MAX_ATTEMPTS: usize = 24;

// ─────────────────────────────────────────────────────────────────────────────
// Harness
//
// Mirrors `crates/integration-tests/src/lib.rs` (`TestNode`): TempDir +
// Database + StateManager + Mempool + PoAEngine + `init_genesis`, with
// submit_tx / produce_block / balance / nonce helpers and a raw `db()`
// accessor. Duplicated here rather than imported because `sumchain-consensus`
// does not (and should not) depend on the integration-tests crate.
// ─────────────────────────────────────────────────────────────────────────────

struct ProbeNode {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    /// Held for its Drop guard: the temp dir must outlive the database.
    _dir: TempDir,
}

impl ProbeNode {
    /// Stand up a fully independent node on the *shared* genesis instance, so
    /// A and B agree on the genesis block byte-for-byte (a real common
    /// ancestor) while sharing no storage whatsoever.
    fn new(genesis: &Genesis, validator_key_bytes: [u8; 32]) -> Self {
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
                Some(KeyPair::from_bytes(validator_key_bytes)),
            )
            .expect("create consensus engine"),
        );

        consensus.init_genesis(genesis).expect("init genesis");

        Self { db, state, mempool, consensus, _dir: dir }
    }

    fn submit_tx(&self, tx: SignedTransaction) {
        self.mempool.add(tx).expect("mempool accepts tx");
    }

    async fn produce_block(&self) -> Block {
        let txs = self.mempool.select_for_block(100);
        assert!(!txs.is_empty(), "probe requires a non-empty block");
        self.consensus.propose_block(txs).await.expect("propose block")
    }

    fn balance(&self, addr: &Address) -> u128 {
        self.state.get_balance(addr).unwrap_or(0)
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.state.get_nonce(addr).unwrap_or(0)
    }

    fn db(&self) -> &Arc<Database> {
        &self.db
    }

    fn genesis_block(&self) -> Block {
        self.consensus
            .get_block_by_height(0)
            .expect("genesis block present")
    }

    /// Every account that currently exists in `cf::STATE`, as
    /// base58(address) -> (balance, nonce).
    ///
    /// Account rows are written by `StateStore::put_account` under the key
    /// `b"acct" || address[0..20]` in `cf::STATE`; other subsystems share that
    /// CF under different prefixes, so filter on the prefix and key length.
    fn account_snapshot(&self) -> BTreeMap<String, (u128, u64)> {
        let mut out = BTreeMap::new();
        for (key, _value) in self.db().iter(cf::STATE).expect("iterate cf::STATE") {
            if key.len() != 24 || &key[..4] != b"acct" {
                continue;
            }
            let addr = Address::from_slice(&key[4..]).expect("20-byte address");
            out.insert(addr.to_base58(), (self.balance(&addr), self.nonce(&addr)));
        }
        out
    }

    /// The raw, undecoded `cf::STATE_DIFFS` row for one specific block.
    ///
    /// `put_state_diff` keys this CF by `(height, block_hash)`. Before the #253
    /// fix it keyed by `height.to_be_bytes()` and nothing else, so two siblings
    /// at one height contended for a single row and the second import silently
    /// destroyed the first's undo journal. Asking by block hash is what lets
    /// this probe distinguish "A's journal is intact" from "A's journal was
    /// overwritten by B's".
    fn raw_application_journal_row(&self, height: u64, block_hash: &Hash) -> Option<Vec<u8>> {
        self.db()
            .get(
                cf::APPLICATION_JOURNAL,
                &sumchain_storage::schema::journal_key(height, block_hash),
            )
            .expect("read cf::APPLICATION_JOURNAL")
    }

    fn raw_state_diff_row(&self, height: u64, block_hash: &Hash) -> Option<Vec<u8>> {
        self.db()
            .get(
                cf::STATE_DIFFS,
                &sumchain_storage::schema::journal_key(height, block_hash),
            )
            .expect("read cf::STATE_DIFFS")
    }

    /// The decoded undo journal for one specific block, as the set of addresses
    /// it covers. Used to tell "the journal describes A's block" from "the
    /// journal was overwritten to describe B's block".
    fn state_diff_addresses(&self, height: u64, block_hash: &Hash) -> Option<BTreeSet<String>> {
        let store = StateStore::new(self.db());
        store
            .get_state_diff(height, block_hash)
            .expect("decode state diff")
            .map(|d| d.changes.iter().map(|(a, _, _)| a.to_base58()).collect())
    }
}

fn signed_transfer(
    from: &KeyPair,
    to: Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to, amount, fee, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

fn diff_maps(
    left: &BTreeMap<String, (u128, u64)>,
    right: &BTreeMap<String, (u128, u64)>,
) -> Vec<String> {
    let mut keys: BTreeSet<&String> = left.keys().collect();
    keys.extend(right.keys());
    keys.into_iter()
        .filter(|k| left.get(*k) != right.get(*k))
        .map(|k| format!("{k}: {:?} vs {:?}", left.get(k), right.get(k)))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe
// ─────────────────────────────────────────────────────────────────────────────

/// Which of the four issue-#253 outcomes the import produced.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// (1) `Err(InvalidBlock)` naming a state-root mismatch: sibling blocks
    /// cannot be imported at all, so the reorg path is unreachable at depth 1.
    StateRootMismatch,
    /// (2) `Ok` and the reorg path actually ran.
    ReorgRan,
    /// (3) `Ok` but fork choice declined to switch.
    OkNoSwitch,
    /// (4) anything else — the harness failed to build a real sibling.
    OtherError(String),
}

struct Evidence {
    outcome: Outcome,
    import_result: String,
    /// True iff a `ConsensusEvent::Reorg` was observed on A's broadcast. This,
    /// plus the head change, is how outcome (2) is detected: both are existing
    /// observables, no production hook was added.
    saw_reorg_event: bool,
    saw_block_imported_event: bool,
    reorg_depth: Option<u64>,

    genesis_hash: Hash,
    a_hash: Hash,
    b_hash: Hash,
    head_after: Hash,
    attempts: usize,
    fee_b: u128,

    /// A's cached state root immediately after `init_genesis`, i.e. the
    /// accumulator input both A and B used when producing their height-1 block.
    root_at_genesis: Hash,
    /// A's height-1 header root. Once A has applied its own block this becomes
    /// the accumulator input for anything A executes next, which is why A's
    /// recomputation of B's block cannot reproduce B's header root.
    a_state_root: Hash,
    b_state_root: Hash,

    /// A's accounts before the import (A's own height-1 chain state).
    accounts_a_before: BTreeMap<String, (u128, u64)>,
    /// A's accounts after the import.
    accounts_a_after: BTreeMap<String, (u128, u64)>,
    /// B's accounts — the canonical state of the chain A just adopted.
    accounts_b: BTreeMap<String, (u128, u64)>,

    diff_row_before: Option<Vec<u8>>,
    diff_row_after: Option<Vec<u8>>,
    /// The GENERIC application-journal row for A's own height-1 block, before
    /// and after the import. Present before and gone after is the evidence that
    /// the real encoded record — not an oracle, and not only the legacy diffs —
    /// is what the live reorg path consumed.
    app_journal_row_before: Option<Vec<u8>>,
    app_journal_row_after: Option<Vec<u8>>,
    diff_addrs_before: Option<BTreeSet<String>>,
    diff_addrs_after: Option<BTreeSet<String>>,
    /// Addresses B's block touches.
    b_touched: BTreeSet<String>,
    /// Addresses only A's block touches (the orphaned block's footprint).
    a_only_touched: BTreeSet<String>,
}

impl Evidence {
    /// Accounts on A whose (balance, nonce) differ between the pre-import
    /// snapshot and the post-import re-read.
    fn residue(&self) -> Vec<String> {
        diff_maps(&self.accounts_a_before, &self.accounts_a_after)
    }

    /// Accounts where node A, after adopting B's block as its head, disagrees
    /// with node B — the node whose chain A claims to be on. Any entry here is
    /// a hard consensus divergence between two nodes at the same head.
    fn divergence(&self) -> Vec<String> {
        diff_maps(&self.accounts_a_after, &self.accounts_b)
    }

    fn report(&self) -> String {
        let fmt = |v: &Vec<String>| {
            if v.is_empty() {
                "(none)".to_string()
            } else {
                v.join("\n      ")
            }
        };
        format!(
            "\n─── issue #253 fork-reachability probe ───\n\
             genesis (common ancestor):   {}\n\
             A head @1:                   {}   state_root={}\n\
             B sibling @1:                {}   state_root={}   (fee_b={}, attempts={})\n\
             state root at genesis:       {}\n\
             fork choice wants to switch: {} (hash(B) < hash(A))\n\
             import B into A returned:    {}\n\
             CLASSIFIED OUTCOME:          {:?}\n\
             Reorg event observed:        {} (depth={:?})\n\
             BlockImported observed:      {}\n\
             A head after import:         {}\n\
             STATE_DIFFS[1] before:       {} bytes, addrs={:?}\n\
             STATE_DIFFS[1] after:        {} bytes, addrs={:?}\n\
             STATE_DIFFS[1] changed:      {}\n\
             B's block touches:           {:?}\n\
             A's block alone touches:     {:?}\n\
             A pre-import vs A post-import ({}):\n      {}\n\
             A post-import vs B ({}) -- same head, different state:\n      {}\n\
             ──────────────────────────────────────────\n",
            self.genesis_hash,
            self.a_hash,
            self.a_state_root,
            self.b_hash,
            self.b_state_root,
            self.fee_b,
            self.attempts,
            self.root_at_genesis,
            self.b_hash < self.a_hash,
            self.import_result,
            self.outcome,
            self.saw_reorg_event,
            self.reorg_depth,
            self.saw_block_imported_event,
            self.head_after,
            self.diff_row_before.as_ref().map_or(0, |v| v.len()),
            self.diff_addrs_before,
            self.diff_row_after.as_ref().map_or(0, |v| v.len()),
            self.diff_addrs_after,
            self.diff_row_before != self.diff_row_after,
            self.b_touched,
            self.a_only_touched,
            self.residue().len(),
            fmt(&self.residue()),
            self.divergence().len(),
            fmt(&self.divergence()),
        )
    }
}

/// Build a genuine depth-1 fork and import B's block into A.
///
/// Steps 1-7 of the issue-#253 probe specification, in order.
async fn run_probe() -> Evidence {
    // ── 1. Genesis with a SINGLE validator ──────────────────────────────────
    // `compute_proposer` selects `validators[height % N]`; with N == 1 the sole
    // validator is the proposer at *every* height, so `is_proposer(1)` is true
    // on both nodes and both may legitimately produce a block at height 1.
    //
    // Accounts are funded through the genesis allocation. That is the only way
    // to fund them identically on both nodes without consuming height 1 — the
    // height the fork must occupy — and it keeps the genesis block, and hence
    // the common ancestor, byte-identical on A and B.
    let validator = KeyPair::generate();
    let validator_key_bytes = *validator.private_key().as_bytes();
    let alice = KeyPair::generate();
    let bob = KeyPair::generate();
    let carol = KeyPair::generate();
    let dave = KeyPair::generate();

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
    assert_eq!(
        genesis.validator_pubkeys().expect("validator pubkeys").len(),
        1,
        "probe requires a single-validator genesis so both nodes may propose at height 1"
    );

    // ── 5. Arrange that fork choice would deterministically want to switch ──
    // `LongestChainForkChoice::should_switch(head, candidate)` at equal height
    // is exactly `candidate.hash() < head.hash()`. Vary B's fee — which changes
    // B's tx hash, tx_root, receipt fee and therefore its block hash — and retry
    // until the ordering holds, so a "no switch" result could never be blamed on
    // fork choice merely declining.
    for attempt in 0..MAX_ATTEMPTS {
        let fee_b = 20u128 + attempt as u128;

        // ── 2. Two fully independent nodes on the same genesis + validator ──
        let node_a = ProbeNode::new(&genesis, validator_key_bytes);
        let node_b = ProbeNode::new(&genesis, validator_key_bytes);

        let genesis_hash = node_a.genesis_block().hash();
        assert_eq!(
            genesis_hash,
            node_b.genesis_block().hash(),
            "A and B must share a byte-identical genesis block, else there is no common ancestor"
        );
        let root_at_genesis = node_a.state.state_root();

        // ── 3. Different transaction sets, one block each at height 1 ───────
        // Disjoint senders, so B's transaction is still executable on A after A
        // has applied its own block (bob's nonce and balance on A are untouched
        // by A's block). This keeps the probe about fork handling rather than
        // about a transaction that happens to fail on re-execution.
        node_a.submit_tx(signed_transfer(&alice, carol.address(), 1_000, 10, 0));
        node_b.submit_tx(signed_transfer(&bob, dave.address(), 2_000, fee_b, 0));

        let block_a = node_a.produce_block().await;
        let block_b = node_b.produce_block().await;

        // ── 4. Assert the fork is real BEFORE testing anything ──────────────
        assert_eq!(block_a.height(), 1, "A must be at height 1");
        assert_eq!(block_b.height(), 1, "B must be at height 1");
        assert_eq!(
            block_a.header.parent_hash, genesis_hash,
            "A's block must descend from genesis"
        );
        assert_eq!(
            block_b.header.parent_hash, genesis_hash,
            "B's block must descend from genesis — a real common ancestor"
        );
        assert_eq!(
            block_a.header.parent_hash, block_b.header.parent_hash,
            "siblings must share a parent"
        );
        assert_ne!(
            block_a.hash(),
            block_b.hash(),
            "siblings must be distinct blocks, else this is not a fork"
        );

        if block_b.hash() >= block_a.hash() {
            // Fork choice would not switch for this pair; retry with a new fee.
            continue;
        }

        // The accumulator premise: A's state root moved when A applied its own
        // block, so A's recomputation of B's block mixes a different prior root
        // than B did. The header/computed roots therefore cannot agree, and any
        // `Ok` result can only come from the `height <= 496720` historical
        // exception in `do_import_block` force-adopting the header's root.
        assert_ne!(
            root_at_genesis, block_a.header.state_root,
            "A's state root must move when A applies its own block, else the probe's \
             premise about the chained accumulator does not hold"
        );

        // ── 6. Snapshot A: every account, plus the raw STATE_DIFFS[1] row ───
        let accounts_a_before = node_a.account_snapshot();
        let a_hash = block_a.hash();
        let diff_row_before = node_a.raw_state_diff_row(1, &a_hash);
        let diff_addrs_before = node_a.state_diff_addresses(1, &a_hash);
        let app_journal_row_before = node_a.raw_application_journal_row(1, &a_hash);
        assert!(
            app_journal_row_before.is_some(),
            "A must have written a generic application journal for its own height-1 \
             block: `publish` writes one unconditionally, so its absence would mean \
             the block never went through the publication path"
        );
        assert!(
            diff_row_before.is_some(),
            "A must have written an undo journal for its own height-1 block"
        );

        let b_touched: BTreeSet<String> = [bob.address(), dave.address(), validator.address()]
            .iter()
            .map(|a| a.to_base58())
            .collect();
        let a_only_touched: BTreeSet<String> = [alice.address(), carol.address()]
            .iter()
            .map(|a| a.to_base58())
            .collect();

        // B's canonical state: the chain A is about to adopt.
        let accounts_b = node_b.account_snapshot();

        // ── 7. Import B's block into A ──────────────────────────────────────
        // Subscribe first so the Reorg / BlockImported broadcast — an existing
        // observable, no new hook — is captured if the reorg path runs.
        let mut events = node_a.consensus.subscribe();
        let import_result = node_a.consensus.import_block(block_b.clone()).await;

        let mut saw_reorg_event = false;
        let mut saw_block_imported_event = false;
        let mut reorg_depth = None;
        loop {
            match events.try_recv() {
                Ok(ConsensusEvent::Reorg { depth, .. }) => {
                    saw_reorg_event = true;
                    reorg_depth = Some(depth);
                }
                Ok(ConsensusEvent::BlockImported(_)) => saw_block_imported_event = true,
                Ok(_) => {}
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }

        let head_after = node_a.consensus.best_block_hash();
        let accounts_a_after = node_a.account_snapshot();
        let diff_row_after = node_a.raw_state_diff_row(1, &a_hash);
        let diff_addrs_after = node_a.state_diff_addresses(1, &a_hash);
        let app_journal_row_after = node_a.raw_application_journal_row(1, &a_hash);

        let import_result_str = match &import_result {
            Ok(()) => "Ok(())".to_string(),
            Err(e) => format!("Err({e})"),
        };

        let outcome = match &import_result {
            Err(ConsensusError::InvalidBlock(msg)) if msg.contains("State root mismatch") => {
                Outcome::StateRootMismatch
            }
            Err(e) => Outcome::OtherError(format!("{e}")),
            Ok(()) if saw_reorg_event || head_after == block_b.hash() => Outcome::ReorgRan,
            Ok(()) => Outcome::OkNoSwitch,
        };

        return Evidence {
            outcome,
            import_result: import_result_str,
            saw_reorg_event,
            saw_block_imported_event,
            reorg_depth,
            genesis_hash,
            a_hash: block_a.hash(),
            b_hash: block_b.hash(),
            head_after,
            attempts: attempt + 1,
            fee_b,
            root_at_genesis,
            a_state_root: block_a.header.state_root,
            b_state_root: block_b.header.state_root,
            accounts_a_before,
            accounts_a_after,
            accounts_b,
            diff_row_before,
            diff_row_after,
            app_journal_row_before,
            app_journal_row_after,
            diff_addrs_before,
            diff_addrs_after,
            b_touched,
            a_only_touched,
        };
    }

    panic!(
        "could not arrange hash(B) < hash(A) within {MAX_ATTEMPTS} attempts; \
         fork choice never wanted to switch, so the probe would be vacuous"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies what actually happens when a genuine depth-1 sibling is imported,
/// and pins the **observed** behaviour of `main` — established by running the
/// probe, not by guessing. Outcome (4) (any other error, e.g. `ParentNotFound`)
/// is treated as a harness defect and fails loudly, because it would mean no
/// real sibling was built and nothing had been demonstrated.
///
/// Observed: **outcome (2)** — `Ok`, and the reorg path really ran.
///
/// Detected with two existing observables and no production hook:
///   * `ConsensusEvent::Reorg` on the engine's own broadcast channel, which
///     `do_import_block` sends only from inside the `handle_reorg` branch; and
///   * `best_block_hash()` moving from A's block to B's block.
///
/// Secondary observation, asserted here because it is the mechanism behind the
/// divergence: `cf::STATE_DIFFS` is keyed by height alone, so importing B's
/// block overwrote A's height-1 undo journal with B's changes; `handle_reorg`
/// then reverted that row (undoing the block being *adopted*, not the block
/// being orphaned) and deleted it. The journal for height 1 is simply gone.
#[tokio::test]
async fn depth1_sibling_import_reaches_the_reorg_path() {
    let ev = run_probe().await;
    println!("{}", ev.report());

    if let Outcome::OtherError(msg) = &ev.outcome {
        panic!(
            "outcome (4): import failed for a reason other than a state-root mismatch: {msg}. \
             The harness did not build a real sibling; this confirms nothing.{}",
            ev.report()
        );
    }

    assert!(
        ev.b_hash < ev.a_hash,
        "probe invariant: should_switch requires hash(B) < hash(A)"
    );

    assert_eq!(
        ev.outcome,
        Outcome::ReorgRan,
        "observed on main: a depth-1 sibling is ACCEPTED and the reorg path runs. The \
         state-root check does mismatch, but height 1 falls inside the `height <= 496720` \
         historical-exception window in do_import_block, which downgrades the mismatch to a \
         warning and force-adopts the header's root. Import returned: {}{}",
        ev.import_result,
        ev.report()
    );

    assert!(
        ev.saw_reorg_event,
        "the reorg path is identified by the engine's own ConsensusEvent::Reorg broadcast{}",
        ev.report()
    );
    assert_eq!(
        ev.reorg_depth,
        Some(1),
        "a sibling over the genesis parent is a depth-1 reorg{}",
        ev.report()
    );
    assert!(ev.saw_block_imported_event, "the adopted block is announced as imported");
    assert_eq!(
        ev.head_after, ev.b_hash,
        "A's head must have moved to B's block{}",
        ev.report()
    );

    // ── the unwind ran on the REAL encoded application journal ───────────────
    //
    // `PoAEngine::import_reorg` resolves an `ActivatedJournal` against this
    // node's own activation boundary. A published its genesis and its height-1
    // block through `publish`, which writes a record for each, so the observed
    // boundary is 0 and height 1 is in the REQUIRED region: the unwind read A's
    // height-1 record off `cf::APPLICATION_JOURNAL`, decoded it through
    // `ApplicationJournal::decode_for` — magic, format version, identity against
    // the key, canonical order, framing — checked every row against the 8-byte
    // after-tag it carries, and deleted the record in the same batch that applied
    // the restores. No oracle, no snapshot diff.
    //
    // Present before and gone after is the observable form of that. It is not
    // circumstantial: nothing else in the import path touches this family, and a
    // reorg driven by anything else would have left the row behind.
    assert!(
        ev.app_journal_row_before.is_some(),
        "A must have had a generic application journal for its own height-1 block{}",
        ev.report()
    );
    assert!(
        ev.app_journal_row_after.is_none(),
        "the generic application-journal row for the ABANDONED block must have been \
         consumed and deleted by the unwind; if it survived, the live reorg path did \
         not run on the real encoded record{}",
        ev.report()
    );

    // Mechanism: the single-slot, height-keyed undo journal.
    assert!(
        ev.diff_row_before != ev.diff_row_after,
        "importing a sibling must have disturbed the height-1 undo journal{}",
        ev.report()
    );
    assert!(
        ev.diff_addrs_after.is_none(),
        "handle_reorg consumed and deleted the height-1 journal row, leaving no undo record \
         for either sibling{}",
        ev.report()
    );
    let before = ev
        .diff_addrs_before
        .as_ref()
        .expect("A wrote a journal for its own block");
    assert!(
        before.is_superset(&ev.a_only_touched),
        "before the import, the height-1 journal described A's block{}",
        ev.report()
    );
}

/// After adopting a chain, a node holds that chain's state.
///
/// Issue #253. Node A imports node B's height-1 sibling, fork choice switches,
/// and A's head becomes B's block. A therefore claims to be on B's chain, and
/// must hold B's chain's account state.
///
/// # What used to happen, and why this test was `#[ignore]`d
///
/// Two defects, in sequence.
///
/// First, `cf::STATE_DIFFS` was keyed by `height.to_be_bytes()` alone. Two
/// siblings at one height named ONE undo row, so importing B overwrote A's
/// journal with B's changes before the reorg could read it. The revert then
/// undid B's changes — the block being ADOPTED — and left A's, the ones being
/// orphaned, permanently applied. Re-keying the journals by `(height, block
/// hash)` fixed that: A's own journal survives B's import and the revert now
/// consumes the right record.
///
/// That was not enough, and this test kept failing for a second reason. The
/// reorg import path executed the arriving block and then DROPPED the
/// candidate — no acceptance, no publication. Once execution moved behind
/// `ApplicationOverlay`, dropping the candidate discards every state write it
/// made, so B's block's state was never committed at all; only its journal,
/// block row, transactions and receipts were. Its own comment, "new chain
/// blocks are already applied during import", had stopped being true. A ended
/// on B's block with the GENESIS state: A's changes correctly reverted, B's
/// never applied.
///
/// # What happens now
///
/// The reorg arm resolves the fork with `plan_reorg`, unwinds the abandoned
/// branch newest-first from its per-block journals with each pre-image
/// validated against the value the journal says the block left, restores the
/// accumulator from the ancestor's header, and applies the adopted branch
/// through the ordinary publication path. See `sumchain_consensus::reorg`.
///
/// # What this test does and does not cover
///
/// It compares ACCOUNT state — every row in `cf::STATE` under the `acct`
/// prefix — between A and B. Those now agree exactly.
///
/// It does not compare every column family, and one of them still diverges:
/// `cf::SUPPLY` is written by every block and journalled by nothing, so the
/// unwind cannot restore it. Because `SupplyStore::v_state_digest` is folded
/// into the block state root, the replayed root for B's block does not equal
/// its header's, and at height 1 — inside the `height <= 496720` compatibility
/// window — that mismatch is force-adopted rather than refused. The reorg
/// reports it as `ReorgOutcome::force_adopted` and the engine logs it, but
/// nothing here fails on it. That gap is a PRODUCER-side obligation on the
/// undo journal, measured and pinned in
/// `reorg_execution.rs::the_subsystem_journals_do_not_cover_every_family_a_block_writes`.
#[tokio::test]
async fn reorged_node_must_converge_with_the_chain_it_adopted_issue_253() {
    let ev = run_probe().await;
    println!("{}", ev.report());

    // Only meaningful if A actually adopted B's block.
    assert_eq!(
        ev.head_after, ev.b_hash,
        "this assertion is about the *adoption* path; A did not adopt B's block{}",
        ev.report()
    );

    let divergence = ev.divergence();
    assert!(
        divergence.is_empty(),
        "node A adopted B's block {} as its head (import returned `{}`, \
         ConsensusEvent::Reorg depth={:?}), but {} account(s) on A disagree with node B, \
         which is on that very block. A node cannot be on a chain and not hold its state. \
         Height-1 undo journal after the import: {} bytes. \
         Divergent accounts (A post-import vs B):\n      {}\n\
         For reference, A's own pre/post-import change was {} account(s):\n      {}{}",
        ev.b_hash,
        ev.import_result,
        ev.reorg_depth,
        divergence.len(),
        ev.diff_row_after.as_ref().map_or(0, |v| v.len()),
        divergence.join("\n      "),
        ev.residue().len(),
        if ev.residue().is_empty() {
            "(none)".to_string()
        } else {
            ev.residue().join("\n      ")
        },
        ev.report()
    );
}
