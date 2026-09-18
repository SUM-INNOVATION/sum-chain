//! Account state and the authoritative commitment.
//!
//! `compute_block_state_root` folds header fields, receipt outcomes, the gated
//! contract / supply / compute-pool / beacon digests and the previous root. It
//! reads the account rows nowhere. The first test in this file DEMONSTRATES the
//! consequence rather than asserting it from the source: a balance altered
//! behind the executor's back produces an identical block state root, so two
//! nodes can disagree about every balance on the chain and the commitment
//! cannot tell.
//!
//! The rest of the file is the closure of that hole and the evidence for it: an
//! account digest folded into the root behind its own activation height, a
//! byte-level proof that the pre-activation formula is unchanged, the inverse
//! of the finding above the boundary, the determinism the commitment needs to
//! be a function of state at all, and the mixed-version behaviour — old binary
//! against new — on both sides of the boundary.

mod common;

use std::sync::Arc;
use std::time::Instant;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::account_root::{account_row_count, account_state_digest, v_account_state_digest};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::supply::SupplyStore;
use sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::AccountState;
use sumchain_storage::{cf, Database, StateStore};

const CHAIN_ID: u64 = 1;
const PROPOSER: [u8; 32] = [0x5A; 32];
const LIMIT: u64 = 1 << 30;

/// The activation height these tests use.
///
/// ABOVE `LEGACY_ROOT_COMPATIBILITY_HEIGHT`, and that is not a detail. At or
/// below that height `accept_imported` ADOPTS a mismatching header root instead
/// of rejecting the block (`Acceptance::LegacyCompatibility`), so a
/// mixed-version disagreement there is absorbed rather than detected. An
/// activation height inside the legacy window would split the network silently,
/// which is the one outcome this work exists to prevent. See
/// `a_boundary_inside_the_legacy_window_would_be_absorbed_not_detected`.
const BOUNDARY: u64 = LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// One node: its own database, its own state manager, its own executor — and
/// therefore its own `ChainParams`, which is what makes an "old binary" and a
/// "new binary" expressible in one test process. The only difference between
/// the two is `account_root_enabled_from_height`, which is exactly the
/// difference an un-upgraded node has.
struct Node {
    dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    exec: BlockExecutor,
    params: ChainParams,
}

fn node(params: ChainParams) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let exec = BlockExecutor::new(state.clone(), db.clone(), params.clone());
    Node {
        dir,
        db,
        state,
        exec,
        params,
    }
}

/// A node on the CURRENT binary with the commitment dormant — which is also,
/// byte for byte, a node on the old binary: the gate is closed at every height,
/// so `compute_block_state_root` takes the same branches it takes today.
fn old_binary() -> Node {
    node(ChainParams::with_v2_enabled())
}

/// A node on the new binary with the commitment activating at `height`.
fn new_binary_from(height: u64) -> Node {
    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(height);
    node(params)
}

impl Node {
    /// Write an account row straight into `cf::STATE`, behind the executor.
    fn seed(&self, who: &Address, balance: u128, nonce: u64) {
        StateStore::new(&self.db)
            .put_account(who, &AccountState { balance, nonce })
            .unwrap();
    }

    /// Delete an account row, behind the executor.
    fn delete_account(&self, who: &Address) {
        self.db
            .delete(cf::STATE, &StateStore::account_key(who))
            .unwrap();
    }

    fn account(&self, who: &Address) -> AccountState {
        StateStore::new(&self.db).get_account(who).unwrap()
    }

    /// The account digest over COMMITTED state.
    fn committed_digest(&self) -> Hash {
        account_state_digest(&self.db).unwrap()
    }

    /// Stop this node and start it again on the same directory.
    ///
    /// A real restart, not a re-read: every handle on the old `Database` is
    /// dropped before the new one opens — RocksDB refuses a directory whose lock
    /// is still held, so a "restart" that left one alive would be a no-op that
    /// passed. The in-memory state-root cache is restored the way
    /// `PoAEngine::load_chain` restores it, out of `BlockStore::get_latest`,
    /// because that is the only place a restarted node can get it from: the root
    /// lives in a `RwLock` and nothing persists it separately.
    fn restart(self) -> Node {
        let Node {
            dir,
            db,
            state,
            exec,
            params,
        } = self;
        drop(exec);
        drop(state);
        drop(db);

        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        if let Some(block) = sumchain_storage::BlockStore::new(&db).get_latest().unwrap() {
            state.set_state_root(block.header.state_root);
        }
        let exec = BlockExecutor::new(state.clone(), db.clone(), params.clone());
        Node {
            dir,
            db,
            state,
            exec,
            params,
        }
    }

    /// Execute `block` and PUBLISH it the way a proposer does, returning the
    /// state root its own execution computed (which is the root that lands in
    /// the header).
    fn produce(&self, block: &mut Block) -> (Hash, Vec<Receipt>) {
        let exec = self
            .exec
            .execute_block(block, self.state.state_root(), &[])
            .expect("execute_block");
        block.header.state_root = exec.computed_root();
        let (executed, _sd, _cd) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(block).expect("accept_produced");
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        (block.header.state_root, receipts)
    }

    /// The whole produce path for a block this node builds itself.
    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> (Block, Hash, Vec<Receipt>) {
        let mut block = block_at(height, txs);
        let (root, receipts) = self.produce(&mut block);
        (block, root, receipts)
    }

    /// IMPORT a block another node produced: execute it and hand the result to
    /// `accept_imported`, which owns both sides of the root comparison.
    ///
    /// Returns this node's OWN computed root on acceptance and the refusal text
    /// on rejection. This is the seam where a mixed-version split becomes
    /// visible, or does not.
    fn import(&self, block: &Block) -> std::result::Result<Hash, String> {
        let exec = self
            .exec
            .execute_block(block, self.state.state_root(), &[])
            .expect("execute_block");
        let computed = exec.computed_root();
        let (executed, _sd, _cd) = exec.into_parts();
        match executed.accept_imported(block) {
            Ok(accepted) => {
                let accumulator = accepted.accumulator();
                accepted.publish().expect("publish");
                self.state.set_state_root(accumulator);
                Ok(computed)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

fn block_at(height: u64, txs: Vec<SignedTransaction>) -> Block {
    let header = BlockHeader::new(Hash::ZERO, height, 1_000, Hash::ZERO, Hash::ZERO, PROPOSER);
    Block::new(header, txs)
}

fn key(n: u8) -> KeyPair {
    KeyPair::from_bytes([n; 32])
}

fn addr(n: u8) -> Address {
    Address::new([n; 20])
}

fn transfer(
    from: &KeyPair,
    to: &Address,
    amount: u128,
    fee: u128,
    nonce: u64,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: from.address(),
        fee,
        nonce,
        payload: TxPayload::Transfer { to: *to, amount },
    };
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// The account digest over a FRESH, EMPTY candidate on `db` — committed state
/// reached through the EXECUTION-path function rather than the committed one.
/// Used to show the two agree.
fn digest_through_a_view(db: &Database) -> Hash {
    let mut overlay = ApplicationOverlay::new(db, LIMIT);
    let view = ExecutionView::new(&mut overlay);
    v_account_state_digest(&view).unwrap()
}

/// TODAY'S state-root formula, transcribed independently of the production code
/// path.
///
/// This is the reference the pre-activation root is checked against. It is
/// deliberately a SECOND implementation rather than a call into the first:
/// asserting that the gate-closed branch equals itself would prove nothing. The
/// contract, compute-pool and beacon gates are all `None` under
/// `ChainParams::with_v2_enabled`, so their folds are absent here exactly as
/// they are absent there.
///
/// The supply digest is read from COMMITTED state after publication, which is
/// the value the candidate held — that equality is the subject of
/// `supply_candidate.rs::the_candidate_digest_is_the_digest_of_what_gets_published`.
fn root_today(
    block: &Block,
    receipts: &[Receipt],
    previous_root: Hash,
    db: &Arc<Database>,
) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&block.height().to_be_bytes());
    data.extend_from_slice(block.header.parent_hash.as_bytes());
    data.extend_from_slice(&block.header.timestamp.to_be_bytes());
    data.extend_from_slice(block.header.tx_root.as_bytes());
    for receipt in receipts {
        data.extend_from_slice(receipt.tx_hash.as_bytes());
        data.push(if receipt.is_success() { 1 } else { 0 });
        data.extend_from_slice(&receipt.fee_paid.to_be_bytes());
    }
    if let Some(digest) = SupplyStore::new(db.clone()).state_digest().unwrap() {
        data.extend_from_slice(digest.as_bytes());
    }
    data.extend_from_slice(previous_root.as_bytes());
    Hash::hash(&data)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The finding
// ─────────────────────────────────────────────────────────────────────────────

/// Account rows do NOT participate in the authoritative commitment below the
/// gate — reproduced, not argued.
///
/// A balance is written straight into `cf::STATE` on one of two otherwise
/// identical nodes, both then publish the same block, and the two roots are
/// compared. Equal roots is the finding: the commitment does not detect a
/// disagreement about account state, so nothing built on it — light client,
/// fast-sync check, fraud proof — can either.
#[test]
fn the_finding_account_rows_are_absent_from_todays_commitment() {
    let alice = key(1);
    let carol = addr(3);
    let mallory = addr(4);

    let honest = old_binary();
    let tampered = old_binary();
    for n in [&honest, &tampered] {
        n.seed(&alice.address(), 10_000_000, 0);
    }
    let (_, g1, _) = honest.publish(10, Vec::new());
    let (_, g2, _) = tampered.publish(10, Vec::new());
    assert_eq!(g1, g2, "identical nodes, identical roots");

    // A balance that no transaction created.
    tampered.seed(&mallory, 999_999_999, 0);
    assert_eq!(honest.account(&mallory).balance, 0);
    assert_eq!(tampered.account(&mallory).balance, 999_999_999);

    let (_, r1, _) = honest.publish(11, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    let (_, r2, _) = tampered.publish(11, vec![transfer(&alice, &carol, 1_000, 500, 0)]);

    assert_eq!(
        r1, r2,
        "THE FINDING: two nodes holding different account state publish one \
         identical root, and the commitment cannot tell"
    );
    assert_ne!(
        honest.account(&mallory).balance,
        tampered.account(&mallory).balance
    );
    // The digest that is NOT folded below the gate does see the difference,
    // which is what makes folding it the fix rather than a restatement of it.
    assert_ne!(honest.committed_digest(), tampered.committed_digest());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The pre-activation formula is unchanged
// ─────────────────────────────────────────────────────────────────────────────

/// Below the activation height the root is byte-identical to today's, over a
/// sequence of blocks — checked against an INDEPENDENT transcription of today's
/// formula, not against the same code path.
#[test]
fn the_pre_activation_root_is_byte_identical_to_todays_formula() {
    let alice = key(1);
    let carol = addr(3);

    // One chain, two configurations: the gate absent entirely, and the gate
    // present but above every height these blocks occupy.
    let dormant = old_binary();
    let armed = new_binary_from(BOUNDARY);
    for n in [&dormant, &armed] {
        n.seed(&alice.address(), 10_000_000, 0);
    }

    for (i, height) in [10u64, 11, 12, 13].into_iter().enumerate() {
        let txs = vec![transfer(&alice, &carol, 1_000, 500, i as u64)];

        let previous = armed.state.state_root();
        let (block, armed_root, receipts) = armed.publish(height, txs.clone());
        let reference = root_today(&block, &receipts, previous, &armed.db);
        assert_eq!(
            armed_root, reference,
            "height {height}: the armed node's pre-activation root must equal \
             today's formula byte for byte"
        );

        let (_, dormant_root, _) = dormant.publish(height, txs);
        assert_eq!(
            armed_root, dormant_root,
            "height {height}: a node that has never heard of the gate computes \
             the same root"
        );
    }

    // The account state really did move under those blocks — the equality above
    // is not the equality of two chains that did nothing.
    assert_eq!(armed.account(&carol).balance, 4_000);
    assert_eq!(armed.account(&alice.address()).nonce, 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The inverse of the finding, above the boundary
// ─────────────────────────────────────────────────────────────────────────────

/// Above the activation height, a changed balance changes the root.
///
/// The exact inverse of `the_finding_account_rows_are_absent_from_todays_commitment`:
/// same tamper, same block, opposite outcome.
#[test]
fn above_the_boundary_a_changed_balance_changes_the_root() {
    let alice = key(1);
    let carol = addr(3);
    let mallory = addr(4);

    let honest = new_binary_from(BOUNDARY);
    let tampered = new_binary_from(BOUNDARY);
    for n in [&honest, &tampered] {
        n.seed(&alice.address(), 10_000_000, 0);
    }
    let (_, g1, _) = honest.publish(BOUNDARY, Vec::new());
    let (_, g2, _) = tampered.publish(BOUNDARY, Vec::new());
    assert_eq!(g1, g2, "identical state above the gate still agrees");

    tampered.seed(&mallory, 999_999_999, 0);

    let (_, r1, _) = honest.publish(BOUNDARY + 1, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    let (_, r2, _) = tampered.publish(BOUNDARY + 1, vec![transfer(&alice, &carol, 1_000, 500, 0)]);

    assert_ne!(
        r1, r2,
        "above the gate account state IS committed: a balance no transaction \
         created must move the root"
    );
}

/// A nonce change is detected as well as a balance change.
///
/// Worth its own test: the nonce is the replay-protection counter, and a
/// commitment that covered balances alone would let two nodes disagree about
/// which transactions an account has already spent.
#[test]
fn above_the_boundary_a_changed_nonce_changes_the_root() {
    let alice = key(1);
    let carol = addr(3);
    let bystander = addr(7);

    let honest = new_binary_from(BOUNDARY);
    let tampered = new_binary_from(BOUNDARY);
    for n in [&honest, &tampered] {
        n.seed(&alice.address(), 10_000_000, 0);
        n.seed(&bystander, 500, 0);
    }
    // Only the nonce differs, and only on an account no transaction touches.
    tampered.seed(&bystander, 500, 9);
    assert_eq!(
        honest.account(&bystander).balance,
        tampered.account(&bystander).balance
    );
    assert_ne!(
        honest.account(&bystander).nonce,
        tampered.account(&bystander).nonce
    );

    let (_, r1, _) = honest.publish(BOUNDARY, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    let (_, r2, _) = tampered.publish(BOUNDARY, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    assert_ne!(r1, r2, "a nonce-only divergence must move the root");
}

/// Account creation and account deletion are both reflected.
///
/// The two transitions a digest over values alone can miss: an account created
/// with `{balance: 0, nonce: 0}` holds the same values as an absent one, and a
/// deleted account leaves no row to fold. The per-address record and the count
/// term cover both.
#[test]
fn creation_and_deletion_both_move_the_commitment() {
    let a = old_binary();
    let empty = a.committed_digest();

    // Creating an account with all-zero values — the state `get_account`
    // flattens absence into — must not be indistinguishable from absence.
    a.seed(&addr(1), 0, 0);
    let one_zero_account = a.committed_digest();
    assert_ne!(
        empty, one_zero_account,
        "a present-and-zero account must differ from an absent one"
    );

    a.seed(&addr(2), 77, 3);
    let two = a.committed_digest();
    assert_ne!(one_zero_account, two);

    // Deleting it must be reflected, and must land back on the earlier value.
    a.delete_account(&addr(2));
    assert_eq!(one_zero_account, a.committed_digest());

    a.delete_account(&addr(1));
    assert_eq!(empty, a.committed_digest());
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Determinism
// ─────────────────────────────────────────────────────────────────────────────

/// The commitment is a function of the account SET and nothing else: not of
/// insertion order, not of the write history that produced the rows, not of
/// which database or process holds them.
#[test]
fn the_commitment_is_a_function_of_state_not_of_how_it_was_built() {
    let rows: Vec<(Address, u128, u64)> = (0u8..24)
        .map(|i| {
            (
                addr(i.wrapping_mul(7).wrapping_add(3)),
                (i as u128) * 1_000 + 1,
                i as u64,
            )
        })
        .collect();

    // Ascending insertion.
    let a = old_binary();
    for (who, balance, nonce) in rows.iter() {
        a.seed(who, *balance, *nonce);
    }

    // Descending insertion on a different database, through intermediate values
    // that are later overwritten: a different write history, the same final
    // state.
    let b = old_binary();
    for (who, balance, nonce) in rows.iter().rev() {
        b.seed(who, u128::MAX - *balance, nonce.wrapping_add(1));
    }
    for (who, balance, nonce) in rows.iter() {
        b.seed(who, *balance, *nonce);
    }

    assert_eq!(
        a.committed_digest(),
        b.committed_digest(),
        "identical account state, identical commitment"
    );

    // Recomputation is stable, and the execution-path function agrees with the
    // committed one. Those are the two computations a proposer and a validator
    // actually perform.
    assert_eq!(a.committed_digest(), a.committed_digest());
    assert_eq!(a.committed_digest(), digest_through_a_view(&a.db));
    assert_eq!(b.committed_digest(), digest_through_a_view(&b.db));

    // And one changed row anywhere in the set moves it.
    let (who, balance, nonce) = rows[11];
    b.seed(&who, balance + 1, nonce);
    assert_ne!(a.committed_digest(), b.committed_digest());
}

/// The digest a proposer folded over its candidate is the digest a validator
/// reaches over the state that block published.
///
/// The consensus property the whole design rests on: if a candidate fold and a
/// committed scan could disagree, every block would be a split.
#[test]
fn the_candidate_fold_and_the_committed_scan_agree() {
    let alice = key(1);
    let carol = addr(3);
    let n = new_binary_from(BOUNDARY);
    n.seed(&alice.address(), 10_000_000, 0);

    let (_, root, _) = n.publish(BOUNDARY, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    assert_eq!(n.committed_digest(), digest_through_a_view(&n.db));

    // A second node that IMPORTS the same block reaches the same root, which is
    // only possible if its candidate fold matched the proposer's.
    let m = new_binary_from(BOUNDARY);
    m.seed(&alice.address(), 10_000_000, 0);
    let mut block = block_at(BOUNDARY, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    block.header.state_root = root;
    assert_eq!(
        m.import(&block).expect("the importer must agree"),
        root,
        "proposer's candidate fold == importer's candidate fold"
    );
    assert_eq!(m.committed_digest(), n.committed_digest());
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Mixed version
// ─────────────────────────────────────────────────────────────────────────────

/// An old binary and a new binary agree on every block below the activation
/// height, and disagree in a DEFINED, detectable way above it.
///
/// Both halves on one chain, because the interesting claim is the transition:
/// the same pair of nodes that agreed at `BOUNDARY - 1` must refuse each
/// other's blocks at `BOUNDARY`.
#[test]
fn mixed_version_agrees_below_the_boundary_and_is_refused_above_it() {
    let alice = key(1);
    let carol = addr(3);

    let old = old_binary();
    let new = new_binary_from(BOUNDARY);
    for n in [&old, &new] {
        n.seed(&alice.address(), 10_000_000, 0);
    }

    // ── Below the boundary: the new node proposes, the old node imports, and
    //    the old node's own execution reaches the identical root.
    for (i, height) in [BOUNDARY - 3, BOUNDARY - 2, BOUNDARY - 1]
        .into_iter()
        .enumerate()
    {
        let txs = vec![transfer(&alice, &carol, 1_000, 500, i as u64)];
        let (block, new_root, _) = new.publish(height, txs);
        let old_root = old
            .import(&block)
            .unwrap_or_else(|e| panic!("height {height}: the old binary must accept: {e}"));
        assert_eq!(
            new_root, old_root,
            "height {height}: below the boundary the two binaries agree"
        );
    }
    assert_eq!(old.state.state_root(), new.state.state_root());
    assert_eq!(old.committed_digest(), new.committed_digest());

    // ── At the boundary: the new node folds account state, the old node does
    //    not, and the old node REFUSES the block rather than adopting its root.
    let txs = vec![transfer(&alice, &carol, 1_000, 500, 3)];
    let (block, _new_root, _) = new.publish(BOUNDARY, txs.clone());
    let refusal = old
        .import(&block)
        .expect_err("the old binary must refuse a block above the boundary");
    assert!(
        refusal.contains("state root mismatch")
            && refusal.contains(&format!("at height {BOUNDARY}")),
        "the refusal must NAME the disagreement rather than absorb it: {refusal}"
    );

    // ── And symmetrically: a block the OLD node produces at the boundary is
    //    refused by the new one. The split is mutual and immediate, not a
    //    one-directional drift only one side notices.
    let old2 = old_binary();
    let new2 = new_binary_from(BOUNDARY);
    for n in [&old2, &new2] {
        n.seed(&alice.address(), 10_000_000, 0);
    }
    let (block, _, _) = old2.publish(BOUNDARY, txs);
    let refusal = new2
        .import(&block)
        .expect_err("the new binary must refuse the old binary's block");
    assert!(
        refusal.contains("state root mismatch"),
        "expected a named root mismatch: {refusal}"
    );
}

/// An activation height inside the legacy-root window would be ABSORBED, not
/// detected — so the boundary must be chosen above it.
///
/// `accept_imported` adopts a mismatching header root at or below
/// `LEGACY_ROOT_COMPATIBILITY_HEIGHT` instead of rejecting it. That allowance
/// predates this work and is not changed here, but it constrains the activation
/// height: inside the window the two binaries would diverge on stored state
/// while both published the proposer's root — the silent split this commitment
/// exists to make impossible. Recorded as a test so the constraint cannot be
/// lost.
#[test]
fn a_boundary_inside_the_legacy_window_would_be_absorbed_not_detected() {
    let alice = key(1);
    let carol = addr(3);
    let inside = LEGACY_ROOT_COMPATIBILITY_HEIGHT;

    let old = old_binary();
    let new = new_binary_from(inside);
    for n in [&old, &new] {
        n.seed(&alice.address(), 10_000_000, 0);
    }

    let (block, new_root, _) = new.publish(inside, vec![transfer(&alice, &carol, 1_000, 500, 0)]);
    let old_computed = old
        .import(&block)
        .expect("inside the legacy window the mismatch is ADOPTED, not refused");
    assert_ne!(
        old_computed, new_root,
        "the two binaries did disagree about the root"
    );
    assert_eq!(
        old.state.state_root(),
        new_root,
        "and the old node published the proposer's root anyway — a silent \
         divergence. This is why the activation height must be above \
         LEGACY_ROOT_COMPATIBILITY_HEIGHT."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Cost
// ─────────────────────────────────────────────────────────────────────────────

/// The per-block cost of the commitment at a realistic account count, as a
/// number.
///
/// The fold is O(accounts) per block with O(1) memory, and that cost is the
/// design decision rather than a footnote: it is paid on EVERY block by every
/// node, so it is measured rather than assumed.
///
/// `ACCOUNT_ROOT_COST_ACCOUNTS` overrides the count (default 100_000, which
/// keeps the unoptimised test build quick). The measured numbers are recorded
/// in the accompanying report. The assertion here is deliberately loose: it is
/// a tripwire on the ORDER of the cost — that the fold is still a linear
/// streaming scan and has not acquired a per-account allocation, map build or
/// re-seek — not a benchmark gate, because a test machine's absolute timings
/// are not a consensus parameter.
#[test]
fn the_cost_of_the_account_commitment_at_a_realistic_account_count() {
    let accounts: usize = std::env::var("ACCOUNT_ROOT_COST_ACCOUNTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);

    let n = old_binary();
    let mut batch = n.db.batch();
    for i in 0..accounts {
        let mut raw = [0u8; 20];
        raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
        raw[12..].copy_from_slice(&(i as u64).to_be_bytes());
        let account = AccountState {
            balance: (i as u128) * 1_000 + 1,
            nonce: i as u64,
        };
        batch
            .put(
                cf::STATE,
                &StateStore::account_key(&Address::new(raw)),
                &sumchain_storage::schema::encode_account(&account).unwrap(),
            )
            .unwrap();
    }
    batch.commit().unwrap();

    // Three measurements, because they answer different questions. The FIRST
    // scan runs against a database that has just taken a bulk write, so it
    // reads largely out of the memtable; the second is the steady state a
    // running node's block loop sees. Neither is a cold-cache number — nothing
    // portable drops the OS page cache — and that limitation is the honest
    // caveat on all of these.
    let started = Instant::now();
    let first = n.committed_digest();
    let first_elapsed = started.elapsed();

    let started = Instant::now();
    let committed = n.committed_digest();
    let committed_elapsed = started.elapsed();
    assert_eq!(first, committed);

    let started = Instant::now();
    let through_view = digest_through_a_view(&n.db);
    let view_elapsed = started.elapsed();
    assert_eq!(committed, through_view);

    eprintln!(
        "ACCOUNT-ROOT COST: {accounts} accounts | first scan {first_elapsed:?} \
         | committed scan {committed_elapsed:?} ({:.3} us/account) \
         | execution-path merged scan {view_elapsed:?} ({:.3} us/account) \
         | digest {committed}",
        committed_elapsed.as_secs_f64() * 1e6 / accounts as f64,
        view_elapsed.as_secs_f64() * 1e6 / accounts as f64,
    );

    let per_account_us = view_elapsed.as_secs_f64() * 1e6 / accounts as f64;
    assert!(
        per_account_us < 50.0,
        "per-account fold cost {per_account_us:.3} us is not a linear streaming scan"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. The activation height itself
// ─────────────────────────────────────────────────────────────────────────────
//
// Sections 1–6 establish what the commitment does once a height is chosen.
// This section is about choosing one. Two constraints bind it, they bind in
// opposite directions, and both are configuration facts — so both are checked
// before a block is executed rather than at the boundary, where the node has
// already been publishing.

/// An activation at or below the legacy window is REFUSED, not merely
/// documented.
///
/// `a_boundary_inside_the_legacy_window_would_be_absorbed_not_detected` above
/// demonstrates what such a height does: the two binaries disagree about the
/// root and the old one publishes the proposer's anyway, because
/// `accept_imported` force-adopts at or below `LEGACY_ROOT_COMPATIBILITY_HEIGHT`.
/// That test proves the hazard. This one proves the configuration is now
/// unreachable, which is the difference between a comment and a guard.
#[test]
fn an_activation_inside_the_legacy_window_is_refused() {
    for height in [
        0,
        1,
        LEGACY_ROOT_COMPATIBILITY_HEIGHT - 1,
        LEGACY_ROOT_COMPATIBILITY_HEIGHT,
    ] {
        let mut params = sound_activation();
        params.account_root_enabled_from_height = Some(height);
        let err = sumchain_state::account_root::validate_account_root_activation(&params)
            .expect_err("an activation inside the legacy window must be refused");
        let text = err.to_string();
        assert!(
            text.contains("legacy root-compatibility cutoff")
                && text.contains(&LEGACY_ROOT_COMPATIBILITY_HEIGHT.to_string()),
            "the refusal must name the cutoff it is below: {text}"
        );
    }

    // And one block above it is accepted, so the boundary is the boundary and
    // not an interval somebody widened.
    let mut params = sound_activation();
    params.account_root_enabled_from_height = Some(BOUNDARY);
    params.application_journal_enabled_from_height = Some(0);
    sumchain_state::account_root::validate_account_root_activation(&params)
        .expect("one block above the cutoff, with a journal far below, is sound");
}

/// The account gate requires a PINNED journal gate, at least one full reorg
/// horizon below it.
///
/// Three refusals, one for each way the pair can be wrong, because they have
/// different causes and an operator has to tell them apart:
///
/// * the journal gate ABSENT — `None` is not "off", it is "observed from this
///   node's own chain", and a node-local boundary cannot support a commitment
///   that is folded into the state root;
/// * the journal gate LATER than the account gate — a band of heights where the
///   root commits to account rows and no record exists to restore them;
/// * the journal gate earlier but not far enough — a reorg at the activation
///   height can walk `MAX_REORG_WALK` blocks back, so records must begin at
///   least that far below it.
///
/// The failure all three prevent is the same and it is terminal: a reorg that
/// reaches a height where the root includes account state and the journal cannot
/// put the rows back leaves a chain that can neither revert nor agree.
#[test]
fn the_account_gate_requires_a_pinned_journal_gate_far_enough_below_it() {
    let account = 13_800_000;
    let horizon = sumchain_storage::pruner::UNDO_RETENTION_FLOOR;

    // Absent.
    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(account);
    params.application_journal_enabled_from_height = None;
    let text = sumchain_state::account_root::validate_account_root_activation(&params)
        .expect_err("an unpinned journal boundary must be refused")
        .to_string();
    assert!(
        text.contains("PINNED") && text.contains("node-local"),
        "the refusal must say why `None` is not enough: {text}"
    );

    // Later than the account gate.
    for journal in [account + 1, account + horizon] {
        let mut params = ChainParams::with_v2_enabled();
        params.account_root_enabled_from_height = Some(account);
        params.application_journal_enabled_from_height = Some(journal);
        let text = sumchain_state::account_root::validate_account_root_activation(&params)
            .expect_err("a journal gate above the account gate must be refused")
            .to_string();
        assert!(
            text.contains(&journal.to_string()) && text.contains(&account.to_string()),
            "the refusal must name both heights: {text}"
        );
    }

    // Earlier, but inside the reorg horizon.
    for journal in [account, account - 1, account - horizon + 1] {
        let mut params = ChainParams::with_v2_enabled();
        params.account_root_enabled_from_height = Some(account);
        params.application_journal_enabled_from_height = Some(journal);
        sumchain_state::account_root::validate_account_root_activation(&params)
            .expect_err("a journal gate inside the reorg horizon must be refused");
    }

    // Exactly one horizon below is the first sound pair, and anything earlier
    // stays sound.
    for journal in [account - horizon, account - horizon - 1, 0] {
        let mut params = ChainParams::with_v2_enabled();
        params.account_root_enabled_from_height = Some(account);
        params.application_journal_enabled_from_height = Some(journal);
        sumchain_state::account_root::validate_account_root_activation(&params)
            .unwrap_or_else(|e| panic!("journal at {journal} must be accepted: {e}"));
    }
}

/// The production default is sound, and stays sound.
///
/// `account_root_enabled_from_height == None` asks nothing of the journal gate,
/// which is what lets this land on a running chain without touching its
/// configuration at all.
#[test]
fn the_dormant_default_requires_nothing_of_the_journal() {
    let params = ChainParams::default();
    assert_eq!(params.account_root_enabled_from_height, None);
    assert_eq!(params.application_journal_enabled_from_height, None);
    sumchain_state::account_root::validate_account_root_activation(&params)
        .expect("the dormant default must be sound");
}

/// The refusal happens at STARTUP, before any block is executed.
///
/// The distinction this test exists for: a check that fired at the activation
/// boundary would fire on a node that had already been publishing for however
/// long the operator had the bad configuration, at the moment the chain most
/// needs it to keep working. `StateManager::init_from_genesis` runs before the
/// first row of state exists, and a chain on an unsound pair cannot be created
/// at all.
#[test]
fn an_unsound_activation_pair_fails_before_the_chain_exists() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = StateManager::new(db.clone(), CHAIN_ID);

    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(13_800_000);
    params.application_journal_enabled_from_height = None;
    let genesis = sumchain_genesis::Genesis::new(
        CHAIN_ID,
        0,
        vec!["GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8".to_string()],
        [("8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4".to_string(), 500u128)]
            .into_iter()
            .collect(),
        params,
    );

    let err = state
        .init_from_genesis(&genesis)
        .expect_err("a chain must not be initialisable on an unsound pair")
        .to_string();
    // WHICH layer names the fault is pinned by
    // `runtime_activation.rs::the_shared_validator_reports_the_ordering_fault_before_the_window_fault`,
    // not here: `validate_runtime_activation` runs `ChainParams::validate`
    // first, so an unpinned journal gate is reported by the loader with the
    // loader's wording, and the narrow validator's `...WithoutPinnedJournal` is
    // never reached for this pair. Asserting on that wording made this test a
    // second, quieter opinion about the ordering — it went red when the two
    // entry points were merged, and what it was reporting was the merge, not a
    // regression. What this test owns is that a chain cannot be CREATED on the
    // pair and that the refusal is actionable: it must name the gate to fix.
    assert!(
        err.contains("application_journal_enabled_from_height")
            && err.to_lowercase().contains("pin"),
        "the startup refusal must name the gate to pin: {err}"
    );

    // And nothing was written: the refusal precedes the allocation, so the
    // operator's data directory is exactly as they left it.
    assert_eq!(
        account_state_digest(&db).unwrap(),
        account_state_digest(&Database::open_default(
            tempfile::TempDir::new().unwrap().path()
        )
        .unwrap())
        .unwrap(),
        "a refused init must leave the account family empty"
    );
}

/// A sound pair, for the tests above to vary one field of.
fn sound_activation() -> ChainParams {
    let mut params = ChainParams::with_v2_enabled();
    params.application_journal_enabled_from_height = Some(0);
    params
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Cost with a COLD cache
// ─────────────────────────────────────────────────────────────────────────────

/// The per-block cost of the commitment when the data is not already in memory.
///
/// `the_cost_of_the_account_commitment_at_a_realistic_account_count` above is
/// WARM: it writes the account family and immediately scans it, so the rows come
/// out of the memtable, the block cache and the OS page cache in turn, and the
/// number it produces is a lower bound on what a running node pays. That
/// limitation was recorded honestly and never measured. This measures it.
///
/// # The three states, and which one a node is actually in
///
/// * **warm** — the steady state of a node whose whole account family fits in
///   memory and is scanned every block. This is what the existing test reports.
/// * **cold block cache** — RocksDB reopened, its own cache empty, the OS page
///   cache still holding the SST files. This is a node that has just restarted,
///   and it is also the floor for a node whose account family is larger than the
///   block cache but smaller than RAM.
/// * **cold page cache** — the OS cache evicted too, so the scan reaches the
///   device. This is a node whose account family does not fit in RAM alongside
///   everything else the machine is doing, and it is the case that decides
///   whether the scheme has a ceiling in practice or only in principle.
///
/// The first two are measured on every run. The third requires evicting the
/// page cache, which is not portable and is not cheap — the only reliable way
/// without privileges is to read enough unrelated data to push the database out
/// — so it runs only when `ACCOUNT_ROOT_EVICT_PAGE_CACHE` is set to a byte
/// count. Set it larger than the machine's RAM.
///
/// `ACCOUNT_ROOT_COST_ACCOUNTS` sets the account count, default 100,000.
///
/// # What is asserted, and what is only reported
///
/// The assertion is a tripwire on the SHAPE of the cost — that a cold scan is
/// still a linear streaming read and has not acquired a per-account seek — not a
/// benchmark gate. A test machine's absolute timings are not a consensus
/// parameter and must not become one by being asserted on. The numbers go to
/// stderr and into the report.
#[test]
fn the_cost_of_the_account_commitment_with_a_cold_cache() {
    let accounts: usize = std::env::var("ACCOUNT_ROOT_COST_ACCOUNTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);

    // The directory outlives the database handle, which is the whole mechanism:
    // "cold" here means a new `Database` over the same files.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().to_path_buf();

    let (warm, warm_digest) = {
        let db = Arc::new(Database::open_default(&path).unwrap());
        // Committed in chunks. One `WriteBatch` holding ten million account rows
        // is a few hundred megabytes of process memory before a single byte
        // reaches disk, and a measurement harness that pages the machine is
        // measuring the machine.
        const CHUNK: usize = 250_000;
        let mut batch = db.batch();
        for i in 0..accounts {
            let mut raw = [0u8; 20];
            raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
            raw[12..].copy_from_slice(&(i as u64).to_be_bytes());
            let account = AccountState {
                balance: (i as u128) * 1_000 + 1,
                nonce: i as u64,
            };
            batch
                .put(
                    cf::STATE,
                    &StateStore::account_key(&Address::new(raw)),
                    &sumchain_storage::schema::encode_account(&account).unwrap(),
                )
                .unwrap();
            if (i + 1) % CHUNK == 0 {
                batch.commit().unwrap();
                batch = db.batch();
            }
        }
        batch.commit().unwrap();

        // Onto disk and into one level, so the cold scan below reads SST files
        // rather than a memtable that survived the reopen in the page cache as
        // a write-ahead log.
        db.flush().unwrap();
        db.compact().unwrap();

        // Two scans; the second is the steady state.
        let _ = account_state_digest(&db).unwrap();
        let started = Instant::now();
        let digest = account_state_digest(&db).unwrap();
        let elapsed = started.elapsed();
        (elapsed, digest)
    };

    // The bytes on disk, summed from the directory rather than from
    // `Database::approximate_size` — that reads RocksDB's live-data estimate for
    // the default column family and reports 0 for a database whose rows are all
    // in `cf::STATE`, which is every database this harness builds.
    let on_disk: u64 = std::fs::read_dir(&path)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();

    // Every handle dropped: RocksDB refuses to reopen a directory whose lock is
    // still held, so a "reopen" that left one alive would be measuring the warm
    // cache again.
    let cold_block_cache = {
        let db = Database::open_default(&path).unwrap();
        let started = Instant::now();
        let digest = account_state_digest(&db).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(
            digest, warm_digest,
            "a cold scan must reach the same commitment as a warm one"
        );
        elapsed
    };

    // Optional third state.
    let cold_page_cache = std::env::var("ACCOUNT_ROOT_EVICT_PAGE_CACHE")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|bytes| {
            evict_page_cache(bytes);
            let db = Database::open_default(&path).unwrap();
            let started = Instant::now();
            let digest = account_state_digest(&db).unwrap();
            let elapsed = started.elapsed();
            assert_eq!(digest, warm_digest);
            elapsed
        });

    let per = |d: std::time::Duration| d.as_secs_f64() * 1e6 / accounts as f64;
    eprintln!(
        "ACCOUNT-ROOT COLD COST: {accounts} accounts | on disk {on_disk} B \
         ({:.1} B/account) | warm {warm:?} ({:.3} us/account) | cold block cache \
         {cold_block_cache:?} ({:.3} us/account) | cold page cache {} ",
        on_disk as f64 / accounts as f64,
        per(warm),
        per(cold_block_cache),
        match cold_page_cache {
            Some(d) => format!("{d:?} ({:.3} us/account)", per(d)),
            None => "not measured (set ACCOUNT_ROOT_EVICT_PAGE_CACHE=<bytes>)".to_string(),
        }
    );

    // The tripwire: a cold scan that had acquired a per-account seek would be
    // orders of magnitude slower than this, not a small multiple of the warm
    // number. Deliberately loose — it is a shape check, not a benchmark gate.
    let cold_per_account = per(cold_block_cache);
    assert!(
        cold_per_account < 200.0,
        "cold per-account fold cost {cold_per_account:.3} us is not a linear \
         streaming read"
    );
}

/// Push the OS page cache out by reading `bytes` of unrelated data.
///
/// There is no portable way to drop the page cache: `posix_fadvise(DONTNEED)`
/// does not exist on macOS, `purge` needs privileges this test does not have,
/// and `F_NOCACHE` applies to a descriptor this test does not own — RocksDB
/// opens its own. So the cache is evicted the only way a normal process can,
/// by making the kernel choose. `bytes` must exceed the machine's RAM for that
/// choice to reach the database's pages.
///
/// This is approximate and it is labelled approximate. It cannot guarantee that
/// every SST page was evicted, only that far more pressure was applied than the
/// database occupies, so the resulting number is an upper bound on warm and a
/// lower bound on a truly cold device read.
fn evict_page_cache(bytes: u64) {
    use std::io::{Read, Write};

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("ballast");
    let chunk = vec![0x5Au8; 64 << 20];
    {
        let mut f = std::fs::File::create(&path).unwrap();
        let mut written = 0u64;
        while written < bytes {
            f.write_all(&chunk).unwrap();
            written += chunk.len() as u64;
        }
        f.sync_all().unwrap();
    }
    let mut f = std::fs::File::open(&path).unwrap();
    let mut buf = vec![0u8; 64 << 20];
    let mut total = 0u64;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n as u64,
            Err(_) => break,
        }
    }
    eprintln!("page-cache eviction: wrote and read back {total} B of ballast");
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. The count that cost depends on
// ─────────────────────────────────────────────────────────────────────────────

/// `account_row_count` counts STORED ROWS, which is not the same number as
/// "accounts holding value".
///
/// The distinction is the whole reason this function exists rather than a
/// balance query or a transaction-graph walk. The commitment folds one record
/// per stored row and the per-block cost is linear in that count. A row whose
/// balance and nonce are both zero is indistinguishable from an absent account
/// by VALUE — `get_account` flattens absence into exactly those values — and
/// entirely distinguishable from one by COST. A performance argument built on
/// the value-holding count is an argument about a different number.
///
/// Four rows, of which only one holds value. The count is four.
#[test]
fn the_row_count_is_not_the_count_of_accounts_holding_value() {
    let n = old_binary();
    assert_eq!(account_row_count(&n.db).unwrap(), 0);

    n.seed(&addr(1), 1_000, 0); // value and no history
    n.seed(&addr(2), 0, 7); // history and no value — a spent account
    n.seed(&addr(3), 0, 0); // neither: present, and zero in both fields
    n.seed(&addr(4), 0, 0);

    assert_eq!(
        account_row_count(&n.db).unwrap(),
        4,
        "every stored row counts, including the three that hold nothing"
    );

    // A balance-based count would say one. That is the number a supply
    // cross-check or a transaction-graph closure produces, and it is not the
    // number the fold pays for.
    let holding_value = [addr(1), addr(2), addr(3), addr(4)]
        .iter()
        .filter(|a| n.account(a).balance > 0)
        .count();
    assert_eq!(holding_value, 1);

    // The count tracks the fold exactly: it is the same scan, so deleting a row
    // moves both together.
    let before = n.committed_digest();
    n.delete_account(&addr(3));
    assert_eq!(account_row_count(&n.db).unwrap(), 3);
    assert_ne!(before, n.committed_digest());
}

/// The row count is the number of records the commitment folds — established by
/// agreement with the fold rather than by reading the two implementations.
#[test]
fn the_row_count_agrees_with_the_fold_it_predicts() {
    let n = old_binary();
    for i in 0u8..37 {
        n.seed(&addr(i.wrapping_mul(7).wrapping_add(3)), i as u128, i as u64);
    }
    // 37 distinct addresses under `wrapping_mul(7)` on a byte: 7 is coprime with
    // 256, so the map is injective and no two collide.
    let rows = account_row_count(&n.db).unwrap();
    assert_eq!(rows, 37);

    // The count term the digest folds is the same u64. Changing the set by one
    // row must move both, which is what makes the count a cost predictor rather
    // than a statistic computed nearby.
    let digest = n.committed_digest();
    n.seed(&addr(200), 1, 1);
    assert_eq!(account_row_count(&n.db).unwrap(), rows + 1);
    assert_ne!(digest, n.committed_digest());
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. The commitment through every path by which state reaches a node
// ─────────────────────────────────────────────────────────────────────────────
//
// Sections 1–9 establish what the digest IS: a function of the account set, the
// same under the candidate fold and the committed scan, folded into the root
// behind an activation height whose preconditions are checked before a block is
// executed. What they do not establish is that it stays true as state moves.
//
// There are five ways account state reaches or changes on a node, and the
// commitment has to survive all five or it is a commitment to whichever ones it
// survives. This section is that set. Two of the five are proven elsewhere,
// because the machinery they need lives elsewhere, and they are named here so
// the set can be read as one thing:
//
// | path            | where                                                       |
// |-----------------|-------------------------------------------------------------|
// | publication     | `the_commitment_survives_publishing_a_chain_of_blocks`, below |
// | restart         | `the_commitment_survives_a_restart`, below                  |
// | reorg           | `crates/consensus/tests/reorg_execution.rs::a_reorg_converges_account_rows_supply_rows_journals_and_the_activated_root` |
// | snapshot policy | `snapshot_commitment.rs::the_snapshot_policy_admits_only_what_the_commitment_can_check` |
// | mixed versions  | `mixed_version_agrees_below_the_boundary_and_is_refused_above_it`, section 5 |
//
// The reorg case is in the consensus crate because a reorg is a consensus
// operation: it needs the fork-choice planner and the journal unwind, neither of
// which this crate can drive. The snapshot case is in `snapshot_commitment.rs`
// because that is where the snapshot fixtures are.

/// Publication: at every height, the digest the published root folded is the
/// digest committed state reproduces — and an importer reaches both.
///
/// `the_candidate_fold_and_the_committed_scan_agree` in section 4 proves this
/// for ONE block. One block is not the claim. The claim is that it holds as a
/// chain accumulates, because the root folds the PREVIOUS root: an error at any
/// height is carried forward, so a single-block test cannot distinguish "the
/// fold is right" from "the fold is right the first time".
///
/// Five heights across the boundary, with real transactions creating accounts,
/// moving balances and advancing nonces, checked at each height against a second
/// node that only ever imported.
#[test]
fn the_commitment_survives_publishing_a_chain_of_blocks() {
    let alice = key(1);
    let bob = key(2);
    let proposer = new_binary_from(BOUNDARY);
    let importer = new_binary_from(BOUNDARY);
    for n in [&proposer, &importer] {
        n.seed(&alice.address(), 10_000_000, 0);
        n.seed(&bob.address(), 5_000_000, 0);
    }

    // Start below the boundary and cross it, so the chain contains blocks whose
    // roots do not fold the digest and blocks whose roots do. A commitment that
    // only worked on a chain that had always had it would not be deployable.
    let mut digests = Vec::new();
    for (i, height) in (BOUNDARY - 2..=BOUNDARY + 2).enumerate() {
        let txs = vec![
            transfer(
                &alice,
                &addr(0x30 + i as u8),
                1_000 + i as u128,
                500,
                i as u64,
            ),
            transfer(&bob, &addr(0x40 + i as u8), 2_000, 500, i as u64),
        ];
        let (block, root, _) = proposer.publish(height, txs);

        let imported = importer
            .import(&block)
            .unwrap_or_else(|e| panic!("height {height}: the importer must agree: {e}"));
        assert_eq!(
            imported, root,
            "height {height}: the importer's own execution must reach the \
             published root"
        );

        // The two nodes hold the same account set, reached by different routes:
        // one executed as proposer, the other as importer.
        let committed = proposer.committed_digest();
        assert_eq!(
            committed,
            importer.committed_digest(),
            "height {height}: proposer and importer must hold one account set"
        );
        // And the committed scan agrees with the execution-path fold over the
        // same database, which is the pair the root depends on.
        assert_eq!(
            committed,
            digest_through_a_view(&proposer.db),
            "height {height}: committed scan and candidate fold must agree"
        );
        digests.push((height, committed));
    }

    // The digest moved at every height — otherwise the equalities above would be
    // satisfied by a fold that ignores its input.
    for pair in digests.windows(2) {
        assert_ne!(
            pair[0].1, pair[1].1,
            "heights {} and {} published different account state and must have \
             different digests",
            pair[0].0, pair[1].0
        );
    }
    assert_eq!(
        proposer.state.state_root(),
        importer.state.state_root(),
        "and the chains converge on one root"
    );
}

/// Restart: a node stopped and started again reaches the same commitment, and
/// the chain continues rather than forking at the next block.
///
/// The failure this excludes is a commitment that depends on anything a process
/// accumulates — an iterator warmed by the writes that produced the rows, a
/// cached count, an ordering that held because the memtable was still hot. The
/// digest is claimed to be a function of the account SET; a restart is the
/// cheapest way to ask whether it is a function of the PROCESS.
///
/// Both halves matter. Recomputing the same digest proves the stored rows
/// survived; publishing the next block and reaching the root a never-restarted
/// twin reaches proves the node came back onto the same chain rather than onto a
/// plausible-looking fork.
#[test]
fn the_commitment_survives_a_restart() {
    let alice = key(1);
    let bob = key(2);

    let build = || {
        let n = new_binary_from(BOUNDARY);
        n.seed(&alice.address(), 10_000_000, 0);
        n.seed(&bob.address(), 5_000_000, 0);
        n.seed(&addr(0xF0), 0, 0); // a zero row: stored, invisible to a balance query
        for (i, height) in (BOUNDARY - 1..=BOUNDARY + 1).enumerate() {
            n.publish(
                height,
                vec![transfer(
                    &alice,
                    &addr(0x50 + i as u8),
                    1_000,
                    500,
                    i as u64,
                )],
            );
        }
        n
    };

    let restarted = build();
    let twin = build();
    let before = restarted.committed_digest();
    let root_before = restarted.state.state_root();
    let rows_before = account_row_count(&restarted.db).unwrap();
    assert_eq!(before, twin.committed_digest(), "the twins start identical");

    let restarted = restarted.restart();

    assert_eq!(
        restarted.committed_digest(),
        before,
        "the digest is a function of the account set, so a restart cannot move it"
    );
    assert_eq!(
        account_row_count(&restarted.db).unwrap(),
        rows_before,
        "and the row count with it — including the zero row, which no balance \
         query would have noticed going missing"
    );
    assert_eq!(
        restarted.state.state_root(),
        root_before,
        "the state root a restarted node restores from its latest block header \
         is the one it stopped at"
    );
    // The execution-path fold, over a fresh overlay on a freshly-opened
    // database. This is the one that would break if the digest depended on a
    // warm iterator.
    assert_eq!(digest_through_a_view(&restarted.db), before);

    // And the next block: same height, same transaction, on a restarted node and
    // on one that never stopped.
    let tx = vec![transfer(&alice, &addr(0x60), 4_242, 500, 3)];
    let (_, root_restarted, _) = restarted.publish(BOUNDARY + 2, tx.clone());
    let (_, root_twin, _) = twin.publish(BOUNDARY + 2, tx);
    assert_eq!(
        root_restarted, root_twin,
        "a restarted node must continue the chain, not fork onto a root only it \
         computes"
    );
    assert_eq!(restarted.committed_digest(), twin.committed_digest());
}
