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
use sumchain_state::account_root::{account_state_digest, v_account_state_digest};
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
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    exec: BlockExecutor,
}

fn node(params: ChainParams) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let exec = BlockExecutor::new(state.clone(), db.clone(), params);
    Node {
        _dir: dir,
        db,
        state,
        exec,
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
