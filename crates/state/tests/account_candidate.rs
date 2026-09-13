//! Accounts read and write the block's candidate.
//!
//! Accounts are the row almost every transaction touches. The fee debit, the
//! proposer credit and the nonce bump run on 27 of the 30 dispatcher arms —
//! including nine of the twelve whose own subsystem rows were already on the
//! overlay — so until this moved, those blocks committed balances as they
//! executed, whether or not they were ever accepted. The three exceptions are
//! explicitly fee-free: ComputePool, BeaconSetup and BeaconSigning return
//! `fee_paid: 0` on every path, the gate-open success included, so they debit
//! nothing to begin with.
//!
//! What that makes testable is narrow and sharp: a block must see its own
//! account writes, and a block that is abandoned must leave `cf::STATE` exactly
//! as it found it — byte for byte.
//!
//! Byte-for-byte, and NOT because the state root covers it. The accumulator in
//! `compute_block_state_root` folds header fields, receipt outcomes and the
//! gated contract, supply, compute-pool and beacon digests; it does not commit
//! to account rows at all. That is precisely why an abandoned block's balances
//! have to be checked directly: nothing downstream would notice them, and
//! `cf::STATE` is still the canonical balance every later block reads and every
//! RPC reports.

mod common;

use std::sync::Arc;

use sumchain_primitives::Address;
use sumchain_state::state::StateManager;
use sumchain_storage::schema::{AccountState, StateStore};
use sumchain_storage::{cf, Database};

const LIMIT: u64 = 1 << 20;

fn open() -> (tempfile::TempDir, Arc<Database>, Arc<StateManager>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    (dir, db, state)
}

fn view_of<'v, 'db>(
    overlay: &'v mut sumchain_storage::overlay::ApplicationOverlay<'db>,
) -> sumchain_storage::exec_view::ExecutionView<'v, 'db> {
    sumchain_storage::exec_view::ExecutionView::new(overlay)
}

/// Every account row in `cf::STATE`, as raw bytes.
///
/// Bytes, not decoded balances: the claim is that an abandoned block leaves the
/// column family untouched, and a decoded comparison would pass even if the
/// rows had been rewritten to an equal value — which is a write, and a write is
/// what must not happen.
fn seed(db: &Database, address: &Address, balance: u128, nonce: u64) {
    StateStore::new(db)
        .put_account(address, &AccountState { balance, nonce })
        .unwrap();
}

fn account_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = db
        .prefix_iter(cf::STATE, b"acct")
        .unwrap()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    out.sort();
    out
}

// ── Same-block visibility ────────────────────────────────────────────────────

/// A debit staged earlier in the block is visible to the next read.
#[test]
fn a_balance_moved_earlier_in_the_block_is_visible_later_in_it() {
    let (_dir, db, state) = open();
    let a = Address::new([0xA1; 20]);
    seed(&db, &a, 1_000, 0);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    StateManager::v_deduct(&mut view, &a, 400).unwrap();
    assert_eq!(
        StateManager::v_get_balance(&view, &a).unwrap(),
        600,
        "the read must see the debit this block staged"
    );

    // A second debit draws from what the first left, not from the parent's row.
    StateManager::v_deduct(&mut view, &a, 600).unwrap();
    assert_eq!(StateManager::v_get_balance(&view, &a).unwrap(), 0);
    assert!(
        StateManager::v_deduct(&mut view, &a, 1).is_err(),
        "a third debit must fail against the staged balance, not the parent's"
    );

    // Committed storage still holds the parent's row.
    assert_eq!(state.get_balance(&a).unwrap(), 1_000);
}

/// A nonce bumped earlier in the block is visible to the next read.
///
/// This is what admission and validity depend on: two transactions from the
/// same sender in one block must see 0 then 1, or the second is rejected as a
/// replay — or, worse, accepted twice.
#[test]
fn a_nonce_bumped_earlier_in_the_block_is_visible_later_in_it() {
    let (_dir, db, state) = open();
    let a = Address::new([0xA2; 20]);
    seed(&db, &a, 10, 0);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    assert_eq!(StateManager::v_get_nonce(&view, &a).unwrap(), 0);
    StateManager::v_increment_nonce(&mut view, &a).unwrap();
    assert_eq!(StateManager::v_get_nonce(&view, &a).unwrap(), 1);
    StateManager::v_increment_nonce(&mut view, &a).unwrap();
    assert_eq!(StateManager::v_get_nonce(&view, &a).unwrap(), 2);

    assert_eq!(state.get_nonce(&a).unwrap(), 0, "the parent is unmoved");
}

/// A self-transfer reads the debit it just staged.
///
/// The credit half reads the account AFTER the debit half wrote it. Read the
/// parent's row instead and the credit restores what the debit removed, so the
/// fee is refunded and the sender pays nothing.
#[test]
fn a_self_transfer_sees_its_own_debit() {
    let (_dir, db, _state) = open();
    let a = Address::new([0xA3; 20]);
    let proposer = Address::new([0xB1; 20]);
    seed(&db, &a, 1_000, 0);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    StateManager::v_transfer(&mut view, &a, &a, 100, 10, &proposer).unwrap();

    assert_eq!(
        StateManager::v_get_balance(&view, &a).unwrap(),
        990,
        "a self-transfer costs exactly the fee"
    );
    assert_eq!(StateManager::v_get_nonce(&view, &a).unwrap(), 1);
    assert_eq!(StateManager::v_get_balance(&view, &proposer).unwrap(), 10);
}

// ── Absent-account pre-images ────────────────────────────────────────────────

/// Absent and present-and-zero stay distinct through the view.
///
/// The undo journal needs the difference: reverting a block that CREATED an
/// account has to delete the row, and a pre-image captured as `Some(default)`
/// can only write a zero row back — a different chain state, and one the
/// account root would distinguish if there were one.
#[test]
fn an_absent_account_is_not_a_zero_account() {
    let (_dir, db, _state) = open();
    let never = Address::new([0xC1; 20]);
    let zeroed = Address::new([0xC2; 20]);
    seed(&db, &zeroed, 0, 0);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    let view = view_of(&mut overlay);

    assert!(
        StateManager::v_get_account_opt(&view, &never).unwrap().is_none(),
        "an account that has never existed reads as absent"
    );
    let present = StateManager::v_get_account_opt(&view, &zeroed)
        .unwrap()
        .expect("a stored zero row reads as present");
    assert_eq!((present.balance, present.nonce), (0, 0));
    // The flattening reader cannot tell them apart, which is why it is not the
    // primitive.
    let flat_never = StateManager::v_get_account(&view, &never).unwrap();
    let flat_zeroed = StateManager::v_get_account(&view, &zeroed).unwrap();
    assert_eq!(
        (flat_never.balance, flat_never.nonce),
        (flat_zeroed.balance, flat_zeroed.nonce)
    );
}

/// Creating an account in a block records `None` as its pre-image.
///
/// `ExecutionView` captures the pre-image on FIRST write. For an account the
/// block creates there is nothing to capture, and the journal has to see that —
/// the revert deletes the row rather than writing zero over it.
#[test]
fn creating_an_account_records_an_absent_preimage() {
    let (_dir, db, _state) = open();
    let fresh = Address::new([0xC3; 20]);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = view_of(&mut overlay);
        assert!(StateManager::v_get_account_opt(&view, &fresh).unwrap().is_none());
        StateManager::v_credit(&mut view, &fresh, 500).unwrap();
        assert_eq!(StateManager::v_get_balance(&view, &fresh).unwrap(), 500);

        let key = StateStore::account_key(&fresh);
        assert_eq!(
            view.preimage(cf::STATE, &key),
            Some(&None),
            "the pre-image of an account this block created must be ABSENT, not \
             a zero row: a revert has to delete it"
        );
    }
}

/// Overwriting an existing account records the row it replaced.
#[test]
fn overwriting_an_account_records_the_row_it_replaced() {
    let (_dir, db, _state) = open();
    let a = Address::new([0xC4; 20]);
    seed(&db, &a, 700, 3);
    let before = db
        .get(cf::STATE, &StateStore::account_key(&a))
        .unwrap()
        .expect("seeded");

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = view_of(&mut overlay);
        StateManager::v_deduct(&mut view, &a, 200).unwrap();
        assert_eq!(
            view.preimage(cf::STATE, &StateStore::account_key(&a)),
            Some(&Some(before)),
            "the pre-image is the parent's row, byte for byte"
        );
    }
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A dropped candidate leaves `cf::STATE` byte-identical.
#[test]
fn a_dropped_candidate_leaves_accounts_byte_identical() {
    let (_dir, db, _state) = open();
    let a = Address::new([0xD1; 20]);
    let b = Address::new([0xD2; 20]);
    seed(&db, &a, 5_000, 1);
    seed(&db, &b, 10, 0);
    let before = account_rows(&db);
    assert_eq!(before.len(), 2);

    {
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
        let mut view = view_of(&mut overlay);
        StateManager::v_transfer(&mut view, &a, &b, 1_000, 25, &Address::new([0xD3; 20])).unwrap();
        StateManager::v_increment_nonce(&mut view, &b).unwrap();
        StateManager::v_credit(&mut view, &Address::new([0xD4; 20]), 999).unwrap();
        // Dropped here: never accepted, never published.
    }

    assert_eq!(
        account_rows(&db),
        before,
        "an abandoned block must leave every account row exactly as it found it \
         — including creating none"
    );
}

/// ONE `v_transfer` stages the sender, then fails on the recipient.
///
/// Two earlier versions of this test were wrong, each in a way worth keeping.
///
/// The first ran a successful transfer and then a failing one, and found
/// committed storage untouched — but `v_transfer` checks the balance before it
/// writes anything, so the failing transfer staged nothing at all. Every row it
/// proved rolled back came from the SUCCESSFUL transfer. It tested abandonment
/// wearing a failure's name.
///
/// The second staged a bare `v_deduct` and then ran a separate failing
/// `v_transfer`. The half-applied state was real, but it was assembled from two
/// unrelated operations; the failing one still staged nothing. A partial write
/// that only exists because the test wrote half of it by hand is not evidence
/// that a single operation can fail half-way.
///
/// This is one call. `v_transfer` writes the sender, then reads and writes the
/// recipient, so an overlay whose ceiling is exactly the sender update's charge
/// accepts the first write and refuses the second — the operation fails with
/// the debit already staged and no matching credit anywhere. The charge is
/// measured rather than guessed: a disposable overlay performs the identical
/// sender write and reports what it cost. The error is checked to name the
/// limit, so a balance check rejecting the transfer before it wrote anything
/// could not pass for a half-way failure — which is exactly how the first
/// version of this test went wrong.
///
/// Dropping that candidate must still leave `cf::STATE` byte-identical.
#[test]
fn a_transfer_that_fails_after_staging_the_sender_leaves_accounts_byte_identical() {
    const START: u128 = 100;
    const AMOUNT: u128 = 40;

    let (_dir, db, _state) = open();
    let sender = Address::new([0xE1; 20]);
    let absent = Address::new([0xE2; 20]);
    seed(&db, &sender, START, 0);
    let before = account_rows(&db);

    // 1. What the sender update costs, measured by performing exactly it. With
    //    `fee` 0 and a zero proposer, this is byte-for-byte the first write
    //    `v_transfer` will make: same key, same post-debit row.
    let sender_charge = {
        let mut scratch = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
        let mut view = view_of(&mut scratch);
        let mut debited = StateManager::v_get_account(&view, &sender).unwrap();
        debited.balance -= AMOUNT;
        debited.nonce += 1;
        StateManager::v_put_account(&mut view, &sender, &debited).unwrap();
        scratch.logical_bytes()
    };
    assert!(sender_charge > 0, "the sender update must cost something");

    {
        // 2. A ceiling of exactly that: the sender write fits, nothing else does.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, sender_charge);
        let mut view = view_of(&mut overlay);

        // 3 & 4. One operation, which fails part-way through itself.
        let err = StateManager::v_transfer(&mut view, &sender, &absent, AMOUNT, 0, &Address::ZERO)
            .expect_err("the recipient write must be refused");
        assert!(
            err.to_string().contains("limit"),
            "it must fail because the RECIPIENT write was refused, not because \
             the balance check rejected it before writing anything: {err}"
        );

        // 5. The half it got through is staged, and the half it did not is not.
        let staged = StateManager::v_get_account(&view, &sender).unwrap();
        assert_eq!(
            (staged.balance, staged.nonce),
            (START - AMOUNT, 1),
            "the sender update is staged — the transfer failed AFTER writing it"
        );
        assert!(
            StateManager::v_get_account_opt(&view, &absent)
                .unwrap()
                .is_none(),
            "the recipient must still be absent: its write is the one that was \
             refused, and an absent account is not a zero account"
        );

        // The candidate holds a state no successful execution produces: the
        // amount has left the sender and reached nobody.
        let total: u128 = StateManager::v_iter_all_accounts(&view)
            .unwrap()
            .iter()
            .map(|(_, a)| a.balance)
            .sum();
        assert_eq!(total, START - AMOUNT, "value is destroyed in the candidate");
    }

    // 6. Dropped, not published. Bytes, not decoded values.
    assert_eq!(
        account_rows(&db),
        before,
        "a transfer that failed half-way must leave every account row exactly \
         as it found it"
    );
}

/// The census reads the candidate's accounts.
///
/// Economic supply is Σ account balances plus the other INCLUDE buckets, and
/// the correction mints `TARGET - economic_supply`. A census that read the
/// parent's balances against a block that had already moved them would mint the
/// difference into the reserve.
#[test]
fn the_account_census_sees_this_blocks_balances() {
    let (_dir, db, _state) = open();
    let a = Address::new([0xF1; 20]);
    let b = Address::new([0xF2; 20]);
    seed(&db, &a, 900, 0);

    let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    let parent: u128 = StateManager::v_iter_all_accounts(&view)
        .unwrap()
        .iter()
        .map(|(_, s)| s.balance)
        .sum();
    assert_eq!(parent, 900);

    // A transfer conserves the total; a credit to a NEW account raises it, and
    // the new row has to appear in the scan or the census misses it entirely.
    StateManager::v_transfer(&mut view, &a, &b, 100, 0, &Address::ZERO).unwrap();
    let after_move: u128 = StateManager::v_iter_all_accounts(&view)
        .unwrap()
        .iter()
        .map(|(_, s)| s.balance)
        .sum();
    assert_eq!(after_move, 900, "a transfer conserves the total");
    assert_eq!(
        StateManager::v_iter_all_accounts(&view).unwrap().len(),
        2,
        "the account this block created must be in the scan"
    );

    StateManager::v_credit(&mut view, &Address::new([0xF3; 20]), 42).unwrap();
    let after_mint: u128 = StateManager::v_iter_all_accounts(&view)
        .unwrap()
        .iter()
        .map(|(_, s)| s.balance)
        .sum();
    assert_eq!(after_mint, 942);

    // Committed storage is unmoved throughout.
    assert_eq!(
        StateStore::new(&db)
            .iter_all_accounts()
            .unwrap()
            .iter()
            .map(|(_, s)| s.balance)
            .sum::<u128>(),
        900
    );
}
