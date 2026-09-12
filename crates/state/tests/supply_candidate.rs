//! The supply subsystem reads and writes the block's candidate.
//!
//! Supply is not one subsystem's private store: settlement, staking,
//! governance, storage-metadata and the block executor itself all mutate it,
//! and its digest is folded into the block state root once the correction is
//! applied. Two consequences drive this file.
//!
//! A block that touches supply twice — a settlement claim accruing credit and
//! then a grant unlock spending it — must see its own first write. And a block
//! that is rejected must leave the reserve, the ledger and every grant exactly
//! as it found them, because those are the rows the root commits to.

mod common;

use std::sync::Arc;

use sumchain_primitives::supply::{ProtocolReserve, ServiceKind, SupplyLedger};
use sumchain_genesis::ChainParams;
use sumchain_primitives::supply::GENESIS_ACCOUNTED_SUPPLY;
use sumchain_crypto::{sign, KeyPair};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::supply::SupplyStore;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database};

const LIMIT: u64 = 1 << 20;

fn open_db() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

/// A parent whose correction has been applied, reached the way the chain
/// reaches it: fund the 1B genesis supply, then PUBLISH the block that applies
/// the correction.
///
/// Not a hand-written seed. The rows a candidate starts from must be rows a
/// block actually published, or these tests would be asserting against a parent
/// state the chain cannot produce.
fn seed_applied(state: &Arc<StateManager>, db: &Arc<Database>, exec: &BlockExecutor) {
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    state.credit(&Address::new([0xE1; 20]), half).unwrap();
    state.credit(&Address::new([0xE2; 20]), half).unwrap();
    common::publish_empty_block(state, exec, 100, &[0x5Au8; 32]);
    assert!(
        SupplyStore::new(db.clone()).is_migration_applied().unwrap(),
        "the correction block must apply it"
    );
}

/// A mainnet-shaped chain with the correction already applied.
fn applied() -> (tempfile::TempDir, Arc<Database>, Arc<StateManager>, BlockExecutor) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let exec = BlockExecutor::new(state.clone(), db.clone(), ChainParams::with_v2_enabled());
    seed_applied(&state, &db, &exec);
    (dir, db, state, exec)
}

#[test]
fn a_block_sees_the_credit_it_accrued_earlier_in_itself() {
    // Accrual and the aggregate both live in SUPPLY. A second accrual in the
    // same block must add to the first, not to the parent's value — otherwise
    // two reward sites in one block silently keep only the larger.
    let (_d, db, state, exec) = applied();
    let _ = (&state, &exec);
    let who = Address::new([4u8; 20]);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    SupplyStore::accrue_earned_credit(&mut view, &who, ServiceKind::Validator, 100).unwrap();
    assert_eq!(
        SupplyStore::v_get_earned_credit(&view, &who, ServiceKind::Validator).unwrap(),
        100
    );

    SupplyStore::accrue_earned_credit(&mut view, &who, ServiceKind::Validator, 50).unwrap();
    assert_eq!(
        SupplyStore::v_get_earned_credit(&view, &who, ServiceKind::Validator).unwrap(),
        150,
        "the second accrual must build on the first, not on the parent's zero"
    );
    assert_eq!(
        SupplyStore::v_get_aggregate(&view).unwrap().total_earned_validator,
        150,
        "the aggregate must accumulate both"
    );

    // Committed state is untouched: the accruals are buffered.
    assert_eq!(
        SupplyStore::new(db.clone())
            .get_earned_credit(&who, ServiceKind::Validator)
            .unwrap(),
        0
    );
}

#[test]
fn a_milestone_counter_advances_once_per_call_within_a_block() {
    let (_d, db, state, exec) = applied();
    let _ = (&state, &exec);
    let who = Address::new([5u8; 20]);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for expected in 1..=3u64 {
        SupplyStore::record_por_proof(&mut view, &who).unwrap();
        assert_eq!(
            SupplyStore::v_get_milestones(&view, &who, ServiceKind::Archive)
                .unwrap()
                .por_proofs,
            expected,
            "each proof in the block must see the previous count"
        );
    }
    assert_eq!(
        SupplyStore::new(db.clone())
            .get_milestones(&who, ServiceKind::Archive)
            .unwrap()
            .por_proofs,
        0
    );
}

/// A fee-paying transfer, so the block credits its proposer and reaches
/// `accrue_earned_credit` — the executor's own supply accrual site.
fn transfer(from: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: 1,
        from: from.address(),
        fee,
        nonce,
        payload: TxPayload::Transfer {
            to: Address::new([0x11u8; 20]),
            amount: 1,
        },
    };
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

#[test]
fn the_candidate_digest_is_the_digest_of_what_gets_published() {
    // The consensus property: a proposer folds the digest over its candidate; a
    // validator that stores the block recomputes it over committed state. The
    // two must agree.
    //
    // Driven through a REAL published block — a fee-paying transfer, so the
    // proposer's fee reaches `accrue_earned_credit`, which is the executor's own
    // supply accrual site.
    let (_d, db, state, exec) = applied();
    let store = SupplyStore::new(db.clone());
    let before = store.state_digest().unwrap().expect("correction applied");

    let payer = KeyPair::generate();
    state
        .put_account(
            &payer.address(),
            &sumchain_storage::schema::AccountState {
                balance: 1_000_000,
                nonce: 0,
            },
        )
        .unwrap();
    let proposer = KeyPair::generate();
    let receipts = common::publish_block(
        &state,
        &exec,
        101,
        proposer.public_key().as_bytes(),
        vec![transfer(&payer, 0, 5_000)],
        &[],
    );
    assert!(receipts[0].is_success(), "{:?}", receipts[0].status);

    let published = store.state_digest().unwrap().unwrap();
    assert_ne!(
        published, before,
        "a block that pays a fee must change the supply digest; if it does not,          the accrual never reached the published state"
    );

    // The validator's recomputation: a candidate opened on the published
    // database must digest to exactly what is committed.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let view = ExecutionView::new(&mut overlay);
    assert_eq!(
        SupplyStore::v_state_digest(&view).unwrap().unwrap(),
        published,
        "candidate and committed digests must agree over identical rows"
    );
}

#[test]
fn a_dropped_candidate_leaves_supply_byte_identical() {
    let (_d, db, state, exec) = applied();
    let _ = (&state, &exec);
    let store = SupplyStore::new(db.clone());
    let before_digest = store.state_digest().unwrap();
    let before_reserve = store.get_reserve().unwrap();
    let who = Address::new([7u8; 20]);

    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        SupplyStore::accrue_earned_credit(&mut view, &who, ServiceKind::Archive, 1_000).unwrap();
        SupplyStore::record_por_proof(&mut view, &who).unwrap();
        SupplyStore::record_settlement_claim(&mut view, &who).unwrap();
        // Dropped here, unpublished.
    }

    assert_eq!(store.state_digest().unwrap(), before_digest);
    assert_eq!(store.get_reserve().unwrap(), before_reserve);
    assert_eq!(
        store.get_earned_credit(&who, ServiceKind::Archive).unwrap(),
        0
    );
    assert_eq!(
        store.get_milestones(&who, ServiceKind::Archive).unwrap().por_proofs,
        0
    );
}

#[test]
fn a_reserve_release_is_visible_to_a_later_release_in_the_same_block() {
    // Two governance releases in one block draw from one pool. The second must
    // see the first's decrement, or the block can pay out more than the pool
    // holds and the reserve underflows.
    use sumchain_primitives::supply::ReservePool;

    let (_d, db, state, exec) = applied();
    let _ = (&state, &exec);
    let to = Address::new([8u8; 20]);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let pool0 = SupplyStore::v_get_reserve(&view)
        .unwrap()
        .unwrap()
        .ecosystem_pool_remaining;
    assert!(pool0 > 2, "the seeded pool must be able to fund two releases");

    SupplyStore::apply_reserve_release(
        &mut view,
        ReservePool::Ecosystem,
        &to,
        1,
        [1u8; 32],
        sumchain_primitives::Hash::new([0u8; 32]),
        10,
    )
    .unwrap();
    let pool1 = SupplyStore::v_get_reserve(&view)
        .unwrap()
        .unwrap()
        .ecosystem_pool_remaining;
    assert_eq!(pool1, pool0 - 1);

    SupplyStore::apply_reserve_release(
        &mut view,
        ReservePool::Ecosystem,
        &to,
        1,
        [2u8; 32],
        sumchain_primitives::Hash::new([0u8; 32]),
        10,
    )
    .unwrap();
    assert_eq!(
        SupplyStore::v_get_reserve(&view)
            .unwrap()
            .unwrap()
            .ecosystem_pool_remaining,
        pool0 - 2,
        "the second release must draw from the pool the first left behind"
    );
}
