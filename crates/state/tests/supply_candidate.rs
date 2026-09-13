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
    common::credit_committed(&db, &Address::new([0xE1; 20]), half);
    common::credit_committed(&db, &Address::new([0xE2; 20]), half);
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
    sumchain_storage::StateStore::new(&db).put_account(
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

/// A same-block inference mutation must move the correction's reserve delta by
/// exactly that amount.
///
/// The census sums inference escrow and verifier bonds into economic supply,
/// and the delta minted is `TARGET - economic_supply`. Inference migrated to the
/// candidate, so a session opened — or an escrow drawn down — earlier in the
/// block changes what the census must measure. Reading committed inference
/// totals here would mint a delta that does not reconcile with the state the
/// same block publishes: the reserve would be wrong by exactly the escrow the
/// block moved.
///
/// The assertion is on the EXACT delta, not merely that it differs: an
/// off-by-anything here is a supply error.
#[test]
fn a_same_block_inference_mutation_moves_the_reserve_delta_exactly() {
    use sumchain_primitives::inference_settlement::{
        InferenceSession, InferenceSessionStatus, InferenceVerifierRecord, InferenceVerifierStatus,
    };
    use sumchain_state::inference_settlement_executor::InferenceSettlementExecutor;
    use sumchain_state::supply::v_assess_supply_correction;

    const ESCROW: u128 = 12_345;
    const BOND: u128 = 6_789;

    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let _state = Arc::new(StateManager::new(db.clone(), 1));
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    common::credit_committed(&db, &Address::new([0xE1; 20]), half);
    common::credit_committed(&db, &Address::new([0xE2; 20]), half);

    let mid = sumchain_primitives::supply::supply_correction_migration_id();

    // Baseline: an empty candidate over this parent.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let baseline = {
        let view = ExecutionView::new(&mut overlay);
        v_assess_supply_correction(&view, &db, 1, false, mid)
    };
    assert_eq!(
        baseline.reason,
        sumchain_primitives::supply::MigrationWithheldReason::NotWithheld,
        "the correction must apply on this parent, or the delta below is not \
         the thing under test"
    );
    drop(overlay);

    // The same parent, with a session opened EARLIER IN THE BLOCK holding
    // `ESCROW`. Economic supply rises by exactly that, so the delta falls by it.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let with_session = {
        let mut view = ExecutionView::new(&mut overlay);
        InferenceSettlementExecutor::v_put_session(
            &mut view,
            &InferenceSession {
                session_id: "opened-in-this-block".to_string(),
                funder: Address::new([0xF1; 20]),
                reward_per_verifier: 1,
                max_verifiers: 1,
                remaining_escrow: ESCROW,
                claims_count: 0,
                dispute_window_blocks: 1,
                status: InferenceSessionStatus::Open,
                created_at_height: 1,
                expires_at_height: 1000,
                consistency: None,
                bond_requirement: None,
            },
        )
        .unwrap();
        // ...and a verifier bond posted in the same block. Both buckets are
        // INCLUDE, and each total has its own reader — covering only one would
        // leave the other free to read committed state unnoticed.
        InferenceSettlementExecutor::v_put_verifier(
            &mut view,
            &InferenceVerifierRecord {
                verifier: Address::new([0xF2; 20]),
                bond: BOND,
                status: InferenceVerifierStatus::Active,
                registered_at_height: 1,
                unbonding_started_height: None,
                unlock_height: None,
            },
        )
        .unwrap();
        v_assess_supply_correction(&view, &db, 1, false, mid)
    };

    assert_eq!(
        with_session.economic_supply,
        baseline.economic_supply + ESCROW + BOND,
        "the escrow AND the bond staged in this block must both be counted"
    );
    assert_eq!(
        with_session.reserve_delta,
        baseline.reserve_delta - ESCROW - BOND,
        "the reserve delta must fall by exactly what the block created"
    );
    assert_eq!(
        with_session.reason,
        sumchain_primitives::supply::MigrationWithheldReason::NotWithheld
    );

    // And the committed census is unmoved: nothing was published.
    let committed = sumchain_state::supply::native_supply_snapshot(&db).unwrap();
    assert_eq!(committed.inference_escrow, 0);
    assert_eq!(committed.inference_verifier_bonds, 0);
    drop(overlay);

    // ── The production call, not just the reader ────────────────────────────
    //
    // Everything above exercises `v_assess_supply_correction` directly. That
    // proves the readers, and would keep passing if
    // `apply_supply_correction_if_needed` — the function a block actually runs
    // — were wired back to the committed `assess_supply_correction`. So drive
    // the real entry point and assert on what it STAGES.
    let expected_delta = baseline.reserve_delta - ESCROW - BOND;

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Same block: the session and bond are staged BEFORE the correction runs,
    // which is the production order — block-level effects run after the
    // transactions that moved those rows.
    InferenceSettlementExecutor::v_put_session(
        &mut view,
        &InferenceSession {
            session_id: "opened-in-this-block".to_string(),
            funder: Address::new([0xF1; 20]),
            reward_per_verifier: 1,
            max_verifiers: 1,
            remaining_escrow: ESCROW,
            claims_count: 0,
            dispute_window_blocks: 1,
            status: InferenceSessionStatus::Open,
            created_at_height: 1,
            expires_at_height: 1000,
            consistency: None,
            bond_requirement: None,
        },
    )
    .unwrap();
    InferenceSettlementExecutor::v_put_verifier(
        &mut view,
        &InferenceVerifierRecord {
            verifier: Address::new([0xF2; 20]),
            bond: BOND,
            status: InferenceVerifierStatus::Active,
            registered_at_height: 1,
            unbonding_started_height: None,
            unlock_height: None,
        },
    )
    .unwrap();

    let applied =
        sumchain_state::supply::apply_supply_correction_if_needed(&mut view, &db, 1, 8_900_000)
            .unwrap();
    assert!(applied, "the correction must apply on this parent");

    // Read the ledger and reserve back through the SAME view: they are staged,
    // not published, and the delta they carry must be the candidate-derived one.
    let ledger = SupplyStore::v_get_ledger(&view).unwrap();
    assert_eq!(
        ledger.total_minted_by_migration, expected_delta,
        "the staged ledger must record the delta measured against THIS block's \
         inference rows, not the parent's"
    );
    let reserve = SupplyStore::v_get_reserve(&view).unwrap().unwrap();
    assert_eq!(
        reserve.total_remaining(),
        expected_delta,
        "the staged reserve must hold exactly that delta"
    );
    assert!(ledger.migration_applied);
    assert_eq!(ledger.migration_activation_height, 8_900_000);

    // Nothing published: the correction is the block's to publish or abandon.
    drop(overlay);
    assert!(!SupplyStore::new(db.clone()).is_migration_applied().unwrap());
    assert!(SupplyStore::new(db.clone()).get_reserve().unwrap().is_none());
}
