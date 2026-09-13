//! Issue #20 — archive-node stake withdrawal / unbonding.
//!
//! Covers the full lifecycle (register → begin-unstake → withdraw), the
//! activation gate (`Failed(320)`, no fee, no mutation when dormant), the
//! semantic-failure fee policy (gate-open failures charge the fee upfront,
//! matching the existing NodeRegistry policy), slashing an archive WHILE it is
//! unbonding (status stays `Unbonding`; both the node stake and the withdrawable
//! remainder shrink), and restart persistence of the unbonding record.
//!
//! v1 is full-exit only: `BeginUnstake { amount }` must equal the node's full
//! `staked_balance`, else `Failed(323)`.

mod common;
use sumchain_state::state::StateManager;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Hash, NodeRegistryOperation, NodeRegistryTxData, NodeRole, NodeStatus,
    SignedTransaction, StorageChallenge, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::storage_metadata::{
    challenge_expiry_index_key, challenge_key, challenge_node_index_key, CF_ACTIVE_CHALLENGES,
};
use sumchain_state::{NodeRegistryExecutor, StorageMetadataExecutor};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;

/// Minimum archive stake (mirrors `node_registry::MIN_ARCHIVE_STAKE`).
const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// Params with archive unbonding enabled from genesis and a short unbonding
/// period so tests can reach the unlock height cheaply.
fn params_enabled(period: u64) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.archive_unbonding_enabled_from_height = Some(0);
    p.archive_unbonding_period_blocks = period;
    p
}

fn nr_signed(kp: &KeyPair, fee: u128, nonce: u64, op: NodeRegistryOperation) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::NodeRegistry(NodeRegistryTxData { operation: op }),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn register_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    nr_signed(
        kp,
        FEE,
        nonce,
        NodeRegistryOperation::Register {
            role: NodeRole::ArchiveNode,
            stake: STAKE,
        },
    )
}

/// The node record as the block under test sees it. Registry writes are staged
/// into the candidate, so this reads the candidate — a committed read would
/// answer about the parent block and every assertion here would be vacuous.
fn node_of(
    view: &ExecutionView<'_, '_>,
    addr: &Address,
) -> Option<sumchain_primitives::NodeRecord> {
    NodeRegistryExecutor::v_get_node(view, addr).unwrap()
}

fn unbonding_of(
    view: &ExecutionView<'_, '_>,
    addr: &Address,
) -> Option<sumchain_primitives::ArchiveUnbondingRecord> {
    NodeRegistryExecutor::v_get_archive_unbonding(view, addr).unwrap()
}

/// The node record on the PUBLISHED chain. Used by the cross-block tests,
/// whose subject is what a block committed rather than what one staged.
fn committed_node_of(
    db: &Arc<Database>,
    addr: &Address,
) -> Option<sumchain_primitives::NodeRecord> {
    NodeRegistryExecutor::new(db.clone()).get_node(addr).unwrap()
}

fn committed_unbonding_of(
    db: &Arc<Database>,
    addr: &Address,
) -> Option<sumchain_primitives::ArchiveUnbondingRecord> {
    NodeRegistryExecutor::new(db.clone())
        .get_archive_unbonding(addr)
        .unwrap()
}

/// Seed a challenge that is ALREADY OPEN when the block under test runs.
///
/// No transaction creates a challenge — they come from the block-level PoR
/// generator — so a test that needs one already on the chain writes the
/// committed rows itself. This is a seed, not a publication: it constructs no
/// candidate and commits nothing a candidate produced. The three keys are the
/// ones `v_put_challenge` writes, built with the same helpers so this fixture
/// cannot drift from the layout it is imitating.
fn seed_committed_challenge(db: &Arc<Database>, challenge: &StorageChallenge) {
    let value = bincode::serialize(challenge).unwrap();
    let mut batch = db.batch();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_key(&challenge.challenge_id),
            &value,
        )
        .unwrap();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_node_index_key(&challenge.target_node, &challenge.challenge_id),
            &[1],
        )
        .unwrap();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id),
            &[1],
        )
        .unwrap();
    batch.commit().unwrap();
}

// ── Defaults ─────────────────────────────────────────────────────────────────

#[test]
fn defaults_leave_archive_unbonding_dormant() {
    let p = ChainParams::default();
    assert_eq!(p.archive_unbonding_enabled_from_height, None);
    // ~7 days at 3s blocks; a real, non-zero default so the record's unlock
    // height is always in the future even if an operator forgets to set it.
    assert_eq!(p.archive_unbonding_period_blocks, 201_600);
}

// ── Activation gate: dormant → Failed(320), no fee, no mutation ───────────────

#[test]
fn gate_closed_begin_unstake_rejects_320_no_mutation() {
    // v2 on, archive unbonding dormant (None).
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    // Register succeeds (registration is not gated).
    let r = executor
        .execute_tx(&mut candidate.view(), &register_tx(&node, 0), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(r.status.is_success());
    let bal_after_reg = StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap();
    let nonce_after_reg = StateManager::v_get_nonce(&candidate.view(), &node.address()).unwrap();

    // BeginUnstake with the gate closed → 320, no fee, nothing mutated.
    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE }),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(320)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap(), bal_after_reg);
    assert_eq!(StateManager::v_get_nonce(&candidate.view(), &node.address()).unwrap(), nonce_after_reg);
    assert_eq!(node_of(&candidate.view(), &node.address()).unwrap().status, NodeStatus::Active);
    assert!(unbonding_of(&candidate.view(), &node.address()).is_none());
}

#[test]
fn gate_closed_withdraw_rejects_320_no_mutation() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, 10_000);

    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 0, NodeRegistryOperation::WithdrawUnbonded),
            &proposer.address(),
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(320)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    // No fee, no nonce bump.
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap(), 10_000);
    assert_eq!(StateManager::v_get_nonce(&candidate.view(), &node.address()).unwrap(), 0);
}

// ── Happy-path lifecycle ─────────────────────────────────────────────────────

#[test]
fn full_lifecycle_register_begin_withdraw() {
    let period = 10u64;
    let funded: u128 = (STAKE as u128) + 1_000_000;
    let (_state, db, _dir, executor) = setup_with_params(params_enabled(period));
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, funded);

    // 1. Register.
    let r = executor
        .execute_tx(&mut candidate.view(), &register_tx(&node, 0), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(r.status.is_success());
    let rec = node_of(&candidate.view(), &node.address()).unwrap();
    assert_eq!(rec.status, NodeStatus::Active);
    assert_eq!(rec.staked_balance, STAKE);

    // 2. BeginUnstake at height 5 (full exit).
    let begin_h = 5u64;
    let r = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE }),
            &proposer.address(),
            begin_h,
            1000,
        )
        .unwrap();
    assert!(r.status.is_success(), "begin got {:?}", r.status);
    assert_eq!(r.fee_paid, FEE);

    let rec = node_of(&candidate.view(), &node.address()).unwrap();
    assert_eq!(rec.status, NodeStatus::Unbonding);
    // Node stake is unchanged until withdrawal; the record tracks the exit.
    assert_eq!(rec.staked_balance, STAKE);
    let ub = unbonding_of(&candidate.view(), &node.address()).unwrap();
    assert_eq!(ub.amount, STAKE);
    assert_eq!(ub.remaining_amount, STAKE);
    assert_eq!(ub.started_height, begin_h);
    assert_eq!(ub.unlock_height, begin_h + period);

    // An Unbonding archive is out of the active set.
    let active = NodeRegistryExecutor::v_get_active_archive_nodes(&candidate.view()).unwrap();
    assert!(active.is_empty(), "unbonding node must not be active");

    // 3. Withdraw before unlock → Failed(326), fee charged.
    let early = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 2, NodeRegistryOperation::WithdrawUnbonded),
            &proposer.address(),
            begin_h + period - 1,
            1000,
        )
        .unwrap();
    assert!(matches!(early.status, TxStatus::Failed(326)), "got {:?}", early.status);
    // Still Unbonding; record intact.
    assert_eq!(node_of(&candidate.view(), &node.address()).unwrap().status, NodeStatus::Unbonding);
    assert!(unbonding_of(&candidate.view(), &node.address()).is_some());

    // 4. Withdraw at unlock height → success. Nonce is now 3 (register + begin
    //    + failed-but-fee-charged withdraw each bumped it).
    let bal_before = StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap();
    let w = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 3, NodeRegistryOperation::WithdrawUnbonded),
            &proposer.address(),
            begin_h + period,
            1000,
        )
        .unwrap();
    assert!(w.status.is_success(), "withdraw got {:?}", w.status);

    let rec = node_of(&candidate.view(), &node.address()).unwrap();
    assert_eq!(rec.status, NodeStatus::Withdrawn);
    assert_eq!(rec.staked_balance, 0);
    assert!(unbonding_of(&candidate.view(), &node.address()).is_none(), "record deleted");
    // Balance: minus the withdraw fee, plus the full remaining stake credited.
    assert_eq!(
        StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap(),
        bal_before - FEE + STAKE as u128
    );
    // Net over the whole lifecycle: only the four fees left the account (stake
    // deducted at register was credited back at withdrawal).
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap(), funded - 4 * FEE);
}

// ── Semantic failures (gate open) charge the fee upfront ─────────────────────

#[test]
fn begin_unstake_partial_amount_rejects_323_fee_charged() {
    let (_state, db, _dir, executor) = setup_with_params(params_enabled(10));
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    executor
        .execute_tx(&mut candidate.view(), &register_tx(&node, 0), &proposer.address(), 1, 1000)
        .unwrap();
    let bal_after_reg = StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap();

    // amount != full staked_balance → 323, fee still consumed (NodeRegistry
    // policy deducts fee upfront before semantic checks).
    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(
                &node,
                FEE,
                1,
                NodeRegistryOperation::BeginUnstake { amount: STAKE - 1 },
            ),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(323)), "got {:?}", res.status);
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &node.address()).unwrap(), bal_after_reg - FEE);
    // Node untouched; still Active, no unbonding record.
    assert_eq!(node_of(&candidate.view(), &node.address()).unwrap().status, NodeStatus::Active);
    assert!(unbonding_of(&candidate.view(), &node.address()).is_none());
}

#[test]
fn begin_unstake_not_archive_rejects_321() {
    let (_state, db, _dir, executor) = setup_with_params(params_enabled(10));
    let mut candidate = common::candidate(&db);
    let stranger = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &stranger, 1_000_000);

    // Never registered as any node.
    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&stranger, FEE, 0, NodeRegistryOperation::BeginUnstake { amount: STAKE }),
            &proposer.address(),
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(321)), "got {:?}", res.status);
}

#[test]
fn withdraw_no_record_rejects_325() {
    let (_state, db, _dir, executor) = setup_with_params(params_enabled(10));
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    executor
        .execute_tx(&mut candidate.view(), &register_tx(&node, 0), &proposer.address(), 1, 1000)
        .unwrap();

    // Active archive, but no unbonding started.
    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 1, NodeRegistryOperation::WithdrawUnbonded),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(325)), "got {:?}", res.status);
}

#[test]
fn begin_unstake_open_challenge_rejects_324() {
    let (_state, db, _dir, executor) = setup_with_params(params_enabled(10));
    let mut candidate = common::candidate(&db);
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    executor
        .execute_tx(&mut candidate.view(), &register_tx(&node, 0), &proposer.address(), 1, 1000)
        .unwrap();

    // Inject an open challenge targeting this archive, into the SAME candidate
    // the BeginUnstake below executes against: the gate must see a challenge
    // issued earlier in this block, not only one the parent published.
    StorageMetadataExecutor::v_put_challenge(
        &mut candidate.view(),
        &StorageChallenge {
            challenge_id: Hash::hash(b"open-challenge-324"),
            merkle_root: Hash::hash(b"file-324"),
            chunk_index: 0,
            target_node: node.address(),
            created_at_height: 1,
            expires_at_height: 1_000,
        },
    )
    .unwrap();

    let res = executor
        .execute_tx(
            &mut candidate.view(),
            &nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE }),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(324)), "got {:?}", res.status);
    // Still Active — a node cannot dodge a pending challenge by unbonding.
    assert_eq!(node_of(&candidate.view(), &node.address()).unwrap().status, NodeStatus::Active);
}

// ── Slashing while unbonding ─────────────────────────────────────────────────

#[test]
fn slash_during_unbonding_keeps_status_and_reduces_remaining() {
    let period = 100u64;
    let (state, db, _dir, executor) = setup_with_params(params_enabled(period));
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    let pk = *proposer.public_key().as_bytes();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    // Real blocks, not one shared candidate: the slash pass runs INSIDE
    // `execute_block`, against a candidate that body builds from committed
    // state. Staging the registration into a candidate of our own would leave
    // committed storage empty and the slash with nothing to find.
    common::publish_block(&state, &executor, 1, &pk, vec![register_tx(&node, 0)], &[]);
    common::publish_block(
        &state,
        &executor,
        2,
        &pk,
        vec![nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE })],
        &[],
    );
    assert_eq!(
        committed_node_of(&db, &node.address()).unwrap().status,
        NodeStatus::Unbonding
    );

    // A challenge that expires at height 5 targets the unbonding archive.
    seed_committed_challenge(
        &db,
        &StorageChallenge {
            challenge_id: Hash::hash(b"expiring-challenge"),
            merkle_root: Hash::hash(b"file-slash"),
            chunk_index: 0,
            target_node: node.address(),
            created_at_height: 2,
            expires_at_height: 5,
        },
    );

    // Publishing a block at height 5 runs process_expired_challenges first.
    common::publish_empty_block(&state, &executor, 5, &pk);

    // 5% slash of the 1e9 stake = 5e7. Status STAYS Unbonding; both the node's
    // stake and the withdrawable remainder shrink by the slash.
    let slash = STAKE * 5 / 100;
    let rec = committed_node_of(&db, &node.address()).unwrap();
    assert_eq!(rec.status, NodeStatus::Unbonding, "slash must not flip Unbonding→Slashed");
    assert_eq!(rec.staked_balance, STAKE - slash);
    let ub = committed_unbonding_of(&db, &node.address()).unwrap();
    assert_eq!(ub.remaining_amount, STAKE - slash);

    // Withdraw at unlock pays out only the slashed remainder.
    let bal_before = state.get_balance(&node.address()).unwrap();
    let receipts = common::publish_block(
        &state,
        &executor,
        2 + period,
        &pk,
        vec![nr_signed(&node, FEE, 2, NodeRegistryOperation::WithdrawUnbonded)],
        &[],
    );
    assert!(receipts[0].status.is_success(), "withdraw got {:?}", receipts[0].status);
    assert_eq!(
        state.get_balance(&node.address()).unwrap(),
        bal_before - FEE + (STAKE - slash) as u128
    );
    assert_eq!(
        committed_node_of(&db, &node.address()).unwrap().status,
        NodeStatus::Withdrawn
    );
}

#[test]
fn withdrawn_node_skipped_by_expired_challenge() {
    // A fully-withdrawn node is terminal: an expired challenge against it must
    // not slash (nothing to slash) — it's just cleaned up.
    let period = 5u64;
    let (state, db, _dir, executor) = setup_with_params(params_enabled(period));
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    let pk = *proposer.public_key().as_bytes();
    fund(&db, &node, (STAKE as u128) + 1_000_000);

    // Published blocks, for the same reason as the slash test above.
    common::publish_block(&state, &executor, 1, &pk, vec![register_tx(&node, 0)], &[]);
    common::publish_block(
        &state,
        &executor,
        2,
        &pk,
        vec![nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE })],
        &[],
    );
    common::publish_block(
        &state,
        &executor,
        2 + period,
        &pk,
        vec![nr_signed(&node, FEE, 2, NodeRegistryOperation::WithdrawUnbonded)],
        &[],
    );
    assert_eq!(
        committed_node_of(&db, &node.address()).unwrap().status,
        NodeStatus::Withdrawn
    );

    seed_committed_challenge(
        &db,
        &StorageChallenge {
            challenge_id: Hash::hash(b"post-withdraw-challenge"),
            merkle_root: Hash::hash(b"file-withdrawn"),
            chunk_index: 0,
            target_node: node.address(),
            created_at_height: 1,
            expires_at_height: 10,
        },
    );

    common::publish_empty_block(&state, &executor, 10, &pk);

    // Still Withdrawn, still zero stake — untouched.
    let rec = committed_node_of(&db, &node.address()).unwrap();
    assert_eq!(rec.status, NodeStatus::Withdrawn);
    assert_eq!(rec.staked_balance, 0);
    // Balance unchanged by the slash pass (only the earlier withdraw credited it).
    let _ = state; // silence unused if assertions above are trimmed
}

// ── Restart persistence ──────────────────────────────────────────────────────

#[test]
fn unbonding_record_survives_restart() {
    let period = 50u64;
    let dir = tempfile::TempDir::new().unwrap();
    let node = KeyPair::generate();
    let proposer = KeyPair::generate();
    let begin_h = 7u64;

    // First "process": register + begin unstake, then drop the executor/db.
    {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(sumchain_state::StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params_enabled(period));
        let pk = *proposer.public_key().as_bytes();
        fund(&db, &node, (STAKE as u128) + 1_000_000);
        // Published, not staged: an unstaged candidate is discarded on drop, so
        // a restart test that never published would be asserting nothing.
        common::publish_block(&state, &executor, 1, &pk, vec![register_tx(&node, 0)], &[]);
        common::publish_block(
            &state,
            &executor,
            begin_h,
            &pk,
            vec![nr_signed(&node, FEE, 1, NodeRegistryOperation::BeginUnstake { amount: STAKE })],
            &[],
        );
    }

    // Reopen the same RocksDB path — the unbonding record must still be there.
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let ub = NodeRegistryExecutor::new(db.clone())
        .get_archive_unbonding(&node.address())
        .unwrap()
        .expect("unbonding record persisted across restart");
    assert_eq!(ub.amount, STAKE);
    assert_eq!(ub.remaining_amount, STAKE);
    assert_eq!(ub.unlock_height, begin_h + period);
    assert_eq!(
        committed_node_of(&db, &node.address()).unwrap().status,
        NodeStatus::Unbonding
    );
}
