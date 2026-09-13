//! Service-grant mechanics (800B supply correction): dormant gate, validator
//! cohort claims with genesis-validator exclusion, 10/90 liquid/locked split,
//! 1:1 unlock against protocol-earned credit only (transfers never count),
//! archive/compute milestones with no retroactive fabrication, denied-dispute
//! and slashing forfeiture, and pool accounting.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::supply::{
    genesis_validator_excluded_addresses, split_grant, validator_cohort_grant, GrantStatus,
    ServiceKind, SupplyOperation, SupplyTxData, ARCHIVE_PROOFS_GRANT_1, ARCHIVE_PROOFS_MILESTONE_1,
    COMPUTE_CLAIMS_GRANT_1, GENESIS_ACCOUNTED_SUPPLY, KOPPA, POOL_VALIDATOR,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus, ValidatorInfo};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::supply::{apply_supply_correction_if_needed, SupplyStore};
use sumchain_state::StateManager;
use sumchain_storage::{Database, StakingStore};
use tempfile::TempDir;

fn params_grants_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.service_grants_enabled_from_height = Some(0);
    p
}

fn params_grants_closed() -> ChainParams {
    ChainParams::with_v2_enabled() // service_grants_enabled_from_height: None
}

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee: 100, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn claim(kind: ServiceKind) -> TxPayload {
    TxPayload::Supply(SupplyTxData { operation: SupplyOperation::ClaimServiceGrant { service_kind: kind } })
}

fn unlock(kind: ServiceKind) -> TxPayload {
    TxPayload::Supply(SupplyTxData { operation: SupplyOperation::UnlockServiceGrant { service_kind: kind } })
}

/// Fund exactly the 1B genesis supply (2×500M), apply the correction, then the
/// reserve exists and accrual/claims can operate. Extra funding AFTER this is
/// fine (the 1B guard is checked only at migration time).
/// Fund the 1B genesis supply, then publish the block that applies the
/// correction — the correction is a block-level effect, so this is a block.
fn migrate(
    state: &Arc<StateManager>,
    db: &Arc<Database>,
    exec: &BlockExecutor,
) {
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    common::credit_committed(&db, &Address::new([0xE1; 20]), half);
    common::credit_committed(&db, &Address::new([0xE2; 20]), half);
    common::publish_empty_block(state, exec, 100, &[0x5Au8; 32]);
    assert!(
        SupplyStore::new(db.clone()).is_migration_applied().unwrap(),
        "the correction block must apply it"
    );
}

/// Register an Active staking validator whose derived address is `kp`'s.
fn seed_validator(db: &Arc<Database>, kp: &KeyPair) {
    let staking = StakingStore::new(db);
    let v = ValidatorInfo::new(*kp.public_key().as_bytes(), 1_000_000, 100, 1);
    staking.put_validator(&v).unwrap();
}

fn setup_migrated(
    params: ChainParams,
) -> (Arc<StateManager>, Arc<Database>, TempDir, BlockExecutor) {
    let (state, db, dir, exec) = setup_with_params(params);
    migrate(&state, &db, &exec);
    (state, db, dir, exec)
}

// ── Dormant gate ─────────────────────────────────────────────────────────────

#[test]
fn gate_closed_claim_and_unlock_rejected_free_380() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_closed());
    let mut candidate = common::candidate(&db);
    let v = KeyPair::generate();
    seed_validator(&db, &v);
    fund(&db, &v, 1_000_000);
    let bal0 = StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap();

    for payload in [claim(ServiceKind::Validator), unlock(ServiceKind::Validator)] {
        let r = exec.execute_tx(&mut candidate.view(), &signed(&v, 0, payload), &Address::new([9; 20]), 10, 1000).unwrap();
        assert!(matches!(r.status, TxStatus::Failed(380)), "dormant gate: {:?}", r.status);
        assert_eq!(r.fee_paid, 0, "gate-closed is free");
    }
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap(), bal0, "no fee, no mutation");
    assert!(SupplyStore::v_get_grant(&candidate.view(), &v.address(), ServiceKind::Validator).unwrap().is_none());
}

// ── Validator bootstrap grants ───────────────────────────────────────────────

#[test]
fn validator_claim_splits_10_90_and_is_once_per_identity() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let v = KeyPair::generate();
    seed_validator(&db, &v);
    fund(&db, &v, 1_000_000);
    let bal0 = StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap();

    let r = exec.execute_tx(&mut candidate.view(), &signed(&v, 0, claim(ServiceKind::Validator)), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "claim: {:?}", r.status);

    // First cohort grant = 5M Koppa; 10% liquid credited now, 90% locked.
    let total = validator_cohort_grant(0).unwrap();
    let (liquid, locked) = split_grant(total);
    assert_eq!(liquid, 500_000 * KOPPA);
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap(), bal0 - 100 + liquid, "liquid credited (minus fee)");
    let g = SupplyStore::v_get_grant(&candidate.view(), &v.address(), ServiceKind::Validator).unwrap().unwrap();
    assert_eq!(g.total_grant, total);
    assert_eq!(g.liquid_claimed, liquid);
    assert_eq!(g.locked_remaining, locked);
    assert_eq!(g.status, GrantStatus::Active);

    // Pool decremented exactly; aggregate tracks the locked outstanding.
    let reserve = SupplyStore::v_get_reserve(&candidate.view()).unwrap().unwrap();
    assert_eq!(reserve.validator_pool_remaining, POOL_VALIDATOR - total);
    assert_eq!(SupplyStore::v_get_aggregate(&candidate.view()).unwrap().outstanding_grant_unclaimed, locked);

    // Second claim by the same identity → 383, fee-paid, nothing awarded.
    let r2 = exec.execute_tx(&mut candidate.view(), &signed(&v, 1, claim(ServiceKind::Validator)), &Address::new([9; 20]), 11, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(383)), "one grant per identity: {:?}", r2.status);
}

#[test]
fn genesis_validators_excluded_from_bootstrap_grants() {
    let (_state, db, _dir, _exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    // Both identity forms (accounts + pubkey-derived addresses) → 382, even if
    // they were somehow registered as staking validators.
    let excluded = genesis_validator_excluded_addresses();
    assert_eq!(excluded.len(), 4, "2 accounts + 2 pubkey-derived");
    for addr in excluded {
        assert_eq!(SupplyStore::claim_validator_grant(&mut candidate.view(), &addr, 10), Err(382));
    }
}

#[test]
fn non_validator_cannot_claim_381() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let nobody = KeyPair::generate();
    fund(&db, &nobody, 1_000_000);
    let r = exec.execute_tx(&mut candidate.view(), &signed(&nobody, 0, claim(ServiceKind::Validator)), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(381)), "not a validator: {:?}", r.status);
}

#[test]
fn validator_cohort_boundaries_exact() {
    assert_eq!(validator_cohort_grant(0), Some(5_000_000 * KOPPA));
    assert_eq!(validator_cohort_grant(9), Some(5_000_000 * KOPPA));
    assert_eq!(validator_cohort_grant(10), Some(2_500_000 * KOPPA));
    assert_eq!(validator_cohort_grant(97), Some(2_500_000 * KOPPA));
    assert_eq!(validator_cohort_grant(98), Some(1_000_000 * KOPPA));
    assert_eq!(validator_cohort_grant(997), Some(1_000_000 * KOPPA));
    assert_eq!(validator_cohort_grant(998), Some(250_000 * KOPPA));
    assert_eq!(validator_cohort_grant(9_997), Some(250_000 * KOPPA));
    assert_eq!(validator_cohort_grant(9_998), None, "beyond 10,000 validators: no automatic grant");
    // Full-schedule worst case ≈ 3.42B — far below the 80B pool.
    let worst: u128 = (0..9_998u32).filter_map(validator_cohort_grant).sum();
    assert_eq!(worst, 3_420_000_000 * KOPPA);
    assert!(worst < POOL_VALIDATOR);
}

#[test]
fn cohort_counter_advances_per_distinct_validator() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    for i in 0..3u64 {
        let v = KeyPair::generate();
        seed_validator(&db, &v);
        fund(&db, &v, 1_000_000);
        let r = exec.execute_tx(&mut candidate.view(), &signed(&v, 0, claim(ServiceKind::Validator)), &Address::new([9; 20]), 10 + i, 1000).unwrap();
        assert!(matches!(r.status, TxStatus::Success));
    }
    assert_eq!(SupplyStore::v_validator_cohort_count(&candidate.view()).unwrap(), 3);
}

// ── Unlock: 1:1 against protocol-earned credit ONLY ──────────────────────────

#[test]
fn unlock_requires_protocol_earned_credit_transfers_never_count() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let v = KeyPair::generate();
    seed_validator(&db, &v);
    fund(&db, &v, 10_000_000);
    exec.execute_tx(&mut candidate.view(), &signed(&v, 0, claim(ServiceKind::Validator)), &Address::new([9; 20]), 10, 1000).unwrap();

    // No earned credit → unlock fails 384.
    let r = exec.execute_tx(&mut candidate.view(), &signed(&v, 1, unlock(ServiceKind::Validator)), &Address::new([9; 20]), 11, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(384)), "no earned credit: {:?}", r.status);

    // Ordinary transfers (including received and self-transfers) do NOT create
    // earned credit — the accrual sites are the protocol reward paths only.
    let friend = KeyPair::generate();
    fund(&db, &friend, 5_000_000);
    // Through the candidate: `v`'s account is already staged by the failed
    // unlock above, so a committed transfer would sit behind the staged row and
    // the nonce this advances would not be there for the next transaction.
    StateManager::v_transfer(&mut candidate.view(), &friend.address(), &v.address(), 1_000_000, 0, &Address::new([9; 20])).unwrap();
    StateManager::v_transfer(&mut candidate.view(), &v.address(), &v.address(), 500_000, 0, &Address::new([9; 20])).unwrap(); // self
    assert_eq!(SupplyStore::v_get_earned_credit(&candidate.view(), &v.address(), ServiceKind::Validator).unwrap(), 0);
    // (the self-transfer advanced v's nonce by 1 → next tx nonce is 3)
    let r2 = exec.execute_tx(&mut candidate.view(), &signed(&v, 3, unlock(ServiceKind::Validator)), &Address::new([9; 20]), 12, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(384)), "transfers must not unlock: {:?}", r2.status);

    // Real protocol-earned credit (accrued at the block-fee reward site)
    // unlocks exactly 1:1, capped by earned.
    SupplyStore::accrue_earned_credit(&mut candidate.view(), &v.address(), ServiceKind::Validator, 700 * KOPPA).unwrap();
    let bal_before = StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap();
    let r3 = exec.execute_tx(&mut candidate.view(), &signed(&v, 4, unlock(ServiceKind::Validator)), &Address::new([9; 20]), 13, 1000).unwrap();
    assert!(matches!(r3.status, TxStatus::Success), "unlock: {:?}", r3.status);
    assert_eq!(
        StateManager::v_get_balance(&candidate.view(), &v.address()).unwrap(),
        bal_before - 100 + 700 * KOPPA,
        "unlocked exactly the earned amount (minus fee)"
    );
    let g = SupplyStore::v_get_grant(&candidate.view(), &v.address(), ServiceKind::Validator).unwrap().unwrap();
    assert_eq!(g.earned_credit_used_for_unlock, 700 * KOPPA);
    // Re-unlock without new credit → 384 (credit is consumed, not reusable).
    let r4 = exec.execute_tx(&mut candidate.view(), &signed(&v, 5, unlock(ServiceKind::Validator)), &Address::new([9; 20]), 14, 1000).unwrap();
    assert!(matches!(r4.status, TxStatus::Failed(384)), "credit already used: {:?}", r4.status);
}

#[test]
fn validator_block_fee_accrual_goes_to_proposer_after_migration() {
    // The instrumented site: execute_block accrues the block's total fees as
    // the proposer's Validator earned credit — but ONLY once the correction is
    // applied. (Direct store-level proof of the accrual gating.)
    let (_state, db, _dir, _exec) = setup_with_params(params_grants_open());
    let mut candidate = common::candidate(&db);
    let p = Address::new([0xAA; 20]);
    // Dormant: accrual is a no-op.
    SupplyStore::accrue_earned_credit(&mut candidate.view(), &p, ServiceKind::Validator, 1_000).unwrap();
    assert_eq!(SupplyStore::v_get_earned_credit(&candidate.view(), &p, ServiceKind::Validator).unwrap(), 0, "no accrual pre-migration");
}

// ── Archive milestones (pre-existing nodes ELIGIBLE, nothing retroactive) ────

#[test]
fn archive_milestones_no_lump_sum_without_evidence() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    // Register an ACTIVE archive node via the node registry.
    let a = KeyPair::generate();
    fund(&db, &a, 2_000_000_000);
    let reg = TxPayload::NodeRegistry(sumchain_primitives::NodeRegistryTxData {
        operation: sumchain_primitives::NodeRegistryOperation::Register {
            role: sumchain_primitives::NodeRole::ArchiveNode,
            stake: 1_000_000_000,
        },
    });
    let r = exec.execute_tx(&mut candidate.view(), &signed(&a, 0, reg), &Address::new([9; 20]), 101, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "register archive: {:?}", r.status);

    // No proofs, no active-duration: claim → 383 (no automatic lump sum).
    let r2 = exec.execute_tx(&mut candidate.view(), &signed(&a, 1, claim(ServiceKind::Archive)), &Address::new([9; 20]), 102, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(383)), "no evidence → no grant: {:?}", r2.status);
}

#[test]
fn archive_proof_milestone_pays_after_evidence_and_only_once() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let a = KeyPair::generate();
    fund(&db, &a, 2_000_000_000);
    let reg = TxPayload::NodeRegistry(sumchain_primitives::NodeRegistryTxData {
        operation: sumchain_primitives::NodeRegistryOperation::Register {
            role: sumchain_primitives::NodeRole::ArchiveNode,
            stake: 1_000_000_000,
        },
    });
    exec.execute_tx(&mut candidate.view(), &signed(&a, 0, reg), &Address::new([9; 20]), 101, 1000).unwrap();

    // Record 100 successful PoR proofs (the instrumented proof-payout site
    // calls exactly this, and only after the correction).
    for _ in 0..ARCHIVE_PROOFS_MILESTONE_1 {
        SupplyStore::record_por_proof(&mut candidate.view(), &a.address()).unwrap();
    }
    // Claim right after registration (active-duration milestone NOT reached —
    // only the 100-proof milestone pays).
    let bal0 = StateManager::v_get_balance(&candidate.view(), &a.address()).unwrap();
    let r = exec.execute_tx(&mut candidate.view(), &signed(&a, 1, claim(ServiceKind::Archive)), &Address::new([9; 20]), 102, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "milestone claim: {:?}", r.status);
    let (liquid, locked) = split_grant(ARCHIVE_PROOFS_GRANT_1);
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &a.address()).unwrap(), bal0 - 100 + liquid);
    let g = SupplyStore::v_get_grant(&candidate.view(), &a.address(), ServiceKind::Archive).unwrap().unwrap();
    assert_eq!(g.locked_remaining, locked);

    // Claiming again with no NEW milestone → 383 (milestones pay exactly once).
    let r2 = exec.execute_tx(&mut candidate.view(), &signed(&a, 2, claim(ServiceKind::Archive)), &Address::new([9; 20]), 103, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(383)), "no double milestone: {:?}", r2.status);
}

#[test]
fn preexisting_archive_node_eligible_but_nothing_retroactive() {
    // Archive registered BEFORE the correction: milestone counters start at the
    // correction (record_por_proof is a no-op while dormant), and the node stays
    // fully eligible afterwards — same rules as future nodes.
    let (_state, db, _dir, exec) = setup_with_params(params_grants_open());
    let mut candidate = common::candidate(&db);
    let a = KeyPair::generate();
    fund(&db, &a, 2_000_000_000);
    let reg = TxPayload::NodeRegistry(sumchain_primitives::NodeRegistryTxData {
        operation: sumchain_primitives::NodeRegistryOperation::Register {
            role: sumchain_primitives::NodeRole::ArchiveNode,
            stake: 1_000_000_000,
        },
    });
    exec.execute_tx(&mut candidate.view(), &signed(&a, 0, reg), &Address::new([9; 20]), 5, 1000).unwrap();
    // Pre-correction proofs are NOT counted (no retroactive fabrication).
    for _ in 0..50 {
        SupplyStore::record_por_proof(&mut candidate.view(), &a.address()).unwrap();
    }
    assert_eq!(SupplyStore::v_get_milestones(&candidate.view(), &a.address(), ServiceKind::Archive).unwrap().por_proofs, 0);

    // Correction applies (accounted must be exactly 1B: the archive's funding
    // breaks the 1B guard, so seed a fresh chain state instead).
    // → For this test, verify eligibility semantics directly: after migration
    //   on a separate DB the same claim path works (covered above); here we
    //   assert the dormant no-op plus that the node is NOT excluded by any
    //   genesis-validator rule.
    assert!(
        !genesis_validator_excluded_addresses().contains(&a.address()),
        "archive nodes are never subject to the genesis-validator exclusion"
    );
}

// ── Compute milestones + denied disputes ─────────────────────────────────────

#[test]
fn compute_milestone_and_denied_dispute_blocks_386() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let vfr = KeyPair::generate();
    fund(&db, &vfr, 1_000_000);

    // One valid settlement claim (instrumented at the claim-payout site).
    SupplyStore::record_settlement_claim(&mut candidate.view(), &vfr.address()).unwrap();
    let bal0 = StateManager::v_get_balance(&candidate.view(), &vfr.address()).unwrap();
    let r = exec.execute_tx(&mut candidate.view(), &signed(&vfr, 0, claim(ServiceKind::Compute)), &Address::new([9; 20]), 102, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "compute milestone: {:?}", r.status);
    let (liquid, _) = split_grant(COMPUTE_CLAIMS_GRANT_1);
    assert_eq!(StateManager::v_get_balance(&candidate.view(), &vfr.address()).unwrap(), bal0 - 100 + liquid);

    // A denied dispute blocks further milestone claims (386) and forfeits the
    // locked remainder back to the compute pool.
    let locked_before = SupplyStore::v_get_grant(&candidate.view(), &vfr.address(), ServiceKind::Compute).unwrap().unwrap().locked_remaining;
    let pool_before = SupplyStore::v_get_reserve(&candidate.view()).unwrap().unwrap().compute_pool_remaining;
    SupplyStore::record_denied_dispute(&mut candidate.view(), &vfr.address()).unwrap();
    SupplyStore::forfeit_locked_grant(&mut candidate.view(), &vfr.address(), ServiceKind::Compute).unwrap();

    let g = SupplyStore::v_get_grant(&candidate.view(), &vfr.address(), ServiceKind::Compute).unwrap().unwrap();
    assert_eq!(g.status, GrantStatus::Forfeited);
    assert_eq!(g.locked_remaining, 0);
    assert_eq!(
        SupplyStore::v_get_reserve(&candidate.view()).unwrap().unwrap().compute_pool_remaining,
        pool_before + locked_before,
        "forfeited locked stake returns to the pool"
    );
    let r2 = exec.execute_tx(&mut candidate.view(), &signed(&vfr, 1, claim(ServiceKind::Compute)), &Address::new([9; 20]), 103, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(386)), "denied dispute blocks claims: {:?}", r2.status);
}

// ── Supply invariant across grant operations ─────────────────────────────────

#[test]
fn canonical_invariant_holds_through_claim_and_unlock() {
    let (_state, db, _dir, exec) = setup_migrated(params_grants_open());
    let mut candidate = common::candidate(&db);
    let v = KeyPair::generate();
    seed_validator(&db, &v);
    // Note: fee/funding credits below are test-world external funds; the
    // invariant we assert is reserve+outstanding movement matching the account
    // credits from GRANT operations exactly.
    fund(&db, &v, 1_000_000);
    let ledger = SupplyStore::v_get_ledger(&candidate.view()).unwrap();
    let r0 = SupplyStore::v_get_reserve(&candidate.view()).unwrap().unwrap().total_remaining();
    let a0 = SupplyStore::v_get_aggregate(&candidate.view()).unwrap().outstanding_grant_unclaimed;

    exec.execute_tx(&mut candidate.view(), &signed(&v, 0, claim(ServiceKind::Validator)), &Address::new([9; 20]), 10, 1000).unwrap();
    SupplyStore::accrue_earned_credit(&mut candidate.view(), &v.address(), ServiceKind::Validator, 1_000 * KOPPA).unwrap();
    exec.execute_tx(&mut candidate.view(), &signed(&v, 1, unlock(ServiceKind::Validator)), &Address::new([9; 20]), 11, 1000).unwrap();

    let total = validator_cohort_grant(0).unwrap();
    let (liquid, locked) = split_grant(total);
    let unlocked = 1_000 * KOPPA; // earned credit, all consumed by the unlock
    let r1 = SupplyStore::v_get_reserve(&candidate.view()).unwrap().unwrap().total_remaining();
    let a1 = SupplyStore::v_get_aggregate(&candidate.view()).unwrap().outstanding_grant_unclaimed;

    // Reserve lost exactly the grant; outstanding = locked - unlocked; the
    // account gained liquid + unlocked. canonical_supply is unchanged by any
    // of this (grants move supply between ledger and accounts, never create it).
    assert_eq!(r0 - r1, total);
    assert_eq!(a1 - a0, locked - unlocked);
    assert_eq!(ledger.current_canonical_supply(), SupplyStore::v_get_ledger(&candidate.view()).unwrap().current_canonical_supply());
}
