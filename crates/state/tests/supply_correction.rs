//! One-time mainnet 800B supply correction (protocol-reserve model).
//!
//! Proves the consensus-critical invariants directly on the guarded entry point
//! `apply_supply_correction_if_needed`: applies once, replay/restart-safe, fails
//! closed on a bad pre-state, credits no account, and lands canonical supply at
//! 800B while account balances stay 1B (the 799B lives in the reserve ledger).

use std::sync::Arc;

use sumchain_primitives::staking::DelegationInfo;
use sumchain_primitives::supply::{
    MigrationWithheldReason, ProtocolReserve, FIXED_SERVICE_POOLS, GENESIS_ACCOUNTED_SUPPLY, KOPPA,
    SUPPLY_CORRECTION_DELTA, TARGET_CANONICAL_SUPPLY,
};
use sumchain_primitives::Address;
use sumchain_state::supply::{
    accounted_account_supply, apply_supply_correction_if_needed, assess_supply_correction,
    native_supply_snapshot, SupplyStore,
};
use sumchain_state::StateManager;
use sumchain_storage::{Database, DelegationStore};
use tempfile::TempDir;

/// The live mainnet shortfall: accounted account balances are short of the 1B
/// genesis supply by exactly 1,003 Koppa, which lives in non-account ledgers.
const MAINNET_SHORTFALL: u128 = 1_003 * KOPPA;

/// Fresh db + state on the mainnet chain (id 1), pre-funded so accounted supply
/// == exactly 1B (two accounts of 500M, mirroring the two genesis validators).
fn mainnet_1b() -> (Arc<Database>, Arc<StateManager>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    state.credit(&Address::new([1u8; 20]), half).unwrap();
    state.credit(&Address::new([2u8; 20]), half).unwrap();
    (db, state, dir)
}

#[test]
fn migration_applies_once_and_lands_800b_with_accounts_unchanged() {
    let (db, _state, _dir) = mainnet_1b();
    let store = SupplyStore::new(db.clone());

    // Pre: dormant, canonical == accounted == 1B, no reserve.
    assert!(!store.is_migration_applied().unwrap());
    assert_eq!(accounted_account_supply(&db).unwrap(), GENESIS_ACCOUNTED_SUPPLY);
    assert!(store.get_reserve().unwrap().is_none());

    let applied = apply_supply_correction_if_needed(&db, 1, 8_900_000).unwrap();
    assert!(applied, "correction applies on first eligible block");

    // Canonical supply is now 800B; the 799B delta is in the reserve ledger.
    let ledger = store.get_ledger().unwrap();
    assert!(ledger.migration_applied);
    assert_eq!(ledger.initial_canonical_supply, TARGET_CANONICAL_SUPPLY);
    assert_eq!(ledger.total_minted_by_migration, SUPPLY_CORRECTION_DELTA);
    assert_eq!(ledger.total_minted_by_governance, 0);
    assert_eq!(ledger.current_canonical_supply(), TARGET_CANONICAL_SUPPLY);
    assert_eq!(ledger.migration_activation_height, 8_900_000);

    let reserve = store.get_reserve().unwrap().expect("reserve initialized");
    assert_eq!(reserve.total_remaining(), SUPPLY_CORRECTION_DELTA);
    assert_eq!(reserve, ProtocolReserve::initial());

    // CRITICAL: no account was credited — accounted balances remain exactly 1B.
    assert_eq!(
        accounted_account_supply(&db).unwrap(),
        GENESIS_ACCOUNTED_SUPPLY,
        "reserve is a ledger, not an account; balances must stay 1B"
    );
    // The reserve is NOT an account balance.
    assert_eq!(_state.get_balance(&Address::ZERO).unwrap(), 0, "Address::ZERO untouched");

    // Idempotent / replay-safe: a second call is a no-op and mutates nothing.
    let again = apply_supply_correction_if_needed(&db, 1, 8_900_001).unwrap();
    assert!(!again, "marker prevents re-application");
    let ledger2 = store.get_ledger().unwrap();
    assert_eq!(ledger2.migration_activation_height, 8_900_000, "height not overwritten");
    assert_eq!(store.get_reserve().unwrap().unwrap().total_remaining(), SUPPLY_CORRECTION_DELTA);
}

#[test]
fn canonical_equals_accounts_plus_reserve_invariant() {
    let (db, _state, _dir) = mainnet_1b();
    apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    let store = SupplyStore::new(db.clone());
    let accounts = accounted_account_supply(&db).unwrap();
    let reserve = store.get_reserve().unwrap().unwrap().total_remaining();
    // canonical = accounts + reserve (+ outstanding grants = 0 at this stage).
    assert_eq!(accounts + reserve, store.get_ledger().unwrap().current_canonical_supply());
    assert_eq!(accounts + reserve, TARGET_CANONICAL_SUPPLY);
}

#[test]
fn applies_when_shortfall_is_held_in_an_included_ledger() {
    // LIVE MAINNET SHAPE (the bug this fix targets): accounted balances are
    // 999,998,997 Koppa — short of 1B by 1,003 Koppa — because that Koppa was
    // deducted out of accounts into a non-account INCLUDE ledger (here, an
    // active delegation). The census measures economic supply == exactly 1B, so
    // the correction APPLIES (the old exact-1B-accounts guard wrongly withheld
    // it) and the reserve delta is the full 799B.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    // Accounts hold 1B − 1,003 Koppa (mirrors live accounted_account_supply).
    state
        .credit(&Address::new([1u8; 20]), GENESIS_ACCOUNTED_SUPPLY - MAINNET_SHORTFALL)
        .unwrap();
    // The missing 1,003 Koppa sits in an active delegation (an INCLUDE bucket).
    DelegationStore::new(&db)
        .put_delegation(&DelegationInfo::new([7u8; 32], [9u8; 32], MAINNET_SHORTFALL, 0))
        .unwrap();

    // Accounted < 1B, but the census measures economic == exactly 1B.
    assert_eq!(
        accounted_account_supply(&db).unwrap(),
        GENESIS_ACCOUNTED_SUPPLY - MAINNET_SHORTFALL
    );
    let snap = native_supply_snapshot(&db).unwrap();
    assert_eq!(snap.active_delegations, MAINNET_SHORTFALL);
    assert_eq!(snap.economic_supply().unwrap(), GENESIS_ACCOUNTED_SUPPLY);

    let applied = apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    assert!(applied, "measured economic supply == 1B → correction applies");

    let store = SupplyStore::new(db.clone());
    let ledger = store.get_ledger().unwrap();
    assert_eq!(
        ledger.total_minted_by_migration, SUPPLY_CORRECTION_DELTA,
        "delta = 799B, derived from economic supply not hardcoded"
    );
    assert_eq!(ledger.current_canonical_supply(), TARGET_CANONICAL_SUPPLY);
    // Delta was exactly 799B, so the split is the canonical initial split.
    let reserve = store.get_reserve().unwrap().unwrap();
    assert_eq!(reserve, ProtocolReserve::initial());
    // TRUE conservation identity: economic (accounts + buckets) + reserve == 800B.
    let econ = native_supply_snapshot(&db).unwrap().economic_supply().unwrap();
    assert_eq!(econ + reserve.total_remaining(), TARGET_CANONICAL_SUPPLY);
}

#[test]
fn applies_and_restores_a_truly_leaked_shortfall_via_a_larger_reserve() {
    // The OTHER shape: the 1,003 Koppa is not in any counted ledger — it was
    // destroyed by a sink (e.g. the V2 abandon-retain leak). Economic supply is
    // then genuinely 1B − 1,003. The correction still lands canonical at 800B by
    // minting a LARGER reserve delta (799B + 1,003), restoring the leaked value
    // into the governance reserve. No account is credited.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    state
        .credit(&Address::new([1u8; 20]), GENESIS_ACCOUNTED_SUPPLY - MAINNET_SHORTFALL)
        .unwrap();
    // No bucket holds the shortfall → economic < 1B.
    let econ_before = native_supply_snapshot(&db).unwrap().economic_supply().unwrap();
    assert_eq!(econ_before, GENESIS_ACCOUNTED_SUPPLY - MAINNET_SHORTFALL);

    assert!(apply_supply_correction_if_needed(&db, 1, 1).unwrap(), "still applies");

    let store = SupplyStore::new(db.clone());
    let ledger = store.get_ledger().unwrap();
    // Reserve delta absorbs the leak: 799B + 1,003 Koppa.
    assert_eq!(
        ledger.total_minted_by_migration,
        SUPPLY_CORRECTION_DELTA + MAINNET_SHORTFALL,
        "reserve delta increases by exactly the leaked amount"
    );
    // Canonical still lands at 800B.
    assert_eq!(ledger.current_canonical_supply(), TARGET_CANONICAL_SUPPLY);
    // The restored leak lands entirely in the long-term governance reserve; the
    // fixed service pools keep their spec'd sizes.
    let reserve = store.get_reserve().unwrap().unwrap();
    assert_eq!(
        reserve.governance_reserve_remaining,
        (SUPPLY_CORRECTION_DELTA + MAINNET_SHORTFALL) - FIXED_SERVICE_POOLS
    );
    assert_eq!(
        reserve,
        ProtocolReserve::from_reserve_delta(SUPPLY_CORRECTION_DELTA + MAINNET_SHORTFALL).unwrap()
    );
    // canonical identity holds here too (no buckets ⇒ accounts == economic).
    let accounts = accounted_account_supply(&db).unwrap();
    assert_eq!(accounts + reserve.total_remaining(), TARGET_CANONICAL_SUPPLY);
}

#[test]
fn withholds_when_economic_supply_is_zero() {
    // Empty ledgers → economic supply 0 → fail closed (never mint 800B out of
    // nothing). Deterministic skip, nothing mutated.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let _state = Arc::new(StateManager::new(db.clone(), 1));

    let applied = apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    assert!(!applied, "must withhold on zero economic supply");
    assert!(!SupplyStore::new(db.clone()).is_migration_applied().unwrap());
    assert!(SupplyStore::new(db.clone()).get_reserve().unwrap().is_none());
    let a = assess_supply_correction(&db, 1, false, sumchain_primitives::supply::supply_correction_migration_id());
    assert_eq!(a.reason, MigrationWithheldReason::EconomicSupplyZero);
    assert_eq!(a.reserve_delta, 0);
}

#[test]
fn withholds_when_economic_supply_exceeds_target() {
    // Economic supply above the 800B target → fail closed (a negative delta must
    // never be minted). Nothing mutated.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    state.credit(&Address::new([1u8; 20]), TARGET_CANONICAL_SUPPLY + KOPPA).unwrap();

    let applied = apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    assert!(!applied, "must withhold when economic supply exceeds target");
    assert!(!SupplyStore::new(db.clone()).is_migration_applied().unwrap());
    let a = assess_supply_correction(&db, 1, false, sumchain_primitives::supply::supply_correction_migration_id());
    assert_eq!(a.reason, MigrationWithheldReason::EconomicSupplyOverTarget);
}

#[test]
fn assess_reports_precise_reasons() {
    let mid = sumchain_primitives::supply::supply_correction_migration_id();
    // Would-apply (mainnet, pre-migration, economic == 1B).
    let (db, _state, _dir) = mainnet_1b();
    let a = assess_supply_correction(&db, 1, false, mid);
    assert_eq!(a.reason, MigrationWithheldReason::NotWithheld);
    assert_eq!(a.economic_supply, GENESIS_ACCOUNTED_SUPPLY);
    assert_eq!(a.reserve_delta, SUPPLY_CORRECTION_DELTA);
    // Non-mainnet.
    assert_eq!(
        assess_supply_correction(&db, 1337, false, mid).reason,
        MigrationWithheldReason::WrongChainId
    );
    // Already applied.
    apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    let a2 = assess_supply_correction(&db, 1, true, mid);
    assert_eq!(a2.reason, MigrationWithheldReason::AlreadyApplied);
    assert_eq!(a2.reserve_delta, 0);
}

#[test]
fn skips_on_non_mainnet_chain() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1337));
    state.credit(&Address::new([1u8; 20]), GENESIS_ACCOUNTED_SUPPLY).unwrap();

    // chain_id 1337 ≠ mainnet → not applicable, no error, no mutation.
    let applied = apply_supply_correction_if_needed(&db, 1337, 1).unwrap();
    assert!(!applied);
    assert!(!SupplyStore::new(db).is_migration_applied().unwrap());
}

#[test]
fn state_digest_none_while_dormant_some_after() {
    let (db, _state, _dir) = mainnet_1b();
    let store = SupplyStore::new(db.clone());
    assert!(store.state_digest().unwrap().is_none(), "no fold before correction");
    apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    assert!(store.state_digest().unwrap().is_some(), "folded after correction");
}

#[test]
fn restart_replay_preserves_marker_and_digest() {
    // Apply on one DB handle, then REOPEN the same directory (a node restart):
    // the marker survives, the correction does not rerun, and the state digest
    // is byte-identical (replay-safe fold into the block state root).
    let dir = TempDir::new().unwrap();
    let digest_before;
    {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let half = GENESIS_ACCOUNTED_SUPPLY / 2;
        state.credit(&Address::new([1u8; 20]), half).unwrap();
        state.credit(&Address::new([2u8; 20]), half).unwrap();
        assert!(apply_supply_correction_if_needed(&db, 1, 8_900_000).unwrap());
        digest_before = SupplyStore::new(db.clone()).state_digest().unwrap().unwrap();
    } // drop → close the DB
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let store = SupplyStore::new(db.clone());
    assert!(store.is_migration_applied().unwrap(), "marker survives restart");
    assert!(!apply_supply_correction_if_needed(&db, 1, 8_900_001).unwrap(), "no rerun after restart");
    assert_eq!(
        store.state_digest().unwrap().unwrap(),
        digest_before,
        "state digest identical across restart/replay"
    );
    assert_eq!(store.get_ledger().unwrap().migration_activation_height, 8_900_000);
}
