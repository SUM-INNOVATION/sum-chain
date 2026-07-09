//! One-time mainnet 800B supply correction (protocol-reserve model).
//!
//! Proves the consensus-critical invariants directly on the guarded entry point
//! `apply_supply_correction_if_needed`: applies once, replay/restart-safe, fails
//! closed on a bad pre-state, credits no account, and lands canonical supply at
//! 800B while account balances stay 1B (the 799B lives in the reserve ledger).

use std::sync::Arc;

use sumchain_primitives::supply::{
    ProtocolReserve, GENESIS_ACCOUNTED_SUPPLY, SUPPLY_CORRECTION_DELTA, TARGET_CANONICAL_SUPPLY,
};
use sumchain_primitives::Address;
use sumchain_state::supply::{
    accounted_account_supply, apply_supply_correction_if_needed, SupplyStore,
};
use sumchain_state::StateManager;
use sumchain_storage::Database;
use tempfile::TempDir;

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
fn withholds_when_pre_supply_is_not_1b() {
    // Chain-state guard: not-exactly-1B accounted supply WITHHOLDS the
    // correction (deterministic skip + loud error log) — the chain keeps
    // producing blocks, but the correction is never applied and nothing is
    // mutated. (In-binary config corruption — pool sum / migration id — is a
    // hard error instead; those constants are compile-time-tested.)
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    // Wrong pre-state: not exactly 1B.
    state.credit(&Address::new([1u8; 20]), GENESIS_ACCOUNTED_SUPPLY + 1).unwrap();

    let applied = apply_supply_correction_if_needed(&db, 1, 1).unwrap();
    assert!(!applied, "must withhold, never apply on a wrong pre-state");
    // Nothing applied, nothing mutated.
    assert!(!SupplyStore::new(db.clone()).is_migration_applied().unwrap());
    assert!(SupplyStore::new(db).get_reserve().unwrap().is_none());
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
