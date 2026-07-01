//! Issue #26 (sub-issue): Legal case-anchor storage read helpers round-trip.
//! Case/docket anchors ONLY. This test documents the STORE-level contract that
//! the RPC layer relies on for sealed-case exclusion:
//!   - `list_active()` returns Filed/Active and never Sealed.
//!   - `get()` returns ANY status incl. Sealed (RPC layer filters it).
//!   - `get_by_jurisdiction()` returns all statuses incl. Sealed (RPC filters).

use sumchain_primitives::legal::{CaseAnchor, CaseStatus, CaseType, LegalIssuerClass};
use sumchain_primitives::Address;
use sumchain_storage::{CaseStore, Database};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn case(case_id: [u8; 32], jurisdiction: &str, status: CaseStatus) -> CaseAnchor {
    CaseAnchor {
        case_id,
        case_commitment: [2u8; 32],
        jurisdiction_code: jurisdiction.to_string(),
        case_type: Some(CaseType::Civil),
        public_reference: None,
        policy_id: [3u8; 32],
        issuer_class: LegalIssuerClass::CourtSystem,
        issuer_address: Address::new([0xE1; 20]),
        status,
        created_at: 1000,
        updated_at: 1000,
        anchored_at_height: 5,
        related_cases: vec![],
    }
}

#[test]
fn case_get_active_by_jurisdiction_store_contract() {
    let (db, _dir) = temp_db();
    let store = CaseStore::new(&db);

    store.put(&case([0x01; 32], "US-NY", CaseStatus::Active)).unwrap();
    store.put(&case([0x02; 32], "US-NY", CaseStatus::Filed)).unwrap();
    store.put(&case([0x03; 32], "US-NY", CaseStatus::Closed)).unwrap();
    store.put(&case([0x04; 32], "US-NY", CaseStatus::Sealed)).unwrap();

    // get() returns ANY status, including Sealed — the RPC layer is responsible
    // for filtering sealed cases, not the store.
    assert_eq!(store.get(&[0x04; 32]).unwrap().unwrap().status, CaseStatus::Sealed);
    assert!(store.get(&[0u8; 32]).unwrap().is_none());

    // list_active() = Filed + Active; never Sealed, never Closed.
    let active = store.list_active().unwrap();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|c| c.status == CaseStatus::Active || c.status == CaseStatus::Filed));

    // get_by_jurisdiction() returns all statuses incl. Sealed (index-based).
    let ny = store.get_by_jurisdiction("US-NY").unwrap();
    assert_eq!(ny.len(), 4);
    assert!(ny.iter().any(|c| c.status == CaseStatus::Sealed));
    assert_eq!(store.get_by_jurisdiction("US-TX").unwrap().len(), 0);
}
