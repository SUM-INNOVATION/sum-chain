//! Issue #26 (sub-issue): Finance issuer-registry storage read helpers
//! round-trip. Institution issuer profiles ONLY — no address proofs,
//! bank-standing credentials, KYC attestations, proofs, events, or any
//! subject/holder records.

use sumchain_primitives::finance::{FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus};
use sumchain_primitives::Address;
use sumchain_storage::{Database, FinanceIssuerStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn issuer(addr: Address, jurisdiction: &str, status: FinanceIssuerStatus) -> FinanceIssuerProfile {
    FinanceIssuerProfile {
        issuer_address: addr,
        issuer_class: FinanceIssuerClass::RegulatedBank,
        issuer_commitment: [2u8; 32],
        jurisdiction_code: jurisdiction.to_string(),
        policy_id: [3u8; 32],
        status,
        registered_at_height: 5,
        created_at: 1000,
        updated_at: 1000,
    }
}

#[test]
fn issuer_get_active_by_jurisdiction() {
    let (db, _dir) = temp_db();
    let store = FinanceIssuerStore::new(&db);
    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xB2; 20]);
    let c = Address::new([0xC3; 20]);

    store.put(&issuer(a, "US", FinanceIssuerStatus::Active)).unwrap();
    store.put(&issuer(b, "US", FinanceIssuerStatus::Revoked)).unwrap();
    store.put(&issuer(c, "GB", FinanceIssuerStatus::Active)).unwrap();

    // get by address
    assert_eq!(store.get(&a).unwrap().unwrap().jurisdiction_code, "US");
    assert!(store.get(&Address::new([0u8; 20])).unwrap().is_none());

    // active only (Revoked filtered out)
    assert_eq!(store.list_active().unwrap().len(), 2);

    // by jurisdiction (index includes all statuses for that jurisdiction)
    assert_eq!(store.get_by_jurisdiction("US").unwrap().len(), 2);
    assert_eq!(store.get_by_jurisdiction("GB").unwrap().len(), 1);
    assert_eq!(store.get_by_jurisdiction("FR").unwrap().len(), 0);
}
