//! Issue #41: Healthcare provider storage read helpers round-trip.
//!
//! Documents the STORE-level contract the RPC layer relies on: `ProviderStore`
//! is deliberately broad — `get` returns any provider type/status, and
//! `list_active` returns Active providers of any type. The institutional
//! allowlist gate lives in the RPC layer, not here.

use sumchain_primitives::healthcare::{
    HealthcareIssuerClass, ProviderProfile, ProviderStatus, ProviderType,
};
use sumchain_primitives::Address;
use sumchain_storage::{Database, ProviderStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn provider(id: u8, ptype: ProviderType, status: ProviderStatus) -> ProviderProfile {
    ProviderProfile {
        provider_id: [id; 32],
        provider_commitment: [2u8; 32],
        provider_type: ptype,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: None,
        credentials_commitment: None,
        policy_id: [5u8; 32],
        issuer_class: HealthcareIssuerClass::AccreditationBody,
        issuer_address: Address::new([0xE1; 20]),
        status,
        created_at: 1000,
        updated_at: 1000,
        registered_at_height: 5,
        network_affiliations: vec![],
        attachments: vec![],
    }
}

#[test]
fn provider_store_get_and_list_active_are_broad() {
    let (db, _dir) = temp_db();
    let store = ProviderStore::new(&db);

    // A mix of institutional and individual-clinician types / statuses.
    store.put(&provider(1, ProviderType::Hospital, ProviderStatus::Active)).unwrap();
    store.put(&provider(2, ProviderType::Physician, ProviderStatus::Active)).unwrap();
    store.put(&provider(3, ProviderType::Pharmacy, ProviderStatus::Suspended)).unwrap();

    // get() returns any provider type/status — the RPC layer filters, not the store.
    assert_eq!(store.get(&[1; 32]).unwrap().unwrap().provider_type, ProviderType::Hospital);
    assert_eq!(store.get(&[2; 32]).unwrap().unwrap().provider_type, ProviderType::Physician);
    assert!(store.get(&[0u8; 32]).unwrap().is_none());

    // list_active() returns Active providers of ANY type (Hospital + Physician),
    // excluding the Suspended one. Institutional filtering is not the store's job.
    let active = store.list_active().unwrap();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|p| p.status == ProviderStatus::Active));
}
