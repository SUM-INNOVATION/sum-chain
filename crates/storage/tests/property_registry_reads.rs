//! Issue #26 (sub-issue): Property asset-anchor storage read helpers round-trip.
//! Asset anchors ONLY — no title events, encumbrances, coverage, claims,
//! proofs, system events, party identities, or off-chain content.

use sumchain_primitives::property::{AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass};
use sumchain_primitives::Address;
use sumchain_storage::{AssetStore, Database};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn asset(asset_id: [u8; 32], jurisdiction: &str, status: AssetStatus) -> AssetAnchor {
    AssetAnchor {
        asset_id,
        asset_commitment: [2u8; 32],
        asset_type: AssetType::Commercial,
        jurisdiction_code: jurisdiction.to_string(),
        public_reference: None,
        policy_id: [3u8; 32],
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: Address::new([0xE1; 20]),
        status,
        created_at: 1000,
        updated_at: 1000,
        anchored_at_height: 5,
        related_assets: vec![],
        attachments: vec![],
    }
}

#[test]
fn asset_get_active_by_jurisdiction() {
    let (db, _dir) = temp_db();
    let store = AssetStore::new(&db);

    store.put(&asset([0x01; 32], "US-CA-LA", AssetStatus::Active)).unwrap();
    store.put(&asset([0x02; 32], "US-CA-LA", AssetStatus::Deregistered)).unwrap();
    store.put(&asset([0x03; 32], "US-NY-NY", AssetStatus::Active)).unwrap();

    // get by id
    assert_eq!(store.get(&[0x01; 32]).unwrap().unwrap().jurisdiction_code, "US-CA-LA");
    assert!(store.get(&[0u8; 32]).unwrap().is_none());

    // active only (Deregistered filtered out)
    assert_eq!(store.list_active().unwrap().len(), 2);

    // by jurisdiction (index includes all statuses for that jurisdiction)
    assert_eq!(store.get_by_jurisdiction("US-CA-LA").unwrap().len(), 2);
    assert_eq!(store.get_by_jurisdiction("US-NY-NY").unwrap().len(), 1);
    assert_eq!(store.get_by_jurisdiction("US-TX-AU").unwrap().len(), 0);
}
