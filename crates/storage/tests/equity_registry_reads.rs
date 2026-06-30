//! Issue #26 (sub-issue 2): Equity registry storage read helpers round-trip.
//! Registry/admin records only (entities, share classes, controller config) —
//! no balances, holders, snapshots, proofs, governance, or events.

use sumchain_primitives::equity::{
    ControllerModel, EntityProfile, EntityStatus, EquityControllerConfig, EquityToken, OrgType,
    ShareClassType, TokenStatus,
};
use sumchain_primitives::Address;
use sumchain_storage::{Database, EntityProfileStore, EquityControllerStore, EquityTokenStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn entity(subject: [u8; 32], org: OrgType, controller: Address, status: EntityStatus) -> EntityProfile {
    EntityProfile {
        subject_id: subject,
        org_type: org,
        name_commitment: [1u8; 32],
        jurisdiction: Some("US-DE".to_string()),
        registration_commitment: None,
        controller_model: ControllerModel::SingleSigner,
        controllers: vec![controller],
        multisig_threshold: None,
        services: vec![],
        metadata_hash: [2u8; 32],
        created_at: 100,
        updated_at: 100,
        status,
    }
}

fn token(class_id: [u8; 32], issuer: [u8; 32]) -> EquityToken {
    EquityToken {
        issuer_subject: issuer,
        class_id,
        share_class_type: ShareClassType::Common,
        name: "Common".to_string(),
        symbol: "CMN".to_string(),
        authorized_shares: 1_000_000,
        issued_shares: 250_000,
        votes_per_share: 1,
        economic_rights_hash: [3u8; 32],
        liquidation_preference_hash: None,
        dividend_policy_hash: None,
        conversion_rules_hash: None,
        controller: Address::new([9u8; 20]),
        par_value: Some(1),
        created_at: 200,
        updated_at: 200,
        status: TokenStatus::Active,
    }
}

#[test]
fn entity_get_active_and_by_org_type() {
    let (db, _dir) = temp_db();
    let store = EntityProfileStore::new(&db);
    let ctrl = Address::new([0xC1; 20]);
    store.put(&entity([0xE1; 32], OrgType::Corporation, ctrl, EntityStatus::Active)).unwrap();
    store.put(&entity([0xE2; 32], OrgType::DAO, Address::new([0xC2; 20]), EntityStatus::Dissolved)).unwrap();

    assert_eq!(store.get(&[0xE1; 32]).unwrap().unwrap().org_type, OrgType::Corporation);
    assert!(store.get(&[0u8; 32]).unwrap().is_none());
    assert_eq!(store.list_active().unwrap().len(), 1); // only the Active one
    assert_eq!(store.list_by_org_type(OrgType::Corporation).unwrap().len(), 1);
    assert_eq!(store.list_by_org_type(OrgType::LLC).unwrap().len(), 0);
    assert_eq!(store.get_by_controller(&ctrl).unwrap().len(), 1);
}

#[test]
fn share_class_get_active_and_by_issuer() {
    let (db, _dir) = temp_db();
    let store = EquityTokenStore::new(&db);
    let issuer = [0xE1; 32];
    store.put(&token([0xA1; 32], issuer)).unwrap();
    store.put(&token([0xA2; 32], [0xEE; 32])).unwrap();

    assert_eq!(store.get(&[0xA1; 32]).unwrap().unwrap().symbol, "CMN");
    assert!(store.get(&[0u8; 32]).unwrap().is_none());
    assert_eq!(store.list_active().unwrap().len(), 2);
    assert_eq!(store.get_by_issuer(&issuer).unwrap().len(), 1);
}

#[test]
fn controller_config_get() {
    let (db, _dir) = temp_db();
    let store = EquityControllerStore::new(&db);
    let cfg = EquityControllerConfig {
        address: Address::new([7u8; 20]),
        whitelist_enabled: true,
        trading_windows: vec![],
        transfer_limit: 0,
        governance_policy_id: [4u8; 32],
        paused: false,
    };
    store.put(&[0xA1; 32], &cfg).unwrap();
    assert!(store.get(&[0xA1; 32]).unwrap().is_some());
    assert!(store.get(&[0u8; 32]).unwrap().is_none());
}
