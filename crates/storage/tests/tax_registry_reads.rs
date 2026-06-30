//! Issue #26 (sub-issue 1): Tax registry storage read helpers round-trip.
//! Registry records only (claim types, issuers, policies) — no subject data.

use sumchain_primitives::tax::{
    ClaimTypeStatus, IssuerRequirements, QuorumRule, TaxClaimTypeEntry, TaxIssuer, TaxIssuerClass,
    TaxIssuerStatus, TaxPolicy, TaxPolicyTemplate, TaxRiskLevel,
};
use sumchain_primitives::Address;
use sumchain_storage::{Database, TaxClaimTypeStore, TaxIssuerStore, TaxPolicyStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn claim_type(id: &str) -> TaxClaimTypeEntry {
    TaxClaimTypeEntry {
        claim_type: id.to_string(),
        schema_hash: [1u8; 32],
        risk_level: TaxRiskLevel::Medium,
        recommended_validity_secs: 86_400,
        required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
        status: ClaimTypeStatus::Active,
        version: 1,
        created_at: 100,
        updated_at: 100,
    }
}

fn issuer(addr: Address, class: TaxIssuerClass, status: TaxIssuerStatus) -> TaxIssuer {
    TaxIssuer {
        address: addr,
        tax_class: class,
        jurisdictions: vec!["US".to_string()],
        attributes_hash: [2u8; 32],
        attributes_schema_hash: [3u8; 32],
        registered_at: 200,
        updated_at: 200,
        status,
        expires_at: None,
    }
}

fn policy(id: [u8; 32]) -> TaxPolicy {
    TaxPolicy {
        policy_id: id,
        template: TaxPolicyTemplate::Filed,
        claim_types: vec!["tax.filed.return".to_string()],
        issuer_requirements: IssuerRequirements {
            groups: vec![vec![TaxIssuerClass::AuditorCpa]],
            quorum: QuorumRule::Any,
        },
        jurisdictions: vec!["US".to_string()],
        tax_years: vec![2024],
        max_age_secs: 31_536_000,
        revocation_check: true,
        creator: Address::new([9u8; 20]),
        created_at: 300,
    }
}

#[test]
fn claim_type_get_and_list() {
    let (db, _dir) = temp_db();
    let store = TaxClaimTypeStore::new(&db);
    store.put(&claim_type("tax.filed.return")).unwrap();
    store.put(&claim_type("tax.paid.status")).unwrap();

    let got = store.get(&"tax.filed.return".to_string()).unwrap().unwrap();
    assert_eq!(got.version, 1);
    assert!(store.get(&"tax.unknown".to_string()).unwrap().is_none());
    assert_eq!(store.list_all().unwrap().len(), 2);
}

#[test]
fn issuer_get_active_and_by_class() {
    let (db, _dir) = temp_db();
    let store = TaxIssuerStore::new(&db);
    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xB2; 20]);
    store.put(&issuer(a, TaxIssuerClass::TaxAuthority, TaxIssuerStatus::Active)).unwrap();
    store.put(&issuer(b, TaxIssuerClass::BankBroker, TaxIssuerStatus::Revoked)).unwrap();

    assert_eq!(store.get(&a).unwrap().unwrap().tax_class, TaxIssuerClass::TaxAuthority);
    assert!(store.get(&Address::new([0xCC; 20])).unwrap().is_none());
    // Only the Active issuer is listed as active.
    let active = store.list_active().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].address, a);
    // Class filter.
    assert_eq!(store.list_by_class(TaxIssuerClass::TaxAuthority).unwrap().len(), 1);
    assert_eq!(store.list_by_class(TaxIssuerClass::AuditorCpa).unwrap().len(), 0);
}

#[test]
fn policy_get_and_list() {
    let (db, _dir) = temp_db();
    let store = TaxPolicyStore::new(&db);
    store.put(&policy([7u8; 32])).unwrap();
    store.put(&policy([8u8; 32])).unwrap();

    let got = store.get(&[7u8; 32]).unwrap().unwrap();
    assert_eq!(got.template, TaxPolicyTemplate::Filed);
    assert!(store.get(&[0u8; 32]).unwrap().is_none());
    assert_eq!(store.list_all().unwrap().len(), 2);
}
