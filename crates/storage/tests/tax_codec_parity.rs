//! Tax: the committed store's rows are exactly what the shared helpers build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_issuer(...)` proves nothing: the
//! store CALLS that helper, so a wrong helper moves both sides of the
//! assertion together. That exact hole was found by mutation in the messaging
//! preparation commit, where flipping `encode_u32` to little-endian passed
//! every test.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand. Both are what the
//! committed store produced BEFORE this commit extracted the helpers: the row
//! layout is the compatibility contract, and it must not move.
//!
//! ## Keys, spelled out
//!
//!     claim types    the claim-type STRING's bytes
//!     issuers        the 20-byte address
//!     policies       the 32-byte policy id
//!     proofs         the 32-byte proof id
//!     subject index  the 32-byte subject nullifier, value a bincode Vec<ProofId>
//!     disclosures    the 32-byte payload hash

use sumchain_primitives::tax::{
    ClaimTypeStatus, DisclosureContentType, IssuerRequirements, QuorumRule, TaxClaimTypeEntry,
    TaxDisclosureEnvelope, TaxIssuer, TaxIssuerClass, TaxIssuerStatus, TaxPolicy,
    TaxPolicyTemplate, TaxProofEnvelope, TaxProofType, TaxRiskLevel,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::tax_store::{decode_proof_ids, TaxStore};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

fn claim_type_entry() -> TaxClaimTypeEntry {
    TaxClaimTypeEntry {
        claim_type: "tax.filed.return".to_string(),
        schema_hash: [1u8; 32],
        risk_level: TaxRiskLevel::Low,
        recommended_validity_secs: 86_400,
        required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
        status: ClaimTypeStatus::Active,
        version: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn issuer() -> TaxIssuer {
    TaxIssuer {
        address: addr(3),
        tax_class: TaxIssuerClass::TaxAuthority,
        jurisdictions: vec!["US".to_string()],
        attributes_hash: [2u8; 32],
        attributes_schema_hash: [3u8; 32],
        registered_at: 1_000,
        updated_at: 2_000,
        status: TaxIssuerStatus::Active,
        expires_at: None,
    }
}

fn policy() -> TaxPolicy {
    TaxPolicy {
        policy_id: [4u8; 32],
        template: TaxPolicyTemplate::Filed,
        claim_types: vec!["tax.filed.return".to_string()],
        issuer_requirements: IssuerRequirements {
            groups: vec![vec![TaxIssuerClass::TaxAuthority]],
            quorum: QuorumRule::Any,
        },
        jurisdictions: vec!["US".to_string()],
        tax_years: vec![2026],
        max_age_secs: 3_600,
        revocation_check: true,
        creator: addr(3),
        created_at: 1_000,
    }
}

fn proof_envelope() -> TaxProofEnvelope {
    TaxProofEnvelope {
        proof_id: [5u8; 32],
        profile_id: "profile".to_string(),
        policy_ids: vec![[4u8; 32]],
        claim_ids: vec![],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![9, 9],
        proof_type: TaxProofType::Groth16,
        subject_nullifier: [6u8; 32],
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

fn disclosure() -> TaxDisclosureEnvelope {
    TaxDisclosureEnvelope {
        payload_hash: [7u8; 32],
        payload_size: 42,
        hint_uri: Some("ipfs://x".to_string()),
        encryption_meta: None,
        content_type: DisclosureContentType::TaxReturn,
        claim_id: None,
        proof_id: Some([5u8; 32]),
        created_at: 1_000,
    }
}

#[test]
fn a_claim_type_row_is_bincode_at_the_claim_type_string_key() {
    let (db, _dir) = db();
    let entry = claim_type_entry();
    TaxStore::new(&db).claim_types().put(&entry).unwrap();

    assert_eq!(
        row(&db, cf::TAX_CLAIM_TYPES, b"tax.filed.return"),
        Some(bincode::serialize(&entry).unwrap()),
        "the key is the claim-type string's bytes, the value plain bincode"
    );
}

#[test]
fn an_issuer_row_is_bincode_at_the_address_key() {
    let (db, _dir) = db();
    let i = issuer();
    TaxStore::new(&db).issuers().put(&i).unwrap();

    assert_eq!(
        row(&db, cf::TAX_ISSUERS, &[3u8; 20]),
        Some(bincode::serialize(&i).unwrap())
    );
}

#[test]
fn a_policy_row_is_bincode_at_the_policy_id_key() {
    let (db, _dir) = db();
    let p = policy();
    TaxStore::new(&db).policies().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::TAX_POLICIES, &[4u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_indexes_its_subject() {
    let (db, _dir) = db();
    let p = proof_envelope();
    TaxStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::TAX_PROOFS, &[5u8; 32]),
        Some(bincode::serialize(&p).unwrap()),
        "the proof, at its id"
    );
    // The index VALUE is a bincode Vec<ProofId>, not a presence marker: it
    // accumulates, which is why appending is a read-modify-write.
    assert_eq!(
        row(&db, cf::TAX_SUBJECT_INDEX, &[6u8; 32]),
        Some(bincode::serialize(&vec![[5u8; 32]]).unwrap()),
        "and a one-element list at the subject nullifier"
    );
}

#[test]
fn a_second_proof_for_one_subject_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = TaxStore::new(&db);
    let first = proof_envelope();
    let mut second = proof_envelope();
    second.proof_id = [8u8; 32];

    store.proofs().put(&first).unwrap();
    store.proofs().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::TAX_SUBJECT_INDEX, &[6u8; 32]),
        Some(bincode::serialize(&vec![[5u8; 32], [8u8; 32]]).unwrap()),
        "both ids, in insertion order"
    );
    assert_eq!(
        decode_proof_ids(&row(&db, cf::TAX_SUBJECT_INDEX, &[6u8; 32]).unwrap()).unwrap(),
        vec![[5u8; 32], [8u8; 32]]
    );
}

#[test]
fn a_disclosure_row_is_bincode_at_the_payload_hash_key() {
    let (db, _dir) = db();
    let d = disclosure();
    TaxStore::new(&db).disclosures().put(&d).unwrap();

    assert_eq!(
        row(&db, cf::TAX_DISCLOSURES, &[7u8; 32]),
        Some(bincode::serialize(&d).unwrap())
    );
}

#[test]
fn malformed_bytes_are_refused_by_every_tax_decoder() {
    use sumchain_storage::tax_store::{
        decode_claim_type, decode_disclosure, decode_issuer, decode_policy, decode_proof,
    };
    let junk = b"not a row";
    assert!(decode_claim_type(junk).is_err());
    assert!(decode_issuer(junk).is_err());
    assert!(decode_policy(junk).is_err());
    assert!(decode_proof(junk).is_err());
    assert!(decode_proof_ids(junk).is_err());
    assert!(
        decode_disclosure(junk).is_err(),
        "including disclosures, which execution does not read but the RPC does"
    );
}
