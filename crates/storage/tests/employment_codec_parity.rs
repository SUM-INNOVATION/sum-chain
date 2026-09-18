//! Employment: the committed store's rows are exactly what the shared helpers
//! build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_issuer(...)` proves nothing: the
//! store CALLS that helper, so a wrong helper moves both sides of the
//! assertion together. The same hole exists for keys — asserting against
//! `issuer_key(..)` would pass for any key builder at all, including one that
//! returned the wrong field.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand. Both are what the
//! committed store produced BEFORE this commit extracted the helpers: the row
//! layout is the compatibility contract, and it must not move.
//!
//! Three families are keyed by a 20-byte ADDRESS and five hold the same
//! `Vec<[u8; 32]>` value, so a builder or codec pointed at the wrong one of
//! them would still type-check. Every family is therefore asserted separately,
//! with a DISTINCT byte pattern per field, so a swap cannot be absorbed.
//!
//! ## Keys, spelled out
//!
//!     issuers                 the issuer's 20-byte address
//!     credentials             the 32-byte employment id
//!     employee index          the 32-byte employee_ref commitment
//!     employee-address index  the employee's 20-byte WALLET address
//!     employer index          the 32-byte employer_ref commitment
//!     income attestations     the 32-byte attestation id
//!     subject income index    the 32-byte subject_ref commitment
//!     holder-address index    the holder's 20-byte WALLET address
//!     proofs                  the 32-byte proof id
//!     events                  height (8) || index (4), both big-endian
//!
//! Every index VALUE is a bincode `Vec<[u8; 32]>` — an accumulating list, not
//! a presence marker, which is why appending is a read-modify-write.

use sumchain_primitives::employment::{
    EmploymentCredential, EmploymentEvent, EmploymentIssuerClass, EmploymentIssuerProfile,
    EmploymentProofEnvelope, EmploymentProofType, EmploymentStatus, EmploymentType,
    IncomeAttestation, IncomeBracket, IncomePeriod, IssuerStatus,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::employment_store::{
    decode_attestation, decode_credential, decode_event, decode_id_list, decode_issuer,
    decode_proof, EmploymentStore,
};
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

// Distinct byte patterns everywhere, so a builder that reached for a
// neighbouring field of the same type would produce a different key.
const ISSUER_ADDR: u8 = 0x11;
const EMPLOYEE_ADDR: u8 = 0x22;
const HOLDER_ADDR: u8 = 0x33;
const EMPLOYMENT_ID: u8 = 0x44;
const EMPLOYEE_REF: u8 = 0x55;
const EMPLOYER_REF: u8 = 0x66;
const ATTESTATION_ID: u8 = 0x77;
const SUBJECT_REF: u8 = 0x88;
const PROOF_ID: u8 = 0x99;

fn issuer() -> EmploymentIssuerProfile {
    EmploymentIssuerProfile {
        issuer_address: addr(ISSUER_ADDR),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        display_name: "Payroll Co".to_string(),
        issuer_commitment: [0xA1; 32],
        jurisdiction_code: "US-CA".to_string(),
        policy_id: [0xA2; 32],
        status: IssuerStatus::Active,
        registered_at_height: 100,
        created_at: 1_000,
        updated_at: 2_000,
    }
}

fn credential() -> EmploymentCredential {
    EmploymentCredential {
        employment_id: [EMPLOYMENT_ID; 32],
        employee_address: addr(EMPLOYEE_ADDR),
        employee_ref: [EMPLOYEE_REF; 32],
        employer_ref: [EMPLOYER_REF; 32],
        status: EmploymentStatus::Active,
        tenure_commitment: [0xB1; 32],
        role_commitment: Some([0xB2; 32]),
        employment_type: EmploymentType::FullTime,
        valid_from: 1_000,
        expiry: 0,
        policy_id: [0xB3; 32],
        revocation_ref: None,
        issuer_address: addr(ISSUER_ADDR),
        issuer_name: "Payroll Co".to_string(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn attestation() -> IncomeAttestation {
    IncomeAttestation {
        attestation_id: [ATTESTATION_ID; 32],
        holder_address: addr(HOLDER_ADDR),
        subject_ref: [SUBJECT_REF; 32],
        period_commitment: [0xC1; 32],
        period_type: IncomePeriod::Annual,
        income_bracket: IncomeBracket::Bracket4,
        threshold_commitment: None,
        employment_id: Some([EMPLOYMENT_ID; 32]),
        issuer_address: addr(ISSUER_ADDR),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [0xC2; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn proof() -> EmploymentProofEnvelope {
    EmploymentProofEnvelope {
        proof_id: [PROOF_ID; 32],
        profile_id: [0xD1; 32],
        proof_type: EmploymentProofType::CurrentlyEmployed,
        subject_nullifier: [0xD2; 32],
        proof_data: vec![1, 2, 3],
        public_inputs_commitment: [0xD3; 32],
        credential_refs: vec![[EMPLOYMENT_ID; 32]],
        source_issuer_class: EmploymentIssuerClass::PayrollProcessor,
        policy_id: [0xD4; 32],
        valid_from: 1_000,
        expiry: 2_000,
        created_at: 1_000,
    }
}

fn event() -> EmploymentEvent {
    EmploymentEvent::IssuerRegistered {
        issuer_address: addr(ISSUER_ADDR),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        timestamp: 1_000,
    }
}

#[test]
fn an_issuer_row_is_bincode_at_the_address_key() {
    let (db, _dir) = db();
    let i = issuer();
    EmploymentStore::new(&db).issuers().put(&i).unwrap();

    assert_eq!(
        row(&db, cf::EMPLOYMENT_ISSUERS, &[ISSUER_ADDR; 20]),
        Some(bincode::serialize(&i).unwrap()),
        "the key is the 20-byte issuer address, the value plain bincode"
    );
}

#[test]
fn an_issuer_status_update_rewrites_the_same_row() {
    let (db, _dir) = db();
    let store = EmploymentStore::new(&db);
    let i = issuer();
    store.issuers().put(&i).unwrap();
    store
        .issuers()
        .update_status(&i.issuer_address, IssuerStatus::Suspended, 9_999)
        .unwrap();

    let mut expected = i;
    expected.status = IssuerStatus::Suspended;
    expected.updated_at = 9_999;
    assert_eq!(
        row(&db, cf::EMPLOYMENT_ISSUERS, &[ISSUER_ADDR; 20]),
        Some(bincode::serialize(&expected).unwrap()),
        "an update keys the same row and changes exactly status and updated_at"
    );
}

#[test]
fn a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes() {
    let (db, _dir) = db();
    let c = credential();
    EmploymentStore::new(&db).credentials().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::EMPLOYMENT_CREDENTIALS, &[EMPLOYMENT_ID; 32]),
        Some(bincode::serialize(&c).unwrap()),
        "the credential, at its employment id"
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYEE_INDEX, &[EMPLOYEE_REF; 32]),
        Some(bincode::serialize(&vec![[EMPLOYMENT_ID; 32]]).unwrap()),
        "a one-element list at the employee COMMITMENT"
    );
    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            &[EMPLOYEE_ADDR; 20]
        ),
        Some(bincode::serialize(&vec![[EMPLOYMENT_ID; 32]]).unwrap()),
        "and one at the employee's WALLET address -- a different key, same value shape"
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYER_INDEX, &[EMPLOYER_REF; 32]),
        Some(bincode::serialize(&vec![[EMPLOYMENT_ID; 32]]).unwrap()),
        "and one at the employer commitment"
    );
}

#[test]
fn a_second_credential_appends_to_each_of_the_three_lists() {
    let (db, _dir) = db();
    let store = EmploymentStore::new(&db);
    let first = credential();
    let mut second = credential();
    second.employment_id = [0xEE; 32];

    store.credentials().put(&first).unwrap();
    store.credentials().put(&second).unwrap();

    let both = bincode::serialize(&vec![[EMPLOYMENT_ID; 32], [0xEEu8; 32]]).unwrap();
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYEE_INDEX, &[EMPLOYEE_REF; 32]),
        Some(both.clone()),
        "both ids, in insertion order"
    );
    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            &[EMPLOYEE_ADDR; 20]
        ),
        Some(both.clone())
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYER_INDEX, &[EMPLOYER_REF; 32]),
        Some(both)
    );
    assert_eq!(
        decode_id_list(&row(&db, cf::EMPLOYMENT_EMPLOYEE_INDEX, &[EMPLOYEE_REF; 32]).unwrap())
            .unwrap(),
        vec![[EMPLOYMENT_ID; 32], [0xEEu8; 32]]
    );
}

#[test]
fn an_update_and_a_revoke_rewrite_only_the_credential_row() {
    let (db, _dir) = db();
    let store = EmploymentStore::new(&db);
    let c = credential();
    store.credentials().put(&c).unwrap();

    store
        .credentials()
        .update_status(&c.employment_id, EmploymentStatus::Suspended, 5_000)
        .unwrap();
    let mut expected = c.clone();
    expected.status = EmploymentStatus::Suspended;
    expected.updated_at = 5_000;
    assert_eq!(
        row(&db, cf::EMPLOYMENT_CREDENTIALS, &[EMPLOYMENT_ID; 32]),
        Some(bincode::serialize(&expected).unwrap())
    );

    store
        .credentials()
        .revoke(&c.employment_id, [0xFA; 32], 6_000)
        .unwrap();
    let mut revoked = c;
    revoked.status = EmploymentStatus::Ended;
    revoked.revocation_ref = Some([0xFA; 32]);
    revoked.updated_at = 6_000;
    assert_eq!(
        row(&db, cf::EMPLOYMENT_CREDENTIALS, &[EMPLOYMENT_ID; 32]),
        Some(bincode::serialize(&revoked).unwrap())
    );

    // The three index rows are STILL the one-element lists creation wrote:
    // neither update nor revoke touches them. That is the committed
    // behaviour, pinned here rather than corrected.
    let one = bincode::serialize(&vec![[EMPLOYMENT_ID; 32]]).unwrap();
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYEE_INDEX, &[EMPLOYEE_REF; 32]),
        Some(one.clone())
    );
    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            &[EMPLOYEE_ADDR; 20]
        ),
        Some(one.clone())
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_EMPLOYER_INDEX, &[EMPLOYER_REF; 32]),
        Some(one)
    );
}

#[test]
fn an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes() {
    let (db, _dir) = db();
    let a = attestation();
    EmploymentStore::new(&db)
        .income_attestations()
        .put(&a)
        .unwrap();

    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            &[ATTESTATION_ID; 32]
        ),
        Some(bincode::serialize(&a).unwrap())
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, &[SUBJECT_REF; 32]),
        Some(bincode::serialize(&vec![[ATTESTATION_ID; 32]]).unwrap()),
        "a one-element list at the subject commitment"
    );
    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            &[HOLDER_ADDR; 20]
        ),
        Some(bincode::serialize(&vec![[ATTESTATION_ID; 32]]).unwrap()),
        "and one at the holder's WALLET address"
    );
}

#[test]
fn a_revoked_attestation_keeps_its_key_and_its_two_index_rows() {
    let (db, _dir) = db();
    let store = EmploymentStore::new(&db);
    let a = attestation();
    store.income_attestations().put(&a).unwrap();
    store
        .income_attestations()
        .revoke(&a.attestation_id, [0xFB; 32], 7_000)
        .unwrap();

    let mut expected = a;
    expected.revocation_ref = Some([0xFB; 32]);
    expected.updated_at = 7_000;
    assert_eq!(
        row(
            &db,
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            &[ATTESTATION_ID; 32]
        ),
        Some(bincode::serialize(&expected).unwrap())
    );
    assert_eq!(
        row(&db, cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, &[SUBJECT_REF; 32]),
        Some(bincode::serialize(&vec![[ATTESTATION_ID; 32]]).unwrap()),
        "the subject index is untouched by a revocation"
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key() {
    let (db, _dir) = db();
    let p = proof();
    EmploymentStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::EMPLOYMENT_PROOFS, &[PROOF_ID; 32]),
        Some(bincode::serialize(&p).unwrap()),
        "proofs have no index of their own"
    );
}

#[test]
fn an_event_row_is_bincode_at_a_big_endian_height_and_index_key() {
    let (db, _dir) = db();
    let e = event();
    EmploymentStore::new(&db).events().put(7, 3, &e).unwrap();

    // Hand-built: eight bytes of height, then four of index, both big-endian.
    let key = [0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 3];
    assert_eq!(
        row(&db, cf::EMPLOYMENT_SYSTEM_EVENTS, &key),
        Some(bincode::serialize(&e).unwrap())
    );
    // And the height alone is a usable scan prefix, which is the only reason
    // the ordering of the two halves matters.
    assert_eq!(
        EmploymentStore::new(&db).events().get_by_height(7).unwrap(),
        vec![e],
        "the height prefix selects exactly that block's events"
    );
    assert!(EmploymentStore::new(&db)
        .events()
        .get_by_height(8)
        .unwrap()
        .is_empty());
}

#[test]
fn malformed_bytes_are_refused_by_every_employment_decoder() {
    let junk = b"not a row";
    assert!(decode_issuer(junk).is_err());
    assert!(decode_credential(junk).is_err());
    assert!(decode_attestation(junk).is_err());
    assert!(decode_proof(junk).is_err());
    assert!(decode_id_list(junk).is_err());
    assert!(
        decode_event(junk).is_err(),
        "including events, which execution does not read"
    );
}
