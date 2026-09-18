//! Finance: the committed store's rows are exactly what the shared helpers build.
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
//! ## Nine families, spelled out
//!
//!     issuers               the 20-byte issuer address
//!     jurisdiction index    the jurisdiction-code STRING's bytes,
//!                           value a bincode Vec<Address>
//!     address proofs        the 32-byte proof id
//!     subject address index the 32-byte subject ref,
//!                           value a bincode Vec<[u8; 32]>
//!     bank standings        the 32-byte credential id
//!     subject bank index    the 32-byte subject ref, same list shape
//!     kyc attestations      the 32-byte attestation id
//!     subject kyc index     the 32-byte subject ref, same list shape
//!     proofs                the 32-byte proof id
//!
//! The four indexes are ACCUMULATING lists, not presence markers. Three of them
//! share one value type and one codec, and each has its OWN key builder and its
//! own family -- which is why the three are asserted separately below rather
//! than once: a builder that returned the wrong family's key would otherwise
//! ride along on its neighbour's assertion.

use sumchain_primitives::finance::{
    AccountStanding, AccountType, AddressProof, AddressProofType, AmlRisk, BalanceBracket,
    BankStandingCredential, FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus,
    FinanceProofEnvelope, FinanceProofType, KycAttestation, KycLevel, KycStatus,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::finance_store::{decode_addresses, decode_id_list, FinanceStore};
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

fn issuer() -> FinanceIssuerProfile {
    FinanceIssuerProfile {
        issuer_address: addr(3),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        issuer_commitment: [2u8; 32],
        jurisdiction_code: "US-NY".to_string(),
        policy_id: [3u8; 32],
        status: FinanceIssuerStatus::Active,
        registered_at_height: 100,
        created_at: 1_000,
        updated_at: 2_000,
    }
}

fn address_proof() -> AddressProof {
    AddressProof {
        proof_id: [4u8; 32],
        subject_ref: [5u8; 32],
        holder_address: addr(0x30),
        address_commitment: [6u8; 32],
        jurisdiction_code: "US-NY".to_string(),
        postal_commitment: [7u8; 32],
        proof_type: AddressProofType::UtilityBill,
        document_date: 900,
        issuer_address: addr(3),
        issuer_class: FinanceIssuerClass::RegulatedUtility,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [9u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn bank_standing() -> BankStandingCredential {
    BankStandingCredential {
        credential_id: [10u8; 32],
        subject_ref: [11u8; 32],
        holder_address: addr(0x31),
        account_commitment: [12u8; 32],
        bank_ref: [13u8; 32],
        account_type: AccountType::Checking,
        standing: AccountStanding::Good,
        tenure_commitment: [14u8; 32],
        balance_bracket: BalanceBracket::Bracket5,
        threshold_commitment: None,
        issuer_address: addr(3),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [16u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn kyc_attestation() -> KycAttestation {
    KycAttestation {
        attestation_id: [17u8; 32],
        subject_ref: [18u8; 32],
        holder_address: addr(0x32),
        kyc_level: KycLevel::Enhanced,
        aml_risk: AmlRisk::Low,
        identity_commitment: [19u8; 32],
        subject_jurisdiction: "US".to_string(),
        methods_commitment: [20u8; 32],
        status: KycStatus::Active,
        issuer_address: addr(3),
        issuer_class: FinanceIssuerClass::RegulatedBank,
        valid_from: 1_000,
        expiry: 2_000,
        policy_id: [22u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn proof_envelope() -> FinanceProofEnvelope {
    FinanceProofEnvelope {
        proof_id: [23u8; 32],
        profile_id: [24u8; 32],
        proof_type: FinanceProofType::KycLevelAchieved,
        subject_nullifier: [25u8; 32],
        proof_data: vec![9, 9, 9],
        public_inputs_commitment: [26u8; 32],
        credential_refs: vec![[17u8; 32]],
        source_issuer_class: FinanceIssuerClass::RegulatedBank,
        policy_id: [27u8; 32],
        valid_from: 1_000,
        expiry: 2_000,
        created_at: 1_000,
    }
}

#[test]
fn an_issuer_row_is_bincode_at_the_address_key_and_indexes_its_jurisdiction() {
    let (db, _dir) = db();
    let i = issuer();
    FinanceStore::new(&db).issuers().put(&i).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_ISSUERS, &[3u8; 20]),
        Some(bincode::serialize(&i).unwrap()),
        "the key is the 20-byte address, the value plain bincode"
    );
    // The jurisdiction index VALUE is a bincode `Vec<Address>`, not a presence
    // marker, and its KEY is the jurisdiction-code string's bytes -- NOT a
    // hash and NOT the address.
    assert_eq!(
        row(&db, cf::FINANCE_JURISDICTION_INDEX, b"US-NY"),
        Some(bincode::serialize(&vec![addr(3)]).unwrap()),
        "and a one-element address list at the jurisdiction code"
    );
}

#[test]
fn a_second_issuer_in_one_jurisdiction_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let first = issuer();
    let mut second = issuer();
    second.issuer_address = addr(4);

    store.issuers().put(&first).unwrap();
    store.issuers().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_JURISDICTION_INDEX, b"US-NY"),
        Some(bincode::serialize(&vec![addr(3), addr(4)]).unwrap()),
        "both addresses, in registration order"
    );
    assert_eq!(
        decode_addresses(&row(&db, cf::FINANCE_JURISDICTION_INDEX, b"US-NY").unwrap()).unwrap(),
        vec![addr(3), addr(4)]
    );
}

#[test]
fn re_registering_an_issuer_does_not_duplicate_its_jurisdiction_entry() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let i = issuer();
    store.issuers().put(&i).unwrap();
    store.issuers().put(&i).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_JURISDICTION_INDEX, b"US-NY"),
        Some(bincode::serialize(&vec![addr(3)]).unwrap()),
        "the second put must leave the list exactly one element long"
    );
}

#[test]
fn an_address_proof_row_is_bincode_at_the_proof_id_and_indexes_its_subject() {
    let (db, _dir) = db();
    let p = address_proof();
    FinanceStore::new(&db).address_proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_ADDRESS_PROOFS, &[4u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[5u8; 32]),
        Some(bincode::serialize(&vec![[4u8; 32]]).unwrap()),
        "a one-element id list at the subject ref"
    );
}

#[test]
fn a_second_address_proof_for_one_subject_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let first = address_proof();
    let mut second = address_proof();
    second.proof_id = [0x44u8; 32];

    store.address_proofs().put(&first).unwrap();
    store.address_proofs().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[5u8; 32]),
        Some(bincode::serialize(&vec![[4u8; 32], [0x44u8; 32]]).unwrap()),
        "both ids, in insertion order"
    );
    assert_eq!(
        decode_id_list(&row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[5u8; 32]).unwrap()).unwrap(),
        vec![[4u8; 32], [0x44u8; 32]]
    );
}

#[test]
fn a_bank_standing_row_is_bincode_at_the_credential_id_and_indexes_its_subject() {
    let (db, _dir) = db();
    let c = bank_standing();
    FinanceStore::new(&db).bank_standings().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_BANK_STANDINGS, &[10u8; 32]),
        Some(bincode::serialize(&c).unwrap())
    );
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_BANK_INDEX, &[11u8; 32]),
        Some(bincode::serialize(&vec![[10u8; 32]]).unwrap()),
        "in the BANK subject index, keyed by the bank credential's subject ref"
    );
    // And nowhere else. The three subject indexes share a value type; only the
    // key builder and the family distinguish them.
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[11u8; 32]),
        None
    );
    assert_eq!(row(&db, cf::FINANCE_SUBJECT_KYC_INDEX, &[11u8; 32]), None);
}

#[test]
fn a_second_bank_standing_for_one_subject_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let first = bank_standing();
    let mut second = bank_standing();
    second.credential_id = [0x55u8; 32];

    store.bank_standings().put(&first).unwrap();
    store.bank_standings().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_BANK_INDEX, &[11u8; 32]),
        Some(bincode::serialize(&vec![[10u8; 32], [0x55u8; 32]]).unwrap())
    );
}

#[test]
fn a_kyc_row_is_bincode_at_the_attestation_id_and_indexes_its_subject() {
    let (db, _dir) = db();
    let a = kyc_attestation();
    FinanceStore::new(&db).kyc_attestations().put(&a).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_KYC_ATTESTATIONS, &[17u8; 32]),
        Some(bincode::serialize(&a).unwrap())
    );
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_KYC_INDEX, &[18u8; 32]),
        Some(bincode::serialize(&vec![[17u8; 32]]).unwrap()),
        "in the KYC subject index, keyed by the attestation's subject ref"
    );
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[18u8; 32]),
        None
    );
    assert_eq!(row(&db, cf::FINANCE_SUBJECT_BANK_INDEX, &[18u8; 32]), None);
}

#[test]
fn a_second_kyc_attestation_for_one_subject_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let first = kyc_attestation();
    let mut second = kyc_attestation();
    second.attestation_id = [0x66u8; 32];

    store.kyc_attestations().put(&first).unwrap();
    store.kyc_attestations().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_KYC_INDEX, &[18u8; 32]),
        Some(bincode::serialize(&vec![[17u8; 32], [0x66u8; 32]]).unwrap())
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_indexes_nothing() {
    let (db, _dir) = db();
    let p = proof_envelope();
    FinanceStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::FINANCE_PROOFS, &[23u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    // SRC-895 proofs carry a subject nullifier but are NOT indexed by it --
    // unlike the three credential families. Pinned so that adding an index
    // here is a deliberate change with a failing test attached.
    assert_eq!(
        row(&db, cf::FINANCE_SUBJECT_ADDRESS_INDEX, &[25u8; 32]),
        None
    );
    assert_eq!(row(&db, cf::FINANCE_SUBJECT_BANK_INDEX, &[25u8; 32]), None);
    assert_eq!(row(&db, cf::FINANCE_SUBJECT_KYC_INDEX, &[25u8; 32]), None);
}

#[test]
fn an_update_rewrites_the_primary_row_and_leaves_the_indexes_alone() {
    let (db, _dir) = db();
    let store = FinanceStore::new(&db);
    let mut i = issuer();
    store.issuers().put(&i).unwrap();

    store
        .issuers()
        .update_status(&i.issuer_address, FinanceIssuerStatus::Revoked, 3_000)
        .unwrap();

    i.status = FinanceIssuerStatus::Revoked;
    i.updated_at = 3_000;
    assert_eq!(
        row(&db, cf::FINANCE_ISSUERS, &[3u8; 20]),
        Some(bincode::serialize(&i).unwrap()),
        "status and updated_at, and nothing else, change"
    );
    // PRE-EXISTING: a revoked issuer stays listed under its jurisdiction.
    assert_eq!(
        row(&db, cf::FINANCE_JURISDICTION_INDEX, b"US-NY"),
        Some(bincode::serialize(&vec![addr(3)]).unwrap()),
        "the jurisdiction index is not rewritten by a status change -- a \
         dangling listing the committed path has always left"
    );
}

#[test]
fn malformed_bytes_are_refused_by_every_finance_decoder() {
    use sumchain_storage::finance_store::{
        decode_address_proof, decode_bank_standing, decode_issuer, decode_kyc_attestation,
        decode_proof,
    };
    let junk = b"not a row";
    assert!(decode_issuer(junk).is_err());
    assert!(decode_addresses(junk).is_err());
    assert!(decode_address_proof(junk).is_err());
    assert!(decode_bank_standing(junk).is_err());
    assert!(decode_kyc_attestation(junk).is_err());
    assert!(decode_id_list(junk).is_err());
    assert!(
        decode_proof(junk).is_err(),
        "including proof envelopes, which execution never decodes but the RPC does"
    );
}
