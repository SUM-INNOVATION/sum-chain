//! DocClass: the committed store's rows are exactly what the shared helpers
//! build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_identity_root(...)` proves nothing:
//! the store CALLS that helper, so a wrong helper moves both sides of the
//! assertion together. That exact hole was found by mutation in the messaging
//! preparation commit, where flipping `encode_u32` to little-endian passed every
//! test.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand as a literal or assembled
//! from `to_be_bytes` in the test body. Both are what the committed store
//! produced BEFORE this commit extracted the helpers: the row layout is the
//! compatibility contract, and it must not move.
//!
//! ## Keys, spelled out
//!
//!     identity roots   the 32-byte identity id
//!     eligibility      the 32-byte credential id
//!     credentials      the 32-byte credential id
//!     issuers          the 20 raw address bytes
//!     subject index    the 32-byte subject commitment
//!     issuer index     the 20 raw address bytes of the ISSUER
//!     revocations      credential_id (32) || revoked_at_height (8, BIG-endian)
//!     events           height (8) || tx_index (4) || event_index (2), all BE
//!
//! Two of those are worth reading twice.
//!
//! **The subject index holds two incompatible value shapes at one key.**
//! `IdentityRootStore` writes `Vec<(CredentialId, DocSubcode)>`;
//! `EligibilityStore` and `CredentialStore` write `Vec<CredentialId>`. An
//! identity and a credential that share a subject commitment therefore write
//! over each other, and the second reader gets the wrong shape.
//! `an_identity_and_a_credential_sharing_a_subject_commitment_collide` pins
//! that, because it is the behaviour on the chain today and fixing it would
//! change which transactions are valid.
//!
//! **Both composite keys are big-endian**, and both are read back by prefix
//! scan. Little-endian would still round-trip a single row and would reorder
//! every scan; `the_two_composite_keys_are_big_endian` fixes the bytes.

use sumchain_primitives::{
    AcademicCredential, Address, CredentialAttribute, CredentialMetadata, DocClassEvent,
    DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocSubcode, EligibilityAttestation,
    EligibilityType, IdentityKey, IdentityRoot, IdentityStatus, IssuerKey, KeyPurpose, KeyType,
    RevocationReason, RevocationRecord, RevocationStatus, ServiceEndpoint,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::docclass_store::{
    decode_issuer_credential_index, decode_subject_credential_index, decode_subject_identity_index,
    DocClassStore,
};
use tempfile::TempDir;

const IDENTITY: [u8; 32] = [1u8; 32];
const ELIG: [u8; 32] = [2u8; 32];
const CRED: [u8; 32] = [3u8; 32];
const SUBJECT_IDENTITY: [u8; 32] = [0xA0u8; 32];
const SUBJECT_ELIG: [u8; 32] = [0xA1u8; 32];
const SUBJECT_CRED: [u8; 32] = [0xA2u8; 32];

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

fn identity_key() -> IdentityKey {
    IdentityKey {
        key_id: "auth-1".to_string(),
        key_type: KeyType::Ed25519,
        public_key: [4u8; 32],
        purposes: vec![KeyPurpose::Authentication, KeyPurpose::Assertion],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn issuer_signing_key() -> IssuerKey {
    IssuerKey {
        key_id: "issuer-1".to_string(),
        public_key: [5u8; 32],
        key_type: KeyType::Ed25519,
        added_at: 1_000,
        expires_at: 0,
        active: true,
        is_primary: true,
    }
}

fn identity_root() -> IdentityRoot {
    IdentityRoot {
        identity_id: IDENTITY,
        subject_commitment: SUBJECT_IDENTITY,
        controller: Address::new([6u8; 20]),
        additional_controllers: vec![Address::new([7u8; 20])],
        keys: vec![identity_key()],
        services: vec![ServiceEndpoint {
            service_id: "svc-1".to_string(),
            service_type: "CredentialRegistry".to_string(),
            endpoint: "https://example.invalid/registry".to_string(),
            description: Some("registry".to_string()),
        }],
        created_at: 1_000,
        updated_at: 2_000,
        status: IdentityStatus::Active,
        schema_hash: [8u8; 32],
    }
}

fn eligibility() -> EligibilityAttestation {
    EligibilityAttestation {
        credential_id: ELIG,
        subject_address: Address::new([9u8; 20]),
        subcode: DocSubcode::EligibilityAttestation,
        subject_commitment: SUBJECT_ELIG,
        issuer: Address::new([10u8; 20]),
        jurisdiction: "US-CA".to_string(),
        eligibility_type: EligibilityType::Citizenship,
        schema_hash: [11u8; 32],
        content_commitment: [12u8; 32],
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: Some([13u8; 32]),
        payload_hint: Some("ipfs://cid".to_string()),
        encryption_meta: None,
        issuer_signature: [14u8; 64],
        issuer_key_id: "issuer-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn credential() -> AcademicCredential {
    AcademicCredential {
        credential_id: CRED,
        subject_address: Address::new([15u8; 20]),
        subcode: DocSubcode::Diploma,
        subject_commitment: SUBJECT_CRED,
        issuer: Address::new([16u8; 20]),
        institution_id: "UCLA".to_string(),
        jurisdiction: "US".to_string(),
        schema_hash: [17u8; 32],
        content_commitment: [18u8; 32],
        metadata: CredentialMetadata {
            title: "Bachelor of Science".to_string(),
            credential_type: "undergraduate_degree".to_string(),
            program: Some("Computer Science".to_string()),
            issue_date: "2024-05-15".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "honors".to_string(),
                value: "cum_laude".to_string(),
            }],
        },
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [19u8; 64],
        issuer_key_id: "issuer-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn docclass_issuer(address: Address) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Test Registry".to_string(),
        issuer_type: DocClassIssuerType::Government,
        jurisdictions: vec!["US".to_string()],
        authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
        keys: vec![issuer_signing_key()],
        registered_at: 1_000,
        updated_at: 2_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 42,
        metadata: Some("{}".to_string()),
    }
}

fn revocation_record(credential_id: [u8; 32], height: u64) -> RevocationRecord {
    RevocationRecord {
        credential_id,
        status: RevocationStatus::Revoked,
        reason: RevocationReason::KeyCompromise,
        reason_details: Some("key leaked".to_string()),
        revoker: Address::new([20u8; 20]),
        revoked_at: 1_700_000_000,
        revoked_at_height: height,
        superseded_by: None,
        signature: [21u8; 64],
    }
}

fn event() -> DocClassEvent {
    DocClassEvent::IdentityRootCreated {
        identity_id: IDENTITY,
        controller: Address::new([6u8; 20]),
        subject_commitment: SUBJECT_IDENTITY,
    }
}

// ── Primary rows and their indexes ──────────────────────────────────────────

#[test]
fn an_identity_row_is_bincode_at_the_identity_id_key_and_indexes_its_subject() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let identity = identity_root();
    store.identity_roots().put(&identity).unwrap();

    assert_eq!(
        row(&db, cf::DOCCLASS_IDENTITY_ROOTS, &[1u8; 32]),
        Some(bincode::serialize(&identity).unwrap()),
        "the identity row is bincode at the bare 32-byte identity id"
    );
    // The subject index entry is a PAIR list, not a bare id list.
    assert_eq!(
        row(&db, cf::DOCCLASS_SUBJECT_INDEX, &[0xA0u8; 32]),
        Some(bincode::serialize(&vec![(IDENTITY, DocSubcode::IdentityRoot)]).unwrap()),
        "the identity store indexes (id, subcode) pairs by subject commitment"
    );
}

#[test]
fn a_second_identity_for_one_subject_appends_to_the_same_pair_list() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let first = identity_root();
    let mut second = identity_root();
    second.identity_id = [0x22u8; 32];

    store.identity_roots().put(&first).unwrap();
    store.identity_roots().put(&second).unwrap();

    assert_eq!(
        row(&db, cf::DOCCLASS_SUBJECT_INDEX, &[0xA0u8; 32]),
        Some(
            bincode::serialize(&vec![
                (IDENTITY, DocSubcode::IdentityRoot),
                ([0x22u8; 32], DocSubcode::IdentityRoot),
            ])
            .unwrap()
        ),
        "both ids, in insertion order"
    );
}

#[test]
fn re_putting_the_same_identity_does_not_duplicate_its_index_entry() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let identity = identity_root();
    store.identity_roots().put(&identity).unwrap();
    store.identity_roots().put(&identity).unwrap();

    let bytes = row(&db, cf::DOCCLASS_SUBJECT_INDEX, &[0xA0u8; 32]).unwrap();
    assert_eq!(decode_subject_identity_index(&bytes).unwrap().len(), 1);
}

#[test]
fn an_eligibility_row_is_bincode_and_indexes_both_its_subject_and_its_issuer() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let attestation = eligibility();
    store.eligibility().put(&attestation).unwrap();

    assert_eq!(
        row(&db, cf::DOCCLASS_ELIGIBILITY, &[2u8; 32]),
        Some(bincode::serialize(&attestation).unwrap())
    );
    assert_eq!(
        row(&db, cf::DOCCLASS_SUBJECT_INDEX, &[0xA1u8; 32]),
        Some(bincode::serialize(&vec![ELIG]).unwrap()),
        "the eligibility store indexes BARE ids by subject commitment"
    );
    assert_eq!(
        row(&db, cf::DOCCLASS_ISSUER_INDEX, &[10u8; 20]),
        Some(bincode::serialize(&vec![ELIG]).unwrap()),
        "and by the 20 raw address bytes of the issuer"
    );
}

#[test]
fn a_credential_row_is_bincode_and_indexes_both_its_subject_and_its_issuer() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let cred = credential();
    store.credentials().put(&cred).unwrap();

    assert_eq!(
        row(&db, cf::DOCCLASS_CREDENTIALS, &[3u8; 32]),
        Some(bincode::serialize(&cred).unwrap())
    );
    assert_eq!(
        row(&db, cf::DOCCLASS_SUBJECT_INDEX, &[0xA2u8; 32]),
        Some(bincode::serialize(&vec![CRED]).unwrap())
    );
    assert_eq!(
        row(&db, cf::DOCCLASS_ISSUER_INDEX, &[16u8; 20]),
        Some(bincode::serialize(&vec![CRED]).unwrap())
    );
}

#[test]
fn two_credentials_from_one_issuer_append_to_the_same_issuer_list() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let first = credential();
    let mut second = credential();
    second.credential_id = [0x33u8; 32];
    second.subject_commitment = [0xA3u8; 32];

    store.credentials().put(&first).unwrap();
    store.credentials().put(&second).unwrap();

    let bytes = row(&db, cf::DOCCLASS_ISSUER_INDEX, &[16u8; 20]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![CRED, [0x33u8; 32]]).unwrap(),
        "both ids, in insertion order"
    );
    assert_eq!(decode_issuer_credential_index(&bytes).unwrap().len(), 2);
}

#[test]
fn an_issuer_row_is_bincode_at_the_raw_address_bytes_and_writes_no_index() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let address = Address::new([0x44u8; 20]);
    let issuer = docclass_issuer(address);
    store.issuers().put(&issuer).unwrap();

    assert_eq!(
        row(&db, cf::DOCCLASS_ISSUERS, &[0x44u8; 20]),
        Some(bincode::serialize(&issuer).unwrap()),
        "20 bytes, not 32: the issuer registry is keyed by the address itself"
    );
    assert_eq!(
        db.prefix_iter(cf::DOCCLASS_ISSUER_INDEX, &[])
            .unwrap()
            .count(),
        0,
        "registering an issuer writes no index row -- the issuer index is a \
         CREDENTIAL index that happens to be keyed by issuer"
    );
}

#[test]
fn a_revocation_row_is_bincode_at_the_credential_id_and_height_key() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let record = revocation_record(ELIG, 0x0102_0304_0506_0708);
    store.revocations().put(&record).unwrap();

    let mut expected_key = Vec::new();
    expected_key.extend_from_slice(&ELIG);
    expected_key.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(expected_key.len(), 40);

    assert_eq!(
        row(&db, cf::DOCCLASS_REVOCATIONS, &expected_key),
        Some(bincode::serialize(&record).unwrap())
    );
}

#[test]
fn an_event_row_is_bincode_at_the_height_txindex_eventindex_key() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let e = event();
    store
        .events()
        .put(0x0102_0304_0506_0708, 0x090A_0B0C, 0x0D0E, &e)
        .unwrap();

    let expected_key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    assert_eq!(expected_key.len(), 14);
    assert_eq!(
        row(&db, cf::DOCCLASS_EVENTS, &expected_key),
        Some(bincode::serialize(&e).unwrap())
    );
}

// ── The two composite keys ──────────────────────────────────────────────────

/// Both composite keys are big-endian, and both are read back by prefix scan.
///
/// Little-endian would round-trip a single row perfectly and silently reverse
/// every scan, so the bytes are fixed here rather than inferred from a
/// round-trip.
#[test]
fn the_two_composite_keys_are_big_endian() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);

    store
        .revocations()
        .put(&revocation_record(ELIG, 1))
        .unwrap();
    store
        .revocations()
        .put(&revocation_record(ELIG, 256))
        .unwrap();

    let keys: Vec<Vec<u8>> = db
        .prefix_iter(cf::DOCCLASS_REVOCATIONS, &ELIG)
        .unwrap()
        .map(|(k, _)| k.to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![
            [ELIG.to_vec(), vec![0, 0, 0, 0, 0, 0, 0, 1]].concat(),
            [ELIG.to_vec(), vec![0, 0, 0, 0, 0, 0, 1, 0]].concat(),
        ],
        "height 1 then height 256, and the 256 key must be 0x0100 not 0x0001"
    );

    store.events().put(1, 1, 1, &event()).unwrap();
    store.events().put(256, 0, 0, &event()).unwrap();
    let keys: Vec<Vec<u8>> = db
        .prefix_iter(cf::DOCCLASS_EVENTS, &[])
        .unwrap()
        .map(|(k, _)| k.to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![
            vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1],
            vec![0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        ]
    );
}

/// A revocation record written twice at one height is ONE row.
///
/// The key carries the height and nothing else that distinguishes two records,
/// so a revoke and a reactivation in the same block collapse into whichever ran
/// last. Preserved: widening the key would change what a chain replays to.
#[test]
fn two_revocations_at_one_height_are_one_row() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    store
        .revocations()
        .put(&revocation_record(ELIG, 7))
        .unwrap();

    let mut second = revocation_record(ELIG, 7);
    second.status = RevocationStatus::Active;
    second.reason = RevocationReason::Unspecified;
    store.revocations().put(&second).unwrap();

    assert_eq!(
        db.prefix_iter(cf::DOCCLASS_REVOCATIONS, &ELIG)
            .unwrap()
            .count(),
        1,
        "one key, one row"
    );
    assert_eq!(
        store.revocations().get_status(&ELIG).unwrap(),
        RevocationStatus::Active,
        "and the later write is the one that survives"
    );
}

// ── The subject-index collision ─────────────────────────────────────────────

/// An identity and a credential sharing a subject commitment write over each
/// other, and the loser's reader gets the wrong shape.
///
/// Reproduced, not repaired. Splitting the family or tagging the value would
/// change the bytes at a live key and therefore the state root.
#[test]
fn an_identity_and_a_credential_sharing_a_subject_commitment_collide() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);

    let shared = [0xB0u8; 32];
    let mut identity = identity_root();
    identity.subject_commitment = shared;
    let mut attestation = eligibility();
    attestation.subject_commitment = shared;

    store.identity_roots().put(&identity).unwrap();
    // The eligibility store reads the pair list as a bare id list. bincode
    // allows trailing bytes, so this does NOT error -- it decodes the first 32
    // bytes of the first pair as an id and drops the subcode.
    store.eligibility().put(&attestation).unwrap();

    let bytes = row(&db, cf::DOCCLASS_SUBJECT_INDEX, &shared).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![IDENTITY, ELIG]).unwrap(),
        "the eligibility store rewrote the row as a BARE id list, so the \
         identity's subcode is gone"
    );
    assert!(
        store.identity_roots().get_by_subject(&shared).is_err(),
        "and the identity store's own reader can no longer decode its index"
    );
    assert_eq!(
        decode_subject_credential_index(&bytes).unwrap(),
        vec![IDENTITY, ELIG]
    );
}

// ── Round trips and malformed rows ──────────────────────────────────────────

#[test]
fn every_round_trip_returns_the_value_that_was_written() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    let address = Address::new([0x44u8; 20]);

    store.identity_roots().put(&identity_root()).unwrap();
    store.eligibility().put(&eligibility()).unwrap();
    store.credentials().put(&credential()).unwrap();
    store.issuers().put(&docclass_issuer(address)).unwrap();
    store
        .revocations()
        .put(&revocation_record(ELIG, 9))
        .unwrap();
    store.events().put(9, 0, 0, &event()).unwrap();

    assert_eq!(
        store.identity_roots().get(&IDENTITY).unwrap(),
        Some(identity_root())
    );
    assert_eq!(store.eligibility().get(&ELIG).unwrap(), Some(eligibility()));
    assert_eq!(store.credentials().get(&CRED).unwrap(), Some(credential()));
    assert_eq!(
        store.issuers().get(&address).unwrap(),
        Some(docclass_issuer(address))
    );
    assert_eq!(
        store.revocations().get_latest(&ELIG).unwrap(),
        Some(revocation_record(ELIG, 9))
    );
    assert_eq!(
        store.events().get_events_at_height(9).unwrap(),
        vec![event()]
    );
}

/// Absence and corruption are different answers, from every decoding reader.
#[test]
fn a_malformed_row_is_an_error_from_every_decoding_reader() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    const CORRUPT: &[u8] = b"not a valid row";
    let address = Address::new([0x44u8; 20]);

    db.put(cf::DOCCLASS_IDENTITY_ROOTS, &IDENTITY, CORRUPT)
        .unwrap();
    db.put(cf::DOCCLASS_ELIGIBILITY, &ELIG, CORRUPT).unwrap();
    db.put(cf::DOCCLASS_CREDENTIALS, &CRED, CORRUPT).unwrap();
    db.put(cf::DOCCLASS_ISSUERS, address.as_bytes(), CORRUPT)
        .unwrap();
    db.put(cf::DOCCLASS_SUBJECT_INDEX, &SUBJECT_ELIG, CORRUPT)
        .unwrap();
    db.put(cf::DOCCLASS_ISSUER_INDEX, address.as_bytes(), CORRUPT)
        .unwrap();

    let mut revocation_key = SUBJECT_CRED.to_vec();
    revocation_key.extend_from_slice(&7u64.to_be_bytes());
    db.put(cf::DOCCLASS_REVOCATIONS, &revocation_key, CORRUPT)
        .unwrap();
    db.put(cf::DOCCLASS_EVENTS, &[0u8; 14], CORRUPT).unwrap();

    assert!(store.identity_roots().get(&IDENTITY).is_err());
    assert!(store.eligibility().get(&ELIG).is_err());
    assert!(store.credentials().get(&CRED).is_err());
    assert!(store.issuers().get(&address).is_err());
    assert!(store
        .identity_roots()
        .get_by_subject(&SUBJECT_ELIG)
        .is_err());
    // The same corrupt row through the OTHER shape's reader: the eligibility
    // and credential stores decode this family as a bare id list, and that
    // decoder has to report the failure too.
    assert!(store.eligibility().get_by_subject(&SUBJECT_ELIG).is_err());
    assert!(store.credentials().get_by_subject(&SUBJECT_ELIG).is_err());
    assert!(store.eligibility().get_by_issuer(&address).is_err());
    assert!(store.revocations().get_status(&SUBJECT_CRED).is_err());
    assert!(store.events().get_events_at_height(0).is_err());

    // `exists` is a `contains`, so it says PRESENT for a corrupt row. That is
    // the safe direction for a duplicate guard and is preserved deliberately.
    assert!(store.identity_roots().exists(&IDENTITY).unwrap());
    assert!(store.eligibility().exists(&ELIG).unwrap());
    assert!(store.credentials().exists(&CRED).unwrap());
    assert!(store.issuers().is_registered(&address).unwrap());
}

/// A revocation key of the wrong WIDTH is skipped, not decoded.
///
/// RocksDB prefix iteration can overrun the prefix, so the reader checks both
/// the width and the first 32 bytes. Without the width check a 33-byte key
/// sharing the prefix would be decoded as this credential's record.
#[test]
fn a_revocation_key_of_the_wrong_width_is_skipped() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);
    store
        .revocations()
        .put(&revocation_record(ELIG, 5))
        .unwrap();

    let mut short = ELIG.to_vec();
    short.push(0);
    db.put(cf::DOCCLASS_REVOCATIONS, &short, b"not a valid row")
        .unwrap();

    assert_eq!(
        store.revocations().get_for_credential(&ELIG).unwrap(),
        vec![revocation_record(ELIG, 5)],
        "the 33-byte key is skipped before it is decoded"
    );
}

/// The latest record wins, and `get_status` reports `Active` for a credential
/// with no records at all.
#[test]
fn the_latest_revocation_record_by_height_is_the_status() {
    let (db, _dir) = db();
    let store = DocClassStore::new(&db);

    let mut low = revocation_record(ELIG, 10);
    low.status = RevocationStatus::Suspended;
    let mut high = revocation_record(ELIG, 300);
    high.status = RevocationStatus::Revoked;
    // Written low-then-high and high-then-low would both have to give the same
    // answer: the order is decided by the decoded height, not by write order.
    store.revocations().put(&high).unwrap();
    store.revocations().put(&low).unwrap();

    assert_eq!(
        store.revocations().get_status(&ELIG).unwrap(),
        RevocationStatus::Revoked
    );
    assert_eq!(
        store.revocations().get_status(&[0xEEu8; 32]).unwrap(),
        RevocationStatus::Active,
        "absence is Active"
    );
}
