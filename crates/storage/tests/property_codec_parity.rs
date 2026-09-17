//! Property: the committed store's rows are exactly what the shared helpers
//! build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_asset(...)` proves nothing: the store
//! CALLS that helper, so a wrong helper moves both sides of the assertion
//! together. That exact hole was found by mutation in the messaging
//! preparation commit, where flipping `encode_u32` to little-endian passed
//! every test.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand as a literal. Both are
//! what the committed store produced BEFORE this commit extracted the helpers:
//! the row layout is the compatibility contract, and it must not move.
//!
//! ## Keys, spelled out
//!
//!     assets              the 32-byte asset id
//!     jurisdiction index  the UTF-8 BYTES of the jurisdiction code,
//!                         value a bincode Vec<AssetId>
//!     title events        the 32-byte event id
//!     asset title index   the 32-byte ASSET id, value a bincode Vec<TitleEventId>
//!     encumbrances        the 32-byte encumbrance id
//!     asset enc. index    the 32-byte ASSET id, value a bincode Vec<EncumbranceId>
//!     coverage            the 32-byte coverage id
//!     asset cov. index    the 32-byte ASSET id, value a bincode Vec<CoverageId>
//!     claims              the 32-byte claim id
//!     coverage claim idx  the 32-byte COVERAGE id, value a bincode Vec<ClaimId>
//!     proofs              the 32-byte proof id
//!
//! The jurisdiction index is the one worth reading twice. It is the only
//! family in the subsystem not keyed by a 32-byte id: its key is the raw UTF-8
//! of a free-form string, so its width is whatever the payload said, and two
//! jurisdictions that differ only in case or trailing space are two rows.

use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, ClaimStatus, ClaimType, CoverageStatus, CoverageType,
    Encumbrance, EncumbranceStatus, EncumbranceType, InsuranceClaim, InsuranceCoverage,
    PriorityPosition, PropertyIssuerClass, PropertyProofEnvelope, PropertyProofProfile,
    PropertyProofType, TitleEvent, TitleEventStatus, TitleEventType,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::property_store::{
    decode_asset_coverage_ids, decode_asset_encumbrance_ids, decode_asset_title_event_ids,
    decode_coverage_claim_ids, decode_jurisdiction_asset_ids, PropertyStore,
};
use tempfile::TempDir;

const ASSET: [u8; 32] = [1u8; 32];
const JURISDICTION: &str = "US-CA-LA";

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

fn asset() -> AssetAnchor {
    AssetAnchor {
        asset_id: ASSET,
        asset_commitment: [2u8; 32],
        asset_type: AssetType::SingleFamilyResidence,
        jurisdiction_code: JURISDICTION.to_string(),
        public_reference: Some("APN 1234".to_string()),
        policy_id: [3u8; 32],
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: Address::new([4u8; 20]),
        status: AssetStatus::Active,
        created_at: 1_000,
        updated_at: 2_000,
        anchored_at_height: 7,
        related_assets: vec![[0x77u8; 32]],
        attachments: vec![],
    }
}

fn title_event() -> TitleEvent {
    TitleEvent {
        event_id: [5u8; 32],
        asset_id: ASSET,
        event_type: TitleEventType::WarrantyDeed,
        event_commitment: [6u8; 32],
        grantor_ref: Some(PartyRef::Commitment([0xA1; 32])),
        grantee_ref: Some(PartyRef::Commitment([0xB2; 32])),
        issuer_address: Address::new([7u8; 20]),
        issuer_class: PropertyIssuerClass::TitleCompany,
        effective_date: 1_000,
        recording_ref: Some("2024-000123".to_string()),
        policy_id: [3u8; 32],
        revocation_ref: None,
        status: TitleEventStatus::Recorded,
        created_at: 1_000,
        recorded_at_height: 7,
        supersedes: None,
        attachments: vec![],
    }
}

fn encumbrance() -> Encumbrance {
    Encumbrance {
        encumbrance_id: [8u8; 32],
        asset_id: ASSET,
        encumbrance_type: EncumbranceType::FirstMortgage,
        encumbrance_commitment: [9u8; 32],
        holder_ref: PartyRef::Commitment([0xC3; 32]),
        obligor_ref: Some(PartyRef::Commitment([0xD4; 32])),
        priority: PriorityPosition::First,
        amount_commitment: Some([10u8; 32]),
        effective_from: 1_000,
        expiry: Some(9_000_000),
        issuer_address: Address::new([11u8; 20]),
        issuer_class: PropertyIssuerClass::MortgageLender,
        policy_id: [3u8; 32],
        revocation_ref: None,
        status: EncumbranceStatus::Active,
        created_at: 1_000,
        updated_at: 2_000,
        recorded_at_height: 7,
        agreement_id: Some([0xEEu8; 32]),
        attachments: vec![],
    }
}

fn coverage() -> InsuranceCoverage {
    InsuranceCoverage {
        coverage_id: [12u8; 32],
        asset_id: ASSET,
        coverage_type: CoverageType::Homeowners,
        coverage_commitment: [13u8; 32],
        insurer_ref: PartyRef::Commitment([0xE5; 32]),
        insured_ref: PartyRef::Commitment([0xF6; 32]),
        additional_insureds: vec![],
        limit_commitment: [14u8; 32],
        deductible_commitment: Some([15u8; 32]),
        premium_commitment: None,
        effective_from: 1_000,
        expiry: 9_000_000,
        issuer_address: Address::new([16u8; 20]),
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [3u8; 32],
        revocation_ref: None,
        status: CoverageStatus::Active,
        created_at: 1_000,
        updated_at: 2_000,
        recorded_at_height: 7,
        prior_coverage_id: None,
        attachments: vec![],
    }
}

fn claim() -> InsuranceClaim {
    InsuranceClaim {
        claim_id: [17u8; 32],
        coverage_id: [12u8; 32],
        asset_id: ASSET,
        claim_type: ClaimType::WaterDamage,
        claim_commitment: [18u8; 32],
        claimant_ref: PartyRef::Commitment([0xA7; 32]),
        date_of_loss: 900,
        date_filed: 1_000,
        loss_amount_commitment: Some([19u8; 32]),
        approved_amount_commitment: None,
        paid_amount_commitment: None,
        adjuster_ref: None,
        issuer_address: Address::new([20u8; 20]),
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [3u8; 32],
        revocation_ref: None,
        status: ClaimStatus::Filed,
        created_at: 1_000,
        updated_at: 2_000,
        recorded_at_height: 7,
        related_claims: vec![],
        attachments: vec![],
    }
}

fn proof() -> PropertyProofEnvelope {
    PropertyProofEnvelope {
        proof_id: [21u8; 32],
        profile: PropertyProofProfile::CoverageInForce,
        profile_id: "property.coverage_in_force.v1".to_string(),
        policy_ids: vec![[3u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: PropertyProofType::Groth16,
        subject_nullifier: [22u8; 32],
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

#[test]
fn an_asset_row_is_bincode_at_the_asset_id_key_and_indexes_its_jurisdiction() {
    let (db, _dir) = db();
    let a = asset();
    PropertyStore::new(&db).assets().put(&a).unwrap();

    assert_eq!(
        row(&db, cf::PROPERTY_ASSETS, &[1u8; 32]),
        Some(bincode::serialize(&a).unwrap()),
        "the asset, at its id"
    );
    // The jurisdiction index key is the STRING's bytes -- eight of them here,
    // not thirty-two -- and its value is a one-element list, not a marker.
    assert_eq!(
        row(&db, cf::PROPERTY_JURISDICTION_INDEX, b"US-CA-LA"),
        Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
        "a one-element list at the raw jurisdiction bytes"
    );
    assert_eq!(
        row(&db, cf::PROPERTY_JURISDICTION_INDEX, b"us-ca-la"),
        None,
        "the key is the exact bytes: a different case is a different row"
    );
}

#[test]
fn a_second_asset_in_one_jurisdiction_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let first = asset();
    let mut second = asset();
    second.asset_id = [30u8; 32];

    store.assets().put(&first).unwrap();
    store.assets().put(&second).unwrap();

    let bytes = row(&db, cf::PROPERTY_JURISDICTION_INDEX, b"US-CA-LA").unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[1u8; 32], [30u8; 32]]).unwrap(),
        "both asset ids, in insertion order"
    );
    assert_eq!(
        decode_jurisdiction_asset_ids(&bytes).unwrap(),
        vec![[1u8; 32], [30u8; 32]]
    );
}

#[test]
fn re_putting_the_same_asset_does_not_duplicate_its_index_entry() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let a = asset();
    store.assets().put(&a).unwrap();
    store.assets().put(&a).unwrap();

    assert_eq!(
        row(&db, cf::PROPERTY_JURISDICTION_INDEX, b"US-CA-LA"),
        Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
        "still one element -- the append is guarded by a `contains` check"
    );
}

#[test]
fn a_title_event_row_is_bincode_at_the_event_id_key_and_indexes_its_asset() {
    let (db, _dir) = db();
    let e = title_event();
    PropertyStore::new(&db).title_events().put(&e).unwrap();

    assert_eq!(
        row(&db, cf::PROPERTY_TITLE_EVENTS, &[5u8; 32]),
        Some(bincode::serialize(&e).unwrap()),
        "the event, at its id"
    );
    assert_eq!(
        row(&db, cf::PROPERTY_ASSET_TITLE_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![[5u8; 32]]).unwrap()),
        "a one-element list at the ASSET id, not the event id"
    );
    assert_eq!(
        row(&db, cf::PROPERTY_ASSET_TITLE_INDEX, &[5u8; 32]),
        None,
        "nothing is written at the event id"
    );
}

#[test]
fn a_second_title_event_for_one_asset_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let first = title_event();
    let mut second = title_event();
    second.event_id = [31u8; 32];

    store.title_events().put(&first).unwrap();
    store.title_events().put(&second).unwrap();

    let bytes = row(&db, cf::PROPERTY_ASSET_TITLE_INDEX, &[1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[5u8; 32], [31u8; 32]]).unwrap(),
        "both event ids, in insertion order"
    );
    assert_eq!(
        decode_asset_title_event_ids(&bytes).unwrap(),
        vec![[5u8; 32], [31u8; 32]]
    );
}

#[test]
fn an_encumbrance_row_is_bincode_at_its_id_key_and_indexes_its_asset() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let first = encumbrance();
    let mut second = encumbrance();
    second.encumbrance_id = [32u8; 32];

    store.encumbrances().put(&first).unwrap();
    assert_eq!(
        row(&db, cf::PROPERTY_ENCUMBRANCES, &[8u8; 32]),
        Some(bincode::serialize(&first).unwrap())
    );
    assert_eq!(
        row(&db, cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![[8u8; 32]]).unwrap()),
        "a one-element list at the ASSET id"
    );

    store.encumbrances().put(&second).unwrap();
    let bytes = row(&db, cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX, &[1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[8u8; 32], [32u8; 32]]).unwrap(),
        "both encumbrance ids, in insertion order"
    );
    assert_eq!(
        decode_asset_encumbrance_ids(&bytes).unwrap(),
        vec![[8u8; 32], [32u8; 32]]
    );
}

#[test]
fn a_coverage_row_is_bincode_at_its_id_key_and_indexes_its_asset() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let first = coverage();
    let mut second = coverage();
    second.coverage_id = [33u8; 32];

    store.coverage().put(&first).unwrap();
    assert_eq!(
        row(&db, cf::PROPERTY_COVERAGE, &[12u8; 32]),
        Some(bincode::serialize(&first).unwrap())
    );
    assert_eq!(
        row(&db, cf::PROPERTY_ASSET_COVERAGE_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![[12u8; 32]]).unwrap()),
        "a one-element list at the ASSET id"
    );

    store.coverage().put(&second).unwrap();
    let bytes = row(&db, cf::PROPERTY_ASSET_COVERAGE_INDEX, &[1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[12u8; 32], [33u8; 32]]).unwrap(),
        "both coverage ids, in insertion order"
    );
    assert_eq!(
        decode_asset_coverage_ids(&bytes).unwrap(),
        vec![[12u8; 32], [33u8; 32]]
    );
}

#[test]
fn a_claim_row_is_bincode_at_its_id_key_and_indexes_its_coverage() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let first = claim();
    let mut second = claim();
    second.claim_id = [34u8; 32];

    store.claims().put(&first).unwrap();
    assert_eq!(
        row(&db, cf::PROPERTY_CLAIMS, &[17u8; 32]),
        Some(bincode::serialize(&first).unwrap())
    );
    // The claim index is keyed by COVERAGE, not by asset -- the only index in
    // the subsystem that is not keyed by an asset id or a jurisdiction.
    assert_eq!(
        row(&db, cf::PROPERTY_COVERAGE_CLAIM_INDEX, &[12u8; 32]),
        Some(bincode::serialize(&vec![[17u8; 32]]).unwrap()),
        "a one-element list at the COVERAGE id"
    );
    assert_eq!(
        row(&db, cf::PROPERTY_COVERAGE_CLAIM_INDEX, &[1u8; 32]),
        None,
        "and nothing at the asset id"
    );

    store.claims().put(&second).unwrap();
    let bytes = row(&db, cf::PROPERTY_COVERAGE_CLAIM_INDEX, &[12u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[17u8; 32], [34u8; 32]]).unwrap(),
        "both claim ids, in insertion order"
    );
    assert_eq!(
        decode_coverage_claim_ids(&bytes).unwrap(),
        vec![[17u8; 32], [34u8; 32]]
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index() {
    let (db, _dir) = db();
    let p = proof();
    PropertyStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::PROPERTY_PROOFS, &[21u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    assert_eq!(
        row(&db, cf::PROPERTY_PROOFS, &[22u8; 32]),
        None,
        "the subject nullifier is not a key here"
    );
}

#[test]
fn every_round_trip_returns_the_value_that_was_written() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    let (a, t, e, c, cl, p) = (
        asset(),
        title_event(),
        encumbrance(),
        coverage(),
        claim(),
        proof(),
    );
    store.assets().put(&a).unwrap();
    store.title_events().put(&t).unwrap();
    store.encumbrances().put(&e).unwrap();
    store.coverage().put(&c).unwrap();
    store.claims().put(&cl).unwrap();
    store.proofs().put(&p).unwrap();

    assert_eq!(store.assets().get(&[1u8; 32]).unwrap(), Some(a));
    assert_eq!(store.title_events().get(&[5u8; 32]).unwrap(), Some(t));
    assert_eq!(store.encumbrances().get(&[8u8; 32]).unwrap(), Some(e));
    assert_eq!(store.coverage().get(&[12u8; 32]).unwrap(), Some(c));
    assert_eq!(store.claims().get(&[17u8; 32]).unwrap(), Some(cl));
    assert_eq!(store.proofs().get(&[21u8; 32]).unwrap(), Some(p));
}

#[test]
fn a_malformed_row_is_an_error_from_every_decoding_reader() {
    let (db, _dir) = db();
    let store = PropertyStore::new(&db);
    for (family, key) in [
        (cf::PROPERTY_ASSETS, vec![1u8; 32]),
        (cf::PROPERTY_JURISDICTION_INDEX, b"US-CA-LA".to_vec()),
        (cf::PROPERTY_TITLE_EVENTS, vec![5u8; 32]),
        (cf::PROPERTY_ASSET_TITLE_INDEX, vec![1u8; 32]),
        (cf::PROPERTY_ENCUMBRANCES, vec![8u8; 32]),
        (cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX, vec![1u8; 32]),
        (cf::PROPERTY_COVERAGE, vec![12u8; 32]),
        (cf::PROPERTY_ASSET_COVERAGE_INDEX, vec![1u8; 32]),
        (cf::PROPERTY_CLAIMS, vec![17u8; 32]),
        (cf::PROPERTY_COVERAGE_CLAIM_INDEX, vec![12u8; 32]),
        (cf::PROPERTY_PROOFS, vec![21u8; 32]),
    ] {
        db.put(family, &key, b"not a valid row").unwrap();
    }

    assert!(store.assets().get(&[1u8; 32]).is_err());
    assert!(store.assets().get_by_jurisdiction("US-CA-LA").is_err());
    assert!(store.title_events().get(&[5u8; 32]).is_err());
    assert!(store.title_events().get_by_asset(&[1u8; 32]).is_err());
    assert!(store.encumbrances().get(&[8u8; 32]).is_err());
    assert!(store.encumbrances().get_by_asset(&[1u8; 32]).is_err());
    assert!(store.coverage().get(&[12u8; 32]).is_err());
    assert!(store.coverage().get_by_asset(&[1u8; 32]).is_err());
    assert!(store.claims().get(&[17u8; 32]).is_err());
    assert!(store.claims().get_by_coverage(&[12u8; 32]).is_err());
    assert!(store.proofs().get(&[21u8; 32]).is_err());

    // The `exists` guards do NOT decode, so corruption reads as presence.
    // Preserved deliberately; pinned here and, through dispatch, in
    // `property_routing`.
    assert!(store.assets().exists(&[1u8; 32]).unwrap());
    assert!(store.title_events().exists(&[5u8; 32]).unwrap());
    assert!(store.encumbrances().exists(&[8u8; 32]).unwrap());
    assert!(store.coverage().exists(&[12u8; 32]).unwrap());
    assert!(store.claims().exists(&[17u8; 32]).unwrap());
    assert!(store.proofs().exists(&[21u8; 32]).unwrap());
    // `is_valid` reads through `get`, so it errors rather than answering false.
    assert!(store.proofs().is_valid(&[21u8; 32], 1_500).is_err());
}
