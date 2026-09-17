//! Healthcare: the committed store's rows are exactly what the shared helpers
//! build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_provider(...)` proves nothing: the
//! store CALLS that helper, so a wrong helper moves both sides of the assertion
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
//!     providers          the 32-byte provider id
//!     network index      the 32-byte PLAN id, value a bincode Vec<ProviderId>
//!     memberships        the 32-byte membership id
//!     member index       the 32-byte member NULLIFIER, value Vec<MembershipId>
//!     consents           the 32-byte consent id
//!     subject index      the 32-byte subject NULLIFIER, value Vec<ConsentId>
//!     prescriptions      the 32-byte prescription id
//!     patient index      the 32-byte patient NULLIFIER, value Vec<PrescriptionId>
//!     prescriber index   the 32-byte prescriber PROVIDER id, value Vec<PrescriptionId>
//!     proofs             the 32-byte proof id
//!
//! The five index families are the ones worth reading twice. Every key is 32
//! bytes wide, which is exactly why they are easy to confuse: the network index
//! is keyed by the PLAN and not by the provider whose affiliation caused the
//! write, and the prescriber index is keyed by a provider id where its
//! neighbour is keyed by a nullifier. A builder that took the wrong one of two
//! same-width arguments would be invisible to a shape check.

use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareIssuerClass, HealthcareProofEnvelope, HealthcareProofProfile, HealthcareProofType,
    MembershipRecord, MembershipStatus, MembershipType, Prescription, PrescriptionStatus,
    PrescriptionType, ProviderProfile, ProviderStatus, ProviderType,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::healthcare_store::{
    decode_consent_ids, decode_membership_ids, decode_prescription_ids, decode_provider_ids,
    HealthcareStore,
};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

/// A provider affiliated with TWO plans, so `put` writes two index entries.
fn provider() -> ProviderProfile {
    ProviderProfile {
        provider_id: [1u8; 32],
        provider_commitment: [2u8; 32],
        provider_type: ProviderType::Hospital,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: Some([3u8; 32]),
        credentials_commitment: None,
        policy_id: [4u8; 32],
        issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
        issuer_address: Address::new([5u8; 20]),
        status: ProviderStatus::Active,
        created_at: 1_000,
        updated_at: 2_000,
        registered_at_height: 7,
        network_affiliations: vec![[0xC1; 32], [0xC2; 32]],
        attachments: vec![],
    }
}

fn membership() -> MembershipRecord {
    MembershipRecord {
        membership_id: [6u8; 32],
        provider_id: [1u8; 32],
        membership_type: MembershipType::IndividualHealth,
        membership_commitment: [7u8; 32],
        member_ref: PartyRef::Commitment([8u8; 32]),
        member_address: Address::new([9u8; 20]),
        member_nullifier: [0xD1; 32],
        coverage_tier: Some(CoverageTier::Individual),
        group_commitment: None,
        effective_from: 1_000,
        expiry: Some(9_000_000),
        issuer_address: Address::new([10u8; 20]),
        issuer_class: HealthcareIssuerClass::InsuranceCompany,
        policy_id: [11u8; 32],
        revocation_ref: None,
        status: MembershipStatus::Active,
        created_at: 1_000,
        updated_at: 2_000,
        issued_at_height: 7,
        prior_membership_id: None,
        dependents: vec![[12u8; 32]],
        attachments: vec![],
    }
}

fn consent() -> ConsentEnvelope {
    ConsentEnvelope {
        consent_id: [13u8; 32],
        consent_type: ConsentType::HipaaAuthorization,
        consent_commitment: [14u8; 32],
        subject_ref: PartyRef::Commitment([15u8; 32]),
        subject_address: Address::new([16u8; 20]),
        subject_nullifier: [0xE1; 32],
        recipient_ref: PartyRef::Commitment([17u8; 32]),
        purpose_commitment: [18u8; 32],
        scope: DisclosureScope::TreatmentOnly,
        scope_commitment: None,
        effective_from: 1_000,
        expiry: Some(9_000_000),
        issuer_address: Address::new([19u8; 20]),
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [20u8; 32],
        revocation_ref: None,
        status: ConsentStatus::Granted,
        created_at: 1_000,
        updated_at: 2_000,
        recorded_at_height: 7,
        supersedes: None,
        attachments: vec![],
    }
}

fn prescription() -> Prescription {
    Prescription {
        prescription_id: [21u8; 32],
        prescription_type: PrescriptionType::StandardPrescription,
        prescription_commitment: [22u8; 32],
        patient_ref: PartyRef::Commitment([23u8; 32]),
        patient_address: Address::new([24u8; 20]),
        patient_nullifier: [0xF1; 32],
        prescriber_ref: PartyRef::Commitment([25u8; 32]),
        // The prescriber index is keyed by THIS, and it is a provider id.
        prescriber_provider_id: [1u8; 32],
        pharmacy_ref: None,
        medication_commitment: [26u8; 32],
        quantity_commitment: [27u8; 32],
        days_supply_commitment: None,
        refills_authorized: 3,
        refills_remaining: 3,
        is_controlled: false,
        date_written: 900,
        effective_from: Some(1_000),
        expiry: 9_000_000,
        issuer_address: Address::new([28u8; 20]),
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [29u8; 32],
        revocation_ref: None,
        status: PrescriptionStatus::Active,
        created_at: 900,
        updated_at: 900,
        recorded_at_height: 7,
        supersedes: None,
        fill_history: vec![],
        attachments: vec![],
    }
}

fn proof() -> HealthcareProofEnvelope {
    HealthcareProofEnvelope {
        proof_id: [30u8; 32],
        profile: HealthcareProofProfile::ConsentValid,
        profile_id: "healthcare.consent_valid.v1".to_string(),
        policy_ids: vec![[20u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: HealthcareProofType::Groth16,
        subject_nullifier: [0xE1; 32],
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

#[test]
fn a_provider_row_is_bincode_at_the_provider_id_key_and_indexes_every_plan() {
    let (db, _dir) = db();
    let p = provider();
    HealthcareStore::new(&db).providers().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDERS, &[1u8; 32]),
        Some(bincode::serialize(&p).unwrap()),
        "the provider, at its id"
    );
    // One index entry per PLAN, each a ONE-ELEMENT bincode list of PROVIDER
    // ids -- not a presence marker, which is why appending is a
    // read-modify-write.
    for plan in [[0xC1u8; 32], [0xC2u8; 32]] {
        assert_eq!(
            row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &plan),
            Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
            "a one-element list of providers at plan {:#x}",
            plan[0]
        );
    }
    // And nothing at the PROVIDER's own id, which is the confusion this
    // same-width key layout invites.
    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &[1u8; 32]),
        None,
        "the network index is keyed by the plan, not by the provider"
    );
}

#[test]
fn a_second_provider_in_one_plan_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let first = provider();
    let mut second = provider();
    second.provider_id = [31u8; 32];

    store.providers().put(&first).unwrap();
    store.providers().put(&second).unwrap();

    let bytes = row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &[0xC1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[1u8; 32], [31u8; 32]]).unwrap(),
        "both provider ids, in insertion order"
    );
    assert_eq!(
        decode_provider_ids(&bytes).unwrap(),
        vec![[1u8; 32], [31u8; 32]]
    );
}

#[test]
fn re_putting_the_same_provider_does_not_duplicate_its_index_entry() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let p = provider();
    store.providers().put(&p).unwrap();
    store.providers().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &[0xC1u8; 32]),
        Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
        "still one element -- the append is guarded by a `contains` check"
    );
}

/// The network index is the only one with a REMOVE, and that remove is
/// UNCONDITIONAL: it re-serializes whatever survives the `retain` and writes
/// it, so taking away an affiliation that was never recorded creates an empty
/// list row where there was none.
///
/// Preserved, not fixed. Pinned here as bytes.
#[test]
fn removing_an_affiliation_that_was_never_there_still_writes_an_empty_index() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let mut p = provider();
    p.network_affiliations = vec![];
    store.providers().put(&p).unwrap();
    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &[0xC9u8; 32]),
        None,
        "no index row for a plan this provider never joined"
    );

    store
        .providers()
        .remove_network_affiliation(&[1u8; 32], &[0xC9; 32], 3_000)
        .unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &[0xC9u8; 32]),
        Some(bincode::serialize(&Vec::<[u8; 32]>::new()).unwrap()),
        "an EMPTY list is now written at a plan the provider was never in"
    );
    let mut expected = p.clone();
    expected.updated_at = 3_000;
    assert_eq!(
        row(&db, cf::HEALTHCARE_PROVIDERS, &[1u8; 32]),
        Some(bincode::serialize(&expected).unwrap()),
        "and the provider row is rewritten with a bumped updated_at"
    );
}

#[test]
fn a_membership_row_is_bincode_at_the_membership_id_key_and_indexes_its_member() {
    let (db, _dir) = db();
    let m = membership();
    HealthcareStore::new(&db).memberships().put(&m).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_MEMBERSHIPS, &[6u8; 32]),
        Some(bincode::serialize(&m).unwrap())
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_MEMBER_INDEX, &[0xD1u8; 32]),
        Some(bincode::serialize(&vec![[6u8; 32]]).unwrap()),
        "a one-element list at the member NULLIFIER"
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_MEMBER_INDEX, &[6u8; 32]),
        None,
        "and nothing at the membership id"
    );
}

#[test]
fn a_second_membership_for_one_member_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let first = membership();
    let mut second = membership();
    second.membership_id = [32u8; 32];

    store.memberships().put(&first).unwrap();
    store.memberships().put(&second).unwrap();

    let bytes = row(&db, cf::HEALTHCARE_MEMBER_INDEX, &[0xD1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[6u8; 32], [32u8; 32]]).unwrap()
    );
    assert_eq!(
        decode_membership_ids(&bytes).unwrap(),
        vec![[6u8; 32], [32u8; 32]]
    );
}

#[test]
fn a_consent_row_is_bincode_at_the_consent_id_key_and_indexes_its_subject() {
    let (db, _dir) = db();
    let c = consent();
    HealthcareStore::new(&db).consents().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_CONSENTS, &[13u8; 32]),
        Some(bincode::serialize(&c).unwrap())
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, &[0xE1u8; 32]),
        Some(bincode::serialize(&vec![[13u8; 32]]).unwrap()),
        "a one-element list at the subject NULLIFIER"
    );
}

#[test]
fn a_second_consent_for_one_subject_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let first = consent();
    let mut second = consent();
    second.consent_id = [33u8; 32];

    store.consents().put(&first).unwrap();
    store.consents().put(&second).unwrap();

    let bytes = row(&db, cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, &[0xE1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[13u8; 32], [33u8; 32]]).unwrap()
    );
    assert_eq!(
        decode_consent_ids(&bytes).unwrap(),
        vec![[13u8; 32], [33u8; 32]]
    );
}

#[test]
fn a_prescription_row_is_bincode_and_indexes_both_its_patient_and_its_prescriber() {
    let (db, _dir) = db();
    let p = prescription();
    HealthcareStore::new(&db).prescriptions().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_PRESCRIPTIONS, &[21u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_PATIENT_RX_INDEX, &[0xF1u8; 32]),
        Some(bincode::serialize(&vec![[21u8; 32]]).unwrap()),
        "at the patient NULLIFIER"
    );
    // A provider id, not a nullifier, and not the patient's.
    assert_eq!(
        row(&db, cf::HEALTHCARE_PRESCRIBER_RX_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![[21u8; 32]]).unwrap()),
        "at the prescriber PROVIDER id"
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_PRESCRIBER_RX_INDEX, &[0xF1u8; 32]),
        None,
        "the prescriber index is not keyed by the patient nullifier"
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_PATIENT_RX_INDEX, &[1u8; 32]),
        None,
        "and the patient index is not keyed by the provider id"
    );
}

#[test]
fn a_second_prescription_appends_to_both_of_its_lists() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let first = prescription();
    let mut second = prescription();
    second.prescription_id = [34u8; 32];

    store.prescriptions().put(&first).unwrap();
    store.prescriptions().put(&second).unwrap();

    for (family, key) in [
        (cf::HEALTHCARE_PATIENT_RX_INDEX, [0xF1u8; 32]),
        (cf::HEALTHCARE_PRESCRIBER_RX_INDEX, [1u8; 32]),
    ] {
        let bytes = row(&db, family, &key).unwrap();
        assert_eq!(
            bytes,
            bincode::serialize(&vec![[21u8; 32], [34u8; 32]]).unwrap(),
            "{family}: both ids, in insertion order"
        );
        assert_eq!(
            decode_prescription_ids(&bytes).unwrap(),
            vec![[21u8; 32], [34u8; 32]]
        );
    }
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index() {
    let (db, _dir) = db();
    let p = proof();
    HealthcareStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::HEALTHCARE_PROOFS, &[30u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    // The subject nullifier is carried and is NOT a key: unlike tax, a
    // healthcare proof is not indexed by its subject.
    assert_eq!(
        row(&db, cf::HEALTHCARE_PROOFS, &[0xE1u8; 32]),
        None,
        "the subject nullifier is not a key here"
    );
    assert_eq!(
        row(&db, cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, &[0xE1u8; 32]),
        None,
        "and a proof writes nothing into the consent subject index either"
    );
}

/// `record_fill` derives BOTH the refill counter and the status from the row it
/// read, and writes them together. Expectations built by hand.
#[test]
fn recording_a_fill_decrements_the_counter_and_derives_the_status() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    store.prescriptions().put(&prescription()).unwrap();

    for (n, (fill, refills, status)) in [
        ([40u8; 32], 2u8, PrescriptionStatus::PartiallyFilled),
        ([41u8; 32], 1, PrescriptionStatus::PartiallyFilled),
        ([42u8; 32], 0, PrescriptionStatus::Filled),
    ]
    .into_iter()
    .enumerate()
    {
        store
            .prescriptions()
            .record_fill(&[21u8; 32], fill, 3_000 + n as u64)
            .unwrap();
        let mut expected = prescription();
        expected.fill_history = (0..=n).map(|i| [40u8 + i as u8; 32]).collect();
        expected.refills_remaining = refills;
        expected.status = status;
        expected.updated_at = 3_000 + n as u64;
        assert_eq!(
            row(&db, cf::HEALTHCARE_PRESCRIPTIONS, &[21u8; 32]),
            Some(bincode::serialize(&expected).unwrap()),
            "fill {n}: the whole row, byte for byte"
        );
    }

    // A fourth fill: zero refills and status Filled, so the guard refuses.
    let err = store
        .prescriptions()
        .record_fill(&[21u8; 32], [43u8; 32], 4_000)
        .unwrap_err();
    assert!(
        err.to_string().contains("No refills remaining"),
        "the store's own guard, verbatim: {err}"
    );
}

#[test]
fn every_round_trip_returns_the_value_that_was_written() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    let (pr, m, c, rx, pf) = (provider(), membership(), consent(), prescription(), proof());
    store.providers().put(&pr).unwrap();
    store.memberships().put(&m).unwrap();
    store.consents().put(&c).unwrap();
    store.prescriptions().put(&rx).unwrap();
    store.proofs().put(&pf).unwrap();

    assert_eq!(store.providers().get(&[1u8; 32]).unwrap(), Some(pr));
    assert_eq!(store.memberships().get(&[6u8; 32]).unwrap(), Some(m));
    assert_eq!(store.consents().get(&[13u8; 32]).unwrap(), Some(c));
    assert_eq!(store.prescriptions().get(&[21u8; 32]).unwrap(), Some(rx));
    assert_eq!(store.proofs().get(&[30u8; 32]).unwrap(), Some(pf));
}

#[test]
fn a_malformed_row_is_an_error_from_every_decoding_reader() {
    let (db, _dir) = db();
    let store = HealthcareStore::new(&db);
    for (family, key) in [
        (cf::HEALTHCARE_PROVIDERS, [1u8; 32]),
        (cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, [0xC1u8; 32]),
        (cf::HEALTHCARE_MEMBERSHIPS, [6u8; 32]),
        (cf::HEALTHCARE_MEMBER_INDEX, [0xD1u8; 32]),
        (cf::HEALTHCARE_CONSENTS, [13u8; 32]),
        (cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, [0xE1u8; 32]),
        (cf::HEALTHCARE_PRESCRIPTIONS, [21u8; 32]),
        (cf::HEALTHCARE_PATIENT_RX_INDEX, [0xF1u8; 32]),
        (cf::HEALTHCARE_PRESCRIBER_RX_INDEX, [1u8; 32]),
        (cf::HEALTHCARE_PROOFS, [30u8; 32]),
    ] {
        db.put(family, &key, b"not a valid row").unwrap();
    }

    assert!(store.providers().get(&[1u8; 32]).is_err());
    assert!(store.providers().get_by_network(&[0xC1; 32]).is_err());
    assert!(store.memberships().get(&[6u8; 32]).is_err());
    assert!(store.memberships().get_by_member(&[0xD1; 32]).is_err());
    assert!(store.consents().get(&[13u8; 32]).is_err());
    assert!(store.consents().get_by_subject(&[0xE1; 32]).is_err());
    assert!(store.prescriptions().get(&[21u8; 32]).is_err());
    assert!(store.prescriptions().get_by_patient(&[0xF1; 32]).is_err());
    assert!(store.prescriptions().get_by_prescriber(&[1u8; 32]).is_err());
    assert!(store.proofs().get(&[30u8; 32]).is_err());

    // The `exists` guards do NOT decode, so corruption reads as presence.
    // Preserved deliberately; pinned here and, through dispatch, in
    // `healthcare_routing`.
    assert!(store.providers().exists(&[1u8; 32]).unwrap());
    assert!(store.memberships().exists(&[6u8; 32]).unwrap());
    assert!(store.consents().exists(&[13u8; 32]).unwrap());
    assert!(store.prescriptions().exists(&[21u8; 32]).unwrap());
    assert!(store.proofs().exists(&[30u8; 32]).unwrap());

    // `is_valid` DOES decode, and is the one proof reader that errors.
    assert!(store.proofs().is_valid(&[30u8; 32], 1_500).is_err());
}
