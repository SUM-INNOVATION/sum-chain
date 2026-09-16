//! Agreements: the committed store's rows are exactly what the shared helpers
//! build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_commitment(...)` proves nothing: the
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
//!     commitments      the 32-byte agreement id
//!     party index      the 32-byte party-ref HASH, value a bincode Vec<AgreementId>
//!     signatures       the 32-byte signature id
//!     attestations     the 32-byte attestation id
//!     ip actions       the 32-byte action id
//!     executor links   the 32-byte link id
//!     executor index   the 20-byte executor ADDRESS, value a bincode Vec<ExecutorLinkId>
//!     proofs           the 32-byte proof id
//!
//! The two index families are the ones worth reading twice: different key
//! widths, and list values rather than presence markers.

use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementProofEnvelope, AgreementProofProfile, AgreementProofType,
    AgreementRole, AgreementStatus, AttestationIssuerClass, AttestationPacket, AttestationStatus,
    AttestationTarget, AttestationType, ExecutorLink, ExecutorState, IpActionStatus, IpActionType,
    IpAssetType, IpRightsAction, PartyBinding, PartyRef, PartySignature, SignatureType,
};
use sumchain_primitives::Address;
use sumchain_storage::agreement_store::{decode_agreement_ids, decode_link_ids, AgreementStore};
use sumchain_storage::db::{cf, Database};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

fn commitment() -> AgreementCommitment {
    AgreementCommitment {
        agreement_id: [1u8; 32],
        agreement_commitment: [2u8; 32],
        parties: vec![
            PartyBinding {
                party_ref: PartyRef::Commitment([0xA1; 32]),
                role: AgreementRole::Buyer,
                signed: false,
                signed_at: None,
            },
            PartyBinding {
                party_ref: PartyRef::Commitment([0xB2; 32]),
                role: AgreementRole::Seller,
                signed: true,
                signed_at: Some(1_234),
            },
        ],
        jurisdiction_code: "US-DE".to_string(),
        effective_from: Some(1_000),
        expiry: Some(9_000_000),
        attachments: vec![],
        policy_id: [12u8; 32],
        status: AgreementStatus::PendingSignatures,
        created_at: 1_000,
        updated_at: 2_000,
        created_at_height: 7,
        supersedes: None,
    }
}

fn signature() -> PartySignature {
    PartySignature {
        signature_id: [3u8; 32],
        agreement_id: [1u8; 32],
        party_ref: PartyRef::Commitment([0xA1; 32]),
        role: AgreementRole::Buyer,
        signature_type: SignatureType::Threshold {
            threshold: 2,
            total: 3,
        },
        signature: vec![9u8; 64],
        signer_key: [4u8; 32],
        signed_at: 1_000,
        recorded_at_height: 7,
        witness_attestation_id: Some([5u8; 32]),
    }
}

fn attestation() -> AttestationPacket {
    AttestationPacket {
        attestation_id: [6u8; 32],
        target_ref: AttestationTarget::Agreement([1u8; 32]),
        issuer_address: Address::new([7u8; 20]),
        issuer_class: AttestationIssuerClass::LawFirm,
        attestation_type: AttestationType::Apostille,
        notary_commitment: [8u8; 32],
        jurisdiction_code: "US-NY".to_string(),
        valid_from: 1_000,
        expiry: Some(9_000_000),
        revocation_ref: None,
        status: AttestationStatus::Active,
        created_at: 1_000,
        recorded_at_height: 7,
        policy_id: [12u8; 32],
    }
}

fn ip_action() -> IpRightsAction {
    IpRightsAction {
        action_id: [10u8; 32],
        ip_asset_commitment: [11u8; 32],
        asset_type: IpAssetType::Trademark,
        action_type: IpActionType::ExclusiveLicense,
        scope_commitment: [13u8; 32],
        rightsholder_ref: PartyRef::Commitment([0xA1; 32]),
        counterparty_ref: Some(PartyRef::Commitment([0xB2; 32])),
        policy_id: [12u8; 32],
        valid_from: 1_000,
        expiry: None,
        revocation_ref: Some([14u8; 32]),
        status: IpActionStatus::Active,
        created_at: 1_000,
        recorded_at_height: 7,
        agreement_id: Some([1u8; 32]),
        attachments: vec![],
    }
}

fn executor_link() -> ExecutorLink {
    ExecutorLink {
        link_id: [15u8; 32],
        agreement_id: [1u8; 32],
        executor_contract: Address::new([0xCC; 20]),
        executor_interface_id: [16u8; 32],
        terms_commitment: [17u8; 32],
        activation_policy_id: [12u8; 32],
        state: ExecutorState::Draft,
        created_at: 1_000,
        updated_at: 1_000,
        created_at_height: 7,
        activation_proof_id: None,
    }
}

fn proof() -> AgreementProofEnvelope {
    AgreementProofEnvelope {
        proof_id: [18u8; 32],
        profile: AgreementProofProfile::NotaryAttested,
        profile_id: "agreement.notary_attested.v1".to_string(),
        policy_ids: vec![[12u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: AgreementProofType::Groth16,
        subject_nullifier: [19u8; 32],
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

#[test]
fn a_commitment_row_is_bincode_at_the_agreement_id_key_and_indexes_every_party() {
    let (db, _dir) = db();
    let c = commitment();
    AgreementStore::new(&db).agreements().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_COMMITMENTS, &[1u8; 32]),
        Some(bincode::serialize(&c).unwrap()),
        "the commitment, at its id"
    );
    // One index entry per party, each a ONE-ELEMENT bincode list -- not a
    // presence marker, which is why appending is a read-modify-write.
    for party in [[0xA1u8; 32], [0xB2u8; 32]] {
        assert_eq!(
            row(&db, cf::AGREEMENT_PARTY_INDEX, &party),
            Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
            "a one-element list at party {:#x}",
            party[0]
        );
    }
}

#[test]
fn a_second_agreement_for_one_party_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = AgreementStore::new(&db);
    let first = commitment();
    let mut second = commitment();
    second.agreement_id = [20u8; 32];

    store.agreements().put(&first).unwrap();
    store.agreements().put(&second).unwrap();

    let bytes = row(&db, cf::AGREEMENT_PARTY_INDEX, &[0xA1u8; 32]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[1u8; 32], [20u8; 32]]).unwrap(),
        "both ids, in insertion order"
    );
    assert_eq!(
        decode_agreement_ids(&bytes).unwrap(),
        vec![[1u8; 32], [20u8; 32]]
    );
}

#[test]
fn re_putting_the_same_agreement_does_not_duplicate_its_index_entry() {
    let (db, _dir) = db();
    let store = AgreementStore::new(&db);
    let c = commitment();
    store.agreements().put(&c).unwrap();
    store.agreements().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_PARTY_INDEX, &[0xA1u8; 32]),
        Some(bincode::serialize(&vec![[1u8; 32]]).unwrap()),
        "still one element -- the append is guarded by a `contains` check"
    );
}

#[test]
fn a_signature_row_is_bincode_at_the_signature_id_key() {
    let (db, _dir) = db();
    let s = signature();
    AgreementStore::new(&db).signatures().put(&s).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_SIGNATURES, &[3u8; 32]),
        Some(bincode::serialize(&s).unwrap())
    );
}

#[test]
fn an_attestation_row_is_bincode_at_the_attestation_id_key() {
    let (db, _dir) = db();
    let a = attestation();
    AgreementStore::new(&db).attestations().put(&a).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_ATTESTATIONS, &[6u8; 32]),
        Some(bincode::serialize(&a).unwrap())
    );
}

#[test]
fn an_ip_action_row_is_bincode_at_the_action_id_key() {
    let (db, _dir) = db();
    let a = ip_action();
    AgreementStore::new(&db).ip_actions().put(&a).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_IP_ACTIONS, &[10u8; 32]),
        Some(bincode::serialize(&a).unwrap())
    );
}

#[test]
fn an_executor_link_row_is_bincode_at_the_link_id_key_and_indexes_its_contract() {
    let (db, _dir) = db();
    let l = executor_link();
    AgreementStore::new(&db).executor_links().put(&l).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_EXECUTOR_LINKS, &[15u8; 32]),
        Some(bincode::serialize(&l).unwrap()),
        "the link, at its id"
    );
    // Twenty bytes of key, not thirty-two: the executor index is keyed by
    // ADDRESS.
    assert_eq!(
        row(&db, cf::AGREEMENT_EXECUTOR_INDEX, &[0xCCu8; 20]),
        Some(bincode::serialize(&vec![[15u8; 32]]).unwrap()),
        "and a one-element list at the executor address"
    );
    assert_eq!(
        row(&db, cf::AGREEMENT_EXECUTOR_INDEX, &[0xCCu8; 32]),
        None,
        "nothing is written at a 32-byte spelling of the same address"
    );
}

#[test]
fn a_second_link_for_one_contract_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = AgreementStore::new(&db);
    let first = executor_link();
    let mut second = executor_link();
    second.link_id = [21u8; 32];

    store.executor_links().put(&first).unwrap();
    store.executor_links().put(&second).unwrap();

    let bytes = row(&db, cf::AGREEMENT_EXECUTOR_INDEX, &[0xCCu8; 20]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&vec![[15u8; 32], [21u8; 32]]).unwrap(),
        "both link ids, in insertion order"
    );
    assert_eq!(
        decode_link_ids(&bytes).unwrap(),
        vec![[15u8; 32], [21u8; 32]]
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index() {
    let (db, _dir) = db();
    let p = proof();
    AgreementStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::AGREEMENT_PROOFS, &[18u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    // Unlike tax, an agreement proof is NOT indexed by its subject nullifier.
    assert_eq!(
        row(&db, cf::AGREEMENT_PROOFS, &[19u8; 32]),
        None,
        "the subject nullifier is not a key here"
    );
}

#[test]
fn every_round_trip_returns_the_value_that_was_written() {
    let (db, _dir) = db();
    let store = AgreementStore::new(&db);
    let (c, s, a, i, l, p) = (
        commitment(),
        signature(),
        attestation(),
        ip_action(),
        executor_link(),
        proof(),
    );
    store.agreements().put(&c).unwrap();
    store.signatures().put(&s).unwrap();
    store.attestations().put(&a).unwrap();
    store.ip_actions().put(&i).unwrap();
    store.executor_links().put(&l).unwrap();
    store.proofs().put(&p).unwrap();

    assert_eq!(store.agreements().get(&[1u8; 32]).unwrap(), Some(c));
    assert_eq!(store.signatures().get(&[3u8; 32]).unwrap(), Some(s));
    assert_eq!(store.attestations().get(&[6u8; 32]).unwrap(), Some(a));
    assert_eq!(store.ip_actions().get(&[10u8; 32]).unwrap(), Some(i));
    assert_eq!(store.executor_links().get(&[15u8; 32]).unwrap(), Some(l));
    assert_eq!(store.proofs().get(&[18u8; 32]).unwrap(), Some(p));
}

#[test]
fn a_malformed_row_is_an_error_from_every_decoding_reader() {
    let (db, _dir) = db();
    let store = AgreementStore::new(&db);
    for (family, key) in [
        (cf::AGREEMENT_COMMITMENTS, vec![1u8; 32]),
        (cf::AGREEMENT_PARTY_INDEX, vec![0xA1u8; 32]),
        (cf::AGREEMENT_SIGNATURES, vec![3u8; 32]),
        (cf::AGREEMENT_ATTESTATIONS, vec![6u8; 32]),
        (cf::AGREEMENT_IP_ACTIONS, vec![10u8; 32]),
        (cf::AGREEMENT_EXECUTOR_LINKS, vec![15u8; 32]),
        (cf::AGREEMENT_EXECUTOR_INDEX, vec![0xCCu8; 20]),
        (cf::AGREEMENT_PROOFS, vec![18u8; 32]),
    ] {
        db.put(family, &key, b"not a valid row").unwrap();
    }

    assert!(store.agreements().get(&[1u8; 32]).is_err());
    assert!(store.agreements().get_by_party(&[0xA1u8; 32]).is_err());
    assert!(store.signatures().get(&[3u8; 32]).is_err());
    assert!(store.attestations().get(&[6u8; 32]).is_err());
    assert!(store.ip_actions().get(&[10u8; 32]).is_err());
    assert!(store.executor_links().get(&[15u8; 32]).is_err());
    assert!(store
        .executor_links()
        .get_by_executor(&Address::new([0xCC; 20]))
        .is_err());
    assert!(store.proofs().get(&[18u8; 32]).is_err());

    // The `exists` guards do NOT decode, so corruption reads as presence.
    // Preserved deliberately; pinned here and, through dispatch, in
    // `agreement_routing`.
    assert!(store.agreements().exists(&[1u8; 32]).unwrap());
    assert!(store.signatures().exists(&[3u8; 32]).unwrap());
    assert!(store.attestations().exists(&[6u8; 32]).unwrap());
    assert!(store.ip_actions().exists(&[10u8; 32]).unwrap());
    assert!(store.executor_links().exists(&[15u8; 32]).unwrap());
    assert!(store.proofs().exists(&[18u8; 32]).unwrap());
}
