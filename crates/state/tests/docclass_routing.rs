//! SRC-80X/81X DocClass routed through the block's candidate.
//!
//! Every test here drives a REAL `BlockExecutor` transaction, on one of the two
//! dispatch surfaces, against one candidate. Nothing calls a view accessor to
//! stage a row: if a family appears in a candidate it is because a transaction
//! put it there.
//!
//! ## What a same-block claim has to prove
//!
//! Every "the second transaction sees the first" test here is paired with a
//! NEGATIVE DISCRIMINATOR: the same later transaction, in a block WITHOUT the
//! earlier one, which must fail or observe the parent's state. Without the pair
//! a passing test proves only that the later transaction succeeds, which it
//! would also do if it read committed state and found what it needed there.
//!
//! ## Reading the candidate
//!
//! `prefix_iter` on an `ExecutionView` is MERGED with committed state, so
//! presence in a scan proves nothing about what this block did.
//! [`families_changed`] is a real per-CF diff against the database and is what
//! the abandonment and corrupt-row tests assert on.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    AcademicCredential, Address, CredentialAttribute, CredentialMetadata, DocClassEvent,
    DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData,
    DocSubcode, EligibilityAttestation, EligibilityType, IdentityKey, IdentityRoot, IdentityStatus,
    IssuerKey, KeyPurpose, KeyType, RevocationReason, RevocationStatus, ServiceEndpoint,
    SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{DocClassExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore};

/// The eight families this unit moved, in the order `families_changed` reports
/// them. The corrupt-row cases name subsets of this list with `assert_eq!`, so
/// the order is part of the contract those assertions rest on.
const DOCCLASS_CFS: &[&str] = &[
    cf::DOCCLASS_IDENTITY_ROOTS,
    cf::DOCCLASS_ELIGIBILITY,
    cf::DOCCLASS_CREDENTIALS,
    cf::DOCCLASS_REVOCATIONS,
    cf::DOCCLASS_ISSUERS,
    cf::DOCCLASS_SUBJECT_INDEX,
    cf::DOCCLASS_ISSUER_INDEX,
    cf::DOCCLASS_EVENTS,
];

const JURISDICTION: &str = "US";
/// DocClass's own failure code on both dispatch arms.
const DOCCLASS_FAILED: TxStatus = TxStatus::Failed(8);

/// `min_issuer_stake` defaults to 10^12 base units, and `register_issuer`
/// DEDUCTS the declared stake on top of the fee. Zeroing it here keeps the
/// fixtures about routing; `the_minimum_issuer_stake_is_checked_only_at_registration`
/// sets it back and pins what the check does.
fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

fn params_with_stake(min_issuer_stake: u128) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = min_issuer_stake;
    }
    p
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    operation: DocClassOperation,
    subcode: DocSubcode,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

// ── Payload shapes ──────────────────────────────────────────────────────────
//
// The executor deserializes each operation into a private struct declared
// inside its handler. These are the serializing mirrors, field for field and in
// order, because bincode structs are positional: a field reordered here is a
// different payload.

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

#[derive(serde::Serialize)]
struct RemoveKeyData {
    identity_id: [u8; 32],
    key_id: String,
}

#[derive(serde::Serialize)]
struct RotateKeyData {
    identity_id: [u8; 32],
    old_key_id: String,
    new_key: IdentityKey,
}

#[derive(serde::Serialize)]
struct ControllerData {
    identity_id: [u8; 32],
    controller: Address,
}

#[derive(serde::Serialize)]
struct UpdateServiceData {
    identity_id: [u8; 32],
    service: ServiceEndpoint,
}

#[derive(serde::Serialize)]
struct IdentityIdData {
    identity_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct CredentialIdData {
    credential_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct ReasonedData {
    credential_id: [u8; 32],
    reason: RevocationReason,
}

#[derive(serde::Serialize)]
struct SupersedeData {
    old_credential_id: [u8; 32],
    new_credential_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct IssuerRotateKeyData {
    new_key: IssuerKey,
    old_key_id: String,
}

#[derive(serde::Serialize)]
struct DeactivateIssuerData {
    issuer_address: Address,
}

// ── Row fixtures ────────────────────────────────────────────────────────────

fn identity_key(id: &str, byte: u8) -> IdentityKey {
    IdentityKey {
        key_id: id.to_string(),
        key_type: KeyType::Ed25519,
        public_key: [byte; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn issuer_key(id: &str, byte: u8, is_primary: bool) -> IssuerKey {
    IssuerKey {
        key_id: id.to_string(),
        public_key: [byte; 32],
        key_type: KeyType::Ed25519,
        added_at: 1_000,
        expires_at: 0,
        active: true,
        is_primary,
    }
}

fn service(id: &str, endpoint: &str) -> ServiceEndpoint {
    ServiceEndpoint {
        service_id: id.to_string(),
        service_type: "CredentialRegistry".to_string(),
        endpoint: endpoint.to_string(),
        description: None,
    }
}

fn identity(id: u8, controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id: [id; 32],
        subject_commitment: [id.wrapping_add(0x40); 32],
        controller,
        additional_controllers: vec![],
        keys: vec![identity_key("auth-1", id.wrapping_add(1))],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

fn government_issuer(address: Address) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Registry of Vital Records".to_string(),
        issuer_type: DocClassIssuerType::Government,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
        keys: vec![issuer_key("gov-1", 0x51, true)],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

fn educational_issuer(address: Address) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Institute of Technology".to_string(),
        issuer_type: DocClassIssuerType::Educational,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: vec![DocSubcode::Diploma],
        keys: vec![issuer_key("edu-1", 0x52, true)],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

fn eligibility(id: u8, issuer: Address) -> EligibilityAttestation {
    EligibilityAttestation {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::EligibilityAttestation,
        subject_commitment: [id.wrapping_add(0x40); 32],
        issuer,
        jurisdiction: JURISDICTION.to_string(),
        eligibility_type: EligibilityType::Citizenship,
        schema_hash: [0x61; 32],
        content_commitment: [0x62; 32],
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: "gov-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn credential(id: u8, issuer: Address) -> AcademicCredential {
    AcademicCredential {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::Diploma,
        subject_commitment: [id.wrapping_add(0x40); 32],
        issuer,
        institution_id: "IOT".to_string(),
        jurisdiction: JURISDICTION.to_string(),
        schema_hash: [0x71; 32],
        content_commitment: [0x72; 32],
        metadata: CredentialMetadata {
            title: "Bachelor of Science".to_string(),
            credential_type: "undergraduate_degree".to_string(),
            program: None,
            issue_date: "2024-05-15".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "honors".to_string(),
                value: "none".to_string(),
            }],
        },
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: "edu-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

// ── Canonical / candidate comparison ────────────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in DOCCLASS_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// A real per-CF diff, not a presence check: `prefix_iter` on a view is MERGED
/// with committed state, so presence proves nothing about what this block did.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in DOCCLASS_CFS {
        let committed: Vec<(Vec<u8>, Vec<u8>)> = db
            .prefix_iter(f, &[])
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let staged: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iter(f, &[])
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();
        if committed != staged {
            out.push(*f);
        }
    }
    out
}

// ── Same-block visibility, each with its negative discriminator ─────────────

/// An issuer registered a moment earlier in the same block can issue.
///
/// `issue_eligibility` guards on `can_issue_subcode`, which reads the ISSUERS
/// family. Against committed state the guard would read the parent's empty
/// registry and refuse.
#[test]
fn an_issuer_registered_earlier_in_the_block_can_issue_a_credential() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        for t in [
            tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &government_issuer(gov.address()),
            ),
            tx(
                &gov,
                1,
                DocClassOperation::IssueCredential,
                DocSubcode::EligibilityAttestation,
                &eligibility(0x10, gov.address()),
            ),
        ] {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let stored = DocClassExecutor::v_get_eligibility(&view, &[0x10; 32])
            .unwrap()
            .expect("the attestation is in the candidate");
        assert_eq!(stored.issuer, gov.address());
        assert_eq!(
            DocClassExecutor::v_get_issuer_credential_ids(&view, &gov.address()).unwrap(),
            vec![[0x10u8; 32]]
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

/// The discriminator: the same issue, in a block that did NOT register.
#[test]
fn without_the_registration_the_same_issue_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &gov,
        0,
        DocClassOperation::IssueCredential,
        DocSubcode::EligibilityAttestation,
        &eligibility(0x10, gov.address()),
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(
        r.status, DOCCLASS_FAILED,
        "an unregistered issuer is refused"
    );
    assert!(DocClassExecutor::v_get_eligibility(&view, &[0x10; 32])
        .unwrap()
        .is_none());
    assert_eq!(
        StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
        0,
        "and the refusal advances nothing"
    );
}

/// An identity created a moment earlier in the same block accepts a key.
#[test]
fn an_identity_created_earlier_in_the_block_accepts_a_key() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity(0x20, actor.address()),
        ),
        tx(
            &actor,
            1,
            DocClassOperation::AddKey,
            DocSubcode::IdentityRoot,
            &AddKeyData {
                identity_id: [0x20; 32],
                key: identity_key("auth-2", 0x81),
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let root = DocClassExecutor::v_get_identity_root(&view, &[0x20; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        root.keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["auth-1", "auth-2"]
    );
}

/// The discriminator: the same key addition without the creation.
#[test]
fn without_the_creation_the_same_key_addition_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &actor,
        0,
        DocClassOperation::AddKey,
        DocSubcode::IdentityRoot,
        &AddKeyData {
            identity_id: [0x20; 32],
            key: identity_key("auth-2", 0x81),
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// Two key additions in one block both survive.
///
/// This is the read-modify-write case: each `AddKey` reads the whole identity,
/// pushes one key and writes the row back. Against committed state the second
/// would read the block's starting row and drop the first key.
#[test]
fn two_key_additions_in_one_block_both_survive() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .identity_roots()
        .put(&identity(0x21, actor.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, key_id, byte) in [(0u64, "auth-2", 0x82u8), (1, "auth-3", 0x83)] {
        let t = tx(
            &actor,
            nonce,
            DocClassOperation::AddKey,
            DocSubcode::IdentityRoot,
            &AddKeyData {
                identity_id: [0x21; 32],
                key: identity_key(key_id, byte),
            },
        );
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let root = DocClassExecutor::v_get_identity_root(&view, &[0x21; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        root.keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["auth-1", "auth-2", "auth-3"],
        "the second addition read the row the first one staged"
    );
}

/// The discriminator: the SECOND addition alone leaves one added key, not two.
#[test]
fn without_the_first_addition_the_second_leaves_only_its_own_key() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .identity_roots()
        .put(&identity(0x21, actor.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &actor,
        0,
        DocClassOperation::AddKey,
        DocSubcode::IdentityRoot,
        &AddKeyData {
            identity_id: [0x21; 32],
            key: identity_key("auth-3", 0x83),
        },
    );
    executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();

    let root = DocClassExecutor::v_get_identity_root(&view, &[0x21; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        root.keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["auth-1", "auth-3"],
        "the parent's one key plus this one, and nothing from a transaction \
         that did not run"
    );
}

/// Suspend then reactivate in one block: the reactivation's guard reads the
/// suspension this block staged a moment earlier.
///
/// `reactivate_credential` refuses unless `get_status` says `Suspended`, and
/// `get_status` is a prefix scan over `DOCCLASS_REVOCATIONS` sorted by height.
#[test]
fn suspend_then_reactivate_in_one_block_reactivates_the_credential() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x30, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let suspend = tx(
        &gov,
        0,
        DocClassOperation::SuspendCredential,
        DocSubcode::Revocation,
        &ReasonedData {
            credential_id: [0x30; 32],
            reason: RevocationReason::CertificateHold,
        },
    );
    let r = executor
        .execute_tx(&mut view, &suspend, &proposer, 7, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x30; 32]).unwrap(),
        RevocationStatus::Suspended
    );

    // A different HEIGHT, so the reactivation writes its own row rather than
    // overwriting the suspension's.
    let reactivate = tx(
        &gov,
        1,
        DocClassOperation::ReactivateCredential,
        DocSubcode::Revocation,
        &CredentialIdData {
            credential_id: [0x30; 32],
        },
    );
    let r = executor
        .execute_tx(&mut view, &reactivate, &proposer, 8, 1000)
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the reactivation must see the suspension this block staged: {:?}",
        r.status
    );
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x30; 32]).unwrap(),
        RevocationStatus::Active
    );
    assert_eq!(
        DocClassExecutor::v_get_eligibility(&view, &[0x30; 32])
            .unwrap()
            .unwrap()
            .revocation_status,
        RevocationStatus::Active,
        "and the mirror on the attestation row moved with it"
    );
}

/// The discriminator: without the suspension the same reactivation is refused.
#[test]
fn without_the_suspension_the_same_reactivation_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x30, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let reactivate = tx(
        &gov,
        0,
        DocClassOperation::ReactivateCredential,
        DocSubcode::Revocation,
        &CredentialIdData {
            credential_id: [0x30; 32],
        },
    );
    let r = executor
        .execute_tx(&mut view, &reactivate, &proposer, 8, 1000)
        .unwrap();
    assert_eq!(
        r.status, DOCCLASS_FAILED,
        "only suspended can be reactivated"
    );
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
    assert_eq!(
        StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
        0,
        "the status guard runs BEFORE the fee"
    );
}

/// A credential issued a moment earlier in the same block can be revoked.
///
/// `check_revoke_auth` reads the credential itself and compares its issuer to
/// the sender, so against committed state it would find no credential and
/// answer "not authorized".
#[test]
fn a_credential_issued_earlier_in_the_block_can_be_revoked() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility(0x31, gov.address()),
        ),
        tx(
            &gov,
            1,
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: [0x31; 32],
                reason: RevocationReason::FraudulentIssuance,
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 3, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x31; 32]).unwrap(),
        RevocationStatus::Revoked
    );
    assert_eq!(
        DocClassExecutor::v_get_eligibility(&view, &[0x31; 32])
            .unwrap()
            .unwrap()
            .revocation_status,
        RevocationStatus::Revoked
    );
}

/// The discriminator: without the issue, the same revocation is not authorized.
#[test]
fn without_the_issue_the_same_revocation_is_not_authorized() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &gov,
        0,
        DocClassOperation::RevokeCredential,
        DocSubcode::Revocation,
        &ReasonedData {
            credential_id: [0x31; 32],
            reason: RevocationReason::FraudulentIssuance,
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 3, 1000)
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// An issuer registered earlier in the block can update itself and rotate a key.
#[test]
fn an_issuer_registered_earlier_in_the_block_can_update_itself_and_rotate_a_key() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut updated = government_issuer(gov.address());
    updated.name = "Renamed Registry".to_string();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &government_issuer(gov.address()),
        ),
        tx(
            &gov,
            1,
            DocClassOperation::UpdateIssuer,
            DocSubcode::IssuerRegistry,
            &updated,
        ),
        tx(
            &gov,
            2,
            DocClassOperation::RotateIssuerKey,
            DocSubcode::IssuerRegistry,
            &IssuerRotateKeyData {
                new_key: issuer_key("gov-2", 0x53, true),
                old_key_id: "gov-1".to_string(),
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let issuer = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
        .unwrap()
        .unwrap();
    assert_eq!(
        issuer.name, "Renamed Registry",
        "the update read the registration"
    );
    assert_eq!(
        issuer
            .keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["gov-1", "gov-2"],
        "and the rotation read the update's row, not the registration's"
    );
    assert!(!issuer.keys[0].active && !issuer.keys[0].is_primary);
    assert!(issuer.keys[1].is_primary);
}

/// The discriminator: without the registration, both are refused.
#[test]
fn without_the_registration_the_update_and_rotation_are_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::UpdateIssuer,
            DocSubcode::IssuerRegistry,
            &government_issuer(gov.address()),
        ),
        tx(
            &gov,
            0,
            DocClassOperation::RotateIssuerKey,
            DocSubcode::IssuerRegistry,
            &IssuerRotateKeyData {
                new_key: issuer_key("gov-2", 0x53, true),
                old_key_id: "gov-1".to_string(),
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(r.status, DOCCLASS_FAILED);
    }
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// Create, deactivate and reactivate one identity inside one block.
#[test]
fn an_identity_created_earlier_in_the_block_can_be_deactivated_and_reactivated() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op) in [
        (0u64, DocClassOperation::CreateIdentityRoot),
        (1, DocClassOperation::DeactivateIdentity),
        (2, DocClassOperation::ReactivateIdentity),
    ] {
        let t = if op == DocClassOperation::CreateIdentityRoot {
            tx(
                &actor,
                nonce,
                op,
                DocSubcode::IdentityRoot,
                &identity(0x22, actor.address()),
            )
        } else {
            tx(
                &actor,
                nonce,
                op,
                DocSubcode::IdentityRoot,
                &IdentityIdData {
                    identity_id: [0x22; 32],
                },
            )
        };
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }

    let root = DocClassExecutor::v_get_identity_root(&view, &[0x22; 32])
        .unwrap()
        .unwrap();
    assert_eq!(root.status, IdentityStatus::Active);
    // Three writes of the same identity row, and the subject index still holds
    // ONE entry: both status transitions go through the same `put`, and the
    // append is skipped when the id is already there.
    assert_eq!(
        DocClassExecutor::v_get_subject_identity_entries(&view, &[0x22u8.wrapping_add(0x40); 32])
            .unwrap(),
        vec![([0x22u8; 32], DocSubcode::IdentityRoot)]
    );
}

/// The discriminator: without the creation the deactivation is refused.
#[test]
fn without_the_creation_the_same_deactivation_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &actor,
        0,
        DocClassOperation::DeactivateIdentity,
        DocSubcode::IdentityRoot,
        &IdentityIdData {
            identity_id: [0x22; 32],
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

// ── Duplicate guards, reading the candidate ────────────────────────────────

/// Every duplicate guard in the subsystem refuses a second attempt made in the
/// SAME block as the first.
///
/// All four are `contains` guards, so against committed state each would find
/// the parent's empty family and admit the duplicate. The identity and issuer
/// cases would overwrite a row; the two credential cases would too.
#[test]
fn every_duplicate_guard_reads_the_candidate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    let edu = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    fund(&db, &edu, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Each pair: the first must succeed, the second must be refused.
    let first: Vec<(SignedTransaction, &str)> = vec![
        (
            tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &government_issuer(gov.address()),
            ),
            "issuer registration",
        ),
        (
            tx(
                &gov,
                1,
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &identity(0x23, gov.address()),
            ),
            "identity root",
        ),
        (
            tx(
                &gov,
                2,
                DocClassOperation::IssueCredential,
                DocSubcode::EligibilityAttestation,
                &eligibility(0x32, gov.address()),
            ),
            "eligibility attestation",
        ),
    ];
    for (t, label) in &first {
        let r = executor
            .execute_tx(&mut view, t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{label}: {:?}",
            r.status
        );
    }

    // The academic credential needs its own, Educational, issuer.
    for t in [
        tx(
            &edu,
            0,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &educational_issuer(edu.address()),
        ),
        tx(
            &edu,
            1,
            DocClassOperation::IssueCredential,
            DocSubcode::Diploma,
            &credential(0x33, edu.address()),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // Now the duplicates, each at the sender's current nonce.
    let duplicates: Vec<(SignedTransaction, &str)> = vec![
        (
            tx(
                &gov,
                3,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &government_issuer(gov.address()),
            ),
            "issuer registration",
        ),
        (
            tx(
                &gov,
                3,
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &identity(0x23, gov.address()),
            ),
            "identity root",
        ),
        (
            tx(
                &gov,
                3,
                DocClassOperation::IssueCredential,
                DocSubcode::EligibilityAttestation,
                &eligibility(0x32, gov.address()),
            ),
            "eligibility attestation",
        ),
        (
            tx(
                &edu,
                2,
                DocClassOperation::IssueCredential,
                DocSubcode::Diploma,
                &credential(0x33, edu.address()),
            ),
            "academic credential",
        ),
    ];
    for (t, label) in &duplicates {
        let r = executor
            .execute_tx(&mut view, t, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status, DOCCLASS_FAILED,
            "{label}: the duplicate must be refused against the CANDIDATE"
        );
    }
    assert_eq!(
        StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
        3,
        "three successes, three refusals, and only the successes counted"
    );
    assert_eq!(StateManager::v_get_nonce(&view, &edu.address()).unwrap(), 2);
}

// ── The three accumulating indexes ─────────────────────────────────────────

/// All three index values accumulate within one block.
///
/// Each append is a read-modify-write: read the list, `contains`-dedup, push,
/// re-encode the whole list. Against committed state the second entry in a
/// block would replace the first one's list with a single-element one.
#[test]
fn all_three_indexes_accumulate_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    let edu = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    fund(&db, &edu, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .issuers()
        .put(&educational_issuer(edu.address()))
        .unwrap();

    // Two identities under ONE subject commitment; two attestations under
    // another; two academic credentials under a third. Separate commitments,
    // because the identity index and the credential index are incompatible
    // shapes at one key -- see
    // `an_identity_and_a_credential_sharing_a_subject_commitment_break_the_block`.
    let shared_identity_subject = [0xC0u8; 32];
    let shared_credential_subject = [0xC1u8; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id) in [(0u64, 0x24u8), (1, 0x25)] {
        let mut root = identity(id, gov.address());
        root.subject_commitment = shared_identity_subject;
        let t = tx(
            &gov,
            nonce,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &root,
        );
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    for (nonce, id) in [(2u64, 0x34u8), (3, 0x35)] {
        let mut att = eligibility(id, gov.address());
        att.subject_commitment = shared_credential_subject;
        let t = tx(
            &gov,
            nonce,
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &att,
        );
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    for (nonce, id) in [(0u64, 0x36u8), (1, 0x37)] {
        let t = tx(
            &edu,
            nonce,
            DocClassOperation::IssueCredential,
            DocSubcode::Diploma,
            &credential(id, edu.address()),
        );
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        DocClassExecutor::v_get_subject_identity_entries(&view, &shared_identity_subject).unwrap(),
        vec![
            ([0x24u8; 32], DocSubcode::IdentityRoot),
            ([0x25u8; 32], DocSubcode::IdentityRoot),
        ],
        "the subject index, identity shape: both pairs, in order"
    );
    assert_eq!(
        DocClassExecutor::v_get_subject_credential_ids(&view, &shared_credential_subject).unwrap(),
        vec![[0x34u8; 32], [0x35u8; 32]],
        "the subject index, credential shape: both ids, in order"
    );
    assert_eq!(
        DocClassExecutor::v_get_issuer_credential_ids(&view, &gov.address()).unwrap(),
        vec![[0x34u8; 32], [0x35u8; 32]],
        "the issuer index for the government issuer"
    );
    assert_eq!(
        DocClassExecutor::v_get_issuer_credential_ids(&view, &edu.address()).unwrap(),
        vec![[0x36u8; 32], [0x37u8; 32]],
        "and a separate row for the educational one"
    );
}

/// A re-put does not duplicate an index entry, and a revocation's mirror write
/// goes THROUGH the same `put`, so the indexes are read and rewritten but not
/// grown.
#[test]
fn a_revocation_rewrites_the_row_without_growing_either_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x38, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = tx(
        &gov,
        0,
        DocClassOperation::RevokeCredential,
        DocSubcode::Revocation,
        &ReasonedData {
            credential_id: [0x38; 32],
            reason: RevocationReason::Expired,
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 4, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    assert_eq!(
        DocClassExecutor::v_get_issuer_credential_ids(&view, &gov.address()).unwrap(),
        vec![[0x38u8; 32]],
        "one entry, not two"
    );
    assert_eq!(
        DocClassExecutor::v_get_subject_credential_ids(&view, &[0x38u8.wrapping_add(0x40); 32])
            .unwrap(),
        vec![[0x38u8; 32]]
    );
}

// ── All nineteen operations ────────────────────────────────────────────────

/// Every one of the nineteen operations runs against one candidate, each
/// reading what the one before it staged.
///
/// The heights ADVANCE across the four revocation-lifecycle transactions, and
/// they have to: a revocation row is keyed by `credential_id || height`, so two
/// records at one height are one row and the later one silently replaces the
/// earlier. `every_docclass_event_in_a_block_lands_at_one_key` and
/// `two_revocations_at_one_height_are_one_row` (storage) pin that collision;
/// this test steps around it so the nineteen handlers can be exercised in
/// sequence.
#[test]
fn every_one_of_the_nineteen_operations_runs_against_one_candidate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let delegate = Address::new([0xDD; 20]);
    let before = canonical(&db);

    let mut updated_issuer = government_issuer(gov.address());
    updated_issuer.name = "Renamed".to_string();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let mut nonce = 0u64;
    let run = |t: SignedTransaction, height: u64, label: &str, view: &mut ExecutionView| {
        let r = executor
            .execute_tx(view, &t, &proposer, height, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{label} must succeed: {:?}",
            r.status
        );
    };

    // 1-3: issuer registry.
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &government_issuer(gov.address()),
        ),
        1,
        "RegisterIssuer",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::UpdateIssuer,
            DocSubcode::IssuerRegistry,
            &updated_issuer,
        ),
        1,
        "UpdateIssuer",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RotateIssuerKey,
            DocSubcode::IssuerRegistry,
            &IssuerRotateKeyData {
                new_key: issuer_key("gov-2", 0x53, true),
                old_key_id: "gov-1".to_string(),
            },
        ),
        1,
        "RotateIssuerKey",
        &mut view,
    );
    nonce += 1;

    // 4-12: the identity lifecycle.
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity(0x40, gov.address()),
        ),
        1,
        "CreateIdentityRoot",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::AddKey,
            DocSubcode::IdentityRoot,
            &AddKeyData {
                identity_id: [0x40; 32],
                key: identity_key("auth-2", 0x84),
            },
        ),
        1,
        "AddKey",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RemoveKey,
            DocSubcode::IdentityRoot,
            &RemoveKeyData {
                identity_id: [0x40; 32],
                key_id: "auth-1".to_string(),
            },
        ),
        1,
        "RemoveKey",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RotateKey,
            DocSubcode::IdentityRoot,
            &RotateKeyData {
                identity_id: [0x40; 32],
                old_key_id: "auth-2".to_string(),
                new_key: identity_key("auth-3", 0x85),
            },
        ),
        1,
        "RotateKey",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::AddController,
            DocSubcode::IdentityRoot,
            &ControllerData {
                identity_id: [0x40; 32],
                controller: delegate,
            },
        ),
        1,
        "AddController",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RemoveController,
            DocSubcode::IdentityRoot,
            &ControllerData {
                identity_id: [0x40; 32],
                controller: delegate,
            },
        ),
        1,
        "RemoveController",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::UpdateService,
            DocSubcode::IdentityRoot,
            &UpdateServiceData {
                identity_id: [0x40; 32],
                service: service("svc-1", "https://example.invalid/a"),
            },
        ),
        1,
        "UpdateService",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::DeactivateIdentity,
            DocSubcode::IdentityRoot,
            &IdentityIdData {
                identity_id: [0x40; 32],
            },
        ),
        1,
        "DeactivateIdentity",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::ReactivateIdentity,
            DocSubcode::IdentityRoot,
            &IdentityIdData {
                identity_id: [0x40; 32],
            },
        ),
        1,
        "ReactivateIdentity",
        &mut view,
    );
    nonce += 1;

    // 13-14: issue and "update".
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility(0x41, gov.address()),
        ),
        1,
        "IssueCredential",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::UpdateCredential,
            DocSubcode::EligibilityAttestation,
            &CredentialIdData {
                credential_id: [0x41; 32],
            },
        ),
        1,
        "UpdateCredential",
        &mut view,
    );
    nonce += 1;

    // 15-18: the revocation lifecycle, one height apiece.
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::SuspendCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: [0x41; 32],
                reason: RevocationReason::CertificateHold,
            },
        ),
        2,
        "SuspendCredential",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::ReactivateCredential,
            DocSubcode::Revocation,
            &CredentialIdData {
                credential_id: [0x41; 32],
            },
        ),
        3,
        "ReactivateCredential",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: [0x41; 32],
                reason: RevocationReason::KeyCompromise,
            },
        ),
        4,
        "RevokeCredential",
        &mut view,
    );
    nonce += 1;
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::SupersedeCredential,
            DocSubcode::Revocation,
            &SupersedeData {
                old_credential_id: [0x41; 32],
                new_credential_id: [0x42; 32],
            },
        ),
        5,
        "SupersedeCredential",
        &mut view,
    );
    nonce += 1;

    // 19: deactivate the issuer, last, because it stops the issue path.
    run(
        tx(
            &gov,
            nonce,
            DocClassOperation::DeactivateIssuer,
            DocSubcode::IssuerRegistry,
            &DeactivateIssuerData {
                issuer_address: gov.address(),
            },
        ),
        5,
        "DeactivateIssuer",
        &mut view,
    );
    nonce += 1;

    assert_eq!(nonce, 19, "nineteen operations, nineteen transactions");
    assert_eq!(
        StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
        19,
        "and every one of them charged the sender"
    );

    // What the chain of nineteen left behind.
    let root = DocClassExecutor::v_get_identity_root(&view, &[0x40; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        root.keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["auth-3"],
        "add, remove and rotate each read the row the one before it staged"
    );
    assert!(root.additional_controllers.is_empty());
    assert_eq!(
        root.services
            .iter()
            .map(|s| s.service_id.as_str())
            .collect::<Vec<_>>(),
        vec!["svc-1"]
    );
    assert_eq!(root.status, IdentityStatus::Active);

    let issuer = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
        .unwrap()
        .unwrap();
    assert_eq!(issuer.name, "Renamed");
    assert_eq!(
        issuer
            .keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect::<Vec<_>>(),
        vec!["gov-1", "gov-2"]
    );
    assert_eq!(issuer.status, DocClassIssuerStatus::Suspended);

    let att = DocClassExecutor::v_get_eligibility(&view, &[0x41; 32])
        .unwrap()
        .unwrap();
    assert_eq!(att.revocation_status, RevocationStatus::Superseded);
    assert_eq!(att.superseded_by, Some([0x42u8; 32]));
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x41; 32]).unwrap(),
        RevocationStatus::Superseded
    );
    assert_eq!(
        DocClassExecutor::v_get_revocations_for_credential(&view, &[0x41; 32])
            .unwrap()
            .iter()
            .map(|r| r.revoked_at_height)
            .collect::<Vec<_>>(),
        vec![5, 4, 3, 2],
        "four records, newest height first"
    );

    assert_eq!(canonical(&db), before, "and none of it is committed");
}

// ── Abandonment ────────────────────────────────────────────────────────────

/// Six transactions that between them write all EIGHT DocClass families.
///
/// Used by the abandonment test and by the publication test, so the two are
/// talking about the same block. Two senders, because `can_issue` is decided by
/// issuer TYPE: a `Government` issuer may not issue a `Diploma` and an
/// `Educational` one may not issue an eligibility attestation, and
/// `register_issuer` refuses to register anyone but the sender.
fn a_block_touching_every_family(gov: &KeyPair, edu: &KeyPair, id: u8) -> Vec<SignedTransaction> {
    vec![
        // issuers + events
        tx(
            gov,
            0,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &government_issuer(gov.address()),
        ),
        tx(
            edu,
            0,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &educational_issuer(edu.address()),
        ),
        // identity roots + subject index
        tx(
            gov,
            1,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity(id, gov.address()),
        ),
        // eligibility + subject index + issuer index
        tx(
            gov,
            2,
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility(id.wrapping_add(1), gov.address()),
        ),
        // credentials + subject index + issuer index
        tx(
            edu,
            1,
            DocClassOperation::IssueCredential,
            DocSubcode::Diploma,
            &credential(id.wrapping_add(2), edu.address()),
        ),
        // revocations, and a rewrite of the eligibility row
        tx(
            gov,
            3,
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: [id.wrapping_add(1); 32],
                reason: RevocationReason::KeyCompromise,
            },
        ),
    ]
}

/// A block writing every DocClass family commits none of it.
///
/// All eight are asserted STAGED first, by per-CF diff, so the canonical
/// comparison afterwards is a statement about eight discarded families and not
/// about a block that quietly did nothing.
#[test]
fn an_abandoned_block_leaves_all_eight_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    let edu = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    fund(&db, &edu, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for t in a_block_touching_every_family(&gov, &edu, 0x50) {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let touched = families_changed(&db, &view);
        for f in DOCCLASS_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so this block does not test it"
            );
        }
        // dropped without publication
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every DocClass row byte-identical"
    );
}

// ── Limit refusal ──────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the identity row staged and its subject-index entry not.
///
/// `CreateIdentityRoot` is the operation to calibrate against: it writes the
/// identity row and then the subject-index entry, so a ceiling can land between
/// them. Every ceiling below the measured cost is tried, not a sample.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let signed_tx = tx(
        &actor,
        0,
        DocClassOperation::CreateIdentityRoot,
        DocSubcode::IdentityRoot,
        &identity(0x60, actor.address()),
    );

    assert!(
        db.prefix_iter(cf::DOCCLASS_IDENTITY_ROOTS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::DOCCLASS_SUBJECT_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "both families must start canonically empty for the merged reads below \
         to stand for staged"
    );

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut v = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut v, &signed_tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "creating an identity must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let root_staged = view
            .get(cf::DOCCLASS_IDENTITY_ROOTS, &[0x60u8; 32])
            .unwrap()
            .is_some();
        let index_staged = view
            .get(cf::DOCCLASS_SUBJECT_INDEX, &[0xA0u8; 32])
            .unwrap()
            .is_some();
        if root_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || root_staged,
            "ceiling {ceiling} staged the subject index without the identity, \
             which the write order cannot produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must commit nothing"
        );
    }
    assert!(
        partials > 0,
        "no ceiling refused with the identity staged and its subject index not"
    );
}

// ── Real publication, byte for byte, and a restart ─────────────────────────

/// The PUBLISHED bytes are the byte contract, and this pins them directly.
///
/// Candidate assertions compare against independent expectations, and a restart
/// comparison compares published rows to themselves. Neither pins what actually
/// lands in canonical storage: the step from candidate to committed goes through
/// `ApplicationOverlay::into_batch`. If that step ever reordered a key, dropped
/// a prefix or re-encoded a value, every other assertion here would still pass.
///
/// So: publish a real six-transaction block through the real publisher, then for
/// all EIGHT families read the RAW committed bytes and compare them against a
/// key written out by hand and a value produced by `bincode::serialize` applied
/// here in the test. Nothing on the expected side calls a key builder or a codec
/// from the crate under test. Each family is then asserted to hold exactly the
/// expected number of rows, so a publisher writing correct bytes at an extra key
/// is caught too. Finally the database is closed -- with `Arc::strong_count == 1`
/// asserted first -- reopened at the same path, and every expectation checked
/// again.
#[test]
fn published_docclass_bytes_match_independently_built_keys_and_values() {
    let dir = tempfile::TempDir::new().unwrap();
    let gov = KeyPair::generate();
    let edu = KeyPair::generate();
    const ID: u8 = 0x50;
    const HEIGHT: u64 = 1;

    // Expectations built here, from the schema, with no help from the crate.
    let gov_issuer = government_issuer(gov.address());
    let edu_issuer = educational_issuer(edu.address());
    let root = identity(ID, gov.address());
    let cred = credential(ID.wrapping_add(2), edu.address());

    // The revocation REWRITES the attestation row, so the published value is the
    // revoked form, not the issued one.
    let mut revoked = eligibility(ID.wrapping_add(1), gov.address());
    revoked.revocation_status = RevocationStatus::Revoked;
    revoked.superseded_by = None;

    // `revoked_at` is the block TIMESTAMP the dispatch arm passes, which is a
    // literal 0 on both arms. Pinned here rather than corrected.
    let record = sumchain_primitives::RevocationRecord {
        credential_id: [ID.wrapping_add(1); 32],
        status: RevocationStatus::Revoked,
        reason: RevocationReason::KeyCompromise,
        reason_details: None,
        revoker: gov.address(),
        revoked_at: 0,
        revoked_at_height: HEIGHT,
        superseded_by: None,
        signature: [0u8; 64],
    };
    let mut revocation_key = vec![ID.wrapping_add(1); 32];
    revocation_key.extend_from_slice(&HEIGHT.to_be_bytes());

    // Every event in the block is written at tx_index 0, event_index 0, so the
    // family holds ONE row: the last event the block produced.
    let mut event_key = HEIGHT.to_be_bytes().to_vec();
    event_key.extend_from_slice(&0u32.to_be_bytes());
    event_key.extend_from_slice(&0u16.to_be_bytes());
    let last_event = DocClassEvent::CredentialRevoked {
        credential_id: [ID.wrapping_add(1); 32],
        issuer: gov.address(),
        reason: RevocationReason::KeyCompromise,
        timestamp: 0,
    };

    let expected: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            cf::DOCCLASS_IDENTITY_ROOTS,
            vec![ID; 32],
            bincode::serialize(&root).unwrap(),
        ),
        (
            cf::DOCCLASS_ELIGIBILITY,
            vec![ID.wrapping_add(1); 32],
            bincode::serialize(&revoked).unwrap(),
        ),
        (
            cf::DOCCLASS_CREDENTIALS,
            vec![ID.wrapping_add(2); 32],
            bincode::serialize(&cred).unwrap(),
        ),
        (
            cf::DOCCLASS_REVOCATIONS,
            revocation_key.clone(),
            bincode::serialize(&record).unwrap(),
        ),
        (
            cf::DOCCLASS_ISSUERS,
            gov.address().as_bytes().to_vec(),
            bincode::serialize(&gov_issuer).unwrap(),
        ),
        (
            cf::DOCCLASS_ISSUERS,
            edu.address().as_bytes().to_vec(),
            bincode::serialize(&edu_issuer).unwrap(),
        ),
        // The identity's subject index is a PAIR list; the two credential ones
        // are BARE id lists. Same family, same key width, different shapes.
        (
            cf::DOCCLASS_SUBJECT_INDEX,
            vec![ID.wrapping_add(0x40); 32],
            bincode::serialize(&vec![([ID; 32], DocSubcode::IdentityRoot)]).unwrap(),
        ),
        (
            cf::DOCCLASS_SUBJECT_INDEX,
            vec![ID.wrapping_add(0x41); 32],
            bincode::serialize(&vec![[ID.wrapping_add(1); 32]]).unwrap(),
        ),
        (
            cf::DOCCLASS_SUBJECT_INDEX,
            vec![ID.wrapping_add(0x42); 32],
            bincode::serialize(&vec![[ID.wrapping_add(2); 32]]).unwrap(),
        ),
        (
            cf::DOCCLASS_ISSUER_INDEX,
            gov.address().as_bytes().to_vec(),
            bincode::serialize(&vec![[ID.wrapping_add(1); 32]]).unwrap(),
        ),
        (
            cf::DOCCLASS_ISSUER_INDEX,
            edu.address().as_bytes().to_vec(),
            bincode::serialize(&vec![[ID.wrapping_add(2); 32]]).unwrap(),
        ),
        (
            cf::DOCCLASS_EVENTS,
            event_key.clone(),
            bincode::serialize(&last_event).unwrap(),
        ),
    ];
    /// `(family, rows it must hold)` -- one entry per migrated family, so a
    /// family added later cannot quietly go unpinned.
    const COUNTS: &[(&str, usize)] = &[
        (cf::DOCCLASS_IDENTITY_ROOTS, 1),
        (cf::DOCCLASS_ELIGIBILITY, 1),
        (cf::DOCCLASS_CREDENTIALS, 1),
        (cf::DOCCLASS_REVOCATIONS, 1),
        (cf::DOCCLASS_ISSUERS, 2),
        (cf::DOCCLASS_SUBJECT_INDEX, 3),
        (cf::DOCCLASS_ISSUER_INDEX, 2),
        (cf::DOCCLASS_EVENTS, 1),
    ];
    assert_eq!(COUNTS.len(), DOCCLASS_CFS.len());
    assert_eq!(
        expected.len(),
        COUNTS.iter().map(|(_, n)| n).sum::<usize>(),
        "one expectation per published row"
    );

    {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &gov, 500_000_000);
        fund(&db, &edu, 500_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            HEIGHT,
            &[9u8; 32],
            a_block_touching_every_family(&gov, &edu, ID),
            &[],
        );
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all six must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        for (family, key, value) in &expected {
            assert_eq!(
                db.get(family, key).unwrap().as_deref(),
                Some(&value[..]),
                "{family}: the published row does not match the bytes built \
                 independently in this test"
            );
        }
        for (family, rows) in COUNTS {
            assert_eq!(
                db.prefix_iter(family, &[]).unwrap().count(),
                *rows,
                "{family} must hold exactly {rows} published row(s)"
            );
        }

        drop(executor);
        drop(state);
        assert_eq!(
            std::sync::Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             close it and the reopen proves nothing"
        );
        drop(db);
    }

    let db = Database::open_default(dir.path()).unwrap();
    for (family, key, value) in &expected {
        assert_eq!(
            db.get(family, key).unwrap().as_deref(),
            Some(&value[..]),
            "{family}: the row changed across a close and reopen"
        );
    }
    for (family, rows) in COUNTS {
        assert_eq!(
            db.prefix_iter(family, &[]).unwrap().count(),
            *rows,
            "{family}: the row count changed across a close and reopen"
        );
    }
    // And the committed readers resolve what the block published.
    let store = DocClassStore::new(&db);
    assert!(store.identity_roots().get(&[ID; 32]).unwrap().is_some());
    assert_eq!(
        store.eligibility().get(&[ID.wrapping_add(1); 32]).unwrap(),
        Some(revoked)
    );
    assert_eq!(
        store.credentials().get(&[ID.wrapping_add(2); 32]).unwrap(),
        Some(cred)
    );
    assert_eq!(
        store
            .revocations()
            .get_status(&[ID.wrapping_add(1); 32])
            .unwrap(),
        RevocationStatus::Revoked
    );
    assert!(store.issuers().is_registered(&gov.address()).unwrap());
    assert_eq!(
        store.events().get_events_at_height(HEIGHT).unwrap(),
        vec![last_event],
        "one event row for the whole block"
    );
}

// ── The second dispatch surface ────────────────────────────────────────────

/// `execute_tx_v2` routes DocClass operations through the candidate too.
///
/// It is a separate arm with its own argument list, and it carries its own
/// `0, // block_timestamp placeholder`. A migration that moved only the live
/// arm would leave this one writing committed rows.
#[test]
fn the_v2_dispatch_surface_also_stages_docclass_rows() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let key = *gov.public_key().as_bytes();

    let v2 = |nonce: u64, op: DocClassOperation, data: Vec<u8>| TransactionV2 {
        chain_id: CHAIN_ID,
        from: gov.address(),
        fee: 100,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation: op,
            subcode: DocSubcode::IssuerRegistry,
            data,
            recipient: Address::ZERO,
        }),
    };

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        let t = v2(
            0,
            DocClassOperation::RegisterIssuer,
            bincode::serialize(&government_issuer(gov.address())).unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), gov.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must register an issuer: {:?}",
            r.status
        );
        let changed = families_changed(&db, &view);
        assert!(changed.contains(&cf::DOCCLASS_ISSUERS));
        assert!(changed.contains(&cf::DOCCLASS_EVENTS));

        // A second transaction through the SAME surface, which has to see the
        // first one's issuer row.
        let t = v2(
            1,
            DocClassOperation::IssueCredential,
            bincode::serialize(&eligibility(0x70, gov.address())).unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), gov.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must see the registration it staged a moment ago: \
             {:?}",
            r.status
        );

        // A status transition through this arm, carrying its own literal 0
        // where the block timestamp belongs.
        let t = v2(
            2,
            DocClassOperation::DeactivateIssuer,
            bincode::serialize(&DeactivateIssuerData {
                issuer_address: gov.address(),
            })
            .unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), gov.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let issuer = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap();
        assert_eq!(issuer.status, DocClassIssuerStatus::Suspended);
        assert_eq!(
            issuer.updated_at, 0,
            "and this arm passes 0 where the block timestamp belongs, exactly \
             like the live one"
        );

        // A refusal on this arm carries the DocClass status code, not a
        // neighbouring subsystem's.
        let t = v2(
            3,
            DocClassOperation::RotateIssuerKey,
            bincode::serialize(&IssuerRotateKeyData {
                new_key: issuer_key("gov-2", 0x53, true),
                old_key_id: "gov-1".to_string(),
            })
            .unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), gov.private_key()).as_bytes();
        let _ = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();

        let t = v2(
            4,
            DocClassOperation::CreateIdentityRoot,
            bincode::serialize(&identity(0x71, Address::new([0xEE; 20]))).unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), gov.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status, DOCCLASS_FAILED,
            "a controller that is not the sender must fail IN the DocClass arm \
             of this surface"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
            4,
            "and the refusal does not advance the nonce"
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

// ── Corrupt rows: every family, with the staged state named ───────────────

/// One corrupt-row case: which family is corrupted, the operation that has to
/// READ it, and the exact candidate state the failure is required to leave.
struct CorruptCase {
    family: &'static str,
    label: &'static str,
    /// DocClass families whose candidate contents must differ from committed,
    /// and nothing else. Named exactly -- not an allowed set.
    staged: &'static [&'static str],
    /// The sender's nonce after the failure. `0` means the read failed before
    /// the fee was charged; `1` means execution got past the guards.
    nonce: u64,
}

/// A corrupt row makes the routed transaction ERROR; it is never read as
/// absence. What the candidate holds afterwards is asserted positively, family
/// by family, key by key.
///
/// This is the difference between "no such credential" and "that credential's
/// row is corrupt", and every guard here branches on exactly that. A candidate
/// reader that swallowed a decode failure into `None` would turn corruption
/// into a duplicate-id opportunity, or into a revocation authorized because the
/// issuer could not be read.
///
/// Seven of the eight families are covered: five corrupt PRIMARY rows and both
/// corrupt INDEX rows. The eighth, `DOCCLASS_EVENTS`, has no reader reachable
/// from dispatch at all -- the executor only ever writes it -- which is itself
/// recorded as a deployment blocker.
///
/// The two index cases are the ones that leave state: the primary write precedes
/// the index append, so the row is staged and the fee has been charged when the
/// append fails. Each is asserted as exact bytes, and the corrupt index row is
/// asserted UNCHANGED.
#[test]
fn corrupt_rows_error_through_dispatch_with_exactly_this_staged() {
    const CORRUPT: &[u8] = b"not a valid row";

    let cases = [
        CorruptCase {
            family: cf::DOCCLASS_IDENTITY_ROOTS,
            label: "identity root",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::DOCCLASS_ELIGIBILITY,
            label: "eligibility attestation",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::DOCCLASS_CREDENTIALS,
            label: "academic credential",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::DOCCLASS_REVOCATIONS,
            label: "revocation record",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::DOCCLASS_ISSUERS,
            label: "issuer",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::DOCCLASS_SUBJECT_INDEX,
            label: "subject index",
            staged: &[cf::DOCCLASS_IDENTITY_ROOTS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::DOCCLASS_ISSUER_INDEX,
            label: "issuer index",
            staged: &[cf::DOCCLASS_ELIGIBILITY, cf::DOCCLASS_SUBJECT_INDEX],
            nonce: 1,
        },
    ];

    for case in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let gov = KeyPair::generate();
        fund(&db, &gov, 100_000_000);
        let proposer = Address::new([9; 20]);
        let store = DocClassStore::new(&db);

        // Keys written by hand, from the schema and not from the key builders,
        // so a change to a builder cannot silently move this test with it.
        let key: Vec<u8> = match case.family {
            f if f == cf::DOCCLASS_IDENTITY_ROOTS => vec![0xB0u8; 32],
            f if f == cf::DOCCLASS_ELIGIBILITY => vec![0xB1u8; 32],
            f if f == cf::DOCCLASS_CREDENTIALS => vec![0xB2u8; 32],
            f if f == cf::DOCCLASS_REVOCATIONS => {
                let mut k = vec![0xB3u8; 32];
                k.extend_from_slice(&1u64.to_be_bytes());
                k
            }
            f if f == cf::DOCCLASS_SUBJECT_INDEX => vec![0xB4u8.wrapping_add(0x40); 32],
            // Both address-keyed families.
            _ => gov.address().as_bytes().to_vec(),
        };

        // What each guard needs in order to REACH the corrupt row.
        let signed = match case.family {
            f if f == cf::DOCCLASS_IDENTITY_ROOTS => tx(
                &gov,
                0,
                DocClassOperation::AddKey,
                DocSubcode::IdentityRoot,
                &AddKeyData {
                    identity_id: [0xB0; 32],
                    key: identity_key("auth-2", 0x86),
                },
            ),
            f if f == cf::DOCCLASS_ELIGIBILITY => tx(
                &gov,
                0,
                DocClassOperation::RevokeCredential,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: [0xB1; 32],
                    reason: RevocationReason::Expired,
                },
            ),
            f if f == cf::DOCCLASS_CREDENTIALS => tx(
                &gov,
                0,
                DocClassOperation::UpdateCredential,
                DocSubcode::Diploma,
                &CredentialIdData {
                    credential_id: [0xB2; 32],
                },
            ),
            f if f == cf::DOCCLASS_REVOCATIONS => {
                // The authorization guard runs first and must PASS, so the
                // attestation it reads has to be present and valid.
                store
                    .eligibility()
                    .put(&eligibility(0xB3, gov.address()))
                    .unwrap();
                tx(
                    &gov,
                    0,
                    DocClassOperation::ReactivateCredential,
                    DocSubcode::Revocation,
                    &CredentialIdData {
                        credential_id: [0xB3; 32],
                    },
                )
            }
            f if f == cf::DOCCLASS_ISSUERS => tx(
                &gov,
                0,
                DocClassOperation::RotateIssuerKey,
                DocSubcode::IssuerRegistry,
                &IssuerRotateKeyData {
                    new_key: issuer_key("gov-2", 0x53, true),
                    old_key_id: "gov-1".to_string(),
                },
            ),
            f if f == cf::DOCCLASS_SUBJECT_INDEX => tx(
                &gov,
                0,
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &identity(0xB4, gov.address()),
            ),
            _ => {
                store
                    .issuers()
                    .put(&government_issuer(gov.address()))
                    .unwrap();
                tx(
                    &gov,
                    0,
                    DocClassOperation::IssueCredential,
                    DocSubcode::EligibilityAttestation,
                    &eligibility(0xB5, gov.address()),
                )
            }
        };
        db.put(case.family, &key, CORRUPT).unwrap();

        let before = canonical(&db);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &signed, &proposer, 1, 1000);
            let err = outcome.err().unwrap_or_else(|| {
                panic!(
                    "a corrupt {} row must ERROR, not be read as absence",
                    case.label
                )
            });
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {} failure must name the decode, not something else: {text}",
                case.label
            );

            // Exactly these families changed. Not a subset, not an allowed set.
            assert_eq!(
                families_changed(&db, &view),
                case.staged.to_vec(),
                "{}: the candidate must hold exactly the families named for \
                 this case",
                case.label
            );

            // And exactly this content, where anything is staged at all.
            let staged_rows: Vec<(&str, Vec<u8>, Vec<u8>)> = match case.family {
                f if f == cf::DOCCLASS_SUBJECT_INDEX => vec![(
                    cf::DOCCLASS_IDENTITY_ROOTS,
                    vec![0xB4u8; 32],
                    bincode::serialize(&identity(0xB4, gov.address())).unwrap(),
                )],
                f if f == cf::DOCCLASS_ISSUER_INDEX => vec![
                    (
                        cf::DOCCLASS_ELIGIBILITY,
                        vec![0xB5u8; 32],
                        bincode::serialize(&eligibility(0xB5, gov.address())).unwrap(),
                    ),
                    (
                        cf::DOCCLASS_SUBJECT_INDEX,
                        vec![0xB5u8.wrapping_add(0x40); 32],
                        bincode::serialize(&vec![[0xB5u8; 32]]).unwrap(),
                    ),
                ],
                _ => Vec::new(),
            };
            for (family, k, bytes) in &staged_rows {
                assert_eq!(
                    view.get(family, k).unwrap().as_deref(),
                    Some(&bytes[..]),
                    "{}: the rows written before the failing append, byte for \
                     byte",
                    case.label
                );
            }

            // The corrupt row itself is never rewritten or repaired.
            assert_eq!(
                view.get(case.family, &key).unwrap().as_deref(),
                Some(CORRUPT),
                "{}: the corrupt bytes must be left exactly as they were",
                case.label
            );

            // The account side, positively: whether the fee was charged says
            // where in the arm the failure happened.
            assert_eq!(
                StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
                case.nonce,
                "{}: nonce after the failure",
                case.label
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {}",
            case.label
        );
    }
}

// ── Behaviours reproduced deliberately, not fixed ─────────────────────────

/// `IssueCredential` decides which family a payload belongs to by TRYING to
/// decode it as an `AcademicCredential` first and falling through on failure.
///
/// The fallthrough discards the decode error rather than reporting it, so a
/// malformed academic credential is silently retried as an attestation and, if
/// that also fails, refused as "Invalid credential data". Preserved: reporting
/// the first error would turn today's refusals into block-level errors.
#[test]
fn issue_credential_picks_its_family_by_trying_to_decode_and_falling_through() {
    let elig_bytes = bincode::serialize(&eligibility(0x80, Address::new([1; 20]))).unwrap();
    let cred_bytes = bincode::serialize(&credential(0x81, Address::new([1; 20]))).unwrap();
    assert!(
        bincode::deserialize::<AcademicCredential>(&elig_bytes).is_err(),
        "an attestation payload must not decode as an academic credential, or \
         every attestation would be filed in the wrong family"
    );
    assert!(bincode::deserialize::<EligibilityAttestation>(&cred_bytes).is_err());

    // And a payload that is neither is refused, not errored.
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();

    let t = tx(
        &gov,
        0,
        DocClassOperation::IssueCredential,
        DocSubcode::EligibilityAttestation,
        &CredentialIdData {
            credential_id: [0x82; 32],
        },
    );
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// Both dispatch arms pass a literal `0` where the block timestamp belongs and
/// a literal `0` for the transaction index, so every timestamp the executor
/// itself writes is 0 regardless of the block.
#[test]
fn the_block_timestamp_reaching_docclass_operations_is_always_zero() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .identity_roots()
        .put(&identity(0x83, gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x84, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::DeactivateIdentity,
            DocSubcode::IdentityRoot,
            &IdentityIdData {
                identity_id: [0x83; 32],
            },
        ),
        tx(
            &gov,
            1,
            DocClassOperation::DeactivateIssuer,
            DocSubcode::IssuerRegistry,
            &DeactivateIssuerData {
                issuer_address: gov.address(),
            },
        ),
        tx(
            &gov,
            2,
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: [0x84; 32],
                reason: RevocationReason::Expired,
            },
        ),
    ] {
        // A real, non-zero block timestamp on the live arm.
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 9, 1_700_000_000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        DocClassExecutor::v_get_identity_root(&view, &[0x83; 32])
            .unwrap()
            .unwrap()
            .updated_at,
        0
    );
    assert_eq!(
        DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap()
            .updated_at,
        0
    );
    assert_eq!(
        DocClassExecutor::v_get_latest_revocation(&view, &[0x84; 32])
            .unwrap()
            .unwrap()
            .revoked_at,
        0,
        "a revocation record carries no usable time at all"
    );
}

/// Every DocClass event a block produces lands at ONE key, so the family holds
/// exactly one row per block: the last event.
///
/// The key is `height || tx_index || event_index` and both arms pass `0` for
/// `tx_index`. Preserved, because threading the real index would change the
/// bytes at a live family.
#[test]
fn every_docclass_event_in_a_block_lands_at_one_key() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::RegisterIssuer,
            DocSubcode::IssuerRegistry,
            &government_issuer(gov.address()),
        ),
        tx(
            &gov,
            1,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity(0x85, gov.address()),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 11, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let rows: Vec<(Vec<u8>, Vec<u8>)> = view
        .prefix_iter(cf::DOCCLASS_EVENTS, &[])
        .unwrap()
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect();
    let mut expected_key = 11u64.to_be_bytes().to_vec();
    expected_key.extend_from_slice(&0u32.to_be_bytes());
    expected_key.extend_from_slice(&0u16.to_be_bytes());
    assert_eq!(rows.len(), 1, "two events, one row");
    assert_eq!(rows[0].0, expected_key);
    assert_eq!(
        rows[0].1,
        bincode::serialize(&DocClassEvent::IdentityRootCreated {
            identity_id: [0x85; 32],
            controller: gov.address(),
            subject_commitment: [0x85u8.wrapping_add(0x40); 32],
        })
        .unwrap(),
        "and it is the LAST event, not the first"
    );
}

/// Revocation is reversible: Revoke -> Suspend -> Reactivate returns a revoked
/// credential to Active.
///
/// Neither `revoke_credential` nor `suspend_credential` consults the current
/// status, and `reactivate_credential` only requires the LATEST record to say
/// `Suspended`. Nothing makes `Revoked` terminal.
#[test]
fn a_revoked_credential_can_be_suspended_and_then_reactivated() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x86, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let steps: [(u64, u64, DocClassOperation, RevocationStatus); 3] = [
        (
            0,
            20,
            DocClassOperation::RevokeCredential,
            RevocationStatus::Revoked,
        ),
        (
            1,
            21,
            DocClassOperation::SuspendCredential,
            RevocationStatus::Suspended,
        ),
        (
            2,
            22,
            DocClassOperation::ReactivateCredential,
            RevocationStatus::Active,
        ),
    ];
    for (nonce, height, op, expected) in steps {
        let t = if op == DocClassOperation::ReactivateCredential {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::Revocation,
                &CredentialIdData {
                    credential_id: [0x86; 32],
                },
            )
        } else {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: [0x86; 32],
                    reason: RevocationReason::KeyCompromise,
                },
            )
        };
        let r = executor
            .execute_tx(&mut view, &t, &proposer, height, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
        assert_eq!(
            DocClassExecutor::v_get_revocation_status(&view, &[0x86; 32]).unwrap(),
            expected
        );
    }
    assert_eq!(
        DocClassExecutor::v_get_eligibility(&view, &[0x86; 32])
            .unwrap()
            .unwrap()
            .revocation_status,
        RevocationStatus::Active,
        "a revoked credential is Active again, with no record of the reversal \
         being refused anywhere"
    );
}

/// A registered issuer can rewrite its OWN registry entry with no check on what
/// changed: subcodes, jurisdictions, status and the declared stake are all
/// taken from the payload.
///
/// `min_issuer_stake` is checked at registration only, and the stake it deducts
/// there is never reconciled with the number the row carries afterwards.
#[test]
fn an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself() {
    let (_state, db, _dir, executor) = setup_with_params(params_with_stake(1_000));
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut registered = government_issuer(gov.address());
    registered.stake_amount = 1_000;

    let mut self_promoted = government_issuer(gov.address());
    self_promoted.stake_amount = 999_999_999;
    self_promoted.jurisdictions = vec!["*".to_string()];
    self_promoted.authorized_subcodes = vec![
        DocSubcode::EligibilityAttestation,
        DocSubcode::GovernmentId,
        DocSubcode::Diploma,
    ];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let start = StateManager::v_get_balance(&view, &gov.address()).unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &registered,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    // As registered: one jurisdiction, and the check bites.
    assert!(DocClassExecutor::v_can_issue_subcode(
        &view,
        &gov.address(),
        DocSubcode::EligibilityAttestation,
        JURISDICTION
    )
    .unwrap());
    assert!(
        !DocClassExecutor::v_can_issue_subcode(
            &view,
            &gov.address(),
            DocSubcode::EligibilityAttestation,
            "UK"
        )
        .unwrap(),
        "a jurisdiction the issuer did not register for"
    );
    assert!(
        !DocClassExecutor::v_can_issue_subcode(
            &view,
            &gov.address(),
            DocSubcode::GovernmentId,
            JURISDICTION
        )
        .unwrap(),
        "a subcode the issuer did not register for, even though its TYPE allows it"
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                1,
                DocClassOperation::UpdateIssuer,
                DocSubcode::IssuerRegistry,
                &self_promoted,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let issuer = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
        .unwrap()
        .unwrap();
    assert_eq!(issuer.stake_amount, 999_999_999);
    assert_eq!(issuer.jurisdictions, vec!["*".to_string()]);
    assert_eq!(
        StateManager::v_get_balance(&view, &gov.address()).unwrap(),
        start - 1_000 - 200,
        "the registration deducted its declared stake and two fees were \
         charged; the update's new stake number cost nothing"
    );
    // The type check is the only thing that still bites: `Government` may not
    // issue a `Diploma` however the row is written.
    assert!(
        DocClassExecutor::v_can_issue_subcode(
            &view,
            &gov.address(),
            DocSubcode::GovernmentId,
            "anything"
        )
        .unwrap(),
        "a subcode it was never registered for, in a jurisdiction it was never \
         registered for"
    );
    assert!(!DocClassExecutor::v_can_issue_subcode(
        &view,
        &gov.address(),
        DocSubcode::Diploma,
        "US"
    )
    .unwrap());
}

/// Registration checks `min_issuer_stake`, and the stake it deducts is burned:
/// only the fee reaches the proposer, and nothing gives the stake back.
#[test]
fn the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody() {
    let (_state, db, _dir, executor) = setup_with_params(params_with_stake(1_000));
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut short = government_issuer(gov.address());
    short.stake_amount = 999;
    let mut ok = government_issuer(gov.address());
    ok.stake_amount = 1_000;

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let start = StateManager::v_get_balance(&view, &gov.address()).unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &short,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED, "999 is below the 1000 minimum");

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &ok,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    assert_eq!(
        StateManager::v_get_balance(&view, &gov.address()).unwrap(),
        start - 1_100
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &proposer).unwrap(),
        100,
        "the proposer receives the fee only -- the 1000-unit stake is deducted \
         from the sender and credited to no account at all"
    );

    // And deactivating the issuer returns none of it.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                1,
                DocClassOperation::DeactivateIssuer,
                DocSubcode::IssuerRegistry,
                &DeactivateIssuerData {
                    issuer_address: gov.address(),
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        StateManager::v_get_balance(&view, &gov.address()).unwrap(),
        start - 1_200,
        "one more fee, and no refund"
    );
}

/// `UpdateCredential` charges a fee, advances the nonce and writes nothing.
#[test]
fn update_credential_charges_a_fee_and_writes_nothing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .eligibility()
        .put(&eligibility(0x87, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::UpdateCredential,
                DocSubcode::EligibilityAttestation,
                &CredentialIdData {
                    credential_id: [0x87; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        families_changed(&db, &view),
        Vec::<&str>::new(),
        "no DocClass family moves -- not even the event journal"
    );
    // Stronger than "nothing changed": nothing was WRITTEN. A rewrite of the
    // same bytes would leave the content diff above empty while still staging a
    // row, charging the candidate's ceiling for it and capturing a pre-image, so
    // the pre-image set is what the claim actually rests on.
    for f in DOCCLASS_CFS {
        assert_eq!(
            view.preimages_for(f).count(),
            0,
            "{f}: UpdateCredential must stage no row at all"
        );
    }
    assert_eq!(
        StateManager::v_get_nonce(&view, &gov.address()).unwrap(),
        1,
        "but the fee was charged and the nonce advanced"
    );
}

/// An identity root is stored exactly as the sender supplied it.
///
/// `status`, `created_at`, `updated_at`, `schema_hash`, the key list and the
/// subject commitment all come from the payload. Nothing reconciles any of them
/// with the block, and nothing binds the subject commitment to the sender: any
/// funded account may anchor an identity claiming any subject.
#[test]
fn an_identity_root_is_stored_exactly_as_the_sender_supplied_it() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut hostile = identity(0x88, actor.address());
    hostile.status = IdentityStatus::Revoked;
    hostile.created_at = 0;
    hostile.updated_at = u64::MAX;
    hostile.schema_hash = [0xFF; 32];
    // A subject commitment the sender has no relationship to.
    hostile.subject_commitment = [0xCC; 32];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &hostile,
            ),
            &proposer,
            1,
            1_700_000_000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    assert_eq!(
        DocClassExecutor::v_get_identity_root(&view, &[0x88; 32]).unwrap(),
        Some(hostile),
        "byte for byte what the transaction carried, including a status of \
         Revoked at creation"
    );
    assert_eq!(
        DocClassExecutor::v_get_subject_identity_entries(&view, &[0xCC; 32]).unwrap(),
        vec![([0x88u8; 32], DocSubcode::IdentityRoot)],
        "and it is indexed under a subject commitment nothing tied to the sender"
    );
}

/// Schema validation is inactive below its activation height, which is 385,000.
///
/// `SchemaValidator` returns `Valid` for every credential below that height, so
/// the PII allowlist the module exists to enforce does not run on any chain
/// shorter than that.
#[test]
fn schema_validation_is_inactive_below_its_activation_height() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let edu = KeyPair::generate();
    fund(&db, &edu, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&educational_issuer(edu.address()))
        .unwrap();

    let mut with_pii = credential(0x89, edu.address());
    with_pii.metadata.attributes = vec![CredentialAttribute {
        name: "student_ssn".to_string(),
        value: "000-00-0000".to_string(),
    }];

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &edu,
                0,
                DocClassOperation::IssueCredential,
                DocSubcode::Diploma,
                &with_pii,
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "below the activation height the allowlist is not consulted: {:?}",
        r.status
    );
    assert_eq!(
        DocClassExecutor::v_get_credential(&view, &[0x89; 32])
            .unwrap()
            .unwrap()
            .metadata
            .attributes[0]
            .name,
        "student_ssn"
    );
}

/// The registration guard is a `contains`, so a CORRUPT issuer row reads as
/// registered and the registration is refused rather than reported.
///
/// Preserved, and it is the safe direction: upgrading it would turn today's
/// refusals into block-level errors.
#[test]
fn a_corrupt_issuer_row_is_read_as_presence_not_as_corruption() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    db.put(
        cf::DOCCLASS_ISSUERS,
        gov.address().as_bytes(),
        b"not a valid row",
    )
    .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &government_issuer(gov.address()),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, DOCCLASS_FAILED,
        "refused as already registered, not reported as corrupt"
    );
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// An identity and a credential that share a subject commitment write over each
/// other, and the next identity operation on that subject becomes a BLOCK-LEVEL
/// ERROR.
///
/// One family, one key, two incompatible value shapes. The credential store
/// decodes the identity's pair list as a bare id list -- bincode allows trailing
/// bytes, so it succeeds and silently drops the subcode -- and rewrites the row
/// in its own shape. The identity store then cannot decode its own index.
#[test]
fn an_identity_and_a_credential_sharing_a_subject_commitment_break_the_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();

    let shared = [0xDC; 32];
    let mut root = identity(0x8A, gov.address());
    root.subject_commitment = shared;
    let mut att = eligibility(0x8B, gov.address());
    att.subject_commitment = shared;

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &gov,
            0,
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &root,
        ),
        tx(
            &gov,
            1,
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &att,
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        view.get(cf::DOCCLASS_SUBJECT_INDEX, &shared).unwrap(),
        Some(bincode::serialize(&vec![[0x8Au8; 32], [0x8Bu8; 32]]).unwrap()),
        "the attestation rewrote the row as a BARE id list, so the identity's \
         subcode is gone"
    );

    // Any later identity write on that subject now fails to decode its index.
    let outcome = executor.execute_tx(
        &mut view,
        &tx(
            &gov,
            2,
            DocClassOperation::AddKey,
            DocSubcode::IdentityRoot,
            &AddKeyData {
                identity_id: [0x8A; 32],
                key: identity_key("auth-2", 0x87),
            },
        ),
        &proposer,
        1,
        1000,
    );
    let err = outcome.expect_err(
        "an identity operation on a subject a credential has touched must \
         ERROR, not silently write the wrong shape",
    );
    assert!(err.to_string().contains("Serialization"), "{err}");
}

/// Only the credential's own issuer may revoke it -- the one authorization
/// check in the revocation family that does bite.
#[test]
fn a_third_party_cannot_revoke_someone_elses_credential() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x8C, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                0,
                DocClassOperation::RevokeCredential,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: [0x8C; 32],
                    reason: RevocationReason::FraudulentIssuance,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// A SUSPENDED issuer can still revoke, suspend and supersede its credentials,
/// and can still rewrite its own registry row.
///
/// The revocation family reads the credential, never the registry, so
/// `DeactivateIssuer` stops new issuance and nothing else.
#[test]
fn a_suspended_issuer_can_still_revoke_and_update_itself() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    let mut suspended = government_issuer(gov.address());
    suspended.status = DocClassIssuerStatus::Suspended;
    store.issuers().put(&suspended).unwrap();
    store
        .eligibility()
        .put(&eligibility(0x8D, gov.address()))
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // New issuance is refused.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::IssueCredential,
                DocSubcode::EligibilityAttestation,
                &eligibility(0x8E, gov.address()),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, DOCCLASS_FAILED);

    // Revocation and self-update are not.
    for (nonce, op) in [
        (0u64, DocClassOperation::RevokeCredential),
        (1, DocClassOperation::UpdateIssuer),
    ] {
        let t = if op == DocClassOperation::RevokeCredential {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: [0x8D; 32],
                    reason: RevocationReason::IssuerCompromise,
                },
            )
        } else {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::IssuerRegistry,
                &government_issuer(gov.address()),
            )
        };
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 30, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }
    assert_eq!(
        DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap()
            .status,
        DocClassIssuerStatus::Active,
        "and the self-update put the issuer straight back to Active"
    );
}

/// The committed readers are unpaginated whole-family scans.
#[test]
fn the_committed_docclass_readers_return_two_thousand_rows_whole() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let store = DocClassStore::new(&db);
    for i in 0..2_000u32 {
        let mut address_bytes = [0u8; 20];
        address_bytes[..4].copy_from_slice(&i.to_be_bytes());
        let mut issuer = government_issuer(Address::new(address_bytes));
        issuer.name = format!("issuer-{i}");
        store.issuers().put(&issuer).unwrap();

        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        let mut root = identity(0, Address::new(address_bytes));
        root.identity_id = id;
        root.subject_commitment = id;
        store.identity_roots().put(&root).unwrap();
    }

    assert_eq!(store.issuers().get_all().unwrap().len(), 2_000);
    assert_eq!(store.issuers().get_active().unwrap().len(), 2_000);
    assert_eq!(
        store
            .issuers()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .len(),
        2_000,
        "no limit, no offset, no cursor"
    );
    assert_eq!(
        store
            .identity_roots()
            .get_by_controller(&Address::new({
                let mut b = [0u8; 20];
                b[..4].copy_from_slice(&7u32.to_be_bytes());
                b
            }))
            .unwrap()
            .len(),
        1,
        "and finding one identity by controller decodes all two thousand"
    );
}

/// A revocation key of the wrong WIDTH is skipped by the CANDIDATE reader too.
///
/// RocksDB prefix iteration can overrun the prefix, and a view's `prefix_iter`
/// merges committed rows with staged ones, so the width and prefix checks have
/// to survive the move. Without them a neighbouring row would be decoded as this
/// credential's revocation record -- and here it is not even a record.
#[test]
fn a_revocation_key_of_the_wrong_width_is_skipped_by_the_candidate_reader() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    let store = DocClassStore::new(&db);
    store
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();
    store
        .eligibility()
        .put(&eligibility(0x90, gov.address()))
        .unwrap();

    // 33 bytes: the credential's whole id plus one. A prefix scan yields it.
    let mut overrun = vec![0x90u8; 32];
    overrun.push(0);
    db.put(cf::DOCCLASS_REVOCATIONS, &overrun, b"not a valid row")
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x90; 32]).unwrap(),
        RevocationStatus::Active,
        "the 33-byte row is skipped before it is decoded"
    );

    // Suspend at height 40, then reactivate at 41: the guard has to see the
    // suspension and not the overrun row.
    for (nonce, height, op) in [
        (0u64, 40u64, DocClassOperation::SuspendCredential),
        (1, 41, DocClassOperation::ReactivateCredential),
    ] {
        let t = if op == DocClassOperation::SuspendCredential {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: [0x90; 32],
                    reason: RevocationReason::CertificateHold,
                },
            )
        } else {
            tx(
                &gov,
                nonce,
                op,
                DocSubcode::Revocation,
                &CredentialIdData {
                    credential_id: [0x90; 32],
                },
            )
        };
        let r = executor
            .execute_tx(&mut view, &t, &proposer, height, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &[0x90; 32]).unwrap(),
        RevocationStatus::Active
    );
    assert_eq!(
        DocClassExecutor::v_get_revocations_for_credential(&view, &[0x90; 32])
            .unwrap()
            .len(),
        2,
        "two records, and the overrun row is not one of them"
    );
}

/// A corrupt subject index in its CREDENTIAL shape errors the issue, with the
/// attestation row staged and nothing else.
///
/// The table above corrupts this family in its IDENTITY shape, through
/// `CreateIdentityRoot`. The credential shape is a different reader on the same
/// family and the same key width, and it has to fail the same way.
#[test]
fn a_corrupt_credential_shaped_subject_index_errors_the_issue() {
    const CORRUPT: &[u8] = b"not a valid row";
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&government_issuer(gov.address()))
        .unwrap();

    let subject = [0x91u8.wrapping_add(0x40); 32];
    db.put(cf::DOCCLASS_SUBJECT_INDEX, &subject, CORRUPT)
        .unwrap();
    let before = canonical(&db);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::IssueCredential,
                DocSubcode::EligibilityAttestation,
                &eligibility(0x91, gov.address()),
            ),
            &proposer,
            1,
            1000,
        );
        let err = outcome.expect_err("a corrupt subject index must ERROR");
        assert!(err.to_string().contains("Serialization"), "{err}");

        assert_eq!(
            families_changed(&db, &view),
            vec![cf::DOCCLASS_ELIGIBILITY],
            "the attestation row precedes the subject-index append, and the \
             issuer-index append never runs"
        );
        assert_eq!(
            view.get(cf::DOCCLASS_ELIGIBILITY, &[0x91u8; 32])
                .unwrap()
                .as_deref(),
            Some(&bincode::serialize(&eligibility(0x91, gov.address())).unwrap()[..])
        );
        assert_eq!(
            view.get(cf::DOCCLASS_SUBJECT_INDEX, &subject)
                .unwrap()
                .as_deref(),
            Some(CORRUPT),
            "and the corrupt row is left exactly as it was"
        );
        assert_eq!(StateManager::v_get_nonce(&view, &gov.address()).unwrap(), 1);
    }
    assert_eq!(canonical(&db), before);
}

/// The academic-credential path writes its ROW before either of its indexes,
/// and a ceiling can land between them.
///
/// The identity sweep above calibrates `CreateIdentityRoot`, which has one
/// index. This one calibrates `IssueCredential`, which has two, and requires a
/// ceiling that refuses with the credential staged and NEITHER index written --
/// which only the row-first order can produce.
#[test]
fn a_credential_refusal_part_way_stages_the_row_and_neither_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let edu = KeyPair::generate();
    fund(&db, &edu, 100_000_000);
    let proposer = Address::new([9; 20]);
    DocClassStore::new(&db)
        .issuers()
        .put(&educational_issuer(edu.address()))
        .unwrap();
    let before = canonical(&db);
    let signed_tx = tx(
        &edu,
        0,
        DocClassOperation::IssueCredential,
        DocSubcode::Diploma,
        &credential(0x92, edu.address()),
    );

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut v = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut v, &signed_tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };

    let mut row_only = 0usize;
    let mut row_and_subject = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");

        let row = view
            .get(cf::DOCCLASS_CREDENTIALS, &[0x92u8; 32])
            .unwrap()
            .is_some();
        let subject = view
            .get(cf::DOCCLASS_SUBJECT_INDEX, &[0x92u8.wrapping_add(0x40); 32])
            .unwrap()
            .is_some();
        let issuer = view
            .get(cf::DOCCLASS_ISSUER_INDEX, edu.address().as_bytes())
            .unwrap()
            .is_some();
        assert!(
            !subject || row,
            "ceiling {ceiling} staged the subject index without the credential"
        );
        assert!(
            !issuer || subject,
            "ceiling {ceiling} staged the issuer index without the subject one"
        );
        if row && !subject {
            row_only += 1;
        }
        if row && subject && !issuer {
            row_and_subject += 1;
        }
        assert_eq!(canonical(&db), before);
    }
    assert!(
        row_only > 0,
        "no ceiling refused with the credential staged and neither index"
    );
    assert!(
        row_and_subject > 0,
        "no ceiling refused between the two index appends"
    );
}

/// `RegisterIssuer` refuses to register anyone but the sender, and
/// `CreateIdentityRoot` refuses a controller that is not the sender.
///
/// These two are the whole of the sender-binding in the subsystem's creation
/// paths; the identity-mutation operations check the CONTROLLER on the stored
/// row instead, and nothing binds a subject commitment to anyone.
#[test]
fn registration_and_identity_creation_are_bound_to_the_sender() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let gov = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &gov, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::RegisterIssuer,
                DocSubcode::IssuerRegistry,
                &government_issuer(stranger.address()),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, DOCCLASS_FAILED,
        "a registration naming someone else's address is refused"
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &gov,
                0,
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &identity(0x93, stranger.address()),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, DOCCLASS_FAILED,
        "an identity naming someone else as controller is refused"
    );
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
    assert_eq!(StateManager::v_get_nonce(&view, &gov.address()).unwrap(), 0);
}
