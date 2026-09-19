//! Five DocClass activation heights, and the seven audit rows behind them.
//!
//! `docs/lane-a/ACTIVATION-AUDIT.md` rows AU-34, AU-35, AU-37, OV-23, OV-24,
//! OV-27 and D-19b.
//!
//! Every test here runs the SAME transactions against the SAME seeded database
//! twice -- once with the gate closed and once with it open -- and asserts that
//! the two nodes DISAGREE. The closed side is the unremediated binary, and a
//! closed-gate assertion that merely passes proves nothing: it has to reproduce
//! today's defect exactly, by name, or the gate is not dormant and the pinning
//! tests elsewhere are lying.
//!
//! Every gates literal is spelled `..DocClassGates::CLOSED`. `OPEN` would open
//! eight gates at once, and a pair that differs in six ways cannot attribute a
//! difference to one of them; a fixture spelled field by field stops isolating
//! what it says it isolates the moment another track adds a gate.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    AcademicCredential, Address, CredentialAttribute, CredentialMetadata, DocClassIssuer,
    DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData, DocSubcode,
    EligibilityAttestation, EligibilityType, Hash, IdentityRoot, IdentityStatus, IssuerKey,
    KeyType, RevocationReason, RevocationStatus,
};
use sumchain_state::{DocClassExecutionResult, DocClassExecutor, DocClassGates, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore};

const JURISDICTION: &str = "US";
/// Past `SchemaValidatorConfig::default().activation_height` (385,000), which
/// is a separate and older switch: below it nothing validates on either side of
/// any gate here, and a schema test run below it would pass for the wrong
/// reason.
const SCHEMA_HEIGHT: u64 = 400_000;

/// Only this gate. See the module header for why never `OPEN`.
const AUTHORITY: DocClassGates = DocClassGates {
    issuer_authority: true,
    ..DocClassGates::CLOSED
};
const RECORD: DocClassGates = DocClassGates {
    revocation_record: true,
    ..DocClassGates::CLOSED
};
const SCHEMA: DocClassGates = DocClassGates {
    credential_schema: true,
    ..DocClassGates::CLOSED
};
const BINDING: DocClassGates = DocClassGates {
    identity_binding: true,
    ..DocClassGates::CLOSED
};
const STAKE_RULE: DocClassGates = DocClassGates {
    issuer_stake_requirement: true,
    ..DocClassGates::CLOSED
};
const CLOSED: DocClassGates = DocClassGates::CLOSED;

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

fn issuer_key(id: &str, byte: u8) -> IssuerKey {
    IssuerKey {
        key_id: id.to_string(),
        public_key: [byte; 32],
        key_type: KeyType::Ed25519,
        added_at: 1_000,
        expires_at: 0,
        active: true,
        is_primary: true,
    }
}

fn issuer_of(
    address: Address,
    issuer_type: DocClassIssuerType,
    subcodes: Vec<DocSubcode>,
) -> DocClassIssuer {
    DocClassIssuer {
        address,
        name: "Registry of Vital Records".to_string(),
        issuer_type,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: subcodes,
        keys: vec![issuer_key("k-1", 0x51)],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

fn attestation(id: u8, issuer: Address) -> EligibilityAttestation {
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
        issuer_key_id: "k-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn academic(id: u8, issuer: Address, subcode: DocSubcode) -> AcademicCredential {
    AcademicCredential {
        credential_id: [id; 32],
        subject_address: Address::ZERO,
        subcode,
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
        issuer_key_id: "k-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

fn identity(id: u8, controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id: [id; 32],
        subject_commitment: [id.wrapping_add(0x40); 32],
        controller,
        additional_controllers: vec![],
        keys: vec![],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

#[derive(serde::Serialize)]
struct ReasonedData {
    credential_id: [u8; 32],
    reason: RevocationReason,
}

#[derive(serde::Serialize)]
struct CredentialIdData {
    credential_id: [u8; 32],
}

/// Drive one DocClass operation through the gate seam.
#[allow(clippy::too_many_arguments)]
fn run(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    operation: DocClassOperation,
    subcode: DocSubcode,
    payload: &impl serde::Serialize,
    height: u64,
    gates: DocClassGates,
) -> DocClassExecutionResult {
    DocClassExecutor::execute_with_gates(
        view,
        &params(),
        sender,
        &DocClassTxData {
            operation,
            subcode,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        height,
        1_000,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

/// Raw bytes rather than a serializable value, for the trial-decode cases.
#[allow(clippy::too_many_arguments)]
fn run_raw(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    operation: DocClassOperation,
    subcode: DocSubcode,
    data: Vec<u8>,
    height: u64,
    gates: DocClassGates,
) -> DocClassExecutionResult {
    DocClassExecutor::execute_with_gates(
        view,
        &params(),
        sender,
        &DocClassTxData {
            operation,
            subcode,
            data,
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        height,
        1_000,
        0,
        Hash::ZERO,
        gates,
    )
    .unwrap()
}

fn revocation_keys(view: &ExecutionView<'_, '_>, credential_id: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in view
        .prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)
        .unwrap()
    {
        let (key, _) = entry.unwrap();
        if &key[..32] == credential_id {
            out.push(key.to_vec());
        }
    }
    out.sort();
    out
}

// ── AU-34: the issuer that writes its own authority ─────────────────────────
//
// `UpdateIssuer` deserializes a whole `DocClassIssuer` from the payload and
// writes it over the registry row. The stake half of that wholesale write is
// already closed under `docclass_stake_escrow_enabled_from_height` and pinned
// by `an_update_cannot_inflate_the_recorded_stake_at_the_gate`. What was left,
// and is closed here, is the subcode, jurisdiction and self-reactivation
// halves, the last of which is the sharpest thing in the row: a SUSPENDED
// issuer is Active again after one ordinary transaction it sends itself.

/// A suspended issuer restores itself with one `UpdateIssuer` -- below the gate.
#[test]
fn a_suspended_issuer_reactivates_itself_only_below_the_gate() {
    let gov = KeyPair::generate();
    let mut suspended = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    suspended.status = DocClassIssuerStatus::Suspended;

    let mut restored = suspended.clone();
    restored.status = DocClassIssuerStatus::Active;

    let mut outcomes = Vec::new();
    for gates in [CLOSED, AUTHORITY] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&suspended).unwrap();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // A suspended issuer cannot issue. That is the state both sides start in.
        assert!(
            !DocClassExecutor::v_can_issue_subcode(
                &view,
                &gov.address(),
                DocSubcode::EligibilityAttestation,
                JURISDICTION
            )
            .unwrap(),
            "{gates:?}: a suspended issuer must not be able to issue before it tries"
        );

        let r = run(
            &mut view,
            &gov.address(),
            DocClassOperation::UpdateIssuer,
            DocSubcode::IssuerRegistry,
            &restored,
            1,
            gates,
        );
        assert!(
            r.success,
            "{gates:?}: the update itself succeeds on both sides -- what differs \
             is what it writes: {:?}",
            r.error
        );

        let row = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap();
        let can_issue = DocClassExecutor::v_can_issue_subcode(
            &view,
            &gov.address(),
            DocSubcode::EligibilityAttestation,
            JURISDICTION,
        )
        .unwrap();

        // And the consequence, end to end: issue an attestation.
        let issued = run(
            &mut view,
            &gov.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &attestation(0xA1, gov.address()),
            1,
            gates,
        );
        outcomes.push((row.status, can_issue, issued.success));
    }

    assert_eq!(
        outcomes[0],
        (DocClassIssuerStatus::Active, true, true),
        "below the gate the suspension is self-reversible: the row says Active, \
         the registry agrees, and the issuer issues"
    );
    assert_eq!(
        outcomes[1],
        (DocClassIssuerStatus::Suspended, false, false),
        "at the gate the registry keeps its own record of the status, so the \
         update cannot lift the suspension and the issue is still refused"
    );
}

/// The same transaction cannot grant a subcode, a jurisdiction or an issuer type.
#[test]
fn an_update_cannot_grant_itself_authority_at_the_gate() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );

    let mut promoted = registered.clone();
    promoted.authorized_subcodes = vec![
        DocSubcode::EligibilityAttestation,
        DocSubcode::GovernmentId,
        DocSubcode::Diploma,
    ];
    promoted.jurisdictions = vec!["*".to_string()];
    promoted.issuer_type = DocClassIssuerType::Educational;
    promoted.registered_at = 9_999;

    let mut outcomes = Vec::new();
    for gates in [CLOSED, AUTHORITY] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::UpdateIssuer,
                DocSubcode::IssuerRegistry,
                &promoted,
                1,
                gates,
            )
            .success
        );

        let row = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap();
        // A subcode AND a jurisdiction it never registered for, asked through
        // the real check rather than by reading the row back.
        let diploma_elsewhere =
            DocClassExecutor::v_can_issue_subcode(&view, &gov.address(), DocSubcode::Diploma, "UK")
                .unwrap();
        // And what it DID register for. Below the gate the issuer type it
        // awarded itself costs it this, which is the same defect pointing the
        // other way: the registry is stenographic, so the row can be made
        // incoherent as easily as it can be made generous.
        let own_subcode = DocClassExecutor::v_can_issue_subcode(
            &view,
            &gov.address(),
            DocSubcode::EligibilityAttestation,
            JURISDICTION,
        )
        .unwrap();
        outcomes.push((
            row.authorized_subcodes.len(),
            row.jurisdictions.clone(),
            row.issuer_type,
            row.registered_at,
            diploma_elsewhere,
            own_subcode,
        ));
    }

    assert_eq!(
        outcomes[0],
        (
            3,
            vec!["*".to_string()],
            DocClassIssuerType::Educational,
            9_999,
            true,
            false
        ),
        "below the gate the payload rewrites the row wholesale: the issuer now \
         passes the authorization check for a subcode and a jurisdiction it was \
         never registered for, under a TYPE it awarded itself -- and loses the \
         one subcode it legitimately had"
    );
    assert_eq!(
        outcomes[1],
        (
            1,
            vec![JURISDICTION.to_string()],
            DocClassIssuerType::Government,
            1_000,
            false,
            true
        ),
        "at the gate the five registry-owned fields keep their recorded values"
    );
}

/// The gate freezes the authority and NOTHING else: the descriptive fields the
/// registry never consults are still the sender's to change.
///
/// Without this, "the update writes nothing" would pass every assertion above
/// and would be a different, larger change.
#[test]
fn an_update_still_rewrites_the_descriptive_fields_at_the_gate() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    let mut renamed = registered.clone();
    renamed.name = "Office of Records".to_string();
    renamed.keys = vec![issuer_key("k-2", 0x77)];
    renamed.updated_at = 5_000;
    renamed.metadata = Some("ipfs://cid".to_string());

    for gates in [CLOSED, AUTHORITY] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::UpdateIssuer,
                DocSubcode::IssuerRegistry,
                &renamed,
                1,
                gates,
            )
            .success
        );
        let row = DocClassExecutor::v_get_docclass_issuer(&view, &gov.address())
            .unwrap()
            .unwrap();
        assert_eq!(row.name, "Office of Records", "{gates:?}");
        assert_eq!(row.keys, renamed.keys, "{gates:?}");
        assert_eq!(row.updated_at, 5_000, "{gates:?}");
        assert_eq!(row.metadata.as_deref(), Some("ipfs://cid"), "{gates:?}");
    }
}

// ── OV-23 and OV-24: the revocation record is a history ─────────────────────

/// Revoke, suspend, reactivate walks a REVOKED credential back to Active --
/// below the gate.
#[test]
fn a_revoked_credential_is_walked_back_to_active_only_below_the_gate() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    let cred = [0xC1u8; 32];

    let mut outcomes = Vec::new();
    for gates in [CLOSED, RECORD] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        let store = DocClassStore::new(&db);
        store.issuers().put(&registered).unwrap();
        store
            .eligibility()
            .put(&attestation(0xC1, gov.address()))
            .unwrap();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let revoked = run(
            &mut view,
            &gov.address(),
            DocClassOperation::RevokeCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: cred,
                reason: RevocationReason::KeyCompromise,
            },
            10,
            gates,
        );
        assert!(revoked.success, "{gates:?}: {:?}", revoked.error);
        assert_eq!(
            DocClassExecutor::v_get_revocation_status(&view, &cred).unwrap(),
            RevocationStatus::Revoked,
            "{gates:?}: both sides revoke"
        );

        let suspended = run(
            &mut view,
            &gov.address(),
            DocClassOperation::SuspendCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: cred,
                reason: RevocationReason::CertificateHold,
            },
            11,
            gates,
        );

        let reactivated = run(
            &mut view,
            &gov.address(),
            DocClassOperation::ReactivateCredential,
            DocSubcode::Revocation,
            &CredentialIdData {
                credential_id: cred,
            },
            12,
            gates,
        );

        let final_status = DocClassExecutor::v_get_revocation_status(&view, &cred).unwrap();
        let mirrored = DocClassExecutor::v_get_eligibility(&view, &cred)
            .unwrap()
            .unwrap()
            .revocation_status;
        outcomes.push((
            suspended.success,
            suspended.error.clone(),
            reactivated.success,
            final_status,
            mirrored,
        ));
    }

    let (s_ok, _, r_ok, status, mirrored) = outcomes[0].clone();
    assert!(
        s_ok,
        "below the gate suspension has no current-status guard"
    );
    assert!(
        r_ok,
        "and reactivation then sees `Suspended` and allows itself"
    );
    assert_eq!(
        (status, mirrored),
        (RevocationStatus::Active, RevocationStatus::Active),
        "so a revoked credential is Active again, and the mirrored status on the \
         credential row followed it back"
    );

    let (s_ok, s_err, r_ok, status, mirrored) = outcomes[1].clone();
    assert!(
        !s_ok,
        "at the gate `Revoked` is terminal and suspension refuses"
    );
    assert!(
        s_err.as_deref().unwrap().contains("Cannot suspend"),
        "{s_err:?}"
    );
    assert!(
        !r_ok,
        "and reactivation, still seeing `Revoked`, refuses for its own reason"
    );
    assert_eq!(
        (status, mirrored),
        (RevocationStatus::Revoked, RevocationStatus::Revoked),
        "the credential stays revoked on both records"
    );
}

/// A suspension is still liftable at the gate: the rule is that REVOCATION is
/// terminal, not that the lifecycle is frozen.
#[test]
fn a_suspended_credential_is_still_reactivated_at_the_gate() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    let cred = [0xC2u8; 32];

    for gates in [CLOSED, RECORD] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        let store = DocClassStore::new(&db);
        store.issuers().put(&registered).unwrap();
        store
            .eligibility()
            .put(&attestation(0xC2, gov.address()))
            .unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::SuspendCredential,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: cred,
                    reason: RevocationReason::CertificateHold,
                },
                10,
                gates,
            )
            .success,
            "{gates:?}"
        );
        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::ReactivateCredential,
                DocSubcode::Revocation,
                &CredentialIdData {
                    credential_id: cred,
                },
                11,
                gates,
            )
            .success,
            "{gates:?}"
        );
        assert_eq!(
            DocClassExecutor::v_get_revocation_status(&view, &cred).unwrap(),
            RevocationStatus::Active,
            "{gates:?}: a suspension lifts on both sides"
        );
    }
}

/// Two revocation records at one height are ONE row below the gate and TWO
/// above it -- and the one that survives below is the wrong one.
#[test]
fn two_revocations_at_one_height_are_one_row_below_the_gate_and_two_above_it() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    let cred = [0xC3u8; 32];

    let mut outcomes = Vec::new();
    for gates in [CLOSED, RECORD] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        let store = DocClassStore::new(&db);
        store.issuers().put(&registered).unwrap();
        store
            .eligibility()
            .put(&attestation(0xC3, gov.address()))
            .unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // Both in ONE block, at height 20.
        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::SuspendCredential,
                DocSubcode::Revocation,
                &ReasonedData {
                    credential_id: cred,
                    reason: RevocationReason::CertificateHold,
                },
                20,
                gates,
            )
            .success,
            "{gates:?}"
        );
        assert!(
            run(
                &mut view,
                &gov.address(),
                DocClassOperation::ReactivateCredential,
                DocSubcode::Revocation,
                &CredentialIdData {
                    credential_id: cred,
                },
                20,
                gates,
            )
            .success,
            "{gates:?}"
        );

        let keys = revocation_keys(&view, &cred);
        let records = DocClassExecutor::v_get_revocations_for_credential(&view, &cred).unwrap();
        outcomes.push((
            keys.iter().map(|k| k.len()).collect::<Vec<_>>(),
            records.iter().map(|r| r.status).collect::<Vec<_>>(),
            DocClassExecutor::v_get_revocation_status(&view, &cred).unwrap(),
        ));
    }

    assert_eq!(
        outcomes[0],
        (
            vec![40],
            vec![RevocationStatus::Active],
            RevocationStatus::Active
        ),
        "below the gate the height is the whole key, so the reactivation \
         overwrote the suspension and the block's record of WHY the credential \
         was ever suspended is gone"
    );
    assert_eq!(
        outcomes[1],
        (
            vec![44, 44],
            vec![RevocationStatus::Active, RevocationStatus::Suspended],
            RevocationStatus::Active
        ),
        "at the gate each record is its own row, they come back most recent \
         first within the block, and the current status is still the last one"
    );
}

/// A record written before activation is still found, still ordered, and still
/// the one the status reads -- with a sequenced record landing after it.
#[test]
fn a_legacy_record_and_a_sequenced_one_at_one_height_order_correctly() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );
    let cred = [0xC4u8; 32];

    let (_state, db, _dir, _executor) = setup_with_params(params());
    fund(&db, &gov, 100_000_000);
    let store = DocClassStore::new(&db);
    store.issuers().put(&registered).unwrap();
    store
        .eligibility()
        .put(&attestation(0xC4, gov.address()))
        .unwrap();
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Height 30 below the gate: a legacy 40-byte record.
    assert!(
        run(
            &mut view,
            &gov.address(),
            DocClassOperation::SuspendCredential,
            DocSubcode::Revocation,
            &ReasonedData {
                credential_id: cred,
                reason: RevocationReason::CertificateHold,
            },
            30,
            CLOSED,
        )
        .success
    );
    // The same height, now above it: a sequenced 44-byte record that must NOT
    // replace the legacy one and must read as the later of the two.
    assert!(
        run(
            &mut view,
            &gov.address(),
            DocClassOperation::ReactivateCredential,
            DocSubcode::Revocation,
            &CredentialIdData {
                credential_id: cred,
            },
            30,
            RECORD,
        )
        .success
    );

    let keys = revocation_keys(&view, &cred);
    assert_eq!(
        keys.iter().map(|k| k.len()).collect::<Vec<_>>(),
        vec![40, 44],
        "two rows, one of each width"
    );
    let records = DocClassExecutor::v_get_revocations_for_credential(&view, &cred).unwrap();
    assert_eq!(
        records.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![RevocationStatus::Active, RevocationStatus::Suspended],
        "the sequenced record sorts AFTER the legacy one at the same height, \
         which is the order they were written in"
    );
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &cred).unwrap(),
        RevocationStatus::Active
    );
}

// ── OV-27 and D-19b: the declared subcode decides ───────────────────────────

/// The envelope's subcode is ignored below the gate and authoritative above it.
#[test]
fn the_envelope_subcode_is_ignored_below_the_gate_and_decides_above_it() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // An eligibility attestation, declared in the envelope as a DIPLOMA.
        // Below the gate the envelope is never read: the payload falls through
        // the academic decode and is stored, indexed and evented as an
        // attestation, under a subcode this issuer could not issue.
        let r = run(
            &mut view,
            &gov.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::Diploma,
            &attestation(0xD1, gov.address()),
            1,
            gates,
        );
        let stored = DocClassExecutor::v_eligibility_exists(&view, &[0xD1; 32]).unwrap();
        outcomes.push((r.success, r.error.clone(), stored));
    }

    assert!(
        outcomes[0].0 && outcomes[0].2,
        "below the gate the trial decode wins and the row is written: {:?}",
        outcomes[0].1
    );
    assert!(
        !outcomes[1].0,
        "at the gate a Diploma envelope must decode as an AcademicCredential"
    );
    assert!(
        outcomes[1]
            .1
            .as_deref()
            .unwrap()
            .contains("Not an academic credential"),
        "{:?}",
        outcomes[1].1
    );
    assert!(!outcomes[1].2, "and nothing is stored");
}

/// A credential whose own subcode disagrees with the envelope's.
///
/// This is the half that matters even when both schemas decode: it is
/// `credential.subcode` the schema validator dispatches on and
/// `v_can_issue_subcode` is asked about, so two subcodes that disagree are two
/// different questions answered about one row.
#[test]
fn a_credential_whose_subcode_disagrees_is_stored_below_the_gate_and_refused_above_it() {
    let edu = KeyPair::generate();
    let registered = issuer_of(
        edu.address(),
        DocClassIssuerType::Educational,
        vec![DocSubcode::Diploma, DocSubcode::AcademicTranscript],
    );

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &edu, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // Envelope says 810, the credential says 811.
        let r = run(
            &mut view,
            &edu.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::AcademicTranscript,
            &academic(0xD2, edu.address(), DocSubcode::Diploma),
            1,
            gates,
        );
        let stored = DocClassExecutor::v_credential_exists(&view, &[0xD2; 32]).unwrap();
        outcomes.push((r.success, r.error.clone(), stored));
    }

    assert!(
        outcomes[0].0 && outcomes[0].2,
        "below the gate the envelope is not consulted, so the disagreement is \
         invisible and the row is written: {:?}",
        outcomes[0].1
    );
    assert!(!outcomes[1].0, "at the gate the two subcodes must agree");
    assert!(
        outcomes[1].1.as_deref().unwrap().contains("disagrees"),
        "{:?}",
        outcomes[1].1
    );
    assert!(!outcomes[1].2);
}

/// A subcode that carries no credential family at all.
#[test]
fn an_issue_under_a_non_credential_subcode_is_accepted_below_the_gate_only() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = run(
            &mut view,
            &gov.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::Policy,
            &attestation(0xD3, gov.address()),
            1,
            gates,
        );
        outcomes.push((r.success, r.error.clone()));
    }
    assert!(outcomes[0].0, "{:?}", outcomes[0].1);
    assert!(!outcomes[1].0);
    assert!(
        outcomes[1]
            .1
            .as_deref()
            .unwrap()
            .contains("does not carry subcode"),
        "{:?}",
        outcomes[1].1
    );
}

/// D-19b: the uncovered academic subcodes. 813 has no validator arm, so a
/// megabyte of free text in `metadata.title` is admitted below the gate.
#[test]
fn an_uncovered_academic_subcode_is_unchecked_below_the_gate_and_checked_above_it() {
    let pro = KeyPair::generate();
    let registered = issuer_of(
        pro.address(),
        DocClassIssuerType::Professional,
        vec![DocSubcode::ProfessionalLicense],
    );

    let mut cred = academic(0xD4, pro.address(), DocSubcode::ProfessionalLicense);
    cred.metadata.title = "x".repeat(100_000);

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &pro, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = run(
            &mut view,
            &pro.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::ProfessionalLicense,
            &cred,
            SCHEMA_HEIGHT,
            gates,
        );
        let stored = DocClassExecutor::v_credential_exists(&view, &[0xD4; 32]).unwrap();
        outcomes.push((r.success, r.error.clone(), stored));
    }

    assert!(
        outcomes[0].0 && outcomes[0].2,
        "below the gate the validator has no arm for SRC-813 and returns Valid: \
         {:?}",
        outcomes[0].1
    );
    assert!(!outcomes[1].0, "at the gate the core field bounds apply");
    assert!(
        outcomes[1]
            .1
            .as_deref()
            .unwrap()
            .contains("metadata.title exceeds max length"),
        "{:?}",
        outcomes[1].1
    );
    assert!(!outcomes[1].2);
}

/// And a LAWFUL SRC-813 credential is admitted on both sides: the gate is a
/// bound on the free text, not a ban on the subcode.
///
/// Its own `#[test]` rather than a second loop in the one above, because
/// `execution_boundary.rs::no_test_publishes_a_candidate_by_hand` reads a
/// function that seeds a database after an overlay has existed in it as a
/// second publisher -- which is the right rule and the wrong diagnosis here,
/// and splitting the function is cheaper than arguing with it.
#[test]
fn a_lawful_uncovered_academic_subcode_is_admitted_on_both_sides() {
    let pro = KeyPair::generate();
    let registered = issuer_of(
        pro.address(),
        DocClassIssuerType::Professional,
        vec![DocSubcode::ProfessionalLicense],
    );
    let lawful = academic(0xD5, pro.address(), DocSubcode::ProfessionalLicense);

    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &pro, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        assert!(
            run(
                &mut view,
                &pro.address(),
                DocClassOperation::IssueCredential,
                DocSubcode::ProfessionalLicense,
                &lawful,
                SCHEMA_HEIGHT,
                gates,
            )
            .success,
            "{gates:?}"
        );
        assert!(DocClassExecutor::v_credential_exists(&view, &[0xD5; 32]).unwrap());
    }
}

/// D-19b's other half: eligibility attestations, which no path has ever
/// validated, at any height.
#[test]
fn an_attestation_payload_hint_is_unchecked_below_the_gate_and_checked_above_it() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );

    let mut att = attestation(0xD6, gov.address());
    att.payload_hint =
        Some("https://example.invalid/doc?name=Jane%20Doe&dob=1990-01-01".to_string());

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = run(
            &mut view,
            &gov.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &att,
            SCHEMA_HEIGHT,
            gates,
        );
        let stored = DocClassExecutor::v_eligibility_exists(&view, &[0xD6; 32]).unwrap();
        outcomes.push((r.success, r.error.clone(), stored));
    }

    assert!(
        outcomes[0].0 && outcomes[0].2,
        "below the gate `issue_eligibility` calls no validator at all, so a URL \
         carrying a name and a date of birth is stored verbatim: {:?}",
        outcomes[0].1
    );
    assert!(!outcomes[1].0, "at the gate the storage-hint check applies");
    assert!(
        outcomes[1]
            .1
            .as_deref()
            .unwrap()
            .contains("suspicious PII pattern"),
        "{:?}",
        outcomes[1].1
    );
    assert!(!outcomes[1].2);
}

/// The covered three are unchanged by the wider validator.
///
/// A widening that also changed 810, 811 or 812 would be a second consensus
/// change hiding inside the first.
#[test]
fn the_three_covered_subcodes_behave_identically_on_both_sides() {
    let edu = KeyPair::generate();
    let registered = issuer_of(
        edu.address(),
        DocClassIssuerType::Educational,
        vec![
            DocSubcode::Diploma,
            DocSubcode::AcademicTranscript,
            DocSubcode::EnrollmentVerification,
        ],
    );

    for (i, subcode) in [
        DocSubcode::Diploma,
        DocSubcode::AcademicTranscript,
        DocSubcode::EnrollmentVerification,
    ]
    .into_iter()
    .enumerate()
    {
        // A disallowed attribute key: the allowlist arms reject it, and the
        // wider validator must reject it for exactly the same reason.
        let mut bad = academic(0xE0 + i as u8, edu.address(), subcode);
        bad.metadata.attributes = vec![CredentialAttribute {
            name: "student_full_name".to_string(),
            value: "Jane Doe".to_string(),
        }];

        let mut errs = Vec::new();
        for gates in [CLOSED, SCHEMA] {
            let (_state, db, _dir, _executor) = setup_with_params(params());
            fund(&db, &edu, 100_000_000);
            DocClassStore::new(&db).issuers().put(&registered).unwrap();
            let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
            let mut view = ExecutionView::new(&mut overlay);
            let r = run(
                &mut view,
                &edu.address(),
                DocClassOperation::IssueCredential,
                subcode,
                &bad,
                SCHEMA_HEIGHT,
                gates,
            );
            // The allowlist is a `HashSet`, so the ORDER it prints the allowed
            // keys in is not stable between runs. The claim is the outcome and
            // the rejected key, not the rendering of the set.
            errs.push((
                r.success,
                r.error
                    .as_deref()
                    .map(|e| e.contains("Disallowed attribute key 'student_full_name'")),
            ));
        }
        assert_eq!(
            errs[0], errs[1],
            "{subcode:?}: the covered arms must produce the identical outcome on \
             both sides of the activation"
        );
        assert!(!errs[0].0, "{subcode:?}: and that outcome is a refusal");
        assert_eq!(
            errs[0].1,
            Some(true),
            "{subcode:?}: refused by the subcode's own allowlist"
        );
    }
}

/// A payload that decodes as NEITHER family.
#[test]
fn an_undecodable_credential_payload_fails_on_both_sides_with_different_words() {
    let gov = KeyPair::generate();
    let registered = issuer_of(
        gov.address(),
        DocClassIssuerType::Government,
        vec![DocSubcode::EligibilityAttestation],
    );

    let mut outcomes = Vec::new();
    for gates in [CLOSED, SCHEMA] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &gov, 100_000_000);
        DocClassStore::new(&db).issuers().put(&registered).unwrap();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = run_raw(
            &mut view,
            &gov.address(),
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            b"not a credential".to_vec(),
            1,
            gates,
        );
        outcomes.push((r.success, r.error.clone()));
    }
    assert!(!outcomes[0].0 && !outcomes[1].0);
    assert_eq!(
        outcomes[0].1.as_deref(),
        Some("Invalid credential data"),
        "below the gate both decodes are tried and both errors discarded"
    );
    assert!(
        outcomes[1]
            .1
            .as_deref()
            .unwrap()
            .contains("Not an eligibility attestation:"),
        "at the gate the declared family's own decode error is reported: {:?}",
        outcomes[1].1
    );
}

// ── AU-35: what anchors a subject commitment ────────────────────────────────
//
// `create_identity_root` checks `controller == sender` and then stores the
// deserialized struct verbatim, so any funded account anchors a root claiming
// any `subject_commitment`, in any `status`. The gate closes two halves of
// that; it does not bind the commitment to a person, because this tree records
// nothing to bind it to.

/// A second account anchors a root over somebody else's subject commitment --
/// below the gate.
#[test]
fn a_subject_commitment_is_claimed_by_a_stranger_only_below_the_gate() {
    let first = KeyPair::generate();
    let stranger = KeyPair::generate();
    let shared = [0xB7u8; 32];

    let mut outcomes = Vec::new();
    for gates in [CLOSED, BINDING] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &first, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut mine = identity(0xB1, first.address());
        mine.subject_commitment = shared;
        assert!(
            run(
                &mut view,
                &first.address(),
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &mine,
                1,
                gates,
            )
            .success,
            "{gates:?}: the FIRST anchor succeeds on both sides"
        );

        // A different account, a different identity id, the same subject.
        let mut theirs = identity(0xB2, stranger.address());
        theirs.subject_commitment = shared;
        let r = run(
            &mut view,
            &stranger.address(),
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &theirs,
            1,
            gates,
        );
        let stolen = DocClassExecutor::v_identity_root_exists(&view, &[0xB2; 32]).unwrap();
        let entries = DocClassExecutor::v_get_subject_identity_entries(&view, &shared)
            .unwrap()
            .len();
        let paid = StateManager::v_get_balance(&view, &stranger.address()).unwrap();
        outcomes.push((r.success, r.error.clone(), stolen, entries, paid));

        // And the first controller can still anchor ANOTHER root over its own
        // commitment on both sides: the rule is whose commitment it is, not how
        // many roots may name it.
        let mut second_of_mine = identity(0xB3, first.address());
        second_of_mine.subject_commitment = shared;
        assert!(
            run(
                &mut view,
                &first.address(),
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &second_of_mine,
                1,
                gates,
            )
            .success,
            "{gates:?}: the original controller is not locked out of its own subject"
        );
    }

    let (ok, _, stolen, entries, paid) = outcomes[0].clone();
    assert!(
        ok && stolen,
        "below the gate the stranger's root is written"
    );
    assert_eq!(
        entries, 2,
        "and it joins the first controller's subject index"
    );
    assert_eq!(paid, 100_000_000 - 100, "having paid an ordinary fee");

    let (ok, err, stolen, entries, paid) = outcomes[1].clone();
    assert!(
        !ok,
        "at the gate the commitment belongs to its first controller"
    );
    assert!(
        err.as_deref()
            .unwrap()
            .contains("already anchored by another controller"),
        "{err:?}"
    );
    assert!(!stolen, "nothing is written");
    assert_eq!(entries, 1, "and the index is untouched");
    assert_eq!(paid, 100_000_000, "and the refusal lands before the fee");
}

/// A root created into a lifecycle state the payload chose.
#[test]
fn an_identity_is_created_in_the_payloads_status_only_below_the_gate() {
    let owner = KeyPair::generate();

    let mut statuses = Vec::new();
    for gates in [CLOSED, BINDING] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        fund(&db, &owner, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let mut root = identity(0xB4, owner.address());
        root.status = IdentityStatus::Revoked;
        assert!(
            run(
                &mut view,
                &owner.address(),
                DocClassOperation::CreateIdentityRoot,
                DocSubcode::IdentityRoot,
                &root,
                1,
                gates,
            )
            .success,
            "{gates:?}"
        );
        statuses.push(
            DocClassExecutor::v_get_identity_root(&view, &[0xB4; 32])
                .unwrap()
                .unwrap()
                .status,
        );
    }
    assert_eq!(
        statuses,
        vec![IdentityStatus::Revoked, IdentityStatus::Active],
        "below the gate the sender chooses the lifecycle state the two \
         lifecycle arms exist to reach; at the gate the executor writes Active"
    );
}

// ── AU-37: the declared issuer-stake rule ───────────────────────────────────

/// `require_issuer_stake: false` is read by nothing below the gate, so the
/// minimum is enforced anyway.
#[test]
fn require_issuer_stake_is_read_only_at_the_gate() {
    let mut p = params();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 1_000;
        d.require_issuer_stake = false;
    }

    let mut outcomes = Vec::new();
    for gates in [CLOSED, STAKE_RULE] {
        let (_state, db, _dir, _executor) = setup_with_params(p.clone());
        let gov = KeyPair::generate();
        fund(&db, &gov, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // No stake declared, and the operator said none is required.
        let mut applicant = issuer_of(
            gov.address(),
            DocClassIssuerType::Government,
            vec![DocSubcode::EligibilityAttestation],
        );
        applicant.stake_amount = 0;

        let r = DocClassExecutor::execute_with_gates(
            &mut view,
            &p,
            &gov.address(),
            &DocClassTxData {
                operation: DocClassOperation::RegisterIssuer,
                subcode: DocSubcode::IssuerRegistry,
                data: bincode::serialize(&applicant).unwrap(),
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            100,
            1,
            1_000,
            0,
            Hash::ZERO,
            gates,
        )
        .unwrap();
        outcomes.push((
            r.success,
            r.error.clone(),
            DocClassExecutor::v_issuer_is_registered(&view, &gov.address()).unwrap(),
        ));
    }

    assert!(
        !outcomes[0].0,
        "below the gate `require_issuer_stake: false` is read by nothing and \
         the minimum bites anyway"
    );
    assert_eq!(outcomes[0].1.as_deref(), Some("Insufficient stake"));
    assert!(!outcomes[0].2);

    assert!(
        outcomes[1].0,
        "at the gate the declared rule is the rule applied: {:?}",
        outcomes[1].1
    );
    assert!(outcomes[1].2, "and the issuer is registered");
}

/// `require_issuer_stake: true` behaves identically on both sides, which is
/// what makes the gate a READ of the field rather than a removal of the check.
#[test]
fn a_required_stake_is_still_enforced_at_the_gate() {
    let mut p = params();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 1_000;
        d.require_issuer_stake = true;
    }

    for gates in [CLOSED, STAKE_RULE] {
        let (_state, db, _dir, _executor) = setup_with_params(p.clone());
        let gov = KeyPair::generate();
        fund(&db, &gov, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let mut applicant = issuer_of(
            gov.address(),
            DocClassIssuerType::Government,
            vec![DocSubcode::EligibilityAttestation],
        );
        applicant.stake_amount = 999;
        let r = DocClassExecutor::execute_with_gates(
            &mut view,
            &p,
            &gov.address(),
            &DocClassTxData {
                operation: DocClassOperation::RegisterIssuer,
                subcode: DocSubcode::IssuerRegistry,
                data: bincode::serialize(&applicant).unwrap(),
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            100,
            1,
            1_000,
            0,
            Hash::ZERO,
            gates,
        )
        .unwrap();
        assert!(!r.success, "{gates:?}");
        assert_eq!(r.error.as_deref(), Some("Insufficient stake"), "{gates:?}");
    }
}

// ── Dormancy ────────────────────────────────────────────────────────────────

/// None of the five is open in any shipped configuration, at any height.
#[test]
fn the_five_docclass_gates_are_dormant_by_default() {
    for h in [0u64, 1, 1_000, SCHEMA_HEIGHT, u64::MAX] {
        for p in [ChainParams::default(), ChainParams::with_v2_enabled()] {
            let g = DocClassGates::from_params(&p, h);
            assert!(!g.issuer_authority, "issuer_authority open at {h}");
            assert!(!g.revocation_record, "revocation_record open at {h}");
            assert!(!g.credential_schema, "credential_schema open at {h}");
            assert!(!g.identity_binding, "identity_binding open at {h}");
            assert!(
                !g.issuer_stake_requirement,
                "issuer_stake_requirement open at {h}"
            );
        }
    }
    assert!(!CLOSED.issuer_authority);
    assert!(!CLOSED.revocation_record);
    assert!(!CLOSED.credential_schema);
    assert!(DocClassGates::OPEN.issuer_authority);
    assert!(DocClassGates::OPEN.revocation_record);
    assert!(DocClassGates::OPEN.credential_schema);
    assert!(DocClassGates::OPEN.identity_binding);
    assert!(DocClassGates::OPEN.issuer_stake_requirement);
}

/// Each accessor answers for its own field and no other.
///
/// `remediation_gates.rs` asserts the PAIRING out of the source; this asserts
/// it out of BEHAVIOUR, which is the half a source scan cannot reach.
#[test]
fn each_of_the_five_gates_answers_only_to_its_own_height() {
    let cases: [(&str, fn(&mut ChainParams, u64)); 5] = [
        ("issuer_authority", |p, h| {
            p.docclass_issuer_authority_enabled_from_height = Some(h)
        }),
        ("revocation_record", |p, h| {
            p.docclass_revocation_record_enabled_from_height = Some(h)
        }),
        ("credential_schema", |p, h| {
            p.docclass_credential_schema_enabled_from_height = Some(h)
        }),
        ("identity_binding", |p, h| {
            p.docclass_identity_binding_enabled_from_height = Some(h)
        }),
        ("issuer_stake_requirement", |p, h| {
            p.docclass_issuer_stake_requirement_enabled_from_height = Some(h)
        }),
    ];
    for (name, set) in cases {
        let mut p = ChainParams::with_v2_enabled();
        set(&mut p, 100);
        let below = DocClassGates::from_params(&p, 99);
        let at = DocClassGates::from_params(&p, 100);
        let opened: Vec<&str> = [
            ("issuer_authority", at.issuer_authority),
            ("revocation_record", at.revocation_record),
            ("credential_schema", at.credential_schema),
            ("identity_binding", at.identity_binding),
            ("issuer_stake_requirement", at.issuer_stake_requirement),
        ]
        .into_iter()
        .filter(|(_, open)| *open)
        .map(|(n, _)| n)
        .collect();
        assert_eq!(
            opened,
            vec![name],
            "setting {name}'s height opened {opened:?}"
        );
        assert_eq!(
            below,
            DocClassGates::CLOSED,
            "{name} must be closed one block below its height"
        );
    }
}
