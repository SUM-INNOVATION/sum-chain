//! Every transaction `sumchain_primitives::docclass_build` produces is one the
//! chain executes.
//!
//! The builder module mirrors the executor's private payload structs field for
//! field. A mirror that drifted would still serialize, and only execution would
//! notice, so this file signs each built transaction with a SYNTHETIC key and
//! runs it through a real `BlockExecutor`, once with every DocClass activation
//! closed and once with every one open. Each step asserts both the receipt and
//! the state it was meant to change.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::docclass_build::{
    build_docclass_tx, AcademicCredentialInput, DocClassBuildOp, DocClassTxContext,
};
use sumchain_primitives::{
    Address, CredentialAttribute, CredentialMetadata, DocClassIssuerStatus, DocSubcode, IssuerKey,
    KeyType, RevocationReason, RevocationStatus, SignedTransaction, TxStatus,
};
use sumchain_state::DocClassExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

const FEE: u128 = 1_000_000;
const NOW: u64 = 1_750_000_000_000;

/// Synthetic keys from fixed test seeds. Nothing here is a real key.
fn issuer_key() -> KeyPair {
    KeyPair::from_bytes([0x11; 32])
}
fn admin_key() -> KeyPair {
    KeyPair::from_bytes([0x12; 32])
}
fn holder() -> Address {
    KeyPair::from_bytes([0x13; 32]).address()
}

fn base_params(admin: &Address) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
        d.admin = Some(admin.to_base58());
    }
    p
}

/// Every DocClass activation, and the subsystem activations DocClass reads,
/// open from genesis.
fn all_gates_open(admin: &Address) -> ChainParams {
    let mut p = base_params(admin);
    p.docclass_stake_escrow_enabled_from_height = Some(0);
    p.docclass_subject_index_split_enabled_from_height = Some(0);
    p.docclass_revocation_standing_enabled_from_height = Some(0);
    p.docclass_issuer_authority_enabled_from_height = Some(0);
    p.docclass_revocation_record_enabled_from_height = Some(0);
    p.docclass_credential_schema_enabled_from_height = Some(0);
    p.docclass_identity_binding_enabled_from_height = Some(0);
    p.docclass_issuer_stake_requirement_enabled_from_height = Some(0);
    p.docclass_signature_unsupported_enabled_from_height = Some(0);
    p.docclass_credential_validity_bound_enabled_from_height = Some(0);
    p.docclass_unknown_attribute_refused_enabled_from_height = Some(0);
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p.subsystem_allocation_bound_enabled_from_height = Some(0);
    p.subsystem_no_op_receipt_enabled_from_height = Some(0);
    p.credential_schema_validation_enabled_from_height = Some(0);
    p
}

fn signed(kp: &KeyPair, nonce: u64, op: &DocClassBuildOp) -> (SignedTransaction, Option<[u8; 32]>) {
    let ctx = DocClassTxContext {
        chain_id: CHAIN_ID,
        from: kp.address(),
        nonce,
        fee: FEE,
    };
    let built = build_docclass_tx(&ctx, op).expect("the builder accepts the operation");
    let sig = sign(built.tx.signing_hash().as_bytes(), kp.private_key());
    (
        SignedTransaction::new_v2(built.tx, *sig.as_bytes(), *kp.public_key().as_bytes()),
        built.credential_id,
    )
}

fn diploma(subject: u8) -> AcademicCredentialInput {
    AcademicCredentialInput {
        holder: holder(),
        subcode: DocSubcode::Diploma,
        subject_commitment: [subject; 32],
        institution_id: "Example Institute".to_string(),
        jurisdiction: "US".to_string(),
        schema_hash: [0x71; 32],
        content_commitment: [0x72; 32],
        metadata: CredentialMetadata {
            title: "Bachelor of Science".to_string(),
            credential_type: "undergraduate_degree".to_string(),
            program: None,
            issue_date: "2026-05-15".to_string(),
            completion_date: None,
            // A key on the diploma allowlist, so the credential also passes
            // the schema validator the open activations apply.
            attributes: vec![CredentialAttribute {
                name: "degree_level".to_string(),
                value: "undergraduate".to_string(),
            }],
        },
        issued_at: NOW,
        valid_from: NOW,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
    }
}

/// The whole issuer lifecycle, every step built by `build_docclass_tx`.
fn run_lifecycle(params: ChainParams) {
    let issuer = issuer_key();
    let admin = admin_key();
    let (_state, db, _dir, executor) = setup_with_params(params);
    fund(&db, &issuer, 10_000_000_000);
    fund(&db, &admin, 10_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let run = |view: &mut ExecutionView<'_, '_>, t: &SignedTransaction, what: &str| {
        let r = executor.execute_tx(view, t, &proposer, 1, NOW).unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{what}: {:?}",
            r.status
        );
    };

    // 0. Register, with the sender's own public key.
    let (t, _) = signed(
        &issuer,
        0,
        &DocClassBuildOp::RegisterAcademicIssuer {
            name: "Example Institute".to_string(),
            jurisdiction: "US".to_string(),
            subcodes: vec![DocSubcode::Diploma, DocSubcode::AcademicTranscript],
            stake_amount: 0,
            public_key: *issuer.public_key().as_bytes(),
            registered_at: NOW,
            metadata: None,
        },
    );
    run(&mut view, &t, "register");
    let record = DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
        .unwrap()
        .expect("registered");
    assert_eq!(record.status, DocClassIssuerStatus::Active);
    assert_eq!(record.keys.len(), 1);
    assert_eq!(&record.keys[0].public_key, issuer.public_key().as_bytes());

    // 1. Issue credential A.
    let (t, a) = signed(
        &issuer,
        1,
        &DocClassBuildOp::IssueAcademicCredential(diploma(0x41)),
    );
    run(&mut view, &t, "issue A");
    let a = a.unwrap();
    let stored = DocClassExecutor::v_get_credential(&view, &a)
        .unwrap()
        .expect("A stored");
    assert_eq!(stored.issuer, issuer.address());
    assert!(stored.issuer_key_id.is_empty());

    // 2. Suspend A, 3. reactivate it.
    let (t, _) = signed(
        &issuer,
        2,
        &DocClassBuildOp::SuspendCredential {
            credential_id: a,
            reason: RevocationReason::CertificateHold,
        },
    );
    run(&mut view, &t, "suspend A");
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &a).unwrap(),
        RevocationStatus::Suspended
    );
    let (t, _) = signed(
        &issuer,
        3,
        &DocClassBuildOp::ReactivateCredential { credential_id: a },
    );
    run(&mut view, &t, "reactivate A");
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &a).unwrap(),
        RevocationStatus::Active
    );

    // 4. Issue B, 5. supersede A with B, 6. revoke B.
    let (t, b) = signed(
        &issuer,
        4,
        &DocClassBuildOp::IssueAcademicCredential(diploma(0x42)),
    );
    run(&mut view, &t, "issue B");
    let b = b.unwrap();
    assert_ne!(a, b);
    let (t, _) = signed(
        &issuer,
        5,
        &DocClassBuildOp::SupersedeCredential {
            old_credential_id: a,
            new_credential_id: b,
        },
    );
    run(&mut view, &t, "supersede A by B");
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &a).unwrap(),
        RevocationStatus::Superseded
    );
    let (t, _) = signed(
        &issuer,
        6,
        &DocClassBuildOp::RevokeCredential {
            credential_id: b,
            reason: RevocationReason::KeyCompromise,
        },
    );
    run(&mut view, &t, "revoke B");
    assert_eq!(
        DocClassExecutor::v_get_revocation_status(&view, &b).unwrap(),
        RevocationStatus::Revoked
    );

    // 7. Rotate the issuer key.
    let rotated = KeyPair::from_bytes([0x14; 32]);
    let (t, _) = signed(
        &issuer,
        7,
        &DocClassBuildOp::RotateIssuerKey {
            new_key: IssuerKey {
                key_id: "rotated".to_string(),
                public_key: *rotated.public_key().as_bytes(),
                key_type: KeyType::Ed25519,
                added_at: NOW,
                expires_at: 0,
                active: true,
                is_primary: true,
            },
            old_key_id: "primary".to_string(),
        },
    );
    run(&mut view, &t, "rotate key");
    let record = DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(record.keys.len(), 2);
    assert!(!record.keys[0].active, "the old key is retired");
    assert!(record.keys[1].active && record.keys[1].is_primary);

    // 8. Update the issuer's own profile.
    let mut updated = record.clone();
    updated.name = "Example Institute of Technology".to_string();
    updated.metadata = Some("{\"web\":\"example.invalid\"}".to_string());
    updated.updated_at = NOW + 1;
    let (t, _) = signed(
        &issuer,
        8,
        &DocClassBuildOp::UpdateIssuer { issuer: updated },
    );
    run(&mut view, &t, "update issuer");
    let record = DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(record.name, "Example Institute of Technology");

    // 9. The DocClass admin deactivates the issuer.
    let (t, _) = signed(
        &admin,
        0,
        &DocClassBuildOp::DeactivateIssuer {
            issuer_address: issuer.address(),
        },
    );
    run(&mut view, &t, "admin deactivates");
    let record = DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DocClassIssuerStatus::Suspended);
}

#[test]
fn every_built_operation_executes_with_every_activation_closed() {
    run_lifecycle(base_params(&admin_key().address()));
}

#[test]
fn every_built_operation_executes_with_every_activation_open() {
    run_lifecycle(all_gates_open(&admin_key().address()));
}

/// An issuer can deactivate itself with the same builder.
#[test]
fn an_issuer_can_deactivate_itself() {
    let issuer = KeyPair::from_bytes([0x15; 32]);
    let (_state, db, _dir, executor) = setup_with_params(base_params(&admin_key().address()));
    fund(&db, &issuer, 10_000_000_000);
    let proposer = Address::new([9; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op) in [
        (
            0,
            DocClassBuildOp::RegisterAcademicIssuer {
                name: "Example College".to_string(),
                jurisdiction: "GB".to_string(),
                subcodes: vec![DocSubcode::EnrollmentVerification],
                stake_amount: 0,
                public_key: *issuer.public_key().as_bytes(),
                registered_at: NOW,
                metadata: None,
            },
        ),
        (
            1,
            DocClassBuildOp::DeactivateIssuer {
                issuer_address: issuer.address(),
            },
        ),
    ] {
        let (t, _) = signed(&issuer, nonce, &op);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, NOW)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    let record = DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
        .unwrap()
        .unwrap();
    assert_eq!(record.status, DocClassIssuerStatus::Suspended);
}

/// A sender that is neither the issuer nor the admin is refused by the chain,
/// not by the builder: the builder has no authority to check.
#[test]
fn deactivating_another_issuer_without_admin_rights_is_refused_by_the_chain() {
    let issuer = issuer_key();
    let stranger = KeyPair::from_bytes([0x16; 32]);
    let (_state, db, _dir, executor) = setup_with_params(base_params(&admin_key().address()));
    fund(&db, &issuer, 10_000_000_000);
    fund(&db, &stranger, 10_000_000_000);
    let proposer = Address::new([9; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let (t, _) = signed(
        &issuer,
        0,
        &DocClassBuildOp::RegisterAcademicIssuer {
            name: "Example Institute".to_string(),
            jurisdiction: "US".to_string(),
            subcodes: vec![DocSubcode::Diploma],
            stake_amount: 0,
            public_key: *issuer.public_key().as_bytes(),
            registered_at: NOW,
            metadata: None,
        },
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, NOW)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    let (t, _) = signed(
        &stranger,
        0,
        &DocClassBuildOp::DeactivateIssuer {
            issuer_address: issuer.address(),
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, NOW)
        .unwrap();
    assert!(!matches!(r.status, TxStatus::Success));
    assert_eq!(
        DocClassExecutor::v_get_docclass_issuer(&view, &issuer.address())
            .unwrap()
            .unwrap()
            .status,
        DocClassIssuerStatus::Active
    );
}
