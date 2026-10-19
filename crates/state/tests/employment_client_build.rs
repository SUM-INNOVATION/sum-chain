//! Every transaction `sumchain_primitives::employment_build` produces is one
//! the chain executes.
//!
//! The revoke payload mirrors the executor's private struct field for field,
//! and the register and create payloads are the stored records themselves. A
//! mirror that drifted would still serialize, and only execution would notice,
//! so this file signs each built transaction with a SYNTHETIC key and runs it
//! through a real `BlockExecutor`, once with every Employment activation closed
//! and once with every one open. Each step asserts both the receipt and the
//! state it was meant to change.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::employment_build::{
    build_employment_tx, derive_revocation_ref, EmploymentBuildOp, EmploymentCredentialInput,
    EmploymentTxContext,
};
use sumchain_primitives::{
    Address, EmploymentIssuerClass, EmploymentIssuerStatus, EmploymentStatus, EmploymentType,
    SignedTransaction, TxStatus,
};
use sumchain_state::EmploymentExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

const FEE: u128 = 1_000_000;
const NOW: u64 = 1_750_000_000_000;

/// Synthetic keys from fixed test seeds. Nothing here is a real key.
fn issuer_key() -> KeyPair {
    KeyPair::from_bytes([0x11; 32])
}
fn employee() -> Address {
    KeyPair::from_bytes([0x13; 32]).address()
}

/// Every Employment activation, and the subsystem activations Employment
/// reads, open from genesis.
fn all_gates_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.employment_authorization_enabled_from_height = Some(0);
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p.subsystem_proof_unsupported_enabled_from_height = Some(0);
    p.subsystem_allocation_bound_enabled_from_height = Some(0);
    p.credential_schema_validation_enabled_from_height = Some(0);
    p
}

fn signed(
    kp: &KeyPair,
    nonce: u64,
    op: &EmploymentBuildOp,
) -> (SignedTransaction, Option<[u8; 32]>) {
    let ctx = EmploymentTxContext {
        chain_id: CHAIN_ID,
        from: kp.address(),
        nonce,
        fee: FEE,
    };
    let built = build_employment_tx(&ctx, op).expect("the builder accepts the operation");
    let sig = sign(built.tx.signing_hash().as_bytes(), kp.private_key());
    (
        SignedTransaction::new_v2(built.tx, *sig.as_bytes(), *kp.public_key().as_bytes()),
        built.employment_id,
    )
}

fn credential(tenure: u8) -> EmploymentCredentialInput {
    EmploymentCredentialInput {
        employee_address: employee(),
        employee_ref: [0x31; 32],
        employer_ref: [0x32; 32],
        tenure_commitment: [tenure; 32],
        role_commitment: Some([0x34; 32]),
        employment_type: EmploymentType::FullTime,
        valid_from: NOW,
        expiry: 0,
        policy_id: [0x35; 32],
        issuer_name: "Example Employer Inc".to_string(),
        issuer_class: EmploymentIssuerClass::Employer,
        created_at: NOW,
    }
}

/// Register, create two credentials, revoke one, every step built by
/// `build_employment_tx`.
fn run_lifecycle(params: ChainParams) {
    let issuer = issuer_key();
    let (_state, db, _dir, executor) = setup_with_params(params);
    fund(&db, &issuer, 10_000_000_000);
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

    // 0. Register.
    let (t, _) = signed(
        &issuer,
        0,
        &EmploymentBuildOp::RegisterIssuer {
            issuer_class: EmploymentIssuerClass::Employer,
            display_name: "Example Employer Inc".to_string(),
            issuer_commitment: [0x41; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [0x42; 32],
            registered_at_height: 1,
            registered_at: NOW,
        },
    );
    run(&mut view, &t, "register");
    let record = EmploymentExecutor::v_get_issuer(&view, &issuer.address())
        .unwrap()
        .expect("registered");
    assert_eq!(record.status, EmploymentIssuerStatus::Active);
    assert_eq!(record.display_name, "Example Employer Inc");

    // 1. Create credential A, 2. create credential B.
    let (t, a) = signed(
        &issuer,
        1,
        &EmploymentBuildOp::CreateEmployment(credential(0x33)),
    );
    run(&mut view, &t, "create A");
    let a = a.unwrap();
    let stored = EmploymentExecutor::v_get_credential(&view, &a)
        .unwrap()
        .expect("A stored");
    assert_eq!(stored.issuer_address, issuer.address());
    assert_eq!(stored.employee_address, employee());
    assert_eq!(stored.status, EmploymentStatus::Active);

    let (t, b) = signed(
        &issuer,
        2,
        &EmploymentBuildOp::CreateEmployment(credential(0x36)),
    );
    run(&mut view, &t, "create B");
    let b = b.unwrap();
    assert_ne!(a, b);

    // 3. Revoke A.
    let reference = derive_revocation_ref(&a, NOW, Some("contract ended"));
    let (t, _) = signed(
        &issuer,
        3,
        &EmploymentBuildOp::RevokeEmployment {
            employment_id: a,
            employee_address: employee(),
            revocation_ref: reference,
        },
    );
    run(&mut view, &t, "revoke A");
    let revoked = EmploymentExecutor::v_get_credential(&view, &a)
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status, EmploymentStatus::Ended);
    assert_eq!(revoked.revocation_ref, Some(reference));
    let untouched = EmploymentExecutor::v_get_credential(&view, &b)
        .unwrap()
        .unwrap();
    assert_eq!(untouched.status, EmploymentStatus::Active);
    assert_eq!(untouched.revocation_ref, None);
}

#[test]
fn every_built_operation_executes_with_every_activation_closed() {
    run_lifecycle(ChainParams::with_v2_enabled());
}

#[test]
fn every_built_operation_executes_with_every_activation_open() {
    run_lifecycle(all_gates_open());
}

/// A sender that did not issue the credential is refused by the chain, not by
/// the builder: the builder has no authority to check.
#[test]
fn revoking_another_issuers_credential_is_refused_by_the_chain() {
    let issuer = issuer_key();
    let stranger = KeyPair::from_bytes([0x16; 32]);
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    fund(&db, &issuer, 10_000_000_000);
    fund(&db, &stranger, 10_000_000_000);
    let proposer = Address::new([9; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let (t, _) = signed(
        &issuer,
        0,
        &EmploymentBuildOp::RegisterIssuer {
            issuer_class: EmploymentIssuerClass::Employer,
            display_name: "Example Employer Inc".to_string(),
            issuer_commitment: [0x41; 32],
            jurisdiction_code: "US".to_string(),
            policy_id: [0x42; 32],
            registered_at_height: 1,
            registered_at: NOW,
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, NOW)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    let (t, a) = signed(
        &issuer,
        1,
        &EmploymentBuildOp::CreateEmployment(credential(0x33)),
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, NOW)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    let a = a.unwrap();

    let (t, _) = signed(
        &stranger,
        0,
        &EmploymentBuildOp::RevokeEmployment {
            employment_id: a,
            employee_address: employee(),
            revocation_ref: [0x77; 32],
        },
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, NOW)
        .unwrap();
    assert!(!matches!(r.status, TxStatus::Success));
    let stored = EmploymentExecutor::v_get_credential(&view, &a)
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, EmploymentStatus::Active);
    assert_eq!(stored.revocation_ref, None);
}

/// A credential claiming another issuer cannot be created by the builder: it
/// always names the sender, so a stranger's create is refused by the chain only
/// for lack of a registration.
#[test]
fn a_create_always_names_the_sender_as_issuer() {
    let stranger = KeyPair::from_bytes([0x16; 32]);
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    fund(&db, &stranger, 10_000_000_000);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let (t, id) = signed(
        &stranger,
        0,
        &EmploymentBuildOp::CreateEmployment(credential(0x33)),
    );
    let r = executor
        .execute_tx(&mut view, &t, &Address::new([9; 20]), 1, NOW)
        .unwrap();
    assert!(
        !matches!(r.status, TxStatus::Success),
        "an unregistered sender"
    );
    assert!(EmploymentExecutor::v_get_credential(&view, &id.unwrap())
        .unwrap()
        .is_none());
}
