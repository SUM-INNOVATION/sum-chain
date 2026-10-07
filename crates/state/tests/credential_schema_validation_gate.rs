//! `credential_schema_validation_enabled_from_height` (issue #277).
//!
//! `SchemaValidator` skips every check below its compiled-in
//! `SchemaValidatorConfig::default().activation_height` (385,000). That height
//! is not a chain parameter: whatever a genesis says, every network admits
//! credential metadata the validator would refuse for its first 385,000 blocks.
//!
//! The gate moves the activation into `ChainParams`. Two properties are pinned
//! here, both through the parameter-driven entry points so every decision is
//! derived from `ChainParams` exactly as a node derives it:
//!
//! * DORMANT (the default, and every genesis written before the field): the
//!   outcome at every height -- including 384,999 / 385,000 / 385,001 -- is
//!   exactly the outcome before the field existed.
//! * OPEN: at and above the gate the validator runs whatever the compiled-in
//!   height says; below the gate the compiled-in height still governs, so the
//!   gate can only bring validation earlier, never switch it off.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::employment::{
    EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentOperation,
    EmploymentStatus, EmploymentTxData, EmploymentType, IssuerStatus,
};
use sumchain_primitives::{
    AcademicCredential, Address, CredentialAttribute, CredentialMetadata, DocClassIssuer,
    DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData, DocSubcode,
    EligibilityAttestation, EligibilityType, Hash, IssuerKey, KeyType, RevocationStatus,
};
use sumchain_state::{
    DocClassExecutor, DocClassGates, EmploymentExecutor, EmploymentGates, SchemaValidator,
    SchemaValidatorConfig,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::DocClassStore;

const JURISDICTION: &str = "US";

/// The compiled-in activation height, read rather than restated.
fn compiled() -> u64 {
    SchemaValidatorConfig::default().activation_height
}

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

fn params_gated(h: Option<u64>) -> ChainParams {
    let mut p = params();
    p.credential_schema_validation_enabled_from_height = h;
    p
}

// ── DocClass fixtures ───────────────────────────────────────────────────────

fn docclass_issuer(address: Address, subcode: DocSubcode) -> DocClassIssuer {
    let issuer_type = if subcode == DocSubcode::EligibilityAttestation {
        DocClassIssuerType::Government
    } else {
        DocClassIssuerType::Educational
    };
    DocClassIssuer {
        address,
        name: "Registry".to_string(),
        issuer_type,
        jurisdictions: vec![JURISDICTION.to_string()],
        authorized_subcodes: vec![subcode],
        keys: vec![IssuerKey {
            key_id: "edu-1".to_string(),
            public_key: [0x52; 32],
            key_type: KeyType::Ed25519,
            added_at: 1_000,
            expires_at: 0,
            active: true,
            is_primary: true,
        }],
        registered_at: 1_000,
        updated_at: 1_000,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    }
}

/// A diploma; with `pii`, it carries an attribute the Diploma allowlist refuses.
fn diploma(issuer: Address, pii: bool) -> AcademicCredential {
    let attribute = if pii {
        CredentialAttribute {
            name: "student_ssn".to_string(),
            value: "000-00-0000".to_string(),
        }
    } else {
        CredentialAttribute {
            name: "honors_category".to_string(),
            value: "none".to_string(),
        }
    };
    AcademicCredential {
        credential_id: [0x91; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::Diploma,
        subject_commitment: [0xD1; 32],
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
            attributes: vec![attribute],
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

/// An eligibility attestation whose storage hint carries a PII marker.
fn attestation_with_pii_hint(issuer: Address) -> EligibilityAttestation {
    EligibilityAttestation {
        credential_id: [0x92; 32],
        subject_address: Address::ZERO,
        subcode: DocSubcode::EligibilityAttestation,
        subject_commitment: [0xD2; 32],
        issuer,
        jurisdiction: JURISDICTION.to_string(),
        eligibility_type: EligibilityType::Citizenship,
        schema_hash: [0x61; 32],
        content_commitment: [0x62; 32],
        issued_at: 1_000,
        valid_from: 1_000,
        expires_at: 0,
        payload_hash: None,
        payload_hint: Some("https://example.org/doc?name=alice".to_string()),
        encryption_meta: None,
        issuer_signature: [0u8; 64],
        issuer_key_id: "edu-1".to_string(),
        revocation_status: RevocationStatus::Active,
        superseded_by: None,
    }
}

/// Issue one DocClass credential through `DocClassExecutor::execute`, which
/// derives every gate from `params`. Returns `(success, stored, error)`.
fn docclass_issue(
    params: &ChainParams,
    subcode: DocSubcode,
    payload: &dyn Fn(Address) -> Vec<u8>,
    credential_id: [u8; 32],
    height: u64,
) -> (bool, bool, Option<String>) {
    let edu = KeyPair::generate();
    let (_state, db, _dir, _executor) = setup_with_params(params.clone());
    fund(&db, &edu, 100_000_000);
    DocClassStore::new(&db)
        .issuers()
        .put(&docclass_issuer(edu.address(), subcode))
        .unwrap();
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = DocClassExecutor::execute(
        &mut view,
        params,
        &edu.address(),
        &DocClassTxData {
            operation: DocClassOperation::IssueCredential,
            subcode,
            data: payload(edu.address()),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        100,
        height,
        1_000,
        0,
        Hash::ZERO,
    )
    .unwrap();
    let stored = if subcode == DocSubcode::EligibilityAttestation {
        DocClassExecutor::v_eligibility_exists(&view, &credential_id).unwrap()
    } else {
        DocClassExecutor::v_credential_exists(&view, &credential_id).unwrap()
    };
    (r.success, stored, r.error)
}

fn issue_diploma(params: &ChainParams, pii: bool, height: u64) -> (bool, bool, Option<String>) {
    docclass_issue(
        params,
        DocSubcode::Diploma,
        &|issuer| bincode::serialize(&diploma(issuer, pii)).unwrap(),
        [0x91; 32],
        height,
    )
}

fn assert_admitted(outcome: &(bool, bool, Option<String>), context: &str) {
    assert!(
        outcome.0 && outcome.1,
        "{context}: expected admitted and stored, got {outcome:?}"
    );
}

fn assert_schema_refused(outcome: &(bool, bool, Option<String>), context: &str) {
    assert!(
        !outcome.0 && !outcome.1,
        "{context}: expected refused and not stored, got {outcome:?}"
    );
    assert!(
        outcome
            .2
            .as_deref()
            .is_some_and(|e| e.starts_with("Schema validation failed")),
        "{context}: refused for the wrong reason: {outcome:?}"
    );
}

// ── Pre-activation compatibility ────────────────────────────────────────────

/// The issue's reproduction, kept as the pre-activation pin. With the new gate
/// dormant, a genesis that opens every OTHER credential-schema setting still
/// admits PII below 385,000 -- exactly today's behaviour -- and the
/// compiled-in height switches validation on at 385,000 to the block.
#[test]
fn dormant_gate_keeps_the_compiled_in_height_to_the_block() {
    let mut legacy_docclass_gate_open = params();
    legacy_docclass_gate_open.docclass_credential_schema_enabled_from_height = Some(0);
    let c = compiled();
    for p in [params(), legacy_docclass_gate_open] {
        assert_eq!(p.credential_schema_validation_enabled_from_height, None);
        for h in [1, 1_000, c - 1] {
            assert_admitted(&issue_diploma(&p, true, h), &format!("dormant, height {h}"));
        }
        for h in [c, c + 1, 400_000] {
            assert_schema_refused(&issue_diploma(&p, true, h), &format!("dormant, height {h}"));
        }
    }
}

/// An explicit `null` in a genesis is the dormant gate.
#[test]
fn explicit_null_and_absent_field_are_dormant() {
    let full = serde_json::to_value(params()).unwrap();
    let mut null = full.clone();
    null["credential_schema_validation_enabled_from_height"] = serde_json::Value::Null;
    let mut absent = full;
    absent
        .as_object_mut()
        .unwrap()
        .remove("credential_schema_validation_enabled_from_height")
        .expect("the field is serialised, so an operator can set it");
    for v in [null, absent] {
        let p: ChainParams = serde_json::from_value(v).unwrap();
        assert_eq!(p.credential_schema_validation_enabled_from_height, None);
        assert_admitted(&issue_diploma(&p, true, 1_000), "absent/null");
    }
}

/// Dormant in every shipped default, at every height.
#[test]
fn the_gate_is_dormant_by_default() {
    for p in [ChainParams::default(), ChainParams::with_v2_enabled()] {
        assert_eq!(p.credential_schema_validation_enabled_from_height, None);
        for h in [0u64, 1, 1_000, compiled() - 1, compiled(), u64::MAX] {
            assert!(!DocClassGates::from_params(&p, h).schema_validation, "{h}");
            assert!(
                !EmploymentGates::from_params(&p, h).schema_validation,
                "{h}"
            );
            assert!(!sumchain_state::credential_schema_validation_gate_open(
                &p, h
            ));
        }
    }
    assert!(!DocClassGates::CLOSED.schema_validation);
    assert!(DocClassGates::OPEN.schema_validation);
    assert!(!EmploymentGates::CLOSED.schema_validation);
    assert!(EmploymentGates::OPEN.schema_validation);
}

// ── Post-activation behaviour ───────────────────────────────────────────────

/// The fix: a genesis that sets the gate gets validation from that height,
/// not from 385,000. Below the gate the old rule still applies.
#[test]
fn an_open_gate_validates_from_its_own_height() {
    let p = params_gated(Some(100));
    assert_admitted(&issue_diploma(&p, true, 99), "one below the gate");
    assert_schema_refused(&issue_diploma(&p, true, 100), "at the gate");
    assert_schema_refused(&issue_diploma(&p, true, 1_000), "above the gate");
    assert_schema_refused(
        &issue_diploma(&p, true, compiled()),
        "at the compiled height",
    );

    let p0 = params_gated(Some(0));
    assert_schema_refused(&issue_diploma(&p0, true, 1), "gate at genesis");
}

/// Negative control: an open gate refuses only what the validator refuses.
#[test]
fn an_open_gate_admits_a_lawful_credential() {
    let p = params_gated(Some(0));
    for h in [1, 1_000, compiled() - 1, compiled()] {
        assert_admitted(&issue_diploma(&p, false, h), &format!("lawful, height {h}"));
    }
}

/// A gate set ABOVE the compiled-in height cannot switch validation off: the
/// compiled-in height keeps governing below it.
#[test]
fn a_gate_above_the_compiled_height_changes_nothing() {
    let c = compiled();
    let p = params_gated(Some(c + 100_000));
    assert_admitted(&issue_diploma(&p, true, c - 1), "below both");
    assert_schema_refused(
        &issue_diploma(&p, true, c),
        "compiled height, gate not reached",
    );
    assert_schema_refused(&issue_diploma(&p, true, c + 100_000), "at the gate");
}

/// The gate decides WHEN the validator runs, not WHICH families reach it:
/// eligibility attestations are still validated only under
/// `docclass_credential_schema_enabled_from_height`.
#[test]
fn eligibility_attestations_follow_both_gates() {
    let issue = |p: &ChainParams, h: u64| {
        docclass_issue(
            p,
            DocSubcode::EligibilityAttestation,
            &|issuer| bincode::serialize(&attestation_with_pii_hint(issuer)).unwrap(),
            [0x92; 32],
            h,
        )
    };

    // Only the new gate: the attestation family is not validated (as today).
    assert_admitted(&issue(&params_gated(Some(0)), 1_000), "family gate closed");

    // Only the family gate: validated from 385,000, as today.
    let mut family_only = params();
    family_only.docclass_credential_schema_enabled_from_height = Some(0);
    assert_admitted(
        &issue(&family_only, 1_000),
        "family gate only, below 385,000",
    );
    assert_schema_refused(
        &issue(&family_only, compiled()),
        "family gate only, at 385,000",
    );

    // Both: validated from the new gate's height.
    let mut both = family_only.clone();
    both.credential_schema_validation_enabled_from_height = Some(0);
    assert_schema_refused(&issue(&both, 1_000), "both gates open");
}

// ── Employment ──────────────────────────────────────────────────────────────

fn employment_issuer(kp: &KeyPair) -> EmploymentIssuerProfile {
    EmploymentIssuerProfile {
        issuer_address: kp.address(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        display_name: "Payroll Co".to_string(),
        issuer_commitment: [0xA1; 32],
        jurisdiction_code: "US-CA".to_string(),
        policy_id: [0u8; 32],
        status: IssuerStatus::Active,
        registered_at_height: 1,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

/// An employment credential whose `issuer_name` is refused as phone-number-like.
fn employment_credential(kp: &KeyPair) -> EmploymentCredential {
    EmploymentCredential {
        employment_id: [0x93; 32],
        employee_address: Address::new([7; 20]),
        employee_ref: [0x55; 32],
        employer_ref: [0x66; 32],
        status: EmploymentStatus::Active,
        tenure_commitment: [0xB1; 32],
        role_commitment: Some([0xB2; 32]),
        employment_type: EmploymentType::FullTime,
        valid_from: 100,
        expiry: 0,
        policy_id: [0u8; 32],
        revocation_ref: None,
        issuer_address: kp.address(),
        issuer_name: "Payroll 5551234567".to_string(),
        issuer_class: EmploymentIssuerClass::PayrollProcessor,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn employment_create(params: &ChainParams, height: u64) -> (bool, bool, Option<String>) {
    let issuer = KeyPair::generate();
    let (_state, db, _dir, _executor) = setup_with_params(params.clone());
    fund(&db, &issuer, 100_000_000);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let run = |view: &mut ExecutionView<'_, '_>, op, data: Vec<u8>| {
        EmploymentExecutor::execute(
            view,
            params,
            &issuer.address(),
            &EmploymentTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            100,
            height,
            1_000,
            0,
            Hash::ZERO,
        )
        .unwrap()
    };
    let reg = run(
        &mut view,
        EmploymentOperation::RegisterIssuer,
        bincode::serialize(&employment_issuer(&issuer)).unwrap(),
    );
    assert!(reg.success, "issuer registration: {:?}", reg.error);
    let r = run(
        &mut view,
        EmploymentOperation::CreateEmployment,
        bincode::serialize(&employment_credential(&issuer)).unwrap(),
    );
    let stored = sumchain_state::EmploymentExecutor::v_get_credential(&view, &[0x93; 32])
        .unwrap()
        .is_some();
    (r.success, stored, r.error)
}

/// Employment shares the validator and therefore the gate.
#[test]
fn employment_credentials_follow_the_gate() {
    let c = compiled();
    // Dormant: today's behaviour on both sides of the compiled height.
    assert_admitted(
        &employment_create(&params(), c - 1),
        "dormant, below 385,000",
    );
    assert_schema_refused(&employment_create(&params(), c), "dormant, at 385,000");
    // Open: validated from the gate.
    let p = params_gated(Some(500));
    assert_admitted(&employment_create(&p, 499), "below the gate");
    assert_schema_refused(&employment_create(&p, 500), "at the gate");
}

// ── The validator itself ────────────────────────────────────────────────────
//
// `schema_validator.rs`'s own unit tests are compiled only under the
// `legacy_tests` feature, so the validator-level contract is pinned here.

/// A closed chain gate is the validator as it was: every entry point answers
/// exactly as a validator built without `with_chain_gate`, on both sides of
/// the compiled-in height.
#[test]
fn closed_chain_gate_is_the_compiled_in_rule() {
    let pii = diploma(Address::ZERO, true);
    let kp = KeyPair::generate();
    let employment = employment_credential(&kp);
    let c = compiled();
    let plain = SchemaValidator::new();
    let closed = SchemaValidator::new().with_chain_gate(false);
    for h in [0, 1, c - 1, c, c + 1, u64::MAX] {
        assert_eq!(
            plain.validate_academic_credential(&pii, h).is_valid(),
            closed.validate_academic_credential(&pii, h).is_valid(),
            "{h}"
        );
        assert_eq!(
            plain.validate_academic_credential_wide(&pii, h).is_valid(),
            closed.validate_academic_credential_wide(&pii, h).is_valid(),
            "{h}"
        );
        assert_eq!(
            plain
                .validate_employment_credential(&employment, h)
                .is_valid(),
            closed
                .validate_employment_credential(&employment, h)
                .is_valid(),
            "{h}"
        );
        assert_eq!(
            closed.validate_academic_credential(&pii, h).is_valid(),
            h < c,
            "closed gate at {h}: the compiled-in height alone decides"
        );
    }
}

/// An open chain gate runs the checks below the compiled-in height; the
/// `enabled` switch still turns everything off.
#[test]
fn open_chain_gate_validates_below_the_compiled_in_height() {
    let pii = diploma(Address::ZERO, true);
    let lawful = diploma(Address::ZERO, false);
    let c = compiled();
    let open = SchemaValidator::new().with_chain_gate(true);
    for h in [0, 1, c - 1, c, u64::MAX] {
        assert!(
            !open.validate_academic_credential(&pii, h).is_valid(),
            "{h}"
        );
        assert!(
            !open.validate_academic_credential_wide(&pii, h).is_valid(),
            "{h}"
        );
        assert!(
            open.validate_academic_credential(&lawful, h).is_valid(),
            "{h}"
        );
    }
    let kp = KeyPair::generate();
    assert!(!open
        .validate_employment_credential(&employment_credential(&kp), 0)
        .is_valid());

    let disabled = SchemaValidator::with_config(SchemaValidatorConfig {
        activation_height: 0,
        enabled: false,
    })
    .with_chain_gate(true);
    assert!(disabled.validate_academic_credential(&pii, 0).is_valid());
}
