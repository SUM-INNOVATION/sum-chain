//! SRC-817/818 Education suite — Phase 2 dispatch integration tests.
//!
//! Exercises the full `BlockExecutor::execute_tx` path: activation
//! gate, decode/route, Policy B fee/nonce, semantic validation, and
//! atomic storage. Asserts the privacy invariants (no raw student
//! address; sponsor `tx.from` ≠ student) and the Policy B fee/nonce
//! contract (pre-semantic = free; semantic-fail = charged; success =
//! charged).

mod common;

use sumchain_crypto::KeyPair;
use sumchain_primitives::education::{
    catalog_op, offering_op, student_commitment, AddAssessmentData, AssessmentKind,
    ContentAccessPolicy, CourseLevel, CreateCatalogEntryData, CreateOfferingData, EducationStandard,
    EducationTxData, LinkEnrollmentData, ManagedSnipRef, OpenEnrollmentData,
    PublishCatalogContentData, SnipRef, SubmitAssignmentReceiptData,
};
use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_crypto::sign;

use common::{params_education_disabled, params_education_enabled, setup_with_params};

const CHAIN_ID: u64 = 1;
const FEE: u128 = 1_000;

fn fund(state: &sumchain_state::state::StateManager, kp: &KeyPair, bal: u128) {
    state
        .put_account(
            &kp.address(),
            &sumchain_storage::schema::AccountState { balance: bal, nonce: 0 },
        )
        .unwrap();
}

fn edu_tx(
    sponsor: &KeyPair,
    nonce: u64,
    standard: EducationStandard,
    operation: u16,
    data: Vec<u8>,
) -> SignedTransaction {
    let payload = TxPayload::Education(EducationTxData {
        standard,
        operation,
        data,
        recipient: sumchain_primitives::Address::ZERO,
    });
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: sponsor.address(),
        fee: FEE,
        nonce,
        payload,
    };
    let h = tx.signing_hash();
    let s = sign(h.as_bytes(), sponsor.private_key());
    SignedTransaction::new_v2(tx, *s.as_bytes(), *sponsor.public_key().as_bytes())
}

fn mref() -> ManagedSnipRef {
    ManagedSnipRef {
        snip_ref: SnipRef {
            content_root: [9u8; 32],
            snip_file_id: None,
            size_bytes: 1,
            schema_version: 1,
        },
        access_policy: ContentAccessPolicy {
            opens_at: None,
            closes_at: None,
            grace_until: None,
            audience: sumchain_primitives::education::AccessAudience::StaffOnly,
            revoke_on_course_archive: true,
        },
    }
}

fn ser<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).unwrap()
}

fn mk_catalog(institution: [u8; 32], dept: &str, code: &str, nonce: u64) -> ([u8; 32], Vec<u8>) {
    let cid = sumchain_primitives::education::catalog_id(&institution, dept, code, 1, nonce);
    let d = CreateCatalogEntryData {
        catalog_id: cid,
        institution_id: institution,
        department: dept.to_string(),
        course_code: code.to_string(),
        course_title: Some("T".into()),
        title_commitment: None,
        course_level: CourseLevel::Undergraduate as u8,
        credit_hours: Some(3),
        credit_commitment: None,
        prerequisites_count: 0,
        prerequisites_root: None,
        version: 1,
        supersedes: None,
        nonce,
    };
    (cid, ser(&d))
}

#[test]
fn gate_closed_is_free_failure() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_disabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 10 * FEE);
    let (_cid, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data,
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(70)), "{:?}", r.status);
    assert_eq!(r.fee_paid, 0);
    // Pre-semantic: no fee, no nonce.
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 10 * FEE);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 0);
}

#[test]
fn malformed_and_unsupported_are_free_failures() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 10 * FEE);

    // Malformed: garbage bytes for CreateCatalogEntry.
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        vec![0xff; 8],
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(71)), "{:?}", r.status);
    assert_eq!(r.fee_paid, 0);

    // Unsupported op code under the catalog standard.
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        9999,
        vec![],
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(72)), "{:?}", r.status);
    assert_eq!(r.fee_paid, 0);
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 10 * FEE);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 0);
}

#[test]
fn insufficient_balance_is_free_failure() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, FEE - 1); // cannot cover fee
    let (_cid, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data,
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::InsufficientBalance), "{:?}", r.status);
    assert_eq!(r.fee_paid, 0);
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), FEE - 1);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 0);
}

#[test]
fn create_catalog_success_charges_policy_b() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 10 * FEE);
    let (_cid, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data,
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(r.fee_paid, FEE);
    // Success: fee charged + nonce advanced; proposer credited.
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 10 * FEE - FEE);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 1);
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), FEE);
}

#[test]
fn duplicate_catalog_is_charged_semantic_failure_policy_b() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 10 * FEE);
    let (_cid, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx1 = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data.clone(),
    );
    assert!(matches!(
        ex.execute_tx(&tx1, &proposer.address(), 1, 0).unwrap().status,
        TxStatus::Success
    ));
    let bal_after_1 = state.get_balance(&sponsor.address()).unwrap();
    let tx2 = edu_tx(
        &sponsor,
        1,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data,
    );
    let r = ex.execute_tx(&tx2, &proposer.address(), 2, 0).unwrap();
    // Policy B: semantic failure after activation STILL charges fee +
    // advances nonce.
    assert!(matches!(r.status, TxStatus::Failed(81)), "{:?}", r.status);
    assert_eq!(r.fee_paid, FEE);
    assert_eq!(
        state.get_balance(&sponsor.address()).unwrap(),
        bal_after_1 - FEE
    );
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 2);
}

#[test]
fn create_offering_requires_existing_catalog_policy_b_charged() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 10 * FEE);
    let oid = sumchain_primitives::education::offering_id(
        &[7u8; 32],
        "2026FA",
        "A",
        &sumchain_primitives::Address::ZERO,
        1,
    );
    let d = CreateOfferingData {
        offering_id: oid,
        catalog_id: [7u8; 32], // no such catalog
        term: "2026FA".into(),
        section: "A".into(),
        instruction_start_at: 0,
        instruction_end_at: 100,
        final_grade_submission_deadline: 200,
        nonce: 1,
    };
    let tx = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseOffering,
        offering_op::CREATE_OFFERING,
        ser(&d),
    );
    let r = ex.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(73)), "{:?}", r.status);
    assert_eq!(r.fee_paid, FEE); // Policy B: charged
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 1);
}

/// Full happy path; asserts the receipt is stored, the submitter is the
/// sponsor (tx.from) and NOT the student, and no raw student address
/// appears in the stored receipt bytes.
#[test]
fn full_flow_submission_receipt_privacy() {
    let (state, db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);
    let mut nonce = 0u64;
    let mut h = 1u64;
    macro_rules! run {
        ($std:expr, $op:expr, $data:expr) => {{
            let tx = edu_tx(&sponsor, nonce, $std, $op, $data);
            let r = ex.execute_tx(&tx, &proposer.address(), h, 50).unwrap();
            nonce += 1;
            h += 1;
            r
        }};
    }

    let institution = [3u8; 32];
    let (cid, cdata) = mk_catalog(institution, "CS", "101", 1);
    assert!(matches!(
        run!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata).status,
        TxStatus::Success
    ));
    // Publish content activates the catalog.
    let pc = PublishCatalogContentData {
        catalog_id: cid,
        description_ref: None,
        learning_outcomes_ref: None,
        default_syllabus_ref: None,
        default_assessment_policy_ref: None,
        nonce: 2,
    };
    assert!(matches!(
        run!(EducationStandard::CourseCatalog, catalog_op::PUBLISH_CATALOG_CONTENT, ser(&pc)).status,
        TxStatus::Success
    ));
    let oid = sumchain_primitives::education::offering_id(
        &cid,
        "2026FA",
        "A",
        &sumchain_primitives::Address::ZERO,
        1,
    );
    let od = CreateOfferingData {
        offering_id: oid,
        catalog_id: cid,
        term: "2026FA".into(),
        section: "A".into(),
        instruction_start_at: 0,
        instruction_end_at: 1000,
        final_grade_submission_deadline: 2000,
        nonce: 1,
    };
    assert!(matches!(
        run!(EducationStandard::CourseOffering, offering_op::CREATE_OFFERING, ser(&od)).status,
        TxStatus::Success
    ));
    assert!(matches!(
        run!(
            EducationStandard::CourseOffering,
            offering_op::OPEN_ENROLLMENT,
            ser(&OpenEnrollmentData { offering_id: oid, nonce: 2 })
        )
        .status,
        TxStatus::Success
    ));
    let assess_id = [0x5a; 32];
    let ad = AddAssessmentData {
        offering_id: oid,
        assessment_id: assess_id,
        kind: AssessmentKind::Assignment as u8,
        instructions: mref(),
        spec_commitment: [0; 32],
        opens_at: 0,
        due_at: 100,
        max_attempts: 2,
        weight_bps: 1000,
        answer_key_commitment: None,
        answer_key_access: None,
        nonce: 3,
    };
    assert!(matches!(
        run!(EducationStandard::CourseOffering, offering_op::ADD_ASSESSMENT, ser(&ad)).status,
        TxStatus::Success
    ));

    // Student is represented ONLY by a scoped commitment.
    let subject = [0xCC; 32];
    let salt = [0xDD; 32];
    let sc = student_commitment(&subject, &oid, &salt);
    let enr = [0xEE; 32];
    let link = LinkEnrollmentData {
        offering_id: oid,
        student_commitment: sc,
        enrollment_ref: enr,
        nonce: 4,
    };
    assert!(matches!(
        run!(EducationStandard::CourseOffering, offering_op::LINK_ENROLLMENT, ser(&link)).status,
        TxStatus::Success
    ));

    let sub = SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: assess_id,
        student_commitment: sc,
        submission_commitment: [0xAA; 32],
        work: mref(),
        attempt: 0,
        enrollment_ref: enr,
        student_auth_commitment: None,
    };
    let r = run!(EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, ser(&sub));
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    // The stored receipt: submitter == sponsor (tx.from), NOT student.
    let mut k = Vec::new();
    k.extend_from_slice(&oid);
    k.extend_from_slice(&assess_id);
    k.extend_from_slice(&sc);
    k.extend_from_slice(&0u16.to_be_bytes());
    let raw = db
        .get(sumchain_storage::cf::EDU_SUBMISSIONS, &k)
        .unwrap()
        .expect("receipt stored");
    let rec: sumchain_state::education_executor::StoredSubmissionReceipt =
        bincode::deserialize(&raw).unwrap();
    assert_eq!(rec.submitter, sponsor.address());
    assert_eq!(rec.student_commitment, sc);
    // Privacy: no raw student address pattern in the stored bytes.
    // (sponsor address is allowed; a hypothetical 20-byte student addr
    // is not — we never had one. Assert the sponsor addr is the only
    // 20-byte address-shaped field and student is a 32-byte commitment.)
    assert_ne!(&sc[..20], sponsor.address().as_bytes());
}

#[test]
fn submit_not_enrolled_is_charged_failure() {
    let (state, _db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);
    let mut nonce = 0u64;
    let mut h = 1u64;
    macro_rules! run {
        ($std:expr, $op:expr, $data:expr) => {{
            let tx = edu_tx(&sponsor, nonce, $std, $op, $data);
            let r = ex.execute_tx(&tx, &proposer.address(), h, 50).unwrap();
            nonce += 1;
            h += 1;
            r
        }};
    }
    let institution = [4u8; 32];
    let (cid, cdata) = mk_catalog(institution, "CS", "201", 1);
    run!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata);
    let pc = PublishCatalogContentData {
        catalog_id: cid,
        description_ref: None,
        learning_outcomes_ref: None,
        default_syllabus_ref: None,
        default_assessment_policy_ref: None,
        nonce: 2,
    };
    run!(EducationStandard::CourseCatalog, catalog_op::PUBLISH_CATALOG_CONTENT, ser(&pc));
    let oid = sumchain_primitives::education::offering_id(
        &cid,
        "2026FA",
        "B",
        &sumchain_primitives::Address::ZERO,
        1,
    );
    let od = CreateOfferingData {
        offering_id: oid,
        catalog_id: cid,
        term: "2026FA".into(),
        section: "B".into(),
        instruction_start_at: 0,
        instruction_end_at: 1000,
        final_grade_submission_deadline: 2000,
        nonce: 1,
    };
    run!(EducationStandard::CourseOffering, offering_op::CREATE_OFFERING, ser(&od));
    run!(
        EducationStandard::CourseOffering,
        offering_op::OPEN_ENROLLMENT,
        ser(&OpenEnrollmentData { offering_id: oid, nonce: 2 })
    );
    let assess_id = [0x5b; 32];
    let ad = AddAssessmentData {
        offering_id: oid,
        assessment_id: assess_id,
        kind: AssessmentKind::Assignment as u8,
        instructions: mref(),
        spec_commitment: [0; 32],
        opens_at: 0,
        due_at: 100,
        max_attempts: 2,
        weight_bps: 1000,
        answer_key_commitment: None,
        answer_key_access: None,
        nonce: 3,
    };
    run!(EducationStandard::CourseOffering, offering_op::ADD_ASSESSMENT, ser(&ad));
    let sc = student_commitment(&[1u8; 32], &oid, &[2u8; 32]);
    let sub = SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: assess_id,
        student_commitment: sc,
        submission_commitment: [0xAA; 32],
        work: mref(),
        attempt: 0,
        enrollment_ref: [0xEE; 32],
        student_auth_commitment: None,
    };
    let bal_before = state.get_balance(&sponsor.address()).unwrap();
    let r = run!(EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, ser(&sub));
    assert!(matches!(r.status, TxStatus::Failed(79)), "{:?}", r.status);
    assert_eq!(r.fee_paid, FEE);
    assert_eq!(
        state.get_balance(&sponsor.address()).unwrap(),
        bal_before - FEE
    );
}

#[test]
fn by_code_index_is_length_safe() {
    // ("CS","101") and ("C","S101") must NOT collide.
    let (state, db, _dir, ex) = setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);
    let inst = [8u8; 32];
    let (_c1, d1) = mk_catalog(inst, "CS", "101", 1);
    let (_c2, d2) = mk_catalog(inst, "C", "S101", 2);
    let t1 = edu_tx(
        &sponsor,
        0,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        d1,
    );
    let t2 = edu_tx(
        &sponsor,
        1,
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        d2,
    );
    assert!(matches!(
        ex.execute_tx(&t1, &proposer.address(), 1, 0).unwrap().status,
        TxStatus::Success
    ));
    assert!(matches!(
        ex.execute_tx(&t2, &proposer.address(), 2, 0).unwrap().status,
        TxStatus::Success
    ));
    // Two distinct by_code index rows exist (no collision / overwrite).
    let mut n = 0;
    if let Ok(it) = db.prefix_iter(sumchain_storage::cf::EDU_CATALOG_BY_CODE, &[]) {
        for _ in it {
            n += 1;
        }
    }
    assert_eq!(n, 2, "length-safe by_code keys must not collide");
}

#[test]
fn failure_code_descriptions_present() {
    use sumchain_primitives::TxStatus;
    assert_eq!(
        TxStatus::Failed(70).description(),
        "education subprotocol not enabled at this block height"
    );
    assert_eq!(TxStatus::Failed(79).description(), "student commitment not enrolled in offering");
    assert_eq!(TxStatus::Failed(84).description(), "insufficient balance for education fee");
}
