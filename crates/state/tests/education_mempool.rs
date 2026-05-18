//! SRC-817/818 Education suite — Phase 3 mempool admission tests.
//!
//! Mirrors `inference_attestation_mempool.rs`. Admission is a narrow,
//! non-authoritative filter: it never produces receipts and never
//! mutates state; the Phase 2 executor stays authoritative. Students
//! appear only as `student_commitment`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::education::{
    catalog_op, offering_op, student_commitment, AddAssessmentData, AssessmentKind,
    ContentAccessPolicy, CourseLevel, CreateCatalogEntryData, CreateOfferingData,
    EducationStandard, EducationTxData, LinkEnrollmentData, ManagedSnipRef,
    OpenEnrollmentData, PublishCatalogContentData, SnipRef, SubmitAssignmentReceiptData,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::education_executor::EducationExecutor;
use sumchain_state::executor::BlockExecutor;
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::mempool::{
    EducationAdmission, InferenceAttestationAdmission, Mempool, MempoolConfig,
};
use sumchain_state::state::StateManager;
use sumchain_state::StateError;
use sumchain_storage::Database;
use tempfile::TempDir;

use common::{
    build_signed_attestation_tx, params_education_enabled, sample_digest, setup_with_params,
};

const CHAIN_ID: u64 = 1;
const FEE: u128 = 1_000;

fn fund(state: &StateManager, kp: &KeyPair, bal: u128) {
    state
        .put_account(
            &kp.address(),
            &sumchain_storage::schema::AccountState { balance: bal, nonce: 0 },
        )
        .unwrap();
}

fn ser<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).unwrap()
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
        recipient: Address::ZERO,
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

fn transfer_tx(sender: &KeyPair, nonce: u64) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: sender.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Transfer {
            to: Address::ZERO,
            amount: 1,
        },
    };
    let h = tx.signing_hash();
    let s = sign(h.as_bytes(), sender.private_key());
    SignedTransaction::new_v2(tx, *s.as_bytes(), *sender.public_key().as_bytes())
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

fn admission(db: Arc<Database>, params: ChainParams, height: u64) -> (EducationAdmission, Arc<AtomicU64>) {
    let h = Arc::new(AtomicU64::new(height));
    (
        EducationAdmission {
            executor: Arc::new(EducationExecutor::new(db)),
            params: Arc::new(params),
            current_height: h.clone(),
        },
        h,
    )
}

fn mempool_with(db: Arc<Database>, params: ChainParams, height: u64) -> (Mempool, Arc<AtomicU64>) {
    let (adm, h) = admission(db, params, height);
    (
        Mempool::new(MempoolConfig::default()).with_education_admission(adm),
        h,
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn admission_rejects_pre_activation() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    // ChainParams::default() => education_enabled_from_height = None.
    let (mp, _h) = mempool_with(db, ChainParams::default(), 100);
    let sponsor = KeyPair::generate();
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    let h = tx.hash();
    let err = mp.add(tx).expect_err("pre-activation must reject");
    assert!(matches!(err, StateError::EducationNotActivated), "{err:?}");
    assert!(!mp.contains(&h));
    assert_eq!(mp.len(), 0);
}

#[test]
fn first_valid_catalog_admits() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (mp, _h) = mempool_with(db, params, 5);
    let sponsor = KeyPair::generate();
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let tx = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    let h = tx.hash();
    mp.add(tx).expect("valid catalog admits");
    assert!(mp.contains(&h));
}

#[test]
fn malformed_and_unsupported_rejected() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (mp, _h) = mempool_with(db, params, 5);
    let sponsor = KeyPair::generate();

    let bad = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, vec![0xff; 8]);
    assert!(matches!(
        mp.add(bad).expect_err("malformed"),
        StateError::InvalidEducationTransaction(_)
    ));
    let unsup = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, 9999, vec![]);
    assert!(matches!(
        mp.add(unsup).expect_err("unsupported"),
        StateError::InvalidEducationTransaction(_)
    ));
    assert_eq!(mp.len(), 0);
}

#[test]
fn in_flight_duplicate_rejected_then_remove_clears() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (mp, _h) = mempool_with(db, params, 5);
    let sponsor = KeyPair::generate();
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);

    let tx1 = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone());
    let h1 = tx1.hash();
    mp.add(tx1).expect("first admits");

    // Same catalog identity (different nonce) → in-flight duplicate.
    let tx2 = edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone());
    assert!(matches!(
        mp.add(tx2).expect_err("dup in-flight"),
        StateError::DuplicateEducationRecord
    ));

    // Remove the first → in-flight key cleared → resubmission admits.
    mp.remove(&h1);
    let tx3 = edu_tx(&sponsor, 2, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    mp.add(tx3).expect("admits after remove cleared the in-flight key");
}

#[test]
fn clear_empties_in_flight() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (mp, _h) = mempool_with(db, params, 5);
    let sponsor = KeyPair::generate();
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    mp.add(edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone()))
        .unwrap();
    mp.clear();
    // After clear, the same identity admits again (in-flight emptied).
    mp.add(edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data))
        .expect("admits after clear");
}

#[test]
fn committed_duplicate_rejected() {
    // Commit a catalog via the Phase 2 executor, then admission must
    // reject a fresh tx for the same catalog_id (committed-CF dedup).
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (state, db, _dir, ex): (Arc<StateManager>, Arc<Database>, TempDir, BlockExecutor) =
        setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);
    let (_c, data) = mk_catalog([2u8; 32], "CS", "201", 1);
    let commit_tx = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone());
    assert!(matches!(
        ex.execute_tx(&commit_tx, &proposer.address(), 1, 0).unwrap().status,
        TxStatus::Success
    ));

    let (mp, _h) = mempool_with(db, params, 5);
    let dup = edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    assert!(matches!(
        mp.add(dup).expect_err("committed dup"),
        StateError::DuplicateEducationRecord
    ));
}

#[test]
fn create_offering_missing_or_inactive_catalog_rejected() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    let (mp, _h) = mempool_with(db, params, 5);
    let sponsor = KeyPair::generate();
    let oid = sumchain_primitives::education::offering_id(&[7u8; 32], "2026FA", "A", &Address::ZERO, 1);
    let od = CreateOfferingData {
        offering_id: oid,
        catalog_id: [7u8; 32], // no such catalog
        term: "2026FA".into(),
        section: "A".into(),
        instruction_start_at: 0,
        instruction_end_at: 100,
        final_grade_submission_deadline: 200,
        nonce: 1,
    };
    let tx = edu_tx(&sponsor, 0, EducationStandard::CourseOffering, offering_op::CREATE_OFFERING, ser(&od));
    assert!(matches!(
        mp.add(tx).expect_err("missing catalog"),
        StateError::InvalidEducationTransaction(_)
    ));
}

#[test]
fn submit_not_enrolled_rejected() {
    // Commit catalog+publish+offering+openenroll+assessment (NO link),
    // then admission must reject the submission as not-enrolled.
    let (state, db, _dir, ex): (Arc<StateManager>, Arc<Database>, TempDir, BlockExecutor) =
        setup_with_params(params_education_enabled());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);
    let mut n = 0u64;
    let mut hh = 1u64;
    macro_rules! run {
        ($std:expr, $op:expr, $d:expr) => {{
            let r = ex
                .execute_tx(&edu_tx(&sponsor, n, $std, $op, $d), &proposer.address(), hh, 50)
                .unwrap();
            n += 1;
            hh += 1;
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }};
    }
    let (cid, cdata) = mk_catalog([4u8; 32], "CS", "301", 1);
    run!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata);
    run!(
        EducationStandard::CourseCatalog,
        catalog_op::PUBLISH_CATALOG_CONTENT,
        ser(&PublishCatalogContentData {
            catalog_id: cid,
            description_ref: None,
            learning_outcomes_ref: None,
            default_syllabus_ref: None,
            default_assessment_policy_ref: None,
            nonce: 2,
        })
    );
    let oid = sumchain_primitives::education::offering_id(&cid, "2026FA", "A", &Address::ZERO, 1);
    run!(
        EducationStandard::CourseOffering,
        offering_op::CREATE_OFFERING,
        ser(&CreateOfferingData {
            offering_id: oid,
            catalog_id: cid,
            term: "2026FA".into(),
            section: "A".into(),
            instruction_start_at: 0,
            instruction_end_at: 1000,
            final_grade_submission_deadline: 2000,
            nonce: 1,
        })
    );
    run!(
        EducationStandard::CourseOffering,
        offering_op::OPEN_ENROLLMENT,
        ser(&OpenEnrollmentData { offering_id: oid, nonce: 2 })
    );
    let aid = [0x5a; 32];
    run!(
        EducationStandard::CourseOffering,
        offering_op::ADD_ASSESSMENT,
        ser(&AddAssessmentData {
            offering_id: oid,
            assessment_id: aid,
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
        })
    );

    let (mp, _h) = mempool_with(db, params_education_enabled(), 5);
    let sc = student_commitment(&[0xCC; 32], &oid, &[0xDD; 32]);
    let sub = SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: aid,
        student_commitment: sc,
        submission_commitment: [0xAA; 32],
        work: mref(),
        attempt: 0,
        enrollment_ref: [0xEE; 32],
        student_auth_commitment: None,
    };
    let tx = edu_tx(&sponsor, 0, EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, ser(&sub));
    assert!(matches!(
        mp.add(tx).expect_err("not enrolled"),
        StateError::InvalidEducationTransaction(_)
    ));
}

#[test]
fn non_education_tx_unaffected() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    // Education gate CLOSED — a non-education tx must still admit.
    let (mp, _h) = mempool_with(db, ChainParams::default(), 100);
    let sender = KeyPair::generate();
    let tx = transfer_tx(&sender, 0);
    let h = tx.hash();
    mp.add(tx).expect("transfer unaffected by education admission");
    assert!(mp.contains(&h));
}

#[test]
fn no_context_mempool_in_flight_dedups_only() {
    // No admission ctx: gate + committed checks skipped, but in-flight
    // dedup still applies (parity with inference).
    let mp = Mempool::new(MempoolConfig::default());
    let sponsor = KeyPair::generate();
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let t1 = edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone());
    mp.add(t1).expect("admits without ctx (gate skipped)");
    let t2 = edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    assert!(matches!(
        mp.add(t2).expect_err("in-flight dup still enforced"),
        StateError::DuplicateEducationRecord
    ));
}

#[test]
fn live_height_advance_opens_gate() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(1000);
    let (mp, height) = mempool_with(db, params, 999);
    let sponsor = KeyPair::generate();
    let (_c, d1) = mk_catalog([1u8; 32], "CS", "101", 1);
    assert!(matches!(
        mp.add(edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, d1))
            .expect_err("closed at 999"),
        StateError::EducationNotActivated
    ));
    height.store(1000, Ordering::Relaxed);
    let (_c, d2) = mk_catalog([1u8; 32], "CS", "102", 2);
    mp.add(edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, d2))
        .expect("opens at activation height");
}

/// Commit catalog→publish→offering→openenroll→addassessment via the
/// Phase 2 executor. Optionally also link `sc`. Returns the shared db
/// plus ids so admission tests run against committed state.
/// Deterministic offering id for a `commit_chain(inst, code, ..)` run
/// (mirrors its internal `mk_catalog` + `offering_id` derivation:
/// version=1, nonce=1, term "2026FA", section "A", creator ZERO).
fn expected_oid(inst: [u8; 32], code: &str) -> [u8; 32] {
    let cid = sumchain_primitives::education::catalog_id(&inst, "CS", code, 1, 1);
    sumchain_primitives::education::offering_id(&cid, "2026FA", "A", &Address::ZERO, 1)
}

/// Commits the full chain with correct internal nonce sequencing,
/// optionally links `link_sc`, and optionally pre-commits
/// `precommit_submissions` submissions for that sc (attempts 0..n).
/// No second executor / re-fund (which would reset the account nonce).
#[allow(clippy::type_complexity)]
fn commit_chain(
    inst: [u8; 32],
    code: &str,
    max_attempts: u16,
    link_sc: Option<[u8; 32]>,
    precommit_submissions: u16,
) -> (Arc<Database>, [u8; 32], [u8; 32], KeyPair) {
    let (state, db, dir, ex): (Arc<StateManager>, Arc<Database>, TempDir, BlockExecutor) =
        setup_with_params(params_education_enabled());
    std::mem::forget(dir); // keep the TempDir alive for the test duration
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1000 * FEE);
    let mut n = 0u64;
    let mut hh = 1u64;
    macro_rules! run {
        ($std:expr, $op:expr, $d:expr) => {{
            let r = ex
                .execute_tx(&edu_tx(&sponsor, n, $std, $op, $d), &proposer.address(), hh, 50)
                .unwrap();
            n += 1;
            hh += 1;
            assert!(matches!(r.status, TxStatus::Success), "setup step failed: {:?}", r.status);
        }};
    }
    let (cid, cdata) = mk_catalog(inst, "CS", code, 1);
    run!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata);
    run!(
        EducationStandard::CourseCatalog,
        catalog_op::PUBLISH_CATALOG_CONTENT,
        ser(&PublishCatalogContentData {
            catalog_id: cid,
            description_ref: None,
            learning_outcomes_ref: None,
            default_syllabus_ref: None,
            default_assessment_policy_ref: None,
            nonce: 2,
        })
    );
    let oid = sumchain_primitives::education::offering_id(&cid, "2026FA", "A", &Address::ZERO, 1);
    run!(
        EducationStandard::CourseOffering,
        offering_op::CREATE_OFFERING,
        ser(&CreateOfferingData {
            offering_id: oid,
            catalog_id: cid,
            term: "2026FA".into(),
            section: "A".into(),
            instruction_start_at: 0,
            instruction_end_at: 1000,
            final_grade_submission_deadline: 2000,
            nonce: 1,
        })
    );
    run!(
        EducationStandard::CourseOffering,
        offering_op::OPEN_ENROLLMENT,
        ser(&OpenEnrollmentData { offering_id: oid, nonce: 2 })
    );
    let aid = [0x5a; 32];
    run!(
        EducationStandard::CourseOffering,
        offering_op::ADD_ASSESSMENT,
        ser(&AddAssessmentData {
            offering_id: oid,
            assessment_id: aid,
            kind: AssessmentKind::Assignment as u8,
            instructions: mref(),
            spec_commitment: [0; 32],
            opens_at: 0,
            due_at: 100,
            max_attempts,
            weight_bps: 1000,
            answer_key_commitment: None,
            answer_key_access: None,
            nonce: 3,
        })
    );
    if let Some(sc) = link_sc {
        run!(
            EducationStandard::CourseOffering,
            offering_op::LINK_ENROLLMENT,
            ser(&LinkEnrollmentData {
                offering_id: oid,
                student_commitment: sc,
                enrollment_ref: [0xEE; 32],
                nonce: 4,
            })
        );
        for attempt in 0..precommit_submissions {
            run!(
                EducationStandard::CourseOffering,
                offering_op::SUBMIT_ASSIGNMENT,
                ser(&SubmitAssignmentReceiptData {
                    offering_id: oid,
                    assessment_id: aid,
                    student_commitment: sc,
                    submission_commitment: [attempt as u8; 32],
                    work: mref(),
                    attempt,
                    enrollment_ref: [0xEE; 32],
                    student_auth_commitment: None,
                })
            );
        }
    }
    (db, oid, aid, sponsor)
}

#[test]
fn full_happy_chain_admits_through_submit() {
    // student_commitment is scoped to the deterministic offering id.
    let real_sc = student_commitment(&[0xC1; 32], &expected_oid([10u8; 32], "501"), &[0xD1; 32]);
    let (db, oid, aid, sponsor) = commit_chain([10u8; 32], "501", 3, Some(real_sc), 0);
    assert_eq!(oid, expected_oid([10u8; 32], "501"));

    let (mp, _h) = mempool_with(db, params_education_enabled(), 5);
    let sub = SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: aid,
        student_commitment: real_sc,
        submission_commitment: [0xAA; 32],
        work: mref(),
        attempt: 0,
        enrollment_ref: [0xEE; 32],
        student_auth_commitment: None,
    };
    let tx = edu_tx(&sponsor, 9, EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, ser(&sub));
    let h = tx.hash();
    mp.add(tx).expect("full happy chain: submit must admit");
    assert!(mp.contains(&h));
}

#[test]
fn submit_attempts_exhausted_rejected() {
    // sc scoped to the deterministic offering id; compute up-front.
    let real_sc = student_commitment(&[0xC2; 32], &expected_oid([11u8; 32], "601"), &[0xD2; 32]);
    // max_attempts = 1, link the student, pre-commit 1 submission
    // (attempt 0) → the single allowed attempt is used up.
    let (db, oid, aid, sponsor) = commit_chain([11u8; 32], "601", 1, Some(real_sc), 1);
    assert_eq!(oid, expected_oid([11u8; 32], "601"));

    // Admission of a SECOND attempt → committed_attempts(1) >= max(1).
    let (mp, _h) = mempool_with(db, params_education_enabled(), 5);
    let sub1 = SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: aid,
        student_commitment: real_sc,
        submission_commitment: [0xBB; 32],
        work: mref(),
        attempt: 1,
        enrollment_ref: [0xEE; 32],
        student_auth_commitment: None,
    };
    let tx = edu_tx(&sponsor, 10, EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, ser(&sub1));
    assert!(matches!(
        mp.add(tx).expect_err("attempts exhausted"),
        StateError::InvalidEducationTransaction(_)
    ));
}

#[test]
fn grade_not_enrolled_rejected() {
    // Offering+assessment committed but NO enrollment link for sc.
    let (db, oid, aid, sponsor) = commit_chain([12u8; 32], "701", 2, None, 0);
    let sc = student_commitment(&[0x9A; 32], &oid, &[0x9B; 32]);
    let (mp, _h) = mempool_with(db, params_education_enabled(), 5);
    let g = sumchain_primitives::education::GradeSubmissionData {
        offering_id: oid,
        assessment_id: aid,
        student_commitment: sc,
        grade_commitment: [0x12; 32],
        feedback: None,
        grader_role: 1,
        nonce: 9,
    };
    let tx = edu_tx(&sponsor, 9, EducationStandard::CourseOffering, offering_op::GRADE_SUBMISSION, ser(&g));
    let err = mp.add(tx).expect_err("grade for non-enrolled sc must reject");
    assert!(
        matches!(&err, StateError::InvalidEducationTransaction(m) if m.contains("not enrolled")),
        "{err:?}"
    );
}

#[test]
fn inference_and_education_admission_coexist() {
    // One mempool, both admission contexts. Inference governed by its
    // own gate (omninode None ⇒ rejected); education governed by its
    // own gate (Some(0) ⇒ catalog admits).
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(0);
    // omninode_enabled_from_height stays None.
    let height = Arc::new(AtomicU64::new(5));
    let inf = InferenceAttestationAdmission {
        executor: Arc::new(InferenceAttestationExecutor::new(db.clone())),
        params: Arc::new(params.clone()),
        current_height: height.clone(),
    };
    let edu = EducationAdmission {
        executor: Arc::new(EducationExecutor::new(db.clone())),
        params: Arc::new(params),
        current_height: height.clone(),
    };
    let mp = Mempool::new(MempoolConfig::default())
        .with_inference_admission(inf)
        .with_education_admission(edu);

    let sender = KeyPair::generate();
    // Inference: gate closed → its own rule fires.
    let itx = build_signed_attestation_tx(&sender, 0, FEE, sample_digest("coexist-1"), false);
    assert!(matches!(
        mp.add(itx).expect_err("inference still gated"),
        StateError::OmniNodeNotActivated
    ));
    // Education: catalog admits per education rule.
    let (_c, data) = mk_catalog([1u8; 32], "CS", "101", 1);
    let etx = edu_tx(&sender, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data);
    let eh = etx.hash();
    mp.add(etx).expect("education admits alongside inference ctx");
    assert!(mp.contains(&eh));
}

/// Verbatim mirror of the `Node::new` admission recipe: both admission
/// contexts share ONE live `chain_height` Arc; advancing it past
/// `education_enabled_from_height` opens the education gate. If the
/// node wiring drifts (separate height Arcs, missing builder call),
/// this assertion or the compile fails.
#[test]
fn production_wiring_height_advance_opens_education_gate() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.education_enabled_from_height = Some(1000);

    // Mirror Node::new: one shared chain_height Arc feeding BOTH ctxs.
    let chain_height = Arc::new(AtomicU64::new(999));
    let inference_admission = InferenceAttestationAdmission {
        executor: Arc::new(InferenceAttestationExecutor::new(db.clone())),
        params: Arc::new(params.clone()),
        current_height: chain_height.clone(),
    };
    let education_admission = EducationAdmission {
        executor: Arc::new(EducationExecutor::new(db.clone())),
        params: Arc::new(params.clone()),
        current_height: chain_height.clone(),
    };
    let mp = Mempool::new(MempoolConfig::default())
        .with_inference_admission(inference_admission)
        .with_education_admission(education_admission);

    let sponsor = KeyPair::generate();
    let (_c, d1) = mk_catalog([1u8; 32], "CS", "101", 1);
    assert!(matches!(
        mp.add(edu_tx(&sponsor, 0, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, d1))
            .expect_err("closed at 999"),
        StateError::EducationNotActivated
    ));
    // Same store(...) the node event loop performs on BlockProduced.
    chain_height.store(1000, Ordering::Relaxed);
    let (_c, d2) = mk_catalog([1u8; 32], "CS", "102", 2);
    mp.add(edu_tx(&sponsor, 1, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, d2))
        .expect("shared live height opens the education gate at activation");
}
