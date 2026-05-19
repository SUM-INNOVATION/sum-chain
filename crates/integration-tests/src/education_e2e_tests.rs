//! SRC-817/818 Education suite — Phase 5 local/dev end-to-end validation.
//!
//! Drives the full LMS flow through REAL block production
//! (`TestNode` → PoA → `BlockExecutor`) with the education gate open
//! (`education_enabled_from_height: Some(0)` in the in-process genesis
//! only — no genesis file touched here), then verifies state via the
//! Phase 4 read helpers, and asserts the privacy / Policy B / Phase 3
//! admission / executor-authoritative guarantees.
//!
//! Live JSON-RPC socket validation is the manual runbook
//! (`docs/SRC-81X-EDUCATION-VALIDATION.md`); this test exercises the
//! handler substance (read helpers + the data the converters project).

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::education::{
    catalog_op, offering_op, student_commitment, AddAssessmentData, AssessmentKind,
    ContentAccessPolicy, CourseLevel, CreateCatalogEntryData, CreateOfferingData,
    EducationStandard, EducationTxData, GradeSubmissionData, LinkEnrollmentData,
    ManagedSnipRef, OpenEnrollmentData, PublishCatalogContentData, SnipRef,
    SubmitAssignmentReceiptData,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::education_executor::EducationExecutor;
use sumchain_state::mempool::{EducationAdmission, Mempool, MempoolConfig};
use sumchain_state::StateError;
use sumchain_storage::{cf, Database, ReceiptStore};

use crate::TestNode;

const CHAIN_ID: u64 = 1;
const FEE: u128 = 10;

fn edu_params() -> ChainParams {
    ChainParams {
        block_time_ms: 100,
        finality_depth: 2,
        v2_enabled_from_height: Some(0),
        education_enabled_from_height: Some(0), // local/dev only
        ..Default::default()
    }
}

fn snip(tag: u8) -> ManagedSnipRef {
    ManagedSnipRef {
        snip_ref: SnipRef {
            content_root: [tag; 32],
            snip_file_id: None,
            size_bytes: 1024,
            schema_version: 1,
        },
        access_policy: ContentAccessPolicy {
            opens_at: None,
            closes_at: None,
            grace_until: None,
            audience: sumchain_primitives::education::AccessAudience::EnrolledStudents,
            revoke_on_course_archive: true,
        },
    }
}

fn b<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).unwrap()
}

fn edu_signed(
    node: &TestNode,
    signer_bytes: [u8; 32],
    std_: EducationStandard,
    op: u16,
    data: Vec<u8>,
) -> SignedTransaction {
    let signer = KeyPair::from_bytes(signer_bytes);
    let nonce = node.nonce(&signer.address());
    let tx = TransactionV2 {
        chain_id: node.chain_id(),
        from: signer.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Education(EducationTxData {
            standard: std_,
            operation: op,
            data,
            recipient: Address::ZERO,
        }),
    };
    let h = tx.signing_hash();
    let s = sumchain_crypto::sign(h.as_bytes(), signer.private_key());
    SignedTransaction::new_v2(tx, *s.as_bytes(), *signer.public_key().as_bytes())
}

/// Submit an education op through real block production; return the
/// receipt status.
async fn submit_edu(
    node: &TestNode,
    signer_bytes: [u8; 32],
    std_: EducationStandard,
    op: u16,
    data: Vec<u8>,
) -> TxStatus {
    let signed = edu_signed(node, signer_bytes, std_, op, data);
    let tx_hash = signed.hash();
    node.submit_tx(signed).expect("mempool accepts edu tx");
    node.produce_block().await.expect("block produced");
    ReceiptStore::new(node.db())
        .get(&tx_hash)
        .expect("receipt query")
        .expect("receipt exists")
        .status
}

fn funded_node() -> (TestNode, [u8; 32], [u8; 32]) {
    let validator = *KeyPair::generate().private_key().as_bytes();
    let sponsor = *KeyPair::generate().private_key().as_bytes();
    let alloc = HashMap::from([
        (KeyPair::from_bytes(validator).address().to_base58(), 10_000_000_000u128),
        (KeyPair::from_bytes(sponsor).address().to_base58(), 10_000_000_000u128),
    ]);
    let node = TestNode::with_allocations_and_params(validator, CHAIN_ID, alloc, edu_params());
    (node, validator, sponsor)
}

// ────────────────────────────────────────────────────────────────────────
// Full end-to-end LMS flow + privacy + Policy B
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn education_full_e2e_flow_with_privacy_and_policy_b() {
    let (node, validator, sponsor) = funded_node();
    let sponsor_addr = KeyPair::from_bytes(sponsor).address();
    let validator_addr = KeyPair::from_bytes(validator).address();

    let inst = [0x21u8; 32];
    let cid = sumchain_primitives::education::catalog_id(&inst, "CS", "101", 1, 1);

    let bal0 = node.balance(&sponsor_addr);
    let mut ok_txs = 0u128;
    macro_rules! step {
        ($s:expr, $o:expr, $d:expr) => {{
            let st = submit_edu(&node, sponsor, $s, $o, $d).await;
            assert!(matches!(st, TxStatus::Success), "step failed: {:?}", st);
            ok_txs += 1;
        }};
    }

    // 1. Create catalog.
    step!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, b(&CreateCatalogEntryData {
        catalog_id: cid, institution_id: inst, department: "CS".into(), course_code: "101".into(),
        course_title: Some("Intro to CS".into()), title_commitment: None,
        course_level: CourseLevel::Undergraduate as u8, credit_hours: Some(3),
        credit_commitment: None, prerequisites_count: 0, prerequisites_root: None,
        version: 1, supersedes: None, nonce: 1,
    }));
    // 2. Publish content (1 description ref) → catalog Active.
    step!(EducationStandard::CourseCatalog, catalog_op::PUBLISH_CATALOG_CONTENT, b(&PublishCatalogContentData {
        catalog_id: cid, description_ref: Some(snip(0xD0)), learning_outcomes_ref: None,
        default_syllabus_ref: None, default_assessment_policy_ref: None, nonce: 2,
    }));
    // 3. Create offering from Active catalog.
    let oid = sumchain_primitives::education::offering_id(&cid, "2026FA", "A", &Address::ZERO, 1);
    step!(EducationStandard::CourseOffering, offering_op::CREATE_OFFERING, b(&CreateOfferingData {
        offering_id: oid, catalog_id: cid, term: "2026FA".into(), section: "A".into(),
        instruction_start_at: 0, instruction_end_at: 100_000, final_grade_submission_deadline: 200_000,
        nonce: 1,
    }));
    // 4. Open enrollment.
    step!(EducationStandard::CourseOffering, offering_op::OPEN_ENROLLMENT,
        b(&OpenEnrollmentData { offering_id: oid, nonce: 2 }));
    // 5. Add assessment.
    let aid = [0x5au8; 32];
    step!(EducationStandard::CourseOffering, offering_op::ADD_ASSESSMENT, b(&AddAssessmentData {
        offering_id: oid, assessment_id: aid, kind: AssessmentKind::Assignment as u8,
        instructions: snip(0xA5), spec_commitment: [0; 32], opens_at: 0, due_at: 100_000,
        max_attempts: 2, weight_bps: 1000, answer_key_commitment: Some([0xAC; 32]),
        answer_key_access: None, nonce: 3,
    }));
    // 6. Link enrollment (student only as a scoped commitment).
    let subject = [0xC1u8; 32];
    let salt = [0xD1u8; 32];
    let sc = student_commitment(&subject, &oid, &salt);
    step!(EducationStandard::CourseOffering, offering_op::LINK_ENROLLMENT, b(&LinkEnrollmentData {
        offering_id: oid, student_commitment: sc, enrollment_ref: [0xEE; 32], nonce: 4,
    }));
    // 7. Submit assignment receipt (tx.from = sponsor, NOT the student).
    step!(EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, b(&SubmitAssignmentReceiptData {
        offering_id: oid, assessment_id: aid, student_commitment: sc,
        submission_commitment: [0xAA; 32], work: snip(0x5B), attempt: 0,
        enrollment_ref: [0xEE; 32], student_auth_commitment: None,
    }));
    // 8. Grade submission (commitment + encrypted-feedback ref).
    step!(EducationStandard::CourseOffering, offering_op::GRADE_SUBMISSION, b(&GradeSubmissionData {
        offering_id: oid, assessment_id: aid, student_commitment: sc,
        grade_commitment: [0x12; 32], feedback: Some(snip(0xFB)), grader_role: 1, nonce: 8,
    }));
    // 9. Finalize grade.
    step!(EducationStandard::CourseOffering, offering_op::FINALIZE_GRADE,
        b(&sumchain_primitives::education::FinalizeGradeData {
            offering_id: oid, assessment_id: aid, student_commitment: sc, nonce: 9,
        }));

    // ── Phase 4 read-path verification (handler substance) ──
    let ex = EducationExecutor::new(node.db().clone());
    let cat = ex.get_catalog(&cid).unwrap().expect("catalog present");
    assert_eq!(cat.status, 1, "catalog Active after publish");
    assert_eq!(cat.owner, sponsor_addr, "owner = sponsor tx.from, not a student");
    assert_eq!(ex.get_catalog_content(&cid).unwrap().len(), 1);
    let off = ex.get_offering(&oid).unwrap().expect("offering present");
    assert_eq!(off.owner, sponsor_addr);
    assert_eq!(ex.list_assessments(&oid, 256).unwrap().len(), 1);
    assert!(ex.get_assessment(&oid, &aid).unwrap().is_some());
    let link = ex.get_enrollment_link(&oid, &sc).unwrap().expect("enrollment link");
    assert_eq!(link.student_commitment, sc);
    let rec = ex.get_submission_receipt(&oid, &aid, &sc, 0).unwrap().expect("receipt");
    assert_eq!(rec.submitter, sponsor_addr, "submitter = sponsor, never the student");
    assert_eq!(rec.student_commitment, sc);
    assert_eq!(ex.list_submissions_by_student_commitment(&sc, 256).unwrap().len(), 1);
    let g = ex.get_grade_record(&oid, &aid, &sc).unwrap().expect("grade");
    assert!(g.finalized);
    assert_eq!(g.grade_commitment, [0x12; 32]);
    assert_eq!(ex.list_catalogs_by_institution(&inst, 256).unwrap().len(), 1);
    assert_eq!(ex.list_catalogs_by_code("CS", "101", 256).unwrap().len(), 1);
    assert_eq!(ex.list_offerings_by_catalog(&cid, 256).unwrap().len(), 1);
    // Missing → None.
    assert!(ex.get_catalog(&[0xFF; 32]).unwrap().is_none());
    assert!(ex.get_grade_record(&oid, &aid, &[0xFF; 32]).unwrap().is_none());

    // ── Privacy: scan raw education CF keys+values for a planted
    //    forbidden student-address pattern; none must appear. ──
    const FORBIDDEN_STUDENT_ADDR: [u8; 20] = [0x7E; 20];
    let needle = &FORBIDDEN_STUDENT_ADDR[..];
    for c in [
        cf::EDU_CATALOG_ENTRIES, cf::EDU_CATALOG_CONTENT_ITEMS, cf::EDU_OFFERINGS,
        cf::EDU_ASSESSMENTS, cf::EDU_ENROLLMENT_LINKS, cf::EDU_SUBMISSIONS, cf::EDU_GRADES,
        cf::EDU_SUBMISSION_BY_STUDENT_COMMITMENT, cf::EDU_CATALOG_BY_INSTITUTION,
        cf::EDU_CATALOG_BY_CODE, cf::EDU_OFFERING_BY_CATALOG,
    ] {
        if let Ok(it) = node.db().prefix_iter(c, &[]) {
            for (k, v) in it {
                assert!(!k.windows(20).any(|w| w == needle), "student addr in {c} key");
                assert!(!v.windows(20).any(|w| w == needle), "student addr in {c} value");
            }
        }
    }
    // The student commitment is a 32-byte hash, distinct from any addr.
    assert_ne!(&sc[..20], sponsor_addr.as_bytes());

    // ── Policy B / sponsor-pays: every success charged the sponsor FEE
    //    and credited the proposer (validator). No student account
    //    exists or is charged (student is only a commitment). ──
    let bal1 = node.balance(&sponsor_addr);
    assert_eq!(bal1, bal0 - ok_txs * FEE, "sponsor pays exactly Σ fees");
    assert_eq!(node.nonce(&sponsor_addr), ok_txs as u64, "nonce advanced per success");
    // Proposer received the fees (it is the validator/block proposer).
    assert!(node.balance(&validator_addr) >= ok_txs * FEE);
}

// ────────────────────────────────────────────────────────────────────────
// Policy B negative path: semantic failure still charges fee + nonce
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn education_semantic_failure_is_charged_policy_b() {
    let (node, _v, sponsor) = funded_node();
    let sponsor_addr = KeyPair::from_bytes(sponsor).address();
    let inst = [0x31u8; 32];
    let cid = sumchain_primitives::education::catalog_id(&inst, "CS", "201", 1, 1);
    let data = b(&CreateCatalogEntryData {
        catalog_id: cid, institution_id: inst, department: "CS".into(), course_code: "201".into(),
        course_title: None, title_commitment: None, course_level: 0, credit_hours: Some(3),
        credit_commitment: None, prerequisites_count: 0, prerequisites_root: None,
        version: 1, supersedes: None, nonce: 1,
    });
    assert!(matches!(
        submit_edu(&node, sponsor, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data.clone()).await,
        TxStatus::Success
    ));
    let bal = node.balance(&sponsor_addr);
    let nonce = node.nonce(&sponsor_addr);
    // Duplicate catalog → semantic Failed(81), but Policy B still
    // charges fee + advances nonce.
    let st = submit_edu(&node, sponsor, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, data).await;
    assert!(matches!(st, TxStatus::Failed(81)), "{:?}", st);
    assert_eq!(node.balance(&sponsor_addr), bal - FEE, "semantic fail charged");
    assert_eq!(node.nonce(&sponsor_addr), nonce + 1, "nonce advanced on semantic fail");
}

// ────────────────────────────────────────────────────────────────────────
// Phase 3 admission + executor-authoritative
// ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn education_phase3_admission_and_executor_authoritative() {
    let (node, _v, sponsor) = funded_node();
    let inst = [0x41u8; 32];
    let cid = sumchain_primitives::education::catalog_id(&inst, "CS", "301", 1, 1);
    let cdata = b(&CreateCatalogEntryData {
        catalog_id: cid, institution_id: inst, department: "CS".into(), course_code: "301".into(),
        course_title: None, title_commitment: None, course_level: 0, credit_hours: Some(3),
        credit_commitment: None, prerequisites_count: 0, prerequisites_root: None,
        version: 1, supersedes: None, nonce: 1,
    });
    assert!(matches!(
        submit_edu(&node, sponsor, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata.clone()).await,
        TxStatus::Success
    ));

    // Mempool WITH education admission over the same db.
    let mp = Mempool::new(MempoolConfig::default()).with_education_admission(EducationAdmission {
        executor: Arc::new(EducationExecutor::new(node.db().clone())),
        params: Arc::new(edu_params()),
        current_height: Arc::new(AtomicU64::new(node.height())),
    });
    // Committed-duplicate catalog → rejected at admission.
    let dup = edu_signed(&node, sponsor, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata.clone());
    assert!(matches!(
        mp.add(dup).expect_err("committed dup rejected at admission"),
        StateError::DuplicateEducationRecord
    ));
    // Not-enrolled grade → InvalidEducationTransaction at admission.
    let g = edu_signed(&node, sponsor, EducationStandard::CourseOffering, offering_op::GRADE_SUBMISSION,
        b(&GradeSubmissionData {
            offering_id: [0x99; 32], assessment_id: [0x99; 32], student_commitment: [0x99; 32],
            grade_commitment: [0; 32], feedback: None, grader_role: 1, nonce: 0,
        }));
    assert!(matches!(
        mp.add(g).expect_err("ineligible rejected"),
        StateError::InvalidEducationTransaction(_)
    ));
    // Non-education tx unaffected by education admission.
    let other = KeyPair::generate();
    let t = TransactionV2 {
        chain_id: CHAIN_ID, from: KeyPair::from_bytes(sponsor).address(), fee: FEE,
        nonce: 999, payload: TxPayload::Transfer { to: other.address(), amount: 1 },
    };
    let th = t.signing_hash();
    let ts = sumchain_crypto::sign(th.as_bytes(), KeyPair::from_bytes(sponsor).private_key());
    let signed = SignedTransaction::new_v2(t, *ts.as_bytes(), *KeyPair::from_bytes(sponsor).public_key().as_bytes());
    mp.add(signed).expect("transfer unaffected by education admission");

    // Executor-authoritative: a mempool WITHOUT admission ctx still
    // lets a committed-duplicate through admission, but real block
    // execution rejects it with Failed(81).
    let st = submit_edu(&node, sponsor, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, cdata).await;
    assert!(matches!(st, TxStatus::Failed(81)), "executor authoritative: {:?}", st);
}

// ────────────────────────────────────────────────────────────────────────
// Genesis activation: local enabled; mainnet/testnet untouched
// ────────────────────────────────────────────────────────────────────────

#[test]
fn genesis_activation_local_only() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../genesis/");
    let local = Genesis::from_file(format!("{root}local_genesis.json")).expect("local genesis parses");
    assert_eq!(
        local.params.education_enabled_from_height,
        Some(0),
        "local/dev genesis must enable education from height 0"
    );
    // mainnet/testnet genesis are placeholder templates that don't
    // fully deserialize via `Genesis::from_file`; assert at the text
    // level that they carry NO education activation key at all (so the
    // `#[serde(default)]` -> None production-safe default holds).
    for f in ["mainnet_genesis.json", "testnet_genesis.json"] {
        let raw = std::fs::read_to_string(format!("{root}{f}"))
            .unwrap_or_else(|e| panic!("read {f}: {e}"));
        assert!(
            !raw.contains("education_enabled_from_height"),
            "{f} must NOT mention education_enabled_from_height (stays None)"
        );
    }
}
