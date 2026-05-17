//! SRC-817/818 Education suite — Phase 1 wire-format lock fixtures.
//!
//! These tests pin the append-only enum position and the canonical
//! bincode bytes / commitment outputs so a later refactor that reorders
//! variants, changes a domain tag, or alters a field order fails CI
//! instead of silently re-decoding historical transactions.
//!
//! Inline hex (self-authored vectors — not external).

use sumchain_primitives::education::*;
use sumchain_primitives::transaction::{TxPayload, TxType};
use sumchain_primitives::Address;

// ───────────────────────── Fixed test inputs ────────────────────────────────

const INSTITUTION_ID: [u8; 32] = [0x11; 32];
const SUBJECT: [u8; 32] = [0x22; 32];
const SALT: [u8; 32] = [0x33; 32];
const WORK_HASH: [u8; 32] = [0x44; 32];
const ASSESSMENT_ID: [u8; 32] = [0x55; 32];
const ENROLLMENT_REF: [u8; 32] = [0x66; 32];
// A distinctive 20-byte pattern that would be a *raw student address*
// if the design ever leaked one. It must never appear in receipt bytes.
const FORBIDDEN_STUDENT_ADDR: [u8; 20] = [0xAB; 20];

fn sample_create_catalog_entry() -> CreateCatalogEntryData {
    let cid = catalog_id(&INSTITUTION_ID, "CS", "CS101", 1, 7);
    CreateCatalogEntryData {
        catalog_id: cid,
        institution_id: INSTITUTION_ID,
        department: "CS".to_string(),
        course_code: "CS101".to_string(),
        course_title: Some("Intro to CS".to_string()),
        title_commitment: None,
        course_level: CourseLevel::Undergraduate as u8,
        credit_hours: Some(3),
        credit_commitment: None,
        prerequisites_count: 0,
        prerequisites_root: None,
        version: 1,
        supersedes: None,
        nonce: 7,
    }
}

fn sample_create_offering() -> CreateOfferingData {
    let cid = catalog_id(&INSTITUTION_ID, "CS", "CS101", 1, 7);
    let creator = Address::ZERO;
    let oid = offering_id(&cid, "2026FA", "A", &creator, 9);
    CreateOfferingData {
        offering_id: oid,
        catalog_id: cid,
        term: "2026FA".to_string(),
        section: "A".to_string(),
        instruction_start_at: 1_000,
        instruction_end_at: 2_000,
        final_grade_submission_deadline: 2_500,
        nonce: 9,
    }
}

fn sample_submit_assignment_receipt() -> SubmitAssignmentReceiptData {
    let cid = catalog_id(&INSTITUTION_ID, "CS", "CS101", 1, 7);
    let oid = offering_id(&cid, "2026FA", "A", &Address::ZERO, 9);
    let sc = student_commitment(&SUBJECT, &oid, &SALT);
    let subcommit = submission_commitment(&oid, &ASSESSMENT_ID, &sc, 1, &WORK_HASH, &SALT);
    SubmitAssignmentReceiptData {
        offering_id: oid,
        assessment_id: ASSESSMENT_ID,
        student_commitment: sc,
        submission_commitment: subcommit,
        work: ManagedSnipRef {
            snip_ref: SnipRef {
                content_root: WORK_HASH,
                snip_file_id: None,
                size_bytes: 4096,
                schema_version: 1,
            },
            access_policy: ContentAccessPolicy {
                opens_at: Some(1_000),
                closes_at: None,
                grace_until: None,
                audience: AccessAudience::StaffOnly,
                revoke_on_course_archive: true,
            },
        },
        attempt: 1,
        enrollment_ref: ENROLLMENT_REF,
        student_auth_commitment: None,
    }
}

fn edu_payload(standard: EducationStandard, operation: u16, data: Vec<u8>) -> TxPayload {
    TxPayload::Education(EducationTxData {
        standard,
        operation,
        data,
        recipient: Address::ZERO,
    })
}

// ───────────────────────── Append-only locks ────────────────────────────────

#[test]
fn tx_type_education_ordinal_locked() {
    assert_eq!(TxType::Education as u8, 22);
    assert_eq!(TxType::from_byte(22), Some(TxType::Education));
}

#[test]
fn tx_payload_education_variant_index_locked() {
    // bincode default: enum variant tag is u32 little-endian by
    // declaration ordinal. Education is appended at ordinal 22
    // (InferenceAttestation = 21). Any reorder above it silently
    // re-numbers historical txs.
    let payload = edu_payload(EducationStandard::CourseCatalog, 0, vec![]);
    let bytes = bincode::serialize(&payload).expect("payload encodes");
    let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(
        tag, 22,
        "TxPayload::Education bincode variant tag must be 22 (declaration \
         ordinal, immediately after InferenceAttestation at 21); got {tag}."
    );
}

#[test]
fn tx_payload_low_variants_unmoved() {
    // Guard: variant 0 (Transfer) must still tag 0 and the new
    // Education variant must tag 22 — proves the append did not
    // renumber existing variants.
    let transfer = TxPayload::Transfer {
        to: Address::ZERO,
        amount: 0,
    };
    let tbytes = bincode::serialize(&transfer).expect("encodes");
    assert_eq!(
        u32::from_le_bytes([tbytes[0], tbytes[1], tbytes[2], tbytes[3]]),
        0,
        "TxPayload::Transfer must remain bincode tag 0"
    );
    let edu = edu_payload(EducationStandard::CourseOffering, 0, vec![]);
    let ebytes = bincode::serialize(&edu).expect("encodes");
    assert_eq!(
        u32::from_le_bytes([ebytes[0], ebytes[1], ebytes[2], ebytes[3]]),
        22
    );
}

#[test]
fn education_standard_discriminants_locked() {
    assert_eq!(EducationStandard::CourseCatalog as u8, 0);
    assert_eq!(EducationStandard::CourseOffering as u8, 1);
}

#[test]
fn operation_codes_locked() {
    assert_eq!(catalog_op::CREATE_CATALOG_ENTRY, 0);
    assert_eq!(catalog_op::ARCHIVE_CATALOG_ENTRY, 5);
    assert_eq!(offering_op::CREATE_OFFERING, 0);
    assert_eq!(offering_op::LINK_ENROLLMENT, 7);
    assert_eq!(offering_op::SUBMIT_ASSIGNMENT, 8);
    assert_eq!(offering_op::SUBMIT_EXAM, 9);
    assert_eq!(offering_op::GRADE_SUBMISSION, 10);
    assert_eq!(offering_op::SUSPEND_OR_CANCEL_OFFERING, 14);
}

#[test]
fn max_constants_locked() {
    assert_eq!(MAX_COURSE_CODE_BYTES, 32);
    assert_eq!(MAX_DEPARTMENT_BYTES, 64);
    assert_eq!(MAX_TERM_BYTES, 32);
    assert_eq!(MAX_SECTION_BYTES, 32);
    assert_eq!(MAX_TITLE_BYTES, 256);
    assert_eq!(MAX_EDU_OP_DATA_BYTES, 64 * 1024);
    assert_eq!(MAX_MEMO_BYTES, 1024);
}

// ───────────────────────── Canonical byte locks ─────────────────────────────

const EXPECTED_CREATE_CATALOG_HEX: &str = "1600000000000000000083000000000000003f77062524d1010acc6b3c131c21713c57331ac7edabad06a7f87802e035d7e911111111111111111111111111111111111111111111111111111111111111110200000000000000435305000000000000004353313031010b00000000000000496e74726f20746f2043530000010300000000000000010000000007000000000000000000000000000000000000000000000000000000";
const EXPECTED_CREATE_OFFERING_HEX: &str = "16000000010000000000770000000000000038fcf909fab2f8e0e226153ea5fd45020717ac2c3fa1175569ab2f300d1320273f77062524d1010acc6b3c131c21713c57331ac7edabad06a7f87802e035d7e90600000000000000323032364641010000000000000041e803000000000000d007000000000000c40900000000000009000000000000000000000000000000000000000000000000000000";
const EXPECTED_SUBMIT_RECEIPT_HEX: &str = "16000000010000000800e00000000000000038fcf909fab2f8e0e226153ea5fd45020717ac2c3fa1175569ab2f300d13202755555555555555555555555555555555555555555555555555555555555555558069c08d1d63e419cb8e8166189c95deff7453f005ec739a3388ccfd8617f9ec3bcd27bb49f37697bc535a7158bc7e23e3bd4ebb4e017fd694cfe02841b1f5dd44444444444444444444444444444444444444444444444444444444444444440000100000000000000100000001e8030000000000000000030000000101006666666666666666666666666666666666666666666666666666666666666666000000000000000000000000000000000000000000";

#[test]
fn canonical_create_catalog_entry_bytes() {
    let data = bincode::serialize(&sample_create_catalog_entry()).unwrap();
    let payload = edu_payload(
        EducationStandard::CourseCatalog,
        catalog_op::CREATE_CATALOG_ENTRY,
        data,
    );
    let hexs = hex::encode(bincode::serialize(&payload).unwrap());
    assert_eq!(
        hexs, EXPECTED_CREATE_CATALOG_HEX,
        "CreateCatalogEntry wire drift. actual={hexs}"
    );
}

#[test]
fn canonical_create_offering_bytes() {
    let data = bincode::serialize(&sample_create_offering()).unwrap();
    let payload = edu_payload(
        EducationStandard::CourseOffering,
        offering_op::CREATE_OFFERING,
        data,
    );
    let hexs = hex::encode(bincode::serialize(&payload).unwrap());
    assert_eq!(
        hexs, EXPECTED_CREATE_OFFERING_HEX,
        "CreateOffering wire drift. actual={hexs}"
    );
}

#[test]
fn canonical_submit_assignment_receipt_bytes() {
    let data = bincode::serialize(&sample_submit_assignment_receipt()).unwrap();
    let payload = edu_payload(
        EducationStandard::CourseOffering,
        offering_op::SUBMIT_ASSIGNMENT,
        data,
    );
    let hexs = hex::encode(bincode::serialize(&payload).unwrap());
    assert_eq!(
        hexs, EXPECTED_SUBMIT_RECEIPT_HEX,
        "SubmitAssignmentReceipt wire drift. actual={hexs}"
    );
}

#[test]
fn receipt_round_trips() {
    let data = bincode::serialize(&sample_submit_assignment_receipt()).unwrap();
    let back: SubmitAssignmentReceiptData = bincode::deserialize(&data).unwrap();
    assert_eq!(back, sample_submit_assignment_receipt());
}

#[test]
fn submission_receipt_contains_no_raw_student_address() {
    // The receipt represents the student only via student_commitment.
    // A raw 20-byte student address pattern must never appear.
    let data = bincode::serialize(&sample_submit_assignment_receipt()).unwrap();
    let payload = edu_payload(
        EducationStandard::CourseOffering,
        offering_op::SUBMIT_ASSIGNMENT,
        data,
    );
    let bytes = bincode::serialize(&payload).unwrap();
    let needle = &FORBIDDEN_STUDENT_ADDR[..];
    let found = bytes.windows(needle.len()).any(|w| w == needle);
    assert!(
        !found,
        "raw student address pattern leaked into submission receipt bytes"
    );
}

// ───────────────────────── Commitment locks ─────────────────────────────────
//
// These constants are GENERATED from the fixed fixture inputs above
// (INSTITUTION_ID/SUBJECT/SALT/… + the documented domain tags) run
// through the final deterministic commitment helpers, then pinned.
// They must change ONLY on an intentional wire/helper change — a new
// domain tag, a changed input tuple/field order, a different
// serialization, or modified helper logic. An unexplained diff here
// means the on-chain identifier scheme drifted and historical
// records would become unreachable: treat as a red flag, not a
// re-pin.

const EXPECTED_CATALOG_ID_HEX: &str = "3f77062524d1010acc6b3c131c21713c57331ac7edabad06a7f87802e035d7e9";
const EXPECTED_OFFERING_ID_HEX: &str = "38fcf909fab2f8e0e226153ea5fd45020717ac2c3fa1175569ab2f300d132027";
const EXPECTED_STUDENT_COMMITMENT_HEX: &str = "8069c08d1d63e419cb8e8166189c95deff7453f005ec739a3388ccfd8617f9ec";
const EXPECTED_SUBMISSION_COMMITMENT_HEX: &str = "3bcd27bb49f37697bc535a7158bc7e23e3bd4ebb4e017fd694cfe02841b1f5dd";
const EXPECTED_GRADE_COMMITMENT_HEX: &str = "3bdb0b3c6e6196f1caddb7dd97dfbd953c6cbb92f41479378acbebcea0cee763";

#[test]
fn commitment_helpers_locked() {
    let cid = catalog_id(&INSTITUTION_ID, "CS", "CS101", 1, 7);
    let oid = offering_id(&cid, "2026FA", "A", &Address::ZERO, 9);
    let sc = student_commitment(&SUBJECT, &oid, &SALT);
    let sub = submission_commitment(&oid, &ASSESSMENT_ID, &sc, 1, &WORK_HASH, &SALT);
    let gr = grade_commitment(&oid, &ASSESSMENT_ID, &sc, b"A", &SALT);

    assert_eq!(
        hex::encode(cid),
        EXPECTED_CATALOG_ID_HEX,
        "catalog_id drift. actual={}",
        hex::encode(cid)
    );
    assert_eq!(
        hex::encode(oid),
        EXPECTED_OFFERING_ID_HEX,
        "offering_id drift. actual={}",
        hex::encode(oid)
    );
    assert_eq!(
        hex::encode(sc),
        EXPECTED_STUDENT_COMMITMENT_HEX,
        "student_commitment drift. actual={}",
        hex::encode(sc)
    );
    assert_eq!(
        hex::encode(sub),
        EXPECTED_SUBMISSION_COMMITMENT_HEX,
        "submission_commitment drift. actual={}",
        hex::encode(sub)
    );
    assert_eq!(
        hex::encode(gr),
        EXPECTED_GRADE_COMMITMENT_HEX,
        "grade_commitment drift. actual={}",
        hex::encode(gr)
    );
}

// ───────────────────────── Wire enum-as-u8 locks ────────────────────────────

#[test]
fn payload_enum_fields_encode_as_single_byte() {
    // `SuspendOrCancelOfferingData` = offering_id[32] + action(u8) +
    // nonce(u64) = 41 bytes IFF `action` is one byte. A bincode Rust
    // enum tag would be 4 bytes (u32) → 44 bytes. Length + the exact
    // code byte lock the one-byte encoding.
    let s = SuspendOrCancelOfferingData {
        offering_id: [0x55; 32],
        action: SuspendCancelAction::Cancel as u8,
        nonce: 7,
    };
    let b = bincode::serialize(&s).unwrap();
    assert_eq!(b.len(), 32 + 1 + 8, "action must be a single u8 code");
    assert_eq!(b[32], 2, "SuspendCancelAction::Cancel code must be 2");

    // GradeSubmission grader_role likewise one byte.
    let g = GradeSubmissionData {
        offering_id: [0; 32],
        assessment_id: [0; 32],
        student_commitment: [0; 32],
        grade_commitment: [0; 32],
        feedback: None,
        grader_role: CourseRole::Instructor as u8,
        nonce: 0,
    };
    let gb = bincode::serialize(&g).unwrap();
    // 4×[32] + Option::None(1) + grader_role(1) + nonce(8) = 138.
    assert_eq!(gb.len(), 128 + 1 + 1 + 8);
    assert_eq!(gb[129], 1, "CourseRole::Instructor code must be 1");

    // CreateCatalogEntry course_level is a u8 code, not a 4-byte tag.
    let c = sample_create_catalog_entry();
    assert_eq!(c.course_level, 0, "Undergraduate code must be 0");
    let cb = bincode::serialize(&c).unwrap();
    let cb2 = bincode::serialize(&{
        let mut x = sample_create_catalog_entry();
        x.course_level = CourseLevel::Graduate as u8;
        x
    })
    .unwrap();
    assert_eq!(
        cb.len(),
        cb2.len(),
        "changing the course_level code must not change encoded length \
         (proves it is a fixed u8, not a variable enum tag)"
    );
}

#[test]
fn wire_code_enums_round_trip() {
    for v in 0u8..=5 {
        if let Ok(e) = CourseLevel::try_from(v) {
            assert_eq!(e as u8, v);
        }
    }
    assert!(CourseLevel::try_from(6).is_err());
    assert_eq!(ContentKind::try_from(4).unwrap() as u8, 4);
    assert!(ContentKind::try_from(5).is_err());
    assert_eq!(AssessmentKind::try_from(1).unwrap(), AssessmentKind::Exam);
    assert!(AssessmentKind::try_from(4).is_err());
    assert_eq!(CourseRole::try_from(5).unwrap(), CourseRole::Auditor);
    assert!(CourseRole::try_from(6).is_err());
    assert_eq!(
        SuspendCancelAction::try_from(2).unwrap(),
        SuspendCancelAction::Cancel
    );
    assert!(SuspendCancelAction::try_from(3).is_err());
}
