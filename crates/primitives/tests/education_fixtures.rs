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
        course_level: CourseLevel::Undergraduate,
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

const EXPECTED_CREATE_CATALOG_HEX: &str = "1600000000000000000086000000000000005fec2416c01fe2406a5acae41cd891de1b9b917312e4f832f3a51b8665d1e8c311111111111111111111111111111111111111111111111111111111111111110200000000000000435305000000000000004353313031010b00000000000000496e74726f20746f2043530000000000010300000000000000010000000007000000000000000000000000000000000000000000000000000000";
const EXPECTED_CREATE_OFFERING_HEX: &str = "1600000001000000000077000000000000001a5022dadb5075c5123087ee43ed01821cddc75900988ea9e57e6fa46dbea7a45fec2416c01fe2406a5acae41cd891de1b9b917312e4f832f3a51b8665d1e8c30600000000000000323032364641010000000000000041e803000000000000d007000000000000c40900000000000009000000000000000000000000000000000000000000000000000000";
const EXPECTED_SUBMIT_RECEIPT_HEX: &str = "16000000010000000800e0000000000000001a5022dadb5075c5123087ee43ed01821cddc75900988ea9e57e6fa46dbea7a455555555555555555555555555555555555555555555555555555555555555554eaee80fb2ea581de696155d755efccdefb8cccab16aea4c6f1cd0aee6de648a9eee6b9bae5ef0fab3126c4e2ebe4d5657da272b0bce89ddd554250e5650c63d44444444444444444444444444444444444444444444444444444444444444440000100000000000000100000001e8030000000000000000030000000101006666666666666666666666666666666666666666666666666666666666666666000000000000000000000000000000000000000000";

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

const EXPECTED_CATALOG_ID_HEX: &str = "5fec2416c01fe2406a5acae41cd891de1b9b917312e4f832f3a51b8665d1e8c3";
const EXPECTED_OFFERING_ID_HEX: &str = "1a5022dadb5075c5123087ee43ed01821cddc75900988ea9e57e6fa46dbea7a4";
const EXPECTED_STUDENT_COMMITMENT_HEX: &str = "4eaee80fb2ea581de696155d755efccdefb8cccab16aea4c6f1cd0aee6de648a";
const EXPECTED_SUBMISSION_COMMITMENT_HEX: &str = "9eee6b9bae5ef0fab3126c4e2ebe4d5657da272b0bce89ddd554250e5650c63d";
const EXPECTED_GRADE_COMMITMENT_HEX: &str = "0296e3a9c197d9594d4255b75bef84a81373011b3590ec20c681fce357f94d0d";

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
