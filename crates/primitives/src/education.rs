//! SRC-817 / SRC-818 Education-LMS suite — Phase 1 wire types only.
//!
//! This module defines the canonical bincode wire shapes and
//! domain-separated commitment helpers for the education suite. It does
//! NOT implement any executor behavior, storage, mempool admission,
//! RPC, activation gate, or fee/nonce semantics — those are Phase 2+.
//!
//! Privacy model (frozen Phase 0 baseline, see
//! `docs/SRC-81X-EDUCATION-SUITE.md`):
//! - The submission itself happens in SNIP; the chain records only a
//!   submission *receipt* (commitments + refs + audit fields).
//! - The public chain tx sender is an authorized submitter
//!   (institution / sponsor / relayer / LMS service account) and is
//!   NEVER the student identity. There is no `submitter` field in any
//!   wire payload — it is derived from the signed tx `from` in Phase 2.
//! - Student identity is represented only by a scoped, salted,
//!   non-reversible `student_commitment`; no raw student address, no
//!   PII, no raw grades/submissions/answer keys on chain.
//! - Every `SnipRef` carried in chain state is paired with a
//!   `ContentAccessPolicy` (`ManagedSnipRef`) — no bare/dangling refs.

use serde::{Deserialize, Serialize};

use crate::Address;

// ───────────────────────── Bounded-length constants ─────────────────────────
//
// Enforced by validators in Phase 2; asserted present by the Phase 1
// fixtures so the limits are part of the locked wire contract.

/// Max bytes for a catalog `course_code` (e.g. "CS101").
pub const MAX_COURSE_CODE_BYTES: usize = 32;
/// Max bytes for a catalog `department` string.
pub const MAX_DEPARTMENT_BYTES: usize = 64;
/// Max bytes for an offering `term` coordinate (e.g. "2026FA").
pub const MAX_TERM_BYTES: usize = 32;
/// Max bytes for an offering `section` coordinate (e.g. "A").
pub const MAX_SECTION_BYTES: usize = 32;
/// Max bytes for a plaintext course title.
pub const MAX_TITLE_BYTES: usize = 256;
/// Max bytes for the opaque per-operation `data` payload.
pub const MAX_EDU_OP_DATA_BYTES: usize = 64 * 1024;
/// Max bytes for any optional memo/metadata field.
pub const MAX_MEMO_BYTES: usize = 1024;

// ───────────────────────── Domain-separation tags ───────────────────────────

const DOMAIN_CATALOG_ID: &[u8] = b"SRC817-CATALOG:v1:";
const DOMAIN_OFFERING_ID: &[u8] = b"SRC818-OFFERING:v1:";
const DOMAIN_STUDENT_COMMITMENT: &[u8] = b"SRC818-STUDENT:v1:";
const DOMAIN_SUBMISSION_COMMITMENT: &[u8] = b"SRC818-SUBMISSION:v1:";
const DOMAIN_GRADE_COMMITMENT: &[u8] = b"SRC818-GRADE:v1:";

// ───────────────────────── Envelope ─────────────────────────────────────────

/// Which education standard an `EducationTxData` targets. Append-only:
/// future SRC-81X standards (810 transcript, 811 diploma, …) get new
/// discriminants here, never a new `TxPayload` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EducationStandard {
    CourseCatalog = 0,
    CourseOffering = 1,
}

/// Unified education transaction envelope. Carried by
/// `TxPayload::Education` (the single education `TxPayload` variant).
///
/// `operation` is an explicit `u16` code (not a Rust enum variant tag)
/// so the documented sparse operation codes are the wire truth and are
/// stable regardless of Rust enum declaration order. See `catalog_op`
/// and `offering_op`.
///
/// `recipient` keeps envelope parity with the other transaction
/// families (`DocClass`/`Employment` etc.). Education v1 operations have
/// no soulbound/token target, so `recipient` is set to `Address::ZERO`
/// (the repo's existing no-target convention). It is reserved for a
/// future operation that has a genuine target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EducationTxData {
    pub standard: EducationStandard,
    pub operation: u16,
    pub data: Vec<u8>,
    pub recipient: Address,
}

/// SRC-817 catalog operation codes (documented, wire-authoritative).
pub mod catalog_op {
    pub const CREATE_CATALOG_ENTRY: u16 = 0;
    pub const UPDATE_CATALOG_ENTRY: u16 = 1;
    pub const PUBLISH_CATALOG_CONTENT: u16 = 2;
    pub const DEPRECATE_CATALOG_ENTRY: u16 = 3;
    pub const SUPERSEDE_CATALOG_ENTRY: u16 = 4;
    pub const ARCHIVE_CATALOG_ENTRY: u16 = 5;
}

/// SRC-818 offering operation codes (documented, wire-authoritative).
pub mod offering_op {
    pub const CREATE_OFFERING: u16 = 0;
    pub const UPDATE_OFFERING: u16 = 1;
    pub const PUBLISH_CONTENT: u16 = 2;
    pub const ADD_ASSESSMENT: u16 = 3;
    pub const UPDATE_ASSESSMENT: u16 = 4;
    pub const OPEN_ENROLLMENT: u16 = 5;
    pub const CLOSE_ENROLLMENT: u16 = 6;
    pub const LINK_ENROLLMENT: u16 = 7;
    pub const SUBMIT_ASSIGNMENT: u16 = 8;
    pub const SUBMIT_EXAM: u16 = 9;
    pub const GRADE_SUBMISSION: u16 = 10;
    pub const FINALIZE_GRADE: u16 = 11;
    pub const FINALIZE_COURSE: u16 = 12;
    pub const ARCHIVE_OFFERING: u16 = 13;
    pub const SUSPEND_OR_CANCEL_OFFERING: u16 = 14;
}

// ───────────────────────── Shared SNIP-ref + access policy ──────────────────

/// Off-chain content pointer. No URL, no plaintext, no keys. The actual
/// object lives in SNIP; the chain holds only this pointer + a
/// commitment + an access policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnipRef {
    pub content_root: [u8; 32],
    pub snip_file_id: Option<[u8; 32]>,
    pub size_bytes: u64,
    pub schema_version: u32,
}

/// Audience class a `ContentAccessPolicy` grants access to.
/// `IndividualStudent` carries a scoped `student_commitment` (never a
/// raw address). It is **provisional**: legal/privacy must confirm a
/// per-student commitment in on-chain policy is FERPA-safe, otherwise
/// individual targeting moves entirely into SNIP ACL and chain policy
/// stays audience-class-only. See `docs/SRC-81X-EDUCATION-SUITE.md`
/// §3.2 / §6 Q9. Hard Phase-1-blocking question (tracked in docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessAudience {
    Public,
    EnrolledStudents,
    InstructorsOnly,
    StaffOnly,
    IndividualStudent([u8; 32]),
}

/// Time-windowed access policy. The chain stores the schedule; SNIP
/// enforces actual private object access within the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentAccessPolicy {
    pub opens_at: Option<u64>,
    pub closes_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub audience: AccessAudience,
    pub revoke_on_course_archive: bool,
}

/// A `SnipRef` is never carried bare in education chain state — it is
/// always paired with its `ContentAccessPolicy`. Using this wrapper in
/// every payload makes a dangling content ref structurally impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedSnipRef {
    pub snip_ref: SnipRef,
    pub access_policy: ContentAccessPolicy,
}

// ───────────────────────── Status / role enums ──────────────────────────────
//
// `#[repr(u8)]` documented discriminants. These are not serialized as
// bincode enum tags on the wire where a stable code matters; payloads
// that persist a status do so via the explicit numeric value.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CatalogStatus {
    Draft = 0,
    Active = 1,
    Deprecated = 2,
    Archived = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OfferingStatus {
    Draft = 0,
    Active = 1,
    EnrollmentClosed = 2,
    Completed = 3,
    Archived = 4,
    Suspended = 5,
    Cancelled = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AssessmentKind {
    Assignment = 0,
    Exam = 1,
    Quiz = 2,
    Project = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CourseRole {
    InstitutionAdmin = 0,
    Instructor = 1,
    TeachingAssistant = 2,
    Grader = 3,
    Student = 4,
    Auditor = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CourseLevel {
    Undergraduate = 0,
    Graduate = 1,
    Doctoral = 2,
    Professional = 3,
    Continuing = 4,
    Other = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentKind {
    Syllabus = 0,
    LectureMaterial = 1,
    Reading = 2,
    Resource = 3,
    Other = 4,
}

/// Action carried by the combined Suspend/Cancel offering op
/// (`offering_op::SUSPEND_OR_CANCEL_OFFERING`). `Suspend` is reversible
/// (`Resume`); `Cancel` is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SuspendCancelAction {
    Suspend = 0,
    Resume = 1,
    Cancel = 2,
}

// ───────────────────────── Representative op payloads ───────────────────────
//
// Phase 1 ships the three payloads exercised by the locked fixtures
// (CreateCatalogEntry, CreateOffering, SubmitAssignmentReceipt). The
// remaining operation payloads follow the same shape and are added as
// Phase 1 increments without wire-breaking the envelope.

/// SRC-817 `CreateCatalogEntry` (operation = `catalog_op::CREATE_CATALOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateCatalogEntryData {
    pub catalog_id: [u8; 32],
    pub institution_id: [u8; 32],
    pub department: String,
    pub course_code: String,
    /// Plaintext title (default) — set exactly one of title/commitment.
    pub course_title: Option<String>,
    pub title_commitment: Option<[u8; 32]>,
    pub course_level: CourseLevel,
    /// Plaintext credit hours (default) — or commitment for
    /// confidential programs. Set exactly one.
    pub credit_hours: Option<u16>,
    pub credit_commitment: Option<[u8; 32]>,
    /// Count + root over prerequisite catalog_ids (bounded-collection
    /// rule: no inline unbounded Vec on the primary record).
    pub prerequisites_count: u32,
    pub prerequisites_root: Option<[u8; 32]>,
    pub version: u32,
    pub supersedes: Option<[u8; 32]>,
    pub nonce: u64,
}

/// SRC-818 `CreateOffering` (operation = `offering_op::CREATE_OFFERING`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOfferingData {
    pub offering_id: [u8; 32],
    /// REQUIRED ref to a non-Archived/Deprecated SRC-817 catalog entry.
    pub catalog_id: [u8; 32],
    pub term: String,
    pub section: String,
    /// Academic calendar — public, non-PII; bounds the default student
    /// submission window and content access window.
    pub instruction_start_at: u64,
    pub instruction_end_at: u64,
    pub final_grade_submission_deadline: u64,
    pub nonce: u64,
}

/// SRC-818 `SubmitAssignment` / `SubmitExam` **receipt** payload
/// (operation = `offering_op::SUBMIT_ASSIGNMENT` / `SUBMIT_EXAM`).
///
/// This is a receipt, not the work. There is NO `submitter` field —
/// the authorized submitter is the signed tx `from`, recorded in the
/// stored record in Phase 2. No raw student address, no raw work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitAssignmentReceiptData {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    /// Scoped, salted, non-reversible pseudonym — never a raw address.
    pub student_commitment: [u8; 32],
    pub submission_commitment: [u8; 32],
    /// The submitted work lives in SNIP, referenced + access-policed.
    pub work: ManagedSnipRef,
    pub attempt: u16,
    /// SRC-812 enrollment credential proving student authorization.
    pub enrollment_ref: [u8; 32],
    /// Optional commitment over a student-scoped signature / SNIP
    /// submission authorization proven inside the private payload.
    /// Optional in Phase 1; mandatory-vs-optional enforcement is a
    /// Phase 2 executor/policy decision tied to legal Q9.
    pub student_auth_commitment: Option<[u8; 32]>,
}

// ───────────────────────── Full op payload wire surface ────────────────────
//
// Phase 1 defines the complete SRC-817/818 operation payload wire
// surface. Only the three payloads above carry canonical-byte fixtures
// (representative); these additional payloads complete the wire
// contract so Phase 2 cannot wire-break the envelope. No executor
// behavior is implied by any of these — they are wire types only.

// ---- SRC-817 catalog ----

/// SRC-817 `UpdateCatalogEntry` (`catalog_op::UPDATE_CATALOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCatalogEntryData {
    pub catalog_id: [u8; 32],
    pub course_title: Option<String>,
    pub title_commitment: Option<[u8; 32]>,
    pub course_level: Option<CourseLevel>,
    pub credit_hours: Option<u16>,
    pub credit_commitment: Option<[u8; 32]>,
    pub nonce: u64,
}

/// SRC-817 `PublishCatalogContent` (`catalog_op::PUBLISH_CATALOG_CONTENT`).
/// Every ref is a `ManagedSnipRef` (ref + mandatory access policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishCatalogContentData {
    pub catalog_id: [u8; 32],
    pub description_ref: Option<ManagedSnipRef>,
    pub learning_outcomes_ref: Option<ManagedSnipRef>,
    pub default_syllabus_ref: Option<ManagedSnipRef>,
    pub default_assessment_policy_ref: Option<ManagedSnipRef>,
    pub nonce: u64,
}

/// SRC-817 `DeprecateCatalogEntry` (`catalog_op::DEPRECATE_CATALOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecateCatalogEntryData {
    pub catalog_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-817 `SupersedeCatalogEntry` (`catalog_op::SUPERSEDE_CATALOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersedeCatalogEntryData {
    pub old_catalog_id: [u8; 32],
    pub new_catalog_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-817 `ArchiveCatalogEntry` (`catalog_op::ARCHIVE_CATALOG_ENTRY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveCatalogEntryData {
    pub catalog_id: [u8; 32],
    pub nonce: u64,
}

// ---- SRC-818 offering ----

/// SRC-818 `UpdateOffering` (`offering_op::UPDATE_OFFERING`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateOfferingData {
    pub offering_id: [u8; 32],
    pub term: Option<String>,
    pub section: Option<String>,
    pub instruction_start_at: Option<u64>,
    pub instruction_end_at: Option<u64>,
    pub final_grade_submission_deadline: Option<u64>,
    pub nonce: u64,
}

/// SRC-818 `PublishContent` (`offering_op::PUBLISH_CONTENT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishContentData {
    pub offering_id: [u8; 32],
    pub content_id: [u8; 32],
    pub kind: ContentKind,
    pub item: ManagedSnipRef,
    pub content_commitment: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `AddAssessment` (`offering_op::ADD_ASSESSMENT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAssessmentData {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub kind: AssessmentKind,
    pub instructions: ManagedSnipRef,
    pub spec_commitment: [u8; 32],
    pub opens_at: u64,
    pub due_at: u64,
    pub max_attempts: u16,
    pub weight_bps: u16,
    pub answer_key_commitment: Option<[u8; 32]>,
    pub answer_key_access: Option<ContentAccessPolicy>,
    pub nonce: u64,
}

/// SRC-818 `UpdateAssessment` (`offering_op::UPDATE_ASSESSMENT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAssessmentData {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub opens_at: Option<u64>,
    pub due_at: Option<u64>,
    pub max_attempts: Option<u16>,
    pub weight_bps: Option<u16>,
    pub instructions: Option<ManagedSnipRef>,
    pub nonce: u64,
}

/// SRC-818 `OpenEnrollment` (`offering_op::OPEN_ENROLLMENT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEnrollmentData {
    pub offering_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `CloseEnrollment` (`offering_op::CLOSE_ENROLLMENT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseEnrollmentData {
    pub offering_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `LinkEnrollment` (`offering_op::LINK_ENROLLMENT`). Binds a
/// scoped `student_commitment` (never a raw address) backed by an
/// SRC-812 enrollment credential reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkEnrollmentData {
    pub offering_id: [u8; 32],
    pub student_commitment: [u8; 32],
    pub enrollment_ref: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `SubmitExam` receipt (`offering_op::SUBMIT_EXAM`). The wire
/// shape is identical to the assignment receipt — only the envelope
/// `operation` code differs (8 vs 9). Modeled as a type alias so the
/// two cannot drift apart.
pub type SubmitExamReceiptData = SubmitAssignmentReceiptData;

/// SRC-818 `GradeSubmission` (`offering_op::GRADE_SUBMISSION`). Only a
/// grade *commitment* + optional encrypted-feedback ref — never the
/// raw grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeSubmissionData {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub student_commitment: [u8; 32],
    pub grade_commitment: [u8; 32],
    pub feedback: Option<ManagedSnipRef>,
    pub grader_role: CourseRole,
    pub nonce: u64,
}

/// SRC-818 `FinalizeGrade` (`offering_op::FINALIZE_GRADE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeGradeData {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub student_commitment: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `FinalizeCourse` (`offering_op::FINALIZE_COURSE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeCourseData {
    pub offering_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 `ArchiveOffering` (`offering_op::ARCHIVE_OFFERING`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveOfferingData {
    pub offering_id: [u8; 32],
    pub nonce: u64,
}

/// SRC-818 combined `SuspendOffering` / `CancelOffering`
/// (`offering_op::SUSPEND_OR_CANCEL_OFFERING`). `action` selects
/// Suspend (reversible) / Resume / Cancel (terminal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendOrCancelOfferingData {
    pub offering_id: [u8; 32],
    pub action: SuspendCancelAction,
    pub nonce: u64,
}

// ───────────────────────── Commitment helpers ───────────────────────────────
//
// Pure, domain-separated BLAKE3. Same discipline as
// `inference_attestation.rs`: a stable on-chain identifier scheme that
// the Phase 1 fixtures pin byte-for-byte.

fn blake3_concat(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(domain.len());
    buf.extend_from_slice(domain);
    for p in parts {
        buf.extend_from_slice(p);
    }
    *blake3::hash(&buf).as_bytes()
}

// Call sites slice every fixed-size array (`&arr[..]`) so all parts
// unify to `&[u8]`.

/// `catalog_id = BLAKE3("SRC817-CATALOG:v1:" ‖ institution_id ‖
/// department ‖ course_code ‖ version_le ‖ nonce_le)`.
pub fn catalog_id(
    institution_id: &[u8; 32],
    department: &str,
    course_code: &str,
    version: u32,
    nonce: u64,
) -> [u8; 32] {
    blake3_concat(
        DOMAIN_CATALOG_ID,
        &[
            &institution_id[..],
            department.as_bytes(),
            course_code.as_bytes(),
            &version.to_le_bytes()[..],
            &nonce.to_le_bytes()[..],
        ],
    )
}

/// `offering_id = BLAKE3("SRC818-OFFERING:v1:" ‖ catalog_id ‖ term ‖
/// section ‖ creator ‖ nonce_le)`.
pub fn offering_id(
    catalog_id: &[u8; 32],
    term: &str,
    section: &str,
    creator: &Address,
    nonce: u64,
) -> [u8; 32] {
    blake3_concat(
        DOMAIN_OFFERING_ID,
        &[
            &catalog_id[..],
            term.as_bytes(),
            section.as_bytes(),
            &creator.as_bytes()[..],
            &nonce.to_le_bytes()[..],
        ],
    )
}

/// `student_commitment = BLAKE3("SRC818-STUDENT:v1:" ‖ subject ‖
/// offering_id ‖ salt)` — per-offering/per-context scoped, salted,
/// non-reversible. A global/cross-offering student identifier is
/// prohibited (Phase 0 FERPA rule).
pub fn student_commitment(
    subject: &[u8; 32],
    offering_id: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    blake3_concat(
        DOMAIN_STUDENT_COMMITMENT,
        &[&subject[..], &offering_id[..], &salt[..]],
    )
}

/// `submission_commitment = BLAKE3("SRC818-SUBMISSION:v1:" ‖
/// offering_id ‖ assessment_id ‖ student_commitment ‖ attempt_le ‖
/// work_hash ‖ salt)`.
pub fn submission_commitment(
    offering_id: &[u8; 32],
    assessment_id: &[u8; 32],
    student_commitment: &[u8; 32],
    attempt: u16,
    work_hash: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    blake3_concat(
        DOMAIN_SUBMISSION_COMMITMENT,
        &[
            &offering_id[..],
            &assessment_id[..],
            &student_commitment[..],
            &attempt.to_le_bytes()[..],
            &work_hash[..],
            &salt[..],
        ],
    )
}

/// `grade_commitment = BLAKE3("SRC818-GRADE:v1:" ‖ offering_id ‖
/// assessment_id ‖ student_commitment ‖ grade_value ‖ salt)`. The raw
/// grade is never on chain — only this commitment.
pub fn grade_commitment(
    offering_id: &[u8; 32],
    assessment_id: &[u8; 32],
    student_commitment: &[u8; 32],
    grade_value: &[u8],
    salt: &[u8; 32],
) -> [u8; 32] {
    blake3_concat(
        DOMAIN_GRADE_COMMITMENT,
        &[
            &offering_id[..],
            &assessment_id[..],
            &student_commitment[..],
            grade_value,
            &salt[..],
        ],
    )
}
