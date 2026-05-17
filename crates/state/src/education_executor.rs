//! SRC-817/818 Education-LMS suite — Phase 2 storage + validation.
//!
//! Owns all education RocksDB interaction and the per-operation
//! semantic validation. It does NOT charge fees or advance nonces —
//! Policy B fee/nonce accounting lives in the dispatcher
//! (`executor.rs`), which has the account state handle.
//!
//! Split for Policy B:
//! - [`EducationExecutor::validate`] — pure DB reads; returns either a
//!   failure code (semantic reject) or a fully-prepared write set.
//! - [`EducationExecutor::commit`] — applies the prepared write set in
//!   a single atomic RocksDB batch (so success-path CF writes happen
//!   *after* the dispatcher has charged the fee + advanced the nonce,
//!   and a partial write is impossible).
//!
//! Privacy invariants (enforced here): students appear ONLY as a
//! scoped `student_commitment` — never a raw `Address`; every stored
//! SNIP ref is a `ManagedSnipRef`; primary records hold counters +
//! rolling-commitment roots, never unbounded vectors; no raw grades /
//! submissions / answer keys / PII. `tx.from` is the
//! sponsor/submitter/owner/grader, recorded as `Address` for Phase 3+
//! registered-institution policy — never the student.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sumchain_primitives::education::*;
use sumchain_primitives::hash::Hash;
use sumchain_primitives::Address;
use sumchain_storage::{cf, Database};

use crate::{Result, StateError};

// ───────────────────────── Failure codes ───────────────────────────────────
// Mirrors TxStatus::Failed(code) descriptions in primitives/receipt.rs.
pub const F_MALFORMED: u8 = 71;
pub const F_UNSUPPORTED: u8 = 72;
pub const F_CATALOG_NOT_FOUND: u8 = 73;
pub const F_CATALOG_WRONG_STATE: u8 = 74;
pub const F_OFFERING_NOT_FOUND: u8 = 75;
pub const F_OFFERING_WRONG_STATE: u8 = 76;
pub const F_ASSESSMENT_NOT_FOUND: u8 = 77;
pub const F_WINDOW_CLOSED: u8 = 78;
pub const F_NOT_ENROLLED: u8 = 79;
pub const F_ATTEMPTS_EXHAUSTED: u8 = 80;
pub const F_DUPLICATE: u8 = 81;
pub const F_INVALID_REFERENCE: u8 = 82;
pub const F_NOT_AUTHORIZED: u8 = 83;

// Status codes (mirror primitives enums' #[repr(u8)] discriminants).
const CAT_DRAFT: u8 = 0;
const CAT_ACTIVE: u8 = 1;
const CAT_DEPRECATED: u8 = 2;
const CAT_ARCHIVED: u8 = 3;
const OFF_DRAFT: u8 = 0;
const OFF_ACTIVE: u8 = 1;
const OFF_ENROLLMENT_CLOSED: u8 = 2;
const OFF_COMPLETED: u8 = 3;
const OFF_ARCHIVED: u8 = 4;
const OFF_SUSPENDED: u8 = 5;
const OFF_CANCELLED: u8 = 6;
const ASSESS_OPEN: u8 = 1;

// ───────────────────────── Stored records ──────────────────────────────────
// Distinct from the primitives wire payloads. `owner` / `submitter` /
// `grader` are `tx.from` (sponsor/institution), never a student.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCatalogEntry {
    pub catalog_id: [u8; 32],
    pub institution_id: [u8; 32],
    pub department: String,
    pub course_code: String,
    pub course_title: Option<String>,
    pub title_commitment: Option<[u8; 32]>,
    pub course_level: u8,
    pub credit_hours: Option<u16>,
    pub credit_commitment: Option<[u8; 32]>,
    pub prerequisites_count: u32,
    pub prerequisites_root: [u8; 32],
    pub accreditation_count: u32,
    pub accreditation_root: [u8; 32],
    pub status: u8,
    pub version: u32,
    pub supersedes: Option<[u8; 32]>,
    pub superseded_by: Option<[u8; 32]>,
    /// CreateCatalogEntry `tx.from` — sponsoring institution/admin.
    pub owner: Address,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredOffering {
    pub offering_id: [u8; 32],
    pub catalog_id: [u8; 32],
    pub term: String,
    pub section: String,
    pub instruction_start_at: u64,
    pub instruction_end_at: u64,
    pub final_grade_submission_deadline: u64,
    /// CreateOffering `tx.from` — sponsoring institution/admin.
    pub owner: Address,
    pub status: u8,
    pub instructor_count: u32,
    pub instructor_root: [u8; 32],
    pub content_count: u32,
    pub content_root: [u8; 32],
    pub assessment_count: u32,
    pub assessment_root: [u8; 32],
    pub enrollment_count: u32,
    pub enrollment_root: [u8; 32],
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredContentItem {
    pub offering_id: [u8; 32],
    pub content_id: [u8; 32],
    pub kind: u8,
    pub item: ManagedSnipRef,
    pub content_commitment: [u8; 32],
    pub created_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAssessment {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub kind: u8,
    pub instructions: ManagedSnipRef,
    pub spec_commitment: [u8; 32],
    pub opens_at: u64,
    pub due_at: u64,
    pub max_attempts: u16,
    pub weight_bps: u16,
    pub answer_key_commitment: Option<[u8; 32]>,
    pub answer_key_access: Option<ContentAccessPolicy>,
    pub status: u8,
    pub created_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnrollmentLink {
    /// Scoped pseudonym — NOT a raw address.
    pub student_commitment: [u8; 32],
    pub enrollment_ref: [u8; 32],
    pub linked_at_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSubmissionReceipt {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub student_commitment: [u8; 32],
    pub attempt: u16,
    pub submission_commitment: [u8; 32],
    pub work: ManagedSnipRef,
    pub student_auth_commitment: Option<[u8; 32]>,
    pub enrollment_ref: [u8; 32],
    /// `tx.from` — sponsor/relayer/LMS service account. NEVER student.
    pub submitter: Address,
    pub late: bool,
    pub submitted_at_height: u64,
    pub submitted_at_ts: u64,
    pub status: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGradeRecord {
    pub offering_id: [u8; 32],
    pub assessment_id: [u8; 32],
    pub student_commitment: [u8; 32],
    pub grade_commitment: [u8; 32],
    pub feedback: Option<ManagedSnipRef>,
    /// `tx.from` of GradeSubmission — instructor/grader institutional addr.
    pub grader: Address,
    pub grader_role: u8,
    pub graded_at_height: u64,
    pub status: u8,
    pub finalized: bool,
}

// ───────────────────────── Helpers ─────────────────────────────────────────

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    bincode::serialize(v).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn de<T: DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, u8> {
    bincode::deserialize::<T>(bytes).map_err(|_| F_MALFORMED)
}

/// Order-sensitive rolling commitment over inserted child keys. Keeps
/// the primary record bounded (one [u8;32], not a Vec). Length-safe:
/// fixed-size inputs only. A full merkle tree can replace this later
/// without a storage migration (the field stays [u8;32]).
fn roll(domain: &[u8], old: &[u8; 32], item_key: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(domain.len() + 32 + item_key.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(old);
    buf.extend_from_slice(item_key);
    *Hash::hash(&buf).as_bytes()
}

/// Length-safe `edu_catalog_by_code` hash component.
fn by_code_hash(department: &str, course_code: &str) -> [u8; 32] {
    let inner = bincode::serialize(&(department, course_code))
        .expect("(&str,&str) is infallibly serializable");
    let mut buf = Vec::with_capacity(26 + inner.len());
    buf.extend_from_slice(b"SRC817-CATALOG-BY-CODE:v1:");
    buf.extend_from_slice(&inner);
    *Hash::hash(&buf).as_bytes()
}

fn cat2(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(a.len() + b.len());
    k.extend_from_slice(a);
    k.extend_from_slice(b);
    k
}

/// A fully-prepared, validated write set. `commit` applies it in one
/// atomic batch. Building this in `validate` (pure reads) and applying
/// it in `commit` lets the dispatcher charge the Policy B fee/nonce
/// *between* the two, so success-path CF writes land only after fee
/// accounting and can never partially apply.
#[derive(Debug, Default)]
pub struct PreparedBatch {
    puts: Vec<(&'static str, Vec<u8>, Vec<u8>)>,
    dels: Vec<(&'static str, Vec<u8>)>,
}

impl PreparedBatch {
    fn put(&mut self, cf_name: &'static str, key: Vec<u8>, val: Vec<u8>) {
        self.puts.push((cf_name, key, val));
    }
    fn del(&mut self, cf_name: &'static str, key: Vec<u8>) {
        self.dels.push((cf_name, key));
    }
    pub fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.dels.is_empty()
    }
}

/// Decoded education operation, ready for semantic validation.
pub enum EduParsed {
    CreateCatalog(CreateCatalogEntryData),
    ArchiveCatalog(ArchiveCatalogEntryData),
    DeprecateCatalog(DeprecateCatalogEntryData),
    SupersedeCatalog(SupersedeCatalogEntryData),
    UpdateCatalog(UpdateCatalogEntryData),
    PublishCatalogContent(PublishCatalogContentData),
    CreateOffering(CreateOfferingData),
    UpdateOffering(UpdateOfferingData),
    PublishContent(PublishContentData),
    AddAssessment(AddAssessmentData),
    UpdateAssessment(UpdateAssessmentData),
    OpenEnrollment(OpenEnrollmentData),
    CloseEnrollment(CloseEnrollmentData),
    LinkEnrollment(LinkEnrollmentData),
    Submit(SubmitAssignmentReceiptData, bool /* is_exam */),
    Grade(GradeSubmissionData),
    FinalizeGrade(FinalizeGradeData),
    FinalizeCourse(FinalizeCourseData),
    ArchiveOffering(ArchiveOfferingData),
    SuspendOrCancel(SuspendOrCancelOfferingData),
}

/// Decode + route. Returns `Err(code)` with 72 (unknown standard/op)
/// or 71 (malformed/oversize payload) — both pre-semantic, free fail.
pub fn parse_education(tx: &EducationTxData) -> std::result::Result<EduParsed, u8> {
    if tx.data.len() > MAX_EDU_OP_DATA_BYTES {
        return Err(F_MALFORMED);
    }
    let d = &tx.data;
    Ok(match tx.standard {
        EducationStandard::CourseCatalog => match tx.operation {
            x if x == catalog_op::CREATE_CATALOG_ENTRY => EduParsed::CreateCatalog(de(d)?),
            x if x == catalog_op::UPDATE_CATALOG_ENTRY => EduParsed::UpdateCatalog(de(d)?),
            x if x == catalog_op::PUBLISH_CATALOG_CONTENT => {
                EduParsed::PublishCatalogContent(de(d)?)
            }
            x if x == catalog_op::DEPRECATE_CATALOG_ENTRY => EduParsed::DeprecateCatalog(de(d)?),
            x if x == catalog_op::SUPERSEDE_CATALOG_ENTRY => EduParsed::SupersedeCatalog(de(d)?),
            x if x == catalog_op::ARCHIVE_CATALOG_ENTRY => EduParsed::ArchiveCatalog(de(d)?),
            _ => return Err(F_UNSUPPORTED),
        },
        EducationStandard::CourseOffering => match tx.operation {
            x if x == offering_op::CREATE_OFFERING => EduParsed::CreateOffering(de(d)?),
            x if x == offering_op::UPDATE_OFFERING => EduParsed::UpdateOffering(de(d)?),
            x if x == offering_op::PUBLISH_CONTENT => EduParsed::PublishContent(de(d)?),
            x if x == offering_op::ADD_ASSESSMENT => EduParsed::AddAssessment(de(d)?),
            x if x == offering_op::UPDATE_ASSESSMENT => EduParsed::UpdateAssessment(de(d)?),
            x if x == offering_op::OPEN_ENROLLMENT => EduParsed::OpenEnrollment(de(d)?),
            x if x == offering_op::CLOSE_ENROLLMENT => EduParsed::CloseEnrollment(de(d)?),
            x if x == offering_op::LINK_ENROLLMENT => EduParsed::LinkEnrollment(de(d)?),
            x if x == offering_op::SUBMIT_ASSIGNMENT => EduParsed::Submit(de(d)?, false),
            x if x == offering_op::SUBMIT_EXAM => EduParsed::Submit(de(d)?, true),
            x if x == offering_op::GRADE_SUBMISSION => EduParsed::Grade(de(d)?),
            x if x == offering_op::FINALIZE_GRADE => EduParsed::FinalizeGrade(de(d)?),
            x if x == offering_op::FINALIZE_COURSE => EduParsed::FinalizeCourse(de(d)?),
            x if x == offering_op::ARCHIVE_OFFERING => EduParsed::ArchiveOffering(de(d)?),
            x if x == offering_op::SUSPEND_OR_CANCEL_OFFERING => {
                EduParsed::SuspendOrCancel(de(d)?)
            }
            _ => return Err(F_UNSUPPORTED),
        },
    })
}

pub struct EducationExecutor {
    db: Arc<Database>,
}

impl EducationExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub fn get_catalog(&self, id: &[u8; 32]) -> Result<Option<StoredCatalogEntry>> {
        match self.db.get(cf::EDU_CATALOG_ENTRIES, id)? {
            None => Ok(None),
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
        }
    }

    pub fn get_offering(&self, id: &[u8; 32]) -> Result<Option<StoredOffering>> {
        match self.db.get(cf::EDU_OFFERINGS, id)? {
            None => Ok(None),
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
        }
    }

    pub fn get_assessment(
        &self,
        offering_id: &[u8; 32],
        assessment_id: &[u8; 32],
    ) -> Result<Option<StoredAssessment>> {
        let k = cat2(offering_id, assessment_id);
        match self.db.get(cf::EDU_ASSESSMENTS, &k)? {
            None => Ok(None),
            Some(b) => Ok(Some(
                bincode::deserialize(&b)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
        }
    }

    fn exists(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        Ok(self.db.get(cf_name, key)?.is_some())
    }

    fn count_attempts(
        &self,
        offering_id: &[u8; 32],
        assessment_id: &[u8; 32],
        sc: &[u8; 32],
    ) -> Result<u16> {
        // Submission key prefix: offering || assessment || sc (then attempt_be[2]).
        let mut prefix = Vec::with_capacity(96);
        prefix.extend_from_slice(offering_id);
        prefix.extend_from_slice(assessment_id);
        prefix.extend_from_slice(sc);
        let mut n: u16 = 0;
        match self.db.prefix_iter(cf::EDU_SUBMISSIONS, &prefix) {
            Ok(it) => {
                for (k, _) in it {
                    if k.len() == 98 && k[..96] == prefix[..] {
                        n = n.saturating_add(1);
                    }
                }
            }
            Err(sumchain_storage::StorageError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(n)
    }

    /// Pure-read semantic validation. `Ok(batch)` = passes, apply via
    /// `commit` after Policy B fee/nonce. `Err(code)` = semantic reject
    /// (dispatcher still charges fee + advances nonce under Policy B).
    pub fn validate(
        &self,
        op: &EduParsed,
        sponsor: &Address,
        height: u64,
        ts: u64,
    ) -> Result<std::result::Result<PreparedBatch, u8>> {
        Ok(self.validate_inner(op, sponsor, height, ts)?)
    }

    fn validate_inner(
        &self,
        op: &EduParsed,
        sponsor: &Address,
        height: u64,
        ts: u64,
    ) -> Result<std::result::Result<PreparedBatch, u8>> {
        let mut pb = PreparedBatch::default();
        macro_rules! reject {
            ($c:expr) => {
                return Ok(Err($c))
            };
        }

        match op {
            EduParsed::CreateCatalog(d) => {
                if self.exists(cf::EDU_CATALOG_ENTRIES, &d.catalog_id)? {
                    reject!(F_DUPLICATE);
                }
                let rec = StoredCatalogEntry {
                    catalog_id: d.catalog_id,
                    institution_id: d.institution_id,
                    department: d.department.clone(),
                    course_code: d.course_code.clone(),
                    course_title: d.course_title.clone(),
                    title_commitment: d.title_commitment,
                    course_level: d.course_level,
                    credit_hours: d.credit_hours,
                    credit_commitment: d.credit_commitment,
                    prerequisites_count: d.prerequisites_count,
                    prerequisites_root: d.prerequisites_root.unwrap_or([0u8; 32]),
                    accreditation_count: 0,
                    accreditation_root: [0u8; 32],
                    status: CAT_DRAFT,
                    version: d.version,
                    supersedes: d.supersedes,
                    superseded_by: None,
                    owner: *sponsor,
                    created_at_height: height,
                    updated_at_height: height,
                    nonce: d.nonce,
                };
                pb.put(cf::EDU_CATALOG_ENTRIES, d.catalog_id.to_vec(), ser(&rec)?);
                pb.put(
                    cf::EDU_CATALOG_BY_INSTITUTION,
                    cat2(&d.institution_id, &d.catalog_id),
                    vec![],
                );
                pb.put(
                    cf::EDU_CATALOG_BY_CODE,
                    cat2(&by_code_hash(&d.department, &d.course_code), &d.catalog_id),
                    vec![],
                );
                pb.put(
                    cf::EDU_CATALOG_BY_STATUS,
                    cat2(&[CAT_DRAFT], &d.catalog_id),
                    vec![],
                );
            }

            EduParsed::UpdateCatalog(d) => {
                let mut rec = match self.get_catalog(&d.catalog_id)? {
                    Some(r) => r,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                if rec.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if rec.status != CAT_DRAFT && rec.status != CAT_ACTIVE {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                if let Some(t) = &d.course_title {
                    rec.course_title = Some(t.clone());
                }
                if let Some(tc) = d.title_commitment {
                    rec.title_commitment = Some(tc);
                }
                if let Some(cl) = d.course_level {
                    rec.course_level = cl;
                }
                if let Some(ch) = d.credit_hours {
                    rec.credit_hours = Some(ch);
                }
                if let Some(cc) = d.credit_commitment {
                    rec.credit_commitment = Some(cc);
                }
                rec.updated_at_height = height;
                pb.put(cf::EDU_CATALOG_ENTRIES, d.catalog_id.to_vec(), ser(&rec)?);
            }

            EduParsed::PublishCatalogContent(d) => {
                let mut rec = match self.get_catalog(&d.catalog_id)? {
                    Some(r) => r,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                if rec.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if rec.status != CAT_DRAFT && rec.status != CAT_ACTIVE {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                // Persist the SNIP content refs as bounded child rows
                // (kind byte: 0=description, 1=learning_outcomes,
                // 2=default_syllabus, 3=default_assessment_policy). Every
                // stored ref is a ManagedSnipRef. Refs not provided in
                // this op are left untouched (no silent drop).
                let mut put_ref = |kind: u8, r: &Option<ManagedSnipRef>| -> Result<()> {
                    if let Some(m) = r {
                        pb.put(
                            cf::EDU_CATALOG_CONTENT_ITEMS,
                            cat2(&d.catalog_id, &[kind]),
                            ser(m)?,
                        );
                    }
                    Ok(())
                };
                put_ref(0, &d.description_ref)?;
                put_ref(1, &d.learning_outcomes_ref)?;
                put_ref(2, &d.default_syllabus_ref)?;
                put_ref(3, &d.default_assessment_policy_ref)?;
                // First publish activates a Draft entry; drop the stale
                // Draft by-status index row before adding the Active one.
                if rec.status == CAT_DRAFT {
                    pb.del(
                        cf::EDU_CATALOG_BY_STATUS,
                        cat2(&[CAT_DRAFT], &d.catalog_id),
                    );
                    pb.put(
                        cf::EDU_CATALOG_BY_STATUS,
                        cat2(&[CAT_ACTIVE], &d.catalog_id),
                        vec![],
                    );
                    rec.status = CAT_ACTIVE;
                }
                rec.updated_at_height = height;
                pb.put(cf::EDU_CATALOG_ENTRIES, d.catalog_id.to_vec(), ser(&rec)?);
            }

            EduParsed::DeprecateCatalog(d) => {
                let mut rec = match self.get_catalog(&d.catalog_id)? {
                    Some(r) => r,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                if rec.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if rec.status != CAT_ACTIVE {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                rec.status = CAT_DEPRECATED;
                rec.updated_at_height = height;
                pb.put(cf::EDU_CATALOG_ENTRIES, d.catalog_id.to_vec(), ser(&rec)?);
                pb.del(
                    cf::EDU_CATALOG_BY_STATUS,
                    cat2(&[CAT_ACTIVE], &d.catalog_id),
                );
                pb.put(
                    cf::EDU_CATALOG_BY_STATUS,
                    cat2(&[CAT_DEPRECATED], &d.catalog_id),
                    vec![],
                );
            }

            EduParsed::SupersedeCatalog(d) => {
                let mut old = match self.get_catalog(&d.old_catalog_id)? {
                    Some(r) => r,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                if old.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if old.status == CAT_ARCHIVED {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                if !self.exists(cf::EDU_CATALOG_ENTRIES, &d.new_catalog_id)? {
                    reject!(F_INVALID_REFERENCE);
                }
                old.superseded_by = Some(d.new_catalog_id);
                old.updated_at_height = height;
                pb.put(
                    cf::EDU_CATALOG_ENTRIES,
                    d.old_catalog_id.to_vec(),
                    ser(&old)?,
                );
            }

            EduParsed::ArchiveCatalog(d) => {
                let mut rec = match self.get_catalog(&d.catalog_id)? {
                    Some(r) => r,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                if rec.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if rec.status == CAT_ARCHIVED {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                let old_status = rec.status;
                rec.status = CAT_ARCHIVED;
                rec.updated_at_height = height;
                pb.put(cf::EDU_CATALOG_ENTRIES, d.catalog_id.to_vec(), ser(&rec)?);
                pb.del(
                    cf::EDU_CATALOG_BY_STATUS,
                    cat2(&[old_status], &d.catalog_id),
                );
                pb.put(
                    cf::EDU_CATALOG_BY_STATUS,
                    cat2(&[CAT_ARCHIVED], &d.catalog_id),
                    vec![],
                );
            }

            EduParsed::CreateOffering(d) => {
                if self.exists(cf::EDU_OFFERINGS, &d.offering_id)? {
                    reject!(F_DUPLICATE);
                }
                let cat = match self.get_catalog(&d.catalog_id)? {
                    Some(c) => c,
                    None => reject!(F_CATALOG_NOT_FOUND),
                };
                // A NEW offering may bind only an Active catalog entry.
                // Deprecated entries stay resolvable for offerings bound
                // before deprecation, but cannot anchor new offerings.
                if cat.status != CAT_ACTIVE {
                    reject!(F_CATALOG_WRONG_STATE);
                }
                let rec = StoredOffering {
                    offering_id: d.offering_id,
                    catalog_id: d.catalog_id,
                    term: d.term.clone(),
                    section: d.section.clone(),
                    instruction_start_at: d.instruction_start_at,
                    instruction_end_at: d.instruction_end_at,
                    final_grade_submission_deadline: d.final_grade_submission_deadline,
                    owner: *sponsor,
                    status: OFF_DRAFT,
                    instructor_count: 0,
                    instructor_root: [0u8; 32],
                    content_count: 0,
                    content_root: [0u8; 32],
                    assessment_count: 0,
                    assessment_root: [0u8; 32],
                    enrollment_count: 0,
                    enrollment_root: [0u8; 32],
                    created_at_height: height,
                    updated_at_height: height,
                    nonce: d.nonce,
                };
                pb.put(cf::EDU_OFFERINGS, d.offering_id.to_vec(), ser(&rec)?);
                pb.put(
                    cf::EDU_OFFERING_BY_CATALOG,
                    cat2(&d.catalog_id, &d.offering_id),
                    vec![],
                );
                pb.put(
                    cf::EDU_OFFERING_BY_STATUS,
                    cat2(&[OFF_DRAFT], &d.offering_id),
                    vec![],
                );
            }

            EduParsed::UpdateOffering(d) => {
                let mut rec = match self.get_offering(&d.offering_id)? {
                    Some(r) => r,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                if rec.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if !offering_mutable(rec.status) {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                if let Some(t) = &d.term {
                    rec.term = t.clone();
                }
                if let Some(s) = &d.section {
                    rec.section = s.clone();
                }
                if let Some(v) = d.instruction_start_at {
                    rec.instruction_start_at = v;
                }
                if let Some(v) = d.instruction_end_at {
                    rec.instruction_end_at = v;
                }
                if let Some(v) = d.final_grade_submission_deadline {
                    rec.final_grade_submission_deadline = v;
                }
                rec.updated_at_height = height;
                pb.put(cf::EDU_OFFERINGS, d.offering_id.to_vec(), ser(&rec)?);
            }

            EduParsed::PublishContent(d) => {
                let mut off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if !offering_mutable(off.status) {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                let ck = cat2(&d.offering_id, &d.content_id);
                if self.exists(cf::EDU_CONTENT_ITEMS, &ck)? {
                    reject!(F_DUPLICATE);
                }
                let item = StoredContentItem {
                    offering_id: d.offering_id,
                    content_id: d.content_id,
                    kind: d.kind,
                    item: d.item.clone(),
                    content_commitment: d.content_commitment,
                    created_at_height: height,
                };
                off.content_count = off.content_count.saturating_add(1);
                off.content_root = roll(b"SRC818-CONTENT-ROOT:v1:", &off.content_root, &ck);
                off.updated_at_height = height;
                pb.put(cf::EDU_CONTENT_ITEMS, ck, ser(&item)?);
                pb.put(cf::EDU_OFFERINGS, d.offering_id.to_vec(), ser(&off)?);
            }

            EduParsed::AddAssessment(d) => {
                let mut off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if !offering_mutable(off.status) {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                let ak = cat2(&d.offering_id, &d.assessment_id);
                if self.exists(cf::EDU_ASSESSMENTS, &ak)? {
                    reject!(F_DUPLICATE);
                }
                let a = StoredAssessment {
                    offering_id: d.offering_id,
                    assessment_id: d.assessment_id,
                    kind: d.kind,
                    instructions: d.instructions.clone(),
                    spec_commitment: d.spec_commitment,
                    opens_at: d.opens_at,
                    due_at: d.due_at,
                    max_attempts: d.max_attempts,
                    weight_bps: d.weight_bps,
                    answer_key_commitment: d.answer_key_commitment,
                    answer_key_access: d.answer_key_access.clone(),
                    status: ASSESS_OPEN,
                    created_at_height: height,
                };
                off.assessment_count = off.assessment_count.saturating_add(1);
                off.assessment_root =
                    roll(b"SRC818-ASSESS-ROOT:v1:", &off.assessment_root, &ak);
                off.updated_at_height = height;
                pb.put(cf::EDU_ASSESSMENTS, ak, ser(&a)?);
                pb.put(cf::EDU_OFFERINGS, d.offering_id.to_vec(), ser(&off)?);
            }

            EduParsed::UpdateAssessment(d) => {
                let off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if !offering_mutable(off.status) {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                let mut a = match self.get_assessment(&d.offering_id, &d.assessment_id)? {
                    Some(a) => a,
                    None => reject!(F_ASSESSMENT_NOT_FOUND),
                };
                if let Some(v) = d.opens_at {
                    a.opens_at = v;
                }
                if let Some(v) = d.due_at {
                    a.due_at = v;
                }
                if let Some(v) = d.max_attempts {
                    a.max_attempts = v;
                }
                if let Some(v) = d.weight_bps {
                    a.weight_bps = v;
                }
                if let Some(i) = &d.instructions {
                    a.instructions = i.clone();
                }
                pb.put(
                    cf::EDU_ASSESSMENTS,
                    cat2(&d.offering_id, &d.assessment_id),
                    ser(&a)?,
                );
            }

            EduParsed::OpenEnrollment(d) => {
                let s = self.set_offering_status(
                    &d.offering_id,
                    sponsor,
                    &[OFF_DRAFT, OFF_ACTIVE, OFF_ENROLLMENT_CLOSED],
                    OFF_ACTIVE,
                    height,
                    &mut pb,
                )?;
                if let Err(c) = s {
                    reject!(c);
                }
            }
            EduParsed::CloseEnrollment(d) => {
                let s = self.set_offering_status(
                    &d.offering_id,
                    sponsor,
                    &[OFF_ACTIVE],
                    OFF_ENROLLMENT_CLOSED,
                    height,
                    &mut pb,
                )?;
                if let Err(c) = s {
                    reject!(c);
                }
            }
            EduParsed::FinalizeCourse(d) => {
                let s = self.set_offering_status(
                    &d.offering_id,
                    sponsor,
                    &[OFF_ENROLLMENT_CLOSED],
                    OFF_COMPLETED,
                    height,
                    &mut pb,
                )?;
                if let Err(c) = s {
                    reject!(c);
                }
            }
            EduParsed::ArchiveOffering(d) => {
                let s = self.set_offering_status(
                    &d.offering_id,
                    sponsor,
                    &[OFF_COMPLETED],
                    OFF_ARCHIVED,
                    height,
                    &mut pb,
                )?;
                if let Err(c) = s {
                    reject!(c);
                }
            }
            EduParsed::SuspendOrCancel(d) => {
                let (allowed, target): (&[u8], u8) = match d.action {
                    a if a == SuspendCancelAction::Suspend as u8 => {
                        (&[OFF_ACTIVE, OFF_ENROLLMENT_CLOSED], OFF_SUSPENDED)
                    }
                    a if a == SuspendCancelAction::Resume as u8 => (&[OFF_SUSPENDED], OFF_ACTIVE),
                    a if a == SuspendCancelAction::Cancel as u8 => {
                        (&[OFF_DRAFT, OFF_ACTIVE], OFF_CANCELLED)
                    }
                    _ => reject!(F_MALFORMED),
                };
                let s = self.set_offering_status(
                    &d.offering_id,
                    sponsor,
                    allowed,
                    target,
                    height,
                    &mut pb,
                )?;
                if let Err(c) = s {
                    reject!(c);
                }
            }

            EduParsed::LinkEnrollment(d) => {
                let off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                // Enrollment is an admin op: only the offering owner
                // (institution/admin) may bind a student commitment.
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                // New enrollment links only while Active (EnrollmentClosed
                // blocks NEW links per Phase 0 decision).
                if off.status != OFF_ACTIVE {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                if d.enrollment_ref == [0u8; 32] {
                    reject!(F_INVALID_REFERENCE);
                }
                let lk = cat2(&d.offering_id, &d.student_commitment);
                if self.exists(cf::EDU_ENROLLMENT_LINKS, &lk)? {
                    reject!(F_DUPLICATE);
                }
                let link = StoredEnrollmentLink {
                    student_commitment: d.student_commitment,
                    enrollment_ref: d.enrollment_ref,
                    linked_at_height: height,
                };
                let mut off2 = off;
                off2.enrollment_count = off2.enrollment_count.saturating_add(1);
                off2.enrollment_root =
                    roll(b"SRC818-ENROLL-ROOT:v1:", &off2.enrollment_root, &lk);
                off2.updated_at_height = height;
                pb.put(cf::EDU_ENROLLMENT_LINKS, lk, ser(&link)?);
                pb.put(cf::EDU_OFFERINGS, d.offering_id.to_vec(), ser(&off2)?);
            }

            EduParsed::Submit(d, is_exam) => {
                let off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                // Submissions accepted in Active and EnrollmentClosed.
                // (Finer per-student extension/accommodation gating for
                // EnrollmentClosed is deferred — see PR notes; base rule
                // here is offering-state + assessment window.)
                if off.status != OFF_ACTIVE && off.status != OFF_ENROLLMENT_CLOSED {
                    reject!(F_OFFERING_WRONG_STATE);
                }
                let a = match self.get_assessment(&d.offering_id, &d.assessment_id)? {
                    Some(a) => a,
                    None => reject!(F_ASSESSMENT_NOT_FOUND),
                };
                let want_kind = if *is_exam {
                    AssessmentKind::Exam as u8
                } else {
                    AssessmentKind::Assignment as u8
                };
                if a.kind != want_kind || a.status != ASSESS_OPEN {
                    reject!(F_ASSESSMENT_NOT_FOUND);
                }
                // Enrollment: student_commitment must have a link.
                let lk = cat2(&d.offering_id, &d.student_commitment);
                if !self.exists(cf::EDU_ENROLLMENT_LINKS, &lk)? {
                    reject!(F_NOT_ENROLLED);
                }
                if d.enrollment_ref == [0u8; 32] {
                    reject!(F_INVALID_REFERENCE);
                }
                // Window: opens_at <= ts; late flag if past due_at.
                if ts < a.opens_at {
                    reject!(F_WINDOW_CLOSED);
                }
                let late = ts > a.due_at;
                // Attempts.
                let used = self.count_attempts(
                    &d.offering_id,
                    &d.assessment_id,
                    &d.student_commitment,
                )?;
                if a.max_attempts != 0 && used >= a.max_attempts {
                    reject!(F_ATTEMPTS_EXHAUSTED);
                }
                let attempt = d.attempt;
                let mut subk = Vec::with_capacity(98);
                subk.extend_from_slice(&d.offering_id);
                subk.extend_from_slice(&d.assessment_id);
                subk.extend_from_slice(&d.student_commitment);
                subk.extend_from_slice(&attempt.to_be_bytes());
                if self.exists(cf::EDU_SUBMISSIONS, &subk)? {
                    reject!(F_DUPLICATE);
                }
                let rec = StoredSubmissionReceipt {
                    offering_id: d.offering_id,
                    assessment_id: d.assessment_id,
                    student_commitment: d.student_commitment,
                    attempt,
                    submission_commitment: d.submission_commitment,
                    work: d.work.clone(),
                    student_auth_commitment: d.student_auth_commitment,
                    enrollment_ref: d.enrollment_ref,
                    submitter: *sponsor, // tx.from — NEVER the student
                    late,
                    submitted_at_height: height,
                    submitted_at_ts: ts,
                    status: 0,
                };
                let mut idxk = Vec::with_capacity(98);
                idxk.extend_from_slice(&d.student_commitment);
                idxk.extend_from_slice(&d.offering_id);
                idxk.extend_from_slice(&d.assessment_id);
                idxk.extend_from_slice(&attempt.to_be_bytes());
                pb.put(cf::EDU_SUBMISSIONS, subk, ser(&rec)?);
                pb.put(cf::EDU_SUBMISSION_BY_STUDENT_COMMITMENT, idxk, vec![]);
            }

            EduParsed::Grade(d) => {
                let off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                // Phase 2 fail-closed: only the offering owner may
                // grade. Per-grader SRC-882 role resolution (delegating
                // to instructors/TAs) is deferred to a later phase;
                // until then grading is owner-gated, not permissive.
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                if self
                    .get_assessment(&d.offering_id, &d.assessment_id)?
                    .is_none()
                {
                    reject!(F_ASSESSMENT_NOT_FOUND);
                }
                let lk = cat2(&d.offering_id, &d.student_commitment);
                if !self.exists(cf::EDU_ENROLLMENT_LINKS, &lk)? {
                    reject!(F_NOT_ENROLLED);
                }
                let mut gk = Vec::with_capacity(96);
                gk.extend_from_slice(&d.offering_id);
                gk.extend_from_slice(&d.assessment_id);
                gk.extend_from_slice(&d.student_commitment);
                // Re-grade allowed unless finalized.
                if let Some(b) = self.db.get(cf::EDU_GRADES, &gk)? {
                    let prev: StoredGradeRecord = bincode::deserialize(&b)
                        .map_err(|e| StateError::SerializationError(e.to_string()))?;
                    if prev.finalized {
                        reject!(F_DUPLICATE);
                    }
                }
                let rec = StoredGradeRecord {
                    offering_id: d.offering_id,
                    assessment_id: d.assessment_id,
                    student_commitment: d.student_commitment,
                    grade_commitment: d.grade_commitment,
                    feedback: d.feedback.clone(),
                    grader: *sponsor,
                    grader_role: d.grader_role,
                    graded_at_height: height,
                    status: 0,
                    finalized: false,
                };
                pb.put(cf::EDU_GRADES, gk, ser(&rec)?);
            }

            EduParsed::FinalizeGrade(d) => {
                // Owner-gated, fail-closed (same as Grade).
                let off = match self.get_offering(&d.offering_id)? {
                    Some(o) => o,
                    None => reject!(F_OFFERING_NOT_FOUND),
                };
                if off.owner != *sponsor {
                    reject!(F_NOT_AUTHORIZED);
                }
                let mut gk = Vec::with_capacity(96);
                gk.extend_from_slice(&d.offering_id);
                gk.extend_from_slice(&d.assessment_id);
                gk.extend_from_slice(&d.student_commitment);
                let mut rec: StoredGradeRecord = match self.db.get(cf::EDU_GRADES, &gk)? {
                    Some(b) => bincode::deserialize(&b)
                        .map_err(|e| StateError::SerializationError(e.to_string()))?,
                    None => reject!(F_ASSESSMENT_NOT_FOUND),
                };
                if rec.finalized {
                    reject!(F_DUPLICATE);
                }
                rec.finalized = true;
                rec.status = 1;
                pb.put(cf::EDU_GRADES, gk, ser(&rec)?);
            }
        }

        Ok(Ok(pb))
    }

    fn set_offering_status(
        &self,
        id: &[u8; 32],
        sponsor: &Address,
        allowed: &[u8],
        target: u8,
        height: u64,
        pb: &mut PreparedBatch,
    ) -> Result<std::result::Result<(), u8>> {
        let mut rec = match self.get_offering(id)? {
            Some(r) => r,
            None => return Ok(Err(F_OFFERING_NOT_FOUND)),
        };
        // Phase 2 reference-shape auth: only the offering owner
        // (sponsoring institution/admin = CreateOffering tx.from) may
        // drive lifecycle transitions.
        if rec.owner != *sponsor {
            return Ok(Err(F_NOT_AUTHORIZED));
        }
        if !allowed.contains(&rec.status) {
            return Ok(Err(F_OFFERING_WRONG_STATE));
        }
        let old_status = rec.status;
        rec.status = target;
        rec.updated_at_height = height;
        pb.put(cf::EDU_OFFERINGS, id.to_vec(), ser(&rec)?);
        // Remove the stale by-status index row, then add the new one.
        pb.del(cf::EDU_OFFERING_BY_STATUS, cat2(&[old_status], id));
        pb.put(cf::EDU_OFFERING_BY_STATUS, cat2(&[target], id), vec![]);
        Ok(Ok(()))
    }

    /// Apply a validated write set atomically. Called by the dispatcher
    /// AFTER Policy B fee/nonce mutation on the success path.
    pub fn commit(&self, pb: PreparedBatch) -> Result<()> {
        let mut batch = self.db.batch();
        for (cf_name, k) in &pb.dels {
            batch.delete(cf_name, k)?;
        }
        for (cf_name, k, v) in &pb.puts {
            batch.put(cf_name, k, v)?;
        }
        batch.commit()?;
        Ok(())
    }
}

fn offering_mutable(status: u8) -> bool {
    status == OFF_DRAFT || status == OFF_ACTIVE || status == OFF_ENROLLMENT_CLOSED
}
