//! Schema Validation for Privacy Enforcement
//!
//! Provides deterministic allowlist-based validation to prevent PII from being
//! stored on-chain in credential metadata.
//!
//! Design principles:
//! - HARD REJECTION: Transactions violating schema are rejected at consensus
//! - ALLOWLIST-BASED: Only explicitly permitted fields/keys are allowed
//! - NO HEURISTICS: No regex/ML PII detection (too brittle)
//! - DETERMINISTIC: Same input always produces same validation result
//! - BACKWARD COMPATIBLE: Existing credentials remain valid
//!
//! Enforcement applies ONLY to NEW credentials issued after activation height.

use std::collections::HashSet;

use sumchain_primitives::{
    AcademicCredential, BlockHeight, CredentialAttribute, CredentialMetadata, DocSubcode,
    EligibilityAttestation,
};
use sumchain_primitives::employment::EmploymentCredential;
use sumchain_primitives::healthcare::MembershipRecord;
use sumchain_primitives::tax::TaxDisclosureEnvelope;

/// The credential field length caps, at module scope so the protocol digest can
/// read them.
///
/// Each one decides, above `docclass_schema_validation_enabled_from_height`,
/// whether a credential-issuing transaction is ACCEPTED or REJECTED, so two
/// binaries holding different caps write different state from the same block.
/// They were previously declared inside the function bodies that read them,
/// which put them out of reach of any comparison — the same hazard as a
/// `ChainParams` field nobody digests, one level further down. Values unchanged.
pub const MAX_TITLE_LENGTH: usize = 200;
/// Cap on `metadata.credential_type`. See [`MAX_TITLE_LENGTH`].
pub const MAX_CREDENTIAL_TYPE_LENGTH: usize = 100;
/// Cap on the optional `metadata.program`. See [`MAX_TITLE_LENGTH`].
pub const MAX_PROGRAM_LENGTH: usize = 200;
/// Cap on `issue_date` and `completion_date`. See [`MAX_TITLE_LENGTH`].
pub const MAX_DATE_LENGTH: usize = 50;
/// Cap on one attribute value. See [`MAX_TITLE_LENGTH`].
pub const MAX_ATTRIBUTE_VALUE_LENGTH: usize = 500;
/// Cap on an institutional name. See [`MAX_TITLE_LENGTH`].
pub const MAX_NAME_LENGTH: usize = 200;
/// Cap on a storage hint. See [`MAX_TITLE_LENGTH`].
pub const MAX_HINT_LENGTH: usize = 500;

/// Schema validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Credential passes all validation checks
    Valid,
    /// Credential violates schema rules
    Invalid { reason: String },
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    pub fn invalid(reason: impl Into<String>) -> Self {
        ValidationResult::Invalid {
            reason: reason.into(),
        }
    }
}

/// Schema validation configuration
#[derive(Debug, Clone)]
pub struct SchemaValidatorConfig {
    /// Block height when validation becomes active (for backward compatibility)
    pub activation_height: BlockHeight,
    /// Whether to enforce validation (can be disabled for testing)
    pub enabled: bool,
}

impl Default for SchemaValidatorConfig {
    fn default() -> Self {
        Self {
            // Schema validation activation height
            // Current block: 384,017
            // Buffer for deployment: ~1000 blocks (~1-2 hours)
            activation_height: 385000,
            enabled: true,
        }
    }
}

/// Schema validator for academic credentials (SRC-81X)
pub struct SchemaValidator {
    config: SchemaValidatorConfig,
}

impl SchemaValidator {
    /// Create new validator with default config
    pub fn new() -> Self {
        Self {
            config: SchemaValidatorConfig::default(),
        }
    }

    /// Create validator with custom config
    pub fn with_config(config: SchemaValidatorConfig) -> Self {
        Self { config }
    }

    /// Validate academic credential metadata schema
    ///
    /// Returns ValidationResult::Invalid if metadata contains disallowed fields
    /// that could expose PII.
    pub fn validate_academic_credential(
        &self,
        credential: &AcademicCredential,
        block_height: BlockHeight,
    ) -> ValidationResult {
        // Backward compatibility: only validate credentials issued after activation
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        // Validate based on subcode
        match credential.subcode {
            DocSubcode::AcademicTranscript => {
                self.validate_transcript_metadata(&credential.metadata)
            }
            DocSubcode::Diploma => self.validate_diploma_metadata(&credential.metadata),
            DocSubcode::EnrollmentVerification => {
                self.validate_enrollment_metadata(&credential.metadata)
            }
            // Other academic subcodes (813+) - allow for now, can add validation later
            _ if credential.subcode.is_academic_class() => ValidationResult::Valid,
            // Non-academic subcodes - no validation in this module
            _ => ValidationResult::Valid,
        }
    }

    /// Every academic subcode, not only the three that have an allowlist.
    ///
    /// The gated counterpart of [`Self::validate_academic_credential`], reached
    /// only when `docclass_credential_schema_enabled_from_height` is open.
    /// ACTIVATION-AUDIT row D-19b: the ungated validator dispatches on
    /// `credential.subcode`, has arms for 810, 811 and 812, and returns `Valid`
    /// for every other academic subcode -- so an SRC-813 professional licence,
    /// an SRC-814 government id and an SRC-815 employment verification are
    /// admitted with a megabyte of free text in `metadata.title` and an
    /// arbitrary number of arbitrarily named attributes.
    ///
    /// What the uncovered subcodes get here is the checks that do NOT need an
    /// allowlist: the core field length bounds every covered subcode already
    /// applies, the per-attribute value cap, and a bound on the attribute NAME.
    /// An allowlist is a policy decision about which public attributes a
    /// credential type may carry, and inventing three of them in a remediation
    /// pass would be writing standard rather than closing a defect -- so the
    /// keys stay unrestricted for the subcodes whose standard does not list
    /// them, and that is recorded rather than hidden. The covered three are
    /// dispatched to their existing arms unchanged, so a credential valid below
    /// the gate under 810, 811 or 812 is valid above it.
    ///
    /// `payload_hint` is checked for every academic subcode, covered or not: it
    /// is free text in the payload, it is stored verbatim, and
    /// [`Self::validate_storage_hint`] is the check the Tax disclosure family
    /// already applies to exactly the same kind of field.
    pub fn validate_academic_credential_wide(
        &self,
        credential: &AcademicCredential,
        block_height: BlockHeight,
    ) -> ValidationResult {
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        if let Some(ref hint) = credential.payload_hint {
            if let Err(reason) = self.validate_storage_hint(hint, "payload_hint") {
                return ValidationResult::invalid(reason);
            }
        }

        match credential.subcode {
            DocSubcode::AcademicTranscript
            | DocSubcode::Diploma
            | DocSubcode::EnrollmentVerification => {
                self.validate_academic_credential(credential, block_height)
            }
            _ => {
                if let Err(reason) = self.validate_metadata_fields(&credential.metadata) {
                    return ValidationResult::invalid(reason);
                }
                for attr in &credential.metadata.attributes {
                    if attr.name.len() > MAX_CREDENTIAL_TYPE_LENGTH {
                        return ValidationResult::invalid(format!(
                            "Attribute name exceeds max length {} (got {})",
                            MAX_CREDENTIAL_TYPE_LENGTH,
                            attr.name.len()
                        ));
                    }
                    if attr.value.len() > MAX_ATTRIBUTE_VALUE_LENGTH {
                        return ValidationResult::invalid(format!(
                            "Attribute '{}' value exceeds max length {} (got {})",
                            attr.name,
                            MAX_ATTRIBUTE_VALUE_LENGTH,
                            attr.value.len()
                        ));
                    }
                }
                ValidationResult::Valid
            }
        }
    }

    /// SRC-807 eligibility attestations, which no path validates at any height.
    ///
    /// The other half of ACTIVATION-AUDIT row D-19b, and the half the row calls
    /// "nothing in SRC-80X": `issue_eligibility` has never called a validator
    /// at all, so the two free-text fields an attestation carries --
    /// `jurisdiction` and `payload_hint` -- reach storage unexamined, and
    /// `payload_hint` is the one a URL with `?name=` in it arrives through.
    ///
    /// Reached only when `docclass_credential_schema_enabled_from_height` is
    /// open. There is no metadata block on this family and therefore no
    /// allowlist to apply: the checks are the two free-text fields, and the
    /// jurisdiction bound is the one `MAX_INDEX_KEY_TEXT_BYTES` already imposes
    /// on the same field in Property and Legal, restated here as a length so
    /// this family's rule does not depend on a different subsystem's gate.
    pub fn validate_eligibility_attestation(
        &self,
        attestation: &EligibilityAttestation,
        block_height: BlockHeight,
    ) -> ValidationResult {
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        if attestation.jurisdiction.len() > MAX_DATE_LENGTH {
            return ValidationResult::invalid(format!(
                "jurisdiction exceeds max length {} (got {})",
                MAX_DATE_LENGTH,
                attestation.jurisdiction.len()
            ));
        }

        if let Some(ref hint) = attestation.payload_hint {
            if let Err(reason) = self.validate_storage_hint(hint, "payload_hint") {
                return ValidationResult::invalid(reason);
            }
        }

        ValidationResult::Valid
    }

    /// Validate transcript metadata (SRC-810)
    fn validate_transcript_metadata(&self, metadata: &CredentialMetadata) -> ValidationResult {
        // Check metadata field lengths
        if let Err(reason) = self.validate_metadata_fields(metadata) {
            return ValidationResult::invalid(reason);
        }

        // Validate attribute keys against allowlist
        self.validate_attribute_keys(&metadata.attributes, &Self::transcript_allowed_keys())
    }

    /// Validate diploma metadata (SRC-811)
    fn validate_diploma_metadata(&self, metadata: &CredentialMetadata) -> ValidationResult {
        // Check metadata field lengths
        if let Err(reason) = self.validate_metadata_fields(metadata) {
            return ValidationResult::invalid(reason);
        }

        // Validate attribute keys against allowlist
        self.validate_attribute_keys(&metadata.attributes, &Self::diploma_allowed_keys())
    }

    /// Validate enrollment metadata (SRC-812)
    fn validate_enrollment_metadata(&self, metadata: &CredentialMetadata) -> ValidationResult {
        // Check metadata field lengths
        if let Err(reason) = self.validate_metadata_fields(metadata) {
            return ValidationResult::invalid(reason);
        }

        // Validate attribute keys against allowlist
        self.validate_attribute_keys(&metadata.attributes, &Self::enrollment_allowed_keys())
    }

    /// Validate CredentialMetadata core fields
    ///
    /// Ensures fields don't contain excessive data that might be PII in disguise
    fn validate_metadata_fields(&self, metadata: &CredentialMetadata) -> Result<(), String> {
        // Title: reasonable length, describes credential type
        if metadata.title.len() > MAX_TITLE_LENGTH {
            return Err(format!(
                "metadata.title exceeds max length {} (got {})",
                MAX_TITLE_LENGTH,
                metadata.title.len()
            ));
        }

        // Credential type: short identifier
        if metadata.credential_type.len() > MAX_CREDENTIAL_TYPE_LENGTH {
            return Err(format!(
                "metadata.credential_type exceeds max length {} (got {})",
                MAX_CREDENTIAL_TYPE_LENGTH,
                metadata.credential_type.len()
            ));
        }

        // Program: field of study (optional, can be omitted for privacy)
        if let Some(ref program) = metadata.program {
            if program.len() > MAX_PROGRAM_LENGTH {
                return Err(format!(
                    "metadata.program exceeds max length {} (got {})",
                    MAX_PROGRAM_LENGTH,
                    program.len()
                ));
            }
        }

        // Issue date: ISO 8601 format (YYYY-MM-DD or YYYY-MM)
        if metadata.issue_date.len() > MAX_DATE_LENGTH {
            return Err(format!(
                "metadata.issue_date exceeds max length {} (got {})",
                MAX_DATE_LENGTH,
                metadata.issue_date.len()
            ));
        }

        // Completion date (optional)
        if let Some(ref date) = metadata.completion_date {
            if date.len() > MAX_DATE_LENGTH {
                return Err(format!(
                    "metadata.completion_date exceeds max length {} (got {})",
                    MAX_DATE_LENGTH,
                    date.len()
                ));
            }
        }

        Ok(())
    }

    /// Validate attribute keys against allowlist
    ///
    /// Returns Invalid if any attribute key is not in the allowlist
    fn validate_attribute_keys(
        &self,
        attributes: &[CredentialAttribute],
        allowed_keys: &HashSet<&'static str>,
    ) -> ValidationResult {
        for attr in attributes {
            if !allowed_keys.contains(attr.name.as_str()) {
                return ValidationResult::invalid(format!(
                    "Disallowed attribute key '{}'. Allowed keys: {}",
                    attr.name,
                    allowed_keys
                        .iter()
                        .map(|s| format!("'{}'", s))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            // Validate attribute value length
            if attr.value.len() > MAX_ATTRIBUTE_VALUE_LENGTH {
                return ValidationResult::invalid(format!(
                    "Attribute '{}' value exceeds max length {} (got {})",
                    attr.name,
                    MAX_ATTRIBUTE_VALUE_LENGTH,
                    attr.value.len()
                ));
            }
        }

        ValidationResult::Valid
    }

    /// Allowed attribute keys for SRC-810 (Academic Transcript)
    ///
    /// These are NON-PII metadata fields safe for public on-chain storage.
    ///
    /// REMOVED: issuer_signature (use chain tx signature instead)
    /// REMOVED: verification_url (centralization/tracking vector)
    /// REMOVED: json_cid/json_hash (payload_hint is canonical)
    /// REMOVED: gpa_bracket/credit_range (can de-anonymize small cohorts)
    fn transcript_allowed_keys() -> HashSet<&'static str> {
        [
            // PDF artifact (optional, human-readable only)
            "pdf_cid",         // IPFS CID of rendered PDF
            "pdf_hash",        // BLAKE3 hash of PDF for integrity
            "pdf_format",      // MIME type: "application/pdf"
            "rendered_at",     // Timestamp when PDF was generated
            // Credential environment/context
            "environment",     // "production" / "staging"
            "version",         // Schema version: "1.0"
            "credential_subtype", // More specific type: "partial_transcript", "final_transcript"
            // Academic period references (non-PII)
            "academic_year",   // "2024-2025"
            "semester",        // "Fall", "Spring", "Summer"
            "term_count",      // Number of terms: "8"
            // Institutional metadata
            "issuer_department", // "Office of the Registrar"
            "signature_method", // "Ed25519", "multisig"
            // Commitments (BLAKE3 with domain separation - see canonicalization spec)
            // Format: "blake3:<hex>" or "0x<hex>"
            // Domain: "SRC-810-COURSES-v1", "SRC-810-GRADES-v1", etc.
            "courses_commitment", // BLAKE3(domain || canonical_json(courses))
            "grades_commitment",  // BLAKE3(domain || canonical_json(grades))
            "student_commitment", // BLAKE3(domain || canonical_json(student_data))
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Allowed attribute keys for SRC-811 (Diploma/Degree)
    ///
    /// REMOVED: verification_url (centralization/tracking vector)
    /// REMOVED: json_cid/json_hash (payload_hint is canonical)
    fn diploma_allowed_keys() -> HashSet<&'static str> {
        [
            // PDF artifact (optional, human-readable only)
            "pdf_cid",
            "pdf_hash",
            "pdf_format",
            "rendered_at",
            // Credential environment
            "environment",
            "version",
            "credential_subtype", // "bachelor", "master", "doctoral", "certificate"
            // Degree context (non-PII)
            "graduation_year",    // "2025"
            "graduation_semester", // "Spring"
            "degree_level",       // "undergraduate", "graduate", "doctoral"
            "honors_category",    // "latin_honors", "departmental_honors" (NOT specific honors)
            // Institutional metadata
            "issuer_department",
            "signature_method",
            "conferral_ceremony_date", // Public event date
            "diploma_number", // Public diploma serial number (if institution uses non-PII serials)
            // Commitments (BLAKE3 with domain separation)
            "degree_commitment",
            "major_commitment",
            "minor_commitment",
            "honors_commitment",
            "student_commitment",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Allowed attribute keys for SRC-812 (Enrollment Verification)
    ///
    /// REMOVED: verification_url (centralization/tracking vector)
    /// REMOVED: json_cid/json_hash (payload_hint is canonical)
    fn enrollment_allowed_keys() -> HashSet<&'static str> {
        [
            // PDF artifact (optional, human-readable only)
            "pdf_cid",
            "pdf_hash",
            "pdf_format",
            "rendered_at",
            // Credential environment
            "environment",
            "version",
            // Enrollment context (non-PII)
            "enrollment_year",   // "2025"
            "enrollment_semester", // "Fall"
            "enrollment_status", // "full_time", "part_time", "leave_of_absence"
            "program_level",     // "undergraduate", "graduate"
            "expected_graduation_year", // "2029" (year only, not exact date)
            // Institutional metadata
            "issuer_department",
            "signature_method",
            // Commitments (BLAKE3 with domain separation)
            "enrollment_commitment",
            "program_commitment",
            "student_commitment",
        ]
        .iter()
        .copied()
        .collect()
    }

    // =========================================================================
    // SRC-88X: Employment Validation
    // =========================================================================

    /// Validate SRC-882 employment credential
    ///
    /// Employment credentials have fixed struct fields (no flexible attributes),
    /// but we validate free-form String fields to ensure they don't contain PII.
    pub fn validate_employment_credential(
        &self,
        credential: &EmploymentCredential,
        block_height: BlockHeight,
    ) -> ValidationResult {
        // Backward compatibility check
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        // Validate issuer_name (should be institutional, NOT personal name)
        if let Err(reason) = self.validate_institutional_name(&credential.issuer_name, "issuer_name") {
            return ValidationResult::invalid(reason);
        }

        // Note: employee_ref, employer_ref, tenure_commitment, role_commitment are
        // all commitments (hashes), so they are privacy-preserving by design.
        // employment_type is an enum, so it's safe.
        // The only free-form field is issuer_name, which we validated above.

        ValidationResult::Valid
    }

    // =========================================================================
    // SRC-87X: Healthcare Validation
    // =========================================================================

    /// Validate SRC-871 healthcare membership record
    ///
    /// Healthcare tokens have fixed struct fields with commitments for sensitive data.
    /// We validate that no PII leaks through any free-form fields (though most are fixed types).
    pub fn validate_healthcare_membership(
        &self,
        _membership: &MembershipRecord,
        block_height: BlockHeight,
    ) -> ValidationResult {
        // Backward compatibility check
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        // MembershipRecord has no free-form String fields that could contain PII:
        // - membership_id: [u8; 32] (hash)
        // - member_address: Address (pseudonymous)
        // - provider_id: [u8; 32] (hash)
        // - membership_type: enum (safe)
        // - membership_commitment: [u8; 32] (hash)
        // - member_ref: PartyRef (commitment)
        // - member_nullifier: [u8; 32] (hash)
        // - All other fields are timestamps, addresses, or commitments

        // Healthcare tokens are privacy-safe by design due to commitment-based architecture
        ValidationResult::Valid
    }

    // =========================================================================
    // SRC-82X: Tax Validation
    // =========================================================================

    /// Validate SRC-825 tax disclosure envelope
    ///
    /// Tax disclosures store encrypted payloads with only hashes on-chain.
    /// Validate hint_uri to ensure it doesn't leak PII.
    pub fn validate_tax_disclosure(
        &self,
        envelope: &TaxDisclosureEnvelope,
        block_height: BlockHeight,
    ) -> ValidationResult {
        // Backward compatibility check
        if !self.config.enabled || block_height < self.config.activation_height {
            return ValidationResult::Valid;
        }

        // Validate hint_uri if present (should be IPFS CID or generic URL, no PII)
        if let Some(ref hint_uri) = envelope.hint_uri {
            if let Err(reason) = self.validate_storage_hint(hint_uri, "hint_uri") {
                return ValidationResult::invalid(reason);
            }
        }

        // All other fields are hashes, enums, or timestamps (privacy-safe)
        ValidationResult::Valid
    }

    // =========================================================================
    // Helper Validation Methods
    // =========================================================================

    /// Validate institutional name (employer, issuer, etc.)
    ///
    /// Must be institutional/company name, NOT personal names.
    /// We don't use heuristics - just check length and basic format.
    pub fn validate_institutional_name(&self, name: &str, field_name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err(format!("{} cannot be empty", field_name));
        }

        if name.len() > MAX_NAME_LENGTH {
            return Err(format!(
                "{} too long (max {} bytes, got {})",
                field_name,
                MAX_NAME_LENGTH,
                name.len()
            ));
        }

        // Check for obvious PII patterns (email addresses)
        if name.contains('@') && name.contains('.') {
            return Err(format!(
                "{} appears to be an email address (not allowed)",
                field_name
            ));
        }

        // Check for phone number patterns (simple check)
        let digit_count = name.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count >= 10 {
            return Err(format!(
                "{} contains too many digits (possible phone number)",
                field_name
            ));
        }

        Ok(())
    }

    /// Validate storage hint (IPFS CID, URL, etc.)
    ///
    /// Must be a generic storage reference, not contain PII.
    pub fn validate_storage_hint(&self, hint: &str, field_name: &str) -> Result<(), String> {
        if hint.len() > MAX_HINT_LENGTH {
            return Err(format!(
                "{} too long (max {} bytes, got {})",
                field_name,
                MAX_HINT_LENGTH,
                hint.len()
            ));
        }

        // Check for obvious PII in URL parameters
        let hint_lower = hint.to_lowercase();
        let pii_patterns = ["name=", "email=", "ssn=", "phone=", "dob="];

        for pattern in &pii_patterns {
            if hint_lower.contains(pattern) {
                return Err(format!(
                    "{} contains suspicious PII pattern: {}",
                    field_name, pattern
                ));
            }
        }

        Ok(())
    }

    /// Get list of explicitly DISALLOWED keys that represent PII
    ///
    /// These keys should NEVER appear in metadata.attributes.
    /// This is a documentation/reference list - actual enforcement is via allowlist.
    #[allow(dead_code)]
    fn disallowed_keys() -> HashSet<&'static str> {
        [
            // Personal identifiers
            "student_name",
            "student_first_name",
            "student_last_name",
            "student_middle_name",
            "name",
            "full_name",
            "legal_name",
            "preferred_name",
            "student_id",
            "student_number",
            "id_number",
            "ssn",
            "social_security_number",
            "national_id",
            "passport_number",
            "drivers_license",
            // Contact information
            "email",
            "email_address",
            "phone",
            "phone_number",
            "mobile",
            "address",
            "street_address",
            "city",
            "state",
            "zip",
            "postal_code",
            "country",
            // Academic details (PII when detailed)
            "courses", // Array of course objects with grades
            "course_list",
            "grades",
            "grade_list",
            // Exact GPA. `gpa_bracket` is NOT the alternative any more -- it was
            // removed from the allowlist as a de-anonymization vector. Carry
            // grade information as `grades_commitment`.
            "gpa",
            "exact_gpa",
            "cumulative_gpa",
            "term_gpa",
            // Exact credit count. `credit_range` was removed from the allowlist
            // for the same reason as `gpa_bracket`.
            "credits",
            "exact_credits",
            "total_credits",
            "instructor_name",
            "instructor",
            "professor",
            "advisor",
            "advisor_name",
            "department_chair",
            // Birth/demographic data
            "date_of_birth",
            "birth_date",
            "dob",
            "age",
            "gender",
            "ethnicity",
            "race",
            "nationality",
            "citizenship",
            // Financial/employment
            "tuition",
            "financial_aid",
            "scholarship",
            "employer",
            "salary",
            // Detailed records
            "transcript", // Full transcript data
            "transcript_data",
            "grade_report",
            "course_history",
            "attendance_record",
            "disciplinary_record",
            "medical_record",
            "disability_status",
            // Exact honors (use commitments instead)
            "honors", // e.g., "Summa Cum Laude" - use honors_commitment
            "honors_level",
            "latin_honors",
            "dean_list",
            // Other identifiers
            "username",
            "login",
            "password",
            "parent_name",
            "guardian_name",
            "emergency_contact",
        ]
        .iter()
        .copied()
        .collect()
    }
}

impl Default for SchemaValidator {
    fn default() -> Self {
        Self::new()
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use sumchain_primitives::DocSubcode;

    /// A validator that actually enforces at the heights these tests use.
    ///
    /// Every test routed through this asserts about credentials at block height
    /// 100. `SchemaValidator::new()` carries the SHIPPED activation height
    /// (385_000), so a validator built that way returns `Valid` for everything
    /// at height 100 without looking at the credential — which made the "should
    /// be rejected" tests fail and, worse, made the "should be accepted" tests
    /// pass without validating anything. Pin the activation height at 0 so the
    /// assertions are about the schema rules and not about the height.
    ///
    /// Fourteen of the sixteen tests in this module route through this. The
    /// other two — `test_backward_compatibility_before_activation` and
    /// `test_disabled_validator` — build their own config on purpose, because
    /// the height and the `enabled` flag are their respective subjects.
    ///
    /// Pinning the height is NECESSARY AND NOT SUFFICIENT: a validator that
    /// returned `Valid` unconditionally would still satisfy every "should be
    /// accepted" assertion, which is how these went unnoticed. So each test
    /// below also carries an input that must produce the OPPOSITE verdict.
    fn enforcing_validator() -> SchemaValidator {
        SchemaValidator::with_config(SchemaValidatorConfig {
            activation_height: 0,
            enabled: true,
        })
    }

    fn make_test_credential(
        subcode: DocSubcode,
        metadata: CredentialMetadata,
    ) -> AcademicCredential {
        AcademicCredential {
            credential_id: [0u8; 32],
            subject_address: sumchain_primitives::Address::new([1u8; 20]),
            subcode,
            subject_commitment: [0u8; 32],
            issuer: sumchain_primitives::Address::new([2u8; 20]),
            institution_id: "TEST_INST".to_string(),
            jurisdiction: "US".to_string(),
            schema_hash: [0u8; 32],
            content_commitment: [0u8; 32],
            metadata,
            issued_at: 1000,
            valid_from: 1000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            encryption_meta: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: sumchain_primitives::RevocationStatus::Active,
            superseded_by: None,
        }
    }

    /// Assert that `result` is a REJECTION whose reason names `needle`.
    ///
    /// `!is_valid()` on its own cannot tell "refused by the rule this test
    /// names" from "refused by some other rule the fixture happens to trip",
    /// and the reason string is what a node operator reads when a credential
    /// is refused, so every rejection below is pinned to its reason.
    fn assert_rejected_for(result: &ValidationResult, needle: &str, context: &str) {
        match result {
            ValidationResult::Invalid { reason } => assert!(
                reason.contains(needle),
                "{}: rejected, but the reason does not name `{}`: {}",
                context,
                needle,
                reason
            ),
            ValidationResult::Valid => panic!(
                "{}: expected a rejection naming `{}`, got Valid",
                context, needle
            ),
        }
    }

    /// An SRC-882 employment credential differing only in `issuer_name`.
    ///
    /// `issuer_name` is the ONLY free-form field
    /// `validate_employment_credential` reads -- every other field is a
    /// commitment, an address, an enum or a timestamp -- so holding the rest
    /// fixed is what makes an accept/reject pair in one test a controlled
    /// comparison rather than two unrelated fixtures.
    fn employment_credential(issuer_name: &str) -> EmploymentCredential {
        use sumchain_primitives::employment::{
            EmploymentIssuerClass, EmploymentStatus, EmploymentType,
        };

        EmploymentCredential {
            employment_id: [1u8; 32],
            employee_address: sumchain_primitives::Address::new([1u8; 20]),
            employee_ref: [2u8; 32],
            employer_ref: [3u8; 32],
            status: EmploymentStatus::Active,
            tenure_commitment: [4u8; 32],
            role_commitment: Some([5u8; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: 1000,
            expiry: 0,
            policy_id: [6u8; 32],
            revocation_ref: None,
            issuer_address: sumchain_primitives::Address::new([7u8; 20]),
            issuer_name: issuer_name.to_string(),
            issuer_class: EmploymentIssuerClass::Employer,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    /// An SRC-825 tax disclosure envelope differing only in `hint_uri`.
    ///
    /// `hint_uri` is the only field `validate_tax_disclosure` reads; the rest
    /// are hashes, enums and timestamps.
    fn tax_envelope(hint_uri: Option<&str>) -> TaxDisclosureEnvelope {
        use sumchain_primitives::tax::DisclosureContentType;

        TaxDisclosureEnvelope {
            payload_hash: [1u8; 32],
            payload_size: 1024,
            hint_uri: hint_uri.map(|h| h.to_string()),
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: Some([2u8; 32]),
            proof_id: None,
            created_at: 1000,
        }
    }

    /// GUARANTEE: above the activation height a transcript carrying NO
    /// attributes is accepted, so the allowlist never refuses the smallest
    /// credential a registrar can issue -- and that acceptance is the allowlist
    /// consulting an empty list, not the allowlist being skipped.
    #[test]
    fn test_valid_transcript_minimal() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(result.is_valid(), "Minimal transcript should be valid");

        // POSITIVE CONTROL. `Valid` above is evidence only if the same
        // validator, on the same fixture, can still say `Invalid`. One key
        // that is not on the transcript allowlist -- carrying no PII at all,
        // because the allowlist denies by default -- must flip the verdict.
        let mut unlisted = credential.clone();
        unlisted.metadata.attributes.push(CredentialAttribute {
            name: "registrar_note".to_string(),
            value: "none".to_string(),
        });
        assert_rejected_for(
            &validator.validate_academic_credential(&unlisted, 100),
            "'registrar_note'",
            "one unlisted key added to the minimal transcript",
        );
    }

    /// GUARANTEE: the transcript keys on `transcript_allowed_keys` are accepted
    /// above the activation height, and `gpa_bracket` -- struck from that
    /// allowlist because a bracket can de-anonymize a small cohort -- is not
    /// quietly back on it.
    #[test]
    fn test_valid_transcript_with_allowed_attributes() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: Some("Computer Science".to_string()),
            issue_date: "2025-05-15".to_string(),
            completion_date: Some("2025-05-15".to_string()),
            attributes: vec![
                CredentialAttribute {
                    name: "pdf_cid".to_string(),
                    value: "QmYwAPJzv5CZsnA636s8...".to_string(),
                },
                CredentialAttribute {
                    name: "pdf_hash".to_string(),
                    value: "0xblake3hash...".to_string(),
                },
                CredentialAttribute {
                    name: "environment".to_string(),
                    value: "production".to_string(),
                },
                // NOT `gpa_bracket`: that key was removed from the transcript
                // allowlist because a bracket can de-anonymize a small cohort.
                // The allowlisted way to carry grade information is a
                // domain-separated commitment.
                CredentialAttribute {
                    name: "grades_commitment".to_string(),
                    value: format!("blake3:{}", "0".repeat(64)),
                },
            ],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            result.is_valid(),
            "Transcript with allowed attributes should be valid"
        );

        // POSITIVE CONTROL: the removed key, in the slot the commitment
        // occupies, on an otherwise identical credential. If this is accepted
        // the allowlist has been widened back to a de-anonymization vector.
        let mut bracketed = credential.clone();
        bracketed.metadata.attributes[3] = CredentialAttribute {
            name: "gpa_bracket".to_string(),
            value: "3.5-4.0".to_string(),
        };
        assert_rejected_for(
            &validator.validate_academic_credential(&bracketed, 100),
            "'gpa_bracket'",
            "the removed gpa_bracket key on an otherwise valid transcript",
        );
    }

    /// GUARANTEE: a transcript carrying a `student_name` attribute is refused
    /// above the activation height, so a plaintext student name cannot reach
    /// chain state through SRC-810 metadata -- and it is the KEY that refuses
    /// it, not the fixture: the same value under `student_commitment` passes.
    #[test]
    fn test_invalid_transcript_with_student_name() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "student_name".to_string(), // <- DISALLOWED PII
                value: "John Doe".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with student_name should be rejected"
        );
        assert_rejected_for(
            &result,
            "student_name",
            "a transcript carrying a plaintext student name",
        );

        // POSITIVE CONTROL: same credential, same value, allowlisted key.
        let mut committed = credential.clone();
        committed.metadata.attributes[0].name = "student_commitment".to_string();
        assert!(
            validator
                .validate_academic_credential(&committed, 100)
                .is_valid(),
            "the same value under the allowlisted student_commitment key must pass, \
             or the rejection above is not about the key"
        );
    }

    /// GUARANTEE: a transcript carrying an exact `gpa` is refused above the
    /// activation height, while the allowlisted `grades_commitment` carrying
    /// the same bytes is accepted -- grade information reaches the chain only
    /// as a commitment.
    #[test]
    fn test_invalid_transcript_with_exact_gpa() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "gpa".to_string(), // <- DISALLOWED (carry grades_commitment instead)
                value: "3.85".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with exact GPA should be rejected"
        );
        assert_rejected_for(&result, "'gpa'", "a transcript carrying an exact GPA");

        // POSITIVE CONTROL: the allowlisted commitment form of the same fact.
        let mut committed = credential.clone();
        committed.metadata.attributes[0].name = "grades_commitment".to_string();
        assert!(
            validator
                .validate_academic_credential(&committed, 100)
                .is_valid(),
            "grades_commitment is the allowlisted way to carry grade information"
        );
    }

    /// GUARANTEE: a transcript carrying a detailed `courses` list is refused
    /// above the activation height, while `courses_commitment` is accepted --
    /// per-course records stay off chain.
    #[test]
    fn test_invalid_transcript_with_courses() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "courses".to_string(), // <- DISALLOWED (detailed course list)
                value: "[{\"code\": \"CS101\", \"grade\": \"A\"}]".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with detailed courses should be rejected"
        );
        assert_rejected_for(&result, "'courses'", "a transcript carrying a course list");

        // POSITIVE CONTROL: the allowlisted commitment form of the same fact.
        let mut committed = credential.clone();
        committed.metadata.attributes[0].name = "courses_commitment".to_string();
        assert!(
            validator
                .validate_academic_credential(&committed, 100)
                .is_valid(),
            "courses_commitment is the allowlisted way to carry course information"
        );
    }

    /// GUARANTEE: the activation height is a strict `<` boundary. A credential
    /// the allowlist would refuse is accepted at EVERY height below
    /// `activation_height` and refused from that height on, so credentials
    /// already on chain when the rule ships stay valid and the first block that
    /// enforces it is exactly `activation_height` -- not one before, not one
    /// after.
    ///
    /// This test builds its own validator on purpose and is deliberately NOT
    /// routed through `enforcing_validator`: the height is its subject.
    #[test]
    fn test_backward_compatibility_before_activation() {
        let config = SchemaValidatorConfig {
            activation_height: 1000,
            enabled: true,
        };
        let validator = SchemaValidator::with_config(config);

        // Credential with PII (would normally be rejected)
        let metadata = CredentialMetadata {
            title: "Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "student_name".to_string(),
                value: "Old Credential".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        // At block 500 (before activation), should pass
        let result = validator.validate_academic_credential(&credential, 500);
        assert!(
            result.is_valid(),
            "Should pass before activation height (backward compatibility)"
        );

        // The block immediately before activation is still unenforced. `<` and
        // `<=` differ by exactly this block, and they are a consensus fork
        // apart.
        assert!(
            validator
                .validate_academic_credential(&credential, 999)
                .is_valid(),
            "height 999 is below activation 1000 and must not be enforced"
        );

        // At block 1000+ (after activation), should fail
        let result = validator.validate_academic_credential(&credential, 1000);
        assert!(!result.is_valid(), "Should fail after activation height");
        assert_rejected_for(
            &result,
            "student_name",
            "the activation block itself enforces the allowlist",
        );
        assert!(
            !validator
                .validate_academic_credential(&credential, 1001)
                .is_valid(),
            "enforcement does not stop after the activation block"
        );
    }

    /// GUARANTEE: the SRC-811 diploma allowlist accepts its own keys above the
    /// activation height, and the allowlists are PER SUBCODE -- a key that is
    /// allowed on a transcript is not thereby allowed on a diploma.
    #[test]
    fn test_diploma_with_allowed_keys() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Doctor of Philosophy".to_string(),
            credential_type: "doctoral_degree".to_string(),
            program: None, // Program can be omitted for privacy
            issue_date: "2025-12-20".to_string(),
            completion_date: Some("2025-12-20".to_string()),
            attributes: vec![
                CredentialAttribute {
                    name: "pdf_cid".to_string(),
                    value: "QmDiplomaPDF...".to_string(),
                },
                CredentialAttribute {
                    name: "degree_level".to_string(),
                    value: "doctoral".to_string(),
                },
                CredentialAttribute {
                    name: "graduation_year".to_string(),
                    value: "2025".to_string(),
                },
            ],
        };

        let credential = make_test_credential(DocSubcode::Diploma, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(result.is_valid(), "Diploma with allowed keys should be valid");

        // POSITIVE CONTROL: `semester` is on the SRC-810 transcript allowlist
        // and NOT on the SRC-811 diploma one. If a diploma accepts it, the
        // validator is consulting one shared list, or none.
        let mut cross_subcode = credential.clone();
        cross_subcode.metadata.attributes.push(CredentialAttribute {
            name: "semester".to_string(),
            value: "Spring".to_string(),
        });
        assert_rejected_for(
            &validator.validate_academic_credential(&cross_subcode, 100),
            "'semester'",
            "a transcript-only key on a diploma",
        );
    }

    /// GUARANTEE: `metadata.title` is capped at `MAX_TITLE_LENGTH` bytes above
    /// the activation height, and the cap is inclusive -- a title of exactly
    /// `MAX_TITLE_LENGTH` is accepted and one byte more is refused. The cap is
    /// consensus-visible, so its exact boundary decides whether two binaries
    /// write the same state.
    #[test]
    fn test_excessive_title_length() {
        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "A".repeat(MAX_TITLE_LENGTH + 1),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Excessive title length should be rejected"
        );
        assert_rejected_for(&result, "metadata.title", "a title one byte over the cap");

        // POSITIVE CONTROL: exactly at the cap, which must be accepted -- a
        // validator that refused every long title, or refused everything,
        // would fail here.
        let mut at_cap = credential.clone();
        at_cap.metadata.title = "A".repeat(MAX_TITLE_LENGTH);
        assert!(
            validator
                .validate_academic_credential(&at_cap, 100)
                .is_valid(),
            "a title of exactly MAX_TITLE_LENGTH ({}) is within the cap",
            MAX_TITLE_LENGTH
        );
    }

    /// GUARANTEE: `enabled: false` suspends enforcement at every height, and it
    /// is the FLAG that suspends it -- the same credential, at the same height,
    /// under the same activation height, is refused with `enabled: true`. The
    /// flag is an operator-facing kill switch, so "disabled accepts everything"
    /// is only meaningful alongside "enabled does not".
    ///
    /// This test builds its own validator on purpose and is deliberately NOT
    /// routed through `enforcing_validator`: the flag is its subject.
    #[test]
    fn test_disabled_validator() {
        let config = SchemaValidatorConfig {
            activation_height: 0,
            enabled: false, // Disabled
        };
        let validator = SchemaValidator::with_config(config);

        // Even with PII, should pass when disabled
        let metadata = CredentialMetadata {
            title: "Test".to_string(),
            credential_type: "test".to_string(),
            program: None,
            issue_date: "2025".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "student_name".to_string(),
                value: "Test User".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(result.is_valid(), "Should pass when validator is disabled");

        // POSITIVE CONTROL: the same config with the flag flipped, and nothing
        // else changed.
        let enabled = SchemaValidator::with_config(SchemaValidatorConfig {
            activation_height: 0,
            enabled: true,
        });
        assert_rejected_for(
            &enabled.validate_academic_credential(&credential, 100),
            "student_name",
            "the same credential with enabled: true",
        );
    }

    /// GUARANTEE: encryption metadata and an encrypted payload hint are
    /// themselves accepted above the activation height -- and they are NOT an
    /// exemption: an encrypted credential still has its attribute keys checked
    /// against the allowlist, because the attributes are stored in the clear
    /// whatever the payload does.
    #[test]
    fn test_valid_encrypted_credential() {
        use sumchain_primitives::agreement::{EncryptionAlgorithm, EncryptionMeta};

        let validator = enforcing_validator();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![
                CredentialAttribute {
                    name: "pdf_cid".to_string(),
                    value: "bafybeig...".to_string(),
                },
                CredentialAttribute {
                    name: "courses_commitment".to_string(),
                    value: "blake3:a7f2c9...".to_string(),
                },
            ],
        };

        let mut credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        // Add encryption metadata
        credential.encryption_meta = Some(EncryptionMeta {
            algorithm: EncryptionAlgorithm::X25519Aes256Gcm,
            key_commitment: Some([1u8; 32]),
            nonce: Some(vec![2u8; 12]),
        });
        credential.payload_hint = Some("bafybeig...encrypted".to_string());

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(result.is_valid(), "Valid encrypted credential should pass");

        // POSITIVE CONTROL: the same encrypted credential with one PII key in
        // its cleartext attributes. Encrypting the payload must not buy an
        // exemption from the allowlist.
        let mut with_pii = credential.clone();
        with_pii.metadata.attributes.push(CredentialAttribute {
            name: "student_name".to_string(),
            value: "John Doe".to_string(),
        });
        assert_rejected_for(
            &validator.validate_academic_credential(&with_pii, 100),
            "student_name",
            "an encrypted credential with a cleartext PII attribute",
        );
    }

    // =========================================================================
    // SRC-88X Employment Tests
    // =========================================================================

    /// GUARANTEE: an SRC-882 credential whose `issuer_name` is an institutional
    /// name is accepted above the activation height, and an EMPTY `issuer_name`
    /// is not -- the field is required, so an issuer cannot erase its own
    /// identity from the credential it signs.
    #[test]
    fn test_valid_employment_credential() {
        let validator = enforcing_validator();

        let credential = employment_credential("SUM INNOVATION INC");

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(result.is_valid(), "Valid employment credential should pass");

        // POSITIVE CONTROL: the only free-form field, emptied.
        assert_rejected_for(
            &validator.validate_employment_credential(&employment_credential(""), 100),
            "issuer_name",
            "an employment credential with an empty issuer_name",
        );
    }

    /// GUARANTEE: an `issuer_name` that is an email address -- containing both
    /// `@` and `.` -- is refused above the activation height, so a personal
    /// mailbox cannot be written to chain as an employer's name. The rule is
    /// exactly that conjunction: the control pins `hr@company`, with no dot, as
    /// accepted, so a future tightening has to update this test rather than
    /// pass it by accident.
    #[test]
    fn test_invalid_employment_with_email() {
        let validator = enforcing_validator();

        let credential = employment_credential("hr@company.com"); // Invalid: email address

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Employment with email in issuer_name should be rejected"
        );
        assert_rejected_for(
            &result,
            "email address",
            "an employment credential naming a mailbox as its issuer",
        );

        // POSITIVE CONTROL: `@` without `.` is not what the rule matches.
        assert!(
            validator
                .validate_employment_credential(&employment_credential("hr@company"), 100)
                .is_valid(),
            "the email rule is `@` AND `.`; a name with no dot is outside it"
        );
    }

    /// GUARANTEE: an `issuer_name` containing ten or more digits is refused
    /// above the activation height as a possible phone number, and the
    /// threshold is exactly ten -- nine digits is accepted. A digit count is a
    /// consensus decision here, so its boundary has to be pinned in both
    /// directions.
    #[test]
    fn test_invalid_employment_with_phone() {
        let validator = enforcing_validator();

        // Eleven ASCII digits.
        let credential = employment_credential("1-800-555-1234");

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Employment with phone number in issuer_name should be rejected"
        );
        assert_rejected_for(
            &result,
            "phone number",
            "an employment credential naming a phone number as its issuer",
        );

        // POSITIVE CONTROL: nine ASCII digits, one below the threshold.
        let nine_digits = "1-800-555-12";
        assert_eq!(
            nine_digits.chars().filter(|c| c.is_ascii_digit()).count(),
            9,
            "the control has to sit one digit below the threshold to pin it"
        );
        assert!(
            validator
                .validate_employment_credential(&employment_credential(nine_digits), 100)
                .is_valid(),
            "nine digits is below the ten-digit phone-number threshold"
        );
    }

    // =========================================================================
    // SRC-82X Tax Tests
    // =========================================================================

    /// GUARANTEE: an SRC-825 envelope whose `hint_uri` is a bare storage
    /// reference is accepted above the activation height, an envelope with no
    /// hint at all is accepted, and the `MAX_HINT_LENGTH` cap is live -- a hint
    /// one byte over it is refused.
    #[test]
    fn test_valid_tax_disclosure() {
        let validator = enforcing_validator();

        let envelope = tax_envelope(Some("ipfs://bafybeig...")); // Valid IPFS CID

        let result = validator.validate_tax_disclosure(&envelope, 100);
        assert!(result.is_valid(), "Valid tax disclosure should pass");

        assert!(
            validator
                .validate_tax_disclosure(&tax_envelope(None), 100)
                .is_valid(),
            "an envelope with no hint has nothing to validate"
        );

        // POSITIVE CONTROL: one byte over the hint cap.
        let over_cap = format!("ipfs://{}", "a".repeat(MAX_HINT_LENGTH + 1 - 7));
        assert_eq!(over_cap.len(), MAX_HINT_LENGTH + 1);
        assert_rejected_for(
            &validator.validate_tax_disclosure(&tax_envelope(Some(&over_cap)), 100),
            "hint_uri",
            "a hint_uri one byte over MAX_HINT_LENGTH",
        );
    }

    /// GUARANTEE: an SRC-825 `hint_uri` carrying a PII query parameter is
    /// refused above the activation height, so a tax disclosure cannot point at
    /// a URL that names the taxpayer -- and it is the PARAMETER that refuses
    /// it: the same host and path without the query is accepted.
    #[test]
    fn test_invalid_tax_disclosure_with_pii_in_uri() {
        let validator = enforcing_validator();

        // Invalid: PII in URL
        let envelope = tax_envelope(Some("https://example.com/tax?name=John&ssn=123-45-6789"));

        let result = validator.validate_tax_disclosure(&envelope, 100);
        assert!(
            !result.is_valid(),
            "Tax disclosure with PII in URL should be rejected"
        );
        assert_rejected_for(
            &result,
            "name=",
            "a hint_uri whose query names the taxpayer",
        );

        // POSITIVE CONTROL: same host and path, query removed.
        assert!(
            validator
                .validate_tax_disclosure(&tax_envelope(Some("https://example.com/tax")), 100)
                .is_valid(),
            "the same URL without the PII query must pass, or the rejection \
             above is not about the query"
        );
    }

    // =========================================================================
    // SRC-87X Healthcare Tests
    // =========================================================================

    /// GUARANTEE: SRC-871 membership records are accepted UNCONDITIONALLY above
    /// the activation height. That is a deliberate absence of rules, not a rule
    /// that passes: `validate_healthcare_membership` ignores its argument
    /// entirely because every field of a `MembershipRecord` is a hash, an
    /// address, an enum or a timestamp, with no free-form string to carry PII.
    /// If a rejection path is ever added to this surface, this test fails and
    /// whoever adds it has to record it here.
    ///
    /// Because the subject accepts everything by construction, no input to it
    /// can produce the opposite verdict. The positive control is therefore the
    /// SAME validator instance refusing an academic credential inside this
    /// test: without it, this test would pass against a validator that returned
    /// `Valid` for everything -- which is exactly the defect that made this
    /// module's tests vacuous.
    #[test]
    fn test_valid_healthcare_membership() {
        use sumchain_primitives::agreement::PartyRef;
        use sumchain_primitives::healthcare::{
            CoverageTier, HealthcareIssuerClass, MembershipRecord, MembershipStatus, MembershipType,
        };

        let validator = enforcing_validator();

        let membership = MembershipRecord {
            membership_id: [1u8; 32],
            member_address: sumchain_primitives::Address::new([1u8; 20]),
            provider_id: [2u8; 32],
            membership_type: MembershipType::IndividualHealth,
            membership_commitment: [3u8; 32],
            member_ref: PartyRef::Commitment([4u8; 32]),
            member_nullifier: [5u8; 32],
            coverage_tier: Some(CoverageTier::Individual),
            group_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: sumchain_primitives::Address::new([6u8; 20]),
            issuer_class: HealthcareIssuerClass::InsuranceCompany,
            policy_id: [7u8; 32],
            revocation_ref: None,
            status: MembershipStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            prior_membership_id: None,
            dependents: vec![],
            attachments: vec![],
        };

        let result = validator.validate_healthcare_membership(&membership, 100);
        assert!(
            result.is_valid(),
            "Valid healthcare membership should pass (privacy-safe by design)"
        );

        // POSITIVE CONTROL: this validator is enforcing, so the acceptance
        // above is the healthcare surface having no rules rather than the
        // validator having no teeth.
        let pii = make_test_credential(
            DocSubcode::AcademicTranscript,
            CredentialMetadata {
                title: "Academic Transcript".to_string(),
                credential_type: "transcript".to_string(),
                program: None,
                issue_date: "2025-05".to_string(),
                completion_date: None,
                attributes: vec![CredentialAttribute {
                    name: "student_name".to_string(),
                    value: "John Doe".to_string(),
                }],
            },
        );
        assert_rejected_for(
            &validator.validate_academic_credential(&pii, 100),
            "student_name",
            "the same validator instance on an academic credential",
        );
    }
}
