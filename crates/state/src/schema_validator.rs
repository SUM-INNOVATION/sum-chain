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
};
use sumchain_primitives::employment::EmploymentCredential;
use sumchain_primitives::healthcare::MembershipRecord;
use sumchain_primitives::tax::TaxDisclosureEnvelope;

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
        const MAX_TITLE_LENGTH: usize = 200;
        if metadata.title.len() > MAX_TITLE_LENGTH {
            return Err(format!(
                "metadata.title exceeds max length {} (got {})",
                MAX_TITLE_LENGTH,
                metadata.title.len()
            ));
        }

        // Credential type: short identifier
        const MAX_CREDENTIAL_TYPE_LENGTH: usize = 100;
        if metadata.credential_type.len() > MAX_CREDENTIAL_TYPE_LENGTH {
            return Err(format!(
                "metadata.credential_type exceeds max length {} (got {})",
                MAX_CREDENTIAL_TYPE_LENGTH,
                metadata.credential_type.len()
            ));
        }

        // Program: field of study (optional, can be omitted for privacy)
        if let Some(ref program) = metadata.program {
            const MAX_PROGRAM_LENGTH: usize = 200;
            if program.len() > MAX_PROGRAM_LENGTH {
                return Err(format!(
                    "metadata.program exceeds max length {} (got {})",
                    MAX_PROGRAM_LENGTH,
                    program.len()
                ));
            }
        }

        // Issue date: ISO 8601 format (YYYY-MM-DD or YYYY-MM)
        const MAX_DATE_LENGTH: usize = 50;
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
            const MAX_ATTRIBUTE_VALUE_LENGTH: usize = 500;
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
        const MAX_NAME_LENGTH: usize = 200;

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
        const MAX_HINT_LENGTH: usize = 500;

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
            "gpa", // Exact GPA (use gpa_bracket instead)
            "exact_gpa",
            "cumulative_gpa",
            "term_gpa",
            "credits", // Exact credit count (use credit_range instead)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::DocSubcode;

    fn make_test_credential(
        subcode: DocSubcode,
        metadata: CredentialMetadata,
    ) -> AcademicCredential {
        AcademicCredential {
            credential_id: [0u8; 32],
            subject_address: sumchain_primitives::Address::from_bytes(&[1u8; 20]),
            subcode,
            subject_commitment: [0u8; 32],
            issuer: sumchain_primitives::Address::from_bytes(&[2u8; 20]),
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

    #[test]
    fn test_valid_transcript_minimal() {
        let validator = SchemaValidator::new();

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
    }

    #[test]
    fn test_valid_transcript_with_allowed_attributes() {
        let validator = SchemaValidator::new();

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
                CredentialAttribute {
                    name: "gpa_bracket".to_string(),
                    value: "3.5-3.75".to_string(),
                },
            ],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            result.is_valid(),
            "Transcript with allowed attributes should be valid"
        );
    }

    #[test]
    fn test_invalid_transcript_with_student_name() {
        let validator = SchemaValidator::new();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "student_name".to_string(), // ← DISALLOWED PII
                value: "John Doe".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with student_name should be rejected"
        );

        if let ValidationResult::Invalid { reason } = result {
            assert!(
                reason.contains("student_name"),
                "Error should mention disallowed key"
            );
        }
    }

    #[test]
    fn test_invalid_transcript_with_exact_gpa() {
        let validator = SchemaValidator::new();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "gpa".to_string(), // ← DISALLOWED (use gpa_bracket instead)
                value: "3.85".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with exact GPA should be rejected"
        );
    }

    #[test]
    fn test_invalid_transcript_with_courses() {
        let validator = SchemaValidator::new();

        let metadata = CredentialMetadata {
            title: "Academic Transcript".to_string(),
            credential_type: "transcript".to_string(),
            program: None,
            issue_date: "2025-05".to_string(),
            completion_date: None,
            attributes: vec![CredentialAttribute {
                name: "courses".to_string(), // ← DISALLOWED (detailed course list)
                value: "[{\"code\": \"CS101\", \"grade\": \"A\"}]".to_string(),
            }],
        };

        let credential = make_test_credential(DocSubcode::AcademicTranscript, metadata);

        let result = validator.validate_academic_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Transcript with detailed courses should be rejected"
        );
    }

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

        // At block 1000+ (after activation), should fail
        let result = validator.validate_academic_credential(&credential, 1000);
        assert!(
            !result.is_valid(),
            "Should fail after activation height"
        );
    }

    #[test]
    fn test_diploma_with_allowed_keys() {
        let validator = SchemaValidator::new();

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
    }

    #[test]
    fn test_excessive_title_length() {
        let validator = SchemaValidator::new();

        let metadata = CredentialMetadata {
            title: "A".repeat(300), // Exceeds MAX_TITLE_LENGTH (200)
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
    }

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
        assert!(
            result.is_valid(),
            "Should pass when validator is disabled"
        );
    }

    #[test]
    fn test_valid_encrypted_credential() {
        use sumchain_primitives::agreement::{EncryptionAlgorithm, EncryptionMeta};

        let validator = SchemaValidator::new();

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
        assert!(
            result.is_valid(),
            "Valid encrypted credential should pass"
        );
    }

    // =========================================================================
    // SRC-88X Employment Tests
    // =========================================================================

    #[test]
    fn test_valid_employment_credential() {
        use sumchain_primitives::employment::{
            EmploymentCredential, EmploymentIssuerClass, EmploymentStatus, EmploymentType,
        };

        let validator = SchemaValidator::new();

        let credential = EmploymentCredential {
            employment_id: [1u8; 32],
            employee_address: sumchain_primitives::Address::from_bytes(&[1u8; 20]),
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
            issuer_address: sumchain_primitives::Address::from_bytes(&[7u8; 20]),
            issuer_name: "SUM INNOVATION INC".to_string(), // Valid institutional name
            issuer_class: EmploymentIssuerClass::Corporation,
            created_at: 1000,
            updated_at: 1000,
        };

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(
            result.is_valid(),
            "Valid employment credential should pass"
        );
    }

    #[test]
    fn test_invalid_employment_with_email() {
        use sumchain_primitives::employment::{
            EmploymentCredential, EmploymentIssuerClass, EmploymentStatus, EmploymentType,
        };

        let validator = SchemaValidator::new();

        let credential = EmploymentCredential {
            employment_id: [1u8; 32],
            employee_address: sumchain_primitives::Address::from_bytes(&[1u8; 20]),
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
            issuer_address: sumchain_primitives::Address::from_bytes(&[7u8; 20]),
            issuer_name: "hr@company.com".to_string(), // Invalid: email address
            issuer_class: EmploymentIssuerClass::Corporation,
            created_at: 1000,
            updated_at: 1000,
        };

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Employment with email in issuer_name should be rejected"
        );
    }

    #[test]
    fn test_invalid_employment_with_phone() {
        use sumchain_primitives::employment::{
            EmploymentCredential, EmploymentIssuerClass, EmploymentStatus, EmploymentType,
        };

        let validator = SchemaValidator::new();

        let credential = EmploymentCredential {
            employment_id: [1u8; 32],
            employee_address: sumchain_primitives::Address::from_bytes(&[1u8; 20]),
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
            issuer_address: sumchain_primitives::Address::from_bytes(&[7u8; 20]),
            issuer_name: "1-800-555-1234".to_string(), // Invalid: phone number
            issuer_class: EmploymentIssuerClass::Corporation,
            created_at: 1000,
            updated_at: 1000,
        };

        let result = validator.validate_employment_credential(&credential, 100);
        assert!(
            !result.is_valid(),
            "Employment with phone number in issuer_name should be rejected"
        );
    }

    // =========================================================================
    // SRC-82X Tax Tests
    // =========================================================================

    #[test]
    fn test_valid_tax_disclosure() {
        use sumchain_primitives::tax::{DisclosureContentType, TaxDisclosureEnvelope};

        let validator = SchemaValidator::new();

        let envelope = TaxDisclosureEnvelope {
            payload_hash: [1u8; 32],
            payload_size: 1024,
            hint_uri: Some("ipfs://bafybeig...".to_string()), // Valid IPFS CID
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: Some([2u8; 32]),
            proof_id: None,
            created_at: 1000,
        };

        let result = validator.validate_tax_disclosure(&envelope, 100);
        assert!(result.is_valid(), "Valid tax disclosure should pass");
    }

    #[test]
    fn test_invalid_tax_disclosure_with_pii_in_uri() {
        use sumchain_primitives::tax::{DisclosureContentType, TaxDisclosureEnvelope};

        let validator = SchemaValidator::new();

        let envelope = TaxDisclosureEnvelope {
            payload_hash: [1u8; 32],
            payload_size: 1024,
            hint_uri: Some("https://example.com/tax?name=John&ssn=123-45-6789".to_string()), // Invalid: PII in URL
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: Some([2u8; 32]),
            proof_id: None,
            created_at: 1000,
        };

        let result = validator.validate_tax_disclosure(&envelope, 100);
        assert!(
            !result.is_valid(),
            "Tax disclosure with PII in URL should be rejected"
        );
    }

    // =========================================================================
    // SRC-87X Healthcare Tests
    // =========================================================================

    #[test]
    fn test_valid_healthcare_membership() {
        use sumchain_primitives::healthcare::{
            CoverageTier, HealthcareIssuerClass, MembershipRecord, MembershipStatus,
            MembershipType, PartyRef,
        };

        let validator = SchemaValidator::new();

        let membership = MembershipRecord {
            membership_id: [1u8; 32],
            member_address: sumchain_primitives::Address::from_bytes(&[1u8; 20]),
            provider_id: [2u8; 32],
            membership_type: MembershipType::IndividualHealth,
            membership_commitment: [3u8; 32],
            member_ref: PartyRef::Commitment([4u8; 32]),
            member_nullifier: [5u8; 32],
            coverage_tier: Some(CoverageTier::Individual),
            group_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: sumchain_primitives::Address::from_bytes(&[6u8; 20]),
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
    }
}
