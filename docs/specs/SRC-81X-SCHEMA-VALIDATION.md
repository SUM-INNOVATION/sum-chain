# SRC-81X Schema Validation: Developer Reference

## Overview

This document describes the **deterministic allowlist-based schema validation** implemented for SRC-81X academic credentials (subcodes 810, 811, 812) to prevent personally identifiable information (PII) from being stored on-chain.

**Enforcement Level**: Consensus (hard rejection)
**Rollout Status**: Pilot for SRC-81X, designed to extend to other SRC-8XX families
**Implementation**: `crates/state/src/schema_validator.rs`
**Integration Point**: `DocClassExecutor::issue_academic_credential()` (line ~615)

---

## Design Principles

1. **HARD REJECTION**: Transactions violating schema are rejected at consensus before state changes
2. **ALLOWLIST-BASED**: Only explicitly permitted metadata + attribute keys are allowed
3. **NO HEURISTICS**: No regex/ML PII detection (too brittle and bypassable)
4. **DETERMINISTIC**: Same credential input always produces same validation result
5. **BACKWARD COMPATIBLE**: Existing credentials remain valid via `activation_height` mechanism

---

## Privacy Architecture

### What Goes On-Chain (Allowed)
- ✅ **Commitments (hashes)**: BLAKE3 hashes of sensitive data
- ✅ **Institutional names**: University names, issuer identifiers (public entities)
- ✅ **Credential types**: "Transcript", "Diploma", "Enrollment"
- ✅ **Timestamps**: Issue dates, graduation year, academic year
- ✅ **Pseudonymous addresses**: Wallet addresses (not linked to real identity)
- ✅ **Ranges/brackets**: "GPA 3.5-4.0" (NOT exact "3.87")
- ✅ **IPFS CIDs**: References to encrypted off-chain payloads

### What NEVER Goes On-Chain (Disallowed)
- ❌ **Student names**: Real name, legal name, any name field
- ❌ **Student IDs**: Institutional student ID numbers
- ❌ **Contact info**: Email, phone, physical address
- ❌ **SSN/Tax ID**: Any government identification
- ❌ **Exact grades**: Specific course grades, exact GPA values
- ❌ **Course lists**: Individual course names/codes
- ❌ **Instructor names**: Faculty names
- ❌ **Date of birth**: Any DOB information
- ❌ **Any PII**: Per FERPA/GDPR definitions

### Commitment-Based Privacy Pattern

```
On-Chain:
{
  "credential_id": "0x...",
  "subcode": 810,  // Transcript
  "metadata": {
    "title": "Academic Transcript",
    "credential_type": "SRC-810",
    "program": "Bachelor of Science - Computer Science",  // Institutional, non-PII
    "issue_date": "2026-01-15",
    "completion_date": "2025-12-20",
    "attributes": [
      {"name": "pdf_cid", "value": "bafybeig..."},
      {"name": "pdf_hash", "value": "blake3:a7f2c..."},
      {"name": "gpa_bracket", "value": "3.5-4.0"},          // Range, not exact
      {"name": "courses_commitment", "value": "blake3:d9e..."},  // Hash only
      {"name": "grades_commitment", "value": "blake3:f1a..."}    // Hash only
    ]
  },
  "payload_hint": "bafybeig..."  // IPFS CID for encrypted full payload
}

Off-Chain (IPFS, encrypted):
{
  "student_name": "Yuumi de Cat",
  "student_id": "20260001",
  "gpa": "3.87",  // Exact value
  "courses": [
    {"code": "CS101", "title": "Intro to Programming", "grade": "A"},
    {"code": "MATH201", "title": "Calculus II", "grade": "A-"}
  ]
}
```

---

## Allowed Attribute Keys by Subcode

### SRC-810: Academic Transcript

#### Metadata References (Always Allowed)
```
pdf_cid              // IPFS CID of rendered PDF
pdf_hash             // BLAKE3 hash of PDF for integrity
pdf_format           // "application/pdf"
rendered_at          // Timestamp of PDF generation
json_cid             // IPFS CID of canonical JSON
json_hash            // BLAKE3 hash of canonical JSON
environment          // "production", "staging", "testnet"
version              // Schema version "1.0"
```

#### Academic Context (Non-PII)
```
credential_subtype   // "Official", "Unofficial", "Partial"
academic_year        // "2025-2026"
semester             // "Fall 2025", "Spring 2026"
program_level        // "Undergraduate", "Graduate"
issuer_category      // "Public University", "Private College"
```

#### Privacy-Preserving Ranges (NOT Exact Values)
```
credit_range         // "90-120 credits" (NOT "107 credits")
gpa_bracket          // "3.5-4.0" (NOT "3.87")
courses_count_range  // "30-40 courses" (NOT "34 courses")
```

#### Commitments (Hashes Only)
```
courses_commitment   // BLAKE3(canonical_json(courses))
grades_commitment    // BLAKE3(canonical_json(grades))
degree_commitment    // BLAKE3(canonical_json(degree_requirements))
honors_commitment    // BLAKE3(canonical_json(honors_details))
```

#### Verification Metadata
```
verification_url     // Institutional verification endpoint
issuer_signature     // Cryptographic signature (public operation)
attestation_type     // "Registrar", "Dean", "Automated"
```

**Total Allowed Keys**: 18 keys

#### Explicitly DISALLOWED Keys (Examples)
```
student_name         // PII: Real name
student_id           // PII: Institutional ID
ssn                  // PII: Government ID
email                // PII: Contact info
courses              // EXACT course list (use courses_commitment)
grades               // EXACT grades (use grades_commitment)
gpa                  // EXACT GPA (use gpa_bracket)
instructor_names     // PII: Faculty names
date_of_birth        // PII
address              // PII: Physical address
phone                // PII: Contact info
parent_name          // PII
emergency_contact    // PII
```

---

### SRC-811: Diploma

#### Metadata References (Always Allowed)
```
pdf_cid              // IPFS CID of diploma PDF
pdf_hash             // BLAKE3 hash of PDF
pdf_format           // "application/pdf"
rendered_at          // PDF generation timestamp
json_cid             // IPFS CID of canonical JSON
json_hash            // BLAKE3 hash of canonical JSON
environment          // "production", "staging", "testnet"
version              // Schema version "1.0"
```

#### Degree Information (Non-PII)
```
degree_level         // "Bachelor", "Master", "Doctorate"
degree_type          // "BS", "BA", "MS", "MA", "PhD"
graduation_year      // "2025" (year only, not exact date)
graduation_term      // "Fall", "Spring", "Summer"
honors_category      // "Summa Cum Laude", "Magna Cum Laude", "Cum Laude", "None"
program_level        // "Undergraduate", "Graduate"
conferral_status     // "Conferred", "Pending", "Posthumous"
```

#### Commitments (Hashes Only)
```
degree_commitment    // BLAKE3(canonical_json(degree_details))
major_commitment     // BLAKE3(canonical_json(major_minor))
honors_commitment    // BLAKE3(canonical_json(honors_details))
thesis_commitment    // BLAKE3(canonical_json(thesis_info)) - if applicable
```

#### Verification Metadata
```
verification_url     // Institutional verification endpoint
issuer_signature     // Cryptographic signature
conferral_authority  // "Board of Trustees", "President", "Provost"
```

**Total Allowed Keys**: 19 keys

#### Explicitly DISALLOWED Keys (Examples)
```
student_name         // PII: Recipient name
student_id           // PII: Institutional ID
ssn                  // PII: Government ID
major                // EXACT major (use major_commitment)
minor                // EXACT minor (use major_commitment)
concentration        // EXACT details (use degree_commitment)
thesis_title         // EXACT thesis title (use thesis_commitment)
advisor_name         // PII: Faculty advisor
gpa                  // EXACT GPA (use honors_category for ranges)
date_of_birth        // PII
```

---

### SRC-812: Enrollment Verification

#### Metadata References (Always Allowed)
```
pdf_cid              // IPFS CID of verification letter PDF
pdf_hash             // BLAKE3 hash of PDF
pdf_format           // "application/pdf"
rendered_at          // PDF generation timestamp
json_cid             // IPFS CID of canonical JSON
json_hash            // BLAKE3 hash of canonical JSON
environment          // "production", "staging", "testnet"
version              // Schema version "1.0"
```

#### Enrollment Context (Non-PII)
```
enrollment_year      // "2026" (current academic year)
enrollment_term      // "Fall", "Spring", "Summer", "Full-Year"
enrollment_status    // "Full-Time", "Part-Time", "Leave of Absence"
program_level        // "Undergraduate", "Graduate", "Non-Degree"
student_type         // "Degree-Seeking", "Exchange", "Visiting"
expected_grad_year   // "2029" (year only)
```

#### Commitments (Hashes Only)
```
enrollment_commitment  // BLAKE3(canonical_json(enrollment_details))
program_commitment     // BLAKE3(canonical_json(program_info))
schedule_commitment    // BLAKE3(canonical_json(course_schedule)) - if needed
```

#### Verification Metadata
```
verification_url     // Institutional verification endpoint
issuer_signature     // Cryptographic signature
valid_from           // Timestamp enrollment verification valid from
valid_until          // Timestamp enrollment verification expires
purpose              // "Loan Deferment", "Visa", "Insurance", "General"
```

**Total Allowed Keys**: 18 keys

#### Explicitly DISALLOWED Keys (Examples)
```
student_name         // PII: Real name
student_id           // PII: Institutional ID
ssn                  // PII: Government ID
email                // PII: Contact info
schedule             // EXACT course schedule (use schedule_commitment)
course_list          // EXACT courses (use schedule_commitment)
credits_enrolled     // EXACT credit count (use enrollment_status)
advisor_name         // PII: Faculty advisor
financial_aid_status // PII: Financial information
```

---

## Validation Logic

### Enforcement Flow

1. **Transaction Submitted**: Client submits `docclass_issueAcademicCredential` transaction
2. **Basic Validation**: DocClassExecutor validates issuer authorization, credential existence
3. **Schema Validation** (NEW):
   ```rust
   let validation_result = self.schema_validator
       .validate_academic_credential(&credential, block_height);

   if !validation_result.is_valid() {
       // HARD REJECTION: Return error BEFORE state changes
       return Ok(DocClassExecutionResult::failure(
           format!("Schema validation failed: {}", reason)
       ));
   }
   ```
4. **State Changes**: Only if validation passes, deduct fee and store credential
5. **Transaction Receipt**: Success or hard rejection error

### Validation Algorithm

```rust
fn validate_academic_credential(
    &self,
    credential: &AcademicCredential,
    block_height: BlockHeight,
) -> ValidationResult {
    // Step 1: Backward compatibility check
    if block_height < self.config.activation_height {
        return ValidationResult::Valid;  // Skip validation for old blocks
    }

    // Step 2: Dispatch to subcode-specific validator
    match credential.subcode {
        DocSubcode::AcademicTranscript =>
            self.validate_transcript_metadata(&credential.metadata),
        DocSubcode::Diploma =>
            self.validate_diploma_metadata(&credential.metadata),
        DocSubcode::EnrollmentVerification =>
            self.validate_enrollment_metadata(&credential.metadata),
        _ => ValidationResult::Valid,  // Unknown subcode, skip
    }
}

fn validate_transcript_metadata(&self, metadata: &CredentialMetadata) -> ValidationResult {
    // Step 1: Check title length
    if metadata.title.len() > MAX_TITLE_LENGTH {
        return ValidationResult::invalid("Title too long");
    }

    // Step 2: Check type length
    if metadata.credential_type.len() > MAX_TYPE_LENGTH {
        return ValidationResult::invalid("Type too long");
    }

    // Step 3: Check program length (if present)
    if let Some(program) = &metadata.program {
        if program.len() > MAX_PROGRAM_LENGTH {
            return ValidationResult::invalid("Program name too long");
        }
    }

    // Step 4: Validate attribute keys (CORE PRIVACY CHECK)
    let allowed_keys = Self::transcript_allowed_keys();
    for attr in &metadata.attributes {
        if !allowed_keys.contains(attr.name.as_str()) {
            return ValidationResult::invalid(format!(
                "Disallowed attribute key '{}'. Allowed keys: {}",
                attr.name,
                allowed_keys.iter().join(", ")
            ));
        }

        // Step 5: Check attribute value length
        if attr.value.len() > MAX_ATTRIBUTE_VALUE_LENGTH {
            return ValidationResult::invalid(format!(
                "Attribute '{}' value too long (max {} bytes)",
                attr.name, MAX_ATTRIBUTE_VALUE_LENGTH
            ));
        }
    }

    // Step 6: Validate date fields (if present)
    if let Err(e) = self.validate_date_field(&metadata.issue_date, "issue_date") {
        return ValidationResult::invalid(e);
    }
    if let Some(completion) = &metadata.completion_date {
        if let Err(e) = self.validate_date_field(completion, "completion_date") {
            return ValidationResult::invalid(e);
        }
    }

    ValidationResult::Valid
}
```

### Error Messages

When validation fails, the transaction is rejected with a descriptive error:

```json
{
  "success": false,
  "error": "Schema validation failed: Disallowed attribute key 'student_name'. Allowed keys: pdf_cid, pdf_hash, pdf_format, rendered_at, json_cid, json_hash, environment, version, credential_subtype, academic_year, semester, credit_range, gpa_bracket, courses_commitment, grades_commitment, verification_url, issuer_signature, attestation_type"
}
```

---

## Configuration

### Backward Compatibility via Activation Height

```rust
pub struct SchemaValidatorConfig {
    /// Block height when validation becomes active
    pub activation_height: BlockHeight,
    /// Whether to enforce validation (can be disabled for testing)
    pub enabled: bool,
}

impl Default for SchemaValidatorConfig {
    fn default() -> Self {
        Self {
            // TODO: Set appropriate activation height for mainnet
            // For testnet: activate immediately (0)
            activation_height: 0,
            enabled: true,
        }
    }
}
```

**How Activation Height Works**:
- Credentials issued **before** activation height: validation skipped (backward compatible)
- Credentials issued **at or after** activation height: validation enforced
- Allows phased rollout: testnet (height 0), mainnet (height TBD)

### Mainnet Deployment Plan

1. **Testnet Deployment**: `activation_height = 0` (immediate enforcement)
2. **Testnet Testing Period**: 2-4 weeks of validation
3. **Mainnet Deployment**: `activation_height = [future block]` (e.g., block 1,500,000)
4. **Grace Period**: Announce activation height 2 weeks in advance
5. **Activation**: Schema validation enforces at specified height

---

## Test Cases

### Valid Credential Examples

#### Valid Transcript (SRC-810)
```json
{
  "credential_id": "0x1234...",
  "subcode": 810,
  "subject_address": "SUMxxx...",
  "metadata": {
    "title": "Official Academic Transcript",
    "credential_type": "SRC-810-Transcript",
    "program": "Bachelor of Science - Computer Science",
    "issue_date": "2026-01-15",
    "completion_date": "2025-12-20",
    "attributes": [
      {"name": "pdf_cid", "value": "bafybeig..."},
      {"name": "pdf_hash", "value": "blake3:a7f2c..."},
      {"name": "gpa_bracket", "value": "3.5-4.0"},
      {"name": "courses_commitment", "value": "blake3:d9e..."}
    ]
  },
  "payload_hint": "bafybeig..."
}
```
**Result**: ✅ VALID - Uses allowed keys, commitments for sensitive data

#### Valid Diploma (SRC-811)
```json
{
  "credential_id": "0x5678...",
  "subcode": 811,
  "subject_address": "SUMxxx...",
  "metadata": {
    "title": "Bachelor of Science Diploma",
    "credential_type": "SRC-811-Diploma",
    "program": "Computer Science",
    "issue_date": "2025-05-15",
    "attributes": [
      {"name": "pdf_cid", "value": "bafybeig..."},
      {"name": "degree_level", "value": "Bachelor"},
      {"name": "graduation_year", "value": "2025"},
      {"name": "honors_category", "value": "Summa Cum Laude"},
      {"name": "degree_commitment", "value": "blake3:f1a..."}
    ]
  },
  "payload_hint": "bafybeig..."
}
```
**Result**: ✅ VALID - Institutional public info + commitments only

### Invalid Credential Examples

#### Invalid: Student Name (PII)
```json
{
  "metadata": {
    "title": "Academic Transcript",
    "credential_type": "SRC-810-Transcript",
    "attributes": [
      {"name": "student_name", "value": "Yuumi de Cat"}  // ❌ PII
    ]
  }
}
```
**Result**: ❌ REJECTED - `Disallowed attribute key 'student_name'`

#### Invalid: Exact GPA
```json
{
  "metadata": {
    "title": "Academic Transcript",
    "credential_type": "SRC-810-Transcript",
    "attributes": [
      {"name": "gpa", "value": "3.87"}  // ❌ Exact value (use gpa_bracket)
    ]
  }
}
```
**Result**: ❌ REJECTED - `Disallowed attribute key 'gpa'`

#### Invalid: Course List
```json
{
  "metadata": {
    "title": "Academic Transcript",
    "credential_type": "SRC-810-Transcript",
    "attributes": [
      {"name": "courses", "value": "[{\"code\":\"CS101\"...}]"}  // ❌ EXACT list
    ]
  }
}
```
**Result**: ❌ REJECTED - `Disallowed attribute key 'courses'` (use `courses_commitment`)

---

## Extension to Other SRC Families

### Designed for Extensibility

The schema validator is designed as a **registry system** to easily add allowlists for other SRC families:

```rust
pub enum SrcFamily {
    SRC81X,  // Academic (implemented)
    SRC82X,  // Tax (next priority)
    SRC83X,  // Business
    SRC84X,  // Agreements
    SRC85X,  // Legal
    SRC86X,  // Property
    SRC87X,  // Healthcare (HIPAA - high priority)
    SRC88X,  // Employment
    SRC89X,  // Finance
}

impl SchemaValidator {
    pub fn validate_credential(
        &self,
        family: SrcFamily,
        credential: &dyn Credential,
        block_height: BlockHeight,
    ) -> ValidationResult {
        match family {
            SrcFamily::SRC81X => self.validate_academic(...),
            SrcFamily::SRC82X => self.validate_tax(...),
            SrcFamily::SRC87X => self.validate_healthcare(...),
            // ... more families
        }
    }
}
```

### Next Priorities for Allowlist Implementation

1. **SRC-82X (Tax)**: Maximum privacy (SSN, income, account numbers)
2. **SRC-87X (Healthcare)**: HIPAA compliance (PHI, medical records)
3. **SRC-88X (Employment)**: Salary, SSN, performance data
4. **SRC-89X (Finance)**: Account numbers, balances, transaction details

---

## References

### Implementation Files
- **Schema Validator**: `crates/state/src/schema_validator.rs`
- **Docclass Executor Integration**: `crates/state/src/docclass_executor.rs` (line ~615)
- **State Module Exports**: `crates/state/src/lib.rs`

### Related Documentation
- **Privacy Analysis**: `SRC-TOKEN-FAMILIES-PRIVACY-ANALYSIS.md`
- **Academic Credentials Spec**: `ACADEMIC-CREDENTIALS-HANDOFF-SPEC.md`
- **Implementation Addendum**: `ACADEMIC-CREDENTIALS-IMPLEMENTATION-ADDENDUM.md`

### Standards References
- **SRC-810**: Academic Transcript Standard
- **SRC-811**: Diploma Standard
- **SRC-812**: Enrollment Verification Standard
- **FERPA**: Family Educational Rights and Privacy Act (U.S. education privacy law)
- **GDPR**: General Data Protection Regulation (EU privacy law)

---

## FAQ

### Q: Why allowlists instead of regex/ML PII detection?
**A**: Allowlists are deterministic and consensus-safe. Regex/ML detection is:
- Too brittle (false positives/negatives)
- Bypassable (obfuscation, encoding tricks)
- Non-deterministic (different nodes may disagree)
- Computationally expensive at consensus

### Q: What happens to credentials issued before activation?
**A**: They remain valid. Validation only applies to credentials issued at or after the configured `activation_height`.

### Q: Can issuers request new allowed keys?
**A**: Yes, via governance proposal. New keys must be:
1. Non-PII (institutional/public information only)
2. Justified use case (why needed on-chain)
3. Cannot be replaced by commitment
4. Approved by chain governance

### Q: How are ranges/brackets enforced?
**A**: Validation only checks the **key name** (e.g., `gpa_bracket` allowed, `gpa` disallowed). The **value format** is not validated - that's the issuer's responsibility. Chain only prevents PII keys from existing.

### Q: What if an issuer wants to store arbitrary metadata?
**A**: Use the `payload_hint` field (IPFS CID). Full metadata goes **off-chain** (encrypted on IPFS), and the CID reference goes on-chain. Verifiers fetch and decrypt the full payload as needed.

### Q: How do verifiers access full credential data?
**A**: Verifiers use the on-chain `payload_hint` (IPFS CID) to fetch the encrypted full payload from IPFS. Students/subjects provide decryption keys via out-of-band mechanisms (QR codes, secure links, etc.).

### Q: Can this be bypassed by encoding PII in commitments?
**A**: No. Commitments (BLAKE3 hashes) are one-way functions. Even if an issuer encodes "name:Yuumi" and hashes it, the chain stores only the hash. The original PII is not readable on-chain. This achieves the privacy goal.

---

## Contact

For questions about schema validation implementation:
- **SUM Chain Core Team**: Contact via governance channels
- **Schema Change Proposals**: Submit via chain governance process
- **Bug Reports**: File issues in chain repository

---

**Document Version**: 1.0
**Last Updated**: 2026-02-01
**Status**: Active (Testnet), Pending Mainnet Activation
