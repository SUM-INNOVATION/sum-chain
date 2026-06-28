# SUMail Verification Layer — Protocol Clarifications (ANSWERS)

> **Status:** historical / integration handoff
> **Last verified:** 2026-06-27
>
> This is an integration handoff document. Current usage is in [docs/tokens.md](../tokens.md) and [docs/policy-accounts-and-contracts.md](../policy-accounts-and-contracts.md).

**Date**: 2026-02-01
**Status**: PRODUCTION ANSWERS - Activation Height 385,000
**Audience**: SUMail Verification SDK/Gateway Implementation Team

---

## Q1: Can we update metadata.attributes[] after mint?

### SHORT ANSWER: **NO** ❌

### DETAILED EXPLANATION:

Academic credentials (SRC-810/811/812) are **immutable after issuance**. This is a fundamental blockchain property.

**Why immutable?**
- Credentials are cryptographically signed by the issuer
- The `content_commitment` field (32-byte hash) binds the entire credential structure
- Any modification to `metadata.attributes[]` would invalidate the `issuer_signature`
- Blockchain consensus enforces signature verification

**What if you need to fix/update a credential?**

Use the **supersede mechanism**:

1. Issue a NEW credential with corrected data
2. Reference the old credential ID in the new credential's `superseded_by` field
3. Mark the old credential as `revocation_status: Superseded`

**Code reference**: [crates/primitives/src/docclass.rs:611-613](../../crates/primitives/src/docclass.rs#L611-L613)

```rust
/// Revocation status
pub revocation_status: RevocationStatus,
/// If superseded, the new credential ID
pub superseded_by: Option<CredentialId>,
```

**IMPORTANT**: Plan your credential issuance carefully. Once on-chain, it's permanent.

---

## Q2: Which signature standard? secp256k1 or Ed25519?

### SHORT ANSWER: **Chain uses secp256k1, but you specify issuer signature algorithm separately** ✅

### DETAILED EXPLANATION:

**Two different signatures:**

1. **Transaction signature** (chain-level):
   - Algorithm: **secp256k1** (Ethereum-compatible)
   - Signs the entire transaction submitting the credential
   - Proves issuer authorization (issuer must sign tx to mint)
   - This is the **primary authentication mechanism**

2. **Credential issuer_signature** (credential-level):
   - Algorithm: **Your choice** (Ed25519, secp256k1, multisig, etc.)
   - Stored in `AcademicCredential.issuer_signature` field
   - Can be different from tx signature (e.g., institutional multisig)
   - Specify algorithm in `metadata.attributes[]` with key `signature_method`

**Allowed values for `signature_method` attribute**:
- `"Ed25519"` - Recommended for modern systems
- `"secp256k1"` - Ethereum-compatible
- `"multisig"` - Multi-party institutional signing
- Custom values allowed (not validated by schema)

**Code reference**: [crates/state/src/schema_validator.rs:268](../../crates/state/src/schema_validator.rs#L268)

```rust
"signature_method", // "Ed25519", "multisig"
```

**Best practice**: Use **Ed25519** for `issuer_signature` field, rely on secp256k1 tx signature for chain authorization.

---

## Q3: What is the exact schema for `docclass_issueCredential`?

### SHORT ANSWER: See Rust struct below (exact production schema) ✅

### DETAILED SCHEMA:

**RPC Method**: `docclass_issueAcademicCredential`

**Request Structure** (JSON-RPC 2.0):

```json
{
  "jsonrpc": "2.0",
  "method": "docclass_issueAcademicCredential",
  "params": [{
    "subcode": 810,  // 810=Transcript, 811=Diploma, 812=Enrollment
    "subject": "0x1234567890abcdef1234567890abcdef12345678",
    "content_commitment": "0xabcd...",  // 32-byte BLAKE3 hash (hex)
    "metadata": {
      "title": "Academic Transcript",
      "credential_type": "transcript",
      "program": null,  // optional
      "issue_date": "2025-05-15",
      "completion_date": null,  // optional
      "attributes": [
        {"name": "pdf_cid", "value": "bafybeig..."},
        {"name": "courses_commitment", "value": "blake3:a7f2c9..."},
        {"name": "grades_commitment", "value": "blake3:1234..."},
        {"name": "student_commitment", "value": "blake3:5678..."},
        {"name": "academic_year", "value": "2024-2025"},
        {"name": "semester", "value": "Fall"},
        {"name": "signature_method", "value": "Ed25519"}
      ]
    },
    "issued_at": 1735689600,  // Unix timestamp
    "valid_from": 1735689600,
    "expires_at": 0,  // 0 = no expiry
    "payload_hash": null,  // optional
    "payload_hint": "bafybeig...json_payload",  // IPFS CID
    "encryption_meta": {  // OPTIONAL - only if encrypted
      "algorithm": "X25519Aes256Gcm",
      "key_commitment": "0x1234...",  // 32-byte hash (hex)
      "nonce": [1,2,3,4,5,6,7,8,9,10,11,12]  // byte array
    },
    "issuer_signature": "0xabcd...",  // 64-byte signature (hex)
    "issuer_key_id": "registrar-key-2025"
  }],
  "id": 1
}
```

**Rust Struct Reference**: [crates/primitives/src/docclass.rs:580-614](../../crates/primitives/src/docclass.rs#L580-L614)

```rust
pub struct AcademicCredential {
    pub subcode: DocSubcode,
    pub subject: Address,
    pub content_commitment: [u8; 32],
    pub metadata: CredentialMetadata,
    pub issued_at: Timestamp,
    pub valid_from: Timestamp,
    pub expires_at: Timestamp,
    pub payload_hash: Option<[u8; 32]>,
    pub payload_hint: Option<String>,
    pub encryption_meta: Option<EncryptionMeta>,
    pub issuer_signature: [u8; 64],
    pub issuer_key_id: String,
    pub revocation_status: RevocationStatus,
    pub superseded_by: Option<CredentialId>,
}

pub struct CredentialMetadata {
    pub title: String,
    pub credential_type: String,
    pub program: Option<String>,
    pub issue_date: String,
    pub completion_date: Option<String>,
    pub attributes: Vec<CredentialAttribute>,
}

pub struct CredentialAttribute {
    pub name: String,
    pub value: String,
}
```

**CRITICAL**: All hex values must be prefixed with `0x`. Byte arrays use decimal integers.

---

## Q4: What is the EXACT allowlist for metadata.attributes[]?

### SHORT ANSWER: See tables below (production allowlists) ✅

### COMMON ATTRIBUTES (All SRC-81X Credentials)

| Attribute Key | Description | Example Value | Required? |
|--------------|-------------|---------------|-----------|
| `pdf_cid` | IPFS CID of PDF | `"bafybeig..."` | Optional |
| `pdf_hash` | BLAKE3 hash of PDF | `"blake3:a7f2..."` | Optional |
| `pdf_format` | MIME type | `"application/pdf"` | Optional |
| `rendered_at` | PDF generation timestamp | `"2025-05-15T10:30:00Z"` | Optional |
| `environment` | Deployment environment | `"production"` / `"staging"` | Optional |
| `version` | Schema version | `"1.0"` | Optional |

### SRC-810 (Academic Transcript) SPECIFIC

| Attribute Key | Description | Example Value | Required? |
|--------------|-------------|---------------|-----------|
| `credential_subtype` | Transcript type | `"partial_transcript"` / `"final_transcript"` | Optional |
| `academic_year` | Academic year | `"2024-2025"` | Optional |
| `semester` | Term | `"Fall"` / `"Spring"` / `"Summer"` | Optional |
| `term_count` | Number of terms | `"8"` | Optional |
| `issuer_department` | Issuing department | `"Office of the Registrar"` | Optional |
| `signature_method` | Signature algorithm | `"Ed25519"` / `"multisig"` | Optional |
| **`courses_commitment`** | BLAKE3 hash of courses | `"blake3:a7f2..."` | **REQUIRED** |
| **`grades_commitment`** | BLAKE3 hash of grades | `"blake3:1234..."` | **REQUIRED** |
| **`student_commitment`** | BLAKE3 hash of student data | `"blake3:5678..."` | **REQUIRED** |

### SRC-811 (Diploma/Degree) SPECIFIC

| Attribute Key | Description | Example Value | Required? |
|--------------|-------------|---------------|-----------|
| `credential_subtype` | Degree type | `"bachelor"` / `"master"` / `"doctoral"` | Optional |
| `graduation_year` | Year of graduation | `"2025"` | Optional |
| `graduation_semester` | Graduation term | `"Spring"` | Optional |
| `degree_level` | Academic level | `"undergraduate"` / `"graduate"` | Optional |
| `honors_category` | Honors category | `"latin_honors"` / `"departmental_honors"` | Optional |
| `issuer_department` | Issuing department | `"Office of the Registrar"` | Optional |
| `signature_method` | Signature algorithm | `"Ed25519"` | Optional |
| `conferral_ceremony_date` | Public ceremony date | `"2025-05-20"` | Optional |
| `diploma_number` | Public serial number | `"D-2025-12345"` | Optional |
| **`degree_commitment`** | BLAKE3 hash of degree data | `"blake3:..."` | **REQUIRED** |
| **`major_commitment`** | BLAKE3 hash of major data | `"blake3:..."` | **REQUIRED** |
| `minor_commitment` | BLAKE3 hash of minor data | `"blake3:..."` | Optional |
| `honors_commitment` | BLAKE3 hash of honors data | `"blake3:..."` | Optional |
| **`student_commitment`** | BLAKE3 hash of student data | `"blake3:..."` | **REQUIRED** |

### SRC-812 (Enrollment Verification) SPECIFIC

| Attribute Key | Description | Example Value | Required? |
|--------------|-------------|---------------|-----------|
| `enrollment_year` | Enrollment year | `"2025"` | Optional |
| `enrollment_semester` | Enrollment term | `"Fall"` | Optional |
| `enrollment_status` | Enrollment type | `"full_time"` / `"part_time"` / `"leave_of_absence"` | Optional |
| `program_level` | Academic level | `"undergraduate"` / `"graduate"` | Optional |
| `expected_graduation_year` | Expected graduation | `"2029"` | Optional |
| `issuer_department` | Issuing department | `"Office of the Registrar"` | Optional |
| `signature_method` | Signature algorithm | `"Ed25519"` | Optional |
| **`enrollment_commitment`** | BLAKE3 hash of enrollment data | `"blake3:..."` | **REQUIRED** |
| **`program_commitment`** | BLAKE3 hash of program data | `"blake3:..."` | **REQUIRED** |
| **`student_commitment`** | BLAKE3 hash of student data | `"blake3:..."` | **REQUIRED** |

### EXPLICITLY BLOCKED (Will Cause Hard Rejection) ❌

| Blocked Key | Reason | Alternative |
|------------|--------|-------------|
| `student_name` | PII | Use `student_commitment` |
| `student_id` | PII | Use `student_commitment` |
| `ssn` | PII | NEVER on-chain |
| `email` | PII | NEVER on-chain |
| `phone` | PII | NEVER on-chain |
| `date_of_birth` | PII | NEVER on-chain |
| `courses` | PII (raw data) | Use `courses_commitment` |
| `grades` | PII (raw data) | Use `grades_commitment` |
| `gpa` | PII | Use `grades_commitment` |
| `instructor_name` | PII | Use `courses_commitment` |
| `issuer_signature` | Redundant | Chain tx signature provides auth |
| `verification_url` | Centralization risk | Use IPFS payload |
| `json_cid` | Duplicate | Use `payload_hint` instead |
| `json_hash` | Duplicate | Use `payload_hint` instead |
| `gpa_bracket` | De-anonymization risk | Use `grades_commitment` |
| `credit_range` | De-anonymization risk | Use `courses_commitment` |

**Code Reference**: [crates/state/src/schema_validator.rs:251-349](../../crates/state/src/schema_validator.rs#L251-L349)

---

## Q5: Encryption — client-side or chain-provided? Algorithm details?

### SHORT ANSWER: **CLIENT-SIDE encryption with NATIVE chain support** ✅

### DETAILED EXPLANATION:

**Encryption Model:**
- **Chain does NOT encrypt** - you encrypt before submitting
- **Chain STORES encryption metadata** - via `encryption_meta` field
- **Chain does NOT decrypt** - only authorized parties can decrypt

**Privacy Layers:**

1. **On-Chain** (Always Private):
   - Zero PII stored
   - Only BLAKE3 commitments (hashes)
   - Subject addresses are pseudonymous
   - Encryption metadata (algorithm, key_commitment, nonce) stored

2. **Off-Chain IPFS** (Your Choice):
   - **Option A**: Store JSON unencrypted (public to CID holders)
   - **Option B**: Encrypt JSON before uploading to IPFS (private)

**Supported Encryption Algorithms** (Native Support):

| Algorithm | Use Case | Key Size | Nonce Size | Status |
|-----------|----------|----------|------------|--------|
| `Aes256Gcm` | Symmetric encryption | 256-bit | 12 bytes | ✅ Supported |
| `ChaCha20Poly1305` | Symmetric encryption | 256-bit | 12 bytes | ✅ Supported |
| `X25519Aes256Gcm` | **Recommended** - Hybrid key exchange | 256-bit | 12 bytes | ✅ Supported |
| `ThresholdEncryption` | Multi-party threshold | Variable | Variable | ✅ Supported |

**Code Reference**: [crates/primitives/src/agreement.rs:130-151](../../crates/primitives/src/agreement.rs#L130-L151)

```rust
pub struct EncryptionMeta {
    /// Encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Commitment to the encryption key (for key escrow/recovery)
    pub key_commitment: Option<[u8; 32]>,
    /// Nonce/IV if applicable
    pub nonce: Option<Vec<u8>>,
}

pub enum EncryptionAlgorithm {
    Aes256Gcm = 0,
    ChaCha20Poly1305 = 1,
    X25519Aes256Gcm = 2,  // RECOMMENDED
    ThresholdEncryption = 3,
}
```

**Recommended Implementation (X25519Aes256Gcm)**:

```typescript
import * as nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

// 1. Generate issuer keypair (do this once, store securely)
const issuerKeyPair = nacl.box.keyPair();

// 2. Get subject's public key (from their identity/wallet)
const subjectPublicKey = getSubjectPublicKey();

// 3. Compute shared secret (X25519 key exchange)
const sharedSecret = nacl.box.before(subjectPublicKey, issuerKeyPair.secretKey);

// 4. Encrypt JSON payload
const payload = JSON.stringify({
  courses: [{course_code: "CS101", grade: "A"}],
  student: {name: "John Doe", id: "12345"}
});

const nonce = randomBytes(12);
const encrypted = nacl.secretbox(
  new TextEncoder().encode(payload),
  nonce,
  sharedSecret
);

// 5. Upload encrypted blob to IPFS
const ipfsCid = await ipfs.add(encrypted);

// 6. Create credential with encryption metadata
const credential = {
  // ... other fields ...
  payload_hint: ipfsCid,
  encryption_meta: {
    algorithm: "X25519Aes256Gcm",
    key_commitment: blake3(sharedSecret),  // For verification
    nonce: Array.from(nonce)
  }
};
```

**Key Points:**
- Issuer and subject exchange public keys off-chain
- Shared secret derived via X25519 key exchange
- Only issuer and subject can decrypt (verifiers need subject's permission)
- `key_commitment` allows subject to prove correct key was used
- Nonce stored on-chain for decryption reference

**IMPORTANT**: Subject controls who can verify encrypted credentials by sharing decryption capability.

---

## Q6: One commitment or multiple commitments? Format?

### SHORT ANSWER: **MULTIPLE separate commitments, each for different data** ✅

### DETAILED EXPLANATION:

**Why Multiple Commitments?**
- Selective disclosure - reveal only parts of credential
- Privacy granularity - student can share grades without courses
- Verification flexibility - verifier can check specific fields

**Commitment Structure for SRC-810 (Transcript)**:

```json
{
  "metadata": {
    "attributes": [
      {
        "name": "courses_commitment",
        "value": "blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
      },
      {
        "name": "grades_commitment",
        "value": "blake3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
      },
      {
        "name": "student_commitment",
        "value": "blake3:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
      }
    ]
  }
}
```

**Each Commitment is Independent:**

1. **courses_commitment** = BLAKE3("SRC-810-COURSES-v1" || canonical_json(courses_array))
2. **grades_commitment** = BLAKE3("SRC-810-GRADES-v1" || canonical_json(grades_array))
3. **student_commitment** = BLAKE3("SRC-810-STUDENT-v1" || canonical_json(student_data))

**Format Rules:**

- **Prefix**: `"blake3:"` followed by hex-encoded hash
- **Alternative**: `"0x"` prefix also accepted
- **Length**: 64 hex characters (32 bytes)
- **Case**: Lowercase hex recommended
- **Domain Separator**: MUST match spec (e.g., `"SRC-810-COURSES-v1"`)

**Canonical JSON Rules** (CRITICAL for verification):

```typescript
function canonicalize(obj: any): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (typeof obj === 'object' && obj !== null) {
    const keys = Object.keys(obj).sort();  // SORT KEYS ALPHABETICALLY
    const pairs = keys
      .filter(k => obj[k] !== null)  // OMIT NULL VALUES
      .map(k => `"${k}":${canonicalize(obj[k])}`);
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(obj);  // Primitives
}

function computeCommitment(domain: string, data: any): string {
  const canonical = canonicalize(data);
  const input = domain + canonical;
  const hash = blake3(new TextEncoder().encode(input));
  return `blake3:${Buffer.from(hash).toString('hex')}`;
}

// Example usage
const courses = [
  {course_code: "CS101", credits: 3, grade: "A"},
  {course_code: "MATH201", credits: 4, grade: "B+"}
];

const commitment = computeCommitment("SRC-810-COURSES-v1", courses);
// Result: "blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
```

**IPFS Payload Structure** (`payload_hint` reference):

```json
{
  "courses": [
    {"course_code": "CS101", "credits": 3, "grade": "A"},
    {"course_code": "MATH201", "credits": 4, "grade": "B+"}
  ],
  "grades": {
    "gpa": "3.87",
    "total_credits": 120,
    "honors": "cum_laude"
  },
  "student": {
    "name": "John Doe",
    "id": "S12345678",
    "email": "john.doe@university.edu"
  }
}
```

**Verification Process:**

1. Verifier requests `payload_hint` IPFS content from subject/issuer
2. If encrypted, subject provides decryption key
3. Verifier decrypts (if needed) and extracts specific field (e.g., `courses`)
4. Verifier recomputes commitment using same domain separator and canonicalization
5. Verifier compares computed commitment with on-chain commitment
6. ✅ Match = data authentic and unmodified

**Full Specification**: See `SRC-81X-COMMITMENT-CANONICALIZATION.md`

---

## Q7: What changes at activation block 385,000?

### SHORT ANSWER: **Schema validation activates - PII rejection enforced** ✅

### BEFORE Activation (Block < 385,000):

| Behavior | Description |
|----------|-------------|
| ✅ Old credentials accepted | Credentials with PII (`student_name`, `gpa`, etc.) still accepted |
| ✅ No validation | `metadata.attributes[]` not checked against allowlist |
| ✅ Backward compatible | All existing issuance code continues working |

### AFTER Activation (Block >= 385,000):

| Behavior | Description |
|----------|-------------|
| ❌ PII rejected | Credentials with disallowed keys (e.g., `student_name`) **HARD REJECTED** |
| ✅ Allowlist enforced | Only approved attribute keys accepted (see Q4 tables) |
| ✅ Encryption supported | Native `encryption_meta` field available |
| ❌ Removed fields rejected | `issuer_signature`, `verification_url`, `json_cid` all rejected |

**What Happens to Old Credentials?**
- **Already on-chain credentials**: NOT affected, remain valid forever
- **New credential submissions**: MUST comply with new rules

**Example Error After Activation:**

```bash
# Before 385,000: This succeeds ✅
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "attributes": [
          {"name": "student_name", "value": "John Doe"}
        ]
      }
    }],
    "id": 1
  }'

# After 385,000: This fails ❌
# Error: "Schema validation failed: Disallowed attribute key 'student_name'.
#         Allowed keys: pdf_cid, pdf_hash, courses_commitment, grades_commitment,
#         student_commitment, academic_year, semester, ..."
```

**Code Reference**: [crates/state/src/schema_validator.rs:51-60](../../crates/state/src/schema_validator.rs#L51-L60)

```rust
impl Default for SchemaValidatorConfig {
    fn default() -> Self {
        Self {
            activation_height: 385000,  // ACTIVATION HEIGHT
            enabled: true,
        }
    }
}
```

**Validation Logic**:

```rust
pub fn validate_academic_credential(&self, credential: &AcademicCredential, current_height: u64) -> ValidationResult {
    // Skip validation if before activation height
    if current_height < self.config.activation_height {
        return ValidationResult::Valid;
    }

    // Validate attributes against allowlist
    // ...
}
```

**Migration Strategy:**

1. **Before 385,000**: Update your issuance code to use commitments
2. **Test**: Submit test credentials to ensure compliance
3. **At 385,000**: Validation automatically activates
4. **After 385,000**: Only compliant credentials accepted

**Current Status** (as of writing):
- **Current block**: ~384,300
- **Activation block**: 385,000
- **Blocks remaining**: ~700 blocks (~1-2 hours)
- **Status**: Validators deployed, waiting for activation

---

## Q8: Batch RPC limits? How many credentials per request?

### SHORT ANSWER: **No specific batch limit in schema validation, but practical RPC limits apply** ⚠️

### DETAILED EXPLANATION:

**Schema Validation Perspective:**
- Schema validator validates **one credential at a time**
- No batching logic in validation layer
- Each credential validated independently

**RPC/Transaction Limits:**

| Limit Type | Value | Notes |
|-----------|-------|-------|
| **Max transaction size** | ~128 KB | Standard Ethereum-compatible limit |
| **Max gas per transaction** | Variable | Depends on network congestion |
| **Recommended batch size** | 1-10 credentials | For reliability |
| **Maximum practical batch** | ~50 credentials | Approaching tx size limit |

**Why Batch Size Matters:**

1. **Transaction Size**: Each credential ~2-5 KB (with metadata)
   - 10 credentials ≈ 20-50 KB ✅
   - 50 credentials ≈ 100-250 KB ⚠️ (close to limit)
   - 100 credentials ≈ 200-500 KB ❌ (exceeds limit)

2. **Gas Costs**: Validation has computational cost
   - Each attribute key lookup: ~minimal gas
   - 100 attributes across 10 credentials: ~acceptable
   - 1000 attributes across 100 credentials: ~may exceed gas limit

3. **Error Handling**: If ONE credential fails validation
   - **Entire batch rejected** (atomic transaction)
   - Better to submit smaller batches to isolate failures

**Recommended Batching Strategy:**

```typescript
// DON'T: Submit 100 credentials at once
const batch = credentials.slice(0, 100);
await rpc.batchIssueCredentials(batch);  // ❌ May fail

// DO: Submit in small batches with error handling
const BATCH_SIZE = 10;
for (let i = 0; i < credentials.length; i += BATCH_SIZE) {
  const batch = credentials.slice(i, i + BATCH_SIZE);
  try {
    await rpc.batchIssueCredentials(batch);
  } catch (error) {
    // Handle batch failure, retry individually if needed
    console.error(`Batch ${i}-${i+BATCH_SIZE} failed:`, error);
  }
}
```

**Client-Side Pre-Validation (CRITICAL for batching):**

```typescript
const ALLOWED_KEYS: Record<number, Set<string>> = {
  810: new Set(["pdf_cid", "courses_commitment", "grades_commitment", "student_commitment", "academic_year", ...]),
  811: new Set(["pdf_cid", "degree_commitment", "major_commitment", "student_commitment", ...]),
  812: new Set(["pdf_cid", "enrollment_commitment", "program_commitment", "student_commitment", ...])
};

function validateBeforeSubmit(credential: AcademicCredential): void {
  const allowed = ALLOWED_KEYS[credential.subcode];

  for (const attr of credential.metadata.attributes) {
    if (!allowed.has(attr.name)) {
      throw new Error(`PRE-VALIDATION FAILED: Disallowed key '${attr.name}' in subcode ${credential.subcode}`);
    }

    if (attr.value.length > 500) {
      throw new Error(`PRE-VALIDATION FAILED: Attribute '${attr.name}' value too long (${attr.value.length} bytes, max 500)`);
    }
  }
}

// Validate ALL credentials before submitting batch
const validatedBatch = batch.filter(cred => {
  try {
    validateBeforeSubmit(cred);
    return true;
  } catch (error) {
    console.error(`Credential ${cred.subject} failed pre-validation:`, error);
    return false;
  }
});

// Submit only valid credentials
await rpc.batchIssueCredentials(validatedBatch);
```

**Best Practices:**

1. **Pre-validate client-side** to avoid rejected transactions
2. **Batch 5-10 credentials** for optimal throughput
3. **Implement retry logic** for failed batches
4. **Monitor gas costs** to adjust batch size dynamically
5. **Use individual submission** for mission-critical credentials

**No Hard Limit**: Chain doesn't enforce a specific batch limit, but practical limits (tx size, gas) apply.

---

## Additional Notes

### Testing After Activation (Block 385,000+)

**Test 1: Invalid Credential (Should Fail)**

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "subject": "0x1234567890abcdef1234567890abcdef12345678",
      "content_commitment": "0xabcd...",
      "metadata": {
        "title": "Test Transcript",
        "credential_type": "transcript",
        "issue_date": "2025-05-15",
        "attributes": [
          {"name": "student_name", "value": "John Doe"}
        ]
      },
      "issued_at": 1735689600,
      "valid_from": 1735689600,
      "expires_at": 0,
      "issuer_signature": "0x...",
      "issuer_key_id": "test-key"
    }],
    "id": 1
  }'
```

**Expected Error**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Schema validation failed: Disallowed attribute key 'student_name'. Allowed keys: pdf_cid, pdf_hash, pdf_format, rendered_at, environment, version, credential_subtype, academic_year, semester, term_count, issuer_department, signature_method, courses_commitment, grades_commitment, student_commitment"
  }
}
```

**Test 2: Valid Credential (Should Succeed)**

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "subject": "0x1234567890abcdef1234567890abcdef12345678",
      "content_commitment": "0xabcd...",
      "metadata": {
        "title": "Academic Transcript",
        "credential_type": "transcript",
        "issue_date": "2025-05-15",
        "attributes": [
          {"name": "pdf_cid", "value": "bafybeig..."},
          {"name": "courses_commitment", "value": "blake3:a7f2c9e1d8b5f3a4c6e8d9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
          {"name": "grades_commitment", "value": "blake3:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
          {"name": "student_commitment", "value": "blake3:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"},
          {"name": "academic_year", "value": "2024-2025"},
          {"name": "semester", "value": "Fall"}
        ]
      },
      "issued_at": 1735689600,
      "valid_from": 1735689600,
      "expires_at": 0,
      "payload_hint": "bafybeig...json",
      "issuer_signature": "0x...",
      "issuer_key_id": "test-key"
    }],
    "id": 1
  }'
```

**Expected Success**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "credential_id": "0x...",
    "transaction_hash": "0x...",
    "block_number": 385042
  }
}
```

**Test 3: Valid Encrypted Credential (Should Succeed)**

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "subject": "0x1234567890abcdef1234567890abcdef12345678",
      "content_commitment": "0xabcd...",
      "metadata": {
        "title": "Academic Transcript (Encrypted)",
        "credential_type": "transcript",
        "issue_date": "2025-05-15",
        "attributes": [
          {"name": "courses_commitment", "value": "blake3:a7f2c9e1d8b5..."},
          {"name": "grades_commitment", "value": "blake3:1234567890ab..."},
          {"name": "student_commitment", "value": "blake3:fedcba098765..."}
        ]
      },
      "issued_at": 1735689600,
      "valid_from": 1735689600,
      "expires_at": 0,
      "payload_hint": "bafybeig...encrypted",
      "encryption_meta": {
        "algorithm": "X25519Aes256Gcm",
        "key_commitment": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "nonce": [1,2,3,4,5,6,7,8,9,10,11,12]
      },
      "issuer_signature": "0x...",
      "issuer_key_id": "test-key"
    }],
    "id": 1
  }'
```

**Expected Success**: Same as Test 2 (encryption is fully supported)

---

## Quick Reference

### Must-Read Documentation

1. **[VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md)** - Complete implementation guide
2. **`SRC-81X-COMMITMENT-CANONICALIZATION.md`** - Hashing specification
3. **`DEPLOYMENT-GUIDE.md`** - Validator deployment instructions

### Code References

- **Credential Schema**: [crates/primitives/src/docclass.rs:580-640](../../crates/primitives/src/docclass.rs#L580-L640)
- **Validation Logic**: [crates/state/src/schema_validator.rs:51-450](../../crates/state/src/schema_validator.rs#L51-L450)
- **Allowlists**: [crates/state/src/schema_validator.rs:251-349](../../crates/state/src/schema_validator.rs#L251-L349)
- **Encryption Types**: [crates/primitives/src/agreement.rs:130-151](../../crates/primitives/src/agreement.rs#L130-L151)

### Key Dates

- **Deployment Date**: 2026-02-01
- **Activation Block**: 385,000
- **Current Block**: ~384,300 (at time of writing)
- **Time to Activation**: ~1-2 hours

---

**Document Version**: 1.0
**Status**: PRODUCTION ANSWERS
**Reviewed By**: Chain Core Team
**Contact**: File issues in chain repository

---

**END OF PROTOCOL ANSWERS**
