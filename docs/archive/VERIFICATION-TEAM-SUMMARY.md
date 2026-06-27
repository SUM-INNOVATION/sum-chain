# Schema Validation Changes: Verification Team Summary (SRC-810/811/812)

> **Status:** historical / integration handoff
> **Last verified:** 2026-06-27
>
> This is an integration handoff document. Current usage is in [docs/tokens.md](../tokens.md) and [docs/policy-accounts-and-contracts.md](../policy-accounts-and-contracts.md).

## Executive Summary

Academic credentials (SRC-810, 811, 812) now enforce **hard rejection** at consensus if they contain disallowed metadata fields. This prevents PII from being permanently stored on-chain.

**Effective**: After activation height (to be announced)

**NEW - Encryption Support**: Native encryption metadata now available in credential structure. Use `encryption_meta` field with X25519Aes256Gcm for encrypted IPFS payloads. See section 3 for implementation details.

---

## Critical Changes

### 1. **REMOVED Fields** (Will Cause Rejection)

| Field | Why Removed | Alternative |
|-------|-------------|-------------|
| `issuer_signature` | Redundant (use chain tx signature) | Chain provides issuer auth via tx signature |
| `verification_url` | Centralization/tracking vector | Off-chain verification via IPFS payload |
| `json_cid` / `json_hash` | Duplication | `payload_hint` is canonical reference |

### 2. **payload_hint is Canonical**

- **`payload_hint`** (in credential root) → Points to JSON payload on IPFS
- **`pdf_cid`** (in attributes) → Optional, human-readable PDF only
- **Rule**: Don't duplicate. Use `payload_hint` for structured data, `pdf_cid` for PDF rendering.

### 3. **Encryption Support (Available)**

**Native encryption metadata is NOW supported** in `AcademicCredential` structure.

#### What IS Privacy-Protected:
- ✅ **On-chain commitments** (courses_commitment, grades_commitment, student_commitment) - BLAKE3 hashes only
- ✅ **Subject identity** - Pseudonymous address, not linked to real identity on-chain
- ✅ **No PII on-chain** - Schema validation ensures zero PII in permanent chain state

#### Encryption Options:

**Option A: Public credentials (unencrypted IPFS)**
- ⚠️ IPFS payloads publicly accessible to anyone with the CID
- ⚠️ Full data readable by CID holders
- ✅ Use case: Public records with subject consent

**Option B: Encrypted credentials (recommended for sensitive data)**
- ✅ Native `encryption_meta` field in credential structure
- ✅ IPFS payload encrypted, only authorized parties can decrypt
- ✅ Use case: Private academic records

#### Encryption Implementation:

**Supported Algorithms:**
- `Aes256Gcm` - AES-256-GCM symmetric encryption
- `ChaCha20Poly1305` - ChaCha20-Poly1305 symmetric encryption
- `X25519Aes256Gcm` - X25519 key exchange + AES-256-GCM (recommended)
- `ThresholdEncryption` - Multi-party threshold encryption

**How to use:**
1. Generate shared secret using X25519 key exchange (issuer ↔ subject)
2. Encrypt JSON payload with chosen algorithm
3. Upload encrypted blob to IPFS
4. Set `payload_hint` to encrypted IPFS CID
5. Set `encryption_meta` field with algorithm, key_commitment, and nonce
6. Share decryption capability only with authorized verifiers (via subject)

#### Privacy Model Summary:
- **On-chain**: Zero PII, only commitments and pseudonymous addresses
- **Off-chain (IPFS)**: Sensitive data accessible to CID holders (encrypt if needed)
- **Verification**: Verifiers get IPFS payload from subject/issuer, validate against on-chain commitments

### 4. **Commitment Canonicalization Required**

**Problem**: Two teams hashing same data differently → verification breaks

**Solution**: Follow [SRC-81X-COMMITMENT-CANONICALIZATION.md](../specs/SRC-81X-COMMITMENT-CANONICALIZATION.md)

**Key Rules**:
- Sort object keys lexicographically
- No whitespace
- Domain separators (e.g., `SRC-810-COURSES-v1`)
- BLAKE3 (not SHA-256)
- Output format: `blake3:<hex>` or `0x<hex>`

---

## Allowed Metadata Attributes (Updated)

### Common (All Credentials)

```
✅ pdf_cid          - IPFS CID of PDF (optional)
✅ pdf_hash         - BLAKE3 hash of PDF
✅ pdf_format       - MIME type "application/pdf"
✅ rendered_at      - PDF generation timestamp
✅ environment      - "production" / "staging"
✅ version          - Schema version "1.0"
```

### SRC-810 (Transcript)

```
✅ credential_subtype   - "partial_transcript" / "final_transcript"
✅ academic_year        - "2024-2025"
✅ semester             - "Fall" / "Spring" / "Summer"
✅ term_count           - "8" (number of terms)
✅ issuer_department    - "Office of the Registrar"
✅ signature_method     - "Ed25519" / "multisig"

COMMITMENTS (BLAKE3 with domain separation):
✅ courses_commitment   - BLAKE3("SRC-810-COURSES-v1" || canonical_json)
✅ grades_commitment    - BLAKE3("SRC-810-GRADES-v1" || canonical_json)
✅ student_commitment   - BLAKE3("SRC-810-STUDENT-v1" || canonical_json)
```

### SRC-811 (Diploma)

```
✅ credential_subtype      - "bachelor" / "master" / "doctoral"
✅ graduation_year         - "2025"
✅ graduation_semester     - "Spring"
✅ degree_level            - "undergraduate" / "graduate"
✅ honors_category         - "latin_honors" / "departmental_honors"
✅ issuer_department       - "Office of the Registrar"
✅ signature_method        - "Ed25519"
✅ conferral_ceremony_date - Public event date
✅ diploma_number          - Public serial (if non-PII)

COMMITMENTS:
✅ degree_commitment   - BLAKE3("SRC-811-DEGREE-v1" || canonical_json)
✅ major_commitment    - BLAKE3("SRC-811-MAJOR-v1" || canonical_json)
✅ minor_commitment    - BLAKE3("SRC-811-MINOR-v1" || canonical_json)
✅ honors_commitment   - BLAKE3("SRC-811-HONORS-v1" || canonical_json)
✅ student_commitment  - BLAKE3("SRC-811-STUDENT-v1" || canonical_json)
```

### SRC-812 (Enrollment)

```
✅ enrollment_year         - "2025"
✅ enrollment_semester     - "Fall"
✅ enrollment_status       - "full_time" / "part_time"
✅ program_level           - "undergraduate" / "graduate"
✅ expected_graduation_year - "2029"
✅ issuer_department       - "Office of the Registrar"
✅ signature_method        - "Ed25519"

COMMITMENTS:
✅ enrollment_commitment - BLAKE3("SRC-812-ENROLLMENT-v1" || canonical_json)
✅ program_commitment    - BLAKE3("SRC-812-PROGRAM-v1" || canonical_json)
✅ student_commitment    - BLAKE3("SRC-812-STUDENT-v1" || canonical_json)
```

---

## Explicitly DISALLOWED (Will Cause Hard Rejection)

```
❌ student_name          - Use student_commitment
❌ student_id            - Use student_commitment
❌ ssn                   - NEVER on-chain
❌ email                 - NEVER on-chain
❌ phone                 - NEVER on-chain
❌ courses               - Use courses_commitment
❌ grades                - Use grades_commitment
❌ gpa                   - Use grades_commitment
❌ instructor_name       - Use courses_commitment
❌ date_of_birth         - NEVER on-chain
❌ issuer_signature      - Use chain tx signature
❌ verification_url      - Centralization vector
❌ json_cid / json_hash  - Use payload_hint instead
```

---

## What Verification Team Must Do

### 1. **Decide on Encryption Approach**

Based on your privacy requirements:

**Option A: Public credentials (no encryption needed)**
- Use case: Public academic records with subject consent
- Implementation: Upload JSON payload to IPFS unencrypted, use CID as `payload_hint`
- Privacy: Only commitments are private, full data is publicly verifiable

**Option B: Private credentials (client-side encryption)**
- Use case: Sensitive academic data requiring privacy
- Implementation:
  1. Generate shared secret using X25519 key exchange (issuer ↔ subject)
  2. Encrypt JSON payload with AES-256-GCM
  3. Upload encrypted blob to IPFS
  4. Store CID in `payload_hint`
  5. Share decryption key only with authorized verifiers (via subject)
- Privacy: Full privacy - only authorized parties can decrypt IPFS payload

### 2. **Update Credential Issuance**

#### Before (WRONG):
```json
{
  "metadata": {
    "attributes": [
      {"name": "gpa", "value": "3.87"},
      {"name": "courses", "value": "[{...}]"},
      {"name": "json_cid", "value": "bafybeig..."},
      {"name": "issuer_signature", "value": "0x..."}
    ]
  }
}
```

#### After (CORRECT):
```json
{
  "metadata": {
    "attributes": [
      {"name": "courses_commitment", "value": "blake3:a7f2c9..."},  // Hash
      {"name": "pdf_cid", "value": "bafybeig..."}   // Optional PDF
    ]
  },
  "payload_hint": "bafybeig..."  // Canonical JSON payload (IPFS)
}
```

### 3. **Implement Commitment Canonicalization**

**Required Reading**: [SRC-81X-COMMITMENT-CANONICALIZATION.md](../specs/SRC-81X-COMMITMENT-CANONICALIZATION.md)

**Quick Example** (TypeScript):

```typescript
import { blake3 } from 'blake3';

function canonicalize(obj: any): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  if (typeof obj === 'object' && obj !== null) {
    const keys = Object.keys(obj).sort();  // SORT KEYS
    const pairs = keys
      .filter(k => obj[k] !== null)
      .map(k => `"${k}":${canonicalize(obj[k])}`);
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(obj);
}

function computeCommitment(domain: string, data: any): string {
  const canonical = canonicalize(data);
  const input = domain + canonical;
  const hash = blake3(new TextEncoder().encode(input));
  return `blake3:${Buffer.from(hash).toString('hex')}`;
}

// Usage
const courses = [
  {course_code: "CS101", grade: "A", credits: 3}
];
const commitment = computeCommitment("SRC-810-COURSES-v1", courses);
// Store `commitment` in metadata.attributes
```

**Encryption Example** (TypeScript):

```typescript
import * as nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

// Generate X25519 key pair for encryption
const issuerKeyPair = nacl.box.keyPair();
const subjectPublicKey = getSubjectPublicKey(); // From subject's identity

// Compute shared secret
const sharedSecret = nacl.box.before(subjectPublicKey, issuerKeyPair.secretKey);

// Encrypt JSON payload
const payload = JSON.stringify({
  courses: [{course_code: "CS101", grade: "A"}],
  student: {name: "John Doe", id: "12345"}
});

const nonce = randomBytes(24);
const encrypted = nacl.secretbox(
  new TextEncoder().encode(payload),
  nonce,
  sharedSecret
);

// Upload to IPFS
const ipfsCid = await ipfs.add(encrypted);

// Create credential with encryption metadata
const credential = {
  // ... other fields ...
  payload_hint: ipfsCid,
  encryption_meta: {
    algorithm: "X25519Aes256Gcm",
    key_commitment: blake3(sharedSecret), // For verification
    nonce: Array.from(nonce)
  }
};
```

### 4. **Client-Side Pre-Validation**

Validate BEFORE submitting to avoid rejected transactions:

```typescript
const ALLOWED_KEYS: Record<number, string[]> = {
  810: ["pdf_cid", "pdf_hash", "courses_commitment", "grades_commitment", "student_commitment", ...],
  811: ["pdf_cid", "pdf_hash", "degree_level", "degree_commitment", ...],
  812: ["pdf_cid", "pdf_hash", "enrollment_status", "enrollment_commitment", ...]
};

function validateAttributes(subcode: number, attributes: any[]): void {
  const allowed = ALLOWED_KEYS[subcode];
  for (const attr of attributes) {
    if (!allowed.includes(attr.name)) {
      throw new Error(`Disallowed key: ${attr.name}`);
    }
  }
}
```

### 5. **Update Verification Logic**

When verifying credentials:

```typescript
// Verify commitment
const coursesCommitment = credential.metadata.attributes
  .find(a => a.name === "courses_commitment")?.value;

// Get preimage from IPFS (via payload_hint)
const payload = await fetchIPFS(credential.payload_hint);
const actualCourses = payload.courses;

// Recompute commitment
const recomputed = computeCommitment("SRC-810-COURSES-v1", actualCourses);

if (recomputed === coursesCommitment) {
  // ✅ Courses authentic and unmodified
}
```

---

## Error Handling

### Error Format

```json
{
  "success": false,
  "error": "Schema validation failed: Disallowed attribute key 'student_name'. Allowed keys: pdf_cid, pdf_hash, ..."
}
```

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Disallowed attribute key 'X'` | Key not in allowlist | Remove key or use commitment |
| `Disallowed attribute key 'issuer_signature'` | Redundant field removed | Remove (chain provides auth) |
| `Disallowed attribute key 'verification_url'` | Centralization vector | Remove (verify via IPFS) |
| `Disallowed attribute key 'json_cid'` | Duplicate of payload_hint | Remove (use payload_hint) |
| `Attribute 'X' value too long` | Value > 500 bytes | Use commitment for large data |

---

## Backward Compatibility

**Existing credentials (issued before activation height) are NOT affected.**

- Old credentials with PII remain valid
- Validation only applies to NEW credentials
- No migration needed

---

## Testing

### Test Valid Credential

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "metadata": {
        "title": "Academic Transcript",
        "attributes": [
          {"name": "pdf_cid", "value": "bafybeig..."},
          {"name": "courses_commitment", "value": "blake3:a7f2c9..."}
        ]
      },
      "payload_hint": "bafybeig..."
    }],
    "id": 1
  }'
```

**Expected**: Success ✅

### Test Invalid Credential

```bash
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
```

**Expected**: Error: `"Schema validation failed: Disallowed attribute key 'student_name'"`

---

## Resources

### Documentation
- **Commitment Canonicalization**: [SRC-81X-COMMITMENT-CANONICALIZATION.md](../specs/SRC-81X-COMMITMENT-CANONICALIZATION.md)
- **Full Schema Details**: [SRC-81X-SCHEMA-VALIDATION.md](../specs/SRC-81X-SCHEMA-VALIDATION.md)
- **Privacy Analysis**: [SRC-TOKEN-FAMILIES-PRIVACY-ANALYSIS.md](../specs/SRC-TOKEN-FAMILIES-PRIVACY-ANALYSIS.md)

### Reference Implementations
- TypeScript: See commitment canonicalization spec
- Rust: See commitment canonicalization spec

### Contact
- Schema questions: Chain core team
- Integration support: Developer relations
- Bug reports: File in chain repository

---

**Document Version**: 2.0 (Updated after security review)
**Last Updated**: 2026-02-01
**Status**: Production-Ready
**Review**: Passed security audit with fixes applied
