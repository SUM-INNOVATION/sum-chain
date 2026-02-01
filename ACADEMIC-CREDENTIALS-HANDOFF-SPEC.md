# SUM Chain → SUMail Academic Credentials Handoff Specification
## TESTNET ONLY / FICTIONAL DEMO PROOF OF CONCEPT

**Version:** 1.0
**Date:** 2026-02-01
**Status:** DEMO SPECIFICATION - NOT FOR PRODUCTION USE

---

## ⚠️ CRITICAL DISCLAIMERS

1. **THIS IS A TESTNET-ONLY DEMONSTRATION**
2. **ALL CREDENTIALS ARE FICTIONAL AND FOR TESTING PURPOSES ONLY**
3. **NO REAL ACADEMIC INSTITUTIONS ARE INVOLVED**
4. **DEMO ISSUERS ARE NOT ACCREDITED AND HAVE NO LEGAL AUTHORITY**
5. **DO NOT USE FOR ACTUAL CREDENTIAL VERIFICATION**

---

## A) Roles + Invariants

### Role Definitions

#### 1. **Issuer** (Educational Institution)
**Capabilities:**
- Register as educational issuer (one-time, on-chain)
- Issue enrollment records (SRC-812)
- Issue transcript records (SRC-810)
- Issue degree records (SRC-811)
- Amend credentials (with student acknowledgment)
- Revoke credentials (with on-chain event)

**Restrictions:**
- CANNOT view encrypted credential payloads without student grant
- CANNOT disclose credentials to verifiers
- CANNOT transfer credentials (soulbound enforcement)
- CANNOT bypass student-controlled disclosure

**On-Chain State:**
```rust
IssuerRegistry {
    address: Address,
    issuer_type: IssuerType::Educational,
    display_name: String,  // "SUM Hypothesis Institute Technology (DEMO)"
    issuer_commitment: [u8; 32],  // SHA256(institution_details)
    jurisdiction_code: String,  // ISO 3166-1 alpha-2
    registration_timestamp: Timestamp,
    is_active: bool,
    policy_id: [u8; 32],  // Governance policy
}
```

#### 2. **Student** (Credential Subject)
**Capabilities:**
- Receive credentials (to their address)
- Control disclosure (grant/revoke verifier access)
- Create scoped grants (specific courses, time-bounded)
- Revoke grants at any time
- Acknowledge credential amendments

**Restrictions:**
- CANNOT forge credentials (cryptographically impossible)
- CANNOT modify issued credentials
- CANNOT transfer credentials (soulbound)
- CANNOT bypass issuer signature verification

**On-Chain State:**
```rust
Subject {
    address: Address,
    subject_id: [u8; 32],  // Identity anchor
    identity_commitment: [u8; 32],  // Private identity data hash
    recovery_addresses: Vec<Address>,  // Optional recovery
    created_at: Timestamp,
}
```

#### 3. **Verifier** (Third Party)
**Capabilities:**
- Request access to credentials (from student)
- Verify credential authenticity (issuer signature)
- Verify credential integrity (commitment matching)
- Check revocation status (on-chain registry)
- Validate grants (check student authorization)

**Restrictions:**
- CANNOT access credentials without student grant
- CANNOT bypass student disclosure controls
- CANNOT forge or modify credentials
- CANNOT access revoked credentials

**No On-Chain State** (stateless verification)

---

### Invariants (Hard Rules)

#### I1: Forgery Prevention
```
∀ credential C:
  C.issuer_signature = Sign(issuer_privkey, Hash(C.payload))
  → Student CANNOT create valid C without issuer_privkey
```

#### I2: Disclosure Control
```
∀ credential C with encrypted_payload:
  Verifier can decrypt C.encrypted_payload
  ↔ ∃ valid Grant G where:
    - G.student == C.subject_address
    - G.verifier == Verifier.address
    - G.credential_id == C.id
    - G.is_active == true
    - G.expires_at > current_time
```

#### I3: Soulbound Enforcement
```
∀ credential C:
  Transfer(C.subject_address → other_address) = REVERT
  ∧ C.subject_address is immutable after issuance
```

#### I4: Issuer Cannot Disclose
```
∀ credential C:
  Issuer can create C
  ∧ Issuer CANNOT decrypt C.encrypted_payload (student holds encryption key)
  ∧ Issuer CANNOT grant Verifier access to C
```

#### I5: Verifier Cannot Bypass
```
∀ verifier V, credential C:
  V.can_access(C) = true
  ↔ (∃ valid Grant) ∨ (C.encrypted_payload == null && C.is_public)
```

---

## B) Token/Claim Types (3 Required)

### 1. Enrollment Record (SRC-812)

**Purpose:** Verify that a student is/was enrolled in a specific program during a specific term.

**Required Fields:**
```json
{
  "credential_type": "EnrollmentVerification",
  "subcode": 812,
  "student_address": "base58_address",
  "program": "Computer Science BS",
  "term": "Fall 2025",
  "enrollment_date": 1725177600000,  // Unix ms
  "status": "Active",  // Active | OnLeave | Graduated | Withdrawn
  "expected_graduation": 1748822400000,  // Unix ms, 0 = ongoing
  "issuer_address": "base58_address",
  "credential_id": "0x...",
  "issued_at": 1735689600000
}
```

**Issuer-Only Mutable Fields:**
- `status` (can change: Active → Graduated, Active → Withdrawn)
- `expected_graduation` (can be updated if program extended)

**Revocation Behavior:**
- Enrollment records can be revoked if enrollment was fraudulent or administratively cancelled
- Revocation emits `CredentialRevoked` event with reason
- Revoked enrollment records fail verification checks

**Linking Strategy:**
- Links to student via `student_address`
- Links to issuer via `issuer_address`
- Can be referenced by transcript/degree via `enrollment_credential_id` field

---

### 2. Transcript Record (SRC-810)

**Purpose:** Provide official academic record with courses, grades, and cumulative metrics.

**Design Decision:** One token per term/year with multiple course claims (more efficient than per-course tokens).

**Required Fields:**
```json
{
  "credential_type": "AcademicTranscript",
  "subcode": 810,
  "student_address": "base58_address",
  "academic_period": "Fall 2025",
  "issue_date": 1735689600000,
  "courses": [
    {
      "course_code": "MOUSE101",
      "course_name": "Mousing I",
      "grade": "A+",
      "credits": 4.0,
      "term": "Fall 2025"
    },
    {
      "course_code": "MOUSE102",
      "course_name": "Mousing II",
      "grade": "A",
      "credits": 4.0,
      "term": "Fall 2025"
    }
  ],
  "gpa": 3.95,
  "total_credits": 8.0,
  "cumulative_gpa": 3.95,
  "cumulative_credits": 8.0,
  "issuer_address": "base58_address",
  "credential_id": "0x...",
  "issued_at": 1735689600000,
  "encrypted_payload_cid": "Qm...",  // IPFS CID of encrypted full transcript
  "transcript_commitment": "0x..."  // SHA256(canonical_json(courses))
}
```

**Issuer-Only Mutable Fields:**
- `courses` (can add/modify grades within grade change period)
- `gpa` / `cumulative_gpa` (recalculated when courses change)
- Amendment requires student acknowledgment (two-phase commit)

**Revocation Behavior:**
- Full transcript revocation if academic fraud discovered
- Individual course amendments via new transcript version
- Old versions remain on-chain but marked as superseded

**Linking Strategy:**
- Links to student via `student_address`
- Links to enrollment via optional `enrollment_credential_id`
- Links to degree via `prerequisite_for_degree_id`

---

### 3. Degree Record (SRC-811)

**Purpose:** Official proof of degree conferral.

**Required Fields:**
```json
{
  "credential_type": "Diploma",
  "subcode": 811,
  "student_address": "base58_address",
  "degree_type": "DrMeow",  // BS | BA | MS | MA | MBA | PhD | Custom
  "major": "Advanced Mousing Studies",
  "minor": null,  // optional
  "graduation_date": 1735689600000,
  "conferral_date": 1735689600000,
  "honors": "Summa Cum Laude",  // optional
  "final_gpa": 3.95,
  "total_credits": 120.0,
  "issuer_address": "base58_address",
  "credential_id": "0x...",
  "issued_at": 1735689600000,
  "transcript_credential_ids": ["0x...", "0x..."],  // Supporting transcripts
  "degree_commitment": "0x..."  // SHA256(degree_details)
}
```

**Issuer-Only Mutable Fields:**
- NONE (degrees are immutable once issued)
- Errors require revocation + reissuance

**Revocation Behavior:**
- Revocable only in extreme cases (fraud, clerical error)
- Revocation emits event with detailed reason
- Cannot be amended (must revoke + reissue)

**Linking Strategy:**
- Links to student via `student_address`
- Links to transcripts via `transcript_credential_ids`
- Can be verified independently of transcripts

---

## C) Data Layout and Crypto Commitments

### Canonical JSON Schema

**Field Ordering Rules:**
1. Sort all object keys alphabetically
2. No whitespace (minified JSON)
3. UTF-8 encoding
4. Numbers as primitives (not strings)
5. Timestamps in Unix milliseconds (integers)

**Example Canonical Form:**
```json
{"academic_period":"Fall 2025","courses":[{"course_code":"MOUSE101","course_name":"Mousing I","credits":4.0,"grade":"A+","term":"Fall 2025"}],"credential_id":"0x1234","credential_type":"AcademicTranscript","cumulative_credits":8.0,"cumulative_gpa":3.95,"gpa":3.95,"issue_date":1735689600000,"issued_at":1735689600000,"issuer_address":"abc123","student_address":"xyz789","subcode":810,"total_credits":8.0,"transcript_commitment":"0xabcd"}
```

### Hashing Rules

**Domain Separation Tags:**
```
ENROLLMENT_COMMITMENT = "SUM_CHAIN_ENROLLMENT_V1"
TRANSCRIPT_COMMITMENT = "SUM_CHAIN_TRANSCRIPT_V1"
DEGREE_COMMITMENT = "SUM_CHAIN_DEGREE_V1"
```

**Commitment Calculation:**
```python
import json
import hashlib

def calculate_commitment(credential_data, domain_tag):
    # 1. Sort keys alphabetically
    canonical = json.dumps(credential_data, sort_keys=True, separators=(',', ':'))

    # 2. Apply domain separation
    message = f"{domain_tag}||{canonical}"

    # 3. Hash with SHA-256
    commitment = hashlib.sha256(message.encode('utf-8')).hexdigest()

    return commitment
```

**Example:**
```python
transcript_data = {
    "student_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
    "academic_period": "Fall 2025",
    "courses": [
        {"course_code": "MOUSE101", "grade": "A+", "credits": 4.0}
    ],
    "gpa": 4.0
}

commitment = calculate_commitment(transcript_data, "SUM_CHAIN_TRANSCRIPT_V1")
# → "0x7f3b9c..."
```

### On-Chain vs Off-Chain Storage

**On-Chain (Public Blockchain):**
```rust
Credential {
    credential_id: [u8; 32],          // Unique ID
    subcode: u16,                     // 810/811/812
    subject_address: Address,         // Student
    issuer_address: Address,          // Institution
    credential_commitment: [u8; 32],  // Hash of full payload
    issued_at: Timestamp,
    valid_from: Timestamp,
    expiry: Timestamp,                // 0 = no expiry
    is_revoked: bool,
    revocation_reason: Option<String>,
    policy_id: [u8; 32],
    metadata_cid: Option<String>,     // IPFS CID → encrypted payload
}
```

**Off-Chain (IPFS - Encrypted):**
```json
{
  "version": "1.0",
  "credential_type": "AcademicTranscript",
  "encryption": {
    "algorithm": "AES-256-GCM",
    "key_derivation": "student_public_key_encryption"
  },
  "payload": {
    "student_name": "Yuumi de Cat (DEMO)",
    "student_id": "DEMO-2025-001",
    "courses": [...],
    "detailed_grades": {...},
    "issuer_notes": "FICTIONAL DEMO - NOT REAL"
  },
  "disclaimer": "THIS IS A FICTIONAL DEMO CREDENTIAL. NOT FOR ACTUAL USE."
}
```

**Encryption Scheme:**
- Student generates encryption keypair (separate from signing key)
- Student shares public encryption key in subject registry
- Issuer encrypts full payload with student's public key
- Encrypted payload uploaded to IPFS
- CID stored on-chain in `metadata_cid`
- Only student can decrypt (has private key)

---

## D) Student-Controlled Disclosure Mechanism

### Access Model Architecture

**Core Principle:** Student encrypts payload → Only student can grant decryption access.

### Verifier Public Key Representation

**On-Chain Verifier Registry:**
```rust
VerifierProfile {
    verifier_address: Address,
    public_key: [u8; 32],        // X25519 encryption key
    organization: String,         // "ACME Corp HR"
    purpose: String,              // "Employment Verification"
    registered_at: Timestamp,
}
```

Verifiers register their encryption public key on-chain via:
```
verifier_registerProfile(public_key, organization, purpose)
```

### Grant Representation

**On-Chain Grant Registry:**
```rust
AccessGrant {
    grant_id: [u8; 32],              // Unique grant ID
    student_address: Address,         // Who issued grant
    verifier_address: Address,        // Who receives access
    credential_id: [u8; 32],         // Which credential
    scope: GrantScope,               // Full | Partial (specific fields)
    granted_at: Timestamp,
    expires_at: Timestamp,           // Unix ms, 0 = no expiry
    is_active: bool,                 // Student can revoke
    encrypted_key: Vec<u8>,          // Decryption key encrypted with verifier's pubkey
}

enum GrantScope {
    FullCredential,
    PartialFields {
        fields: Vec<String>,  // ["gpa", "major", "graduation_date"]
    },
    SpecificCourses {
        course_codes: Vec<String>,  // ["MOUSE101", "MOUSE103"]
    },
}
```

**Grant Creation Flow:**
```python
def create_grant(student_privkey, verifier_address, credential_id, scope, duration_days):
    # 1. Student retrieves verifier's public key
    verifier_pubkey = get_verifier_profile(verifier_address).public_key

    # 2. Student retrieves credential decryption key (from their keystore)
    credential_key = get_credential_key(student_privkey, credential_id)

    # 3. Encrypt credential key with verifier's public key
    encrypted_key = encrypt(credential_key, verifier_pubkey)  # X25519 + ChaCha20

    # 4. Calculate expiry
    expires_at = current_time() + (duration_days * 86400 * 1000)

    # 5. Submit grant transaction
    grant_tx = {
        "private_key": student_privkey,
        "verifier_address": verifier_address,
        "credential_id": credential_id,
        "scope": scope,
        "expires_at": expires_at,
        "encrypted_key": encrypted_key
    }

    return rpc_call("credential_createGrant", [grant_tx])
```

### Scoped Sharing (Subset of Courses)

**Partial Field Disclosure:**
```python
# Grant access to only GPA and major (not course list)
grant = create_grant(
    student_privkey=STUDENT_KEY,
    verifier_address="EmployerAddressXYZ",
    credential_id="0x1234...",
    scope={
        "type": "PartialFields",
        "fields": ["gpa", "major", "graduation_date"]
    },
    duration_days=30
)
```

**Specific Course Disclosure:**
```python
# Grant access to only specific courses
grant = create_grant(
    student_privkey=STUDENT_KEY,
    verifier_address="GradSchoolAdmissionsXYZ",
    credential_id="0x1234...",
    scope={
        "type": "SpecificCourses",
        "course_codes": ["MOUSE101", "MOUSE102"]  # Hide MOUSE103 (B+)
    },
    duration_days=90
)
```

### Time-Bounded Grants

**Automatic Expiry:**
- Grants have `expires_at` timestamp
- Verifiers must check `expires_at > current_time` before accessing
- Expired grants fail verification automatically

**Example:**
```python
# 7-day grant for background check
short_term_grant = create_grant(
    student_privkey=STUDENT_KEY,
    verifier_address="BackgroundCheckCo",
    credential_id="0x1234...",
    scope={"type": "FullCredential"},
    duration_days=7  # Auto-expires after 7 days
)
```

### Grant Revocation

**Student-Initiated Revocation:**
```python
def revoke_grant(student_privkey, grant_id):
    revoke_tx = {
        "private_key": student_privkey,
        "grant_id": grant_id
    }

    return rpc_call("credential_revokeGrant", [revoke_tx])
```

**Events Emitted:**
```
event GrantRevoked {
    grant_id: [u8; 32],
    student_address: Address,
    verifier_address: Address,
    revoked_at: Timestamp,
}
```

**Verifier Must Check:**
```python
def verify_grant_valid(grant_id):
    grant = get_grant(grant_id)

    # Check 1: Grant exists
    assert grant is not None, "Grant not found"

    # Check 2: Grant is active (not revoked)
    assert grant.is_active == True, "Grant revoked by student"

    # Check 3: Grant not expired
    assert grant.expires_at == 0 or grant.expires_at > current_time(), "Grant expired"

    return True
```

---

## E) Soulbound + Co-Ownership Policies

### Non-Transferability Enforcement

**Protocol-Level Enforcement:**
```rust
// In credential transfer function:
fn transfer_credential(from: Address, to: Address, credential_id: [u8; 32]) -> Result<()> {
    // ALWAYS REJECT
    return Err("Credentials are soulbound and cannot be transferred".into());
}

// Credential subject_address is immutable:
impl Credential {
    pub fn set_subject(&mut self, new_subject: Address) -> Result<()> {
        Err("subject_address is immutable".into())
    }
}
```

**Verification Check:**
```python
def verify_soulbound(credential):
    # Credential must be held by subject_address
    assert credential.subject_address == credential.holder_address
    assert credential.transfer_history == []  # No transfers allowed
```

### Policy Modes (Fixed Set)

#### Mode 1: ISSUER_ONLY_MINT
```rust
Policy {
    mode: PolicyMode::IssuerOnlyMint,
    rules: {
        "can_mint": [issuer_address],
        "can_revoke": [issuer_address],
        "can_amend": [issuer_address],  // with student ack
        "can_transfer": [],  // Empty = no one
    }
}
```

**Behavior:**
- Only registered issuer can mint credentials
- Student CANNOT self-mint
- Third parties CANNOT mint

#### Mode 2: ISSUER_ONLY_REVOKE
```rust
Policy {
    mode: PolicyMode::IssuerOnlyRevoke,
    rules: {
        "can_revoke": [issuer_address],
        "can_student_revoke": false,
        "revocation_requires_reason": true,
    }
}
```

**Behavior:**
- Only issuer can revoke credentials
- Student cannot revoke their own credentials
- Revocation must include reason (logged on-chain)

#### Mode 3: STUDENT_ONLY_DISCLOSURE
```rust
Policy {
    mode: PolicyMode::StudentOnlyDisclosure,
    rules: {
        "can_create_grant": [subject_address],  // Only student
        "can_revoke_grant": [subject_address],
        "issuer_can_view": false,
        "public_by_default": false,
    }
}
```

**Behavior:**
- Only student can grant verifier access
- Issuer CANNOT grant access (even though they issued credential)
- Credentials are private by default (encrypted)

#### Mode 4: STUDENT_DELEGATE_VIEW_RIGHTS
```rust
Policy {
    mode: PolicyMode::StudentDelegateViewRights,
    rules: {
        "can_create_grant": [subject_address],
        "grant_scope_options": ["Full", "Partial", "Courses"],
        "grant_max_duration": 31536000000,  // 1 year in ms
        "grant_can_expire": true,
        "grant_can_be_revoked": true,
    }
}
```

**Behavior:**
- Student can create scoped grants (partial fields, specific courses)
- Grants can be time-bounded (max 1 year)
- Student can revoke grants at any time

#### Mode 5: ISSUER_PROPOSE_STUDENT_ACK_UPDATE
```rust
Policy {
    mode: PolicyMode::IssuerProposeStudentAck,
    rules: {
        "can_propose_amendment": [issuer_address],
        "requires_student_signature": true,
        "amendment_timeout": 2592000000,  // 30 days
        "student_can_reject": true,
    }
}
```

**Behavior:**
- Issuer proposes amendment (grade change, correction)
- Amendment sits in "pending" state
- Student must sign to accept (two-phase commit)
- Student can reject or ignore (times out after 30 days)
- Once accepted, new version is issued

**Amendment Flow:**
```python
# Step 1: Issuer proposes amendment
amendment_proposal = propose_amendment(
    issuer_privkey=INSTITUTION_KEY,
    credential_id="0x1234...",
    changes={
        "courses[2].grade": "A-"  # Change grade from B+ to A-
    },
    reason="Grade calculation error corrected"
)
# → Creates PendingAmendment with proposal_id

# Step 2: Student reviews and accepts
accept_amendment(
    student_privkey=STUDENT_KEY,
    proposal_id=amendment_proposal.proposal_id
)
# → New credential version issued with updated data
# → Old version marked as "superseded_by: new_credential_id"
```

---

## F) Revocation + Verification Steps

### Revocation Registry Mechanism

**On-Chain Revocation Storage:**
```rust
RevocationEntry {
    credential_id: [u8; 32],
    revoked_by: Address,  // Must be issuer
    revoked_at: Timestamp,
    reason: String,       // Public reason
    block_height: BlockHeight,
}
```

**Revocation Events:**
```
event CredentialRevoked {
    credential_id: [u8; 32],
    credential_type: u16,  // 810/811/812
    subject_address: Address,
    issuer_address: Address,
    revoked_at: Timestamp,
    reason: String,
}
```

**Revocation Function:**
```python
def revoke_credential(issuer_privkey, credential_id, reason):
    revoke_tx = {
        "private_key": issuer_privkey,
        "credential_id": credential_id,
        "reason": reason  # e.g., "Academic fraud discovered"
    }

    return rpc_call("credential_revoke", [revoke_tx])
```

### Canonical Verifier Checklist

**Complete Verification Flow:**

```python
def verify_credential_complete(credential_id, grant_id=None):
    """
    Canonical credential verification checklist.
    Returns (is_valid: bool, errors: List[str])
    """
    errors = []

    # ═══════════════════════════════════════════════════════════
    # STEP 1: Retrieve credential from chain
    # ═══════════════════════════════════════════════════════════
    credential = rpc_call("credential_get", [credential_id])
    if not credential:
        return (False, ["Credential not found on-chain"])

    # ═══════════════════════════════════════════════════════════
    # STEP 2: Issuer Authenticity
    # ═══════════════════════════════════════════════════════════
    issuer = rpc_call("issuer_get", [credential.issuer_address])
    if not issuer:
        errors.append("Issuer not registered")

    if issuer.issuer_type != "Educational":
        errors.append("Issuer is not an educational institution")

    if not issuer.is_active:
        errors.append("Issuer registration is inactive")

    # ═══════════════════════════════════════════════════════════
    # STEP 3: Token Integrity (Commitment Verification)
    # ═══════════════════════════════════════════════════════════
    if grant_id:
        # Retrieve encrypted payload from IPFS
        encrypted_payload = ipfs_get(credential.metadata_cid)

        # Retrieve grant
        grant = rpc_call("grant_get", [grant_id])
        if not grant:
            errors.append("Grant not found")

        # Decrypt credential key using verifier's private key
        verifier_privkey = get_verifier_privkey()  # From secure storage
        credential_key = decrypt(grant.encrypted_key, verifier_privkey)

        # Decrypt payload
        payload = decrypt_payload(encrypted_payload, credential_key)

        # Verify commitment matches
        calculated_commitment = calculate_commitment(
            payload,
            domain_tag=get_domain_tag(credential.subcode)
        )

        if calculated_commitment != credential.credential_commitment:
            errors.append("Commitment mismatch - payload tampered")

    # ═══════════════════════════════════════════════════════════
    # STEP 4: Revocation Status
    # ═══════════════════════════════════════════════════════════
    revocation = rpc_call("credential_getRevocation", [credential_id])
    if revocation:
        errors.append(f"Credential revoked: {revocation.reason}")

    if credential.is_revoked:
        errors.append("Credential marked as revoked")

    # ═══════════════════════════════════════════════════════════
    # STEP 5: Grant Validity (if using access grant)
    # ═══════════════════════════════════════════════════════════
    if grant_id:
        grant = rpc_call("grant_get", [grant_id])

        # Check grant exists
        if not grant:
            errors.append("Access grant not found")

        # Check grant is for this credential
        if grant.credential_id != credential_id:
            errors.append("Grant is for different credential")

        # Check grant is for this verifier
        verifier_address = get_current_verifier_address()
        if grant.verifier_address != verifier_address:
            errors.append("Grant is for different verifier")

        # Check grant is active
        if not grant.is_active:
            errors.append("Grant has been revoked by student")

        # Check grant not expired
        current_time = get_current_timestamp()
        if grant.expires_at != 0 and grant.expires_at < current_time:
            errors.append("Grant has expired")

    # ═══════════════════════════════════════════════════════════
    # STEP 6: Soulbound Verification
    # ═══════════════════════════════════════════════════════════
    # Credential must be held by subject
    if credential.subject_address != credential.holder_address:
        errors.append("Credential is not held by subject (soulbound violation)")

    # ═══════════════════════════════════════════════════════════
    # STEP 7: Expiry Check
    # ═══════════════════════════════════════════════════════════
    if credential.expiry != 0 and credential.expiry < current_time:
        errors.append("Credential has expired")

    # ═══════════════════════════════════════════════════════════
    # RESULT
    # ═══════════════════════════════════════════════════════════
    is_valid = len(errors) == 0
    return (is_valid, errors)
```

**Quick Reference Checklist:**
- [ ] Credential exists on-chain
- [ ] Issuer is registered and active
- [ ] Issuer type matches credential type (Educational for SRC-81X)
- [ ] Commitment matches decrypted payload
- [ ] Credential not revoked
- [ ] Access grant exists (if encrypted)
- [ ] Grant is active and not expired
- [ ] Grant is for correct verifier
- [ ] Credential is soulbound (held by subject)
- [ ] Credential not expired

---

## G) Demo Mint Script + Disclaimers

### Fictional Demo Issuer Setup

```python
#!/usr/bin/env python3
"""
TESTNET DEMO SCRIPT - NOT FOR PRODUCTION
Mints fictional academic credentials for testing purposes only
"""

import json
import requests
import hashlib
from datetime import datetime

RPC_URL = "http://127.0.0.1:8545"  # Local testnet

# ═══════════════════════════════════════════════════════════════
# DEMO DISCLAIMERS
# ═══════════════════════════════════════════════════════════════
DEMO_DISCLAIMER = """
⚠️  CRITICAL: THIS IS A FICTIONAL DEMONSTRATION ⚠️

1. This issuer is NOT a real educational institution
2. This issuer is NOT accredited by any authority
3. These credentials have NO legal or academic validity
4. DO NOT USE for actual employment or education verification
5. This is TESTNET ONLY for technical demonstration

Issuer: SUM Hypothesis Institute Technology (FICTIONAL)
Status: DEMO / NOT REAL / NOT ACCREDITED
"""

print(DEMO_DISCLAIMER)

# ═══════════════════════════════════════════════════════════════
# Step 1: Register Fictional Institution
# ═══════════════════════════════════════════════════════════════

def register_demo_institution():
    """Register fictional demo institution"""

    # Generate institution key (demo only)
    import secrets
    institution_key = "0x" + secrets.token_hex(32)

    institution_name = "SUM Hypothesis Institute Technology (FICTIONAL DEMO / NOT REAL / NOT ACCREDITED)"

    # Create issuer commitment with demo disclaimer
    commitment_data = f"{institution_name}|XX|DEMO_NOT_REAL"
    issuer_commitment = hashlib.sha256(commitment_data.encode()).hexdigest()

    request = {
        "private_key": institution_key,
        "issuer_type": "Educational",
        "display_name": institution_name,
        "issuer_commitment": issuer_commitment,
        "jurisdiction_code": "XX",  # XX = not a real jurisdiction
        "policy_id": "0" * 64,
        "metadata": {
            "disclaimer": "FICTIONAL DEMO - NOT A REAL INSTITUTION",
            "accreditation": "NONE - NOT ACCREDITED",
            "purpose": "TESTNET DEMONSTRATION ONLY"
        }
    }

    result = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_registerIssuer",
        "params": [request]
    }).json()

    print(f"✓ Registered demo institution: {result}")
    return institution_key

# ═══════════════════════════════════════════════════════════════
# Step 2: Mint Enrollment Record for Yuumi de Cat
# ═══════════════════════════════════════════════════════════════

def mint_demo_enrollment(institution_key):
    """Mint fictional enrollment for Yuumi de Cat"""

    student_address = "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S"  # Yuumi's address

    # Fall 2025 term
    enrollment_date = int(datetime(2025, 9, 1).timestamp() * 1000)
    graduation_date = int(datetime(2025, 12, 20).timestamp() * 1000)

    request = {
        "private_key": institution_key,
        "credential_type": "EnrollmentVerification",
        "subject_address": student_address,
        "program": "Advanced Mousing Studies (DEMO)",
        "term": "Fall 2025",
        "enrollment_date": enrollment_date,
        "expected_graduation": graduation_date,
        "status": "Active",
        "policy_id": "0" * 64,
        "metadata": {
            "student_name": "Yuumi de Cat (DEMO)",
            "disclaimer": "FICTIONAL DEMO STUDENT - NOT REAL"
        }
    }

    result = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    }).json()

    print(f"✓ Enrolled Yuumi de Cat: {result}")
    return result.get("result", {}).get("credential_id")

# ═══════════════════════════════════════════════════════════════
# Step 3: Mint Transcript Record
# ═══════════════════════════════════════════════════════════════

def mint_demo_transcript(institution_key, enrollment_id):
    """Mint fictional transcript with demo courses"""

    student_address = "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S"

    courses = [
        {
            "course_code": "MOUSE101",
            "course_name": "Mousing I (DEMO COURSE)",
            "grade": "A+",
            "credits": 4.0,
            "term": "Fall 2025",
            "instructor": "Prof. Whiskers (FICTIONAL)"
        },
        {
            "course_code": "MOUSE102",
            "course_name": "Mousing II (DEMO COURSE)",
            "grade": "A",
            "credits": 4.0,
            "term": "Fall 2025",
            "instructor": "Prof. Meowington (FICTIONAL)"
        },
        {
            "course_code": "MOUSE103",
            "course_name": "Mousing III (DEMO COURSE)",
            "grade": "B+",
            "credits": 4.0,
            "term": "Fall 2025",
            "instructor": "Prof. Paws (FICTIONAL)"
        }
    ]

    # Calculate demo GPA
    grade_points = {"A+": 4.0, "A": 4.0, "A-": 3.7, "B+": 3.3, "B": 3.0}
    total_points = sum(grade_points[c["grade"]] * c["credits"] for c in courses)
    total_credits = sum(c["credits"] for c in courses)
    gpa = round(total_points / total_credits, 2)

    # Create transcript commitment
    transcript_data = {
        "student_address": student_address,
        "academic_period": "Fall 2025",
        "courses": courses,
        "gpa": gpa,
        "total_credits": total_credits
    }
    transcript_commitment = calculate_commitment(
        transcript_data,
        "SUM_CHAIN_TRANSCRIPT_V1"
    )

    request = {
        "private_key": institution_key,
        "credential_type": "AcademicTranscript",
        "subject_address": student_address,
        "academic_period": "Fall 2025",
        "courses": courses,
        "gpa": gpa,
        "total_credits": total_credits,
        "cumulative_gpa": gpa,
        "cumulative_credits": total_credits,
        "transcript_commitment": transcript_commitment,
        "enrollment_credential_id": enrollment_id,
        "policy_id": "0" * 64,
        "metadata": {
            "student_name": "Yuumi de Cat (DEMO)",
            "disclaimer": "FICTIONAL DEMO TRANSCRIPT - NOT REAL COURSES",
            "institution_disclaimer": "SUM Hypothesis Institute Technology is FICTIONAL"
        }
    }

    result = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    }).json()

    print(f"✓ Issued transcript with courses:")
    for course in courses:
        print(f"    {course['course_code']}: {course['grade']}")
    print(f"  GPA: {gpa}")

    return result.get("result", {}).get("credential_id")

# ═══════════════════════════════════════════════════════════════
# Step 4: Mint Degree Record
# ═══════════════════════════════════════════════════════════════

def mint_demo_degree(institution_key, transcript_id):
    """Mint fictional Dr. Meow degree"""

    student_address = "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S"
    graduation_date = int(datetime(2025, 12, 20).timestamp() * 1000)

    degree_data = {
        "student_address": student_address,
        "degree_type": "DrMeow",
        "major": "Advanced Mousing Studies",
        "graduation_date": graduation_date,
        "final_gpa": 3.78
    }
    degree_commitment = calculate_commitment(
        degree_data,
        "SUM_CHAIN_DEGREE_V1"
    )

    request = {
        "private_key": institution_key,
        "credential_type": "Diploma",
        "subject_address": student_address,
        "degree_type": "DrMeow (FICTIONAL DEGREE)",
        "major": "Advanced Mousing Studies (DEMO FIELD)",
        "graduation_date": graduation_date,
        "final_gpa": 3.78,
        "total_credits": 12.0,
        "honors": "Summa Cum Laude (DEMO)",
        "degree_commitment": degree_commitment,
        "transcript_credential_ids": [transcript_id],
        "policy_id": "0" * 64,
        "metadata": {
            "student_name": "Yuumi de Cat (DEMO)",
            "full_title": "Doctor of Meow in Advanced Mousing Studies",
            "disclaimer": "FICTIONAL DEMO DEGREE - NOT REAL ACCREDITATION",
            "institution_disclaimer": "NOT A REAL INSTITUTION"
        }
    }

    result = requests.post(RPC_URL, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "docclass_issueCredential",
        "params": [request]
    }).json()

    print(f"✓ Conferred Dr. Meow degree: {result}")
    return result.get("result", {}).get("credential_id")

# ═══════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════

def calculate_commitment(data, domain_tag):
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
    message = f"{domain_tag}||{canonical}"
    return "0x" + hashlib.sha256(message.encode('utf-8')).hexdigest()

def main():
    print("\n" + "═" * 70)
    print("DEMO: Academic Credentials for Yuumi de Cat")
    print("TESTNET ONLY - FICTIONAL DEMONSTRATION")
    print("═" * 70 + "\n")

    # Step 1: Register institution
    print("Step 1: Registering fictional institution...")
    institution_key = register_demo_institution()

    # Step 2: Enroll student
    print("\nStep 2: Enrolling Yuumi de Cat...")
    enrollment_id = mint_demo_enrollment(institution_key)

    # Step 3: Issue transcript
    print("\nStep 3: Issuing transcript...")
    transcript_id = mint_demo_transcript(institution_key, enrollment_id)

    # Step 4: Confer degree
    print("\nStep 4: Conferring degree...")
    degree_id = mint_demo_degree(institution_key, transcript_id)

    print("\n" + "═" * 70)
    print("✓ DEMO COMPLETE")
    print("═" * 70)
    print(f"\nCredential IDs:")
    print(f"  Enrollment: {enrollment_id}")
    print(f"  Transcript: {transcript_id}")
    print(f"  Degree:     {degree_id}")
    print(f"\nStudent: Yuumi de Cat (DEMO)")
    print(f"Address: EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S")
    print(f"\n⚠️  REMINDER: These are FICTIONAL credentials for TESTNET ONLY")
    print("═" * 70 + "\n")

if __name__ == "__main__":
    main()
```

---

## OUTPUT FORMATS FOR SUMAIL

### 1. Concise Spec Doc (This Document)
**Location:** `ACADEMIC-CREDENTIALS-HANDOFF-SPEC.md`
**Purpose:** Complete technical specification for SUMail integration

### 2. Example JSON Payloads

#### Enrollment Record Example:
```json
{
  "credential_type": "EnrollmentVerification",
  "subcode": 812,
  "credential_id": "0x3f7a9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "student_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
  "issuer_address": "2MoruEuJ8K1QP7ktggdTjdXsmE6gC5EwF",
  "program": "Advanced Mousing Studies (DEMO)",
  "term": "Fall 2025",
  "enrollment_date": 1725177600000,
  "expected_graduation": 1734652800000,
  "status": "Active",
  "issued_at": 1735689600000,
  "valid_from": 1725177600000,
  "expiry": 0,
  "is_revoked": false,
  "policy_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "metadata": {
    "student_name": "Yuumi de Cat (DEMO)",
    "disclaimer": "FICTIONAL DEMO - NOT REAL"
  }
}
```

#### Transcript Record Example:
```json
{
  "credential_type": "AcademicTranscript",
  "subcode": 810,
  "credential_id": "0x7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c",
  "student_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
  "issuer_address": "2MoruEuJ8K1QP7ktggdTjdXsmE6gC5EwF",
  "academic_period": "Fall 2025",
  "issue_date": 1735689600000,
  "courses": [
    {
      "course_code": "MOUSE101",
      "course_name": "Mousing I (DEMO COURSE)",
      "grade": "A+",
      "credits": 4.0,
      "term": "Fall 2025"
    },
    {
      "course_code": "MOUSE102",
      "course_name": "Mousing II (DEMO COURSE)",
      "grade": "A",
      "credits": 4.0,
      "term": "Fall 2025"
    },
    {
      "course_code": "MOUSE103",
      "course_name": "Mousing III (DEMO COURSE)",
      "grade": "B+",
      "credits": 4.0,
      "term": "Fall 2025"
    }
  ],
  "gpa": 3.78,
  "total_credits": 12.0,
  "cumulative_gpa": 3.78,
  "cumulative_credits": 12.0,
  "transcript_commitment": "0xabc123...",
  "encrypted_payload_cid": "QmYwAPJzv5CZsnA636s8...",
  "issued_at": 1735689600000,
  "is_revoked": false,
  "metadata": {
    "student_name": "Yuumi de Cat (DEMO)",
    "disclaimer": "FICTIONAL DEMO TRANSCRIPT"
  }
}
```

#### Degree Record Example:
```json
{
  "credential_type": "Diploma",
  "subcode": 811,
  "credential_id": "0x1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
  "student_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
  "issuer_address": "2MoruEuJ8K1QP7ktggdTjdXsmE6gC5EwF",
  "degree_type": "DrMeow",
  "major": "Advanced Mousing Studies",
  "graduation_date": 1734652800000,
  "conferral_date": 1734652800000,
  "honors": "Summa Cum Laude (DEMO)",
  "final_gpa": 3.78,
  "total_credits": 12.0,
  "degree_commitment": "0xdef456...",
  "transcript_credential_ids": ["0x7b8c9d..."],
  "issued_at": 1735689600000,
  "is_revoked": false,
  "metadata": {
    "student_name": "Yuumi de Cat (DEMO)",
    "full_title": "Doctor of Meow in Advanced Mousing Studies",
    "disclaimer": "FICTIONAL DEMO DEGREE"
  }
}
```

### 3. Example Verifier Flow (Step-by-Step)

```python
# ═══════════════════════════════════════════════════════════════
# VERIFIER FLOW: Employer verifying Yuumi's degree
# ═══════════════════════════════════════════════════════════════

# Step 1: Verifier registers their encryption key
def verifier_register():
    verifier_privkey, verifier_pubkey = generate_keypair()

    rpc_call("verifier_registerProfile", [{
        "private_key": verifier_privkey,
        "public_key": verifier_pubkey,
        "organization": "ACME Corp HR (DEMO)",
        "purpose": "Employment Verification"
    }])

    return verifier_privkey, verifier_pubkey

# Step 2: Verifier requests access from student
def verifier_request_access(student_address, credential_id):
    # Off-chain: Send request email/notification to student
    send_notification(
        to=student_address,
        message=f"ACME Corp requests access to credential {credential_id}"
    )

# Step 3: Student grants access (30-day grant, GPA + major only)
def student_grant_access(student_privkey, verifier_address, credential_id):
    grant = rpc_call("credential_createGrant", [{
        "private_key": student_privkey,
        "verifier_address": verifier_address,
        "credential_id": credential_id,
        "scope": {
            "type": "PartialFields",
            "fields": ["final_gpa", "major", "graduation_date"]
        },
        "duration_days": 30
    }])

    return grant["result"]["grant_id"]

# Step 4: Verifier retrieves and verifies credential
def verifier_verify_credential(verifier_privkey, credential_id, grant_id):
    # Get credential metadata
    credential = rpc_call("credential_get", [credential_id])

    # Get grant
    grant = rpc_call("grant_get", [grant_id])

    # Decrypt credential key
    credential_key = decrypt(grant["encrypted_key"], verifier_privkey)

    # Retrieve encrypted payload from IPFS
    encrypted_payload = ipfs_get(credential["metadata_cid"])

    # Decrypt payload
    payload = decrypt_payload(encrypted_payload, credential_key)

    # Apply scope filter (only GPA, major, graduation_date)
    filtered_payload = {
        "final_gpa": payload["final_gpa"],
        "major": payload["major"],
        "graduation_date": payload["graduation_date"]
    }

    # Verify commitment
    calculated_commitment = calculate_commitment(
        payload,  # Full payload for commitment
        "SUM_CHAIN_DEGREE_V1"
    )

    assert calculated_commitment == credential["degree_commitment"]

    # Check revocation
    assert not credential["is_revoked"]

    # Check issuer
    issuer = rpc_call("issuer_get", [credential["issuer_address"]])
    assert issuer["is_active"]

    print("✓ Credential verified!")
    print(f"  GPA: {filtered_payload['final_gpa']}")
    print(f"  Major: {filtered_payload['major']}")
    print(f"  Graduated: {filtered_payload['graduation_date']}")

    return filtered_payload

# Full flow
verifier_privkey, verifier_pubkey = verifier_register()
verifier_request_access("EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S", "0x1b2c3d...")
grant_id = student_grant_access(STUDENT_KEY, VERIFIER_ADDR, "0x1b2c3d...")
verified_data = verifier_verify_credential(verifier_privkey, "0x1b2c3d...", grant_id)
```

### 4. Example Student Grant Flow (Step-by-Step)

```python
# ═══════════════════════════════════════════════════════════════
# STUDENT FLOW: Granting access to specific courses
# ═══════════════════════════════════════════════════════════════

# Scenario: Yuumi wants to share only MOUSE101 and MOUSE102 with grad school,
# hiding MOUSE103 (B+ grade)

# Step 1: Student retrieves their credentials
def student_list_credentials(student_address):
    credentials = rpc_call("credential_getBySubject", [student_address])

    for cred in credentials:
        print(f"ID: {cred['credential_id']}")
        print(f"Type: {cred['credential_type']}")
        print(f"Issued: {cred['issued_at']}")

    return credentials

# Step 2: Student creates scoped grant (specific courses only)
def student_create_scoped_grant(student_privkey, verifier_address, transcript_id):
    # Get verifier's public key
    verifier = rpc_call("verifier_getProfile", [verifier_address])
    verifier_pubkey = verifier["public_key"]

    # Get credential decryption key from keystore
    credential_key = get_credential_key(student_privkey, transcript_id)

    # Encrypt credential key with verifier's pubkey
    encrypted_key = encrypt(credential_key, verifier_pubkey)

    # Create grant with course scope
    grant = rpc_call("credential_createGrant", [{
        "private_key": student_privkey,
        "verifier_address": verifier_address,
        "credential_id": transcript_id,
        "scope": {
            "type": "SpecificCourses",
            "course_codes": ["MOUSE101", "MOUSE102"]  # Exclude MOUSE103
        },
        "duration_days": 90,  # 90-day access
        "encrypted_key": encrypted_key
    }])

    print(f"✓ Grant created: {grant['result']['grant_id']}")
    print(f"  Access: MOUSE101, MOUSE102 only")
    print(f"  Duration: 90 days")
    print(f"  Verifier: {verifier_address}")

    return grant["result"]["grant_id"]

# Step 3: Student revokes grant (if needed)
def student_revoke_grant(student_privkey, grant_id):
    revoke = rpc_call("credential_revokeGrant", [{
        "private_key": student_privkey,
        "grant_id": grant_id
    }])

    print(f"✓ Grant {grant_id} revoked")
    return revoke

# Step 4: Student views active grants
def student_view_grants(student_address):
    grants = rpc_call("grant_listByStudent", [student_address])

    for grant in grants:
        print(f"Grant ID: {grant['grant_id']}")
        print(f"  Verifier: {grant['verifier_address']}")
        print(f"  Credential: {grant['credential_id']}")
        print(f"  Scope: {grant['scope']}")
        print(f"  Expires: {grant['expires_at']}")
        print(f"  Active: {grant['is_active']}")

    return grants

# Full student flow
credentials = student_list_credentials("EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S")
transcript_id = credentials[1]["credential_id"]  # Transcript
grad_school_address = "GradSchoolVerifierXYZ..."

grant_id = student_create_scoped_grant(
    STUDENT_KEY,
    grad_school_address,
    transcript_id
)

# Later: revoke access
# student_revoke_grant(STUDENT_KEY, grant_id)
```

### 5. Events/API Surface for SUMail

#### Events to Listen To:

```solidity
// Credential issuance events
event CredentialIssued {
    credential_id: [u8; 32],
    credential_type: u16,  // 810/811/812
    subject_address: Address,
    issuer_address: Address,
    issued_at: Timestamp,
}

// Credential revocation events
event CredentialRevoked {
    credential_id: [u8; 32],
    subject_address: Address,
    issuer_address: Address,
    revoked_at: Timestamp,
    reason: String,
}

// Access grant events
event GrantCreated {
    grant_id: [u8; 32],
    student_address: Address,
    verifier_address: Address,
    credential_id: [u8; 32],
    scope: GrantScope,
    expires_at: Timestamp,
}

event GrantRevoked {
    grant_id: [u8; 32],
    student_address: Address,
    verifier_address: Address,
    revoked_at: Timestamp,
}

// Amendment events
event AmendmentProposed {
    proposal_id: [u8; 32],
    credential_id: [u8; 32],
    issuer_address: Address,
    proposed_at: Timestamp,
}

event AmendmentAccepted {
    proposal_id: [u8; 32],
    credential_id: [u8; 32],
    new_credential_id: [u8; 32],
    student_address: Address,
    accepted_at: Timestamp,
}
```

#### RPC Methods for SUMail:

```python
# Credential queries
credential_get(credential_id) → Credential
credential_getBySubject(student_address) → List[Credential]
credential_getByIssuer(issuer_address) → List[Credential]
credential_isRevoked(credential_id) → bool

# Issuer queries
issuer_get(issuer_address) → IssuerRegistry
issuer_canIssue(issuer_address, credential_type) → bool
issuer_listActive() → List[IssuerRegistry]

# Grant management
grant_get(grant_id) → AccessGrant
grant_listByStudent(student_address) → List[AccessGrant]
grant_listByVerifier(verifier_address) → List[AccessGrant]
grant_isValid(grant_id) → bool

# Verification
credential_verify(credential_id, grant_id?) → VerificationResult
commitment_verify(payload, commitment, domain_tag) → bool

# Write operations
credential_createGrant(request) → grant_id
credential_revokeGrant(grant_id) → tx_hash
credential_revoke(credential_id, reason) → tx_hash
```

#### WebSocket Subscription Examples:

```javascript
// Subscribe to credentials for a student
ws.subscribe({
  method: "credential_subscribeBySubject",
  params: ["EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S"]
}, (credential) => {
  console.log("New credential issued:", credential);
});

// Subscribe to grants for a verifier
ws.subscribe({
  method: "grant_subscribeByVerifier",
  params: ["VerifierAddressXYZ"]
}, (grant) => {
  console.log("New grant received:", grant);
});

// Subscribe to revocations
ws.subscribe({
  method: "credential_subscribeRevocations",
  params: []
}, (revocation) => {
  console.log("Credential revoked:", revocation);
});
```

---

## FINAL REMINDERS

1. **This is TESTNET ONLY** - Do not deploy to production
2. **Fictional credentials** - No real academic value
3. **Demo disclaimers required** - Must be in all payloads
4. **Security audit required** - Before any mainnet deployment
5. **Encryption is critical** - Student privacy depends on it
6. **Test all verification flows** - Before trusting credentials
7. **Monitor revocation events** - Credentials can be invalidated
8. **Grant management is key** - Students must control disclosure

---

**END OF SPECIFICATION**

*Version 1.0 - 2026-02-01*
*TESTNET DEMO / NOT FOR PRODUCTION USE*
