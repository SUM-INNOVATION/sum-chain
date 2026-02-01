# Academic Credentials Implementation Addendum
## Answers to SUMail Gateway Questions

**Date:** 2026-02-01
**Version:** 1.0
**Status:** DEFINITIVE IMPLEMENTATION GUIDE

This document provides authoritative answers to the SUMail Gateway team's questions about the academic credentials specification, based on the actual SUM Chain implementation.

---

## C1: Commitment Verification Data Source

### Question
*"Is the full JSON credential payload stored on-chain, or only on IPFS? If on-chain, what RPC method returns it? If IPFS, how does commitment verification work?"*

### Answer

**ACTUAL IMPLEMENTATION:**

The credential structure stored on-chain is:

```rust
pub struct AcademicCredential {
    pub credential_id: CredentialId,
    pub subject_address: Address,
    pub subcode: DocSubcode,  // 810/811/812
    pub subject_commitment: [u8; 32],
    pub issuer: Address,
    pub institution_id: String,
    pub jurisdiction: String,
    pub schema_hash: [u8; 32],
    pub content_commitment: [u8; 32],  // ← COMMITMENT HASH
    pub metadata: CredentialMetadata,   // ← PUBLIC METADATA (non-PII)
    pub issued_at: Timestamp,
    pub valid_from: Timestamp,
    pub expires_at: Timestamp,
    pub payload_hash: Option<[u8; 32]>,
    pub payload_hint: Option<String>,   // ← IPFS CID or storage URL
    pub issuer_signature: [u8; 64],
    pub issuer_key_id: String,
    pub revocation_status: RevocationStatus,
    pub superseded_by: Option<CredentialId>,
}

pub struct CredentialMetadata {
    pub title: String,              // e.g., "Bachelor of Science in CS"
    pub credential_type: String,    // e.g., "undergraduate_transcript"
    pub program: Option<String>,    // e.g., "Computer Science"
    pub issue_date: String,
    pub completion_date: Option<String>,
    pub attributes: Vec<CredentialAttribute>,  // Public non-PII fields
}
```

**Key Points:**

1. **On-Chain Storage:**
   - ✅ `CredentialMetadata` (public non-PII data like degree title, program, dates)
   - ✅ `content_commitment` (hash of full credential data)
   - ✅ `payload_hint` (optional IPFS CID or URL to encrypted payload)

2. **Off-Chain Storage (IPFS via `payload_hint`):**
   - Full JSON with PII (student name, SSN, detailed grades)
   - Can be encrypted or unencrypted depending on use case

3. **RPC Method to Retrieve Credential:**
   ```json
   {
     "jsonrpc": "2.0",
     "method": "docclass_getCredential",
     "params": ["0x1234...credential_id"],
     "id": 1
   }
   ```

   **Returns:** Full `AcademicCredential` struct including `metadata` and `payload_hint`

4. **Commitment Verification Flow:**
   ```python
   # Step 1: Get on-chain credential
   credential = rpc_call("docclass_getCredential", [credential_id])

   # Step 2: Retrieve full payload (if payload_hint exists)
   if credential.payload_hint:
       full_payload = ipfs_get(credential.payload_hint)
   else:
       # Use on-chain metadata as canonical data
       full_payload = credential.metadata

   # Step 3: Calculate commitment from full payload
   calculated_commitment = blake3(
       COMMITMENT_DOMAIN_SEP +
       schema_hash +
       canonical_json(full_payload) +
       salt
   )

   # Step 4: Verify matches on-chain commitment
   assert calculated_commitment == credential.content_commitment
   ```

**FOR SUMAIL GATEWAY:**

- **Authoritative Source:** On-chain credential via `docclass_getCredential`
- **Full JSON:** Available in `credential.metadata` (public) + optionally `payload_hint` (IPFS)
- **Commitment Verification:** Gateway can verify on-chain `content_commitment` matches the payload they render
- **PDF Generation:** Can use `credential.metadata` + `payload_hint` data to generate PDF

---

## C2: PDF CID Storage Location

### Question
*"The on-chain struct has `metadata_cid` but we need to store a PDF CID. Can we repurpose it? If not, what field should we use?"*

### Answer

**ACTUAL IMPLEMENTATION:**

The field is called `payload_hint`, not `metadata_cid`:

```rust
pub payload_hint: Option<String>,  // Optional storage hint (IPFS CID, URL, etc.)
```

**Purpose:** Flexible storage pointer that can reference:
- IPFS CID of encrypted JSON payload
- IPFS CID of rendered PDF
- HTTP URL to document
- Any other storage identifier

**FOR SUMAIL GATEWAY:**

### Option 1: Single CID Approach (Recommended for Simplicity)
```rust
// Store PDF CID directly in payload_hint
credential.payload_hint = Some("QmPDFCIDHere...")
```

**Pros:**
- Simple, uses existing field
- No schema changes needed
- PDF is the primary verifier-facing format

**Cons:**
- No separate storage for raw JSON + PDF simultaneously

### Option 2: Extended Metadata Approach (Recommended for Flexibility)
```rust
// Use CredentialMetadata.attributes for additional CIDs
credential.metadata.attributes = vec![
    CredentialAttribute {
        name: "json_payload_cid".to_string(),
        value: "QmJSONPayloadCID...".to_string(),
    },
    CredentialAttribute {
        name: "pdf_cid".to_string(),
        value: "QmPDFRenderedCID...".to_string(),
    },
    CredentialAttribute {
        name: "pdf_hash".to_string(),
        value: "0xblake3hash...".to_string(),
    },
];
```

**Pros:**
- Can store multiple document formats
- Extensible for future formats (XML, HTML, etc.)
- Metadata is publicly queryable

**Cons:**
- Slightly more complex parsing

### Recommendation:

Use **Option 2** with this schema:

```json
{
  "credential_id": "0x1234...",
  "metadata": {
    "title": "Doctor of Meow in Advanced Mousing Studies",
    "credential_type": "diploma",
    "program": "Advanced Mousing Studies",
    "issue_date": "2025-12-20",
    "attributes": [
      {
        "name": "pdf_cid",
        "value": "QmYwAPJzv5CZsnA636s8..."
      },
      {
        "name": "pdf_hash",
        "value": "0xblake3hashofpdf..."
      },
      {
        "name": "pdf_format",
        "value": "application/pdf"
      },
      {
        "name": "rendered_at",
        "value": "1735689600000"
      }
    ]
  },
  "payload_hint": "QmYwAPJzv5CZsnA636s8..."  // Points to PDF
}
```

---

## C3: RPC Endpoint Details

### Question
*"What is the RPC base URL for testnet? What are the exact response schemas?"*

### Answer

**TESTNET RPC ENDPOINTS:**

Based on the validator configuration:

```
V1 (Validator 1): http://100.124.197.122:8545
V2 (Validator 2): http://100.84.189.95:8545
Local (for testing): http://127.0.0.1:8545
```

**Protocol:** JSON-RPC 2.0

**Example Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "docclass_getCredential",
  "params": ["0x1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c"],
  "id": 1
}
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "credential_id": "0x1b2c3d...",
    "subject_address": "EgHb6jcqGdngzrEAcoYo4KUKvbNDkvC3S",
    "subcode": 811,
    "subject_commitment": "0xabc123...",
    "issuer": "2MoruEuJ8K1QP7ktggdTjdXsmE6gC5EwF",
    "institution_id": "SUM_HYPO_INST",
    "jurisdiction": "XX",
    "schema_hash": "0xdef456...",
    "content_commitment": "0x789abc...",
    "metadata": {
      "title": "Doctor of Meow in Advanced Mousing Studies",
      "credential_type": "diploma",
      "program": "Advanced Mousing Studies",
      "issue_date": "2025-12-20",
      "completion_date": "2025-12-20",
      "attributes": [
        {
          "name": "gpa",
          "value": "3.78"
        },
        {
          "name": "honors",
          "value": "Summa Cum Laude"
        },
        {
          "name": "pdf_cid",
          "value": "QmPDFCID..."
        }
      ]
    },
    "issued_at": 1735689600000,
    "valid_from": 1735689600000,
    "expires_at": 0,
    "payload_hash": null,
    "payload_hint": "QmPDFCID...",
    "issuer_signature": "0x1234567890abcdef...(128 hex chars)",
    "issuer_key_id": "key-2025-001",
    "revocation_status": 0,
    "superseded_by": null
  },
  "id": 1
}
```

**FULL API REFERENCE:**

```python
# Credential Queries
docclass_getCredential(credential_id: str) → AcademicCredential
docclass_getCredentialsBySubject(subject_address: str, subcode?: int) → List[AcademicCredential]
docclass_getCredentialsByIssuer(issuer_address: str, subcode?: int) → List[AcademicCredential]
docclass_isCredentialValid(credential_id: str) → bool

# Issuer Queries
docclass_getIssuer(issuer_address: str) → IssuerInfo
docclass_getIssuers() → List[IssuerInfo]
docclass_getIssuersByJurisdiction(jurisdiction: str) → List[IssuerInfo]
docclass_canIssue(issuer_address: str, subcode: int) → bool

# System Info
docclass_getConfig() → DocClassConfig
docclass_getSummary() → DocClassSummary

# Identity (SRC-801)
docclass_getIdentity(identity_id: str) → IdentityRoot
docclass_getIdentityByController(controller_address: str) → List[IdentityRoot]

# Write Operations (require private key signature)
docclass_registerIssuer(request: RegisterIssuerRequest) → tx_hash
docclass_issueCredential(request: IssueCredentialRequest) → {tx_hash, credential_id}
docclass_revokeCredential(request: RevokeCredentialRequest) → tx_hash
```

**BATCH REQUESTS:**

JSON-RPC 2.0 supports batching:

```json
[
  {
    "jsonrpc": "2.0",
    "method": "docclass_getCredential",
    "params": ["0x1234..."],
    "id": 1
  },
  {
    "jsonrpc": "2.0",
    "method": "docclass_isCredentialValid",
    "params": ["0x1234..."],
    "id": 2
  }
]
```

Response will be an array of results matching the request IDs.

---

## C4: Event Subscription Mechanism

### Question
*"What is the WebSocket endpoint? What is the subscription format? Should we poll or subscribe for revocations?"*

### Answer

**CURRENT IMPLEMENTATION STATUS:**

Based on code inspection, **WebSocket subscriptions are not yet implemented** for docclass events in the current version.

**AVAILABLE OPTIONS:**

### Option 1: Polling (Current Recommendation)
```python
import time

def poll_revocations(credential_ids, interval_seconds=30):
    """Poll for revocation status changes"""
    while True:
        for cred_id in credential_ids:
            is_valid = rpc_call("docclass_isCredentialValid", [cred_id])
            credential = rpc_call("docclass_getCredential", [cred_id])

            if credential["revocation_status"] != 0:  # Not Active
                handle_revocation(credential)

        time.sleep(interval_seconds)
```

**Polling Interval Recommendations:**
- High-priority credentials (active verifications): 30-60 seconds
- Low-priority credentials (archived): 5-10 minutes
- Background monitoring: 1 hour

### Option 2: Block Subscription (If Available)
```python
# Subscribe to new blocks, check for DocClass transactions
ws_subscribe("sum_newBlocks", callback=check_block_for_credential_events)
```

### Option 3: Future WebSocket API (Not Yet Available)
```javascript
// FUTURE API (not implemented yet)
ws.send({
  "jsonrpc": "2.0",
  "method": "docclass_subscribe",
  "params": ["credentialRevoked", {
    "credential_ids": ["0x1234...", "0x5678..."]
  }],
  "id": 1
});
```

**FOR SUMAIL GATEWAY:**

**Recommended Approach:** Hybrid polling + caching

```python
class CredentialMonitor:
    def __init__(self, rpc_url, poll_interval=60):
        self.rpc_url = rpc_url
        self.poll_interval = poll_interval
        self.credential_cache = {}  # {cred_id: {status, last_check}}

    def monitor_credential(self, credential_id):
        """Add credential to monitoring list"""
        self.credential_cache[credential_id] = {
            "status": "Active",
            "last_check": time.time()
        }

    def poll_updates(self):
        """Check all monitored credentials for status changes"""
        for cred_id, cache_data in self.credential_cache.items():
            # Only check if last check was > poll_interval ago
            if time.time() - cache_data["last_check"] < self.poll_interval:
                continue

            credential = rpc_call("docclass_getCredential", [cred_id])
            new_status = credential["revocation_status"]

            # Status changed - trigger alert
            if new_status != cache_data["status"]:
                self.handle_status_change(cred_id, cache_data["status"], new_status)

            # Update cache
            self.credential_cache[cred_id] = {
                "status": new_status,
                "last_check": time.time()
            }

    def handle_status_change(self, cred_id, old_status, new_status):
        """Handle revocation or status change"""
        print(f"Credential {cred_id} changed: {old_status} → {new_status}")
        # Invalidate PDF cache, send notifications, etc.
```

---

## C5: Scope Enforcement Location

### Question
*"Is scope enforcement on-chain or off-chain? How do we enforce PartialFields/SpecificCourses with pre-rendered PDFs?"*

### Answer

**CRITICAL FINDING:**

Looking at the actual implementation, **there is NO on-chain access grant system implemented yet**. The `GrantScope` enum from the spec was **aspirational/proposed**, not actual.

**ACTUAL IMPLEMENTATION:**

```rust
// From docclass.rs - NO grant/scope system exists yet
pub struct AcademicCredential {
    // ... no grant_id field
    // ... no encrypted_key field
    // ... no scope field
}
```

**The current implementation uses a simpler model:**

1. **Credentials are issued to a subject_address**
2. **Subject controls the credential by controlling their private key**
3. **Metadata is public (on-chain)**
4. **Optional encrypted payloads can be stored off-chain (via `payload_hint`)**

**FOR SUMAIL GATEWAY:**

Since on-chain access grants don't exist yet, you have **three implementation options**:

### Option A: Public Credentials Only (Simplest)
```python
# All credential metadata is public
# PDF generation uses public on-chain data
def generate_pdf(credential_id):
    cred = rpc_call("docclass_getCredential", [credential_id])

    # Use public metadata to render PDF
    pdf = render_credential_pdf(
        title=cred["metadata"]["title"],
        program=cred["metadata"]["program"],
        issue_date=cred["metadata"]["issue_date"],
        # ... all metadata fields are public
    )

    return pdf
```

**Pros:** Simple, works with current implementation
**Cons:** No privacy, all data is public

### Option B: Off-Chain Access Control (Gateway-Managed)
```python
# Gateway implements its own access control
class GatewayAccessControl:
    def __init__(self):
        self.grants = {}  # {grant_id: {student, verifier, credential_id, scope}}

    def create_grant(self, student_signature, verifier_address, credential_id, scope):
        """Student signs a grant message off-chain"""
        # Verify student signature
        message = f"GRANT:{verifier_address}:{credential_id}:{scope}"
        assert verify_signature(message, student_signature, student_address)

        grant_id = generate_grant_id()
        self.grants[grant_id] = {
            "student": student_address,
            "verifier": verifier_address,
            "credential_id": credential_id,
            "scope": scope,
            "created_at": time.time(),
            "expires_at": time.time() + (30 * 86400)  # 30 days
        }

        return grant_id

    def generate_scoped_pdf(self, grant_id):
        """Generate PDF based on grant scope"""
        grant = self.grants[grant_id]
        cred = rpc_call("docclass_getCredential", [grant["credential_id"]])

        if grant["scope"]["type"] == "PartialFields":
            # Filter metadata to only include specified fields
            filtered_data = {
                k: v for k, v in cred["metadata"].items()
                if k in grant["scope"]["fields"]
            }
            return render_pdf(filtered_data)

        elif grant["scope"]["type"] == "SpecificCourses":
            # Load full transcript from IPFS
            full_transcript = ipfs_get(cred["payload_hint"])

            # Filter to only requested courses
            filtered_courses = [
                course for course in full_transcript["courses"]
                if course["course_code"] in grant["scope"]["course_codes"]
            ]

            return render_pdf_with_courses(filtered_courses)

        else:  # FullCredential
            return render_full_pdf(cred)
```

**Pros:**
- Full control over scoped sharing
- Can implement all spec features
- Works with current chain

**Cons:**
- Gateway becomes a trusted party
- Off-chain grants are not cryptographically verifiable on-chain

### Option C: Hybrid - Multiple PDF Versions on IPFS
```python
# When credential is issued, generate multiple PDF versions
def issue_credential_with_pdfs(credential_data):
    # Generate full PDF
    full_pdf = render_full_pdf(credential_data)
    full_pdf_cid = ipfs_add(full_pdf)

    # Generate partial PDFs (pre-rendered for common scopes)
    gpa_only_pdf = render_pdf_with_fields(credential_data, ["gpa", "major"])
    gpa_pdf_cid = ipfs_add(gpa_only_pdf)

    # Store all CIDs in metadata
    metadata = {
        "title": "Degree",
        "attributes": [
            {"name": "pdf_full_cid", "value": full_pdf_cid},
            {"name": "pdf_gpa_only_cid", "value": gpa_pdf_cid},
            # ... other variants
        ]
    }

    # Issue credential with all PDF CIDs
    rpc_call("docclass_issueCredential", [{
        "metadata": metadata,
        "payload_hint": full_pdf_cid  # Default to full
    }])
```

**Pros:**
- PDFs are immutable on IPFS
- No runtime PDF generation needed
- Student can share different CIDs for different purposes

**Cons:**
- More storage required
- Not flexible for arbitrary scopes
- Student must manage multiple CIDs

### Recommendation:

For **MVP (Minimum Viable Product)**, use **Option A** (Public Credentials) with this workflow:

1. Credential issued with public metadata
2. PDF rendered from public metadata + stored on IPFS
3. PDF CID added to `metadata.attributes`
4. Verifiers retrieve credential → get PDF CID → download from IPFS
5. Verify PDF hash matches `pdf_hash` attribute

For **future enhancement**, implement **Option B** (Gateway Access Control) when you need privacy features.

---

## Summary Table

| Question | Answer |
|----------|--------|
| **C1: Data Source** | On-chain `AcademicCredential` struct via `docclass_getCredential`. Metadata is public on-chain, optional full payload on IPFS via `payload_hint`. |
| **C2: PDF CID Storage** | Use `metadata.attributes` array with `pdf_cid` entry. Optionally set `payload_hint` to PDF CID. |
| **C3: RPC Endpoints** | Testnet: `http://100.84.189.95:8545`. Protocol: JSON-RPC 2.0. Batching supported. See full API list in C3. |
| **C4: Event Subscriptions** | WebSockets not implemented yet. Use polling with 30-60 second intervals. See hybrid polling pattern in C4. |
| **C5: Scope Enforcement** | No on-chain grants exist yet. Implement off-chain access control in Gateway or use public credentials only (Option A recommended for MVP). |

---

## Critical Implementation Notes

### 1. Hash Algorithm: BLAKE3 (not SHA-256)
```python
# CORRECT:
import blake3
commitment = blake3.blake3(data).digest()

# WRONG (from original spec):
import hashlib
commitment = hashlib.sha256(data).hexdigest()  # ❌ Chain uses BLAKE3
```

### 2. Commitment Domain Separator
```rust
pub const COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC-8XX-COMMITMENT-v1";
```

### 3. Revocation Status Values
```rust
pub enum RevocationStatus {
    Active = 0,      // Valid credential
    Suspended = 1,   // Temporarily invalid (can reactivate)
    Revoked = 2,     // Permanently invalid
    Superseded = 3,  // Replaced by newer version
    Expired = 4,     // Past expiry timestamp
}
```

### 4. Subcode Values
```
810 = AcademicTranscript
811 = Diploma/Degree
812 = EnrollmentVerification
```

### 5. Response Field Types
- `credential_id`: Hex string `"0x..."`
- Timestamps: Unix milliseconds (integer)
- `subcode`: Integer (810/811/812)
- `revocation_status`: Integer (0-4)

---

## Next Steps for SUMail Gateway Team

1. **Immediate:**
   - ✅ Update spec assumptions to match actual implementation
   - ✅ Switch hash algorithm from SHA-256 to BLAKE3
   - ✅ Use `metadata.attributes` for PDF CID storage
   - ✅ Implement polling for revocation checks (60s interval)

2. **Short-term:**
   - Implement Option A (Public Credentials) for MVP
   - Test `docclass_getCredential` RPC calls
   - Build PDF renderer using on-chain metadata
   - Add PDF upload to IPFS + CID storage

3. **Medium-term:**
   - Implement Option B (Gateway Access Control) for privacy
   - Build off-chain grant management system
   - Add scoped PDF generation

4. **Long-term:**
   - Request on-chain grant system from SUM Chain team
   - Migrate to on-chain access control when available
   - Add WebSocket subscriptions when implemented

---

**END OF ADDENDUM**

*Version 1.0 - 2026-02-01*
*Answers based on actual codebase inspection*
