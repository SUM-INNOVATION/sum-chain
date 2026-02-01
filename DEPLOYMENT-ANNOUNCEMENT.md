# SRC-810/811/812 Schema Validation Deployment Announcement

## To: Verification Team
## Subject: Schema Validation Ready for Deployment - Action Required

---

## Summary

Schema validation for academic credentials (SRC-810, 811, 812) is **ready for mainnet deployment**.

**What this does:**
- Enforces hard rejection at consensus for credentials containing PII in metadata
- Prevents permanent on-chain storage of student names, grades, courses, etc.
- Maintains privacy through cryptographic commitments (BLAKE3 hashes)

**Activation**: Will be announced (set via activation_height parameter)

---

## CRITICAL: Encryption Support

**NEW - Native Encryption Available**: Credential structures now include native `encryption_meta` field for encrypted IPFS payloads.

### What This Means:

**Privacy Protection (ON-CHAIN):**
✅ Zero PII stored on-chain
✅ Only commitments (BLAKE3 hashes) in permanent chain state
✅ Subject addresses are pseudonymous (not linked to real identity)

**Privacy Options (OFF-CHAIN):**
⚠️ **Without encryption**: IPFS payloads are publicly accessible to anyone with the CID
✅ **With encryption**: Native encryption metadata support for private credentials
✅ **Supported algorithms**: X25519Aes256Gcm (recommended), Aes256Gcm, ChaCha20Poly1305, ThresholdEncryption

### Recommended Approaches:

**Option A: Public Credentials (No Encryption)**
- **Use case**: Public academic records with explicit subject consent
- **Implementation**: Upload JSON to IPFS unencrypted, use CID as `payload_hint`
- **Suitable for**: Non-sensitive records, public verification systems

**Option B: Private Credentials (Native Encryption) - RECOMMENDED**
- **Use case**: Sensitive academic data requiring full privacy
- **Implementation**:
  1. Generate shared secret using X25519 key exchange (issuer ↔ subject)
  2. Encrypt JSON payload with AES-256-GCM
  3. Upload encrypted blob to IPFS
  4. Store encrypted CID in `payload_hint`
  5. Set `encryption_meta` field with algorithm, key_commitment, and nonce
  6. Share decryption capability only with authorized verifiers (via subject)
- **Suitable for**: Production systems with privacy requirements
- **Documentation**: See [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) section 3 for complete implementation examples

---

## Breaking Changes

### REMOVED Fields (Will Cause Rejection):

| Field | Why Removed | Alternative |
|-------|-------------|-------------|
| `issuer_signature` | Redundant | Chain tx signature provides issuer auth |
| `verification_url` | Centralization/tracking risk | Use IPFS payload for verification |
| `json_cid` / `json_hash` | Duplication | `payload_hint` is canonical |
| `gpa_bracket` / `credit_range` | De-anonymization risk | Use commitments only |

### NEW Requirements:

1. **Commitment Canonicalization**: Follow exact rules in [SRC-81X-COMMITMENT-CANONICALIZATION.md](SRC-81X-COMMITMENT-CANONICALIZATION.md)
   - Sorted JSON keys (lexicographic)
   - No whitespace
   - Domain separators (e.g., `SRC-810-COURSES-v1`)
   - BLAKE3 hashing (not SHA-256)

2. **Allowlist-Based Validation**: Only approved metadata attributes accepted
   - See [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) for full list

---

## Action Required

### Before Activation:

1. **Review documentation**:
   - [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) - Complete implementation guide
   - [SRC-81X-COMMITMENT-CANONICALIZATION.md](SRC-81X-COMMITMENT-CANONICALIZATION.md) - Hashing spec

2. **Update your credential issuance**:
   - Remove disallowed fields (`issuer_signature`, `verification_url`, etc.)
   - Implement commitment canonicalization for sensitive data
   - Choose encryption approach (Option A: public vs. Option B: native encryption)
   - If using encryption, implement `encryption_meta` field population

3. **Implement client-side validation**:
   - Pre-validate credentials before submission to avoid rejections
   - Check all attribute keys against allowlist

4. **Test on staging/testnet** (if available):
   - Validate credential issuance with new rules
   - Test both valid and invalid credentials
   - Verify commitment computation matches spec

### After Activation:

5. **Monitor for errors**:
   - Watch for schema validation rejection errors
   - Fix any non-compliant credential submissions

6. **Update verification logic**:
   - Verify commitments against IPFS payloads
   - Handle encrypted payloads if using Option B (check `encryption_meta` field)
   - Decrypt IPFS payload using shared secret before commitment verification

---

## Testing Examples

### Valid Credential (Will Succeed):

```json
{
  "subcode": 810,
  "metadata": {
    "title": "Academic Transcript",
    "attributes": [
      {"name": "pdf_cid", "value": "bafybeig..."},
      {"name": "courses_commitment", "value": "blake3:a7f2c9..."}
    ]
  },
  "payload_hint": "bafybeig..."
}
```

### Invalid Credential (Will Be REJECTED):

```json
{
  "subcode": 810,
  "metadata": {
    "attributes": [
      {"name": "student_name", "value": "John Doe"}  // ❌ DISALLOWED
    ]
  }
}
```

**Error**: `"Schema validation failed: Disallowed attribute key 'student_name'"`

---

## Timeline

- **Code deployed**: [To be scheduled]
- **Activation height**: [To be announced]
- **Effective date**: [Block height will determine exact time]

---

## Support

**Questions or issues?**
- Documentation: [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md)
- Commitment spec: [SRC-81X-COMMITMENT-CANONICALIZATION.md](SRC-81X-COMMITMENT-CANONICALIZATION.md)
- Bug reports: File in chain repository

---

**Document Version**: 1.0
**Date**: 2026-02-01
**Status**: Ready for Deployment
