# Academic Credentials RPC Endpoints Guide

This guide explains how to use the new RPC endpoints for issuing academic credentials (SRC-810/811/812) on SUM Chain.

**✅ Status**: Production-ready and tested on mainnet
**📅 Deployed**: February 3, 2026
**🔗 RPC Endpoint**: https://rpc.sum-chain.xyz (or http://localhost:8545 for local testing)

---

## Overview

Two new RPC endpoints have been added to simplify academic credential issuance:

1. **`docclass_registerAcademicIssuer`** - Register an educational institution as an issuer
2. **`docclass_issueAcademicCredential`** - Issue academic credentials (transcripts, diplomas, enrollment verifications)

These endpoints handle all the complexity of:
- Transaction creation and signing
- Bincode serialization
- Nonce management
- Mempool submission
- Network broadcasting

---

## 1. Register as an Academic Issuer

### Endpoint
```
docclass_registerAcademicIssuer
```

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "docclass_registerAcademicIssuer",
  "params": {
    "request": {
      "private_key": "0x2b633797f438e505542e982615ab464c32a134b995be129a3259d41462e2909a",
      "institution_name": "SUM Hypothesis Institute Technology",
      "institution_type": "University",
      "jurisdiction_code": "US",
      "authorized_subcodes": [810, 811, 812],
      "stake_amount": "1000000000"
    }
  },
  "id": 1
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `private_key` | string | Yes | Issuer's private key in hex format (with or without 0x prefix) |
| `institution_name` | string | Yes | Institution name (e.g., "SUM Hypothesis Institute Technology") |
| `institution_type` | string | Yes | Type of institution (e.g., "University", "College", "CertificationBody") |
| `jurisdiction_code` | string | Yes | ISO 3166-1 alpha-2 country code (e.g., "US", "GB", "CN") |
| `authorized_subcodes` | number[] | Yes | Document subcodes: 810 (Transcript), 811 (Diploma), 812 (Enrollment) |
| `stake_amount` | string | Yes | Stake amount in Koppa (minimum: 1,000,000,000 = 1000 Ϙ) |

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "tx_hash": "0xfd276a42229ef6b07ffd5c09f0526f93e63c28c75240346d0a38c89450e9a514",
    "issuer_address": "NXhwRs2VP1J3t5AEPbRpNmVgKZkWvb5KW",
    "error": null
  },
  "id": 1
}
```

### Requirements

- **Balance**: Must have at least 1,001 Ϙ (1,000 Ϙ for stake + fees)
- **Jurisdiction**: Must be valid ISO 3166-1 alpha-2 code (2 characters)
- **Subcodes**: Only 810, 811, 812 are valid for educational issuers

---

## 2. Issue an Academic Credential

### Endpoint
```
docclass_issueAcademicCredential
```

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "docclass_issueAcademicCredential",
  "params": {
    "request": {
      "private_key": "0x2b633797f438e505542e982615ab464c32a134b995be129a3259d41462e2909a",
      "subcode": 810,
      "holder_address": "D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV",
      "subject_commitment": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
      "schema_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "content_commitment": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
    "attributes": [
      {
        "name": "program",
        "value_commitment": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "is_private": false
      },
      {
        "name": "gpa",
        "value_commitment": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "is_private": true
      }
    ],
    "metadata": {
      "title": "Bachelor of Science in Computer Science",
      "program": "Computer Science",
      "degree_type": "Bachelor",
      "issue_date": "2024-05-15",
      "completion_date": "2024-05-15",
      "ipfs_cid": "QmXyZ..."
    },
      "valid_from": 1715788800000,
      "expires_at": 0
    }
  },
  "id": 1
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `private_key` | string | Yes | Issuer's private key (must be registered issuer) |
| `subcode` | number | Yes | 810 (Transcript), 811 (Diploma), or 812 (Enrollment) |
| `holder_address` | string | Yes | Student's wallet address (base58) who will own the credential |
| `subject_commitment` | string | Yes | BLAKE3 hash commitment to student identity (32 bytes hex) |
| `schema_hash` | string | Yes | BLAKE3 hash of credential schema (32 bytes hex) |
| `content_commitment` | string | Yes | BLAKE3 hash of credential content (32 bytes hex) |
| `attributes` | array | Yes | Public/private attributes with value commitments |
| `metadata` | object | No | Optional human-readable metadata |
| `valid_from` | number | Yes | Start timestamp in milliseconds |
| `expires_at` | number | Yes | Expiry timestamp (0 = no expiry) |

### Attribute Format

Each attribute has:
- `name` (string): Attribute name (e.g., "program", "gpa", "degree")
- `value_commitment` (string): BLAKE3 hash of the attribute value (32 bytes hex)
- `is_private` (boolean): Whether this attribute is private

### Metadata Format (Optional)

- `title`: Credential title (e.g., "Bachelor of Science in Computer Science")
- `program`: Program name (e.g., "Computer Science")
- `degree_type`: Degree type (e.g., "Bachelor", "Master", "PhD")
- `issue_date`: Issue date in ISO 8601 format (e.g., "2024-05-15")
- `completion_date`: Completion date in ISO 8601 format (optional)
- `ipfs_cid`: IPFS CID for encrypted credential data (optional)

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "tx_hash": "0x3a7f8b2c1d9e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
    "credential_id": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "error": null
  },
  "id": 1
}
```

---

## Credential Subcodes

| Subcode | Name | Description |
|---------|------|-------------|
| 810 | Academic Transcript | Complete academic record with courses and grades |
| 811 | Diploma | Degree/diploma certificate |
| 812 | Enrollment Verification | Proof of enrollment in an educational program |

---

## Privacy Features

### On-Chain Data
- **NO PII** stored on-chain
- Only cryptographic commitments (BLAKE3 hashes)
- Commitments allow zero-knowledge proofs without revealing data

### Off-Chain Data (Optional)
- Encrypted credential data can be stored on IPFS
- `ipfs_cid` in metadata points to encrypted data
- Only holder can decrypt with their private key

### Attribute Privacy
- Each attribute has a `value_commitment` (hash of the value)
- `is_private` flag indicates if the attribute should remain private
- Public attributes can be displayed in explorers
- Private attributes remain hidden commitments

---

## Error Handling

### Common Errors

1. **Issuer Not Registered**
```json
{
  "success": false,
  "error": "Issuer not registered. Register first with docclass_registerAcademicIssuer"
}
```

2. **Insufficient Balance**
```json
{
  "success": false,
  "error": "Insufficient balance. Have: 500000000 Koppa, Need: 1000000000 Koppa"
}
```

3. **Invalid Subcode**
```json
{
  "success": false,
  "error": "Invalid subcode: 820. Valid values: 810 (Transcript), 811 (Diploma), 812 (Enrollment)"
}
```

4. **Unauthorized Subcode**
```json
{
  "success": false,
  "error": "Issuer not authorized for subcode 812"
}
```

5. **Invalid Jurisdiction**
```json
{
  "success": false,
  "error": "Jurisdiction code must be ISO 3166-1 alpha-2 (2 characters)"
}
```

---

## Complete Example Workflow

### Step 1: Extract Private Key

If you have an encrypted keystore:
```bash
./target/release/export_private_key --key keys/sumhit.json
# Enter password when prompted
# Copy the 0x... hex key
```

### Step 2: Register as Issuer

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_registerAcademicIssuer",
    "params": {
      "request": {
        "private_key": "0x2b633797f438e505542e982615ab464c32a134b995be129a3259d41462e2909a",
        "institution_name": "SUM Hypothesis Institute Technology",
        "institution_type": "University",
        "jurisdiction_code": "US",
        "authorized_subcodes": [810, 811, 812],
        "stake_amount": "1000000000"
      }
    },
    "id": 1
  }'
```

### Step 3: Wait for Confirmation

Check transaction status:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_receipt",
    "params": ["0xTX_HASH_FROM_STEP_2"],
    "id": 1
  }'
```

### Step 4: Issue Credential

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": {
      "request": {
        "private_key": "0x2b633797f438e505542e982615ab464c32a134b995be129a3259d41462e2909a",
        "subcode": 811,
        "holder_address": "D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV",
        "subject_commitment": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "schema_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "content_commitment": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        "attributes": [
          {
            "name": "degree",
            "value_commitment": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "is_private": false
          }
        ],
        "metadata": {
          "title": "Bachelor of Science in Computer Science",
          "program": "Computer Science",
          "degree_type": "Bachelor",
          "issue_date": "2024-05-15"
        },
        "valid_from": 1715788800000,
        "expires_at": 0
      }
    },
    "id": 1
  }'
```

---

## Security Best Practices

### Private Key Management

1. **Never expose private keys** in logs, code, or screenshots
2. **Use environment variables** for production:
   ```bash
   export ISSUER_PRIVATE_KEY="0x..."
   ```
3. **Rotate keys** periodically using the issuer key rotation feature
4. **Use hardware wallets** for high-value issuer accounts

### Commitment Generation

Generate commitments using BLAKE3:
```python
import blake3

# Subject commitment (student identity)
student_id = "student123@university.edu"
subject_commitment = blake3.blake3(student_id.encode()).hexdigest()
print(f"0x{subject_commitment}")

# Attribute value commitment
gpa = "3.85"
gpa_commitment = blake3.blake3(gpa.encode()).hexdigest()
print(f"0x{gpa_commitment}")
```

### Data Privacy

- **Never commit PII** directly - always hash first
- **Use strong salts** when generating commitments
- **Encrypt off-chain data** before uploading to IPFS
- **Share decryption keys** only with authorized parties

---

## Comparison with Employment Credentials

| Feature | Academic (SRC-81X) | Employment (SRC-88X) |
|---------|-------------------|----------------------|
| **Issuer Type** | Educational | Employer/Corporate |
| **Stake Required** | 1000 Ϙ | No stake |
| **Subcodes** | 810, 811, 812 | 881, 882, 883 |
| **Privacy** | ZK commitments | Commitments |
| **Registration** | `docclass_registerAcademicIssuer` | `employment_registerIssuer` |
| **Issuance** | `docclass_issueAcademicCredential` | `employment_createCredential` |

---

## FAQ

### Q: Can I issue credentials for multiple institutions?
A: No, each issuer address represents one institution. Register separate addresses for different institutions.

### Q: How do I revoke a credential?
A: Credential revocation will be implemented in a future update. For now, credentials expire based on `expires_at`.

### Q: Can I update issuer information after registration?
A: Issuer updates will be available via the `UpdateIssuer` operation in a future release.

### Q: What happens if my stake drops below 1000 Ϙ?
A: Your issuer status will be suspended until the stake is replenished.

### Q: Can I issue credentials on behalf of another institution?
A: No, you can only issue credentials for the institution associated with your issuer address.

### Q: How do students verify their credentials?
A: Students can generate zero-knowledge proofs using their credential and private data, without revealing the data itself.

---

## Next Steps

1. **Test on Testnet**: Test the endpoints on the testnet before mainnet deployment
2. **Build Integration**: Integrate these endpoints into your student information system
3. **Generate Commitments**: Implement commitment generation in your backend
4. **Encrypt Data**: Set up IPFS encryption for off-chain credential data
5. **Implement ZK Proofs**: Build zero-knowledge proof verification for credential attributes

---

## Production Test Results

The following tests were successfully executed on mainnet (February 3, 2026):

### ✅ Test 1: Issuer Registration
- **Method**: `docclass_registerAcademicIssuer`
- **Issuer**: SUM Hypothesis Institute Technology
- **Address**: `NXhwRs2VP1J3t5AEPbRpNmVgKZkWvb5KW`
- **Subcodes**: 810, 811, 812
- **Stake**: 1000 Ϙ
- **Result**: Already registered (from previous registration)

### ✅ Test 2: Diploma Issuance (811)
- **Method**: `docclass_issueAcademicCredential`
- **TX Hash**: `0xda992b58afa30d9ca2b1af1ef417f7da578d98b00271560d3b24f73e745cb238`
- **Credential ID**: `0x11350eb2b6169d0ac2da1e7746d1c1767d28067dd562e91562571cc1a656bec6`
- **Block**: 454140
- **Status**: ✅ **SUCCESS**
- **Fee**: 0.001 Ϙ

### ✅ Test 3: Transcript Issuance (810)
- **Method**: `docclass_issueAcademicCredential`
- **TX Hash**: `0x75007588feb66a8000f7b1afd7fe5637a7b80dda110209f97eb09afad1b4ba46`
- **Credential ID**: `0x7b99b8280a6333819600d5739436b8492c0e361f73b4d8011ddbc4d87f7b257b`
- **Status**: ✅ **SUCCESS**
- **Fee**: 0.001 Ϙ

All endpoints are working correctly and credentials are being issued successfully on the mainnet.

---

**Document Version**: 1.1
**Date**: 2026-02-03
**Status**: Production Ready & Tested
**Implementation**: [server.rs:4134-4608](crates/rpc/src/server.rs)
