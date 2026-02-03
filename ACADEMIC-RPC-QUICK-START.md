# Academic Credentials RPC - Quick Start

✅ **Status**: Live on mainnet
📅 **Deployed**: February 3, 2026
🔗 **Endpoint**: https://rpc.sum-chain.xyz

---

## Two Simple Endpoints

### 1. Register as Academic Issuer

**Method**: `docclass_registerAcademicIssuer`

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_registerAcademicIssuer",
    "params": {
      "request": {
        "private_key": "0xYOUR_PRIVATE_KEY",
        "institution_name": "Your University Name",
        "institution_type": "University",
        "jurisdiction_code": "US",
        "authorized_subcodes": [810, 811, 812],
        "stake_amount": "1000000000"
      }
    },
    "id": 1
  }'
```

**Requirements**:
- Minimum balance: 1,001 Ϙ (1,000 for stake + fees)
- 2-letter country code (ISO 3166-1)
- Subcodes: 810 (Transcript), 811 (Diploma), 812 (Enrollment)

---

### 2. Issue Academic Credential

**Method**: `docclass_issueAcademicCredential`

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": {
      "request": {
        "private_key": "0xYOUR_PRIVATE_KEY",
        "subcode": 811,
        "holder_address": "STUDENT_ADDRESS",
        "subject_commitment": "0xHASH_OF_STUDENT_ID",
        "schema_hash": "0xHASH_OF_SCHEMA",
        "content_commitment": "0xHASH_OF_CONTENT",
        "attributes": [],
        "metadata": {
          "title": "Bachelor of Science in Computer Science",
          "program": "Computer Science",
          "degree_type": "Bachelor",
          "issue_date": "2026-02-03"
        },
        "valid_from": 1738540800000,
        "expires_at": 0
      }
    },
    "id": 1
  }'
```

**Credential Types**:
- **810**: Academic Transcript
- **811**: Diploma/Degree
- **812**: Enrollment Verification

---

## Key Features

✅ **Zero PII on-chain** - Only cryptographic commitments
✅ **Automatic signing** - Just provide private key
✅ **No complexity** - Simple JSON API
✅ **Privacy-preserving** - BLAKE3 hash commitments
✅ **NFT-based** - Credentials are transferable tokens

---

## Response Format

Success:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "tx_hash": "0xda992b58afa30d9ca2b1af1ef417f7da578d98b00271560d3b24f73e745cb238",
    "credential_id": "0x11350eb2b6169d0ac2da1e7746d1c1767d28067dd562e91562571cc1a656bec6",
    "error": null
  },
  "id": 1
}
```

---

## Generating Commitments

Use BLAKE3 to hash sensitive data:

```python
import blake3

# Student identity commitment
student_id = "student123@university.edu"
subject_commitment = "0x" + blake3.blake3(student_id.encode()).hexdigest()

# Schema commitment
schema = "diploma_v1_schema"
schema_hash = "0x" + blake3.blake3(schema.encode()).hexdigest()

# Content commitment
content = f"{student_id}|Computer Science|Bachelor|2026"
content_commitment = "0x" + blake3.blake3(content.encode()).hexdigest()
```

---

## Production Test Results (Feb 3, 2026)

✅ **Diploma Issued**
- TX: `0xda992b58afa30d9ca2b1af1ef417f7da578d98b00271560d3b24f73e745cb238`
- Block: 454140
- Fee: 0.001 Ϙ

✅ **Transcript Issued**
- TX: `0x75007588feb66a8000f7b1afd7fe5637a7b80dda110209f97eb09afad1b4ba46`
- Fee: 0.001 Ϙ

---

## Documentation

📖 **Full Guide**: [ACADEMIC-CREDENTIALS-RPC-GUIDE.md](ACADEMIC-CREDENTIALS-RPC-GUIDE.md)

---

## Support

- **Issues**: Report at your project repository
- **Questions**: Contact your blockchain team

---

**Ready to integrate? Start issuing credentials now!**
