# Testing SUMaillet Academic Credentials Query

> **Archived / historical.** Kept for history; for current truth see [docs/tokens.md](../tokens.md) and [docs/policy-accounts-and-contracts.md](../policy-accounts-and-contracts.md).

## What Was Added

A new RPC endpoint to query academic credentials by holder address (wallet address):

**Method**: `docclass_getAcademicCredentialsByHolder`

This allows SUMaillet to fetch and display credentials owned by a user's wallet.

---

## After Deployment - Test the Endpoint

### 1. Query Credentials by Holder Address

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_getAcademicCredentialsByHolder",
    "params": ["MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE"],
    "id": 1
  }' | jq
```

**Expected Response**:
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "credential_id": "0x...",
      "subcode": 811,
      "subcode_name": "Diploma",
      "subject_commitment": "0x...",
      "issuer": "NXhwRs2VP1J3t5AEPbRpNmVgKZkWvb5KW",
      "jurisdiction": "US",
      "schema_hash": "0x...",
      "content_commitment": "0x...",
      "issued_at": 1738540800000,
      "valid_from": 1738540800000,
      "expires_at": 0,
      "revocation_status": "Active",
      "superseded_by": null,
      "metadata": {
        "title": "Bachelor of Science in Computer Science",
        "credential_type": "diploma",
        "program": "Computer Science",
        "issue_date": "2026-02-03",
        "completion_date": null
      }
    }
  ],
  "id": 1
}
```

---

## Your Test Credentials

Based on your transaction `0x0a5d5ca62a340452a000cad2122b50bd577d7ec013d25da2baa520b62e77b3fe`:

- **Holder Address**: `MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE`
- **Block**: 455206
- **Issuer**: `NXhwRs2VP1J3t5AEPbRpNmVgKZkWvb5KW`

After deployment, run:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_getAcademicCredentialsByHolder",
    "params": ["MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE"],
    "id": 1
  }' | jq
```

This should return the credential you just minted!

---

## For SUMaillet Integration

SUMaillet can now call this endpoint to display all academic credentials:

```javascript
// Fetch credentials for current wallet
async function fetchAcademicCredentials(walletAddress) {
  const response = await fetch('https://rpc.sum-chain.xyz', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'docclass_getAcademicCredentialsByHolder',
      params: [walletAddress],
      id: 1
    })
  });

  const data = await response.json();
  return data.result; // Array of credentials
}

// Usage
const credentials = await fetchAcademicCredentials('MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE');

// Display in UI
credentials.forEach(cred => {
  console.log(`${cred.subcode_name}: ${cred.metadata.title}`);
  console.log(`Issued by: ${cred.issuer}`);
  console.log(`Status: ${cred.revocation_status}`);
});
```

---

## Deployment Steps (For You)

1. Stop the RPC service on validator
2. Backup current binary
3. Upload `target/release/sumchain` to validator
4. Replace the binary
5. Start the service
6. Test the endpoint

---

## What This Fixes

✅ **Before**: SUMaillet couldn't see credentials because no query method by wallet address
✅ **After**: SUMaillet can call `docclass_getAcademicCredentialsByHolder(address)` to fetch all credentials

---

## Files Modified

1. **api.rs**: Added `docclass_getAcademicCredentialsByHolder` method definition
2. **server.rs**: Implemented the method (queries all academic subcodes and filters by holder address)

---

**Status**: ✅ Ready for deployment
**Binary**: `target/release/sumchain` (21 MB)
**Date**: February 3, 2026
