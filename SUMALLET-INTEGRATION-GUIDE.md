# SUMaillet Academic Credentials Integration Guide

> **Status:** historical / integration handoff — pending consolidation
> **Last verified:** 2026-06-27
> **Public RPC support:** for current, code-verified usage see [docs/tokens.md](docs/tokens.md)
>
> This is an integration handoff document and may contain dated "live / mainnet / production" claims. Treat [docs/tokens.md](docs/tokens.md) and [docs/policy-accounts-and-contracts.md](docs/policy-accounts-and-contracts.md) as the current source of truth.

**For Mobile Development Team**

## Overview

SUMaillet can now display academic credentials (diplomas, transcripts, enrollment verifications) owned by users' wallets.

**Endpoint**: `https://rpc.sum-chain.xyz`
**Status**: ✅ Live on mainnet (tested Feb 3, 2026)

---

## Quick Integration

### Endpoint

```
docclass_getAcademicCredentialsByHolder
```

### Request Format

```typescript
const response = await fetch('https://rpc.sum-chain.xyz', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'docclass_getAcademicCredentialsByHolder',
    params: [walletAddress], // User's wallet address (base58)
    id: 1
  })
});

const data = await response.json();
const credentials = data.result; // Array of credentials
```

### Response Format

```typescript
{
  "jsonrpc": "2.0",
  "result": [
    {
      "credential_id": "0x61d149a0684bc50528e9a086bdfd96e7d8c75112ca23184d51ba6bd9c415e2dd",
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
        "degree_type": "Bachelor",
        "issue_date": "2026-02-03",
        "completion_date": null,
        "ipfs_cid": null
      }
    }
  ],
  "id": 1
}
```

---

## TypeScript Types

```typescript
interface AcademicCredential {
  credential_id: string;
  subcode: number;
  subcode_name: string;
  subject_commitment: string;
  issuer: string;
  jurisdiction: string;
  schema_hash: string;
  content_commitment: string;
  issued_at: number; // Unix timestamp (milliseconds)
  valid_from: number;
  expires_at: number; // 0 = no expiry
  revocation_status: 'Active' | 'Revoked' | 'Suspended';
  superseded_by: string | null;
  metadata: CredentialMetadata;
}

interface CredentialMetadata {
  title: string;
  credential_type?: string;
  program?: string;
  degree_type?: string;
  issue_date?: string; // ISO 8601 format
  completion_date?: string | null;
  ipfs_cid?: string | null;
}
```

---

## Credential Types (Subcodes)

| Subcode | Name | Description |
|---------|------|-------------|
| 810 | Academic Transcript | Complete academic record with courses and grades |
| 811 | Diploma | Degree/diploma certificate |
| 812 | Enrollment Verification | Proof of enrollment in an educational program |

---

## Complete Implementation Example

```typescript
// api/credentials.ts
export async function fetchAcademicCredentials(
  walletAddress: string
): Promise<AcademicCredential[]> {
  try {
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

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();

    if (data.error) {
      throw new Error(data.error.message || 'RPC error');
    }

    return data.result || [];
  } catch (error) {
    console.error('Failed to fetch credentials:', error);
    return [];
  }
}

// hooks/useCredentials.ts
import { useState, useEffect } from 'react';

export function useAcademicCredentials(walletAddress: string | null) {
  const [credentials, setCredentials] = useState<AcademicCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!walletAddress) {
      setCredentials([]);
      return;
    }

    const loadCredentials = async () => {
      setLoading(true);
      setError(null);

      try {
        const data = await fetchAcademicCredentials(walletAddress);
        setCredentials(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load credentials');
      } finally {
        setLoading(false);
      }
    };

    loadCredentials();
  }, [walletAddress]);

  return { credentials, loading, error, refresh: () => loadCredentials() };
}

// components/CredentialsList.tsx
import React from 'react';
import { useAcademicCredentials } from '../hooks/useCredentials';

interface Props {
  walletAddress: string;
}

export function CredentialsList({ walletAddress }: Props) {
  const { credentials, loading, error } = useAcademicCredentials(walletAddress);

  if (loading) {
    return <div>Loading credentials...</div>;
  }

  if (error) {
    return <div>Error: {error}</div>;
  }

  if (credentials.length === 0) {
    return <div>No credentials found</div>;
  }

  return (
    <div className="credentials-list">
      {credentials.map(cred => (
        <CredentialCard key={cred.credential_id} credential={cred} />
      ))}
    </div>
  );
}

// components/CredentialCard.tsx
interface CredentialCardProps {
  credential: AcademicCredential;
}

function CredentialCard({ credential }: CredentialCardProps) {
  const isActive = credential.revocation_status === 'Active';
  const isExpired = credential.expires_at > 0 && credential.expires_at < Date.now();

  return (
    <div className="credential-card">
      <div className="credential-header">
        <span className="credential-type">{credential.subcode_name}</span>
        <span className={`status ${isActive && !isExpired ? 'active' : 'inactive'}`}>
          {isActive && !isExpired ? 'Active' : isExpired ? 'Expired' : credential.revocation_status}
        </span>
      </div>

      <h3>{credential.metadata.title}</h3>

      {credential.metadata.program && (
        <p className="program">Program: {credential.metadata.program}</p>
      )}

      {credential.metadata.degree_type && (
        <p className="degree">Degree: {credential.metadata.degree_type}</p>
      )}

      {credential.metadata.issue_date && (
        <p className="date">Issued: {credential.metadata.issue_date}</p>
      )}

      <div className="credential-footer">
        <p className="issuer">Issuer: {credential.issuer}</p>
        <p className="jurisdiction">{credential.jurisdiction}</p>
      </div>
    </div>
  );
}
```

---

## UI/UX Recommendations

### Grouping Credentials

```typescript
function groupCredentialsByType(credentials: AcademicCredential[]) {
  return credentials.reduce((groups, cred) => {
    const type = cred.subcode_name;
    if (!groups[type]) groups[type] = [];
    groups[type].push(cred);
    return groups;
  }, {} as Record<string, AcademicCredential[]>);
}
```

### Sorting Credentials

```typescript
// Sort by most recent first
const sorted = credentials.sort((a, b) => b.issued_at - a.issued_at);
```

### Status Badges

- **Active** (green): `revocation_status === 'Active' && !expired`
- **Expired** (gray): `expires_at > 0 && expires_at < Date.now()`
- **Revoked** (red): `revocation_status === 'Revoked'`
- **Suspended** (yellow): `revocation_status === 'Suspended'`

---

## Error Handling

```typescript
// Common errors
const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Unable to connect to blockchain',
  INVALID_ADDRESS: 'Invalid wallet address format',
  NO_CREDENTIALS: 'No credentials found for this wallet',
  RPC_ERROR: 'Blockchain query failed',
};

// Validate wallet address format (base58)
function isValidAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}
```

---

## Testing

### Test Wallet

**Address**: `MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE`

This wallet has a test diploma credential you can use for development.

### Test Command (curl)

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_getAcademicCredentialsByHolder",
    "params": ["MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE"],
    "id": 1
  }' | jq
```

---

## Performance Notes

- Endpoint typically responds in < 500ms
- No pagination needed (most users have < 10 credentials)
- Cache results for 5-10 minutes to reduce load
- Refresh on pull-to-refresh gesture

---

## Privacy Considerations

- **No PII exposed**: All sensitive data is hashed (commitments)
- **Display metadata only**: Show `metadata` fields in UI
- **Commitment hashes**: Don't display raw commitment values to users
- **Issuer verification**: Future feature - verify issuer reputation

---

## Future Features

These features are planned but not yet implemented:

- Credential verification endpoint
- Issuer reputation/registry
- Revocation checking
- Zero-knowledge proof generation
- QR code sharing

For now, display credentials as-is from the endpoint response.

---

## Support

- **API Issues**: Contact blockchain team
- **Integration Help**: Refer to [ACADEMIC-CREDENTIALS-RPC-GUIDE.md](ACADEMIC-CREDENTIALS-RPC-GUIDE.md)
- **Production RPC**: `https://rpc.sum-chain.xyz`
- **Testnet RPC**: Contact DevOps for testnet endpoint

---

## Quick Checklist

- [ ] Add `fetchAcademicCredentials` function to API layer
- [ ] Create credential list UI component
- [ ] Add loading/error states
- [ ] Implement credential card design
- [ ] Add status badges (Active/Expired/Revoked)
- [ ] Test with address: `MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE`
- [ ] Add pull-to-refresh to reload credentials
- [ ] Cache credentials for performance
- [ ] Handle empty state (no credentials)

---

**Ready to integrate? Start with the test wallet above!**

**Document Version**: 1.0
**Date**: 2026-02-03
**Status**: Production Ready
**Tested**: ✅ Live on mainnet
