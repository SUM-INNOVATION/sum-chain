# SRC-80X/81X: DocClass Credential Family

## Abstract

SRC-80X and SRC-81X define a family of document/credential standards for the SUM Chain blockchain, enabling privacy-preserving issuance, verification, and revocation of identity credentials, eligibility attestations, and academic/professional credentials.

## Motivation

Traditional credential systems suffer from several limitations:
1. **Privacy leakage**: Credentials often reveal more information than necessary
2. **Centralization**: Single points of failure in verification
3. **No portability**: Credentials are locked to specific platforms
4. **Limited revocation**: Poor revocation transparency and latency

DocClass addresses these issues through:
- Privacy-first design using cryptographic commitments (no raw PII on-chain)
- Decentralized issuer registry with jurisdiction-based authorization
- Standard formats enabling cross-platform interoperability
- On-chain revocation registry with instant verification

## Specification

### SRC-80X: Identity & Civil Credentials

| Subcode | Name | Description |
|---------|------|-------------|
| 800 | Identity Root | Self-sovereign identity anchors (DID-like) |
| 802 | Eligibility Attestation | Age verification, citizenship, residency proofs |
| 805 | Revocation Status | Credential revocation/suspension records |

### SRC-81X: Academic & Professional Credentials

| Subcode | Name | Description |
|---------|------|-------------|
| 810 | Academic Transcript | Course grades and credits |
| 811 | Diploma | Degree completion certificates |
| 812 | Enrollment Verification | Current student status |
| 813 | Professional License | Licenses and certifications |

## Core Types

### CredentialId

A 32-byte unique identifier for each credential:

```rust
pub type CredentialId = [u8; 32];
```

Generated using BLAKE3 hash of:
- Issuer address
- Subject commitment
- Subcode
- Issuance timestamp
- Random nonce

### Subject Commitment

Privacy-preserving binding to credential holder. Generated as:

```
commitment = BLAKE3(secret || subject_pii_hash)
```

Where:
- `secret`: 32-byte random value known only to subject
- `subject_pii_hash`: Hash of subject's identifying information

This allows selective disclosure proofs without revealing PII.

### DocSubcode

```rust
pub enum DocSubcode {
    IdentityRoot = 800,
    EligibilityAttestation = 802,
    RevocationStatus = 805,
    AcademicTranscript = 810,
    Diploma = 811,
    EnrollmentVerification = 812,
    ProfessionalLicense = 813,
}
```

## Identity Root (SRC-800)

Identity roots anchor self-sovereign identities on-chain, similar to DIDs.

### Structure

```rust
pub struct IdentityRoot {
    pub identity_id: CredentialId,
    pub subject_commitment: [u8; 32],
    pub controller: Address,
    pub additional_controllers: Vec<Address>,
    pub keys: Vec<IdentityKey>,
    pub services: Vec<ServiceEndpoint>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub status: IdentityStatus,
    pub schema_hash: [u8; 32],
}
```

### Operations

- `CreateIdentityRoot`: Create new identity anchor
- `AddKey`: Add authentication/signing key
- `RemoveKey`: Remove/revoke a key
- `RotateKey`: Replace old key with new key
- `AddController`: Add recovery/delegate controller
- `RemoveController`: Remove controller
- `UpdateService`: Add/update service endpoints
- `DeactivateIdentity`: Deactivate identity

### Key Types

```rust
pub enum KeyType {
    Ed25519,
    Secp256k1,
    P256,
    Bls12381G1,
    Bls12381G2,
}

pub enum KeyPurpose {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}
```

## Eligibility Attestation (SRC-802)

Attestations about subject eligibility without revealing specific data.

### Structure

```rust
pub struct EligibilityAttestation {
    pub credential_id: CredentialId,
    pub subcode: DocSubcode,
    pub subject_commitment: [u8; 32],
    pub issuer: Address,
    pub jurisdiction: String,
    pub eligibility_type: EligibilityType,
    pub schema_hash: [u8; 32],
    pub content_commitment: [u8; 32],
    pub issued_at: Timestamp,
    pub valid_from: Timestamp,
    pub expires_at: Timestamp,
    pub payload_hash: Option<[u8; 32]>,
    pub payload_hint: Option<String>,
    pub issuer_signature: [u8; 64],
    pub issuer_key_id: String,
    pub revocation_status: RevocationStatus,
    pub superseded_by: Option<CredentialId>,
}
```

### Eligibility Types

```rust
pub enum EligibilityType {
    AgeOver18,
    AgeOver21,
    AgeOver65,
    Citizenship,
    PermanentResident,
    WorkAuthorization,
    VotingEligibility,
    BenefitsEligibility,
    Custom(String),
}
```

## Academic Credentials (SRC-810/811/812)

### Structure

```rust
pub struct AcademicCredential {
    pub credential_id: CredentialId,
    pub subcode: DocSubcode,
    pub subject_commitment: [u8; 32],
    pub issuer: Address,
    pub institution_name: String,
    pub program_name: String,
    pub degree_type: Option<String>,
    pub schema_hash: [u8; 32],
    pub content_commitment: [u8; 32],
    pub issued_at: Timestamp,
    pub effective_date: Timestamp,
    pub expires_at: Timestamp,
    pub attributes: Vec<CredentialAttribute>,
    pub issuer_signature: [u8; 64],
    pub issuer_key_id: String,
    pub revocation_status: RevocationStatus,
    pub metadata: Option<CredentialMetadata>,
}
```

### Credential Attributes

Generic key-value attributes:

```rust
pub struct CredentialAttribute {
    pub key: String,
    pub value: String,
    pub value_type: String,
    pub encrypted: bool,
}
```

## Issuer Registry

### Registration Requirements

1. Issuers must register with required stake amount
2. Authorization is jurisdiction-specific (ISO 3166 codes)
3. Issuers specify which subcodes they can issue
4. Key rotation is supported for security

### Issuer Structure

```rust
pub struct DocClassIssuer {
    pub address: Address,
    pub name: String,
    pub issuer_type: DocClassIssuerType,
    pub jurisdictions: Vec<String>,
    pub authorized_subcodes: Vec<DocSubcode>,
    pub keys: Vec<IssuerKey>,
    pub registered_at: Timestamp,
    pub updated_at: Timestamp,
    pub status: DocClassIssuerStatus,
    pub stake_amount: Balance,
    pub metadata: Option<String>,
}
```

### Issuer Types

```rust
pub enum DocClassIssuerType {
    Government,
    Educational,
    Professional,
    Corporate,
    Healthcare,
    Legal,
    SelfSovereign,
}
```

### Authorization Check

For issuing credentials, the following must be true:
1. Issuer is registered and active
2. Issuer has the subcode in `authorized_subcodes`
3. Issuer has the jurisdiction in `jurisdictions`
4. Issuer has an active signing key

## Revocation System

### Revocation Record

```rust
pub struct RevocationRecord {
    pub credential_id: CredentialId,
    pub status: RevocationStatus,
    pub reason: RevocationReason,
    pub reason_details: Option<String>,
    pub revoker: Address,
    pub revoked_at: Timestamp,
    pub revoked_at_height: BlockHeight,
    pub superseded_by: Option<CredentialId>,
    pub signature: [u8; 64],
}
```

### Revocation Status

```rust
pub enum RevocationStatus {
    Active,
    Revoked,
    Suspended,
    Expired,
}
```

### Revocation Reasons

```rust
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    IssuerCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
}
```

### Operations

- `Revoke`: Permanently revoke credential
- `Suspend`: Temporarily suspend (can be reactivated)
- `Reactivate`: Reactivate suspended credential
- `Supersede`: Revoke and link to replacement credential

## Transaction Format

### DocClassTxData

```rust
pub struct DocClassTxData {
    pub operation: DocClassOperation,
    pub subcode: DocSubcode,
    pub data: Vec<u8>,
}
```

### Operations

```rust
pub enum DocClassOperation {
    // Identity operations
    CreateIdentityRoot,
    IdentityAddKey,
    IdentityRemoveKey,
    IdentityRotateKey,
    IdentityAddController,
    IdentityRemoveController,
    IdentityUpdateService,
    DeactivateIdentity,

    // Credential operations
    IssueEligibility,
    IssueAcademic,
    UpdateCredential,

    // Revocation operations
    Revoke,
    Suspend,
    Reactivate,
    Supersede,

    // Issuer operations
    RegisterIssuer,
    UpdateIssuer,
    RotateIssuerKey,
    DeactivateIssuer,
}
```

## Events

```rust
pub enum DocClassEvent {
    IdentityRootCreated { identity_id, controller, timestamp },
    KeyAdded { identity_id, key_id, key_type },
    KeyRemoved { identity_id, key_id },
    KeyRotated { identity_id, old_key_id, new_key_id },
    ControllerAdded { identity_id, controller },
    ControllerRemoved { identity_id, controller },
    ServiceUpdated { identity_id, service_id },
    IdentityDeactivated { identity_id, timestamp },
    EligibilityIssued { credential_id, issuer, subject_commitment, eligibility_type, jurisdiction, timestamp },
    AcademicIssued { credential_id, issuer, subject_commitment, subcode, timestamp },
    CredentialRevoked { credential_id, issuer, reason, timestamp },
    CredentialSuspended { credential_id, issuer, reason, timestamp },
    CredentialReactivated { credential_id, issuer, timestamp },
    CredentialSuperseded { old_credential_id, new_credential_id, issuer },
    IssuerRegistered { issuer, issuer_type, jurisdictions, subcodes },
    IssuerUpdated { issuer },
    IssuerKeyRotated { issuer, old_key_id, new_key_id },
    IssuerStatusChanged { issuer, new_status },
}
```

## RPC Endpoints

### Configuration
- `docclass_getConfig`: Get DocClass configuration
- `docclass_getSummary`: Get DocClass statistics

### Identity
- `docclass_getIdentity(identity_id)`: Get identity root
- `docclass_getIdentityByController(controller)`: Get identity by controller

### Credentials
- `docclass_getCredential(credential_id)`: Get any credential
- `docclass_getCredentialsBySubject(subject_commitment)`: Get credentials by subject
- `docclass_getCredentialsByIssuer(issuer)`: Get credentials by issuer
- `docclass_isCredentialValid(credential_id)`: Check credential validity

### Issuers
- `docclass_getIssuer(address)`: Get issuer info
- `docclass_getIssuers(limit, offset)`: List issuers
- `docclass_getIssuersByJurisdiction(jurisdiction)`: Get issuers by jurisdiction
- `docclass_canIssue(issuer, subcode, jurisdiction)`: Check issuer authorization

## Privacy Considerations

### Data On-Chain
- Cryptographic commitments only
- No raw PII
- Issuer signatures for verification

### Data Off-Chain
- Actual credential content (encrypted)
- Subject identity information
- Detailed metadata

### Verification Flow
1. Verifier requests proof from holder
2. Holder provides selective disclosure proof
3. Verifier checks on-chain:
   - Commitment exists
   - Issuer signature valid
   - Not revoked
   - Not expired
4. Verifier verifies holder's proof against commitment

## Security Considerations

### Issuer Key Management
- Multi-key support for redundancy
- Key rotation without credential reissuance
- Key expiration for automatic rotation

### Revocation Transparency
- All revocations on-chain
- Instant propagation
- Historical audit trail

### Replay Protection
- Unique credential IDs
- Nonce in commitment generation
- Block height in revocation records

## Reference Implementation

See the following files in the SUM Chain codebase:
- `crates/primitives/src/docclass.rs`: Core types
- `crates/storage/src/docclass_store.rs`: Storage layer
- `crates/state/src/docclass_executor.rs`: Transaction executor
- `crates/rpc/src/server.rs`: RPC endpoints

## Copyright

This document is released under CC0 1.0 Universal.
