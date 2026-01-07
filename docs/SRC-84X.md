# SRC-84X: Legal Instruments, IP, Notary & Attestation

## Overview

SRC-84X is a privacy-first infrastructure for managing legal agreements, intellectual property rights, notary attestations, and executor contracts on the SUM Chain. It provides a comprehensive framework for recording and managing legally-binding commitments without exposing sensitive personal data on-chain.

## Design Principles

1. **Privacy-First**: No plaintext personal data stored on-chain. All sensitive information is represented as BLAKE3 commitments.
2. **Policy-Driven Trust**: All operations are governed by SRC-803 policies for authorization.
3. **Domain Separation**: Each standard uses unique domain separators for deterministic hashing.
4. **SRC-805 Revocation Compatible**: All entities support revocation references.

---

## Standards

### SRC-841: Agreement Commitment

Provides privacy-preserving agreement anchoring with support for multi-party contracts.

#### Data Structures

```rust
/// Agreement Commitment
struct AgreementCommitment {
    agreement_id: [u8; 32],           // Unique identifier
    agreement_commitment: [u8; 32],    // BLAKE3 hash of agreement content
    parties: Vec<PartyBinding>,        // Parties and their roles
    jurisdiction_code: String,         // e.g., "US-DE", "UK", "SG"
    effective_from: Option<Timestamp>,
    expiry: Option<Timestamp>,
    attachments: Vec<AttachmentRef>,   // Encrypted attachment references
    policy_id: [u8; 32],              // SRC-803 policy
    status: AgreementStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    created_at_height: BlockHeight,
    supersedes: Option<AgreementId>,   // For agreement succession
}

/// Party Reference (privacy-preserving)
enum PartyRef {
    Commitment([u8; 32]),  // BLAKE3 commitment of identity
    Subject(SubjectId),    // Explicit SRC-801 subject (with consent)
}

/// Agreement Status
enum AgreementStatus {
    Draft = 0,
    PendingSignatures = 1,
    Executed = 2,
    Active = 3,
    Expired = 4,
    Terminated = 5,
    Superseded = 6,
    Voided = 7,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 0 | `CommitAgreement` | Create a new agreement commitment |
| 1 | `UpdateAgreement` | Update agreement status |
| 2 | `TerminateAgreement` | Terminate an active agreement |
| 3 | `VoidAgreement` | Void an agreement (never became effective) |
| 4 | `SupersedeAgreement` | Replace with a new agreement |

#### Commitment Generation

```rust
// Agreement ID generation
fn generate_id(creator: &Address, commitment: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    blake3::hash(b"SRC841-AGREEMENT:v1:" || creator || commitment || nonce)
}

// Party commitment (privacy-preserving)
fn generate_party_commitment(subject: &SubjectId, salt: &[u8; 32]) -> [u8; 32] {
    blake3::hash(b"SRC841-PARTY:v1:" || subject || salt)
}
```

---

### SRC-842: Party Signatures & Role Binding

Manages offer/countersign workflows with role-based signing.

#### Data Structures

```rust
/// Party Signature
struct PartySignature {
    signature_id: [u8; 32],
    agreement_id: [u8; 32],
    party_ref: PartyRef,
    role: AgreementRole,
    signature_type: SignatureType,
    signature: Vec<u8>,
    signer_key: [u8; 32],
    signed_at: Timestamp,
    recorded_at_height: BlockHeight,
    witness_attestation_id: Option<AttestationId>,
}

/// Agreement Roles
enum AgreementRole {
    Buyer = 0,
    Seller = 1,
    Employer = 2,
    Employee = 3,
    Landlord = 4,
    Tenant = 5,
    Licensor = 6,
    Licensee = 7,
    Lender = 8,
    Borrower = 9,
    Guarantor = 10,
    Beneficiary = 11,
    Trustee = 12,
    Settlor = 13,
    Assignor = 14,
    Assignee = 15,
    Principal = 16,
    Agent = 17,
    Partner = 18,
    Shareholder = 19,
    Witness = 20,
    Notary = 21,
    Mediator = 22,
    Arbitrator = 23,
    Other = 255,
}

/// Signature Types
enum SignatureType {
    Single,                              // Standard signature
    Threshold { threshold: u8, total: u8 }, // t-of-n threshold
    Multi { required: u8 },              // All required
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 10 | `SignAgreement` | Add a party signature |
| 11 | `RevokeSignature` | Revoke a signature |
| 12 | `AddParty` | Add a party to agreement |
| 13 | `RemoveParty` | Remove a party from agreement |

#### Signing Message Generation

```rust
fn generate_signing_message(
    agreement_id: &[u8; 32],
    commitment: &[u8; 32],
    party_ref: &PartyRef,
    role: AgreementRole,
    policy_id: &[u8; 32],
) -> [u8; 32] {
    blake3::hash(
        b"SRC842-SIGN-MSG:v1:" ||
        agreement_id ||
        commitment ||
        party_ref.as_hash() ||
        role ||
        policy_id
    )
}
```

---

### SRC-843: Notary & Attestation Packet

Supports certified notarization and professional attestations.

#### Data Structures

```rust
/// Attestation Packet
struct AttestationPacket {
    attestation_id: [u8; 32],
    target_ref: AttestationTarget,
    issuer_address: Address,
    issuer_class: AttestationIssuerClass,
    attestation_type: AttestationType,
    notary_commitment: [u8; 32],
    jurisdiction_code: String,
    valid_from: Timestamp,
    expiry: Option<Timestamp>,
    revocation_ref: Option<[u8; 32]>,
    status: AttestationStatus,
    created_at: Timestamp,
    recorded_at_height: BlockHeight,
    policy_id: [u8; 32],
}

/// Attestation Target
enum AttestationTarget {
    Agreement(AgreementId),
    DocumentHash([u8; 32]),
    Signature(SignatureId),
    IpAction(IpAssetId),
}

/// Issuer Classes (SRC-802 compatible)
enum AttestationIssuerClass {
    NotaryPublic = 0,
    LawFirm = 1,
    Auditor = 2,
    Cpa = 3,
    CourtOfficial = 4,
    GovernmentAgency = 5,
    RegisteredAgent = 6,
    EscrowAgent = 7,
    TitleCompany = 8,
    Other = 255,
}

/// Attestation Types
enum AttestationType {
    Notarization = 0,
    SignatureWitness = 1,
    IdentityVerification = 2,
    DocumentAuthentication = 3,
    Apostille = 4,
    Certification = 5,
    Acknowledgment = 6,
    Jurat = 7,
    CopyCertification = 8,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 20 | `CreateAttestation` | Create a new attestation |
| 21 | `RevokeAttestation` | Revoke an attestation |
| 22 | `UpdateAttestationStatus` | Update attestation status |

---

### SRC-844: IP Rights & Creative Actions

Manages intellectual property assignments, licenses, and pledges.

#### Data Structures

```rust
/// IP Rights Action
struct IpRightsAction {
    action_id: [u8; 32],
    ip_asset_commitment: [u8; 32],     // Hash of IP asset details
    asset_type: IpAssetType,
    action_type: IpActionType,
    scope_commitment: [u8; 32],        // Territory/term/field-of-use
    rightsholder_ref: PartyRef,
    counterparty_ref: Option<PartyRef>,
    policy_id: [u8; 32],
    valid_from: Timestamp,
    expiry: Option<Timestamp>,
    revocation_ref: Option<[u8; 32]>,
    status: IpActionStatus,
    created_at: Timestamp,
    recorded_at_height: BlockHeight,
    agreement_id: Option<AgreementId>,
    attachments: Vec<AttachmentRef>,
}

/// IP Asset Types
enum IpAssetType {
    Patent = 0,
    Trademark = 1,
    Copyright = 2,
    TradeSecret = 3,
    Design = 4,
    Software = 5,
    Database = 6,
    Domain = 7,
    Other = 255,
}

/// IP Action Types
enum IpActionType {
    Assignment = 0,
    License = 1,
    Pledge = 2,
    Release = 3,
    ExclusiveLicense = 4,
    NonExclusiveLicense = 5,
    Sublicense = 6,
    LicenseTermination = 7,
    PledgeTransfer = 8,
    PledgeRelease = 9,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 30 | `RecordIpAction` | Record a new IP action |
| 31 | `UpdateIpAction` | Update an IP action |
| 32 | `TerminateIpAction` | Terminate an IP action |
| 33 | `RevokeIpAction` | Revoke an IP action |

---

### SRC-845: Execution Link Standard

Links agreements to smart contract executors for automated enforcement.

#### Data Structures

```rust
/// Executor Link
struct ExecutorLink {
    link_id: [u8; 32],
    agreement_id: [u8; 32],
    executor_contract: Address,
    executor_interface_id: [u8; 32],
    terms_commitment: [u8; 32],
    activation_policy_id: [u8; 32],
    state: ExecutorState,
    created_at: Timestamp,
    updated_at: Timestamp,
    created_at_height: BlockHeight,
    activation_proof_id: Option<ProofId>,
}

/// Executor States
enum ExecutorState {
    Draft = 0,
    Active = 1,
    Paused = 2,
    Terminated = 3,
    Completed = 4,
    Disputed = 5,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 40 | `LinkExecutor` | Create a new executor link |
| 41 | `ActivateExecutor` | Activate a draft executor |
| 42 | `PauseExecutor` | Pause an active executor |
| 43 | `ResumeExecutor` | Resume a paused executor |
| 44 | `TerminateExecutor` | Terminate an executor |
| 45 | `CompleteExecutor` | Mark executor as completed |

---

### SRC-846: 84X Proof Profiles

ZK proof interfaces for privacy-preserving verification.

#### Data Structures

```rust
/// Agreement Proof Envelope
struct AgreementProofEnvelope {
    proof_id: [u8; 32],
    profile: AgreementProofProfile,
    profile_id: String,               // e.g., "agreement.signed_by_roles.v1"
    policy_ids: Vec<[u8; 32]>,
    public_inputs: Vec<u8>,
    proof_data: Vec<u8>,
    proof_type: AgreementProofType,
    subject_nullifier: [u8; 32],
    generated_at: Timestamp,
    expires_at: Timestamp,
}

/// Proof Profiles
enum AgreementProofProfile {
    SignedByRoles = 0,      // Prove agreement is signed by specified roles
    NotaryAttested = 1,     // Prove notary attestation exists
    IpAssignmentValid = 2,  // Prove IP assignment is valid
    ExecutorBoundActive = 3, // Prove executor is bound and active
    PartyBound = 4,         // Prove party is bound to agreement
    AgreementStatus = 5,    // Prove agreement is in specified status
}

/// Proof Types (SRC-806 compatible)
enum AgreementProofType {
    Mock = 0,
    Groth16 = 1,
    Plonk = 2,
    ThresholdSignature = 3,
    MerkleInclusion = 4,
}
```

#### Operations

| Code | Operation | Description |
|------|-----------|-------------|
| 50 | `SubmitProof` | Submit a proof envelope |
| 51 | `VerifyProof` | Request proof verification |

---

## Transaction Format

```rust
/// SRC-84X Transaction Data
struct AgreementTxData {
    operation: AgreementOperation,
    data: Vec<u8>,  // Bincode-serialized operation data
}
```

### Transaction Type

- **TxType**: `Agreement = 10`
- **TxPayload**: `Agreement(AgreementTxData)`

---

## Storage Schema

### Column Families

| Column Family | Description |
|--------------|-------------|
| `agreement_commitments` | Agreement commitment records |
| `agreement_signatures` | Party signature records |
| `agreement_attestations` | Attestation packets |
| `agreement_ip_actions` | IP rights actions |
| `agreement_executor_links` | Executor link records |
| `agreement_proofs` | Proof envelopes |
| `agreement_party_index` | Party → Agreement index |
| `agreement_executor_index` | Executor → Link index |
| `agreement_events` | System events |

---

## Events

```rust
enum AgreementEvent {
    // SRC-841
    AgreementCommitted { agreement_id, policy_id, commitment_hash, timestamp },
    AgreementUpdated { agreement_id, new_status, timestamp },
    AgreementTerminated { agreement_id, timestamp },
    AgreementSuperseded { old_agreement_id, new_agreement_id, timestamp },

    // SRC-842
    AgreementSigned { agreement_id, party_ref_hash, role, signer, timestamp },
    SignatureRevoked { agreement_id, signature_id, timestamp },

    // SRC-843
    NotaryAttested { target_id, notary, attestation_hash, timestamp },
    AttestationRevoked { attestation_id, timestamp },

    // SRC-844
    IpActionRecorded { ip_asset_hash, action_type, policy_id, timestamp },
    IpActionUpdated { action_id, new_status, timestamp },

    // SRC-845
    ExecutorLinked { agreement_id, executor, interface_id, state, timestamp },
    ExecutorStateUpdated { agreement_id, link_id, new_state, timestamp },

    // SRC-846
    ProofSubmitted { proof_id, profile, timestamp },
    ProofVerified { proof_id, valid, timestamp },
}
```

---

## Security Considerations

1. **Authorization**: All operations require proper SRC-803 policy authorization.
2. **Issuer Verification**: Attestation issuers must be registered under SRC-802.
3. **Signature Verification**: All signatures are verified on-chain.
4. **Revocation Checking**: Operations check SRC-805 revocation status.

---

## Example Usage

### Creating an Agreement

```rust
let agreement = AgreementCommitment {
    agreement_id: AgreementCommitment::generate_id(&creator, &commitment, &nonce),
    agreement_commitment: AgreementCommitment::generate_commitment(terms, schema_hash, 1),
    parties: vec![
        PartyBinding {
            party_ref: PartyRef::Commitment(buyer_commitment),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        },
        PartyBinding {
            party_ref: PartyRef::Commitment(seller_commitment),
            role: AgreementRole::Seller,
            signed: false,
            signed_at: None,
        },
    ],
    jurisdiction_code: "US-DE".to_string(),
    effective_from: Some(now),
    expiry: Some(now + ONE_YEAR),
    attachments: vec![],
    policy_id: policy_id,
    status: AgreementStatus::PendingSignatures,
    created_at: now,
    updated_at: now,
    created_at_height: current_height,
    supersedes: None,
};

let tx_data = AgreementTxData {
    operation: AgreementOperation::CommitAgreement,
    data: bincode::serialize(&agreement).unwrap(),
};
```

### Signing an Agreement

```rust
let signature = PartySignature {
    signature_id: PartySignature::generate_id(&agreement_id, &party_ref, role, &nonce),
    agreement_id,
    party_ref: PartyRef::Commitment(my_commitment),
    role: AgreementRole::Buyer,
    signature_type: SignatureType::Single,
    signature: ed25519_sign(signing_message),
    signer_key: my_public_key,
    signed_at: now,
    recorded_at_height: current_height,
    witness_attestation_id: None,
};

let tx_data = AgreementTxData {
    operation: AgreementOperation::SignAgreement,
    data: bincode::serialize(&signature).unwrap(),
};
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial release |
