# SRC-80X: Layered Trust Architecture

## Abstract

SRC-80X defines a modular, ZK-first trust architecture for the SUM Chain blockchain. Rather than bundling identity and claims into monolithic credentials, SRC-80X separates concerns into distinct, composable standards:

| Standard | Name | Purpose |
|----------|------|---------|
| SRC-801 | Subject Standard | DID-like identity anchors |
| SRC-802 | Issuer Registry | Who may attest |
| SRC-803 | Policy Token | Verification rules |
| SRC-804 | Claim Token | Verifiable statements |
| SRC-805 | Revocation Standard | Privacy-preserving invalidation |
| SRC-806 | Proof Envelope | ZK proof containers |

## Design Principles

1. **Identity is not data** — A subject is a cryptographic reference point, not a container of personal information
2. **Trust is plural** — No single issuer monopolizes attestation authority; policies define acceptable trust sources
3. **Verification rules are code** — Policies are deterministic, on-chain objects that define validity
4. **The chain stores verifiability, not information** — Only commitments and proofs; never raw PII
5. **Claims must be revocable without being traceable** — Revocation operates on claims, not subjects
6. **Verifiers trust math and quorum, not institutions** — ZK proofs and policy compliance, not blind trust

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CONSUMERS                                 │
│         (Voting, Access Control, DeFi, Applications)            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SRC-806: Proof Envelope                       │
│              (ZK Proofs, Context Separation, Unlinkability)     │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   SRC-804       │ │   SRC-803       │ │   SRC-805       │
│   Claim Token   │ │   Policy Token  │ │   Revocation    │
└─────────────────┘ └─────────────────┘ └─────────────────┘
          │                   │                   │
          ▼                   ▼                   │
┌─────────────────┐ ┌─────────────────┐           │
│   SRC-802       │ │   Quorum/Trust  │           │
│   Issuer Reg    │ │   Rules         │◄──────────┘
└─────────────────┘ └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SRC-801: Subject Standard                     │
│                  (DID, Keys, Controllers, Lifecycle)            │
└─────────────────────────────────────────────────────────────────┘
```

## Module Dependencies

```
SRC-806 (Proof) ──depends on──► SRC-804 (Claim)
                               SRC-803 (Policy)
                               SRC-805 (Revocation)

SRC-804 (Claim) ──depends on──► SRC-801 (Subject)
                               SRC-802 (Issuer)
                               SRC-803 (Policy)
                               SRC-805 (Revocation)

SRC-803 (Policy) ──depends on─► SRC-802 (Issuer) [for issuer class refs]

SRC-802 (Issuer) ──standalone──

SRC-801 (Subject) ──standalone──

SRC-805 (Revocation) ──depends on─► SRC-804 (Claim) [for claim refs]
```

---

# SRC-801: Subject Standard

## Purpose

Defines the on-chain representation of a subject (person, organization, or agent) without embedding real-world identity data. The subject is a cryptographic anchor, not a data store.

## Principle

> Identity is not data — it is a cryptographic reference point.

## Data Model

```rust
/// Unique subject identifier (DID-style)
pub type SubjectId = [u8; 32];

/// On-chain subject record
pub struct Subject {
    /// Unique identifier (hash of creation params + nonce)
    pub id: SubjectId,

    /// Primary controller address (can update keys, manage lifecycle)
    pub controller: Address,

    /// Additional controllers (recovery, delegates)
    pub recovery_controllers: Vec<Address>,

    /// Active public keys for this subject
    pub keys: Vec<SubjectKey>,

    /// Lifecycle status
    pub status: SubjectStatus,

    /// Creation block height
    pub created_at: BlockHeight,

    /// Last modification block height
    pub updated_at: BlockHeight,

    /// Nonce for replay protection
    pub nonce: u64,
}

/// Subject key with purpose designation
pub struct SubjectKey {
    /// Key identifier (unique within subject)
    pub key_id: String,

    /// Cryptographic algorithm
    pub key_type: KeyType,

    /// Public key bytes
    pub public_key: [u8; 32],

    /// Authorized purposes for this key
    pub purposes: Vec<KeyPurpose>,

    /// Block height when added
    pub added_at: BlockHeight,

    /// Optional expiration (0 = no expiry)
    pub expires_at: BlockHeight,

    /// Whether key is currently active
    pub active: bool,
}

pub enum KeyType {
    Ed25519,
    Secp256k1,
    Bls12381G2,
}

pub enum KeyPurpose {
    /// Sign authentication challenges
    Authentication,
    /// Sign claims/assertions
    AssertionMethod,
    /// Derive shared secrets
    KeyAgreement,
    /// Invoke capabilities
    CapabilityInvocation,
    /// Delegate capabilities
    CapabilityDelegation,
}

pub enum SubjectStatus {
    Active,
    Deactivated,
    Suspended,
}
```

## Operations

```rust
pub enum SubjectOperation {
    /// Create new subject anchor
    Create,
    /// Add a new key
    AddKey,
    /// Remove/revoke a key
    RemoveKey,
    /// Rotate key (atomic remove + add)
    RotateKey,
    /// Add recovery controller
    AddController,
    /// Remove controller
    RemoveController,
    /// Transfer primary control
    TransferControl,
    /// Deactivate subject (permanent)
    Deactivate,
    /// Suspend subject (reversible)
    Suspend,
    /// Reactivate suspended subject
    Reactivate,
}
```

## Events

```rust
pub enum SubjectEvent {
    Created {
        subject_id: SubjectId,
        controller: Address,
        initial_key_id: String,
    },
    KeyAdded {
        subject_id: SubjectId,
        key_id: String,
        key_type: KeyType,
        purposes: Vec<KeyPurpose>,
    },
    KeyRemoved {
        subject_id: SubjectId,
        key_id: String,
    },
    KeyRotated {
        subject_id: SubjectId,
        old_key_id: String,
        new_key_id: String,
    },
    ControllerAdded {
        subject_id: SubjectId,
        controller: Address,
    },
    ControllerRemoved {
        subject_id: SubjectId,
        controller: Address,
    },
    ControlTransferred {
        subject_id: SubjectId,
        old_controller: Address,
        new_controller: Address,
    },
    StatusChanged {
        subject_id: SubjectId,
        old_status: SubjectStatus,
        new_status: SubjectStatus,
    },
}
```

## Constraints

- A subject MUST have at least one active authentication key
- A subject MUST have exactly one primary controller
- Key IDs MUST be unique within a subject
- Deactivation is PERMANENT and irreversible
- No personal attributes are stored in the subject record

---

# SRC-802: Issuer Registry Standard

## Purpose

Defines who is allowed to issue or attest to claims. Issuers are categorized by class and authorized per claim type.

## Principle

> Trust is plural and permissioned by policy, not monopolized.

## Data Model

```rust
/// Unique issuer identifier
pub type IssuerId = Address;

/// Issuer class taxonomy
pub enum IssuerClass {
    /// Government agencies (DMV, passport office, etc.)
    Government,
    /// Banks, credit unions, financial institutions
    Financial,
    /// Universities, schools, certification bodies
    Educational,
    /// Professional licensing boards
    Professional,
    /// Employers, corporations
    Corporate,
    /// Hospitals, clinics, medical boards
    Healthcare,
    /// Courts, notaries, law firms
    Legal,
    /// Audit firms, rating agencies
    Auditor,
    /// Community-based attestation
    Community,
    /// Custom class (specified by ID)
    Custom(u32),
}

/// Registered issuer record
pub struct Issuer {
    /// Issuer address (primary identifier)
    pub id: IssuerId,

    /// Human-readable name
    pub name: String,

    /// Issuer classification
    pub class: IssuerClass,

    /// Claim types this issuer may attest
    pub authorized_claim_types: Vec<ClaimType>,

    /// Active signing keys
    pub keys: Vec<IssuerKey>,

    /// Staked amount (for slashing)
    pub stake: Balance,

    /// Reputation score (0-1000)
    pub reputation: u32,

    /// Registration status
    pub status: IssuerStatus,

    /// Metadata URI (off-chain details)
    pub metadata_uri: Option<String>,

    /// Registration block
    pub registered_at: BlockHeight,

    /// Last update block
    pub updated_at: BlockHeight,
}

pub struct IssuerKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key: [u8; 32],
    pub added_at: BlockHeight,
    pub expires_at: BlockHeight,
    pub active: bool,
}

pub enum IssuerStatus {
    /// Can issue claims
    Active,
    /// Temporarily cannot issue
    Suspended,
    /// Permanently removed
    Revoked,
    /// Pending approval
    Pending,
}

/// Claim types that can be attested
pub enum ClaimType {
    /// Age threshold (18+, 21+, 65+)
    AgeThreshold,
    /// Citizenship/nationality
    Citizenship,
    /// Residency status
    Residency,
    /// Employment status
    Employment,
    /// Educational credential
    Education,
    /// Professional license
    License,
    /// Financial standing
    Financial,
    /// Health status
    Health,
    /// Membership status
    Membership,
    /// Accreditation
    Accreditation,
    /// Custom type
    Custom(u32),
}
```

## Operations

```rust
pub enum IssuerOperation {
    /// Register new issuer
    Register,
    /// Update issuer metadata
    Update,
    /// Add signing key
    AddKey,
    /// Remove signing key
    RemoveKey,
    /// Rotate key
    RotateKey,
    /// Add authorized claim type
    AddClaimType,
    /// Remove authorized claim type
    RemoveClaimType,
    /// Increase stake
    Stake,
    /// Withdraw stake (after cooldown)
    Unstake,
    /// Suspend issuer (admin only)
    Suspend,
    /// Revoke issuer (admin only)
    Revoke,
    /// Reactivate issuer
    Reactivate,
}
```

## Events

```rust
pub enum IssuerEvent {
    Registered {
        issuer: IssuerId,
        class: IssuerClass,
        initial_stake: Balance,
    },
    KeyAdded {
        issuer: IssuerId,
        key_id: String,
    },
    KeyRemoved {
        issuer: IssuerId,
        key_id: String,
    },
    ClaimTypeAuthorized {
        issuer: IssuerId,
        claim_type: ClaimType,
    },
    ClaimTypeRevoked {
        issuer: IssuerId,
        claim_type: ClaimType,
    },
    StakeChanged {
        issuer: IssuerId,
        old_stake: Balance,
        new_stake: Balance,
    },
    ReputationChanged {
        issuer: IssuerId,
        old_reputation: u32,
        new_reputation: u32,
    },
    StatusChanged {
        issuer: IssuerId,
        old_status: IssuerStatus,
        new_status: IssuerStatus,
    },
    Slashed {
        issuer: IssuerId,
        amount: Balance,
        reason: SlashReason,
    },
}

pub enum SlashReason {
    FalseAttestation,
    KeyCompromise,
    ProtocolViolation,
}
```

## Authorization Rules

For an issuer to attest a claim:
1. Issuer status MUST be `Active`
2. Issuer MUST have `claim_type` in `authorized_claim_types`
3. Issuer MUST have at least one active, non-expired signing key
4. If policy requires minimum stake: `issuer.stake >= policy.min_stake`
5. If policy requires minimum reputation: `issuer.reputation >= policy.min_reputation`

---

# SRC-803: Policy Token Standard

## Purpose

Defines the verification rules required for a claim to be considered valid. Policies are on-chain, composable objects that specify trust requirements.

## Principle

> Verification rules are code, not discretion.

## Data Model

```rust
/// Unique policy identifier (hash of policy content)
pub type PolicyId = [u8; 32];

/// Policy definition
pub struct Policy {
    /// Unique identifier
    pub id: PolicyId,

    /// Human-readable name
    pub name: String,

    /// What type of claim this policy validates
    pub claim_type: ClaimType,

    /// Quorum rule for issuer attestations
    pub quorum: QuorumRule,

    /// Allowed issuer constraints
    pub issuer_constraints: IssuerConstraints,

    /// Optional jurisdiction scope
    pub jurisdiction: Option<Jurisdiction>,

    /// Risk classification
    pub risk_level: RiskLevel,

    /// Revocation checking strategy
    pub revocation_strategy: RevocationStrategy,

    /// Minimum claim validity period (seconds)
    pub min_validity: u64,

    /// Maximum claim validity period (seconds)
    pub max_validity: u64,

    /// Policy version
    pub version: u32,

    /// Creator address
    pub creator: Address,

    /// Creation block
    pub created_at: BlockHeight,

    /// Whether policy is active
    pub active: bool,
}

/// Quorum rules for multi-issuer attestation
pub enum QuorumRule {
    /// Single issuer sufficient
    Single,

    /// t-of-n from any allowed issuers
    Threshold {
        required: u32,
        total: u32,
    },

    /// t-of-n from specific issuer classes
    ClassBased {
        required_per_class: Vec<(IssuerClass, u32)>,
    },

    /// Specific issuer set required
    ExplicitSet {
        required_issuers: Vec<IssuerId>,
        threshold: u32,
    },

    /// Weighted voting by stake
    StakeWeighted {
        min_total_stake: Balance,
        min_issuers: u32,
    },
}

/// Constraints on which issuers may satisfy this policy
pub struct IssuerConstraints {
    /// Allowed issuer classes (empty = all)
    pub allowed_classes: Vec<IssuerClass>,

    /// Explicitly allowed issuers (empty = class-based)
    pub allowed_issuers: Vec<IssuerId>,

    /// Explicitly blocked issuers
    pub blocked_issuers: Vec<IssuerId>,

    /// Minimum stake required
    pub min_stake: Balance,

    /// Minimum reputation required (0-1000)
    pub min_reputation: u32,
}

pub struct Jurisdiction {
    /// ISO 3166-1 alpha-2 country code
    pub country: String,
    /// ISO 3166-2 subdivision code (optional)
    pub subdivision: Option<String>,
}

pub enum RiskLevel {
    /// Low-stakes verification (age check for content)
    Low,
    /// Medium-stakes (membership verification)
    Medium,
    /// High-stakes (financial, legal)
    High,
    /// Critical (voting, government)
    Critical,
}

pub enum RevocationStrategy {
    /// Check on-chain revocation registry
    OnChain,
    /// Short-lived claims, no revocation check
    ShortLived,
    /// Accumulator-based (ZK-friendly)
    Accumulator,
    /// Validity period only, no explicit revocation
    ValidityOnly,
}
```

## Policy Evaluation

```rust
/// Result of policy evaluation
pub struct PolicyEvaluation {
    pub policy_id: PolicyId,
    pub satisfied: bool,
    pub quorum_met: bool,
    pub valid_attestations: u32,
    pub required_attestations: u32,
    pub revocation_clear: bool,
    pub within_validity: bool,
}

/// Evaluate a claim against a policy
pub fn evaluate_policy(
    policy: &Policy,
    claim: &Claim,
    attestations: &[Attestation],
    revocation_state: &RevocationState,
    current_block: BlockHeight,
) -> PolicyEvaluation;
```

## Events

```rust
pub enum PolicyEvent {
    Created {
        policy_id: PolicyId,
        claim_type: ClaimType,
        creator: Address,
    },
    Updated {
        policy_id: PolicyId,
        old_version: u32,
        new_version: u32,
    },
    Deactivated {
        policy_id: PolicyId,
    },
    Reactivated {
        policy_id: PolicyId,
    },
}
```

## ZK Compatibility

Policies are designed to be evaluable inside ZK circuits:
- Fixed-size data structures where possible
- Deterministic evaluation order
- No floating-point arithmetic
- Hash-based references only

---

# SRC-804: Claim Token Standard

## Purpose

Represents a verified statement about a subject, without revealing underlying data. Claims are purpose-limited, time-bounded, and always reference a policy.

## Principle

> The chain stores verifiability, not information.

## Data Model

```rust
/// Unique claim identifier
pub type ClaimId = [u8; 32];

/// On-chain claim record
pub struct Claim {
    /// Unique identifier (hash of claim content)
    pub id: ClaimId,

    /// Reference to subject (SRC-801)
    pub subject_id: SubjectId,

    /// Type of claim
    pub claim_type: ClaimType,

    /// Policy that governs this claim (SRC-803)
    pub policy_id: PolicyId,

    /// Commitment to claim content (BLAKE3)
    pub content_commitment: [u8; 32],

    /// Issuer attestations
    pub attestations: Vec<Attestation>,

    /// Revocation reference (SRC-805)
    pub revocation_ref: RevocationRef,

    /// Validity window
    pub valid_from: Timestamp,
    pub valid_until: Timestamp,

    /// Creation block
    pub created_at: BlockHeight,

    /// Claim schema version
    pub schema_version: u32,
}

/// Issuer attestation on a claim
pub struct Attestation {
    /// Attesting issuer (SRC-802)
    pub issuer_id: IssuerId,

    /// Key used for signing
    pub key_id: String,

    /// Signature over claim commitment
    pub signature: [u8; 64],

    /// Block height of attestation
    pub attested_at: BlockHeight,

    /// Optional attestation metadata commitment
    pub metadata_commitment: Option<[u8; 32]>,
}

/// Reference to revocation state
pub struct RevocationRef {
    /// Revocation method
    pub method: RevocationMethod,

    /// Method-specific reference data
    pub reference: [u8; 32],
}

pub enum RevocationMethod {
    /// Direct on-chain lookup
    OnChain,
    /// Cryptographic accumulator
    Accumulator,
    /// Merkle tree inclusion
    MerkleTree,
    /// No revocation (validity period only)
    None,
}
```

## Content Commitment

The `content_commitment` is generated as:

```
content_commitment = BLAKE3(
    claim_type ||
    subject_id ||
    policy_id ||
    claim_data_hash ||
    valid_from ||
    valid_until ||
    nonce
)
```

Where `claim_data_hash` is the hash of the actual claim data (held off-chain by the subject). This enables:
- Selective disclosure proofs
- ZK proofs about claim properties
- No on-chain storage of claim content

## Operations

```rust
pub enum ClaimOperation {
    /// Issue new claim with attestations
    Issue,
    /// Add attestation to existing claim
    AddAttestation,
    /// Renew claim with new validity period
    Renew,
    /// Supersede with new claim
    Supersede,
}
```

## Events

```rust
pub enum ClaimEvent {
    Issued {
        claim_id: ClaimId,
        subject_id: SubjectId,
        claim_type: ClaimType,
        policy_id: PolicyId,
        initial_attestations: u32,
    },
    AttestationAdded {
        claim_id: ClaimId,
        issuer_id: IssuerId,
        attestation_count: u32,
    },
    Renewed {
        claim_id: ClaimId,
        old_valid_until: Timestamp,
        new_valid_until: Timestamp,
    },
    Superseded {
        old_claim_id: ClaimId,
        new_claim_id: ClaimId,
    },
}
```

## Validation Flow

```
1. Subject requests claim from issuer(s)
2. Issuer(s) verify off-chain data
3. Issuer(s) sign commitment and create attestations
4. Claim is submitted to chain with attestations
5. Chain validates:
   - Subject exists and is active
   - Policy exists and is active
   - All issuers are registered and authorized
   - Quorum is satisfied per policy
   - Signatures are valid
6. Claim is stored with revocation reference
```

---

# SRC-805: Revocation & Expiry Standard

## Purpose

Allows claims to be invalidated without breaking privacy or enabling traceability across contexts.

## Principle

> A claim must be revocable without being traceable.

## Data Model

```rust
/// Revocation registry entry
pub struct RevocationEntry {
    /// Claim being revoked
    pub claim_id: ClaimId,

    /// Revocation status
    pub status: RevocationStatus,

    /// Reason for revocation
    pub reason: RevocationReason,

    /// Who initiated revocation
    pub revoker: Address,

    /// Block height of revocation
    pub revoked_at: BlockHeight,

    /// Signature of revoker
    pub signature: [u8; 64],
}

pub enum RevocationStatus {
    /// Claim is valid
    Active,
    /// Claim is permanently invalid
    Revoked,
    /// Claim is temporarily invalid
    Suspended,
    /// Claim expired naturally
    Expired,
}

pub enum RevocationReason {
    /// No specific reason
    Unspecified,
    /// Subject's key compromised
    SubjectKeyCompromise,
    /// Issuer's key compromised
    IssuerKeyCompromise,
    /// Underlying data changed
    DataChanged,
    /// Replaced by new claim
    Superseded,
    /// Issuer ceased operations
    IssuerCeased,
    /// Administrative hold
    Hold,
    /// Fraud detected
    Fraud,
}
```

## Accumulator-Based Revocation

For ZK-friendly revocation without revealing which claims are revoked:

```rust
/// Cryptographic accumulator state
pub struct AccumulatorState {
    /// Current accumulator value
    pub accumulator: [u8; 32],

    /// Epoch number
    pub epoch: u64,

    /// Block height of last update
    pub updated_at: BlockHeight,
}

/// Witness for non-revocation proof
pub struct NonRevocationWitness {
    /// Claim ID
    pub claim_id: ClaimId,

    /// Accumulator epoch this witness is valid for
    pub epoch: u64,

    /// Witness data for membership proof
    pub witness: Vec<u8>,
}
```

## Operations

```rust
pub enum RevocationOperation {
    /// Revoke a claim permanently
    Revoke,
    /// Suspend a claim temporarily
    Suspend,
    /// Reactivate a suspended claim
    Reactivate,
    /// Update accumulator state
    UpdateAccumulator,
    /// Publish new witness epoch
    PublishEpoch,
}
```

## Events

```rust
pub enum RevocationEvent {
    Revoked {
        claim_id: ClaimId,
        reason: RevocationReason,
        revoker: Address,
    },
    Suspended {
        claim_id: ClaimId,
        reason: RevocationReason,
        revoker: Address,
    },
    Reactivated {
        claim_id: ClaimId,
        revoker: Address,
    },
    AccumulatorUpdated {
        old_accumulator: [u8; 32],
        new_accumulator: [u8; 32],
        epoch: u64,
    },
}
```

## Revocation Checking

```rust
/// Check revocation status
pub fn check_revocation(
    claim_id: ClaimId,
    strategy: RevocationStrategy,
    current_block: BlockHeight,
) -> RevocationResult;

pub enum RevocationResult {
    /// Claim is not revoked
    Valid,
    /// Claim is revoked
    Revoked(RevocationReason),
    /// Claim is suspended
    Suspended,
    /// Claim expired
    Expired,
    /// Could not determine (accumulator witness needed)
    WitnessRequired,
}
```

## Privacy Properties

- Revocation is CLAIM-scoped, not SUBJECT-scoped
- No global blacklist of subjects
- Accumulator proofs reveal nothing about other claims
- Revocation events do not link to subject identity

---

# SRC-806: Proof Envelope Standard

## Purpose

Defines how off-chain verification is expressed and validated. Proof envelopes wrap ZK proofs with context separation to ensure unlinkability.

## Principle

> Verifiers trust math and quorum, not institutions.

## Data Model

```rust
/// Unique proof identifier
pub type ProofId = [u8; 32];

/// Proof envelope for verification
pub struct ProofEnvelope {
    /// Unique identifier (hash of envelope content)
    pub id: ProofId,

    /// Context domain (prevents cross-context linkage)
    pub context: ProofContext,

    /// The zero-knowledge proof
    pub proof: ZkProof,

    /// Policy being satisfied
    pub policy_id: PolicyId,

    /// Public inputs to the proof
    pub public_inputs: Vec<[u8; 32]>,

    /// Revocation witness (if accumulator-based)
    pub revocation_witness: Option<NonRevocationWitness>,

    /// Timestamp of proof generation
    pub generated_at: Timestamp,

    /// Expiry of this proof
    pub expires_at: Timestamp,
}

/// Context for domain separation
pub struct ProofContext {
    /// Domain string (e.g., "vote:2026:US-CA", "access:club:1234")
    pub domain: String,

    /// Nonce for this specific verification
    pub nonce: [u8; 32],

    /// Optional session binding
    pub session_id: Option<[u8; 32]>,
}

/// Zero-knowledge proof
pub struct ZkProof {
    /// Proof system identifier
    pub system: ProofSystem,

    /// Verification key hash (for circuit identification)
    pub vk_hash: [u8; 32],

    /// Proof bytes
    pub proof_data: Vec<u8>,
}

pub enum ProofSystem {
    /// Groth16 (SNARK)
    Groth16,
    /// PLONK
    Plonk,
    /// Halo2
    Halo2,
    /// STARK
    Stark,
    /// Bulletproofs
    Bulletproofs,
}
```

## Proof Verification

```rust
/// Verification result
pub struct VerificationResult {
    pub valid: bool,
    pub policy_satisfied: bool,
    pub revocation_clear: bool,
    pub within_validity: bool,
    pub context_valid: bool,
}

/// Verify a proof envelope
pub fn verify_proof_envelope(
    envelope: &ProofEnvelope,
    expected_context: &ProofContext,
    current_block: BlockHeight,
) -> VerificationResult;
```

## What Proofs Can Prove

A valid SRC-806 proof demonstrates:

1. **Claim existence**: Prover holds a valid claim of the specified type
2. **Policy compliance**: Claim satisfies the referenced policy
3. **Issuer attestation**: Required quorum of authorized issuers attested
4. **Non-revocation**: Claim has not been revoked (per revocation strategy)
5. **Validity period**: Current time is within claim's validity window

A valid SRC-806 proof does NOT reveal:

- Subject identity or subject ID
- Specific claim content
- Which specific issuers attested
- Any linkable identifier across contexts

## Context Separation

Each proof is bound to a specific context:

```
context_commitment = BLAKE3(
    domain ||
    nonce ||
    session_id ||
    policy_id ||
    timestamp
)
```

This ensures:
- Proof for "vote:2026:election" cannot be reused for "access:bar:check"
- Same subject proving the same claim in different contexts produces different proofs
- No cross-context linkability

## Events

```rust
pub enum ProofEvent {
    Verified {
        proof_id: ProofId,
        policy_id: PolicyId,
        context_domain: String,
        verifier: Address,
    },
    Rejected {
        proof_id: ProofId,
        reason: RejectionReason,
        verifier: Address,
    },
}

pub enum RejectionReason {
    InvalidProof,
    PolicyNotSatisfied,
    Revoked,
    Expired,
    InvalidContext,
    QuorumNotMet,
}
```

## Consumer Integration

Future standards (voting, access control, DeFi) consume SRC-806 without touching identity:

```rust
/// Example: Access control gate
pub fn check_access(
    envelope: &ProofEnvelope,
    required_policy: PolicyId,
    access_context: &str,
) -> bool {
    // Verify proof
    let result = verify_proof_envelope(
        envelope,
        &ProofContext {
            domain: access_context.to_string(),
            nonce: generate_nonce(),
            session_id: None,
        },
        current_block(),
    );

    result.valid &&
    result.policy_satisfied &&
    envelope.policy_id == required_policy
}

/// Example: Voting eligibility (future SRC-9XX)
pub fn verify_voter_eligibility(
    envelope: &ProofEnvelope,
    election_id: &str,
) -> bool {
    // Voting system only sees:
    // - Valid proof
    // - Policy satisfied
    // - Context matches election
    //
    // Voting system does NOT see:
    // - Who the voter is
    // - What specific claim they hold
    // - Any linkable identifier

    verify_proof_envelope(
        envelope,
        &ProofContext {
            domain: format!("vote:{}", election_id),
            nonce: election_nonce(),
            session_id: Some(ballot_session()),
        },
        current_block(),
    ).valid
}
```

---

# Transaction Format

## Unified Transaction Data

```rust
pub struct Src80xTxData {
    /// Which standard this transaction targets
    pub standard: Src80xStandard,

    /// Operation within that standard
    pub operation: Vec<u8>, // Serialized operation enum

    /// Operation data
    pub data: Vec<u8>,
}

pub enum Src80xStandard {
    Subject,     // SRC-801
    Issuer,      // SRC-802
    Policy,      // SRC-803
    Claim,       // SRC-804
    Revocation,  // SRC-805
    Proof,       // SRC-806
}
```

---

# Storage Schema

## Column Families

```rust
// SRC-801 Subject
pub const SUBJECTS: &str = "src801_subjects";
pub const SUBJECT_KEYS: &str = "src801_subject_keys";
pub const SUBJECT_CONTROLLERS: &str = "src801_controllers";

// SRC-802 Issuer
pub const ISSUERS: &str = "src802_issuers";
pub const ISSUER_KEYS: &str = "src802_issuer_keys";
pub const ISSUER_CLAIM_TYPES: &str = "src802_claim_types";

// SRC-803 Policy
pub const POLICIES: &str = "src803_policies";
pub const POLICY_BY_CLAIM_TYPE: &str = "src803_by_claim_type";

// SRC-804 Claim
pub const CLAIMS: &str = "src804_claims";
pub const CLAIM_ATTESTATIONS: &str = "src804_attestations";
pub const CLAIMS_BY_SUBJECT: &str = "src804_by_subject";
pub const CLAIMS_BY_POLICY: &str = "src804_by_policy";

// SRC-805 Revocation
pub const REVOCATIONS: &str = "src805_revocations";
pub const ACCUMULATOR_STATE: &str = "src805_accumulator";
pub const REVOCATION_WITNESSES: &str = "src805_witnesses";

// SRC-806 Proof (verification logs only)
pub const PROOF_VERIFICATIONS: &str = "src806_verifications";
```

---

# RPC Endpoints

## SRC-801 Subject

```
src801_getSubject(subject_id) -> Subject
src801_getSubjectByController(controller) -> Vec<SubjectId>
src801_getSubjectKeys(subject_id) -> Vec<SubjectKey>
src801_isSubjectActive(subject_id) -> bool
```

## SRC-802 Issuer

```
src802_getIssuer(issuer_id) -> Issuer
src802_getIssuersByClass(class) -> Vec<IssuerId>
src802_getIssuersByClaimType(claim_type) -> Vec<IssuerId>
src802_canIssue(issuer_id, claim_type) -> bool
src802_getIssuerReputation(issuer_id) -> u32
```

## SRC-803 Policy

```
src803_getPolicy(policy_id) -> Policy
src803_getPoliciesByClaimType(claim_type) -> Vec<PolicyId>
src803_evaluatePolicy(policy_id, claim_id) -> PolicyEvaluation
```

## SRC-804 Claim

```
src804_getClaim(claim_id) -> Claim
src804_getClaimsBySubject(subject_id) -> Vec<ClaimId>
src804_getClaimsByPolicy(policy_id) -> Vec<ClaimId>
src804_getAttestations(claim_id) -> Vec<Attestation>
src804_isClaimValid(claim_id) -> bool
```

## SRC-805 Revocation

```
src805_getRevocationStatus(claim_id) -> RevocationStatus
src805_getAccumulatorState() -> AccumulatorState
src805_getWitness(claim_id, epoch) -> NonRevocationWitness
```

## SRC-806 Proof

```
src806_verifyProof(envelope, context) -> VerificationResult
src806_getVerificationLog(proof_id) -> Option<ProofEvent>
```

---

# Security Considerations

## Subject Security
- Subjects must protect their private keys
- Recovery controllers should use multi-sig or time-locks
- Deactivation is permanent to prevent key compromise attacks

## Issuer Security
- Issuers must maintain key hygiene
- Stake provides economic security against false attestations
- Reputation creates long-term incentive alignment
- Slashing punishes misbehavior

## Policy Security
- Policies are immutable once created (versioning for updates)
- Quorum rules prevent single-issuer compromise
- Risk levels guide appropriate policy selection

## Claim Security
- Content commitments prevent data leakage
- Attestation signatures are claim-specific
- Validity periods limit exposure window

## Revocation Security
- Accumulator-based revocation preserves privacy
- No global subject blacklists
- Revocation is claim-scoped, not subject-scoped

## Proof Security
- Context separation prevents replay
- Nonces ensure freshness
- Proof systems must be sound and zero-knowledge

---

# Implementation Notes

## Migration from Previous Design

The previous SRC-80X design bundled identity and claims. Migration path:

1. Existing `IdentityRoot` records become SRC-801 `Subject` records
2. Existing `EligibilityAttestation` records become SRC-804 `Claim` records
3. Existing `DocClassIssuer` records become SRC-802 `Issuer` records
4. Existing revocation records migrate to SRC-805
5. New SRC-803 policies must be created for existing claim types
6. SRC-806 proof system is entirely new

## Backward Compatibility

- Old `DocSubcode` values map to new `ClaimType` enum
- Old issuer types map to new `IssuerClass` enum
- Storage column families are renamed with `src80x_` prefix
- RPC endpoints change from `docclass_*` to `src80x_*`

---

# SRC-81X: Education & Professional Credentials

SRC-81X is a reserved range (810-813) for **education and professional credentials** that build on SRC-80X infrastructure:

| Standard | Domain | Examples |
|----------|--------|----------|
| SRC-810 | Academic Transcript | Course records, grades, credits |
| SRC-811 | Diploma/Degree | Bachelor's, Master's, PhD, certificates |
| SRC-812 | Enrollment Verification | Current student status, enrollment dates |
| SRC-813 | Professional License | Medical, legal, engineering licenses, certifications |

Each SRC-81X standard defines:
- Specific `ClaimType` variants (`Education`, `License`)
- Required issuer classes (`Educational`, `Professional`)
- Recommended policies for verification
- Domain-specific ZK circuits for selective disclosure

## Issuer Authorization

| Issuer Type | Authorized Standards |
|-------------|---------------------|
| `Educational` | SRC-810, SRC-811, SRC-812 |
| `Professional` | SRC-813 |

## Not Part of SRC-81X

The following credential types are **not** part of the SRC-81X family and will be defined in separate standard ranges:

- **Government credentials** (ID verification, voter registration) - Government issuers
- **Employment credentials** (work history, income verification) - Corporate issuers
- **Healthcare credentials** (vaccinations, prescriptions) - Healthcare issuers
- **Financial credentials** (credit status, account standing) - Financial issuers

---

# Copyright

This document is released under CC0 1.0 Universal.
