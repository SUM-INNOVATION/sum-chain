//! SRC-84X Legal Instruments, IP, Notary & Attestation Domain
//!
//! Privacy-first infrastructure for:
//! - SRC-841: Agreement Commitments
//! - SRC-842: Party Signatures & Role Binding
//! - SRC-843: Notary & Attestation Packets
//! - SRC-844: IP Rights & Creative Actions
//! - SRC-845: Execution Link Standard
//! - SRC-846: 84X Proof Profiles

use serde::{Deserialize, Serialize};
use crate::{Address, BlockHeight, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Unique agreement identifier
pub type AgreementId = [u8; 32];
/// Unique signature identifier
pub type SignatureId = [u8; 32];
/// Notary attestation identifier
pub type AttestationId = [u8; 32];
/// IP asset identifier
pub type IpAssetId = [u8; 32];
/// Executor link identifier
pub type ExecutorLinkId = [u8; 32];
/// Policy identifier (SRC-803 compatible)
pub type PolicyId = [u8; 32];
/// Proof identifier (SRC-806 compatible)
pub type ProofId = [u8; 32];
/// Subject identifier (SRC-801 compatible)
pub type SubjectId = [u8; 32];

// =============================================================================
// Domain Separators (for deterministic hashing)
// =============================================================================

pub const AGREEMENT_DOMAIN_SEP: &[u8] = b"SRC841-AGREEMENT:";
pub const AGREEMENT_COMMITMENT_SEP: &[u8] = b"SRC841-COMMITMENT:v1:";
pub const PARTY_COMMITMENT_SEP: &[u8] = b"SRC841-PARTY:v1:";
pub const SIGNATURE_DOMAIN_SEP: &[u8] = b"SRC842-SIGNATURE:";
pub const SIGNATURE_MESSAGE_SEP: &[u8] = b"SRC842-SIGN-MSG:v1:";
pub const ATTESTATION_DOMAIN_SEP: &[u8] = b"SRC843-ATTESTATION:";
pub const NOTARY_COMMITMENT_SEP: &[u8] = b"SRC843-NOTARY:v1:";
pub const IP_ACTION_DOMAIN_SEP: &[u8] = b"SRC844-IP-ACTION:";
pub const IP_SCOPE_COMMITMENT_SEP: &[u8] = b"SRC844-SCOPE:v1:";
pub const EXECUTOR_LINK_DOMAIN_SEP: &[u8] = b"SRC845-EXECUTOR:";
pub const TERMS_COMMITMENT_SEP: &[u8] = b"SRC845-TERMS:v1:";
pub const PROOF_PROFILE_DOMAIN_SEP: &[u8] = b"SRC846-PROOF:";

// =============================================================================
// SRC-841: Agreement Commitment
// =============================================================================

/// Party reference - supports both privacy-preserving commitments and explicit subjects
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartyRef {
    /// Privacy-preserving: BLAKE3 commitment of party identity
    Commitment([u8; 32]),
    /// Explicit subject ID (SRC-801) - only when party consents
    Subject(SubjectId),
}

impl PartyRef {
    /// Generate a party commitment from subject and salt
    pub fn generate_commitment(subject: &SubjectId, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PARTY_COMMITMENT_SEP);
        hasher.update(subject);
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Get the hash for indexing (works for both variants)
    pub fn as_hash(&self) -> [u8; 32] {
        match self {
            PartyRef::Commitment(c) => *c,
            PartyRef::Subject(s) => *s,
        }
    }
}

/// Role of a party in an agreement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AgreementRole {
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

/// Encrypted attachment reference (no plaintext on-chain)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// BLAKE3 hash of the encrypted payload
    pub payload_hash: [u8; 32],
    /// Size of the payload in bytes
    pub payload_size: u64,
    /// Optional URI hint for retrieval (e.g., "ipfs://...", "https://...")
    pub hint_uri: Option<String>,
    /// Encryption metadata (algorithm, key commitment, etc.)
    pub encryption_meta: Option<EncryptionMeta>,
}

/// Encryption metadata for attachments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionMeta {
    /// Encryption algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Commitment to the encryption key (for key escrow/recovery)
    pub key_commitment: Option<[u8; 32]>,
    /// Nonce/IV if applicable
    pub nonce: Option<Vec<u8>>,
}

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm = 0,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 1,
    /// X25519 + AES-256-GCM (hybrid)
    X25519Aes256Gcm = 2,
    /// Threshold encryption scheme
    ThresholdEncryption = 3,
}

/// Party binding within an agreement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyBinding {
    /// Party reference (commitment or subject)
    pub party_ref: PartyRef,
    /// Role in the agreement
    pub role: AgreementRole,
    /// Whether this party has signed
    pub signed: bool,
    /// Signature timestamp if signed
    pub signed_at: Option<Timestamp>,
}

/// Agreement status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AgreementStatus {
    /// Draft - not yet finalized
    Draft = 0,
    /// Pending signatures
    PendingSignatures = 1,
    /// Fully executed (all required signatures)
    Executed = 2,
    /// Active and in effect
    Active = 3,
    /// Expired by time
    Expired = 4,
    /// Terminated by parties
    Terminated = 5,
    /// Superseded by another agreement
    Superseded = 6,
    /// Voided (never became effective)
    Voided = 7,
}

/// SRC-841 Agreement Commitment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementCommitment {
    /// Unique agreement identifier
    pub agreement_id: AgreementId,
    /// BLAKE3 hash of canonical agreement content
    pub agreement_commitment: [u8; 32],
    /// Parties and their roles
    pub parties: Vec<PartyBinding>,
    /// Jurisdiction code (e.g., "US-DE", "UK", "SG")
    pub jurisdiction_code: String,
    /// When the agreement becomes effective
    pub effective_from: Option<Timestamp>,
    /// When the agreement expires
    pub expiry: Option<Timestamp>,
    /// Encrypted attachment references
    pub attachments: Vec<AttachmentRef>,
    /// Policy ID governing signature requirements
    pub policy_id: PolicyId,
    /// Current status
    pub status: AgreementStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when created
    pub created_at_height: BlockHeight,
    /// Optional: supersedes another agreement
    pub supersedes: Option<AgreementId>,
}

impl AgreementCommitment {
    /// Generate deterministic agreement ID
    pub fn generate_id(
        creator: &Address,
        agreement_commitment: &[u8; 32],
        nonce: &[u8; 32],
    ) -> AgreementId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AGREEMENT_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(creator.as_ref());
        hasher.update(agreement_commitment);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate commitment from agreement terms
    pub fn generate_commitment(
        terms_data: &[u8],
        schema_hash: &[u8; 32],
        version: u32,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AGREEMENT_COMMITMENT_SEP);
        hasher.update(schema_hash);
        hasher.update(&version.to_le_bytes());
        hasher.update(terms_data);
        *hasher.finalize().as_bytes()
    }

    /// Check if all required parties have signed
    pub fn is_fully_signed(&self) -> bool {
        self.parties.iter().all(|p| p.signed)
    }

    /// Count signed parties
    pub fn signed_count(&self) -> usize {
        self.parties.iter().filter(|p| p.signed).count()
    }
}

// =============================================================================
// SRC-842: Party Signatures & Role Binding
// =============================================================================

/// Signature type for agreements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    /// Single ECDSA/Ed25519 signature
    Single,
    /// Threshold signature (t-of-n)
    Threshold { threshold: u8, total: u8 },
    /// Multi-signature (all required)
    Multi { required: u8 },
}

/// Party signature record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartySignature {
    /// Signature identifier
    pub signature_id: SignatureId,
    /// Agreement being signed
    pub agreement_id: AgreementId,
    /// Party reference (commitment or subject)
    pub party_ref: PartyRef,
    /// Role being signed for
    pub role: AgreementRole,
    /// Signature type
    pub signature_type: SignatureType,
    /// The actual signature bytes
    pub signature: Vec<u8>,
    /// Signer's public key or commitment
    pub signer_key: [u8; 32],
    /// Signing timestamp
    pub signed_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Optional: witness or notary attestation
    pub witness_attestation_id: Option<AttestationId>,
}

impl PartySignature {
    /// Generate signature ID
    pub fn generate_id(
        agreement_id: &AgreementId,
        party_ref: &PartyRef,
        role: AgreementRole,
        nonce: &[u8; 32],
    ) -> SignatureId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SIGNATURE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(agreement_id);
        hasher.update(&party_ref.as_hash());
        hasher.update(&[role as u8]);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate the message to be signed (domain-separated)
    pub fn generate_signing_message(
        agreement_id: &AgreementId,
        agreement_commitment: &[u8; 32],
        party_ref: &PartyRef,
        role: AgreementRole,
        policy_id: &PolicyId,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SIGNATURE_MESSAGE_SEP);
        hasher.update(agreement_id);
        hasher.update(agreement_commitment);
        hasher.update(&party_ref.as_hash());
        hasher.update(&[role as u8]);
        hasher.update(policy_id);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-843: Notary & Attestation Packet
// =============================================================================

/// Notary/attestation issuer class (SRC-802 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationIssuerClass {
    /// Certified notary public
    NotaryPublic = 0,
    /// Law firm / attorney
    LawFirm = 1,
    /// Licensed auditor
    Auditor = 2,
    /// Certified public accountant
    Cpa = 3,
    /// Court official
    CourtOfficial = 4,
    /// Government agency
    GovernmentAgency = 5,
    /// Registered agent
    RegisteredAgent = 6,
    /// Escrow agent
    EscrowAgent = 7,
    /// Title company
    TitleCompany = 8,
    /// Other authorized
    Other = 255,
}

/// Attestation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationType {
    /// Document notarization
    Notarization = 0,
    /// Signature witnessing
    SignatureWitness = 1,
    /// Identity verification
    IdentityVerification = 2,
    /// Document authentication
    DocumentAuthentication = 3,
    /// Apostille
    Apostille = 4,
    /// Certification
    Certification = 5,
    /// Acknowledgment
    Acknowledgment = 6,
    /// Jurat (oath/affirmation)
    Jurat = 7,
    /// Copy certification
    CopyCertification = 8,
}

/// Attestation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationStatus {
    Active = 0,
    Expired = 1,
    Revoked = 2,
    Superseded = 3,
}

/// SRC-843 Notary & Attestation Packet
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPacket {
    /// Unique attestation identifier
    pub attestation_id: AttestationId,
    /// Target: agreement ID or document hash
    pub target_ref: AttestationTarget,
    /// Notary/issuer address (must be SRC-802 registered)
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: AttestationIssuerClass,
    /// Type of attestation
    pub attestation_type: AttestationType,
    /// Notary commitment (commission/venue/procedure)
    pub notary_commitment: [u8; 32],
    /// Jurisdiction code
    pub jurisdiction_code: String,
    /// When attestation becomes valid
    pub valid_from: Timestamp,
    /// When attestation expires
    pub expiry: Option<Timestamp>,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: AttestationStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Policy ID used for authorization
    pub policy_id: PolicyId,
}

/// Target of an attestation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationTarget {
    /// Attest to an agreement
    Agreement(AgreementId),
    /// Attest to a document hash
    DocumentHash([u8; 32]),
    /// Attest to a signature
    Signature(SignatureId),
    /// Attest to an IP action
    IpAction(IpAssetId),
}

impl AttestationPacket {
    /// Generate attestation ID
    pub fn generate_id(
        issuer: &Address,
        target: &AttestationTarget,
        attestation_type: AttestationType,
        nonce: &[u8; 32],
    ) -> AttestationId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ATTESTATION_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(issuer.as_ref());
        match target {
            AttestationTarget::Agreement(id) => {
                hasher.update(b"agreement:");
                hasher.update(id);
            }
            AttestationTarget::DocumentHash(h) => {
                hasher.update(b"document:");
                hasher.update(h);
            }
            AttestationTarget::Signature(id) => {
                hasher.update(b"signature:");
                hasher.update(id);
            }
            AttestationTarget::IpAction(id) => {
                hasher.update(b"ip_action:");
                hasher.update(id);
            }
        }
        hasher.update(&[attestation_type as u8]);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate notary commitment
    pub fn generate_notary_commitment(
        commission_number: &str,
        venue: &str,
        procedure_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NOTARY_COMMITMENT_SEP);
        hasher.update(commission_number.as_bytes());
        hasher.update(venue.as_bytes());
        hasher.update(procedure_hash);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-844: IP Rights & Creative Actions
// =============================================================================

/// IP action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpActionType {
    /// Full assignment of rights
    Assignment = 0,
    /// License grant
    License = 1,
    /// Pledge/security interest
    Pledge = 2,
    /// Release to public domain
    Release = 3,
    /// Exclusive license
    ExclusiveLicense = 4,
    /// Non-exclusive license
    NonExclusiveLicense = 5,
    /// Sublicense
    Sublicense = 6,
    /// Termination of license
    LicenseTermination = 7,
    /// Transfer of pledge
    PledgeTransfer = 8,
    /// Release of pledge
    PledgeRelease = 9,
}

/// IP asset type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpAssetType {
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

/// IP action status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpActionStatus {
    Pending = 0,
    Active = 1,
    Expired = 2,
    Revoked = 3,
    Superseded = 4,
    Terminated = 5,
}

/// SRC-844 IP Rights Action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpRightsAction {
    /// Unique action identifier
    pub action_id: IpAssetId,
    /// IP asset commitment (hash of asset details)
    pub ip_asset_commitment: [u8; 32],
    /// Type of IP asset
    pub asset_type: IpAssetType,
    /// Action being taken
    pub action_type: IpActionType,
    /// Scope commitment (territory/term/field-of-use)
    pub scope_commitment: [u8; 32],
    /// Rights holder party reference
    pub rightsholder_ref: PartyRef,
    /// Counterparty reference (assignee, licensee, etc.)
    pub counterparty_ref: Option<PartyRef>,
    /// Policy ID governing this action
    pub policy_id: PolicyId,
    /// When action becomes effective
    pub valid_from: Timestamp,
    /// When action expires
    pub expiry: Option<Timestamp>,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: IpActionStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Related agreement ID (if any)
    pub agreement_id: Option<AgreementId>,
    /// Attachments (e.g., license terms)
    pub attachments: Vec<AttachmentRef>,
}

impl IpRightsAction {
    /// Generate IP action ID
    pub fn generate_id(
        rightsholder: &PartyRef,
        ip_asset_commitment: &[u8; 32],
        action_type: IpActionType,
        nonce: &[u8; 32],
    ) -> IpAssetId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(IP_ACTION_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(&rightsholder.as_hash());
        hasher.update(ip_asset_commitment);
        hasher.update(&[action_type as u8]);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate scope commitment
    pub fn generate_scope_commitment(
        territory: &str,
        field_of_use: &str,
        duration_secs: Option<u64>,
        additional_terms: Option<&[u8]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(IP_SCOPE_COMMITMENT_SEP);
        hasher.update(territory.as_bytes());
        hasher.update(b"|");
        hasher.update(field_of_use.as_bytes());
        if let Some(dur) = duration_secs {
            hasher.update(b"|");
            hasher.update(&dur.to_le_bytes());
        }
        if let Some(terms) = additional_terms {
            hasher.update(b"|");
            hasher.update(terms);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-845: Execution Link Standard
// =============================================================================

/// Executor lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExecutorState {
    /// Draft - not yet activated
    Draft = 0,
    /// Active - executor is operational
    Active = 1,
    /// Paused - temporarily suspended
    Paused = 2,
    /// Terminated - executor relationship ended
    Terminated = 3,
    /// Completed - all obligations fulfilled
    Completed = 4,
    /// Disputed - under dispute resolution
    Disputed = 5,
}

/// SRC-845 Execution Link
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorLink {
    /// Unique link identifier
    pub link_id: ExecutorLinkId,
    /// Agreement being linked
    pub agreement_id: AgreementId,
    /// Executor contract address
    pub executor_contract: Address,
    /// Executor interface identifier (function selector or interface hash)
    pub executor_interface_id: [u8; 32],
    /// Terms commitment (must match what executor expects)
    pub terms_commitment: [u8; 32],
    /// Policy ID for activation/modification
    pub activation_policy_id: PolicyId,
    /// Current lifecycle state
    pub state: ExecutorState,
    /// When link was created
    pub created_at: Timestamp,
    /// Last state change
    pub updated_at: Timestamp,
    /// Block height when created
    pub created_at_height: BlockHeight,
    /// Optional: proof envelope for activation
    pub activation_proof_id: Option<ProofId>,
}

impl ExecutorLink {
    /// Generate executor link ID
    pub fn generate_id(
        agreement_id: &AgreementId,
        executor_contract: &Address,
        nonce: &[u8; 32],
    ) -> ExecutorLinkId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EXECUTOR_LINK_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(agreement_id);
        hasher.update(executor_contract.as_ref());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate terms commitment
    pub fn generate_terms_commitment(
        terms_data: &[u8],
        executor_interface_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TERMS_COMMITMENT_SEP);
        hasher.update(executor_interface_id);
        hasher.update(terms_data);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-846: 84X Proof Profiles
// =============================================================================

/// Proof profile types for SRC-84X
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AgreementProofProfile {
    /// Prove agreement is signed by specified roles
    SignedByRoles = 0,
    /// Prove notary attestation exists
    NotaryAttested = 1,
    /// Prove IP assignment is valid
    IpAssignmentValid = 2,
    /// Prove executor is bound and active
    ExecutorBoundActive = 3,
    /// Prove party is bound to agreement
    PartyBound = 4,
    /// Prove agreement is in specified status
    AgreementStatus = 5,
}

/// Proof type (SRC-806 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AgreementProofType {
    /// Mock proof (for testing)
    Mock = 0,
    /// Groth16 ZK-SNARK
    Groth16 = 1,
    /// PLONK proof
    Plonk = 2,
    /// Threshold signature proof
    ThresholdSignature = 3,
    /// Merkle inclusion proof
    MerkleInclusion = 4,
}

/// SRC-846 Agreement Proof Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementProofEnvelope {
    /// Proof identifier
    pub proof_id: ProofId,
    /// Proof profile being proven
    pub profile: AgreementProofProfile,
    /// Profile version string (e.g., "agreement.signed_by_roles.v1")
    pub profile_id: String,
    /// Policy IDs that were checked
    pub policy_ids: Vec<PolicyId>,
    /// Public inputs to the proof
    pub public_inputs: Vec<u8>,
    /// The proof data
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: AgreementProofType,
    /// Subject nullifier (for revocation checking)
    pub subject_nullifier: [u8; 32],
    /// When proof was generated
    pub generated_at: Timestamp,
    /// When proof expires
    pub expires_at: Timestamp,
}

impl AgreementProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile: AgreementProofProfile,
        subject_nullifier: &[u8; 32],
        policy_ids: &[PolicyId],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROOF_PROFILE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(&[profile as u8]);
        hasher.update(subject_nullifier);
        for policy_id in policy_ids {
            hasher.update(policy_id);
        }
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Operations
// =============================================================================

/// SRC-84X Operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AgreementOperation {
    // SRC-841: Agreement Commitment (0-9)
    CommitAgreement = 0,
    UpdateAgreement = 1,
    TerminateAgreement = 2,
    VoidAgreement = 3,
    SupersedeAgreement = 4,

    // SRC-842: Party Signatures (10-19)
    SignAgreement = 10,
    RevokeSignature = 11,
    AddParty = 12,
    RemoveParty = 13,

    // SRC-843: Notary & Attestation (20-29)
    CreateAttestation = 20,
    RevokeAttestation = 21,
    UpdateAttestationStatus = 22,

    // SRC-844: IP Rights (30-39)
    RecordIpAction = 30,
    UpdateIpAction = 31,
    TerminateIpAction = 32,
    RevokeIpAction = 33,

    // SRC-845: Executor Link (40-49)
    LinkExecutor = 40,
    ActivateExecutor = 41,
    PauseExecutor = 42,
    ResumeExecutor = 43,
    TerminateExecutor = 44,
    CompleteExecutor = 45,

    // SRC-846: Proof Operations (50-59)
    SubmitProof = 50,
    VerifyProof = 51,
}

/// Transaction data for SRC-84X operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementTxData {
    pub operation: AgreementOperation,
    pub data: Vec<u8>,
}

// =============================================================================
// Events
// =============================================================================

/// SRC-84X Events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgreementEvent {
    // SRC-841 Events
    AgreementCommitted {
        agreement_id: AgreementId,
        policy_id: PolicyId,
        commitment_hash: [u8; 32],
        timestamp: Timestamp,
    },
    AgreementUpdated {
        agreement_id: AgreementId,
        new_status: AgreementStatus,
        timestamp: Timestamp,
    },
    AgreementTerminated {
        agreement_id: AgreementId,
        timestamp: Timestamp,
    },
    AgreementSuperseded {
        old_agreement_id: AgreementId,
        new_agreement_id: AgreementId,
        timestamp: Timestamp,
    },

    // SRC-842 Events
    AgreementSigned {
        agreement_id: AgreementId,
        party_ref_hash: [u8; 32],
        role: AgreementRole,
        signer: Address,
        timestamp: Timestamp,
    },
    SignatureRevoked {
        agreement_id: AgreementId,
        signature_id: SignatureId,
        timestamp: Timestamp,
    },

    // SRC-843 Events
    NotaryAttested {
        target_id: [u8; 32],
        notary: Address,
        attestation_hash: [u8; 32],
        timestamp: Timestamp,
    },
    AttestationRevoked {
        attestation_id: AttestationId,
        timestamp: Timestamp,
    },

    // SRC-844 Events
    IpActionRecorded {
        ip_asset_hash: [u8; 32],
        action_type: IpActionType,
        policy_id: PolicyId,
        timestamp: Timestamp,
    },
    IpActionUpdated {
        action_id: IpAssetId,
        new_status: IpActionStatus,
        timestamp: Timestamp,
    },

    // SRC-845 Events
    ExecutorLinked {
        agreement_id: AgreementId,
        executor: Address,
        interface_id: [u8; 32],
        state: ExecutorState,
        timestamp: Timestamp,
    },
    ExecutorStateUpdated {
        agreement_id: AgreementId,
        link_id: ExecutorLinkId,
        new_state: ExecutorState,
        timestamp: Timestamp,
    },

    // SRC-846 Events
    ProofSubmitted {
        proof_id: ProofId,
        profile: AgreementProofProfile,
        timestamp: Timestamp,
    },
    ProofVerified {
        proof_id: ProofId,
        valid: bool,
        timestamp: Timestamp,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_ref_commitment() {
        let subject = [1u8; 32];
        let salt = [2u8; 32];
        let commitment = PartyRef::generate_commitment(&subject, &salt);
        assert_ne!(commitment, [0u8; 32]);

        // Different salt = different commitment
        let salt2 = [3u8; 32];
        let commitment2 = PartyRef::generate_commitment(&subject, &salt2);
        assert_ne!(commitment, commitment2);
    }

    #[test]
    fn test_agreement_id_generation() {
        let creator = Address::new([1u8; 20]);
        let commitment = [2u8; 32];
        let nonce = [3u8; 32];

        let id = AgreementCommitment::generate_id(&creator, &commitment, &nonce);
        assert_ne!(id, [0u8; 32]);

        // Same inputs = same ID
        let id2 = AgreementCommitment::generate_id(&creator, &commitment, &nonce);
        assert_eq!(id, id2);
    }

    #[test]
    fn test_signing_message_domain_separation() {
        let agreement_id = [1u8; 32];
        let commitment = [2u8; 32];
        let party_ref = PartyRef::Commitment([3u8; 32]);
        let policy_id = [4u8; 32];

        let msg1 = PartySignature::generate_signing_message(
            &agreement_id,
            &commitment,
            &party_ref,
            AgreementRole::Buyer,
            &policy_id,
        );

        // Different role = different message
        let msg2 = PartySignature::generate_signing_message(
            &agreement_id,
            &commitment,
            &party_ref,
            AgreementRole::Seller,
            &policy_id,
        );

        assert_ne!(msg1, msg2);
    }

    #[test]
    fn test_attestation_id_generation() {
        let issuer = Address::new([1u8; 20]);
        let target = AttestationTarget::Agreement([2u8; 32]);
        let nonce = [3u8; 32];

        let id = AttestationPacket::generate_id(
            &issuer,
            &target,
            AttestationType::Notarization,
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_ip_scope_commitment() {
        let commitment = IpRightsAction::generate_scope_commitment(
            "US",
            "software",
            Some(31536000),
            None,
        );
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_executor_terms_commitment() {
        let terms = b"escrow terms here";
        let interface = [1u8; 32];

        let commitment = ExecutorLink::generate_terms_commitment(terms, &interface);
        assert_ne!(commitment, [0u8; 32]);
    }
}
