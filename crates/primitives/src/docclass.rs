//! SRC-80X Layered Trust Architecture
//!
//! This module defines the data structures for the modular trust architecture:
//! - SRC-801: Subject Standard (DID-like identity anchors)
//! - SRC-802: Issuer Registry (who may attest)
//! - SRC-803: Policy Token (verification rules)
//! - SRC-804: Claim Token (verifiable statements)
//! - SRC-805: Revocation Standard (privacy-preserving invalidation)
//! - SRC-806: Proof Envelope (ZK proof containers)
//! - SRC-81X: Domain-specific claims (academic, professional, etc.)
//!
//! Design Principles:
//! - Identity is not data - it is a cryptographic reference point
//! - Trust is plural - policies define acceptable trust sources
//! - Verification rules are code - deterministic on-chain objects
//! - The chain stores verifiability, not information
//! - Claims must be revocable without being traceable
//! - Verifiers trust math and quorum, not institutions

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, Balance, BlockHeight, Timestamp};

// =============================================================================
// Type Aliases for New Architecture
// =============================================================================

/// Subject ID (SRC-801) - alias for identity anchors
pub type SubjectId = [u8; 32];

/// Policy ID (SRC-803) - hash of policy content
pub type PolicyId = [u8; 32];

/// Claim ID (SRC-804) - unique claim identifier
pub type ClaimId = [u8; 32];

/// Proof ID (SRC-806) - unique proof identifier
pub type ProofId = [u8; 32];

// =============================================================================
// Claim Types for Policy Matching (SRC-803)
// =============================================================================

/// High-level claim type categories for policy matching.
/// Used by policies to specify which types of claims satisfy requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClaimType {
    /// Identity-related claims (government ID, etc.)
    Identity = 0,
    /// Eligibility attestations (citizenship, residency, age)
    Eligibility = 1,
    /// Education credentials (transcripts, diplomas)
    Education = 2,
    /// Professional licenses and certifications
    License = 3,
    /// Employment verification
    Employment = 4,
    /// Healthcare credentials
    Healthcare = 5,
    /// Financial attestations
    Financial = 6,
    /// Custom/other claim types
    Custom = 255,
}

impl ClaimType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ClaimType::Identity),
            1 => Some(ClaimType::Eligibility),
            2 => Some(ClaimType::Education),
            3 => Some(ClaimType::License),
            4 => Some(ClaimType::Employment),
            5 => Some(ClaimType::Healthcare),
            6 => Some(ClaimType::Financial),
            255 => Some(ClaimType::Custom),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ClaimType::Identity => "Identity",
            ClaimType::Eligibility => "Eligibility",
            ClaimType::Education => "Education",
            ClaimType::License => "License",
            ClaimType::Employment => "Employment",
            ClaimType::Healthcare => "Healthcare",
            ClaimType::Financial => "Financial",
            ClaimType::Custom => "Custom",
        }
    }
}

// =============================================================================
// DocClass Subcodes (Claim Types)
// =============================================================================

/// DocClass subcode identifying the credential/claim type.
/// Range 800-899 is reserved for DocClass family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum DocSubcode {
    // SRC-80X Core Standards
    /// 801: Subject (DID-equivalent) - key binding, controllers
    Subject = 801,
    /// 802: Issuer Registry entry
    IssuerRegistry = 802,
    /// 803: Policy Token
    Policy = 803,
    /// 804: Claim Token
    Claim = 804,
    /// 805: Revocation entry
    Revocation = 805,
    /// 806: Proof verification log
    ProofLog = 806,

    // SRC-80X Legacy (backward compat)
    /// 800: Identity Root (legacy, maps to Subject)
    IdentityRoot = 800,
    /// 807: Eligibility Attestation (claim type)
    EligibilityAttestation = 807,

    // SRC-81X: Domain-Specific Claims
    /// 810: Academic Transcript Credential
    AcademicTranscript = 810,
    /// 811: Diploma / Degree Credential
    Diploma = 811,
    /// 812: Enrollment Verification
    EnrollmentVerification = 812,
    /// 813: Professional License / Certification
    ProfessionalLicense = 813,
    /// 814: Government ID verification
    GovernmentId = 814,
    /// 815: Employment verification
    Employment = 815,
}

impl DocSubcode {
    /// Check if this is an SRC-80X core standard (800-809)
    pub fn is_core_standard(&self) -> bool {
        (*self as u16) >= 800 && (*self as u16) < 810
    }

    /// Check if this is an SRC-80X (Identity/Civil) subcode (legacy alias)
    pub fn is_identity_class(&self) -> bool {
        self.is_core_standard()
    }

    /// Check if this is an SRC-81X (Domain-specific claim) subcode
    pub fn is_domain_claim(&self) -> bool {
        (*self as u16) >= 810 && (*self as u16) < 820
    }

    /// Check if this is an SRC-81X (Academic/Professional) subcode (legacy alias)
    pub fn is_academic_class(&self) -> bool {
        self.is_domain_claim()
    }

    /// Get the subcode as u16
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }

    /// Parse from u16
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            800 => Some(DocSubcode::IdentityRoot),
            801 => Some(DocSubcode::Subject),
            802 => Some(DocSubcode::IssuerRegistry),
            803 => Some(DocSubcode::Policy),
            804 => Some(DocSubcode::Claim),
            805 => Some(DocSubcode::Revocation),
            806 => Some(DocSubcode::ProofLog),
            807 => Some(DocSubcode::EligibilityAttestation),
            810 => Some(DocSubcode::AcademicTranscript),
            811 => Some(DocSubcode::Diploma),
            812 => Some(DocSubcode::EnrollmentVerification),
            813 => Some(DocSubcode::ProfessionalLicense),
            814 => Some(DocSubcode::GovernmentId),
            815 => Some(DocSubcode::Employment),
            _ => None,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            DocSubcode::IdentityRoot => "Identity Root (Legacy)",
            DocSubcode::Subject => "Subject",
            DocSubcode::IssuerRegistry => "Issuer Registry",
            DocSubcode::Policy => "Policy",
            DocSubcode::Claim => "Claim",
            DocSubcode::Revocation => "Revocation",
            DocSubcode::ProofLog => "Proof Log",
            DocSubcode::EligibilityAttestation => "Eligibility Attestation",
            DocSubcode::AcademicTranscript => "Academic Transcript",
            DocSubcode::Diploma => "Diploma/Degree",
            DocSubcode::EnrollmentVerification => "Enrollment Verification",
            DocSubcode::ProfessionalLicense => "Professional License",
            DocSubcode::GovernmentId => "Government ID",
            DocSubcode::Employment => "Employment",
        }
    }

    /// Convert to ClaimType for policy matching
    pub fn to_claim_type(&self) -> Option<ClaimType> {
        match self {
            DocSubcode::EligibilityAttestation => Some(ClaimType::Eligibility),
            DocSubcode::AcademicTranscript => Some(ClaimType::Education),
            DocSubcode::Diploma => Some(ClaimType::Education),
            DocSubcode::EnrollmentVerification => Some(ClaimType::Education),
            DocSubcode::ProfessionalLicense => Some(ClaimType::License),
            DocSubcode::GovernmentId => Some(ClaimType::Identity),
            DocSubcode::Employment => Some(ClaimType::Employment),
            _ => None,
        }
    }
}

// =============================================================================
// Credential ID
// =============================================================================

/// Unique identifier for a DocClass credential.
/// Derived from: blake3(issuer || subcode || subject_commitment || nonce)
pub type CredentialId = [u8; 32];

/// Generate a credential ID
pub fn generate_credential_id(
    issuer: &Address,
    subcode: DocSubcode,
    subject_commitment: &[u8; 32],
    nonce: u64,
) -> CredentialId {
    let mut data = Vec::with_capacity(20 + 2 + 32 + 8);
    data.extend_from_slice(issuer.as_bytes());
    data.extend_from_slice(&(subcode.as_u16()).to_be_bytes());
    data.extend_from_slice(subject_commitment);
    data.extend_from_slice(&nonce.to_be_bytes());
    *blake3::hash(&data).as_bytes()
}

// =============================================================================
// Commitment Scheme
// =============================================================================

/// Domain separator for commitment generation
pub const COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC-8XX-COMMITMENT-v1";

/// Generate a privacy-preserving commitment to credential attributes.
/// commitment = blake3(domain_sep || schema_hash || canonical_attributes || salt)
pub fn generate_commitment(
    schema_hash: &[u8; 32],
    canonical_attributes: &[u8],
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_DOMAIN_SEP);
    hasher.update(schema_hash);
    hasher.update(canonical_attributes);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Generate a subject commitment (identity binding without revealing identity)
/// subject_commitment = blake3("SRC-8XX-SUBJECT" || subject_identifier || salt)
pub fn generate_subject_commitment(subject_identifier: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SRC-8XX-SUBJECT-v1");
    hasher.update(subject_identifier);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

// =============================================================================
// SRC-800: Identity Root
// =============================================================================

/// Identity Root record (DID-equivalent).
/// Represents a self-sovereign identity with key binding and recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRoot {
    /// Unique identity ID (credential_id for this identity)
    pub identity_id: CredentialId,
    /// Subject commitment (privacy-preserving identity binding)
    pub subject_commitment: [u8; 32],
    /// Primary controller address (can update keys, add controllers)
    pub controller: Address,
    /// Additional controller addresses (recovery, delegates)
    pub additional_controllers: Vec<Address>,
    /// Active public keys for this identity
    pub keys: Vec<IdentityKey>,
    /// Service endpoints (DID-style services)
    pub services: Vec<ServiceEndpoint>,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Identity status
    pub status: IdentityStatus,
    /// Schema hash for the identity structure
    pub schema_hash: [u8; 32],
}

/// Public key associated with an identity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKey {
    /// Key ID (unique within identity)
    pub key_id: String,
    /// Key type (Ed25519, X25519, etc.)
    pub key_type: KeyType,
    /// Public key bytes
    pub public_key: [u8; 32],
    /// Key purpose flags
    pub purposes: Vec<KeyPurpose>,
    /// When this key was added
    pub added_at: Timestamp,
    /// Optional expiry timestamp (0 = no expiry)
    pub expires_at: Timestamp,
    /// Is this key currently active?
    pub active: bool,
}

/// Key types supported by identity roots
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyType {
    /// Ed25519 signing key
    Ed25519 = 0,
    /// X25519 key exchange key
    X25519 = 1,
    /// Secp256k1 (for Ethereum compatibility)
    Secp256k1 = 2,
}

/// Purpose flags for identity keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyPurpose {
    /// Authentication (prove control of identity)
    Authentication = 0,
    /// Assertion (sign credentials/claims)
    Assertion = 1,
    /// Key Agreement (encryption key exchange)
    KeyAgreement = 2,
    /// Capability Invocation (authorize actions)
    CapabilityInvocation = 3,
    /// Capability Delegation (delegate to others)
    CapabilityDelegation = 4,
}

/// Service endpoint for identity (DID-style)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Service ID (unique within identity)
    pub service_id: String,
    /// Service type (e.g., "CredentialRegistry", "Messaging", "Website")
    pub service_type: String,
    /// Service endpoint URL or URI
    pub endpoint: String,
    /// Optional description
    pub description: Option<String>,
}

/// Identity status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IdentityStatus {
    /// Active and valid
    Active = 0,
    /// Temporarily deactivated by controller
    Deactivated = 1,
    /// Permanently revoked (cannot be reactivated)
    Revoked = 2,
}

// =============================================================================
// SRC-802: Eligibility Attestation
// =============================================================================

/// Eligibility attestation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EligibilityType {
    /// Citizenship attestation
    Citizenship = 0,
    /// Residency attestation
    Residency = 1,
    /// Age eligibility (e.g., over 18, over 21)
    AgeEligibility = 2,
    /// Voter eligibility
    VoterEligibility = 3,
    /// Civil registry attestation (birth, marriage, etc.)
    CivilRegistry = 4,
    /// Custom eligibility type (defined by schema)
    Custom = 255,
}

impl EligibilityType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EligibilityType::Citizenship),
            1 => Some(EligibilityType::Residency),
            2 => Some(EligibilityType::AgeEligibility),
            3 => Some(EligibilityType::VoterEligibility),
            4 => Some(EligibilityType::CivilRegistry),
            255 => Some(EligibilityType::Custom),
            _ => None,
        }
    }
}

/// Eligibility attestation credential (SRC-802)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityAttestation {
    /// Unique credential ID
    pub credential_id: CredentialId,
    /// Subject wallet address (for token ownership)
    pub subject_address: Address,
    /// Document subcode (802)
    pub subcode: DocSubcode,
    /// Subject commitment (NOT the subject address)
    pub subject_commitment: [u8; 32],
    /// Issuer address
    pub issuer: Address,
    /// Jurisdiction code (ISO 3166-1/2, e.g., "US", "US-CA", "CA-BC")
    pub jurisdiction: String,
    /// Eligibility type
    pub eligibility_type: EligibilityType,
    /// Schema hash defining the attestation structure
    pub schema_hash: [u8; 32],
    /// Commitment to the credential content
    pub content_commitment: [u8; 32],
    /// Issuance timestamp
    pub issued_at: Timestamp,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: Timestamp,
    /// Optional encrypted payload reference (hash of encrypted blob)
    pub payload_hash: Option<[u8; 32]>,
    /// Optional payload hint (e.g., IPFS CID, storage URL)
    pub payload_hint: Option<String>,
    /// Issuer signature over the credential
    #[serde(with = "BigArray")]
    pub issuer_signature: [u8; 64],
    /// Key ID used for signing (for key rotation support)
    pub issuer_key_id: String,
    /// Revocation status
    pub revocation_status: RevocationStatus,
    /// If superseded, the new credential ID
    pub superseded_by: Option<CredentialId>,
}

// =============================================================================
// SRC-805: Revocation / Status Update
// =============================================================================

/// Revocation status for credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RevocationStatus {
    /// Credential is active and valid
    Active = 0,
    /// Credential is suspended (can be reactivated)
    Suspended = 1,
    /// Credential is revoked (permanent)
    Revoked = 2,
    /// Credential is superseded by a newer version
    Superseded = 3,
    /// Credential has expired
    Expired = 4,
}

impl RevocationStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RevocationStatus::Active),
            1 => Some(RevocationStatus::Suspended),
            2 => Some(RevocationStatus::Revoked),
            3 => Some(RevocationStatus::Superseded),
            4 => Some(RevocationStatus::Expired),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, RevocationStatus::Active)
    }
}

/// Revocation reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RevocationReason {
    /// Unspecified reason
    Unspecified = 0,
    /// Key compromise
    KeyCompromise = 1,
    /// Issuer compromise
    IssuerCompromise = 2,
    /// Affiliation changed
    AffiliationChanged = 3,
    /// Superseded by new credential
    Superseded = 4,
    /// Cessation of operation
    CessationOfOperation = 5,
    /// Certificate hold (temporary suspension)
    CertificateHold = 6,
    /// Privilege withdrawn
    PrivilegeWithdrawn = 7,
    /// Credential expired
    Expired = 8,
    /// Fraudulent issuance
    FraudulentIssuance = 9,
}

impl RevocationReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RevocationReason::Unspecified),
            1 => Some(RevocationReason::KeyCompromise),
            2 => Some(RevocationReason::IssuerCompromise),
            3 => Some(RevocationReason::AffiliationChanged),
            4 => Some(RevocationReason::Superseded),
            5 => Some(RevocationReason::CessationOfOperation),
            6 => Some(RevocationReason::CertificateHold),
            7 => Some(RevocationReason::PrivilegeWithdrawn),
            8 => Some(RevocationReason::Expired),
            9 => Some(RevocationReason::FraudulentIssuance),
            _ => None,
        }
    }
}

/// Revocation record (SRC-805)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The credential being revoked/updated
    pub credential_id: CredentialId,
    /// New status
    pub status: RevocationStatus,
    /// Reason for revocation/suspension
    pub reason: RevocationReason,
    /// Optional reason details
    pub reason_details: Option<String>,
    /// Issuer who performed the revocation
    pub revoker: Address,
    /// Timestamp of revocation
    pub revoked_at: Timestamp,
    /// Block height of revocation
    pub revoked_at_height: BlockHeight,
    /// If superseded, the new credential ID
    pub superseded_by: Option<CredentialId>,
    /// Signature over the revocation
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

// =============================================================================
// SRC-81X: Academic & Professional Credentials
// =============================================================================

/// Base structure for academic/professional credentials
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcademicCredential {
    /// Unique credential ID
    pub credential_id: CredentialId,
    /// Subject wallet address (for token ownership)
    pub subject_address: Address,
    /// Document subcode (810, 811, 812, or 813)
    pub subcode: DocSubcode,
    /// Subject commitment (NOT the subject's real identity)
    pub subject_commitment: [u8; 32],
    /// Issuer address (institution)
    pub issuer: Address,
    /// Institution identifier (e.g., "UCLA", "MIT")
    pub institution_id: String,
    /// Jurisdiction/country (ISO 3166-1 alpha-2)
    pub jurisdiction: String,
    /// Schema hash defining the credential structure
    pub schema_hash: [u8; 32],
    /// Commitment to the credential content
    pub content_commitment: [u8; 32],
    /// Credential metadata (non-PII, public info)
    pub metadata: CredentialMetadata,
    /// Issuance timestamp
    pub issued_at: Timestamp,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp (0 = no expiry for most degrees)
    pub expires_at: Timestamp,
    /// Optional encrypted payload reference
    pub payload_hash: Option<[u8; 32]>,
    /// Optional payload hint (storage location)
    pub payload_hint: Option<String>,
    /// Issuer signature
    #[serde(with = "BigArray")]
    pub issuer_signature: [u8; 64],
    /// Key ID used for signing
    pub issuer_key_id: String,
    /// Revocation status
    pub revocation_status: RevocationStatus,
    /// If superseded, the new credential ID
    pub superseded_by: Option<CredentialId>,
}

/// Non-sensitive metadata for credentials
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Credential title (e.g., "Bachelor of Science in Computer Science")
    pub title: String,
    /// Credential type within subcode (e.g., "undergraduate_transcript", "doctoral_degree")
    pub credential_type: String,
    /// Program/field of study (optional, can be commitment instead)
    pub program: Option<String>,
    /// Issue date in human-readable format (e.g., "2024-05-15")
    pub issue_date: String,
    /// Optional completion date
    pub completion_date: Option<String>,
    /// Additional public attributes (non-PII)
    pub attributes: Vec<CredentialAttribute>,
}

/// Public attribute for credentials (non-PII only)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialAttribute {
    /// Attribute name
    pub name: String,
    /// Attribute value (must be non-PII)
    pub value: String,
}

// =============================================================================
// DocClass Operations
// =============================================================================

/// Operations for DocClass transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DocClassOperation {
    // Identity Root operations (800)
    /// Create a new identity root
    CreateIdentityRoot = 0,
    /// Add a key to identity
    AddKey = 1,
    /// Remove a key from identity
    RemoveKey = 2,
    /// Rotate a key (add new, remove old)
    RotateKey = 3,
    /// Add a controller
    AddController = 4,
    /// Remove a controller
    RemoveController = 5,
    /// Update service endpoint
    UpdateService = 6,
    /// Deactivate identity
    DeactivateIdentity = 7,
    /// Reactivate identity
    ReactivateIdentity = 8,

    // Credential operations (802, 810-813)
    /// Issue a new credential
    IssueCredential = 10,
    /// Update credential (metadata only, not content)
    UpdateCredential = 11,

    // Revocation operations (805)
    /// Revoke a credential
    RevokeCredential = 20,
    /// Suspend a credential
    SuspendCredential = 21,
    /// Reactivate a suspended credential
    ReactivateCredential = 22,
    /// Supersede credential with new version
    SupersedeCredential = 23,

    // Issuer registry operations
    /// Register as issuer
    RegisterIssuer = 30,
    /// Update issuer info
    UpdateIssuer = 31,
    /// Rotate issuer key
    RotateIssuerKey = 32,
    /// Deactivate issuer
    DeactivateIssuer = 33,
}

impl DocClassOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DocClassOperation::CreateIdentityRoot),
            1 => Some(DocClassOperation::AddKey),
            2 => Some(DocClassOperation::RemoveKey),
            3 => Some(DocClassOperation::RotateKey),
            4 => Some(DocClassOperation::AddController),
            5 => Some(DocClassOperation::RemoveController),
            6 => Some(DocClassOperation::UpdateService),
            7 => Some(DocClassOperation::DeactivateIdentity),
            8 => Some(DocClassOperation::ReactivateIdentity),
            10 => Some(DocClassOperation::IssueCredential),
            11 => Some(DocClassOperation::UpdateCredential),
            20 => Some(DocClassOperation::RevokeCredential),
            21 => Some(DocClassOperation::SuspendCredential),
            22 => Some(DocClassOperation::ReactivateCredential),
            23 => Some(DocClassOperation::SupersedeCredential),
            30 => Some(DocClassOperation::RegisterIssuer),
            31 => Some(DocClassOperation::UpdateIssuer),
            32 => Some(DocClassOperation::RotateIssuerKey),
            33 => Some(DocClassOperation::DeactivateIssuer),
            _ => None,
        }
    }
}

/// Transaction data for DocClass operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocClassTxData {
    /// Operation type
    pub operation: DocClassOperation,
    /// Document subcode (for context)
    pub subcode: DocSubcode,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
    /// Token recipient address - the owner of the minted token
    pub recipient: crate::Address,
}

// =============================================================================
// Issuer Registry Types
// =============================================================================

/// Registered issuer for DocClass credentials
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocClassIssuer {
    /// Issuer address
    pub address: Address,
    /// Issuer name/organization
    pub name: String,
    /// Issuer type
    pub issuer_type: DocClassIssuerType,
    /// Jurisdictions the issuer can issue for (ISO 3166-1/2 codes)
    pub jurisdictions: Vec<String>,
    /// Document subcodes the issuer is authorized for
    pub authorized_subcodes: Vec<DocSubcode>,
    /// Issuer's active public keys
    pub keys: Vec<IssuerKey>,
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Issuer status
    pub status: DocClassIssuerStatus,
    /// Optional bond/stake amount (for slashing in future)
    pub stake_amount: Balance,
    /// Optional metadata (JSON)
    pub metadata: Option<String>,
}

/// Issuer key for signing credentials
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerKey {
    /// Key ID (unique within issuer)
    pub key_id: String,
    /// Public key bytes
    pub public_key: [u8; 32],
    /// Key type
    pub key_type: KeyType,
    /// When this key was added
    pub added_at: Timestamp,
    /// Optional expiry (0 = no expiry)
    pub expires_at: Timestamp,
    /// Is this key currently active?
    pub active: bool,
    /// Is this the primary key?
    pub is_primary: bool,
}

/// Types of DocClass issuers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DocClassIssuerType {
    /// Government agency (for 80X credentials)
    Government = 0,
    /// Educational institution (for 81X credentials)
    Educational = 1,
    /// Professional licensing body
    Professional = 2,
    /// Corporate entity
    Corporate = 3,
    /// Healthcare provider
    Healthcare = 4,
    /// Legal entity
    Legal = 5,
    /// Self-sovereign (for identity roots only)
    SelfSovereign = 6,
}

impl DocClassIssuerType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DocClassIssuerType::Government),
            1 => Some(DocClassIssuerType::Educational),
            2 => Some(DocClassIssuerType::Professional),
            3 => Some(DocClassIssuerType::Corporate),
            4 => Some(DocClassIssuerType::Healthcare),
            5 => Some(DocClassIssuerType::Legal),
            6 => Some(DocClassIssuerType::SelfSovereign),
            _ => None,
        }
    }

    /// Check if this issuer type can issue the given subcode
    pub fn can_issue(&self, subcode: DocSubcode) -> bool {
        match self {
            DocClassIssuerType::Government => {
                matches!(
                    subcode,
                    DocSubcode::EligibilityAttestation
                        | DocSubcode::GovernmentId
                        | DocSubcode::Revocation
                )
            }
            DocClassIssuerType::Educational => {
                matches!(
                    subcode,
                    DocSubcode::AcademicTranscript
                        | DocSubcode::Diploma
                        | DocSubcode::EnrollmentVerification
                        | DocSubcode::Revocation
                )
            }
            DocClassIssuerType::Professional => {
                matches!(
                    subcode,
                    DocSubcode::ProfessionalLicense | DocSubcode::Revocation
                )
            }
            DocClassIssuerType::Corporate => {
                matches!(
                    subcode,
                    DocSubcode::Employment | DocSubcode::Revocation
                )
            }
            DocClassIssuerType::SelfSovereign => {
                matches!(subcode, DocSubcode::IdentityRoot | DocSubcode::Subject)
            }
            _ => false,
        }
    }
}

/// Issuer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DocClassIssuerStatus {
    /// Active and can issue credentials
    Active = 0,
    /// Suspended (cannot issue, but existing credentials remain valid)
    Suspended = 1,
    /// Revoked (cannot issue, and credentials should be treated with caution)
    Revoked = 2,
}

impl DocClassIssuerStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(DocClassIssuerStatus::Active),
            1 => Some(DocClassIssuerStatus::Suspended),
            2 => Some(DocClassIssuerStatus::Revoked),
            _ => None,
        }
    }

    pub fn can_issue(&self) -> bool {
        matches!(self, DocClassIssuerStatus::Active)
    }
}

// =============================================================================
// ZK Proof Inputs (for future voting integration)
// =============================================================================

/// Data structure for ZK proof inputs.
/// This defines what fields future ZK circuits will consume to prove
/// eligibility without revealing identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofInputs {
    /// Credential ID being proven
    pub credential_id: CredentialId,
    /// Issuer's public key used for signing
    pub issuer_public_key: [u8; 32],
    /// Issuer key ID (for key rotation support)
    pub issuer_key_id: String,
    /// Content commitment
    pub content_commitment: [u8; 32],
    /// Subject commitment
    pub subject_commitment: [u8; 32],
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Eligibility type (for 802 credentials)
    pub eligibility_type: Option<EligibilityType>,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expires_at: Timestamp,
    /// Revocation check hook (merkle root or on-chain state root)
    pub revocation_merkle_root: Option<[u8; 32]>,
    /// Current block height (for freshness)
    pub current_block_height: BlockHeight,
    /// Issuer signature
    #[serde(with = "BigArray")]
    pub issuer_signature: [u8; 64],
}

/// Nullifier for preventing double-use (e.g., double voting)
/// nullifier = blake3("SRC-8XX-NULLIFIER" || credential_id || context || secret)
pub fn generate_nullifier(credential_id: &CredentialId, context: &[u8], secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SRC-8XX-NULLIFIER-v1");
    hasher.update(credential_id);
    hasher.update(context);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

// =============================================================================
// Canonical JSON for Commitments
// =============================================================================

/// Rules for canonical JSON encoding (for deterministic commitments):
/// 1. Keys are sorted lexicographically (Unicode code points)
/// 2. No whitespace between elements
/// 3. UTF-8 encoding
/// 4. Numbers: integers as-is, floats with minimal representation
/// 5. Strings: escaped as per JSON spec
/// 6. Arrays: elements in order, no trailing comma
/// 7. Objects: sorted keys, no trailing comma
/// 8. Null values are included (not omitted)
///
/// Example: {"age":21,"country":"US","name":"John Doe"}
pub mod canonical {
    use serde::Serialize;
    use std::collections::BTreeMap;

    /// Serialize a value to canonical JSON bytes
    pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
        // First serialize to serde_json::Value to normalize
        let json_value = serde_json::to_value(value)?;
        // Then serialize with sorted keys and no whitespace
        let canonical = canonical_json_value(&json_value);
        Ok(canonical.into_bytes())
    }

    fn canonical_json_value(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => serde_json::to_string(s).unwrap(),
            serde_json::Value::Array(arr) => {
                let elements: Vec<String> = arr.iter().map(canonical_json_value).collect();
                format!("[{}]", elements.join(","))
            }
            serde_json::Value::Object(obj) => {
                // Sort keys lexicographically
                let sorted: BTreeMap<_, _> = obj.iter().collect();
                let pairs: Vec<String> = sorted
                    .iter()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json_value(v)))
                    .collect();
                format!("{{{}}}", pairs.join(","))
            }
        }
    }
}

// =============================================================================
// Events
// =============================================================================

/// Events emitted by DocClass operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocClassEvent {
    // Identity Root events
    IdentityRootCreated {
        identity_id: CredentialId,
        controller: Address,
        subject_commitment: [u8; 32],
    },
    KeyAdded {
        identity_id: CredentialId,
        key_id: String,
        key_type: KeyType,
    },
    KeyRemoved {
        identity_id: CredentialId,
        key_id: String,
    },
    KeyRotated {
        identity_id: CredentialId,
        old_key_id: String,
        new_key_id: String,
    },
    ControllerAdded {
        identity_id: CredentialId,
        controller: Address,
    },
    ControllerRemoved {
        identity_id: CredentialId,
        controller: Address,
    },
    ServiceUpdated {
        identity_id: CredentialId,
        service_id: String,
    },
    IdentityStatusChanged {
        identity_id: CredentialId,
        new_status: IdentityStatus,
    },

    // Credential events
    CredentialIssued {
        credential_id: CredentialId,
        subcode: DocSubcode,
        issuer: Address,
        jurisdiction: String,
        subject_commitment: [u8; 32],
        schema_hash: [u8; 32],
        expires_at: Timestamp,
    },
    CredentialRevoked {
        credential_id: CredentialId,
        issuer: Address,
        reason: RevocationReason,
        timestamp: Timestamp,
    },
    CredentialSuspended {
        credential_id: CredentialId,
        issuer: Address,
        reason: RevocationReason,
        timestamp: Timestamp,
    },
    CredentialReactivated {
        credential_id: CredentialId,
        issuer: Address,
        timestamp: Timestamp,
    },
    CredentialSuperseded {
        old_credential_id: CredentialId,
        new_credential_id: CredentialId,
        issuer: Address,
        timestamp: Timestamp,
    },

    // Issuer registry events
    IssuerRegistered {
        issuer: Address,
        issuer_type: DocClassIssuerType,
        jurisdictions: Vec<String>,
        subcodes: Vec<DocSubcode>,
    },
    IssuerUpdated {
        issuer: Address,
    },
    IssuerKeyRotated {
        issuer: Address,
        old_key_id: String,
        new_key_id: String,
    },
    IssuerStatusChanged {
        issuer: Address,
        new_status: DocClassIssuerStatus,
    },
}

// =============================================================================
// Schema Registry (predefined schemas)
// =============================================================================

/// Predefined schema hashes for common credential types.
/// In production, these would be registered in a schema registry.
pub mod schemas {
    /// Schema for citizenship eligibility attestation
    pub const CITIZENSHIP_SCHEMA: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x43, 0x49, 0x54, 0x49, 0x5a, 0x45, 0x4e, 0x53,
        0x48, 0x49, 0x50, 0x5f, 0x56, 0x31, 0x00, 0x00,
    ];

    /// Schema for residency eligibility attestation
    pub const RESIDENCY_SCHEMA: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x52, 0x45, 0x53, 0x49, 0x44, 0x45, 0x4e, 0x43,
        0x59, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Schema for age eligibility attestation
    pub const AGE_ELIGIBILITY_SCHEMA: [u8; 32] = [
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x47, 0x45, 0x5f, 0x45, 0x4c, 0x49, 0x47,
        0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Schema for academic transcript
    pub const TRANSCRIPT_SCHEMA: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x54, 0x52, 0x41, 0x4e, 0x53, 0x43, 0x52, 0x49,
        0x50, 0x54, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00,
    ];

    /// Schema for diploma/degree
    pub const DIPLOMA_SCHEMA: [u8; 32] = [
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x49, 0x50, 0x4c, 0x4f, 0x4d, 0x41, 0x5f,
        0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Schema for professional license
    pub const LICENSE_SCHEMA: [u8; 32] = [
        0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4c, 0x49, 0x43, 0x45, 0x4e, 0x53, 0x45, 0x5f,
        0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Schema for identity root
    pub const IDENTITY_ROOT_SCHEMA: [u8; 32] = [
        0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0x44, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f,
        0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subcode_classification() {
        assert!(DocSubcode::IdentityRoot.is_identity_class());
        assert!(DocSubcode::EligibilityAttestation.is_identity_class());
        assert!(!DocSubcode::AcademicTranscript.is_identity_class());

        assert!(!DocSubcode::IdentityRoot.is_academic_class());
        assert!(DocSubcode::AcademicTranscript.is_academic_class());
        assert!(DocSubcode::Diploma.is_academic_class());
        assert!(DocSubcode::ProfessionalLicense.is_academic_class());
    }

    #[test]
    fn test_commitment_determinism() {
        let schema_hash = [1u8; 32];
        let attributes = b"test_attributes";
        let salt = [2u8; 32];

        let c1 = generate_commitment(&schema_hash, attributes, &salt);
        let c2 = generate_commitment(&schema_hash, attributes, &salt);
        assert_eq!(c1, c2);

        // Different salt should produce different commitment
        let different_salt = [3u8; 32];
        let c3 = generate_commitment(&schema_hash, attributes, &different_salt);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_credential_id_generation() {
        let issuer = Address::new([1u8; 20]);
        let subcode = DocSubcode::EligibilityAttestation;
        let subject_commitment = [2u8; 32];
        let nonce = 12345u64;

        let id1 = generate_credential_id(&issuer, subcode, &subject_commitment, nonce);
        let id2 = generate_credential_id(&issuer, subcode, &subject_commitment, nonce);
        assert_eq!(id1, id2);

        // Different nonce should produce different ID
        let id3 = generate_credential_id(&issuer, subcode, &subject_commitment, nonce + 1);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_nullifier_generation() {
        let credential_id = [1u8; 32];
        let context = b"election_2024";
        let secret = [2u8; 32];

        let n1 = generate_nullifier(&credential_id, context, &secret);
        let n2 = generate_nullifier(&credential_id, context, &secret);
        assert_eq!(n1, n2);

        // Different context should produce different nullifier
        let n3 = generate_nullifier(&credential_id, b"election_2025", &secret);
        assert_ne!(n1, n3);
    }

    #[test]
    fn test_canonical_json() {
        use serde_json::json;

        let value = json!({
            "name": "John",
            "age": 21,
            "country": "US"
        });

        let canonical = canonical::to_canonical_json(&value).unwrap();
        let canonical_str = String::from_utf8(canonical).unwrap();

        // Keys should be sorted alphabetically
        assert_eq!(canonical_str, r#"{"age":21,"country":"US","name":"John"}"#);
    }

    #[test]
    fn test_issuer_type_permissions() {
        assert!(DocClassIssuerType::Government.can_issue(DocSubcode::EligibilityAttestation));
        assert!(!DocClassIssuerType::Government.can_issue(DocSubcode::AcademicTranscript));

        assert!(DocClassIssuerType::Educational.can_issue(DocSubcode::Diploma));
        assert!(DocClassIssuerType::Educational.can_issue(DocSubcode::AcademicTranscript));
        assert!(!DocClassIssuerType::Educational.can_issue(DocSubcode::EligibilityAttestation));

        assert!(DocClassIssuerType::Professional.can_issue(DocSubcode::ProfessionalLicense));
        assert!(!DocClassIssuerType::Professional.can_issue(DocSubcode::Diploma));

        assert!(DocClassIssuerType::SelfSovereign.can_issue(DocSubcode::IdentityRoot));
        assert!(!DocClassIssuerType::SelfSovereign.can_issue(DocSubcode::EligibilityAttestation));
    }

    #[test]
    fn test_revocation_status() {
        assert!(RevocationStatus::Active.is_valid());
        assert!(!RevocationStatus::Revoked.is_valid());
        assert!(!RevocationStatus::Suspended.is_valid());
        assert!(!RevocationStatus::Superseded.is_valid());
        assert!(!RevocationStatus::Expired.is_valid());
    }
}
