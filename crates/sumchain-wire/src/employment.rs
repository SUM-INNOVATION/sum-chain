//! SRC-88X Employment & HR Domain Standards
//!
//! This module implements the employment and HR domain family:
//! - SRC-881: Employer & Payroll Issuer Profile
//! - SRC-882: Employment Relationship Credential
//! - SRC-883: Income / Payroll Attestation
//! - SRC-885: 88X Proof Profiles
//!
//! Design Principles:
//! - No PII on-chain - only commitments and hashes
//! - Policy-driven verification via SRC-803
//! - ZK-ready structures for SRC-806 proofs
//! - Range-first income verification (brackets, not exact amounts)
//! - Supports both Phase 1 (employers, payroll) and Phase 2 (official institutions)

use serde::{Deserialize, Serialize};

use crate::{Address, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Employment ID (32-byte hash)
pub type EmploymentId = [u8; 32];

/// Income attestation ID (32-byte hash)
pub type IncomeAttestationId = [u8; 32];

/// Policy ID (32-byte hash)
pub type PolicyId = [u8; 32];

/// Proof ID (32-byte hash)
pub type ProofId = [u8; 32];

/// Subject reference (commitment to employee identity)
pub type SubjectRef = [u8; 32];

/// Employer reference (commitment or issuer ID)
pub type EmployerRef = [u8; 32];

// =============================================================================
// Domain Separation Constants
// =============================================================================

/// Domain separator for employment credential commitments
pub const EMPLOYMENT_CREDENTIAL_DOMAIN_SEP: &[u8] = b"SRC882-EMPLOYMENT-v1";

/// Domain separator for income attestation commitments
pub const INCOME_ATTESTATION_DOMAIN_SEP: &[u8] = b"SRC883-INCOME-v1";

/// Domain separator for tenure commitments
pub const TENURE_COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC882-TENURE-v1";

/// Domain separator for role commitments
pub const ROLE_COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC882-ROLE-v1";

/// Domain separator for income bracket commitments
pub const INCOME_BRACKET_DOMAIN_SEP: &[u8] = b"SRC883-BRACKET-v1";

/// Domain separator for period commitments
pub const PERIOD_COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC883-PERIOD-v1";

/// Domain separator for proof profiles
pub const EMPLOYMENT_PROOF_DOMAIN_SEP: &[u8] = b"SRC885-PROOF-v1";

// =============================================================================
// SRC-881: Employer & Payroll Issuer Profile
// =============================================================================

/// Issuer class for employment domain (layered over SRC-802)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentIssuerClass {
    // Phase 2 (Official/Lower Risk)
    /// Government labor department
    GovernmentLabor = 0,
    /// Licensed payroll processor (ADP, Paychex, etc.)
    PayrollProcessor = 1,
    /// Regulated HR platform with compliance
    RegulatedHrPlatform = 2,
    /// Professional employer organization
    Peo = 3,

    // Phase 1 (Higher Risk)
    /// Direct employer
    Employer = 10,
    /// Unregulated HR platform
    HrPlatform = 11,
    /// Staffing agency
    StaffingAgency = 12,
    /// Gig platform
    GigPlatform = 13,
}

impl EmploymentIssuerClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentIssuerClass::GovernmentLabor),
            1 => Some(EmploymentIssuerClass::PayrollProcessor),
            2 => Some(EmploymentIssuerClass::RegulatedHrPlatform),
            3 => Some(EmploymentIssuerClass::Peo),
            10 => Some(EmploymentIssuerClass::Employer),
            11 => Some(EmploymentIssuerClass::HrPlatform),
            12 => Some(EmploymentIssuerClass::StaffingAgency),
            13 => Some(EmploymentIssuerClass::GigPlatform),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EmploymentIssuerClass::GovernmentLabor => "Government Labor Department",
            EmploymentIssuerClass::PayrollProcessor => "Payroll Processor",
            EmploymentIssuerClass::RegulatedHrPlatform => "Regulated HR Platform",
            EmploymentIssuerClass::Peo => "Professional Employer Organization",
            EmploymentIssuerClass::Employer => "Employer",
            EmploymentIssuerClass::HrPlatform => "HR Platform",
            EmploymentIssuerClass::StaffingAgency => "Staffing Agency",
            EmploymentIssuerClass::GigPlatform => "Gig Platform",
        }
    }

    /// Check if this is a Phase 2 (official) issuer class
    pub fn is_official(&self) -> bool {
        matches!(
            self,
            EmploymentIssuerClass::GovernmentLabor
                | EmploymentIssuerClass::PayrollProcessor
                | EmploymentIssuerClass::RegulatedHrPlatform
                | EmploymentIssuerClass::Peo
        )
    }

    /// Check if this is a Phase 1 (lowkey) issuer class
    pub fn is_lowkey(&self) -> bool {
        !self.is_official()
    }

    /// Get default risk level for this issuer class
    pub fn default_risk_level(&self) -> EmploymentRiskLevel {
        match self {
            EmploymentIssuerClass::GovernmentLabor => EmploymentRiskLevel::Low,
            EmploymentIssuerClass::PayrollProcessor => EmploymentRiskLevel::Low,
            EmploymentIssuerClass::RegulatedHrPlatform => EmploymentRiskLevel::Medium,
            EmploymentIssuerClass::Peo => EmploymentRiskLevel::Medium,
            EmploymentIssuerClass::Employer => EmploymentRiskLevel::Medium,
            EmploymentIssuerClass::HrPlatform => EmploymentRiskLevel::High,
            EmploymentIssuerClass::StaffingAgency => EmploymentRiskLevel::Medium,
            EmploymentIssuerClass::GigPlatform => EmploymentRiskLevel::High,
        }
    }
}

/// Risk level for employment credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentRiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl EmploymentRiskLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentRiskLevel::Low),
            1 => Some(EmploymentRiskLevel::Medium),
            2 => Some(EmploymentRiskLevel::High),
            3 => Some(EmploymentRiskLevel::Critical),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EmploymentRiskLevel::Low => "Low",
            EmploymentRiskLevel::Medium => "Medium",
            EmploymentRiskLevel::High => "High",
            EmploymentRiskLevel::Critical => "Critical",
        }
    }
}

/// Employer/Payroll issuer profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentIssuerProfile {
    /// Issuer address on-chain
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: EmploymentIssuerClass,
    /// Display name (public, e.g., "SUM INNOVATION INC")
    #[serde(default)]
    pub display_name: String,
    /// Issuer commitment (company name, EIN, etc. - all committed, not revealed)
    pub issuer_commitment: [u8; 32],
    /// Jurisdiction code (ISO 3166-1 alpha-2 + optional subdivision)
    pub jurisdiction_code: String,
    /// Policy ID governing this issuer
    pub policy_id: PolicyId,
    /// Status
    pub status: IssuerStatus,
    /// Registered at height
    pub registered_at_height: u64,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

/// Issuer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IssuerStatus {
    Pending = 0,
    Active = 1,
    Suspended = 2,
    Revoked = 3,
}

impl IssuerStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(IssuerStatus::Pending),
            1 => Some(IssuerStatus::Active),
            2 => Some(IssuerStatus::Suspended),
            3 => Some(IssuerStatus::Revoked),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, IssuerStatus::Active)
    }
}

// =============================================================================
// SRC-882: Employment Relationship Credential
// =============================================================================

/// Employment relationship status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentStatus {
    /// Currently employed
    Active = 0,
    /// Employment temporarily suspended
    Suspended = 1,
    /// Employment ended
    Ended = 2,
    /// On leave (still employed but not working)
    OnLeave = 3,
}

impl EmploymentStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentStatus::Active),
            1 => Some(EmploymentStatus::Suspended),
            2 => Some(EmploymentStatus::Ended),
            3 => Some(EmploymentStatus::OnLeave),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EmploymentStatus::Active => "Active",
            EmploymentStatus::Suspended => "Suspended",
            EmploymentStatus::Ended => "Ended",
            EmploymentStatus::OnLeave => "On Leave",
        }
    }

    pub fn is_currently_employed(&self) -> bool {
        matches!(self, EmploymentStatus::Active | EmploymentStatus::OnLeave)
    }
}

/// Employment relationship credential (SRC-882)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentCredential {
    /// Unique employment ID
    pub employment_id: EmploymentId,
    /// Employee wallet address (for direct wallet-based ownership)
    pub employee_address: Address,
    /// Employee reference (subject commitment - NO PII)
    pub employee_ref: SubjectRef,
    /// Employer reference (issuer commitment or subject ID)
    pub employer_ref: EmployerRef,
    /// Employment status
    pub status: EmploymentStatus,
    /// Tenure commitment (start date committed, not revealed)
    /// commitment = blake3(TENURE_DOMAIN || start_date || salt)
    pub tenure_commitment: [u8; 32],
    /// Optional role commitment
    /// commitment = blake3(ROLE_DOMAIN || role_title || department || salt)
    pub role_commitment: Option<[u8; 32]>,
    /// Employment type
    pub employment_type: EmploymentType,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp (0 = no expiry for ongoing employment)
    pub expiry: Timestamp,
    /// Policy ID governing this credential
    pub policy_id: PolicyId,
    /// Revocation reference (for SRC-805 compatibility)
    pub revocation_ref: Option<[u8; 32]>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer display name (public, e.g., "SUM INNOVATION INC")
    #[serde(default)]
    pub issuer_name: String,
    /// Issuer class
    pub issuer_class: EmploymentIssuerClass,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

impl EmploymentCredential {
    /// Generate employment ID
    pub fn generate_id(
        employee_ref: &SubjectRef,
        employer_ref: &EmployerRef,
        tenure_commitment: &[u8; 32],
        nonce: u64,
    ) -> EmploymentId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EMPLOYMENT_CREDENTIAL_DOMAIN_SEP);
        hasher.update(employee_ref);
        hasher.update(employer_ref);
        hasher.update(tenure_commitment);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate tenure commitment
    pub fn generate_tenure_commitment(start_date: Timestamp, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TENURE_COMMITMENT_DOMAIN_SEP);
        hasher.update(&start_date.to_le_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate role commitment
    pub fn generate_role_commitment(role_title: &str, department: &str, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ROLE_COMMITMENT_DOMAIN_SEP);
        hasher.update(role_title.as_bytes());
        hasher.update(b":");
        hasher.update(department.as_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Check if credential is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from
            && (self.expiry == 0 || current_time < self.expiry)
            && self.revocation_ref.is_none()
            && self.status.is_currently_employed()
    }
}

/// Employment type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentType {
    FullTime = 0,
    PartTime = 1,
    Contract = 2,
    Temporary = 3,
    Internship = 4,
    Freelance = 5,
    Gig = 6,
}

impl EmploymentType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentType::FullTime),
            1 => Some(EmploymentType::PartTime),
            2 => Some(EmploymentType::Contract),
            3 => Some(EmploymentType::Temporary),
            4 => Some(EmploymentType::Internship),
            5 => Some(EmploymentType::Freelance),
            6 => Some(EmploymentType::Gig),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            EmploymentType::FullTime => "Full-time",
            EmploymentType::PartTime => "Part-time",
            EmploymentType::Contract => "Contract",
            EmploymentType::Temporary => "Temporary",
            EmploymentType::Internship => "Internship",
            EmploymentType::Freelance => "Freelance",
            EmploymentType::Gig => "Gig",
        }
    }
}

// =============================================================================
// SRC-883: Income / Payroll Attestation (Range-first)
// =============================================================================

/// Income bracket for range-first verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IncomeBracket {
    /// Below $25,000 annually
    Bracket0 = 0,
    /// $25,000 - $50,000
    Bracket1 = 1,
    /// $50,000 - $75,000
    Bracket2 = 2,
    /// $75,000 - $100,000
    Bracket3 = 3,
    /// $100,000 - $150,000
    Bracket4 = 4,
    /// $150,000 - $200,000
    Bracket5 = 5,
    /// $200,000 - $300,000
    Bracket6 = 6,
    /// $300,000 - $500,000
    Bracket7 = 7,
    /// Above $500,000
    Bracket8 = 8,
    /// Custom threshold (use threshold_commitment)
    Custom = 255,
}

impl IncomeBracket {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(IncomeBracket::Bracket0),
            1 => Some(IncomeBracket::Bracket1),
            2 => Some(IncomeBracket::Bracket2),
            3 => Some(IncomeBracket::Bracket3),
            4 => Some(IncomeBracket::Bracket4),
            5 => Some(IncomeBracket::Bracket5),
            6 => Some(IncomeBracket::Bracket6),
            7 => Some(IncomeBracket::Bracket7),
            8 => Some(IncomeBracket::Bracket8),
            255 => Some(IncomeBracket::Custom),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            IncomeBracket::Bracket0 => "Below $25,000",
            IncomeBracket::Bracket1 => "$25,000 - $50,000",
            IncomeBracket::Bracket2 => "$50,000 - $75,000",
            IncomeBracket::Bracket3 => "$75,000 - $100,000",
            IncomeBracket::Bracket4 => "$100,000 - $150,000",
            IncomeBracket::Bracket5 => "$150,000 - $200,000",
            IncomeBracket::Bracket6 => "$200,000 - $300,000",
            IncomeBracket::Bracket7 => "$300,000 - $500,000",
            IncomeBracket::Bracket8 => "Above $500,000",
            IncomeBracket::Custom => "Custom threshold",
        }
    }

    /// Check if income is at least this bracket
    pub fn is_at_least(&self, other: &IncomeBracket) -> bool {
        (*self as u8) >= (*other as u8) && *self != IncomeBracket::Custom
    }
}

/// Income attestation period
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IncomePeriod {
    Monthly = 0,
    Quarterly = 1,
    Annual = 2,
    YearToDate = 3,
}

impl IncomePeriod {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(IncomePeriod::Monthly),
            1 => Some(IncomePeriod::Quarterly),
            2 => Some(IncomePeriod::Annual),
            3 => Some(IncomePeriod::YearToDate),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            IncomePeriod::Monthly => "Monthly",
            IncomePeriod::Quarterly => "Quarterly",
            IncomePeriod::Annual => "Annual",
            IncomePeriod::YearToDate => "Year-to-Date",
        }
    }
}

/// Income/Payroll attestation (SRC-883)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomeAttestation {
    /// Unique attestation ID
    pub attestation_id: IncomeAttestationId,
    /// Holder wallet address (for token ownership)
    pub holder_address: Address,
    /// Subject reference (commitment to employee)
    pub subject_ref: SubjectRef,
    /// Period commitment (period type + dates committed)
    pub period_commitment: [u8; 32],
    /// Income period type
    pub period_type: IncomePeriod,
    /// Income bracket (range-first)
    pub income_bracket: IncomeBracket,
    /// Optional threshold commitment for custom brackets
    /// commitment = blake3(BRACKET_DOMAIN || threshold_min || threshold_max || currency || salt)
    pub threshold_commitment: Option<[u8; 32]>,
    /// Employment ID (links to employment credential)
    pub employment_id: Option<EmploymentId>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: EmploymentIssuerClass,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expiry: Timestamp,
    /// Policy ID governing this attestation
    pub policy_id: PolicyId,
    /// Revocation reference (for SRC-805 compatibility)
    pub revocation_ref: Option<[u8; 32]>,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

impl IncomeAttestation {
    /// Generate attestation ID
    pub fn generate_id(
        subject_ref: &SubjectRef,
        period_commitment: &[u8; 32],
        income_bracket: IncomeBracket,
        nonce: u64,
    ) -> IncomeAttestationId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(INCOME_ATTESTATION_DOMAIN_SEP);
        hasher.update(subject_ref);
        hasher.update(period_commitment);
        hasher.update(&[income_bracket as u8]);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate period commitment
    pub fn generate_period_commitment(
        period_type: IncomePeriod,
        start_date: Timestamp,
        end_date: Timestamp,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PERIOD_COMMITMENT_DOMAIN_SEP);
        hasher.update(&[period_type as u8]);
        hasher.update(&start_date.to_le_bytes());
        hasher.update(&end_date.to_le_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate threshold commitment for custom brackets
    pub fn generate_threshold_commitment(
        threshold_min: u64,
        threshold_max: u64,
        currency: &str,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(INCOME_BRACKET_DOMAIN_SEP);
        hasher.update(&threshold_min.to_le_bytes());
        hasher.update(&threshold_max.to_le_bytes());
        hasher.update(currency.as_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Check if attestation is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from
            && current_time < self.expiry
            && self.revocation_ref.is_none()
    }
}

// =============================================================================
// SRC-885: 88X Proof Profiles
// =============================================================================

/// Proof profile types for employment domain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentProofType {
    /// Prove currently employed with optional employer scope
    CurrentlyEmployed = 0,
    /// Prove employed for at least a duration
    EmployedForDuration = 1,
    /// Prove income in a specific bracket
    IncomeInBracket = 2,
    /// Prove role in a set of allowed roles
    RoleInSet = 3,
    /// Prove employment type
    EmploymentType = 4,
    /// Combined proof (multiple conditions)
    Combined = 255,
}

impl EmploymentProofType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentProofType::CurrentlyEmployed),
            1 => Some(EmploymentProofType::EmployedForDuration),
            2 => Some(EmploymentProofType::IncomeInBracket),
            3 => Some(EmploymentProofType::RoleInSet),
            4 => Some(EmploymentProofType::EmploymentType),
            255 => Some(EmploymentProofType::Combined),
            _ => None,
        }
    }
}

/// Employment proof profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentProofProfile {
    /// Profile ID
    pub profile_id: [u8; 32],
    /// Profile type
    pub proof_type: EmploymentProofType,
    /// Minimum employer scope commitment (optional)
    pub employer_scope: Option<[u8; 32]>,
    /// Minimum duration in seconds (for EmployedForDuration)
    pub min_duration_secs: Option<u64>,
    /// Minimum income bracket (for IncomeInBracket)
    pub min_income_bracket: Option<IncomeBracket>,
    /// Allowed role set commitment (for RoleInSet)
    pub role_set_commitment: Option<[u8; 32]>,
    /// Required employment types (for EmploymentType)
    pub required_employment_types: Vec<EmploymentType>,
    /// Required issuer classes
    pub required_issuer_classes: Vec<EmploymentIssuerClass>,
    /// Maximum age of credential in seconds
    pub max_credential_age_secs: u64,
    /// Policy ID
    pub policy_id: PolicyId,
}

impl EmploymentProofProfile {
    /// Generate profile ID
    pub fn generate_id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EMPLOYMENT_PROOF_DOMAIN_SEP);
        hasher.update(&[self.proof_type.clone() as u8]);
        if let Some(scope) = &self.employer_scope {
            hasher.update(scope);
        }
        if let Some(duration) = self.min_duration_secs {
            hasher.update(&duration.to_le_bytes());
        }
        if let Some(bracket) = &self.min_income_bracket {
            hasher.update(&[*bracket as u8]);
        }
        hasher.update(&self.policy_id);
        *hasher.finalize().as_bytes()
    }
}

/// Employment proof envelope (SRC-806 compatible)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentProofEnvelope {
    /// Unique proof ID
    pub proof_id: ProofId,
    /// Proof profile ID
    pub profile_id: [u8; 32],
    /// Proof type
    pub proof_type: EmploymentProofType,
    /// Subject nullifier (prevents linkability)
    pub subject_nullifier: [u8; 32],
    /// Proof data (ZK proof bytes or threshold signature)
    pub proof_data: Vec<u8>,
    /// Public inputs commitment
    pub public_inputs_commitment: [u8; 32],
    /// Credential references (commitments to source credentials)
    pub credential_refs: Vec<[u8; 32]>,
    /// Issuer class of source credential
    pub source_issuer_class: EmploymentIssuerClass,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expiry: Timestamp,
    /// Created at timestamp
    pub created_at: Timestamp,
}

impl EmploymentProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile_id: &[u8; 32],
        subject_nullifier: &[u8; 32],
        proof_data: &[u8],
        nonce: u64,
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EMPLOYMENT_PROOF_DOMAIN_SEP);
        hasher.update(profile_id);
        hasher.update(subject_nullifier);
        hasher.update(&blake3::hash(proof_data).as_bytes()[..]);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check if proof is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from && current_time < self.expiry
    }
}

// =============================================================================
// Events
// =============================================================================

/// Employment domain events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmploymentEvent {
    /// Issuer registered
    IssuerRegistered {
        issuer_address: Address,
        issuer_class: EmploymentIssuerClass,
        timestamp: Timestamp,
    },
    /// Issuer status updated
    IssuerStatusUpdated {
        issuer_address: Address,
        old_status: IssuerStatus,
        new_status: IssuerStatus,
        timestamp: Timestamp,
    },
    /// Employment credential created
    EmploymentCreated {
        employment_id: EmploymentId,
        employee_ref: SubjectRef,
        employer_ref: EmployerRef,
        status: EmploymentStatus,
        timestamp: Timestamp,
    },
    /// Employment status updated
    EmploymentUpdated {
        employment_id: EmploymentId,
        old_status: EmploymentStatus,
        new_status: EmploymentStatus,
        timestamp: Timestamp,
    },
    /// Employment revoked
    EmploymentRevoked {
        employment_id: EmploymentId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    },
    /// Income attestation created
    IncomeAttestationCreated {
        attestation_id: IncomeAttestationId,
        subject_ref: SubjectRef,
        income_bracket: IncomeBracket,
        timestamp: Timestamp,
    },
    /// Income attestation revoked
    IncomeAttestationRevoked {
        attestation_id: IncomeAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    },
    /// Proof submitted
    ProofSubmitted {
        proof_id: ProofId,
        proof_type: EmploymentProofType,
        timestamp: Timestamp,
    },
    /// Proof verified
    ProofVerified {
        proof_id: ProofId,
        verifier: Address,
        result: bool,
        timestamp: Timestamp,
    },
}

// =============================================================================
// Operations
// =============================================================================

/// Employment domain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EmploymentOperation {
    // Issuer operations (SRC-881)
    RegisterIssuer = 0,
    UpdateIssuer = 1,
    SuspendIssuer = 2,
    RevokeIssuer = 3,
    ReactivateIssuer = 4,

    // Employment credential operations (SRC-882)
    CreateEmployment = 10,
    UpdateEmployment = 11,
    SuspendEmployment = 12,
    EndEmployment = 13,
    RevokeEmployment = 14,

    // Income attestation operations (SRC-883)
    CreateIncomeAttestation = 20,
    UpdateIncomeAttestation = 21,
    RevokeIncomeAttestation = 22,

    // Proof operations (SRC-885)
    SubmitProof = 30,
    VerifyProof = 31,
}

impl EmploymentOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EmploymentOperation::RegisterIssuer),
            1 => Some(EmploymentOperation::UpdateIssuer),
            2 => Some(EmploymentOperation::SuspendIssuer),
            3 => Some(EmploymentOperation::RevokeIssuer),
            4 => Some(EmploymentOperation::ReactivateIssuer),
            10 => Some(EmploymentOperation::CreateEmployment),
            11 => Some(EmploymentOperation::UpdateEmployment),
            12 => Some(EmploymentOperation::SuspendEmployment),
            13 => Some(EmploymentOperation::EndEmployment),
            14 => Some(EmploymentOperation::RevokeEmployment),
            20 => Some(EmploymentOperation::CreateIncomeAttestation),
            21 => Some(EmploymentOperation::UpdateIncomeAttestation),
            22 => Some(EmploymentOperation::RevokeIncomeAttestation),
            30 => Some(EmploymentOperation::SubmitProof),
            31 => Some(EmploymentOperation::VerifyProof),
            _ => None,
        }
    }
}

/// Employment transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmploymentTxData {
    pub operation: EmploymentOperation,
    pub data: Vec<u8>,
    /// Token recipient address - the owner of the minted token
    pub recipient: crate::Address,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_class_risk_levels() {
        assert_eq!(
            EmploymentIssuerClass::GovernmentLabor.default_risk_level(),
            EmploymentRiskLevel::Low
        );
        assert_eq!(
            EmploymentIssuerClass::GigPlatform.default_risk_level(),
            EmploymentRiskLevel::High
        );
    }

    #[test]
    fn test_issuer_class_phases() {
        assert!(EmploymentIssuerClass::PayrollProcessor.is_official());
        assert!(!EmploymentIssuerClass::PayrollProcessor.is_lowkey());
        assert!(EmploymentIssuerClass::Employer.is_lowkey());
        assert!(!EmploymentIssuerClass::Employer.is_official());
    }

    #[test]
    fn test_employment_id_generation() {
        let employee_ref = [1u8; 32];
        let employer_ref = [2u8; 32];
        let tenure_commitment = [3u8; 32];
        let id = EmploymentCredential::generate_id(&employee_ref, &employer_ref, &tenure_commitment, 1);
        assert_ne!(id, [0u8; 32]);

        // Same inputs, different nonce = different ID
        let id2 = EmploymentCredential::generate_id(&employee_ref, &employer_ref, &tenure_commitment, 2);
        assert_ne!(id, id2);
    }

    #[test]
    fn test_tenure_commitment_generation() {
        let start_date: Timestamp = 1700000000;
        let salt = [4u8; 32];
        let commitment = EmploymentCredential::generate_tenure_commitment(start_date, &salt);
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_income_bracket_ordering() {
        assert!(IncomeBracket::Bracket5.is_at_least(&IncomeBracket::Bracket3));
        assert!(!IncomeBracket::Bracket2.is_at_least(&IncomeBracket::Bracket5));
        assert!(!IncomeBracket::Custom.is_at_least(&IncomeBracket::Bracket1));
    }

    #[test]
    fn test_income_attestation_id_generation() {
        let subject_ref = [5u8; 32];
        let period_commitment = [6u8; 32];
        let id = IncomeAttestation::generate_id(
            &subject_ref,
            &period_commitment,
            IncomeBracket::Bracket3,
            1,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_employment_status_checks() {
        assert!(EmploymentStatus::Active.is_currently_employed());
        assert!(EmploymentStatus::OnLeave.is_currently_employed());
        assert!(!EmploymentStatus::Ended.is_currently_employed());
        assert!(!EmploymentStatus::Suspended.is_currently_employed());
    }
}
