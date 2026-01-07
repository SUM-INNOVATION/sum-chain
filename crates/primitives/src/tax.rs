//! SRC-82X Tax & Compliance Domain Standards
//!
//! This module implements the tax and compliance domain family:
//! - SRC-821: Tax Claim Type Registry
//! - SRC-822: Tax Issuer Classes & Roles
//! - SRC-823: Tax Policy Templates
//! - SRC-824: Tax Proof Profiles
//! - SRC-825: Tax Disclosure Envelope
//!
//! Design Principles:
//! - No PII on-chain - only commitments and hashes
//! - Policy-driven verification via SRC-803
//! - ZK-ready structures for SRC-806 proofs
//! - Jurisdictional flexibility

use serde::{Deserialize, Serialize};

use crate::{Address, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Tax claim type identifier (e.g., "tax.filed.return")
pub type TaxClaimType = String;

/// Policy ID (32-byte hash)
pub type PolicyId = [u8; 32];

/// Claim ID (32-byte hash)
pub type ClaimId = [u8; 32];

/// Proof ID (32-byte hash)
pub type ProofId = [u8; 32];

// =============================================================================
// Domain Separation Constants
// =============================================================================

/// Domain separator for tax schema hashes
pub const TAX_SCHEMA_DOMAIN_SEP: &[u8] = b"SRC821-SCHEMA:";

/// Domain separator for tax policy IDs
pub const TAX_POLICY_DOMAIN_SEP: &[u8] = b"SRC823-POLICY:";

/// Domain separator for tax proof profiles
pub const TAX_PROOF_DOMAIN_SEP: &[u8] = b"SRC824-PROOF:";

/// Domain separator for disclosure envelopes
pub const TAX_DISCLOSURE_DOMAIN_SEP: &[u8] = b"SRC825-DISCLOSURE-v1";

/// Domain separator for claim commitments
pub const TAX_CLAIM_COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC82X-CLAIM-COMMITMENT-v1";

// =============================================================================
// SRC-821: Tax Claim Type Registry
// =============================================================================

/// Risk level for tax claims
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxRiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl TaxRiskLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TaxRiskLevel::Low),
            1 => Some(TaxRiskLevel::Medium),
            2 => Some(TaxRiskLevel::High),
            3 => Some(TaxRiskLevel::Critical),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TaxRiskLevel::Low => "Low",
            TaxRiskLevel::Medium => "Medium",
            TaxRiskLevel::High => "High",
            TaxRiskLevel::Critical => "Critical",
        }
    }
}

/// Claim type status in the registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClaimTypeStatus {
    Active = 0,
    Deprecated = 1,
    Retired = 2,
}

impl ClaimTypeStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ClaimTypeStatus::Active),
            1 => Some(ClaimTypeStatus::Deprecated),
            2 => Some(ClaimTypeStatus::Retired),
            _ => None,
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(self, ClaimTypeStatus::Active | ClaimTypeStatus::Deprecated)
    }
}

/// Tax claim type registry entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxClaimTypeEntry {
    /// Claim type identifier (e.g., "tax.filed.return")
    pub claim_type: TaxClaimType,
    /// Schema hash (BLAKE3)
    pub schema_hash: [u8; 32],
    /// Risk level
    pub risk_level: TaxRiskLevel,
    /// Recommended validity window in seconds
    pub recommended_validity_secs: u64,
    /// Required issuer classes (OR logic between groups, AND within groups)
    pub required_issuer_classes: Vec<Vec<TaxIssuerClass>>,
    /// Entry status
    pub status: ClaimTypeStatus,
    /// Version number
    pub version: u32,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

impl TaxClaimTypeEntry {
    /// Generate schema hash for a claim type
    pub fn generate_schema_hash(claim_type: &str, version: u32) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TAX_SCHEMA_DOMAIN_SEP);
        hasher.update(claim_type.as_bytes());
        hasher.update(b":v");
        hasher.update(&version.to_string().as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check if issuer classes satisfy requirements
    pub fn check_issuer_classes(&self, issuer_classes: &[TaxIssuerClass]) -> bool {
        // OR logic between groups
        for group in &self.required_issuer_classes {
            // AND logic within group - all classes in group must be present
            let group_satisfied = group.iter().all(|required| issuer_classes.contains(required));
            if group_satisfied {
                return true;
            }
        }
        false
    }
}

/// V1 predefined tax claim types
pub mod v1_claim_types {
    use super::*;

    pub const TAX_FILED_RETURN: &str = "tax.filed.return";
    pub const TAX_PAID_STATUS: &str = "tax.paid.status";
    pub const TAX_BALANCE_STATUS: &str = "tax.balance.status";
    pub const TAX_INCOME_BRACKET: &str = "tax.income.bracket";
    pub const TAX_WITHHOLDING_BRACKET: &str = "tax.withholding.bracket";
    pub const TAX_NOTICE_OPEN: &str = "tax.notice.open";
    pub const TAX_GOOD_STANDING: &str = "tax.good_standing";

    /// Create the V1 tax.filed.return entry
    pub fn tax_filed_return_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_FILED_RETURN.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_FILED_RETURN, 1),
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 365 * 24 * 60 * 60, // 365 days
            required_issuer_classes: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::AuditorCpa, TaxIssuerClass::TaxFilingProvider],
            ],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.paid.status entry
    pub fn tax_paid_status_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_PAID_STATUS.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_PAID_STATUS, 1),
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 90 * 24 * 60 * 60, // 90 days
            required_issuer_classes: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::BankBroker],
            ],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.balance.status entry
    pub fn tax_balance_status_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_BALANCE_STATUS.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_BALANCE_STATUS, 1),
            risk_level: TaxRiskLevel::High,
            recommended_validity_secs: 30 * 24 * 60 * 60, // 30 days
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.income.bracket entry
    pub fn tax_income_bracket_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_INCOME_BRACKET.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_INCOME_BRACKET, 1),
            risk_level: TaxRiskLevel::High,
            recommended_validity_secs: 365 * 24 * 60 * 60, // 365 days
            required_issuer_classes: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::AuditorCpa],
            ],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.withholding.bracket entry
    pub fn tax_withholding_bracket_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_WITHHOLDING_BRACKET.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_WITHHOLDING_BRACKET, 1),
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 365 * 24 * 60 * 60, // 365 days
            required_issuer_classes: vec![
                vec![TaxIssuerClass::EmployerPayroll],
                vec![TaxIssuerClass::TaxAuthority],
            ],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.notice.open entry
    pub fn tax_notice_open_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_NOTICE_OPEN.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_NOTICE_OPEN, 1),
            risk_level: TaxRiskLevel::High,
            recommended_validity_secs: 30 * 24 * 60 * 60, // 30 days
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create the V1 tax.good_standing entry
    pub fn tax_good_standing_entry(now: Timestamp) -> TaxClaimTypeEntry {
        TaxClaimTypeEntry {
            claim_type: TAX_GOOD_STANDING.to_string(),
            schema_hash: TaxClaimTypeEntry::generate_schema_hash(TAX_GOOD_STANDING, 1),
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 90 * 24 * 60 * 60, // 90 days
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get all V1 claim type entries
    pub fn all_v1_entries(now: Timestamp) -> Vec<TaxClaimTypeEntry> {
        vec![
            tax_filed_return_entry(now),
            tax_paid_status_entry(now),
            tax_balance_status_entry(now),
            tax_income_bracket_entry(now),
            tax_withholding_bracket_entry(now),
            tax_notice_open_entry(now),
            tax_good_standing_entry(now),
        ]
    }
}

// =============================================================================
// SRC-822: Tax Issuer Classes & Roles
// =============================================================================

/// Tax-specific issuer class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxIssuerClass {
    /// Government tax authority (IRS, HMRC, CRA, etc.)
    TaxAuthority = 0,
    /// Employer payroll systems
    EmployerPayroll = 1,
    /// Financial institutions (banks, brokers)
    BankBroker = 2,
    /// Licensed auditors and CPAs
    AuditorCpa = 3,
    /// Tax preparation software/services
    TaxFilingProvider = 4,
}

impl TaxIssuerClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TaxIssuerClass::TaxAuthority),
            1 => Some(TaxIssuerClass::EmployerPayroll),
            2 => Some(TaxIssuerClass::BankBroker),
            3 => Some(TaxIssuerClass::AuditorCpa),
            4 => Some(TaxIssuerClass::TaxFilingProvider),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TaxIssuerClass::TaxAuthority => "Tax Authority",
            TaxIssuerClass::EmployerPayroll => "Employer Payroll",
            TaxIssuerClass::BankBroker => "Bank/Broker",
            TaxIssuerClass::AuditorCpa => "Auditor/CPA",
            TaxIssuerClass::TaxFilingProvider => "Tax Filing Provider",
        }
    }

    pub fn trust_level(&self) -> u8 {
        match self {
            TaxIssuerClass::TaxAuthority => 5, // Highest
            TaxIssuerClass::AuditorCpa => 4,
            TaxIssuerClass::BankBroker => 3,
            TaxIssuerClass::EmployerPayroll => 2,
            TaxIssuerClass::TaxFilingProvider => 1, // Lowest
        }
    }

    /// Check if this issuer class can issue the given claim type
    pub fn can_issue(&self, claim_type: &str) -> bool {
        match self {
            TaxIssuerClass::TaxAuthority => true, // Can issue all tax claims
            TaxIssuerClass::EmployerPayroll => {
                matches!(
                    claim_type,
                    "tax.withholding.bracket" | "tax.paid.status"
                )
            }
            TaxIssuerClass::BankBroker => {
                matches!(claim_type, "tax.paid.status" | "tax.withholding.bracket")
            }
            TaxIssuerClass::AuditorCpa => {
                matches!(claim_type, "tax.filed.return" | "tax.income.bracket")
            }
            TaxIssuerClass::TaxFilingProvider => {
                // Only with co-signature from AuditorCpa
                matches!(claim_type, "tax.filed.return")
            }
        }
    }
}

/// Tax issuer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxIssuerStatus {
    Active = 0,
    Suspended = 1,
    Revoked = 2,
    Expired = 3,
}

impl TaxIssuerStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TaxIssuerStatus::Active),
            1 => Some(TaxIssuerStatus::Suspended),
            2 => Some(TaxIssuerStatus::Revoked),
            3 => Some(TaxIssuerStatus::Expired),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, TaxIssuerStatus::Active)
    }
}

/// Tax issuer registration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxIssuer {
    /// Base issuer address (links to SRC-802)
    pub address: Address,
    /// Tax-specific issuer class
    pub tax_class: TaxIssuerClass,
    /// Jurisdictions authorized for (ISO 3166-1/2 codes)
    pub jurisdictions: Vec<String>,
    /// Class-specific attributes hash
    pub attributes_hash: [u8; 32],
    /// Attribute schema hash
    pub attributes_schema_hash: [u8; 32],
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Status
    pub status: TaxIssuerStatus,
    /// Optional expiry timestamp
    pub expires_at: Option<Timestamp>,
}

impl TaxIssuer {
    /// Check if issuer is authorized for jurisdiction
    pub fn is_authorized_for_jurisdiction(&self, jurisdiction: &str) -> bool {
        // Empty list means all jurisdictions
        if self.jurisdictions.is_empty() {
            return true;
        }
        // Check exact match or parent jurisdiction
        self.jurisdictions.iter().any(|j| {
            j == jurisdiction || jurisdiction.starts_with(&format!("{}-", j))
        })
    }

    /// Check if issuer can issue claim type in jurisdiction
    pub fn can_issue_in_jurisdiction(&self, claim_type: &str, jurisdiction: &str) -> bool {
        self.status.is_valid()
            && self.tax_class.can_issue(claim_type)
            && self.is_authorized_for_jurisdiction(jurisdiction)
    }
}

// =============================================================================
// SRC-823: Tax Policy Templates
// =============================================================================

/// Quorum rule for policy satisfaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum QuorumRule {
    /// Any single group satisfies
    Any = 0,
    /// All groups must satisfy
    All = 1,
    /// At least N groups must satisfy
    AtLeast(u8) = 2,
}

/// Issuer requirements for a policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRequirements {
    /// Issuer class groups (OR between groups, AND within)
    pub groups: Vec<Vec<TaxIssuerClass>>,
    /// Quorum rule
    pub quorum: QuorumRule,
}

impl IssuerRequirements {
    /// Check if issuer classes satisfy requirements
    pub fn is_satisfied(&self, issuer_classes: &[TaxIssuerClass]) -> bool {
        let satisfied_groups: Vec<bool> = self
            .groups
            .iter()
            .map(|group| group.iter().all(|c| issuer_classes.contains(c)))
            .collect();

        match self.quorum {
            QuorumRule::Any => satisfied_groups.iter().any(|&s| s),
            QuorumRule::All => satisfied_groups.iter().all(|&s| s),
            QuorumRule::AtLeast(n) => {
                satisfied_groups.iter().filter(|&&s| s).count() >= n as usize
            }
        }
    }
}

/// Tax policy template types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxPolicyTemplate {
    /// P-Filed: Tax filing verification
    Filed = 0,
    /// P-IncomeBracket: Income bracket verification
    IncomeBracket = 1,
    /// P-NoBalance: Zero balance verification
    NoBalance = 2,
    /// P-GoodStanding: Tax good standing
    GoodStanding = 3,
}

impl TaxPolicyTemplate {
    pub fn name(&self) -> &'static str {
        match self {
            TaxPolicyTemplate::Filed => "P-Filed",
            TaxPolicyTemplate::IncomeBracket => "P-IncomeBracket",
            TaxPolicyTemplate::NoBalance => "P-NoBalance",
            TaxPolicyTemplate::GoodStanding => "P-GoodStanding",
        }
    }
}

/// Tax policy instance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxPolicy {
    /// Policy ID (derived hash)
    pub policy_id: PolicyId,
    /// Template type
    pub template: TaxPolicyTemplate,
    /// Claim types accepted
    pub claim_types: Vec<TaxClaimType>,
    /// Issuer requirements
    pub issuer_requirements: IssuerRequirements,
    /// Jurisdiction scope (empty = any)
    pub jurisdictions: Vec<String>,
    /// Tax years scope (for applicable templates)
    pub tax_years: Vec<u32>,
    /// Maximum age of claim in seconds
    pub max_age_secs: u64,
    /// Require revocation check
    pub revocation_check: bool,
    /// Policy creator
    pub creator: Address,
    /// Created timestamp
    pub created_at: Timestamp,
}

impl TaxPolicy {
    /// Generate policy ID
    pub fn generate_policy_id(
        template: TaxPolicyTemplate,
        jurisdictions: &[String],
        tax_years: &[u32],
        params_hash: &[u8; 32],
    ) -> PolicyId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TAX_POLICY_DOMAIN_SEP);
        hasher.update(template.name().as_bytes());
        hasher.update(b":");

        // Hash jurisdictions
        let mut j_hasher = blake3::Hasher::new();
        for j in jurisdictions {
            j_hasher.update(j.as_bytes());
            j_hasher.update(b",");
        }
        hasher.update(j_hasher.finalize().as_bytes());
        hasher.update(b":");

        // Hash tax years
        let mut y_hasher = blake3::Hasher::new();
        for y in tax_years {
            y_hasher.update(&y.to_be_bytes());
        }
        hasher.update(y_hasher.finalize().as_bytes());
        hasher.update(b":");

        hasher.update(params_hash);
        *hasher.finalize().as_bytes()
    }

    /// Create P-Filed policy
    pub fn create_p_filed(
        jurisdictions: Vec<String>,
        tax_years: Vec<u32>,
        max_age_days: u32,
        creator: Address,
        now: Timestamp,
    ) -> Self {
        let params_hash = blake3::hash(&max_age_days.to_be_bytes());
        let policy_id = Self::generate_policy_id(
            TaxPolicyTemplate::Filed,
            &jurisdictions,
            &tax_years,
            params_hash.as_bytes(),
        );

        TaxPolicy {
            policy_id,
            template: TaxPolicyTemplate::Filed,
            claim_types: vec![v1_claim_types::TAX_FILED_RETURN.to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![
                    vec![TaxIssuerClass::TaxAuthority],
                    vec![TaxIssuerClass::AuditorCpa, TaxIssuerClass::TaxFilingProvider],
                ],
                quorum: QuorumRule::Any,
            },
            jurisdictions,
            tax_years,
            max_age_secs: max_age_days as u64 * 86400,
            revocation_check: true,
            creator,
            created_at: now,
        }
    }

    /// Create P-IncomeBracket policy
    pub fn create_p_income_bracket(
        jurisdictions: Vec<String>,
        tax_year: u32,
        max_age_days: u32,
        creator: Address,
        now: Timestamp,
    ) -> Self {
        let params_hash = blake3::hash(&[max_age_days.to_be_bytes(), tax_year.to_be_bytes()].concat());
        let policy_id = Self::generate_policy_id(
            TaxPolicyTemplate::IncomeBracket,
            &jurisdictions,
            &[tax_year],
            params_hash.as_bytes(),
        );

        TaxPolicy {
            policy_id,
            template: TaxPolicyTemplate::IncomeBracket,
            claim_types: vec![v1_claim_types::TAX_INCOME_BRACKET.to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![
                    vec![TaxIssuerClass::TaxAuthority],
                    vec![TaxIssuerClass::AuditorCpa],
                ],
                quorum: QuorumRule::Any,
            },
            jurisdictions,
            tax_years: vec![tax_year],
            max_age_secs: max_age_days as u64 * 86400,
            revocation_check: true,
            creator,
            created_at: now,
        }
    }

    /// Create P-NoBalance policy
    pub fn create_p_no_balance(
        jurisdictions: Vec<String>,
        max_age_days: u32,
        creator: Address,
        now: Timestamp,
    ) -> Self {
        let params_hash = blake3::hash(&max_age_days.to_be_bytes());
        let policy_id = Self::generate_policy_id(
            TaxPolicyTemplate::NoBalance,
            &jurisdictions,
            &[],
            params_hash.as_bytes(),
        );

        TaxPolicy {
            policy_id,
            template: TaxPolicyTemplate::NoBalance,
            claim_types: vec![v1_claim_types::TAX_BALANCE_STATUS.to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![vec![TaxIssuerClass::TaxAuthority]],
                quorum: QuorumRule::Any,
            },
            jurisdictions,
            tax_years: vec![],
            max_age_secs: max_age_days as u64 * 86400,
            revocation_check: true,
            creator,
            created_at: now,
        }
    }

    /// Create P-GoodStanding policy
    pub fn create_p_good_standing(
        jurisdictions: Vec<String>,
        max_age_days: u32,
        creator: Address,
        now: Timestamp,
    ) -> Self {
        let params_hash = blake3::hash(&max_age_days.to_be_bytes());
        let policy_id = Self::generate_policy_id(
            TaxPolicyTemplate::GoodStanding,
            &jurisdictions,
            &[],
            params_hash.as_bytes(),
        );

        TaxPolicy {
            policy_id,
            template: TaxPolicyTemplate::GoodStanding,
            claim_types: vec![v1_claim_types::TAX_GOOD_STANDING.to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![vec![TaxIssuerClass::TaxAuthority]],
                quorum: QuorumRule::Any,
            },
            jurisdictions,
            tax_years: vec![],
            max_age_secs: max_age_days as u64 * 86400,
            revocation_check: true,
            creator,
            created_at: now,
        }
    }
}

// =============================================================================
// SRC-824: Tax Proof Profiles
// =============================================================================

/// Tax proof profile identifiers
pub mod proof_profiles {
    pub const TAX_PROVE_FILED: &str = "tax.prove_filed.v1";
    pub const TAX_PROVE_INCOME_BRACKET: &str = "tax.prove_income_bracket.v1";
    pub const TAX_PROVE_NO_BALANCE: &str = "tax.prove_no_balance.v1";
    pub const TAX_PROVE_GOOD_STANDING: &str = "tax.prove_good_standing.v1";
}

/// Public inputs for prove_tax_filed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxFiledPublicInputs {
    /// Tax year
    pub year: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Filing status commitment (hides actual status)
    pub status_commitment: [u8; 32],
    /// Timestamp of proof generation
    pub proof_timestamp: Timestamp,
}

/// Public inputs for prove_income_in_bracket
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomeBracketPublicInputs {
    /// Bracket ID being proven
    pub bracket_id: u32,
    /// Tax year
    pub year: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Public inputs for prove_no_outstanding_balance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoBalancePublicInputs {
    /// Period end date (YYYYMMDD)
    pub period_end: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Zero balance commitment
    pub balance_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Public inputs for prove_tax_good_standing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoodStandingPublicInputs {
    /// Period start date (YYYYMMDD)
    pub period_start: u32,
    /// Period end date (YYYYMMDD)
    pub period_end: u32,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Standing commitment
    pub standing_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Tax proof envelope (SRC-806 compatible)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxProofEnvelope {
    /// Proof ID
    pub proof_id: ProofId,
    /// Profile ID
    pub profile_id: String,
    /// Policy ID(s) this proof satisfies
    pub policy_ids: Vec<PolicyId>,
    /// Claim ID(s) used in proof
    pub claim_ids: Vec<ClaimId>,
    /// Public inputs (serialized JSON)
    pub public_inputs: Vec<u8>,
    /// Proof data (ZK proof bytes or placeholder)
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: TaxProofType,
    /// Subject nullifier (for unlinkability)
    pub subject_nullifier: [u8; 32],
    /// Generated timestamp
    pub generated_at: Timestamp,
    /// Expires at
    pub expires_at: Timestamp,
}

/// Proof type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxProofType {
    /// Placeholder/mock proof (for testing)
    Mock = 0,
    /// Groth16 ZK proof
    Groth16 = 1,
    /// PLONK ZK proof
    Plonk = 2,
    /// Signature-based attestation
    Signature = 3,
}

impl TaxProofEnvelope {
    /// Generate proof ID
    pub fn generate_proof_id(
        profile_id: &str,
        public_inputs: &[u8],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TAX_PROOF_DOMAIN_SEP);
        hasher.update(profile_id.as_bytes());
        hasher.update(b":");
        hasher.update(public_inputs);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }
}

/// Verification result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxVerificationResult {
    /// Is proof valid
    pub valid: bool,
    /// Profile ID verified
    pub profile_id: String,
    /// Is policy compliant
    pub policy_compliant: bool,
    /// Revocation check result
    pub revocation_status: TaxRevocationCheckResult,
    /// Verified at timestamp
    pub verified_at: Timestamp,
    /// Verifier address
    pub verifier: Option<Address>,
}

/// Revocation check result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxRevocationCheckResult {
    /// Was check performed
    pub checked: bool,
    /// Is any claim revoked
    pub revoked: bool,
    /// Revocation reason (if revoked)
    pub revocation_reason: Option<TaxRevocationReason>,
}

/// Tax revocation reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxRevocationReason {
    /// Unspecified
    Unspecified = 0,
    /// Information superseded
    Superseded = 1,
    /// Fraudulent filing
    Fraud = 2,
    /// Amendment filed
    Amended = 3,
    /// Audit adjustment
    AuditAdjustment = 4,
    /// Issuer revoked
    IssuerRevoked = 5,
}

// =============================================================================
// SRC-825: Tax Disclosure Envelope
// =============================================================================

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncryptionAlgorithm {
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 0,
    /// AES-256-GCM
    Aes256Gcm = 1,
    /// X25519 + ChaCha20-Poly1305
    X25519ChaCha = 2,
}

/// Disclosure content type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisclosureContentType {
    /// Tax return document
    TaxReturn = 0,
    /// W-2 or equivalent
    W2Form = 1,
    /// 1099 or equivalent
    Form1099 = 2,
    /// Tax transcript
    Transcript = 3,
    /// Payment receipt
    PaymentReceipt = 4,
    /// Assessment notice
    AssessmentNotice = 5,
    /// Other document
    Other = 255,
}

impl DisclosureContentType {
    pub fn name(&self) -> &'static str {
        match self {
            DisclosureContentType::TaxReturn => "Tax Return",
            DisclosureContentType::W2Form => "W-2 Form",
            DisclosureContentType::Form1099 => "Form 1099",
            DisclosureContentType::Transcript => "Tax Transcript",
            DisclosureContentType::PaymentReceipt => "Payment Receipt",
            DisclosureContentType::AssessmentNotice => "Assessment Notice",
            DisclosureContentType::Other => "Other",
        }
    }
}

/// Encryption metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionMeta {
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Key derivation hint (for recipient)
    pub key_hint: [u8; 32],
    /// Initialization vector (if applicable)
    pub iv: Option<[u8; 12]>,
}

/// Tax disclosure envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxDisclosureEnvelope {
    /// Payload hash (BLAKE3 of encrypted content)
    pub payload_hash: [u8; 32],
    /// Payload size in bytes
    pub payload_size: u64,
    /// Optional storage hint (IPFS CID, URL, etc.)
    pub hint_uri: Option<String>,
    /// Encryption metadata
    pub encryption_meta: Option<EncryptionMeta>,
    /// Content type
    pub content_type: DisclosureContentType,
    /// Associated claim ID
    pub claim_id: Option<ClaimId>,
    /// Associated proof ID
    pub proof_id: Option<ProofId>,
    /// Created timestamp
    pub created_at: Timestamp,
}

impl TaxDisclosureEnvelope {
    /// Generate commitment for disclosure envelope
    pub fn generate_commitment(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TAX_DISCLOSURE_DOMAIN_SEP);
        hasher.update(&self.payload_hash);
        hasher.update(&[self.content_type as u8]);
        if let Some(ref claim_id) = self.claim_id {
            hasher.update(claim_id);
        }
        if let Some(ref proof_id) = self.proof_id {
            hasher.update(proof_id);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Tax Domain Operations
// =============================================================================

/// Tax domain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TaxOperation {
    // Registry operations (0-9)
    /// Register claim type
    RegisterClaimType = 0,
    /// Update claim type
    UpdateClaimType = 1,
    /// Deprecate claim type
    DeprecateClaimType = 2,

    // Issuer operations (10-19)
    /// Register tax issuer
    RegisterIssuer = 10,
    /// Update tax issuer
    UpdateIssuer = 11,
    /// Suspend tax issuer
    SuspendIssuer = 12,
    /// Revoke tax issuer
    RevokeIssuer = 13,

    // Policy operations (20-29)
    /// Create policy
    CreatePolicy = 20,
    /// Update policy
    UpdatePolicy = 21,

    // Claim operations (30-39)
    /// Issue tax claim
    IssueClaim = 30,
    /// Revoke tax claim
    RevokeClaim = 31,

    // Proof operations (40-49)
    /// Submit proof for verification
    VerifyProof = 40,

    // Disclosure operations (50-59)
    /// Attach disclosure
    AttachDisclosure = 50,
}

impl TaxOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TaxOperation::RegisterClaimType),
            1 => Some(TaxOperation::UpdateClaimType),
            2 => Some(TaxOperation::DeprecateClaimType),
            10 => Some(TaxOperation::RegisterIssuer),
            11 => Some(TaxOperation::UpdateIssuer),
            12 => Some(TaxOperation::SuspendIssuer),
            13 => Some(TaxOperation::RevokeIssuer),
            20 => Some(TaxOperation::CreatePolicy),
            21 => Some(TaxOperation::UpdatePolicy),
            30 => Some(TaxOperation::IssueClaim),
            31 => Some(TaxOperation::RevokeClaim),
            40 => Some(TaxOperation::VerifyProof),
            50 => Some(TaxOperation::AttachDisclosure),
            _ => None,
        }
    }
}

/// Tax domain transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxTxData {
    /// Operation type
    pub operation: TaxOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

// =============================================================================
// Tax Domain Events
// =============================================================================

/// Tax registry events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxRegistryEvent {
    /// Claim type added
    ClaimTypeAdded {
        claim_type: TaxClaimType,
        schema_hash: [u8; 32],
        version: u32,
    },
    /// Claim type updated
    ClaimTypeUpdated {
        claim_type: TaxClaimType,
        schema_hash: [u8; 32],
        old_version: u32,
        new_version: u32,
    },
    /// Claim type deprecated
    ClaimTypeDeprecated {
        claim_type: TaxClaimType,
        version: u32,
    },
}

/// Tax issuer events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxIssuerEvent {
    /// Issuer registered
    IssuerRegistered {
        address: Address,
        tax_class: TaxIssuerClass,
        jurisdictions: Vec<String>,
    },
    /// Issuer updated
    IssuerUpdated {
        address: Address,
    },
    /// Issuer status changed
    IssuerStatusChanged {
        address: Address,
        old_status: TaxIssuerStatus,
        new_status: TaxIssuerStatus,
    },
}

/// Tax policy events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxPolicyEvent {
    /// Policy created
    PolicyCreated {
        policy_id: PolicyId,
        template: TaxPolicyTemplate,
        creator: Address,
    },
    /// Policy updated
    PolicyUpdated {
        policy_id: PolicyId,
        updater: Address,
    },
}

/// Tax proof events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxProofEvent {
    /// Proof verified
    ProofVerified {
        proof_id: ProofId,
        profile_id: String,
        policy_ids: Vec<PolicyId>,
        verifier: Address,
        valid: bool,
    },
}

/// Tax disclosure events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxDisclosureEvent {
    /// Disclosure attached
    DisclosureAttached {
        disclosure_commitment: [u8; 32],
        claim_id: Option<ClaimId>,
        proof_id: Option<ProofId>,
        content_type: DisclosureContentType,
    },
}

/// Combined tax event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaxEvent {
    Registry(TaxRegistryEvent),
    Issuer(TaxIssuerEvent),
    Policy(TaxPolicyEvent),
    Proof(TaxProofEvent),
    Disclosure(TaxDisclosureEvent),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_type_schema_hash() {
        let hash1 = TaxClaimTypeEntry::generate_schema_hash("tax.filed.return", 1);
        let hash2 = TaxClaimTypeEntry::generate_schema_hash("tax.filed.return", 1);
        let hash3 = TaxClaimTypeEntry::generate_schema_hash("tax.filed.return", 2);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_issuer_class_authorization() {
        let authority = TaxIssuerClass::TaxAuthority;
        let cpa = TaxIssuerClass::AuditorCpa;
        let filing_provider = TaxIssuerClass::TaxFilingProvider;

        // Tax authority can issue all
        assert!(authority.can_issue("tax.filed.return"));
        assert!(authority.can_issue("tax.income.bracket"));
        assert!(authority.can_issue("tax.balance.status"));

        // CPA can issue filed.return and income.bracket
        assert!(cpa.can_issue("tax.filed.return"));
        assert!(cpa.can_issue("tax.income.bracket"));
        assert!(!cpa.can_issue("tax.balance.status"));

        // Filing provider can only issue filed.return (with co-signature)
        assert!(filing_provider.can_issue("tax.filed.return"));
        assert!(!filing_provider.can_issue("tax.income.bracket"));
    }

    #[test]
    fn test_issuer_requirements_satisfaction() {
        let requirements = IssuerRequirements {
            groups: vec![
                vec![TaxIssuerClass::TaxAuthority],
                vec![TaxIssuerClass::AuditorCpa, TaxIssuerClass::TaxFilingProvider],
            ],
            quorum: QuorumRule::Any,
        };

        // Tax authority alone satisfies
        assert!(requirements.is_satisfied(&[TaxIssuerClass::TaxAuthority]));

        // CPA + Filing provider together satisfy
        assert!(requirements.is_satisfied(&[
            TaxIssuerClass::AuditorCpa,
            TaxIssuerClass::TaxFilingProvider
        ]));

        // CPA alone does not satisfy
        assert!(!requirements.is_satisfied(&[TaxIssuerClass::AuditorCpa]));

        // Filing provider alone does not satisfy
        assert!(!requirements.is_satisfied(&[TaxIssuerClass::TaxFilingProvider]));
    }

    #[test]
    fn test_policy_id_determinism() {
        let creator = Address::ZERO;
        let now = 1704067200000u64;

        let policy1 = TaxPolicy::create_p_filed(
            vec!["US".to_string()],
            vec![2023],
            365,
            creator,
            now,
        );

        let policy2 = TaxPolicy::create_p_filed(
            vec!["US".to_string()],
            vec![2023],
            365,
            creator,
            now,
        );

        let policy3 = TaxPolicy::create_p_filed(
            vec!["CA".to_string()],
            vec![2023],
            365,
            creator,
            now,
        );

        assert_eq!(policy1.policy_id, policy2.policy_id);
        assert_ne!(policy1.policy_id, policy3.policy_id);
    }

    #[test]
    fn test_v1_claim_types() {
        let now = 1704067200000u64;
        let entries = v1_claim_types::all_v1_entries(now);

        assert_eq!(entries.len(), 7);

        // Verify all entries have unique claim types
        let mut claim_types: Vec<_> = entries.iter().map(|e| &e.claim_type).collect();
        claim_types.sort();
        claim_types.dedup();
        assert_eq!(claim_types.len(), 7);
    }

    #[test]
    fn test_disclosure_commitment() {
        let disclosure = TaxDisclosureEnvelope {
            payload_hash: [1u8; 32],
            payload_size: 1024,
            hint_uri: Some("ipfs://Qm...".to_string()),
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: Some([2u8; 32]),
            proof_id: None,
            created_at: 1704067200000,
        };

        let commitment1 = disclosure.generate_commitment();
        let commitment2 = disclosure.generate_commitment();

        assert_eq!(commitment1, commitment2);

        // Different payload should give different commitment
        let mut disclosure2 = disclosure.clone();
        disclosure2.payload_hash = [3u8; 32];
        let commitment3 = disclosure2.generate_commitment();

        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn test_tax_issuer_jurisdiction_check() {
        let issuer = TaxIssuer {
            address: Address::ZERO,
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [0u8; 32],
            attributes_schema_hash: [0u8; 32],
            registered_at: 1704067200000,
            updated_at: 1704067200000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };

        // Exact match
        assert!(issuer.is_authorized_for_jurisdiction("US"));

        // Sub-jurisdiction
        assert!(issuer.is_authorized_for_jurisdiction("US-CA"));
        assert!(issuer.is_authorized_for_jurisdiction("US-NY"));

        // Different jurisdiction
        assert!(!issuer.is_authorized_for_jurisdiction("CA"));
        assert!(!issuer.is_authorized_for_jurisdiction("GB"));
    }
}
