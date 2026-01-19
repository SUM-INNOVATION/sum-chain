//! SRC-89X Utility Address Proof, Banking & Finance Domain Standards
//!
//! This module implements the finance and banking domain family:
//! - SRC-891: Financial Institution & Utility Issuer Profile
//! - SRC-892: Proof-of-Address Credential
//! - SRC-893: Bank Account Standing Credential
//! - SRC-894: KYC / AML Attestation
//! - SRC-895: 89X Proof Profiles
//!
//! Design Principles:
//! - No PII on-chain - only commitments and hashes
//! - Policy-driven verification via SRC-803
//! - ZK-ready structures for SRC-806 proofs
//! - Supports both Phase 1 (banks, utilities) and Phase 2 (official institutions)

use serde::{Deserialize, Serialize};

use crate::{Address, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Address proof ID (32-byte hash)
pub type AddressProofId = [u8; 32];

/// Bank standing ID (32-byte hash)
pub type BankStandingId = [u8; 32];

/// KYC attestation ID (32-byte hash)
pub type KycAttestationId = [u8; 32];

/// Policy ID (32-byte hash)
pub type PolicyId = [u8; 32];

/// Proof ID (32-byte hash)
pub type ProofId = [u8; 32];

/// Subject reference (commitment to identity)
pub type SubjectRef = [u8; 32];

/// Issuer reference (commitment or issuer ID)
pub type IssuerRef = [u8; 32];

// =============================================================================
// Domain Separation Constants
// =============================================================================

/// Domain separator for address proof commitments
pub const ADDRESS_PROOF_DOMAIN_SEP: &[u8] = b"SRC892-ADDRESS-v1";

/// Domain separator for bank standing commitments
pub const BANK_STANDING_DOMAIN_SEP: &[u8] = b"SRC893-STANDING-v1";

/// Domain separator for KYC attestation commitments
pub const KYC_ATTESTATION_DOMAIN_SEP: &[u8] = b"SRC894-KYC-v1";

/// Domain separator for physical address commitments
pub const PHYSICAL_ADDRESS_DOMAIN_SEP: &[u8] = b"SRC892-PHYS-v1";

/// Domain separator for account commitment
pub const ACCOUNT_COMMITMENT_DOMAIN_SEP: &[u8] = b"SRC893-ACCOUNT-v1";

/// Domain separator for balance bracket commitments
pub const BALANCE_BRACKET_DOMAIN_SEP: &[u8] = b"SRC893-BALANCE-v1";

/// Domain separator for proof profiles
pub const FINANCE_PROOF_DOMAIN_SEP: &[u8] = b"SRC895-PROOF-v1";

// =============================================================================
// SRC-891: Financial Institution & Utility Issuer Profile
// =============================================================================

/// Issuer class for finance domain (layered over SRC-802)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinanceIssuerClass {
    // Phase 2 (Official/Lower Risk)
    /// Government revenue/tax authority
    GovernmentRevenue = 0,
    /// Central bank or treasury
    CentralBank = 1,
    /// Regulated commercial bank
    RegulatedBank = 2,
    /// Licensed credit union
    CreditUnion = 3,
    /// Regulated utility company
    RegulatedUtility = 4,
    /// Official address verification service
    AddressVerificationService = 5,

    // Phase 1 (Higher Risk)
    /// Fintech company
    Fintech = 10,
    /// Neobank / digital-only bank
    Neobank = 11,
    /// Money service business
    MoneyServiceBusiness = 12,
    /// Utility company (unregulated)
    Utility = 13,
    /// Telecom provider
    Telecom = 14,
    /// Payment processor
    PaymentProcessor = 15,
}

impl FinanceIssuerClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FinanceIssuerClass::GovernmentRevenue),
            1 => Some(FinanceIssuerClass::CentralBank),
            2 => Some(FinanceIssuerClass::RegulatedBank),
            3 => Some(FinanceIssuerClass::CreditUnion),
            4 => Some(FinanceIssuerClass::RegulatedUtility),
            5 => Some(FinanceIssuerClass::AddressVerificationService),
            10 => Some(FinanceIssuerClass::Fintech),
            11 => Some(FinanceIssuerClass::Neobank),
            12 => Some(FinanceIssuerClass::MoneyServiceBusiness),
            13 => Some(FinanceIssuerClass::Utility),
            14 => Some(FinanceIssuerClass::Telecom),
            15 => Some(FinanceIssuerClass::PaymentProcessor),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            FinanceIssuerClass::GovernmentRevenue => "Government Revenue Authority",
            FinanceIssuerClass::CentralBank => "Central Bank / Treasury",
            FinanceIssuerClass::RegulatedBank => "Regulated Commercial Bank",
            FinanceIssuerClass::CreditUnion => "Credit Union",
            FinanceIssuerClass::RegulatedUtility => "Regulated Utility",
            FinanceIssuerClass::AddressVerificationService => "Address Verification Service",
            FinanceIssuerClass::Fintech => "Fintech Company",
            FinanceIssuerClass::Neobank => "Neobank / Digital Bank",
            FinanceIssuerClass::MoneyServiceBusiness => "Money Service Business",
            FinanceIssuerClass::Utility => "Utility Company",
            FinanceIssuerClass::Telecom => "Telecom Provider",
            FinanceIssuerClass::PaymentProcessor => "Payment Processor",
        }
    }

    /// Check if this is a Phase 2 (official) issuer class
    pub fn is_official(&self) -> bool {
        matches!(
            self,
            FinanceIssuerClass::GovernmentRevenue
                | FinanceIssuerClass::CentralBank
                | FinanceIssuerClass::RegulatedBank
                | FinanceIssuerClass::CreditUnion
                | FinanceIssuerClass::RegulatedUtility
                | FinanceIssuerClass::AddressVerificationService
        )
    }

    /// Check if this is a Phase 1 (lowkey) issuer class
    pub fn is_lowkey(&self) -> bool {
        !self.is_official()
    }

    /// Get default risk level for this issuer class
    pub fn default_risk_level(&self) -> FinanceRiskLevel {
        match self {
            FinanceIssuerClass::GovernmentRevenue => FinanceRiskLevel::Low,
            FinanceIssuerClass::CentralBank => FinanceRiskLevel::Low,
            FinanceIssuerClass::RegulatedBank => FinanceRiskLevel::Low,
            FinanceIssuerClass::CreditUnion => FinanceRiskLevel::Low,
            FinanceIssuerClass::RegulatedUtility => FinanceRiskLevel::Low,
            FinanceIssuerClass::AddressVerificationService => FinanceRiskLevel::Medium,
            FinanceIssuerClass::Fintech => FinanceRiskLevel::Medium,
            FinanceIssuerClass::Neobank => FinanceRiskLevel::Medium,
            FinanceIssuerClass::MoneyServiceBusiness => FinanceRiskLevel::High,
            FinanceIssuerClass::Utility => FinanceRiskLevel::Medium,
            FinanceIssuerClass::Telecom => FinanceRiskLevel::Medium,
            FinanceIssuerClass::PaymentProcessor => FinanceRiskLevel::Medium,
        }
    }

    /// Check if this issuer can issue address proofs
    pub fn can_issue_address_proof(&self) -> bool {
        matches!(
            self,
            FinanceIssuerClass::GovernmentRevenue
                | FinanceIssuerClass::RegulatedBank
                | FinanceIssuerClass::CreditUnion
                | FinanceIssuerClass::RegulatedUtility
                | FinanceIssuerClass::AddressVerificationService
                | FinanceIssuerClass::Utility
                | FinanceIssuerClass::Telecom
        )
    }

    /// Check if this issuer can issue bank standing credentials
    pub fn can_issue_bank_standing(&self) -> bool {
        matches!(
            self,
            FinanceIssuerClass::CentralBank
                | FinanceIssuerClass::RegulatedBank
                | FinanceIssuerClass::CreditUnion
                | FinanceIssuerClass::Neobank
                | FinanceIssuerClass::Fintech
        )
    }

    /// Check if this issuer can issue KYC attestations
    pub fn can_issue_kyc(&self) -> bool {
        matches!(
            self,
            FinanceIssuerClass::GovernmentRevenue
                | FinanceIssuerClass::CentralBank
                | FinanceIssuerClass::RegulatedBank
                | FinanceIssuerClass::CreditUnion
                | FinanceIssuerClass::Fintech
                | FinanceIssuerClass::Neobank
                | FinanceIssuerClass::MoneyServiceBusiness
                | FinanceIssuerClass::PaymentProcessor
        )
    }
}

/// Risk level for finance credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinanceRiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl FinanceRiskLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FinanceRiskLevel::Low),
            1 => Some(FinanceRiskLevel::Medium),
            2 => Some(FinanceRiskLevel::High),
            3 => Some(FinanceRiskLevel::Critical),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            FinanceRiskLevel::Low => "Low",
            FinanceRiskLevel::Medium => "Medium",
            FinanceRiskLevel::High => "High",
            FinanceRiskLevel::Critical => "Critical",
        }
    }
}

/// Finance issuer profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinanceIssuerProfile {
    /// Issuer address on-chain
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: FinanceIssuerClass,
    /// Issuer commitment (company name, license number, etc. - all committed, not revealed)
    pub issuer_commitment: [u8; 32],
    /// Jurisdiction code (ISO 3166-1 alpha-2 + optional subdivision)
    pub jurisdiction_code: String,
    /// Policy ID governing this issuer
    pub policy_id: PolicyId,
    /// Status
    pub status: FinanceIssuerStatus,
    /// Registered at height
    pub registered_at_height: u64,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

/// Finance issuer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinanceIssuerStatus {
    Pending = 0,
    Active = 1,
    Suspended = 2,
    Revoked = 3,
}

impl FinanceIssuerStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FinanceIssuerStatus::Pending),
            1 => Some(FinanceIssuerStatus::Active),
            2 => Some(FinanceIssuerStatus::Suspended),
            3 => Some(FinanceIssuerStatus::Revoked),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, FinanceIssuerStatus::Active)
    }
}

// =============================================================================
// SRC-892: Proof-of-Address Credential
// =============================================================================

/// Address proof type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddressProofType {
    /// Utility bill (electricity, gas, water)
    UtilityBill = 0,
    /// Bank statement
    BankStatement = 1,
    /// Tax document
    TaxDocument = 2,
    /// Government correspondence
    GovernmentMail = 3,
    /// Telecom bill
    TelecomBill = 4,
    /// Insurance document
    InsuranceDocument = 5,
    /// Rental agreement
    RentalAgreement = 6,
    /// Property ownership record
    PropertyOwnership = 7,
    /// Voter registration
    VoterRegistration = 8,
}

impl AddressProofType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AddressProofType::UtilityBill),
            1 => Some(AddressProofType::BankStatement),
            2 => Some(AddressProofType::TaxDocument),
            3 => Some(AddressProofType::GovernmentMail),
            4 => Some(AddressProofType::TelecomBill),
            5 => Some(AddressProofType::InsuranceDocument),
            6 => Some(AddressProofType::RentalAgreement),
            7 => Some(AddressProofType::PropertyOwnership),
            8 => Some(AddressProofType::VoterRegistration),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AddressProofType::UtilityBill => "Utility Bill",
            AddressProofType::BankStatement => "Bank Statement",
            AddressProofType::TaxDocument => "Tax Document",
            AddressProofType::GovernmentMail => "Government Correspondence",
            AddressProofType::TelecomBill => "Telecom Bill",
            AddressProofType::InsuranceDocument => "Insurance Document",
            AddressProofType::RentalAgreement => "Rental Agreement",
            AddressProofType::PropertyOwnership => "Property Ownership Record",
            AddressProofType::VoterRegistration => "Voter Registration",
        }
    }
}

/// Proof-of-Address credential (SRC-892)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressProof {
    /// Unique address proof ID
    pub proof_id: AddressProofId,
    /// Holder wallet address (for token ownership)
    pub holder_address: Address,
    /// Subject reference (commitment to identity - NO PII)
    pub subject_ref: SubjectRef,
    /// Address commitment (full address committed, not revealed)
    /// commitment = blake3(ADDRESS_DOMAIN || country || region || city || postal || street || salt)
    pub address_commitment: [u8; 32],
    /// Jurisdiction code (country + optional subdivision, revealed for compliance)
    pub jurisdiction_code: String,
    /// Postal code commitment (for regional matching)
    /// commitment = blake3(POSTAL_DOMAIN || postal_code || salt)
    pub postal_commitment: [u8; 32],
    /// Proof type
    pub proof_type: AddressProofType,
    /// Document date (when the proof document was issued)
    pub document_date: Timestamp,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: FinanceIssuerClass,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expiry: Timestamp,
    /// Policy ID governing this credential
    pub policy_id: PolicyId,
    /// Revocation reference (for SRC-805 compatibility)
    pub revocation_ref: Option<[u8; 32]>,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

impl AddressProof {
    /// Generate address proof ID
    pub fn generate_id(
        subject_ref: &SubjectRef,
        address_commitment: &[u8; 32],
        proof_type: AddressProofType,
        nonce: u64,
    ) -> AddressProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ADDRESS_PROOF_DOMAIN_SEP);
        hasher.update(subject_ref);
        hasher.update(address_commitment);
        hasher.update(&[proof_type as u8]);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate address commitment
    pub fn generate_address_commitment(
        country: &str,
        region: &str,
        city: &str,
        postal_code: &str,
        street_address: &str,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PHYSICAL_ADDRESS_DOMAIN_SEP);
        hasher.update(country.as_bytes());
        hasher.update(b":");
        hasher.update(region.as_bytes());
        hasher.update(b":");
        hasher.update(city.as_bytes());
        hasher.update(b":");
        hasher.update(postal_code.as_bytes());
        hasher.update(b":");
        hasher.update(street_address.as_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate postal commitment (for regional matching)
    pub fn generate_postal_commitment(postal_code: &str, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SRC892-POSTAL-v1");
        hasher.update(postal_code.as_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Check if proof is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from
            && current_time < self.expiry
            && self.revocation_ref.is_none()
    }
}

// =============================================================================
// SRC-893: Bank Account Standing Credential
// =============================================================================

/// Account standing type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccountStanding {
    /// Account in good standing
    Good = 0,
    /// Account with minor issues
    Fair = 1,
    /// Account with significant issues
    Poor = 2,
    /// Account restricted
    Restricted = 3,
    /// Account closed
    Closed = 4,
}

impl AccountStanding {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AccountStanding::Good),
            1 => Some(AccountStanding::Fair),
            2 => Some(AccountStanding::Poor),
            3 => Some(AccountStanding::Restricted),
            4 => Some(AccountStanding::Closed),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AccountStanding::Good => "Good Standing",
            AccountStanding::Fair => "Fair Standing",
            AccountStanding::Poor => "Poor Standing",
            AccountStanding::Restricted => "Restricted",
            AccountStanding::Closed => "Closed",
        }
    }

    pub fn is_good(&self) -> bool {
        matches!(self, AccountStanding::Good | AccountStanding::Fair)
    }
}

/// Account type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccountType {
    Checking = 0,
    Savings = 1,
    MoneyMarket = 2,
    CertificateOfDeposit = 3,
    Brokerage = 4,
    Retirement = 5,
    Business = 6,
    Joint = 7,
}

impl AccountType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AccountType::Checking),
            1 => Some(AccountType::Savings),
            2 => Some(AccountType::MoneyMarket),
            3 => Some(AccountType::CertificateOfDeposit),
            4 => Some(AccountType::Brokerage),
            5 => Some(AccountType::Retirement),
            6 => Some(AccountType::Business),
            7 => Some(AccountType::Joint),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AccountType::Checking => "Checking",
            AccountType::Savings => "Savings",
            AccountType::MoneyMarket => "Money Market",
            AccountType::CertificateOfDeposit => "Certificate of Deposit",
            AccountType::Brokerage => "Brokerage",
            AccountType::Retirement => "Retirement",
            AccountType::Business => "Business",
            AccountType::Joint => "Joint Account",
        }
    }
}

/// Balance bracket for range-first verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BalanceBracket {
    /// Below $1,000
    Bracket0 = 0,
    /// $1,000 - $5,000
    Bracket1 = 1,
    /// $5,000 - $10,000
    Bracket2 = 2,
    /// $10,000 - $25,000
    Bracket3 = 3,
    /// $25,000 - $50,000
    Bracket4 = 4,
    /// $50,000 - $100,000
    Bracket5 = 5,
    /// $100,000 - $250,000
    Bracket6 = 6,
    /// $250,000 - $500,000
    Bracket7 = 7,
    /// $500,000 - $1,000,000
    Bracket8 = 8,
    /// Above $1,000,000
    Bracket9 = 9,
    /// Custom threshold (use threshold_commitment)
    Custom = 255,
}

impl BalanceBracket {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(BalanceBracket::Bracket0),
            1 => Some(BalanceBracket::Bracket1),
            2 => Some(BalanceBracket::Bracket2),
            3 => Some(BalanceBracket::Bracket3),
            4 => Some(BalanceBracket::Bracket4),
            5 => Some(BalanceBracket::Bracket5),
            6 => Some(BalanceBracket::Bracket6),
            7 => Some(BalanceBracket::Bracket7),
            8 => Some(BalanceBracket::Bracket8),
            9 => Some(BalanceBracket::Bracket9),
            255 => Some(BalanceBracket::Custom),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            BalanceBracket::Bracket0 => "Below $1,000",
            BalanceBracket::Bracket1 => "$1,000 - $5,000",
            BalanceBracket::Bracket2 => "$5,000 - $10,000",
            BalanceBracket::Bracket3 => "$10,000 - $25,000",
            BalanceBracket::Bracket4 => "$25,000 - $50,000",
            BalanceBracket::Bracket5 => "$50,000 - $100,000",
            BalanceBracket::Bracket6 => "$100,000 - $250,000",
            BalanceBracket::Bracket7 => "$250,000 - $500,000",
            BalanceBracket::Bracket8 => "$500,000 - $1,000,000",
            BalanceBracket::Bracket9 => "Above $1,000,000",
            BalanceBracket::Custom => "Custom threshold",
        }
    }

    /// Check if balance is at least this bracket
    pub fn is_at_least(&self, other: &BalanceBracket) -> bool {
        (*self as u8) >= (*other as u8) && *self != BalanceBracket::Custom
    }
}

/// Bank account standing credential (SRC-893)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BankStandingCredential {
    /// Unique credential ID
    pub credential_id: BankStandingId,
    /// Holder wallet address (for token ownership)
    pub holder_address: Address,
    /// Subject reference (commitment to account holder identity - NO PII)
    pub subject_ref: SubjectRef,
    /// Account commitment (account number committed, not revealed)
    /// commitment = blake3(ACCOUNT_DOMAIN || routing || account || account_type || salt)
    pub account_commitment: [u8; 32],
    /// Bank issuer reference (commitment to bank identity)
    pub bank_ref: IssuerRef,
    /// Account type
    pub account_type: AccountType,
    /// Account standing
    pub standing: AccountStanding,
    /// Account tenure commitment (how long account has been open)
    /// commitment = blake3(TENURE_DOMAIN || open_date || salt)
    pub tenure_commitment: [u8; 32],
    /// Balance bracket (range-first, not exact)
    pub balance_bracket: BalanceBracket,
    /// Optional threshold commitment for custom brackets
    pub threshold_commitment: Option<[u8; 32]>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: FinanceIssuerClass,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expiry: Timestamp,
    /// Policy ID governing this credential
    pub policy_id: PolicyId,
    /// Revocation reference (for SRC-805 compatibility)
    pub revocation_ref: Option<[u8; 32]>,
    /// Created at timestamp
    pub created_at: Timestamp,
    /// Updated at timestamp
    pub updated_at: Timestamp,
}

impl BankStandingCredential {
    /// Generate credential ID
    pub fn generate_id(
        subject_ref: &SubjectRef,
        account_commitment: &[u8; 32],
        bank_ref: &IssuerRef,
        nonce: u64,
    ) -> BankStandingId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BANK_STANDING_DOMAIN_SEP);
        hasher.update(subject_ref);
        hasher.update(account_commitment);
        hasher.update(bank_ref);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate account commitment
    pub fn generate_account_commitment(
        routing_number: &str,
        account_number: &str,
        account_type: AccountType,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ACCOUNT_COMMITMENT_DOMAIN_SEP);
        hasher.update(routing_number.as_bytes());
        hasher.update(b":");
        hasher.update(account_number.as_bytes());
        hasher.update(&[account_type as u8]);
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate tenure commitment
    pub fn generate_tenure_commitment(open_date: Timestamp, salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SRC893-TENURE-v1");
        hasher.update(&open_date.to_le_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate threshold commitment for custom balance brackets
    pub fn generate_threshold_commitment(
        threshold_min: u64,
        threshold_max: u64,
        currency: &str,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BALANCE_BRACKET_DOMAIN_SEP);
        hasher.update(&threshold_min.to_le_bytes());
        hasher.update(&threshold_max.to_le_bytes());
        hasher.update(currency.as_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Check if credential is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from
            && current_time < self.expiry
            && self.revocation_ref.is_none()
            && self.standing.is_good()
    }
}

// =============================================================================
// SRC-894: KYC / AML Attestation
// =============================================================================

/// KYC level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KycLevel {
    /// No KYC performed
    None = 0,
    /// Basic KYC (name, email, phone)
    Basic = 1,
    /// Enhanced KYC (ID verification)
    Enhanced = 2,
    /// Full KYC (ID + proof of address + source of funds)
    Full = 3,
    /// Institutional KYC (for businesses)
    Institutional = 4,
}

impl KycLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(KycLevel::None),
            1 => Some(KycLevel::Basic),
            2 => Some(KycLevel::Enhanced),
            3 => Some(KycLevel::Full),
            4 => Some(KycLevel::Institutional),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            KycLevel::None => "No KYC",
            KycLevel::Basic => "Basic KYC",
            KycLevel::Enhanced => "Enhanced KYC",
            KycLevel::Full => "Full KYC",
            KycLevel::Institutional => "Institutional KYC",
        }
    }

    /// Check if level meets minimum requirement
    pub fn meets_requirement(&self, required: &KycLevel) -> bool {
        (*self as u8) >= (*required as u8)
    }
}

/// AML risk classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AmlRisk {
    Low = 0,
    Medium = 1,
    High = 2,
    Prohibited = 3,
}

impl AmlRisk {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AmlRisk::Low),
            1 => Some(AmlRisk::Medium),
            2 => Some(AmlRisk::High),
            3 => Some(AmlRisk::Prohibited),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AmlRisk::Low => "Low Risk",
            AmlRisk::Medium => "Medium Risk",
            AmlRisk::High => "High Risk",
            AmlRisk::Prohibited => "Prohibited",
        }
    }

    pub fn is_acceptable(&self) -> bool {
        !matches!(self, AmlRisk::Prohibited)
    }
}

/// KYC attestation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KycStatus {
    Pending = 0,
    Active = 1,
    Expired = 2,
    Revoked = 3,
    UnderReview = 4,
}

impl KycStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(KycStatus::Pending),
            1 => Some(KycStatus::Active),
            2 => Some(KycStatus::Expired),
            3 => Some(KycStatus::Revoked),
            4 => Some(KycStatus::UnderReview),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, KycStatus::Active)
    }
}

/// KYC / AML Attestation (SRC-894)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KycAttestation {
    /// Unique attestation ID
    pub attestation_id: KycAttestationId,
    /// Holder wallet address (for token ownership)
    pub holder_address: Address,
    /// Subject reference (commitment to identity - NO PII)
    pub subject_ref: SubjectRef,
    /// KYC level achieved
    pub kyc_level: KycLevel,
    /// AML risk classification
    pub aml_risk: AmlRisk,
    /// Identity verification commitment
    /// commitment = blake3(ID_DOMAIN || id_type || id_hash || verification_date || salt)
    pub identity_commitment: [u8; 32],
    /// Jurisdiction of subject (for compliance)
    pub subject_jurisdiction: String,
    /// Verification methods used (committed)
    /// commitment = blake3(METHODS_DOMAIN || methods_list || salt)
    pub methods_commitment: [u8; 32],
    /// Status
    pub status: KycStatus,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: FinanceIssuerClass,
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

impl KycAttestation {
    /// Generate attestation ID
    pub fn generate_id(
        subject_ref: &SubjectRef,
        identity_commitment: &[u8; 32],
        kyc_level: KycLevel,
        nonce: u64,
    ) -> KycAttestationId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KYC_ATTESTATION_DOMAIN_SEP);
        hasher.update(subject_ref);
        hasher.update(identity_commitment);
        hasher.update(&[kyc_level as u8]);
        hasher.update(&nonce.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Generate identity commitment
    pub fn generate_identity_commitment(
        id_type: &str,
        id_hash: &[u8; 32],
        verification_date: Timestamp,
        salt: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SRC894-ID-v1");
        hasher.update(id_type.as_bytes());
        hasher.update(id_hash);
        hasher.update(&verification_date.to_le_bytes());
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Generate methods commitment
    pub fn generate_methods_commitment(methods: &[&str], salt: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SRC894-METHODS-v1");
        for method in methods {
            hasher.update(method.as_bytes());
            hasher.update(b",");
        }
        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Check if attestation is valid at a given time
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        current_time >= self.valid_from
            && current_time < self.expiry
            && self.revocation_ref.is_none()
            && self.status.is_active()
            && self.aml_risk.is_acceptable()
    }
}

// =============================================================================
// SRC-895: 89X Proof Profiles
// =============================================================================

/// Proof profile types for finance domain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinanceProofType {
    /// Prove address in a jurisdiction
    AddressInJurisdiction = 0,
    /// Prove bank account in good standing
    AccountInGoodStanding = 1,
    /// Prove balance at least in a bracket
    BalanceAtLeast = 2,
    /// Prove KYC level achieved
    KycLevelAchieved = 3,
    /// Prove AML risk acceptable
    AmlRiskAcceptable = 4,
    /// Combined proof (multiple conditions)
    Combined = 255,
}

impl FinanceProofType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FinanceProofType::AddressInJurisdiction),
            1 => Some(FinanceProofType::AccountInGoodStanding),
            2 => Some(FinanceProofType::BalanceAtLeast),
            3 => Some(FinanceProofType::KycLevelAchieved),
            4 => Some(FinanceProofType::AmlRiskAcceptable),
            255 => Some(FinanceProofType::Combined),
            _ => None,
        }
    }
}

/// Finance proof profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinanceProofProfile {
    /// Profile ID
    pub profile_id: [u8; 32],
    /// Profile type
    pub proof_type: FinanceProofType,
    /// Required jurisdiction (for address proofs)
    pub required_jurisdiction: Option<String>,
    /// Minimum balance bracket
    pub min_balance_bracket: Option<BalanceBracket>,
    /// Minimum KYC level
    pub min_kyc_level: Option<KycLevel>,
    /// Maximum acceptable AML risk
    pub max_aml_risk: Option<AmlRisk>,
    /// Required issuer classes
    pub required_issuer_classes: Vec<FinanceIssuerClass>,
    /// Maximum age of credential in seconds
    pub max_credential_age_secs: u64,
    /// Policy ID
    pub policy_id: PolicyId,
}

impl FinanceProofProfile {
    /// Generate profile ID
    pub fn generate_id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FINANCE_PROOF_DOMAIN_SEP);
        hasher.update(&[self.proof_type.clone() as u8]);
        if let Some(ref jurisdiction) = self.required_jurisdiction {
            hasher.update(jurisdiction.as_bytes());
        }
        if let Some(ref bracket) = self.min_balance_bracket {
            hasher.update(&[*bracket as u8]);
        }
        if let Some(ref level) = self.min_kyc_level {
            hasher.update(&[*level as u8]);
        }
        hasher.update(&self.policy_id);
        *hasher.finalize().as_bytes()
    }
}

/// Finance proof envelope (SRC-806 compatible)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinanceProofEnvelope {
    /// Unique proof ID
    pub proof_id: ProofId,
    /// Proof profile ID
    pub profile_id: [u8; 32],
    /// Proof type
    pub proof_type: FinanceProofType,
    /// Subject nullifier (prevents linkability)
    pub subject_nullifier: [u8; 32],
    /// Proof data (ZK proof bytes or threshold signature)
    pub proof_data: Vec<u8>,
    /// Public inputs commitment
    pub public_inputs_commitment: [u8; 32],
    /// Credential references (commitments to source credentials)
    pub credential_refs: Vec<[u8; 32]>,
    /// Issuer class of source credential
    pub source_issuer_class: FinanceIssuerClass,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Valid from timestamp
    pub valid_from: Timestamp,
    /// Expiry timestamp
    pub expiry: Timestamp,
    /// Created at timestamp
    pub created_at: Timestamp,
}

impl FinanceProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile_id: &[u8; 32],
        subject_nullifier: &[u8; 32],
        proof_data: &[u8],
        nonce: u64,
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FINANCE_PROOF_DOMAIN_SEP);
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

/// Finance domain events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinanceEvent {
    /// Issuer registered
    IssuerRegistered {
        issuer_address: Address,
        issuer_class: FinanceIssuerClass,
        timestamp: Timestamp,
    },
    /// Issuer status updated
    IssuerStatusUpdated {
        issuer_address: Address,
        old_status: FinanceIssuerStatus,
        new_status: FinanceIssuerStatus,
        timestamp: Timestamp,
    },
    /// Address proof created
    AddressProofCreated {
        proof_id: AddressProofId,
        subject_ref: SubjectRef,
        proof_type: AddressProofType,
        timestamp: Timestamp,
    },
    /// Address proof revoked
    AddressProofRevoked {
        proof_id: AddressProofId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    },
    /// Bank standing credential created
    BankStandingCreated {
        credential_id: BankStandingId,
        subject_ref: SubjectRef,
        standing: AccountStanding,
        timestamp: Timestamp,
    },
    /// Bank standing credential updated
    BankStandingUpdated {
        credential_id: BankStandingId,
        old_standing: AccountStanding,
        new_standing: AccountStanding,
        timestamp: Timestamp,
    },
    /// Bank standing credential revoked
    BankStandingRevoked {
        credential_id: BankStandingId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    },
    /// KYC attestation created
    KycAttestationCreated {
        attestation_id: KycAttestationId,
        subject_ref: SubjectRef,
        kyc_level: KycLevel,
        timestamp: Timestamp,
    },
    /// KYC attestation updated
    KycAttestationUpdated {
        attestation_id: KycAttestationId,
        old_status: KycStatus,
        new_status: KycStatus,
        timestamp: Timestamp,
    },
    /// KYC attestation revoked
    KycAttestationRevoked {
        attestation_id: KycAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    },
    /// Proof submitted
    ProofSubmitted {
        proof_id: ProofId,
        proof_type: FinanceProofType,
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

/// Finance domain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FinanceOperation {
    // Issuer operations (SRC-891)
    RegisterIssuer = 0,
    UpdateIssuer = 1,
    SuspendIssuer = 2,
    RevokeIssuer = 3,
    ReactivateIssuer = 4,

    // Address proof operations (SRC-892)
    CreateAddressProof = 10,
    UpdateAddressProof = 11,
    RevokeAddressProof = 12,

    // Bank standing operations (SRC-893)
    CreateBankStanding = 20,
    UpdateBankStanding = 21,
    RevokeBankStanding = 22,

    // KYC attestation operations (SRC-894)
    CreateKycAttestation = 30,
    UpdateKycAttestation = 31,
    RevokeKycAttestation = 32,

    // Proof operations (SRC-895)
    SubmitProof = 40,
    VerifyProof = 41,
}

impl FinanceOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FinanceOperation::RegisterIssuer),
            1 => Some(FinanceOperation::UpdateIssuer),
            2 => Some(FinanceOperation::SuspendIssuer),
            3 => Some(FinanceOperation::RevokeIssuer),
            4 => Some(FinanceOperation::ReactivateIssuer),
            10 => Some(FinanceOperation::CreateAddressProof),
            11 => Some(FinanceOperation::UpdateAddressProof),
            12 => Some(FinanceOperation::RevokeAddressProof),
            20 => Some(FinanceOperation::CreateBankStanding),
            21 => Some(FinanceOperation::UpdateBankStanding),
            22 => Some(FinanceOperation::RevokeBankStanding),
            30 => Some(FinanceOperation::CreateKycAttestation),
            31 => Some(FinanceOperation::UpdateKycAttestation),
            32 => Some(FinanceOperation::RevokeKycAttestation),
            40 => Some(FinanceOperation::SubmitProof),
            41 => Some(FinanceOperation::VerifyProof),
            _ => None,
        }
    }
}

/// Finance transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinanceTxData {
    pub operation: FinanceOperation,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_class_risk_levels() {
        assert_eq!(
            FinanceIssuerClass::RegulatedBank.default_risk_level(),
            FinanceRiskLevel::Low
        );
        assert_eq!(
            FinanceIssuerClass::MoneyServiceBusiness.default_risk_level(),
            FinanceRiskLevel::High
        );
    }

    #[test]
    fn test_issuer_class_phases() {
        assert!(FinanceIssuerClass::RegulatedBank.is_official());
        assert!(!FinanceIssuerClass::RegulatedBank.is_lowkey());
        assert!(FinanceIssuerClass::Fintech.is_lowkey());
        assert!(!FinanceIssuerClass::Fintech.is_official());
    }

    #[test]
    fn test_issuer_capabilities() {
        assert!(FinanceIssuerClass::RegulatedUtility.can_issue_address_proof());
        assert!(!FinanceIssuerClass::RegulatedUtility.can_issue_bank_standing());
        assert!(FinanceIssuerClass::RegulatedBank.can_issue_bank_standing());
        assert!(FinanceIssuerClass::RegulatedBank.can_issue_kyc());
    }

    #[test]
    fn test_address_proof_id_generation() {
        let subject_ref = [1u8; 32];
        let address_commitment = [2u8; 32];
        let id = AddressProof::generate_id(
            &subject_ref,
            &address_commitment,
            AddressProofType::UtilityBill,
            1,
        );
        assert_ne!(id, [0u8; 32]);

        // Same inputs, different nonce = different ID
        let id2 = AddressProof::generate_id(
            &subject_ref,
            &address_commitment,
            AddressProofType::UtilityBill,
            2,
        );
        assert_ne!(id, id2);
    }

    #[test]
    fn test_address_commitment_generation() {
        let salt = [3u8; 32];
        let commitment = AddressProof::generate_address_commitment(
            "US",
            "CA",
            "San Francisco",
            "94102",
            "123 Main St",
            &salt,
        );
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_balance_bracket_ordering() {
        assert!(BalanceBracket::Bracket5.is_at_least(&BalanceBracket::Bracket3));
        assert!(!BalanceBracket::Bracket2.is_at_least(&BalanceBracket::Bracket5));
        assert!(!BalanceBracket::Custom.is_at_least(&BalanceBracket::Bracket1));
    }

    #[test]
    fn test_bank_standing_id_generation() {
        let subject_ref = [4u8; 32];
        let account_commitment = [5u8; 32];
        let bank_ref = [6u8; 32];
        let id = BankStandingCredential::generate_id(
            &subject_ref,
            &account_commitment,
            &bank_ref,
            1,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_kyc_level_requirements() {
        assert!(KycLevel::Full.meets_requirement(&KycLevel::Basic));
        assert!(KycLevel::Enhanced.meets_requirement(&KycLevel::Enhanced));
        assert!(!KycLevel::Basic.meets_requirement(&KycLevel::Full));
    }

    #[test]
    fn test_kyc_attestation_id_generation() {
        let subject_ref = [7u8; 32];
        let identity_commitment = [8u8; 32];
        let id = KycAttestation::generate_id(
            &subject_ref,
            &identity_commitment,
            KycLevel::Enhanced,
            1,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_account_standing_checks() {
        assert!(AccountStanding::Good.is_good());
        assert!(AccountStanding::Fair.is_good());
        assert!(!AccountStanding::Poor.is_good());
        assert!(!AccountStanding::Closed.is_good());
    }

    #[test]
    fn test_aml_risk_acceptability() {
        assert!(AmlRisk::Low.is_acceptable());
        assert!(AmlRisk::Medium.is_acceptable());
        assert!(AmlRisk::High.is_acceptable());
        assert!(!AmlRisk::Prohibited.is_acceptable());
    }
}
