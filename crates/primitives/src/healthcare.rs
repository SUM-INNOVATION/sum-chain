//! SRC-87X Healthcare & Regulated Membership Domain
//!
//! Privacy-first infrastructure for:
//! - SRC-871: Provider/Plan Registry Profile
//! - SRC-872: Coverage & Membership Status
//! - SRC-874: Consent & Disclosure Envelope
//! - SRC-875: 87X Proof Profiles
//! - SRC-876: Prescription Standard (NON-TRANSFERABLE)

use serde::{Deserialize, Serialize};
use crate::{Address, BlockHeight, Timestamp};
use crate::agreement::{AttachmentRef, PartyRef};

// =============================================================================
// Type Aliases
// =============================================================================

/// Provider/plan registry identifier
pub type ProviderId = [u8; 32];
/// Membership/coverage identifier
pub type MembershipId = [u8; 32];
/// Consent envelope identifier
pub type ConsentId = [u8; 32];
/// Prescription identifier
pub type PrescriptionId = [u8; 32];
/// Policy identifier (SRC-803 compatible)
pub type PolicyId = [u8; 32];
/// Proof identifier (SRC-806 compatible)
pub type ProofId = [u8; 32];
/// Subject identifier (SRC-801 compatible)
pub type SubjectId = [u8; 32];

// =============================================================================
// Domain Separators (for deterministic hashing)
// =============================================================================

pub const PROVIDER_DOMAIN_SEP: &[u8] = b"SRC871-PROVIDER:";
pub const PROVIDER_COMMITMENT_SEP: &[u8] = b"SRC871-COMMITMENT:v1:";
pub const MEMBERSHIP_DOMAIN_SEP: &[u8] = b"SRC872-MEMBERSHIP:";
pub const MEMBERSHIP_COMMITMENT_SEP: &[u8] = b"SRC872-COMMITMENT:v1:";
pub const CONSENT_DOMAIN_SEP: &[u8] = b"SRC874-CONSENT:";
pub const CONSENT_COMMITMENT_SEP: &[u8] = b"SRC874-COMMITMENT:v1:";
pub const PRESCRIPTION_DOMAIN_SEP: &[u8] = b"SRC876-PRESCRIPTION:";
pub const PRESCRIPTION_COMMITMENT_SEP: &[u8] = b"SRC876-COMMITMENT:v1:";
pub const HEALTHCARE_PROOF_DOMAIN_SEP: &[u8] = b"SRC875-PROOF:";

// =============================================================================
// SRC-871: Provider/Plan Registry Profile
// =============================================================================

/// Provider type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProviderType {
    // Healthcare Providers (0-29)
    /// Hospital/health system
    Hospital = 0,
    /// Physician/doctor
    Physician = 1,
    /// Specialist
    Specialist = 2,
    /// Clinic
    Clinic = 3,
    /// Nursing facility
    NursingFacility = 4,
    /// Home health agency
    HomeHealthAgency = 5,
    /// Pharmacy
    Pharmacy = 6,
    /// Laboratory
    Laboratory = 7,
    /// Imaging center
    ImagingCenter = 8,
    /// Mental health provider
    MentalHealthProvider = 9,
    /// Dentist
    Dentist = 10,
    /// Optometrist
    Optometrist = 11,
    /// Physical therapist
    PhysicalTherapist = 12,
    /// Chiropractor
    Chiropractor = 13,
    /// Ambulance/EMS
    AmbulanceEms = 14,
    /// Hospice
    Hospice = 15,
    /// Urgent care
    UrgentCare = 16,
    /// Telemedicine
    Telemedicine = 17,

    // Insurance/Plan Providers (30-49)
    /// Health insurance company
    HealthInsurer = 30,
    /// Pharmacy benefit manager
    Pbm = 31,
    /// Third party administrator
    Tpa = 32,
    /// Medicare
    Medicare = 33,
    /// Medicaid
    Medicaid = 34,
    /// Health plan
    HealthPlan = 35,
    /// HMO
    Hmo = 36,
    /// PPO
    Ppo = 37,

    // Membership Organizations (50-69)
    /// Professional association
    ProfessionalAssociation = 50,
    /// Trade union
    TradeUnion = 51,
    /// Gym/fitness center
    GymFitness = 52,
    /// Membership club
    MembershipClub = 53,
    /// Alumni association
    AlumniAssociation = 54,
    /// Religious organization
    ReligiousOrganization = 55,
    /// Cooperative
    Cooperative = 56,

    /// Other provider type
    Other = 255,
}

/// Provider status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProviderStatus {
    /// Active and in good standing
    Active = 0,
    /// Pending approval
    Pending = 1,
    /// Suspended
    Suspended = 2,
    /// Revoked
    Revoked = 3,
    /// Expired
    Expired = 4,
    /// Under review
    UnderReview = 5,
    /// Inactive
    Inactive = 6,
}

/// Healthcare issuer class (SRC-802 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthcareIssuerClass {
    // Official/Phase 2 Issuers (0-9)
    /// Government health agency (CMS, FDA, etc.)
    GovernmentHealthAgency = 0,
    /// State medical board
    StateMedicalBoard = 1,
    /// DEA (for prescriptions)
    Dea = 2,
    /// State pharmacy board
    StatePharmacyBoard = 3,
    /// Accreditation body (JCAHO, etc.)
    AccreditationBody = 4,

    // Phase 1/Lowkey Issuers (10-29)
    /// Hospital/health system
    HospitalSystem = 10,
    /// Insurance company
    InsuranceCompany = 11,
    /// Medical practice
    MedicalPractice = 12,
    /// Pharmacy chain
    PharmacyChain = 13,
    /// Laboratory network
    LaboratoryNetwork = 14,
    /// Health information exchange
    Hie = 15,
    /// Clearinghouse
    Clearinghouse = 16,
    /// Credentialing organization
    CredentialingOrg = 17,

    /// Other authorized issuer
    Other = 255,
}

impl HealthcareIssuerClass {
    /// Check if this is an official (Phase 2) issuer
    pub fn is_official(&self) -> bool {
        matches!(
            self,
            Self::GovernmentHealthAgency
                | Self::StateMedicalBoard
                | Self::Dea
                | Self::StatePharmacyBoard
                | Self::AccreditationBody
        )
    }

    /// Check if this is a Phase 1 (lowkey) issuer
    pub fn is_lowkey(&self) -> bool {
        matches!(
            self,
            Self::HospitalSystem
                | Self::InsuranceCompany
                | Self::MedicalPractice
                | Self::PharmacyChain
                | Self::LaboratoryNetwork
                | Self::Hie
        )
    }
}

/// Network status for provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NetworkStatus {
    /// In-network
    InNetwork = 0,
    /// Out-of-network
    OutOfNetwork = 1,
    /// Preferred
    Preferred = 2,
    /// Tier 1
    Tier1 = 3,
    /// Tier 2
    Tier2 = 4,
    /// Participating
    Participating = 5,
    /// Non-participating
    NonParticipating = 6,
}

/// SRC-871 Provider/Plan Registry Profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderProfile {
    /// Unique provider identifier
    pub provider_id: ProviderId,
    /// BLAKE3 commitment of provider details (NPI, name, etc.)
    pub provider_commitment: [u8; 32],
    /// Provider type classification
    pub provider_type: ProviderType,
    /// Jurisdiction code (e.g., "US-CA")
    pub jurisdiction_code: String,
    /// Optional public reference (last 4 of NPI, etc.)
    pub public_reference: Option<String>,
    /// Specialties commitment (list of specialty codes)
    pub specialties_commitment: Option<[u8; 32]>,
    /// Credentials commitment (licenses, certifications)
    pub credentials_commitment: Option<[u8; 32]>,
    /// Policy ID governing this provider
    pub policy_id: PolicyId,
    /// Issuer class that registered this
    pub issuer_class: HealthcareIssuerClass,
    /// Issuer address
    pub issuer_address: Address,
    /// Current status
    pub status: ProviderStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when registered
    pub registered_at_height: BlockHeight,
    /// Network affiliations (plan IDs this provider is in-network with)
    pub network_affiliations: Vec<ProviderId>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl ProviderProfile {
    /// Generate deterministic provider ID
    pub fn generate_id(
        issuer: &Address,
        provider_commitment: &[u8; 32],
        provider_type: ProviderType,
        jurisdiction: &str,
        nonce: &[u8; 32],
    ) -> ProviderId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVIDER_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(issuer.as_ref());
        hasher.update(provider_commitment);
        hasher.update(&[provider_type as u8]);
        hasher.update(jurisdiction.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate provider commitment from details
    pub fn generate_commitment(
        npi_commitment: Option<&[u8; 32]>,
        name_commitment: &[u8; 32],
        address_commitment: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROVIDER_COMMITMENT_SEP);
        if let Some(npi) = npi_commitment {
            hasher.update(npi);
        }
        hasher.update(name_commitment);
        if let Some(addr) = address_commitment {
            hasher.update(addr);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-872: Coverage & Membership Status
// =============================================================================

/// Membership/coverage type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MembershipType {
    // Health Coverage (0-19)
    /// Individual health plan
    IndividualHealth = 0,
    /// Family health plan
    FamilyHealth = 1,
    /// Employer-sponsored health
    EmployerHealth = 2,
    /// Medicare Part A
    MedicarePartA = 3,
    /// Medicare Part B
    MedicarePartB = 4,
    /// Medicare Part C (Advantage)
    MedicareAdvantage = 5,
    /// Medicare Part D (Prescription)
    MedicarePartD = 6,
    /// Medicaid
    MedicaidCoverage = 7,
    /// CHIP
    Chip = 8,
    /// Dental coverage
    Dental = 9,
    /// Vision coverage
    Vision = 10,
    /// Pharmacy coverage
    Pharmacy = 11,
    /// Mental health coverage
    MentalHealth = 12,
    /// HSA/FSA
    HsaFsa = 13,

    // Professional Memberships (20-39)
    /// Professional license
    ProfessionalLicense = 20,
    /// Board certification
    BoardCertification = 21,
    /// Association membership
    AssociationMembership = 22,
    /// Union membership
    UnionMembership = 23,
    /// Accreditation
    Accreditation = 24,

    // General Memberships (40-59)
    /// Gym membership
    GymMembership = 40,
    /// Club membership
    ClubMembership = 41,
    /// Subscription
    Subscription = 42,
    /// Loyalty program
    LoyaltyProgram = 43,
    /// Alumni status
    AlumniStatus = 44,

    /// Other membership
    Other = 255,
}

/// Membership status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MembershipStatus {
    /// Active
    Active = 0,
    /// Pending
    Pending = 1,
    /// Suspended
    Suspended = 2,
    /// Cancelled
    Cancelled = 3,
    /// Expired
    Expired = 4,
    /// Lapsed
    Lapsed = 5,
    /// Terminated
    Terminated = 6,
    /// Grace period
    GracePeriod = 7,
    /// Cobra
    Cobra = 8,
}

/// Coverage tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoverageTier {
    /// Employee only
    EmployeeOnly = 0,
    /// Employee + spouse
    EmployeeSpouse = 1,
    /// Employee + children
    EmployeeChildren = 2,
    /// Family
    Family = 3,
    /// Individual
    Individual = 4,
    /// Self only
    SelfOnly = 5,
    /// Self + one
    SelfPlusOne = 6,
}

/// SRC-872 Membership/Coverage Record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRecord {
    /// Unique membership identifier
    pub membership_id: MembershipId,
    /// Member wallet address (for token ownership)
    pub member_address: Address,
    /// Provider/plan issuing this membership
    pub provider_id: ProviderId,
    /// Membership type
    pub membership_type: MembershipType,
    /// BLAKE3 commitment of membership details
    pub membership_commitment: [u8; 32],
    /// Member reference (privacy-preserving)
    pub member_ref: PartyRef,
    /// Member nullifier for anonymous verification
    pub member_nullifier: [u8; 32],
    /// Coverage tier (if applicable)
    pub coverage_tier: Option<CoverageTier>,
    /// Group number commitment (if applicable)
    pub group_commitment: Option<[u8; 32]>,
    /// Effective date
    pub effective_from: Timestamp,
    /// Expiry/termination date
    pub expiry: Option<Timestamp>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: HealthcareIssuerClass,
    /// Policy ID (SRC-803)
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: MembershipStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when issued
    pub issued_at_height: BlockHeight,
    /// Prior membership ID (for renewals)
    pub prior_membership_id: Option<MembershipId>,
    /// Dependents (commitment hashes)
    pub dependents: Vec<[u8; 32]>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl MembershipRecord {
    /// Generate membership ID
    pub fn generate_id(
        provider_id: &ProviderId,
        membership_type: MembershipType,
        member_nullifier: &[u8; 32],
        nonce: &[u8; 32],
    ) -> MembershipId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MEMBERSHIP_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(provider_id);
        hasher.update(&[membership_type as u8]);
        hasher.update(member_nullifier);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate membership commitment
    pub fn generate_commitment(
        member_id_commitment: &[u8; 32],
        benefits_commitment: Option<&[u8; 32]>,
        copay_commitment: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MEMBERSHIP_COMMITMENT_SEP);
        hasher.update(member_id_commitment);
        if let Some(bc) = benefits_commitment {
            hasher.update(bc);
        }
        if let Some(cc) = copay_commitment {
            hasher.update(cc);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if membership is currently active
    pub fn is_active(&self, current_time: Timestamp) -> bool {
        if !matches!(
            self.status,
            MembershipStatus::Active | MembershipStatus::GracePeriod | MembershipStatus::Cobra
        ) {
            return false;
        }
        if current_time < self.effective_from {
            return false;
        }
        if let Some(exp) = self.expiry {
            if current_time >= exp {
                return false;
            }
        }
        true
    }
}

// =============================================================================
// SRC-874: Consent & Disclosure Envelope
// =============================================================================

/// Consent type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConsentType {
    // HIPAA Consents (0-19)
    /// HIPAA authorization for disclosure
    HipaaAuthorization = 0,
    /// Notice of privacy practices acknowledgment
    NppAcknowledgment = 1,
    /// Consent to treat
    ConsentToTreat = 2,
    /// Assignment of benefits
    AssignmentOfBenefits = 3,
    /// Release of medical records
    RecordsRelease = 4,
    /// Research consent
    ResearchConsent = 5,
    /// Telehealth consent
    TelehealthConsent = 6,
    /// Psychotherapy notes consent
    PsychotherapyNotes = 7,
    /// Substance abuse records (42 CFR Part 2)
    SubstanceAbuseRecords = 8,
    /// HIV/STI disclosure
    HivStiDisclosure = 9,
    /// Genetic information
    GeneticInformation = 10,

    // Data Processing Consents (20-39)
    /// GDPR consent
    GdprConsent = 20,
    /// Marketing consent
    MarketingConsent = 21,
    /// Data sharing consent
    DataSharingConsent = 22,
    /// Analytics consent
    AnalyticsConsent = 23,
    /// Third party sharing
    ThirdPartySharing = 24,

    // Membership Consents (40-49)
    /// Terms of service
    TermsOfService = 40,
    /// Privacy policy
    PrivacyPolicy = 41,
    /// Code of conduct
    CodeOfConduct = 42,
    /// Background check authorization
    BackgroundCheck = 43,

    /// Other consent type
    Other = 255,
}

/// Consent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConsentStatus {
    /// Consent given
    Granted = 0,
    /// Consent pending
    Pending = 1,
    /// Consent revoked
    Revoked = 2,
    /// Consent expired
    Expired = 3,
    /// Consent denied
    Denied = 4,
    /// Consent superseded
    Superseded = 5,
}

/// Disclosure scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisclosureScope {
    /// All records
    AllRecords = 0,
    /// Date range
    DateRange = 1,
    /// Specific encounter
    SpecificEncounter = 2,
    /// Specific condition
    SpecificCondition = 3,
    /// Treatment only
    TreatmentOnly = 4,
    /// Payment only
    PaymentOnly = 5,
    /// Healthcare operations
    HealthcareOperations = 6,
    /// Minimum necessary
    MinimumNecessary = 7,
}

/// SRC-874 Consent/Disclosure Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentEnvelope {
    /// Unique consent identifier
    pub consent_id: ConsentId,
    /// Subject wallet address (for token ownership)
    pub subject_address: Address,
    /// Consent type
    pub consent_type: ConsentType,
    /// BLAKE3 commitment of consent details
    pub consent_commitment: [u8; 32],
    /// Subject giving consent (patient/member)
    pub subject_ref: PartyRef,
    /// Subject nullifier for anonymous verification
    pub subject_nullifier: [u8; 32],
    /// Recipient of consent (provider, organization)
    pub recipient_ref: PartyRef,
    /// Purpose of consent
    pub purpose_commitment: [u8; 32],
    /// Disclosure scope
    pub scope: DisclosureScope,
    /// Scope details commitment (date range, etc.)
    pub scope_commitment: Option<[u8; 32]>,
    /// Effective date
    pub effective_from: Timestamp,
    /// Expiry date (required for HIPAA)
    pub expiry: Option<Timestamp>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: HealthcareIssuerClass,
    /// Policy ID (SRC-803)
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: ConsentStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Supersedes consent ID
    pub supersedes: Option<ConsentId>,
    /// Attachments (signed consent form, etc.)
    pub attachments: Vec<AttachmentRef>,
}

impl ConsentEnvelope {
    /// Generate consent ID
    pub fn generate_id(
        subject_nullifier: &[u8; 32],
        consent_type: ConsentType,
        recipient_ref: &PartyRef,
        nonce: &[u8; 32],
    ) -> ConsentId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONSENT_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(subject_nullifier);
        hasher.update(&[consent_type as u8]);
        hasher.update(&recipient_ref.as_hash());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate consent commitment
    pub fn generate_commitment(
        consent_text_hash: &[u8; 32],
        purpose_commitment: &[u8; 32],
        restrictions_hash: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONSENT_COMMITMENT_SEP);
        hasher.update(consent_text_hash);
        hasher.update(purpose_commitment);
        if let Some(rh) = restrictions_hash {
            hasher.update(rh);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if consent is currently valid
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        if !matches!(self.status, ConsentStatus::Granted) {
            return false;
        }
        if current_time < self.effective_from {
            return false;
        }
        if let Some(exp) = self.expiry {
            if current_time >= exp {
                return false;
            }
        }
        true
    }
}

// =============================================================================
// SRC-876: Prescription Standard (NON-TRANSFERABLE)
// =============================================================================

/// Prescription type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrescriptionType {
    // Controlled Substances (0-19)
    /// Schedule I (not prescribed)
    ScheduleI = 0,
    /// Schedule II
    ScheduleII = 1,
    /// Schedule III
    ScheduleIII = 2,
    /// Schedule IV
    ScheduleIV = 3,
    /// Schedule V
    ScheduleV = 4,

    // Non-Controlled (20-39)
    /// Standard prescription drug
    StandardPrescription = 20,
    /// Specialty medication
    SpecialtyMedication = 21,
    /// Compound medication
    CompoundMedication = 22,
    /// Biologic
    Biologic = 23,
    /// Biosimilar
    Biosimilar = 24,
    /// Generic
    Generic = 25,
    /// Brand name
    BrandName = 26,

    // DME/Supplies (40-49)
    /// Durable medical equipment
    Dme = 40,
    /// Medical supplies
    MedicalSupplies = 41,
    /// Prosthetics
    Prosthetics = 42,
    /// Orthotics
    Orthotics = 43,

    // Other (50-59)
    /// Over the counter (with Rx benefits)
    Otc = 50,
    /// Nutritional supplement
    NutritionalSupplement = 51,
    /// Optical
    Optical = 52,

    /// Other type
    Other = 255,
}

/// Prescription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrescriptionStatus {
    /// Prescription active
    Active = 0,
    /// Prescription pending
    Pending = 1,
    /// Prescription on hold
    OnHold = 2,
    /// Prescription filled
    Filled = 3,
    /// Prescription partially filled
    PartiallyFilled = 4,
    /// Prescription expired
    Expired = 5,
    /// Prescription cancelled
    Cancelled = 6,
    /// Prescription superseded
    Superseded = 7,
    /// Transfer requested (NOT allowed for controlled substances)
    TransferRequested = 8,
    /// Prescription denied
    Denied = 9,
}

/// SRC-876 Prescription (NON-TRANSFERABLE for controlled substances)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prescription {
    /// Unique prescription identifier
    pub prescription_id: PrescriptionId,
    /// Patient wallet address (for token ownership)
    pub patient_address: Address,
    /// Prescription type
    pub prescription_type: PrescriptionType,
    /// BLAKE3 commitment of prescription details
    pub prescription_commitment: [u8; 32],
    /// Patient reference (privacy-preserving)
    pub patient_ref: PartyRef,
    /// Patient nullifier for anonymous verification
    pub patient_nullifier: [u8; 32],
    /// Prescriber reference (physician)
    pub prescriber_ref: PartyRef,
    /// Prescriber's provider ID
    pub prescriber_provider_id: ProviderId,
    /// Pharmacy reference (if assigned)
    pub pharmacy_ref: Option<PartyRef>,
    /// Medication commitment (NDC, name, strength, etc.)
    pub medication_commitment: [u8; 32],
    /// Quantity commitment
    pub quantity_commitment: [u8; 32],
    /// Days supply commitment
    pub days_supply_commitment: Option<[u8; 32]>,
    /// Refills authorized
    pub refills_authorized: u8,
    /// Refills remaining
    pub refills_remaining: u8,
    /// Is controlled substance (affects transferability)
    pub is_controlled: bool,
    /// Date written
    pub date_written: Timestamp,
    /// Effective date (if different from written)
    pub effective_from: Option<Timestamp>,
    /// Expiry date
    pub expiry: Timestamp,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: HealthcareIssuerClass,
    /// Policy ID (SRC-803)
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: PrescriptionStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Supersedes prescription ID
    pub supersedes: Option<PrescriptionId>,
    /// Fill history (commitment hashes of each fill)
    pub fill_history: Vec<[u8; 32]>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl Prescription {
    /// Generate prescription ID
    pub fn generate_id(
        prescriber_provider_id: &ProviderId,
        patient_nullifier: &[u8; 32],
        medication_commitment: &[u8; 32],
        date_written: Timestamp,
        nonce: &[u8; 32],
    ) -> PrescriptionId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PRESCRIPTION_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(prescriber_provider_id);
        hasher.update(patient_nullifier);
        hasher.update(medication_commitment);
        hasher.update(&date_written.to_le_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate prescription commitment
    pub fn generate_commitment(
        medication_commitment: &[u8; 32],
        dosage_commitment: &[u8; 32],
        instructions_hash: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PRESCRIPTION_COMMITMENT_SEP);
        hasher.update(medication_commitment);
        hasher.update(dosage_commitment);
        if let Some(ih) = instructions_hash {
            hasher.update(ih);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if prescription is currently valid for filling
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        if !matches!(
            self.status,
            PrescriptionStatus::Active | PrescriptionStatus::PartiallyFilled
        ) {
            return false;
        }
        if let Some(eff) = self.effective_from {
            if current_time < eff {
                return false;
            }
        }
        if current_time >= self.expiry {
            return false;
        }
        true
    }

    /// Check if prescription can be transferred (NOT for controlled substances)
    pub fn can_transfer(&self) -> bool {
        !self.is_controlled
            && matches!(self.status, PrescriptionStatus::Active)
            && self.refills_remaining > 0
    }

    /// Check if any refills remain
    pub fn has_refills(&self) -> bool {
        self.refills_remaining > 0
    }
}

// =============================================================================
// SRC-875: 87X Proof Profiles
// =============================================================================

/// Proof profile types for SRC-87X
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthcareProofProfile {
    /// Prove membership is active
    MembershipActive = 0,
    /// Prove provider is in-network
    ProviderInNetwork = 1,
    /// Prove consent exists
    ConsentExists = 2,
    /// Prove consent is valid
    ConsentValid = 3,
    /// Prove prescription is valid
    PrescriptionValid = 4,
    /// Prove prescription has refills
    PrescriptionHasRefills = 5,
    /// Prove coverage tier
    CoverageTier = 6,
    /// Prove benefit eligibility
    BenefitEligible = 7,
}

/// Proof type (SRC-806 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthcareProofType {
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

/// SRC-875 Healthcare Proof Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthcareProofEnvelope {
    /// Proof identifier
    pub proof_id: ProofId,
    /// Proof profile being proven
    pub profile: HealthcareProofProfile,
    /// Profile version string (e.g., "healthcare.membership_active.v1")
    pub profile_id: String,
    /// Policy IDs that were checked
    pub policy_ids: Vec<PolicyId>,
    /// Public inputs to the proof
    pub public_inputs: Vec<u8>,
    /// The proof data
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: HealthcareProofType,
    /// Subject nullifier (for revocation checking)
    pub subject_nullifier: [u8; 32],
    /// When proof was generated
    pub generated_at: Timestamp,
    /// When proof expires
    pub expires_at: Timestamp,
}

impl HealthcareProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile: HealthcareProofProfile,
        subject_nullifier: &[u8; 32],
        policy_ids: &[PolicyId],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(HEALTHCARE_PROOF_DOMAIN_SEP);
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

/// SRC-87X Operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthcareOperation {
    // SRC-871: Provider Registry (0-9)
    RegisterProvider = 0,
    UpdateProvider = 1,
    SuspendProvider = 2,
    RevokeProvider = 3,
    ReactivateProvider = 4,
    AddNetworkAffiliation = 5,
    RemoveNetworkAffiliation = 6,

    // SRC-872: Membership (10-19)
    IssueMembership = 10,
    UpdateMembership = 11,
    RenewMembership = 12,
    SuspendMembership = 13,
    TerminateMembership = 14,
    ReinstateMembership = 15,
    AddDependent = 16,
    RemoveDependent = 17,

    // SRC-874: Consent (20-29)
    GrantConsent = 20,
    UpdateConsent = 21,
    RevokeConsent = 22,
    SupersedeConsent = 23,

    // SRC-876: Prescription (30-39)
    IssuePrescription = 30,
    UpdatePrescription = 31,
    FillPrescription = 32,
    PartialFillPrescription = 33,
    CancelPrescription = 34,
    HoldPrescription = 35,
    ReleaseHold = 36,
    // Note: Transfer operation intentionally restricted for controlled substances

    // SRC-875: Proof Operations (40-49)
    SubmitProof = 40,
    VerifyProof = 41,
}

/// Transaction data for SRC-87X operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthcareTxData {
    pub operation: HealthcareOperation,
    pub data: Vec<u8>,
    /// Token recipient address - the owner of the minted token
    pub recipient: crate::Address,
}

// =============================================================================
// Events
// =============================================================================

/// SRC-87X Events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthcareEvent {
    // SRC-871 Events
    ProviderRegistered {
        provider_id: ProviderId,
        provider_type: ProviderType,
        jurisdiction: String,
        timestamp: Timestamp,
    },
    ProviderUpdated {
        provider_id: ProviderId,
        new_status: ProviderStatus,
        timestamp: Timestamp,
    },
    NetworkAffiliationChanged {
        provider_id: ProviderId,
        plan_id: ProviderId,
        added: bool,
        timestamp: Timestamp,
    },

    // SRC-872 Events
    MembershipIssued {
        membership_id: MembershipId,
        provider_id: ProviderId,
        membership_type: MembershipType,
        effective_from: Timestamp,
        timestamp: Timestamp,
    },
    MembershipStatusUpdated {
        membership_id: MembershipId,
        new_status: MembershipStatus,
        timestamp: Timestamp,
    },
    DependentChanged {
        membership_id: MembershipId,
        dependent_hash: [u8; 32],
        added: bool,
        timestamp: Timestamp,
    },

    // SRC-874 Events
    ConsentGranted {
        consent_id: ConsentId,
        consent_type: ConsentType,
        subject_nullifier: [u8; 32],
        timestamp: Timestamp,
    },
    ConsentRevoked {
        consent_id: ConsentId,
        timestamp: Timestamp,
    },
    ConsentSuperseded {
        old_consent_id: ConsentId,
        new_consent_id: ConsentId,
        timestamp: Timestamp,
    },

    // SRC-876 Events
    PrescriptionIssued {
        prescription_id: PrescriptionId,
        prescription_type: PrescriptionType,
        is_controlled: bool,
        date_written: Timestamp,
        expiry: Timestamp,
        timestamp: Timestamp,
    },
    PrescriptionFilled {
        prescription_id: PrescriptionId,
        fill_commitment: [u8; 32],
        refills_remaining: u8,
        timestamp: Timestamp,
    },
    PrescriptionStatusUpdated {
        prescription_id: PrescriptionId,
        new_status: PrescriptionStatus,
        timestamp: Timestamp,
    },

    // SRC-875 Events
    HealthcareProofSubmitted {
        proof_id: ProofId,
        profile: HealthcareProofProfile,
        timestamp: Timestamp,
    },
    HealthcareProofVerified {
        proof_id: ProofId,
        valid: bool,
        timestamp: Timestamp,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_id_generation() {
        let issuer = Address::new([1u8; 20]);
        let commitment = [2u8; 32];
        let nonce = [3u8; 32];

        let id = ProviderProfile::generate_id(
            &issuer,
            &commitment,
            ProviderType::Hospital,
            "US-CA",
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);

        // Same inputs = same ID
        let id2 = ProviderProfile::generate_id(
            &issuer,
            &commitment,
            ProviderType::Hospital,
            "US-CA",
            &nonce,
        );
        assert_eq!(id, id2);

        // Different provider type = different ID
        let id3 = ProviderProfile::generate_id(
            &issuer,
            &commitment,
            ProviderType::Pharmacy,
            "US-CA",
            &nonce,
        );
        assert_ne!(id, id3);
    }

    #[test]
    fn test_provider_commitment() {
        let name = [1u8; 32];
        let commitment = ProviderProfile::generate_commitment(None, &name, None);
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_membership_active() {
        let membership = MembershipRecord {
            membership_id: [1u8; 32],
            member_address: Address::new([0u8; 20]),
            provider_id: [2u8; 32],
            membership_type: MembershipType::IndividualHealth,
            membership_commitment: [3u8; 32],
            member_ref: PartyRef::Commitment([4u8; 32]),
            member_nullifier: [5u8; 32],
            coverage_tier: Some(CoverageTier::Individual),
            group_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([6u8; 20]),
            issuer_class: HealthcareIssuerClass::InsuranceCompany,
            policy_id: [7u8; 32],
            revocation_ref: None,
            status: MembershipStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            prior_membership_id: None,
            dependents: vec![],
            attachments: vec![],
        };

        assert!(!membership.is_active(500));  // Before effective
        assert!(membership.is_active(1500)); // During validity
        assert!(!membership.is_active(2500)); // After expiry
    }

    #[test]
    fn test_consent_valid() {
        let consent = ConsentEnvelope {
            consent_id: [1u8; 32],
            subject_address: Address::new([0u8; 20]),
            consent_type: ConsentType::HipaaAuthorization,
            consent_commitment: [2u8; 32],
            subject_ref: PartyRef::Commitment([3u8; 32]),
            subject_nullifier: [4u8; 32],
            recipient_ref: PartyRef::Commitment([5u8; 32]),
            purpose_commitment: [6u8; 32],
            scope: DisclosureScope::TreatmentOnly,
            scope_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([7u8; 20]),
            issuer_class: HealthcareIssuerClass::MedicalPractice,
            policy_id: [8u8; 32],
            revocation_ref: None,
            status: ConsentStatus::Granted,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            supersedes: None,
            attachments: vec![],
        };

        assert!(!consent.is_valid(500));  // Before effective
        assert!(consent.is_valid(1500)); // During validity
        assert!(!consent.is_valid(2500)); // After expiry
    }

    #[test]
    fn test_prescription_validity() {
        let prescription = Prescription {
            prescription_id: [1u8; 32],
            patient_address: Address::new([0u8; 20]),
            prescription_type: PrescriptionType::StandardPrescription,
            prescription_commitment: [2u8; 32],
            patient_ref: PartyRef::Commitment([3u8; 32]),
            patient_nullifier: [4u8; 32],
            prescriber_ref: PartyRef::Commitment([5u8; 32]),
            prescriber_provider_id: [6u8; 32],
            pharmacy_ref: None,
            medication_commitment: [7u8; 32],
            quantity_commitment: [8u8; 32],
            days_supply_commitment: None,
            refills_authorized: 3,
            refills_remaining: 2,
            is_controlled: false,
            date_written: 900,
            effective_from: Some(1000),
            expiry: 2000,
            issuer_address: Address::new([9u8; 20]),
            issuer_class: HealthcareIssuerClass::MedicalPractice,
            policy_id: [10u8; 32],
            revocation_ref: None,
            status: PrescriptionStatus::Active,
            created_at: 900,
            updated_at: 900,
            recorded_at_height: 100,
            supersedes: None,
            fill_history: vec![],
            attachments: vec![],
        };

        assert!(!prescription.is_valid(500));  // Before effective
        assert!(prescription.is_valid(1500)); // During validity
        assert!(!prescription.is_valid(2500)); // After expiry
        assert!(prescription.can_transfer());
        assert!(prescription.has_refills());
    }

    #[test]
    fn test_controlled_prescription_no_transfer() {
        let prescription = Prescription {
            prescription_id: [1u8; 32],
            patient_address: Address::new([0u8; 20]),
            prescription_type: PrescriptionType::ScheduleII,
            prescription_commitment: [2u8; 32],
            patient_ref: PartyRef::Commitment([3u8; 32]),
            patient_nullifier: [4u8; 32],
            prescriber_ref: PartyRef::Commitment([5u8; 32]),
            prescriber_provider_id: [6u8; 32],
            pharmacy_ref: None,
            medication_commitment: [7u8; 32],
            quantity_commitment: [8u8; 32],
            days_supply_commitment: None,
            refills_authorized: 0, // Schedule II cannot have refills
            refills_remaining: 0,
            is_controlled: true,
            date_written: 900,
            effective_from: None,
            expiry: 2000,
            issuer_address: Address::new([9u8; 20]),
            issuer_class: HealthcareIssuerClass::MedicalPractice,
            policy_id: [10u8; 32],
            revocation_ref: None,
            status: PrescriptionStatus::Active,
            created_at: 900,
            updated_at: 900,
            recorded_at_height: 100,
            supersedes: None,
            fill_history: vec![],
            attachments: vec![],
        };

        // Controlled substance cannot be transferred
        assert!(!prescription.can_transfer());
        assert!(!prescription.has_refills());
    }

    #[test]
    fn test_healthcare_issuer_class() {
        assert!(HealthcareIssuerClass::GovernmentHealthAgency.is_official());
        assert!(HealthcareIssuerClass::Dea.is_official());
        assert!(!HealthcareIssuerClass::InsuranceCompany.is_official());

        assert!(HealthcareIssuerClass::InsuranceCompany.is_lowkey());
        assert!(HealthcareIssuerClass::MedicalPractice.is_lowkey());
        assert!(!HealthcareIssuerClass::GovernmentHealthAgency.is_lowkey());
    }

    #[test]
    fn test_healthcare_proof_id() {
        let nullifier = [1u8; 32];
        let policies = vec![[2u8; 32], [3u8; 32]];
        let nonce = [4u8; 32];

        let id = HealthcareProofEnvelope::generate_id(
            HealthcareProofProfile::MembershipActive,
            &nullifier,
            &policies,
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }
}
