//! SRC-86X Property, Real Estate & Insurance Domain
//!
//! Privacy-first infrastructure for:
//! - SRC-861: Asset Anchor (Property/Asset Identity)
//! - SRC-862: Title/Ownership State Event
//! - SRC-863: Encumbrance Standard (Lien/Mortgage/Leasehold)
//! - SRC-864: Insurance Coverage Standard
//! - SRC-865: Insurance Claim Lifecycle
//! - SRC-866: 86X Proof Profiles

use serde::{Deserialize, Serialize};
use crate::{Address, BlockHeight, Timestamp};
use crate::agreement::{AttachmentRef, PartyRef};

// =============================================================================
// Type Aliases
// =============================================================================

/// Unique asset anchor identifier
pub type AssetId = [u8; 32];
/// Title event identifier
pub type TitleEventId = [u8; 32];
/// Encumbrance identifier
pub type EncumbranceId = [u8; 32];
/// Insurance coverage identifier
pub type CoverageId = [u8; 32];
/// Insurance claim identifier
pub type ClaimId = [u8; 32];
/// Policy identifier (SRC-803 compatible)
pub type PolicyId = [u8; 32];
/// Proof identifier (SRC-806 compatible)
pub type ProofId = [u8; 32];
/// Subject identifier (SRC-801 compatible)
pub type SubjectId = [u8; 32];

// =============================================================================
// Domain Separators (for deterministic hashing)
// =============================================================================

pub const ASSET_DOMAIN_SEP: &[u8] = b"SRC861-ASSET:";
pub const ASSET_COMMITMENT_SEP: &[u8] = b"SRC861-COMMITMENT:v1:";
pub const TITLE_DOMAIN_SEP: &[u8] = b"SRC862-TITLE:";
pub const TITLE_COMMITMENT_SEP: &[u8] = b"SRC862-COMMITMENT:v1:";
pub const ENCUMBRANCE_DOMAIN_SEP: &[u8] = b"SRC863-ENCUMBRANCE:";
pub const ENCUMBRANCE_COMMITMENT_SEP: &[u8] = b"SRC863-COMMITMENT:v1:";
pub const COVERAGE_DOMAIN_SEP: &[u8] = b"SRC864-COVERAGE:";
pub const COVERAGE_COMMITMENT_SEP: &[u8] = b"SRC864-COMMITMENT:v1:";
pub const CLAIM_DOMAIN_SEP: &[u8] = b"SRC865-CLAIM:";
pub const CLAIM_COMMITMENT_SEP: &[u8] = b"SRC865-COMMITMENT:v1:";
pub const PROPERTY_PROOF_DOMAIN_SEP: &[u8] = b"SRC866-PROOF:";

// =============================================================================
// SRC-861: Asset Anchor (Property/Asset Identity)
// =============================================================================

/// Asset type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AssetType {
    // Real Estate (0-19)
    /// Single family residence
    SingleFamilyResidence = 0,
    /// Multi-family residence
    MultiFamilyResidence = 1,
    /// Condominium
    Condominium = 2,
    /// Townhouse
    Townhouse = 3,
    /// Commercial property
    Commercial = 4,
    /// Industrial property
    Industrial = 5,
    /// Vacant land
    VacantLand = 6,
    /// Agricultural land
    Agricultural = 7,
    /// Mixed use
    MixedUse = 8,
    /// Manufactured home
    ManufacturedHome = 9,

    // Vehicles (20-39)
    /// Automobile
    Automobile = 20,
    /// Motorcycle
    Motorcycle = 21,
    /// Boat/Watercraft
    Watercraft = 22,
    /// Aircraft
    Aircraft = 23,
    /// Recreational vehicle
    RecreationalVehicle = 24,
    /// Commercial vehicle
    CommercialVehicle = 25,
    /// Heavy equipment
    HeavyEquipment = 26,

    // Personal Property (40-59)
    /// Fine art
    FineArt = 40,
    /// Jewelry
    Jewelry = 41,
    /// Collectibles
    Collectibles = 42,
    /// Antiques
    Antiques = 43,
    /// Musical instruments
    MusicalInstruments = 44,
    /// Electronics
    Electronics = 45,
    /// Furniture
    Furniture = 46,

    // Business Assets (60-79)
    /// Inventory
    Inventory = 60,
    /// Equipment
    Equipment = 61,
    /// Fixtures
    Fixtures = 62,
    /// Intellectual property bundle
    IpBundle = 63,
    /// Goodwill
    Goodwill = 64,

    /// Other asset type
    Other = 255,
}

/// Asset status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AssetStatus {
    /// Asset registered and active
    Active = 0,
    /// Asset under transfer
    PendingTransfer = 1,
    /// Asset encumbered
    Encumbered = 2,
    /// Asset seized/frozen
    Seized = 3,
    /// Asset destroyed/demolished
    Destroyed = 4,
    /// Asset merged with another
    Merged = 5,
    /// Asset subdivided
    Subdivided = 6,
    /// Asset deregistered
    Deregistered = 7,
}

/// Property issuer class (SRC-802 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PropertyIssuerClass {
    // Official/Phase 2 Issuers (0-9)
    /// Land registry/recorder's office
    LandRegistry = 0,
    /// Motor vehicle department
    MotorVehicleDept = 1,
    /// Tax assessor
    TaxAssessor = 2,
    /// Government agency
    GovernmentAgency = 3,
    /// FAA (aircraft registry)
    AviationAuthority = 4,
    /// Coast Guard (vessel registry)
    MaritimeAuthority = 5,

    // Phase 1/Lowkey Issuers (10-29)
    /// Title company
    TitleCompany = 10,
    /// Escrow company
    EscrowCompany = 11,
    /// Real estate attorney
    RealEstateAttorney = 12,
    /// Appraiser
    Appraiser = 13,
    /// Surveyor
    Surveyor = 14,
    /// Insurance company
    InsuranceCompany = 15,
    /// Mortgage lender
    MortgageLender = 16,
    /// Property manager
    PropertyManager = 17,
    /// Notary
    Notary = 18,

    /// Other authorized issuer
    Other = 255,
}

impl PropertyIssuerClass {
    /// Check if this is an official (Phase 2) issuer
    pub fn is_official(&self) -> bool {
        matches!(
            self,
            Self::LandRegistry
                | Self::MotorVehicleDept
                | Self::TaxAssessor
                | Self::GovernmentAgency
                | Self::AviationAuthority
                | Self::MaritimeAuthority
        )
    }

    /// Check if this is a Phase 1 (lowkey) issuer
    pub fn is_lowkey(&self) -> bool {
        matches!(
            self,
            Self::TitleCompany
                | Self::EscrowCompany
                | Self::RealEstateAttorney
                | Self::Appraiser
                | Self::Surveyor
                | Self::InsuranceCompany
                | Self::MortgageLender
        )
    }
}

/// SRC-861 Asset Anchor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetAnchor {
    /// Unique asset identifier
    pub asset_id: AssetId,
    /// BLAKE3 commitment of asset details (address, parcel, VIN, etc.)
    pub asset_commitment: [u8; 32],
    /// Asset type classification
    pub asset_type: AssetType,
    /// Jurisdiction code (e.g., "US-CA-LA" for Los Angeles County)
    pub jurisdiction_code: String,
    /// Optional public reference (APN, VIN last 4, etc. - only if opted in)
    pub public_reference: Option<String>,
    /// Policy ID governing this asset
    pub policy_id: PolicyId,
    /// Issuer class that registered this
    pub issuer_class: PropertyIssuerClass,
    /// Issuer address
    pub issuer_address: Address,
    /// Current status
    pub status: AssetStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when anchored
    pub anchored_at_height: BlockHeight,
    /// Related asset IDs (for subdivisions, mergers)
    pub related_assets: Vec<AssetId>,
    /// Attachments (encrypted references)
    pub attachments: Vec<AttachmentRef>,
}

impl AssetAnchor {
    /// Generate deterministic asset ID
    pub fn generate_id(
        issuer: &Address,
        asset_commitment: &[u8; 32],
        asset_type: AssetType,
        jurisdiction: &str,
        nonce: &[u8; 32],
    ) -> AssetId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSET_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(issuer.as_ref());
        hasher.update(asset_commitment);
        hasher.update(&[asset_type as u8]);
        hasher.update(jurisdiction.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate asset commitment from details
    pub fn generate_commitment(
        asset_details: &[u8],
        location_commitment: Option<&[u8; 32]>,
        identifier_commitment: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSET_COMMITMENT_SEP);
        hasher.update(asset_details);
        if let Some(loc) = location_commitment {
            hasher.update(loc);
        }
        if let Some(id) = identifier_commitment {
            hasher.update(id);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-862: Title/Ownership State Event
// =============================================================================

/// Title event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TitleEventType {
    // Initial Events (0-9)
    /// Initial title registration
    InitialRegistration = 0,
    /// Title search completed
    TitleSearch = 1,
    /// Title examination
    TitleExamination = 2,
    /// Title insurance commitment
    TitleCommitment = 3,

    // Transfer Events (10-19)
    /// Deed recorded
    DeedRecorded = 10,
    /// Grant deed
    GrantDeed = 11,
    /// Warranty deed
    WarrantyDeed = 12,
    /// Quitclaim deed
    QuitclaimDeed = 13,
    /// Trust deed
    TrustDeed = 14,
    /// Deed of gift
    DeedOfGift = 15,
    /// Executor's deed
    ExecutorsDeed = 16,
    /// Tax deed
    TaxDeed = 17,
    /// Sheriff's deed
    SheriffsDeed = 18,

    // Ownership Changes (20-29)
    /// Ownership transfer
    OwnershipTransfer = 20,
    /// Joint tenancy creation
    JointTenancyCreated = 21,
    /// Tenancy in common
    TenancyInCommon = 22,
    /// Trust assignment
    TrustAssignment = 23,
    /// Inheritance
    Inheritance = 24,
    /// Divorce decree transfer
    DivorceTransfer = 25,

    // Title Adjustments (30-39)
    /// Title correction
    TitleCorrection = 30,
    /// Name change
    NameChange = 31,
    /// Legal description update
    LegalDescriptionUpdate = 32,
    /// Easement recorded
    EasementRecorded = 33,
    /// Covenant recorded
    CovenantRecorded = 34,

    // Termination Events (40-49)
    /// Title cleared
    TitleCleared = 40,
    /// Foreclosure completed
    ForeclosureCompleted = 41,
    /// Tax sale completed
    TaxSaleCompleted = 42,
    /// Condemnation
    Condemnation = 43,

    /// Other event
    Other = 255,
}

/// Title event status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TitleEventStatus {
    /// Event recorded
    Recorded = 0,
    /// Event pending
    Pending = 1,
    /// Event superseded
    Superseded = 2,
    /// Event voided
    Voided = 3,
    /// Event corrected
    Corrected = 4,
}

/// SRC-862 Title Event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TitleEvent {
    /// Unique event identifier
    pub event_id: TitleEventId,
    /// Asset this event relates to
    pub asset_id: AssetId,
    /// Event type
    pub event_type: TitleEventType,
    /// BLAKE3 commitment of event details
    pub event_commitment: [u8; 32],
    /// Grantor (current owner) reference
    pub grantor_ref: Option<PartyRef>,
    /// Grantee (new owner) reference
    pub grantee_ref: Option<PartyRef>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: PropertyIssuerClass,
    /// Event effective date
    pub effective_date: Timestamp,
    /// Recording reference (instrument number, etc.)
    pub recording_ref: Option<String>,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: TitleEventStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Supersedes event ID
    pub supersedes: Option<TitleEventId>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl TitleEvent {
    /// Generate event ID
    pub fn generate_id(
        asset_id: &AssetId,
        event_type: TitleEventType,
        issuer: &Address,
        nonce: &[u8; 32],
    ) -> TitleEventId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TITLE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(asset_id);
        hasher.update(&[event_type as u8]);
        hasher.update(issuer.as_ref());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate event commitment
    pub fn generate_commitment(
        deed_hash: &[u8; 32],
        parties_commitment: &[u8; 32],
        consideration_commitment: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(TITLE_COMMITMENT_SEP);
        hasher.update(deed_hash);
        hasher.update(parties_commitment);
        if let Some(cc) = consideration_commitment {
            hasher.update(cc);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-863: Encumbrance Standard (Lien/Mortgage/Leasehold)
// =============================================================================

/// Encumbrance type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncumbranceType {
    // Mortgages (0-9)
    /// First mortgage/deed of trust
    FirstMortgage = 0,
    /// Second mortgage
    SecondMortgage = 1,
    /// Home equity line of credit
    Heloc = 2,
    /// Reverse mortgage
    ReverseMortgage = 3,
    /// Construction loan
    ConstructionLoan = 4,
    /// Commercial mortgage
    CommercialMortgage = 5,

    // Liens (10-29)
    /// Mechanics lien
    MechanicsLien = 10,
    /// Tax lien
    TaxLien = 11,
    /// Judgment lien
    JudgmentLien = 12,
    /// HOA lien
    HoaLien = 13,
    /// Child support lien
    ChildSupportLien = 14,
    /// IRS lien
    IrsLien = 15,
    /// Municipal lien
    MunicipalLien = 16,
    /// UCC lien
    UccLien = 17,
    /// Voluntary lien
    VoluntaryLien = 18,
    /// Attachment lien
    AttachmentLien = 19,

    // Leaseholds (30-39)
    /// Residential lease
    ResidentialLease = 30,
    /// Commercial lease
    CommercialLease = 31,
    /// Ground lease
    GroundLease = 32,
    /// Sublease
    Sublease = 33,

    // Easements & Restrictions (40-49)
    /// Easement
    Easement = 40,
    /// Right of way
    RightOfWay = 41,
    /// Restrictive covenant
    RestrictiveCovenant = 42,
    /// Conservation easement
    ConservationEasement = 43,
    /// Utility easement
    UtilityEasement = 44,

    // Other (50-59)
    /// Lis pendens
    LisPendens = 50,
    /// Notice of default
    NoticeOfDefault = 51,
    /// Notice of trustee sale
    NoticeOfTrusteeSale = 52,

    /// Other encumbrance
    Other = 255,
}

/// Encumbrance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncumbranceStatus {
    /// Encumbrance active
    Active = 0,
    /// Encumbrance pending
    Pending = 1,
    /// Encumbrance subordinated
    Subordinated = 2,
    /// Encumbrance released/satisfied
    Released = 3,
    /// Encumbrance foreclosed
    Foreclosed = 4,
    /// Encumbrance expired
    Expired = 5,
    /// Encumbrance disputed
    Disputed = 6,
    /// Encumbrance voided
    Voided = 7,
}

/// Priority position for encumbrance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PriorityPosition {
    First = 1,
    Second = 2,
    Third = 3,
    Fourth = 4,
    Fifth = 5,
    Subordinate = 10,
    Unspecified = 255,
}

/// SRC-863 Encumbrance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encumbrance {
    /// Unique encumbrance identifier
    pub encumbrance_id: EncumbranceId,
    /// Asset being encumbered
    pub asset_id: AssetId,
    /// Encumbrance type
    pub encumbrance_type: EncumbranceType,
    /// BLAKE3 commitment of encumbrance details
    pub encumbrance_commitment: [u8; 32],
    /// Holder of the encumbrance (lender, lienor, lessor)
    pub holder_ref: PartyRef,
    /// Obligor (borrower, debtor, lessee)
    pub obligor_ref: Option<PartyRef>,
    /// Priority position
    pub priority: PriorityPosition,
    /// Amount commitment (for monetary encumbrances)
    pub amount_commitment: Option<[u8; 32]>,
    /// Effective date
    pub effective_from: Timestamp,
    /// Expiry/maturity date
    pub expiry: Option<Timestamp>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: PropertyIssuerClass,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: EncumbranceStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Related agreement ID (SRC-841)
    pub agreement_id: Option<[u8; 32]>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl Encumbrance {
    /// Generate encumbrance ID
    pub fn generate_id(
        asset_id: &AssetId,
        encumbrance_type: EncumbranceType,
        holder_ref: &PartyRef,
        nonce: &[u8; 32],
    ) -> EncumbranceId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENCUMBRANCE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(asset_id);
        hasher.update(&[encumbrance_type as u8]);
        hasher.update(&holder_ref.as_hash());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate encumbrance commitment
    pub fn generate_commitment(
        terms_hash: &[u8; 32],
        amount_commitment: Option<&[u8; 32]>,
        parties_commitment: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENCUMBRANCE_COMMITMENT_SEP);
        hasher.update(terms_hash);
        if let Some(ac) = amount_commitment {
            hasher.update(ac);
        }
        hasher.update(parties_commitment);
        *hasher.finalize().as_bytes()
    }

    /// Check if encumbrance is currently active
    pub fn is_active(&self, current_time: Timestamp) -> bool {
        if !matches!(self.status, EncumbranceStatus::Active | EncumbranceStatus::Subordinated) {
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
// SRC-864: Insurance Coverage Standard
// =============================================================================

/// Insurance coverage type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoverageType {
    // Property Insurance (0-19)
    /// Homeowners insurance
    Homeowners = 0,
    /// Renters insurance
    Renters = 1,
    /// Landlord insurance
    Landlord = 2,
    /// Commercial property
    CommercialProperty = 3,
    /// Flood insurance
    Flood = 4,
    /// Earthquake insurance
    Earthquake = 5,
    /// Fire insurance
    Fire = 6,
    /// Windstorm/hurricane
    Windstorm = 7,

    // Vehicle Insurance (20-39)
    /// Auto liability
    AutoLiability = 20,
    /// Auto collision
    AutoCollision = 21,
    /// Auto comprehensive
    AutoComprehensive = 22,
    /// Uninsured motorist
    UninsuredMotorist = 23,
    /// Personal injury protection
    PersonalInjuryProtection = 24,
    /// Gap insurance
    GapInsurance = 25,
    /// Watercraft insurance
    Watercraft = 26,
    /// Aircraft insurance
    Aircraft = 27,

    // Title Insurance (40-49)
    /// Owner's title policy
    OwnersTitlePolicy = 40,
    /// Lender's title policy
    LendersTitlePolicy = 41,
    /// Extended coverage
    ExtendedCoverage = 42,

    // Liability Insurance (50-59)
    /// General liability
    GeneralLiability = 50,
    /// Professional liability
    ProfessionalLiability = 51,
    /// Umbrella policy
    UmbrellaPolicy = 52,
    /// Product liability
    ProductLiability = 53,

    // Specialty (60-69)
    /// Builder's risk
    BuildersRisk = 60,
    /// Inland marine
    InlandMarine = 61,
    /// Valuable articles
    ValuableArticles = 62,
    /// Equipment breakdown
    EquipmentBreakdown = 63,

    /// Other coverage
    Other = 255,
}

/// Coverage status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoverageStatus {
    /// Coverage active
    Active = 0,
    /// Coverage pending
    Pending = 1,
    /// Coverage suspended
    Suspended = 2,
    /// Coverage cancelled
    Cancelled = 3,
    /// Coverage expired
    Expired = 4,
    /// Coverage lapsed
    Lapsed = 5,
    /// Coverage renewed
    Renewed = 6,
    /// Coverage non-renewed
    NonRenewed = 7,
}

/// SRC-864 Insurance Coverage
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceCoverage {
    /// Unique coverage identifier
    pub coverage_id: CoverageId,
    /// Asset being insured
    pub asset_id: AssetId,
    /// Coverage type
    pub coverage_type: CoverageType,
    /// BLAKE3 commitment of coverage details
    pub coverage_commitment: [u8; 32],
    /// Insurer reference
    pub insurer_ref: PartyRef,
    /// Insured (policyholder) reference
    pub insured_ref: PartyRef,
    /// Additional insureds
    pub additional_insureds: Vec<PartyRef>,
    /// Coverage limit commitment
    pub limit_commitment: [u8; 32],
    /// Deductible commitment
    pub deductible_commitment: Option<[u8; 32]>,
    /// Premium commitment
    pub premium_commitment: Option<[u8; 32]>,
    /// Policy effective date
    pub effective_from: Timestamp,
    /// Policy expiry date
    pub expiry: Timestamp,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: PropertyIssuerClass,
    /// Policy ID (SRC-803)
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: CoverageStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Prior coverage ID (for renewals)
    pub prior_coverage_id: Option<CoverageId>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl InsuranceCoverage {
    /// Generate coverage ID
    pub fn generate_id(
        asset_id: &AssetId,
        coverage_type: CoverageType,
        insurer_ref: &PartyRef,
        insured_ref: &PartyRef,
        nonce: &[u8; 32],
    ) -> CoverageId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COVERAGE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(asset_id);
        hasher.update(&[coverage_type as u8]);
        hasher.update(&insurer_ref.as_hash());
        hasher.update(&insured_ref.as_hash());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate coverage commitment
    pub fn generate_commitment(
        policy_terms_hash: &[u8; 32],
        limit_commitment: &[u8; 32],
        exclusions_hash: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COVERAGE_COMMITMENT_SEP);
        hasher.update(policy_terms_hash);
        hasher.update(limit_commitment);
        if let Some(eh) = exclusions_hash {
            hasher.update(eh);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if coverage is currently in force
    pub fn is_in_force(&self, current_time: Timestamp) -> bool {
        if !matches!(self.status, CoverageStatus::Active | CoverageStatus::Renewed) {
            return false;
        }
        if current_time < self.effective_from {
            return false;
        }
        if current_time >= self.expiry {
            return false;
        }
        true
    }
}

// =============================================================================
// SRC-865: Insurance Claim Lifecycle
// =============================================================================

/// Claim type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClaimType {
    // Property Claims (0-19)
    /// Fire damage
    FireDamage = 0,
    /// Water damage
    WaterDamage = 1,
    /// Storm damage
    StormDamage = 2,
    /// Theft
    Theft = 3,
    /// Vandalism
    Vandalism = 4,
    /// Structural damage
    StructuralDamage = 5,
    /// Flood damage
    FloodDamage = 6,
    /// Earthquake damage
    EarthquakeDamage = 7,

    // Vehicle Claims (20-39)
    /// Collision
    Collision = 20,
    /// Comprehensive (non-collision)
    Comprehensive = 21,
    /// Hit and run
    HitAndRun = 22,
    /// Total loss
    TotalLoss = 23,
    /// Uninsured motorist
    UninsuredMotoristClaim = 24,

    // Liability Claims (40-49)
    /// Bodily injury
    BodilyInjury = 40,
    /// Property damage liability
    PropertyDamageLiability = 41,
    /// Personal injury
    PersonalInjuryClaim = 42,

    // Title Claims (50-59)
    /// Title defect
    TitleDefect = 50,
    /// Lien not shown
    LienNotShown = 51,
    /// Forgery
    Forgery = 52,
    /// Fraud
    Fraud = 53,
    /// Encroachment
    Encroachment = 54,

    /// Other claim type
    Other = 255,
}

/// Claim status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ClaimStatus {
    /// Claim filed
    Filed = 0,
    /// Claim acknowledged
    Acknowledged = 1,
    /// Under investigation
    UnderInvestigation = 2,
    /// Pending documentation
    PendingDocumentation = 3,
    /// In review
    InReview = 4,
    /// Approved
    Approved = 5,
    /// Partially approved
    PartiallyApproved = 6,
    /// Denied
    Denied = 7,
    /// Paid
    Paid = 8,
    /// Closed
    Closed = 9,
    /// Reopened
    Reopened = 10,
    /// In litigation
    InLitigation = 11,
    /// Subrogation pending
    SubrogationPending = 12,
    /// Withdrawn
    Withdrawn = 13,
}

/// SRC-865 Insurance Claim
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceClaim {
    /// Unique claim identifier
    pub claim_id: ClaimId,
    /// Coverage under which claim is made
    pub coverage_id: CoverageId,
    /// Asset involved
    pub asset_id: AssetId,
    /// Claim type
    pub claim_type: ClaimType,
    /// BLAKE3 commitment of claim details
    pub claim_commitment: [u8; 32],
    /// Claimant reference
    pub claimant_ref: PartyRef,
    /// Date of loss
    pub date_of_loss: Timestamp,
    /// Date claim filed
    pub date_filed: Timestamp,
    /// Loss amount commitment
    pub loss_amount_commitment: Option<[u8; 32]>,
    /// Approved amount commitment
    pub approved_amount_commitment: Option<[u8; 32]>,
    /// Paid amount commitment
    pub paid_amount_commitment: Option<[u8; 32]>,
    /// Adjuster assigned
    pub adjuster_ref: Option<PartyRef>,
    /// Issuer address
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: PropertyIssuerClass,
    /// Policy ID (SRC-803)
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: ClaimStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Related claim IDs (for split claims, etc.)
    pub related_claims: Vec<ClaimId>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl InsuranceClaim {
    /// Generate claim ID
    pub fn generate_id(
        coverage_id: &CoverageId,
        claim_type: ClaimType,
        claimant_ref: &PartyRef,
        date_of_loss: Timestamp,
        nonce: &[u8; 32],
    ) -> ClaimId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CLAIM_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(coverage_id);
        hasher.update(&[claim_type as u8]);
        hasher.update(&claimant_ref.as_hash());
        hasher.update(&date_of_loss.to_le_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate claim commitment
    pub fn generate_commitment(
        loss_description_hash: &[u8; 32],
        loss_amount_commitment: Option<&[u8; 32]>,
        documentation_hash: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CLAIM_COMMITMENT_SEP);
        hasher.update(loss_description_hash);
        if let Some(lac) = loss_amount_commitment {
            hasher.update(lac);
        }
        if let Some(dh) = documentation_hash {
            hasher.update(dh);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if claim is open
    pub fn is_open(&self) -> bool {
        matches!(
            self.status,
            ClaimStatus::Filed
                | ClaimStatus::Acknowledged
                | ClaimStatus::UnderInvestigation
                | ClaimStatus::PendingDocumentation
                | ClaimStatus::InReview
                | ClaimStatus::Reopened
                | ClaimStatus::InLitigation
                | ClaimStatus::SubrogationPending
        )
    }

    /// Check if claim is resolved
    pub fn is_resolved(&self) -> bool {
        matches!(
            self.status,
            ClaimStatus::Approved
                | ClaimStatus::PartiallyApproved
                | ClaimStatus::Denied
                | ClaimStatus::Paid
                | ClaimStatus::Closed
                | ClaimStatus::Withdrawn
        )
    }
}

// =============================================================================
// SRC-866: 86X Proof Profiles
// =============================================================================

/// Proof profile types for SRC-86X
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PropertyProofProfile {
    /// Prove ownership of asset
    OwnershipProof = 0,
    /// Prove asset is unencumbered (or encumbrance status)
    EncumbranceStatus = 1,
    /// Prove coverage exists
    CoverageExists = 2,
    /// Prove coverage is in force
    CoverageInForce = 3,
    /// Prove claim status
    ClaimStatus = 4,
    /// Prove title event occurred
    TitleEventOccurred = 5,
    /// Prove asset type
    AssetTypeProof = 6,
    /// Prove no liens of type
    NoLiensOfType = 7,
}

/// Proof type (SRC-806 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PropertyProofType {
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

/// SRC-866 Property Proof Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyProofEnvelope {
    /// Proof identifier
    pub proof_id: ProofId,
    /// Proof profile being proven
    pub profile: PropertyProofProfile,
    /// Profile version string (e.g., "property.ownership.v1")
    pub profile_id: String,
    /// Policy IDs that were checked
    pub policy_ids: Vec<PolicyId>,
    /// Public inputs to the proof
    pub public_inputs: Vec<u8>,
    /// The proof data
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: PropertyProofType,
    /// Subject nullifier (for revocation checking)
    pub subject_nullifier: [u8; 32],
    /// When proof was generated
    pub generated_at: Timestamp,
    /// When proof expires
    pub expires_at: Timestamp,
}

impl PropertyProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile: PropertyProofProfile,
        subject_nullifier: &[u8; 32],
        policy_ids: &[PolicyId],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROPERTY_PROOF_DOMAIN_SEP);
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

/// SRC-86X Operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PropertyOperation {
    // SRC-861: Asset Anchor (0-9)
    AnchorAsset = 0,
    UpdateAsset = 1,
    TransferAsset = 2,
    MergeAssets = 3,
    SubdivideAsset = 4,
    DeregisterAsset = 5,

    // SRC-862: Title Events (10-19)
    RecordTitleEvent = 10,
    UpdateTitleEvent = 11,
    SupersedeTitleEvent = 12,
    VoidTitleEvent = 13,

    // SRC-863: Encumbrances (20-29)
    RecordEncumbrance = 20,
    UpdateEncumbrance = 21,
    SubordinateEncumbrance = 22,
    ReleaseEncumbrance = 23,
    ForecloseEncumbrance = 24,

    // SRC-864: Coverage (30-39)
    IssueCoverage = 30,
    UpdateCoverage = 31,
    RenewCoverage = 32,
    CancelCoverage = 33,
    SuspendCoverage = 34,
    ReinstateCoverage = 35,

    // SRC-865: Claims (40-49)
    FileClaim = 40,
    UpdateClaim = 41,
    ApproveClaim = 42,
    DenyClaim = 43,
    PayClaim = 44,
    CloseClaim = 45,
    ReopenClaim = 46,
    WithdrawClaim = 47,

    // SRC-866: Proof Operations (50-59)
    SubmitProof = 50,
    VerifyProof = 51,
}

/// Transaction data for SRC-86X operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyTxData {
    pub operation: PropertyOperation,
    pub data: Vec<u8>,
}

// =============================================================================
// Events
// =============================================================================

/// SRC-86X Events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyEvent {
    // SRC-861 Events
    AssetAnchored {
        asset_id: AssetId,
        asset_type: AssetType,
        jurisdiction: String,
        timestamp: Timestamp,
    },
    AssetUpdated {
        asset_id: AssetId,
        new_status: AssetStatus,
        timestamp: Timestamp,
    },
    AssetTransferred {
        asset_id: AssetId,
        from_ref_hash: [u8; 32],
        to_ref_hash: [u8; 32],
        timestamp: Timestamp,
    },

    // SRC-862 Events
    TitleEventRecorded {
        event_id: TitleEventId,
        asset_id: AssetId,
        event_type: TitleEventType,
        timestamp: Timestamp,
    },
    TitleEventSuperseded {
        old_event_id: TitleEventId,
        new_event_id: TitleEventId,
        timestamp: Timestamp,
    },

    // SRC-863 Events
    EncumbranceRecorded {
        encumbrance_id: EncumbranceId,
        asset_id: AssetId,
        encumbrance_type: EncumbranceType,
        priority: PriorityPosition,
        timestamp: Timestamp,
    },
    EncumbranceReleased {
        encumbrance_id: EncumbranceId,
        asset_id: AssetId,
        timestamp: Timestamp,
    },
    EncumbranceForeclosed {
        encumbrance_id: EncumbranceId,
        asset_id: AssetId,
        timestamp: Timestamp,
    },

    // SRC-864 Events
    CoverageIssued {
        coverage_id: CoverageId,
        asset_id: AssetId,
        coverage_type: CoverageType,
        effective_from: Timestamp,
        expiry: Timestamp,
        timestamp: Timestamp,
    },
    CoverageStatusUpdated {
        coverage_id: CoverageId,
        new_status: CoverageStatus,
        timestamp: Timestamp,
    },

    // SRC-865 Events
    ClaimFiled {
        claim_id: ClaimId,
        coverage_id: CoverageId,
        claim_type: ClaimType,
        date_of_loss: Timestamp,
        timestamp: Timestamp,
    },
    ClaimStatusUpdated {
        claim_id: ClaimId,
        new_status: ClaimStatus,
        timestamp: Timestamp,
    },
    ClaimPaid {
        claim_id: ClaimId,
        amount_commitment: [u8; 32],
        timestamp: Timestamp,
    },

    // SRC-866 Events
    PropertyProofSubmitted {
        proof_id: ProofId,
        profile: PropertyProofProfile,
        timestamp: Timestamp,
    },
    PropertyProofVerified {
        proof_id: ProofId,
        valid: bool,
        timestamp: Timestamp,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_id_generation() {
        let issuer = Address::new([1u8; 20]);
        let commitment = [2u8; 32];
        let nonce = [3u8; 32];

        let id = AssetAnchor::generate_id(
            &issuer,
            &commitment,
            AssetType::SingleFamilyResidence,
            "US-CA-LA",
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);

        // Same inputs = same ID
        let id2 = AssetAnchor::generate_id(
            &issuer,
            &commitment,
            AssetType::SingleFamilyResidence,
            "US-CA-LA",
            &nonce,
        );
        assert_eq!(id, id2);

        // Different asset type = different ID
        let id3 = AssetAnchor::generate_id(
            &issuer,
            &commitment,
            AssetType::Commercial,
            "US-CA-LA",
            &nonce,
        );
        assert_ne!(id, id3);
    }

    #[test]
    fn test_asset_commitment() {
        let details = b"property details here";
        let commitment = AssetAnchor::generate_commitment(details, None, None);
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_title_event_id() {
        let asset_id = [1u8; 32];
        let issuer = Address::new([2u8; 20]);
        let nonce = [3u8; 32];

        let id = TitleEvent::generate_id(
            &asset_id,
            TitleEventType::DeedRecorded,
            &issuer,
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_encumbrance_active() {
        let encumbrance = Encumbrance {
            encumbrance_id: [1u8; 32],
            asset_id: [2u8; 32],
            encumbrance_type: EncumbranceType::FirstMortgage,
            encumbrance_commitment: [3u8; 32],
            holder_ref: PartyRef::Commitment([4u8; 32]),
            obligor_ref: Some(PartyRef::Commitment([5u8; 32])),
            priority: PriorityPosition::First,
            amount_commitment: Some([6u8; 32]),
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([7u8; 20]),
            issuer_class: PropertyIssuerClass::MortgageLender,
            policy_id: [8u8; 32],
            revocation_ref: None,
            status: EncumbranceStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            agreement_id: None,
            attachments: vec![],
        };

        assert!(!encumbrance.is_active(500));  // Before effective
        assert!(encumbrance.is_active(1500)); // During validity
        assert!(!encumbrance.is_active(2500)); // After expiry
    }

    #[test]
    fn test_coverage_in_force() {
        let coverage = InsuranceCoverage {
            coverage_id: [1u8; 32],
            asset_id: [2u8; 32],
            coverage_type: CoverageType::Homeowners,
            coverage_commitment: [3u8; 32],
            insurer_ref: PartyRef::Commitment([4u8; 32]),
            insured_ref: PartyRef::Commitment([5u8; 32]),
            additional_insureds: vec![],
            limit_commitment: [6u8; 32],
            deductible_commitment: None,
            premium_commitment: None,
            effective_from: 1000,
            expiry: 2000,
            issuer_address: Address::new([7u8; 20]),
            issuer_class: PropertyIssuerClass::InsuranceCompany,
            policy_id: [8u8; 32],
            revocation_ref: None,
            status: CoverageStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            prior_coverage_id: None,
            attachments: vec![],
        };

        assert!(!coverage.is_in_force(500));  // Before effective
        assert!(coverage.is_in_force(1500)); // During validity
        assert!(!coverage.is_in_force(2500)); // After expiry
    }

    #[test]
    fn test_claim_status() {
        let claim = InsuranceClaim {
            claim_id: [1u8; 32],
            coverage_id: [2u8; 32],
            asset_id: [3u8; 32],
            claim_type: ClaimType::WaterDamage,
            claim_commitment: [4u8; 32],
            claimant_ref: PartyRef::Commitment([5u8; 32]),
            date_of_loss: 900,
            date_filed: 1000,
            loss_amount_commitment: Some([6u8; 32]),
            approved_amount_commitment: None,
            paid_amount_commitment: None,
            adjuster_ref: None,
            issuer_address: Address::new([7u8; 20]),
            issuer_class: PropertyIssuerClass::InsuranceCompany,
            policy_id: [8u8; 32],
            revocation_ref: None,
            status: ClaimStatus::Filed,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            related_claims: vec![],
            attachments: vec![],
        };

        assert!(claim.is_open());
        assert!(!claim.is_resolved());
    }

    #[test]
    fn test_property_issuer_class() {
        assert!(PropertyIssuerClass::LandRegistry.is_official());
        assert!(PropertyIssuerClass::MotorVehicleDept.is_official());
        assert!(!PropertyIssuerClass::TitleCompany.is_official());

        assert!(PropertyIssuerClass::TitleCompany.is_lowkey());
        assert!(PropertyIssuerClass::MortgageLender.is_lowkey());
        assert!(!PropertyIssuerClass::LandRegistry.is_lowkey());
    }

    #[test]
    fn test_property_proof_id() {
        let nullifier = [1u8; 32];
        let policies = vec![[2u8; 32], [3u8; 32]];
        let nonce = [4u8; 32];

        let id = PropertyProofEnvelope::generate_id(
            PropertyProofProfile::OwnershipProof,
            &nullifier,
            &policies,
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }
}
