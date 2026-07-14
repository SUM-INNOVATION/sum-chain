//! SRC-85X Court & Legal Process, Government Benefits Domain
//!
//! Privacy-first infrastructure for:
//! - SRC-851: Case/Docket Anchor
//! - SRC-852: Legal Process Events
//! - SRC-853: Court Orders/Judgments
//! - SRC-854: Government Benefit Determinations
//! - SRC-855: 85X Proof Profiles

use serde::{Deserialize, Serialize};
use crate::{Address, BlockHeight, Timestamp};
use crate::agreement::AttachmentRef;

// =============================================================================
// Type Aliases
// =============================================================================

/// Unique case identifier
pub type CaseId = [u8; 32];
/// Legal process event identifier
pub type ProcessEventId = [u8; 32];
/// Court order identifier
pub type OrderId = [u8; 32];
/// Benefit determination identifier
pub type BenefitId = [u8; 32];
/// Policy identifier (SRC-803 compatible)
pub type PolicyId = [u8; 32];
/// Proof identifier (SRC-806 compatible)
pub type ProofId = [u8; 32];
/// Subject identifier (SRC-801 compatible)
pub type SubjectId = [u8; 32];

// =============================================================================
// Domain Separators (for deterministic hashing)
// =============================================================================

pub const CASE_DOMAIN_SEP: &[u8] = b"SRC851-CASE:";
pub const CASE_COMMITMENT_SEP: &[u8] = b"SRC851-COMMITMENT:v1:";
pub const PROCESS_EVENT_DOMAIN_SEP: &[u8] = b"SRC852-EVENT:";
pub const EVENT_COMMITMENT_SEP: &[u8] = b"SRC852-COMMITMENT:v1:";
pub const ORDER_DOMAIN_SEP: &[u8] = b"SRC853-ORDER:";
pub const ORDER_COMMITMENT_SEP: &[u8] = b"SRC853-COMMITMENT:v1:";
pub const BENEFIT_DOMAIN_SEP: &[u8] = b"SRC854-BENEFIT:";
pub const DETERMINATION_COMMITMENT_SEP: &[u8] = b"SRC854-DETERMINATION:v1:";
pub const LEGAL_PROOF_DOMAIN_SEP: &[u8] = b"SRC855-PROOF:";

// =============================================================================
// SRC-851: Case/Docket Anchor
// =============================================================================

/// Case type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaseType {
    /// Civil litigation
    Civil = 0,
    /// Criminal proceeding
    Criminal = 1,
    /// Administrative proceeding
    Administrative = 2,
    /// Family law
    Family = 3,
    /// Probate/Estate
    Probate = 4,
    /// Bankruptcy
    Bankruptcy = 5,
    /// Small claims
    SmallClaims = 6,
    /// Arbitration
    Arbitration = 7,
    /// Mediation
    Mediation = 8,
    /// Regulatory
    Regulatory = 9,
    /// Tax court
    TaxCourt = 10,
    /// Immigration
    Immigration = 11,
    /// Other
    Other = 255,
}

/// Case status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaseStatus {
    /// Case filed
    Filed = 0,
    /// Case active/pending
    Active = 1,
    /// Case stayed
    Stayed = 2,
    /// Case closed
    Closed = 3,
    /// Case dismissed
    Dismissed = 4,
    /// Case settled
    Settled = 5,
    /// Case consolidated
    Consolidated = 6,
    /// Case transferred
    Transferred = 7,
    /// Case on appeal
    OnAppeal = 8,
    /// Case sealed
    Sealed = 9,
}

/// Issuer class for legal process (SRC-802 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum LegalIssuerClass {
    /// Court system (official)
    CourtSystem = 0,
    /// Government agency (official)
    GovernmentAgency = 1,
    /// Tribunal
    Tribunal = 2,
    /// Arbitration body
    ArbitrationBody = 3,
    /// Law firm (Phase 1 - higher risk)
    LawFirm = 10,
    /// Notary (Phase 1 - higher risk)
    Notary = 11,
    /// Auditor (Phase 1 - higher risk)
    Auditor = 12,
    /// Legal aid organization
    LegalAid = 13,
    /// Process server
    ProcessServer = 14,
    /// Court reporter
    CourtReporter = 15,
    /// Guardian ad litem
    GuardianAdLitem = 16,
    /// Mediator
    Mediator = 17,
    /// Other authorized
    Other = 255,
}

impl LegalIssuerClass {
    /// Check if this is an official (Phase 2) issuer
    pub fn is_official(&self) -> bool {
        matches!(self, Self::CourtSystem | Self::GovernmentAgency | Self::Tribunal)
    }

    /// Check if this is a Phase 1 (lowkey) issuer
    pub fn is_lowkey(&self) -> bool {
        matches!(
            self,
            Self::LawFirm
                | Self::Notary
                | Self::Auditor
                | Self::LegalAid
                | Self::ProcessServer
        )
    }
}

/// SRC-851 Case/Docket Anchor
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseAnchor {
    /// Unique case identifier
    pub case_id: CaseId,
    /// BLAKE3 commitment of case details
    pub case_commitment: [u8; 32],
    /// Jurisdiction code (e.g., "US-NY-SDNY", "UK-EWHC")
    pub jurisdiction_code: String,
    /// Case type
    pub case_type: Option<CaseType>,
    /// Optional public reference (only if user opts in)
    pub public_reference: Option<String>,
    /// Policy ID governing this case
    pub policy_id: PolicyId,
    /// Issuer class that created this
    pub issuer_class: LegalIssuerClass,
    /// Issuer address
    pub issuer_address: Address,
    /// Current status
    pub status: CaseStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when anchored
    pub anchored_at_height: BlockHeight,
    /// Related case IDs (e.g., for appeals, consolidation)
    pub related_cases: Vec<CaseId>,
}

impl CaseAnchor {
    /// Generate deterministic case ID
    pub fn generate_id(
        issuer: &Address,
        case_commitment: &[u8; 32],
        jurisdiction: &str,
        nonce: &[u8; 32],
    ) -> CaseId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CASE_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(issuer.as_ref());
        hasher.update(case_commitment);
        hasher.update(jurisdiction.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate case commitment from case details
    pub fn generate_commitment(
        case_number: &str,
        parties_commitment: &[u8; 32],
        filing_date: Timestamp,
        additional_data: Option<&[u8]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CASE_COMMITMENT_SEP);
        hasher.update(case_number.as_bytes());
        hasher.update(parties_commitment);
        hasher.update(&filing_date.to_le_bytes());
        if let Some(data) = additional_data {
            hasher.update(data);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-852: Legal Process Events
// =============================================================================

/// Legal process event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProcessEventType {
    // Filing Events (0-9)
    /// Initial complaint/petition filed
    Filed = 0,
    /// Answer/response filed
    AnswerFiled = 1,
    /// Motion filed
    MotionFiled = 2,
    /// Amendment filed
    AmendmentFiled = 3,
    /// Discovery filed
    DiscoveryFiled = 4,
    /// Appeal filed
    AppealFiled = 5,

    // Service Events (10-19)
    /// Summons served
    Served = 10,
    /// Notice delivered
    NoticeDelivered = 11,
    /// Subpoena served
    SubpoenaServed = 12,
    /// Publication completed
    PublicationCompleted = 13,

    // Hearing Events (20-29)
    /// Hearing scheduled
    HearingScheduled = 20,
    /// Hearing held
    HearingHeld = 21,
    /// Hearing continued
    HearingContinued = 22,
    /// Hearing cancelled
    HearingCancelled = 23,
    /// Trial started
    TrialStarted = 24,
    /// Trial concluded
    TrialConcluded = 25,

    // Order Events (30-39)
    /// Order issued
    OrderIssued = 30,
    /// Judgment entered
    JudgmentEntered = 31,
    /// Ruling issued
    RulingIssued = 32,
    /// Verdict rendered
    VerdictRendered = 33,

    // Status Events (40-49)
    /// Case stayed
    CaseStayed = 40,
    /// Stay lifted
    StayLifted = 41,
    /// Case sealed
    CaseSealed = 42,
    /// Case unsealed
    CaseUnsealed = 43,
    /// Case dismissed
    CaseDismissed = 44,
    /// Case settled
    CaseSettled = 45,
    /// Case closed
    CaseClosed = 46,
    /// Case reopened
    CaseReopened = 47,

    // Other Events (50-59)
    /// Evidence admitted
    EvidenceAdmitted = 50,
    /// Witness testimony
    WitnessTestimony = 51,
    /// Expert opinion
    ExpertOpinion = 52,
    /// Mediation completed
    MediationCompleted = 53,
    /// Settlement conference
    SettlementConference = 54,

    /// Other event
    Other = 255,
}

/// Event status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProcessEventStatus {
    /// Event recorded
    Recorded = 0,
    /// Event superseded by later event
    Superseded = 1,
    /// Event revoked/withdrawn
    Revoked = 2,
    /// Event corrected
    Corrected = 3,
}

/// SRC-852 Legal Process Event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Unique event identifier
    pub event_id: ProcessEventId,
    /// Case this event belongs to
    pub case_id: CaseId,
    /// Event type
    pub event_type: ProcessEventType,
    /// BLAKE3 commitment of event details
    pub event_commitment: [u8; 32],
    /// Issuer (must satisfy policy)
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: LegalIssuerClass,
    /// Event time window (start)
    pub event_time_start: Option<Timestamp>,
    /// Event time window (end)
    pub event_time_end: Option<Timestamp>,
    /// Attachments (encrypted references)
    pub attachments: Vec<AttachmentRef>,
    /// Policy ID for this event
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Status
    pub status: ProcessEventStatus,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Supersedes event ID (if this corrects/updates another)
    pub supersedes: Option<ProcessEventId>,
}

impl ProcessEvent {
    /// Generate event ID
    pub fn generate_id(
        case_id: &CaseId,
        event_type: ProcessEventType,
        issuer: &Address,
        nonce: &[u8; 32],
    ) -> ProcessEventId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PROCESS_EVENT_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(case_id);
        hasher.update(&[event_type as u8]);
        hasher.update(issuer.as_ref());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate event commitment
    pub fn generate_commitment(
        event_details: &[u8],
        timestamp: Timestamp,
        participants_commitment: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EVENT_COMMITMENT_SEP);
        hasher.update(event_details);
        hasher.update(&timestamp.to_le_bytes());
        if let Some(pc) = participants_commitment {
            hasher.update(pc);
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-853: Court Order/Judgment
// =============================================================================

/// Order type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OrderType {
    // Preliminary Orders (0-9)
    /// Temporary restraining order
    Tro = 0,
    /// Preliminary injunction
    PreliminaryInjunction = 1,
    /// Protective order
    ProtectiveOrder = 2,
    /// Discovery order
    DiscoveryOrder = 3,
    /// Scheduling order
    SchedulingOrder = 4,

    // Judgment Types (10-19)
    /// Default judgment
    DefaultJudgment = 10,
    /// Summary judgment
    SummaryJudgment = 11,
    /// Final judgment
    FinalJudgment = 12,
    /// Consent judgment
    ConsentJudgment = 13,
    /// Declaratory judgment
    DeclaratoryJudgment = 14,

    // Injunctions (20-29)
    /// Permanent injunction
    PermanentInjunction = 20,
    /// Mandatory injunction
    MandatoryInjunction = 21,
    /// Prohibitory injunction
    ProhibitoryInjunction = 22,

    // Financial Orders (30-39)
    /// Money judgment
    MoneyJudgment = 30,
    /// Garnishment order
    GarnishmentOrder = 31,
    /// Attachment order
    AttachmentOrder = 32,
    /// Restitution order
    RestitutionOrder = 33,
    /// Cost order
    CostOrder = 34,

    // Family/Probate (40-49)
    /// Child custody order
    ChildCustodyOrder = 40,
    /// Support order
    SupportOrder = 41,
    /// Divorce decree
    DivorceDecree = 42,
    /// Probate order
    ProbateOrder = 43,
    /// Guardianship order
    GuardianshipOrder = 44,

    // Criminal (50-59)
    /// Sentence
    Sentence = 50,
    /// Bail order
    BailOrder = 51,
    /// Probation order
    ProbationOrder = 52,
    /// Expungement order
    ExpungementOrder = 53,

    // Administrative (60-69)
    /// Administrative order
    AdministrativeOrder = 60,
    /// Consent decree
    ConsentDecree = 61,
    /// Compliance order
    ComplianceOrder = 62,

    /// Other order type
    Other = 255,
}

/// Order status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OrderStatus {
    /// Order is active
    Active = 0,
    /// Order is stayed pending appeal
    Stayed = 1,
    /// Order has been vacated
    Vacated = 2,
    /// Order superseded by another
    Superseded = 3,
    /// Order has expired
    Expired = 4,
    /// Order fully satisfied/completed
    Satisfied = 5,
    /// Order modified
    Modified = 6,
    /// Order reversed on appeal
    Reversed = 7,
    /// Order affirmed on appeal
    Affirmed = 8,
}

/// SRC-853 Court Order/Judgment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CourtOrder {
    /// Unique order identifier
    pub order_id: OrderId,
    /// Case this order belongs to
    pub case_id: CaseId,
    /// Order type
    pub order_type: OrderType,
    /// BLAKE3 commitment of order content
    pub order_commitment: [u8; 32],
    /// Issuer address (court/tribunal)
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: LegalIssuerClass,
    /// Current status
    pub status: OrderStatus,
    /// When order becomes effective
    pub effective_from: Timestamp,
    /// When order expires (if applicable)
    pub expiry: Option<Timestamp>,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Revocation/expiry reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last status change
    pub updated_at: Timestamp,
    /// Block height when issued
    pub issued_at_height: BlockHeight,
    /// Supersedes another order (if any)
    pub supersedes_order_id: Option<OrderId>,
    /// Attachments
    pub attachments: Vec<AttachmentRef>,
}

impl CourtOrder {
    /// Generate order ID
    pub fn generate_id(
        case_id: &CaseId,
        order_type: OrderType,
        issuer: &Address,
        nonce: &[u8; 32],
    ) -> OrderId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ORDER_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(case_id);
        hasher.update(&[order_type as u8]);
        hasher.update(issuer.as_ref());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate order commitment
    pub fn generate_commitment(
        order_text_hash: &[u8; 32],
        obligations_hash: Option<&[u8; 32]>,
        parties_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ORDER_COMMITMENT_SEP);
        hasher.update(order_text_hash);
        if let Some(oh) = obligations_hash {
            hasher.update(oh);
        }
        hasher.update(parties_hash);
        *hasher.finalize().as_bytes()
    }

    /// Check if order is currently in effect
    pub fn is_in_effect(&self, current_time: Timestamp) -> bool {
        if !matches!(self.status, OrderStatus::Active | OrderStatus::Affirmed) {
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
// SRC-854: Government Benefit Determination
// =============================================================================

/// Benefit type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BenefitType {
    // Social Security (0-9)
    SocialSecurityRetirement = 0,
    SocialSecurityDisability = 1,
    SupplementalSecurityIncome = 2,
    SurvivorsInsurance = 3,

    // Healthcare (10-19)
    Medicare = 10,
    Medicaid = 11,
    ChildHealthInsurance = 12,
    VeteranHealthcare = 13,

    // Employment (20-29)
    UnemploymentInsurance = 20,
    WorkersCompensation = 21,
    DisabilityInsurance = 22,
    TrainingBenefit = 23,

    // Food/Housing (30-39)
    FoodAssistance = 30,
    HousingAssistance = 31,
    EnergyAssistance = 32,
    ChildNutrition = 33,

    // Family (40-49)
    ChildTaxCredit = 40,
    EarnedIncomeCredit = 41,
    ChildcareAssistance = 42,
    FamilyLeave = 43,

    // Education (50-59)
    EducationGrant = 50,
    StudentLoanSubsidy = 51,
    TuitionAssistance = 52,

    // Veterans (60-69)
    VeteranPension = 60,
    VeteranDisability = 61,
    GiBill = 62,
    VeteranHousing = 63,

    // Immigration (70-79)
    RefugeeAssistance = 70,
    AsylumSupport = 71,

    /// Other benefit
    Other = 255,
}

/// Benefit determination status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BenefitStatus {
    /// Eligibility determination in progress
    Pending = 0,
    /// Determined eligible
    Eligible = 1,
    /// Benefit approved
    Approved = 2,
    /// Benefit denied
    Denied = 3,
    /// Benefit terminated
    Terminated = 4,
    /// Benefit suspended
    Suspended = 5,
    /// Under review/appeal
    UnderReview = 6,
    /// Benefit expired
    Expired = 7,
    /// Benefit reduced
    Reduced = 8,
    /// Benefit increased
    Increased = 9,
}

/// SRC-854 Government Benefit Determination
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenefitDetermination {
    /// Unique benefit identifier
    pub benefit_id: BenefitId,
    /// Benefit type
    pub benefit_type: BenefitType,
    /// Jurisdiction code
    pub jurisdiction_code: String,
    /// Current status
    pub status: BenefitStatus,
    /// BLAKE3 commitment of determination details
    pub determination_commitment: [u8; 32],
    /// Subject nullifier (for privacy-preserving verification)
    pub subject_nullifier: [u8; 32],
    /// Issuer address (government agency)
    pub issuer_address: Address,
    /// Issuer class
    pub issuer_class: LegalIssuerClass,
    /// When determination becomes valid
    pub valid_from: Timestamp,
    /// When determination expires
    pub expiry: Option<Timestamp>,
    /// Policy ID
    pub policy_id: PolicyId,
    /// Revocation reference (SRC-805 compatible)
    pub revocation_ref: Option<[u8; 32]>,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last update timestamp
    pub updated_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
    /// Supersedes another determination (if any)
    pub supersedes: Option<BenefitId>,
}

impl BenefitDetermination {
    /// Generate benefit ID
    pub fn generate_id(
        subject_nullifier: &[u8; 32],
        benefit_type: BenefitType,
        jurisdiction: &str,
        nonce: &[u8; 32],
    ) -> BenefitId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BENEFIT_DOMAIN_SEP);
        hasher.update(b":v1:");
        hasher.update(subject_nullifier);
        hasher.update(&[benefit_type as u8]);
        hasher.update(jurisdiction.as_bytes());
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Generate determination commitment
    pub fn generate_commitment(
        eligibility_criteria_hash: &[u8; 32],
        amount_commitment: Option<&[u8; 32]>,
        conditions_hash: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DETERMINATION_COMMITMENT_SEP);
        hasher.update(eligibility_criteria_hash);
        if let Some(ac) = amount_commitment {
            hasher.update(ac);
        }
        if let Some(ch) = conditions_hash {
            hasher.update(ch);
        }
        *hasher.finalize().as_bytes()
    }

    /// Check if benefit is currently valid
    pub fn is_valid(&self, current_time: Timestamp) -> bool {
        if !matches!(
            self.status,
            BenefitStatus::Eligible | BenefitStatus::Approved | BenefitStatus::Increased
        ) {
            return false;
        }
        if current_time < self.valid_from {
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
// SRC-855: 85X Proof Profiles
// =============================================================================

/// Proof profile types for SRC-85X
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LegalProofProfile {
    /// Prove active order of specified type exists
    ActiveOrderOfType = 0,
    /// Prove benefit is approved
    BenefitApproved = 1,
    /// Prove case event exists (policy-gated)
    CaseEventExists = 2,
    /// Prove case status
    CaseStatus = 3,
    /// Prove order was issued by valid issuer
    OrderIssuedByValid = 4,
    /// Prove benefit eligibility without revealing details
    BenefitEligible = 5,
    /// Prove no active orders of type (for clearance checks)
    NoActiveOrderOfType = 6,
}

/// Proof type (SRC-806 compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LegalProofType {
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

/// SRC-855 Legal Proof Envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalProofEnvelope {
    /// Proof identifier
    pub proof_id: ProofId,
    /// Proof profile being proven
    pub profile: LegalProofProfile,
    /// Profile version string (e.g., "legal.active_order.v1")
    pub profile_id: String,
    /// Policy IDs that were checked
    pub policy_ids: Vec<PolicyId>,
    /// Public inputs to the proof
    pub public_inputs: Vec<u8>,
    /// The proof data
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: LegalProofType,
    /// Subject nullifier (for revocation checking)
    pub subject_nullifier: [u8; 32],
    /// When proof was generated
    pub generated_at: Timestamp,
    /// When proof expires
    pub expires_at: Timestamp,
}

impl LegalProofEnvelope {
    /// Generate proof ID
    pub fn generate_id(
        profile: LegalProofProfile,
        subject_nullifier: &[u8; 32],
        policy_ids: &[PolicyId],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(LEGAL_PROOF_DOMAIN_SEP);
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

/// SRC-85X Operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LegalOperation {
    // SRC-851: Case Anchor (0-9)
    AnchorCase = 0,
    UpdateCase = 1,
    CloseCase = 2,
    SealCase = 3,
    UnsealCase = 4,
    ConsolidateCase = 5,
    TransferCase = 6,

    // SRC-852: Process Events (10-19)
    RecordEvent = 10,
    UpdateEvent = 11,
    SupersedeEvent = 12,
    RevokeEvent = 13,

    // SRC-853: Orders (20-29)
    IssueOrder = 20,
    UpdateOrderStatus = 21,
    StayOrder = 22,
    VacateOrder = 23,
    SupersedeOrder = 24,
    ModifyOrder = 25,

    // SRC-854: Benefits (30-39)
    DetermineBenefit = 30,
    UpdateBenefitStatus = 31,
    TerminateBenefit = 32,
    SuspendBenefit = 33,
    ReinstateBenefit = 34,

    // SRC-855: Proof Operations (40-49)
    SubmitProof = 40,
    VerifyProof = 41,
}

/// Transaction data for SRC-85X operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalTxData {
    pub operation: LegalOperation,
    pub data: Vec<u8>,
    /// Token recipient address - the owner of the minted token
    pub recipient: crate::Address,
}

// =============================================================================
// Events
// =============================================================================

/// SRC-85X Events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegalEvent {
    // SRC-851 Events
    CaseAnchored {
        case_id: CaseId,
        jurisdiction: String,
        case_commitment: [u8; 32],
        timestamp: Timestamp,
    },
    CaseUpdated {
        case_id: CaseId,
        new_status: CaseStatus,
        timestamp: Timestamp,
    },
    CaseSealed {
        case_id: CaseId,
        timestamp: Timestamp,
    },
    CaseUnsealed {
        case_id: CaseId,
        timestamp: Timestamp,
    },

    // SRC-852 Events
    CaseEventRecorded {
        case_id: CaseId,
        event_type: ProcessEventType,
        issuer: Address,
        event_hash: [u8; 32],
        timestamp: Timestamp,
    },
    CaseEventSuperseded {
        old_event_id: ProcessEventId,
        new_event_id: ProcessEventId,
        timestamp: Timestamp,
    },

    // SRC-853 Events
    OrderIssued {
        order_id: OrderId,
        case_id: CaseId,
        order_type: OrderType,
        status: OrderStatus,
        timestamp: Timestamp,
    },
    OrderStatusUpdated {
        order_id: OrderId,
        new_status: OrderStatus,
        timestamp: Timestamp,
    },

    // SRC-854 Events
    BenefitDetermined {
        benefit_id: BenefitId,
        benefit_type: BenefitType,
        status: BenefitStatus,
        jurisdiction: String,
        timestamp: Timestamp,
    },
    BenefitUpdated {
        benefit_id: BenefitId,
        new_status: BenefitStatus,
        timestamp: Timestamp,
    },

    // SRC-855 Events
    LegalProofSubmitted {
        proof_id: ProofId,
        profile: LegalProofProfile,
        timestamp: Timestamp,
    },
    LegalProofVerified {
        proof_id: ProofId,
        valid: bool,
        timestamp: Timestamp,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_id_generation() {
        let issuer = Address::new([1u8; 20]);
        let commitment = [2u8; 32];
        let nonce = [3u8; 32];

        let id = CaseAnchor::generate_id(&issuer, &commitment, "US-NY", &nonce);
        assert_ne!(id, [0u8; 32]);

        // Same inputs = same ID
        let id2 = CaseAnchor::generate_id(&issuer, &commitment, "US-NY", &nonce);
        assert_eq!(id, id2);

        // Different jurisdiction = different ID
        let id3 = CaseAnchor::generate_id(&issuer, &commitment, "US-CA", &nonce);
        assert_ne!(id, id3);
    }

    #[test]
    fn test_case_commitment() {
        let parties = [1u8; 32];
        let commitment = CaseAnchor::generate_commitment("2024-CV-12345", &parties, 1000, None);
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_process_event_id() {
        let case_id = [1u8; 32];
        let issuer = Address::new([2u8; 20]);
        let nonce = [3u8; 32];

        let id = ProcessEvent::generate_id(&case_id, ProcessEventType::Filed, &issuer, &nonce);
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_order_id_generation() {
        let case_id = [1u8; 32];
        let issuer = Address::new([2u8; 20]);
        let nonce = [3u8; 32];

        let id = CourtOrder::generate_id(&case_id, OrderType::FinalJudgment, &issuer, &nonce);
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_order_in_effect() {
        let order = CourtOrder {
            order_id: [1u8; 32],
            case_id: [2u8; 32],
            order_type: OrderType::FinalJudgment,
            order_commitment: [3u8; 32],
            issuer_address: Address::new([4u8; 20]),
            issuer_class: LegalIssuerClass::CourtSystem,
            status: OrderStatus::Active,
            effective_from: 1000,
            expiry: Some(2000),
            policy_id: [5u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            supersedes_order_id: None,
            attachments: vec![],
        };

        assert!(!order.is_in_effect(500));  // Before effective
        assert!(order.is_in_effect(1500)); // During validity
        assert!(!order.is_in_effect(2500)); // After expiry
    }

    #[test]
    fn test_benefit_id_generation() {
        let nullifier = [1u8; 32];
        let nonce = [2u8; 32];

        let id = BenefitDetermination::generate_id(
            &nullifier,
            BenefitType::SocialSecurityRetirement,
            "US",
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_benefit_validity() {
        let benefit = BenefitDetermination {
            benefit_id: [1u8; 32],
            benefit_type: BenefitType::Medicare,
            jurisdiction_code: "US".to_string(),
            status: BenefitStatus::Approved,
            determination_commitment: [2u8; 32],
            subject_nullifier: [3u8; 32],
            issuer_address: Address::new([4u8; 20]),
            issuer_class: LegalIssuerClass::GovernmentAgency,
            valid_from: 1000,
            expiry: None,
            policy_id: [5u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            supersedes: None,
        };

        assert!(!benefit.is_valid(500));   // Before valid_from
        assert!(benefit.is_valid(1500));   // After valid_from, no expiry
    }

    #[test]
    fn test_legal_issuer_class() {
        assert!(LegalIssuerClass::CourtSystem.is_official());
        assert!(LegalIssuerClass::GovernmentAgency.is_official());
        assert!(!LegalIssuerClass::LawFirm.is_official());

        assert!(LegalIssuerClass::LawFirm.is_lowkey());
        assert!(LegalIssuerClass::Notary.is_lowkey());
        assert!(!LegalIssuerClass::CourtSystem.is_lowkey());
    }

    #[test]
    fn test_legal_proof_id() {
        let nullifier = [1u8; 32];
        let policies = vec![[2u8; 32], [3u8; 32]];
        let nonce = [4u8; 32];

        let id = LegalProofEnvelope::generate_id(
            LegalProofProfile::BenefitApproved,
            &nullifier,
            &policies,
            &nonce,
        );
        assert_ne!(id, [0u8; 32]);
    }
}
