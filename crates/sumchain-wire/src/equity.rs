//! SRC-83X Business, Governance & Equity Domain Standards
//!
//! This module implements the business and equity domain family:
//! - SRC-831: Entity Identity Profile
//! - SRC-832: Governance Action Standard
//! - SRC-833: Equity Token Standard
//! - SRC-834: Equity Controller Standard
//! - SRC-835: Corporate Actions Interface
//! - SRC-836: Ownership Proof Profiles
//!
//! Design Principles:
//! - Controller-gated operations
//! - Policy-driven governance
//! - Privacy-preserving ownership proofs
//! - Fungible equity with transfer restrictions

use serde::{Deserialize, Serialize};

use crate::{Address, BlockHeight, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Subject ID (32-byte hash, SRC-801)
pub type SubjectId = [u8; 32];

/// Policy ID (32-byte hash, SRC-803)
pub type PolicyId = [u8; 32];

/// Proof ID (32-byte hash)
pub type ProofId = [u8; 32];

/// Class ID for equity tokens
pub type ClassId = [u8; 32];

/// Action ID for governance actions
pub type ActionId = [u8; 32];

/// Snapshot ID
pub type SnapshotId = [u8; 32];

// =============================================================================
// Domain Separation Constants
// =============================================================================

/// Domain separator for entity profiles
pub const ENTITY_DOMAIN_SEP: &[u8] = b"SRC831-ENTITY:";

/// Domain separator for governance actions
pub const GOVERNANCE_ACTION_DOMAIN_SEP: &[u8] = b"SRC832-ACTION:";

/// Domain separator for equity token IDs
pub const EQUITY_TOKEN_DOMAIN_SEP: &[u8] = b"SRC833-TOKEN:";

/// Domain separator for corporate actions
pub const CORPORATE_ACTION_DOMAIN_SEP: &[u8] = b"SRC835-CORP-ACTION:";

/// Domain separator for ownership proofs
pub const OWNERSHIP_PROOF_DOMAIN_SEP: &[u8] = b"SRC836-PROOF:";

/// Domain separator for snapshots
pub const SNAPSHOT_DOMAIN_SEP: &[u8] = b"SRC835-SNAPSHOT:";

// =============================================================================
// SRC-831: Entity Identity Profile
// =============================================================================

/// Organization types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OrgType {
    /// Corporation (C-Corp, S-Corp)
    Corporation = 0,
    /// Limited Liability Company
    LLC = 1,
    /// Partnership (LP, LLP, GP)
    Partnership = 2,
    /// Decentralized Autonomous Organization
    DAO = 3,
    /// Foundation / Non-profit
    Foundation = 4,
    /// Trust
    Trust = 5,
    /// Cooperative
    Cooperative = 6,
    /// Other
    Other = 255,
}

impl OrgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OrgType::Corporation),
            1 => Some(OrgType::LLC),
            2 => Some(OrgType::Partnership),
            3 => Some(OrgType::DAO),
            4 => Some(OrgType::Foundation),
            5 => Some(OrgType::Trust),
            6 => Some(OrgType::Cooperative),
            255 => Some(OrgType::Other),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            OrgType::Corporation => "Corporation",
            OrgType::LLC => "LLC",
            OrgType::Partnership => "Partnership",
            OrgType::DAO => "DAO",
            OrgType::Foundation => "Foundation",
            OrgType::Trust => "Trust",
            OrgType::Cooperative => "Cooperative",
            OrgType::Other => "Other",
        }
    }
}

/// Controller model hints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControllerModel {
    /// Single authorized signer
    SingleSigner = 0,
    /// Multi-signature (M-of-N)
    MultiSig = 1,
    /// Board of directors
    BoardMultiSig = 2,
    /// Token-weighted governance
    TokenGovernance = 3,
    /// Hybrid (board + token)
    Hybrid = 4,
}

impl ControllerModel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ControllerModel::SingleSigner),
            1 => Some(ControllerModel::MultiSig),
            2 => Some(ControllerModel::BoardMultiSig),
            3 => Some(ControllerModel::TokenGovernance),
            4 => Some(ControllerModel::Hybrid),
            _ => None,
        }
    }
}

/// Entity service types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EntityServiceType {
    /// Corporate mailbox
    Mailbox = 0,
    /// Investor relations
    InvestorRelations = 1,
    /// Transfer agent
    TransferAgent = 2,
    /// Cap table management
    CapTable = 3,
    /// Governance portal
    Governance = 4,
    /// Website
    Website = 5,
    /// Other
    Other = 255,
}

/// Entity service endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityService {
    /// Service ID
    pub service_id: String,
    /// Service type
    pub service_type: EntityServiceType,
    /// Endpoint URI
    pub endpoint: String,
}

/// Entity status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EntityStatus {
    /// Active and in good standing
    Active = 0,
    /// Pending registration
    Pending = 1,
    /// Suspended
    Suspended = 2,
    /// Dissolved
    Dissolved = 3,
}

impl EntityStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EntityStatus::Active),
            1 => Some(EntityStatus::Pending),
            2 => Some(EntityStatus::Suspended),
            3 => Some(EntityStatus::Dissolved),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, EntityStatus::Active)
    }
}

/// Entity Identity Profile (SRC-831)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityProfile {
    /// Subject ID (SRC-801)
    pub subject_id: SubjectId,
    /// Organization type
    pub org_type: OrgType,
    /// Legal name commitment (BLAKE3 hash, not actual name)
    pub name_commitment: [u8; 32],
    /// Jurisdiction of incorporation (ISO 3166-1/2)
    pub jurisdiction: Option<String>,
    /// Registration number commitment (if applicable)
    pub registration_commitment: Option<[u8; 32]>,
    /// Controller model hint
    pub controller_model: ControllerModel,
    /// Controller address(es)
    pub controllers: Vec<Address>,
    /// Multi-sig threshold (if applicable)
    pub multisig_threshold: Option<u8>,
    /// Service endpoints
    pub services: Vec<EntityService>,
    /// Profile metadata hash
    pub metadata_hash: [u8; 32],
    /// Created timestamp
    pub created_at: Timestamp,
    /// Updated timestamp
    pub updated_at: Timestamp,
    /// Status
    pub status: EntityStatus,
}

impl EntityProfile {
    /// Generate subject ID for an entity
    pub fn generate_subject_id(
        org_type: OrgType,
        name_commitment: &[u8; 32],
        nonce: &[u8; 32],
    ) -> SubjectId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENTITY_DOMAIN_SEP);
        hasher.update(&[org_type as u8]);
        hasher.update(b":v1:");
        hasher.update(name_commitment);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Check if controller can act
    pub fn can_controller_act(&self, controller: &Address) -> bool {
        self.status.is_active() && self.controllers.contains(controller)
    }
}

// =============================================================================
// SRC-832: Governance Action Standard
// =============================================================================

/// Governance action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum GovernanceActionType {
    // Board actions (100-199)
    /// Board resolution approved
    BoardResolutionApproved = 100,
    /// Board meeting minutes recorded
    BoardMeetingMinutes = 101,
    /// Board member appointed
    BoardMemberAppointed = 102,
    /// Board member removed
    BoardMemberRemoved = 103,

    // Shareholder actions (200-299)
    /// Shareholder vote approved
    ShareholderVoteApproved = 200,
    /// Annual meeting held
    AnnualMeetingHeld = 201,
    /// Special meeting held
    SpecialMeetingHeld = 202,
    /// Written consent obtained
    WrittenConsentObtained = 203,

    // Officer actions (300-399)
    /// Officer appointed
    OfficerAppointment = 300,
    /// Officer removed
    OfficerRemoval = 301,
    /// Officer role changed
    OfficerRoleChanged = 302,

    // Authority actions (400-499)
    /// Signing authority granted
    SigningAuthorityGrant = 400,
    /// Signing authority revoked
    SigningAuthorityRevoke = 401,
    /// Authority scope changed
    AuthorityScopeChanged = 402,

    // Corporate structure (500-599)
    /// Bylaws amended
    BylawsAmended = 500,
    /// Articles amended
    ArticlesAmended = 501,
    /// Registered agent changed
    RegisteredAgentChanged = 502,
}

impl GovernanceActionType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            100 => Some(GovernanceActionType::BoardResolutionApproved),
            101 => Some(GovernanceActionType::BoardMeetingMinutes),
            102 => Some(GovernanceActionType::BoardMemberAppointed),
            103 => Some(GovernanceActionType::BoardMemberRemoved),
            200 => Some(GovernanceActionType::ShareholderVoteApproved),
            201 => Some(GovernanceActionType::AnnualMeetingHeld),
            202 => Some(GovernanceActionType::SpecialMeetingHeld),
            203 => Some(GovernanceActionType::WrittenConsentObtained),
            300 => Some(GovernanceActionType::OfficerAppointment),
            301 => Some(GovernanceActionType::OfficerRemoval),
            302 => Some(GovernanceActionType::OfficerRoleChanged),
            400 => Some(GovernanceActionType::SigningAuthorityGrant),
            401 => Some(GovernanceActionType::SigningAuthorityRevoke),
            402 => Some(GovernanceActionType::AuthorityScopeChanged),
            500 => Some(GovernanceActionType::BylawsAmended),
            501 => Some(GovernanceActionType::ArticlesAmended),
            502 => Some(GovernanceActionType::RegisteredAgentChanged),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            GovernanceActionType::BoardResolutionApproved => "Board Resolution Approved",
            GovernanceActionType::BoardMeetingMinutes => "Board Meeting Minutes",
            GovernanceActionType::BoardMemberAppointed => "Board Member Appointed",
            GovernanceActionType::BoardMemberRemoved => "Board Member Removed",
            GovernanceActionType::ShareholderVoteApproved => "Shareholder Vote Approved",
            GovernanceActionType::AnnualMeetingHeld => "Annual Meeting Held",
            GovernanceActionType::SpecialMeetingHeld => "Special Meeting Held",
            GovernanceActionType::WrittenConsentObtained => "Written Consent Obtained",
            GovernanceActionType::OfficerAppointment => "Officer Appointment",
            GovernanceActionType::OfficerRemoval => "Officer Removal",
            GovernanceActionType::OfficerRoleChanged => "Officer Role Changed",
            GovernanceActionType::SigningAuthorityGrant => "Signing Authority Grant",
            GovernanceActionType::SigningAuthorityRevoke => "Signing Authority Revoke",
            GovernanceActionType::AuthorityScopeChanged => "Authority Scope Changed",
            GovernanceActionType::BylawsAmended => "Bylaws Amended",
            GovernanceActionType::ArticlesAmended => "Articles Amended",
            GovernanceActionType::RegisteredAgentChanged => "Registered Agent Changed",
        }
    }
}

/// Attachment content types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttachmentContentType {
    Resolution = 0,
    Minutes = 1,
    Agreement = 2,
    Certificate = 3,
    Other = 255,
}

/// Governance attachment reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceAttachment {
    /// Attachment hash (BLAKE3)
    pub hash: [u8; 32],
    /// Size in bytes
    pub size: u64,
    /// Storage hint
    pub hint_uri: Option<String>,
    /// Content type
    pub content_type: AttachmentContentType,
}

/// Governance action status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum GovernanceActionStatus {
    /// Pending approvals
    Pending = 0,
    /// Approved and effective
    Approved = 1,
    /// Executed
    Executed = 2,
    /// Expired
    Expired = 3,
    /// Revoked/Cancelled
    Revoked = 4,
}

impl GovernanceActionStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(GovernanceActionStatus::Pending),
            1 => Some(GovernanceActionStatus::Approved),
            2 => Some(GovernanceActionStatus::Executed),
            3 => Some(GovernanceActionStatus::Expired),
            4 => Some(GovernanceActionStatus::Revoked),
            _ => None,
        }
    }

    pub fn is_effective(&self) -> bool {
        matches!(self, GovernanceActionStatus::Approved | GovernanceActionStatus::Executed)
    }
}

/// Governance action record (SRC-832)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceAction {
    /// Unique action ID
    pub action_id: ActionId,
    /// Organization subject (SRC-801)
    pub org_subject: SubjectId,
    /// Action type
    pub action_type: GovernanceActionType,
    /// Policy ID that authorized this action (SRC-803)
    pub policy_id: PolicyId,
    /// Action commitment (BLAKE3 hash of resolution/minutes/terms)
    pub action_commitment: [u8; 32],
    /// Effective timestamp
    pub effective_at: Timestamp,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: Timestamp,
    /// Optional attachments reference
    pub attachments: Option<GovernanceAttachment>,
    /// Approvers (addresses that signed/approved)
    pub approvers: Vec<Address>,
    /// Required threshold
    pub required_threshold: u8,
    /// Action status
    pub status: GovernanceActionStatus,
    /// Created timestamp
    pub created_at: Timestamp,
    /// Block height when recorded
    pub recorded_at_height: BlockHeight,
}

impl GovernanceAction {
    /// Generate action ID
    pub fn generate_action_id(
        org_subject: &SubjectId,
        action_type: GovernanceActionType,
        action_commitment: &[u8; 32],
        nonce: &[u8; 32],
    ) -> ActionId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GOVERNANCE_ACTION_DOMAIN_SEP);
        hasher.update(&(action_type as u16).to_be_bytes());
        hasher.update(b":v1:");
        hasher.update(org_subject);
        hasher.update(action_commitment);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }

    /// Check if threshold is met
    pub fn is_threshold_met(&self) -> bool {
        self.approvers.len() >= self.required_threshold as usize
    }

    /// Check if action is expired
    pub fn is_expired(&self, current_time: Timestamp) -> bool {
        self.expires_at > 0 && current_time > self.expires_at
    }
}

// =============================================================================
// SRC-833: Equity Token Standard
// =============================================================================

/// Share class type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ShareClassType {
    /// Common shares
    Common = 0,
    /// Preferred shares
    Preferred = 1,
}

impl ShareClassType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ShareClassType::Common),
            1 => Some(ShareClassType::Preferred),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ShareClassType::Common => "Common",
            ShareClassType::Preferred => "Preferred",
        }
    }
}

/// Token status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenStatus {
    Active = 0,
    Paused = 1,
    Retired = 2,
}

impl TokenStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TokenStatus::Active),
            1 => Some(TokenStatus::Paused),
            2 => Some(TokenStatus::Retired),
            _ => None,
        }
    }

    pub fn is_transferable(&self) -> bool {
        matches!(self, TokenStatus::Active)
    }
}

/// Equity token (SRC-833)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquityToken {
    /// Issuer subject (SRC-801 org)
    pub issuer_subject: SubjectId,
    /// Share class ID
    pub class_id: ClassId,
    /// Share class type
    pub share_class_type: ShareClassType,
    /// Class name
    pub name: String,
    /// Symbol
    pub symbol: String,
    /// Authorized shares cap
    pub authorized_shares: u128,
    /// Issued shares (currently outstanding)
    pub issued_shares: u128,
    /// Votes per share (0 = non-voting)
    pub votes_per_share: u64,
    /// Economic rights hash (required)
    pub economic_rights_hash: [u8; 32],
    /// Liquidation preference hash (optional)
    pub liquidation_preference_hash: Option<[u8; 32]>,
    /// Dividend policy hash (optional)
    pub dividend_policy_hash: Option<[u8; 32]>,
    /// Conversion rules hash (optional)
    pub conversion_rules_hash: Option<[u8; 32]>,
    /// Controller address (mandatory)
    pub controller: Address,
    /// Par value (if applicable)
    pub par_value: Option<u128>,
    /// Created timestamp
    pub created_at: Timestamp,
    /// Updated timestamp
    pub updated_at: Timestamp,
    /// Status
    pub status: TokenStatus,
}

impl EquityToken {
    /// Generate class ID
    pub fn generate_class_id(
        issuer_subject: &SubjectId,
        name: &str,
        share_class_type: ShareClassType,
    ) -> ClassId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(EQUITY_TOKEN_DOMAIN_SEP);
        hasher.update(issuer_subject);
        hasher.update(b":");
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(&[share_class_type as u8]);
        *hasher.finalize().as_bytes()
    }

    /// Check if can mint more shares
    pub fn can_mint(&self, amount: u128) -> bool {
        self.status.is_transferable()
            && self.issued_shares.saturating_add(amount) <= self.authorized_shares
    }

    /// Get remaining authorized shares
    pub fn remaining_authorized(&self) -> u128 {
        self.authorized_shares.saturating_sub(self.issued_shares)
    }
}

// =============================================================================
// SRC-834: Equity Controller Standard
// =============================================================================

/// Transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransferType {
    /// Regular transfer
    Regular = 0,
    /// Transfer via corporate action
    CorporateAction = 1,
    /// Transfer via conversion
    Conversion = 2,
    /// Transfer via redemption
    Redemption = 3,
}

/// Transfer context for controller hooks
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferContext {
    /// Transaction initiator
    pub initiator: Address,
    /// Optional governance action reference
    pub governance_action: Option<ActionId>,
    /// Transfer type
    pub transfer_type: TransferType,
    /// Additional data
    pub data: Vec<u8>,
}

/// Issuance type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IssuanceType {
    /// Initial issuance
    Initial = 0,
    /// Follow-on offering
    FollowOn = 1,
    /// Stock option exercise
    OptionExercise = 2,
    /// Warrant exercise
    WarrantExercise = 3,
    /// Conversion
    Conversion = 4,
    /// Stock split
    StockSplit = 5,
    /// Stock dividend
    StockDividend = 6,
}

/// Issuance reference for minting
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRef {
    /// Governance action authorizing issuance
    pub governance_action_id: ActionId,
    /// Issuance type
    pub issuance_type: IssuanceType,
    /// Price per share (if applicable)
    pub price_per_share: Option<u128>,
    /// Round identifier
    pub round_id: Option<String>,
}

/// Burn reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BurnReason {
    /// Redemption
    Redemption = 0,
    /// Buyback
    Buyback = 1,
    /// Cancellation
    Cancellation = 2,
    /// Reverse split
    ReverseSplit = 3,
    /// Conversion
    Conversion = 4,
}

/// Controller error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum ControllerErrorCode {
    // Transfer errors (1000-1099)
    SenderNotWhitelisted = 1000,
    RecipientNotWhitelisted = 1001,
    SenderInLockup = 1002,
    TradingWindowClosed = 1003,
    TransferAmountExceedsLimit = 1004,
    InsufficientBalance = 1005,

    // Mint errors (1100-1199)
    ExceedsAuthorizedCap = 1100,
    UnauthorizedMinter = 1101,
    InvalidIssuanceRef = 1102,

    // Burn errors (1200-1299)
    UnauthorizedBurner = 1200,
    InvalidBurnReason = 1201,

    // Corporate action errors (1300-1399)
    InvalidCorporateAction = 1300,
    InsufficientApprovals = 1301,
    ActionNotAuthorized = 1302,

    // General errors (9000-9999)
    PolicyCheckFailed = 9000,
    ControllerPaused = 9001,
    Unknown = 9999,
}

/// Lockup information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockupInfo {
    /// Amount locked
    pub amount: u128,
    /// Unlock timestamp
    pub unlock_at: Timestamp,
    /// Vesting schedule (if applicable)
    pub vesting: Option<VestingSchedule>,
}

/// Vesting schedule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Total amount
    pub total_amount: u128,
    /// Already vested
    pub vested_amount: u128,
    /// Vesting start
    pub start_at: Timestamp,
    /// Cliff duration (seconds)
    pub cliff_duration: u64,
    /// Total duration (seconds)
    pub total_duration: u64,
    /// Vesting interval (seconds)
    pub interval: u64,
}

impl VestingSchedule {
    /// Calculate vested amount at a given time
    pub fn vested_at(&self, current_time: Timestamp) -> u128 {
        if current_time < self.start_at {
            return 0;
        }

        let elapsed = current_time.saturating_sub(self.start_at);

        // Check cliff
        if elapsed < self.cliff_duration {
            return 0;
        }

        // Check if fully vested
        if elapsed >= self.total_duration {
            return self.total_amount;
        }

        // Calculate linear vesting
        let vesting_elapsed = elapsed.saturating_sub(self.cliff_duration);
        let vesting_duration = self.total_duration.saturating_sub(self.cliff_duration);

        if vesting_duration == 0 {
            return self.total_amount;
        }

        // Calculate based on intervals
        let intervals_passed = vesting_elapsed / self.interval;
        let total_intervals = vesting_duration / self.interval;

        if total_intervals == 0 {
            return self.total_amount;
        }

        (self.total_amount * intervals_passed as u128) / total_intervals as u128
    }
}

/// Trading window
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradingWindow {
    /// Window start (day of month, 1-31)
    pub start_day: u8,
    /// Window end (day of month, 1-31)
    pub end_day: u8,
    /// Allowed months (bitmask, bit 0 = Jan)
    pub months: u16,
}

impl TradingWindow {
    /// Check if trading is allowed at given day of month and month
    pub fn is_open(&self, day: u8, month: u8) -> bool {
        // Check month (0-indexed in bitmask)
        if !(1..=12).contains(&month) {
            return false;
        }
        let month_allowed = (self.months & (1 << (month - 1))) != 0;
        if !month_allowed {
            return false;
        }

        // Check day range
        if self.start_day <= self.end_day {
            day >= self.start_day && day <= self.end_day
        } else {
            // Wraps around month boundary
            day >= self.start_day || day <= self.end_day
        }
    }
}

/// Equity controller configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquityControllerConfig {
    /// Controller address
    pub address: Address,
    /// Whitelist enabled
    pub whitelist_enabled: bool,
    /// Trading windows
    pub trading_windows: Vec<TradingWindow>,
    /// Transfer limit per transaction (0 = no limit)
    pub transfer_limit: u128,
    /// Policy ID for governance
    pub governance_policy_id: PolicyId,
    /// Is paused
    pub paused: bool,
}

// =============================================================================
// SRC-835: Corporate Actions Interface
// =============================================================================

/// Corporate action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CorporateActionType {
    /// Stock split
    StockSplit = 0,
    /// Reverse split
    ReverseSplit = 1,
    /// Cash dividend declaration
    DividendDeclare = 2,
    /// Cash dividend distribution
    DividendDistribute = 3,
    /// Stock dividend
    StockDividend = 4,
    /// Buyback/redemption
    Buyback = 5,
    /// Conversion
    Conversion = 6,
    /// Record date snapshot
    RecordDateSnapshot = 7,
    /// Rights offering
    RightsOffering = 8,
}

impl CorporateActionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CorporateActionType::StockSplit),
            1 => Some(CorporateActionType::ReverseSplit),
            2 => Some(CorporateActionType::DividendDeclare),
            3 => Some(CorporateActionType::DividendDistribute),
            4 => Some(CorporateActionType::StockDividend),
            5 => Some(CorporateActionType::Buyback),
            6 => Some(CorporateActionType::Conversion),
            7 => Some(CorporateActionType::RecordDateSnapshot),
            8 => Some(CorporateActionType::RightsOffering),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CorporateActionType::StockSplit => "Stock Split",
            CorporateActionType::ReverseSplit => "Reverse Split",
            CorporateActionType::DividendDeclare => "Dividend Declaration",
            CorporateActionType::DividendDistribute => "Dividend Distribution",
            CorporateActionType::StockDividend => "Stock Dividend",
            CorporateActionType::Buyback => "Buyback",
            CorporateActionType::Conversion => "Conversion",
            CorporateActionType::RecordDateSnapshot => "Record Date Snapshot",
            CorporateActionType::RightsOffering => "Rights Offering",
        }
    }
}

/// Rounding mode for splits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RoundingMode {
    /// Round down (truncate)
    Down = 0,
    /// Round up
    Up = 1,
    /// Round to nearest
    Nearest = 2,
}

/// Stock split parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StockSplitParams {
    /// Split ratio numerator
    pub ratio_numerator: u64,
    /// Split ratio denominator
    pub ratio_denominator: u64,
}

impl StockSplitParams {
    /// Apply split to a balance
    pub fn apply(&self, balance: u128) -> u128 {
        (balance * self.ratio_numerator as u128) / self.ratio_denominator as u128
    }
}

/// Reverse split parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseSplitParams {
    /// Ratio numerator
    pub ratio_numerator: u64,
    /// Ratio denominator
    pub ratio_denominator: u64,
    /// Rounding mode
    pub rounding: RoundingMode,
    /// Cash out fractional shares
    pub cash_out_fractional: bool,
    /// Price per fractional share (if cashing out)
    pub fractional_price: Option<u128>,
}

impl ReverseSplitParams {
    /// Apply reverse split to a balance
    pub fn apply(&self, balance: u128) -> (u128, u128) {
        let numerator = self.ratio_numerator as u128;
        let denominator = self.ratio_denominator as u128;

        let new_balance = (balance * numerator) / denominator;
        let remainder = balance - (new_balance * denominator) / numerator;

        let fractional = match self.rounding {
            RoundingMode::Down => 0,
            RoundingMode::Up => {
                if remainder > 0 {
                    1
                } else {
                    0
                }
            }
            RoundingMode::Nearest => {
                if remainder * 2 >= denominator / numerator {
                    1
                } else {
                    0
                }
            }
        };

        (new_balance + fractional, remainder)
    }
}

/// Dividend currency
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DividendCurrency {
    /// Native chain token
    Native,
    /// SRC-20 token
    Token(Address),
}

/// Dividend declaration parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DividendDeclareParams {
    /// Dividend per share (in smallest currency unit)
    pub amount_per_share: u128,
    /// Currency
    pub currency: DividendCurrency,
    /// Record date
    pub record_date: Timestamp,
    /// Payment date
    pub payment_date: Timestamp,
}

/// Distribution method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DistributionMethod {
    /// Pro-rata by snapshot
    ProRataSnapshot = 0,
    /// Pro-rata by current balance
    ProRataCurrent = 1,
}

/// Dividend distribution parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DividendDistributeParams {
    /// Declaration action ID
    pub declaration_id: ActionId,
    /// Snapshot ID (from record date)
    pub snapshot_id: SnapshotId,
    /// Distribution method
    pub method: DistributionMethod,
}

/// Conversion parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversionParams {
    /// Source class ID
    pub from_class_id: ClassId,
    /// Target class ID
    pub to_class_id: ClassId,
    /// Conversion ratio
    pub conversion_ratio: u64,
    /// Holder address (for single-holder conversion)
    pub holder: Option<Address>,
}

/// Snapshot purpose
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SnapshotPurpose {
    /// Dividend distribution
    Dividend = 0,
    /// Voting record
    Voting = 1,
    /// Rights offering
    Rights = 2,
    /// Other
    Other = 255,
}

/// Record snapshot parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSnapshotParams {
    /// Purpose of snapshot
    pub purpose: SnapshotPurpose,
    /// Reference (e.g., proposal ID)
    pub reference: Option<[u8; 32]>,
}

/// Corporate action status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CorporateActionStatus {
    Proposed = 0,
    Approved = 1,
    Executing = 2,
    Completed = 3,
    Cancelled = 4,
    Failed = 5,
}

/// Corporate action parameters (union type)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorporateActionParams {
    StockSplit(StockSplitParams),
    ReverseSplit(ReverseSplitParams),
    DividendDeclare(DividendDeclareParams),
    DividendDistribute(DividendDistributeParams),
    Conversion(ConversionParams),
    RecordSnapshot(RecordSnapshotParams),
}

/// Corporate action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorporateAction {
    /// Unique action ID
    pub action_id: ActionId,
    /// Share class ID
    pub class_id: ClassId,
    /// Action type
    pub action_type: CorporateActionType,
    /// Action parameters
    pub params: CorporateActionParams,
    /// Record date (for snapshots)
    pub record_date: Option<Timestamp>,
    /// Execution date
    pub execution_date: Timestamp,
    /// Governance action authorizing this
    pub governance_action_id: ActionId,
    /// Status
    pub status: CorporateActionStatus,
    /// Created timestamp
    pub created_at: Timestamp,
    /// Executed timestamp
    pub executed_at: Option<Timestamp>,
}

impl CorporateAction {
    /// Generate corporate action ID
    pub fn generate_action_id(
        class_id: &ClassId,
        action_type: CorporateActionType,
        governance_action_id: &ActionId,
    ) -> ActionId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CORPORATE_ACTION_DOMAIN_SEP);
        hasher.update(&[action_type as u8]);
        hasher.update(b":v1:");
        hasher.update(class_id);
        hasher.update(governance_action_id);
        *hasher.finalize().as_bytes()
    }
}

/// Ownership snapshot
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipSnapshot {
    /// Snapshot ID
    pub snapshot_id: SnapshotId,
    /// Class ID
    pub class_id: ClassId,
    /// Snapshot timestamp
    pub timestamp: Timestamp,
    /// Block height
    pub block_height: BlockHeight,
    /// Total supply at snapshot
    pub total_supply: u128,
    /// Holder count
    pub holder_count: u64,
    /// Merkle root of balances
    pub balances_root: [u8; 32],
    /// Purpose
    pub purpose: SnapshotPurpose,
    /// Reference
    pub reference: Option<[u8; 32]>,
}

impl OwnershipSnapshot {
    /// Generate snapshot ID
    pub fn generate_snapshot_id(
        class_id: &ClassId,
        purpose: SnapshotPurpose,
        timestamp: Timestamp,
    ) -> SnapshotId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAPSHOT_DOMAIN_SEP);
        hasher.update(&[purpose as u8]);
        hasher.update(b":v1:");
        hasher.update(class_id);
        hasher.update(&timestamp.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// SRC-836: Ownership Proof Profiles
// =============================================================================

/// Ownership proof profile identifiers
pub mod proof_profiles {
    pub const EQUITY_PROVE_MEMBERSHIP: &str = "equity.prove_membership.v1";
    pub const EQUITY_PROVE_OWNERSHIP_THRESHOLD: &str = "equity.prove_ownership_threshold.v1";
    pub const EQUITY_PROVE_VOTING_POWER: &str = "equity.prove_voting_power.v1";
}

/// Public inputs for membership proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Share class ID
    pub class_id: ClassId,
    /// Membership commitment
    pub membership_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Public inputs for ownership threshold proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipThresholdPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Share class ID
    pub class_id: ClassId,
    /// Minimum shares threshold
    pub threshold: u128,
    /// Ownership commitment
    pub ownership_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Public inputs for voting power proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingPowerPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Voting power threshold
    pub threshold: u128,
    /// Reference to proposal or record date
    pub reference: Option<[u8; 32]>,
    /// Voting power commitment
    pub voting_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: Timestamp,
}

/// Ownership proof type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OwnershipProofType {
    /// Mock proof (for testing)
    Mock = 0,
    /// Groth16 ZK proof
    Groth16 = 1,
    /// PLONK ZK proof
    Plonk = 2,
    /// Signature-based attestation
    Signature = 3,
}

/// Ownership proof envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipProofEnvelope {
    /// Proof ID
    pub proof_id: ProofId,
    /// Profile ID
    pub profile_id: String,
    /// Policy ID(s) this proof satisfies
    pub policy_ids: Vec<PolicyId>,
    /// Public inputs (serialized JSON)
    pub public_inputs: Vec<u8>,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Proof type
    pub proof_type: OwnershipProofType,
    /// Subject nullifier
    pub subject_nullifier: [u8; 32],
    /// Generated timestamp
    pub generated_at: Timestamp,
    /// Expires at
    pub expires_at: Timestamp,
}

impl OwnershipProofEnvelope {
    /// Generate proof ID
    pub fn generate_proof_id(
        profile_id: &str,
        public_inputs: &[u8],
        nonce: &[u8; 32],
    ) -> ProofId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(OWNERSHIP_PROOF_DOMAIN_SEP);
        hasher.update(profile_id.as_bytes());
        hasher.update(b":");
        hasher.update(public_inputs);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Equity Domain Operations
// =============================================================================

/// Equity domain operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EquityOperation {
    // Entity operations (0-9)
    /// Create entity profile
    CreateEntity = 0,
    /// Update entity profile
    UpdateEntity = 1,
    /// Add entity controller
    AddController = 2,
    /// Remove entity controller
    RemoveController = 3,

    // Governance operations (10-19)
    /// Propose governance action
    ProposeAction = 10,
    /// Approve governance action
    ApproveAction = 11,
    /// Execute governance action
    ExecuteAction = 12,
    /// Revoke governance action
    RevokeAction = 13,

    // Token operations (20-29)
    /// Create equity token
    CreateToken = 20,
    /// Update token
    UpdateToken = 21,
    /// Pause token
    PauseToken = 22,
    /// Unpause token
    UnpauseToken = 23,

    // Transfer operations (30-39)
    /// Transfer shares
    Transfer = 30,
    /// Approve spender
    Approve = 31,
    /// Transfer from
    TransferFrom = 32,

    // Mint/Burn operations (40-49)
    /// Mint shares
    Mint = 40,
    /// Burn shares
    Burn = 41,

    // Controller operations (50-59)
    /// Update controller
    UpdateController = 50,
    /// Add to whitelist
    AddToWhitelist = 51,
    /// Remove from whitelist
    RemoveFromWhitelist = 52,
    /// Set lockup
    SetLockup = 53,

    // Corporate actions (60-69)
    /// Execute stock split
    ExecuteStockSplit = 60,
    /// Execute reverse split
    ExecuteReverseSplit = 61,
    /// Declare dividend
    DeclareDividend = 62,
    /// Distribute dividend
    DistributeDividend = 63,
    /// Execute conversion
    ExecuteConversion = 64,
    /// Take snapshot
    TakeSnapshot = 65,

    // Proof operations (70-79)
    /// Verify ownership proof
    VerifyOwnershipProof = 70,
}

impl EquityOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(EquityOperation::CreateEntity),
            1 => Some(EquityOperation::UpdateEntity),
            2 => Some(EquityOperation::AddController),
            3 => Some(EquityOperation::RemoveController),
            10 => Some(EquityOperation::ProposeAction),
            11 => Some(EquityOperation::ApproveAction),
            12 => Some(EquityOperation::ExecuteAction),
            13 => Some(EquityOperation::RevokeAction),
            20 => Some(EquityOperation::CreateToken),
            21 => Some(EquityOperation::UpdateToken),
            22 => Some(EquityOperation::PauseToken),
            23 => Some(EquityOperation::UnpauseToken),
            30 => Some(EquityOperation::Transfer),
            31 => Some(EquityOperation::Approve),
            32 => Some(EquityOperation::TransferFrom),
            40 => Some(EquityOperation::Mint),
            41 => Some(EquityOperation::Burn),
            50 => Some(EquityOperation::UpdateController),
            51 => Some(EquityOperation::AddToWhitelist),
            52 => Some(EquityOperation::RemoveFromWhitelist),
            53 => Some(EquityOperation::SetLockup),
            60 => Some(EquityOperation::ExecuteStockSplit),
            61 => Some(EquityOperation::ExecuteReverseSplit),
            62 => Some(EquityOperation::DeclareDividend),
            63 => Some(EquityOperation::DistributeDividend),
            64 => Some(EquityOperation::ExecuteConversion),
            65 => Some(EquityOperation::TakeSnapshot),
            70 => Some(EquityOperation::VerifyOwnershipProof),
            _ => None,
        }
    }
}

/// Equity domain transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquityTxData {
    /// Operation type
    pub operation: EquityOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
    /// Token recipient address - the owner of the minted token
    pub recipient: crate::Address,
}

// =============================================================================
// Equity Domain Events
// =============================================================================

/// Entity profile events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityProfileEvent {
    EntityCreated {
        subject_id: SubjectId,
        org_type: OrgType,
        controller_model: ControllerModel,
    },
    EntityUpdated {
        subject_id: SubjectId,
    },
    ControllerChanged {
        subject_id: SubjectId,
        old_controllers: Vec<Address>,
        new_controllers: Vec<Address>,
    },
    EntityStatusChanged {
        subject_id: SubjectId,
        old_status: EntityStatus,
        new_status: EntityStatus,
    },
}

/// Governance action events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceActionEvent {
    ActionProposed {
        action_id: ActionId,
        org_subject: SubjectId,
        action_type: GovernanceActionType,
        policy_id: PolicyId,
        proposer: Address,
    },
    ActionApproved {
        action_id: ActionId,
        approver: Address,
        approval_count: u32,
        threshold: u32,
    },
    ActionExecuted {
        action_id: ActionId,
        executor: Address,
        effective_at: Timestamp,
    },
    ActionRevoked {
        action_id: ActionId,
        revoker: Address,
    },
}

/// Equity token events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquityTokenEvent {
    TokenCreated {
        issuer_subject: SubjectId,
        class_id: ClassId,
        share_class_type: ShareClassType,
        authorized_shares: u128,
    },
    Transfer {
        class_id: ClassId,
        from: Address,
        to: Address,
        amount: u128,
    },
    Approval {
        class_id: ClassId,
        owner: Address,
        spender: Address,
        amount: u128,
    },
    ControllerUpdated {
        class_id: ClassId,
        old_controller: Address,
        new_controller: Address,
        governance_action_id: ActionId,
    },
    TokenPaused {
        class_id: ClassId,
    },
    TokenUnpaused {
        class_id: ClassId,
    },
}

/// Corporate action events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorporateActionEvent {
    ActionProposed {
        action_id: ActionId,
        class_id: ClassId,
        action_type: CorporateActionType,
        governance_action_id: ActionId,
    },
    ActionExecuted {
        action_id: ActionId,
        action_type: CorporateActionType,
        affected_holders: u64,
        total_shares_affected: u128,
    },
    DividendDeclared {
        declaration_id: ActionId,
        class_id: ClassId,
        amount_per_share: u128,
        record_date: Timestamp,
        payment_date: Timestamp,
    },
    DividendDistributed {
        declaration_id: ActionId,
        total_distributed: u128,
        recipient_count: u64,
    },
    SnapshotTaken {
        snapshot_id: SnapshotId,
        class_id: ClassId,
        purpose: SnapshotPurpose,
        holder_count: u64,
    },
}

/// Ownership proof events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnershipProofEvent {
    ProofVerified {
        proof_id: ProofId,
        profile_id: String,
        org_subject: SubjectId,
        verifier: Address,
        valid: bool,
    },
}

/// Combined equity event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquityEvent {
    Entity(EntityProfileEvent),
    Governance(GovernanceActionEvent),
    Token(EquityTokenEvent),
    CorporateAction(CorporateActionEvent),
    Proof(OwnershipProofEvent),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_subject_id_generation() {
        let name_commitment = [1u8; 32];
        let nonce = [2u8; 32];

        let id1 = EntityProfile::generate_subject_id(
            OrgType::Corporation,
            &name_commitment,
            &nonce,
        );
        let id2 = EntityProfile::generate_subject_id(
            OrgType::Corporation,
            &name_commitment,
            &nonce,
        );
        let id3 = EntityProfile::generate_subject_id(
            OrgType::LLC,
            &name_commitment,
            &nonce,
        );

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_governance_action_threshold() {
        let action = GovernanceAction {
            action_id: [0u8; 32],
            org_subject: [0u8; 32],
            action_type: GovernanceActionType::BoardResolutionApproved,
            policy_id: [0u8; 32],
            action_commitment: [0u8; 32],
            effective_at: 0,
            expires_at: 0,
            attachments: None,
            approvers: vec![Address::ZERO, Address::ZERO],
            required_threshold: 3,
            status: GovernanceActionStatus::Pending,
            created_at: 0,
            recorded_at_height: 0,
        };

        assert!(!action.is_threshold_met());

        let mut action2 = action.clone();
        action2.approvers.push(Address::ZERO);
        assert!(action2.is_threshold_met());
    }

    #[test]
    fn test_equity_token_mint_check() {
        let token = EquityToken {
            issuer_subject: [0u8; 32],
            class_id: [0u8; 32],
            share_class_type: ShareClassType::Common,
            name: "Common Shares".to_string(),
            symbol: "ACME".to_string(),
            authorized_shares: 1_000_000,
            issued_shares: 500_000,
            votes_per_share: 1,
            economic_rights_hash: [0u8; 32],
            liquidation_preference_hash: None,
            dividend_policy_hash: None,
            conversion_rules_hash: None,
            controller: Address::ZERO,
            par_value: None,
            created_at: 0,
            updated_at: 0,
            status: TokenStatus::Active,
        };

        assert!(token.can_mint(100_000));
        assert!(token.can_mint(500_000));
        assert!(!token.can_mint(500_001));
        assert_eq!(token.remaining_authorized(), 500_000);
    }

    #[test]
    fn test_vesting_schedule() {
        let schedule = VestingSchedule {
            total_amount: 1_000_000,
            vested_amount: 0,
            start_at: 1000,
            cliff_duration: 100,
            total_duration: 400,
            interval: 30,
        };

        // Before start
        assert_eq!(schedule.vested_at(500), 0);

        // During cliff
        assert_eq!(schedule.vested_at(1050), 0);

        // Just after cliff (at exactly cliff time, no vesting yet)
        assert_eq!(schedule.vested_at(1100), 0);
        // After first interval
        assert!(schedule.vested_at(1130) > 0);

        // At end
        assert_eq!(schedule.vested_at(1400), 1_000_000);

        // After end
        assert_eq!(schedule.vested_at(2000), 1_000_000);
    }

    #[test]
    fn test_trading_window() {
        let window = TradingWindow {
            start_day: 1,
            end_day: 10,
            months: 0b000000000101, // Jan and Mar
        };

        // January, day 5
        assert!(window.is_open(5, 1));

        // March, day 1
        assert!(window.is_open(1, 3));

        // January, day 15
        assert!(!window.is_open(15, 1));

        // February (not allowed)
        assert!(!window.is_open(5, 2));
    }

    #[test]
    fn test_stock_split_params() {
        let split = StockSplitParams {
            ratio_numerator: 2,
            ratio_denominator: 1,
        };

        assert_eq!(split.apply(100), 200);
        assert_eq!(split.apply(1), 2);
        assert_eq!(split.apply(0), 0);
    }

    #[test]
    fn test_reverse_split_params() {
        let reverse = ReverseSplitParams {
            ratio_numerator: 1,
            ratio_denominator: 10,
            rounding: RoundingMode::Down,
            cash_out_fractional: false,
            fractional_price: None,
        };

        let (new_balance, remainder) = reverse.apply(100);
        assert_eq!(new_balance, 10);
        assert_eq!(remainder, 0);

        let (new_balance2, remainder2) = reverse.apply(95);
        assert_eq!(new_balance2, 9);
        assert!(remainder2 > 0);
    }

    #[test]
    fn test_class_id_determinism() {
        let subject = [1u8; 32];

        let id1 = EquityToken::generate_class_id(&subject, "Series A", ShareClassType::Preferred);
        let id2 = EquityToken::generate_class_id(&subject, "Series A", ShareClassType::Preferred);
        let id3 = EquityToken::generate_class_id(&subject, "Series B", ShareClassType::Preferred);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_snapshot_id_determinism() {
        let class_id = [1u8; 32];
        let timestamp = 1704067200000u64;

        let id1 = OwnershipSnapshot::generate_snapshot_id(&class_id, SnapshotPurpose::Dividend, timestamp);
        let id2 = OwnershipSnapshot::generate_snapshot_id(&class_id, SnapshotPurpose::Dividend, timestamp);
        let id3 = OwnershipSnapshot::generate_snapshot_id(&class_id, SnapshotPurpose::Voting, timestamp);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }
}
