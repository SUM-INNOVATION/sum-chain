# SRC-83X: Business, Governance & Equity Domain Standards

## Abstract

SRC-83X defines a family of standards for business entities, governance actions, and equity tokens on SUM Chain. Built on the SRC-80X trust architecture, these standards enable compliant equity issuance, transfer restrictions, corporate actions, and ownership proofs without exposing cap table details.

## Design Principles

1. **Controller-Gated Operations** — All equity operations go through policy-controlled hooks
2. **Policy-Driven Governance** — Corporate actions require SRC-803 policy compliance
3. **Privacy-Preserving Ownership** — Cap tables are not public; ownership proven via SRC-806
4. **Fungible Equity** — Shares are fungible tokens with transfer restrictions
5. **Public vs Private by Policy** — Token type doesn't determine tradability; controller does

## Standard Overview

| Standard | Name | Purpose |
|----------|------|---------|
| SRC-831 | Entity Identity Profile | Organization subject profiles |
| SRC-832 | Governance Action Standard | Verifiable governance events |
| SRC-833 | Equity Token Standard | Fungible share tokens |
| SRC-834 | Equity Controller Standard | Transfer/mint/burn hooks |
| SRC-835 | Corporate Actions Interface | Stock splits, dividends, etc. |
| SRC-836 | Ownership Proof Profiles | Privacy-preserving ownership proofs |

---

# SRC-831: Entity Identity Profile

## Purpose

Defines conventions for using SRC-801 Subjects as organizations (corporations, LLCs, DAOs, foundations). An Entity Identity Profile extends the base subject with organization-specific metadata.

## Data Model

```rust
/// Organization types
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

/// Controller model hints
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

/// Entity Identity Profile (extends SRC-801 Subject)
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
    pub created_at: u64,
    /// Updated timestamp
    pub updated_at: u64,
    /// Status
    pub status: EntityStatus,
}

/// Entity service endpoint
pub struct EntityService {
    /// Service ID
    pub service_id: String,
    /// Service type
    pub service_type: EntityServiceType,
    /// Endpoint URI
    pub endpoint: String,
}

/// Entity service types
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

/// Entity status
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
```

## Operations

```rust
pub enum EntityProfileOperation {
    /// Create new entity profile
    Create = 0,
    /// Update profile metadata
    UpdateProfile = 1,
    /// Add controller
    AddController = 2,
    /// Remove controller
    RemoveController = 3,
    /// Update controller model
    UpdateControllerModel = 4,
    /// Add service endpoint
    AddService = 5,
    /// Remove service endpoint
    RemoveService = 6,
    /// Update status
    UpdateStatus = 7,
}
```

## Events

```rust
pub enum EntityProfileEvent {
    EntityCreated {
        subject_id: SubjectId,
        org_type: OrgType,
        controller_model: ControllerModel,
    },
    EntityUpdated {
        subject_id: SubjectId,
        update_type: EntityProfileOperation,
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
```

---

# SRC-832: Governance Action Standard

## Purpose

Represents governance actions as verifiable events controlled by SRC-803 policies. Actions can be proven via SRC-806 proof envelopes.

## Action Types

### V1 Action Types

```rust
/// Governance action types
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
```

## Data Model

```rust
/// Governance action record
pub struct GovernanceAction {
    /// Unique action ID
    pub action_id: [u8; 32],
    /// Organization subject (SRC-801)
    pub org_subject: SubjectId,
    /// Action type
    pub action_type: GovernanceActionType,
    /// Policy ID that authorized this action (SRC-803)
    pub policy_id: PolicyId,
    /// Action commitment (BLAKE3 hash of resolution/minutes/terms)
    pub action_commitment: [u8; 32],
    /// Effective timestamp (when action takes effect)
    pub effective_at: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: u64,
    /// Optional encrypted attachments reference
    pub attachments: Option<GovernanceAttachment>,
    /// Approvers (addresses that signed/approved)
    pub approvers: Vec<Address>,
    /// Approval threshold met
    pub threshold_met: bool,
    /// Action status
    pub status: GovernanceActionStatus,
    /// Created timestamp
    pub created_at: u64,
    /// Block height when recorded
    pub recorded_at_height: u64,
}

/// Governance attachment reference
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

/// Attachment content types
#[repr(u8)]
pub enum AttachmentContentType {
    Resolution = 0,
    Minutes = 1,
    Agreement = 2,
    Certificate = 3,
    Other = 255,
}

/// Action status
#[repr(u8)]
pub enum GovernanceActionStatus {
    /// Pending approvals
    Pending = 0,
    /// Approved and effective
    Approved = 1,
    /// Executed (for actions that require execution)
    Executed = 2,
    /// Expired
    Expired = 3,
    /// Revoked/Cancelled
    Revoked = 4,
}
```

## Policy Enforcement

All governance actions require policy compliance:

```rust
/// Governance action validation
pub trait GovernanceValidator {
    /// Validate action against policy
    fn validate_action(
        &self,
        action: &GovernanceAction,
        policy: &Policy,
        signatures: &[Signature],
    ) -> Result<ValidationResult, GovernanceError>;

    /// Check if action can be executed
    fn can_execute(
        &self,
        action: &GovernanceAction,
    ) -> Result<bool, GovernanceError>;
}
```

## Events

```rust
pub enum GovernanceEvent {
    ActionProposed {
        action_id: [u8; 32],
        org_subject: SubjectId,
        action_type: GovernanceActionType,
        policy_id: PolicyId,
        proposer: Address,
    },
    ActionApproved {
        action_id: [u8; 32],
        approver: Address,
        approval_count: u32,
        threshold: u32,
    },
    ActionExecuted {
        action_id: [u8; 32],
        executor: Address,
        effective_at: u64,
    },
    ActionRevoked {
        action_id: [u8; 32],
        revoker: Address,
        reason: Option<String>,
    },
}
```

---

# SRC-833: Equity Token Standard

## Purpose

Defines fungible equity tokens (shares) representing ownership. Transfer restrictions and tradability are controlled by the controller, not the token type itself.

## Data Model

```rust
/// Share class type
#[repr(u8)]
pub enum ShareClassType {
    /// Common shares
    Common = 0,
    /// Preferred shares
    Preferred = 1,
}

/// Equity token (share class)
pub struct EquityToken {
    /// Issuer subject (SRC-801 org)
    pub issuer_subject: SubjectId,
    /// Share class ID (unique per issuer)
    pub class_id: [u8; 32],
    /// Share class type
    pub share_class_type: ShareClassType,
    /// Class name (e.g., "Series A Preferred")
    pub name: String,
    /// Symbol (e.g., "ACME-A")
    pub symbol: String,
    /// Authorized shares cap (hard limit)
    pub authorized_shares: u128,
    /// Issued shares (currently outstanding)
    pub issued_shares: u128,
    /// Votes per share (0 = non-voting)
    pub votes_per_share: u64,
    /// Economic rights hash (required)
    pub economic_rights_hash: [u8; 32],
    /// Liquidation preference hash (optional, for preferred)
    pub liquidation_preference_hash: Option<[u8; 32]>,
    /// Dividend policy hash (optional)
    pub dividend_policy_hash: Option<[u8; 32]>,
    /// Conversion rules hash (optional, for convertible)
    pub conversion_rules_hash: Option<[u8; 32]>,
    /// Controller address (mandatory)
    pub controller: Address,
    /// Par value (if applicable, in smallest units)
    pub par_value: Option<u128>,
    /// Created timestamp
    pub created_at: u64,
    /// Status
    pub status: TokenStatus,
}

/// Token status
#[repr(u8)]
pub enum TokenStatus {
    Active = 0,
    Paused = 1,
    Retired = 2,
}
```

## Token Functions

```rust
pub trait EquityTokenInterface {
    // === View Functions ===

    /// Get token name
    fn name(&self) -> &str;

    /// Get token symbol
    fn symbol(&self) -> &str;

    /// Get total issued shares
    fn total_supply(&self) -> u128;

    /// Get authorized shares cap
    fn authorized_shares(&self) -> u128;

    /// Get balance of holder
    fn balance_of(&self, holder: &Address) -> u128;

    /// Get votes per share
    fn votes_per_share(&self) -> u64;

    /// Get voting power of holder
    fn voting_power_of(&self, holder: &Address) -> u128;

    /// Get controller address
    fn controller(&self) -> &Address;

    // === State-Changing Functions ===

    /// Transfer shares (MUST call controller hook)
    fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u128,
        context: &TransferContext,
    ) -> Result<(), EquityError>;

    /// Transfer from (with approval, MUST call controller hook)
    fn transfer_from(
        &mut self,
        spender: &Address,
        from: &Address,
        to: &Address,
        amount: u128,
        context: &TransferContext,
    ) -> Result<(), EquityError>;

    /// Mint new shares (ONLY controller)
    fn mint(
        &mut self,
        to: &Address,
        amount: u128,
        issuance_ref: &IssuanceRef,
    ) -> Result<(), EquityError>;

    /// Burn shares (ONLY controller)
    fn burn(
        &mut self,
        from: &Address,
        amount: u128,
        reason: BurnReason,
    ) -> Result<(), EquityError>;

    /// Set controller (ONLY via governance action/policy)
    fn set_controller(
        &mut self,
        new_controller: &Address,
        governance_action: &GovernanceAction,
    ) -> Result<(), EquityError>;
}

/// Transfer context for controller hooks
pub struct TransferContext {
    /// Transaction initiator
    pub initiator: Address,
    /// Optional governance action reference
    pub governance_action: Option<[u8; 32]>,
    /// Transfer type
    pub transfer_type: TransferType,
    /// Additional data
    pub data: Vec<u8>,
}

/// Transfer types
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

/// Issuance reference for minting
pub struct IssuanceRef {
    /// Governance action authorizing issuance
    pub governance_action_id: [u8; 32],
    /// Issuance type
    pub issuance_type: IssuanceType,
    /// Price per share (if applicable)
    pub price_per_share: Option<u128>,
    /// Round identifier
    pub round_id: Option<String>,
}

/// Issuance types
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
    /// Dividend (stock)
    StockDividend = 6,
}

/// Burn reasons
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
```

## Events

```rust
pub enum EquityTokenEvent {
    Transfer {
        class_id: [u8; 32],
        from: Address,
        to: Address,
        amount: u128,
    },
    Approval {
        class_id: [u8; 32],
        owner: Address,
        spender: Address,
        amount: u128,
    },
    ControllerUpdated {
        class_id: [u8; 32],
        old_controller: Address,
        new_controller: Address,
        governance_action_id: [u8; 32],
    },
    CorporateActionExecuted {
        class_id: [u8; 32],
        action_type: CorporateActionType,
        params_hash: [u8; 32],
    },
    TokenCreated {
        issuer_subject: SubjectId,
        class_id: [u8; 32],
        share_class_type: ShareClassType,
        authorized_shares: u128,
    },
    TokenPaused {
        class_id: [u8; 32],
    },
    TokenUnpaused {
        class_id: [u8; 32],
    },
}
```

---

# SRC-834: Equity Controller Standard

## Purpose

Defines the standard hook interface for enforcing transfer/mint/burn restrictions and corporate action permissions.

## Controller Interface

```rust
/// Equity controller interface
pub trait EquityController {
    // === Transfer Hooks ===

    /// Called before any transfer
    fn before_transfer(
        &self,
        token: &EquityToken,
        from: &Address,
        to: &Address,
        amount: u128,
        context: &TransferContext,
    ) -> Result<(), ControllerError>;

    /// Called after transfer completes
    fn after_transfer(
        &self,
        token: &EquityToken,
        from: &Address,
        to: &Address,
        amount: u128,
        context: &TransferContext,
    ) -> Result<(), ControllerError>;

    // === Mint/Burn Hooks ===

    /// Called before minting
    fn before_mint(
        &self,
        token: &EquityToken,
        to: &Address,
        amount: u128,
        issuance_ref: &IssuanceRef,
    ) -> Result<(), ControllerError>;

    /// Called before burning
    fn before_burn(
        &self,
        token: &EquityToken,
        from: &Address,
        amount: u128,
        reason: BurnReason,
    ) -> Result<(), ControllerError>;

    // === Corporate Action Hooks ===

    /// Validate corporate action
    fn validate_corporate_action(
        &self,
        token: &EquityToken,
        action: &CorporateAction,
    ) -> Result<(), ControllerError>;

    /// Execute corporate action
    fn execute_corporate_action(
        &self,
        token: &mut EquityToken,
        action: &CorporateAction,
    ) -> Result<CorporateActionResult, ControllerError>;

    // === Policy Queries ===

    /// Check if address is whitelisted
    fn is_whitelisted(&self, address: &Address) -> bool;

    /// Check if address is in lockup
    fn is_locked(&self, address: &Address) -> Option<LockupInfo>;

    /// Check if in trading window
    fn is_trading_window_open(&self) -> bool;

    /// Get authorized shares cap
    fn get_authorized_cap(&self, token: &EquityToken) -> u128;
}

/// Controller error with reason code
#[derive(Debug)]
pub struct ControllerError {
    pub code: ControllerErrorCode,
    pub message: String,
}

/// Controller error codes
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
```

## Standard Controller Implementation

```rust
/// Standard equity controller with basic restrictions
pub struct StandardEquityController {
    /// Controller address
    pub address: Address,
    /// Whitelist enabled
    pub whitelist_enabled: bool,
    /// Whitelisted addresses
    pub whitelist: HashSet<Address>,
    /// Lockups by address
    pub lockups: HashMap<Address, LockupInfo>,
    /// Trading windows
    pub trading_windows: Vec<TradingWindow>,
    /// Transfer limit per transaction
    pub transfer_limit: Option<u128>,
    /// Policy ID for governance
    pub governance_policy_id: PolicyId,
    /// Is paused
    pub paused: bool,
}

/// Lockup information
pub struct LockupInfo {
    /// Amount locked
    pub amount: u128,
    /// Unlock timestamp
    pub unlock_at: u64,
    /// Vesting schedule (if applicable)
    pub vesting: Option<VestingSchedule>,
}

/// Vesting schedule
pub struct VestingSchedule {
    /// Total amount
    pub total_amount: u128,
    /// Already vested
    pub vested_amount: u128,
    /// Vesting start
    pub start_at: u64,
    /// Cliff duration (seconds)
    pub cliff_duration: u64,
    /// Total duration (seconds)
    pub total_duration: u64,
    /// Vesting interval (seconds)
    pub interval: u64,
}

/// Trading window
pub struct TradingWindow {
    /// Window start (day of month, 1-31)
    pub start_day: u8,
    /// Window end (day of month, 1-31)
    pub end_day: u8,
    /// Allowed months (bitmask, bit 0 = Jan)
    pub months: u16,
}

impl EquityController for StandardEquityController {
    fn before_transfer(
        &self,
        token: &EquityToken,
        from: &Address,
        to: &Address,
        amount: u128,
        context: &TransferContext,
    ) -> Result<(), ControllerError> {
        // Check if paused
        if self.paused {
            return Err(ControllerError {
                code: ControllerErrorCode::ControllerPaused,
                message: "Controller is paused".to_string(),
            });
        }

        // Check whitelist
        if self.whitelist_enabled {
            if !self.whitelist.contains(from) {
                return Err(ControllerError {
                    code: ControllerErrorCode::SenderNotWhitelisted,
                    message: "Sender not whitelisted".to_string(),
                });
            }
            if !self.whitelist.contains(to) {
                return Err(ControllerError {
                    code: ControllerErrorCode::RecipientNotWhitelisted,
                    message: "Recipient not whitelisted".to_string(),
                });
            }
        }

        // Check lockups
        if let Some(lockup) = self.lockups.get(from) {
            if lockup.unlock_at > current_timestamp() {
                // Check if transfer exceeds unlocked amount
                let unlocked = self.get_unlocked_amount(from);
                if amount > unlocked {
                    return Err(ControllerError {
                        code: ControllerErrorCode::SenderInLockup,
                        message: "Amount exceeds unlocked balance".to_string(),
                    });
                }
            }
        }

        // Check trading window
        if !self.is_trading_window_open() {
            return Err(ControllerError {
                code: ControllerErrorCode::TradingWindowClosed,
                message: "Trading window is closed".to_string(),
            });
        }

        // Check transfer limit
        if let Some(limit) = self.transfer_limit {
            if amount > limit {
                return Err(ControllerError {
                    code: ControllerErrorCode::TransferAmountExceedsLimit,
                    message: "Amount exceeds transfer limit".to_string(),
                });
            }
        }

        Ok(())
    }

    fn before_mint(
        &self,
        token: &EquityToken,
        to: &Address,
        amount: u128,
        issuance_ref: &IssuanceRef,
    ) -> Result<(), ControllerError> {
        // Check authorized cap
        if token.issued_shares + amount > token.authorized_shares {
            return Err(ControllerError {
                code: ControllerErrorCode::ExceedsAuthorizedCap,
                message: "Would exceed authorized shares".to_string(),
            });
        }

        // Verify issuance reference (governance action)
        // This would check the governance action is valid

        Ok(())
    }

    // ... other implementations
}
```

## Controller Upgrade

Controllers can only be upgraded via policy-governed mechanism:

```rust
impl StandardEquityController {
    /// Upgrade controller (requires governance action)
    pub fn upgrade_controller(
        &mut self,
        new_controller: Address,
        governance_action: &GovernanceAction,
    ) -> Result<(), ControllerError> {
        // Verify governance action
        if governance_action.action_type != GovernanceActionType::SigningAuthorityGrant {
            return Err(ControllerError {
                code: ControllerErrorCode::ActionNotAuthorized,
                message: "Invalid action type for controller upgrade".to_string(),
            });
        }

        // Verify policy compliance
        // (would call policy verifier here)

        // Emit event
        // (would emit ControllerUpdated event)

        Ok(())
    }
}
```

---

# SRC-835: Corporate Actions Interface

## Purpose

Defines canonical corporate actions with policy-gated execution.

## Action Types

```rust
/// Corporate action types
#[repr(u8)]
pub enum CorporateActionType {
    /// Stock split (e.g., 2:1)
    StockSplit = 0,
    /// Reverse split (e.g., 1:10)
    ReverseSplit = 1,
    /// Cash dividend declaration
    DividendDeclare = 2,
    /// Cash dividend distribution
    DividendDistribute = 3,
    /// Stock dividend
    StockDividend = 4,
    /// Buyback/redemption
    Buyback = 5,
    /// Conversion (preferred to common)
    Conversion = 6,
    /// Record date snapshot
    RecordDateSnapshot = 7,
    /// Rights offering
    RightsOffering = 8,
}

/// Corporate action
pub struct CorporateAction {
    /// Unique action ID
    pub action_id: [u8; 32],
    /// Share class ID
    pub class_id: [u8; 32],
    /// Action type
    pub action_type: CorporateActionType,
    /// Action parameters
    pub params: CorporateActionParams,
    /// Record date (for snapshots)
    pub record_date: Option<u64>,
    /// Execution date
    pub execution_date: u64,
    /// Governance action authorizing this
    pub governance_action_id: [u8; 32],
    /// Status
    pub status: CorporateActionStatus,
}

/// Action parameters
pub enum CorporateActionParams {
    StockSplit(StockSplitParams),
    ReverseSplit(ReverseSplitParams),
    DividendDeclare(DividendDeclareParams),
    DividendDistribute(DividendDistributeParams),
    Buyback(BuybackParams),
    Conversion(ConversionParams),
    RecordSnapshot(RecordSnapshotParams),
}

/// Stock split parameters
pub struct StockSplitParams {
    /// Split ratio numerator (e.g., 2 for 2:1)
    pub ratio_numerator: u64,
    /// Split ratio denominator (e.g., 1 for 2:1)
    pub ratio_denominator: u64,
}

/// Reverse split parameters
pub struct ReverseSplitParams {
    /// Ratio numerator (e.g., 1 for 1:10)
    pub ratio_numerator: u64,
    /// Ratio denominator (e.g., 10 for 1:10)
    pub ratio_denominator: u64,
    /// Rounding mode
    pub rounding: RoundingMode,
    /// Cash out fractional shares
    pub cash_out_fractional: bool,
    /// Price per fractional share (if cashing out)
    pub fractional_price: Option<u128>,
}

/// Rounding mode for splits
#[repr(u8)]
pub enum RoundingMode {
    /// Round down (truncate)
    Down = 0,
    /// Round up
    Up = 1,
    /// Round to nearest
    Nearest = 2,
}

/// Dividend declaration parameters
pub struct DividendDeclareParams {
    /// Dividend per share (in smallest currency unit)
    pub amount_per_share: u128,
    /// Currency (token address or native)
    pub currency: DividendCurrency,
    /// Record date
    pub record_date: u64,
    /// Payment date
    pub payment_date: u64,
}

/// Dividend currency
pub enum DividendCurrency {
    /// Native chain token
    Native,
    /// SRC-20 token
    Token(Address),
}

/// Dividend distribution parameters
pub struct DividendDistributeParams {
    /// Declaration action ID
    pub declaration_id: [u8; 32],
    /// Snapshot ID (from record date)
    pub snapshot_id: [u8; 32],
    /// Distribution method
    pub method: DistributionMethod,
}

/// Distribution method
#[repr(u8)]
pub enum DistributionMethod {
    /// Pro-rata by snapshot
    ProRataSnapshot = 0,
    /// Pro-rata by current balance
    ProRataCurrent = 1,
}

/// Buyback parameters
pub struct BuybackParams {
    /// Maximum shares to buy back
    pub max_shares: u128,
    /// Maximum price per share
    pub max_price: u128,
    /// Tender offer end date
    pub end_date: u64,
}

/// Conversion parameters
pub struct ConversionParams {
    /// Source class ID (e.g., preferred)
    pub from_class_id: [u8; 32],
    /// Target class ID (e.g., common)
    pub to_class_id: [u8; 32],
    /// Conversion ratio
    pub conversion_ratio: u64,
    /// Holder address (for single-holder conversion)
    pub holder: Option<Address>,
}

/// Record snapshot parameters
pub struct RecordSnapshotParams {
    /// Purpose of snapshot
    pub purpose: SnapshotPurpose,
    /// Reference (e.g., proposal ID)
    pub reference: Option<[u8; 32]>,
}

/// Snapshot purpose
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

/// Action status
#[repr(u8)]
pub enum CorporateActionStatus {
    Proposed = 0,
    Approved = 1,
    Executing = 2,
    Completed = 3,
    Cancelled = 4,
    Failed = 5,
}
```

## Corporate Action Execution

```rust
/// Corporate action executor
pub trait CorporateActionExecutor {
    /// Execute stock split
    fn execute_stock_split(
        &mut self,
        token: &mut EquityToken,
        params: &StockSplitParams,
        balances: &mut HashMap<Address, u128>,
    ) -> Result<CorporateActionResult, CorporateActionError>;

    /// Execute reverse split
    fn execute_reverse_split(
        &mut self,
        token: &mut EquityToken,
        params: &ReverseSplitParams,
        balances: &mut HashMap<Address, u128>,
    ) -> Result<CorporateActionResult, CorporateActionError>;

    /// Declare dividend
    fn declare_dividend(
        &mut self,
        token: &EquityToken,
        params: &DividendDeclareParams,
    ) -> Result<DividendDeclaration, CorporateActionError>;

    /// Distribute dividend
    fn distribute_dividend(
        &mut self,
        token: &EquityToken,
        params: &DividendDistributeParams,
        snapshot: &OwnershipSnapshot,
    ) -> Result<DividendDistribution, CorporateActionError>;

    /// Execute buyback
    fn execute_buyback(
        &mut self,
        token: &mut EquityToken,
        params: &BuybackParams,
        tenders: &[BuybackTender],
    ) -> Result<BuybackResult, CorporateActionError>;

    /// Execute conversion
    fn execute_conversion(
        &mut self,
        from_token: &mut EquityToken,
        to_token: &mut EquityToken,
        params: &ConversionParams,
    ) -> Result<ConversionResult, CorporateActionError>;

    /// Take record date snapshot
    fn take_snapshot(
        &mut self,
        token: &EquityToken,
        params: &RecordSnapshotParams,
        balances: &HashMap<Address, u128>,
    ) -> Result<OwnershipSnapshot, CorporateActionError>;
}

/// Ownership snapshot
pub struct OwnershipSnapshot {
    /// Snapshot ID
    pub snapshot_id: [u8; 32],
    /// Class ID
    pub class_id: [u8; 32],
    /// Snapshot timestamp
    pub timestamp: u64,
    /// Block height
    pub block_height: u64,
    /// Total supply at snapshot
    pub total_supply: u128,
    /// Holder count
    pub holder_count: u64,
    /// Merkle root of balances
    pub balances_root: [u8; 32],
    /// Purpose
    pub purpose: SnapshotPurpose,
}

/// Corporate action result
pub struct CorporateActionResult {
    pub action_id: [u8; 32],
    pub action_type: CorporateActionType,
    pub affected_holders: u64,
    pub total_shares_affected: u128,
    pub execution_timestamp: u64,
}
```

## Stock Split Implementation

```rust
impl CorporateActionExecutor for StandardCorporateActionExecutor {
    fn execute_stock_split(
        &mut self,
        token: &mut EquityToken,
        params: &StockSplitParams,
        balances: &mut HashMap<Address, u128>,
    ) -> Result<CorporateActionResult, CorporateActionError> {
        let ratio = params.ratio_numerator as u128;
        let divisor = params.ratio_denominator as u128;

        // Update each holder's balance
        let mut affected_holders = 0u64;
        let mut total_affected = 0u128;

        for (_addr, balance) in balances.iter_mut() {
            let old_balance = *balance;
            *balance = (old_balance * ratio) / divisor;
            affected_holders += 1;
            total_affected += *balance - old_balance;
        }

        // Update token total supply
        let old_supply = token.issued_shares;
        token.issued_shares = (old_supply * ratio) / divisor;

        // Update authorized shares proportionally
        token.authorized_shares = (token.authorized_shares * ratio) / divisor;

        Ok(CorporateActionResult {
            action_id: generate_action_id(),
            action_type: CorporateActionType::StockSplit,
            affected_holders,
            total_shares_affected: total_affected,
            execution_timestamp: current_timestamp(),
        })
    }
}
```

## Events

```rust
pub enum CorporateActionEvent {
    ActionProposed {
        action_id: [u8; 32],
        class_id: [u8; 32],
        action_type: CorporateActionType,
        governance_action_id: [u8; 32],
    },
    ActionApproved {
        action_id: [u8; 32],
    },
    ActionExecuted {
        action_id: [u8; 32],
        action_type: CorporateActionType,
        affected_holders: u64,
        total_shares_affected: u128,
    },
    DividendDeclared {
        declaration_id: [u8; 32],
        class_id: [u8; 32],
        amount_per_share: u128,
        record_date: u64,
        payment_date: u64,
    },
    DividendDistributed {
        declaration_id: [u8; 32],
        total_distributed: u128,
        recipient_count: u64,
    },
    SnapshotTaken {
        snapshot_id: [u8; 32],
        class_id: [u8; 32],
        purpose: SnapshotPurpose,
        holder_count: u64,
    },
}
```

---

# SRC-836: Ownership Proof Profiles

## Purpose

Standardizes proof profiles for ownership verification without revealing cap table details.

## Proof Profiles

### prove_shareholder_membership

Proves holder owns at least 1 share of a specific class.

```rust
pub struct ProofProfileShareholderMembership {
    pub profile_id: &'static str, // "equity.prove_membership.v1"
    pub domain_sep: &'static str, // "SRC836-PROOF:equity.prove_membership:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: MembershipPublicInputs,
}

pub struct MembershipPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Share class ID
    pub class_id: [u8; 32],
    /// Membership commitment (hides holder address)
    pub membership_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

### prove_ownership_at_least

Proves holder owns at least N shares.

```rust
pub struct ProofProfileOwnershipThreshold {
    pub profile_id: &'static str, // "equity.prove_ownership_threshold.v1"
    pub domain_sep: &'static str, // "SRC836-PROOF:equity.prove_ownership_threshold:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: OwnershipThresholdPublicInputs,
}

pub struct OwnershipThresholdPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Share class ID
    pub class_id: [u8; 32],
    /// Minimum shares threshold
    pub threshold: u128,
    /// Ownership commitment
    pub ownership_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

### prove_voting_power_at_least

Proves holder has at least N voting power.

```rust
pub struct ProofProfileVotingPower {
    pub profile_id: &'static str, // "equity.prove_voting_power.v1"
    pub domain_sep: &'static str, // "SRC836-PROOF:equity.prove_voting_power:v1"
    pub required_policies: Vec<PolicyId>,
    pub public_inputs: VotingPowerPublicInputs,
}

pub struct VotingPowerPublicInputs {
    /// Organization subject ID
    pub org_subject: SubjectId,
    /// Voting power threshold
    pub threshold: u128,
    /// Optional: reference to proposal or record date
    pub reference: Option<[u8; 32]>,
    /// Voting power commitment
    pub voting_commitment: [u8; 32],
    /// Proof timestamp
    pub proof_timestamp: u64,
}
```

## Verifier Interface

```rust
/// Ownership proof verifier
pub trait OwnershipProofVerifier {
    /// Verify membership proof
    fn verify_membership(
        &self,
        envelope: &ProofEnvelope,
        org_subject: &SubjectId,
        class_id: &[u8; 32],
    ) -> Result<VerificationResult, VerifierError>;

    /// Verify ownership threshold proof
    fn verify_ownership_threshold(
        &self,
        envelope: &ProofEnvelope,
        org_subject: &SubjectId,
        class_id: &[u8; 32],
        threshold: u128,
    ) -> Result<VerificationResult, VerifierError>;

    /// Verify voting power proof
    fn verify_voting_power(
        &self,
        envelope: &ProofEnvelope,
        org_subject: &SubjectId,
        threshold: u128,
        reference: Option<&[u8; 32]>,
    ) -> Result<VerificationResult, VerifierError>;
}
```

## Mock Verifier

```rust
/// Mock verifier for testing
pub struct MockOwnershipVerifier {
    /// Pre-registered valid proofs
    valid_proofs: HashSet<[u8; 32]>,
}

impl OwnershipProofVerifier for MockOwnershipVerifier {
    fn verify_membership(
        &self,
        envelope: &ProofEnvelope,
        org_subject: &SubjectId,
        class_id: &[u8; 32],
    ) -> Result<VerificationResult, VerifierError> {
        // Check proof format
        // Check proof is in valid set
        // Check policy compliance
        // Return result
        Ok(VerificationResult {
            valid: self.valid_proofs.contains(&envelope.proof_hash),
            profile_id: "equity.prove_membership.v1".to_string(),
            policy_compliant: true,
            revocation_status: RevocationCheckResult {
                checked: true,
                revoked: false,
                revocation_reason: None,
            },
            verified_at: current_timestamp(),
        })
    }
}
```

---

# Domain Separation Strings

| Context | Domain Separation String |
|---------|-------------------------|
| Entity Profile | `SRC831-ENTITY:<org_type>:v1` |
| Governance Action | `SRC832-ACTION:<action_type>:v1` |
| Equity Token ID | `SRC833-TOKEN:<issuer_subject>:<class_name>` |
| Corporate Action | `SRC835-CORP-ACTION:<action_type>:v1` |
| Ownership Proof | `SRC836-PROOF:<profile_id>:v1` |
| Snapshot | `SRC835-SNAPSHOT:<purpose>:v1` |

---

# Canonical Encoding

SRC-83X uses deterministic JSON (same as SRC-82X):

1. **Sorted Keys**: Object keys sorted lexicographically
2. **UTF-8**: All strings UTF-8 encoded
3. **No Whitespace**: No spaces, newlines, or tabs
4. **Number Format**: Integers as decimal strings, no leading zeros
5. **Address Format**: Hex-encoded with `0x` prefix

---

# Security Considerations

1. **Controller Security**: Controller is the trust root for all operations
2. **Policy Compliance**: All actions must comply with governance policies
3. **Snapshot Integrity**: Snapshots must be tamper-evident
4. **No Cap Table Exposure**: Ownership proven via ZK, not public balances
5. **Corporate Action Authorization**: All actions require governance approval
6. **Controller Upgrade Security**: Controller changes require policy approval

---

# Future Extensions

## Integration with SRC-806 Proofs

Voting modules will consume SRC-836 ownership proofs:

```rust
/// Example: Voting module consuming ownership proof
fn cast_vote(
    proposal_id: [u8; 32],
    choice: u8,
    ownership_proof: ProofEnvelope,
) -> Result<(), VotingError> {
    // Verify ownership proof using SRC-836 verifier
    let verification = ownership_verifier.verify_voting_power(
        &ownership_proof,
        &proposal.org_subject,
        proposal.min_voting_power,
        Some(&proposal_id),
    )?;

    if !verification.valid {
        return Err(VotingError::InvalidOwnershipProof);
    }

    // Record vote with nullifier to prevent double-voting
    // ...
}
```

## Integration with ATS/Markets

Transfer restrictions via controller hooks enable compliant trading:

```rust
/// Example: ATS consuming controller hooks
fn execute_trade(
    order: &Order,
    equity_token: &EquityToken,
    controller: &dyn EquityController,
) -> Result<TradeResult, ATSError> {
    // Check transfer restrictions
    controller.before_transfer(
        equity_token,
        &order.seller,
        &order.buyer,
        order.amount,
        &TransferContext {
            initiator: ats_address(),
            governance_action: None,
            transfer_type: TransferType::Regular,
            data: vec![],
        },
    )?;

    // Execute settlement
    // ...
}
```

---

# Copyright

This document is released under CC0 1.0 Universal.
