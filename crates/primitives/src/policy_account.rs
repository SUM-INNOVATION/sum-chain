//! Policy Account Module - Consensus-Enforced Multi-Signature Governance
//!
//! This module implements group-governed addresses with configurable approval policies.
//! Key features:
//! - Group-governed addresses with multiple members
//! - Action-class-based approval thresholds
//! - Built-in policy profiles for common use cases
//! - Replay protection for group-authorized actions
//! - Deterministic action classification
//!
//! Design principles:
//! - Security-first: fail-closed for unknown actions
//! - Compatibility: existing single-owner addresses work unchanged
//! - Flexibility: configurable per-action-class rules
//! - Transparency: all governance on-chain

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, BlockHeight, Hash, Timestamp};

// =============================================================================
// Type Aliases
// =============================================================================

/// Policy Account ID (derived from members and creation parameters)
pub type PolicyAccountId = [u8; 32];

/// Proposal ID for group-authorized actions
pub type ProposalId = [u8; 32];

/// Nonce for replay protection within a policy account
pub type PolicyNonce = u64;

// =============================================================================
// Domain Separation Constants
// =============================================================================

/// Domain separator for policy account IDs
pub const POLICY_ACCOUNT_DOMAIN_SEP: &[u8] = b"POLICY-ACCOUNT:";

/// Domain separator for proposal IDs
pub const PROPOSAL_DOMAIN_SEP: &[u8] = b"POLICY-PROPOSAL:";

/// Domain separator for approval messages
pub const APPROVAL_DOMAIN_SEP: &[u8] = b"POLICY-APPROVAL:";

// =============================================================================
// Limits (DoS Prevention)
// =============================================================================

/// Maximum members per policy account
pub const MAX_MEMBERS: usize = 100;

/// Maximum custom rules per policy account
pub const MAX_CUSTOM_RULES: usize = 50;

/// Maximum approvals per proposal
pub const MAX_APPROVALS: usize = 100;

/// Maximum proposal payload size (bytes)
pub const MAX_PROPOSAL_PAYLOAD_SIZE: usize = 100_000; // 100 KB

// =============================================================================
// Action Classification
// =============================================================================

/// Action classes for policy enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActionClass {
    /// Transfer native balance from policy account
    TransferNative = 0,

    /// Transfer token ownership (SRC-20, NFT, etc.)
    TransferTokenOwnership = 1,

    /// Administrative token actions (pause, metadata, minter management)
    AdministerToken = 2,

    /// Stake, unstake, delegate operations
    StakingOperation = 3,

    /// Governance vote, proposal, parameter change
    GovernanceAction = 4,

    /// Modify policy account membership
    ModifyMembership = 5,

    /// Modify policy account rules
    ModifyPolicy = 6,

    /// Deploy smart contract
    DeployContract = 7,

    /// Call smart contract
    CallContract = 8,

    /// Other actions (must be explicitly configured, fail-closed by default)
    Other = 255,
}

impl ActionClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ActionClass::TransferNative),
            1 => Some(ActionClass::TransferTokenOwnership),
            2 => Some(ActionClass::AdministerToken),
            3 => Some(ActionClass::StakingOperation),
            4 => Some(ActionClass::GovernanceAction),
            5 => Some(ActionClass::ModifyMembership),
            6 => Some(ActionClass::ModifyPolicy),
            7 => Some(ActionClass::DeployContract),
            8 => Some(ActionClass::CallContract),
            255 => Some(ActionClass::Other),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ActionClass::TransferNative => "Transfer Native Balance",
            ActionClass::TransferTokenOwnership => "Transfer Token Ownership",
            ActionClass::AdministerToken => "Administer Token",
            ActionClass::StakingOperation => "Staking Operation",
            ActionClass::GovernanceAction => "Governance Action",
            ActionClass::ModifyMembership => "Modify Membership",
            ActionClass::ModifyPolicy => "Modify Policy",
            ActionClass::DeployContract => "Deploy Contract",
            ActionClass::CallContract => "Call Contract",
            ActionClass::Other => "Other",
        }
    }
}

// =============================================================================
// Approval Threshold Types
// =============================================================================

/// Approval threshold for an action class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalThreshold {
    /// Requires unanimous approval from all members
    Unanimous,

    /// Requires simple majority (>50%)
    Majority,

    /// Requires specific percentage (1-100)
    Percentage(u8),

    /// Requires absolute number of approvals
    Absolute(u32),

    /// Requires weighted threshold (for weighted members)
    WeightedPercentage(u8),

    /// Deny all (cannot be executed)
    Deny,
}

impl ApprovalThreshold {
    /// Validate threshold is sensible
    pub fn is_valid(&self) -> bool {
        match self {
            ApprovalThreshold::Percentage(p) if *p == 0 || *p > 100 => false,
            ApprovalThreshold::WeightedPercentage(p) if *p == 0 || *p > 100 => false,
            ApprovalThreshold::Absolute(0) => false,
            _ => true,
        }
    }

    /// Check if threshold is met
    pub fn is_met(
        &self,
        num_approvals: u32,
        total_members: u32,
        approval_weight: u64,
        total_weight: u64,
    ) -> bool {
        match self {
            ApprovalThreshold::Unanimous => num_approvals == total_members,
            ApprovalThreshold::Majority => num_approvals * 2 > total_members,
            ApprovalThreshold::Percentage(p) => {
                num_approvals * 100 >= total_members * (*p as u32)
            }
            ApprovalThreshold::Absolute(n) => num_approvals >= *n,
            ApprovalThreshold::WeightedPercentage(p) => {
                approval_weight * 100 >= total_weight * (*p as u64)
            }
            ApprovalThreshold::Deny => false,
        }
    }
}

// =============================================================================
// Policy Profiles (Safe Defaults)
// =============================================================================

/// Pre-configured policy profiles for common use cases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyProfile {
    /// Conservative: unanimous for all asset transfers, majority for admin
    /// Use case: high-value assets, house, family trust
    Conservative = 0,

    /// Company: majority for governance, unanimous for ownership transfers
    /// Use case: traditional corporate governance
    Company = 1,

    /// DAO: majority for most actions, weighted voting for governance
    /// Use case: decentralized organizations
    DAO = 2,

    /// Personal: simple majority for all actions
    /// Use case: joint personal accounts, shared assets
    Personal = 3,

    /// Trust: specific thresholds for fiduciary responsibilities
    /// Use case: legal trusts, estate planning
    Trust = 4,

    /// Custom: user defines all rules
    Custom = 255,
}

impl PolicyProfile {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PolicyProfile::Conservative),
            1 => Some(PolicyProfile::Company),
            2 => Some(PolicyProfile::DAO),
            3 => Some(PolicyProfile::Personal),
            4 => Some(PolicyProfile::Trust),
            255 => Some(PolicyProfile::Custom),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            PolicyProfile::Conservative => "Conservative",
            PolicyProfile::Company => "Company",
            PolicyProfile::DAO => "DAO",
            PolicyProfile::Personal => "Personal",
            PolicyProfile::Trust => "Trust",
            PolicyProfile::Custom => "Custom",
        }
    }

    /// Get default threshold for an action class under this profile
    pub fn default_threshold(&self, action_class: ActionClass) -> ApprovalThreshold {
        match (self, action_class) {
            // Conservative: unanimous for transfers, majority for admin
            (PolicyProfile::Conservative, ActionClass::TransferNative) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Conservative, ActionClass::TransferTokenOwnership) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Conservative, ActionClass::ModifyMembership) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Conservative, ActionClass::ModifyPolicy) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Conservative, _) => ApprovalThreshold::Majority,

            // Company: majority for governance, unanimous for ownership
            (PolicyProfile::Company, ActionClass::TransferNative) => ApprovalThreshold::Unanimous,
            (PolicyProfile::Company, ActionClass::TransferTokenOwnership) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Company, ActionClass::GovernanceAction) => ApprovalThreshold::Majority,
            (PolicyProfile::Company, ActionClass::ModifyMembership) => {
                ApprovalThreshold::Percentage(67) // Supermajority
            }
            (PolicyProfile::Company, ActionClass::ModifyPolicy) => {
                ApprovalThreshold::Percentage(67)
            }
            (PolicyProfile::Company, _) => ApprovalThreshold::Majority,

            // DAO: weighted voting for governance, majority for admin
            (PolicyProfile::DAO, ActionClass::GovernanceAction) => {
                ApprovalThreshold::WeightedPercentage(51)
            }
            (PolicyProfile::DAO, ActionClass::TransferNative) => ApprovalThreshold::Majority,
            (PolicyProfile::DAO, ActionClass::TransferTokenOwnership) => {
                ApprovalThreshold::Majority
            }
            (PolicyProfile::DAO, ActionClass::ModifyMembership) => {
                ApprovalThreshold::WeightedPercentage(67)
            }
            (PolicyProfile::DAO, ActionClass::ModifyPolicy) => {
                ApprovalThreshold::WeightedPercentage(67)
            }
            (PolicyProfile::DAO, _) => ApprovalThreshold::Majority,

            // Personal: simple majority for all
            (PolicyProfile::Personal, _) => ApprovalThreshold::Majority,

            // Trust: conservative with fiduciary requirements
            (PolicyProfile::Trust, ActionClass::TransferNative) => ApprovalThreshold::Unanimous,
            (PolicyProfile::Trust, ActionClass::TransferTokenOwnership) => {
                ApprovalThreshold::Unanimous
            }
            (PolicyProfile::Trust, ActionClass::ModifyMembership) => ApprovalThreshold::Unanimous,
            (PolicyProfile::Trust, ActionClass::ModifyPolicy) => ApprovalThreshold::Unanimous,
            (PolicyProfile::Trust, _) => ApprovalThreshold::Percentage(67),

            // Custom: deny by default (must be explicitly configured)
            (PolicyProfile::Custom, _) => ApprovalThreshold::Deny,
        }
    }
}

// =============================================================================
// Member and Weight
// =============================================================================

/// Policy account member with optional weight
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMember {
    /// Member address
    pub address: Address,

    /// Weight for weighted voting (1 if not weighted)
    pub weight: u64,
}

impl PolicyMember {
    pub fn new(address: Address) -> Self {
        Self { address, weight: 1 }
    }

    pub fn with_weight(address: Address, weight: u64) -> Self {
        Self { address, weight }
    }
}

// =============================================================================
// Policy Rules
// =============================================================================

/// Override rule for a specific action class
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Action class this rule applies to
    pub action_class: ActionClass,

    /// Threshold override
    pub threshold: ApprovalThreshold,
}

/// Complete policy configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Base profile
    pub profile: PolicyProfile,

    /// Custom overrides (empty if using profile defaults)
    pub overrides: Vec<PolicyRule>,
}

impl PolicyConfig {
    /// Get effective threshold for an action class
    pub fn threshold_for(&self, action_class: ActionClass) -> ApprovalThreshold {
        // Check for override first
        for rule in &self.overrides {
            if rule.action_class == action_class {
                return rule.threshold;
            }
        }

        // Fall back to profile default
        self.profile.default_threshold(action_class)
    }

    /// Validate policy configuration
    pub fn is_valid(&self) -> bool {
        // Check limits
        if self.overrides.len() > MAX_CUSTOM_RULES {
            return false;
        }

        // Check all thresholds are valid
        for rule in &self.overrides {
            if !rule.threshold.is_valid() {
                return false;
            }
        }

        true
    }
}

// =============================================================================
// Policy Account
// =============================================================================

/// Policy account status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyAccountStatus {
    /// Active and operational
    Active = 0,

    /// Frozen (no operations allowed)
    Frozen = 1,
}

impl PolicyAccountStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PolicyAccountStatus::Active),
            1 => Some(PolicyAccountStatus::Frozen),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, PolicyAccountStatus::Active)
    }
}

/// Policy-governed account
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAccount {
    /// Unique policy account ID
    pub id: PolicyAccountId,

    /// The address this policy controls (derived from ID)
    pub address: Address,

    /// Members with optional weights
    pub members: Vec<PolicyMember>,

    /// Policy configuration
    pub policy: PolicyConfig,

    /// Nonce for replay protection
    pub nonce: PolicyNonce,

    /// Status
    pub status: PolicyAccountStatus,

    /// Creation block height
    pub created_at: BlockHeight,

    /// Creation timestamp
    pub created_timestamp: Timestamp,
}

impl PolicyAccount {
    /// Compute policy account ID
    pub fn compute_id(members: &[PolicyMember], salt: &[u8]) -> PolicyAccountId {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(POLICY_ACCOUNT_DOMAIN_SEP);

        // Hash all members (sorted by address for determinism)
        let mut sorted_members = members.to_vec();
        sorted_members.sort_by(|a, b| a.address.cmp(&b.address));

        for member in &sorted_members {
            hasher.update(member.address.as_bytes());
            hasher.update(&member.weight.to_le_bytes());
        }

        hasher.update(salt);
        *hasher.finalize().as_bytes()
    }

    /// Derive address from policy account ID
    pub fn id_to_address(id: &PolicyAccountId) -> Address {
        // Take last 20 bytes of the ID as the address
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&id[12..32]);
        Address::new(addr_bytes)
    }

    /// Check if address is a member
    pub fn is_member(&self, addr: &Address) -> bool {
        self.members.iter().any(|m| &m.address == addr)
    }

    /// Get total weight of all members
    pub fn total_weight(&self) -> u64 {
        self.members.iter().map(|m| m.weight).sum()
    }

    /// Validate policy account structure
    pub fn is_valid(&self) -> bool {
        // Check member count
        if self.members.is_empty() || self.members.len() > MAX_MEMBERS {
            return false;
        }

        // Check for duplicate members
        for i in 0..self.members.len() {
            for j in (i + 1)..self.members.len() {
                if self.members[i].address == self.members[j].address {
                    return false;
                }
            }
        }

        // Check all weights are positive
        if self.members.iter().any(|m| m.weight == 0) {
            return false;
        }

        // Validate policy
        if !self.policy.is_valid() {
            return false;
        }

        // Verify address matches ID
        if self.address != Self::id_to_address(&self.id) {
            return false;
        }

        true
    }
}

// =============================================================================
// Proposal (Group-Authorized Action)
// =============================================================================

/// Proposal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProposalStatus {
    /// Collecting approvals
    Pending = 0,

    /// Executed successfully
    Executed = 1,

    /// Expired before execution
    Expired = 2,

    /// Cancelled by proposer
    Cancelled = 3,
}

impl ProposalStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ProposalStatus::Pending),
            1 => Some(ProposalStatus::Executed),
            2 => Some(ProposalStatus::Expired),
            3 => Some(ProposalStatus::Cancelled),
            _ => None,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, ProposalStatus::Pending)
    }
}

/// Member approval for a proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberApproval {
    /// Approver address
    pub approver: Address,

    /// Ed25519 signature over approval message
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],

    /// Timestamp of approval
    pub timestamp: Timestamp,
}

/// Proposal for group-authorized action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: ProposalId,

    /// Policy account ID this proposal is for
    pub policy_account_id: PolicyAccountId,

    /// Policy nonce at proposal creation (for replay protection)
    pub policy_nonce: PolicyNonce,

    /// Proposer address (must be a member)
    pub proposer: Address,

    /// Action class for this proposal
    pub action_class: ActionClass,

    /// Serialized action data (transaction payload)
    pub action_data: Vec<u8>,

    /// Hash of action data (for quick validation)
    pub action_hash: Hash,

    /// Approvals collected
    pub approvals: Vec<MemberApproval>,

    /// Status
    pub status: ProposalStatus,

    /// Expiration timestamp
    pub expires_at: Timestamp,

    /// Creation timestamp
    pub created_at: Timestamp,

    /// Creation block height
    pub created_height: BlockHeight,
}

impl Proposal {
    /// Compute proposal ID
    pub fn compute_id(
        policy_account_id: &PolicyAccountId,
        policy_nonce: PolicyNonce,
        action_hash: &Hash,
    ) -> ProposalId {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(PROPOSAL_DOMAIN_SEP);
        hasher.update(policy_account_id);
        hasher.update(&policy_nonce.to_le_bytes());
        hasher.update(action_hash.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Compute approval message to be signed by members
    pub fn approval_message(
        proposal_id: &ProposalId,
        policy_account_id: &PolicyAccountId,
        action_hash: &Hash,
        policy_nonce: PolicyNonce,
    ) -> Hash {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(APPROVAL_DOMAIN_SEP);
        hasher.update(proposal_id);
        hasher.update(policy_account_id);
        hasher.update(action_hash.as_bytes());
        hasher.update(&policy_nonce.to_le_bytes());
        Hash::new(*hasher.finalize().as_bytes())
    }

    /// Check if approver already approved
    pub fn has_approval(&self, approver: &Address) -> bool {
        self.approvals.iter().any(|a| &a.approver == approver)
    }

    /// Validate proposal structure
    pub fn is_valid(&self) -> bool {
        // Check payload size
        if self.action_data.len() > MAX_PROPOSAL_PAYLOAD_SIZE {
            return false;
        }

        // Check approval count
        if self.approvals.len() > MAX_APPROVALS {
            return false;
        }

        // Verify action hash matches data
        let computed_hash = Hash::hash(&self.action_data);
        if computed_hash != self.action_hash {
            return false;
        }

        // Check for duplicate approvals
        for i in 0..self.approvals.len() {
            for j in (i + 1)..self.approvals.len() {
                if self.approvals[i].approver == self.approvals[j].approver {
                    return false;
                }
            }
        }

        true
    }
}

// =============================================================================
// Transaction Data
// =============================================================================

/// Policy account operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyAccountOperation {
    /// Create a new policy account
    Create = 0,

    /// Submit a proposal (or add approvals)
    SubmitProposal = 1,

    /// Execute a proposal (once threshold met)
    ExecuteProposal = 2,

    /// Cancel a proposal (proposer only)
    CancelProposal = 3,

    /// Modify membership (via group approval)
    ModifyMembership = 4,

    /// Modify policy rules (via group approval)
    ModifyPolicy = 5,

    /// Freeze policy account
    Freeze = 6,

    /// Unfreeze policy account
    Unfreeze = 7,
}

impl PolicyAccountOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PolicyAccountOperation::Create),
            1 => Some(PolicyAccountOperation::SubmitProposal),
            2 => Some(PolicyAccountOperation::ExecuteProposal),
            3 => Some(PolicyAccountOperation::CancelProposal),
            4 => Some(PolicyAccountOperation::ModifyMembership),
            5 => Some(PolicyAccountOperation::ModifyPolicy),
            6 => Some(PolicyAccountOperation::Freeze),
            7 => Some(PolicyAccountOperation::Unfreeze),
            _ => None,
        }
    }
}

/// Policy account transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAccountTxData {
    /// Operation code
    pub operation: PolicyAccountOperation,

    /// Operation-specific data (serialized)
    pub data: Vec<u8>,

    /// Recipient address (for fee distribution, etc.)
    pub recipient: Address,
}
