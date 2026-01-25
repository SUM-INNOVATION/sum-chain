//! Policy Account RPC Types
//!
//! Request and response types for Policy Account RPC endpoints

use serde::{Deserialize, Serialize};
use sumchain_primitives::{
    policy_account::{
        ActionClass, ApprovalThreshold, MemberApproval, PolicyAccountId, PolicyAccountStatus,
        PolicyNonce, PolicyProfile, ProposalId, ProposalStatus,
    },
    Address, BlockHeight, Timestamp,
};

// =============================================================================
// Request Types
// =============================================================================

/// Request to create a policy account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyAccountRequest {
    /// Creator's private key (hex-encoded)
    pub private_key: String,
    /// Policy account members
    pub members: Vec<PolicyMemberInfo>,
    /// Policy configuration
    pub policy: PolicyConfigInfo,
    /// Salt for ID generation (hex-encoded)
    pub salt: String,
}

/// Request to submit a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProposalRequest {
    /// Proposer's private key (hex-encoded)
    pub proposer_private_key: String,
    /// Policy account ID (hex-encoded)
    pub policy_account_id: String,
    /// Embedded action data (hex-encoded serialized TxPayload)
    pub action_data: String,
    /// Member approvals
    pub approvals: Vec<ApprovalInfo>,
    /// Expiration time (seconds from now)
    pub expires_in_seconds: u64,
}

/// Request to execute a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteProposalRequest {
    /// Executor's private key (hex-encoded, can be any member)
    pub executor_private_key: String,
    /// Proposal ID (hex-encoded)
    pub proposal_id: String,
}

/// Request to cancel a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelProposalRequest {
    /// Proposer's private key (hex-encoded)
    pub proposer_private_key: String,
    /// Proposal ID (hex-encoded)
    pub proposal_id: String,
}

// =============================================================================
// Response Types
// =============================================================================

/// Response from creating a policy account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyAccountResponse {
    /// Policy account ID (hex-encoded)
    pub policy_account_id: String,
    /// Controlled address (base58-encoded)
    pub address: String,
    /// Transaction hash (hex-encoded)
    pub tx_hash: String,
}

/// Response from submitting a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProposalResponse {
    /// Proposal ID (hex-encoded)
    pub proposal_id: String,
    /// Proposal status
    pub status: String,
    /// Transaction hash (hex-encoded)
    pub tx_hash: String,
}

/// Response from executing a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteProposalResponse {
    /// Success flag
    pub success: bool,
    /// New policy nonce after execution
    pub new_policy_nonce: u64,
    /// Execution message
    pub message: String,
    /// Transaction hash (hex-encoded)
    pub tx_hash: String,
}

/// Response from canceling a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelProposalResponse {
    /// Success flag
    pub success: bool,
    /// Message
    pub message: String,
    /// Transaction hash (hex-encoded)
    pub tx_hash: String,
}

// =============================================================================
// Info Types (for queries)
// =============================================================================

/// Policy account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAccountInfo {
    /// Policy account ID (hex-encoded)
    pub id: String,
    /// Controlled address (base58-encoded)
    pub address: String,
    /// Members with weights
    pub members: Vec<PolicyMemberInfo>,
    /// Policy configuration
    pub policy: PolicyConfigInfo,
    /// Current nonce
    pub nonce: u64,
    /// Status
    pub status: String,
    /// Creation block height
    pub created_at: u64,
    /// Creation timestamp (milliseconds)
    pub created_timestamp: u64,
}

/// Proposal information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalInfo {
    /// Proposal ID (hex-encoded)
    pub id: String,
    /// Policy account ID (hex-encoded)
    pub policy_account_id: String,
    /// Policy nonce when proposal was created
    pub policy_nonce: u64,
    /// Proposer address (base58-encoded)
    pub proposer: String,
    /// Action class
    pub action_class: String,
    /// Action hash (hex-encoded)
    pub action_hash: String,
    /// Number of approvals
    pub approval_count: usize,
    /// Approvals
    pub approvals: Vec<ApprovalInfoResponse>,
    /// Status
    pub status: String,
    /// Expiration timestamp (milliseconds)
    pub expires_at: u64,
    /// Creation timestamp (milliseconds)
    pub created_at: u64,
    /// Creation block height
    pub created_height: u64,
}

/// Policy member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMemberInfo {
    /// Member address (base58-encoded)
    pub address: String,
    /// Voting weight
    pub weight: u64,
}

/// Policy configuration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfigInfo {
    /// Base profile
    pub profile: String,
    /// Custom rule overrides
    pub overrides: Vec<PolicyRuleInfo>,
}

/// Policy rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleInfo {
    /// Action class
    pub action_class: String,
    /// Threshold
    pub threshold: ThresholdInfo,
}

/// Threshold information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ThresholdInfo {
    Unanimous,
    Majority,
    Percentage(u8),
    Absolute(u32),
    WeightedPercentage(u8),
    Deny,
}

impl From<ApprovalThreshold> for ThresholdInfo {
    fn from(t: ApprovalThreshold) -> Self {
        match t {
            ApprovalThreshold::Unanimous => ThresholdInfo::Unanimous,
            ApprovalThreshold::Majority => ThresholdInfo::Majority,
            ApprovalThreshold::Percentage(p) => ThresholdInfo::Percentage(p),
            ApprovalThreshold::Absolute(a) => ThresholdInfo::Absolute(a),
            ApprovalThreshold::WeightedPercentage(p) => ThresholdInfo::WeightedPercentage(p),
            ApprovalThreshold::Deny => ThresholdInfo::Deny,
        }
    }
}

impl Into<ApprovalThreshold> for ThresholdInfo {
    fn into(self) -> ApprovalThreshold {
        match self {
            ThresholdInfo::Unanimous => ApprovalThreshold::Unanimous,
            ThresholdInfo::Majority => ApprovalThreshold::Majority,
            ThresholdInfo::Percentage(p) => ApprovalThreshold::Percentage(p),
            ThresholdInfo::Absolute(a) => ApprovalThreshold::Absolute(a),
            ThresholdInfo::WeightedPercentage(p) => ApprovalThreshold::WeightedPercentage(p),
            ThresholdInfo::Deny => ApprovalThreshold::Deny,
        }
    }
}

/// Approval information (for requests)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalInfo {
    /// Approver address (base58-encoded)
    pub approver_address: String,
    /// Signature (hex-encoded, 64 bytes)
    pub signature: String,
}

/// Approval information (for responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalInfoResponse {
    /// Approver address (base58-encoded)
    pub approver: String,
    /// Signature (hex-encoded)
    pub signature: String,
    /// Approval timestamp (milliseconds)
    pub timestamp: u64,
}

// =============================================================================
// Helper Functions
// =============================================================================

impl PolicyMemberInfo {
    pub fn from_address_and_weight(address: Address, weight: u64) -> Self {
        Self {
            address: address.to_string(),
            weight,
        }
    }

    pub fn to_address(&self) -> Result<Address, String> {
        Address::from_base58(&self.address)
            .map_err(|e| format!("Invalid address: {}", e))
    }
}

impl PolicyConfigInfo {
    pub fn from_profile(profile: PolicyProfile) -> Self {
        Self {
            profile: match profile {
                PolicyProfile::Conservative => "Conservative".to_string(),
                PolicyProfile::Company => "Company".to_string(),
                PolicyProfile::DAO => "DAO".to_string(),
                PolicyProfile::Personal => "Personal".to_string(),
                PolicyProfile::Trust => "Trust".to_string(),
                PolicyProfile::Custom => "Custom".to_string(),
            },
            overrides: vec![],
        }
    }

    pub fn to_profile(&self) -> Result<PolicyProfile, String> {
        match self.profile.as_str() {
            "Conservative" => Ok(PolicyProfile::Conservative),
            "Company" => Ok(PolicyProfile::Company),
            "DAO" => Ok(PolicyProfile::DAO),
            "Personal" => Ok(PolicyProfile::Personal),
            "Trust" => Ok(PolicyProfile::Trust),
            "Custom" => Ok(PolicyProfile::Custom),
            _ => Err(format!("Unknown profile: {}", self.profile)),
        }
    }
}

impl PolicyRuleInfo {
    pub fn action_class_from_str(s: &str) -> Result<ActionClass, String> {
        match s {
            "TransferNative" => Ok(ActionClass::TransferNative),
            "TransferTokenOwnership" => Ok(ActionClass::TransferTokenOwnership),
            "AdministerToken" => Ok(ActionClass::AdministerToken),
            "StakingOperation" => Ok(ActionClass::StakingOperation),
            "GovernanceAction" => Ok(ActionClass::GovernanceAction),
            "ModifyMembership" => Ok(ActionClass::ModifyMembership),
            "ModifyPolicy" => Ok(ActionClass::ModifyPolicy),
            "DeployContract" => Ok(ActionClass::DeployContract),
            "CallContract" => Ok(ActionClass::CallContract),
            "Other" => Ok(ActionClass::Other),
            _ => Err(format!("Unknown action class: {}", s)),
        }
    }

    pub fn action_class_to_str(ac: ActionClass) -> String {
        match ac {
            ActionClass::TransferNative => "TransferNative".to_string(),
            ActionClass::TransferTokenOwnership => "TransferTokenOwnership".to_string(),
            ActionClass::AdministerToken => "AdministerToken".to_string(),
            ActionClass::StakingOperation => "StakingOperation".to_string(),
            ActionClass::GovernanceAction => "GovernanceAction".to_string(),
            ActionClass::ModifyMembership => "ModifyMembership".to_string(),
            ActionClass::ModifyPolicy => "ModifyPolicy".to_string(),
            ActionClass::DeployContract => "DeployContract".to_string(),
            ActionClass::CallContract => "CallContract".to_string(),
            ActionClass::Other => "Other".to_string(),
        }
    }
}
