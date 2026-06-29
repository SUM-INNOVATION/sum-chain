//! Policy Account RPC Types
//!
//! Request and response types for Policy Account RPC endpoints.
//!
//! Write access is provided exclusively through no-key *builder* helpers: the
//! server assembles an unsigned [`sumchain_primitives::TransactionV2`] and
//! returns its bincode encoding plus the signing hash. Clients sign locally
//! and submit via `sum_sendRawTransaction`. The server never sees a private
//! key for policy operations.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{
    policy_account::{
        ActionClass, ApprovalThreshold, MemberApproval, PolicyAccount, PolicyConfig, PolicyMember,
        PolicyProfile, Proposal,
    },
    Address,
};

// =============================================================================
// Builder Request Types (no private keys)
// =============================================================================

/// Request to build an unsigned create-policy-account transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCreateAccountRequest {
    /// Sender / submitter address (base58-encoded). The server fills the
    /// chain id and this account's current nonce.
    pub from: String,
    /// Policy account members.
    pub members: Vec<PolicyMemberInfo>,
    /// Policy configuration.
    pub policy: PolicyConfigInfo,
    /// Salt for ID generation (hex-encoded).
    pub salt: String,
    /// Optional fee (Koppa base units). Defaults to the house default.
    #[serde(default)]
    pub fee: Option<u128>,
}

/// Request to build an unsigned submit-proposal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSubmitProposalRequest {
    /// Sender / submitter address (base58-encoded).
    pub from: String,
    /// Policy account ID (hex-encoded).
    pub policy_account_id: String,
    /// Embedded action data (hex-encoded serialized `TxPayload`).
    pub action_data: String,
    /// Member approvals over the canonical approval signing bytes.
    pub approvals: Vec<ApprovalInfo>,
    /// Absolute expiration timestamp (milliseconds since epoch).
    pub expires_at: u64,
    /// Optional fee (Koppa base units). Defaults to the house default.
    #[serde(default)]
    pub fee: Option<u128>,
}

/// Request to build an unsigned execute-proposal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildExecuteProposalRequest {
    /// Sender / submitter address (base58-encoded).
    pub from: String,
    /// Proposal ID (hex-encoded).
    pub proposal_id: String,
    /// Optional fee (Koppa base units). Defaults to the house default.
    #[serde(default)]
    pub fee: Option<u128>,
}

/// Request to build an unsigned cancel-proposal transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCancelProposalRequest {
    /// Sender / submitter address (base58-encoded; must be the proposer).
    pub from: String,
    /// Proposal ID (hex-encoded).
    pub proposal_id: String,
    /// Optional fee (Koppa base units). Defaults to the house default.
    #[serde(default)]
    pub fee: Option<u128>,
}

// =============================================================================
// Builder Response
// =============================================================================

/// Unsigned transaction material returned by every `policy_build*` helper.
///
/// The builder never signs. `unsigned_tx` is the bincode encoding of the
/// `TransactionV2`; `signing_hash` is what the client must sign with the
/// `from` key. Submit the resulting signed transaction via
/// `sum_sendRawTransaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBuildResponse {
    /// Bincode-encoded unsigned `TransactionV2` (hex-encoded).
    pub unsigned_tx: String,
    /// Hash the client must sign (hex-encoded).
    pub signing_hash: String,
    /// Sender address echoed back (base58-encoded).
    pub from: String,
    /// Nonce the server filled in.
    pub nonce: u64,
    /// Fee the server filled in (Koppa base units).
    pub fee: u128,
    /// Chain id the server filled in.
    pub chain_id: u64,
    /// Derived policy account ID for create requests (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_account_id: Option<String>,
    /// Derived controlled address for create requests (base58-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Derived proposal ID for submit requests (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    /// Derived action hash for submit requests (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_hash: Option<String>,
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

impl From<ThresholdInfo> for ApprovalThreshold {
    fn from(t: ThresholdInfo) -> Self {
        match t {
            ThresholdInfo::Unanimous => ApprovalThreshold::Unanimous,
            ThresholdInfo::Majority => ApprovalThreshold::Majority,
            ThresholdInfo::Percentage(p) => ApprovalThreshold::Percentage(p),
            ThresholdInfo::Absolute(a) => ApprovalThreshold::Absolute(a),
            ThresholdInfo::WeightedPercentage(p) => ApprovalThreshold::WeightedPercentage(p),
            ThresholdInfo::Deny => ApprovalThreshold::Deny,
        }
    }
}

/// Approval information (for requests).
///
/// `approver_pubkey` is required because an `Address` is a one-way hash of the
/// Ed25519 key and cannot recover it for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalInfo {
    /// Approver address (base58-encoded)
    pub approver_address: String,
    /// Approver Ed25519 public key (hex-encoded, 32 bytes)
    pub approver_pubkey: String,
    /// Signature (hex-encoded, 64 bytes)
    pub signature: String,
}

/// Approval information (for responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalInfoResponse {
    /// Approver address (base58-encoded)
    pub approver: String,
    /// Approver Ed25519 public key (hex-encoded)
    pub approver_pubkey: String,
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
        Self { address: address.to_base58(), weight }
    }

    pub fn from_member(member: &PolicyMember) -> Self {
        Self { address: member.address.to_base58(), weight: member.weight }
    }

    pub fn to_member(&self) -> Result<PolicyMember, String> {
        Ok(PolicyMember {
            address: self.to_address()?,
            weight: self.weight.max(1),
        })
    }

    pub fn to_address(&self) -> Result<Address, String> {
        Address::from_base58(&self.address).map_err(|e| format!("Invalid address: {}", e))
    }
}

impl PolicyConfigInfo {
    pub fn from_profile(profile: PolicyProfile) -> Self {
        Self { profile: profile_to_str(profile), overrides: vec![] }
    }

    pub fn from_config(config: &PolicyConfig) -> Self {
        Self {
            profile: profile_to_str(config.profile),
            overrides: config
                .overrides
                .iter()
                .map(|r| PolicyRuleInfo {
                    action_class: PolicyRuleInfo::action_class_to_str(r.action_class),
                    threshold: ThresholdInfo::from(r.threshold),
                })
                .collect(),
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

    pub fn to_config(&self) -> Result<PolicyConfig, String> {
        let mut overrides = Vec::with_capacity(self.overrides.len());
        for r in &self.overrides {
            overrides.push(sumchain_primitives::policy_account::PolicyRule {
                action_class: PolicyRuleInfo::action_class_from_str(&r.action_class)?,
                threshold: r.threshold.clone().into(),
            });
        }
        Ok(PolicyConfig { profile: self.to_profile()?, overrides })
    }
}

fn profile_to_str(profile: PolicyProfile) -> String {
    match profile {
        PolicyProfile::Conservative => "Conservative".to_string(),
        PolicyProfile::Company => "Company".to_string(),
        PolicyProfile::DAO => "DAO".to_string(),
        PolicyProfile::Personal => "Personal".to_string(),
        PolicyProfile::Trust => "Trust".to_string(),
        PolicyProfile::Custom => "Custom".to_string(),
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

impl ApprovalInfo {
    /// Convert into a consensus [`MemberApproval`], parsing/validating the
    /// address, public key, and signature. Does not verify the signature —
    /// that happens in the executor against the canonical signing bytes.
    pub fn to_member_approval(&self) -> Result<MemberApproval, String> {
        let approver = Address::from_base58(&self.approver_address)
            .map_err(|e| format!("Invalid approver address: {}", e))?;
        let pk = hex::decode(self.approver_pubkey.strip_prefix("0x").unwrap_or(&self.approver_pubkey))
            .map_err(|e| format!("Invalid approver pubkey hex: {}", e))?;
        if pk.len() != 32 {
            return Err("Approver pubkey must be 32 bytes".to_string());
        }
        let sig = hex::decode(self.signature.strip_prefix("0x").unwrap_or(&self.signature))
            .map_err(|e| format!("Invalid signature hex: {}", e))?;
        if sig.len() != 64 {
            return Err("Signature must be 64 bytes".to_string());
        }
        let mut approver_pubkey = [0u8; 32];
        approver_pubkey.copy_from_slice(&pk);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig);
        Ok(MemberApproval { approver, approver_pubkey, signature, timestamp: 0 })
    }
}

impl ApprovalInfoResponse {
    pub fn from_approval(a: &MemberApproval) -> Self {
        Self {
            approver: a.approver.to_base58(),
            approver_pubkey: format!("0x{}", hex::encode(a.approver_pubkey)),
            signature: format!("0x{}", hex::encode(a.signature)),
            timestamp: a.timestamp,
        }
    }
}

impl PolicyAccountInfo {
    pub fn from_account(account: &PolicyAccount) -> Self {
        use sumchain_primitives::policy_account::PolicyAccountStatus;
        Self {
            id: format!("0x{}", hex::encode(account.id)),
            address: account.address.to_base58(),
            members: account.members.iter().map(PolicyMemberInfo::from_member).collect(),
            policy: PolicyConfigInfo::from_config(&account.policy),
            nonce: account.nonce,
            status: match account.status {
                PolicyAccountStatus::Active => "Active".to_string(),
                PolicyAccountStatus::Frozen => "Frozen".to_string(),
            },
            created_at: account.created_at,
            created_timestamp: account.created_timestamp,
        }
    }
}

impl ProposalInfo {
    pub fn from_proposal(p: &Proposal) -> Self {
        use sumchain_primitives::policy_account::ProposalStatus;
        Self {
            id: format!("0x{}", hex::encode(p.id)),
            policy_account_id: format!("0x{}", hex::encode(p.policy_account_id)),
            policy_nonce: p.policy_nonce,
            proposer: p.proposer.to_base58(),
            action_class: PolicyRuleInfo::action_class_to_str(p.action_class),
            action_hash: format!("0x{}", hex::encode(p.action_hash.as_bytes())),
            approval_count: p.approvals.len(),
            approvals: p.approvals.iter().map(ApprovalInfoResponse::from_approval).collect(),
            status: match p.status {
                ProposalStatus::Pending => "Pending".to_string(),
                ProposalStatus::Executed => "Executed".to_string(),
                ProposalStatus::Expired => "Expired".to_string(),
                ProposalStatus::Cancelled => "Cancelled".to_string(),
            },
            expires_at: p.expires_at,
            created_at: p.created_at,
            created_height: p.created_height,
        }
    }
}
