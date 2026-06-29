//! Policy Account Executor
//!
//! Handles execution of policy account operations:
//! - Creating group-governed addresses
//! - Submitting proposals with member approvals
//! - Executing proposals once threshold is met
//! - Managing membership and policy changes

use std::sync::Arc;

use sumchain_primitives::{
    policy_account::{
        ActionClass, MemberApproval, PolicyAccount, PolicyAccountId, PolicyAccountOperation,
        PolicyAccountStatus, PolicyAccountTxData, PolicyConfig, PolicyMember, PolicyNonce,
        PolicyProfile, PolicyRule, Proposal, ProposalId, ProposalStatus, MAX_APPROVALS,
        MAX_MEMBERS, MAX_PROPOSAL_PAYLOAD_SIZE,
    },
    Address, Balance, BlockHeight, Hash, Timestamp, TxPayload,
};
use sumchain_primitives::{NftOperation, TokenOperation};
use sumchain_crypto::verify_bytes;
use sumchain_storage::{Database, PolicyAccountStorage, Result as StorageResult};

use crate::{Result, State, StateError};

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a policy account
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreatePolicyAccountRequest {
    pub members: Vec<PolicyMember>,
    pub policy: PolicyConfig,
    pub salt: Vec<u8>,
}

/// Response from creating a policy account
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreatePolicyAccountResponse {
    pub policy_account_id: PolicyAccountId,
    pub address: Address,
}

/// Request to submit a proposal
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitProposalRequest {
    pub policy_account_id: PolicyAccountId,
    pub action_payload: Vec<u8>, // Serialized TxPayload
    pub approvals: Vec<MemberApproval>,
    pub expires_at: Timestamp,
}

/// Response from submitting a proposal
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitProposalResponse {
    pub proposal_id: ProposalId,
    pub status: ProposalStatus,
}

/// Request to execute a proposal
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecuteProposalRequest {
    pub proposal_id: ProposalId,
}

/// Response from executing a proposal
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecuteProposalResponse {
    pub success: bool,
    pub new_policy_nonce: PolicyNonce,
    pub message: String,
}

/// Request to modify membership
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModifyMembershipRequest {
    pub new_members: Vec<PolicyMember>,
}

/// Request to modify policy
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModifyPolicyRequest {
    pub new_policy: PolicyConfig,
}

// =============================================================================
// Action Classification
// =============================================================================

/// Classify a transaction payload into an action class
pub fn classify_action(payload: &TxPayload) -> ActionClass {
    match payload {
        // Native transfers
        TxPayload::Transfer { .. } => ActionClass::TransferNative,

        // Token operations
        TxPayload::Token(data) => {
            let operation_byte = data.data.first().copied().unwrap_or(255);
            match TokenOperation::from_byte(operation_byte) {
                Some(TokenOperation::Transfer) | Some(TokenOperation::TransferOwnership) => {
                    ActionClass::TransferTokenOwnership
                }
                Some(TokenOperation::Pause)
                | Some(TokenOperation::Unpause)
                | Some(TokenOperation::AddMinter)
                | Some(TokenOperation::RemoveMinter) => ActionClass::AdministerToken,
                _ => ActionClass::Other,
            }
        }

        // NFT operations
        TxPayload::Nft(data) => match data.operation {
            NftOperation::Transfer | NftOperation::TransferCollectionOwnership => {
                ActionClass::TransferTokenOwnership
            }
            NftOperation::UpdateMetadata
            | NftOperation::UpdateCollectionConfig
            | NftOperation::LockToken
            | NftOperation::UnlockToken => ActionClass::AdministerToken,
            _ => ActionClass::Other,
        },

        // Staking operations
        TxPayload::Staking(_) => ActionClass::StakingOperation,

        // Governance actions (Equity domain)
        TxPayload::Equity(_) => ActionClass::GovernanceAction,

        // Contract operations
        TxPayload::ContractDeploy(_) => ActionClass::DeployContract,
        TxPayload::ContractCall(_) => ActionClass::CallContract,

        // Policy account self-management
        TxPayload::PolicyAccount(data) => match data.operation {
            PolicyAccountOperation::ModifyMembership => ActionClass::ModifyMembership,
            PolicyAccountOperation::ModifyPolicy => ActionClass::ModifyPolicy,
            _ => ActionClass::Other,
        },

        // All other actions default to Other (fail-closed)
        _ => ActionClass::Other,
    }
}

// =============================================================================
// Policy Account Executor
// =============================================================================

pub struct PolicyAccountExecutor {
    db: Arc<Database>,
}

impl PolicyAccountExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Execute a policy account operation
    pub fn execute(
        &self,
        sender: &Address,
        data: &PolicyAccountTxData,
        state: &State,
        proposer: &Address,
        fee: Balance,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        match data.operation {
            PolicyAccountOperation::Create => self.create_policy_account(sender, &data.data, state, current_height, block_timestamp),
            PolicyAccountOperation::SubmitProposal => {
                self.submit_proposal(sender, &data.data, state, current_height, block_timestamp)
            }
            PolicyAccountOperation::ExecuteProposal => {
                self.execute_proposal(sender, &data.data, state, proposer, fee, current_height, block_timestamp)
            }
            PolicyAccountOperation::CancelProposal => {
                self.cancel_proposal(sender, &data.data, state)
            }
            PolicyAccountOperation::ModifyMembership => {
                // This should only be called via ExecuteProposal
                Err(StateError::InvalidOperation(
                    "ModifyMembership must be executed via proposal".to_string(),
                ))
            }
            PolicyAccountOperation::ModifyPolicy => {
                // This should only be called via ExecuteProposal
                Err(StateError::InvalidOperation(
                    "ModifyPolicy must be executed via proposal".to_string(),
                ))
            }
            PolicyAccountOperation::Freeze => self.freeze_policy_account(sender, &data.data, state),
            PolicyAccountOperation::Unfreeze => {
                self.unfreeze_policy_account(sender, &data.data, state)
            }
        }
    }

    /// Create a new policy account
    fn create_policy_account(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize request
        let request: CreatePolicyAccountRequest = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Validate members
        if request.members.is_empty() || request.members.len() > MAX_MEMBERS {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Invalid member count: {} (must be 1-{})",
                request.members.len(),
                MAX_MEMBERS
            )));
        }

        // Check for duplicate members
        for i in 0..request.members.len() {
            for j in (i + 1)..request.members.len() {
                if request.members[i].address == request.members[j].address {
                    return Ok(PolicyAccountExecutionResult::failure(
                        "Duplicate member addresses".to_string(),
                    ));
                }
            }
        }

        // Validate all weights are positive
        for member in &request.members {
            if member.weight == 0 {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Member weights must be positive".to_string(),
                ));
            }
        }

        // Validate policy
        if !request.policy.is_valid() {
            return Ok(PolicyAccountExecutionResult::failure(
                "Invalid policy configuration".to_string(),
            ));
        }

        // Compute policy account ID
        let id = PolicyAccount::compute_id(&request.members, &request.salt);

        // Check if already exists
        let storage = PolicyAccountStorage::new(&self.db);
        if storage.policy_accounts().exists(&id)? {
            return Ok(PolicyAccountExecutionResult::failure(
                "Policy account already exists".to_string(),
            ));
        }

        // Derive address
        let address = PolicyAccount::id_to_address(&id);

        // Create policy account
        let policy_account = PolicyAccount {
            id,
            address,
            members: request.members.clone(),
            policy: request.policy,
            nonce: 0,
            status: PolicyAccountStatus::Active,
            created_at: current_height,
            created_timestamp: block_timestamp,
        };

        // Store
        storage.policy_accounts().put(&policy_account)?;

        // Build response
        let response = CreatePolicyAccountResponse {
            policy_account_id: id,
            address,
        };
        let response_data = bincode::serialize(&response)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: response_data,
            message: format!("Policy account created: {}", hex::encode(id)),
        })
    }

    /// Submit a proposal with approvals
    fn submit_proposal(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize request
        let request: SubmitProposalRequest = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get policy account
        let storage = PolicyAccountStorage::new(&self.db);
        let policy_account = match storage.policy_accounts().get(&request.policy_account_id)? {
            Some(pa) => pa,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Policy account not found".to_string(),
                ))
            }
        };

        // Check if active
        if !policy_account.status.is_active() {
            return Ok(PolicyAccountExecutionResult::failure(
                "Policy account is not active".to_string(),
            ));
        }

        // Verify sender is a member
        if !policy_account.is_member(sender) {
            return Ok(PolicyAccountExecutionResult::failure(
                "Sender is not a member".to_string(),
            ));
        }

        // Validate payload size
        if request.action_payload.len() > MAX_PROPOSAL_PAYLOAD_SIZE {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Action payload too large: {} bytes (max: {})",
                request.action_payload.len(),
                MAX_PROPOSAL_PAYLOAD_SIZE
            )));
        }

        // Deserialize action payload to classify it
        let action_payload: TxPayload = bincode::deserialize(&request.action_payload)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;
        let action_class = classify_action(&action_payload);

        // Compute action hash
        let action_hash = Hash::hash(&request.action_payload);

        // Compute proposal ID
        let proposal_id = Proposal::compute_id(
            &request.policy_account_id,
            policy_account.nonce,
            &action_hash,
        );

        // Check if proposal already exists
        if storage.proposals().exists(&proposal_id)? {
            return Ok(PolicyAccountExecutionResult::failure(
                "Proposal already exists".to_string(),
            ));
        }

        // Validate approvals
        if request.approvals.len() > MAX_APPROVALS {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Too many approvals: {} (max: {})",
                request.approvals.len(),
                MAX_APPROVALS
            )));
        }

        // Check for duplicate approvals
        for i in 0..request.approvals.len() {
            for j in (i + 1)..request.approvals.len() {
                if request.approvals[i].approver == request.approvals[j].approver {
                    return Ok(PolicyAccountExecutionResult::failure(
                        "Duplicate approvals detected".to_string(),
                    ));
                }
            }
        }

        // Verify all approvers are members
        for approval in &request.approvals {
            if !policy_account.is_member(&approval.approver) {
                return Ok(PolicyAccountExecutionResult::failure(format!(
                    "Approver is not a member: {}",
                    approval.approver
                )));
            }
        }

        // Verify each approval's Ed25519 signature over the canonical message.
        // The signing bytes bind the account, the exact action, and the policy
        // nonce (replay protection). An `Address` is a one-way hash of the key,
        // so each approval carries the approver's pubkey, which must hash to the
        // approver address before the signature is checked.
        let approval_message = Proposal::approval_signing_bytes(
            &request.policy_account_id,
            &action_hash,
            policy_account.nonce,
        );

        for approval in &request.approvals {
            if Address::from_public_key(&approval.approver_pubkey) != approval.approver {
                return Ok(PolicyAccountExecutionResult::failure(format!(
                    "Approver pubkey does not match address: {}",
                    approval.approver
                )));
            }
            if verify_bytes(&approval_message, &approval.signature, &approval.approver_pubkey)
                .is_err()
            {
                return Ok(PolicyAccountExecutionResult::failure(format!(
                    "Invalid approval signature from approver: {}",
                    approval.approver
                )));
            }
        }

        // Create proposal
        let proposal = Proposal {
            id: proposal_id,
            policy_account_id: request.policy_account_id,
            policy_nonce: policy_account.nonce,
            proposer: *sender,
            action_class,
            action_data: request.action_payload,
            action_hash,
            approvals: request.approvals,
            status: ProposalStatus::Pending,
            expires_at: request.expires_at,
            created_at: block_timestamp,
            created_height: current_height,
        };

        // Validate proposal structure
        if !proposal.is_valid() {
            return Ok(PolicyAccountExecutionResult::failure(
                "Invalid proposal structure".to_string(),
            ));
        }

        // Store proposal
        storage.proposals().put(&proposal)?;

        // Build response
        let response = SubmitProposalResponse {
            proposal_id,
            status: ProposalStatus::Pending,
        };
        let response_data = bincode::serialize(&response)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: response_data,
            message: format!(
                "Proposal submitted: {} ({} approvals)",
                hex::encode(proposal_id),
                proposal.approvals.len()
            ),
        })
    }

    /// Execute a proposal once threshold is met
    fn execute_proposal(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
        proposer: &Address,
        fee: Balance,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize request
        let request: ExecuteProposalRequest = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get proposal
        let storage = PolicyAccountStorage::new(&self.db);
        let mut proposal = match storage.proposals().get(&request.proposal_id)? {
            Some(p) => p,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Proposal not found".to_string(),
                ))
            }
        };

        // Check status
        if !proposal.status.is_pending() {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Proposal is not pending (status: {:?})",
                proposal.status
            )));
        }

        // Check expiration
        if block_timestamp > proposal.expires_at {
            proposal.status = ProposalStatus::Expired;
            storage.proposals().put(&proposal)?;
            return Ok(PolicyAccountExecutionResult::failure(
                "Proposal has expired".to_string(),
            ));
        }

        // Get policy account
        let mut policy_account = match storage
            .policy_accounts()
            .get(&proposal.policy_account_id)?
        {
            Some(pa) => pa,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Policy account not found".to_string(),
                ))
            }
        };

        // Verify policy nonce matches (replay protection)
        if proposal.policy_nonce != policy_account.nonce {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Nonce mismatch: proposal nonce {} != current nonce {}",
                proposal.policy_nonce, policy_account.nonce
            )));
        }

        // Check if policy account is active
        if !policy_account.status.is_active() {
            return Ok(PolicyAccountExecutionResult::failure(
                "Policy account is not active".to_string(),
            ));
        }

        // Get threshold for this action class
        let threshold = policy_account.policy.threshold_for(proposal.action_class);

        // Count approvals and weights
        let num_approvals = proposal.approvals.len() as u32;
        let total_members = policy_account.members.len() as u32;

        let mut approval_weight = 0u64;
        for approval in &proposal.approvals {
            if let Some(member) = policy_account.members.iter().find(|m| m.address == approval.approver) {
                approval_weight += member.weight;
            }
        }
        let total_weight = policy_account.total_weight();

        // Check if threshold is met
        if !threshold.is_met(num_approvals, total_members, approval_weight, total_weight) {
            return Ok(PolicyAccountExecutionResult::failure(format!(
                "Threshold not met: {} approvals, {} total members, {} approval weight, {} total weight (required: {:?})",
                num_approvals, total_members, approval_weight, total_weight, threshold
            )));
        }

        // Deserialize the action payload
        let action_payload: TxPayload = bincode::deserialize(&proposal.action_data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Handle special cases: ModifyMembership and ModifyPolicy
        match proposal.action_class {
            ActionClass::ModifyMembership => {
                if let TxPayload::PolicyAccount(policy_data) = &action_payload {
                    let modify_request: ModifyMembershipRequest =
                        bincode::deserialize(&policy_data.data)
                            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

                    // Update members
                    policy_account.members = modify_request.new_members;

                    // Validate
                    if !policy_account.is_valid() {
                        return Ok(PolicyAccountExecutionResult::failure(
                            "Invalid new membership configuration".to_string(),
                        ));
                    }
                }
            }
            ActionClass::ModifyPolicy => {
                if let TxPayload::PolicyAccount(policy_data) = &action_payload {
                    let modify_request: ModifyPolicyRequest =
                        bincode::deserialize(&policy_data.data)
                            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

                    // Update policy
                    policy_account.policy = modify_request.new_policy;

                    // Validate
                    if !policy_account.is_valid() {
                        return Ok(PolicyAccountExecutionResult::failure(
                            "Invalid new policy configuration".to_string(),
                        ));
                    }
                }
            }
            ActionClass::TransferNative => {
                // Execute native transfer as policy account
                if let TxPayload::Transfer { to, amount } = &action_payload {
                    state.transfer(&policy_account.address, to, *amount, 0, proposer)?;
                } else {
                    return Ok(PolicyAccountExecutionResult::failure(
                        "Action payload mismatch for TransferNative".to_string(),
                    ));
                }
            }
            ActionClass::TransferTokenOwnership
            | ActionClass::AdministerToken
            | ActionClass::StakingOperation
            | ActionClass::GovernanceAction
            | ActionClass::DeployContract
            | ActionClass::CallContract
            | ActionClass::Other => {
                // Fail closed: wrapped non-policy actions other than native
                // transfer are not executed in v1. Running them "on behalf of"
                // the policy account requires atomic cross-executor dispatch with
                // per-tx rollback, which the state model does not yet provide.
                //
                // Returning a failure here means the proposal is NOT marked
                // Executed and the policy nonce is NOT advanced (the code below
                // is skipped), so the proposal can still execute later once safe
                // dispatch lands. The block executor treats this as a semantic
                // failure and charges the outer fee + submitter nonce.
                return Ok(PolicyAccountExecutionResult::failure(format!(
                    "Wrapped action class {:?} is not supported for execution yet",
                    proposal.action_class
                )));
            }
        }

        // Increment policy nonce (replay protection)
        policy_account.nonce += 1;
        let new_nonce = policy_account.nonce;

        // Update policy account
        storage.policy_accounts().put(&policy_account)?;

        // Mark proposal as executed
        proposal.status = ProposalStatus::Executed;
        storage.proposals().put(&proposal)?;

        // Build response
        let response = ExecuteProposalResponse {
            success: true,
            new_policy_nonce: new_nonce,
            message: "Proposal executed successfully".to_string(),
        };
        let response_data = bincode::serialize(&response)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: response_data,
            message: format!("Proposal executed: {}", hex::encode(request.proposal_id)),
        })
    }

    /// Cancel a proposal (proposer only)
    fn cancel_proposal(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize proposal ID
        let proposal_id: ProposalId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get proposal
        let storage = PolicyAccountStorage::new(&self.db);
        let mut proposal = match storage.proposals().get(&proposal_id)? {
            Some(p) => p,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Proposal not found".to_string(),
                ))
            }
        };

        // Verify sender is proposer
        if &proposal.proposer != sender {
            return Ok(PolicyAccountExecutionResult::failure(
                "Only proposer can cancel".to_string(),
            ));
        }

        // Check status
        if !proposal.status.is_pending() {
            return Ok(PolicyAccountExecutionResult::failure(
                "Proposal is not pending".to_string(),
            ));
        }

        // Mark as cancelled
        proposal.status = ProposalStatus::Cancelled;
        storage.proposals().put(&proposal)?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: vec![],
            message: format!("Proposal cancelled: {}", hex::encode(proposal_id)),
        })
    }

    /// Freeze a policy account
    fn freeze_policy_account(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        let policy_account_id: PolicyAccountId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let storage = PolicyAccountStorage::new(&self.db);
        let policy_account = match storage.policy_accounts().get(&policy_account_id)? {
            Some(pa) => pa,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Policy account not found".to_string(),
                ))
            }
        };

        // Only members can freeze
        if !policy_account.is_member(sender) {
            return Ok(PolicyAccountExecutionResult::failure(
                "Only members can freeze".to_string(),
            ));
        }

        storage
            .policy_accounts()
            .update_status(&policy_account_id, PolicyAccountStatus::Frozen)?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: vec![],
            message: "Policy account frozen".to_string(),
        })
    }

    /// Unfreeze a policy account
    fn unfreeze_policy_account(
        &self,
        sender: &Address,
        data: &[u8],
        state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        let policy_account_id: PolicyAccountId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let storage = PolicyAccountStorage::new(&self.db);
        let policy_account = match storage.policy_accounts().get(&policy_account_id)? {
            Some(pa) => pa,
            None => {
                return Ok(PolicyAccountExecutionResult::failure(
                    "Policy account not found".to_string(),
                ))
            }
        };

        // Only members can unfreeze
        if !policy_account.is_member(sender) {
            return Ok(PolicyAccountExecutionResult::failure(
                "Only members can unfreeze".to_string(),
            ));
        }

        storage
            .policy_accounts()
            .update_status(&policy_account_id, PolicyAccountStatus::Active)?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: vec![],
            message: "Policy account unfrozen".to_string(),
        })
    }
}

// =============================================================================
// Execution Result
// =============================================================================

#[derive(Debug, Clone)]
pub struct PolicyAccountExecutionResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub message: String,
}

impl PolicyAccountExecutionResult {
    pub fn failure(message: String) -> Self {
        Self {
            success: false,
            data: vec![],
            message,
        }
    }
}
