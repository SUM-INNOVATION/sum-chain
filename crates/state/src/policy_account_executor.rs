//! Policy Account Executor
//!
//! Handles execution of policy account operations:
//! - Creating group-governed addresses
//! - Submitting proposals with member approvals
//! - Executing proposals once threshold is met
//! - Managing membership and policy changes

use crate::StateManager;
use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    policy_account::{
        ActionClass, MemberApproval, PolicyAccount, PolicyAccountId, PolicyAccountOperation,
        PolicyAccountStatus, PolicyAccountTxData, PolicyConfig, PolicyMember, PolicyNonce,
        PolicyProfile, PolicyRule, Proposal, ProposalId, ProposalStatus, MAX_APPROVALS,
        MAX_MEMBERS, MAX_PROPOSAL_PAYLOAD_SIZE,
    },
    Address, Balance, BlockHeight, Hash, Timestamp, TxPayload,
};
use sumchain_primitives::{NftOperation, TokenOperation, TokenTxData};
use sumchain_crypto::verify_bytes;

use crate::token_executor::TokenExecutor;
use crate::{Result, State, StateError};

/// Whether a `PolicyAccount` operation may be SUBMITTED as a transaction.
///
/// `ModifyMembership` and `ModifyPolicy` may not: they exist as the effect an
/// `ExecuteProposal` applies once a policy account's members have approved it,
/// and `PolicyAccountExecutor::execute` refuses a directly submitted one on the
/// operation code alone, before reading any state.
///
/// Named once and read twice — by the executor, which refuses, and by
/// `Mempool::add`, which declines to admit what the executor will refuse. Two
/// hand-maintained lists of the same operations would be one edit away from
/// disagreeing, and the disagreement that matters is a mempool admitting a
/// transaction that makes every block it is selected into unexecutable.
pub fn policy_account_operation_is_submittable(op: PolicyAccountOperation) -> bool {
    !matches!(
        op,
        PolicyAccountOperation::ModifyMembership | PolicyAccountOperation::ModifyPolicy
    )
}

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

        // Token operations. Classify from the typed `operation` field — the
        // op-specific `data` is a bincode payload with no op-byte prefix (see the
        // token no-key builder), so the previous `data.first()` byte-sniff
        // mis-classified every real payload (e.g. Pause has empty `data`). Using
        // the field is what makes the five Policy-Account admin ops (#90)
        // classify correctly and reach dispatch.
        TxPayload::Token(data) => match data.operation {
            TokenOperation::Transfer | TokenOperation::TransferOwnership => {
                ActionClass::TransferTokenOwnership
            }
            TokenOperation::Pause
            | TokenOperation::Unpause
            | TokenOperation::AddMinter
            | TokenOperation::RemoveMinter => ActionClass::AdministerToken,
            _ => ActionClass::Other,
        },

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

/// No database handle, by construction.
///
/// Every operation below takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name any more — a committed write
/// here is a compile error rather than a review finding. The committed twins
/// live in `sumchain_storage::policy_account_store` and are still used by the
/// RPC server, which is asking about the canonical chain.
pub struct PolicyAccountExecutor;

impl PolicyAccountExecutor {
    /// Execute a policy account operation
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &PolicyAccountTxData,
        state: &State,
        proposer: &Address,
        fee: Balance,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        match data.operation {
            PolicyAccountOperation::Create => Self::create_policy_account(
                view,
                sender,
                &data.data,
                state,
                current_height,
                block_timestamp,
            ),
            PolicyAccountOperation::SubmitProposal => Self::submit_proposal(
                view,
                sender,
                &data.data,
                state,
                current_height,
                block_timestamp,
            ),
            PolicyAccountOperation::ExecuteProposal => Self::execute_proposal(
                view, sender, &data.data, state, proposer, fee, current_height, block_timestamp,
            ),
            PolicyAccountOperation::CancelProposal => {
                Self::cancel_proposal(view, sender, &data.data, state)
            }
            op @ (PolicyAccountOperation::ModifyMembership
            | PolicyAccountOperation::ModifyPolicy) => {
                // Reachable only as the EFFECT of an ExecuteProposal, never as
                // a submission — decided on the operation code alone, before
                // any state is read. `policy_account_operation_is_submittable`
                // above is the same fact, read by the mempool.
                //
                // `UnsubmittableOperation` rather than `InvalidOperation`, and
                // the difference is what a proposer is allowed to do about it.
                // This error propagates out of `execute_block` and makes the
                // whole block unexecutable, so the proposer must drop the
                // transaction or produce nothing at all; and because no later
                // state reverses the refusal, it may also EVICT it rather than
                // select it first again on the next tick, forever.
                // `InvalidOperation` cannot carry that licence:
                // `StakingView::v_claim_rewards` raises it for a validator that
                // has not registered YET. See
                // `sumchain_state::classify_block_tx_failure`.
                debug_assert!(!policy_account_operation_is_submittable(op));
                Err(StateError::UnsubmittableOperation {
                    operation: format!("PolicyAccount::{op:?}"),
                    reason: "it is reachable only as the effect of an ExecuteProposal".to_string(),
                })
            }
            PolicyAccountOperation::Freeze => {
                Self::freeze_policy_account(view, sender, &data.data, state)
            }
            PolicyAccountOperation::Unfreeze => {
                Self::unfreeze_policy_account(view, sender, &data.data, state)
            }
        }
    }

    /// Create a new policy account
    fn create_policy_account(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
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
        if Self::v_policy_account_exists(view, &id)? {
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
        Self::v_put_policy_account(view, &policy_account)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize request
        let request: SubmitProposalRequest = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get policy account
        let policy_account = match Self::v_get_policy_account(view, &request.policy_account_id)? {
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
        if Self::v_get_proposal(view, &proposal_id)?.is_some() {
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
        Self::v_put_proposal(view, &proposal)?;

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
    #[allow(clippy::too_many_arguments)]
    fn execute_proposal(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
        proposer: &Address,
        fee: Balance,
        current_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize request
        let request: ExecuteProposalRequest = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get proposal
        let mut proposal = match Self::v_get_proposal(view, &request.proposal_id)? {
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
            Self::v_put_proposal(view, &proposal)?;
            return Ok(PolicyAccountExecutionResult::failure(
                "Proposal has expired".to_string(),
            ));
        }

        // Get policy account
        let mut policy_account = match Self::v_get_policy_account(view, &proposal.policy_account_id)?
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
                    StateManager::v_transfer(view, &policy_account.address, to, *amount, 0, proposer)?;
                } else {
                    return Ok(PolicyAccountExecutionResult::failure(
                        "Action payload mismatch for TransferNative".to_string(),
                    ));
                }
            }
            ActionClass::AdministerToken | ActionClass::TransferTokenOwnership => {
                // Governance-v2 (#90): execute the wrapped Token admin op AS the
                // policy account. Only the five allowlisted ops (Pause, Unpause,
                // AddMinter, RemoveMinter, TransferOwnership) run; any other Token
                // op is fail-closed inside `apply_policy_admin_op`. A wrapped Token
                // payload is required — an action-class mismatch (non-Token
                // payload) fails closed.
                let TxPayload::Token(token_data) = &action_payload else {
                    return Ok(PolicyAccountExecutionResult::failure(
                        "Action payload mismatch for token admin op".to_string(),
                    ));
                };
                // Each per-op handler validates fully and performs its single
                // `put_token` only on success, so a failure leaves NO partial
                // token state. `sender = policy_account.address` — the policy
                // account acts as the token owner/authority.
                // Staged into the same candidate as the rest of this action.
                // The wrapped op used to reach a committed `TokenStore` while
                // everything around it staged; a policy account administering a
                // token would then have committed that change even if the block
                // was abandoned.
                let token_result = TokenExecutor::apply_policy_admin_op(
                    view,
                    &policy_account.address,
                    token_data,
                )?;
                if !token_result.success {
                    // Token op rejected: do NOT mark Executed, do NOT advance the
                    // policy nonce (the code below is skipped), and leave no
                    // partial state. Block executor charges the outer fee + nonce.
                    return Ok(PolicyAccountExecutionResult::failure(format!(
                        "Wrapped token op failed: {}",
                        token_result.error.unwrap_or_else(|| "unknown error".to_string())
                    )));
                }
            }
            ActionClass::StakingOperation
            | ActionClass::GovernanceAction
            | ActionClass::DeployContract
            | ActionClass::CallContract
            | ActionClass::Other => {
                // Fail closed: only native transfer and the five Token admin ops
                // are executable on behalf of a policy account. NFT/Staking/
                // Governance/Deploy/Call/Other are not dispatched. Returning a
                // failure means the proposal is NOT marked Executed and the policy
                // nonce is NOT advanced (the code below is skipped). The block
                // executor treats this as a semantic failure and charges the outer
                // fee + submitter nonce.
                return Ok(PolicyAccountExecutionResult::failure(format!(
                    "Wrapped action class {:?} is not supported for execution",
                    proposal.action_class
                )));
            }
        }

        // Increment policy nonce (replay protection)
        policy_account.nonce += 1;
        let new_nonce = policy_account.nonce;

        // Update policy account
        Self::v_put_policy_account(view, &policy_account)?;

        // Mark proposal as executed
        proposal.status = ProposalStatus::Executed;
        Self::v_put_proposal(view, &proposal)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        // Deserialize proposal ID
        let proposal_id: ProposalId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        // Get proposal
        let mut proposal = match Self::v_get_proposal(view, &proposal_id)? {
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
        Self::v_put_proposal(view, &proposal)?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: vec![],
            message: format!("Proposal cancelled: {}", hex::encode(proposal_id)),
        })
    }

    /// Freeze a policy account
    fn freeze_policy_account(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        let policy_account_id: PolicyAccountId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let policy_account = match Self::v_get_policy_account(view, &policy_account_id)? {
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

        Self::v_update_policy_account_status(view, &policy_account_id, PolicyAccountStatus::Frozen)?;

        Ok(PolicyAccountExecutionResult {
            success: true,
            data: vec![],
            message: "Policy account frozen".to_string(),
        })
    }

    /// Unfreeze a policy account
    fn unfreeze_policy_account(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        _state: &State,
    ) -> Result<PolicyAccountExecutionResult> {
        let policy_account_id: PolicyAccountId = bincode::deserialize(data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let policy_account = match Self::v_get_policy_account(view, &policy_account_id)? {
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

        Self::v_update_policy_account_status(view, &policy_account_id, PolicyAccountStatus::Active)?;

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
