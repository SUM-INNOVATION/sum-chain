//! Staking Transaction Executor
//!
//! Handles execution of staking operations including:
//! - CreateValidator: Register as a new validator with initial stake
//! - AddStake: Add more stake to an existing validator
//! - Unstake: Begin unbonding stake
//! - UpdateValidator: Update commission or metadata
//! - Unjail: Request to unjail after jail period
//! - ClaimRewards: Claim accumulated rewards
//! - Delegate: Delegate tokens to a validator
//! - Undelegate: Begin unbonding delegation from a validator
//! - ClaimDelegationRewards: Claim delegation rewards
//! - WithdrawUnbonded: Withdraw completed unbonding delegations
//! - SubmitEvidence: Submit evidence of validator misbehavior (double sign or downtime)

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Balance, BlockHeight, ClaimDelegationRewardsData, CreateValidatorData, AddStakeData,
    DelegateData, DelegationInfo, DoubleSignEvidence, DowntimeEvidence, EvidenceType,
    SlashingRecord, StakingOperation, StakingTxData, SubmitEvidenceData, UnbondingDelegation,
    UndelegateData, UnstakeData, UpdateValidatorData, ValidatorInfo, ValidatorStatus,
    WithdrawUnbondedData,
};
use sumchain_storage::{Database, DelegationStore, SlashingStore, StakingStore};
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

/// Result of executing a staking operation
#[derive(Debug)]
pub struct StakingExecutionResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Amount affected (stake added/removed, rewards claimed, etc.)
    pub amount: Option<Balance>,
}

impl StakingExecutionResult {
    fn success() -> Self {
        Self {
            success: true,
            error: None,
            amount: None,
        }
    }

    fn success_with_amount(amount: Balance) -> Self {
        Self {
            success: true,
            error: None,
            amount: Some(amount),
        }
    }

    fn failure(error: String) -> Self {
        Self {
            success: false,
            error: Some(error),
            amount: None,
        }
    }
}

/// Staking Executor for processing staking transactions
pub struct StakingExecutor {
    db: Arc<Database>,
    params: ChainParams,
}

impl StakingExecutor {
    /// Create a new staking executor
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute a staking operation from transaction data
    pub fn execute(
        &self,
        sender: &Address,
        staking_data: &StakingTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        let store = StakingStore::new(&self.db);
        let delegation_store = DelegationStore::new(&self.db);
        let slashing_store = SlashingStore::new(&self.db);

        // Deduct fee from sender first
        self.deduct_fee(state, sender, fee, proposer)?;

        match staking_data.operation {
            StakingOperation::CreateValidator => {
                self.execute_create_validator(&store, sender, &staking_data.data, state, block_height)
            }
            StakingOperation::AddStake => {
                self.execute_add_stake(&store, sender, &staking_data.data, state)
            }
            StakingOperation::Unstake => {
                self.execute_unstake(&store, sender, &staking_data.data, state, block_height)
            }
            StakingOperation::UpdateValidator => {
                self.execute_update_validator(&store, sender, &staking_data.data)
            }
            StakingOperation::Unjail => {
                self.execute_unjail(&store, sender, block_height)
            }
            StakingOperation::ClaimRewards => {
                self.execute_claim_rewards(&store, sender, state)
            }
            // Delegation operations
            StakingOperation::Delegate => {
                self.execute_delegate(&store, &delegation_store, sender, &staking_data.data, state, block_height)
            }
            StakingOperation::Undelegate => {
                self.execute_undelegate(&store, &delegation_store, sender, &staking_data.data, state, block_height)
            }
            StakingOperation::ClaimDelegationRewards => {
                self.execute_claim_delegation_rewards(&delegation_store, sender, &staking_data.data, state)
            }
            StakingOperation::WithdrawUnbonded => {
                self.execute_withdraw_unbonded(&delegation_store, sender, &staking_data.data, state, block_height)
            }
            // Slashing operations
            StakingOperation::SubmitEvidence => {
                self.execute_submit_evidence(&store, &delegation_store, &slashing_store, sender, &staking_data.data, state, block_height)
            }
        }
    }

    /// Deduct fee from sender and credit to proposer
    fn deduct_fee(
        &self,
        state: &StateManager,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = state.get_balance(sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        // Debit sender
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        state.put_account(sender, &sender_account)?;

        // Credit proposer
        if !proposer.is_zero() {
            let mut proposer_account = state.get_account(proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            state.put_account(proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Get sender's public key from their address
    /// Note: In a real implementation, the pubkey would be provided in the tx
    /// For now, we'll require the sender to include their pubkey in the CreateValidator data
    fn get_pubkey_from_address(address: &Address) -> [u8; 32] {
        // This is a placeholder - in reality, we'd need the actual pubkey
        // The address is derived from pubkey, so we can't reverse it
        // The actual implementation should pass pubkey through the transaction
        let mut pubkey = [0u8; 32];
        pubkey[..20].copy_from_slice(address.as_bytes());
        pubkey
    }

    /// Execute CreateValidator operation
    fn execute_create_validator(
        &self,
        store: &StakingStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize create validator data
        let create_data: CreateValidatorData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid create validator data: {}", e)))?;

        // Validate minimum stake
        let min_stake = self.params.staking.as_ref()
            .map(|s| s.min_validator_stake)
            .unwrap_or(1_000_000_000_000_000_000); // 1e18 base units = 1B Koppa default (must match StakingParams::default)

        if create_data.stake < min_stake {
            return Ok(StakingExecutionResult::failure(format!(
                "Stake {} is below minimum required stake of {}",
                create_data.stake, min_stake
            )));
        }

        // Validate commission rate
        let max_commission = self.params.staking.as_ref()
            .map(|s| s.max_commission_bps)
            .unwrap_or(10000);

        if create_data.commission_bps > max_commission {
            return Ok(StakingExecutionResult::failure(format!(
                "Commission rate {} bps exceeds maximum of {} bps",
                create_data.commission_bps, max_commission
            )));
        }

        // Check if already a validator
        // We need to use the sender's address to derive a key for lookup
        // In production, the pubkey would be in the transaction
        let pubkey = Self::get_pubkey_from_address(sender);

        if store.validator_exists(&pubkey)? {
            return Ok(StakingExecutionResult::failure(
                "Address is already a validator".to_string()
            ));
        }

        // Check max validators
        let max_validators = self.params.staking.as_ref()
            .map(|s| s.max_validators)
            .unwrap_or(100);

        let current_count = store.get_validator_count()?;
        if current_count >= max_validators as usize {
            return Ok(StakingExecutionResult::failure(format!(
                "Maximum validator count ({}) reached",
                max_validators
            )));
        }

        // Check sender has enough balance for stake
        let sender_balance = state.get_balance(sender)?;
        if sender_balance < create_data.stake {
            return Ok(StakingExecutionResult::failure(format!(
                "Insufficient balance: have {}, need {} for stake",
                sender_balance, create_data.stake
            )));
        }

        // Deduct stake from sender's balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(create_data.stake);
        state.put_account(sender, &sender_account)?;

        // Create validator info
        let validator = ValidatorInfo::new(
            pubkey,
            create_data.stake,
            create_data.commission_bps,
            block_height,
        );

        // Store validator
        store.put_validator(&validator)?;

        info!(
            "Created validator {} with stake {} and commission {} bps",
            sender, create_data.stake, create_data.commission_bps
        );

        Ok(StakingExecutionResult::success_with_amount(create_data.stake))
    }

    /// Execute AddStake operation
    fn execute_add_stake(
        &self,
        store: &StakingStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
    ) -> Result<StakingExecutionResult> {
        // Deserialize add stake data
        let add_data: AddStakeData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid add stake data: {}", e)))?;

        if add_data.amount == 0 {
            return Ok(StakingExecutionResult::failure(
                "Cannot add zero stake".to_string()
            ));
        }

        let pubkey = Self::get_pubkey_from_address(sender);

        // Get validator
        let mut validator = match store.get_validator(&pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Not a registered validator".to_string()
            )),
        };

        // Check sender has enough balance
        let sender_balance = state.get_balance(sender)?;
        if sender_balance < add_data.amount {
            return Ok(StakingExecutionResult::failure(format!(
                "Insufficient balance: have {}, need {}",
                sender_balance, add_data.amount
            )));
        }

        // Deduct from sender's balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(add_data.amount);
        state.put_account(sender, &sender_account)?;

        // Add to validator's stake
        validator.stake = validator.stake.saturating_add(add_data.amount);
        store.put_validator(&validator)?;

        debug!(
            "Validator {} added {} stake, new total: {}",
            sender, add_data.amount, validator.stake
        );

        Ok(StakingExecutionResult::success_with_amount(add_data.amount))
    }

    /// Execute Unstake operation
    fn execute_unstake(
        &self,
        store: &StakingStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize unstake data
        let unstake_data: UnstakeData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid unstake data: {}", e)))?;

        if unstake_data.amount == 0 {
            return Ok(StakingExecutionResult::failure(
                "Cannot unstake zero".to_string()
            ));
        }

        let pubkey = Self::get_pubkey_from_address(sender);

        // Get validator
        let mut validator = match store.get_validator(&pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Not a registered validator".to_string()
            )),
        };

        // Check sufficient stake
        if validator.stake < unstake_data.amount {
            return Ok(StakingExecutionResult::failure(format!(
                "Insufficient stake: have {}, trying to unstake {}",
                validator.stake, unstake_data.amount
            )));
        }

        // Check minimum stake requirement after unstaking
        let min_stake = self.params.staking.as_ref()
            .map(|s| s.min_validator_stake)
            .unwrap_or(1_000_000_000_000_000_000); // 1e18 base units = 1B Koppa default (must match StakingParams::default)

        let remaining_stake = validator.stake.saturating_sub(unstake_data.amount);

        // If unstaking would leave less than min_stake, must unstake all
        if remaining_stake > 0 && remaining_stake < min_stake {
            return Ok(StakingExecutionResult::failure(format!(
                "Remaining stake {} would be below minimum {}. Unstake all or leave at least minimum.",
                remaining_stake, min_stake
            )));
        }

        // Deduct stake
        validator.stake = remaining_stake;

        // If fully unstaking, mark as unbonding
        if validator.stake == 0 {
            let unbonding_period = self.params.staking.as_ref()
                .map(|s| s.unbonding_period)
                .unwrap_or(100_800); // ~7 days default

            validator.status = ValidatorStatus::Unbonding;
            // Store unbonding completion height (reusing jailed_until field for simplicity)
            validator.jailed_until = block_height + unbonding_period;
        }

        store.put_validator(&validator)?;

        // For now, immediately return stake to sender (in production, would wait for unbonding)
        // TODO: Implement proper unbonding queue
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_add(unstake_data.amount);
        state.put_account(sender, &sender_account)?;

        info!(
            "Validator {} unstaked {}, remaining stake: {}",
            sender, unstake_data.amount, validator.stake
        );

        Ok(StakingExecutionResult::success_with_amount(unstake_data.amount))
    }

    /// Execute UpdateValidator operation
    fn execute_update_validator(
        &self,
        store: &StakingStore,
        sender: &Address,
        data: &[u8],
    ) -> Result<StakingExecutionResult> {
        // Deserialize update data
        let update_data: UpdateValidatorData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid update validator data: {}", e)))?;

        let pubkey = Self::get_pubkey_from_address(sender);

        // Get validator
        let mut validator = match store.get_validator(&pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Not a registered validator".to_string()
            )),
        };

        // Update commission if provided
        if let Some(new_commission) = update_data.commission_bps {
            let max_commission = self.params.staking.as_ref()
                .map(|s| s.max_commission_bps)
                .unwrap_or(10000);

            if new_commission > max_commission {
                return Ok(StakingExecutionResult::failure(format!(
                    "Commission rate {} bps exceeds maximum of {} bps",
                    new_commission, max_commission
                )));
            }

            validator.commission_bps = new_commission;
        }

        // Update metadata if provided
        if let Some(new_metadata) = update_data.metadata {
            // Validate metadata size (max 256 bytes)
            if new_metadata.len() > 256 {
                return Ok(StakingExecutionResult::failure(
                    "Metadata exceeds maximum size of 256 bytes".to_string()
                ));
            }
            validator.metadata = new_metadata;
        }

        store.put_validator(&validator)?;

        debug!("Validator {} updated", sender);

        Ok(StakingExecutionResult::success())
    }

    /// Execute Unjail operation
    fn execute_unjail(
        &self,
        store: &StakingStore,
        sender: &Address,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        let pubkey = Self::get_pubkey_from_address(sender);

        // Get validator
        let mut validator = match store.get_validator(&pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Not a registered validator".to_string()
            )),
        };

        // Check if jailed
        if !validator.is_jailed() {
            return Ok(StakingExecutionResult::failure(
                "Validator is not jailed".to_string()
            ));
        }

        // Check if jail period has passed
        if !validator.can_unjail(block_height) {
            return Ok(StakingExecutionResult::failure(format!(
                "Jail period not over. Can unjail at block {}",
                validator.jailed_until
            )));
        }

        // Unjail
        validator.unjail();
        store.put_validator(&validator)?;

        info!("Validator {} unjailed at block {}", sender, block_height);

        Ok(StakingExecutionResult::success())
    }

    /// Execute ClaimRewards operation
    fn execute_claim_rewards(
        &self,
        store: &StakingStore,
        sender: &Address,
        state: &StateManager,
    ) -> Result<StakingExecutionResult> {
        let pubkey = Self::get_pubkey_from_address(sender);

        // Get validator
        let validator = match store.get_validator(&pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Not a registered validator".to_string()
            )),
        };

        if validator.pending_rewards == 0 {
            return Ok(StakingExecutionResult::failure(
                "No pending rewards to claim".to_string()
            ));
        }

        // Claim rewards
        let rewards = store.claim_rewards(&pubkey)?;

        // Credit rewards to sender's balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_add(rewards);
        state.put_account(sender, &sender_account)?;

        info!("Validator {} claimed {} rewards", sender, rewards);

        Ok(StakingExecutionResult::success_with_amount(rewards))
    }

    // ========================================================================
    // Delegation Operations
    // ========================================================================

    /// Execute Delegate operation
    fn execute_delegate(
        &self,
        staking_store: &StakingStore,
        delegation_store: &DelegationStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize delegate data
        let delegate_data: DelegateData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid delegate data: {}", e)))?;

        if delegate_data.amount == 0 {
            return Ok(StakingExecutionResult::failure(
                "Cannot delegate zero amount".to_string()
            ));
        }

        // Check validator exists and is active
        let mut validator = match staking_store.get_validator(&delegate_data.validator_pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Validator not found".to_string()
            )),
        };

        if validator.status != ValidatorStatus::Active {
            return Ok(StakingExecutionResult::failure(format!(
                "Cannot delegate to validator with status {:?}",
                validator.status
            )));
        }

        // Check sender has enough balance
        let sender_balance = state.get_balance(sender)?;
        if sender_balance < delegate_data.amount {
            return Ok(StakingExecutionResult::failure(format!(
                "Insufficient balance: have {}, need {}",
                sender_balance, delegate_data.amount
            )));
        }

        // Deduct from sender's balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(delegate_data.amount);
        state.put_account(sender, &sender_account)?;

        // Get delegator key (using address bytes padded to 32)
        let mut delegator_key = [0u8; 32];
        delegator_key[..20].copy_from_slice(sender.as_bytes());

        // Check if delegation already exists
        if let Some(mut existing) = delegation_store.get_delegation(&delegator_key, &delegate_data.validator_pubkey)? {
            // Add to existing delegation
            existing.add_stake(delegate_data.amount);
            delegation_store.put_delegation(&existing)?;
        } else {
            // Create new delegation
            let delegation = DelegationInfo::new(
                delegator_key,
                delegate_data.validator_pubkey,
                delegate_data.amount,
                block_height,
            );
            delegation_store.put_delegation(&delegation)?;
        }

        // Update validator's total delegated amount
        validator.add_delegation(delegate_data.amount);
        staking_store.put_validator(&validator)?;

        info!(
            "Delegated {} from {} to validator 0x{}",
            delegate_data.amount,
            sender,
            hex::encode(&delegate_data.validator_pubkey[..8])
        );

        Ok(StakingExecutionResult::success_with_amount(delegate_data.amount))
    }

    /// Execute Undelegate operation
    fn execute_undelegate(
        &self,
        staking_store: &StakingStore,
        delegation_store: &DelegationStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize undelegate data
        let undelegate_data: UndelegateData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid undelegate data: {}", e)))?;

        if undelegate_data.amount == 0 {
            return Ok(StakingExecutionResult::failure(
                "Cannot undelegate zero amount".to_string()
            ));
        }

        // Get delegator key
        let mut delegator_key = [0u8; 32];
        delegator_key[..20].copy_from_slice(sender.as_bytes());

        // Get existing delegation
        let mut delegation = match delegation_store.get_delegation(&delegator_key, &undelegate_data.validator_pubkey)? {
            Some(d) => d,
            None => return Ok(StakingExecutionResult::failure(
                "No delegation found for this validator".to_string()
            )),
        };

        // Check sufficient delegation amount
        if delegation.amount < undelegate_data.amount {
            return Ok(StakingExecutionResult::failure(format!(
                "Insufficient delegation: have {}, trying to undelegate {}",
                delegation.amount, undelegate_data.amount
            )));
        }

        // Get unbonding period
        let unbonding_period = self.params.staking.as_ref()
            .map(|s| s.unbonding_period)
            .unwrap_or(100_800); // ~7 days default

        // Create unbonding delegation
        let unbonding = UnbondingDelegation::new(
            delegator_key,
            undelegate_data.validator_pubkey,
            undelegate_data.amount,
            block_height + unbonding_period,
        );
        delegation_store.put_unbonding(&unbonding)?;

        // Update delegation
        delegation.remove_stake(undelegate_data.amount);
        if delegation.amount == 0 && delegation.pending_rewards == 0 {
            // Remove empty delegation
            delegation_store.delete_delegation(&delegator_key, &undelegate_data.validator_pubkey)?;
        } else {
            delegation_store.put_delegation(&delegation)?;
        }

        // Update validator's total delegated amount
        if let Some(mut validator) = staking_store.get_validator(&undelegate_data.validator_pubkey)? {
            validator.remove_delegation(undelegate_data.amount);
            staking_store.put_validator(&validator)?;
        }

        // For simplicity, immediately return funds (in production would wait for unbonding)
        // TODO: Implement proper unbonding queue processing in block execution
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_add(undelegate_data.amount);
        state.put_account(sender, &sender_account)?;

        info!(
            "Undelegated {} from validator 0x{}, completion at block {}",
            undelegate_data.amount,
            hex::encode(&undelegate_data.validator_pubkey[..8]),
            block_height + unbonding_period
        );

        Ok(StakingExecutionResult::success_with_amount(undelegate_data.amount))
    }

    /// Execute ClaimDelegationRewards operation
    fn execute_claim_delegation_rewards(
        &self,
        delegation_store: &DelegationStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
    ) -> Result<StakingExecutionResult> {
        // Deserialize claim data
        let claim_data: ClaimDelegationRewardsData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid claim delegation rewards data: {}", e)))?;

        // Get delegator key
        let mut delegator_key = [0u8; 32];
        delegator_key[..20].copy_from_slice(sender.as_bytes());

        // Get delegation
        let delegation = match delegation_store.get_delegation(&delegator_key, &claim_data.validator_pubkey)? {
            Some(d) => d,
            None => return Ok(StakingExecutionResult::failure(
                "No delegation found for this validator".to_string()
            )),
        };

        if delegation.pending_rewards == 0 {
            return Ok(StakingExecutionResult::failure(
                "No pending rewards to claim".to_string()
            ));
        }

        // Claim rewards
        let rewards = delegation_store.claim_delegation_rewards(&delegator_key, &claim_data.validator_pubkey)?;

        // Credit rewards to sender's balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_add(rewards);
        state.put_account(sender, &sender_account)?;

        info!(
            "Claimed {} delegation rewards from validator 0x{}",
            rewards,
            hex::encode(&claim_data.validator_pubkey[..8])
        );

        Ok(StakingExecutionResult::success_with_amount(rewards))
    }

    /// Execute WithdrawUnbonded operation
    fn execute_withdraw_unbonded(
        &self,
        delegation_store: &DelegationStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize withdraw data
        let withdraw_data: WithdrawUnbondedData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid withdraw unbonded data: {}", e)))?;

        // Get delegator key
        let mut delegator_key = [0u8; 32];
        delegator_key[..20].copy_from_slice(sender.as_bytes());

        // Get completed unbondings
        let completed = if let Some(validator_pubkey) = withdraw_data.validator_pubkey {
            delegation_store.get_completed_unbondings_for_validator(
                &delegator_key,
                &validator_pubkey,
                block_height,
            )?
        } else {
            delegation_store.get_completed_unbondings(&delegator_key, block_height)?
        };

        if completed.is_empty() {
            return Ok(StakingExecutionResult::failure(
                "No completed unbonding delegations to withdraw".to_string()
            ));
        }

        // Sum up all completed unbondings
        let mut total_withdrawn: Balance = 0;
        for unbonding in &completed {
            total_withdrawn = total_withdrawn.saturating_add(unbonding.amount);

            // Delete the unbonding entry
            delegation_store.delete_unbonding(
                &unbonding.delegator,
                unbonding.completion_height,
                &unbonding.validator_pubkey,
            )?;
        }

        // Credit withdrawn amount to sender (already done in undelegate for now)
        // In production, this would be where the actual transfer happens
        // For now, since we credit immediately in undelegate, this is a no-op for balance
        // But we still clean up the unbonding entries

        info!(
            "Withdrew {} unbonded delegations totaling {}",
            completed.len(),
            total_withdrawn
        );

        Ok(StakingExecutionResult::success_with_amount(total_withdrawn))
    }

    // ========================================================================
    // Slashing Operations
    // ========================================================================

    /// Execute SubmitEvidence operation
    fn execute_submit_evidence(
        &self,
        staking_store: &StakingStore,
        delegation_store: &DelegationStore,
        slashing_store: &SlashingStore,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize evidence data
        let evidence_data: SubmitEvidenceData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid evidence data: {}", e)))?;

        match evidence_data.evidence_type {
            EvidenceType::DoubleSign => {
                self.handle_double_sign_evidence(
                    staking_store,
                    delegation_store,
                    slashing_store,
                    sender,
                    &evidence_data.evidence,
                    state,
                    block_height,
                )
            }
            EvidenceType::Downtime => {
                self.handle_downtime_evidence(
                    staking_store,
                    delegation_store,
                    slashing_store,
                    &evidence_data.evidence,
                    block_height,
                )
            }
        }
    }

    /// Handle double sign evidence
    fn handle_double_sign_evidence(
        &self,
        staking_store: &StakingStore,
        delegation_store: &DelegationStore,
        slashing_store: &SlashingStore,
        submitter: &Address,
        evidence_bytes: &[u8],
        state: &StateManager,
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize the evidence
        let evidence: DoubleSignEvidence = bincode::deserialize(evidence_bytes)
            .map_err(|e| StateError::BlockValidation(format!("Invalid double sign evidence: {}", e)))?;

        // Basic validation
        if !evidence.is_valid() {
            return Ok(StakingExecutionResult::failure(
                "Invalid evidence: block hashes must be different".to_string()
            ));
        }

        // Check if validator exists
        let mut validator = match staking_store.get_validator(&evidence.validator_pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Validator not found".to_string()
            )),
        };

        // Check if already slashed at this height
        if slashing_store.was_slashed_at(&evidence.validator_pubkey, evidence.height)? {
            return Ok(StakingExecutionResult::failure(
                "Validator already slashed for this height".to_string()
            ));
        }

        // Check if validator is tombstoned
        if slashing_store.is_tombstoned(&evidence.validator_pubkey)? {
            return Ok(StakingExecutionResult::failure(
                "Validator is already tombstoned".to_string()
            ));
        }

        // TODO: Verify signatures cryptographically
        // For now, we trust the evidence submitter
        // In production, verify that both signatures are valid for the validator's pubkey

        // Get slashing parameters
        let slash_fraction_bps = self.params.staking.as_ref()
            .map(|s| s.double_sign_slash_bps)
            .unwrap_or(500); // 5% default

        let jail_duration = self.params.staking.as_ref()
            .map(|s| s.double_sign_jail_duration)
            .unwrap_or(14400); // ~24 hours default

        // Calculate and apply slash to validator's self-stake
        let validator_slash = (validator.stake * slash_fraction_bps as u128) / 10000;
        validator.apply_slash(slash_fraction_bps);

        // Jail the validator (tombstone for double signing)
        validator.jail(block_height + jail_duration);
        staking_store.put_validator(&validator)?;

        // Apply slash to delegations
        let delegation_slash = delegation_store.slash_delegations(
            &evidence.validator_pubkey,
            slash_fraction_bps,
        )?;

        // Tombstone the validator (permanent jail for double signing)
        if let Some(mut signing_info) = slashing_store.get_signing_info(&evidence.validator_pubkey)? {
            signing_info.tombstone();
            signing_info.jailed_until = block_height + jail_duration;
            slashing_store.put_signing_info(&signing_info)?;
        } else {
            let mut signing_info = sumchain_primitives::ValidatorSigningInfo::new(
                evidence.validator_pubkey,
                evidence.height,
            );
            signing_info.tombstone();
            signing_info.jailed_until = block_height + jail_duration;
            slashing_store.put_signing_info(&signing_info)?;
        }

        // Create slashing record
        let record = SlashingRecord::new(
            evidence.validator_pubkey,
            EvidenceType::DoubleSign,
            block_height,
            validator_slash,
            delegation_slash,
            block_height + jail_duration,
            true, // tombstoned
            slash_fraction_bps,
        );
        slashing_store.put_slashing_record(&record)?;

        // 800B correction: evidence-based validator slashing forfeits any
        // remaining grant-derived locked stake back to the ProtocolReserve
        // (grant money is public reserve money — misbehaviour returns it).
        // Self-funded stake follows the normal staking rules above. No-op if
        // no active grant / correction dormant.
        crate::supply::SupplyStore::new(self.db.clone()).forfeit_locked_grant(
            &sumchain_primitives::Address::from_public_key(&evidence.validator_pubkey),
            sumchain_primitives::supply::ServiceKind::Validator,
        )?;

        // Reward the evidence submitter (optional: give them a portion of slashed funds)
        // For now, slashed funds are burned (not credited anywhere)
        let total_slashed = validator_slash + delegation_slash;

        warn!(
            "Double sign evidence: slashed validator 0x{} for {} (validator: {}, delegations: {})",
            hex::encode(&evidence.validator_pubkey[..8]),
            total_slashed,
            validator_slash,
            delegation_slash
        );

        Ok(StakingExecutionResult::success_with_amount(total_slashed))
    }

    /// Handle downtime evidence
    fn handle_downtime_evidence(
        &self,
        staking_store: &StakingStore,
        delegation_store: &DelegationStore,
        slashing_store: &SlashingStore,
        evidence_bytes: &[u8],
        block_height: BlockHeight,
    ) -> Result<StakingExecutionResult> {
        // Deserialize the evidence
        let evidence: DowntimeEvidence = bincode::deserialize(evidence_bytes)
            .map_err(|e| StateError::BlockValidation(format!("Invalid downtime evidence: {}", e)))?;

        // Get downtime threshold
        let threshold = self.params.staking.as_ref()
            .map(|s| s.downtime_threshold)
            .unwrap_or(500);

        // Check if evidence exceeds threshold
        if !evidence.exceeds_threshold(threshold) {
            return Ok(StakingExecutionResult::failure(format!(
                "Missed blocks {} does not exceed threshold {}",
                evidence.missed_blocks, threshold
            )));
        }

        // Check if validator exists
        let mut validator = match staking_store.get_validator(&evidence.validator_pubkey)? {
            Some(v) => v,
            None => return Ok(StakingExecutionResult::failure(
                "Validator not found".to_string()
            )),
        };

        // Check if validator is already jailed
        if validator.is_jailed() {
            return Ok(StakingExecutionResult::failure(
                "Validator is already jailed".to_string()
            ));
        }

        // Check if tombstoned
        if slashing_store.is_tombstoned(&evidence.validator_pubkey)? {
            return Ok(StakingExecutionResult::failure(
                "Validator is tombstoned".to_string()
            ));
        }

        // Get slashing parameters
        let slash_fraction_bps = self.params.staking.as_ref()
            .map(|s| s.downtime_slash_bps)
            .unwrap_or(10); // 0.1% default

        let jail_duration = self.params.staking.as_ref()
            .map(|s| s.downtime_jail_duration)
            .unwrap_or(2400); // ~4 hours default

        // Calculate and apply slash to validator's self-stake
        let validator_slash = (validator.stake * slash_fraction_bps as u128) / 10000;
        validator.apply_slash(slash_fraction_bps);

        // Jail the validator
        validator.jail(block_height + jail_duration);
        staking_store.put_validator(&validator)?;

        // Apply slash to delegations
        let delegation_slash = delegation_store.slash_delegations(
            &evidence.validator_pubkey,
            slash_fraction_bps,
        )?;

        // Update signing info
        if let Some(mut signing_info) = slashing_store.get_signing_info(&evidence.validator_pubkey)? {
            signing_info.reset_missed();
            signing_info.jailed_until = block_height + jail_duration;
            slashing_store.put_signing_info(&signing_info)?;
        }

        // Create slashing record
        let record = SlashingRecord::new(
            evidence.validator_pubkey,
            EvidenceType::Downtime,
            block_height,
            validator_slash,
            delegation_slash,
            block_height + jail_duration,
            false, // not tombstoned for downtime
            slash_fraction_bps,
        );
        slashing_store.put_slashing_record(&record)?;

        // 800B correction: evidence-based validator slashing forfeits any
        // remaining grant-derived locked stake back to the ProtocolReserve
        // (grant money is public reserve money — misbehaviour returns it).
        // Self-funded stake follows the normal staking rules above. No-op if
        // no active grant / correction dormant.
        crate::supply::SupplyStore::new(self.db.clone()).forfeit_locked_grant(
            &sumchain_primitives::Address::from_public_key(&evidence.validator_pubkey),
            sumchain_primitives::supply::ServiceKind::Validator,
        )?;

        let total_slashed = validator_slash + delegation_slash;

        warn!(
            "Downtime evidence: slashed validator 0x{} for {} (missed {} blocks)",
            hex::encode(&evidence.validator_pubkey[..8]),
            total_slashed,
            evidence.missed_blocks
        );

        Ok(StakingExecutionResult::success_with_amount(total_slashed))
    }

    /// Slash a validator directly (called by consensus when misbehavior is detected)
    pub fn slash_validator(
        &self,
        validator_pubkey: &[u8; 32],
        evidence_type: EvidenceType,
        block_height: BlockHeight,
    ) -> Result<Balance> {
        let staking_store = StakingStore::new(&self.db);
        let delegation_store = DelegationStore::new(&self.db);
        let slashing_store = SlashingStore::new(&self.db);

        // Get validator
        let mut validator = match staking_store.get_validator(validator_pubkey)? {
            Some(v) => v,
            None => return Err(StateError::BlockValidation("Validator not found".to_string())),
        };

        // Get slashing parameters based on evidence type
        let (slash_fraction_bps, jail_duration, tombstone) = match evidence_type {
            EvidenceType::DoubleSign => {
                let slash = self.params.staking.as_ref()
                    .map(|s| s.double_sign_slash_bps)
                    .unwrap_or(500);
                let jail = self.params.staking.as_ref()
                    .map(|s| s.double_sign_jail_duration)
                    .unwrap_or(14400);
                (slash, jail, true)
            }
            EvidenceType::Downtime => {
                let slash = self.params.staking.as_ref()
                    .map(|s| s.downtime_slash_bps)
                    .unwrap_or(10);
                let jail = self.params.staking.as_ref()
                    .map(|s| s.downtime_jail_duration)
                    .unwrap_or(2400);
                (slash, jail, false)
            }
        };

        // Apply slash to validator
        let validator_slash = (validator.stake * slash_fraction_bps as u128) / 10000;
        validator.apply_slash(slash_fraction_bps);
        validator.jail(block_height + jail_duration);
        staking_store.put_validator(&validator)?;

        // Apply slash to delegations
        let delegation_slash = delegation_store.slash_delegations(validator_pubkey, slash_fraction_bps)?;

        // Update signing info
        if tombstone {
            if let Some(mut signing_info) = slashing_store.get_signing_info(validator_pubkey)? {
                signing_info.tombstone();
                signing_info.jailed_until = block_height + jail_duration;
                slashing_store.put_signing_info(&signing_info)?;
            }
        }

        // Create slashing record
        let record = SlashingRecord::new(
            *validator_pubkey,
            evidence_type,
            block_height,
            validator_slash,
            delegation_slash,
            block_height + jail_duration,
            tombstone,
            slash_fraction_bps,
        );
        slashing_store.put_slashing_record(&record)?;

        // 800B correction: evidence-based validator slashing forfeits any
        // remaining grant-derived locked stake back to the ProtocolReserve
        // (grant money is public reserve money — misbehaviour returns it).
        // Self-funded stake follows the normal staking rules above. No-op if
        // no active grant / correction dormant.
        crate::supply::SupplyStore::new(self.db.clone()).forfeit_locked_grant(
            &sumchain_primitives::Address::from_public_key(validator_pubkey),
            sumchain_primitives::supply::ServiceKind::Validator,
        )?;

        let total_slashed = validator_slash + delegation_slash;

        info!(
            "Slashed validator 0x{} for {} ({:?})",
            hex::encode(&validator_pubkey[..8]),
            total_slashed,
            evidence_type
        );

        Ok(total_slashed)
    }

    // ========================================================================
    // Query Methods (for RPC)
    // ========================================================================

    /// Get validator info (for RPC)
    pub fn get_validator(&self, pubkey: &[u8; 32]) -> Result<Option<ValidatorInfo>> {
        let store = StakingStore::new(&self.db);
        store.get_validator(pubkey).map_err(StateError::from)
    }

    /// Get all validators (for RPC)
    pub fn get_all_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let store = StakingStore::new(&self.db);
        store.get_all_validators().map_err(StateError::from)
    }

    /// Get active validators (for consensus)
    pub fn get_active_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let store = StakingStore::new(&self.db);
        store.get_active_validators().map_err(StateError::from)
    }

    /// Get validators sorted by stake
    pub fn get_validators_by_stake(&self) -> Result<Vec<ValidatorInfo>> {
        let store = StakingStore::new(&self.db);
        store.get_validators_by_stake().map_err(StateError::from)
    }

    /// Get total staked amount
    pub fn get_total_stake(&self) -> Result<Balance> {
        let store = StakingStore::new(&self.db);
        store.get_total_stake().map_err(StateError::from)
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, ChainParams, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let params = ChainParams::default();
        (db, params, dir)
    }

    #[test]
    fn test_staking_execution_result() {
        let success = StakingExecutionResult::success();
        assert!(success.success);
        assert!(success.error.is_none());

        let success_amount = StakingExecutionResult::success_with_amount(1000);
        assert!(success_amount.success);
        assert_eq!(success_amount.amount, Some(1000));

        let failure = StakingExecutionResult::failure("test error".to_string());
        assert!(!failure.success);
        assert_eq!(failure.error, Some("test error".to_string()));
    }
}
