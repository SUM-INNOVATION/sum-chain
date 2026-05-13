//! Staking types for SUM Chain validators.
//!
//! Defines validator staking structures, operations, and parameters.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Balance, BlockHeight};

/// Validator status in the staking system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ValidatorStatus {
    /// Actively participating in consensus
    Active = 0,
    /// Voluntarily stopped validating
    Inactive = 1,
    /// Penalized and temporarily removed from validator set
    Jailed = 2,
    /// Waiting to withdraw stake (unbonding period)
    Unbonding = 3,
}

impl ValidatorStatus {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ValidatorStatus::Active),
            1 => Some(ValidatorStatus::Inactive),
            2 => Some(ValidatorStatus::Jailed),
            3 => Some(ValidatorStatus::Unbonding),
            _ => None,
        }
    }

    /// Check if validator can participate in consensus
    pub fn can_validate(&self) -> bool {
        matches!(self, ValidatorStatus::Active)
    }
}

impl Default for ValidatorStatus {
    fn default() -> Self {
        ValidatorStatus::Inactive
    }
}

/// Validator information stored on-chain
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator's Ed25519 public key (32 bytes)
    pub pubkey: [u8; 32],
    /// Self-staked amount
    pub stake: Balance,
    /// Total amount delegated to this validator by others
    pub total_delegated: Balance,
    /// Commission rate in basis points (100 = 1%, max 10000 = 100%)
    pub commission_bps: u16,
    /// Current status
    pub status: ValidatorStatus,
    /// Block height when validator joined
    pub joined_at: BlockHeight,
    /// Block height when validator was jailed (0 if not jailed)
    pub jailed_until: BlockHeight,
    /// Number of times this validator has been slashed
    pub slash_count: u32,
    /// Accumulated rewards (not yet claimed)
    pub pending_rewards: Balance,
    /// Optional metadata (e.g., name, website) - max 256 bytes
    pub metadata: Vec<u8>,
}

impl ValidatorInfo {
    /// Create a new validator with initial stake
    pub fn new(pubkey: [u8; 32], stake: Balance, commission_bps: u16, joined_at: BlockHeight) -> Self {
        Self {
            pubkey,
            stake,
            total_delegated: 0,
            commission_bps: commission_bps.min(10000), // Cap at 100%
            status: ValidatorStatus::Active,
            joined_at,
            jailed_until: 0,
            slash_count: 0,
            pending_rewards: 0,
            metadata: Vec::new(),
        }
    }

    /// Get total voting power (self-stake + delegations)
    pub fn total_stake(&self) -> Balance {
        self.stake.saturating_add(self.total_delegated)
    }

    /// Add delegation to this validator
    pub fn add_delegation(&mut self, amount: Balance) {
        self.total_delegated = self.total_delegated.saturating_add(amount);
    }

    /// Remove delegation from this validator
    pub fn remove_delegation(&mut self, amount: Balance) {
        self.total_delegated = self.total_delegated.saturating_sub(amount);
    }

    /// Check if validator is currently jailed
    pub fn is_jailed(&self) -> bool {
        self.status == ValidatorStatus::Jailed
    }

    /// Check if validator can be unjailed at given height
    pub fn can_unjail(&self, current_height: BlockHeight) -> bool {
        self.is_jailed() && current_height >= self.jailed_until
    }

    /// Apply a slash penalty
    pub fn apply_slash(&mut self, penalty_bps: u16) {
        let penalty = (self.stake * penalty_bps as u128) / 10000;
        self.stake = self.stake.saturating_sub(penalty);
        self.slash_count += 1;
    }

    /// Jail the validator until a specific height
    pub fn jail(&mut self, until_height: BlockHeight) {
        self.status = ValidatorStatus::Jailed;
        self.jailed_until = until_height;
    }

    /// Unjail the validator
    pub fn unjail(&mut self) {
        self.status = ValidatorStatus::Active;
        self.jailed_until = 0;
    }
}

/// Staking operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum StakingOperation {
    /// Register as a new validator with initial stake
    CreateValidator = 0,
    /// Add more stake to an existing validator
    AddStake = 1,
    /// Begin unbonding stake (start withdrawal process)
    Unstake = 2,
    /// Update validator commission or metadata
    UpdateValidator = 3,
    /// Request to unjail after jail period
    Unjail = 4,
    /// Claim accumulated rewards
    ClaimRewards = 5,
    // Delegation operations (6-9)
    /// Delegate tokens to a validator
    Delegate = 6,
    /// Begin unbonding delegation from a validator
    Undelegate = 7,
    /// Claim delegation rewards from a validator
    ClaimDelegationRewards = 8,
    /// Withdraw completed unbonding delegations
    WithdrawUnbonded = 9,
    // Slashing operations (10)
    /// Submit evidence of misbehavior (double sign or downtime)
    SubmitEvidence = 10,
}

impl StakingOperation {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(StakingOperation::CreateValidator),
            1 => Some(StakingOperation::AddStake),
            2 => Some(StakingOperation::Unstake),
            3 => Some(StakingOperation::UpdateValidator),
            4 => Some(StakingOperation::Unjail),
            5 => Some(StakingOperation::ClaimRewards),
            6 => Some(StakingOperation::Delegate),
            7 => Some(StakingOperation::Undelegate),
            8 => Some(StakingOperation::ClaimDelegationRewards),
            9 => Some(StakingOperation::WithdrawUnbonded),
            10 => Some(StakingOperation::SubmitEvidence),
            _ => None,
        }
    }

    /// Check if this operation requires the sender to be a validator
    pub fn requires_validator(&self) -> bool {
        matches!(
            self,
            StakingOperation::AddStake
                | StakingOperation::Unstake
                | StakingOperation::UpdateValidator
                | StakingOperation::Unjail
                | StakingOperation::ClaimRewards
        )
    }

    /// Check if this operation is a delegation operation
    pub fn is_delegation(&self) -> bool {
        matches!(
            self,
            StakingOperation::Delegate
                | StakingOperation::Undelegate
                | StakingOperation::ClaimDelegationRewards
                | StakingOperation::WithdrawUnbonded
        )
    }

    /// Check if this operation is a slashing operation
    pub fn is_slashing(&self) -> bool {
        matches!(self, StakingOperation::SubmitEvidence)
    }
}

/// Staking transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingTxData {
    /// Staking operation type
    pub operation: StakingOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

impl StakingTxData {
    /// Create a new staking transaction data
    pub fn new(operation: StakingOperation, data: Vec<u8>) -> Self {
        Self { operation, data }
    }
}

/// Data for CreateValidator operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateValidatorData {
    /// Initial stake amount
    pub stake: Balance,
    /// Commission rate in basis points
    pub commission_bps: u16,
    /// Optional metadata (name, website, etc.)
    pub metadata: Vec<u8>,
}

/// Data for AddStake operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddStakeData {
    /// Amount to add to stake
    pub amount: Balance,
}

/// Data for Unstake operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnstakeData {
    /// Amount to unstake
    pub amount: Balance,
}

/// Data for UpdateValidator operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateValidatorData {
    /// New commission rate (None = keep current)
    pub commission_bps: Option<u16>,
    /// New metadata (None = keep current)
    pub metadata: Option<Vec<u8>>,
}

// ============================================================================
// Delegation Types
// ============================================================================

/// Delegation information for a delegator to a validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationInfo {
    /// Delegator's address (32 bytes)
    pub delegator: [u8; 32],
    /// Validator's public key (32 bytes)
    pub validator_pubkey: [u8; 32],
    /// Delegated amount
    pub amount: Balance,
    /// Accumulated rewards (not yet claimed)
    pub pending_rewards: Balance,
    /// Block height when delegation started
    pub delegated_at: BlockHeight,
}

impl DelegationInfo {
    /// Create a new delegation
    pub fn new(delegator: [u8; 32], validator_pubkey: [u8; 32], amount: Balance, delegated_at: BlockHeight) -> Self {
        Self {
            delegator,
            validator_pubkey,
            amount,
            pending_rewards: 0,
            delegated_at,
        }
    }

    /// Add more stake to the delegation
    pub fn add_stake(&mut self, amount: Balance) {
        self.amount = self.amount.saturating_add(amount);
    }

    /// Remove stake from the delegation
    pub fn remove_stake(&mut self, amount: Balance) -> Balance {
        let removed = amount.min(self.amount);
        self.amount = self.amount.saturating_sub(removed);
        removed
    }

    /// Add rewards to pending rewards
    pub fn add_rewards(&mut self, rewards: Balance) {
        self.pending_rewards = self.pending_rewards.saturating_add(rewards);
    }

    /// Claim all pending rewards, returning the amount claimed
    pub fn claim_rewards(&mut self) -> Balance {
        let rewards = self.pending_rewards;
        self.pending_rewards = 0;
        rewards
    }

    /// Apply a slash penalty to the delegation
    pub fn apply_slash(&mut self, penalty_bps: u16) {
        let penalty = (self.amount * penalty_bps as u128) / 10000;
        self.amount = self.amount.saturating_sub(penalty);
    }
}

/// Unbonding delegation entry (pending withdrawal)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingDelegation {
    /// Delegator's address (32 bytes)
    pub delegator: [u8; 32],
    /// Validator's public key (32 bytes)
    pub validator_pubkey: [u8; 32],
    /// Amount being unbonded
    pub amount: Balance,
    /// Block height when unbonding completes
    pub completion_height: BlockHeight,
}

impl UnbondingDelegation {
    /// Create a new unbonding delegation
    pub fn new(
        delegator: [u8; 32],
        validator_pubkey: [u8; 32],
        amount: Balance,
        completion_height: BlockHeight,
    ) -> Self {
        Self {
            delegator,
            validator_pubkey,
            amount,
            completion_height,
        }
    }

    /// Check if unbonding is complete
    pub fn is_complete(&self, current_height: BlockHeight) -> bool {
        current_height >= self.completion_height
    }
}

/// Data for Delegate operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateData {
    /// Validator public key to delegate to (hex)
    pub validator_pubkey: [u8; 32],
    /// Amount to delegate
    pub amount: Balance,
}

/// Data for Undelegate operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndelegateData {
    /// Validator public key to undelegate from
    pub validator_pubkey: [u8; 32],
    /// Amount to undelegate
    pub amount: Balance,
}

/// Data for ClaimDelegationRewards operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDelegationRewardsData {
    /// Validator public key to claim rewards from
    pub validator_pubkey: [u8; 32],
}

/// Data for WithdrawUnbonded operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawUnbondedData {
    /// Validator public key (optional - if None, withdraw all)
    pub validator_pubkey: Option<[u8; 32]>,
}

// ============================================================================
// Slashing Types
// ============================================================================

/// Type of slashing evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EvidenceType {
    /// Validator signed two different blocks at the same height
    DoubleSign = 0,
    /// Validator was offline/missed too many blocks
    Downtime = 1,
}

impl EvidenceType {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(EvidenceType::DoubleSign),
            1 => Some(EvidenceType::Downtime),
            _ => None,
        }
    }

    /// Get the name of this evidence type
    pub fn name(&self) -> &'static str {
        match self {
            EvidenceType::DoubleSign => "double_sign",
            EvidenceType::Downtime => "downtime",
        }
    }
}

/// Evidence of double signing (equivocation)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    /// Validator's public key
    pub validator_pubkey: [u8; 32],
    /// Block height where double sign occurred
    pub height: BlockHeight,
    /// First block hash signed
    pub block_hash_1: [u8; 32],
    /// Signature for first block
    #[serde(with = "BigArray")]
    pub signature_1: [u8; 64],
    /// Second block hash signed (different from first)
    pub block_hash_2: [u8; 32],
    /// Signature for second block
    #[serde(with = "BigArray")]
    pub signature_2: [u8; 64],
    /// Block height when evidence was submitted
    pub submitted_at: BlockHeight,
}

impl DoubleSignEvidence {
    /// Create new double sign evidence
    pub fn new(
        validator_pubkey: [u8; 32],
        height: BlockHeight,
        block_hash_1: [u8; 32],
        signature_1: [u8; 64],
        block_hash_2: [u8; 32],
        signature_2: [u8; 64],
        submitted_at: BlockHeight,
    ) -> Self {
        Self {
            validator_pubkey,
            height,
            block_hash_1,
            signature_1,
            block_hash_2,
            signature_2,
            submitted_at,
        }
    }

    /// Check if evidence is valid (basic checks, not cryptographic verification)
    pub fn is_valid(&self) -> bool {
        // Block hashes must be different
        self.block_hash_1 != self.block_hash_2
    }
}

/// Evidence of downtime (missed blocks)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DowntimeEvidence {
    /// Validator's public key
    pub validator_pubkey: [u8; 32],
    /// Starting height of the downtime window
    pub start_height: BlockHeight,
    /// Ending height of the downtime window
    pub end_height: BlockHeight,
    /// Number of blocks missed in this window
    pub missed_blocks: u64,
    /// Block height when evidence was submitted
    pub submitted_at: BlockHeight,
}

impl DowntimeEvidence {
    /// Create new downtime evidence
    pub fn new(
        validator_pubkey: [u8; 32],
        start_height: BlockHeight,
        end_height: BlockHeight,
        missed_blocks: u64,
        submitted_at: BlockHeight,
    ) -> Self {
        Self {
            validator_pubkey,
            start_height,
            end_height,
            missed_blocks,
            submitted_at,
        }
    }

    /// Check if evidence meets threshold
    pub fn exceeds_threshold(&self, threshold: u64) -> bool {
        self.missed_blocks >= threshold
    }
}

/// Validator signing info for tracking liveness
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSigningInfo {
    /// Validator's public key
    pub validator_pubkey: [u8; 32],
    /// Block height when signing info was last updated
    pub start_height: BlockHeight,
    /// Index offset into signed blocks bit array
    pub index_offset: u64,
    /// Number of blocks missed in the current window
    pub missed_blocks_counter: u64,
    /// Whether the validator has been tombstoned (permanently jailed)
    pub tombstoned: bool,
    /// Block height of the last time validator was jailed
    pub jailed_until: BlockHeight,
}

impl ValidatorSigningInfo {
    /// Create new signing info for a validator
    pub fn new(validator_pubkey: [u8; 32], start_height: BlockHeight) -> Self {
        Self {
            validator_pubkey,
            start_height,
            index_offset: 0,
            missed_blocks_counter: 0,
            tombstoned: false,
            jailed_until: 0,
        }
    }

    /// Increment missed blocks counter
    pub fn increment_missed(&mut self) {
        self.missed_blocks_counter = self.missed_blocks_counter.saturating_add(1);
    }

    /// Reset missed blocks counter (e.g., when validator is slashed)
    pub fn reset_missed(&mut self) {
        self.missed_blocks_counter = 0;
    }

    /// Check if validator has exceeded downtime threshold
    pub fn exceeds_threshold(&self, threshold: u64) -> bool {
        self.missed_blocks_counter >= threshold
    }

    /// Tombstone the validator (permanent jail)
    pub fn tombstone(&mut self) {
        self.tombstoned = true;
    }
}

/// Record of a slashing event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    /// Validator's public key
    pub validator_pubkey: [u8; 32],
    /// Type of evidence that caused the slash
    pub evidence_type: EvidenceType,
    /// Block height when slash was applied
    pub slashed_at: BlockHeight,
    /// Amount of validator's self-stake slashed
    pub validator_slash_amount: Balance,
    /// Amount of delegator stake slashed
    pub delegation_slash_amount: Balance,
    /// Jail until block height (0 if not jailed)
    pub jailed_until: BlockHeight,
    /// Whether this was a tombstone (permanent jail)
    pub tombstoned: bool,
    /// Fraction slashed (basis points)
    pub slash_fraction_bps: u16,
}

impl SlashingRecord {
    /// Create a new slashing record
    pub fn new(
        validator_pubkey: [u8; 32],
        evidence_type: EvidenceType,
        slashed_at: BlockHeight,
        validator_slash_amount: Balance,
        delegation_slash_amount: Balance,
        jailed_until: BlockHeight,
        tombstoned: bool,
        slash_fraction_bps: u16,
    ) -> Self {
        Self {
            validator_pubkey,
            evidence_type,
            slashed_at,
            validator_slash_amount,
            delegation_slash_amount,
            jailed_until,
            tombstoned,
            slash_fraction_bps,
        }
    }

    /// Get total slashed amount
    pub fn total_slashed(&self) -> Balance {
        self.validator_slash_amount.saturating_add(self.delegation_slash_amount)
    }
}

/// Data for SubmitEvidence operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEvidenceData {
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Serialized evidence data
    pub evidence: Vec<u8>,
}

/// Staking parameters from genesis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingParams {
    /// Minimum stake required to be a validator
    pub min_validator_stake: Balance,
    /// Maximum number of active validators
    pub max_validators: u32,
    /// Unbonding period in blocks
    pub unbonding_period: BlockHeight,
    /// Maximum commission rate in basis points
    pub max_commission_bps: u16,
    /// Slash penalty for double signing (basis points)
    pub double_sign_slash_bps: u16,
    /// Slash penalty for downtime (basis points)
    pub downtime_slash_bps: u16,
    /// Jail duration for double signing (blocks)
    pub double_sign_jail_duration: BlockHeight,
    /// Jail duration for downtime (blocks)
    pub downtime_jail_duration: BlockHeight,
    /// Number of missed blocks before downtime slash
    pub downtime_threshold: u64,
    /// Epoch length in blocks (validator set updates at epoch boundaries)
    pub epoch_length: BlockHeight,
    /// Enable stake-weighted proposer selection (vs round-robin)
    pub stake_weighted_selection: bool,
}

impl Default for StakingParams {
    fn default() -> Self {
        Self {
            min_validator_stake: 1_000_000_000_000_000_000, // 1e18 base units = 1,000,000,000 Koppa (1B Koppa with 9 decimals)
            max_validators: 100,
            unbonding_period: 100_800, // ~7 days at 6s blocks
            max_commission_bps: 10000, // 100%
            double_sign_slash_bps: 500, // 5%
            downtime_slash_bps: 10, // 0.1%
            double_sign_jail_duration: 14400, // ~24 hours
            downtime_jail_duration: 2400, // ~4 hours
            downtime_threshold: 500, // 500 missed blocks
            epoch_length: 14400, // ~24 hours at 6s blocks
            stake_weighted_selection: true, // Use stake-weighted selection by default
        }
    }
}

impl StakingParams {
    /// Get the epoch number for a given block height
    pub fn epoch_for_height(&self, height: BlockHeight) -> u64 {
        if self.epoch_length == 0 {
            return 0;
        }
        height / self.epoch_length
    }

    /// Check if a block height is at an epoch boundary
    pub fn is_epoch_boundary(&self, height: BlockHeight) -> bool {
        if self.epoch_length == 0 {
            return false;
        }
        height > 0 && height % self.epoch_length == 0
    }

    /// Get the first block height of an epoch
    pub fn epoch_start_height(&self, epoch: u64) -> BlockHeight {
        epoch * self.epoch_length
    }

    /// Get the last block height of an epoch
    pub fn epoch_end_height(&self, epoch: u64) -> BlockHeight {
        (epoch + 1) * self.epoch_length - 1
    }
}

// ============================================================================
// Validator Set Types
// ============================================================================

/// A validator in the active set with voting power
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSetEntry {
    /// Validator's public key
    pub pubkey: [u8; 32],
    /// Total voting power (stake + delegations)
    pub voting_power: Balance,
    /// Commission rate in basis points
    pub commission_bps: u16,
}

impl ValidatorSetEntry {
    /// Create a new validator set entry
    pub fn new(pubkey: [u8; 32], voting_power: Balance, commission_bps: u16) -> Self {
        Self {
            pubkey,
            voting_power,
            commission_bps,
        }
    }
}

/// The active validator set for an epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// The epoch this validator set is for
    pub epoch: u64,
    /// Block height when this set became active
    pub active_from: BlockHeight,
    /// List of validators sorted by voting power (descending)
    pub validators: Vec<ValidatorSetEntry>,
    /// Total voting power in this set
    pub total_voting_power: Balance,
    /// Proposer selection seed (hash of previous epoch's last block)
    pub proposer_seed: [u8; 32],
}

impl ValidatorSet {
    /// Create a new validator set
    pub fn new(epoch: u64, active_from: BlockHeight, validators: Vec<ValidatorSetEntry>, proposer_seed: [u8; 32]) -> Self {
        let total_voting_power = validators.iter().map(|v| v.voting_power).sum();
        Self {
            epoch,
            active_from,
            validators,
            total_voting_power,
            proposer_seed,
        }
    }

    /// Get the number of validators
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get validator pubkeys
    pub fn pubkeys(&self) -> Vec<[u8; 32]> {
        self.validators.iter().map(|v| v.pubkey).collect()
    }

    /// Check if a pubkey is in the validator set
    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.validators.iter().any(|v| &v.pubkey == pubkey)
    }

    /// Get a validator's entry by pubkey
    pub fn get(&self, pubkey: &[u8; 32]) -> Option<&ValidatorSetEntry> {
        self.validators.iter().find(|v| &v.pubkey == pubkey)
    }

    /// Get the proposer for a given height using stake-weighted selection
    pub fn get_stake_weighted_proposer(&self, height: BlockHeight) -> Option<[u8; 32]> {
        if self.validators.is_empty() || self.total_voting_power == 0 {
            return None;
        }

        // Combine proposer seed with height for deterministic but varying selection
        let mut seed_input = [0u8; 40];
        seed_input[..32].copy_from_slice(&self.proposer_seed);
        seed_input[32..40].copy_from_slice(&height.to_le_bytes());

        // Simple hash to get a selection point
        let hash = blake3::hash(&seed_input);
        let hash_bytes = hash.as_bytes();

        // Convert first 16 bytes to u128 for selection
        let selection_bytes: [u8; 16] = hash_bytes[..16].try_into().unwrap();
        let selection_value = u128::from_le_bytes(selection_bytes);

        // Map to range [0, total_voting_power)
        let selection_point = selection_value % (self.total_voting_power as u128);

        // Select proposer based on cumulative voting power
        let mut cumulative = 0u128;
        for validator in &self.validators {
            cumulative += validator.voting_power as u128;
            if selection_point < cumulative {
                return Some(validator.pubkey);
            }
        }

        // Fallback to first validator (shouldn't happen)
        Some(self.validators[0].pubkey)
    }

    /// Get the proposer for a given height using round-robin selection
    pub fn get_round_robin_proposer(&self, height: BlockHeight) -> Option<[u8; 32]> {
        if self.validators.is_empty() {
            return None;
        }
        let idx = (height as usize) % self.validators.len();
        Some(self.validators[idx].pubkey)
    }

    /// Get the voting power for a validator
    pub fn voting_power(&self, pubkey: &[u8; 32]) -> Balance {
        self.get(pubkey).map(|v| v.voting_power).unwrap_or(0)
    }

    /// Calculate the voting power percentage for a validator (in basis points)
    pub fn voting_power_percentage(&self, pubkey: &[u8; 32]) -> u16 {
        if self.total_voting_power == 0 {
            return 0;
        }
        let power = self.voting_power(pubkey);
        ((power * 10000) / self.total_voting_power) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_status_from_byte() {
        assert_eq!(ValidatorStatus::from_byte(0), Some(ValidatorStatus::Active));
        assert_eq!(ValidatorStatus::from_byte(1), Some(ValidatorStatus::Inactive));
        assert_eq!(ValidatorStatus::from_byte(2), Some(ValidatorStatus::Jailed));
        assert_eq!(ValidatorStatus::from_byte(3), Some(ValidatorStatus::Unbonding));
        assert_eq!(ValidatorStatus::from_byte(99), None);
    }

    #[test]
    fn test_validator_info_creation() {
        let pubkey = [1u8; 32];
        let validator = ValidatorInfo::new(pubkey, 1000, 500, 100);

        assert_eq!(validator.stake, 1000);
        assert_eq!(validator.commission_bps, 500);
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert!(!validator.is_jailed());
    }

    #[test]
    fn test_validator_slash() {
        let pubkey = [1u8; 32];
        let mut validator = ValidatorInfo::new(pubkey, 10000, 500, 100);

        validator.apply_slash(500); // 5% slash

        assert_eq!(validator.stake, 9500);
        assert_eq!(validator.slash_count, 1);
    }

    #[test]
    fn test_validator_jail_unjail() {
        let pubkey = [1u8; 32];
        let mut validator = ValidatorInfo::new(pubkey, 1000, 500, 100);

        validator.jail(200);
        assert!(validator.is_jailed());
        assert!(!validator.can_unjail(150));
        assert!(validator.can_unjail(200));

        validator.unjail();
        assert!(!validator.is_jailed());
        assert_eq!(validator.status, ValidatorStatus::Active);
    }

    #[test]
    fn test_staking_operation_from_byte() {
        assert_eq!(StakingOperation::from_byte(0), Some(StakingOperation::CreateValidator));
        assert_eq!(StakingOperation::from_byte(4), Some(StakingOperation::Unjail));
        assert_eq!(StakingOperation::from_byte(99), None);
    }

    #[test]
    fn test_commission_cap() {
        let pubkey = [1u8; 32];
        let validator = ValidatorInfo::new(pubkey, 1000, 15000, 100); // Try 150%

        assert_eq!(validator.commission_bps, 10000); // Capped at 100%
    }

    // ========================================================================
    // Delegation Tests
    // ========================================================================

    #[test]
    fn test_validator_delegation() {
        let pubkey = [1u8; 32];
        let mut validator = ValidatorInfo::new(pubkey, 1000, 500, 100);

        assert_eq!(validator.total_stake(), 1000);
        assert_eq!(validator.total_delegated, 0);

        validator.add_delegation(500);
        assert_eq!(validator.total_delegated, 500);
        assert_eq!(validator.total_stake(), 1500);

        validator.remove_delegation(200);
        assert_eq!(validator.total_delegated, 300);
        assert_eq!(validator.total_stake(), 1300);
    }

    #[test]
    fn test_delegation_info_creation() {
        let delegator = [2u8; 32];
        let validator_pubkey = [1u8; 32];
        let delegation = DelegationInfo::new(delegator, validator_pubkey, 1000, 100);

        assert_eq!(delegation.delegator, delegator);
        assert_eq!(delegation.validator_pubkey, validator_pubkey);
        assert_eq!(delegation.amount, 1000);
        assert_eq!(delegation.pending_rewards, 0);
        assert_eq!(delegation.delegated_at, 100);
    }

    #[test]
    fn test_delegation_stake_operations() {
        let delegator = [2u8; 32];
        let validator_pubkey = [1u8; 32];
        let mut delegation = DelegationInfo::new(delegator, validator_pubkey, 1000, 100);

        delegation.add_stake(500);
        assert_eq!(delegation.amount, 1500);

        let removed = delegation.remove_stake(700);
        assert_eq!(removed, 700);
        assert_eq!(delegation.amount, 800);

        // Try to remove more than available
        let removed = delegation.remove_stake(1000);
        assert_eq!(removed, 800);
        assert_eq!(delegation.amount, 0);
    }

    #[test]
    fn test_delegation_rewards() {
        let delegator = [2u8; 32];
        let validator_pubkey = [1u8; 32];
        let mut delegation = DelegationInfo::new(delegator, validator_pubkey, 1000, 100);

        delegation.add_rewards(100);
        assert_eq!(delegation.pending_rewards, 100);

        delegation.add_rewards(50);
        assert_eq!(delegation.pending_rewards, 150);

        let claimed = delegation.claim_rewards();
        assert_eq!(claimed, 150);
        assert_eq!(delegation.pending_rewards, 0);
    }

    #[test]
    fn test_delegation_slash() {
        let delegator = [2u8; 32];
        let validator_pubkey = [1u8; 32];
        let mut delegation = DelegationInfo::new(delegator, validator_pubkey, 10000, 100);

        delegation.apply_slash(500); // 5% slash
        assert_eq!(delegation.amount, 9500);
    }

    #[test]
    fn test_unbonding_delegation() {
        let delegator = [2u8; 32];
        let validator_pubkey = [1u8; 32];
        let unbonding = UnbondingDelegation::new(delegator, validator_pubkey, 500, 200);

        assert!(!unbonding.is_complete(100));
        assert!(!unbonding.is_complete(199));
        assert!(unbonding.is_complete(200));
        assert!(unbonding.is_complete(300));
    }

    #[test]
    fn test_delegation_operations() {
        assert_eq!(StakingOperation::from_byte(6), Some(StakingOperation::Delegate));
        assert_eq!(StakingOperation::from_byte(7), Some(StakingOperation::Undelegate));
        assert_eq!(StakingOperation::from_byte(8), Some(StakingOperation::ClaimDelegationRewards));
        assert_eq!(StakingOperation::from_byte(9), Some(StakingOperation::WithdrawUnbonded));

        assert!(StakingOperation::Delegate.is_delegation());
        assert!(StakingOperation::Undelegate.is_delegation());
        assert!(!StakingOperation::CreateValidator.is_delegation());
    }
}
