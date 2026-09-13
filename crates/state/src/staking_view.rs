//! Staking, delegation and slashing, as this block's candidate sees them.
//!
//! The committed twins live in `sumchain_storage::schema` as `StakingStore`,
//! `DelegationStore` and `SlashingStore`. They still exist, and still write
//! straight to the database — genesis, fast-sync snapshots, RPC diagnostics,
//! mempool admission and the reorg revert all need them, and none of those is
//! block execution.
//!
//! What block execution needs is a view of the same rows that can be thrown
//! away. Until this module existed, a Staking transaction moved a validator's
//! bonded stake, rewrote delegation rows and wrote slashing records the moment
//! it executed, whether or not the block was ever accepted — six column
//! families committed mid-execution, including the two the supply census reads.
//!
//! ## Why these are associated functions
//!
//! No `self` receiver, so there is no `Arc<Database>` in scope to reach. A
//! committed staking write on an execution path is a compile error rather than
//! a silent one — the same construction the account family uses, and the reason
//! `StakingExecutor`'s handlers below take a view and nothing else.
//!
//! ## Shared keys, shared codecs
//!
//! Every key builder and every encoder here is the one the committed store
//! uses: `DelegationStore::delegation_key`, `encode_validator`, and the rest are
//! public for exactly this reason. A candidate and the chain cannot disagree
//! about bytes they both produce from the same function, and nothing downstream
//! would catch it if they did — `compute_block_state_root` does not commit to
//! staking rows any more than it does to account rows.
//!
//! ## The delegation index is part of the row
//!
//! `cf::DELEGATIONS` is paired with `cf::DELEGATION_VALIDATOR_INDEX`, which
//! holds the delegator list a validator's slash and reward paths scan. Writing
//! one without the other leaves a delegation nothing can find, or an index
//! entry pointing at a row that is gone, so `v_put_delegation` and
//! `v_delete_delegation` maintain both — as the committed store does.

use sumchain_primitives::{
    Balance, BlockHeight, DelegationInfo, SlashingRecord, UnbondingDelegation, ValidatorInfo,
    ValidatorSigningInfo, ValidatorStatus,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::schema::{
    decode_delegation, decode_delegator_list, decode_signing_info, decode_unbonding,
    decode_validator, encode_delegation, encode_delegator_list, encode_signing_info,
    encode_slashing_record, encode_unbonding, encode_validator, DelegationStore, SlashingStore,
};
use sumchain_storage::cf;

use crate::staking_executor::StakingExecutor;
use crate::{Result, StateError};

/// Σ validator self-stake, with checked addition. Shared with the committed
/// census so the two cannot differ on what they include or on overflow.
pub(crate) fn sum_self_stake(validators: &[ValidatorInfo]) -> Result<u128> {
    let mut sum: u128 = 0;
    for v in validators {
        sum = sum.checked_add(v.stake).ok_or_else(|| {
            StateError::InvalidOperation("validator self-stake sum overflow".to_string())
        })?;
    }
    Ok(sum)
}

/// Active validators, in the order the committed store yields them.
pub(crate) fn only_active(all: Vec<ValidatorInfo>) -> Vec<ValidatorInfo> {
    all.into_iter()
        .filter(|v| v.status == ValidatorStatus::Active)
        .collect()
}

/// Descending by stake, as the committed store sorts.
pub(crate) fn by_stake_desc(mut all: Vec<ValidatorInfo>) -> Vec<ValidatorInfo> {
    all.sort_by(|a, b| b.stake.cmp(&a.stake));
    all
}

impl StakingExecutor {
    // ── Validators ──────────────────────────────────────────────────────────

    /// A validator as the candidate sees it, including one staged by an earlier
    /// transaction of the same block.
    pub fn v_get_validator(
        view: &ExecutionView<'_, '_>,
        pubkey: &[u8; 32],
    ) -> Result<Option<ValidatorInfo>> {
        match view.get(cf::VALIDATORS, pubkey).map_err(StateError::Storage)? {
            Some(bytes) => Ok(Some(decode_validator(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_validator(
        view: &mut ExecutionView<'_, '_>,
        validator: &ValidatorInfo,
    ) -> Result<()> {
        let bytes = encode_validator(validator)?;
        view.put(cf::VALIDATORS, &validator.pubkey, &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_validator_exists(
        view: &ExecutionView<'_, '_>,
        pubkey: &[u8; 32],
    ) -> Result<bool> {
        view.contains(cf::VALIDATORS, pubkey)
            .map_err(StateError::Storage)
    }

    pub fn v_get_all_validators(view: &ExecutionView<'_, '_>) -> Result<Vec<ValidatorInfo>> {
        let mut validators = Vec::new();
        for item in view
            .prefix_iter(cf::VALIDATORS, &[])
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan. Stopping silently would under-report
            // the validator set, and what is computed from it is consensus.
            let (_, value) = item.map_err(StateError::Storage)?;
            validators.push(decode_validator(&value)?);
        }
        Ok(validators)
    }

    pub fn v_get_active_validators(view: &ExecutionView<'_, '_>) -> Result<Vec<ValidatorInfo>> {
        Ok(only_active(Self::v_get_all_validators(view)?))
    }

    pub fn v_get_validators_by_stake(view: &ExecutionView<'_, '_>) -> Result<Vec<ValidatorInfo>> {
        Ok(by_stake_desc(Self::v_get_all_validators(view)?))
    }

    pub fn v_get_validator_count(view: &ExecutionView<'_, '_>) -> Result<usize> {
        Ok(Self::v_get_all_validators(view)?.len())
    }

    pub fn v_get_total_stake(view: &ExecutionView<'_, '_>) -> Result<Balance> {
        Ok(Self::v_get_all_validators(view)?.iter().map(|v| v.stake).sum())
    }

    /// Σ validator self-stake in the candidate. The supply census reads this:
    /// a census that read the parent's validators against a block that had
    /// already bonded or slashed stake would mint the difference.
    pub fn v_total_validator_self_stake(view: &ExecutionView<'_, '_>) -> Result<u128> {
        sum_self_stake(&Self::v_get_all_validators(view)?)
    }

    pub fn v_claim_rewards(
        view: &mut ExecutionView<'_, '_>,
        pubkey: &[u8; 32],
    ) -> Result<Balance> {
        match Self::v_get_validator(view, pubkey)? {
            Some(mut validator) => {
                let rewards = validator.pending_rewards;
                validator.pending_rewards = 0;
                Self::v_put_validator(view, &validator)?;
                Ok(rewards)
            }
            None => Err(StateError::InvalidOperation("Validator not found".to_string())),
        }
    }

    // ── Delegations, and the index that finds them ──────────────────────────

    pub fn v_get_validator_delegators(
        view: &ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>> {
        match view
            .get(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_delegator_list(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_validator_index(
        view: &mut ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
        delegator: &[u8; 32],
    ) -> Result<()> {
        let mut delegators = Self::v_get_validator_delegators(view, validator_pubkey)?;
        if !delegators.iter().any(|d| d == delegator) {
            delegators.push(*delegator);
            let bytes = encode_delegator_list(&delegators)?;
            view.put(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey, &bytes)
                .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    fn v_remove_from_validator_index(
        view: &mut ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
        delegator: &[u8; 32],
    ) -> Result<()> {
        let mut delegators = Self::v_get_validator_delegators(view, validator_pubkey)?;
        delegators.retain(|d| d != delegator);

        if delegators.is_empty() {
            view.delete(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey)
                .map_err(StateError::Storage)?;
        } else {
            let bytes = encode_delegator_list(&delegators)?;
            view.put(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey, &bytes)
                .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    pub fn v_get_delegation(
        view: &ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        validator_pubkey: &[u8; 32],
    ) -> Result<Option<DelegationInfo>> {
        let key = DelegationStore::delegation_key(delegator, validator_pubkey);
        match view.get(cf::DELEGATIONS, &key).map_err(StateError::Storage)? {
            Some(bytes) => Ok(Some(decode_delegation(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Stage a delegation AND its index entry. Writing one without the other
    /// leaves a row nothing can find, or an index entry pointing at nothing.
    pub fn v_put_delegation(
        view: &mut ExecutionView<'_, '_>,
        delegation: &DelegationInfo,
    ) -> Result<()> {
        let key =
            DelegationStore::delegation_key(&delegation.delegator, &delegation.validator_pubkey);
        let bytes = encode_delegation(delegation)?;
        view.put(cf::DELEGATIONS, &key, &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_validator_index(view, &delegation.validator_pubkey, &delegation.delegator)
    }

    /// Remove a delegation AND its index entry. See [`Self::v_put_delegation`].
    pub fn v_delete_delegation(
        view: &mut ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        validator_pubkey: &[u8; 32],
    ) -> Result<()> {
        let key = DelegationStore::delegation_key(delegator, validator_pubkey);
        view.delete(cf::DELEGATIONS, &key)
            .map_err(StateError::Storage)?;
        Self::v_remove_from_validator_index(view, validator_pubkey, delegator)
    }

    pub fn v_get_delegations_by_validator(
        view: &ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
    ) -> Result<Vec<DelegationInfo>> {
        let delegators = Self::v_get_validator_delegators(view, validator_pubkey)?;
        let mut delegations = Vec::with_capacity(delegators.len());
        for delegator in delegators {
            if let Some(d) = Self::v_get_delegation(view, &delegator, validator_pubkey)? {
                delegations.push(d);
            }
        }
        Ok(delegations)
    }

    /// Σ active delegation amounts in the candidate, with checked addition.
    /// The supply census reads this for the same reason it reads candidate
    /// self-stake.
    pub fn v_total_active_delegations(view: &ExecutionView<'_, '_>) -> Result<u128> {
        let mut sum: u128 = 0;
        for item in view.iter(cf::DELEGATIONS).map_err(StateError::Storage)? {
            let (key, value) = item.map_err(StateError::Storage)?;
            if key.len() != 64 {
                continue;
            }
            let delegation = decode_delegation(&value)?;
            sum = sum.checked_add(delegation.amount).ok_or_else(|| {
                StateError::InvalidOperation("active delegations sum overflow".to_string())
            })?;
        }
        Ok(sum)
    }

    pub fn v_claim_delegation_rewards(
        view: &mut ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        validator_pubkey: &[u8; 32],
    ) -> Result<Balance> {
        match Self::v_get_delegation(view, delegator, validator_pubkey)? {
            Some(mut delegation) => {
                let rewards = delegation.claim_rewards();
                if delegation.amount == 0 {
                    Self::v_delete_delegation(view, delegator, validator_pubkey)?;
                } else {
                    Self::v_put_delegation(view, &delegation)?;
                }
                Ok(rewards)
            }
            None => Err(StateError::InvalidOperation("Delegation not found".to_string())),
        }
    }

    pub fn v_slash_delegations(
        view: &mut ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
        penalty_bps: u16,
    ) -> Result<Balance> {
        let delegations = Self::v_get_delegations_by_validator(view, validator_pubkey)?;
        let mut total_slashed = 0u128;

        for delegation in delegations {
            let old_amount = delegation.amount;
            let mut updated = delegation.clone();
            updated.apply_slash(penalty_bps);
            let slashed = old_amount.saturating_sub(updated.amount);

            if updated.amount == 0 {
                Self::v_delete_delegation(view, &delegation.delegator, validator_pubkey)?;
            } else {
                Self::v_put_delegation(view, &updated)?;
            }

            total_slashed += slashed;
        }

        Ok(total_slashed)
    }

    // ── Unbonding delegations ───────────────────────────────────────────────

    pub fn v_put_unbonding(
        view: &mut ExecutionView<'_, '_>,
        unbonding: &UnbondingDelegation,
    ) -> Result<()> {
        let key = DelegationStore::unbonding_key(
            &unbonding.delegator,
            unbonding.completion_height,
            &unbonding.validator_pubkey,
        );
        let bytes = encode_unbonding(unbonding)?;
        view.put(cf::UNBONDING_DELEGATIONS, &key, &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_delete_unbonding(
        view: &mut ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        completion_height: BlockHeight,
        validator_pubkey: &[u8; 32],
    ) -> Result<()> {
        let key =
            DelegationStore::unbonding_key(delegator, completion_height, validator_pubkey);
        view.delete(cf::UNBONDING_DELEGATIONS, &key)
            .map_err(StateError::Storage)
    }

    pub fn v_get_unbondings_by_delegator(
        view: &ExecutionView<'_, '_>,
        delegator: &[u8; 32],
    ) -> Result<Vec<UnbondingDelegation>> {
        let mut unbondings = Vec::new();
        for item in view
            .prefix_iter(cf::UNBONDING_DELEGATIONS, delegator)
            .map_err(StateError::Storage)?
        {
            let (key, value) = item.map_err(StateError::Storage)?;
            // 72 bytes: delegator + completion height + validator pubkey.
            if key.len() == 72 && &key[..32] == delegator {
                unbondings.push(decode_unbonding(&value)?);
            }
        }
        Ok(unbondings)
    }

    pub fn v_get_completed_unbondings(
        view: &ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        current_height: BlockHeight,
    ) -> Result<Vec<UnbondingDelegation>> {
        Ok(Self::v_get_unbondings_by_delegator(view, delegator)?
            .into_iter()
            .filter(|u| u.is_complete(current_height))
            .collect())
    }

    pub fn v_get_completed_unbondings_for_validator(
        view: &ExecutionView<'_, '_>,
        delegator: &[u8; 32],
        validator_pubkey: &[u8; 32],
        current_height: BlockHeight,
    ) -> Result<Vec<UnbondingDelegation>> {
        Ok(Self::v_get_unbondings_by_delegator(view, delegator)?
            .into_iter()
            .filter(|u| u.validator_pubkey == *validator_pubkey && u.is_complete(current_height))
            .collect())
    }

    // ── Slashing ────────────────────────────────────────────────────────────

    pub fn v_put_slashing_record(
        view: &mut ExecutionView<'_, '_>,
        record: &SlashingRecord,
    ) -> Result<()> {
        let key = SlashingStore::slashing_key(&record.validator_pubkey, record.slashed_at);
        let bytes = encode_slashing_record(record)?;
        view.put(cf::SLASHING_RECORDS, &key, &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_was_slashed_at(
        view: &ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
        slashed_at: BlockHeight,
    ) -> Result<bool> {
        let key = SlashingStore::slashing_key(validator_pubkey, slashed_at);
        view.contains(cf::SLASHING_RECORDS, &key)
            .map_err(StateError::Storage)
    }

    pub fn v_get_signing_info(
        view: &ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
    ) -> Result<Option<ValidatorSigningInfo>> {
        match view
            .get(cf::VALIDATOR_SIGNING_INFO, validator_pubkey)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_signing_info(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_signing_info(
        view: &mut ExecutionView<'_, '_>,
        info: &ValidatorSigningInfo,
    ) -> Result<()> {
        let bytes = encode_signing_info(info)?;
        view.put(cf::VALIDATOR_SIGNING_INFO, &info.validator_pubkey, &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_is_tombstoned(
        view: &ExecutionView<'_, '_>,
        validator_pubkey: &[u8; 32],
    ) -> Result<bool> {
        Ok(Self::v_get_signing_info(view, validator_pubkey)?
            .map(|i| i.tombstoned)
            .unwrap_or(false))
    }
}
