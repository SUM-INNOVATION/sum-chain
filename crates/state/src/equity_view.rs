//! SRC-83X equity rows, as this block's candidate sees them.
//!
//! Unused on purpose — preparation, like [`crate::token_view`]. Governance
//! reads equity state to register a class and to weigh an equity vote, so
//! equity cannot migrate on its own any more than token can.
//!
//! ## The two shapes worth stating
//!
//! An equity balance is a bincode `u64`. A token balance, one module over, is a
//! bare 16-byte big-endian `u128`. Both encode "a balance" and they are not
//! interchangeable; the shared codecs are what keep that from becoming a
//! silent, round-tripping corruption.
//!
//! `cf::EQUITY_BALANCES` is paired with `cf::EQUITY_HOLDER_INDEX`, which is how
//! a class finds its holders. Writing one without the other leaves a balance no
//! holder scan can see, so `v_set_balance` maintains both — and, at zero,
//! deletes the balance row and drops the index entry rather than storing a
//! zero, exactly as the committed store does.

use sumchain_primitives::equity::{
    ActionId, ClassId, EntityProfile, EquityToken, GovernanceAction, OwnershipProofEnvelope,
    ProofId, SubjectId,
};
use sumchain_storage::cf;
use sumchain_storage::equity_store::{
    decode_action_id_list, decode_class_id_list, decode_entity_profile, decode_equity_balance,
    decode_equity_token, decode_governance_action, decode_ownership_proof, encode_action_id_list,
    encode_class_id_list, encode_entity_profile, encode_equity_balance, encode_equity_token,
    encode_governance_action, encode_ownership_proof, EquityBalanceStore,
};
use sumchain_storage::exec_view::ExecutionView;

use crate::equity_executor::EquityExecutor;
use crate::{Result, StateError};

impl EquityExecutor {
    // ── Entity profiles ─────────────────────────────────────────────────────

    pub fn v_get_entity(
        view: &ExecutionView<'_, '_>,
        subject_id: &SubjectId,
    ) -> Result<Option<EntityProfile>> {
        match view
            .get(cf::EQUITY_ENTITIES, subject_id)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_entity_profile(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_entity(
        view: &mut ExecutionView<'_, '_>,
        entity: &EntityProfile,
    ) -> Result<()> {
        view.put(
            cf::EQUITY_ENTITIES,
            &entity.subject_id,
            &encode_entity_profile(entity)?,
        )
        .map_err(StateError::Storage)
    }

    // ── Governance actions, and the entity index that finds them ────────────

    pub fn v_get_governance_action(
        view: &ExecutionView<'_, '_>,
        action_id: &ActionId,
    ) -> Result<Option<GovernanceAction>> {
        match view
            .get(cf::EQUITY_GOVERNANCE, action_id)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_governance_action(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_get_entity_actions(
        view: &ExecutionView<'_, '_>,
        entity_subject_id: &SubjectId,
    ) -> Result<Vec<ActionId>> {
        match view
            .get(cf::EQUITY_ENTITY_INDEX, entity_subject_id)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_action_id_list(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    /// Stage a governance action AND its entity index entry.
    pub fn v_put_governance_action(
        view: &mut ExecutionView<'_, '_>,
        action: &GovernanceAction,
    ) -> Result<()> {
        view.put(
            cf::EQUITY_GOVERNANCE,
            &action.action_id,
            &encode_governance_action(action)?,
        )
        .map_err(StateError::Storage)?;

        let mut ids = Self::v_get_entity_actions(view, &action.org_subject)?;
        if !ids.contains(&action.action_id) {
            ids.push(action.action_id);
            view.put(
                cf::EQUITY_ENTITY_INDEX,
                &action.org_subject,
                &encode_action_id_list(&ids)?,
            )
            .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    // ── Equity tokens ───────────────────────────────────────────────────────

    pub fn v_get_equity_token(
        view: &ExecutionView<'_, '_>,
        class_id: &ClassId,
    ) -> Result<Option<EquityToken>> {
        match view
            .get(cf::EQUITY_TOKENS, class_id)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_equity_token(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_equity_token(
        view: &mut ExecutionView<'_, '_>,
        token: &EquityToken,
    ) -> Result<()> {
        view.put(
            cf::EQUITY_TOKENS,
            &token.class_id,
            &encode_equity_token(token)?,
        )
        .map_err(StateError::Storage)
    }

    // ── Balances, and the holder index that is part of them ─────────────────

    pub fn v_get_equity_balance(
        view: &ExecutionView<'_, '_>,
        class_id: &ClassId,
        holder_commitment: &[u8; 32],
    ) -> Result<u64> {
        let key = EquityBalanceStore::make_key(class_id, holder_commitment);
        match view
            .get(cf::EQUITY_BALANCES, &key)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_equity_balance(&bytes)?),
            None => Ok(0),
        }
    }

    pub fn v_set_equity_balance(
        view: &mut ExecutionView<'_, '_>,
        class_id: &ClassId,
        holder_commitment: &[u8; 32],
        balance: u64,
    ) -> Result<()> {
        let key = EquityBalanceStore::make_key(class_id, holder_commitment);
        if balance == 0 {
            view.delete(cf::EQUITY_BALANCES, &key)
                .map_err(StateError::Storage)?;
            Self::v_remove_from_holder_index(view, holder_commitment, class_id)
        } else {
            view.put(cf::EQUITY_BALANCES, &key, &encode_equity_balance(&balance)?)
                .map_err(StateError::Storage)?;
            Self::v_add_to_holder_index(view, holder_commitment, class_id)
        }
    }

    /// Move shares between two holders of one class.
    ///
    /// # This reproduces a defect, on purpose
    ///
    /// Both balances are read BEFORE either write, which is what the committed
    /// `EquityBalanceStore::transfer` does. For a SELF-transfer that inflates:
    /// `from_balance` and `to_balance` are the same row, so a holder with 90
    /// transferring 30 to themselves is written 60 and then 90 + 30 = 120. The
    /// class gains 30 shares out of nothing.
    ///
    /// The account family does not have this bug — `StateManager::v_transfer`
    /// reads the recipient AFTER staging the sender's debit, precisely so a
    /// self-transfer sees its own subtraction — and an earlier version of this
    /// function copied that ordering. That was wrong HERE. This is a parity
    /// preparation: its job is to let the executor change caller without
    /// changing what the chain computes, and silently fixing a consensus-visible
    /// bug inside it would have hidden the fix inside a refactor and made the
    /// routing commit unreviewable against the behaviour it replaced.
    ///
    /// The inflation is tracked separately, for an activation-gated change. Until
    /// that lands, candidate and committed must agree — including here.
    /// [`crate::equity_executor`]'s callers are unchanged either way.
    pub fn v_transfer_equity(
        view: &mut ExecutionView<'_, '_>,
        class_id: &ClassId,
        from_commitment: &[u8; 32],
        to_commitment: &[u8; 32],
        amount: u64,
    ) -> Result<()> {
        let from_balance = Self::v_get_equity_balance(view, class_id, from_commitment)?;
        if from_balance < amount {
            return Err(StateError::InvalidOperation(
                "Insufficient balance".to_string(),
            ));
        }

        // Read before either write: committed ordering, defect included.
        let to_balance = Self::v_get_equity_balance(view, class_id, to_commitment)?;

        Self::v_set_equity_balance(view, class_id, from_commitment, from_balance - amount)?;
        Self::v_set_equity_balance(view, class_id, to_commitment, to_balance + amount)
    }

    /// Every holder of a class, from the candidate. Governance weighs an equity
    /// vote from this, so it has to see the shares this block moved.
    ///
    /// # The prefix is deliberately not re-checked
    ///
    /// The committed `EquityBalanceStore::get_holders` filters a prefix scan on
    /// `key.len() == 64` alone — it never re-checks that the key still starts
    /// with `class_id`. `GovStore::scan_token_holders`, doing the same job one
    /// family over, does check. That asymmetry is a live defect: a scan that
    /// over-runs its prefix returns holders of a DIFFERENT class, with the right
    /// key length and the wrong shares.
    ///
    /// This reproduces the unbounded form on purpose, for the same reason
    /// [`Self::v_transfer_equity`] reproduces the self-transfer inflation: a
    /// parity preparation must not change what the chain computes. Adding the
    /// bound here would fix committed behaviour inside a refactor and leave the
    /// routing commit with no baseline. Tracked separately, for an
    /// activation-gated change.
    pub fn v_get_equity_holders(
        view: &ExecutionView<'_, '_>,
        class_id: &ClassId,
    ) -> Result<Vec<([u8; 32], u64)>> {
        let mut holders = Vec::new();
        for item in view
            .prefix_iter(cf::EQUITY_BALANCES, class_id)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan. Stopping silently would under-report
            // the holder set, and a vote weighed from it is consensus.
            let (key, value) = item.map_err(StateError::Storage)?;
            if key.len() == 64 {
                let mut holder = [0u8; 32];
                holder.copy_from_slice(&key[32..64]);
                holders.push((holder, decode_equity_balance(&value)?));
            }
        }
        Ok(holders)
    }

    pub fn v_get_equity_holdings(
        view: &ExecutionView<'_, '_>,
        holder_commitment: &[u8; 32],
    ) -> Result<Vec<ClassId>> {
        match view
            .get(cf::EQUITY_HOLDER_INDEX, holder_commitment)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_class_id_list(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_holder_index(
        view: &mut ExecutionView<'_, '_>,
        holder_commitment: &[u8; 32],
        class_id: &ClassId,
    ) -> Result<()> {
        let mut class_ids = Self::v_get_equity_holdings(view, holder_commitment)?;
        if !class_ids.contains(class_id) {
            class_ids.push(*class_id);
            view.put(
                cf::EQUITY_HOLDER_INDEX,
                holder_commitment,
                &encode_class_id_list(&class_ids)?,
            )
            .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    fn v_remove_from_holder_index(
        view: &mut ExecutionView<'_, '_>,
        holder_commitment: &[u8; 32],
        class_id: &ClassId,
    ) -> Result<()> {
        let mut class_ids = Self::v_get_equity_holdings(view, holder_commitment)?;
        if let Some(pos) = class_ids.iter().position(|id| id == class_id) {
            class_ids.remove(pos);
            // Empty DELETES the row, as the committed store does.
            if class_ids.is_empty() {
                view.delete(cf::EQUITY_HOLDER_INDEX, holder_commitment)
                    .map_err(StateError::Storage)?;
            } else {
                view.put(
                    cf::EQUITY_HOLDER_INDEX,
                    holder_commitment,
                    &encode_class_id_list(&class_ids)?,
                )
                .map_err(StateError::Storage)?;
            }
        }
        Ok(())
    }

    // ── Ownership proofs ────────────────────────────────────────────────────

    pub fn v_get_ownership_proof(
        view: &ExecutionView<'_, '_>,
        proof_id: &ProofId,
    ) -> Result<Option<OwnershipProofEnvelope>> {
        match view
            .get(cf::EQUITY_PROOFS, proof_id)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_ownership_proof(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_ownership_proof(
        view: &mut ExecutionView<'_, '_>,
        proof: &OwnershipProofEnvelope,
    ) -> Result<()> {
        view.put(
            cf::EQUITY_PROOFS,
            &proof.proof_id,
            &encode_ownership_proof(proof)?,
        )
        .map_err(StateError::Storage)
    }
}
