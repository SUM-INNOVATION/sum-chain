//! Policy accounts and proposals, as this block's candidate sees them.
//!
//! The committed twins in `sumchain_storage::policy_account_store` stay, and
//! are still correct for what reads them: the RPC server, which answers about
//! the canonical chain and must not see a block that is still being built.
//!
//! ## What these must reproduce exactly
//!
//! * The key layout — the id, unprefixed — from `policy_account_key` and
//!   `proposal_key`.
//! * The codec, including its REFUSAL of an invalid structure: the committed
//!   `put` rejected those, so a candidate that accepted them would stage rows
//!   the chain would not have taken.
//!
//! Both come from the shared builders rather than being restated here, so
//! there is no second encoder to drift.
//!
//! ## Why this subsystem had to move as one unit
//!
//! Every write here is preceded by a read of the same row: `create` refuses a
//! duplicate id, `execute_proposal` checks the proposal's status and matches
//! its policy nonce against the account's, `freeze` reads the account to check
//! membership. Those reads were committed reads, which was only correct because
//! the writes were committed too — mid-block, an earlier transaction of the
//! same block had already landed. Moving the writes without the reads would
//! have left the duplicate guard and the nonce check reading pre-block state.

use sumchain_primitives::policy_account::{
    PolicyAccount, PolicyAccountId, PolicyAccountStatus, Proposal, ProposalId,
};
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::policy_account_store::{
    decode_policy_account, decode_proposal, encode_policy_account, encode_proposal,
    policy_account_key, proposal_key,
};

use crate::policy_account_executor::PolicyAccountExecutor;
use crate::{Result, StateError};

impl PolicyAccountExecutor {
    // ── Policy accounts ─────────────────────────────────────────────────────

    /// A policy account as the candidate sees it, including one created by an
    /// earlier transaction of the same block.
    pub fn v_get_policy_account(
        view: &ExecutionView<'_, '_>,
        id: &PolicyAccountId,
    ) -> Result<Option<PolicyAccount>> {
        match view
            .get(cf::POLICY_ACCOUNTS, policy_account_key(id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_policy_account(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    /// Whether the candidate has a policy account under `id`.
    ///
    /// The duplicate guard for `create`. Reading committed state here would let
    /// two creations of the same id both succeed in one block, and both commit.
    pub fn v_policy_account_exists(
        view: &ExecutionView<'_, '_>,
        id: &PolicyAccountId,
    ) -> Result<bool> {
        view.contains(cf::POLICY_ACCOUNTS, policy_account_key(id))
            .map_err(StateError::Storage)
    }

    pub fn v_put_policy_account(
        view: &mut ExecutionView<'_, '_>,
        account: &PolicyAccount,
    ) -> Result<()> {
        let bytes = encode_policy_account(account).map_err(StateError::Storage)?;
        view.put(cf::POLICY_ACCOUNTS, policy_account_key(&account.id), &bytes)
            .map_err(StateError::Storage)
    }

    /// Read, set the status, write. The committed `update_status` did the same
    /// three things and returned `NotFound` for an absent account; so does this.
    pub fn v_update_policy_account_status(
        view: &mut ExecutionView<'_, '_>,
        id: &PolicyAccountId,
        status: PolicyAccountStatus,
    ) -> Result<()> {
        match Self::v_get_policy_account(view, id)? {
            Some(mut account) => {
                account.status = status;
                Self::v_put_policy_account(view, &account)
            }
            // The committed twin returned `StorageError::NotFound` here, and
            // the caller's behaviour depends on which error it gets, so this
            // returns the same one rather than a state-level equivalent.
            None => Err(StateError::Storage(
                sumchain_storage::StorageError::NotFound(format!(
                    "Policy account not found: {:?}",
                    hex::encode(id)
                )),
            )),
        }
    }

    // ── Proposals ───────────────────────────────────────────────────────────

    /// A proposal as the candidate sees it, including one submitted earlier in
    /// the same block.
    pub fn v_get_proposal(
        view: &ExecutionView<'_, '_>,
        id: &ProposalId,
    ) -> Result<Option<Proposal>> {
        match view
            .get(cf::POLICY_PROPOSALS, proposal_key(id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_proposal(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_proposal(view: &mut ExecutionView<'_, '_>, proposal: &Proposal) -> Result<()> {
        let bytes = encode_proposal(proposal).map_err(StateError::Storage)?;
        view.put(cf::POLICY_PROPOSALS, proposal_key(&proposal.id), &bytes)
            .map_err(StateError::Storage)
    }
}
