//! Policy Account Storage
//!
//! Storage layer for:
//! - Policy accounts (group-governed addresses)
//! - Proposals (group-authorized actions)
//! - Membership and policy configurations

use sumchain_primitives::{
    policy_account::{
        PolicyAccount, PolicyAccountId, PolicyAccountStatus, Proposal, ProposalId, ProposalStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// =============================================================================
// Shared key layout and codec
// =============================================================================
//
// One builder and one codec per row, used by the committed store below and by
// the candidate surface in `sumchain_state::policy_account_view`. Two encoders
// would be free to drift: a candidate that wrote a differently-shaped row would
// still round-trip through itself and only disagree with the chain.

/// The row key for a policy account: the id, unprefixed.
///
/// Returned as a slice of the caller's id rather than a fresh `Vec`, because
/// that is exactly what the key is — there is no prefix, no separator and no
/// encoding step to get wrong, and saying so here is what stops one appearing
/// on one side only.
pub fn policy_account_key(id: &PolicyAccountId) -> &[u8] {
    id
}

/// The row key for a proposal: the id, unprefixed. See
/// [`policy_account_key`].
pub fn proposal_key(id: &ProposalId) -> &[u8] {
    id
}

/// Encode a policy account, REFUSING an invalid one.
///
/// The validity check belongs here rather than in either caller. It was in the
/// committed `put`, so a candidate path that encoded directly would accept
/// structures the chain refuses, and the difference would only appear when the
/// block was published.
pub fn encode_policy_account(account: &PolicyAccount) -> Result<Vec<u8>> {
    if !account.is_valid() {
        return Err(StorageError::InvalidData(
            "Invalid policy account structure".to_string(),
        ));
    }
    bincode::serialize(account).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_policy_account(bytes: &[u8]) -> Result<PolicyAccount> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Encode a proposal, REFUSING an invalid one. See [`encode_policy_account`].
pub fn encode_proposal(proposal: &Proposal) -> Result<Vec<u8>> {
    if !proposal.is_valid() {
        return Err(StorageError::InvalidData(
            "Invalid proposal structure".to_string(),
        ));
    }
    bincode::serialize(proposal).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_proposal(bytes: &[u8]) -> Result<Proposal> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

// =============================================================================
// Policy Account Storage
// =============================================================================

/// Storage for Policy Accounts
pub struct PolicyAccountStore<'a> {
    db: &'a Database,
}

impl<'a> PolicyAccountStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a policy account
    pub fn put(&self, policy_account: &PolicyAccount) -> Result<()> {
        self.db.put(
            cf::POLICY_ACCOUNTS,
            policy_account_key(&policy_account.id),
            &encode_policy_account(policy_account)?,
        )
    }

    /// Get a policy account by ID
    pub fn get(&self, id: &PolicyAccountId) -> Result<Option<PolicyAccount>> {
        match self.db.get(cf::POLICY_ACCOUNTS, policy_account_key(id))? {
            Some(bytes) => Ok(Some(decode_policy_account(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get policy account by controlled address
    pub fn get_by_address(&self, address: &Address) -> Result<Option<PolicyAccount>> {
        // Scan all policy accounts to find one with matching address
        for (_, value) in self.db.iter(cf::POLICY_ACCOUNTS)? {
            let account = decode_policy_account(&value)?;
            if &account.address == address {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// Check if policy account exists
    pub fn exists(&self, id: &PolicyAccountId) -> Result<bool> {
        self.db.contains(cf::POLICY_ACCOUNTS, policy_account_key(id))
    }

    /// Check if address is controlled by a policy account
    pub fn is_policy_controlled(&self, address: &Address) -> Result<bool> {
        Ok(self.get_by_address(address)?.is_some())
    }

    /// Update policy account status
    pub fn update_status(
        &self,
        id: &PolicyAccountId,
        status: PolicyAccountStatus,
    ) -> Result<()> {
        match self.get(id)? {
            Some(mut account) => {
                account.status = status;
                self.put(&account)
            }
            None => Err(StorageError::NotFound(format!(
                "Policy account not found: {:?}",
                hex::encode(id)
            ))),
        }
    }

    /// Increment policy account nonce (for replay protection)
    pub fn increment_nonce(&self, id: &PolicyAccountId) -> Result<u64> {
        match self.get(id)? {
            Some(mut account) => {
                let new_nonce = account.nonce + 1;
                account.nonce = new_nonce;
                self.put(&account)?;
                Ok(new_nonce)
            }
            None => Err(StorageError::NotFound(format!(
                "Policy account not found: {:?}",
                hex::encode(id)
            ))),
        }
    }

    /// Update policy account (for membership/policy changes)
    pub fn update(&self, policy_account: &PolicyAccount) -> Result<()> {
        // Verify it exists first
        if !self.exists(&policy_account.id)? {
            return Err(StorageError::NotFound(format!(
                "Policy account not found: {:?}",
                hex::encode(policy_account.id)
            )));
        }

        self.put(policy_account)
    }

    /// List all policy accounts
    pub fn list_all(&self) -> Result<Vec<PolicyAccount>> {
        let mut accounts = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_ACCOUNTS)? {
            let account = decode_policy_account(&value)?;
            accounts.push(account);
        }
        Ok(accounts)
    }

    /// List policy accounts where address is a member
    pub fn list_by_member(&self, member: &Address) -> Result<Vec<PolicyAccount>> {
        let mut accounts = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_ACCOUNTS)? {
            let account = decode_policy_account(&value)?;
            if account.is_member(member) {
                accounts.push(account);
            }
        }
        Ok(accounts)
    }
}

// =============================================================================
// Proposal Storage
// =============================================================================

/// Storage for Proposals
pub struct ProposalStore<'a> {
    db: &'a Database,
}

impl<'a> ProposalStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a proposal
    pub fn put(&self, proposal: &Proposal) -> Result<()> {
        self.db.put(
            cf::POLICY_PROPOSALS,
            proposal_key(&proposal.id),
            &encode_proposal(proposal)?,
        )
    }

    /// Get a proposal by ID
    pub fn get(&self, id: &ProposalId) -> Result<Option<Proposal>> {
        match self.db.get(cf::POLICY_PROPOSALS, proposal_key(id))? {
            Some(bytes) => Ok(Some(decode_proposal(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if proposal exists
    pub fn exists(&self, id: &ProposalId) -> Result<bool> {
        self.db.contains(cf::POLICY_PROPOSALS, proposal_key(id))
    }

    /// Update proposal status
    pub fn update_status(&self, id: &ProposalId, status: ProposalStatus) -> Result<()> {
        match self.get(id)? {
            Some(mut proposal) => {
                proposal.status = status;
                self.put(&proposal)
            }
            None => Err(StorageError::NotFound(format!(
                "Proposal not found: {:?}",
                hex::encode(id)
            ))),
        }
    }

    /// Update proposal (for adding approvals)
    pub fn update(&self, proposal: &Proposal) -> Result<()> {
        // Verify it exists first
        if !self.exists(&proposal.id)? {
            return Err(StorageError::NotFound(format!(
                "Proposal not found: {:?}",
                hex::encode(proposal.id)
            )));
        }

        self.put(proposal)
    }

    /// List all proposals for a policy account
    pub fn list_by_policy_account(
        &self,
        policy_account_id: &PolicyAccountId,
    ) -> Result<Vec<Proposal>> {
        let mut proposals = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_PROPOSALS)? {
            let proposal = decode_proposal(&value)?;
            if &proposal.policy_account_id == policy_account_id {
                proposals.push(proposal);
            }
        }
        Ok(proposals)
    }

    /// List pending proposals for a policy account
    pub fn list_pending(&self, policy_account_id: &PolicyAccountId) -> Result<Vec<Proposal>> {
        let mut proposals = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_PROPOSALS)? {
            let proposal = decode_proposal(&value)?;
            if &proposal.policy_account_id == policy_account_id && proposal.status.is_pending() {
                proposals.push(proposal);
            }
        }
        Ok(proposals)
    }

    /// List proposals by proposer
    pub fn list_by_proposer(&self, proposer: &Address) -> Result<Vec<Proposal>> {
        let mut proposals = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_PROPOSALS)? {
            let proposal = decode_proposal(&value)?;
            if &proposal.proposer == proposer {
                proposals.push(proposal);
            }
        }
        Ok(proposals)
    }

    /// Expire proposals that have passed their expiration time
    pub fn expire_old_proposals(&self, current_time: Timestamp) -> Result<usize> {
        let mut expired_count = 0;
        for (_, value) in self.db.iter(cf::POLICY_PROPOSALS)? {
            let mut proposal = decode_proposal(&value)?;
            if proposal.status.is_pending() && proposal.expires_at < current_time {
                proposal.status = ProposalStatus::Expired;
                self.put(&proposal)?;
                expired_count += 1;
            }
        }
        Ok(expired_count)
    }
}

// =============================================================================
// Combined Store Access
// =============================================================================

/// Combined storage for all Policy Account components
pub struct PolicyAccountStorage<'a> {
    db: &'a Database,
}

impl<'a> PolicyAccountStorage<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get policy account store
    pub fn policy_accounts(&self) -> PolicyAccountStore {
        PolicyAccountStore::new(self.db)
    }

    /// Get proposal store
    pub fn proposals(&self) -> ProposalStore {
        ProposalStore::new(self.db)
    }
}
