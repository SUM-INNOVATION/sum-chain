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
        // Validate before storing
        if !policy_account.is_valid() {
            return Err(StorageError::InvalidData(
                "Invalid policy account structure".to_string(),
            ));
        }

        let bytes = bincode::serialize(policy_account)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db
            .put(cf::POLICY_ACCOUNTS, &policy_account.id, &bytes)
    }

    /// Get a policy account by ID
    pub fn get(&self, id: &PolicyAccountId) -> Result<Option<PolicyAccount>> {
        match self.db.get(cf::POLICY_ACCOUNTS, id)? {
            Some(bytes) => {
                let account: PolicyAccount = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Get policy account by controlled address
    pub fn get_by_address(&self, address: &Address) -> Result<Option<PolicyAccount>> {
        // Scan all policy accounts to find one with matching address
        for (_, value) in self.db.iter(cf::POLICY_ACCOUNTS)? {
            let account: PolicyAccount = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if &account.address == address {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    /// Check if policy account exists
    pub fn exists(&self, id: &PolicyAccountId) -> Result<bool> {
        self.db.contains(cf::POLICY_ACCOUNTS, id)
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
            let account: PolicyAccount = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            accounts.push(account);
        }
        Ok(accounts)
    }

    /// List policy accounts where address is a member
    pub fn list_by_member(&self, member: &Address) -> Result<Vec<PolicyAccount>> {
        let mut accounts = Vec::new();
        for (_, value) in self.db.iter(cf::POLICY_ACCOUNTS)? {
            let account: PolicyAccount = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
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
        // Validate before storing
        if !proposal.is_valid() {
            return Err(StorageError::InvalidData(
                "Invalid proposal structure".to_string(),
            ));
        }

        let bytes =
            bincode::serialize(proposal).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::POLICY_PROPOSALS, &proposal.id, &bytes)
    }

    /// Get a proposal by ID
    pub fn get(&self, id: &ProposalId) -> Result<Option<Proposal>> {
        match self.db.get(cf::POLICY_PROPOSALS, id)? {
            Some(bytes) => {
                let proposal: Proposal = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proposal))
            }
            None => Ok(None),
        }
    }

    /// Check if proposal exists
    pub fn exists(&self, id: &ProposalId) -> Result<bool> {
        self.db.contains(cf::POLICY_PROPOSALS, id)
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
            let proposal: Proposal = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
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
            let proposal: Proposal = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
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
            let proposal: Proposal = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
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
            let mut proposal: Proposal = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
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
