//! Storage Metadata Executor
//!
//! Manages on-chain metadata for files stored in the decentralized storage layer.
//! Each file is identified by its Blake3 Merkle root and carries an access control
//! list (ACL) plus a locked fee pool for storage payouts.
//!
//! **Atomicity guarantee:** fee deduction and metadata creation are performed as
//! in-memory state mutations within `execute_block()`. If the DB write fails, the
//! entire block's state changes are rolled back — no funds are burned.

use std::sync::Arc;

use sumchain_primitives::{
    Address, Balance, Hash, StorageMetadata, StorageMetadataOperation, StorageMetadataTxData,
};
use sumchain_storage::Database;
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Column family name for storage metadata
pub const CF_STORAGE_METADATA: &str = "storage_metadata";

// ─── Key helpers ─────────────────────────────────────────────────────────────

fn metadata_key(merkle_root: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b'F');
    key.extend_from_slice(merkle_root.as_bytes());
    key
}

fn owner_index_key(owner: &Address, merkle_root: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(53);
    key.push(b'O');
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(merkle_root.as_bytes());
    key
}

// ─── Executor ────────────────────────────────────────────────────────────────

/// Result of a storage metadata operation
#[derive(Debug)]
pub struct StorageMetadataExecutionResult {
    pub success: bool,
    pub error: Option<String>,
}

impl StorageMetadataExecutionResult {
    fn ok() -> Self {
        Self { success: true, error: None }
    }
    fn fail(msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()) }
    }
}

pub struct StorageMetadataExecutor {
    db: Arc<Database>,
}

impl StorageMetadataExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
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

        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        state.put_account(sender, &sender_account)?;

        if !proposer.is_zero() {
            let mut proposer_account = state.get_account(proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            state.put_account(proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Execute a storage metadata operation.
    pub fn execute(
        &self,
        sender: &Address,
        data: &StorageMetadataTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        self.deduct_fee(state, sender, fee, proposer)?;

        match &data.operation {
            StorageMetadataOperation::RegisterFile {
                merkle_root,
                total_size_bytes,
                access_list,
                fee_deposit,
            } => self.execute_register_file(
                sender, merkle_root, *total_size_bytes, access_list, *fee_deposit, state, block_height,
            ),
            StorageMetadataOperation::UpdateAccessList {
                merkle_root,
                new_access_list,
            } => self.execute_update_access_list(sender, merkle_root, new_access_list),
            StorageMetadataOperation::AddAccess {
                merkle_root,
                address,
            } => self.execute_add_access(sender, merkle_root, address),
            StorageMetadataOperation::RemoveAccess {
                merkle_root,
                address,
            } => self.execute_remove_access(sender, merkle_root, address),
            StorageMetadataOperation::TopUpFeePool {
                merkle_root,
                amount,
            } => self.execute_top_up(sender, merkle_root, *amount, state),
        }
    }

    // ── Operations ───────────────────────────────────────────────────────────

    fn execute_register_file(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        total_size_bytes: u64,
        access_list: &[Address],
        fee_deposit: u64,
        state: &StateManager,
        block_height: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        if self.get_metadata(merkle_root)?.is_some() {
            return Ok(StorageMetadataExecutionResult::fail(
                "File with this merkle_root already registered",
            ));
        }

        if fee_deposit == 0 {
            return Ok(StorageMetadataExecutionResult::fail("fee_deposit must be > 0"));
        }

        let balance = state.get_balance(sender)?;
        if balance < fee_deposit as u128 {
            return Ok(StorageMetadataExecutionResult::fail(format!(
                "Insufficient balance for fee deposit: need {}, have {}",
                fee_deposit, balance
            )));
        }

        // Atomic: deduct balance then write metadata.
        // Both are in-memory; if put_metadata fails the block reverts entirely.
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee_deposit as u128);
        state.put_account(sender, &sender_account)?;

        let metadata = StorageMetadata {
            merkle_root: *merkle_root,
            owner: *sender,
            total_size_bytes,
            access_list: access_list.to_vec(),
            fee_pool: fee_deposit,
            created_at: block_height,
        };

        self.put_metadata(&metadata)?;

        info!(
            "File registered: merkle_root={}, owner={}, size={}, fee_pool={}",
            merkle_root, sender, total_size_bytes, fee_deposit
        );

        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_update_access_list(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        new_access_list: &[Address],
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match self.get_metadata(merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if meta.owner != *sender {
            return Ok(StorageMetadataExecutionResult::fail(
                "Only the owner can update the access list",
            ));
        }

        meta.access_list = new_access_list.to_vec();
        self.put_metadata(&meta)?;

        debug!("Access list updated for {}", merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_add_access(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match self.get_metadata(merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if meta.owner != *sender {
            return Ok(StorageMetadataExecutionResult::fail(
                "Only the owner can modify the access list",
            ));
        }

        if meta.access_list.contains(address) {
            return Ok(StorageMetadataExecutionResult::fail("Address already in access list"));
        }

        meta.access_list.push(*address);
        self.put_metadata(&meta)?;

        debug!("Added {} to access list for {}", address, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_remove_access(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match self.get_metadata(merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if meta.owner != *sender {
            return Ok(StorageMetadataExecutionResult::fail(
                "Only the owner can modify the access list",
            ));
        }

        let before = meta.access_list.len();
        meta.access_list.retain(|a| a != address);

        if meta.access_list.len() == before {
            return Ok(StorageMetadataExecutionResult::fail("Address not in access list"));
        }

        self.put_metadata(&meta)?;

        debug!("Removed {} from access list for {}", address, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_top_up(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        amount: u64,
        state: &StateManager,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match self.get_metadata(merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if amount == 0 {
            return Ok(StorageMetadataExecutionResult::fail("Amount must be > 0"));
        }

        let balance = state.get_balance(sender)?;
        if balance < amount as u128 {
            return Ok(StorageMetadataExecutionResult::fail(format!(
                "Insufficient balance: need {}, have {}",
                amount, balance
            )));
        }

        // Atomic: deduct then update
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(amount as u128);
        state.put_account(sender, &sender_account)?;

        meta.fee_pool = meta.fee_pool.saturating_add(amount);
        self.put_metadata(&meta)?;

        debug!("Fee pool topped up by {} for {}", amount, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    // ── Storage operations ───────────────────────────────────────────────────

    fn put_metadata(&self, meta: &StorageMetadata) -> Result<()> {
        let key = metadata_key(&meta.merkle_root);
        let value = bincode::serialize(meta)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(CF_STORAGE_METADATA, &key, &value)
            .map_err(|e| StateError::Storage(e))?;

        let idx_key = owner_index_key(&meta.owner, &meta.merkle_root);
        self.db.put(CF_STORAGE_METADATA, &idx_key, &[1])
            .map_err(|e| StateError::Storage(e))?;

        Ok(())
    }

    pub fn get_metadata(&self, merkle_root: &Hash) -> Result<Option<StorageMetadata>> {
        let key = metadata_key(merkle_root);
        match self.db.get(CF_STORAGE_METADATA, &key) {
            Ok(Some(data)) => {
                let meta: StorageMetadata = bincode::deserialize(&data)
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                Ok(Some(meta))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    pub fn get_by_owner(&self, owner: &Address) -> Result<Vec<StorageMetadata>> {
        let prefix = {
            let mut p = Vec::with_capacity(21);
            p.push(b'O');
            p.extend_from_slice(owner.as_bytes());
            p
        };

        let mut files = Vec::new();
        let entries: Vec<_> = self.db
            .prefix_iter(CF_STORAGE_METADATA, &prefix)
            .map_err(|e| StateError::Storage(e))?
            .collect();

        for (key, _) in entries {
            if key.len() >= 53 {
                let hash = Hash::from_slice(&key[21..53])
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                if let Some(meta) = self.get_metadata(&hash)? {
                    files.push(meta);
                }
            }
        }

        Ok(files)
    }
}
