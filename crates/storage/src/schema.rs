//! Storage schemas for different data types.
//!
//! Provides typed access to blocks, state, transactions, and receipts.


use sumchain_primitives::{Address, Balance, Block, BlockHeight, Hash, Nonce, Receipt, SignedTransaction};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

/// Keys for metadata storage
pub mod meta_keys {
    pub const LATEST_BLOCK_HASH: &[u8] = b"latest_block_hash";
    pub const LATEST_BLOCK_HEIGHT: &[u8] = b"latest_block_height";
    pub const GENESIS_HASH: &[u8] = b"genesis_hash";
    pub const CHAIN_ID: &[u8] = b"chain_id";
    pub const FINALIZED_HEIGHT: &[u8] = b"finalized_height";
    pub const FINALIZED_HASH: &[u8] = b"finalized_hash";
}

/// Block storage operations
pub struct BlockStore<'a> {
    db: &'a Database,
}

impl<'a> BlockStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a block by its hash
    pub fn put(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let bytes = block.to_bytes();

        // Store block by hash
        self.db.put(cf::BLOCKS, hash.as_bytes(), &bytes)?;

        // Store height -> hash mapping
        let height_key = block.height().to_be_bytes();
        self.db.put(cf::BLOCK_HEIGHT, &height_key, hash.as_bytes())?;

        Ok(())
    }

    /// Get a block by hash
    pub fn get_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        match self.db.get(cf::BLOCKS, hash.as_bytes())? {
            Some(bytes) => {
                let block = Block::from_bytes(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get a block by height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Option<Block>> {
        let height_key = height.to_be_bytes();
        match self.db.get(cf::BLOCK_HEIGHT, &height_key)? {
            Some(hash_bytes) => {
                let hash = Hash::from_slice(&hash_bytes)
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                self.get_by_hash(&hash)
            }
            None => Ok(None),
        }
    }

    /// Get block hash by height
    pub fn get_hash_by_height(&self, height: BlockHeight) -> Result<Option<Hash>> {
        let height_key = height.to_be_bytes();
        match self.db.get(cf::BLOCK_HEIGHT, &height_key)? {
            Some(hash_bytes) => {
                let hash = Hash::from_slice(&hash_bytes)
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Check if a block exists
    pub fn contains(&self, hash: &Hash) -> Result<bool> {
        self.db.contains(cf::BLOCKS, hash.as_bytes())
    }

    /// Get the latest block hash
    pub fn get_latest_hash(&self) -> Result<Option<Hash>> {
        match self.db.get(cf::META, meta_keys::LATEST_BLOCK_HASH)? {
            Some(bytes) => {
                let hash = Hash::from_slice(&bytes)
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Set the latest block hash
    pub fn set_latest_hash(&self, hash: &Hash) -> Result<()> {
        self.db.put(cf::META, meta_keys::LATEST_BLOCK_HASH, hash.as_bytes())
    }

    /// Get the latest block height
    pub fn get_latest_height(&self) -> Result<Option<BlockHeight>> {
        match self.db.get(cf::META, meta_keys::LATEST_BLOCK_HEIGHT)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(StorageError::InvalidData("Invalid height bytes".to_string()));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Set the latest block height
    pub fn set_latest_height(&self, height: BlockHeight) -> Result<()> {
        self.db.put(cf::META, meta_keys::LATEST_BLOCK_HEIGHT, &height.to_be_bytes())
    }

    /// Get the latest block
    pub fn get_latest(&self) -> Result<Option<Block>> {
        match self.get_latest_hash()? {
            Some(hash) => self.get_by_hash(&hash),
            None => Ok(None),
        }
    }

    /// Get the finalized block height
    pub fn get_finalized_height(&self) -> Result<Option<BlockHeight>> {
        match self.db.get(cf::META, meta_keys::FINALIZED_HEIGHT)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(StorageError::InvalidData("Invalid finalized height bytes".to_string()));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Set the finalized block height
    pub fn set_finalized_height(&self, height: BlockHeight) -> Result<()> {
        self.db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &height.to_be_bytes())
    }

    /// Get the finalized block hash
    pub fn get_finalized_hash(&self) -> Result<Option<Hash>> {
        match self.db.get(cf::META, meta_keys::FINALIZED_HASH)? {
            Some(bytes) => {
                let hash = Hash::from_slice(&bytes)
                    .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Set the finalized block hash
    pub fn set_finalized_hash(&self, hash: &Hash) -> Result<()> {
        self.db.put(cf::META, meta_keys::FINALIZED_HASH, hash.as_bytes())
    }

    /// Get the finalized block
    pub fn get_finalized(&self) -> Result<Option<Block>> {
        match self.get_finalized_hash()? {
            Some(hash) => self.get_by_hash(&hash),
            None => Ok(None),
        }
    }
}

/// Account state (balance and nonce)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountState {
    pub balance: Balance,
    pub nonce: Nonce,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            balance: 0,
            nonce: 0,
        }
    }
}

/// State storage operations
pub struct StateStore<'a> {
    db: &'a Database,
}

impl<'a> StateStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Create the key for an account
    fn account_key(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + 20);
        key.extend_from_slice(b"acct");
        key.extend_from_slice(address.as_bytes());
        key
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Result<AccountState> {
        let key = Self::account_key(address);
        match self.db.get(cf::STATE, &key)? {
            Some(bytes) => {
                let state: AccountState = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(state)
            }
            None => Ok(AccountState::default()),
        }
    }

    /// Set account state
    pub fn put_account(&self, address: &Address, state: &AccountState) -> Result<()> {
        let key = Self::account_key(address);
        let bytes = bincode::serialize(state)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::STATE, &key, &bytes)
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> Result<Balance> {
        Ok(self.get_account(address)?.balance)
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> Result<Nonce> {
        Ok(self.get_account(address)?.nonce)
    }

    /// Store a state diff for a block (for reorgs)
    pub fn put_state_diff(&self, height: BlockHeight, diff: &StateDiff) -> Result<()> {
        let key = height.to_be_bytes();
        let bytes = bincode::serialize(diff)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::STATE_DIFFS, &key, &bytes)
    }

    /// Get a state diff for a block
    pub fn get_state_diff(&self, height: BlockHeight) -> Result<Option<StateDiff>> {
        let key = height.to_be_bytes();
        match self.db.get(cf::STATE_DIFFS, &key)? {
            Some(bytes) => {
                let diff: StateDiff = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(diff))
            }
            None => Ok(None),
        }
    }

    /// Delete a state diff
    pub fn delete_state_diff(&self, height: BlockHeight) -> Result<()> {
        let key = height.to_be_bytes();
        self.db.delete(cf::STATE_DIFFS, &key)
    }

    /// Iterate over all accounts in state
    /// Returns (Address, AccountState) pairs
    pub fn iter_all_accounts(&self) -> Result<Vec<(Address, AccountState)>> {
        let prefix = b"acct";
        let mut accounts = Vec::new();

        // Use iterator to get all keys with "acct" prefix in STATE column family
        for (key, value) in self.db.prefix_iter(cf::STATE, prefix)? {
            // Skip if key doesn't match expected length (4 byte prefix + 20 byte address)
            if key.len() != 24 {
                continue;
            }

            // Extract address from key (skip "acct" prefix)
            let mut addr_bytes = [0u8; 20];
            addr_bytes.copy_from_slice(&key[4..24]);
            let address = Address::new(addr_bytes);

            // Deserialize account state
            let state: AccountState = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            accounts.push((address, state));
        }

        Ok(accounts)
    }
}

/// State diff for a single block (for reorg support)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateDiff {
    /// Changes: (address, old_state, new_state)
    pub changes: Vec<(Address, Option<AccountState>, AccountState)>,
}

impl StateDiff {
    pub fn new() -> Self {
        Self { changes: Vec::new() }
    }

    pub fn add_change(&mut self, address: Address, old: Option<AccountState>, new: AccountState) {
        self.changes.push((address, old, new));
    }
}

impl Default for StateDiff {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction storage operations
pub struct TxStore<'a> {
    db: &'a Database,
}

impl<'a> TxStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a transaction
    pub fn put(&self, tx: &SignedTransaction) -> Result<()> {
        let hash = tx.hash();
        let bytes = tx.to_bytes();
        self.db.put(cf::TRANSACTIONS, hash.as_bytes(), &bytes)
    }

    /// Get a transaction by hash
    pub fn get(&self, hash: &Hash) -> Result<Option<SignedTransaction>> {
        match self.db.get(cf::TRANSACTIONS, hash.as_bytes())? {
            Some(bytes) => {
                let tx = SignedTransaction::from_bytes(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// Check if a transaction exists
    pub fn contains(&self, hash: &Hash) -> Result<bool> {
        self.db.contains(cf::TRANSACTIONS, hash.as_bytes())
    }
}

/// Receipt storage operations
pub struct ReceiptStore<'a> {
    db: &'a Database,
}

impl<'a> ReceiptStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a receipt
    pub fn put(&self, receipt: &Receipt) -> Result<()> {
        let bytes = receipt.to_bytes();
        self.db.put(cf::RECEIPTS, receipt.tx_hash.as_bytes(), &bytes)
    }

    /// Get a receipt by transaction hash
    pub fn get(&self, tx_hash: &Hash) -> Result<Option<Receipt>> {
        match self.db.get(cf::RECEIPTS, tx_hash.as_bytes())? {
            Some(bytes) => {
                let receipt = Receipt::from_bytes(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }
}

/// Helper to get chain ID from storage
pub fn get_chain_id(db: &Database) -> Result<Option<u64>> {
    match db.get(cf::META, meta_keys::CHAIN_ID)? {
        Some(bytes) => {
            if bytes.len() != 8 {
                return Err(StorageError::InvalidData("Invalid chain_id bytes".to_string()));
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            Ok(Some(u64::from_be_bytes(arr)))
        }
        None => Ok(None),
    }
}

/// Helper to set chain ID in storage
pub fn set_chain_id(db: &Database, chain_id: u64) -> Result<()> {
    db.put(cf::META, meta_keys::CHAIN_ID, &chain_id.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_account_state() {
        let (db, _dir) = temp_db();
        let store = StateStore::new(&db);

        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        // Default state
        let state = store.get_account(&addr).unwrap();
        assert_eq!(state.balance, 0);
        assert_eq!(state.nonce, 0);

        // Update state
        let new_state = AccountState {
            balance: 1000,
            nonce: 5,
        };
        store.put_account(&addr, &new_state).unwrap();

        let state = store.get_account(&addr).unwrap();
        assert_eq!(state.balance, 1000);
        assert_eq!(state.nonce, 5);
    }

    #[test]
    fn test_block_storage() {
        let (db, _dir) = temp_db();
        let store = BlockStore::new(&db);

        let genesis = Block::genesis(Hash::hash(b"state"), [0u8; 32], 12345);
        let hash = genesis.hash();

        store.put(&genesis).unwrap();

        // Get by hash
        let retrieved = store.get_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved, genesis);

        // Get by height
        let retrieved = store.get_by_height(0).unwrap().unwrap();
        assert_eq!(retrieved, genesis);
    }

    #[test]
    fn test_latest_block() {
        let (db, _dir) = temp_db();
        let store = BlockStore::new(&db);

        let genesis = Block::genesis(Hash::hash(b"state"), [0u8; 32], 12345);
        let hash = genesis.hash();

        store.put(&genesis).unwrap();
        store.set_latest_hash(&hash).unwrap();
        store.set_latest_height(0).unwrap();

        assert_eq!(store.get_latest_hash().unwrap(), Some(hash));
        assert_eq!(store.get_latest_height().unwrap(), Some(0));

        let latest = store.get_latest().unwrap().unwrap();
        assert_eq!(latest, genesis);
    }

    #[test]
    fn test_chain_id() {
        let (db, _dir) = temp_db();

        assert!(get_chain_id(&db).unwrap().is_none());

        set_chain_id(&db, 12345).unwrap();
        assert_eq!(get_chain_id(&db).unwrap(), Some(12345));
    }
}
