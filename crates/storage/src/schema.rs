//! Storage schemas for different data types.
//!
//! Provides typed access to blocks, state, transactions, and receipts.


use sumchain_primitives::{
    Address, Balance, Block, BlockHeight, DelegationInfo, EvidenceType, Hash, Nonce, Receipt,
    SignedTransaction, SlashingRecord, UnbondingDelegation, ValidatorInfo, ValidatorSigningInfo,
    ValidatorStatus,
};

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

    /// Store the per-block contract-state diff (for reorg revert).
    pub fn put_contract_state_diff(
        &self,
        height: BlockHeight,
        diff: &ContractStateDiff,
    ) -> Result<()> {
        let key = height.to_be_bytes();
        let bytes = bincode::serialize(diff)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::CONTRACT_STATE_DIFFS, &key, &bytes)
    }

    /// Get the per-block contract-state diff.
    pub fn get_contract_state_diff(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ContractStateDiff>> {
        let key = height.to_be_bytes();
        match self.db.get(cf::CONTRACT_STATE_DIFFS, &key)? {
            Some(bytes) => {
                let diff: ContractStateDiff = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(diff))
            }
            None => Ok(None),
        }
    }

    /// Delete the per-block contract-state diff.
    pub fn delete_contract_state_diff(&self, height: BlockHeight) -> Result<()> {
        let key = height.to_be_bytes();
        self.db.delete(cf::CONTRACT_STATE_DIFFS, &key)
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

/// CF-kind tags for contract-state mutations (the CF a record targets).
pub mod contract_cf_kind {
    pub const STORAGE: u8 = 0;
    pub const CODE: u8 = 1;
    pub const METADATA: u8 = 2;
}

/// Domain separator for the contract-state-diff digest (consensus ABI v1).
pub const CONTRACT_STATE_DIFF_DOMAIN: &[u8] = b"SUM-CONTRACT-STATE-DIFF:v1";

/// One contract-state mutation, captured for reorg revert + root commitment.
/// `key` is the raw column-family row key; `cf_kind` selects the CF.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractMutation {
    pub cf_kind: u8,
    pub key: Vec<u8>,
    pub old: Option<Vec<u8>>,
    pub new: Option<Vec<u8>>,
}

/// Per-block journal of contract code/storage/metadata mutations.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContractStateDiff {
    pub records: Vec<ContractMutation>,
}

impl ContractStateDiff {
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn push(&mut self, m: ContractMutation) {
        self.records.push(m);
    }

    /// Sort records deterministically by `(cf_kind, key)`. MUST be called
    /// before persistence and digesting so every validator agrees.
    pub fn sort(&mut self) {
        self.records
            .sort_by(|a, b| a.cf_kind.cmp(&b.cf_kind).then_with(|| a.key.cmp(&b.key)));
    }

    /// Deterministic, domain-separated digest over the (already-sorted)
    /// records. An empty diff hashes to the domain-only digest. Per record:
    /// `cf_kind(u8) | key_len(u32 LE) | key | old_present(u8) [old_len(u32 LE)|old]
    /// | new_present(u8) [new_len(u32 LE)|new]`.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTRACT_STATE_DIFF_DOMAIN);
        for r in &self.records {
            hasher.update(&[r.cf_kind]);
            hasher.update(&(r.key.len() as u32).to_le_bytes());
            hasher.update(&r.key);
            match &r.old {
                Some(v) => {
                    hasher.update(&[1u8]);
                    hasher.update(&(v.len() as u32).to_le_bytes());
                    hasher.update(v);
                }
                None => {
                    hasher.update(&[0u8]);
                }
            }
            match &r.new {
                Some(v) => {
                    hasher.update(&[1u8]);
                    hasher.update(&(v.len() as u32).to_le_bytes());
                    hasher.update(v);
                }
                None => {
                    hasher.update(&[0u8]);
                }
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Column-family name for a `cf_kind` (used by reorg revert). `None` for
    /// an unknown kind.
    pub fn cf_name(cf_kind: u8) -> Option<&'static str> {
        match cf_kind {
            contract_cf_kind::STORAGE => Some(cf::CONTRACT_STORAGE),
            contract_cf_kind::CODE => Some(cf::CONTRACT_CODE),
            contract_cf_kind::METADATA => Some(cf::CONTRACT_METADATA),
            _ => None,
        }
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

/// Transaction index entry containing block height, tx index, and tx hash
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxIndexEntry {
    pub block_height: BlockHeight,
    pub tx_index: u32,
    pub tx_hash: Hash,
}

/// Transaction index storage operations for querying transactions by address
pub struct TxIndexStore<'a> {
    db: &'a Database,
}

impl<'a> TxIndexStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Create key for sender index: sender (20 bytes) + height (8 bytes BE) + tx_index (4 bytes BE)
    fn sender_key(sender: &Address, height: BlockHeight, tx_index: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(sender.as_bytes());
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Create key for recipient index: recipient (20 bytes) + height (8 bytes BE) + tx_index (4 bytes BE)
    fn recipient_key(recipient: &Address, height: BlockHeight, tx_index: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(recipient.as_bytes());
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key
    }

    /// Index a transaction by its sender
    pub fn index_by_sender(
        &self,
        sender: &Address,
        height: BlockHeight,
        tx_index: u32,
        tx_hash: &Hash,
    ) -> Result<()> {
        let key = Self::sender_key(sender, height, tx_index);
        self.db.put(cf::TX_BY_SENDER, &key, tx_hash.as_bytes())
    }

    /// Index a transaction by its recipient
    pub fn index_by_recipient(
        &self,
        recipient: &Address,
        height: BlockHeight,
        tx_index: u32,
        tx_hash: &Hash,
    ) -> Result<()> {
        let key = Self::recipient_key(recipient, height, tx_index);
        self.db.put(cf::TX_BY_RECIPIENT, &key, tx_hash.as_bytes())
    }

    /// Index a transaction (indexes both sender and recipient)
    pub fn index_transaction(
        &self,
        tx: &SignedTransaction,
        height: BlockHeight,
        tx_index: u32,
    ) -> Result<()> {
        let tx_hash = tx.hash();
        let sender = tx.sender();

        // Index by sender
        self.index_by_sender(&sender, height, tx_index, &tx_hash)?;

        // Index by recipient if present
        if let Some(recipient) = tx.recipient() {
            self.index_by_recipient(&recipient, height, tx_index, &tx_hash)?;
        }

        Ok(())
    }

    /// Get transactions sent by an address, with pagination
    /// Returns (tx_hashes, has_more)
    pub fn get_transactions_by_sender(
        &self,
        sender: &Address,
        start_height: Option<BlockHeight>,
        limit: usize,
    ) -> Result<(Vec<TxIndexEntry>, bool)> {
        let prefix = sender.as_bytes();
        let mut entries = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::TX_BY_SENDER, prefix)? {
            // Verify key belongs to this sender (first 20 bytes)
            if key.len() != 32 || &key[..20] != prefix {
                continue;
            }

            // Parse height and tx_index from key
            let height = BlockHeight::from_be_bytes(
                key[20..28].try_into().map_err(|_| StorageError::InvalidData("Invalid height".to_string()))?
            );
            let tx_index = u32::from_be_bytes(
                key[28..32].try_into().map_err(|_| StorageError::InvalidData("Invalid tx_index".to_string()))?
            );

            // Skip if before start_height
            if let Some(start) = start_height {
                if height < start {
                    continue;
                }
            }

            // Parse tx_hash
            let tx_hash = Hash::from_slice(&value)
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;

            entries.push(TxIndexEntry {
                block_height: height,
                tx_index,
                tx_hash,
            });

            if entries.len() > limit {
                break;
            }
        }

        let has_more = entries.len() > limit;
        if has_more {
            entries.pop();
        }

        // Sort by height descending (most recent first)
        entries.sort_by(|a, b| b.block_height.cmp(&a.block_height));

        Ok((entries, has_more))
    }

    /// Get transactions received by an address, with pagination
    /// Returns (tx_hashes, has_more)
    pub fn get_transactions_by_recipient(
        &self,
        recipient: &Address,
        start_height: Option<BlockHeight>,
        limit: usize,
    ) -> Result<(Vec<TxIndexEntry>, bool)> {
        let prefix = recipient.as_bytes();
        let mut entries = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::TX_BY_RECIPIENT, prefix)? {
            // Verify key belongs to this recipient (first 20 bytes)
            if key.len() != 32 || &key[..20] != prefix {
                continue;
            }

            // Parse height and tx_index from key
            let height = BlockHeight::from_be_bytes(
                key[20..28].try_into().map_err(|_| StorageError::InvalidData("Invalid height".to_string()))?
            );
            let tx_index = u32::from_be_bytes(
                key[28..32].try_into().map_err(|_| StorageError::InvalidData("Invalid tx_index".to_string()))?
            );

            // Skip if before start_height
            if let Some(start) = start_height {
                if height < start {
                    continue;
                }
            }

            // Parse tx_hash
            let tx_hash = Hash::from_slice(&value)
                .map_err(|e| StorageError::InvalidData(e.to_string()))?;

            entries.push(TxIndexEntry {
                block_height: height,
                tx_index,
                tx_hash,
            });

            if entries.len() > limit {
                break;
            }
        }

        let has_more = entries.len() > limit;
        if has_more {
            entries.pop();
        }

        // Sort by height descending (most recent first)
        entries.sort_by(|a, b| b.block_height.cmp(&a.block_height));

        Ok((entries, has_more))
    }

    /// Get all transactions for an address (both sent and received), with pagination
    /// Returns (tx_entries, has_more)
    pub fn get_transactions_by_address(
        &self,
        address: &Address,
        start_height: Option<BlockHeight>,
        limit: usize,
    ) -> Result<(Vec<TxIndexEntry>, bool)> {
        // Get sent transactions
        let (sent, _) = self.get_transactions_by_sender(address, start_height, limit * 2)?;

        // Get received transactions
        let (received, _) = self.get_transactions_by_recipient(address, start_height, limit * 2)?;

        // Merge and deduplicate by tx_hash
        let mut all_entries: Vec<TxIndexEntry> = sent;
        for entry in received {
            if !all_entries.iter().any(|e| e.tx_hash == entry.tx_hash) {
                all_entries.push(entry);
            }
        }

        // Sort by height descending
        all_entries.sort_by(|a, b| b.block_height.cmp(&a.block_height));

        // Apply limit
        let has_more = all_entries.len() > limit;
        all_entries.truncate(limit);

        Ok((all_entries, has_more))
    }

    /// Get transaction count for an address
    pub fn get_transaction_count(&self, address: &Address) -> Result<u64> {
        let (entries, _) = self.get_transactions_by_address(address, None, usize::MAX)?;
        Ok(entries.len() as u64)
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

// ============================================================================
// NFT Storage (SUM-721)
// ============================================================================

/// NFT collection stored data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NftCollectionData {
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Collection description
    pub description: String,
    /// Collection owner
    pub owner: Address,
    /// Max supply (0 = unlimited)
    pub max_supply: u64,
    /// Current total supply
    pub total_supply: u64,
    /// Next token ID
    pub next_token_id: u64,
    /// Whether tokens can be transferred
    pub transferable: bool,
    /// Whether tokens can be burned
    pub burnable: bool,
    /// Whether metadata can be updated
    pub metadata_updatable: bool,
    /// Whether only owner can mint
    pub owner_only_minting: bool,
    /// Royalty in basis points (100 = 1%)
    pub royalty_bps: u16,
    /// Royalty recipient
    pub royalty_recipient: Address,
    /// Base URI for metadata
    pub base_uri: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
}

/// NFT token stored data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NftTokenData {
    /// Collection ID
    pub collection_id: [u8; 32],
    /// Token ID
    pub token_id: u64,
    /// Current owner
    pub owner: Address,
    /// Original creator
    pub creator: Address,
    /// Token metadata (serialized)
    pub metadata: Vec<u8>,
    /// Whether this is a document token
    pub is_document: bool,
    /// Token URI type ("onchain", "ipfs", "url")
    pub uri_type: String,
    /// Token URI value (for ipfs/url)
    pub uri_value: Option<String>,
    /// Approved address for transfer
    pub approved: Option<Address>,
    /// Whether token is locked
    pub locked: bool,
    /// Transfer count
    pub transfer_count: u32,
    /// Minting timestamp
    pub minted_at: u64,
}

/// NFT storage operations
pub struct NftStore<'a> {
    db: &'a Database,
}

impl<'a> NftStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Collection operations
    // ========================================================================

    /// Store a collection
    pub fn put_collection(&self, collection_id: &[u8; 32], data: &NftCollectionData) -> Result<()> {
        let bytes = bincode::serialize(data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::NFT_COLLECTIONS, collection_id, &bytes)
    }

    /// Get a collection
    pub fn get_collection(&self, collection_id: &[u8; 32]) -> Result<Option<NftCollectionData>> {
        match self.db.get(cf::NFT_COLLECTIONS, collection_id)? {
            Some(bytes) => {
                let data: NftCollectionData = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Check if collection exists
    pub fn collection_exists(&self, collection_id: &[u8; 32]) -> Result<bool> {
        self.db.contains(cf::NFT_COLLECTIONS, collection_id)
    }

    // ========================================================================
    // Token operations
    // ========================================================================

    /// Create token key from collection_id and token_id
    fn token_key(collection_id: &[u8; 32], token_id: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(collection_id);
        key.extend_from_slice(&token_id.to_be_bytes());
        key
    }

    /// Store a token
    pub fn put_token(&self, collection_id: &[u8; 32], token_id: u64, data: &NftTokenData) -> Result<()> {
        let key = Self::token_key(collection_id, token_id);
        let bytes = bincode::serialize(data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::NFT_TOKENS, &key, &bytes)
    }

    /// Get a token
    pub fn get_token(&self, collection_id: &[u8; 32], token_id: u64) -> Result<Option<NftTokenData>> {
        let key = Self::token_key(collection_id, token_id);
        match self.db.get(cf::NFT_TOKENS, &key)? {
            Some(bytes) => {
                let data: NftTokenData = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Check if token exists
    pub fn token_exists(&self, collection_id: &[u8; 32], token_id: u64) -> Result<bool> {
        let key = Self::token_key(collection_id, token_id);
        self.db.contains(cf::NFT_TOKENS, &key)
    }

    /// Delete a token (for burns)
    pub fn delete_token(&self, collection_id: &[u8; 32], token_id: u64) -> Result<()> {
        let key = Self::token_key(collection_id, token_id);
        self.db.delete(cf::NFT_TOKENS, &key)
    }

    // ========================================================================
    // Index operations
    // ========================================================================

    /// Add token to owner index
    pub fn add_to_owner_index(&self, owner: &Address, collection_id: &[u8; 32], token_id: u64) -> Result<()> {
        let mut tokens = self.get_owner_tokens(owner)?;

        let entry = (collection_id.to_vec(), token_id);
        if !tokens.iter().any(|(c, t)| c == collection_id && *t == token_id) {
            tokens.push(entry);
        }

        let bytes = bincode::serialize(&tokens)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::NFT_OWNER_INDEX, owner.as_bytes(), &bytes)
    }

    /// Remove token from owner index
    pub fn remove_from_owner_index(&self, owner: &Address, collection_id: &[u8; 32], token_id: u64) -> Result<()> {
        let mut tokens = self.get_owner_tokens(owner)?;
        tokens.retain(|(c, t)| !(c.as_slice() == collection_id && *t == token_id));

        if tokens.is_empty() {
            self.db.delete(cf::NFT_OWNER_INDEX, owner.as_bytes())?;
        } else {
            let bytes = bincode::serialize(&tokens)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::NFT_OWNER_INDEX, owner.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    /// Get all tokens owned by an address
    pub fn get_owner_tokens(&self, owner: &Address) -> Result<Vec<(Vec<u8>, u64)>> {
        match self.db.get(cf::NFT_OWNER_INDEX, owner.as_bytes())? {
            Some(bytes) => {
                let tokens: Vec<(Vec<u8>, u64)> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(tokens)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get token count for an owner
    pub fn get_owner_token_count(&self, owner: &Address) -> Result<u64> {
        Ok(self.get_owner_tokens(owner)?.len() as u64)
    }

    /// Add token to collection index
    pub fn add_to_collection_index(&self, collection_id: &[u8; 32], token_id: u64) -> Result<()> {
        let mut tokens = self.get_collection_tokens(collection_id)?;
        if !tokens.contains(&token_id) {
            tokens.push(token_id);
        }

        let bytes = bincode::serialize(&tokens)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::NFT_COLLECTION_INDEX, collection_id, &bytes)
    }

    /// Remove token from collection index
    pub fn remove_from_collection_index(&self, collection_id: &[u8; 32], token_id: u64) -> Result<()> {
        let mut tokens = self.get_collection_tokens(collection_id)?;
        tokens.retain(|t| *t != token_id);

        let bytes = bincode::serialize(&tokens)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::NFT_COLLECTION_INDEX, collection_id, &bytes)
    }

    /// Get all token IDs in a collection
    pub fn get_collection_tokens(&self, collection_id: &[u8; 32]) -> Result<Vec<u64>> {
        match self.db.get(cf::NFT_COLLECTION_INDEX, collection_id)? {
            Some(bytes) => {
                let tokens: Vec<u64> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(tokens)
            }
            None => Ok(Vec::new()),
        }
    }

    // ========================================================================
    // Convenience methods
    // ========================================================================

    /// Transfer token ownership (updates indices)
    pub fn transfer_token(
        &self,
        collection_id: &[u8; 32],
        token_id: u64,
        from: &Address,
        to: &Address,
    ) -> Result<()> {
        // Update token owner
        if let Some(mut token) = self.get_token(collection_id, token_id)? {
            token.owner = *to;
            token.approved = None;
            token.transfer_count += 1;
            self.put_token(collection_id, token_id, &token)?;
        }

        // Update owner indices
        self.remove_from_owner_index(from, collection_id, token_id)?;
        self.add_to_owner_index(to, collection_id, token_id)?;

        Ok(())
    }

    /// Burn a token (removes from all indices)
    pub fn burn_token(&self, collection_id: &[u8; 32], token_id: u64, owner: &Address) -> Result<()> {
        // Delete token
        self.delete_token(collection_id, token_id)?;

        // Update indices
        self.remove_from_owner_index(owner, collection_id, token_id)?;
        self.remove_from_collection_index(collection_id, token_id)?;

        // Update collection supply
        if let Some(mut collection) = self.get_collection(collection_id)? {
            collection.total_supply = collection.total_supply.saturating_sub(1);
            self.put_collection(collection_id, &collection)?;
        }

        Ok(())
    }
}

// ============================================================================
// Issuer Registry Storage
// ============================================================================

/// Stored issuer data for the registry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuerData {
    /// Issuer's address (signing key)
    pub address: Address,
    /// Official name of the issuing organization
    pub name: String,
    /// Verified domain (e.g., "university.edu")
    pub domain: String,
    /// Organization type code
    pub org_type: u8,
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,
    /// Status (0=Active, 1=Suspended, 2=Revoked)
    pub status: u8,
    /// Document types this issuer can mint
    pub allowed_doc_types: Vec<String>,
    /// When the issuer was registered (timestamp ms)
    pub registered_at: u64,
    /// When the issuer was last updated (timestamp ms)
    pub updated_at: u64,
    /// Registration expiry (0 = no expiry)
    pub expires_at: u64,
    /// Additional metadata (JSON)
    pub metadata: Option<String>,
}

impl IssuerData {
    /// Check if issuer is active
    pub fn is_active(&self) -> bool {
        self.status == 0
    }

    /// Check if issuer can mint documents
    pub fn can_mint(&self, current_time: u64) -> bool {
        self.is_active() && (self.expires_at == 0 || current_time <= self.expires_at)
    }

    /// Check if issuer can mint a specific document type
    pub fn can_mint_doc_type(&self, doc_type: &str, current_time: u64) -> bool {
        if !self.can_mint(current_time) {
            return false;
        }
        // Empty list means all types allowed
        if self.allowed_doc_types.is_empty() {
            return true;
        }
        self.allowed_doc_types.iter().any(|t| t == doc_type || t == "*")
    }
}

/// Issuer registry storage operations
pub struct IssuerStore<'a> {
    db: &'a Database,
}

impl<'a> IssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Register a new issuer
    pub fn put_issuer(&self, address: &Address, data: &IssuerData) -> Result<()> {
        let bytes = bincode::serialize(data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::ISSUER_REGISTRY, address.as_bytes(), &bytes)
    }

    /// Get an issuer by address
    pub fn get_issuer(&self, address: &Address) -> Result<Option<IssuerData>> {
        match self.db.get(cf::ISSUER_REGISTRY, address.as_bytes())? {
            Some(bytes) => {
                let data: IssuerData = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Check if an address is a registered issuer
    pub fn is_registered(&self, address: &Address) -> Result<bool> {
        self.db.contains(cf::ISSUER_REGISTRY, address.as_bytes())
    }

    /// Check if an address can mint certified documents
    pub fn can_mint_documents(&self, address: &Address, doc_type: Option<&str>, current_time: u64) -> Result<bool> {
        match self.get_issuer(address)? {
            Some(issuer) => {
                if let Some(dtype) = doc_type {
                    Ok(issuer.can_mint_doc_type(dtype, current_time))
                } else {
                    Ok(issuer.can_mint(current_time))
                }
            }
            None => Ok(false),
        }
    }

    /// Delete an issuer (for complete removal)
    pub fn delete_issuer(&self, address: &Address) -> Result<()> {
        self.db.delete(cf::ISSUER_REGISTRY, address.as_bytes())
    }

    /// Get all registered issuers
    pub fn get_all_issuers(&self) -> Result<Vec<IssuerData>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::ISSUER_REGISTRY, &[])? {
            let issuer: IssuerData = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            issuers.push(issuer);
        }
        Ok(issuers)
    }

    /// Get all active issuers
    pub fn get_active_issuers(&self) -> Result<Vec<IssuerData>> {
        let all = self.get_all_issuers()?;
        Ok(all.into_iter().filter(|i| i.is_active()).collect())
    }
}

// ============================================================================
// SRC-20 Token Storage
// ============================================================================

/// SRC-20 token stored data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Src20TokenData {
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Decimal places
    pub decimals: u8,
    /// Token owner
    pub owner: Address,
    /// Current total supply
    pub total_supply: u128,
    /// Maximum supply (0 = unlimited)
    pub max_supply: u128,
    /// Whether new tokens can be minted
    pub mintable: bool,
    /// Whether tokens can be burned
    pub burnable: bool,
    /// Whether the token can be paused
    pub pausable: bool,
    /// Whether transfers are currently paused
    pub paused: bool,
    /// List of minter addresses
    pub minters: Vec<Address>,
    /// Creation timestamp
    pub created_at: u64,
    /// Creation block height
    pub created_at_block: u64,
}

/// SRC-20 token storage operations
pub struct TokenStore<'a> {
    db: &'a Database,
}

impl<'a> TokenStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Token operations
    // ========================================================================

    /// Store a token
    pub fn put_token(&self, token_id: &[u8; 32], data: &Src20TokenData) -> Result<()> {
        let bytes = bincode::serialize(data)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TOKENS, token_id, &bytes)
    }

    /// Get a token
    pub fn get_token(&self, token_id: &[u8; 32]) -> Result<Option<Src20TokenData>> {
        match self.db.get(cf::TOKENS, token_id)? {
            Some(bytes) => {
                let data: Src20TokenData = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Check if token exists
    pub fn token_exists(&self, token_id: &[u8; 32]) -> Result<bool> {
        self.db.contains(cf::TOKENS, token_id)
    }

    // ========================================================================
    // Balance operations
    // ========================================================================

    /// Create balance key from token_id and owner
    fn balance_key(token_id: &[u8; 32], owner: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(52);
        key.extend_from_slice(token_id);
        key.extend_from_slice(owner.as_bytes());
        key
    }

    /// Get balance for a token holder
    pub fn get_balance(&self, token_id: &[u8; 32], owner: &Address) -> Result<u128> {
        let key = Self::balance_key(token_id, owner);
        match self.db.get(cf::TOKEN_BALANCES, &key)? {
            Some(bytes) => {
                if bytes.len() != 16 {
                    return Err(StorageError::InvalidData("Invalid balance bytes".to_string()));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(u128::from_be_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Set balance for a token holder
    pub fn set_balance(&self, token_id: &[u8; 32], owner: &Address, balance: u128) -> Result<()> {
        let key = Self::balance_key(token_id, owner);
        if balance == 0 {
            // Remove from balance storage if zero
            self.db.delete(cf::TOKEN_BALANCES, &key)?;
            // Also remove from holder index
            self.remove_from_holder_index(owner, token_id)?;
        } else {
            self.db.put(cf::TOKEN_BALANCES, &key, &balance.to_be_bytes())?;
            // Add to holder index if not already there
            self.add_to_holder_index(owner, token_id)?;
        }
        Ok(())
    }

    // ========================================================================
    // Allowance operations
    // ========================================================================

    /// Create allowance key from token_id, owner, and spender
    fn allowance_key(token_id: &[u8; 32], owner: &Address, spender: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(72);
        key.extend_from_slice(token_id);
        key.extend_from_slice(owner.as_bytes());
        key.extend_from_slice(spender.as_bytes());
        key
    }

    /// Get allowance
    pub fn get_allowance(&self, token_id: &[u8; 32], owner: &Address, spender: &Address) -> Result<u128> {
        let key = Self::allowance_key(token_id, owner, spender);
        match self.db.get(cf::TOKEN_ALLOWANCES, &key)? {
            Some(bytes) => {
                if bytes.len() != 16 {
                    return Err(StorageError::InvalidData("Invalid allowance bytes".to_string()));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(u128::from_be_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Set allowance
    pub fn set_allowance(&self, token_id: &[u8; 32], owner: &Address, spender: &Address, allowance: u128) -> Result<()> {
        let key = Self::allowance_key(token_id, owner, spender);
        if allowance == 0 {
            self.db.delete(cf::TOKEN_ALLOWANCES, &key)
        } else {
            self.db.put(cf::TOKEN_ALLOWANCES, &key, &allowance.to_be_bytes())
        }
    }

    // ========================================================================
    // Holder index operations
    // ========================================================================

    /// Add token to holder's token list
    fn add_to_holder_index(&self, owner: &Address, token_id: &[u8; 32]) -> Result<()> {
        let mut tokens = self.get_holder_tokens(owner)?;
        if !tokens.iter().any(|t| t == token_id) {
            tokens.push(token_id.to_vec());
            let bytes = bincode::serialize(&tokens)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::TOKEN_HOLDER_INDEX, owner.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    /// Remove token from holder's token list
    fn remove_from_holder_index(&self, owner: &Address, token_id: &[u8; 32]) -> Result<()> {
        let mut tokens = self.get_holder_tokens(owner)?;
        tokens.retain(|t| t.as_slice() != token_id);
        if tokens.is_empty() {
            self.db.delete(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())?;
        } else {
            let bytes = bincode::serialize(&tokens)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::TOKEN_HOLDER_INDEX, owner.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    /// Get all tokens held by an address
    pub fn get_holder_tokens(&self, owner: &Address) -> Result<Vec<Vec<u8>>> {
        match self.db.get(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())? {
            Some(bytes) => {
                let tokens: Vec<Vec<u8>> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(tokens)
            }
            None => Ok(Vec::new()),
        }
    }

    // ========================================================================
    // Transfer operations
    // ========================================================================

    /// Transfer tokens between addresses
    pub fn transfer(
        &self,
        token_id: &[u8; 32],
        from: &Address,
        to: &Address,
        amount: u128,
    ) -> Result<()> {
        // Get current balances
        let from_balance = self.get_balance(token_id, from)?;
        let to_balance = self.get_balance(token_id, to)?;

        // Check sufficient balance
        if from_balance < amount {
            return Err(StorageError::InvalidData(format!(
                "Insufficient balance: have {}, need {}",
                from_balance, amount
            )));
        }

        // Update balances
        let new_from = from_balance - amount;
        let new_to = to_balance.checked_add(amount)
            .ok_or_else(|| StorageError::InvalidData("Overflow in transfer".to_string()))?;

        self.set_balance(token_id, from, new_from)?;
        self.set_balance(token_id, to, new_to)?;

        Ok(())
    }

    /// Transfer tokens using allowance
    pub fn transfer_from(
        &self,
        token_id: &[u8; 32],
        spender: &Address,
        from: &Address,
        to: &Address,
        amount: u128,
    ) -> Result<()> {
        // Check allowance
        let allowance = self.get_allowance(token_id, from, spender)?;
        if allowance < amount {
            return Err(StorageError::InvalidData(format!(
                "Insufficient allowance: have {}, need {}",
                allowance, amount
            )));
        }

        // Transfer
        self.transfer(token_id, from, to, amount)?;

        // Reduce allowance
        let new_allowance = allowance - amount;
        self.set_allowance(token_id, from, spender, new_allowance)?;

        Ok(())
    }
}

// ============================================================================
// Validator/Staking Storage
// ============================================================================

/// Validator storage operations
pub struct StakingStore<'a> {
    db: &'a Database,
}

impl<'a> StakingStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Validator operations
    // ========================================================================

    /// Store a validator by their public key
    pub fn put_validator(&self, validator: &ValidatorInfo) -> Result<()> {
        let bytes = bincode::serialize(validator)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::VALIDATORS, &validator.pubkey, &bytes)
    }

    /// Get a validator by public key
    pub fn get_validator(&self, pubkey: &[u8; 32]) -> Result<Option<ValidatorInfo>> {
        match self.db.get(cf::VALIDATORS, pubkey)? {
            Some(bytes) => {
                let validator: ValidatorInfo = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(validator))
            }
            None => Ok(None),
        }
    }

    /// Check if a validator exists
    pub fn validator_exists(&self, pubkey: &[u8; 32]) -> Result<bool> {
        self.db.contains(cf::VALIDATORS, pubkey)
    }

    /// Delete a validator
    pub fn delete_validator(&self, pubkey: &[u8; 32]) -> Result<()> {
        self.db.delete(cf::VALIDATORS, pubkey)
    }

    /// Get all validators
    pub fn get_all_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let mut validators = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::VALIDATORS, &[])? {
            let validator: ValidatorInfo = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            validators.push(validator);
        }
        Ok(validators)
    }

    /// Get all active validators (those that can participate in consensus)
    pub fn get_active_validators(&self) -> Result<Vec<ValidatorInfo>> {
        let all = self.get_all_validators()?;
        Ok(all.into_iter().filter(|v| v.status == ValidatorStatus::Active).collect())
    }

    /// Get validators sorted by stake (descending)
    pub fn get_validators_by_stake(&self) -> Result<Vec<ValidatorInfo>> {
        let mut validators = self.get_all_validators()?;
        validators.sort_by(|a, b| b.stake.cmp(&a.stake));
        Ok(validators)
    }

    /// Get total staked amount across all validators
    pub fn get_total_stake(&self) -> Result<Balance> {
        let validators = self.get_all_validators()?;
        Ok(validators.iter().map(|v| v.stake).sum())
    }

    /// Get the number of validators
    pub fn get_validator_count(&self) -> Result<usize> {
        Ok(self.get_all_validators()?.len())
    }

    /// Get the number of active validators
    pub fn get_active_validator_count(&self) -> Result<usize> {
        Ok(self.get_active_validators()?.len())
    }

    /// Update validator stake
    pub fn update_stake(&self, pubkey: &[u8; 32], new_stake: Balance) -> Result<()> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                validator.stake = new_stake;
                self.put_validator(&validator)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Update validator status
    pub fn update_status(&self, pubkey: &[u8; 32], status: ValidatorStatus) -> Result<()> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                validator.status = status;
                self.put_validator(&validator)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Jail a validator until a specific block height
    pub fn jail_validator(&self, pubkey: &[u8; 32], until_height: BlockHeight) -> Result<()> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                validator.jail(until_height);
                self.put_validator(&validator)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Unjail a validator
    pub fn unjail_validator(&self, pubkey: &[u8; 32]) -> Result<()> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                validator.unjail();
                self.put_validator(&validator)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Apply slash to a validator
    pub fn slash_validator(&self, pubkey: &[u8; 32], penalty_bps: u16) -> Result<Balance> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                let old_stake = validator.stake;
                validator.apply_slash(penalty_bps);
                let slashed_amount = old_stake - validator.stake;
                self.put_validator(&validator)?;
                Ok(slashed_amount)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Add pending rewards to a validator
    pub fn add_rewards(&self, pubkey: &[u8; 32], amount: Balance) -> Result<()> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                validator.pending_rewards = validator.pending_rewards.saturating_add(amount);
                self.put_validator(&validator)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }

    /// Claim pending rewards (returns amount claimed and resets pending_rewards to 0)
    pub fn claim_rewards(&self, pubkey: &[u8; 32]) -> Result<Balance> {
        match self.get_validator(pubkey)? {
            Some(mut validator) => {
                let rewards = validator.pending_rewards;
                validator.pending_rewards = 0;
                self.put_validator(&validator)?;
                Ok(rewards)
            }
            None => Err(StorageError::InvalidData("Validator not found".to_string())),
        }
    }
}

// ============================================================================
// Delegation Storage
// ============================================================================

/// Delegation storage operations
pub struct DelegationStore<'a> {
    db: &'a Database,
}

impl<'a> DelegationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Key generation helpers
    // ========================================================================

    /// Create delegation key from delegator address and validator pubkey
    /// Format: delegator (32 bytes) + validator_pubkey (32 bytes)
    fn delegation_key(delegator: &[u8; 32], validator_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(delegator);
        key.extend_from_slice(validator_pubkey);
        key
    }

    /// Create unbonding delegation key
    /// Format: delegator (32 bytes) + completion_height (8 bytes BE) + validator_pubkey (32 bytes)
    fn unbonding_key(delegator: &[u8; 32], completion_height: BlockHeight, validator_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(72);
        key.extend_from_slice(delegator);
        key.extend_from_slice(&completion_height.to_be_bytes());
        key.extend_from_slice(validator_pubkey);
        key
    }

    // ========================================================================
    // Delegation operations
    // ========================================================================

    /// Store a delegation
    pub fn put_delegation(&self, delegation: &DelegationInfo) -> Result<()> {
        let key = Self::delegation_key(&delegation.delegator, &delegation.validator_pubkey);
        let bytes = bincode::serialize(delegation)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DELEGATIONS, &key, &bytes)?;

        // Update validator index
        self.add_to_validator_index(&delegation.validator_pubkey, &delegation.delegator)?;

        Ok(())
    }

    /// Get a delegation
    pub fn get_delegation(&self, delegator: &[u8; 32], validator_pubkey: &[u8; 32]) -> Result<Option<DelegationInfo>> {
        let key = Self::delegation_key(delegator, validator_pubkey);
        match self.db.get(cf::DELEGATIONS, &key)? {
            Some(bytes) => {
                let delegation: DelegationInfo = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(delegation))
            }
            None => Ok(None),
        }
    }

    /// Check if delegation exists
    pub fn delegation_exists(&self, delegator: &[u8; 32], validator_pubkey: &[u8; 32]) -> Result<bool> {
        let key = Self::delegation_key(delegator, validator_pubkey);
        self.db.contains(cf::DELEGATIONS, &key)
    }

    /// Delete a delegation
    pub fn delete_delegation(&self, delegator: &[u8; 32], validator_pubkey: &[u8; 32]) -> Result<()> {
        let key = Self::delegation_key(delegator, validator_pubkey);
        self.db.delete(cf::DELEGATIONS, &key)?;

        // Update validator index
        self.remove_from_validator_index(validator_pubkey, delegator)?;

        Ok(())
    }

    /// Get all delegations for a delegator
    pub fn get_delegations_by_delegator(&self, delegator: &[u8; 32]) -> Result<Vec<DelegationInfo>> {
        let mut delegations = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::DELEGATIONS, delegator)? {
            // Only match keys that start with this delegator
            if key.len() == 64 && &key[..32] == delegator {
                let delegation: DelegationInfo = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                delegations.push(delegation);
            }
        }

        Ok(delegations)
    }

    /// Get all delegations to a validator
    pub fn get_delegations_by_validator(&self, validator_pubkey: &[u8; 32]) -> Result<Vec<DelegationInfo>> {
        let delegator_list = self.get_validator_delegators(validator_pubkey)?;
        let mut delegations = Vec::new();

        for delegator in delegator_list {
            if let Some(delegation) = self.get_delegation(&delegator, validator_pubkey)? {
                delegations.push(delegation);
            }
        }

        Ok(delegations)
    }

    /// Get total delegated amount to a validator
    pub fn get_total_delegated_to_validator(&self, validator_pubkey: &[u8; 32]) -> Result<Balance> {
        let delegations = self.get_delegations_by_validator(validator_pubkey)?;
        Ok(delegations.iter().map(|d| d.amount).sum())
    }

    /// Get total delegated amount from a delegator
    pub fn get_total_delegated_by_delegator(&self, delegator: &[u8; 32]) -> Result<Balance> {
        let delegations = self.get_delegations_by_delegator(delegator)?;
        Ok(delegations.iter().map(|d| d.amount).sum())
    }

    // ========================================================================
    // Unbonding delegation operations
    // ========================================================================

    /// Store an unbonding delegation
    pub fn put_unbonding(&self, unbonding: &UnbondingDelegation) -> Result<()> {
        let key = Self::unbonding_key(&unbonding.delegator, unbonding.completion_height, &unbonding.validator_pubkey);
        let bytes = bincode::serialize(unbonding)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::UNBONDING_DELEGATIONS, &key, &bytes)
    }

    /// Delete an unbonding delegation
    pub fn delete_unbonding(&self, delegator: &[u8; 32], completion_height: BlockHeight, validator_pubkey: &[u8; 32]) -> Result<()> {
        let key = Self::unbonding_key(delegator, completion_height, validator_pubkey);
        self.db.delete(cf::UNBONDING_DELEGATIONS, &key)
    }

    /// Get all unbonding delegations for a delegator
    pub fn get_unbondings_by_delegator(&self, delegator: &[u8; 32]) -> Result<Vec<UnbondingDelegation>> {
        let mut unbondings = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::UNBONDING_DELEGATIONS, delegator)? {
            // Only match keys that start with this delegator (72 bytes: delegator + height + validator)
            if key.len() == 72 && &key[..32] == delegator {
                let unbonding: UnbondingDelegation = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                unbondings.push(unbonding);
            }
        }

        Ok(unbondings)
    }

    /// Get completed unbonding delegations (ready to withdraw)
    pub fn get_completed_unbondings(&self, delegator: &[u8; 32], current_height: BlockHeight) -> Result<Vec<UnbondingDelegation>> {
        let unbondings = self.get_unbondings_by_delegator(delegator)?;
        Ok(unbondings.into_iter().filter(|u| u.is_complete(current_height)).collect())
    }

    /// Get completed unbondings for a specific validator
    pub fn get_completed_unbondings_for_validator(
        &self,
        delegator: &[u8; 32],
        validator_pubkey: &[u8; 32],
        current_height: BlockHeight,
    ) -> Result<Vec<UnbondingDelegation>> {
        let unbondings = self.get_unbondings_by_delegator(delegator)?;
        Ok(unbondings
            .into_iter()
            .filter(|u| u.validator_pubkey == *validator_pubkey && u.is_complete(current_height))
            .collect())
    }

    /// Get total unbonding amount for a delegator
    pub fn get_total_unbonding(&self, delegator: &[u8; 32]) -> Result<Balance> {
        let unbondings = self.get_unbondings_by_delegator(delegator)?;
        Ok(unbondings.iter().map(|u| u.amount).sum())
    }

    // ========================================================================
    // Validator index operations (validator -> list of delegators)
    // ========================================================================

    /// Add delegator to validator's index
    fn add_to_validator_index(&self, validator_pubkey: &[u8; 32], delegator: &[u8; 32]) -> Result<()> {
        let mut delegators = self.get_validator_delegators(validator_pubkey)?;

        if !delegators.iter().any(|d| d == delegator) {
            delegators.push(*delegator);
            let bytes = bincode::serialize(&delegators)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey, &bytes)?;
        }

        Ok(())
    }

    /// Remove delegator from validator's index
    fn remove_from_validator_index(&self, validator_pubkey: &[u8; 32], delegator: &[u8; 32]) -> Result<()> {
        let mut delegators = self.get_validator_delegators(validator_pubkey)?;
        delegators.retain(|d| d != delegator);

        if delegators.is_empty() {
            self.db.delete(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey)?;
        } else {
            let bytes = bincode::serialize(&delegators)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey, &bytes)?;
        }

        Ok(())
    }

    /// Get list of delegators for a validator
    pub fn get_validator_delegators(&self, validator_pubkey: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        match self.db.get(cf::DELEGATION_VALIDATOR_INDEX, validator_pubkey)? {
            Some(bytes) => {
                let delegators: Vec<[u8; 32]> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(delegators)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get number of delegators for a validator
    pub fn get_delegator_count(&self, validator_pubkey: &[u8; 32]) -> Result<usize> {
        Ok(self.get_validator_delegators(validator_pubkey)?.len())
    }

    // ========================================================================
    // Reward distribution helpers
    // ========================================================================

    /// Distribute rewards proportionally to all delegators of a validator
    /// Returns total amount distributed
    pub fn distribute_rewards(
        &self,
        validator_pubkey: &[u8; 32],
        total_rewards: Balance,
        commission_bps: u16,
    ) -> Result<Balance> {
        // Calculate validator's commission
        let validator_commission = (total_rewards * commission_bps as u128) / 10000;
        let delegator_rewards = total_rewards.saturating_sub(validator_commission);

        // Get total delegated to this validator
        let total_delegated = self.get_total_delegated_to_validator(validator_pubkey)?;

        if total_delegated == 0 {
            return Ok(0);
        }

        // Distribute proportionally to each delegator
        let delegations = self.get_delegations_by_validator(validator_pubkey)?;
        let mut distributed = 0u128;

        for delegation in delegations {
            // Calculate this delegator's share
            let share = (delegator_rewards * delegation.amount) / total_delegated;

            if share > 0 {
                // Update delegation with new rewards
                let mut updated = delegation.clone();
                updated.add_rewards(share);
                self.put_delegation(&updated)?;
                distributed += share;
            }
        }

        Ok(distributed)
    }

    /// Claim rewards for a delegation
    pub fn claim_delegation_rewards(&self, delegator: &[u8; 32], validator_pubkey: &[u8; 32]) -> Result<Balance> {
        match self.get_delegation(delegator, validator_pubkey)? {
            Some(mut delegation) => {
                let rewards = delegation.claim_rewards();
                if delegation.amount == 0 {
                    // If no stake left, remove the delegation
                    self.delete_delegation(delegator, validator_pubkey)?;
                } else {
                    self.put_delegation(&delegation)?;
                }
                Ok(rewards)
            }
            None => Err(StorageError::NotFound("Delegation not found".to_string())),
        }
    }

    // ========================================================================
    // Slash helpers
    // ========================================================================

    /// Apply slash to all delegations of a validator
    /// Returns total slashed amount
    pub fn slash_delegations(&self, validator_pubkey: &[u8; 32], penalty_bps: u16) -> Result<Balance> {
        let delegations = self.get_delegations_by_validator(validator_pubkey)?;
        let mut total_slashed = 0u128;

        for delegation in delegations {
            let old_amount = delegation.amount;
            let mut updated = delegation.clone();
            updated.apply_slash(penalty_bps);
            let slashed = old_amount.saturating_sub(updated.amount);

            if updated.amount == 0 {
                // Remove empty delegation
                self.delete_delegation(&delegation.delegator, validator_pubkey)?;
            } else {
                self.put_delegation(&updated)?;
            }

            total_slashed += slashed;
        }

        Ok(total_slashed)
    }
}

// ============================================================================
// Slashing Storage
// ============================================================================

/// Slashing storage operations
pub struct SlashingStore<'a> {
    db: &'a Database,
}

impl<'a> SlashingStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    // ========================================================================
    // Key generation helpers
    // ========================================================================

    /// Create slashing record key
    /// Format: validator_pubkey (32 bytes) + slashed_at (8 bytes BE)
    fn slashing_key(validator_pubkey: &[u8; 32], slashed_at: BlockHeight) -> Vec<u8> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(validator_pubkey);
        key.extend_from_slice(&slashed_at.to_be_bytes());
        key
    }

    // ========================================================================
    // Slashing record operations
    // ========================================================================

    /// Store a slashing record
    pub fn put_slashing_record(&self, record: &SlashingRecord) -> Result<()> {
        let key = Self::slashing_key(&record.validator_pubkey, record.slashed_at);
        let bytes = bincode::serialize(record)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::SLASHING_RECORDS, &key, &bytes)
    }

    /// Get slashing records for a validator
    pub fn get_slashing_records(&self, validator_pubkey: &[u8; 32]) -> Result<Vec<SlashingRecord>> {
        let mut records = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::SLASHING_RECORDS, validator_pubkey)? {
            if key.len() == 40 && &key[..32] == validator_pubkey {
                let record: SlashingRecord = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                records.push(record);
            }
        }

        Ok(records)
    }

    /// Get slash count for a validator
    pub fn get_slash_count(&self, validator_pubkey: &[u8; 32]) -> Result<u32> {
        let records = self.get_slashing_records(validator_pubkey)?;
        Ok(records.len() as u32)
    }

    /// Check if validator was slashed for a specific evidence type at a height
    pub fn was_slashed_at(
        &self,
        validator_pubkey: &[u8; 32],
        slashed_at: BlockHeight,
    ) -> Result<bool> {
        let key = Self::slashing_key(validator_pubkey, slashed_at);
        self.db.contains(cf::SLASHING_RECORDS, &key)
    }

    // ========================================================================
    // Validator signing info operations
    // ========================================================================

    /// Store validator signing info
    pub fn put_signing_info(&self, info: &ValidatorSigningInfo) -> Result<()> {
        let bytes = bincode::serialize(info)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::VALIDATOR_SIGNING_INFO, &info.validator_pubkey, &bytes)
    }

    /// Get validator signing info
    pub fn get_signing_info(&self, validator_pubkey: &[u8; 32]) -> Result<Option<ValidatorSigningInfo>> {
        match self.db.get(cf::VALIDATOR_SIGNING_INFO, validator_pubkey)? {
            Some(bytes) => {
                let info: ValidatorSigningInfo = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(info))
            }
            None => Ok(None),
        }
    }

    /// Get or create signing info for a validator
    pub fn get_or_create_signing_info(
        &self,
        validator_pubkey: &[u8; 32],
        current_height: BlockHeight,
    ) -> Result<ValidatorSigningInfo> {
        match self.get_signing_info(validator_pubkey)? {
            Some(info) => Ok(info),
            None => {
                let info = ValidatorSigningInfo::new(*validator_pubkey, current_height);
                self.put_signing_info(&info)?;
                Ok(info)
            }
        }
    }

    /// Delete signing info
    pub fn delete_signing_info(&self, validator_pubkey: &[u8; 32]) -> Result<()> {
        self.db.delete(cf::VALIDATOR_SIGNING_INFO, validator_pubkey)
    }

    /// Get all validators' signing info
    pub fn get_all_signing_info(&self) -> Result<Vec<ValidatorSigningInfo>> {
        let mut infos = Vec::new();

        for (_, value) in self.db.iter(cf::VALIDATOR_SIGNING_INFO)? {
            let info: ValidatorSigningInfo = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            infos.push(info);
        }

        Ok(infos)
    }

    // ========================================================================
    // Missed blocks tracking
    // ========================================================================

    /// Record a missed block for a validator
    pub fn record_missed_block(
        &self,
        validator_pubkey: &[u8; 32],
        height: BlockHeight,
    ) -> Result<()> {
        // Get current signing info
        let mut info = self.get_or_create_signing_info(validator_pubkey, height)?;
        info.increment_missed();
        self.put_signing_info(&info)?;

        // Store in missed blocks bitmap for detailed tracking
        let height_bytes = height.to_be_bytes();
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(validator_pubkey);
        key.extend_from_slice(&height_bytes);
        self.db.put(cf::MISSED_BLOCKS, &key, &[1])
    }

    /// Record a signed block for a validator (clears the missed block if any)
    pub fn record_signed_block(
        &self,
        validator_pubkey: &[u8; 32],
        height: BlockHeight,
    ) -> Result<()> {
        // Just delete from missed blocks if it exists
        let height_bytes = height.to_be_bytes();
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(validator_pubkey);
        key.extend_from_slice(&height_bytes);
        self.db.delete(cf::MISSED_BLOCKS, &key)
    }

    /// Check if a validator missed a specific block
    pub fn missed_block(&self, validator_pubkey: &[u8; 32], height: BlockHeight) -> Result<bool> {
        let height_bytes = height.to_be_bytes();
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(validator_pubkey);
        key.extend_from_slice(&height_bytes);
        self.db.contains(cf::MISSED_BLOCKS, &key)
    }

    /// Get missed block count in a range
    pub fn get_missed_block_count(
        &self,
        validator_pubkey: &[u8; 32],
        start_height: BlockHeight,
        end_height: BlockHeight,
    ) -> Result<u64> {
        let mut count = 0u64;

        for height in start_height..=end_height {
            if self.missed_block(validator_pubkey, height)? {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Clear old missed blocks (before a certain height)
    pub fn clear_old_missed_blocks(
        &self,
        validator_pubkey: &[u8; 32],
        before_height: BlockHeight,
    ) -> Result<u64> {
        let mut cleared = 0u64;

        // Iterate with prefix and delete old entries
        for (key, _) in self.db.prefix_iter(cf::MISSED_BLOCKS, validator_pubkey)? {
            if key.len() == 40 && &key[..32] == validator_pubkey {
                let height_bytes: [u8; 8] = key[32..40].try_into()
                    .map_err(|_| StorageError::InvalidData("Invalid height in key".to_string()))?;
                let height = BlockHeight::from_be_bytes(height_bytes);

                if height < before_height {
                    self.db.delete(cf::MISSED_BLOCKS, &key)?;
                    cleared += 1;
                }
            }
        }

        Ok(cleared)
    }

    // ========================================================================
    // Slashing summary helpers
    // ========================================================================

    /// Get total slashed amount for a validator
    pub fn get_total_slashed(&self, validator_pubkey: &[u8; 32]) -> Result<Balance> {
        let records = self.get_slashing_records(validator_pubkey)?;
        Ok(records.iter().map(|r| r.total_slashed()).sum())
    }

    /// Check if validator is tombstoned
    pub fn is_tombstoned(&self, validator_pubkey: &[u8; 32]) -> Result<bool> {
        match self.get_signing_info(validator_pubkey)? {
            Some(info) => Ok(info.tombstoned),
            None => Ok(false),
        }
    }

    /// Get recent slashing records (last N)
    pub fn get_recent_slashing_records(&self, limit: usize) -> Result<Vec<SlashingRecord>> {
        let mut all_records = Vec::new();

        for (_, value) in self.db.iter(cf::SLASHING_RECORDS)? {
            let record: SlashingRecord = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            all_records.push(record);
        }

        // Sort by slashed_at descending
        all_records.sort_by(|a, b| b.slashed_at.cmp(&a.slashed_at));
        all_records.truncate(limit);

        Ok(all_records)
    }
}

// ============================================================================
// Validator Set Storage
// ============================================================================

use sumchain_primitives::ValidatorSet;

/// Validator set storage operations (for epoch-based validator management)
pub struct ValidatorSetStore<'a> {
    db: &'a Database,
}

impl<'a> ValidatorSetStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a validator set for an epoch
    pub fn put_validator_set(&self, validator_set: &ValidatorSet) -> Result<()> {
        let key = validator_set.epoch.to_be_bytes();
        let bytes = bincode::serialize(validator_set)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::VALIDATOR_SETS, &key, &bytes)
    }

    /// Get the validator set for a specific epoch
    pub fn get_validator_set(&self, epoch: u64) -> Result<Option<ValidatorSet>> {
        let key = epoch.to_be_bytes();
        match self.db.get(cf::VALIDATOR_SETS, &key)? {
            Some(bytes) => {
                let set: ValidatorSet = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(set))
            }
            None => Ok(None),
        }
    }

    /// Get the current (latest) validator set
    pub fn get_current_validator_set(&self) -> Result<Option<ValidatorSet>> {
        let mut latest: Option<ValidatorSet> = None;

        for (_, value) in self.db.iter(cf::VALIDATOR_SETS)? {
            let set: ValidatorSet = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if latest.is_none() || set.epoch > latest.as_ref().unwrap().epoch {
                latest = Some(set);
            }
        }

        Ok(latest)
    }

    /// Get the validator set for a given block height
    pub fn get_validator_set_for_height(
        &self,
        height: BlockHeight,
        epoch_length: BlockHeight,
    ) -> Result<Option<ValidatorSet>> {
        if epoch_length == 0 {
            return self.get_current_validator_set();
        }
        let epoch = height / epoch_length;
        self.get_validator_set(epoch)
    }

    /// Delete a validator set (for pruning old epochs)
    pub fn delete_validator_set(&self, epoch: u64) -> Result<()> {
        let key = epoch.to_be_bytes();
        self.db.delete(cf::VALIDATOR_SETS, &key)
    }

    /// Get all validator sets
    pub fn get_all_validator_sets(&self) -> Result<Vec<ValidatorSet>> {
        let mut sets = Vec::new();

        for (_, value) in self.db.iter(cf::VALIDATOR_SETS)? {
            let set: ValidatorSet = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            sets.push(set);
        }

        // Sort by epoch ascending
        sets.sort_by(|a, b| a.epoch.cmp(&b.epoch));

        Ok(sets)
    }

    /// Prune old validator sets, keeping only the latest N epochs
    pub fn prune_old_sets(&self, keep_epochs: u64) -> Result<u64> {
        let sets = self.get_all_validator_sets()?;
        if sets.len() <= keep_epochs as usize {
            return Ok(0);
        }

        let mut pruned = 0;
        let cutoff = sets.len() - keep_epochs as usize;
        for set in sets.iter().take(cutoff) {
            self.delete_validator_set(set.epoch)?;
            pruned += 1;
        }

        Ok(pruned)
    }
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
