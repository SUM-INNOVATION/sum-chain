//! Storage Metadata Executor
//!
//! Manages on-chain metadata for files stored in the decentralized storage layer,
//! and implements the Proof-of-Retrievability (PoR) engine:
//!
//! - File registration with fee pools and native ACLs
//! - Deterministic challenge generation (called from execute_block)
//! - Merkle proof verification and reward settlement
//! - Challenge expiry tracking for slashing
//!
//! **Atomicity guarantee:** all balance mutations and state writes happen as
//! in-memory operations within `execute_block()`. If any write fails the entire
//! block's state changes are rolled back.

use std::sync::Arc;

use sumchain_primitives::{
    Address, Balance, Hash, StorageChallenge, StorageMetadata, StorageMetadataOperation,
    StorageMetadataTxData, CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS, CHUNK_SIZE,
};
use sumchain_storage::Database;
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

// ─── Column Family Names ─────────────────────────────────────────────────────

pub const CF_STORAGE_METADATA: &str = "storage_metadata";
pub const CF_ACTIVE_CHALLENGES: &str = "active_challenges";

// ─── Key Helpers ─────────────────────────────────────────────────────────────

// -- StorageMetadata keys --

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

// -- Challenge keys --

fn challenge_key(challenge_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b'C');
    key.extend_from_slice(challenge_id.as_bytes());
    key
}

fn challenge_node_index_key(target_node: &Address, challenge_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(53);
    key.push(b'N');
    key.extend_from_slice(target_node.as_bytes());
    key.extend_from_slice(challenge_id.as_bytes());
    key
}

fn challenge_expiry_index_key(expires_at_height: u64, challenge_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.push(b'E');
    key.extend_from_slice(&expires_at_height.to_be_bytes());
    key.extend_from_slice(challenge_id.as_bytes());
    key
}

// ─── Merkle Proof Verification ───────────────────────────────────────────────

/// Verify a binary Merkle proof.
///
/// Given a leaf hash (`chunk_hash`) at position `chunk_index`, walk the
/// `merkle_path` (sibling hashes, bottom-up) to reconstruct the root.
/// The bit at each level of `chunk_index` determines left/right ordering.
///
/// Returns `true` if the computed root matches `expected_root`.
pub fn verify_merkle_proof(
    chunk_hash: &Hash,
    chunk_index: u32,
    merkle_path: &[Hash],
    expected_root: &Hash,
) -> bool {
    let mut current = *chunk_hash;

    for (level, sibling) in merkle_path.iter().enumerate() {
        let mut data = Vec::with_capacity(64);

        // Bit at this level determines if we're a left or right child
        if (chunk_index >> level) & 1 == 0 {
            // We are left child: H(current || sibling)
            data.extend_from_slice(current.as_bytes());
            data.extend_from_slice(sibling.as_bytes());
        } else {
            // We are right child: H(sibling || current)
            data.extend_from_slice(sibling.as_bytes());
            data.extend_from_slice(current.as_bytes());
        }

        current = Hash::hash(&data);
    }

    current == *expected_root
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

    // =========================================================================
    // Transaction Dispatcher
    // =========================================================================

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
            StorageMetadataOperation::SubmitStorageProof {
                challenge_id,
                merkle_root,
                chunk_index,
                chunk_hash,
                merkle_path,
            } => self.execute_submit_proof(
                sender, challenge_id, merkle_root, *chunk_index, chunk_hash, merkle_path,
                state, block_height,
            ),
        }
    }

    // =========================================================================
    // File Operations (Phase 1)
    // =========================================================================

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

        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(amount as u128);
        state.put_account(sender, &sender_account)?;

        meta.fee_pool = meta.fee_pool.saturating_add(amount);
        self.put_metadata(&meta)?;

        debug!("Fee pool topped up by {} for {}", amount, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    // =========================================================================
    // Objective 4: SubmitStorageProof — Cryptographic Verification & Settlement
    // =========================================================================

    fn execute_submit_proof(
        &self,
        sender: &Address,
        challenge_id: &Hash,
        merkle_root: &Hash,
        chunk_index: u32,
        chunk_hash: &Hash,
        merkle_path: &[Hash],
        state: &StateManager,
        current_height: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        // 1. Load challenge
        let challenge = match self.get_challenge(challenge_id)? {
            Some(c) => c,
            None => return Ok(StorageMetadataExecutionResult::fail("Challenge does not exist")),
        };

        // 2. Verify sender is the challenged node
        if challenge.target_node != *sender {
            return Ok(StorageMetadataExecutionResult::fail(
                "Only the challenged node can submit proof",
            ));
        }

        // 3. Verify not expired
        if current_height > challenge.expires_at_height {
            return Ok(StorageMetadataExecutionResult::fail("Challenge has expired"));
        }

        // 4. Verify merkle_root and chunk_index match
        if challenge.merkle_root != *merkle_root {
            return Ok(StorageMetadataExecutionResult::fail("merkle_root does not match challenge"));
        }
        if challenge.chunk_index != chunk_index {
            return Ok(StorageMetadataExecutionResult::fail("chunk_index does not match challenge"));
        }

        // 5. Load file metadata to verify path length and root
        let mut meta = match self.get_metadata(merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail(
                "File metadata not found for merkle_root",
            )),
        };

        // 6. Validate merkle_path length
        let chunk_count = (meta.total_size_bytes + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let expected_depth = if chunk_count <= 1 {
            0
        } else {
            // ceil(log2(chunk_count))
            64 - (chunk_count - 1).leading_zeros() as usize
        };

        if merkle_path.len() != expected_depth {
            return Ok(StorageMetadataExecutionResult::fail(format!(
                "Invalid merkle_path length: expected {} levels for {} chunks, got {}",
                expected_depth, chunk_count, merkle_path.len()
            )));
        }

        // 7. Cryptographic Merkle proof verification
        if expected_depth == 0 {
            // Single-chunk file: chunk_hash must equal merkle_root directly
            if *chunk_hash != *merkle_root {
                return Ok(StorageMetadataExecutionResult::fail(
                    "Merkle proof verification failed: single-chunk hash mismatch",
                ));
            }
        } else if !verify_merkle_proof(chunk_hash, chunk_index, merkle_path, merkle_root) {
            return Ok(StorageMetadataExecutionResult::fail(
                "Merkle proof verification failed: computed root does not match",
            ));
        }

        // 8. Settlement: pay reward from fee_pool to target_node
        let payout = if meta.fee_pool >= CHALLENGE_REWARD {
            CHALLENGE_REWARD
        } else {
            meta.fee_pool // Partial payout if pool is low
        };

        if payout > 0 {
            meta.fee_pool = meta.fee_pool.saturating_sub(payout);
            self.put_metadata(&meta)?;

            let mut node_account = state.get_account(&challenge.target_node)?;
            node_account.balance = node_account.balance.saturating_add(payout as u128);
            state.put_account(&challenge.target_node, &node_account)?;
        }

        // 9. Delete the challenge from state
        self.delete_challenge(&challenge)?;

        info!(
            "Storage proof verified: challenge={}, node={}, file={}, chunk={}, payout={}",
            challenge_id, sender, merkle_root, chunk_index, payout
        );

        Ok(StorageMetadataExecutionResult::ok())
    }

    // =========================================================================
    // Objective 2: Deterministic Challenge Generation (called from execute_block)
    // =========================================================================

    /// Generate a deterministic storage challenge using the parent block hash
    /// as a random seed. Called from `execute_block()` when `height % INTERVAL == 0`.
    ///
    /// Returns `Ok(Some(challenge))` if a challenge was created, `Ok(None)` if
    /// no eligible files or nodes exist.
    pub fn generate_challenge(
        &self,
        parent_hash: &Hash,
        height: u64,
        archive_nodes: &[sumchain_primitives::NodeRecord],
    ) -> Result<Option<StorageChallenge>> {
        // Filter to active nodes only (caller should pre-filter, but be safe)
        let active_nodes: Vec<_> = archive_nodes
            .iter()
            .filter(|n| n.status == sumchain_primitives::NodeStatus::Active)
            .collect();

        if active_nodes.is_empty() {
            debug!("No active ArchiveNodes — skipping challenge at height {}", height);
            return Ok(None);
        }

        // Get all files with non-zero fee_pool
        let eligible_roots = self.get_funded_file_roots()?;
        if eligible_roots.is_empty() {
            debug!("No funded files — skipping challenge at height {}", height);
            return Ok(None);
        }

        // Deterministic seed from parent hash
        let seed = Hash::hash_many(&[
            parent_hash.as_bytes(),
            b"storage_challenge",
            &height.to_be_bytes(),
        ]);
        let seed_bytes = seed.as_bytes();

        // Select file
        let file_index = u64::from_be_bytes([
            seed_bytes[0], seed_bytes[1], seed_bytes[2], seed_bytes[3],
            seed_bytes[4], seed_bytes[5], seed_bytes[6], seed_bytes[7],
        ]) % eligible_roots.len() as u64;
        let selected_root = &eligible_roots[file_index as usize];

        // Load file metadata for chunk count
        let meta = match self.get_metadata(selected_root)? {
            Some(m) => m,
            None => return Ok(None), // Should not happen, but be safe
        };

        let chunk_count = (meta.total_size_bytes + CHUNK_SIZE - 1) / CHUNK_SIZE;
        if chunk_count == 0 {
            return Ok(None);
        }

        // Select chunk
        let chunk_index = u32::from_be_bytes([
            seed_bytes[8], seed_bytes[9], seed_bytes[10], seed_bytes[11],
        ]) % chunk_count as u32;

        // Select target node
        let node_index = u64::from_be_bytes([
            seed_bytes[12], seed_bytes[13], seed_bytes[14], seed_bytes[15],
            seed_bytes[16], seed_bytes[17], seed_bytes[18], seed_bytes[19],
        ]) % active_nodes.len() as u64;
        let target_node = active_nodes[node_index as usize].address;

        // Compute deterministic challenge ID
        let challenge_id = Hash::hash_many(&[
            selected_root.as_bytes(),
            &chunk_index.to_be_bytes(),
            &height.to_be_bytes(),
        ]);

        let challenge = StorageChallenge {
            challenge_id,
            merkle_root: *selected_root,
            chunk_index,
            target_node,
            created_at_height: height,
            expires_at_height: height + CHALLENGE_TTL_BLOCKS,
        };

        self.put_challenge(&challenge)?;

        info!(
            "Storage challenge issued: id={}, file={}, chunk={}, node={}, expires={}",
            challenge_id, selected_root, chunk_index, target_node,
            height + CHALLENGE_TTL_BLOCKS
        );

        Ok(Some(challenge))
    }

    // =========================================================================
    // Objective 5: Expired Challenge Detection (called from execute_block)
    // =========================================================================

    /// Find all challenges that have expired by `current_height`.
    /// Scans the expiry index (E prefix, height in BE) for all entries
    /// where `expires_at_height <= current_height`.
    pub fn get_expired_challenges(&self, current_height: u64) -> Result<Vec<StorageChallenge>> {
        // Scan from E+0x0000000000000000 through E+current_height
        // The expiry index key is: [b'E', expires_at_height(8 BE), challenge_id(32)]
        let prefix = vec![b'E'];
        let mut expired = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_ACTIVE_CHALLENGES, &prefix)
            .map_err(|e| StateError::Storage(e))?
            .collect();

        for (key, _) in entries {
            // key = [b'E', 8 bytes height, 32 bytes challenge_id]
            if key.len() < 41 {
                continue;
            }

            let expires_at = u64::from_be_bytes([
                key[1], key[2], key[3], key[4],
                key[5], key[6], key[7], key[8],
            ]);

            if expires_at > current_height {
                // Since keys are BE-sorted, once we hit a height > current,
                // all remaining entries are also unexpired. Stop scanning.
                break;
            }

            let challenge_id = Hash::from_slice(&key[9..41])
                .map_err(|e| StateError::DeserializationError(e.to_string()))?;

            if let Some(challenge) = self.get_challenge(&challenge_id)? {
                expired.push(challenge);
            }
        }

        Ok(expired)
    }

    // =========================================================================
    // StorageMetadata CRUD
    // =========================================================================

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

    /// Get sorted merkle roots of all files with fee_pool > 0.
    /// Used by challenge generation to select eligible files.
    pub fn get_funded_file_roots(&self) -> Result<Vec<Hash>> {
        let prefix = vec![b'F'];
        let mut roots = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_STORAGE_METADATA, &prefix)
            .map_err(|e| StateError::Storage(e))?
            .collect();

        for (key, value) in entries {
            if key.len() >= 33 {
                let meta: StorageMetadata = bincode::deserialize(&value)
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                if meta.fee_pool > 0 {
                    roots.push(meta.merkle_root);
                }
            }
        }

        // Sort for deterministic ordering across all nodes
        roots.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(roots)
    }

    // =========================================================================
    // Challenge CRUD
    // =========================================================================

    /// Get all active challenges assigned to a specific node.
    /// Scans the N (node) prefix index: key = [b'N', target_node(20), challenge_id(32)]
    pub fn get_challenges_by_node(&self, target_node: &Address) -> Result<Vec<StorageChallenge>> {
        let mut prefix = Vec::with_capacity(21);
        prefix.push(b'N');
        prefix.extend_from_slice(target_node.as_bytes());

        let mut challenges = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_ACTIVE_CHALLENGES, &prefix)
            .map_err(|e| StateError::Storage(e))?
            .collect();

        for (key, _) in entries {
            // key = [b'N'(1), target_node(20), challenge_id(32)] = 53 bytes
            if key.len() < 53 {
                continue; // Malformed key — skip safely
            }

            let challenge_id = Hash::from_slice(&key[21..53])
                .map_err(|e| StateError::DeserializationError(e.to_string()))?;

            if let Some(challenge) = self.get_challenge(&challenge_id)? {
                challenges.push(challenge);
            }
        }

        Ok(challenges)
    }

    pub fn put_challenge(&self, challenge: &StorageChallenge) -> Result<()> {
        let value = bincode::serialize(challenge)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;

        // Primary key: C + challenge_id
        let pk = challenge_key(&challenge.challenge_id);
        self.db.put(CF_ACTIVE_CHALLENGES, &pk, &value)
            .map_err(|e| StateError::Storage(e))?;

        // Node index: N + target_node + challenge_id
        let nk = challenge_node_index_key(&challenge.target_node, &challenge.challenge_id);
        self.db.put(CF_ACTIVE_CHALLENGES, &nk, &[1])
            .map_err(|e| StateError::Storage(e))?;

        // Expiry index: E + expires_at_height(BE) + challenge_id
        let ek = challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id);
        self.db.put(CF_ACTIVE_CHALLENGES, &ek, &[1])
            .map_err(|e| StateError::Storage(e))?;

        Ok(())
    }

    pub fn get_challenge(&self, challenge_id: &Hash) -> Result<Option<StorageChallenge>> {
        let pk = challenge_key(challenge_id);
        match self.db.get(CF_ACTIVE_CHALLENGES, &pk) {
            Ok(Some(data)) => {
                let challenge: StorageChallenge = bincode::deserialize(&data)
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                Ok(Some(challenge))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    pub fn delete_challenge(&self, challenge: &StorageChallenge) -> Result<()> {
        // Delete all 3 keys
        let pk = challenge_key(&challenge.challenge_id);
        self.db.delete(CF_ACTIVE_CHALLENGES, &pk)
            .map_err(|e| StateError::Storage(e))?;

        let nk = challenge_node_index_key(&challenge.target_node, &challenge.challenge_id);
        self.db.delete(CF_ACTIVE_CHALLENGES, &nk)
            .map_err(|e| StateError::Storage(e))?;

        let ek = challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id);
        self.db.delete(CF_ACTIVE_CHALLENGES, &ek)
            .map_err(|e| StateError::Storage(e))?;

        Ok(())
    }
}
