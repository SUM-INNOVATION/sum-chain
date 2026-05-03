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
    assigned_archives, is_archive_assigned_to_chunk, AccessEntryV2, Address, Balance,
    FileLifecycleV2, FileVisibilityV2, Hash, NodeRecord, NodeStatus, StorageChallenge,
    StorageMetadata, StorageMetadataOperation, StorageMetadataOperationV2, StorageMetadataTxData,
    StorageMetadataV2, StorageMetadataV2TxData, CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS, CHUNK_SIZE,
};
use sumchain_storage::Database;
use sumchain_genesis::ChainParams;
use tracing::{debug, info, warn};

use crate::node_registry::NodeRegistryExecutor;
use crate::{Result, StateError, StateManager};

// ─── Column Family Names ─────────────────────────────────────────────────────

pub const CF_STORAGE_METADATA: &str = "storage_metadata";
pub const CF_ACTIVE_CHALLENGES: &str = "active_challenges";
/// V2 storage metadata column family. Coexists with V1 — entries keyed by
/// `[b'F', b'2', merkle_root]` so the prefix never overlaps V1 `[b'F', root]`.
pub const CF_STORAGE_METADATA_V2: &str = "storage_metadata_v2";
/// V2 per-(file, archive) AcceptAssignmentV2 bitmap CF. Plan v3.2 §3.6.
pub const CF_ASSIGNMENT_ATTESTATIONS_V2: &str = "assignment_attestations_v2";

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

// -- V2 metadata keys --

/// V2 file row key: `[b'F', b'2', merkle_root_32]`. The leading `b'F'`
/// matches V1's prefix, but the second byte `b'2'` (value 0x32) keeps the
/// keyspaces from colliding because no V1 `merkle_root` byte 0 will ever
/// equal `b'2'` by accident — V1 hashes are 32 bytes uniformly distributed,
/// V2 prepends the literal version tag.
fn metadata_v2_key(merkle_root: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(34);
    key.push(b'F');
    key.push(b'2');
    key.extend_from_slice(merkle_root.as_bytes());
    key
}

/// V2 owner index: `[b'O', b'2', owner_20, merkle_root_32]`. Same rationale.
fn owner_v2_index_key(owner: &Address, merkle_root: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(54);
    key.push(b'O');
    key.push(b'2');
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(merkle_root.as_bytes());
    key
}

/// AcceptAssignmentV2 bitmap key: `[b'A', merkle_root_32, archive_address_20]` (53 bytes).
fn attestation_v2_key(merkle_root: &Hash, archive: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(53);
    key.push(b'A');
    key.extend_from_slice(merkle_root.as_bytes());
    key.extend_from_slice(archive.as_bytes());
    key
}

/// Prefix-scan key for "all attestations for this file": `[b'A', merkle_root_32]`.
fn attestation_v2_file_prefix(merkle_root: &Hash) -> Vec<u8> {
    let mut p = Vec::with_capacity(33);
    p.push(b'A');
    p.extend_from_slice(merkle_root.as_bytes());
    p
}

// ─── Bitmap helpers (Plan v3.2 §3.6) ──────────────────────────────────────────

/// Compute the byte length of the bitmap for `chunk_count` chunks: `ceil(N/8)`.
/// Returns 0 only if `chunk_count == 0` (excluded by `RegisterFilePendingV2`
/// validity, but defensive for callers).
#[inline]
fn bitmap_byte_len(chunk_count: u32) -> usize {
    ((chunk_count as usize) + 7) / 8
}

/// Set the bit at `idx` in `bitmap`. Caller must have ensured `idx < chunk_count`
/// AND `bitmap.len() == bitmap_byte_len(chunk_count)`.
#[inline]
fn bitmap_set(bitmap: &mut [u8], idx: u32) {
    bitmap[(idx / 8) as usize] |= 1 << (idx % 8);
}

/// Read the bit at `idx`.
#[inline]
fn bitmap_get(bitmap: &[u8], idx: u32) -> bool {
    let byte = bitmap[(idx / 8) as usize];
    (byte >> (idx % 8)) & 1 == 1
}

/// Bitwise OR `src` into `dst` (in place). Both must be the same length.
#[inline]
fn bitmap_or_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len(), "bitmap length mismatch");
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d |= *s;
    }
}

/// Total number of 1-bits in the bitmap.
#[inline]
fn bitmap_popcount(bitmap: &[u8]) -> u32 {
    bitmap.iter().map(|b| b.count_ones()).sum()
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

/// Validate one `AccessEntryV2` against the file's visibility (Plan §3.5):
/// Public requires `encrypted_key_bundle == None`; Private requires
/// `Some(bundle)` AND a registered X25519 pubkey for the entry's address.
/// Returns `Ok(Err(reason))` for an executor-level rejection (we wrap into
/// `Failed(35)` at the call site), `Ok(Ok(()))` on success, `Err(state error)`
/// on infrastructure failure (DB read).
fn check_access_entry_for_visibility(
    visibility: FileVisibilityV2,
    entry: &AccessEntryV2,
    node_registry: &NodeRegistryExecutor,
) -> Result<std::result::Result<(), String>> {
    match visibility {
        FileVisibilityV2::Public => {
            if entry.encrypted_key_bundle.is_some() {
                return Ok(Err(
                    "Public file: entry must not carry an encrypted_key_bundle".into(),
                ));
            }
        }
        FileVisibilityV2::Private => {
            if entry.encrypted_key_bundle.is_none() {
                return Ok(Err(
                    "Private file: entry must carry an encrypted_key_bundle".into(),
                ));
            }
            if node_registry.get_encryption_pubkey(&entry.address)?.is_none() {
                return Ok(Err(
                    "Private file: recipient lacks a registered X25519 pubkey".into(),
                ));
            }
        }
    }
    Ok(Ok(()))
}

/// Re-check the access-list bincode byte-cap (plan §3.4) against
/// `max_access_list_bytes`. Returns `Some(reason)` if violated, `None` if OK.
fn access_list_byte_cap_violated(
    list: &[AccessEntryV2],
    max_bytes: u64,
) -> Result<Option<String>> {
    let bytes = bincode::serialize(&list.to_vec())
        .map_err(|e| StateError::SerializationError(e.to_string()))?;
    if bytes.len() as u64 > max_bytes {
        Ok(Some(format!(
            "access list exceeds max_access_list_bytes ({} > {})",
            bytes.len(),
            max_bytes
        )))
    } else {
        Ok(None)
    }
}

/// True iff this archive is currently `Active` per its node-registry record.
/// Used by `ActivateFileV2` and the coverage RPC to exclude
/// post-attestation-Slashed archives from coverage.
fn is_currently_active(
    node_registry: &NodeRegistryExecutor,
    archive: &Address,
) -> Result<bool> {
    Ok(matches!(
        node_registry.get_node(archive)?,
        Some(rec) if rec.status == NodeStatus::Active
    ))
}

/// Per-archive entry computed by `compute_coverage_v2`. `assigned_count` is
/// `Some(n)` when the chunk-count is small enough that the chain computed the
/// per-archive count, else `None` — clients with very large files can compute
/// it locally using the deterministic `assigned_archives_presorted` function.
#[derive(Debug, Clone)]
pub struct ArchivePerEntry {
    pub archive: Address,
    pub attested_count: u32,
    pub currently_active: bool,
    /// `Some(n)` when chunk_count <= [`MAX_ASSIGNED_COUNT_CHUNK_COUNT`]; else `None`.
    pub assigned_count: Option<u32>,
}

/// Hard cap on `chunk_count` for which the coverage RPC will compute the
/// per-archive `assigned_count`. Bounds the worst-case work an RPC client
/// can trigger to roughly:
///   `chunk_count × archive_count × O(BLAKE3 derive_key + log archive_count)`
///
/// At `chunk_count = 16_384`, archive_count = 100 this is ~1.6M BLAKE3 calls
/// × ~100ns = ~160ms — well-bounded for an RPC. Above this cap the RPC
/// returns `assigned_count = None` and clients compute it locally with the
/// deterministic [`assigned_archives_presorted`] function.
pub const MAX_ASSIGNED_COUNT_CHUNK_COUNT: u32 = 16_384;

/// Coverage summary for `storage_getAssignmentCoverageV2`. RPC-side combines
/// this with `assigned_archives` per chunk to produce the wire response.
#[derive(Debug, Clone)]
pub struct CoverageSummaryV2 {
    pub chunk_count: u32,
    pub covered_count: u32,
    pub lifecycle: FileLifecycleV2,
    pub assignment_height: u64,
    pub replication_factor: u32,
    /// OR of all snapshot-active archives' bitmaps. Used by the RPC to
    /// compute `missing_indices`.
    pub union: Vec<u8>,
    pub per_archive: Vec<ArchivePerEntry>,
}

/// Result type for V2 storage operations. Carries an optional `failure_code`
/// so the dispatch layer can surface specific receipt codes (per plan §3.7
/// + checkpoint 1a allocations: 21 generic, 30 RegisterPending, 31 Abandon,
/// 32 not-yet-implemented; 33 AcceptAssignmentV2, 34 ActivateFileV2 for 1b).
#[derive(Debug)]
pub struct StorageMetadataV2ExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub failure_code: Option<u32>,
}

impl StorageMetadataV2ExecutionResult {
    fn ok() -> Self {
        Self { success: true, error: None, failure_code: None }
    }
    #[allow(dead_code)]
    fn fail(msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), failure_code: None }
    }
    fn fail_with_code(code: u32, msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), failure_code: Some(code) }
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

    // =========================================================================
    // V2 Transaction Dispatcher (SNIP V2 Phase 1, checkpoint 1a)
    //
    // 1a implements `RegisterFilePendingV2` + `AbandonFileV2`. The other
    // variants are present in the primitive enum and routed here, but their
    // executor branches return `Failed` until 1b/1c land.
    // =========================================================================

    /// Result type carries an optional failure code so the dispatch layer can
    /// surface specific reason strings via [`sumchain_primitives::TxStatus`].
    /// Codes are assigned per plan v3.1 §3.7:
    /// * 21 — generic V2 StorageMetadata op failed
    /// * 30 — `RegisterFilePendingV2` validity failure (visibility/bundle/cap)
    /// * 31 — `AbandonFileV2` validity failure (state/owner/grace)
    /// * 32 — V2 op not yet implemented in this checkpoint
    pub fn execute_v2(
        &self,
        sender: &Address,
        data: &StorageMetadataV2TxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        // Fee is deducted up-front so failed validity checks still pay the fee.
        // This matches V1 behavior (deduct_fee, then execute branch).
        self.deduct_fee(state, sender, fee, proposer)?;

        match &data.operation {
            StorageMetadataOperationV2::RegisterFilePendingV2 {
                merkle_root,
                plaintext_size_bytes,
                stored_size_bytes,
                chunk_count,
                fee_deposit,
                visibility,
                initial_access,
            } => self.execute_register_file_pending_v2(
                sender,
                merkle_root,
                *plaintext_size_bytes,
                *stored_size_bytes,
                *chunk_count,
                *fee_deposit,
                *visibility,
                initial_access,
                state,
                block_height,
                chain_params,
                node_registry,
            ),
            StorageMetadataOperationV2::AbandonFileV2 { merkle_root } => self
                .execute_abandon_file_v2(
                    sender,
                    merkle_root,
                    state,
                    block_height,
                    chain_params,
                ),
            StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root,
                chunk_indices,
            } => self.execute_accept_assignment_v2(
                sender,
                merkle_root,
                chunk_indices,
                chain_params,
                node_registry,
            ),
            StorageMetadataOperationV2::ActivateFileV2 { merkle_root } => self
                .execute_activate_file_v2(
                    sender,
                    merkle_root,
                    block_height,
                    chain_params,
                    node_registry,
                ),
            StorageMetadataOperationV2::AddAccessV2 { merkle_root, entry } => self
                .execute_add_access_v2(
                    sender,
                    merkle_root,
                    entry,
                    chain_params,
                    node_registry,
                ),
            StorageMetadataOperationV2::RemoveAccessV2 {
                merkle_root,
                address,
            } => self.execute_remove_access_v2(sender, merkle_root, address),
            StorageMetadataOperationV2::UpdateAccessV2 {
                merkle_root,
                address,
                new_entry,
            } => self.execute_update_access_v2(
                sender,
                merkle_root,
                address,
                new_entry,
                chain_params,
                node_registry,
            ),
        }
    }

    /// Plan v3.2 §3.5 AddAccessV2 — append one access entry to an Active file.
    /// Receipt code: 35.
    fn execute_add_access_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        entry: &AccessEntryV2,
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    35,
                    "AddAccessV2: file not found",
                ));
            }
        };
        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "AddAccessV2: only the owner can mutate the access list",
            ));
        }
        if row.lifecycle != FileLifecycleV2::Active {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "AddAccessV2: file must be Active",
            ));
        }
        // Don't allow duplicate addresses — predictable semantics; clients use
        // UpdateAccessV2 to mutate an existing entry.
        if row.access_list.iter().any(|e| e.address == entry.address) {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "AddAccessV2: address already in access list (use UpdateAccessV2)",
            ));
        }
        // Visibility-bundle invariant + Private recipient X25519 check.
        if let Err(reason) =
            check_access_entry_for_visibility(row.visibility, entry, node_registry)?
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(35, reason));
        }
        // Re-enforce byte-cap with the new entry appended.
        let mut next = row.access_list.clone();
        next.push(entry.clone());
        if let Some(reason) =
            access_list_byte_cap_violated(&next, chain_params.max_access_list_bytes)?
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(35, reason));
        }
        row.access_list = next;
        self.put_metadata_v2(&row)?;

        info!(
            "AddAccessV2: file={}, recipient={}",
            merkle_root, entry.address
        );
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.5 RemoveAccessV2 — drop one access entry from an Active file.
    fn execute_remove_access_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    35,
                    "RemoveAccessV2: file not found",
                ));
            }
        };
        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "RemoveAccessV2: only the owner can mutate the access list",
            ));
        }
        if row.lifecycle != FileLifecycleV2::Active {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "RemoveAccessV2: file must be Active",
            ));
        }
        // For Private files, removing the owner would orphan the file's bundles
        // (no party left who can decrypt). Reject as a guardrail — owner can
        // abandon if they really want the file gone.
        if row.visibility == FileVisibilityV2::Private && address.as_bytes() == sender.as_bytes() {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "RemoveAccessV2: cannot remove the owner from a Private file's access list",
            ));
        }
        let len_before = row.access_list.len();
        row.access_list.retain(|e| e.address != *address);
        if row.access_list.len() == len_before {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "RemoveAccessV2: address not in access list",
            ));
        }
        self.put_metadata_v2(&row)?;

        info!("RemoveAccessV2: file={}, removed={}", merkle_root, address);
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.5 UpdateAccessV2 — replace one access entry's bundle/expiry
    /// (rotation). The `new_entry.address` MUST equal the `address` argument
    /// (the entry whose key is rotated); we don't allow a single tx to also
    /// migrate the entry to a different address.
    fn execute_update_access_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
        new_entry: &AccessEntryV2,
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    35,
                    "UpdateAccessV2: file not found",
                ));
            }
        };
        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "UpdateAccessV2: only the owner can mutate the access list",
            ));
        }
        if row.lifecycle != FileLifecycleV2::Active {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "UpdateAccessV2: file must be Active",
            ));
        }
        if new_entry.address != *address {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                35,
                "UpdateAccessV2: new_entry.address must equal the target address",
            ));
        }
        if let Err(reason) =
            check_access_entry_for_visibility(row.visibility, new_entry, node_registry)?
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(35, reason));
        }
        // Find and replace; reject if address is absent.
        let pos = match row.access_list.iter().position(|e| e.address == *address) {
            Some(i) => i,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    35,
                    "UpdateAccessV2: address not in access list",
                ));
            }
        };
        let mut next = row.access_list.clone();
        next[pos] = new_entry.clone();
        if let Some(reason) =
            access_list_byte_cap_violated(&next, chain_params.max_access_list_bytes)?
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(35, reason));
        }
        row.access_list = next;
        self.put_metadata_v2(&row)?;

        info!("UpdateAccessV2: file={}, entry={}", merkle_root, address);
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.6 AcceptAssignmentV2 — OR the supplied `chunk_indices` into
    /// the per-(file, archive) bitmap. Receipt code allocations:
    /// * 33 — AcceptAssignmentV2 validity failure.
    fn execute_accept_assignment_v2(
        &self,
        signer: &Address,
        merkle_root: &Hash,
        chunk_indices: &[u32],
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        // 1. File must exist and be Pending. Pending-only ensures bitmaps stop
        // accumulating once activated — no post-activation re-attestation surface.
        let row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    33,
                    "AcceptAssignmentV2: file not found",
                ));
            }
        };
        if row.lifecycle != FileLifecycleV2::Pending {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: file must be Pending",
            ));
        }

        // 2. Per-tx cap. Enforced before snapshot lookup so a degenerate
        // payload doesn't trigger a database read.
        if chunk_indices.len() as u64 > chain_params.max_chunk_indices_per_tx as u64 {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                format!(
                    "AcceptAssignmentV2: chunk_indices.len() exceeds max_chunk_indices_per_tx ({} > {})",
                    chunk_indices.len(),
                    chain_params.max_chunk_indices_per_tx
                ),
            ));
        }

        // 3. Resolve the snapshot at the file's assignment_height.
        // Signer must be in the snapshot AND currently Active.
        let snapshot = node_registry
            .get_active_archive_nodes_at_height(row.assignment_height)?;
        if !snapshot
            .iter()
            .any(|n| n.address.as_bytes() == signer.as_bytes())
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: signer not in file's assignment snapshot",
            ));
        }
        let signer_currently_active = match node_registry.get_node(signer)? {
            Some(rec) => rec.status == NodeStatus::Active,
            None => false,
        };
        if !signer_currently_active {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: signer is not currently Active",
            ));
        }

        // 4. Per-index validity: idx < chunk_count AND signer is in the
        // assigned set per the deterministic assignment function. Any
        // mismatch rejects the whole tx (no partial application).
        let snapshot_addrs: Vec<Address> =
            snapshot.iter().map(|n| n.address).collect();
        for &idx in chunk_indices {
            if idx >= row.chunk_count {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    33,
                    format!(
                        "AcceptAssignmentV2: chunk_index {} >= chunk_count {}",
                        idx, row.chunk_count
                    ),
                ));
            }
            if !is_archive_assigned_to_chunk(
                merkle_root,
                &snapshot_addrs,
                idx,
                chain_params.assignment_replication_factor,
                signer,
            ) {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    33,
                    format!(
                        "AcceptAssignmentV2: chunk_index {} not assigned to signer",
                        idx
                    ),
                ));
            }
        }

        // 5. OR the supplied indices into the per-(file, archive) bitmap.
        // Lazy allocation: row is created on first accept.
        let bm_len = bitmap_byte_len(row.chunk_count);
        let key = attestation_v2_key(merkle_root, signer);
        let mut bitmap = match self
            .db
            .get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key)
            .map_err(StateError::Storage)?
        {
            Some(bytes) if bytes.len() == bm_len => bytes,
            _ => vec![0u8; bm_len],
        };
        for &idx in chunk_indices {
            bitmap_set(&mut bitmap, idx);
        }
        self.db
            .put(CF_ASSIGNMENT_ATTESTATIONS_V2, &key, &bitmap)
            .map_err(StateError::Storage)?;

        debug!(
            "AcceptAssignmentV2: archive {} attested {} chunks for {} (popcount={})",
            signer,
            chunk_indices.len(),
            merkle_root,
            bitmap_popcount(&bitmap)
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.6 ActivateFileV2 — Pending → Active transition gated on
    /// full-coverage of every chunk by at least one snapshot-active archive's
    /// attestation bitmap.
    fn execute_activate_file_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        block_height: u64,
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    34,
                    "ActivateFileV2: file not found",
                ));
            }
        };
        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                34,
                "ActivateFileV2: only the owner can activate",
            ));
        }
        if row.lifecycle != FileLifecycleV2::Pending {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                34,
                "ActivateFileV2: file must be Pending",
            ));
        }

        // Coverage check. OR all snapshot-active archives' bitmaps and ensure
        // every chunk index in `[0, chunk_count)` has at least one bit set.
        // Inactive (Slashed) archives' bitmaps are excluded — slashing between
        // attest and activate must remove that archive's contribution.
        let snapshot = node_registry.get_active_archive_nodes_at_height(row.assignment_height)?;
        let bm_len = bitmap_byte_len(row.chunk_count);
        let mut union = vec![0u8; bm_len];
        for node in &snapshot {
            if !is_currently_active(node_registry, &node.address)? {
                continue;
            }
            let key = attestation_v2_key(merkle_root, &node.address);
            if let Some(bm) = self
                .db
                .get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key)
                .map_err(StateError::Storage)?
            {
                if bm.len() == bm_len {
                    bitmap_or_into(&mut union, &bm);
                }
                // Length-mismatch row (shouldn't happen — chunk_count is fixed
                // at registration) is silently ignored; treat as no contribution.
            }
        }
        let covered = bitmap_popcount(&union);
        if covered != row.chunk_count {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                34,
                format!(
                    "ActivateFileV2: coverage incomplete — {}/{} chunks attested",
                    covered, row.chunk_count
                ),
            ));
        }

        // Transition.
        row.lifecycle = FileLifecycleV2::Active;
        row.activated_at_height = Some(block_height);
        self.put_metadata_v2(&row)?;

        // Suppress unused warning: replication_factor is captured by callers
        // of the assignment function; unused locally here but referenced in
        // the doc comment.
        let _ = chain_params.assignment_replication_factor;

        info!(
            "V2 file activated: merkle_root={}, owner={}, activated_at={}",
            merkle_root, sender, block_height
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan §3.5 RegisterFilePendingV2 validity rules.
    #[allow(clippy::too_many_arguments)]
    fn execute_register_file_pending_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        plaintext_size_bytes: u64,
        stored_size_bytes: u64,
        chunk_count: u32,
        fee_deposit: u64,
        visibility_byte: u8,
        initial_access: &[AccessEntryV2],
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        // 1. Numeric validity.
        if chunk_count == 0 {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "chunk_count must be > 0",
            ));
        }
        if stored_size_bytes == 0 {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "stored_size_bytes must be > 0",
            ));
        }
        // Plan v3.2 §3.4 — bound `chunk_count` so the per-(file, archive)
        // bitmap row has a known max size (`ceil(N/8)` bytes) before
        // `AcceptAssignmentV2` rows are written in 1b.
        if chunk_count > chain_params.max_chunk_count_per_file {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                format!(
                    "chunk_count exceeds max_chunk_count_per_file ({} > {})",
                    chunk_count, chain_params.max_chunk_count_per_file
                ),
            ));
        }
        // Chunk count must match the canonical `ceil(stored_size_bytes / CHUNK_SIZE)`
        // (V2 inherits V1's fixed 1 MB chunk size — see [crates/primitives/src/storage_metadata.rs]
        // `CHUNK_SIZE`). Without this invariant the bitmap row size is decoupled
        // from the actual file size, which breaks the bounded-row guarantee
        // and makes `AcceptAssignmentV2` chunk-index bounds checks meaningless.
        //
        // Use `u64::div_ceil` rather than the manual `(a + b - 1) / b` form:
        // `stored_size_bytes` is tx-controlled and unbounded before this check,
        // so `+ (CHUNK_SIZE - 1)` panics in debug builds when
        // `stored_size_bytes > u64::MAX - (CHUNK_SIZE - 1)` and silently wraps
        // in release. Consensus validation must not have profile-dependent
        // arithmetic. `u64::div_ceil` is total for any non-zero divisor — and
        // `CHUNK_SIZE = 1 MiB` is a nonzero compile-time constant — so this
        // call is always safe regardless of the input size.
        let expected_chunk_count = stored_size_bytes.div_ceil(CHUNK_SIZE);
        if chunk_count as u64 != expected_chunk_count {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                format!(
                    "chunk_count must equal ceil(stored_size_bytes / CHUNK_SIZE): \
                     got {}, expected {} (stored_size_bytes={}, CHUNK_SIZE={})",
                    chunk_count, expected_chunk_count, stored_size_bytes, CHUNK_SIZE
                ),
            ));
        }
        let visibility = match FileVisibilityV2::from_byte(visibility_byte) {
            Some(v) => v,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    30,
                    "visibility must be 0 (Public) or 1 (Private)",
                ));
            }
        };

        // 2. Access-list byte cap (plan §3.4).
        let access_bytes = bincode::serialize(&initial_access.to_vec())
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        if access_bytes.len() as u64 > chain_params.max_access_list_bytes {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                format!(
                    "initial_access exceeds max_access_list_bytes ({} > {})",
                    access_bytes.len(),
                    chain_params.max_access_list_bytes
                ),
            ));
        }

        // 3. Visibility-dependent bundle/owner rules.
        match visibility {
            FileVisibilityV2::Public => {
                // All bundles MUST be None; list MAY be empty.
                if initial_access
                    .iter()
                    .any(|e| e.encrypted_key_bundle.is_some())
                {
                    return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                        30,
                        "Public file: encrypted_key_bundle must be None for all entries",
                    ));
                }
            }
            FileVisibilityV2::Private => {
                // All bundles MUST be Some; owner MUST be in list with non-None bundle;
                // every recipient MUST have a registered X25519 pubkey.
                if initial_access.is_empty() {
                    return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                        30,
                        "Private file: initial_access must contain at least the owner",
                    ));
                }
                if initial_access
                    .iter()
                    .any(|e| e.encrypted_key_bundle.is_none())
                {
                    return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                        30,
                        "Private file: every entry must have an encrypted_key_bundle",
                    ));
                }
                let owner_present = initial_access
                    .iter()
                    .any(|e| e.address == *sender && e.encrypted_key_bundle.is_some());
                if !owner_present {
                    return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                        30,
                        "Private file: owner must be in initial_access with a bundle",
                    ));
                }
                // Every recipient must have an X25519 pubkey on chain.
                for entry in initial_access {
                    let has_key = node_registry
                        .get_encryption_pubkey(&entry.address)?
                        .is_some();
                    if !has_key {
                        return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                            30,
                            "Private file: a recipient lacks a registered X25519 pubkey",
                        ));
                    }
                }
            }
        }

        // 4. Idempotency / collision: refuse if the merkle_root is already
        // registered (in either V1 or V2). Re-registration would silently
        // overwrite metadata, which is not a use case we want.
        if self.get_metadata_v2(merkle_root)?.is_some() {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "merkle_root already registered as V2 file",
            ));
        }
        if self.get_metadata(merkle_root)?.is_some() {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "merkle_root already registered as V1 file",
            ));
        }

        // 5. Lock fee_deposit into fee_pool. Sender's nonce was already
        // incremented inside deduct_fee; the deposit is a separate balance
        // movement.
        if fee_deposit > 0 {
            let sender_balance = state.get_balance(sender)?;
            if sender_balance < fee_deposit as u128 {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    30,
                    "insufficient balance for fee_deposit",
                ));
            }
            let mut sender_account = state.get_account(sender)?;
            sender_account.balance = sender_account.balance.saturating_sub(fee_deposit as u128);
            state.put_account(sender, &sender_account)?;
        }

        // 6. Persist the V2 row. assignment_height = current block height
        // (Ask 15) — the active-archive snapshot at this height is what
        // subsequent assignment computations and `AcceptAssignmentV2`
        // checks will use.
        let row = StorageMetadataV2 {
            merkle_root: *merkle_root,
            owner: *sender,
            plaintext_size_bytes,
            stored_size_bytes,
            chunk_count,
            fee_pool: fee_deposit,
            created_at: block_height,
            activated_at_height: None,
            abandoned_at_height: None,
            assignment_height: block_height,
            visibility,
            lifecycle: FileLifecycleV2::Pending,
            access_list: initial_access.to_vec(),
            predecessor_root: None,
        };
        self.put_metadata_v2(&row)?;

        info!(
            "V2 file registered Pending: merkle_root={}, owner={}, chunks={}, deposit={}",
            merkle_root, sender, chunk_count, fee_deposit
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan §3.5 AbandonFileV2 — refund (1 - abandonment_fee_percent/100) of
    /// `fee_pool` to owner, retain remainder, transition Pending → Abandoned.
    fn execute_abandon_file_v2(
        &self,
        sender: &Address,
        merkle_root: &Hash,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    31,
                    "file not found",
                ));
            }
        };

        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                31,
                "only the owner can abandon a file",
            ));
        }
        if row.lifecycle != FileLifecycleV2::Pending {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                31,
                "AbandonFileV2 requires lifecycle == Pending",
            ));
        }
        // Anti-grief: cannot abandon within the activation grace window.
        if block_height <= row.created_at.saturating_add(chain_params.activation_grace_blocks) {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                31,
                "AbandonFileV2 only valid after activation_grace_blocks past created_at",
            ));
        }

        // Refund split: `(100 - fee%) / 100` to owner, retain rest.
        let percent = chain_params.abandonment_fee_percent.min(100);
        let retain = row.fee_pool.saturating_mul(percent) / 100;
        let refund = row.fee_pool.saturating_sub(retain);

        if refund > 0 {
            let mut owner_account = state.get_account(sender)?;
            owner_account.balance = owner_account.balance.saturating_add(refund as u128);
            state.put_account(sender, &owner_account)?;
        }

        row.fee_pool = 0;
        row.lifecycle = FileLifecycleV2::Abandoned;
        row.abandoned_at_height = Some(block_height);
        self.put_metadata_v2(&row)?;

        info!(
            "V2 file abandoned: merkle_root={}, owner={}, refund={}, retained={}",
            merkle_root, sender, refund, retain
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Public read of a per-(file, archive) attestation bitmap. Returns `None`
    /// if no row exists yet (first attestation lazily allocates).
    pub fn get_attestation_bitmap_v2(
        &self,
        merkle_root: &Hash,
        archive: &Address,
    ) -> Result<Option<Vec<u8>>> {
        let key = attestation_v2_key(merkle_root, archive);
        match self.db.get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key) {
            Ok(Some(data)) => Ok(Some(data)),
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    /// Compute the OR-coverage and per-archive popcount summaries used by
    /// `storage_getAssignmentCoverageV2`. Snapshot-active filtering matches
    /// the activation precondition exactly.
    ///
    /// `replication_factor` MUST be the consensus value
    /// (`ChainParams::assignment_replication_factor`) — the caller is
    /// responsible for passing it through. Hardcoding here would silently
    /// disagree with `AcceptAssignmentV2` validity on chains tuned to a
    /// different value, and SNIP clients would compute different
    /// `assigned_count` values than the chain emits.
    ///
    /// Per-archive `assigned_count` is computed iff
    /// `chunk_count <= MAX_ASSIGNED_COUNT_CHUNK_COUNT`. Above that cap it's
    /// returned as `None` to keep the RPC bounded; clients compute locally
    /// via [`sumchain_primitives::assigned_archives_presorted`].
    pub fn compute_coverage_v2(
        &self,
        merkle_root: &Hash,
        node_registry: &NodeRegistryExecutor,
        replication_factor: u32,
    ) -> Result<Option<CoverageSummaryV2>> {
        let row = match self.get_metadata_v2(merkle_root)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let snapshot = node_registry.get_active_archive_nodes_at_height(row.assignment_height)?;
        let bm_len = bitmap_byte_len(row.chunk_count);
        let mut union = vec![0u8; bm_len];
        let mut per_archive: Vec<ArchivePerEntry> = Vec::with_capacity(snapshot.len());

        for node in &snapshot {
            let currently_active = is_currently_active(node_registry, &node.address)?;
            let key = attestation_v2_key(merkle_root, &node.address);
            let attested_count = match self
                .db
                .get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key)
                .map_err(StateError::Storage)?
            {
                Some(bm) if bm.len() == bm_len => {
                    if currently_active {
                        bitmap_or_into(&mut union, &bm);
                    }
                    bitmap_popcount(&bm)
                }
                _ => 0,
            };
            per_archive.push(ArchivePerEntry {
                archive: node.address,
                attested_count,
                currently_active,
                assigned_count: None, // populated below if cap permits
            });
        }

        // Per-archive `assigned_count`. Compute iff under the safety cap; one
        // pass over chunks reusing a presorted snapshot — the prior
        // implementation re-sorted the snapshot inside every call, blowing up
        // to O(chunks × archives²). Now O(chunks × archives × log(archives))
        // dominated by BLAKE3, capped by MAX_ASSIGNED_COUNT_CHUNK_COUNT.
        if row.chunk_count <= MAX_ASSIGNED_COUNT_CHUNK_COUNT {
            let mut sorted_addrs: Vec<Address> =
                snapshot.iter().map(|n| n.address).collect();
            sorted_addrs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            sorted_addrs.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

            let mut counts: Vec<u32> = vec![0u32; per_archive.len()];
            for chunk_idx in 0..row.chunk_count {
                let assigned = sumchain_primitives::assigned_archives_presorted(
                    merkle_root,
                    &sorted_addrs,
                    chunk_idx,
                    replication_factor,
                );
                for a in &assigned {
                    if let Some(i) = per_archive
                        .iter()
                        .position(|p| p.archive.as_bytes() == a.as_bytes())
                    {
                        counts[i] += 1;
                    }
                }
            }
            for (i, p) in per_archive.iter_mut().enumerate() {
                p.assigned_count = Some(counts[i]);
            }
        }

        Ok(Some(CoverageSummaryV2 {
            chunk_count: row.chunk_count,
            covered_count: bitmap_popcount(&union),
            lifecycle: row.lifecycle,
            assignment_height: row.assignment_height,
            replication_factor,
            union,
            per_archive,
        }))
    }

    // ── V2 row CRUD ─────────────────────────────────────────────────────────

    fn put_metadata_v2(&self, row: &StorageMetadataV2) -> Result<()> {
        let key = metadata_v2_key(&row.merkle_root);
        let value = bincode::serialize(row)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db
            .put(CF_STORAGE_METADATA_V2, &key, &value)
            .map_err(StateError::Storage)?;

        let idx = owner_v2_index_key(&row.owner, &row.merkle_root);
        self.db
            .put(CF_STORAGE_METADATA_V2, &idx, &[1])
            .map_err(StateError::Storage)?;
        Ok(())
    }

    /// Plan v3.2 §4 — list V2 files in a "pushable" state (Pending or Active),
    /// excluding Abandoned. Backs the `storage_getPushableFilesV2` RPC's
    /// warm-cache use case for archive nodes deciding whether to accept a
    /// push for a given merkle_root.
    ///
    /// Iterates the V2 file CF using the row prefix `[b'F', b'2', ...]`.
    /// O(rows) — bounded by total V2 file count; the RPC layer handles any
    /// further pagination if needed.
    pub fn list_pushable_files_v2(&self) -> Result<Vec<StorageMetadataV2>> {
        let mut out = Vec::new();
        let prefix = [b'F', b'2'];
        for (key, value) in self
            .db
            .prefix_iter(CF_STORAGE_METADATA_V2, &prefix)
            .map_err(StateError::Storage)?
        {
            // Owner-index keys live in the same CF under prefix `[b'O', b'2', ...]`.
            // The row keys are exactly 34 bytes (`F` + `2` + 32-byte hash);
            // skip anything that doesn't match to be defensive.
            if key.len() != 34 || key[0] != b'F' || key[1] != b'2' {
                continue;
            }
            let row: StorageMetadataV2 = bincode::deserialize(&value)
                .map_err(|e| StateError::DeserializationError(e.to_string()))?;
            if matches!(row.lifecycle, FileLifecycleV2::Pending | FileLifecycleV2::Active) {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Look up a V2 file row by its merkle_root.
    pub fn get_metadata_v2(&self, merkle_root: &Hash) -> Result<Option<StorageMetadataV2>> {
        let key = metadata_v2_key(merkle_root);
        match self.db.get(CF_STORAGE_METADATA_V2, &key) {
            Ok(Some(data)) => {
                let row: StorageMetadataV2 = bincode::deserialize(&data)
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                Ok(Some(row))
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
