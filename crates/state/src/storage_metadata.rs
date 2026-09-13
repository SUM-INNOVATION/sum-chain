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
//! # Execution reads and writes the candidate, not the database
//!
//! Every function on the block-execution path is an associated function taking
//! an [`ExecutionView`]. Without a `self` receiver there is no `Arc<Database>`
//! to read through, so a committed read on those paths is a compile error.
//!
//! That matters here more than almost anywhere else, because this subsystem
//! reads the node registry: `process_expired_challenges` slashes archives and
//! rewrites the active-archive snapshot *before* the transaction loop, and
//! `RegisterArchiveNode` / `BeginUnstake` rewrite it *inside* the loop. A
//! storage transaction that resolved its assignment snapshot from committed
//! state would compute an archive set that excludes those changes — a different
//! set from the one every other node computes, in the same block.
//!
//! The `&self` readers below survive for RPC and mempool admission, which
//! answer about the published chain. Each is paired with a `v_` twin over the
//! view, and both share the codec and filter helpers so they cannot drift.

use std::sync::Arc;

use sumchain_primitives::{
    assigned_archives, is_archive_assigned_to_chunk, AccessEntryV2, Address, Balance,
    FileLifecycleV2, FileVisibilityV2, Hash, NodeRecord, NodeStatus, StorageChallenge,
    StorageMetadata, StorageMetadataOperation, StorageMetadataOperationV2, StorageMetadataTxData,
    StorageMetadataV2, StorageMetadataV2TxData, CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS, CHUNK_SIZE,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;
use sumchain_genesis::ChainParams;
use tracing::{debug, info, warn};

use crate::node_registry::NodeRegistryExecutor;
use crate::{Result, StateError, StateManager};

// ─── Column Family Names ─────────────────────────────────────────────────────
//
// Aliases for `sumchain_storage::cf`, which is where a column family is named.
// Re-declaring the string literals here would let this file and the storage
// schema drift apart with nothing to catch it.

pub const CF_STORAGE_METADATA: &str = sumchain_storage::cf::STORAGE_METADATA;
pub const CF_ACTIVE_CHALLENGES: &str = sumchain_storage::cf::ACTIVE_CHALLENGES;
/// Issue #100 — compact challengeable V2-file index: `merkle_root(32)` →
/// `chunk_count` (fixed 4-byte big-endian `u32`). Present iff the V2 file is
/// `Active && fee_pool > 0 && chunk_count > 0`. Maintained on `ActivateFileV2`
/// and on a V2 challenge payout that drains `fee_pool` to 0; the one-time
/// backfill populates pre-upgrade files.
pub const CF_CHALLENGEABLE_FILES_V2: &str = sumchain_storage::cf::CHALLENGEABLE_FILES_V2;
/// General meta CF (shared) — the #100 backfill stores its one-shot completion
/// marker under [`POR_SCHEDULER_BACKFILL_MARKER`] here.
pub const CF_META: &str = sumchain_storage::cf::META;
/// Key in [`CF_META`] recording that the #100 challengeable-index backfill has
/// run. Its presence prevents any further full V2 scan.
pub const POR_SCHEDULER_BACKFILL_MARKER: &[u8] = b"por_scheduler_index_backfilled";
/// V2 storage metadata column family. Coexists with V1 — entries keyed by
/// `[b'F', b'2', merkle_root]` so the prefix never overlaps V1 `[b'F', root]`.
pub const CF_STORAGE_METADATA_V2: &str = sumchain_storage::cf::STORAGE_METADATA_V2;
/// V2 per-(file, archive) AcceptAssignmentV2 bitmap CF. Plan v3.2 §3.6.
/// Epoch-0 only (issue #62): replacement-epoch attestations live in
/// [`CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH`] and never touch this CF.
pub const CF_ASSIGNMENT_ATTESTATIONS_V2: &str = sumchain_storage::cf::ASSIGNMENT_ATTESTATIONS_V2;
/// Per-file archive-reassignment epochs (issue #62): `merkle_root` → `Vec<u64>`
/// of reassignment heights (epoch ≥ 1). Epoch 0 is the file's `assignment_height`
/// and is not stored here.
pub const CF_FILE_REASSIGNMENTS: &str = sumchain_storage::cf::FILE_REASSIGNMENTS;
/// Per-(file, epoch, archive) reassignment attestation bitmaps (issue #62).
pub const CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH: &str =
    sumchain_storage::cf::ASSIGNMENT_ATTESTATIONS_V2_EPOCH;

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

// -- Reassignment keys (issue #62) --

/// `file_reassignments` key: raw 32-byte `merkle_root` (dedicated CF).
fn file_reassignments_key(merkle_root: &Hash) -> Vec<u8> {
    merkle_root.as_bytes().to_vec()
}

/// Reassignment attestation bitmap key:
/// `[b'R', merkle_root_32, epoch_height_be_8, archive_20]` (61 bytes).
fn attestation_v2_epoch_key(merkle_root: &Hash, epoch_height: u64, archive: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(61);
    key.push(b'R');
    key.extend_from_slice(merkle_root.as_bytes());
    key.extend_from_slice(&epoch_height.to_be_bytes());
    key.extend_from_slice(archive.as_bytes());
    key
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

// ─── Codec and row-shape helpers ─────────────────────────────────────────────
//
// Shared by the candidate (`v_`) and committed accessors. The two differ only
// in where the bytes come from; every rule about what a row *means* — how it is
// encoded, which keys in a mixed-key-family CF are data rows, when a file is
// challengeable — lives here once, so a candidate read and an RPC read cannot
// disagree.

fn encode_metadata(meta: &StorageMetadata) -> Result<Vec<u8>> {
    bincode::serialize(meta).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_metadata(bytes: &[u8]) -> Result<StorageMetadata> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

fn encode_metadata_v2(row: &StorageMetadataV2) -> Result<Vec<u8>> {
    bincode::serialize(row).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_metadata_v2(bytes: &[u8]) -> Result<StorageMetadataV2> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

fn encode_challenge(challenge: &StorageChallenge) -> Result<Vec<u8>> {
    bincode::serialize(challenge).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_challenge(bytes: &[u8]) -> Result<StorageChallenge> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

fn encode_epochs(epochs: &[u64]) -> Result<Vec<u8>> {
    bincode::serialize(&epochs.to_vec())
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_epochs(bytes: &[u8]) -> Result<Vec<u64>> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

/// V1 file rows are `[b'F', merkle_root(32)]`. Owner-index keys `[b'O', ...]`
/// share the CF and, being `>= 'F'`, appear in a `[b'F']` prefix scan; their
/// value is the 1-byte marker `[1]`, which must never be decoded as a row
/// (issue #97 — was a `DeserializationError` "unexpected end of file").
fn is_v1_row_key(key: &[u8]) -> bool {
    key.len() >= 33 && key[0] == b'F'
}

/// V2 file rows are exactly `[b'F', b'2', merkle_root(32)]` (34 bytes); owner
/// indexes `[b'O', b'2', ...]` share the CF.
fn is_v2_row_key(key: &[u8]) -> bool {
    key.len() == 34 && key[0] == b'F' && key[1] == b'2'
}

/// The merkle root embedded in an owner-index key `[b'O', owner(20), root(32)]`.
fn owner_index_root(key: &[u8]) -> Result<Option<Hash>> {
    if key.len() < 53 {
        return Ok(None);
    }
    Hash::from_slice(&key[21..53])
        .map(Some)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

/// The challenge id embedded in a node-index key
/// `[b'N', target_node(20), challenge_id(32)]` (53 bytes).
fn challenge_node_index_id(key: &[u8]) -> Result<Option<Hash>> {
    if key.len() < 53 {
        return Ok(None); // Malformed key — skip safely
    }
    Hash::from_slice(&key[21..53])
        .map(Some)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

/// `(expires_at_height, challenge_id)` from an expiry-index key
/// `[b'E', expires_at_height(8 BE), challenge_id(32)]` (41 bytes).
fn challenge_expiry_index_entry(key: &[u8]) -> Result<Option<(u64, Hash)>> {
    if key.len() < 41 {
        return Ok(None);
    }
    let expires_at = u64::from_be_bytes([
        key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8],
    ]);
    let challenge_id = Hash::from_slice(&key[9..41])
        .map_err(|e| StateError::DeserializationError(e.to_string()))?;
    Ok(Some((expires_at, challenge_id)))
}

/// A V2 file is challengeable iff it is funded, `Active`, and has a usable
/// chunk count. This is the single definition behind the #100 index, its
/// backfill, the scheduler's stale-entry guard and the funded-candidate scan.
fn challengeable(row: &StorageMetadataV2) -> bool {
    row.lifecycle == FileLifecycleV2::Active && row.fee_pool > 0 && row.chunk_count > 0
}

/// `(cf, key)` holding the (file, archive) attestation bitmap for `epoch`:
/// epoch 0 lives in the original CF, a reassignment epoch in the epoch-aware one
/// (issue #62). Shared by every read and the one write, so an attestation can
/// never be written to one CF and looked for in the other.
fn attestation_slot(
    row: &StorageMetadataV2,
    epoch: u64,
    archive: &Address,
) -> (&'static str, Vec<u8>) {
    if epoch == row.assignment_height {
        (
            CF_ASSIGNMENT_ATTESTATIONS_V2,
            attestation_v2_key(&row.merkle_root, archive),
        )
    } else {
        (
            CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH,
            attestation_v2_epoch_key(&row.merkle_root, epoch, archive),
        )
    }
}

/// Checked u128 accumulation for the fee-pool census, with the bucket named in
/// the overflow error.
fn add_fee_pool(sum: u128, fee_pool: u64, bucket: &str) -> Result<u128> {
    sum.checked_add(fee_pool as u128).ok_or_else(|| {
        StateError::BlockValidation(format!("storage {bucket} fee_pool sum overflow"))
    })
}

// -- StorageChallenge keys --
//
// Public so a test can SEED a committed challenge row — an archive that already
// carries an open challenge before the block under test runs — without
// restating the key layout. They are pure functions of the challenge fields and
// reach no database; the writers that use them are `v_put_challenge` and
// `v_delete_challenge`, which stage into a candidate.

pub fn challenge_key(challenge_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(b'C');
    key.extend_from_slice(challenge_id.as_bytes());
    key
}

pub fn challenge_node_index_key(target_node: &Address, challenge_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(53);
    key.push(b'N');
    key.extend_from_slice(target_node.as_bytes());
    key.extend_from_slice(challenge_id.as_bytes());
    key
}

pub fn challenge_expiry_index_key(expires_at_height: u64, challenge_id: &Hash) -> Vec<u8> {
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
    recipient_has_key: bool,
) -> std::result::Result<(), String> {
    match visibility {
        FileVisibilityV2::Public => {
            if entry.encrypted_key_bundle.is_some() {
                return Err("Public file: entry must not carry an encrypted_key_bundle".into());
            }
        }
        FileVisibilityV2::Private => {
            if entry.encrypted_key_bundle.is_none() {
                return Err("Private file: entry must carry an encrypted_key_bundle".into());
            }
            if !recipient_has_key {
                return Err("Private file: recipient lacks a registered X25519 pubkey".into());
            }
        }
    }
    Ok(())
}

/// [`check_access_entry_for_visibility`] with the registry lookup resolved from
/// this block's candidate — so a `RegisterEncryptionKey` earlier in the same
/// block makes its sender a valid Private-file recipient.
fn v_check_access_entry_for_visibility(
    view: &ExecutionView<'_, '_>,
    visibility: FileVisibilityV2,
    entry: &AccessEntryV2,
) -> Result<std::result::Result<(), String>> {
    // Resolved only for Private files: a Public file's check never consults the
    // registry, and doing the read anyway would make a Public registration fail
    // on an unrelated storage error.
    let has_key = match visibility {
        FileVisibilityV2::Public => false,
        FileVisibilityV2::Private => {
            NodeRegistryExecutor::v_get_encryption_pubkey(view, &entry.address)?.is_some()
        }
    };
    Ok(check_access_entry_for_visibility(visibility, entry, has_key))
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

/// True iff this archive is currently `Active` per its node-registry record,
/// as this block's candidate sees it — so an archive slashed earlier in the
/// same block is already excluded.
fn v_is_currently_active(view: &ExecutionView<'_, '_>, archive: &Address) -> Result<bool> {
    Ok(matches!(
        NodeRegistryExecutor::v_get_node(view, archive)?,
        Some(rec) if rec.status == NodeStatus::Active
    ))
}

/// Committed twin of [`v_is_currently_active`], for the coverage RPC.
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

/// Per-epoch coverage detail (issue #62). One entry per assignment epoch (epoch
/// 0 = `assignment_height`, then each reassignment height). Its `per_archive`
/// and `covered_count` are self-consistent for that epoch — no mixing of
/// epoch-0 and reassignment data.
#[derive(Debug, Clone)]
pub struct EpochCoverageEntry {
    pub epoch_height: u64,
    pub is_epoch_zero: bool,
    pub covered_count: u32,
    pub per_archive: Vec<ArchivePerEntry>,
}

/// Coverage summary for `storage_getAssignmentCoverageV2`. RPC-side combines
/// this with `assigned_archives` per chunk to produce the wire response.
///
/// Issue #62: top-level scalars (`covered_count`, `union`) are **aggregate**
/// across all epochs (equal to the epoch-0 values for files with no
/// reassignment). Top-level `per_archive` stays **epoch-0-only** for
/// backward-compatibility; all reassignment-aware detail is in `per_epoch`.
#[derive(Debug, Clone)]
pub struct CoverageSummaryV2 {
    pub chunk_count: u32,
    pub covered_count: u32,
    pub lifecycle: FileLifecycleV2,
    pub assignment_height: u64,
    pub replication_factor: u32,
    /// Aggregate OR of every currently-active archive's bitmap across all
    /// epochs. Used by the RPC to compute `missing_indices`.
    pub union: Vec<u8>,
    /// Epoch-0-only per-archive summary (backward-compatible).
    pub per_archive: Vec<ArchivePerEntry>,
    /// All assignment epoch heights, ascending: `[assignment_height, ...reassign]`.
    pub assignment_epochs: Vec<u64>,
    /// The latest epoch height (== `assignment_epochs.last()`).
    pub latest_assignment_epoch: u64,
    /// Whether an originally-/currently-assigned archive has left the active set
    /// since the latest epoch — i.e. `ReassignChunksV2` would be accepted.
    pub reassignment_needed: bool,
    /// Per-epoch coverage detail (reassignment-aware client path).
    pub per_epoch: Vec<EpochCoverageEntry>,
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
    fn deduct_fee(view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = StateManager::v_get_balance(view, sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        StateManager::v_put_account(view, sender, &sender_account)?;

        if !proposer.is_zero() {
            let mut proposer_account = StateManager::v_get_account(view, proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            StateManager::v_put_account(view, proposer, &proposer_account)?;
        }

        Ok(())
    }

    // =========================================================================
    // Transaction Dispatcher
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &StorageMetadataTxData,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;

        match &data.operation {
            StorageMetadataOperation::RegisterFile {
                merkle_root,
                total_size_bytes,
                access_list,
                fee_deposit,
            } => Self::execute_register_file(
                view, sender, merkle_root, *total_size_bytes, access_list, *fee_deposit,
                block_height,
            ),
            StorageMetadataOperation::UpdateAccessList {
                merkle_root,
                new_access_list,
            } => Self::execute_update_access_list(view, sender, merkle_root, new_access_list),
            StorageMetadataOperation::AddAccess {
                merkle_root,
                address,
            } => Self::execute_add_access(view, sender, merkle_root, address),
            StorageMetadataOperation::RemoveAccess {
                merkle_root,
                address,
            } => Self::execute_remove_access(view, sender, merkle_root, address),
            StorageMetadataOperation::TopUpFeePool {
                merkle_root,
                amount,
            } => Self::execute_top_up(view, sender, merkle_root, *amount),
            StorageMetadataOperation::SubmitStorageProof {
                challenge_id,
                merkle_root,
                chunk_index,
                chunk_hash,
                merkle_path,
            } => Self::execute_submit_proof(
                view,
                sender, challenge_id, merkle_root, *chunk_index, chunk_hash, merkle_path,
                block_height,
            ),
        }
    }

    // =========================================================================
    // File Operations (Phase 1)
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    fn execute_register_file(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        total_size_bytes: u64,
        access_list: &[Address],
        fee_deposit: u64,
        block_height: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        if Self::v_get_metadata(view, merkle_root)?.is_some() {
            return Ok(StorageMetadataExecutionResult::fail(
                "File with this merkle_root already registered",
            ));
        }

        if fee_deposit == 0 {
            return Ok(StorageMetadataExecutionResult::fail("fee_deposit must be > 0"));
        }

        let balance = StateManager::v_get_balance(view, sender)?;
        if balance < fee_deposit as u128 {
            return Ok(StorageMetadataExecutionResult::fail(format!(
                "Insufficient balance for fee deposit: need {}, have {}",
                fee_deposit, balance
            )));
        }

        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee_deposit as u128);
        StateManager::v_put_account(view, sender, &sender_account)?;

        let metadata = StorageMetadata {
            merkle_root: *merkle_root,
            owner: *sender,
            total_size_bytes,
            access_list: access_list.to_vec(),
            fee_pool: fee_deposit,
            created_at: block_height,
        };

        Self::v_put_metadata(view, &metadata)?;

        info!(
            "File registered: merkle_root={}, owner={}, size={}, fee_pool={}",
            merkle_root, sender, total_size_bytes, fee_deposit
        );

        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_update_access_list(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        new_access_list: &[Address],
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match Self::v_get_metadata(view, merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if meta.owner != *sender {
            return Ok(StorageMetadataExecutionResult::fail(
                "Only the owner can update the access list",
            ));
        }

        meta.access_list = new_access_list.to_vec();
        Self::v_put_metadata(view, &meta)?;

        debug!("Access list updated for {}", merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_add_access(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match Self::v_get_metadata(view, merkle_root)? {
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
        Self::v_put_metadata(view, &meta)?;

        debug!("Added {} to access list for {}", address, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_remove_access(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match Self::v_get_metadata(view, merkle_root)? {
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

        Self::v_put_metadata(view, &meta)?;

        debug!("Removed {} from access list for {}", address, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    fn execute_top_up(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        amount: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        let mut meta = match Self::v_get_metadata(view, merkle_root)? {
            Some(m) => m,
            None => return Ok(StorageMetadataExecutionResult::fail("File not found")),
        };

        if amount == 0 {
            return Ok(StorageMetadataExecutionResult::fail("Amount must be > 0"));
        }

        let balance = StateManager::v_get_balance(view, sender)?;
        if balance < amount as u128 {
            return Ok(StorageMetadataExecutionResult::fail(format!(
                "Insufficient balance: need {}, have {}",
                amount, balance
            )));
        }

        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(amount as u128);
        StateManager::v_put_account(view, sender, &sender_account)?;

        meta.fee_pool = meta.fee_pool.saturating_add(amount);
        Self::v_put_metadata(view, &meta)?;

        debug!("Fee pool topped up by {} for {}", amount, merkle_root);
        Ok(StorageMetadataExecutionResult::ok())
    }

    // =========================================================================
    // Objective 4: SubmitStorageProof — Cryptographic Verification & Settlement
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    fn execute_submit_proof(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        challenge_id: &Hash,
        merkle_root: &Hash,
        chunk_index: u32,
        chunk_hash: &Hash,
        merkle_path: &[Hash],
        current_height: u64,
    ) -> Result<StorageMetadataExecutionResult> {
        // 1. Load challenge
        let challenge = match Self::v_get_challenge(view, challenge_id)? {
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

        // 5. Load file metadata (V1 preferred; else V2 — issue #100). A V1 row
        // keeps the exact pre-existing settlement; a V2-only file (the assignment
        // world, where challenges now originate) settles against its V2 row so a
        // correctly-storing archive can actually prove and is not slashed.
        let v1 = Self::v_get_metadata(view, merkle_root)?;
        let v2 = if v1.is_none() {
            Self::v_get_metadata_v2(view, merkle_root)?
        } else {
            None
        };

        // Determine chunk_count and (for V2) enforce Active + chunk bound.
        let chunk_count: u64 = match (&v1, &v2) {
            (Some(m), _) => (m.total_size_bytes + CHUNK_SIZE - 1) / CHUNK_SIZE,
            (None, Some(r)) => {
                if r.lifecycle != FileLifecycleV2::Active {
                    return Ok(StorageMetadataExecutionResult::fail(
                        "V2 file is not Active; cannot settle proof",
                    ));
                }
                r.chunk_count as u64
            }
            (None, None) => {
                return Ok(StorageMetadataExecutionResult::fail(
                    "File metadata not found for merkle_root",
                ))
            }
        };
        if (chunk_index as u64) >= chunk_count {
            return Ok(StorageMetadataExecutionResult::fail(
                "chunk_index out of range for file",
            ));
        }

        // 6. Validate merkle_path length
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

        // 7. Cryptographic Merkle proof verification (identical for V1 and V2 —
        // both verify against the same 32-byte `merkle_root`).
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

        // 8. Settlement: pay reward from the file's fee_pool to target_node.
        // Amount/partial-payout rule is identical for V1 and V2; only the row
        // that holds the pool differs.
        let payout;
        if let Some(mut meta) = v1 {
            payout = meta.fee_pool.min(CHALLENGE_REWARD);
            if payout > 0 {
                meta.fee_pool = meta.fee_pool.saturating_sub(payout);
                Self::v_put_metadata(view, &meta)?;
            }
        } else {
            let mut row = v2.expect("V2 row present when V1 absent");
            payout = row.fee_pool.min(CHALLENGE_REWARD);
            if payout > 0 {
                row.fee_pool = row.fee_pool.saturating_sub(payout);
                Self::v_put_metadata_v2(view, &row)?;
                // Drained → no longer challengeable: heal the #100 index.
                if row.fee_pool == 0 {
                    Self::v_challengeable_index_remove(view, merkle_root)?;
                }
            }
        }

        if payout > 0 {
            let mut node_account = StateManager::v_get_account(view, &challenge.target_node)?;
            node_account.balance = node_account.balance.saturating_add(payout as u128);
            StateManager::v_put_account(view, &challenge.target_node, &node_account)?;
        }

        // 800B correction: a successful PoR proof is REAL archive service — it
        // accrues protocol-earned credit (the payout) usable for 1:1 grant
        // unlock, and advances the archive milestone counter. Both are no-ops
        // until the supply correction is applied; nothing retroactive.
        {
            use crate::supply::SupplyStore;
            SupplyStore::accrue_earned_credit(
                view,
                &challenge.target_node,
                sumchain_primitives::supply::ServiceKind::Archive,
                payout as u128,
            )?;
            SupplyStore::record_por_proof(view, &challenge.target_node)?;
        }

        // 9. Delete the challenge from state
        Self::v_delete_challenge(view, &challenge)?;

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
    ///
    /// Issue #97 (Phase 1): the file/chunk candidate is selected identically in
    /// both modes. When `assignment_targeting` is `false` the `target_node` is
    /// drawn from all currently-active archives (exact legacy behavior). When
    /// `true`, the target is drawn only from the archives assigned to the
    /// selected chunk — under the file's latest assignment epoch snapshot — that
    /// are currently Active; if that set is empty the challenge is skipped
    /// (`Ok(None)`), so a bystander is never challenged or slashed.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_challenge(
        view: &mut ExecutionView<'_, '_>,
        parent_hash: &Hash,
        height: u64,
        archive_nodes: &[sumchain_primitives::NodeRecord],
        assignment_targeting: bool,
        replication_factor: u32,
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

        // Deterministic seed from parent hash. File and chunk selection consume
        // seed bytes [0..8] and [8..12] respectively; target selection [12..20].
        // Both gate modes use the same seed material so selection is replayable.
        let seed = Hash::hash_many(&[
            parent_hash.as_bytes(),
            b"storage_challenge",
            &height.to_be_bytes(),
        ]);
        let seed_bytes = seed.as_bytes();
        let seed_u64 = |from: usize| {
            u64::from_be_bytes([
                seed_bytes[from], seed_bytes[from + 1], seed_bytes[from + 2], seed_bytes[from + 3],
                seed_bytes[from + 4], seed_bytes[from + 5], seed_bytes[from + 6], seed_bytes[from + 7],
            ])
        };
        let seed_u32 = |from: usize| {
            u32::from_be_bytes([
                seed_bytes[from], seed_bytes[from + 1], seed_bytes[from + 2], seed_bytes[from + 3],
            ])
        };

        // Select the (file, chunk) candidate and its target. Below the gate the
        // file comes from the legacy V1 funded set and the target from all
        // active archives (byte-identical to the pre-#97 path). At/above the
        // gate the file comes from V2 funded+Active candidates and the target
        // from the chunk's assigned-active set (issue #97).
        let (selected_root, chunk_index, target_node) = if assignment_targeting {
            // File: one candidate from the V2 funded+Active set (deterministic
            // order). Empty ⇒ skip. Single-candidate sampling, not files×chunks.
            let candidates = Self::v_funded_active_v2_candidates(view)?;
            if candidates.is_empty() {
                debug!("No funded+Active V2 files — skipping challenge at height {}", height);
                return Ok(None);
            }
            let (root, chunk_count) = candidates[(seed_u64(0) % candidates.len() as u64) as usize];
            // `funded_active_v2_candidates` guarantees chunk_count > 0.
            let chunk_index = seed_u32(8) % chunk_count;

            // Target: assigned-active archive for the chunk under the file's
            // latest applicable assignment epoch. Empty ⇒ skip (no bystander).
            let target = match Self::v_select_assigned_active_target(
                view,
                &root,
                chunk_index,
                seed_u64(12), // byte-identical to the historical seed_bytes[12..20] pick
                replication_factor,
            )? {
                Some(addr) => addr,
                None => {
                    debug!(
                        "No assigned-active archive for file={} chunk={} — skipping challenge at height {}",
                        root, chunk_index, height
                    );
                    return Ok(None);
                }
            };
            (root, chunk_index, target)
        } else {
            // Legacy V1 path: funded roots, chunk count from total size, target
            // drawn from all currently-active archives.
            let eligible_roots = Self::v_get_funded_file_roots(view)?;
            if eligible_roots.is_empty() {
                debug!("No funded files — skipping challenge at height {}", height);
                return Ok(None);
            }
            let selected_root = eligible_roots[(seed_u64(0) % eligible_roots.len() as u64) as usize];
            let meta = match Self::v_get_metadata(view, &selected_root)? {
                Some(m) => m,
                None => return Ok(None), // Should not happen, but be safe
            };
            let chunk_count = (meta.total_size_bytes + CHUNK_SIZE - 1) / CHUNK_SIZE;
            if chunk_count == 0 {
                return Ok(None);
            }
            let chunk_index = seed_u32(8) % chunk_count as u32;
            let node_index = seed_u64(12) % active_nodes.len() as u64;
            (selected_root, chunk_index, active_nodes[node_index as usize].address)
        };

        // Compute deterministic challenge ID
        let challenge_id = Hash::hash_many(&[
            selected_root.as_bytes(),
            &chunk_index.to_be_bytes(),
            &height.to_be_bytes(),
        ]);

        let challenge = StorageChallenge {
            challenge_id,
            merkle_root: selected_root,
            chunk_index,
            target_node,
            created_at_height: height,
            expires_at_height: height + CHALLENGE_TTL_BLOCKS,
        };

        Self::v_put_challenge(view, &challenge)?;

        info!(
            "Storage challenge issued: id={}, file={}, chunk={}, node={}, expires={}",
            challenge_id, selected_root, chunk_index, target_node,
            height + CHALLENGE_TTL_BLOCKS
        );

        Ok(Some(challenge))
    }

    /// Issue #97 (Phase 1): deterministically choose the challenge target from
    /// the archives assigned to `chunk_index` of `merkle_root` that are
    /// currently Active.
    ///
    /// Resolution mirrors `compute_coverage_v2`'s epoch handling: the file's
    /// latest assignment epoch (epoch 0 = `assignment_height`, plus any #62
    /// reassignment heights, all ≤ current height) selects the archive snapshot;
    /// `assigned_archives_presorted` computes the assigned set for the chunk
    /// under that snapshot; the set is filtered to currently-Active archives.
    /// The target is picked from that set using `pick_seed % assigned_active.len()`,
    /// so selection is deterministic and replayable. The Phase-1 caller passes
    /// `u64::from_be_bytes(seed_bytes[12..20])` (byte-identical to the historical
    /// pick); the #100 scheduler passes a per-`(file, chunk)` derived seed.
    ///
    /// Returns `Ok(None)` when the file has no V2 assignment metadata, or when
    /// no assigned archive is currently Active — the caller then skips the
    /// challenge for this interval. Cost is `O(snapshot_len)` (one assignment
    /// computation for the single selected chunk); it never sweeps files×chunks.
    fn v_select_assigned_active_target(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
        chunk_index: u32,
        pick_seed: u64,
        replication_factor: u32,
    ) -> Result<Option<Address>> {
        // A funded file with no V2 assignment metadata has no assigned archives.
        let row = match Self::v_get_metadata_v2(view, merkle_root)? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Latest applicable assignment epoch and its active-archive snapshot.
        let epochs = Self::v_file_epochs(view, &row)?;
        let epoch = *epochs.last().expect("epoch 0 always present");
        let snapshot =
            NodeRegistryExecutor::v_get_active_archive_nodes_at_height(view, epoch)?;

        // Sorted + deduped addresses, as the deterministic assignment function
        // requires (same preparation as `compute_epoch_coverage`).
        let mut sorted_addrs: Vec<Address> = snapshot.iter().map(|n| n.address).collect();
        sorted_addrs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        sorted_addrs.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

        // Archives assigned to this chunk under the epoch snapshot, filtered to
        // those currently Active (deterministic order preserved).
        let assigned = sumchain_primitives::assigned_archives_presorted(
            merkle_root,
            &sorted_addrs,
            chunk_index,
            replication_factor,
        );
        let mut assigned_active: Vec<Address> = Vec::with_capacity(assigned.len());
        for addr in assigned {
            if v_is_currently_active(view, &addr)? {
                assigned_active.push(addr);
            }
        }
        if assigned_active.is_empty() {
            return Ok(None);
        }

        // Deterministic pick from the assigned-active set.
        let idx = pick_seed % assigned_active.len() as u64;
        Ok(Some(assigned_active[idx as usize]))
    }

    // =========================================================================
    // Issue #100 — challengeable-file index + bounded scheduler
    // =========================================================================

    /// Insert/refresh a file in the challengeable index. Value is the fixed
    /// 4-byte big-endian `chunk_count`.
    pub fn v_challengeable_index_insert(
        view: &mut ExecutionView<'_, '_>,
        merkle_root: &Hash,
        chunk_count: u32,
    ) -> Result<()> {
        view.put(
            CF_CHALLENGEABLE_FILES_V2,
            merkle_root.as_bytes(),
            &chunk_count.to_be_bytes(),
        )
        .map_err(StateError::Storage)
    }

    /// Remove a file from the challengeable index (e.g. `fee_pool` drained to 0).
    pub fn v_challengeable_index_remove(
        view: &mut ExecutionView<'_, '_>,
        merkle_root: &Hash,
    ) -> Result<()> {
        view.delete(CF_CHALLENGEABLE_FILES_V2, merkle_root.as_bytes())
            .map_err(StateError::Storage)
    }

    /// Sync a V2 row into the challengeable index: present iff it is
    /// [`challengeable`], absent otherwise. Called from the `ActivateFileV2` and
    /// V2-payout paths, and by the backfill.
    fn v_challengeable_index_sync(
        view: &mut ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
    ) -> Result<()> {
        if challengeable(row) {
            Self::v_challengeable_index_insert(view, &row.merkle_root, row.chunk_count)
        } else {
            Self::v_challengeable_index_remove(view, &row.merkle_root)
        }
    }

    /// Whether the one-time #100 backfill has already run, as this block's
    /// candidate sees it. The marker and the index rows it guards are staged
    /// together, so a block that runs the backfill does not run it twice.
    pub fn v_por_scheduler_backfill_done(view: &ExecutionView<'_, '_>) -> Result<bool> {
        Ok(view
            .get(CF_META, POR_SCHEDULER_BACKFILL_MARKER)
            .map_err(StateError::Storage)?
            .is_some())
    }

    /// One-time, idempotent backfill of the challengeable index from the V2
    /// metadata CF. This is the **only** full V2 scan and runs exactly once — the
    /// persisted marker in [`CF_META`] prevents any repeat. Returns `Ok(false)`
    /// if it was already done (no scan). Deterministic: the resulting index is a
    /// pure function of current V2 rows, independent of scan order.
    pub fn v_backfill_challengeable_index(view: &mut ExecutionView<'_, '_>) -> Result<bool> {
        if Self::v_por_scheduler_backfill_done(view)? {
            return Ok(false);
        }
        let prefix = [b'F', b'2'];
        // Collected before staging: the scan borrows the view immutably and the
        // index writes need it mutably. Collecting also keeps the backfill's
        // result a pure function of the rows present when it started.
        let mut to_index: Vec<(Hash, u32)> = Vec::new();
        for item in view
            .prefix_iter(CF_STORAGE_METADATA_V2, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan. A partial backfill that still wrote
            // its one-shot marker would leave the index permanently incomplete.
            let (key, value) = item.map_err(StateError::Storage)?;
            if !is_v2_row_key(&key) {
                continue;
            }
            let row = decode_metadata_v2(&value)?;
            if challengeable(&row) {
                to_index.push((row.merkle_root, row.chunk_count));
            }
        }
        for (root, chunk_count) in to_index {
            Self::v_challengeable_index_insert(view, &root, chunk_count)?;
        }
        view.put(CF_META, POR_SCHEDULER_BACKFILL_MARKER, &[1])
            .map_err(StateError::Storage)?;
        Ok(true)
    }

    /// Issue #100 (Phase 2): emit a bounded, deterministic set of assignment-aware
    /// challenges for interval height `height`. Samples ≤ `max_files` files from
    /// the challengeable index via a seeded stride-walk (`iter_from`, wrap-around),
    /// ≤ `max_chunks` chunks per file, resolves each `(file, chunk)` to an
    /// assigned-active target under the file's latest epoch, and writes up to
    /// `max_emit` challenges (identical shape to the single-challenge path).
    /// `(file, chunk)` pairs with no assigned-active archive are skipped. Stale
    /// index entries (file no longer challengeable) are removed and skipped.
    ///
    /// Cost is `O(max_files·(log n + max_chunks·R))` — independent of total files
    /// and chunks. Returns the emitted challenges (already persisted).
    #[allow(clippy::too_many_arguments)]
    pub fn generate_challenge_schedule(
        view: &mut ExecutionView<'_, '_>,
        parent_hash: &Hash,
        height: u64,
        replication_factor: u32,
        max_files: u32,
        max_chunks: u32,
        max_emit: u32,
    ) -> Result<Vec<StorageChallenge>> {
        let mut emitted: Vec<StorageChallenge> = Vec::new();
        if max_emit == 0 || max_files == 0 || max_chunks == 0 {
            return Ok(emitted);
        }
        let seed = Hash::hash_many(&[
            b"snip.por.schedule.v1",
            parent_hash.as_bytes(),
            &height.to_be_bytes(),
        ]);

        let mut seen_files: Vec<[u8; 32]> = Vec::new();
        let mut seen_pairs: Vec<([u8; 32], u32)> = Vec::new();

        'files: for i in 0..max_files {
            if emitted.len() as u32 >= max_emit {
                break;
            }
            // Seeded probe → first index entry at or after it (wrapping to start).
            let probe = Hash::hash_many(&[seed.as_bytes(), b"file", &i.to_be_bytes()]);
            let hit = match view
                .iter_from(CF_CHALLENGEABLE_FILES_V2, probe.as_bytes())
                .map_err(StateError::Storage)?
                .next()
            {
                Some(kv) => Some(kv),
                None => view
                    .iter(CF_CHALLENGEABLE_FILES_V2)
                    .map_err(StateError::Storage)?
                    .next(),
            };
            let (key, _val) = match hit {
                // A read error must not read as "index empty" — that would emit
                // a different challenge set from every other node.
                Some(kv) => kv.map_err(StateError::Storage)?,
                None => break, // index empty
            };
            if key.len() != 32 {
                continue;
            }
            let root = Hash::from_slice(&key).map_err(|e| StateError::DeserializationError(e.to_string()))?;
            let root_bytes: [u8; 32] = *root.as_bytes();
            if seen_files.iter().any(|f| f == &root_bytes) {
                continue;
            }
            seen_files.push(root_bytes);

            // Stale-index guard: re-read the authoritative V2 row. If the file is
            // no longer challengeable, heal the index and skip.
            let chunk_count = match Self::v_get_metadata_v2(view, &root)? {
                Some(r) if challengeable(&r) => r.chunk_count,
                _ => {
                    Self::v_challengeable_index_remove(view, &root)?;
                    continue 'files;
                }
            };

            for j in 0..max_chunks {
                if emitted.len() as u32 >= max_emit {
                    break 'files;
                }
                let chunk_seed = Hash::hash_many(&[seed.as_bytes(), root.as_bytes(), b"chunk", &j.to_be_bytes()]);
                let chunk_index =
                    u32::from_be_bytes(chunk_seed.as_bytes()[0..4].try_into().unwrap()) % chunk_count;
                if seen_pairs.iter().any(|(r, c)| r == &root_bytes && *c == chunk_index) {
                    continue;
                }
                seen_pairs.push((root_bytes, chunk_index));

                let pick = Hash::hash_many(&[seed.as_bytes(), root.as_bytes(), &chunk_index.to_be_bytes(), b"pick"]);
                let pick_seed = u64::from_be_bytes(pick.as_bytes()[0..8].try_into().unwrap());
                let target = match Self::v_select_assigned_active_target(
                    view, &root, chunk_index, pick_seed, replication_factor,
                )? {
                    Some(addr) => addr,
                    None => continue, // no assigned-active archive → skip, no bystander
                };

                let challenge_id = Hash::hash_many(&[
                    root.as_bytes(),
                    &chunk_index.to_be_bytes(),
                    &height.to_be_bytes(),
                ]);
                let challenge = StorageChallenge {
                    challenge_id,
                    merkle_root: root,
                    chunk_index,
                    target_node: target,
                    created_at_height: height,
                    expires_at_height: height + CHALLENGE_TTL_BLOCKS,
                };
                Self::v_put_challenge(view, &challenge)?;
                emitted.push(challenge);
            }
        }

        info!(
            "PoR scheduler emitted {} challenge(s) at height {} (files<= {}, chunks<= {}, cap {})",
            emitted.len(), height, max_files, max_chunks, max_emit
        );
        Ok(emitted)
    }

    // =========================================================================
    // Objective 5: Expired Challenge Detection (called from execute_block)
    // =========================================================================

    /// Find all challenges that have expired by `current_height`, as this
    /// block's candidate sees them.
    /// Scans the expiry index (E prefix, height in BE) for all entries
    /// where `expires_at_height <= current_height`.
    pub fn v_get_expired_challenges(
        view: &ExecutionView<'_, '_>,
        current_height: u64,
    ) -> Result<Vec<StorageChallenge>> {
        // Scan from E+0x0000000000000000 through E+current_height
        // The expiry index key is: [b'E', expires_at_height(8 BE), challenge_id(32)]
        let prefix = vec![b'E'];
        let mut ids = Vec::new();

        for item in view
            .prefix_iter(CF_ACTIVE_CHALLENGES, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan. Truncating it silently would skip
            // slashes that every other node performs.
            let (key, _) = item.map_err(StateError::Storage)?;
            // key = [b'E', 8 bytes height, 32 bytes challenge_id]
            let Some((expires_at, challenge_id)) = challenge_expiry_index_entry(&key)? else {
                continue;
            };
            if expires_at > current_height {
                // Since keys are BE-sorted, once we hit a height > current,
                // all remaining entries are also unexpired. Stop scanning.
                break;
            }
            ids.push(challenge_id);
        }

        let mut expired = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(challenge) = Self::v_get_challenge(view, &id)? {
                expired.push(challenge);
            }
        }

        Ok(expired)
    }

    // =========================================================================
    // StorageMetadata CRUD
    // =========================================================================

    /// Stage a V1 file row and its owner-index mirror into the candidate.
    ///
    /// Both writes move together, always: `get_by_owner` walks the index, so a
    /// candidate holding the row without the index would answer a different
    /// owner listing than the one it is about to publish.
    fn v_put_metadata(view: &mut ExecutionView<'_, '_>, meta: &StorageMetadata) -> Result<()> {
        let key = metadata_key(&meta.merkle_root);
        let value = encode_metadata(meta)?;
        view.put(CF_STORAGE_METADATA, &key, &value)
            .map_err(StateError::Storage)?;

        let idx_key = owner_index_key(&meta.owner, &meta.merkle_root);
        view.put(CF_STORAGE_METADATA, &idx_key, &[1])
            .map_err(StateError::Storage)?;

        Ok(())
    }

    /// A V1 file row as this block's candidate sees it.
    pub fn v_get_metadata(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
    ) -> Result<Option<StorageMetadata>> {
        let key = metadata_key(merkle_root);
        match view.get(CF_STORAGE_METADATA, &key).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_metadata(&data)?)),
            None => Ok(None),
        }
    }

    pub fn get_metadata(&self, merkle_root: &Hash) -> Result<Option<StorageMetadata>> {
        let key = metadata_key(merkle_root);
        match self.db.get(CF_STORAGE_METADATA, &key).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_metadata(&data)?)),
            None => Ok(None),
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
    #[allow(clippy::too_many_arguments)]
    pub fn execute_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &StorageMetadataV2TxData,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        // Fee is deducted up-front so failed validity checks still pay the fee.
        // This matches V1 behavior (deduct_fee, then execute branch).
        Self::deduct_fee(view, sender, fee, proposer)?;

        match &data.operation {
            StorageMetadataOperationV2::RegisterFilePendingV2 {
                merkle_root,
                plaintext_size_bytes,
                stored_size_bytes,
                chunk_count,
                fee_deposit,
                visibility,
                initial_access,
            } => Self::execute_register_file_pending_v2(
                view,
                sender,
                merkle_root,
                *plaintext_size_bytes,
                *stored_size_bytes,
                *chunk_count,
                *fee_deposit,
                *visibility,
                initial_access,
                block_height,
                chain_params,
            ),
            StorageMetadataOperationV2::AbandonFileV2 { merkle_root } => {
                Self::execute_abandon_file_v2(
                    view,
                    sender,
                    merkle_root,
                    block_height,
                    chain_params,
                )
            }
            StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root,
                chunk_indices,
            } => {
                // Reassignment routing only applies when the reassignment gate is
                // open; dormant → exactly the pre-#62 accept path.
                let reassignment_gate_open = matches!(
                    chain_params.archive_reassignment_enabled_from_height,
                    Some(h) if block_height >= h
                );
                Self::execute_accept_assignment_v2(
                    view,
                    sender,
                    merkle_root,
                    chunk_indices,
                    chain_params,
                    reassignment_gate_open,
                )
            }
            StorageMetadataOperationV2::ActivateFileV2 { merkle_root } => {
                Self::execute_activate_file_v2(
                    view,
                    sender,
                    merkle_root,
                    block_height,
                    chain_params,
                )
            }
            StorageMetadataOperationV2::AddAccessV2 { merkle_root, entry } => {
                Self::execute_add_access_v2(view, sender, merkle_root, entry, chain_params)
            }
            StorageMetadataOperationV2::RemoveAccessV2 {
                merkle_root,
                address,
            } => Self::execute_remove_access_v2(view, sender, merkle_root, address),
            StorageMetadataOperationV2::UpdateAccessV2 {
                merkle_root,
                address,
                new_entry,
            } => Self::execute_update_access_v2(
                view,
                sender,
                merkle_root,
                address,
                new_entry,
                chain_params,
            ),
            StorageMetadataOperationV2::ReassignChunksV2 { merkle_root } => {
                Self::execute_reassign_chunks_v2(
                    view,
                    sender,
                    merkle_root,
                    block_height,
                    chain_params,
                )
            }
        }
    }

    /// Plan v3.2 §3.5 AddAccessV2 — append one access entry to an Active file.
    /// Receipt code: 35.
    fn execute_add_access_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        entry: &AccessEntryV2,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match Self::v_get_metadata_v2(view, merkle_root)? {
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
        if let Err(reason) = v_check_access_entry_for_visibility(view, row.visibility, entry)? {
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
        Self::v_put_metadata_v2(view, &row)?;

        info!(
            "AddAccessV2: file={}, recipient={}",
            merkle_root, entry.address
        );
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.5 RemoveAccessV2 — drop one access entry from an Active file.
    fn execute_remove_access_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match Self::v_get_metadata_v2(view, merkle_root)? {
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
        Self::v_put_metadata_v2(view, &row)?;

        info!("RemoveAccessV2: file={}, removed={}", merkle_root, address);
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.5 UpdateAccessV2 — replace one access entry's bundle/expiry
    /// (rotation). The `new_entry.address` MUST equal the `address` argument
    /// (the entry whose key is rotated); we don't allow a single tx to also
    /// migrate the entry to a different address.
    #[allow(clippy::too_many_arguments)]
    fn execute_update_access_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        address: &Address,
        new_entry: &AccessEntryV2,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match Self::v_get_metadata_v2(view, merkle_root)? {
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
            v_check_access_entry_for_visibility(view, row.visibility, new_entry)?
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
        Self::v_put_metadata_v2(view, &row)?;

        info!("UpdateAccessV2: file={}, entry={}", merkle_root, address);
        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.6 AcceptAssignmentV2 — OR the supplied `chunk_indices` into
    /// the per-(file, archive) bitmap. Issue #62 makes this epoch-aware: an
    /// attestation targets the file's **latest** assignment epoch and writes to
    /// the matching CF (epoch 0 → `assignment_attestations_v2`; a reassignment
    /// epoch → `assignment_attestations_v2_epoch`). Receipt codes:
    /// * 33 — AcceptAssignmentV2 validity failure.
    /// * 335 — Active-file re-attestation with no reassignment epoch.
    #[allow(clippy::too_many_arguments)]
    fn execute_accept_assignment_v2(
        view: &mut ExecutionView<'_, '_>,
        signer: &Address,
        merkle_root: &Hash,
        chunk_indices: &[u32],
        chain_params: &ChainParams,
        reassignment_gate_open: bool,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        // 1. File must exist.
        let row = match Self::v_get_metadata_v2(view, merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    33,
                    "AcceptAssignmentV2: file not found",
                ));
            }
        };

        // Reassignment routing engages ONLY when the reassignment gate is open.
        // When dormant, this is exactly the pre-#62 path: Pending-only, epoch 0.
        // (Reassignment epochs cannot exist unless the gate was open, so this is
        // also the natural steady state on a chain that never activated #62.)
        let reassignments = Self::v_get_file_reassignments(view, merkle_root)?;
        let use_reassignment = reassignment_gate_open && !reassignments.is_empty();
        let target_epoch = if use_reassignment {
            *reassignments.last().expect("non-empty checked above")
        } else {
            row.assignment_height
        };

        // 2. Lifecycle gate.
        // - Pending: always acceptable.
        // - Active + gate open + reassignment epoch exists: re-attest to latest.
        // - Active + gate open + no reassignment epoch: 335.
        // - Active + gate dormant, or Abandoned: unchanged pre-#62 rejection (33).
        match row.lifecycle {
            FileLifecycleV2::Pending => {}
            FileLifecycleV2::Active if use_reassignment => {}
            FileLifecycleV2::Active if reassignment_gate_open => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    335,
                    "AcceptAssignmentV2: post-activation re-attestation requires an open reassignment epoch",
                ));
            }
            _ => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    33,
                    "AcceptAssignmentV2: file must be Pending",
                ));
            }
        }

        // 3. Per-tx cap. Enforced before snapshot lookup so a degenerate
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

        // 4. Resolve the snapshot at the TARGET epoch. Signer must be in that
        // snapshot AND currently Active.
        let snapshot =
            NodeRegistryExecutor::v_get_active_archive_nodes_at_height(view, target_epoch)?;
        if !snapshot
            .iter()
            .any(|n| n.address.as_bytes() == signer.as_bytes())
        {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: signer not in the target epoch's assignment snapshot",
            ));
        }
        // An `Unbonding` archive (issue #20) is exiting and must not take on new
        // assignments — reject explicitly so the reason is precise.
        let signer_status =
            NodeRegistryExecutor::v_get_node(view, signer)?.map(|rec| rec.status);
        if signer_status == Some(NodeStatus::Unbonding) {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: signer is unbonding and cannot accept new assignments",
            ));
        }
        let signer_currently_active = signer_status == Some(NodeStatus::Active);
        if !signer_currently_active {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                33,
                "AcceptAssignmentV2: signer is not currently Active",
            ));
        }

        // 5. Per-index validity: idx < chunk_count AND signer is in the
        // assigned set per the deterministic assignment function evaluated over
        // the TARGET epoch's snapshot. Any mismatch rejects the whole tx.
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
                        "AcceptAssignmentV2: chunk_index {} not assigned to signer in target epoch",
                        idx
                    ),
                ));
            }
        }

        // 6. OR the supplied indices into the per-(file, archive) bitmap for the
        // target epoch. Epoch 0 → the original CF (unchanged behavior); a
        // reassignment epoch → the epoch-aware CF. Lazy allocation on first accept.
        let bm_len = bitmap_byte_len(row.chunk_count);
        // One helper picks the column family and the key, for this write and for
        // every read of it — which is what keeps an attestation from being
        // written to the epoch-0 CF and looked for in the epoch CF, or the
        // reverse. It keys off `row.merkle_root`, which is the row stored under
        // `merkle_root`; they differ only if a row was written under a key that
        // disagrees with its own contents.
        debug_assert_eq!(&row.merkle_root, merkle_root);
        let (cf, key) = attestation_slot(&row, target_epoch, signer);
        // Read-modify-write: the bitmap OR must see a bitmap this same block
        // already widened, or two accepts in one block lose the earlier one.
        let mut bitmap = match view.get(cf, &key).map_err(StateError::Storage)? {
            Some(bytes) if bytes.len() == bm_len => bytes,
            _ => vec![0u8; bm_len],
        };
        for &idx in chunk_indices {
            bitmap_set(&mut bitmap, idx);
        }
        view.put(cf, &key, &bitmap).map_err(StateError::Storage)?;

        debug!(
            "AcceptAssignmentV2: archive {} attested {} chunks for {} at epoch {} (popcount={})",
            signer,
            chunk_indices.len(),
            merkle_root,
            target_epoch,
            bitmap_popcount(&bitmap)
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan v3.2 §3.6 ActivateFileV2 — Pending → Active transition gated on
    /// full-coverage of every chunk by at least one snapshot-active archive's
    /// attestation bitmap.
    fn execute_activate_file_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match Self::v_get_metadata_v2(view, merkle_root)? {
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

        // Coverage check. Aggregate the attestation bitmaps of every
        // currently-Active archive across epoch 0 AND all reassignment epochs
        // (issue #62), and require every chunk index in `[0, chunk_count)` to be
        // set. Inactive (Slashed/Unbonding/Withdrawn) archives' bitmaps are
        // excluded. For a file with no reassignment this is exactly the
        // pre-#62 epoch-0 union.
        let union = Self::v_aggregate_coverage_union(view, &row)?;
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
        Self::v_put_metadata_v2(view, &row)?;

        // Issue #100: a now-Active funded file becomes challengeable — index it
        // for the bounded scheduler. Harmless (and unread) while the scheduler
        // gate is dormant; keeps the index complete once activated.
        Self::v_challengeable_index_sync(view, &row)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        plaintext_size_bytes: u64,
        stored_size_bytes: u64,
        chunk_count: u32,
        fee_deposit: u64,
        visibility_byte: u8,
        initial_access: &[AccessEntryV2],
        block_height: u64,
        chain_params: &ChainParams,
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
                    let has_key =
                        NodeRegistryExecutor::v_get_encryption_pubkey(view, &entry.address)?
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
        if Self::v_get_metadata_v2(view, merkle_root)?.is_some() {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "merkle_root already registered as V2 file",
            ));
        }
        if Self::v_get_metadata(view, merkle_root)?.is_some() {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                30,
                "merkle_root already registered as V1 file",
            ));
        }

        // 5. Lock fee_deposit into fee_pool. Sender's nonce was already
        // incremented inside deduct_fee; the deposit is a separate balance
        // movement.
        if fee_deposit > 0 {
            let sender_balance = StateManager::v_get_balance(view, sender)?;
            if sender_balance < fee_deposit as u128 {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    30,
                    "insufficient balance for fee_deposit",
                ));
            }
            let mut sender_account = StateManager::v_get_account(view, sender)?;
            sender_account.balance = sender_account.balance.saturating_sub(fee_deposit as u128);
            StateManager::v_put_account(view, sender, &sender_account)?;
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
        Self::v_put_metadata_v2(view, &row)?;

        info!(
            "V2 file registered Pending: merkle_root={}, owner={}, chunks={}, deposit={}",
            merkle_root, sender, chunk_count, fee_deposit
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// Plan §3.5 AbandonFileV2 — refund (1 - abandonment_fee_percent/100) of
    /// `fee_pool` to owner, retain remainder, transition Pending → Abandoned.
    fn execute_abandon_file_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let mut row = match Self::v_get_metadata_v2(view, merkle_root)? {
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
            let mut owner_account = StateManager::v_get_account(view, sender)?;
            owner_account.balance = owner_account.balance.saturating_add(refund as u128);
            StateManager::v_put_account(view, sender, &owner_account)?;
        }

        // TODO(supply-leak): `retain` is neither credited to any account nor
        // routed to the burn sink — it is destroyed when `fee_pool` is zeroed
        // below. This is a genuine native-Koppa sink: economic supply drops by
        // `retain`, and the 800B supply correction currently restores that lost
        // value into the ProtocolReserve via a larger reserve delta (see
        // `StorageMetadataExecutor::total_fee_pools` / `native_supply_snapshot`).
        // Fix in a separate PR: either credit `retain` to `Address::ZERO`
        // (explicit burn, kept inside canonical) or to a protocol pool. Do NOT
        // fold that fix into the supply-correction PR.
        row.fee_pool = 0;
        row.lifecycle = FileLifecycleV2::Abandoned;
        row.abandoned_at_height = Some(block_height);
        Self::v_put_metadata_v2(view, &row)?;

        info!(
            "V2 file abandoned: merkle_root={}, owner={}, refund={}, retained={}",
            merkle_root, sender, refund, retain
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    /// [`Self::get_attestation_bitmap_v2`] over the candidate: the epoch-0
    /// bitmap as this block staged it — including bits a `AcceptAssignmentV2`
    /// earlier in the same block set.
    ///
    /// The epoch-aware read production uses is
    /// [`Self::v_get_attestation_bitmap`], which routes through
    /// [`attestation_slot`]; this is the flat epoch-0 shape, the candidate twin
    /// of the public committed reader.
    pub fn v_get_attestation_bitmap_v2(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
        archive: &Address,
    ) -> Result<Option<Vec<u8>>> {
        let key = attestation_v2_key(merkle_root, archive);
        view.get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key)
            .map_err(StateError::Storage)
    }

    /// Public read of a per-(file, archive) attestation bitmap. Returns `None`
    /// if no row exists yet (first attestation lazily allocates).
    pub fn get_attestation_bitmap_v2(
        &self,
        merkle_root: &Hash,
        archive: &Address,
    ) -> Result<Option<Vec<u8>>> {
        let key = attestation_v2_key(merkle_root, archive);
        self.db
            .get(CF_ASSIGNMENT_ATTESTATIONS_V2, &key)
            .map_err(StateError::Storage)
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

        // Issue #62: compute coverage per epoch, then aggregate. Epoch 0
        // (`assignment_height`) is always present; reassignment heights follow.
        let epochs = self.file_epochs(&row)?;
        let latest_assignment_epoch = *epochs.last().expect("epoch 0 always present");
        let bm_len = bitmap_byte_len(row.chunk_count);
        let mut agg_union = vec![0u8; bm_len];
        let mut per_epoch: Vec<EpochCoverageEntry> = Vec::with_capacity(epochs.len());
        for &epoch in &epochs {
            let (entry, epoch_union) =
                self.compute_epoch_coverage(&row, epoch, node_registry, replication_factor)?;
            bitmap_or_into(&mut agg_union, &epoch_union);
            per_epoch.push(entry);
        }

        // Top-level `per_archive` stays epoch-0-only for backward-compatibility.
        let per_archive = per_epoch
            .first()
            .map(|e| e.per_archive.clone())
            .unwrap_or_default();
        let reassignment_needed = self.reassignment_needed(&row, node_registry)?;

        Ok(Some(CoverageSummaryV2 {
            chunk_count: row.chunk_count,
            covered_count: bitmap_popcount(&agg_union),
            lifecycle: row.lifecycle,
            assignment_height: row.assignment_height,
            replication_factor,
            union: agg_union,
            per_archive,
            assignment_epochs: epochs,
            latest_assignment_epoch,
            reassignment_needed,
            per_epoch,
        }))
    }

    // ── Reassignment (issue #62) ─────────────────────────────────────────────

    /// Compute one epoch's coverage entry and its (currently-Active) attestation
    /// union. Shared by [`Self::compute_coverage_v2`].
    fn compute_epoch_coverage(
        &self,
        row: &StorageMetadataV2,
        epoch: u64,
        node_registry: &NodeRegistryExecutor,
        replication_factor: u32,
    ) -> Result<(EpochCoverageEntry, Vec<u8>)> {
        let snapshot = node_registry.get_active_archive_nodes_at_height(epoch)?;
        let mut gathered: Vec<(Address, bool, Option<Vec<u8>>)> =
            Vec::with_capacity(snapshot.len());
        for node in &snapshot {
            gathered.push((
                node.address,
                is_currently_active(node_registry, &node.address)?,
                self.get_attestation_bitmap(row, epoch, &node.address)?,
            ));
        }
        Ok(epoch_coverage_from(row, epoch, &gathered, replication_factor))
    }

    /// [`Self::compute_epoch_coverage`] over the candidate.
    ///
    /// `#[cfg(test)]` and crate-visible, deliberately. Production coverage
    /// decisions go through [`Self::v_aggregate_coverage_union`] and
    /// [`Self::v_reassignment_needed`] — that is everything the activation and
    /// reassignment gates need. The FULL summary is an RPC shape with no
    /// execution caller, so shipping a candidate variant of it would be adding
    /// public surface for a test. This exists only so a same-block test inside
    /// this crate can ask that shape about rows the block staged rather than
    /// about the parent's, and it shares
    /// [`epoch_coverage_from`] with the committed reader so the two cannot
    /// disagree.
    #[cfg(test)]
    pub(crate) fn v_compute_epoch_coverage(
        view: &ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
        epoch: u64,
        replication_factor: u32,
    ) -> Result<(EpochCoverageEntry, Vec<u8>)> {
        let snapshot = NodeRegistryExecutor::v_get_active_archive_nodes_at_height(view, epoch)?;
        let mut gathered: Vec<(Address, bool, Option<Vec<u8>>)> =
            Vec::with_capacity(snapshot.len());
        for node in &snapshot {
            gathered.push((
                node.address,
                v_is_currently_active(view, &node.address)?,
                Self::v_get_attestation_bitmap(view, row, epoch, &node.address)?,
            ));
        }
        Ok(epoch_coverage_from(row, epoch, &gathered, replication_factor))
    }
}

/// Assemble one epoch's coverage entry from rows already read.
///
/// Pure: the candidate and committed drivers above differ only in where
/// `gathered` came from, so the arithmetic that turns bitmaps into coverage —
/// which bitmaps join the union, what `attested_count` means, how
/// `assigned_count` is computed and capped — exists once.
fn epoch_coverage_from(
    row: &StorageMetadataV2,
    epoch: u64,
    gathered: &[(Address, bool, Option<Vec<u8>>)],
    replication_factor: u32,
) -> (EpochCoverageEntry, Vec<u8>) {
    let bm_len = bitmap_byte_len(row.chunk_count);
    let mut union = vec![0u8; bm_len];
    let mut per_archive: Vec<ArchivePerEntry> = Vec::with_capacity(gathered.len());

    for (archive, currently_active, bitmap) in gathered {
        let attested_count = match bitmap {
            Some(bm) if bm.len() == bm_len => {
                if *currently_active {
                    bitmap_or_into(&mut union, bm);
                }
                bitmap_popcount(bm)
            }
            _ => 0,
        };
        per_archive.push(ArchivePerEntry {
            archive: *archive,
            attested_count,
            currently_active: *currently_active,
            assigned_count: None,
        });
    }
    {
        let snapshot: Vec<Address> = gathered.iter().map(|(a, _, _)| *a).collect();

        // Per-archive `assigned_count` for THIS epoch's snapshot, under the cap.
        if row.chunk_count <= MAX_ASSIGNED_COUNT_CHUNK_COUNT {
            let mut sorted_addrs: Vec<Address> = snapshot.clone();
            sorted_addrs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            sorted_addrs.dedup_by(|a, b| a.as_bytes() == b.as_bytes());

            let mut counts: Vec<u32> = vec![0u32; per_archive.len()];
            for chunk_idx in 0..row.chunk_count {
                let assigned = sumchain_primitives::assigned_archives_presorted(
                    &row.merkle_root,
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
    }

    let entry = EpochCoverageEntry {
        epoch_height: epoch,
        is_epoch_zero: epoch == row.assignment_height,
        covered_count: bitmap_popcount(&union),
        per_archive,
    };
    (entry, union)
}

impl StorageMetadataExecutor {

    /// Read a file's reassignment epoch heights (issue #62). Empty ⇒ epoch-0-only
    /// (every pre-#62 file). Public so the coverage RPC / clients can read it.
    /// A file's reassignment epoch heights as this block's candidate sees them.
    pub fn v_get_file_reassignments(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
    ) -> Result<Vec<u64>> {
        match view
            .get(CF_FILE_REASSIGNMENTS, &file_reassignments_key(merkle_root))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_epochs(&bytes),
            None => Ok(Vec::new()),
        }
    }

    pub fn get_file_reassignments(&self, merkle_root: &Hash) -> Result<Vec<u64>> {
        match self
            .db
            .get(CF_FILE_REASSIGNMENTS, &file_reassignments_key(merkle_root))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_epochs(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn v_put_file_reassignments(
        view: &mut ExecutionView<'_, '_>,
        merkle_root: &Hash,
        epochs: &[u64],
    ) -> Result<()> {
        let value = encode_epochs(epochs)?;
        view.put(
            CF_FILE_REASSIGNMENTS,
            &file_reassignments_key(merkle_root),
            &value,
        )
        .map_err(StateError::Storage)
    }

    /// Full epoch list for a file as the candidate sees it, ascending:
    /// `[assignment_height, ...reassign]`. Always non-empty (epoch 0 =
    /// `assignment_height`).
    fn v_file_epochs(
        view: &ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
    ) -> Result<Vec<u64>> {
        let mut epochs = vec![row.assignment_height];
        epochs.extend(Self::v_get_file_reassignments(view, &row.merkle_root)?);
        Ok(epochs)
    }

    /// Full epoch list for a file, ascending: `[assignment_height, ...reassign]`.
    /// Always non-empty (epoch 0 = `assignment_height`).
    fn file_epochs(&self, row: &StorageMetadataV2) -> Result<Vec<u64>> {
        let mut epochs = vec![row.assignment_height];
        epochs.extend(self.get_file_reassignments(&row.merkle_root)?);
        Ok(epochs)
    }

    /// The coverage summary [`Self::compute_coverage_v2`] reports, computed over
    /// the candidate. `#[cfg(test)]` for the reason given on
    /// [`Self::v_compute_epoch_coverage`].
    #[cfg(test)]
    pub(crate) fn v_compute_coverage_v2(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
        replication_factor: u32,
    ) -> Result<Option<CoverageSummaryV2>> {
        let row = match Self::v_get_metadata_v2(view, merkle_root)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let epochs = Self::v_file_epochs(view, &row)?;
        let latest_assignment_epoch = *epochs.last().expect("epoch 0 always present");
        let mut agg_union = vec![0u8; bitmap_byte_len(row.chunk_count)];
        let mut per_epoch: Vec<EpochCoverageEntry> = Vec::with_capacity(epochs.len());
        for &epoch in &epochs {
            let (entry, epoch_union) =
                Self::v_compute_epoch_coverage(view, &row, epoch, replication_factor)?;
            bitmap_or_into(&mut agg_union, &epoch_union);
            per_epoch.push(entry);
        }
        let per_archive = per_epoch
            .first()
            .map(|e| e.per_archive.clone())
            .unwrap_or_default();
        let reassignment_needed = Self::v_reassignment_needed(view, &row)?;
        Ok(Some(CoverageSummaryV2 {
            chunk_count: row.chunk_count,
            covered_count: bitmap_popcount(&agg_union),
            lifecycle: row.lifecycle,
            assignment_height: row.assignment_height,
            replication_factor,
            union: agg_union,
            per_archive,
            assignment_epochs: epochs,
            latest_assignment_epoch,
            reassignment_needed,
            per_epoch,
        }))
    }

    /// [`Self::list_pushable_files_v2`] over the candidate. `#[cfg(test)]` and
    /// crate-visible: the pushable list backs an RPC, not execution, so this
    /// exists only for the same-block test of that shape.
    #[cfg(test)]
    pub(crate) fn v_list_pushable_files_v2(
        view: &ExecutionView<'_, '_>,
    ) -> Result<Vec<StorageMetadataV2>> {
        let mut out = Vec::new();
        let prefix = [b'F', b'2'];
        for item in view
            .prefix_iter(CF_STORAGE_METADATA_V2, &prefix)
            .map_err(StateError::Storage)?
        {
            let (key, value) = item.map_err(StateError::Storage)?;
            if !is_v2_row_key(&key) {
                continue;
            }
            let row = decode_metadata_v2(&value)?;
            if matches!(row.lifecycle, FileLifecycleV2::Pending | FileLifecycleV2::Active) {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Read the (file, archive) attestation bitmap for a given epoch from the
    /// candidate — including one written by an earlier tx of the same block.
    pub(crate) fn v_get_attestation_bitmap(
        view: &ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
        epoch: u64,
        archive: &Address,
    ) -> Result<Option<Vec<u8>>> {
        let (cf, key) = attestation_slot(row, epoch, archive);
        view.get(cf, &key).map_err(StateError::Storage)
    }

    /// Read the (file, archive) attestation bitmap for a given epoch, from the
    /// epoch-0 CF or the reassignment-epoch CF as appropriate.
    fn get_attestation_bitmap(
        &self,
        row: &StorageMetadataV2,
        epoch: u64,
        archive: &Address,
    ) -> Result<Option<Vec<u8>>> {
        let (cf, key) = attestation_slot(row, epoch, archive);
        self.db.get(cf, &key).map_err(StateError::Storage)
    }

    /// Aggregate coverage union across all epochs — OR the bitmaps of every
    /// currently-Active archive in each epoch's snapshot. For a file with no
    /// reassignment this equals the epoch-0 union exactly.
    pub(crate) fn v_aggregate_coverage_union(
        view: &ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
    ) -> Result<Vec<u8>> {
        let bm_len = bitmap_byte_len(row.chunk_count);
        let mut union = vec![0u8; bm_len];
        for epoch in Self::v_file_epochs(view, row)? {
            let snapshot =
                NodeRegistryExecutor::v_get_active_archive_nodes_at_height(view, epoch)?;
            for node in &snapshot {
                if !v_is_currently_active(view, &node.address)? {
                    continue;
                }
                if let Some(bm) = Self::v_get_attestation_bitmap(view, row, epoch, &node.address)?
                {
                    if bm.len() == bm_len {
                        bitmap_or_into(&mut union, &bm);
                    }
                }
            }
        }
        Ok(union)
    }

    /// Issue #62 gap predicate. `true` iff an archive from the LATEST epoch's
    /// assignment snapshot has since left the active set (exit / slash / unbond)
    /// — the only condition under which `ReassignChunksV2` is accepted. After a
    /// reassignment the latest snapshot is all-Active, so this returns `false`,
    /// which rejects no-op epoch churn.
    fn v_reassignment_needed(
        view: &ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
    ) -> Result<bool> {
        let epochs = Self::v_file_epochs(view, row)?;
        let latest = *epochs.last().expect("epoch 0 always present");
        let latest_snapshot =
            NodeRegistryExecutor::v_get_active_archive_nodes_at_height(view, latest)?;
        for node in &latest_snapshot {
            if !v_is_currently_active(view, &node.address)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Committed twin of [`Self::v_reassignment_needed`], for the coverage RPC.
    fn reassignment_needed(
        &self,
        row: &StorageMetadataV2,
        node_registry: &NodeRegistryExecutor,
    ) -> Result<bool> {
        let epochs = self.file_epochs(row)?;
        let latest = *epochs.last().expect("epoch 0 always present");
        let latest_snapshot = node_registry.get_active_archive_nodes_at_height(latest)?;
        for node in &latest_snapshot {
            if !is_currently_active(node_registry, &node.address)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `ReassignChunksV2` (issue #62). Owner-triggered epoch advance. The
    /// reassignment activation gate is enforced at the dispatch layer (→ 330, no
    /// fee) before this runs; here the fee is already deducted, so semantic
    /// failures charge the fee (existing V2 policy). Receipt codes 331–334.
    fn execute_reassign_chunks_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        merkle_root: &Hash,
        block_height: u64,
        _chain_params: &ChainParams,
    ) -> Result<StorageMetadataV2ExecutionResult> {
        let row = match Self::v_get_metadata_v2(view, merkle_root)? {
            Some(r) => r,
            None => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    331,
                    "ReassignChunksV2: file not found",
                ));
            }
        };
        if row.owner != *sender {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                332,
                "ReassignChunksV2: signer is not the file owner",
            ));
        }
        match row.lifecycle {
            FileLifecycleV2::Pending | FileLifecycleV2::Active => {}
            FileLifecycleV2::Abandoned => {
                return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                    333,
                    "ReassignChunksV2: Abandoned files cannot be reassigned",
                ));
            }
        }
        if !Self::v_reassignment_needed(view, &row)? {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                334,
                "ReassignChunksV2: no reassignment needed (no coverage gap)",
            ));
        }

        let mut epochs = Self::v_get_file_reassignments(view, merkle_root)?;
        // Anti-churn: never append a duplicate epoch within the same block.
        if epochs.last() == Some(&block_height) {
            return Ok(StorageMetadataV2ExecutionResult::fail_with_code(
                334,
                "ReassignChunksV2: file already reassigned at this height",
            ));
        }
        epochs.push(block_height);
        Self::v_put_file_reassignments(view, merkle_root, &epochs)?;

        info!(
            "ReassignChunksV2: file {} advanced to reassignment epoch {}",
            merkle_root, block_height
        );

        Ok(StorageMetadataV2ExecutionResult::ok())
    }

    // ── V2 row CRUD ─────────────────────────────────────────────────────────

    /// Stage a V2 file row and its owner-index mirror into the candidate. Both
    /// writes move together — see [`Self::v_put_metadata`].
    fn v_put_metadata_v2(
        view: &mut ExecutionView<'_, '_>,
        row: &StorageMetadataV2,
    ) -> Result<()> {
        let key = metadata_v2_key(&row.merkle_root);
        let value = encode_metadata_v2(row)?;
        view.put(CF_STORAGE_METADATA_V2, &key, &value)
            .map_err(StateError::Storage)?;

        let idx = owner_v2_index_key(&row.owner, &row.merkle_root);
        view.put(CF_STORAGE_METADATA_V2, &idx, &[1])
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
            if !is_v2_row_key(&key) {
                continue;
            }
            let row = decode_metadata_v2(&value)?;
            if matches!(row.lifecycle, FileLifecycleV2::Pending | FileLifecycleV2::Active) {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Issue #97 (Phase 1): compact index of *challengeable* V2 files — those
    /// that are funded (`fee_pool > 0`), `Active`, and have a valid
    /// `chunk_count > 0`. Returns `(merkle_root, chunk_count)` pairs sorted by
    /// root for deterministic, consensus-safe selection, without cloning the
    /// full rows. `O(V2 file count)`; the single-challenge path samples one
    /// candidate from this list, never files×chunks.
    pub fn v_funded_active_v2_candidates(
        view: &ExecutionView<'_, '_>,
    ) -> Result<Vec<(Hash, u32)>> {
        let mut out: Vec<(Hash, u32)> = Vec::new();
        let prefix = [b'F', b'2'];
        for item in view
            .prefix_iter(CF_STORAGE_METADATA_V2, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan: the challenge sampled from this list
            // is consensus, so a truncated list is a divergence.
            let (key, value) = item.map_err(StateError::Storage)?;
            // Row keys are exactly `[b'F', b'2', hash(32)]` (34 bytes); skip
            // owner-index keys `[b'O', b'2', ...]` sharing the CF.
            if !is_v2_row_key(&key) {
                continue;
            }
            let row = decode_metadata_v2(&value)?;
            if challengeable(&row) {
                out.push((row.merkle_root, row.chunk_count));
            }
        }
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        Ok(out)
    }

    /// Committed twin of [`Self::v_funded_active_v2_candidates`].
    pub fn funded_active_v2_candidates(&self) -> Result<Vec<(Hash, u32)>> {
        let mut out: Vec<(Hash, u32)> = Vec::new();
        let prefix = [b'F', b'2'];
        for (key, value) in self
            .db
            .prefix_iter(CF_STORAGE_METADATA_V2, &prefix)
            .map_err(StateError::Storage)?
        {
            if !is_v2_row_key(&key) {
                continue;
            }
            let row = decode_metadata_v2(&value)?;
            if challengeable(&row) {
                out.push((row.merkle_root, row.chunk_count));
            }
        }
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        Ok(out)
    }

    /// Σ every native-Koppa `fee_pool` held in storage metadata, as
    /// `(v1_total, v2_total)`, with checked u128 addition. Deterministic full
    /// scans of the two metadata CFs (both are mixed-key-family — data rows plus
    /// owner-index rows — so each row is guarded by the same `[b'F']` /
    /// `[b'F', b'2']` key-tag filters the challenge-selection paths use, and any
    /// other key family is skipped). Summed across **all** lifecycles: funded
    /// Pending/Active rows hold real Koppa; Abandoned rows carry `fee_pool == 0`
    /// (set at abandon) and contribute nothing. Tolerates empty CFs (returns
    /// `(0, 0)`). One-time supply census + `chain_getSupplyInfo` only.
    ///
    /// NOTE (follow-up, not this PR): `execute_abandon_file_v2` retains
    /// `fee_pool * abandonment_fee_percent / 100` and zeroes the row without
    /// crediting or burning the retained amount — a genuine native-Koppa sink.
    /// That leaked value is therefore NOT present in any counted bucket, so the
    /// census under-counts by exactly the leaked total and the supply correction
    /// restores it into the ProtocolReserve via a larger reserve delta. The leak
    /// itself is tracked for a separate fix (see the abandon path).
    /// Σ every native-Koppa `fee_pool` held in storage metadata as **this
    /// block's candidate** sees it, as `(v1_total, v2_total)`.
    ///
    /// This is the total the supply census must use: a block that registers a
    /// file, tops one up, settles a PoR payout or abandons a file changes the
    /// fee-pool bucket it is about to publish, and a census taken from committed
    /// state would measure the parent's.
    ///
    /// Same accounting rules as the committed twin below, and the same row
    /// filters and checked accumulation ([`is_v1_row_key`], [`is_v2_row_key`],
    /// [`add_fee_pool`]).
    pub fn v_total_fee_pools(view: &ExecutionView<'_, '_>) -> Result<(u128, u128)> {
        let mut v1: u128 = 0;
        for item in view.iter(CF_STORAGE_METADATA).map_err(StateError::Storage)? {
            // A read error ends the scan: a short census would under-report
            // supply and the correction would reserve the wrong delta.
            let (key, value) = item.map_err(StateError::Storage)?;
            if is_v1_row_key(&key) {
                v1 = add_fee_pool(v1, decode_metadata(&value)?.fee_pool, "V1")?;
            }
        }
        let mut v2: u128 = 0;
        for item in view.iter(CF_STORAGE_METADATA_V2).map_err(StateError::Storage)? {
            let (key, value) = item.map_err(StateError::Storage)?;
            if is_v2_row_key(&key) {
                v2 = add_fee_pool(v2, decode_metadata_v2(&value)?.fee_pool, "V2")?;
            }
        }
        Ok((v1, v2))
    }

    /// Committed twin of [`Self::v_total_fee_pools`], for `chain_getSupplyInfo`
    /// diagnostics.
    pub fn total_fee_pools(&self) -> Result<(u128, u128)> {
        let mut v1: u128 = 0;
        for (key, value) in self.db.iter(CF_STORAGE_METADATA).map_err(StateError::Storage)? {
            // V1 file rows are `[b'F', merkle_root(32)]` (>= 33 bytes). Owner-index
            // (`[b'O', ...]`) and other families in this CF are skipped.
            if is_v1_row_key(&key) {
                v1 = add_fee_pool(v1, decode_metadata(&value)?.fee_pool, "V1")?;
            }
        }
        let mut v2: u128 = 0;
        for (key, value) in self.db.iter(CF_STORAGE_METADATA_V2).map_err(StateError::Storage)? {
            // V2 file rows are exactly `[b'F', b'2', hash(32)]` (34 bytes).
            if is_v2_row_key(&key) {
                v2 = add_fee_pool(v2, decode_metadata_v2(&value)?.fee_pool, "V2")?;
            }
        }
        Ok((v1, v2))
    }

    /// A V2 file row as this block's candidate sees it — including one written
    /// by an earlier transaction of the same block.
    pub fn v_get_metadata_v2(
        view: &ExecutionView<'_, '_>,
        merkle_root: &Hash,
    ) -> Result<Option<StorageMetadataV2>> {
        let key = metadata_v2_key(merkle_root);
        match view
            .get(CF_STORAGE_METADATA_V2, &key)
            .map_err(StateError::Storage)?
        {
            Some(data) => Ok(Some(decode_metadata_v2(&data)?)),
            None => Ok(None),
        }
    }

    /// Look up a V2 file row by its merkle_root.
    pub fn get_metadata_v2(&self, merkle_root: &Hash) -> Result<Option<StorageMetadataV2>> {
        let key = metadata_v2_key(merkle_root);
        match self
            .db
            .get(CF_STORAGE_METADATA_V2, &key)
            .map_err(StateError::Storage)?
        {
            Some(data) => Ok(Some(decode_metadata_v2(&data)?)),
            None => Ok(None),
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
            if let Some(hash) = owner_index_root(&key)? {
                if let Some(meta) = self.get_metadata(&hash)? {
                    files.push(meta);
                }
            }
        }

        Ok(files)
    }

    /// Sorted merkle roots of all V1 files with `fee_pool > 0`, as this block's
    /// candidate sees them. Used by challenge generation to select eligible
    /// files, so it must include a file funded earlier in the same block.
    pub fn v_get_funded_file_roots(view: &ExecutionView<'_, '_>) -> Result<Vec<Hash>> {
        let prefix = vec![b'F'];
        let mut roots = Vec::new();

        for item in view
            .prefix_iter(CF_STORAGE_METADATA, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan: challenge selection samples from this
            // list, and a truncated list selects a different file.
            let (key, value) = item.map_err(StateError::Storage)?;
            if is_v1_row_key(&key) {
                let meta = decode_metadata(&value)?;
                if meta.fee_pool > 0 {
                    roots.push(meta.merkle_root);
                }
            }
        }

        // Sort for deterministic ordering across all nodes
        roots.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(roots)
    }

    /// Get sorted merkle roots of all files with fee_pool > 0.
    /// Committed twin of [`Self::v_get_funded_file_roots`], for RPC.
    pub fn get_funded_file_roots(&self) -> Result<Vec<Hash>> {
        let prefix = vec![b'F'];
        let mut roots = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_STORAGE_METADATA, &prefix)
            .map_err(StateError::Storage)?
            .collect();

        for (key, value) in entries {
            if is_v1_row_key(&key) {
                let meta = decode_metadata(&value)?;
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
    /// Open challenges against a node as this block's candidate sees them.
    ///
    /// This is the `BeginUnstake` gate: a challenge issued earlier in the same
    /// block must block the unbond, and a challenge settled earlier in the same
    /// block must not.
    pub fn v_get_challenges_by_node(
        view: &ExecutionView<'_, '_>,
        target_node: &Address,
    ) -> Result<Vec<StorageChallenge>> {
        let mut prefix = Vec::with_capacity(21);
        prefix.push(b'N');
        prefix.extend_from_slice(target_node.as_bytes());

        let mut ids = Vec::new();
        for item in view
            .prefix_iter(CF_ACTIVE_CHALLENGES, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan: an under-reported challenge set would
            // let an archive unbond out of an open challenge.
            let (key, _) = item.map_err(StateError::Storage)?;
            if let Some(id) = challenge_node_index_id(&key)? {
                ids.push(id);
            }
        }

        let mut challenges = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(challenge) = Self::v_get_challenge(view, &id)? {
                challenges.push(challenge);
            }
        }
        Ok(challenges)
    }

    pub fn get_challenges_by_node(&self, target_node: &Address) -> Result<Vec<StorageChallenge>> {
        let mut prefix = Vec::with_capacity(21);
        prefix.push(b'N');
        prefix.extend_from_slice(target_node.as_bytes());

        let mut challenges = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_ACTIVE_CHALLENGES, &prefix)
            .map_err(StateError::Storage)?
            .collect();

        for (key, _) in entries {
            // key = [b'N'(1), target_node(20), challenge_id(32)] = 53 bytes
            if let Some(challenge_id) = challenge_node_index_id(&key)? {
                if let Some(challenge) = self.get_challenge(&challenge_id)? {
                    challenges.push(challenge);
                }
            }
        }

        Ok(challenges)
    }

    /// Stage a challenge and both of its indexes into the candidate.
    ///
    /// All three keys move together. The node index answers "does this archive
    /// have an open challenge?", which gates `BeginUnstake` in the same block;
    /// the expiry index is what the next block's slashing scan walks. A
    /// candidate that staged the row without them would let an archive unbond
    /// out of a challenge issued moments earlier in the same block.
    pub fn v_put_challenge(
        view: &mut ExecutionView<'_, '_>,
        challenge: &StorageChallenge,
    ) -> Result<()> {
        let value = encode_challenge(challenge)?;

        // Primary key: C + challenge_id
        let pk = challenge_key(&challenge.challenge_id);
        view.put(CF_ACTIVE_CHALLENGES, &pk, &value)
            .map_err(StateError::Storage)?;

        // Node index: N + target_node + challenge_id
        let nk = challenge_node_index_key(&challenge.target_node, &challenge.challenge_id);
        view.put(CF_ACTIVE_CHALLENGES, &nk, &[1])
            .map_err(StateError::Storage)?;

        // Expiry index: E + expires_at_height(BE) + challenge_id
        let ek = challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id);
        view.put(CF_ACTIVE_CHALLENGES, &ek, &[1])
            .map_err(StateError::Storage)?;

        Ok(())
    }

    /// A challenge as this block's candidate sees it.
    pub fn v_get_challenge(
        view: &ExecutionView<'_, '_>,
        challenge_id: &Hash,
    ) -> Result<Option<StorageChallenge>> {
        let pk = challenge_key(challenge_id);
        match view.get(CF_ACTIVE_CHALLENGES, &pk).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_challenge(&data)?)),
            None => Ok(None),
        }
    }

    pub fn get_challenge(&self, challenge_id: &Hash) -> Result<Option<StorageChallenge>> {
        let pk = challenge_key(challenge_id);
        match self.db.get(CF_ACTIVE_CHALLENGES, &pk).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_challenge(&data)?)),
            None => Ok(None),
        }
    }

    /// Remove a challenge and both of its indexes from the candidate — the
    /// exact inverse of [`Self::v_put_challenge`], all three keys together.
    pub fn v_delete_challenge(
        view: &mut ExecutionView<'_, '_>,
        challenge: &StorageChallenge,
    ) -> Result<()> {
        // Delete all 3 keys
        let pk = challenge_key(&challenge.challenge_id);
        view.delete(CF_ACTIVE_CHALLENGES, &pk)
            .map_err(StateError::Storage)?;

        let nk = challenge_node_index_key(&challenge.target_node, &challenge.challenge_id);
        view.delete(CF_ACTIVE_CHALLENGES, &nk)
            .map_err(StateError::Storage)?;

        let ek = challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id);
        view.delete(CF_ACTIVE_CHALLENGES, &ek)
            .map_err(StateError::Storage)?;

        Ok(())
    }
}
