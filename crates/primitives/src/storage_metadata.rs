//! Storage Metadata types for SUM Chain.
//!
//! Defines on-chain data structures for decentralized file storage metadata,
//! including file identity (Blake3 Merkle root), access control lists,
//! fee pools for storage-node payouts, and Proof-of-Retrievability challenges.

use serde::{Deserialize, Serialize};

use crate::{Address, Hash};

// ─── PoR Constants ───────────────────────────────────────────────────────────

/// Chunk size for PoR challenges: 1 MB
pub const CHUNK_SIZE: u64 = 1_048_576;

/// How many blocks an ArchiveNode has to respond to a challenge
pub const CHALLENGE_TTL_BLOCKS: u64 = 50;

/// Issue a new challenge every N blocks
pub const CHALLENGE_INTERVAL_BLOCKS: u64 = 100;

/// Reward per valid proof: 10 Koppa (in base units)
pub const CHALLENGE_REWARD: u64 = 10_000_000_000;

/// Percentage of staked balance slashed on expired challenge
pub const SLASH_PERCENTAGE: u64 = 5;

// ─── File Metadata ───────────────────────────────────────────────────────────

/// On-chain metadata for a stored file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Blake3 Merkle root of the file's content tree
    pub merkle_root: Hash,
    /// Owner/uploader who controls the file
    pub owner: Address,
    /// Total file size in bytes
    pub total_size_bytes: u64,
    /// Native ACL — addresses allowed to retrieve the file
    pub access_list: Vec<Address>,
    /// Locked Koppa (base units) reserved for storage-node payouts
    pub fee_pool: u64,
    /// Block height at which the metadata was created
    pub created_at: u64,
}

// ─── PoR Challenge ───────────────────────────────────────────────────────────

/// An open cryptographic challenge issued by the L1 to an ArchiveNode.
/// The node must submit a valid Merkle proof before `expires_at_height`
/// or face slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageChallenge {
    /// Deterministic ID: Blake3(merkle_root ++ chunk_index ++ created_at_height)
    pub challenge_id: Hash,
    /// Which file is being challenged
    pub merkle_root: Hash,
    /// Which 1 MB chunk to prove (0-indexed)
    pub chunk_index: u32,
    /// Which ArchiveNode must respond
    pub target_node: Address,
    /// Block height the challenge was issued
    pub created_at_height: u64,
    /// Deadline: must respond before this height
    pub expires_at_height: u64,
}

// ─── Operations ──────────────────────────────────────────────────────────────

/// Operations on storage metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMetadataOperation {
    /// Register a new file's metadata and lock a fee deposit
    RegisterFile {
        merkle_root: Hash,
        total_size_bytes: u64,
        access_list: Vec<Address>,
        fee_deposit: u64,
    },
    /// Replace the entire access list (owner only)
    UpdateAccessList {
        merkle_root: Hash,
        new_access_list: Vec<Address>,
    },
    /// Append a single address to the access list (owner only)
    AddAccess {
        merkle_root: Hash,
        address: Address,
    },
    /// Remove a single address from the access list (owner only)
    RemoveAccess {
        merkle_root: Hash,
        address: Address,
    },
    /// Top up the fee pool for a file (anyone can do this)
    TopUpFeePool {
        merkle_root: Hash,
        amount: u64,
    },
    /// Submit a Merkle proof for a storage challenge (ArchiveNode only)
    SubmitStorageProof {
        /// The challenge being responded to
        challenge_id: Hash,
        /// File merkle root (must match challenge)
        merkle_root: Hash,
        /// Chunk index (must match challenge)
        chunk_index: u32,
        /// Blake3 hash of the raw chunk data
        chunk_hash: Hash,
        /// Merkle path from chunk leaf to root (sibling hashes, bottom-up)
        merkle_path: Vec<Hash>,
    },
}

/// Transaction data for storage metadata operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadataTxData {
    pub operation: StorageMetadataOperation,
}
