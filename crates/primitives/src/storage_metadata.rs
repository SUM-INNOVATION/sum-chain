//! Storage Metadata types for SUM Chain.
//!
//! Defines on-chain data structures for decentralized file storage metadata,
//! including file identity (Blake3 Merkle root), access control lists, and
//! fee pools for storage-node payouts.

use serde::{Deserialize, Serialize};

use crate::{Address, Hash};

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
}

/// Transaction data for storage metadata operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageMetadataTxData {
    pub operation: StorageMetadataOperation,
}
