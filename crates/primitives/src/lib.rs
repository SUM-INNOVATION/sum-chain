//! # SUM Chain Primitives
//!
//! Core types and data structures for the SUM Chain blockchain.
//! This crate provides fundamental building blocks used throughout the chain.

pub mod address;
pub mod block;
pub mod hash;
pub mod receipt;
pub mod transaction;

pub use address::Address;
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub use receipt::{Receipt, TxStatus};
pub use transaction::{SignedTransaction, Transaction};

/// Chain ID type - identifies the network
pub type ChainId = u64;

/// Block height type
pub type BlockHeight = u64;

/// Nonce type for transactions
pub type Nonce = u64;

/// Balance/amount type - u128 supports large values
pub type Balance = u128;

/// Timestamp in milliseconds since Unix epoch
pub type Timestamp = u64;

/// Common result type for primitives
pub type Result<T> = std::result::Result<T, PrimitiveError>;

/// Errors that can occur in primitive operations
#[derive(Debug, thiserror::Error)]
pub enum PrimitiveError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("Invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid address checksum")]
    InvalidChecksum,
}
