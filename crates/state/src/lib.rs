//! # SUM Chain State
//!
//! State management and transaction execution for SUM Chain.
//! Handles account balances, nonces, and transaction application.

pub mod cache;
pub mod executor;
pub mod mempool;
pub mod snapshot;
pub mod state;

pub use cache::{CacheStats, CachedAccount, StateCache};
pub use executor::{BlockExecutor, TxExecutionResult};
pub use mempool::{Mempool, MempoolConfig, MempoolStats};
pub use snapshot::{Snapshot, SnapshotHeader, SnapshotManager, SnapshotSyncConfig, RestoreResult};
pub use state::StateManager;

use thiserror::Error;

/// State errors
#[derive(Debug, Error)]
pub enum StateError {
    #[error("Storage error: {0}")]
    Storage(#[from] sumchain_storage::StorageError),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Invalid chain ID: expected {expected}, got {got}")]
    InvalidChainId { expected: u64, got: u64 },

    #[error("Fee too low: minimum {minimum}, got {got}")]
    FeeTooLow { minimum: u128, got: u128 },

    #[error("Signer mismatch: tx from {from}, signed by {signer}")]
    SignerMismatch { from: String, signer: String },

    #[error("Transaction already exists")]
    TxAlreadyExists,

    #[error("Mempool full")]
    MempoolFull,

    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("Genesis error: {0}")]
    Genesis(String),
}

pub type Result<T> = std::result::Result<T, StateError>;
