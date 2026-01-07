//! # SUM Chain State
//!
//! State management and transaction execution for SUM Chain.
//! Handles account balances, nonces, and transaction application.

pub mod cache;
pub mod contract_executor;
pub mod docclass_executor;
pub mod equity_executor;
pub mod executor;
pub mod mempool;
pub mod messaging_executor;
pub mod nft_executor;
pub mod snapshot;
pub mod staking_executor;
pub mod state;
pub mod tax_executor;
pub mod token_executor;

pub use cache::{CacheStats, CachedAccount, StateCache};
pub use contract_executor::{ContractCallResult, ContractDeployResult, ContractExecutorState, ContractEvent, ContractMetadata};
pub use docclass_executor::{DocClassExecutionResult, DocClassExecutor};
pub use equity_executor::{EquityExecutionResult, EquityExecutor};
pub use executor::{BlockExecutor, TxExecutionResult};
pub use mempool::{Mempool, MempoolConfig, MempoolStats};
pub use messaging_executor::{MessagingExecutionResult, MessagingExecutor};
pub use nft_executor::{NftExecutionResult, NftExecutor};
pub use snapshot::{Snapshot, SnapshotHeader, SnapshotManager, SnapshotSyncConfig, RestoreResult};
pub use staking_executor::{StakingExecutionResult, StakingExecutor};
pub use state::StateManager;
pub use tax_executor::{TaxExecutionResult, TaxExecutor};
pub use token_executor::{TokenExecutionResult, TokenExecutor};

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

    #[error("NFT error: {0}")]
    NftError(String),

    #[error("Contract error: {0}")]
    ContractError(String),
}

pub type Result<T> = std::result::Result<T, StateError>;

impl From<sumc_runtime::RuntimeError> for StateError {
    fn from(e: sumc_runtime::RuntimeError) -> Self {
        StateError::ContractError(e.to_string())
    }
}
