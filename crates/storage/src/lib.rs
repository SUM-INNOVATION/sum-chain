//! # SUM Chain Storage
//!
//! Persistent key-value storage for SUM Chain using RocksDB.
//! Provides schemas for blocks, state, transactions, and receipts.

pub mod db;
pub mod docclass_store;
pub mod messaging_store;
pub mod pruner;
pub mod schema;

pub use db::{BackupInfo, Database, DatabaseConfig};
pub use docclass_store::{
    CredentialStore, DocClassEventStore, DocClassIssuerStore, DocClassStore, EligibilityStore,
    IdentityRootStore, RevocationStore,
};
pub use messaging_store::MessagingStore;
pub use pruner::{DbStats, PruneStats, Pruner, PrunerConfig};
pub use schema::{
    BlockStore, DelegationStore, IssuerData, IssuerStore, NftCollectionData, NftStore,
    NftTokenData, ReceiptStore, SlashingStore, Src20TokenData, StakingStore, StateStore,
    TokenStore, TxStore, ValidatorSetStore,
};

use thiserror::Error;

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Database not initialized")]
    NotInitialized,

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
