//! # SUM Chain State
//!
//! State management and transaction execution for SUM Chain.
//! Handles account balances, nonces, and transaction application.

pub mod agreement_executor;
pub mod beacon_executor;
pub mod beacon_store;
pub mod cache;
pub mod compute_pool;
pub mod compute_pool_manager;
pub mod compute_pool_store;
pub mod contract_executor;
pub mod docclass_executor;
pub mod education_executor;
pub mod employment_executor;
pub mod equity_executor;
pub mod executor;
pub mod supply;
pub mod finance_executor;
pub mod governance_executor;
pub mod healthcare_executor;
pub mod inference_attestation_executor;
pub mod inference_settlement_executor;
pub mod legal_executor;
pub mod mempool;
pub mod messaging_executor;
pub mod nft_executor;
pub mod node_registry;
pub mod policy_account_executor;
pub mod property_executor;
pub mod schema_validator;
pub mod snapshot;
pub mod staking_executor;
pub mod state;
pub mod storage_metadata;
pub mod tax_executor;
pub mod token_executor;
pub mod validator_quorum;

pub use agreement_executor::{AgreementExecutionResult, AgreementExecutor};
pub use cache::{CacheStats, CachedAccount, StateCache};
pub use contract_executor::{ContractCallResult, ContractDeployResult, ContractExecutorState, ContractEvent, ContractMetadata};
pub use docclass_executor::{DocClassExecutionResult, DocClassExecutor};
pub use employment_executor::{EmploymentExecutionResult, EmploymentExecutor};
pub use equity_executor::{EquityExecutionResult, EquityExecutor};
pub use executor::{BlockExecutor, TxExecutionResult};
pub use finance_executor::{FinanceExecutionResult, FinanceExecutor};
pub use healthcare_executor::{HealthcareExecutionResult, HealthcareExecutor};
pub use legal_executor::{LegalExecutionResult, LegalExecutor};
pub use mempool::{Mempool, MempoolConfig, MempoolStats};
pub use messaging_executor::{MessagingExecutionResult, MessagingExecutor};
pub use nft_executor::{NftExecutionResult, NftExecutor};
pub use node_registry::{NodeRegistryExecutionResult, NodeRegistryExecutor};
pub use policy_account_executor::{PolicyAccountExecutionResult, PolicyAccountExecutor};
pub use storage_metadata::{
    ArchivePerEntry, CoverageSummaryV2, StorageMetadataExecutionResult, StorageMetadataExecutor,
    StorageMetadataV2ExecutionResult, MAX_ASSIGNED_COUNT_CHUNK_COUNT,
};
pub use property_executor::{PropertyExecutionResult, PropertyExecutor};
pub use schema_validator::{SchemaValidator, SchemaValidatorConfig, ValidationResult};
pub use snapshot::{Snapshot, SnapshotHeader, SnapshotManager, SnapshotSyncConfig, RestoreResult};
pub use staking_executor::{StakingExecutionResult, StakingExecutor};
pub use state::StateManager;
pub use tax_executor::{TaxExecutionResult, TaxExecutor};
pub use token_executor::{TokenExecutionResult, TokenExecutor};

// Type alias for convenience (used by executors)
pub type State = StateManager;

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

    /// OmniNode `InferenceAttestation` subprotocol is not yet active at the
    /// current block height — `omninode_enabled_from_height` is either
    /// `None` or in the future. Mempool admission rejects with this so
    /// pre-activation txs never enter the mempool.
    #[error("OmniNode InferenceAttestation subprotocol not activated at this height")]
    OmniNodeNotActivated,

    /// Mempool already has an in-flight `InferenceAttestation` for the
    /// same `(session_id, verifier_address)` pair, OR the canonical
    /// `INFERENCE_ATTESTATIONS` column family already records a finalized
    /// attestation for that pair. Either case = duplicate; the tx is
    /// rejected at admission and never reaches the executor.
    #[error("Duplicate InferenceAttestation for this (session_id, verifier) pair")]
    DuplicateInferenceAttestation,

    /// SRC-817/818 Education suite not activated at the current chain
    /// height (`education_enabled_from_height` is `None` or in the
    /// future). Mempool admission rejects pre-activation education txs;
    /// no receipt is produced (admission only).
    #[error("Education suite not activated at this height")]
    EducationNotActivated,

    /// BR1 randomness-beacon subprotocol (#125) is not active: the
    /// `beacon_enabled_from_height` gate is `None`/in the future (and is
    /// fail-closed pending BR1 #127). Beacon payloads (`BeaconSetup` /
    /// `BeaconSigning`) are deterministically rejected at mempool admission so a
    /// gate-closed beacon tx never enters the mempool; no receipt (admission only).
    /// The executor independently rejects any beacon tx that reaches execution
    /// (`crate::beacon_executor`) with the generic `Failed(0)` receipt, mutating no
    /// beacon state (no beacon-specific receipt code is frozen).
    #[error("Beacon subprotocol not activated at this height")]
    BeaconNotActivated,

    /// An education record with the same identity is already in-flight
    /// in the mempool, OR already committed in a Phase 2 education CF.
    /// Rejected at admission; no receipt (admission only).
    #[error("Duplicate education record (in-flight or committed)")]
    DuplicateEducationRecord,

    /// Education tx failed a cheap admission precheck (oversize payload,
    /// undecodable/unsupported op, or a structural prerequisite such as
    /// a missing/inactive catalog or missing enrollment). Rejected at
    /// admission; no receipt — the executor remains authoritative for
    /// txs that pass admission.
    #[error("Invalid education transaction: {0}")]
    InvalidEducationTransaction(String),

    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("Genesis error: {0}")]
    Genesis(String),

    #[error("NFT error: {0}")]
    NftError(String),

    #[error("Contract error: {0}")]
    ContractError(String),

    #[error("Policy account error: {0}")]
    PolicyAccountError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub type Result<T> = std::result::Result<T, StateError>;

impl From<sumc_runtime::RuntimeError> for StateError {
    fn from(e: sumc_runtime::RuntimeError) -> Self {
        StateError::ContractError(e.to_string())
    }
}
