//! # SUM Chain Consensus
//!
//! ## Production Consensus: Proof of Authority (PoA)
//!
//! SUM Chain uses Proof of Authority (PoA) consensus with:
//!
//! - **Round-robin proposer selection**: Validators take turns proposing blocks
//!   based on `validators[height % N]` where N is the validator count.
//!
//! - **Probabilistic finality**: Blocks become finalized after `finality_depth`
//!   confirmations (default: 6 blocks). This provides high confidence against
//!   reorganization while allowing fast block times.
//!
//! - **Longest chain fork choice**: In case of competing forks, the chain with
//!   the most blocks wins, with ties broken by lower block hash.
//!
//! - **Trusted validator set**: Assumes an honest majority of validators.
//!   Validator set is defined in genesis and currently static.
//!
//! ## Finality Model
//!
//! Unlike BFT consensus with instant finality, PoA uses depth-based finality:
//!
//! - A block at height H is finalized when the chain reaches height H + finality_depth
//! - Finalized blocks cannot be reverted by reorganization
//! - The `finalized_height()` and `is_finalized()` methods track finality state
//! - Finality state is persisted to storage for crash recovery
//!
//! ## Experimental: Byzantine Fault Tolerant (BFT)
//!
//! A Tendermint-style BFT implementation exists in the `bft` module but is
//! **not yet production-ready**. It includes:
//!
//! - Two-phase voting (prevote + precommit)
//! - View change mechanism for liveness
//! - Theoretical tolerance for up to 1/3 Byzantine validators
//!
//! Note: The BFT module is incomplete (`propose_block` returns `NotImplemented`).
//! Use PoA for production deployments.
//!
//! ## Architecture
//!
//! The `ConsensusEngine` trait provides a common interface for both implementations,
//! allowing future migration to BFT or PoS when ready.

pub mod bft;
pub mod engine;
pub mod poa;

pub use bft::BftEngine;
pub use engine::{ConsensusEngine, ConsensusEvent};
pub use poa::PoAEngine;

use thiserror::Error;

/// Consensus errors
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Not a validator")]
    NotValidator,

    #[error("Not our turn to propose")]
    NotProposer,

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid vote: {0}")]
    InvalidVote(String),

    #[error("Block already exists")]
    BlockExists,

    #[error("Parent block not found")]
    ParentNotFound,

    #[error("State error: {0}")]
    State(#[from] sumchain_state::StateError),

    #[error("Storage error: {0}")]
    Storage(#[from] sumchain_storage::StorageError),

    #[error("Genesis error: {0}")]
    Genesis(String),

    #[error("Engine not started")]
    NotStarted,

    #[error("Not implemented")]
    NotImplemented,
}

pub type Result<T> = std::result::Result<T, ConsensusError>;
