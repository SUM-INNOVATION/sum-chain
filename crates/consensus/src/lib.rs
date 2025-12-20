//! # SUM Chain Consensus
//!
//! Two consensus implementations are available:
//!
//! ## Proof of Authority (PoA)
//! Simple round-robin validator rotation. Fast and deterministic,
//! but assumes honest majority of validators.
//!
//! ## Byzantine Fault Tolerant (BFT)
//! Tendermint-style consensus with immediate finality and tolerance
//! for up to 1/3 Byzantine (malicious) validators.
//!
//! The consensus interface is designed to be swappable, allowing
//! easy migration from PoA to BFT or future PoS implementation.

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
