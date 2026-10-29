//! # SUM Chain Consensus
//!
//! ## Production Consensus: Proof of Authority (PoA)
//!
//! SUM Chain uses Proof of Authority (PoA) consensus with:
//!
//! - **Round-robin proposer selection**: Validators take turns proposing blocks
//!   based on `validators[height % N]` where N is the validator count.
//!
//! - **Local-depth finality**: a block becomes finalized on this node once its
//!   own head is `finality_depth` blocks above it (`ChainParams::finality_depth`;
//!   3 when genesis leaves it unset, 6 in the repository's `genesis.json`). See
//!   the finality model below: this is not certified network finality.
//!
//! - **Longest chain fork choice**: In case of competing forks, the chain with
//!   the most blocks wins, with ties broken by lower block hash.
//!
//! - **Trusted validator set**: Assumes an honest majority of validators.
//!   Validator set is defined in genesis and currently static.
//!
//! ## Finality Model
//!
//! Finality is local confirmation depth: the consensus configuration's finality
//! rule `0x0011` is `FINALITY_LOCAL_DEPTH`, and RPC responses that say
//! "finalized" label it `finality_mechanism: "local-depth"`
//! ([`FinalityMechanism`]). It is NOT certified network finality (#270):
//!
//! - A block at height H is finalized on THIS node when its own head reaches
//!   H + finality_depth. No votes are collected and no certificate exists, so
//!   another node can hold a different finalized height, and no peer can prove
//!   to a caller that a height is final.
//! - Fork choice refuses a reorganization that would unwind a block at or below
//!   the local finalized height. The operator `rollback` command is not bound by
//!   it: rolling back below the finalized height lowers the stored finalized
//!   height to the rollback target (`reorg::execute_rollback`).
//! - The `finalized_height()` and `is_finalized()` methods track finality state.
//! - Finality state is persisted to storage for crash recovery, as two metadata
//!   writes outside the block's own batch; a node that cannot read it back
//!   restarts from finalized height 0 (#270).
//!
//! ## Experimental: Byzantine Fault Tolerant (BFT)
//!
//! A Tendermint-style BFT implementation exists in the `bft` module but is
//! **not production-ready and does not provide finality**: it aggregates, stores
//! and verifies no certificate. A node configured with `engine = "bft"` refuses
//! to start (#271). It includes:
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

pub mod reorg;
pub mod bft;
pub mod branch_switch;
pub mod consensus_config;
pub mod engine;
pub mod membership;
pub mod poa;

pub use bft::BftEngine;
pub use engine::{ConsensusEngine, ConsensusEvent, ConsensusQuery, FinalityMechanism};
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

    /// This node has stopped: a local condition — a resource budget, its own
    /// undo records, or a failure to reconcile memory with a committed chain
    /// switch — means it cannot continue with an answer it can stand behind.
    /// Refused until restart, which reloads from the committed database.
    #[error("node fail-stopped: {0}")]
    LocalFailStop(String),

    /// A chain switch was validated against a canonical head that is no longer
    /// the head. Nothing was applied; not a verdict on the branch.
    #[error("chain switch not applied, canonical head moved: {0}")]
    StaleSwitch(String),

    /// Under the dormant G5 validator-set wiring (#351) only: the set that
    /// governs a height cannot be resolved, or does not govern yet (its
    /// transition block is not certified). Not a verdict on any block.
    #[error("validator-set membership: {0}")]
    Membership(String),
}

pub type Result<T> = std::result::Result<T, ConsensusError>;
