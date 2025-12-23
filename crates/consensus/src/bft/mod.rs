//! Byzantine Fault Tolerant (BFT) consensus implementation.
//!
//! **STATUS: EXPERIMENTAL - NOT PRODUCTION READY**
//!
//! This module contains an incomplete Tendermint-style BFT implementation.
//! For production use, use the [`PoAEngine`](super::PoAEngine) instead.
//!
//! ## Limitations
//!
//! - `propose_block()` returns `NotImplemented`
//! - P2P vote broadcasting is stubbed (local processing only)
//! - Timeout handling is incomplete
//!
//! ## Design Goals (when complete)
//!
//! - Immediate finality (no confirmations needed)
//! - Byzantine fault tolerance (up to 1/3 malicious validators)
//! - Two-phase voting (prevote + precommit)
//! - View change mechanism for liveness
//!
//! ## Consensus Rounds
//!
//! Each height goes through rounds until consensus is reached:
//! 1. **Propose**: Leader proposes a block
//! 2. **Prevote**: Validators vote on the proposal
//! 3. **Precommit**: Validators commit if >2/3 prevoted
//! 4. **Commit**: Block is committed if >2/3 precommitted
//!
//! If a round times out, validators move to the next round with a new leader.

pub mod engine;
pub mod types;
pub mod vote;

pub use engine::BftEngine;
pub use types::{ConsensusState, Round, Step, TimeoutConfig, View, VoteType};
pub use vote::{Proposal, Vote, VoteSet};
