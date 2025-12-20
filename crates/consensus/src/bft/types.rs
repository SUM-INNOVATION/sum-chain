//! BFT consensus types.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{BlockHeight, Hash};

/// Consensus round number
pub type Round = u32;

/// View identifier (height + round)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct View {
    pub height: BlockHeight,
    pub round: Round,
}

impl View {
    pub fn new(height: BlockHeight, round: Round) -> Self {
        Self { height, round }
    }

    pub fn genesis() -> Self {
        Self {
            height: 0,
            round: 0,
        }
    }

    pub fn next_round(&self) -> Self {
        Self {
            height: self.height,
            round: self.round + 1,
        }
    }

    pub fn next_height(&self) -> Self {
        Self {
            height: self.height + 1,
            round: 0,
        }
    }
}

/// Vote type in BFT consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Prevote phase - signal agreement on proposal
    Prevote,
    /// Precommit phase - commit to proposal
    Precommit,
}

/// Consensus step within a round
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Waiting for proposal
    Propose,
    /// Prevote phase
    Prevote,
    /// Precommit phase
    Precommit,
    /// Commit phase
    Commit,
}

/// Consensus state
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current view (height + round)
    pub view: View,
    /// Current step
    pub step: Step,
    /// Locked block (prevents equivocation)
    pub locked_block: Option<Hash>,
    /// Locked round
    pub locked_round: Option<Round>,
    /// Valid block (can vote for)
    pub valid_block: Option<Hash>,
    /// Valid round
    pub valid_round: Option<Round>,
}

impl ConsensusState {
    pub fn new(height: BlockHeight) -> Self {
        Self {
            view: View::new(height, 0),
            step: Step::Propose,
            locked_block: None,
            locked_round: None,
            valid_block: None,
            valid_round: None,
        }
    }

    pub fn move_to_round(&mut self, round: Round) {
        self.view.round = round;
        self.step = Step::Propose;
    }

    pub fn move_to_step(&mut self, step: Step) {
        self.step = step;
    }

    pub fn move_to_height(&mut self, height: BlockHeight) {
        self.view = View::new(height, 0);
        self.step = Step::Propose;
        self.locked_block = None;
        self.locked_round = None;
        self.valid_block = None;
        self.valid_round = None;
    }
}

/// Timeout configuration for BFT consensus
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Timeout for propose step (ms)
    pub propose: u64,
    /// Timeout for prevote step (ms)
    pub prevote: u64,
    /// Timeout for precommit step (ms)
    pub precommit: u64,
    /// Timeout multiplier for each round
    pub round_multiplier: f64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            propose: 3000,      // 3 seconds
            prevote: 1000,      // 1 second
            precommit: 1000,    // 1 second
            round_multiplier: 1.5,
        }
    }
}

impl TimeoutConfig {
    /// Calculate timeout for a given step and round
    pub fn timeout_for(&self, step: Step, round: Round) -> u64 {
        let base = match step {
            Step::Propose => self.propose,
            Step::Prevote => self.prevote,
            Step::Precommit => self.precommit,
            Step::Commit => 0, // No timeout for commit
        };

        if round == 0 {
            base
        } else {
            (base as f64 * self.round_multiplier.powi(round as i32)) as u64
        }
    }
}
