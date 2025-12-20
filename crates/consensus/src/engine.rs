//! Consensus engine trait and common types.
//!
//! Defines the interface that any consensus mechanism must implement.

use async_trait::async_trait;
use sumchain_genesis::Genesis;
use sumchain_primitives::{Block, BlockHeight, Hash, SignedTransaction};

use crate::Result;

/// Events emitted by the consensus engine
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    /// A new block was produced by this node
    BlockProduced(Block),
    /// A new block was imported from the network
    BlockImported(Block),
    /// A block was finalized (can't be reverted)
    BlockFinalized(Hash, BlockHeight),
    /// Chain reorganization occurred
    Reorg {
        old_head: Hash,
        new_head: Hash,
        depth: u64,
    },
}

/// Consensus engine trait
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Start the consensus engine
    async fn start(&self) -> Result<()>;

    /// Stop the consensus engine
    async fn stop(&self) -> Result<()>;

    /// Check if this node is a validator
    fn is_validator(&self) -> bool;

    /// Get the current block height
    fn current_height(&self) -> BlockHeight;

    /// Get the current best block hash
    fn best_block_hash(&self) -> Hash;

    /// Get the validator set
    fn validators(&self) -> Vec<[u8; 32]>;

    /// Import a block from the network
    async fn import_block(&self, block: Block) -> Result<()>;

    /// Propose a new block (validators only)
    async fn propose_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block>;

    /// Check if it's our turn to propose
    fn is_proposer(&self, height: BlockHeight) -> bool;

    /// Get the proposer for a given height
    fn get_proposer(&self, height: BlockHeight) -> [u8; 32];

    /// Subscribe to consensus events
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConsensusEvent>;

    /// Get a block by height (for sync)
    fn get_block_by_height(&self, height: BlockHeight) -> Option<Block>;

    /// Load the chain from storage, returning the head block if it exists
    fn load_chain(&self) -> Result<Option<Block>>;

    /// Initialize the chain from genesis
    fn init_genesis(&self, genesis: &Genesis) -> Result<()>;

    /// Get the last finalized block height
    fn finalized_height(&self) -> BlockHeight;

    /// Get the last finalized block hash
    fn finalized_hash(&self) -> Hash;

    /// Check if a block at a given height is finalized
    fn is_finalized(&self, height: BlockHeight) -> bool;

    /// Get the finality depth (number of confirmations required)
    fn finality_depth(&self) -> u64;
}

/// Fork choice rule
pub trait ForkChoice: Send + Sync {
    /// Select the best block between two candidates
    fn select_best(&self, block_a: &Block, block_b: &Block) -> Hash;

    /// Check if a block should replace the current head
    fn should_switch(&self, current_head: &Block, candidate: &Block) -> bool;
}

/// Simple longest chain fork choice with hash tiebreaker
pub struct LongestChainForkChoice;

impl ForkChoice for LongestChainForkChoice {
    fn select_best(&self, block_a: &Block, block_b: &Block) -> Hash {
        // Higher height wins
        if block_a.height() > block_b.height() {
            return block_a.hash();
        }
        if block_b.height() > block_a.height() {
            return block_b.hash();
        }

        // Same height: lower hash wins (deterministic tiebreaker)
        if block_a.hash() < block_b.hash() {
            block_a.hash()
        } else {
            block_b.hash()
        }
    }

    fn should_switch(&self, current_head: &Block, candidate: &Block) -> bool {
        // Switch if candidate has higher height
        if candidate.height() > current_head.height() {
            return true;
        }

        // Same height: switch if candidate has lower hash
        if candidate.height() == current_head.height() {
            return candidate.hash() < current_head.hash();
        }

        false
    }
}
