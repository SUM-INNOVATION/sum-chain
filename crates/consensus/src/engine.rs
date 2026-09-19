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

/// The read-only view of consensus state.
///
/// This is the capability the JSON-RPC server is given, and it is deliberately
/// smaller than [`ConsensusEngine`]. Its members are exactly the methods
/// `crates/rpc/src/server.rs` calls on the handle it is handed — no more. It
/// carries NO way to accept a proposal, run fork choice, produce a block, start
/// or stop the engine, or seed genesis.
///
/// # Why this trait exists
///
/// `ConsensusWrapper::as_consensus_query` hands the RPC server the SAME
/// `Arc<PoAEngine>` the node event loop holds. When that handle was an
/// `Arc<dyn ConsensusEngine>`, `import_block` — the single entry point to
/// proposal acceptance, fork choice and reorg (`PoAEngine::do_import_block`) —
/// was a method ON THE HANDLE, one line away from every RPC method that reads a
/// height. Nothing in the type system stopped a future handler from calling it
/// from an HTTP request, with no `PeerId` for the peer-participation check in
/// `Node::admit_peer_block` to judge. That was not a sixth route through the
/// participation boundary; it was a route around it.
///
/// Narrowing the handle's TYPE removes the capability rather than forbidding
/// its use: `dyn ConsensusQuery` has no `import_block` to call, so the mistake
/// no longer has a representation. `crates/rpc/tests/consensus_capability_probe.rs`
/// compiles the attempt and asserts rustc rejects it.
///
/// # Adding a method here
///
/// Is a deliberate widening of what the RPC server can do to consensus. Only
/// methods that cannot influence proposal acceptance, fork choice, block
/// production or engine lifecycle belong. Every method below is a pure read of
/// already-decided state.
///
/// # Why a supertrait rather than a second, independent trait
///
/// Each method is declared once, so the RPC's view cannot drift from the
/// engine's, and every existing `ConsensusEngine` consumer keeps calling these
/// methods unchanged. Note the coercion is one-way: `Arc<dyn ConsensusEngine>`
/// upcasts to `Arc<dyn ConsensusQuery>`, but there is no route back — no `Any`
/// supertrait, so no downcast — which is what makes the narrowed handle final.
pub trait ConsensusQuery: Send + Sync {
    /// Check if this node is a validator
    fn is_validator(&self) -> bool;

    /// Get the current block height
    fn current_height(&self) -> BlockHeight;

    /// Get the validator set
    fn validators(&self) -> Vec<[u8; 32]>;

    /// Get the proposer for a given height
    fn get_proposer(&self, height: BlockHeight) -> [u8; 32];

    /// Get the last finalized block height
    fn finalized_height(&self) -> BlockHeight;

    /// Get the last finalized block hash
    fn finalized_hash(&self) -> Hash;

    /// Check if a block at a given height is finalized
    fn is_finalized(&self, height: BlockHeight) -> bool;

    /// Get the finality depth (number of confirmations required)
    fn finality_depth(&self) -> u64;
}

/// Consensus engine trait
///
/// The full engine: [`ConsensusQuery`]'s reads PLUS the control surface —
/// lifecycle, proposal acceptance (`import_block`), block production and
/// genesis. Hand this out only where a caller is entitled to drive consensus.
/// The RPC server is not; it gets `dyn ConsensusQuery`.
#[async_trait]
pub trait ConsensusEngine: ConsensusQuery {
    /// Start the consensus engine
    async fn start(&self) -> Result<()>;

    /// Stop the consensus engine
    async fn stop(&self) -> Result<()>;

    /// Get the current best block hash
    fn best_block_hash(&self) -> Hash;

    /// Import a block from the network
    async fn import_block(&self, block: Block) -> Result<()>;

    /// Propose a new block (validators only)
    async fn propose_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block>;

    /// Check if it's our turn to propose
    fn is_proposer(&self, height: BlockHeight) -> bool;

    /// Subscribe to consensus events
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConsensusEvent>;

    /// Get a block by height (for sync)
    fn get_block_by_height(&self, height: BlockHeight) -> Option<Block>;

    /// Load the chain from storage, returning the head block if it exists
    fn load_chain(&self) -> Result<Option<Block>>;

    /// Initialize the chain from genesis
    fn init_genesis(&self, genesis: &Genesis) -> Result<()>;
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
