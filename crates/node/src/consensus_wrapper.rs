//! Consensus engine wrapper to support both PoA and BFT.

use std::sync::Arc;

use anyhow::Result;
use sumchain_consensus::{
    bft::{BftEngine, Proposal, Vote, VoteType},
    ConsensusEngine, ConsensusEvent, PoAEngine,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_primitives::{Block, BlockHeight, PublicKey};
use sumchain_state::{Mempool, StateManager};
use sumchain_storage::Database;

/// Wrapper for different consensus engine types
pub enum ConsensusWrapper {
    /// Proof of Authority consensus
    Poa(Arc<PoAEngine>),
    /// Byzantine Fault Tolerant consensus
    Bft(Arc<BftEngine>),
}

impl ConsensusWrapper {
    /// Create PoA consensus engine
    pub fn new_poa(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        genesis: &Genesis,
        validator_key: Option<KeyPair>,
    ) -> Result<Self> {
        let engine = PoAEngine::new(db, state, mempool, genesis, validator_key)?;
        Ok(Self::Poa(Arc::new(engine)))
    }

    /// Create BFT consensus engine
    pub fn new_bft(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        genesis: &Genesis,
        validator_key: Option<KeyPair>,
    ) -> Result<Self> {
        let engine = BftEngine::new(db, state, mempool, genesis, validator_key)?;
        Ok(Self::Bft(Arc::new(engine)))
    }

    /// Check if this node is a validator
    pub fn is_validator(&self) -> bool {
        match self {
            Self::Poa(engine) => engine.is_validator(),
            Self::Bft(_) => true, // BFT requires validator key
        }
    }

    /// Get the consensus engine name
    pub fn engine_name(&self) -> &'static str {
        match self {
            Self::Poa(_) => "PoA",
            Self::Bft(_) => "BFT",
        }
    }

    /// Propose a new block (validator only)
    pub async fn propose_block(
        &self,
        parent_hash: sumchain_primitives::Hash,
        height: BlockHeight,
        transactions: Vec<sumchain_primitives::SignedTransaction>,
        state_root: sumchain_primitives::Hash,
    ) -> Result<Option<Block>> {
        match self {
            Self::Poa(engine) => {
                engine
                    .propose_block(parent_hash, height, transactions, state_root)
                    .await
            }
            Self::Bft(_engine) => {
                // BFT proposal happens in consensus loop
                // This is called from block builder, not directly
                Ok(None)
            }
        }
    }

    /// Handle BFT proposal (BFT only)
    pub fn handle_proposal(&self, proposal: Proposal) -> Result<Option<Vote>> {
        match self {
            Self::Poa(_) => Ok(None), // PoA doesn't use proposals
            Self::Bft(engine) => {
                // Verify proposal
                let leader = engine.get_leader(&proposal.view);
                if !proposal.verify(&leader) {
                    return Err(anyhow::anyhow!("Invalid proposal signature"));
                }

                // Create prevote
                let prevote = engine.create_prevote(
                    proposal.view,
                    Some(proposal.block.hash()),
                )?;

                Ok(Some(prevote))
            }
        }
    }

    /// Handle BFT prevote (BFT only)
    pub fn handle_prevote(&self, vote: Vote) -> Result<Option<Vote>> {
        match self {
            Self::Poa(_) => Ok(None),
            Self::Bft(engine) => {
                let has_quorum = engine.add_prevote(vote)?;

                if has_quorum {
                    // Check if we have >2/3 prevotes for a block
                    if let Some(block_hash) = engine.get_prevote_quorum(&vote.view) {
                        // Create precommit
                        let precommit = engine.create_precommit(
                            vote.view,
                            Some(block_hash),
                        )?;
                        return Ok(Some(precommit));
                    } else {
                        // No quorum, send nil precommit
                        let precommit = engine.create_precommit(vote.view, None)?;
                        return Ok(Some(precommit));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Handle BFT precommit (BFT only)
    pub fn handle_precommit(&self, vote: Vote) -> Result<Option<sumchain_primitives::Hash>> {
        match self {
            Self::Poa(_) => Ok(None),
            Self::Bft(engine) => {
                let has_quorum = engine.add_precommit(vote)?;

                if has_quorum {
                    // Check if we have >2/3 precommits for a block
                    if let Some(block_hash) = engine.get_precommit_quorum(&vote.view) {
                        return Ok(Some(block_hash));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Get BFT engine (if BFT)
    pub fn as_bft(&self) -> Option<&Arc<BftEngine>> {
        match self {
            Self::Bft(engine) => Some(engine),
            _ => None,
        }
    }

    /// Get PoA engine (if PoA)
    pub fn as_poa(&self) -> Option<&Arc<PoAEngine>> {
        match self {
            Self::Poa(engine) => Some(engine),
            _ => None,
        }
    }

    // Delegate ConsensusEngine trait methods

    /// Start consensus engine
    pub async fn start(&self) -> Result<()> {
        match self {
            Self::Poa(engine) => engine.start().await,
            Self::Bft(engine) => engine.start().await,
        }
    }

    /// Stop consensus engine
    pub async fn stop(&self) -> Result<()> {
        match self {
            Self::Poa(engine) => engine.stop().await,
            Self::Bft(engine) => engine.stop().await,
        }
    }

    /// Get current height
    pub fn current_height(&self) -> BlockHeight {
        match self {
            Self::Poa(engine) => engine.current_height(),
            Self::Bft(engine) => engine.current_height(),
        }
    }

    /// Get best block hash
    pub fn best_block_hash(&self) -> sumchain_primitives::Hash {
        match self {
            Self::Poa(engine) => engine.best_block_hash(),
            Self::Bft(engine) => engine.best_block_hash(),
        }
    }

    /// Get validators
    pub fn validators(&self) -> Vec<[u8; 32]> {
        match self {
            Self::Poa(engine) => engine.validators(),
            Self::Bft(engine) => engine.validators(),
        }
    }

    /// Import block
    pub async fn import_block(&self, block: Block) -> Result<()> {
        match self {
            Self::Poa(engine) => engine.import_block(block).await,
            Self::Bft(engine) => engine.import_block(block).await,
        }
    }

    /// Subscribe to consensus events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConsensusEvent> {
        match self {
            Self::Poa(engine) => engine.subscribe(),
            Self::Bft(engine) => engine.subscribe(),
        }
    }

    /// Load chain from storage
    pub fn load_chain(&self) -> Result<Option<Block>> {
        match self {
            Self::Poa(engine) => engine.load_chain(),
            Self::Bft(engine) => engine.load_chain(),
        }
    }

    /// Initialize genesis
    pub fn init_genesis(&self, genesis: &Genesis) -> Result<()> {
        match self {
            Self::Poa(engine) => engine.init_genesis(genesis),
            Self::Bft(engine) => engine.init_genesis(genesis),
        }
    }

    /// Clone the wrapper (clones the Arc, not the engine)
    pub fn clone(&self) -> Self {
        match self {
            Self::Poa(engine) => Self::Poa(Arc::clone(engine)),
            Self::Bft(engine) => Self::Bft(Arc::clone(engine)),
        }
    }

    /// Run block producer loop (PoA and BFT have different implementations)
    pub async fn run_block_producer(&self) {
        match self {
            Self::Poa(engine) => engine.run_block_producer().await,
            Self::Bft(_engine) => {
                // BFT block production happens in consensus loop
                // For now, just log that BFT is active
                tracing::info!("BFT consensus active - block production handled by consensus protocol");
                // Keep task alive
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            }
        }
    }
}
