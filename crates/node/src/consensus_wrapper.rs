//! Consensus engine wrapper to support both PoA and BFT.

use std::sync::Arc;

use anyhow::Result;
use sumchain_consensus::{
    bft::{BftEngine, Proposal, Vote},
    ConsensusEngine, ConsensusEvent, ConsensusQuery, PoAEngine,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_primitives::{Block, BlockHeight};
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
                let view = vote.view;
                let has_quorum = engine.add_prevote(vote)?;

                if has_quorum {
                    // Check if we have >2/3 prevotes for a block
                    if let Some(block_hash) = engine.get_prevote_quorum(&view) {
                        // Create precommit
                        let precommit = engine.create_precommit(
                            view,
                            Some(block_hash),
                        )?;
                        return Ok(Some(precommit));
                    } else {
                        // No quorum, send nil precommit
                        let precommit = engine.create_precommit(view, None)?;
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
                let view = vote.view;
                let has_quorum = engine.add_precommit(vote)?;

                if has_quorum {
                    // Check if we have >2/3 precommits for a block
                    if let Some(block_hash) = engine.get_precommit_quorum(&view) {
                        return Ok(Some(block_hash));
                    }
                }

                Ok(None)
            }
        }
    }

    /// Get BFT engine (if BFT)
    ///
    /// Nothing calls this today, and it is kept rather than deleted because
    /// `consensus_sinks` in `crates/node/tests/consensus_participation_guard.rs`
    /// derives "the calls that can reach consensus" from this impl block's
    /// method list and asserts `as_bft` is among them. Handing out the engine
    /// itself is the capability escape that derivation exists to name; deleting
    /// the method would make that assertion fail, and re-listing the sinks by
    /// hand instead is exactly what the derivation replaced.
    #[allow(dead_code)]
    pub fn as_bft(&self) -> Option<&Arc<BftEngine>> {
        match self {
            Self::Bft(engine) => Some(engine),
            _ => None,
        }
    }

    /// Get PoA engine (if PoA)
    ///
    /// Reached only from the crate's own `#[cfg(test)]` unit tests
    /// (`tests/unit/peer_block_admission_tests.rs`), so the shipped binary
    /// builds it dead. Kept for the same reason as `as_bft`: it is one of the
    /// capability escapes `consensus_sinks` derives, and that derivation is
    /// what makes handing the engine out a reviewable act rather than an
    /// incidental one.
    #[allow(dead_code)]
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
            Self::Poa(engine) => Ok(engine.start().await?),
            Self::Bft(engine) => Ok(engine.start().await?),
        }
    }

    /// Stop consensus engine
    pub async fn stop(&self) -> Result<()> {
        match self {
            Self::Poa(engine) => Ok(engine.stop().await?),
            Self::Bft(engine) => Ok(engine.stop().await?),
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

    /// Import block
    pub async fn import_block(&self, block: Block) -> Result<()> {
        match self {
            Self::Poa(engine) => Ok(engine.import_block(block).await?),
            Self::Bft(engine) => Ok(engine.import_block(block).await?),
        }
    }

    /// Subscribe to consensus events
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConsensusEvent> {
        match self {
            Self::Poa(engine) => engine.subscribe(),
            Self::Bft(engine) => engine.subscribe(),
        }
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        match self {
            Self::Poa(engine) => engine.get_block_by_height(height),
            Self::Bft(engine) => engine.get_block_by_height(height),
        }
    }

    /// Load chain from storage
    pub fn load_chain(&self) -> Result<Option<Block>> {
        match self {
            Self::Poa(engine) => Ok(engine.load_chain()?),
            Self::Bft(engine) => Ok(engine.load_chain()?),
        }
    }

    /// Initialize genesis
    pub fn init_genesis(&self, genesis: &Genesis) -> Result<()> {
        match self {
            Self::Poa(engine) => {
                engine.init_genesis(genesis)?;
                Ok(())
            }
            Self::Bft(engine) => {
                engine.init_genesis(genesis)?;
                Ok(())
            }
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

    /// Get the inner engine as the READ-ONLY consensus handle, for the RPC
    /// server.
    ///
    /// Deliberately `Arc<dyn ConsensusQuery>` and not `Arc<dyn ConsensusEngine>`.
    /// It is the same `Arc<PoAEngine>` the event loop holds — a clone of the
    /// pointer, not of the engine, so every read the RPC server does still sees
    /// live state. What the narrower type removes is the CAPABILITY: the handle
    /// the RPC server ends up with has no `import_block`, so proposal
    /// acceptance and fork choice (`PoAEngine::do_import_block`) are not
    /// reachable from an HTTP request. That route carried no `PeerId`, so
    /// `Node::admit_peer_block`'s participation check had nothing to judge —
    /// it was a route AROUND the boundary, not a route through it.
    ///
    /// The coercion is one-way. `dyn ConsensusQuery` has no `Any` supertrait,
    /// so there is no downcast back to `dyn ConsensusEngine`; handing this out
    /// is final. Proved in `crates/rpc/tests/consensus_capability_probe.rs`.
    pub fn as_consensus_query(&self) -> Arc<dyn ConsensusQuery> {
        match self {
            Self::Poa(engine) => Arc::clone(engine) as Arc<dyn ConsensusQuery>,
            Self::Bft(engine) => Arc::clone(engine) as Arc<dyn ConsensusQuery>,
        }
    }
}
