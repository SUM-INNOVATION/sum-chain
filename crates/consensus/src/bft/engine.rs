//! BFT consensus engine implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Block, BlockHeight, Hash, PublicKey, SignedTransaction};
use sumchain_state::{BlockExecutor, Mempool, StateManager};
use sumchain_storage::{BlockStore, Database};
use tokio::sync::broadcast;
use tokio::time::{interval, sleep};
use tracing::{debug, info, warn};

use super::types::{ConsensusState, Round, Step, TimeoutConfig, View, VoteType};
use super::vote::{Vote, VoteSet};
use crate::engine::{ConsensusEngine, ConsensusEvent};
use crate::{ConsensusError, Result};

/// BFT consensus engine
pub struct BftEngine {
    /// Database
    db: Arc<Database>,
    /// State manager
    state: Arc<StateManager>,
    /// Block executor
    executor: Arc<BlockExecutor>,
    /// Transaction mempool
    mempool: Arc<Mempool>,
    /// Chain parameters
    params: ChainParams,
    /// Validator public keys
    validators: Vec<PublicKey>,
    /// This node's validator key (if validator)
    validator_key: Option<KeyPair>,
    /// Consensus state
    consensus_state: RwLock<ConsensusState>,
    /// Current best block
    best_block: RwLock<Option<Block>>,
    /// Prevote vote sets by view
    prevotes: RwLock<HashMap<View, VoteSet>>,
    /// Precommit vote sets by view
    precommits: RwLock<HashMap<View, VoteSet>>,
    /// Timeout configuration
    timeout_config: TimeoutConfig,
    /// Event broadcaster
    event_tx: broadcast::Sender<ConsensusEvent>,
    /// Running flag
    running: RwLock<bool>,
}

impl BftEngine {
    /// Create a new BFT consensus engine
    pub fn new(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        genesis: &Genesis,
        validator_key: Option<KeyPair>,
    ) -> Result<Self> {
        let validators = genesis
            .validator_pubkeys()
            .map_err(|e| ConsensusError::Genesis(e.to_string()))?;

        let executor = Arc::new(BlockExecutor::new(state.clone(), genesis.params.clone()));
        let (event_tx, _) = broadcast::channel(100);

        let consensus_state = ConsensusState::new(0);

        Ok(Self {
            db,
            state,
            executor,
            mempool,
            params: genesis.params.clone(),
            validators: validators.clone(),
            validator_key,
            consensus_state: RwLock::new(consensus_state),
            best_block: RwLock::new(None),
            prevotes: RwLock::new(HashMap::new()),
            precommits: RwLock::new(HashMap::new()),
            timeout_config: TimeoutConfig::default(),
            event_tx,
            running: RwLock::new(false),
        })
    }

    /// Get leader for a given view
    fn get_leader(&self, view: &View) -> PublicKey {
        let index = (view.height + view.round as u64) % self.validators.len() as u64;
        self.validators[index as usize]
    }

    /// Check if this node is the leader for a view
    fn is_leader(&self, view: &View) -> bool {
        if let Some(ref keypair) = self.validator_key {
            self.get_leader(view) == *keypair.public_key()
        } else {
            false
        }
    }

    /// Broadcast a vote
    fn broadcast_vote(&self, vote: Vote) {
        // In a real implementation, this would send the vote over P2P network
        // For now, we just process it locally
        self.process_vote(vote);
    }

    /// Process a received vote
    fn process_vote(&self, vote: Vote) {
        let view = vote.view;
        let vote_type = vote.vote_type;

        let mut vote_sets = match vote_type {
            VoteType::Prevote => self.prevotes.write(),
            VoteType::Precommit => self.precommits.write(),
        };

        let vote_set = vote_sets
            .entry(view)
            .or_insert_with(|| VoteSet::new(view, vote_type, self.validators.len()));

        match vote_set.add_vote(vote) {
            Ok(true) => {
                debug!("Added {:?} vote for view {:?}", vote_type, view);

                // Check if we have quorum
                if let Some(block_hash) = vote_set.has_two_thirds_majority() {
                    self.on_quorum_reached(view, vote_type, block_hash);
                }
            }
            Ok(false) => {
                // Duplicate vote, ignore
            }
            Err(e) => {
                warn!("Invalid vote: {:?}", e);
            }
        }
    }

    /// Handle quorum being reached
    fn on_quorum_reached(&self, view: View, vote_type: VoteType, block_hash: Hash) {
        let mut state = self.consensus_state.write();

        if state.view != view {
            return; // Old view, ignore
        }

        match vote_type {
            VoteType::Prevote => {
                // >2/3 prevotes -> move to precommit
                if state.step == Step::Prevote {
                    info!("Quorum of prevotes reached for {}", block_hash);
                    state.valid_block = Some(block_hash);
                    state.valid_round = Some(view.round);
                    state.move_to_step(Step::Precommit);

                    // Send our precommit
                    if let Some(ref keypair) = self.validator_key {
                        let vote = Vote::new(view, VoteType::Precommit, Some(block_hash), keypair);
                        self.broadcast_vote(vote);
                    }
                }
            }
            VoteType::Precommit => {
                // >2/3 precommits -> commit block
                if state.step == Step::Precommit {
                    info!("Quorum of precommits reached for {}", block_hash);

                    // Load and commit the block
                    // In real implementation, we'd execute and finalize here
                    state.move_to_height(view.height + 1);

                    // Notify of block finalization
                    let _ = self.event_tx.send(ConsensusEvent::BlockFinalized(block_hash, view.height));
                }
            }
        }
    }

    /// Propose a block (leader only)
    async fn propose(&self, view: View) -> Result<()> {
        if !self.is_leader(&view) {
            return Ok(());
        }

        info!("Proposing block for height {}, round {}", view.height, view.round);

        // Get transactions from mempool
        let txs = self.mempool.get_pending(1000); // Max 1000 txs per block

        // Create block proposal
        // In real implementation, we'd build a proper block here

        // For now, just move to prevote
        let mut state = self.consensus_state.write();
        state.move_to_step(Step::Prevote);

        Ok(())
    }

    /// Send prevote
    fn send_prevote(&self, view: View, block_hash: Option<Hash>) {
        if let Some(ref keypair) = self.validator_key {
            let vote = Vote::new(view, VoteType::Prevote, block_hash, keypair);
            self.broadcast_vote(vote);
        }
    }

    /// Consensus round loop
    async fn consensus_loop(&self) {
        let mut tick = interval(Duration::from_millis(100));

        while *self.running.read() {
            tick.tick().await;

            let state = self.consensus_state.read().clone();
            let view = state.view;

            match state.step {
                Step::Propose => {
                    // Wait for proposal or timeout
                    if self.is_leader(&view) {
                        if let Err(e) = self.propose(view).await {
                            warn!("Failed to propose: {:?}", e);
                        }
                    }
                }
                Step::Prevote => {
                    // Check if we should vote
                    // Simplified: vote for valid block or nil
                    if let Some(valid_block) = state.valid_block {
                        self.send_prevote(view, Some(valid_block));
                    }
                }
                Step::Precommit => {
                    // Handled by on_quorum_reached
                }
                Step::Commit => {
                    // Block committed, move to next height
                }
            }

            // Handle timeouts
            // In real implementation, we'd have proper timeout logic here
        }
    }
}

#[async_trait]
impl ConsensusEngine for BftEngine {
    async fn start(&self) -> Result<()> {
        info!("Starting BFT consensus engine");
        *self.running.write() = true;

        // Spawn consensus loop
        let engine = self.clone(); // Would need Clone impl
        tokio::spawn(async move {
            // engine.consensus_loop().await;
        });

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping BFT consensus engine");
        *self.running.write() = false;
        Ok(())
    }

    fn is_validator(&self) -> bool {
        self.validator_key.is_some()
    }

    fn current_height(&self) -> BlockHeight {
        self.consensus_state.read().view.height
    }

    fn best_block_hash(&self) -> Hash {
        self.best_block
            .read()
            .as_ref()
            .map(|b| b.hash())
            .unwrap_or(Hash::ZERO)
    }

    fn validators(&self) -> Vec<[u8; 32]> {
        self.validators.clone()
    }

    async fn import_block(&self, block: Block) -> Result<()> {
        // Verify and import block
        info!("Importing block at height {}", block.height());
        *self.best_block.write() = Some(block.clone());
        Ok(())
    }

    async fn propose_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block> {
        // Create block (simplified)
        Err(ConsensusError::NotImplemented)
    }

    fn is_proposer(&self, height: BlockHeight) -> bool {
        let view = View::new(height, 0);
        self.is_leader(&view)
    }

    fn get_proposer(&self, height: BlockHeight) -> [u8; 32] {
        let view = View::new(height, 0);
        self.get_leader(&view)
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ConsensusEvent> {
        self.event_tx.subscribe()
    }

    fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        let block_store = BlockStore::new(&self.db);
        block_store.get_by_height(height).ok().flatten()
    }

    fn load_chain(&self) -> Result<Option<Block>> {
        let block_store = BlockStore::new(&self.db);
        let block = block_store.get_latest()?;
        if let Some(ref b) = block {
            *self.best_block.write() = Some(b.clone());
            let mut state = self.consensus_state.write();
            state.move_to_height(b.height() + 1);
        }
        Ok(block)
    }

    fn init_genesis(&self, genesis: &Genesis) -> Result<()> {
        info!("Initializing BFT chain from genesis");

        // Initialize state
        self.state
            .init_from_genesis(genesis)
            .map_err(|e| ConsensusError::State(e))?;

        // Create genesis block
        let genesis_block = genesis
            .create_genesis_block()
            .map_err(|e| ConsensusError::Genesis(e.to_string()))?;

        // Store genesis
        let block_store = BlockStore::new(&self.db);
        block_store.put(&genesis_block)?;
        block_store.set_latest_hash(&genesis_block.hash())?;
        block_store.set_latest_height(0)?;

        *self.best_block.write() = Some(genesis_block);

        Ok(())
    }

    fn finalized_height(&self) -> BlockHeight {
        // In BFT, finalized height = current height (immediate finality)
        self.current_height().saturating_sub(1)
    }

    fn finalized_hash(&self) -> Hash {
        self.best_block_hash()
    }

    fn is_finalized(&self, height: BlockHeight) -> bool {
        height <= self.finalized_height()
    }

    fn finality_depth(&self) -> u64 {
        0 // Immediate finality in BFT
    }
}
