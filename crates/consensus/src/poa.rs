//! Proof of Authority consensus engine.
//!
//! Validators take turns proposing blocks in round-robin order.
//! The proposer for height H is validators[H % N] where N is validator count.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Block, BlockHeader, BlockHeight, Hash, SignedTransaction, Timestamp,
};
use sumchain_state::{BlockExecutor, Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, ReceiptStore, TxStore};
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::engine::{ConsensusEngine, ConsensusEvent, ForkChoice, LongestChainForkChoice};
use crate::{ConsensusError, Result};

/// Proof of Authority consensus engine
pub struct PoAEngine {
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
    validators: Vec<[u8; 32]>,
    /// This node's validator key (if validator)
    validator_key: Option<KeyPair>,
    /// Current best block
    best_block: RwLock<Option<Block>>,
    /// Fork choice rule
    fork_choice: LongestChainForkChoice,
    /// Event broadcaster
    event_tx: broadcast::Sender<ConsensusEvent>,
    /// Running flag
    running: RwLock<bool>,
    /// Last finalized block height
    last_finalized_height: RwLock<BlockHeight>,
    /// Last finalized block hash
    last_finalized_hash: RwLock<Hash>,
}

impl PoAEngine {
    /// Create a new PoA consensus engine
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

        let executor = Arc::new(BlockExecutor::new(state.clone(), db.clone(), genesis.params.clone()));
        let (event_tx, _) = broadcast::channel(100);

        Ok(Self {
            db,
            state,
            executor,
            mempool,
            params: genesis.params.clone(),
            validators,
            validator_key,
            best_block: RwLock::new(None),
            fork_choice: LongestChainForkChoice,
            event_tx,
            running: RwLock::new(false),
            last_finalized_height: RwLock::new(0),
            last_finalized_hash: RwLock::new(Hash::ZERO),
        })
    }

    /// Initialize from genesis
    pub fn init_genesis(&self, genesis: &Genesis) -> Result<Block> {
        info!("Initializing chain from genesis");

        // Initialize state from genesis allocations
        self.state
            .init_from_genesis(genesis)
            .map_err(|e| ConsensusError::State(e))?;

        // Create genesis block
        let genesis_block = genesis
            .create_genesis_block()
            .map_err(|e| ConsensusError::Genesis(e.to_string()))?;

        // Store genesis block
        let block_store = BlockStore::new(&self.db);
        block_store.put(&genesis_block)?;
        block_store.set_latest_hash(&genesis_block.hash())?;
        block_store.set_latest_height(0)?;

        // Set as best block
        *self.best_block.write() = Some(genesis_block.clone());

        info!(
            "Genesis block created: {} (height 0)",
            genesis_block.hash()
        );

        Ok(genesis_block)
    }

    /// Load existing chain state
    pub fn load_chain(&self) -> Result<Option<Block>> {
        let block_store = BlockStore::new(&self.db);

        match block_store.get_latest()? {
            Some(block) => {
                info!(
                    "Loaded chain at height {} ({})",
                    block.height(),
                    block.hash()
                );
                *self.best_block.write() = Some(block.clone());

                // Restore finality state from storage
                if let Ok(Some(finalized_height)) = block_store.get_finalized_height() {
                    *self.last_finalized_height.write() = finalized_height;
                    if let Ok(Some(finalized_hash)) = block_store.get_finalized_hash() {
                        *self.last_finalized_hash.write() = finalized_hash;
                    }
                    info!(
                        "Restored finality state: height {} finalized",
                        finalized_height
                    );
                }

                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Get the current timestamp
    fn current_timestamp() -> Timestamp {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as Timestamp
    }

    /// Check and update finality based on current chain state
    /// A block becomes finalized when finality_depth blocks have been built on top
    fn check_finality(&self) {
        let current_height = self.current_height();
        let finality_depth = self.params.finality_depth;
        let last_finalized = *self.last_finalized_height.read();

        // Can't finalize blocks at or below current finalized height
        if current_height <= finality_depth {
            return;
        }

        // The highest block that can be finalized
        let can_finalize_up_to = current_height - finality_depth;

        // Only process if we have new blocks to finalize
        if can_finalize_up_to <= last_finalized {
            return;
        }

        // Finalize blocks from last_finalized+1 to can_finalize_up_to
        let block_store = BlockStore::new(&self.db);
        for height in (last_finalized + 1)..=can_finalize_up_to {
            if let Ok(Some(block)) = block_store.get_by_height(height) {
                let hash = block.hash();
                *self.last_finalized_height.write() = height;
                *self.last_finalized_hash.write() = hash;

                // Persist finality state to storage
                if let Err(e) = block_store.set_finalized_height(height) {
                    warn!("Failed to persist finalized height: {}", e);
                }
                if let Err(e) = block_store.set_finalized_hash(&hash) {
                    warn!("Failed to persist finalized hash: {}", e);
                }

                // Emit finalization event
                let _ = self.event_tx.send(ConsensusEvent::BlockFinalized(hash, height));

                debug!("Block {} finalized at height {}", hash, height);
            }
        }

        info!(
            "Finality checkpoint: height {} (current: {}, depth: {})",
            can_finalize_up_to, current_height, finality_depth
        );
    }

    /// Get the last finalized block height
    pub fn finalized_height(&self) -> BlockHeight {
        *self.last_finalized_height.read()
    }

    /// Get the last finalized block hash
    pub fn finalized_hash(&self) -> Hash {
        *self.last_finalized_hash.read()
    }

    /// Check if a block at a given height is finalized
    pub fn is_finalized(&self, height: BlockHeight) -> bool {
        height <= *self.last_finalized_height.read()
    }

    /// Create a new block
    fn create_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block> {
        let validator_key = self
            .validator_key
            .as_ref()
            .ok_or(ConsensusError::NotValidator)?;

        let best_block = self
            .best_block
            .read()
            .clone()
            .ok_or(ConsensusError::ParentNotFound)?;

        let height = best_block.height() + 1;

        // Check if we're the proposer
        if !self.is_proposer(height) {
            return Err(ConsensusError::NotProposer);
        }

        // Compute tx root
        let tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let tx_root = Hash::merkle_root(&tx_hashes);

        // Create header (state_root will be set after execution)
        let header = BlockHeader::new(
            best_block.hash(),
            height,
            Self::current_timestamp(),
            tx_root,
            Hash::ZERO, // Will be updated
            *validator_key.public_key().as_bytes(),
        );

        // Create block
        let mut block = Block::new(header, transactions);

        // Execute block to get state root
        let (receipts, state_root, state_diff) = self
            .executor
            .execute_block(&block, self.state.state_root())?;

        // Update state root in header
        block.header.state_root = state_root;

        // Sign the block
        let signing_hash = block.header.signing_hash();
        let signature = sign(signing_hash.as_bytes(), validator_key.private_key());
        block.header.set_signature(*signature.as_bytes());

        // Store receipts and transactions
        let tx_store = TxStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        for tx in &block.transactions {
            tx_store.put(tx)?;
        }
        for receipt in &receipts {
            receipt_store.put(receipt)?;
        }

        // Store state diff for potential reorg
        self.state.save_state_diff(height, state_diff)?;

        // Store the block
        let block_store = BlockStore::new(&self.db);
        block_store.put(&block)?;
        block_store.set_latest_hash(&block.hash())?;
        block_store.set_latest_height(height)?;

        // Update best block
        *self.best_block.write() = Some(block.clone());

        // Remove included transactions from mempool
        let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.mempool.remove_batch(&tx_hashes);

        info!(
            "Created block {} at height {} with {} txs",
            block.hash(),
            height,
            block.tx_count()
        );

        // Check if any blocks can be finalized
        self.check_finality();

        Ok(block)
    }

    /// Validate and import a block
    async fn do_import_block(&self, block: Block) -> Result<()> {
        let hash = block.hash();
        let height = block.height();

        // Check if block already exists
        let block_store = BlockStore::new(&self.db);
        if block_store.contains(&hash)? {
            debug!("Block {} already exists", hash);
            return Ok(());
        }

        // Get parent block
        let parent = if height == 0 {
            None
        } else {
            block_store
                .get_by_hash(&block.header.parent_hash)?
                .ok_or(ConsensusError::ParentNotFound)?
                .into()
        };

        // Validate block
        self.executor
            .validate_block(&block, parent.as_ref(), &self.validators)?;

        // Execute block
        let (receipts, state_root, state_diff) = self
            .executor
            .execute_block(&block, self.state.state_root())?;

        // Verify state root matches
        if block.header.state_root != state_root {
            return Err(ConsensusError::InvalidBlock(format!(
                "State root mismatch: expected {}, got {}",
                block.header.state_root, state_root
            )));
        }

        // Store block
        block_store.put(&block)?;

        // Store receipts and transactions
        let tx_store = TxStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        for tx in &block.transactions {
            tx_store.put(tx)?;
        }
        for receipt in &receipts {
            receipt_store.put(receipt)?;
        }

        // Store state diff
        self.state.save_state_diff(height, state_diff)?;

        // Update best block if this extends the chain
        let current_best = self.best_block.read().clone();
        let should_update = match &current_best {
            Some(best) => self.fork_choice.should_switch(best, &block),
            None => true,
        };

        if should_update {
            // Handle reorg if needed
            if let Some(old_best) = &current_best {
                if block.header.parent_hash != old_best.hash() {
                    // This is a reorg
                    let reorg_depth = self.handle_reorg(old_best, &block).await?;
                    let _ = self.event_tx.send(ConsensusEvent::Reorg {
                        old_head: old_best.hash(),
                        new_head: block.hash(),
                        depth: reorg_depth,
                    });
                }
            }

            block_store.set_latest_hash(&hash)?;
            block_store.set_latest_height(height)?;
            *self.best_block.write() = Some(block.clone());

            // Remove included transactions from mempool
            let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
            self.mempool.remove_batch(&tx_hashes);

            let _ = self.event_tx.send(ConsensusEvent::BlockImported(block));
        }

        info!("Imported block {} at height {}", hash, height);

        // Check if any blocks can be finalized
        self.check_finality();

        Ok(())
    }

    /// Handle chain reorganization
    async fn handle_reorg(&self, old_head: &Block, new_head: &Block) -> Result<u64> {
        // Find common ancestor
        let block_store = BlockStore::new(&self.db);

        let mut old_chain = vec![old_head.clone()];
        let mut new_chain = vec![new_head.clone()];

        // Walk back both chains to find common ancestor
        while old_chain.last().unwrap().hash() != new_chain.last().unwrap().hash() {
            let old_tip_height = old_chain.last().unwrap().height();
            let new_tip_height = new_chain.last().unwrap().height();
            let old_tip_parent = old_chain.last().unwrap().header.parent_hash;
            let new_tip_parent = new_chain.last().unwrap().header.parent_hash;

            if old_tip_height >= new_tip_height {
                if let Some(parent) = block_store.get_by_hash(&old_tip_parent)? {
                    old_chain.push(parent);
                }
            }

            if new_tip_height >= old_tip_height {
                if let Some(parent) = block_store.get_by_hash(&new_tip_parent)? {
                    new_chain.push(parent);
                }
            }
        }

        let reorg_depth = old_chain.len() as u64 - 1;

        warn!(
            "Reorg detected: reverting {} blocks, applying {} blocks",
            old_chain.len() - 1,
            new_chain.len() - 1
        );

        // Revert old chain blocks (except common ancestor)
        for block in old_chain.iter().rev().skip(1) {
            self.state.revert_state_diff(block.height())?;

            // Return transactions to mempool
            for tx in &block.transactions {
                let _ = self.mempool.add(tx.clone());
            }
        }

        // Note: new chain blocks are already applied during import

        Ok(reorg_depth)
    }

    /// Run the block production loop (for validators)
    pub async fn run_block_producer(&self) {
        if self.validator_key.is_none() {
            debug!("Not a validator, skipping block production");
            return;
        }

        // Wait for network mesh to form before starting block production
        // This gives peers time to connect and subscribe to topics
        debug!("Waiting for network mesh to form...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        let block_time = Duration::from_millis(self.params.block_time_ms);
        let mut interval = interval(block_time);

        info!("Block producer started with {}ms block time", self.params.block_time_ms);

        while *self.running.read() {
            interval.tick().await;

            let height = self.current_height() + 1;
            let is_our_turn = self.is_proposer(height);

            debug!("Block tick: height={}, is_proposer={}", height, is_our_turn);

            if is_our_turn {
                info!("Our turn to propose block {}", height);

                // Select transactions from mempool
                let txs = self
                    .mempool
                    .select_for_block(self.params.max_txs_per_block as usize);

                match self.create_block(txs) {
                    Ok(block) => {
                        let hash = block.hash();
                        // Block is already stored and best_block updated in create_block
                        // Just emit the event and broadcast
                        let _ = self.event_tx.send(ConsensusEvent::BlockProduced(block));
                        info!("Produced block {} at height {}", hash, height);
                    }
                    Err(e) => {
                        warn!("Failed to create block: {}", e);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ConsensusEngine for PoAEngine {
    async fn start(&self) -> Result<()> {
        *self.running.write() = true;
        info!("PoA consensus engine started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        *self.running.write() = false;
        info!("PoA consensus engine stopped");
        Ok(())
    }

    fn is_validator(&self) -> bool {
        self.validator_key.is_some()
    }

    fn current_height(&self) -> BlockHeight {
        self.best_block
            .read()
            .as_ref()
            .map(|b| b.height())
            .unwrap_or(0)
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
        self.do_import_block(block).await
    }

    async fn propose_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block> {
        self.create_block(transactions)
    }

    fn is_proposer(&self, height: BlockHeight) -> bool {
        let Some(key) = &self.validator_key else {
            return false;
        };

        let expected_proposer = self.get_proposer(height);
        *key.public_key().as_bytes() == expected_proposer
    }

    fn get_proposer(&self, height: BlockHeight) -> [u8; 32] {
        let idx = (height as usize) % self.validators.len();
        self.validators[idx]
    }

    fn subscribe(&self) -> broadcast::Receiver<ConsensusEvent> {
        self.event_tx.subscribe()
    }

    fn get_block_by_height(&self, height: BlockHeight) -> Option<Block> {
        let block_store = BlockStore::new(&self.db);
        block_store.get_by_height(height).ok().flatten()
    }

    fn load_chain(&self) -> Result<Option<Block>> {
        PoAEngine::load_chain(self)
    }

    fn init_genesis(&self, genesis: &Genesis) -> Result<()> {
        PoAEngine::init_genesis(self, genesis)?;
        Ok(())
    }

    fn finalized_height(&self) -> BlockHeight {
        PoAEngine::finalized_height(self)
    }

    fn finalized_hash(&self) -> Hash {
        PoAEngine::finalized_hash(self)
    }

    fn is_finalized(&self, height: BlockHeight) -> bool {
        PoAEngine::is_finalized(self, height)
    }

    fn finality_depth(&self) -> u64 {
        self.params.finality_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_state::MempoolConfig;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, Arc<StateManager>, Arc<Mempool>, Genesis, [u8; 32], TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());

        let validator = KeyPair::generate();
        let validator_key_bytes = *validator.private_key().as_bytes();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000)]),
            ChainParams::default(),
        );

        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

        (db, state, mempool, genesis, validator_key_bytes, dir)
    }

    #[tokio::test]
    async fn test_init_genesis() {
        let (db, state, mempool, genesis, validator_key, _dir) = setup();

        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool,
            &genesis,
            Some(KeyPair::from_bytes(validator_key)),
        )
        .unwrap();

        let genesis_block = engine.init_genesis(&genesis).unwrap();

        assert_eq!(genesis_block.height(), 0);
        assert!(genesis_block.header.parent_hash.is_zero());
        assert_eq!(engine.current_height(), 0);
    }

    #[tokio::test]
    async fn test_is_proposer() {
        let (db, state, mempool, genesis, validator_key, _dir) = setup();

        let engine = PoAEngine::new(db, state, mempool, &genesis, Some(KeyPair::from_bytes(validator_key))).unwrap();

        // With single validator, always our turn
        assert!(engine.is_proposer(0));
        assert!(engine.is_proposer(1));
        assert!(engine.is_proposer(100));
    }

    #[tokio::test]
    async fn test_create_block() {
        let (db, state, mempool, genesis, validator_key, _dir) = setup();

        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool,
            &genesis,
            Some(KeyPair::from_bytes(validator_key)),
        )
        .unwrap();

        engine.init_genesis(&genesis).unwrap();

        let block = engine.create_block(vec![]).unwrap();

        assert_eq!(block.height(), 1);
        assert!(block.transactions.is_empty());
    }
}
