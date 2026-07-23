//! Proof of Authority consensus engine.
//!
//! Validators take turns proposing blocks in round-robin order.
//! The proposer for height H is validators[H % N] where N is validator count.
//!
//! Supports dynamic validator sets with epoch-based transitions:
//! - Validator set is recalculated at each epoch boundary
//! - Active validators are selected by stake (self-stake + delegations)
//! - Proposer selection can be round-robin or stake-weighted

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Block, BlockHeader, BlockHeight, Hash, SignedTransaction, Timestamp,
    ValidatorSet, ValidatorSetEntry, ValidatorStatus,
};
use sumchain_state::{BlockExecutor, Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, DelegationStore, ReceiptStore, StakingStore, TxIndexStore, TxStore, ValidatorSetStore};
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
    /// Genesis validator public keys (fallback when no staking)
    genesis_validators: Vec<[u8; 32]>,
    /// Current active validator set (dynamic, updated at epoch boundaries)
    active_validator_set: RwLock<Option<ValidatorSet>>,
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
        let genesis_validators = genesis
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
            genesis_validators,
            active_validator_set: RwLock::new(None),
            validator_key,
            best_block: RwLock::new(None),
            fork_choice: LongestChainForkChoice,
            event_tx,
            running: RwLock::new(false),
            last_finalized_height: RwLock::new(0),
            last_finalized_hash: RwLock::new(Hash::ZERO),
        })
    }

    /// Get the active validator set, computing it if necessary
    fn get_active_validator_set(&self) -> Vec<[u8; 32]> {
        // Check if we have an active set
        if let Some(set) = self.active_validator_set.read().as_ref() {
            return set.pubkeys();
        }

        // Fall back to genesis validators
        self.genesis_validators.clone()
    }

    /// Compute the validator set for a new epoch based on staking state
    pub fn compute_validator_set_for_epoch(&self, epoch: u64, active_from: BlockHeight, proposer_seed: [u8; 32]) -> Result<ValidatorSet> {
        let staking_store = StakingStore::new(&self.db);
        let delegation_store = DelegationStore::new(&self.db);

        // Get all validators from staking
        let all_validators = staking_store.get_all_validators()?;

        // Filter and sort validators
        let min_stake = self.params.staking.as_ref()
            .map(|s| s.min_validator_stake)
            .unwrap_or(0);
        let max_validators = self.params.staking.as_ref()
            .map(|s| s.max_validators)
            .unwrap_or(100) as usize;

        let mut eligible_validators: Vec<ValidatorSetEntry> = all_validators
            .iter()
            .filter(|v| {
                // Must be active and not jailed
                v.status == ValidatorStatus::Active && !v.is_jailed()
            })
            .filter_map(|v| {
                // Get total voting power (self-stake + delegations)
                let delegated = delegation_store
                    .get_total_delegated_to_validator(&v.pubkey)
                    .unwrap_or(0);
                let voting_power = v.stake.saturating_add(delegated);

                // Must meet minimum stake requirement
                if voting_power >= min_stake {
                    Some(ValidatorSetEntry::new(v.pubkey, voting_power, v.commission_bps))
                } else {
                    None
                }
            })
            .collect();

        // Sort by voting power descending
        eligible_validators.sort_by(|a, b| b.voting_power.cmp(&a.voting_power));

        // Take top N validators
        eligible_validators.truncate(max_validators);

        // If no staking validators, use genesis validators
        if eligible_validators.is_empty() {
            eligible_validators = self.genesis_validators
                .iter()
                .map(|pubkey| ValidatorSetEntry::new(*pubkey, 1, 0))
                .collect();
        }

        Ok(ValidatorSet::new(epoch, active_from, eligible_validators, proposer_seed))
    }

    /// Update the validator set if at an epoch boundary
    fn maybe_update_validator_set(&self, height: BlockHeight, block_hash: &Hash) {
        let epoch_length = self.params.staking.as_ref()
            .map(|s| s.epoch_length)
            .unwrap_or(0);

        // Skip if epoch transitions are disabled
        if epoch_length == 0 {
            return;
        }

        // Check if this is an epoch boundary
        let is_epoch_boundary = height > 0 && height % epoch_length == 0;
        if !is_epoch_boundary {
            return;
        }

        let new_epoch = height / epoch_length;

        // Use the block hash as the proposer seed for the new epoch
        let proposer_seed: [u8; 32] = *block_hash.as_bytes();

        // Compute new validator set
        match self.compute_validator_set_for_epoch(new_epoch, height, proposer_seed) {
            Ok(new_set) => {
                let validator_count = new_set.len();
                let total_power = new_set.total_voting_power;

                // Store the validator set
                let set_store = ValidatorSetStore::new(&self.db);
                if let Err(e) = set_store.put_validator_set(&new_set) {
                    warn!("Failed to store validator set for epoch {}: {}", new_epoch, e);
                    return;
                }

                // Update active set
                *self.active_validator_set.write() = Some(new_set);

                info!(
                    "Epoch {} started at height {}: {} validators, total voting power {}",
                    new_epoch, height, validator_count, total_power
                );
            }
            Err(e) => {
                warn!("Failed to compute validator set for epoch {}: {}", new_epoch, e);
            }
        }
    }

    /// Get the proposer for a given height
    fn compute_proposer(&self, height: BlockHeight) -> [u8; 32] {
        let use_stake_weighted = self.params.staking.as_ref()
            .map(|s| s.stake_weighted_selection)
            .unwrap_or(false);

        // Check if we have an active validator set
        if let Some(set) = self.active_validator_set.read().as_ref() {
            if use_stake_weighted {
                if let Some(proposer) = set.get_stake_weighted_proposer(height) {
                    return proposer;
                }
            } else {
                if let Some(proposer) = set.get_round_robin_proposer(height) {
                    return proposer;
                }
            }
        }

        // Fall back to genesis validators with round-robin
        let validators = &self.genesis_validators;
        if validators.is_empty() {
            return [0u8; 32];
        }
        let idx = (height as usize) % validators.len();
        validators[idx]
    }

    /// Load or initialize the active validator set from storage
    fn load_active_validator_set(&self) -> Result<()> {
        let set_store = ValidatorSetStore::new(&self.db);

        // Try to load the current validator set
        if let Some(current_set) = set_store.get_current_validator_set()? {
            info!(
                "Loaded validator set for epoch {} ({} validators)",
                current_set.epoch, current_set.len()
            );
            *self.active_validator_set.write() = Some(current_set);
        }

        Ok(())
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

                // Restore state root cache from the latest block
                self.state.set_state_root(block.header.state_root);

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

                // Load active validator set
                if let Err(e) = self.load_active_validator_set() {
                    warn!("Failed to load validator set: {}", e);
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
        // Guarantee strict timestamp monotonicity: if local clock is behind
        // the parent (e.g. NTP skew), bump to parent_ts + 1 so validation
        // (timestamp > parent) cannot reject our own block.
        let timestamp = std::cmp::max(
            Self::current_timestamp(),
            best_block.header.timestamp.saturating_add(1),
        );
        let header = BlockHeader::new(
            best_block.hash(),
            height,
            timestamp,
            tx_root,
            Hash::ZERO, // Will be updated
            *validator_key.public_key().as_bytes(),
        );

        // Create block
        let mut block = Block::new(header, transactions);

        // Execute block to get state root. Authorize validator-quorum actions
        // against the same active set used to select this height's proposer.
        let active_validators = self.get_active_validator_set();
        let (receipts, state_root, state_diff, contract_diff) = self
            .executor
            .execute_block(&block, self.state.state_root(), &active_validators)?;

        // Update state root in header
        block.header.state_root = state_root;

        // Sign the block
        let signing_hash = block.header.signing_hash();
        let signature = sign(signing_hash.as_bytes(), validator_key.private_key());
        block.header.set_signature(*signature.as_bytes());

        // Store receipts and transactions
        let tx_store = TxStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);
        let tx_index_store = TxIndexStore::new(&self.db);

        for (tx_index, tx) in block.transactions.iter().enumerate() {
            tx_store.put(tx)?;
            // Index transaction by sender and recipient for history queries
            if let Err(e) = tx_index_store.index_transaction(tx, height, tx_index as u32) {
                warn!("Failed to index transaction {}: {}", tx.hash(), e);
            }
        }
        for receipt in &receipts {
            receipt_store.put(receipt)?;
        }

        // Store state diff for potential reorg
        self.state.save_state_diff(height, state_diff)?;
        // Persist the contract-state diff alongside the account diff, with
        // identical timing, so a reorg reverts both together.
        self.state.save_contract_state_diff(height, contract_diff)?;

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

        // Check if we need to update the validator set (epoch boundary)
        self.maybe_update_validator_set(height, &block.hash());

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
        let active_validators = self.get_active_validator_set();
        self.executor
            .validate_block(&block, parent.as_ref(), &active_validators)?;

        // Execute block. Authorize validator-quorum actions against the same
        // active set used to validate/produce this block (not the node tip).
        let (receipts, state_root, state_diff, contract_diff) = self
            .executor
            .execute_block(&block, self.state.state_root(), &active_validators)?;

        // Verify state root matches
        //
        // HISTORICAL EXCEPTION (height <= 496720):
        // A state root cache bug caused Hash::ZERO to be mixed into
        // compute_block_state_root() after node restarts during this era.
        // Some blocks in this range carry incorrect state roots permanently
        // committed in their headers. A fresh-syncing node computes the
        // *correct* root which won't match, so we skip verification and
        // force-adopt the header's root to keep the accumulator aligned
        // for the next block.
        //
        // ROOT CAUSE FIX: load_chain() now calls
        //   self.state.set_state_root(block.header.state_root)
        // on startup (line ~301), preventing the bug for all new blocks.
        // Strict enforcement applies for height > 496720.
        if block.header.state_root != state_root {
            if height <= 496720 {
                warn!(
                    "State root mismatch at height {} (historical bug window) - \
                     adopting header root to align accumulator for next block",
                    height
                );
                self.state.set_state_root(block.header.state_root);
            } else {
                return Err(ConsensusError::InvalidBlock(format!(
                    "State root mismatch at height {}: header={}, computed={}",
                    height, block.header.state_root, state_root
                )));
            }
        }

        // Store block
        block_store.put(&block)?;

        // Store receipts and transactions
        let tx_store = TxStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);
        let tx_index_store = TxIndexStore::new(&self.db);

        for (tx_index, tx) in block.transactions.iter().enumerate() {
            tx_store.put(tx)?;
            // Index transaction by sender and recipient for history queries
            if let Err(e) = tx_index_store.index_transaction(tx, height, tx_index as u32) {
                warn!("Failed to index transaction {}: {}", tx.hash(), e);
            }
        }
        for receipt in &receipts {
            receipt_store.put(receipt)?;
        }

        // Store state diff
        self.state.save_state_diff(height, state_diff)?;
        // Persist the contract-state diff alongside the account diff, with
        // identical timing, so a reorg reverts both together.
        self.state.save_contract_state_diff(height, contract_diff)?;

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

        // Check if we need to update the validator set (epoch boundary)
        self.maybe_update_validator_set(height, &hash);

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
            // Atomically revert account + contract state together, so an
            // orphaned block cannot leave contract state behind while account
            // state rolls back (or vice versa).
            self.state.revert_block_state_diffs(block.height())?;
            // Revert the dormant C1 compute-pool transition for this block too,
            // so a reorg rolls back compute-pool state alongside account +
            // contract state. GATE-CLOSED: inert (manager never constructed,
            // nothing reverted) under the production `None` gate.
            self.executor
                .revert_compute_pool_transitions(block.height())?;

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
        self.get_active_validator_set()
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
        self.compute_proposer(height)
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
