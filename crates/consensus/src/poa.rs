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
use sumchain_state::reorg_undo::{MissingJournalPolicy, SubsystemJournals};
use sumchain_state::{BlockExecutor, Mempool, StateManager};
use sumchain_storage::{
    BlockStore, Database, DelegationStore, StakingStore, TxStore, ValidatorSetStore,
};
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::engine::{ConsensusEngine, ConsensusEvent, ForkChoice, LongestChainForkChoice};
use crate::reorg::{execute_reorg, plan_reorg};
use crate::{ConsensusError, Result};

/// Proof of Authority consensus engine
/// How a block relates to the current chain, decided BEFORE it is executed.
///
/// Classifying first is the point: deciding afterwards is what let a block that
/// loses fork choice write its state, journals and indexes and only then be
/// rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Extends the current head and wins fork choice. Publishes.
    DirectExtension,
    /// Loses fork choice. Never reaches the canonical publisher.
    SideBranch,
    /// Wins fork choice but does not extend the current head. Needs
    /// ancestor-based whole-branch execution, not the one-block publisher.
    Reorg,
}

/// Upper bound on how far the ancestor walk may travel.
///
/// An allocation bound, not a consensus rule: `plan_reorg` walks both branches
/// into memory, and a malformed or hostile branch must not be able to make that
/// unbounded. What actually limits how deep a switch may go is finality, which
/// is checked separately and refuses a walk below the finalized height. This
/// only stops a walk that would never meet.
const MAX_REORG_WALK: u64 = 4_096;

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
        let execution = self
            .executor
            .execute_block(&block, self.state.state_root(), &active_validators)?;
        let state_root = execution.computed_root();
        // The diffs are no longer needed here: the journals they encode were
        // bound to the candidate at execution completion and are written by the
        // publisher, in the same batch as the state they invert.
        let (executed, _state_diff, _contract_diff) = execution.into_parts();

        // Update state root in header
        block.header.state_root = state_root;

        // Sign the block
        let signing_hash = block.header.signing_hash();
        let signature = sign(signing_hash.as_bytes(), validator_key.private_key());
        block.header.set_signature(*signature.as_bytes());

        // ── accept, then publish, then announce ─────────────────────────────
        //
        // Signing precedes the PUBLISHER, so a signing failure publishes nothing
        // — no block record, no journals, no head. It does NOT precede every
        // persistent write: `execute_block` above already wrote canonical state
        // through the 36 unmigrated sites, and those are not undone by failing
        // here. An earlier version of this comment claimed the stronger
        // property, which is false until the ratchet reaches zero.
        //
        // Publication precedes every in-memory update and every event, so a
        // publication failure announces nothing: a block the network hears about
        // is a block that is durably on disk.
        let accepted = executed.accept_produced(&block).map_err(|e| {
            ConsensusError::InvalidBlock(format!(
                "produced block {} at height {height} rejected: {e}",
                block.hash()
            ))
        })?;
        let accumulator = accepted.accumulator();

        accepted.publish().map_err(|e| {
            ConsensusError::InvalidBlock(format!(
                "publishing produced block {} at height {height} failed: {e}",
                block.hash()
            ))
        })?;

        // ── only after a durable commit ─────────────────────────────────────
        self.state.set_state_root(accumulator);

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

        // ── classify BEFORE executing ───────────────────────────────────────
        //
        // Fork choice is a decision about the block, not about its execution, so
        // it can be made first — and must be. Deciding afterwards is what let a
        // losing side block write its state, journals and indexes before being
        // rejected.
        let current_best = self.best_block.read().clone();
        let admission = match &current_best {
            None => Admission::DirectExtension,
            Some(best) => {
                if !self.fork_choice.should_switch(best, &block) {
                    Admission::SideBranch
                } else if block.header.parent_hash == best.hash() {
                    Admission::DirectExtension
                } else {
                    Admission::Reorg
                }
            }
        };

        match admission {
            Admission::DirectExtension => {
                let execution = self.executor.execute_block(
                    &block,
                    self.state.state_root(),
                    &active_validators,
                )?;
                let (executed, _state_diff, _contract_diff) = execution.into_parts();

                // Acceptance owns the root comparison AND the historical
                // compatibility window; the cutoff lives inside
                // `accept_imported` so no call site can widen it.
                let accepted = executed.accept_imported(&block).map_err(|e| {
                    ConsensusError::InvalidBlock(format!(
                        "block {hash} at height {height} rejected: {e}"
                    ))
                })?;
                let accumulator = accepted.accumulator();

                // One batch: state, block by hash and height, transactions,
                // receipts, both indexes, all journals, latest head.
                accepted.publish().map_err(|e| {
                    ConsensusError::InvalidBlock(format!(
                        "publishing block {hash} at height {height} failed: {e}"
                    ))
                })?;

                // ── only after a durable commit ─────────────────────────────
                self.state.set_state_root(accumulator);
                *self.best_block.write() = Some(block.clone());
                let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
                self.mempool.remove_batch(&tx_hashes);
                let _ = self.event_tx.send(ConsensusEvent::BlockImported(block));
            }

            Admission::SideBranch => {
                // A block that loses fork choice must not reach the canonical
                // publisher: no state, no journals, no height index, no head.
                //
                // It is still executed, because validity is not yet decidable
                // without executing — and that execution still writes canonical
                // state directly through the 36 unmigrated sites. That is a
                // KNOWN and UNFIXED hole: until the ratchet reaches zero, a side
                // block dirties canonical state even though it publishes
                // nothing. Recording it here rather than implying the publisher
                // closes it.
                let execution = self.executor.execute_block(
                    &block,
                    self.state.state_root(),
                    &active_validators,
                )?;
                let (executed, _state_diff, _contract_diff) = execution.into_parts();
                // Acceptance still runs, so an invalid side block is refused on
                // the same terms as a canonical one.
                let _ = executed.accept_imported(&block).map_err(|e| {
                    ConsensusError::InvalidBlock(format!(
                        "side block {hash} at height {height} rejected: {e}"
                    ))
                })?;

                self.archive_noncanonical(&block)?;
                debug!(
                    "Block {} at height {} lost fork choice; archived without publishing",
                    hash, height
                );
            }

            Admission::Reorg => {
                self.import_reorg(block, &block_store, &active_validators)?;
            }
        }

        info!("Imported block {} at height {}", hash, height);

        // Check if any blocks can be finalized
        self.check_finality();

        // Check if we need to update the validator set (epoch boundary)
        self.maybe_update_validator_set(height, &hash);

        Ok(())
    }

    /// Retain a block that lost fork choice, without touching canonical state.
    ///
    /// Only branch-safe rows: `BLOCKS[block_hash]` is keyed by the block's own
    /// hash, and `TRANSACTIONS[tx_hash]` by the transaction's, so neither can
    /// overwrite a different branch's row — and a transaction present on both
    /// branches serializes identically, which is checked rather than assumed.
    ///
    /// Deliberately NOT archived: `BLOCK_HEIGHT`, which is keyed by height alone
    /// and would point the canonical height index at an abandoned block;
    /// receipts, keyed by transaction hash but whose contents are branch
    /// -specific, so a side branch's receipt would overwrite the canonical one
    /// for the same transaction; the address indexes, keyed by
    /// `(address, height, tx_index)` with no branch identity; and state,
    /// journals and latest-head metadata, none of which a non-canonical block
    /// may touch at all.
    fn archive_noncanonical(&self, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        let block_store = BlockStore::new(&self.db);
        let tx_store = TxStore::new(&self.db);

        // ── pass 1: preflight, retaining nothing ────────────────────────────
        //
        // Every row is compared against freshly-computed bytes and the bytes are
        // dropped immediately. An earlier version kept the serialized payload of
        // every missing transaction in a `Vec` between the two passes — a second
        // copy of the block's payload, held outside any accounting, which is the
        // same unaccounted duplication removed from the publication path and
        // from the execution subject. Serializing twice is the cost; retaining a
        // block-sized buffer is not.
        //
        // These rows are content-addressed — the key IS the hash of the value —
        // so differing bytes under one key mean a collision or an encoding
        // change, not a legitimate update. Refusing is the only safe answer,
        // and it must happen before anything is written.
        if let Some(existing) = block_store.get_raw(&block_hash)? {
            if existing != block.to_bytes() {
                return Err(ConsensusError::InvalidBlock(format!(
                    "archiving side block {block_hash}: a different block is already \
                     stored under that hash; refusing to overwrite"
                )));
            }
        }
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            if let Some(existing) = tx_store.get_raw(&tx_hash)? {
                if existing != tx.to_bytes() {
                    return Err(ConsensusError::InvalidBlock(format!(
                        "archiving side block {block_hash}: transaction {tx_hash} is \
                         already stored with different bytes; refusing to overwrite"
                    )));
                }
            }
        }

        // ── pass 2: stage everything into one batch ─────────────────────────
        //
        // Rows that already exist are written again rather than skipped. They
        // are content-addressed and pass 1 proved them byte-identical, so the
        // rewrite is a no-op in content — and not tracking which were missing is
        // precisely what lets pass 1 keep nothing.
        let mut batch = self.db.batch();
        batch.put(
            sumchain_storage::db::cf::BLOCKS,
            block_hash.as_bytes(),
            &block.to_bytes(),
        )?;
        for tx in &block.transactions {
            batch.put(
                sumchain_storage::db::cf::TRANSACTIONS,
                tx.hash().as_bytes(),
                &tx.to_bytes(),
            )?;
        }
        batch.commit()?;
        Ok(())
    }

    /// Switch to a branch that wins fork choice but does not extend the head.
    ///
    /// A reorg is ONE decision over a whole branch, and the one-block publisher
    /// cannot express it: publishing the new head alone leaves the abandoned
    /// branch's state applied beneath it.
    ///
    /// The sequence this replaces did exactly that, and worse. It executed the
    /// arriving block and then DROPPED the candidate — no acceptance, no
    /// publication — so since execution moved behind the overlay the adopted
    /// block's state was never committed at all; only its journal, block row,
    /// transactions and receipts were. It then reverted the abandoned branch
    /// oldest-first, which leaves the intermediate value for any key more than
    /// one block touched, through an ancestor walk that did not terminate on a
    /// missing parent. Its own comment — "new chain blocks are already applied
    /// during import" — had stopped being true.
    ///
    /// What happens instead, in order:
    ///
    /// 1. Retain the arriving block, so the ancestor walk can see it.
    /// 2. [`plan_reorg`] resolves the fork BY HASH and refuses a gap, a switch
    ///    below finality, or a walk past the allocation bound — before anything
    ///    is written.
    /// 3. [`execute_reorg`] unwinds the abandoned branch newest-first from its
    ///    per-block journals, validating each pre-image against the value the
    ///    journal says the block left, in ONE batch that also carries the
    ///    de-indexing and the head reset; restores the accumulator from the
    ///    ancestor's header; and applies the adopted branch through the ordinary
    ///    publication path, one atomic batch per block.
    ///
    /// Nothing outside this arm changes. A block that extends the head or loses
    /// fork choice takes the same path it did before.
    fn import_reorg(
        &self,
        block: Block,
        block_store: &BlockStore<'_>,
        active_validators: &[[u8; 32]],
    ) -> Result<()> {
        let hash = block.hash();
        let height = block.height();

        // The ancestor walk reads `BLOCKS`, so the arriving block has to be
        // there. Keyed by its own hash, so it cannot shadow anything; `publish`
        // writes the same row again when the branch is adopted.
        block_store.put(&block)?;

        let old_head = self
            .best_block
            .read()
            .clone()
            .ok_or_else(|| ConsensusError::InvalidBlock(
                "classified as a reorg with no current best block;                  a switch needs something to switch away from".to_string(),
            ))?;

        let finalized = block_store.get_finalized_height()?.unwrap_or(0);
        let plan = plan_reorg(block_store, &old_head, &block, finalized, MAX_REORG_WALK)?;

        // The four per-subsystem journals the publisher writes. See
        // `sumchain_state::reorg_undo`: the unwind depends only on their SHAPE,
        // so a generic application journal substitutes here and nowhere else.
        let journals = SubsystemJournals::new(&self.db);
        let outcome = execute_reorg(
            &self.db,
            &self.state,
            &self.executor,
            &plan,
            active_validators,
            &journals,
            // Absence is tolerated, and that is forced rather than chosen. The
            // publisher writes NO row for `JournalRecord::NothingToUndo`, so a
            // block that mutated nothing and a block whose undo record is
            // missing are the same zero bytes on disk. Halting on absence would
            // therefore refuse every reorg over an empty block.
            //
            // This becomes `RequiredFrom(h)` the moment the producer writes a
            // POSITIVE nothing-to-undo record and genesis declares the height
            // from which it does. Until then the count is surfaced instead: a
            // switch with tolerated absences has not fully unwound its branch.
            MissingJournalPolicy::ToleratedEverywhere,
        )?;

        // Only after the switch is durable.
        for abandoned in &plan.old_branch {
            for tx in &abandoned.transactions {
                let _ = self.mempool.add(tx.clone());
            }
        }
        *self.best_block.write() = Some(block.clone());
        let tx_hashes: Vec<Hash> = plan
            .new_branch
            .iter()
            .flat_map(|b| b.transactions.iter().map(|tx| tx.hash()))
            .collect();
        self.mempool.remove_batch(&tx_hashes);

        warn!(
            depth = plan.depth(),
            applied = outcome.applied,
            verified = outcome.verified,
            force_adopted = outcome.force_adopted,
            ancestor = %plan.ancestor_hash,
            old_head = %old_head.hash(),
            new_head = %hash,
            "chain reorganization"
        );
        if outcome.unwound.tolerated_absences > 0 {
            warn!(
                count = outcome.unwound.tolerated_absences,
                "the reorg unwound past {} block(s) with no undo journal; their effects on \
                 state were NOT reverted and remain applied under a chain that no longer \
                 contains them",
                outcome.unwound.tolerated_absences
            );
        }
        if outcome.force_adopted > 0 {
            // Said separately, and loudly. A block adopted under the historical
            // compatibility window had its header root published despite the
            // replay computing a different one, so the state this node now holds
            // is NOT the state the branch commits to. That is a different claim
            // from "the reorg succeeded", and collapsing the two would hide it.
            warn!(
                count = outcome.force_adopted,
                cutoff = sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT,
                "the reorg published {} block(s) whose replayed root did not match their \
                 header, under the historical compatibility allowance; this branch's state \
                 is NOT verified",
                outcome.force_adopted
            );
        }

        let _ = self.event_tx.send(ConsensusEvent::Reorg {
            old_head: old_head.hash(),
            new_head: hash,
            depth: plan.depth(),
        });
        let _ = self.event_tx.send(ConsensusEvent::BlockImported(block));
        info!("Reorged to block {} at height {}", hash, height);
        Ok(())
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
