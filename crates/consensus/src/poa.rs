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
use sumchain_state::reorg_undo::ActivatedJournal;
use sumchain_state::{BlockExecutor, Mempool, StateManager};
use sumchain_storage::journal::ActivationSource;
use sumchain_storage::{
    BlockStore, Database, DelegationStore, StakingStore, TxStore, ValidatorSetStore,
};
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::engine::{ConsensusEngine, ConsensusEvent, ForkChoice, LongestChainForkChoice};
use crate::reorg::{execute_reorg, plan_reorg_within_undo_history};
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
/// An allocation bound, not a consensus rule: `crate::reorg::plan_reorg` walks both branches
/// into memory, and a malformed or hostile branch must not be able to make that
/// unbounded. What actually limits how deep a switch may go is finality, which
/// is checked separately and refuses a walk below the finalized height. This
/// only stops a walk that would never meet.
///
/// Public because it is also the UNDO RETENTION HORIZON. A block within this
/// many of the head can still be named on an abandoned branch, so its journal
/// must still exist: `sumchain_storage::pruner::UNDO_RETENTION_FLOOR` is a copy
/// of this number (the pruner sits below consensus and cannot import it), and
/// `the_pruning_floor_covers_every_reorg_this_engine_will_plan` pins the two
/// together from this side.
pub const MAX_REORG_WALK: u64 = 4_096;

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
    /// The disk budget this node was provisioned for, read once at construction
    /// from its own database. Unbudgeted by default, which is a no-op.
    capacity: sumchain_storage::pruner::CapacityGuard,
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
        let capacity = sumchain_storage::pruner::CapacityGuard::from_db(&db).unwrap_or_else(|e| {
            warn!("unreadable disk budget row ({e}); treating this node as unbudgeted");
            sumchain_storage::pruner::CapacityGuard::unbounded()
        });

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
            capacity,
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

    /// How many UNATTRIBUTED shrinks a proposal may make before it gives up on
    /// fitting and proposes what it has left.
    ///
    /// Unattributed means nobody is at fault: the publication-headroom
    /// truncation, which sheds transactions in proportion to how far over the
    /// budget the block went. That shrink is proportional and therefore
    /// converges geometrically — two or three rounds in every shape observed —
    /// so eight is generous. It is NOT the budget for dropping a named
    /// transaction; see [`Self::MAX_REFUSED_TX_DROPS`], which is separate for
    /// exactly this reason.
    ///
    /// Local to the proposer. Nothing about this number decides whether a block
    /// is VALID — an importing node never reads it — so two proposers holding
    /// different values build different blocks and both are applicable, which
    /// is why it is not a consensus limit and is not folded into the protocol
    /// digest.
    const MAX_BLOCK_FIT_ATTEMPTS: usize = 8;

    /// How many NAMED transactions one proposal may drop before it stops
    /// trying.
    ///
    /// Separate from [`Self::MAX_BLOCK_FIT_ATTEMPTS`], and the separation is a
    /// bug fix rather than tidiness. Each of these drops is attributable
    /// progress — `execute_block` named a specific transaction and it is gone —
    /// whereas the headroom truncation is a guess that converges. Sharing one
    /// budget of eight between them meant NINE transactions that cannot execute
    /// exhausted it, and the proposal that survived still refused: no block,
    /// nothing evicted for the transient ones, the same nine selected first on
    /// the next tick. Nine `min_fee`s, and the halt was back by a side door.
    ///
    /// Sixty-four bounds the proposer's work — every drop costs a full
    /// re-execution, so this is a real CPU budget and not a loop guard — while
    /// making the side door cost sixty-five transactions rather than nine. It
    /// does not CLOSE it: a sustained flood of transactions that refuse
    /// execution costs this proposer up to sixty-four executions a slot, and a
    /// block-time spent executing is its own denial of service. The structural
    /// answer is a per-transaction scope in `execute_block`, so one refusal is
    /// rolled back and the block continues in ONE pass rather than one pass per
    /// refusal — which changes what a block contains and therefore needs an
    /// activation gate and a separate piece of work.
    const MAX_REFUSED_TX_DROPS: usize = 64;

    /// The share of `MAX_BLOCK_WRITE_SET_BYTES` a proposal's EXECUTION may
    /// claim, leaving the rest for PUBLICATION.
    ///
    /// Half. The ceiling is shared between the two: `publish` stages the block
    /// record, a second copy of every transaction, the receipts, the two index
    /// families, the legacy diffs and the application journal through the same
    /// overlay, and the journal records a PRE-IMAGE per key the block wrote. So
    /// publication is not bounded by the block's size — it grows with the write
    /// set, exactly as execution does.
    ///
    /// An allowance sized by `max_block_bytes` would be wrong by two orders of
    /// magnitude for a block of read-modify-writes, which is why this is a
    /// FRACTION of the ceiling rather than a constant number of bytes.
    /// Measured on this path, an execution charge of about 268 MB reached about
    /// 400 MB at publish — a factor of 1.5 — so reserving half is conservative
    /// against what was observed and is not close to binding on honest traffic:
    /// `crates/state/tests/block_write_set_ceiling.rs` measures a block at the
    /// chain's declared limits charging single-digit megabytes.
    const PROPOSAL_EXECUTION_SHARE_DIVISOR: u64 = 2;

    /// Create a new block.
    ///
    /// # Why a proposer cannot just return the error
    ///
    /// `create_block_once` executes a candidate before signing it, so a
    /// proposer never signs a block its own execution refused. That much was
    /// never the gap. The gap is what happens INSTEAD of a block.
    ///
    /// `Mempool::select_for_block` is non-destructive and ordered by FEE, and
    /// `mempool.remove_batch` is reached only on the success path. So a
    /// transaction that makes the candidate unexecutable is still in the
    /// mempool on the next tick, sorted to the FRONT, and is selected first
    /// again — and again. Not a lost slot: a validator that never produces
    /// another block. It costs one `min_fee` and anyone can pay it.
    ///
    /// So every refusal that names a transaction is ACTED ON here rather than
    /// propagated, and the proposal is retried. Each arm shrinks the candidate
    /// strictly, so the loop terminates whatever the input.
    ///
    /// # Acting on it is not the same as destroying it
    ///
    /// The transactions that reach these arms are four populations, and a
    /// remedy that evicts all of them ends the halt by throwing away honest
    /// traffic:
    ///
    ///   * PERMANENTLY INVALID (`BlockTransactionAborted` with
    ///     [`sumchain_state::TxFailureClass::Permanent`]). Refused on the
    ///     transaction's own contents before any state was read —
    ///     `PolicyAccount { ModifyMembership }` is reachable only through
    ///     `ExecuteProposal`, so a directly submitted one fails at every height
    ///     against every state. Evicted, because evicting it is the only thing
    ///     that ends the halt.
    ///   * TEMPORARILY INELIGIBLE (`BlockTransactionAborted` with
    ///     [`sumchain_state::TxFailureClass::Transient`]). Refused against the
    ///     state it met. An NFT mint naming a collection the NEXT block creates
    ///     is the shape: nothing is wrong with the transaction except when it
    ///     arrived. Dropped from this proposal and LEFT IN THE MEMPOOL.
    ///   * TOO BIG FOR THIS BLOCK (`BlockWriteSetExceeded` at an index above
    ///     zero). It crossed `MAX_BLOCK_WRITE_SET_BYTES` because the
    ///     transactions before it had already spent the budget. At the head of
    ///     an emptier block it fits. The proposal is truncated AT it — the
    ///     prefix is known to execute, because it did — and nothing is evicted.
    ///     Index zero is the one case where no emptier block exists, and that
    ///     one is evicted.
    ///   * NO ROOM TO PUBLISH (`BlockWriteSetPublicationHeadroom`). The block
    ///     executed inside the ceiling but left nothing underneath it for the
    ///     block record, the transaction copies, the receipts, the indexes and
    ///     the pre-image journal. Nobody is at fault; the proposal is truncated
    ///     in proportion to how far over it was. The exception is a proposal
    ///     that has already shrunk to ONE transaction and still does not fit:
    ///     that transaction cannot be published in any block, so it is evicted
    ///     rather than left to empty every future block by sitting at the top
    ///     of the fee order.
    ///
    /// Dropping a transaction mid-proposal also drops every LATER transaction
    /// from the SAME SENDER — see [`Self::drop_with_sender_tail`]. Nonces are
    /// contiguous, and splicing one out of the middle of a sender's run would
    /// hand the rest of that run `InvalidNonce` receipts inside this very
    /// block, and `remove_batch` would then delete them. That would destroy
    /// transactions nothing accused, in the name of a repair whose whole point
    /// is not doing that.
    ///
    /// # This is proposer policy, not a consensus rule
    ///
    /// Nothing here changes which blocks are VALID or what any block's state
    /// root is: an importing node is handed a block and applies it or does not,
    /// by rules this function does not touch. What changes is which
    /// transactions THIS proposer puts in the block it builds, which is a
    /// choice every proposer already makes freely (fee order, `max_txs_per_block`,
    /// the fitting loop that preceded this one). So it carries no activation
    /// gate, for the same reason `MAX_BLOCK_FIT_ATTEMPTS` is not in the protocol
    /// digest.
    fn create_block(&self, transactions: Vec<SignedTransaction>) -> Result<Block> {
        let mut candidate_txs = transactions;
        // Two budgets, spent independently: one for shrinks nobody is at fault
        // for, one for drops of a NAMED transaction. See
        // `MAX_REFUSED_TX_DROPS` for what sharing them cost.
        let mut shrinks = 0usize;
        let mut drops = 0usize;
        while shrinks < Self::MAX_BLOCK_FIT_ATTEMPTS && drops < Self::MAX_REFUSED_TX_DROPS {
            let attempt = shrinks + drops;
            match self.create_block_once(candidate_txs.clone()) {
                // ── a transaction that could not be executed at all ──────────
                Err(ConsensusError::State(
                    sumchain_state::StateError::BlockTransactionAborted {
                        tx_index,
                        class,
                        detail,
                    },
                )) if tx_index < candidate_txs.len() => {
                    let offender = candidate_txs[tx_index].hash();
                    match class {
                        sumchain_state::TxFailureClass::Permanent => {
                            warn!(
                                attempt,
                                tx = %offender,
                                index = tx_index,
                                "a selected transaction can never execute, at any height \
                                 against any state; dropping it from the proposal and \
                                 evicting it from the mempool, so the next tick does not \
                                 select it again: {detail}"
                            );
                            // Evicted, not merely skipped. Skipped, it is at the
                            // front of the very next fee-ordered selection and
                            // the halt resumes on the next tick.
                            self.mempool.remove_batch(&[offender]);
                        }
                        sumchain_state::TxFailureClass::Transient => {
                            warn!(
                                attempt,
                                tx = %offender,
                                index = tx_index,
                                "a selected transaction could not execute against THIS \
                                 state; dropping it from the proposal and LEAVING IT in \
                                 the mempool, because a later block may carry it: {detail}"
                            );
                        }
                    }
                    candidate_txs = Self::drop_with_sender_tail(&candidate_txs, tx_index);
                    drops += 1;
                }

                // ── a transaction took the block past the write-set ceiling ──
                Err(ConsensusError::State(sumchain_state::StateError::BlockWriteSetExceeded {
                    tx_index,
                    detail,
                })) if tx_index < candidate_txs.len() => {
                    let offender = candidate_txs[tx_index].hash();
                    drops += 1;
                    if tx_index == 0 {
                        // Nothing preceded it, so no emptier block exists: this
                        // transaction cannot be carried by any block at all.
                        warn!(
                            attempt,
                            tx = %offender,
                            "the FIRST transaction in this proposal already crosses the \
                             block write-set ceiling, so no block can carry it; dropping \
                             it and evicting it from the mempool: {detail}"
                        );
                        self.mempool.remove_batch(&[offender]);
                        candidate_txs = Self::drop_with_sender_tail(&candidate_txs, 0);
                    } else {
                        // It crossed because the prefix spent the budget, not
                        // because of anything it did. Truncated AT it, not
                        // spliced around it: the prefix is known to execute,
                        // because it did. Nothing is evicted — at the head of
                        // the next block this transaction fits, and evicting it
                        // would destroy a transaction whose only fault is the
                        // company it was selected with.
                        warn!(
                            attempt,
                            tx = %offender,
                            index = tx_index,
                            "a selected transaction takes THIS block past the write-set \
                             ceiling; truncating the proposal at it. It stays in the \
                             mempool: it fits at the head of an emptier block: {detail}"
                        );
                        candidate_txs.truncate(tx_index);
                    }
                }

                Err(ConsensusError::State(
                    sumchain_state::StateError::BlockWriteSetPublicationHeadroom {
                        charged,
                        budget,
                    },
                )) if !candidate_txs.is_empty() => {
                    // Proportional, not one-at-a-time. A block 145 transactions
                    // over its budget would need 145 full re-executions to walk
                    // down by one, which is a block time spent executing.
                    //
                    // `min(len - 1)` is what guarantees progress, and therefore
                    // termination, when the proportion rounds to no change at
                    // all.
                    let len = candidate_txs.len();
                    let proportional = (len as u64)
                        .saturating_mul(budget)
                        .checked_div(charged.max(1))
                        .unwrap_or(0) as usize;
                    let keep = proportional.min(len - 1);
                    if keep == 0 && len == 1 {
                        // The proposal has shrunk to one transaction and that
                        // transaction still will not fit underneath the
                        // publication budget. No block can publish it, so
                        // leaving it costs more than a slot: it sits at the top
                        // of the fee order and empties EVERY future block while
                        // the smaller transactions behind it never confirm.
                        let offender = candidate_txs[0].hash();
                        warn!(
                            attempt,
                            charged,
                            budget,
                            tx = %offender,
                            "one transaction alone leaves no room to publish beneath the \
                             write-set ceiling, so no block can carry it; evicting it \
                             from the mempool rather than letting it empty every block \
                             behind it"
                        );
                        self.mempool.remove_batch(&[offender]);
                    } else {
                        warn!(
                            attempt,
                            charged,
                            budget,
                            from = len,
                            to = keep,
                            "this block executes inside the write-set ceiling but leaves \
                             no room to publish beneath it; carrying fewer transactions. \
                             Nothing is evicted: no single transaction is at fault"
                        );
                    }
                    candidate_txs.truncate(keep);
                    shrinks += 1;
                }
                other => return other,
            }
        }

        // ── out of budget ───────────────────────────────────────────────────
        //
        // Propose what survived, and if that still refuses, keep halving until
        // something is accepted. An empty proposal always executes, so this
        // reaches a block.
        //
        // This is what makes running out of budget a SHORT BLOCK rather than NO
        // BLOCK, and the difference is the whole subject of this function: a
        // proposer that returns the refusal here stops producing, and on the
        // next tick it selects the same transactions and stops again. The
        // budget above is a bound on WORK; it must not become a bound on
        // liveness.
        loop {
            match self.create_block_once(candidate_txs.clone()) {
                Ok(block) => return Ok(block),
                // Nothing left to shed. An empty proposal that still refuses is
                // not about its transactions at all — a disk budget, a missing
                // parent, not being the proposer — and those belong to the
                // caller.
                Err(e) if candidate_txs.is_empty() => return Err(e),
                Err(e) => {
                    // HALVED, not walked down one at a time. This is the path
                    // taken after the whole fitting budget is already spent, so
                    // what matters is reaching a block in a bounded number of
                    // executions rather than in the fewest dropped
                    // transactions: halving reaches the empty proposal — which
                    // always executes — in about ten steps for a thousand
                    // transactions, where stepping by one would take a thousand
                    // and spend the slot it is trying to save.
                    let keep = candidate_txs.len() / 2;
                    warn!(
                        shrinks,
                        drops,
                        from = candidate_txs.len(),
                        to = keep,
                        "this proposal is still refused after spending its whole \
                         fitting budget; halving it rather than producing no block \
                         at all: {e}"
                    );
                    candidate_txs.truncate(keep);
                }
            }
        }
    }

    /// The proposal without the transaction at `index`, and without every LATER
    /// transaction from that transaction's SENDER.
    ///
    /// The offender goes because it is what refused. The sender's tail goes
    /// because nonces are contiguous: splice one transaction out of the middle
    /// of a sender's run and every transaction after it in that run fails
    /// `validate_tx` with `InvalidNonce` — which is a RECEIPT, so the block is
    /// built and signed carrying them, and `remove_batch` then deletes them
    /// from the mempool. Transactions nothing accused, destroyed by the repair
    /// meant to stop exactly that.
    ///
    /// Every OTHER sender's transactions are kept, which is what makes this a
    /// splice rather than a truncation: the honest traffic behind a poisoned
    /// transaction is carried by THIS block rather than waiting for the next
    /// one. The dropped tail is untouched in the mempool and is selected again
    /// on the next tick.
    fn drop_with_sender_tail(txs: &[SignedTransaction], index: usize) -> Vec<SignedTransaction> {
        let sender = txs[index].sender();
        txs.iter()
            .enumerate()
            .filter(|(i, tx)| *i < index || (*i > index && tx.sender() != sender))
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    /// One proposal attempt: build, execute, sign, accept, publish, announce.
    fn create_block_once(&self, transactions: Vec<SignedTransaction>) -> Result<Block> {
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

        // ── the disk brake ──────────────────────────────────────────────────
        //
        // This tree ships with pruning DISABLED, so the undo families grow for
        // the life of the database. An operator who records a budget
        // (`sum-node set-disk-budget`) gets a defined behaviour as the database
        // approaches it, instead of discovering the end of the disk inside a
        // `WriteBatch`.
        //
        // Producing is braked; importing is not. Following the chain is not
        // optional and adding to it is, so this is the half that can be given
        // up without the node becoming dishonest. It DELAYS exhaustion rather
        // than preventing it — a node that keeps importing keeps growing — and
        // the operator's actual remedy is more disk or a pruner. Unbudgeted
        // (the default) it is a no-op.
        match self.capacity.assess_db(&self.db) {
            sumchain_storage::pruner::CapacityVerdict::Healthy => {}
            sumchain_storage::pruner::CapacityVerdict::Warn { used, budget } => {
                warn!(
                    used,
                    budget,
                    "database is at {}% of its recorded disk budget; add disk or enable \
                     pruning before it reaches {}%, at which point this node stops \
                     producing blocks",
                    used.saturating_mul(100) / budget.max(1),
                    sumchain_storage::pruner::CAPACITY_STOP_PERCENT,
                );
            }
            sumchain_storage::pruner::CapacityVerdict::StopProducing { used, budget } => {
                return Err(ConsensusError::InvalidBlock(format!(
                    "refusing to produce a block at height {height}: this database uses \
                     {used} byte(s) of a recorded {budget}-byte disk budget, at or above \
                     the {}% stop threshold. Pruning is disabled in this build, so the \
                     undo families grow for the life of the database. Producing is braked \
                     and importing is not, so this delays exhaustion rather than \
                     preventing it: add disk, or enable pruning, or resync. Clear the \
                     budget with `sum-node set-disk-budget --bytes 0` to disable this \
                     brake",
                    sumchain_storage::pruner::CAPACITY_STOP_PERCENT
                )));
            }
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

        // ── publication headroom, BEFORE signing ────────────────────────────
        //
        // Executing inside the ceiling is not enough to commit inside it. The
        // ceiling is SHARED with `publish`, which afterwards stages the block
        // record, a second copy of every transaction, the receipts, the sender
        // and recipient indexes, the legacy diffs and the application journal
        // through the same overlay — and the journal records a PRE-IMAGE per
        // key, so for a block of read-modify-writes publication costs a second
        // helping of the same rows.
        //
        // Discovered rather than assumed: a proposal that executed at 268 MB
        // was refused at publish having reached 400 MB. Without this check the
        // failure lands AFTER `sign`, which is the one place a proposer must
        // not fail — the block is signed, nothing is published, and the slot is
        // lost for a reason the proposer could have seen a moment earlier.
        let charged = executed.logical_bytes();
        let budget =
            sumchain_state::MAX_BLOCK_WRITE_SET_BYTES / Self::PROPOSAL_EXECUTION_SHARE_DIVISOR;
        if charged > budget {
            return Err(ConsensusError::State(
                sumchain_state::StateError::BlockWriteSetPublicationHeadroom { charged, budget },
            ));
        }

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
    /// 2. [`crate::reorg::plan_reorg`] resolves the fork BY HASH and refuses a gap, a switch
    ///    below finality, or a walk past the allocation bound — before anything
    ///    is written.
    /// 3. [`execute_reorg`] unwinds the abandoned branch newest-first from its
    ///    per-block journals — the REAL encoded application journal at and above
    ///    this chain's activation boundary, decoded and validated on the way in,
    ///    and the legacy per-subsystem diffs below it — checking each row against
    ///    the value the journal says the block left, in ONE batch that also
    ///    carries the journal deletions, the de-indexing and the head reset;
    ///    restores the accumulator from the ancestor's header; and applies the
    ///    adopted branch through the ordinary publication path, one atomic batch
    ///    per block.
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
        // there before `plan_reorg` runs. `publish` writes the same row again
        // when the branch is adopted.
        //
        // Through `archive_noncanonical`, NOT `BlockStore::put`. `put` also
        // writes `BLOCK_HEIGHT[height] = hash`, which is keyed by height alone
        // and carries no branch identity — so retaining the arriving block that
        // way pointed the CANONICAL height index at a block that had not been
        // adopted, and left it pointing there if the switch was then refused.
        // The comment this replaces claimed the row "cannot shadow anything"
        // because it is keyed by the block's own hash; that was true of the
        // `BLOCKS` row and false of the height index written beside it.
        //
        // `archive_noncanonical` writes exactly the branch-safe,
        // content-addressed rows — `BLOCKS` and `TRANSACTIONS` — and
        // deliberately not the height index, which is what this needs. It also
        // preflights both against any bytes already stored under those hashes,
        // so a collision is refused before anything is written.
        self.archive_noncanonical(&block)?;

        let old_head = self
            .best_block
            .read()
            .clone()
            .ok_or_else(|| ConsensusError::InvalidBlock(
                "classified as a reorg with no current best block;                  a switch needs something to switch away from".to_string(),
            ))?;

        let finalized = block_store.get_finalized_height()?.unwrap_or(0);

        // The journal this node reverts from, resolved per block against its own
        // activation boundary: the generic application journal at and above it,
        // the four legacy per-subsystem journals below it, never both for one
        // block. See `sumchain_state::reorg_undo::ActivatedJournal`.
        //
        // The boundary comes from this chain's OWN gate,
        // `application_journal_enabled_from_height` — `None` observes it from
        // the journal history this database holds, `Some(h)` pins it. Neither
        // position disables anything: the write side is ungated, so a node that
        // has published a block has journal history and a boundary.
        let journals = ActivatedJournal::resolve(
            &self.db,
            ActivationSource::from_configured_height(
                self.params.application_journal_enabled_from_height,
            ),
        )
        .map_err(|e| {
            ConsensusError::InvalidBlock(format!(
                "cannot resolve the application-journal activation boundary: {e}"
            ))
        })?;

        // Planned against the undo history this node actually HOLDS, not only
        // against the engine's walk limit. A node restored from a snapshot has
        // canonical state and no journals, so its usable depth starts at zero and
        // rebuilds one block per publish; `MAX_REORG_WALK` is what the engine
        // will walk, never a claim about what this database can reverse.
        let plan = plan_reorg_within_undo_history(
            block_store,
            &old_head,
            &block,
            finalized,
            MAX_REORG_WALK,
            &journals.activation(),
        )?;
        // Derived from the same `JournalActivation` the journal itself holds, so
        // the policy and the journal cannot disagree about where the boundary
        // is. A missing record at or above it HALTS the reorg; below it, absence
        // is pre-journal history and is counted and logged.
        let missing = journals.policy();
        let outcome = execute_reorg(
            &self.db,
            &self.state,
            &self.executor,
            &plan,
            active_validators,
            &journals,
            missing,
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
