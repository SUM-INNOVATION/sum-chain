//! Node Registry Executor
//!
//! Manages the registry of network nodes beyond validators.
//! Supports registering nodes with specific roles (Validator, ArchiveNode)
//! and tracking their stake and status.
//!
//! # Execution reads and writes the candidate, not the database
//!
//! Every function on the block-execution path is an associated function taking
//! an [`ExecutionView`]. There is no `self` receiver for them to reach
//! `Arc<Database>` through, so a committed read on those paths is a compile
//! error rather than a silent correctness bug: within one block, a node slashed
//! by `process_expired_challenges` must be *seen as slashed* by the storage
//! transactions that follow it, and a snapshot rewritten by `RegisterArchiveNode`
//! must be *seen* by a later `AcceptAssignmentV2` in the same block.
//!
//! The `&self` readers below survive for RPC and for mempool admission, which
//! answer about the published chain rather than about a candidate. Each is
//! paired with a `v_` twin over the view, and the two share their decode and
//! summation helpers so they cannot drift.

use std::sync::Arc;

use sumchain_crypto::is_low_order_x25519_public_key;
use sumchain_primitives::{
    Address, ArchiveUnbondingRecord, Balance, NodeRecord, NodeRegistryOperation,
    NodeRegistryOperationV2, NodeRegistryTxData, NodeRegistryV2TxData, NodeRole, NodeStatus,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;
use tracing::{info, warn};

use crate::{Result, StateError, StateManager};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum stake required for an ArchiveNode (1 Koppa = 1_000_000_000 base units)
const MIN_ARCHIVE_STAKE: u64 = 1_000_000_000;

// The column families are named once, in `sumchain_storage::cf`. These aliases
// exist so the bodies below stay readable; re-declaring the string literals here
// would let this file and the storage schema drift apart silently.

/// Column family name
const CF_NODE_REGISTRY: &str = sumchain_storage::cf::NODE_REGISTRY;

/// Column family for per-account X25519 encryption pubkeys (SNIP V2 Ask 3).
const CF_ACCOUNT_ENCRYPTION_KEYS: &str = sumchain_storage::cf::ACCOUNT_ENCRYPTION_KEYS;

/// Column family for height-keyed snapshots of the active-archive-node set
/// (SNIP V2 Ask 15, Option A). Snapshot-on-change — written on register,
/// status change to/from Slashed, expired-challenge slashing, and at genesis.
const CF_ACTIVE_ARCHIVE_NODES_HISTORY: &str = sumchain_storage::cf::ACTIVE_ARCHIVE_NODES_HISTORY;

/// Column family for pending archive-node stake unbonding records (issue #20),
/// keyed by operator address -> `ArchiveUnbondingRecord`.
const CF_ARCHIVE_UNBONDING: &str = sumchain_storage::cf::ARCHIVE_UNBONDING;

// ─── Key helpers ─────────────────────────────────────────────────────────────

fn node_key(address: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(21);
    key.push(b'N');
    key.extend_from_slice(address.as_bytes());
    key
}

fn role_index_key(role: NodeRole, address: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(22);
    key.push(b'R');
    key.push(role as u8);
    key.extend_from_slice(address.as_bytes());
    key
}

fn role_index_prefix(role: NodeRole) -> Vec<u8> {
    vec![b'R', role as u8]
}

// ─── Codec and fold helpers ──────────────────────────────────────────────────
//
// Shared by the candidate (`v_`) and committed accessors. The two differ only
// in where the bytes come from; everything that interprets them lives here once,
// so a candidate read and an RPC read cannot disagree about what a row means.

fn encode_node(record: &NodeRecord) -> Result<Vec<u8>> {
    bincode::serialize(record).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_node(bytes: &[u8]) -> Result<NodeRecord> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

fn encode_unbonding(record: &ArchiveUnbondingRecord) -> Result<Vec<u8>> {
    bincode::serialize(record).map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_unbonding(bytes: &[u8]) -> Result<ArchiveUnbondingRecord> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

fn encode_snapshot(nodes: &[NodeRecord]) -> Result<Vec<u8>> {
    bincode::serialize(&nodes.to_vec())
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn decode_snapshot(bytes: &[u8]) -> Result<Vec<NodeRecord>> {
    bincode::deserialize(bytes).map_err(|e| StateError::DeserializationError(e.to_string()))
}

/// The encryption-pubkey row is a bare 32-byte X25519 key. Anything else — a
/// short row, a corrupt row — reads as "this account has never registered one",
/// which is what every caller must do with it anyway.
fn pubkey_from_row(data: Option<Vec<u8>>) -> Option<[u8; 32]> {
    match data {
        Some(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        }
        _ => None,
    }
}

/// Address embedded in a role-index key `[b'R', role, address(20)]`, or `None`
/// for a key that is too short to be one.
fn address_from_role_index_key(key: &[u8]) -> Option<Address> {
    if key.len() < 22 {
        return None;
    }
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&key[2..22]);
    Some(Address::new(addr_bytes))
}

fn active_archives(nodes: Vec<NodeRecord>) -> Vec<NodeRecord> {
    nodes
        .into_iter()
        .filter(|n| n.status == NodeStatus::Active)
        .collect()
}

/// Σ `staked_balance` with checked u128 addition. Shared so the census total and
/// the RPC total cannot differ in their overflow behaviour.
fn sum_archive_stake(nodes: &[NodeRecord]) -> Result<u128> {
    let mut sum: u128 = 0;
    for node in nodes {
        sum = sum.checked_add(node.staked_balance as u128).ok_or_else(|| {
            StateError::BlockValidation("archive staked_balance sum overflow".to_string())
        })?;
    }
    Ok(sum)
}

/// One step of the "largest snapshot height ≤ target" forward scan.
///
/// Returns `false` once the scan has passed the target — keys are
/// `[height_be_bytes_8]`, so RocksDB's lexicographic order is numeric order and
/// no later entry can match. Shared by both scans so the candidate and the
/// committed read agree on which snapshot a height resolves to.
fn snapshot_scan_step(best: &mut Option<Vec<u8>>, key: &[u8], value: &[u8], target: &[u8]) -> bool {
    if key <= target {
        *best = Some(value.to_vec());
        true
    } else {
        false
    }
}

// ─── Executor ────────────────────────────────────────────────────────────────

/// Result of a node registry operation.
///
/// `failure_code`, when `Some(c)`, is the specific `TxStatus::Failed(c)` code
/// the dispatch layer should surface in the receipt — used so that
/// `chain_getTransactionStatus(...).Failed.reason` resolves to the precise
/// reason string defined in [`sumchain_primitives::receipt::TxStatus::description`].
/// Generic failures leave it `None` and the dispatch layer assigns its own
/// fallback code (e.g. `Failed(20)` for V2 NodeRegistry).
#[derive(Debug)]
pub struct NodeRegistryExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub failure_code: Option<u32>,
}

impl NodeRegistryExecutionResult {
    fn ok() -> Self {
        Self { success: true, error: None, failure_code: None }
    }
    fn fail(msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), failure_code: None }
    }
    /// Failure with a specific receipt code. Reserved codes are documented in
    /// [`sumchain_primitives::receipt::TxStatus::description`].
    fn fail_with_code(code: u32, msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), failure_code: Some(code) }
    }
}

pub struct NodeRegistryExecutor {
    db: Arc<Database>,
}

impl NodeRegistryExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// The genesis active-archive snapshot: the empty set, encoded exactly as
    /// [`Self::v_write_active_archive_snapshot`] would encode it.
    ///
    /// Genesis is not block execution — there is no block to abandon and no
    /// candidate to stage into — so its one row is written by
    /// [`sumchain_storage::StateStore::init_genesis_archive_snapshot`], next to
    /// the genesis account writes. The *encoding* stays here, with the type,
    /// so the genesis row and a height-`n` snapshot can never disagree about
    /// their format.
    pub fn genesis_archive_snapshot_bytes() -> Result<Vec<u8>> {
        encode_snapshot(&[])
    }

    /// Deduct fee from sender and credit to proposer (same pattern as other executors)
    fn deduct_fee(view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = StateManager::v_get_balance(view, sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        StateManager::v_put_account(view, sender, &sender_account)?;

        if !proposer.is_zero() {
            let mut proposer_account = StateManager::v_get_account(view, proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            StateManager::v_put_account(view, proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Execute a node registry operation.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &NodeRegistryTxData,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;

        match &data.operation {
            NodeRegistryOperation::Register { role, stake } => {
                Self::execute_register(view, sender, *role, *stake, block_height)
            }
            NodeRegistryOperation::UpdateStatus { target, new_status } => {
                Self::execute_update_status(view, sender, target, *new_status, block_height)
            }
            // Archive-node withdrawal ops (issue #20) are always dispatched via the
            // gated path in `executor.rs` (`execute_begin_unstake` /
            // `execute_withdraw_unbonded`), which supplies the activation gate,
            // the unbonding period, and the open-challenge context this generic
            // entrypoint lacks. Reaching here means a caller bypassed that path.
            NodeRegistryOperation::BeginUnstake { .. }
            | NodeRegistryOperation::WithdrawUnbonded => {
                Ok(NodeRegistryExecutionResult::fail(
                    "archive unbonding operations must be dispatched via the gated path",
                ))
            }
        }
    }

    /// Execute a V2 node registry operation. Additive — V1 `execute` unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_v2(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &NodeRegistryV2TxData,
        proposer: &Address,
        fee: Balance,
        _block_height: u64,
        _block_timestamp: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;

        match &data.operation {
            NodeRegistryOperationV2::RegisterEncryptionKey { encryption_pubkey } => {
                Self::execute_register_encryption_key(view, sender, encryption_pubkey)
            }
        }
    }

    fn execute_register_encryption_key(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        encryption_pubkey: &[u8; 32],
    ) -> Result<NodeRegistryExecutionResult> {
        // Reject low/small-order X25519 public keys before any write.
        // Plan v3.1 §3.3 — matches libsodium `crypto_scalarmult` `has_small_order`
        // (seven byte-string encodings + the all-zero point + high-bit-set variants).
        // Rejecting at registration time means no legitimate sender ever wraps
        // against a small-order point and the registry can't be used for griefing.
        // Constant-time comparison is implemented inside the helper.
        if is_low_order_x25519_public_key(encryption_pubkey) {
            warn!(
                "Rejecting low-order X25519 encryption pubkey from account {}",
                sender
            );
            return Ok(NodeRegistryExecutionResult::fail_with_code(
                22,
                "low-order x25519 public key rejected",
            ));
        }

        // Overwrite-on-rewrite semantics — rotation is allowed and intentional.
        let key = sender.as_bytes().to_vec();
        view.put(CF_ACCOUNT_ENCRYPTION_KEYS, &key, encryption_pubkey)
            .map_err(StateError::Storage)?;

        info!(
            "Encryption pubkey registered/rotated for account {}",
            sender
        );

        Ok(NodeRegistryExecutionResult::ok())
    }

    // ── Active-archive-node snapshot history (SNIP V2 Ask 15, Option A) ─────

    /// Capture the current active-archive-node set as the snapshot for `height`.
    ///
    /// Snapshot-on-change semantics: callers invoke this only after an
    /// operation that may have changed the active set (register, status flip
    /// to/from Slashed, expired-challenge slashing). If the caller invokes for a
    /// height that already has a snapshot, the new write overwrites —
    /// last-writer-wins within a block, which yields the post-block active set.
    /// This is naturally idempotent for the common case (one trigger per block).
    ///
    /// The set it captures is read from the *candidate*, so a node slashed
    /// earlier in this same block is already excluded — which is the ordering
    /// `process_expired_challenges` (before the transaction loop) depends on.
    pub fn v_write_active_archive_snapshot(
        view: &mut ExecutionView<'_, '_>,
        height: u64,
    ) -> Result<()> {
        let active = Self::v_get_active_archive_nodes(view)?;
        let value = encode_snapshot(&active)?;
        view.put(CF_ACTIVE_ARCHIVE_NODES_HISTORY, &height.to_be_bytes(), &value)
            .map_err(StateError::Storage)?;
        Ok(())
    }

    /// Read the active-archive-node set as snapshotted at the largest stored
    /// height `≤ height`, from this block's candidate. Returns `Ok(Vec::new())`
    /// if no snapshot has ever been written (equivalent to the empty genesis
    /// snapshot).
    pub fn v_get_active_archive_nodes_at_height(
        view: &ExecutionView<'_, '_>,
        height: u64,
    ) -> Result<Vec<NodeRecord>> {
        let target = height.to_be_bytes();
        let mut best: Option<Vec<u8>> = None;
        for item in view
            .iter(CF_ACTIVE_ARCHIVE_NODES_HISTORY)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan with an error. Treating it as the end
            // of the iterator would silently answer from a truncated history.
            let (k, v) = item.map_err(StateError::Storage)?;
            if !snapshot_scan_step(&mut best, &k, &v, &target[..]) {
                break;
            }
        }
        match best {
            Some(bytes) => decode_snapshot(&bytes),
            None => Ok(Vec::new()),
        }
    }

    /// Read the active-archive-node set as snapshotted at the largest stored
    /// height `≤ height`. Returns `Ok(Vec::new())` if no snapshot has ever
    /// been written (equivalent to the empty genesis snapshot).
    ///
    /// Committed twin of [`Self::v_get_active_archive_nodes_at_height`], for RPC.
    ///
    /// Implementation: forward scan over the CF (RocksDB orders keys lex-asc,
    /// which equals numeric-asc for `[height_be_bytes_8]`). For v1 with
    /// snapshot-on-change, total snapshot count is bounded by churn events,
    /// so the linear scan is fine.
    ///
    /// TODO(testnet): switch to a reverse-seek iterator
    /// (`IteratorMode::From(target, Direction::Reverse)`) before this becomes
    /// a public high-traffic RPC. Forward scan is `O(snapshot_count)` per
    /// query — fine while this is internal, will need O(log n) seek + O(1)
    /// read once SNIP archive nodes start polling at every push.
    pub fn get_active_archive_nodes_at_height(
        &self,
        height: u64,
    ) -> Result<Vec<NodeRecord>> {
        let target = height.to_be_bytes();
        let mut best: Option<Vec<u8>> = None;
        for (k, v) in self
            .db
            .iter(CF_ACTIVE_ARCHIVE_NODES_HISTORY)
            .map_err(StateError::Storage)?
        {
            if !snapshot_scan_step(&mut best, k.as_ref(), v.as_ref(), &target[..]) {
                break;
            }
        }
        match best {
            Some(bytes) => decode_snapshot(&bytes),
            None => Ok(Vec::new()),
        }
    }

    /// Look up the X25519 encryption pubkey for an account, in this block's
    /// candidate.
    pub fn v_get_encryption_pubkey(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<[u8; 32]>> {
        let key = address.as_bytes().to_vec();
        let row = view
            .get(CF_ACCOUNT_ENCRYPTION_KEYS, &key)
            .map_err(StateError::Storage)?;
        Ok(pubkey_from_row(row))
    }

    /// Look up the X25519 encryption pubkey for an account.
    ///
    /// Returns `None` if the account has never registered one (or if its row
    /// is corrupt and the length check fails — the caller should treat the two
    /// cases identically: the account cannot receive encrypted bundles yet).
    pub fn get_encryption_pubkey(&self, address: &Address) -> Result<Option<[u8; 32]>> {
        let key = address.as_bytes().to_vec();
        let row = self
            .db
            .get(CF_ACCOUNT_ENCRYPTION_KEYS, &key)
            .map_err(StateError::Storage)?;
        Ok(pubkey_from_row(row))
    }

    fn execute_register(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        role: NodeRole,
        stake: u64,
        block_height: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        if Self::v_get_node(view, sender)?.is_some() {
            return Ok(NodeRegistryExecutionResult::fail("Node already registered"));
        }

        let min_stake = match role {
            NodeRole::ArchiveNode => MIN_ARCHIVE_STAKE,
            NodeRole::Validator => {
                return Ok(NodeRegistryExecutionResult::fail(
                    "Validators must register through the staking module",
                ));
            }
        };

        if stake < min_stake {
            return Ok(NodeRegistryExecutionResult::fail(format!(
                "Insufficient stake: minimum {} required, got {}",
                min_stake, stake
            )));
        }

        let balance = StateManager::v_get_balance(view, sender)?;
        if balance < stake as u128 {
            return Ok(NodeRegistryExecutionResult::fail(format!(
                "Insufficient balance for stake: need {}, have {}",
                stake, balance
            )));
        }

        // Deduct stake from sender balance
        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(stake as u128);
        StateManager::v_put_account(view, sender, &sender_account)?;

        let record = NodeRecord {
            address: *sender,
            role,
            staked_balance: stake,
            status: NodeStatus::Active,
            registered_at: block_height,
        };

        Self::v_put_node(view, &record)?;

        // Snapshot the active-archive set at this height — Ask 15. Registering
        // a Validator doesn't affect the archive set, so skip in that case.
        // (Validator role currently rejected above, but guard anyway in case
        // future roles are added.)
        if role == NodeRole::ArchiveNode {
            Self::v_write_active_archive_snapshot(view, block_height)?;
        }

        info!(
            "Node registered: {} as {:?} with stake {}",
            sender, role, stake
        );

        Ok(NodeRegistryExecutionResult::ok())
    }

    fn execute_update_status(
        view: &mut ExecutionView<'_, '_>,
        _sender: &Address,
        target: &Address,
        new_status: NodeStatus,
        block_height: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        let mut record = match Self::v_get_node(view, target)? {
            Some(r) => r,
            None => return Ok(NodeRegistryExecutionResult::fail("Node not found")),
        };

        let old_status = record.status;
        let role = record.role;
        record.status = new_status;
        Self::v_put_node(view, &record)?;

        // Active-archive set changes iff this node is an ArchiveNode AND
        // its status actually flipped. Skip the snapshot write otherwise to
        // avoid duplicate rows for no-op updates.
        if role == NodeRole::ArchiveNode && old_status != new_status {
            Self::v_write_active_archive_snapshot(view, block_height)?;
        }

        info!("Node {} status updated to {:?}", target, new_status);

        Ok(NodeRegistryExecutionResult::ok())
    }

    // ── Archive-node withdrawal / unbonding (issue #20) ──────────────────────

    /// Begin unbonding an archive node's stake (issue #20, step 1).
    ///
    /// v1 is full-exit only: `amount` must equal the node's full
    /// `staked_balance`. The caller (executor dispatch) is responsible for the
    /// activation gate (`Failed(320)`, no fee) *before* invoking this; here the
    /// fee is deducted upfront (matching the existing NodeRegistry fee policy)
    /// and semantic failures return the specific receipt code with the fee
    /// already consumed.
    ///
    /// `has_open_challenge` is computed by the caller from the active-challenge
    /// index (the challenge state lives in the storage-metadata executor, not
    /// here). `period_blocks` is `ChainParams::archive_unbonding_period_blocks`.
    ///
    /// On success the node moves `Active -> Unbonding` (removing it from the
    /// active-archive set, so a fresh snapshot is written) and a single
    /// `ArchiveUnbondingRecord` is persisted with the unlock height.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_begin_unstake(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        amount: u64,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        period_blocks: u64,
        has_open_challenge: bool,
    ) -> Result<NodeRegistryExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;

        let mut record = match Self::v_get_node(view, sender)? {
            Some(r) if r.role == NodeRole::ArchiveNode => r,
            _ => {
                return Ok(NodeRegistryExecutionResult::fail_with_code(
                    321,
                    "not a registered archive node",
                ));
            }
        };

        if record.status != NodeStatus::Active {
            return Ok(NodeRegistryExecutionResult::fail_with_code(
                322,
                "archive node not active (cannot begin unbonding)",
            ));
        }

        // Full-exit only for v1: the requested amount must be the entire stake.
        if amount != record.staked_balance {
            return Ok(NodeRegistryExecutionResult::fail_with_code(
                323,
                "archive unbonding amount must equal the full staked balance",
            ));
        }

        // An archive with open retrievability challenges must resolve them (or be
        // slashed) before it can start exiting — otherwise it could dodge a
        // pending challenge by unbonding.
        if has_open_challenge {
            return Ok(NodeRegistryExecutionResult::fail_with_code(
                324,
                "archive has open retrievability challenges; cannot begin unbonding",
            ));
        }

        let unlock_height = block_height.saturating_add(period_blocks);
        let unbonding = ArchiveUnbondingRecord {
            operator: *sender,
            amount,
            started_height: block_height,
            unlock_height,
            remaining_amount: amount,
        };
        Self::v_put_archive_unbonding(view, &unbonding)?;

        record.status = NodeStatus::Unbonding;
        Self::v_put_node(view, &record)?;

        // Active -> Unbonding removes the node from the active-archive set.
        Self::v_write_active_archive_snapshot(view, block_height)?;

        info!(
            "Archive node {} began unbonding {} (unlock at height {})",
            sender, amount, unlock_height
        );

        Ok(NodeRegistryExecutionResult::ok())
    }

    /// Withdraw an archive node's unbonded stake (issue #20, step 2).
    ///
    /// Allowed only once the unbonding period has elapsed
    /// (`block_height >= record.unlock_height`). Credits the remaining amount
    /// (after any slashes during unbonding) back to the operator's balance,
    /// marks the node `Withdrawn` with a zero stake, and deletes the unbonding
    /// record. The activation gate is enforced by the caller (`Failed(320)`, no
    /// fee); here the fee is deducted upfront.
    ///
    /// No active-archive snapshot is written: an `Unbonding` node was already
    /// excluded from the active set, so `Unbonding -> Withdrawn` does not change
    /// it.
    pub fn execute_withdraw_unbonded(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;

        let unbonding = match Self::v_get_archive_unbonding(view, sender)? {
            Some(u) => u,
            None => {
                return Ok(NodeRegistryExecutionResult::fail_with_code(
                    325,
                    "no archive unbonding in progress",
                ));
            }
        };

        if block_height < unbonding.unlock_height {
            return Ok(NodeRegistryExecutionResult::fail_with_code(
                326,
                "archive unbonding period has not elapsed",
            ));
        }

        // Credit the (possibly slashed) remaining amount back to the operator.
        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account
            .balance
            .saturating_add(unbonding.remaining_amount as u128);
        StateManager::v_put_account(view, sender, &sender_account)?;

        // Mark the node fully exited. If the record is somehow missing we still
        // clear the unbonding entry (the balance credit already happened).
        if let Some(mut record) = Self::v_get_node(view, sender)? {
            record.status = NodeStatus::Withdrawn;
            record.staked_balance = 0;
            Self::v_put_node(view, &record)?;
        }

        Self::v_delete_archive_unbonding(view, sender)?;

        info!(
            "Archive node {} withdrew {} unbonded stake and exited",
            sender, unbonding.remaining_amount
        );

        Ok(NodeRegistryExecutionResult::ok())
    }

    // ── Storage operations ───────────────────────────────────────────────────

    /// Stage a node record and its role-index mirror into this block's candidate.
    ///
    /// Both writes move together, always. The index is what
    /// `v_get_nodes_by_role` walks, so a candidate that staged the row without
    /// the index would compute an archive set — and therefore an assignment set
    /// — that no other node reproduces.
    pub fn v_put_node(view: &mut ExecutionView<'_, '_>, record: &NodeRecord) -> Result<()> {
        let key = node_key(&record.address);
        let value = encode_node(record)?;
        view.put(CF_NODE_REGISTRY, &key, &value)
            .map_err(StateError::Storage)?;

        let idx_key = role_index_key(record.role, &record.address);
        view.put(CF_NODE_REGISTRY, &idx_key, &[1])
            .map_err(StateError::Storage)?;

        Ok(())
    }

    /// A node record as this block's candidate sees it — including one staged
    /// by an earlier transaction of the same block.
    pub fn v_get_node(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<NodeRecord>> {
        let key = node_key(address);
        match view.get(CF_NODE_REGISTRY, &key).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_node(&data)?)),
            None => Ok(None),
        }
    }

    pub fn get_node(&self, address: &Address) -> Result<Option<NodeRecord>> {
        let key = node_key(address);
        match self.db.get(CF_NODE_REGISTRY, &key).map_err(StateError::Storage)? {
            Some(data) => Ok(Some(decode_node(&data)?)),
            None => Ok(None),
        }
    }

    /// All active ArchiveNodes as the candidate sees them (used by PoR
    /// challenge generation and by the snapshot writer).
    pub fn v_get_active_archive_nodes(
        view: &ExecutionView<'_, '_>,
    ) -> Result<Vec<NodeRecord>> {
        Ok(active_archives(Self::v_get_nodes_by_role(
            view,
            NodeRole::ArchiveNode,
        )?))
    }

    /// Get all active ArchiveNodes (used by PoR challenge generation)
    pub fn get_active_archive_nodes(&self) -> Result<Vec<NodeRecord>> {
        Ok(active_archives(self.get_nodes_by_role(NodeRole::ArchiveNode)?))
    }

    // ── Archive-unbonding record storage (issue #20) ─────────────────────────

    /// The pending unbonding record for an operator as the candidate sees it.
    pub fn v_get_archive_unbonding(
        view: &ExecutionView<'_, '_>,
        operator: &Address,
    ) -> Result<Option<ArchiveUnbondingRecord>> {
        match view
            .get(CF_ARCHIVE_UNBONDING, operator.as_bytes())
            .map_err(StateError::Storage)?
        {
            Some(data) => Ok(Some(decode_unbonding(&data)?)),
            None => Ok(None),
        }
    }

    /// Read the pending unbonding record for an operator, if any.
    pub fn get_archive_unbonding(
        &self,
        operator: &Address,
    ) -> Result<Option<ArchiveUnbondingRecord>> {
        match self
            .db
            .get(CF_ARCHIVE_UNBONDING, operator.as_bytes())
            .map_err(StateError::Storage)?
        {
            Some(data) => Ok(Some(decode_unbonding(&data)?)),
            None => Ok(None),
        }
    }

    /// Insert or overwrite an operator's unbonding record in the candidate.
    pub fn v_put_archive_unbonding(
        view: &mut ExecutionView<'_, '_>,
        record: &ArchiveUnbondingRecord,
    ) -> Result<()> {
        let value = encode_unbonding(record)?;
        view.put(CF_ARCHIVE_UNBONDING, record.operator.as_bytes(), &value)
            .map_err(StateError::Storage)
    }

    /// Remove an operator's unbonding record (on full withdrawal).
    pub fn v_delete_archive_unbonding(
        view: &mut ExecutionView<'_, '_>,
        operator: &Address,
    ) -> Result<()> {
        view.delete(CF_ARCHIVE_UNBONDING, operator.as_bytes())
            .map_err(StateError::Storage)
    }

    /// Nodes of a role as the candidate sees them, via the role index.
    pub fn v_get_nodes_by_role(
        view: &ExecutionView<'_, '_>,
        role: NodeRole,
    ) -> Result<Vec<NodeRecord>> {
        let prefix = role_index_prefix(role);
        let mut addrs = Vec::new();
        for item in view
            .prefix_iter(CF_NODE_REGISTRY, &prefix)
            .map_err(StateError::Storage)?
        {
            // A read error ends the scan. Silently stopping would under-report
            // the archive set, and the assignment computed from it is consensus.
            let (key, _) = item.map_err(StateError::Storage)?;
            if let Some(addr) = address_from_role_index_key(&key) {
                addrs.push(addr);
            }
        }

        // The borrow of `view` held by the iterator ends before the point reads.
        let mut nodes = Vec::with_capacity(addrs.len());
        for addr in addrs {
            if let Some(record) = Self::v_get_node(view, &addr)? {
                nodes.push(record);
            }
        }

        Ok(nodes)
    }

    pub fn get_nodes_by_role(&self, role: NodeRole) -> Result<Vec<NodeRecord>> {
        let prefix = role_index_prefix(role);
        let mut nodes = Vec::new();

        let entries: Vec<_> = self
            .db
            .prefix_iter(CF_NODE_REGISTRY, &prefix)
            .map_err(StateError::Storage)?
            .collect();

        for (key, _) in entries {
            if let Some(addr) = address_from_role_index_key(&key) {
                if let Some(record) = self.get_node(&addr)? {
                    nodes.push(record);
                }
            }
        }

        Ok(nodes)
    }

    /// Σ `staked_balance` across all archive nodes as **this block's candidate**
    /// sees them — the total the supply census must use, because a block that
    /// registers, slashes or withdraws an archive changes the live archive stake
    /// it is about to publish.
    ///
    /// Same accounting rules as the committed twin below; both fold through
    /// [`sum_archive_stake`].
    pub fn v_total_archive_staked_balance(view: &ExecutionView<'_, '_>) -> Result<u128> {
        sum_archive_stake(&Self::v_get_nodes_by_role(view, NodeRole::ArchiveNode)?)
    }

    /// Σ `staked_balance` across all archive nodes (any status), with checked
    /// u128 addition. This is the live native-Koppa archive stake: `Withdrawn`
    /// nodes carry `staked_balance == 0`, and a node mid-unbond keeps its
    /// `staked_balance` (the mirrored `ARCHIVE_UNBONDING` record is deliberately
    /// NOT counted, to avoid double-counting). Validators cannot register here
    /// (rejected at registration), so this is archive stake only. Deterministic
    /// (uses the role-index scan), tolerates zero archive nodes.
    ///
    /// Committed twin of [`Self::v_total_archive_staked_balance`], for
    /// `chain_getSupplyInfo` diagnostics.
    pub fn total_archive_staked_balance(&self) -> Result<u128> {
        sum_archive_stake(&self.get_nodes_by_role(NodeRole::ArchiveNode)?)
    }
}
