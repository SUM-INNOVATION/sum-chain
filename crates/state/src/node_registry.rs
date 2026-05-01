//! Node Registry Executor
//!
//! Manages the registry of network nodes beyond validators.
//! Supports registering nodes with specific roles (Validator, ArchiveNode)
//! and tracking their stake and status.

use std::sync::Arc;

use sumchain_crypto::is_low_order_x25519_public_key;
use sumchain_primitives::{
    Address, Balance, NodeRecord, NodeRegistryOperation, NodeRegistryOperationV2,
    NodeRegistryTxData, NodeRegistryV2TxData, NodeRole, NodeStatus,
};
use sumchain_storage::Database;
use tracing::{info, warn};

use crate::{Result, StateError, StateManager};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum stake required for an ArchiveNode (1 Koppa = 1_000_000_000 base units)
const MIN_ARCHIVE_STAKE: u64 = 1_000_000_000;

/// Column family name
const CF_NODE_REGISTRY: &str = "node_registry";

/// Column family for per-account X25519 encryption pubkeys (SNIP V2 Ask 3).
const CF_ACCOUNT_ENCRYPTION_KEYS: &str = "account_encryption_keys";

/// Column family for height-keyed snapshots of the active-archive-node set
/// (SNIP V2 Ask 15, Option A). Snapshot-on-change — written on register,
/// status change to/from Slashed, expired-challenge slashing, and at genesis.
const CF_ACTIVE_ARCHIVE_NODES_HISTORY: &str = "active_archive_nodes_history";

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

    /// Deduct fee from sender and credit to proposer (same pattern as other executors)
    fn deduct_fee(
        &self,
        state: &StateManager,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = state.get_balance(sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        state.put_account(sender, &sender_account)?;

        if !proposer.is_zero() {
            let mut proposer_account = state.get_account(proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            state.put_account(proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Execute a node registry operation.
    pub fn execute(
        &self,
        sender: &Address,
        data: &NodeRegistryTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        _block_timestamp: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        self.deduct_fee(state, sender, fee, proposer)?;

        match &data.operation {
            NodeRegistryOperation::Register { role, stake } => {
                self.execute_register(sender, *role, *stake, state, block_height)
            }
            NodeRegistryOperation::UpdateStatus { target, new_status } => {
                self.execute_update_status(sender, target, *new_status, block_height)
            }
        }
    }

    /// Execute a V2 node registry operation. Additive — V1 `execute` unchanged.
    pub fn execute_v2(
        &self,
        sender: &Address,
        data: &NodeRegistryV2TxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: u64,
        _block_timestamp: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        self.deduct_fee(state, sender, fee, proposer)?;

        match &data.operation {
            NodeRegistryOperationV2::RegisterEncryptionKey { encryption_pubkey } => {
                self.execute_register_encryption_key(sender, encryption_pubkey)
            }
        }
    }

    fn execute_register_encryption_key(
        &self,
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
        self.db
            .put(CF_ACCOUNT_ENCRYPTION_KEYS, &key, encryption_pubkey)
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
    /// to/from Slashed, expired-challenge slashing, genesis init). If the
    /// caller invokes for a height that already has a snapshot, the new write
    /// overwrites — last-writer-wins within a block, which yields the
    /// post-block active set. This is naturally idempotent for the common
    /// case (one trigger per block).
    pub fn write_active_archive_snapshot(&self, height: u64) -> Result<()> {
        let active = self.get_active_archive_nodes()?;
        let value = bincode::serialize(&active)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db
            .put(CF_ACTIVE_ARCHIVE_NODES_HISTORY, &height.to_be_bytes(), &value)
            .map_err(StateError::Storage)?;
        Ok(())
    }

    /// Read the active-archive-node set as snapshotted at the largest stored
    /// height `≤ height`. Returns `Ok(Vec::new())` if no snapshot has ever
    /// been written (equivalent to the empty genesis snapshot).
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
            if k.as_ref() <= &target[..] {
                best = Some(v.into_vec());
            } else {
                // Sorted ascending — once we pass the target, no later entry can match.
                break;
            }
        }
        match best {
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StateError::DeserializationError(e.to_string())),
            None => Ok(Vec::new()),
        }
    }

    /// Look up the X25519 encryption pubkey for an account.
    ///
    /// Returns `None` if the account has never registered one (or if its row
    /// is corrupt and bincode decode fails — the caller should treat the two
    /// cases identically: the account cannot receive encrypted bundles yet).
    pub fn get_encryption_pubkey(&self, address: &Address) -> Result<Option<[u8; 32]>> {
        let key = address.as_bytes().to_vec();
        match self.db.get(CF_ACCOUNT_ENCRYPTION_KEYS, &key) {
            Ok(Some(data)) if data.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&data);
                Ok(Some(out))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    fn execute_register(
        &self,
        sender: &Address,
        role: NodeRole,
        stake: u64,
        state: &StateManager,
        block_height: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        if self.get_node(sender)?.is_some() {
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

        let balance = state.get_balance(sender)?;
        if balance < stake as u128 {
            return Ok(NodeRegistryExecutionResult::fail(format!(
                "Insufficient balance for stake: need {}, have {}",
                stake, balance
            )));
        }

        // Deduct stake from sender balance
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(stake as u128);
        state.put_account(sender, &sender_account)?;

        let record = NodeRecord {
            address: *sender,
            role,
            staked_balance: stake,
            status: NodeStatus::Active,
            registered_at: block_height,
        };

        self.put_node(&record)?;

        // Snapshot the active-archive set at this height — Ask 15. Registering
        // a Validator doesn't affect the archive set, so skip in that case.
        // (Validator role currently rejected above, but guard anyway in case
        // future roles are added.)
        if role == NodeRole::ArchiveNode {
            self.write_active_archive_snapshot(block_height)?;
        }

        info!(
            "Node registered: {} as {:?} with stake {}",
            sender, role, stake
        );

        Ok(NodeRegistryExecutionResult::ok())
    }

    fn execute_update_status(
        &self,
        _sender: &Address,
        target: &Address,
        new_status: NodeStatus,
        block_height: u64,
    ) -> Result<NodeRegistryExecutionResult> {
        let mut record = match self.get_node(target)? {
            Some(r) => r,
            None => return Ok(NodeRegistryExecutionResult::fail("Node not found")),
        };

        let old_status = record.status;
        let role = record.role;
        record.status = new_status;
        self.put_node(&record)?;

        // Active-archive set changes iff this node is an ArchiveNode AND
        // its status actually flipped. Skip the snapshot write otherwise to
        // avoid duplicate rows for no-op updates.
        if role == NodeRole::ArchiveNode && old_status != new_status {
            self.write_active_archive_snapshot(block_height)?;
        }

        info!("Node {} status updated to {:?}", target, new_status);

        Ok(NodeRegistryExecutionResult::ok())
    }

    // ── Storage operations ───────────────────────────────────────────────────

    fn put_node(&self, record: &NodeRecord) -> Result<()> {
        let key = node_key(&record.address);
        let value = bincode::serialize(record)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(CF_NODE_REGISTRY, &key, &value)
            .map_err(|e| StateError::Storage(e))?;

        let idx_key = role_index_key(record.role, &record.address);
        self.db.put(CF_NODE_REGISTRY, &idx_key, &[1])
            .map_err(|e| StateError::Storage(e))?;

        Ok(())
    }

    pub fn get_node(&self, address: &Address) -> Result<Option<NodeRecord>> {
        let key = node_key(address);
        match self.db.get(CF_NODE_REGISTRY, &key) {
            Ok(Some(data)) => {
                let record: NodeRecord = bincode::deserialize(&data)
                    .map_err(|e| StateError::DeserializationError(e.to_string()))?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::Storage(e)),
        }
    }

    /// Get all active ArchiveNodes (used by PoR challenge generation)
    pub fn get_active_archive_nodes(&self) -> Result<Vec<NodeRecord>> {
        let all = self.get_nodes_by_role(NodeRole::ArchiveNode)?;
        Ok(all.into_iter().filter(|n| n.status == NodeStatus::Active).collect())
    }

    pub fn get_nodes_by_role(&self, role: NodeRole) -> Result<Vec<NodeRecord>> {
        let prefix = vec![b'R', role as u8];
        let mut nodes = Vec::new();

        let entries: Vec<_> = self.db
            .prefix_iter(CF_NODE_REGISTRY, &prefix)
            .map_err(|e| StateError::Storage(e))?
            .collect();

        for (key, _) in entries {
            if key.len() >= 22 {
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&key[2..22]);
                let addr = Address::new(addr_bytes);
                if let Some(record) = self.get_node(&addr)? {
                    nodes.push(record);
                }
            }
        }

        Ok(nodes)
    }
}
