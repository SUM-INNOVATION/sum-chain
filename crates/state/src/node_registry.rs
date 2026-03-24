//! Node Registry Executor
//!
//! Manages the registry of network nodes beyond validators.
//! Supports registering nodes with specific roles (Validator, ArchiveNode)
//! and tracking their stake and status.

use std::sync::Arc;

use sumchain_primitives::{
    Address, Balance, NodeRecord, NodeRegistryOperation, NodeRegistryTxData, NodeRole, NodeStatus,
};
use sumchain_storage::Database;
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Minimum stake required for an ArchiveNode (1 Koppa = 1_000_000_000 base units)
const MIN_ARCHIVE_STAKE: u64 = 1_000_000_000;

/// Column family name
const CF_NODE_REGISTRY: &str = "node_registry";

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

/// Result of a node registry operation
#[derive(Debug)]
pub struct NodeRegistryExecutionResult {
    pub success: bool,
    pub error: Option<String>,
}

impl NodeRegistryExecutionResult {
    fn ok() -> Self {
        Self { success: true, error: None }
    }
    fn fail(msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()) }
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
                self.execute_update_status(sender, target, *new_status)
            }
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
    ) -> Result<NodeRegistryExecutionResult> {
        let mut record = match self.get_node(target)? {
            Some(r) => r,
            None => return Ok(NodeRegistryExecutionResult::fail("Node not found")),
        };

        record.status = new_status;
        self.put_node(&record)?;

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
