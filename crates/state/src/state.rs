//! State management for SUM Chain.
//!
//! Provides read/write access to account state with support for
//! state diffs (for reorg handling).

use std::sync::Arc;

use parking_lot::RwLock;
use sumchain_genesis::Genesis;
use sumchain_primitives::{Address, Balance, BlockHeight, ChainId, Hash, Nonce};
use sumchain_storage::{schema::AccountState, Database, StateStore};
use tracing::{debug, info};

use crate::{Result, StateError};

/// State manager for account state
pub struct StateManager {
    db: Arc<Database>,
    chain_id: ChainId,
    /// Cached latest state root
    state_root: RwLock<Hash>,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(db: Arc<Database>, chain_id: ChainId) -> Self {
        Self {
            db,
            chain_id,
            state_root: RwLock::new(Hash::ZERO),
        }
    }

    /// Initialize state from genesis
    pub fn init_from_genesis(&self, genesis: &Genesis) -> Result<Hash> {
        info!("Initializing state from genesis");

        let store = StateStore::new(&self.db);
        let alloc = genesis
            .parsed_alloc()
            .map_err(|e| StateError::Genesis(e.to_string()))?;

        for (addr, balance) in &alloc {
            debug!("Prefunding {} with {}", addr, balance);
            store.put_account(
                addr,
                &AccountState {
                    balance: *balance,
                    nonce: 0,
                },
            )?;
        }

        // Genesis snapshot of the active-archive-node set (Ask 15, plan v3 §5.3).
        // No archive nodes can have registered before genesis (RegisterArchiveNode
        // is a tx, executed post-genesis), so this is always an empty `Vec`.
        // Writing it explicitly lets `storage_getActiveNodesAtHeight(0)` always
        // resolve, and gives the storage layout a self-describing baseline.
        let node_registry = crate::node_registry::NodeRegistryExecutor::new(self.db.clone());
        node_registry.write_active_archive_snapshot(0)?;

        let state_root = genesis
            .compute_state_root()
            .map_err(|e| StateError::Genesis(e.to_string()))?;

        *self.state_root.write() = state_root;

        info!("Genesis state initialized, root: {}", state_root);
        Ok(state_root)
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> Result<Balance> {
        let store = StateStore::new(&self.db);
        Ok(store.get_balance(address)?)
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> Result<Nonce> {
        let store = StateStore::new(&self.db);
        Ok(store.get_nonce(address)?)
    }

    /// Get full account state
    pub fn get_account(&self, address: &Address) -> Result<AccountState> {
        let store = StateStore::new(&self.db);
        Ok(store.get_account(address)?)
    }

    /// Update account state
    pub fn put_account(&self, address: &Address, state: &AccountState) -> Result<()> {
        let store = StateStore::new(&self.db);
        store.put_account(address, state)?;
        Ok(())
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Get current state root
    pub fn state_root(&self) -> Hash {
        *self.state_root.read()
    }

    /// Set state root (after block execution)
    pub fn set_state_root(&self, root: Hash) {
        *self.state_root.write() = root;
    }

    /// Compute state root from current state
    /// (Simplified: in production would use merkle patricia trie)
    pub fn compute_state_root(&self) -> Result<Hash> {
        // For MVP, we use a simple approach: hash all accounts
        // In production, this would be a proper MPT
        let _store = StateStore::new(&self.db);

        // This is a simplified version - in production you'd iterate all accounts
        // For now, just use the cached root or compute from recent changes
        Ok(self.state_root())
    }

    /// Apply a balance transfer (debit from, credit to)
    pub fn transfer(
        &self,
        from: &Address,
        to: &Address,
        amount: Balance,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        let store = StateStore::new(&self.db);

        // Get sender account
        let mut sender_state = store.get_account(from)?;
        let total_cost = amount.saturating_add(fee);

        if sender_state.balance < total_cost {
            return Err(StateError::InsufficientBalance {
                required: total_cost,
                available: sender_state.balance,
            });
        }

        // Debit sender
        sender_state.balance = sender_state.balance.saturating_sub(total_cost);
        sender_state.nonce += 1;
        store.put_account(from, &sender_state)?;

        // Credit recipient
        let mut recipient_state = store.get_account(to)?;
        recipient_state.balance = recipient_state.balance.saturating_add(amount);
        store.put_account(to, &recipient_state)?;

        // Credit fee to proposer
        if fee > 0 && !proposer.is_zero() {
            let mut proposer_state = store.get_account(proposer)?;
            proposer_state.balance = proposer_state.balance.saturating_add(fee);
            store.put_account(proposer, &proposer_state)?;
        }

        Ok(())
    }

    /// Increment an account's nonce without transfer
    pub fn increment_nonce(&self, address: &Address) -> Result<()> {
        let store = StateStore::new(&self.db);
        let mut state = store.get_account(address)?;
        state.nonce += 1;
        store.put_account(address, &state)?;
        Ok(())
    }

    /// Deduct balance from an account
    pub fn deduct(&self, address: &Address, amount: Balance) -> Result<()> {
        let store = StateStore::new(&self.db);
        let mut state = store.get_account(address)?;
        if state.balance < amount {
            return Err(StateError::InsufficientBalance {
                required: amount,
                available: state.balance,
            });
        }
        state.balance = state.balance.saturating_sub(amount);
        store.put_account(address, &state)?;
        Ok(())
    }

    /// Credit balance to an account
    pub fn credit(&self, address: &Address, amount: Balance) -> Result<()> {
        let store = StateStore::new(&self.db);
        let mut state = store.get_account(address)?;
        state.balance = state.balance.saturating_add(amount);
        store.put_account(address, &state)?;
        Ok(())
    }

    /// Store a state diff for potential reorg
    pub fn save_state_diff(
        &self,
        height: BlockHeight,
        diff: sumchain_storage::schema::StateDiff,
    ) -> Result<()> {
        let store = StateStore::new(&self.db);
        store.put_state_diff(height, &diff)?;
        Ok(())
    }

    /// Revert state using a saved diff
    pub fn revert_state_diff(&self, height: BlockHeight) -> Result<()> {
        let store = StateStore::new(&self.db);

        if let Some(diff) = store.get_state_diff(height)? {
            // Apply changes in reverse (old_state replaces new_state)
            for (addr, old_state, _new_state) in diff.changes {
                match old_state {
                    Some(state) => store.put_account(&addr, &state)?,
                    None => {
                        // Account didn't exist before, reset to default
                        store.put_account(&addr, &AccountState::default())?
                    }
                }
            }
            store.delete_state_diff(height)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (Arc::new(db), dir)
    }

    #[test]
    fn test_balance_operations() {
        let (db, _dir) = setup();
        let state = StateManager::new(db, 1);

        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        // Initial balance is 0
        assert_eq!(state.get_balance(&addr).unwrap(), 0);

        // Set balance
        state
            .put_account(
                &addr,
                &AccountState {
                    balance: 1000,
                    nonce: 0,
                },
            )
            .unwrap();

        assert_eq!(state.get_balance(&addr).unwrap(), 1000);
    }

    #[test]
    fn test_transfer() {
        let (db, _dir) = setup();
        let state = StateManager::new(db, 1);

        let from = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let to = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let proposer = Address::from_hex("0x0000000000000000000000000000000000000003").unwrap();

        // Fund sender
        state
            .put_account(
                &from,
                &AccountState {
                    balance: 1000,
                    nonce: 0,
                },
            )
            .unwrap();

        // Transfer
        state.transfer(&from, &to, 500, 10, &proposer).unwrap();

        assert_eq!(state.get_balance(&from).unwrap(), 490); // 1000 - 500 - 10
        assert_eq!(state.get_balance(&to).unwrap(), 500);
        assert_eq!(state.get_balance(&proposer).unwrap(), 10);
        assert_eq!(state.get_nonce(&from).unwrap(), 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let (db, _dir) = setup();
        let state = StateManager::new(db, 1);

        let from = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let to = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();

        state
            .put_account(
                &from,
                &AccountState {
                    balance: 100,
                    nonce: 0,
                },
            )
            .unwrap();

        let result = state.transfer(&from, &to, 200, 10, &Address::ZERO);
        assert!(matches!(result, Err(StateError::InsufficientBalance { .. })));
    }
}
