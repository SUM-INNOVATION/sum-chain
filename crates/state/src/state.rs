//! State management for SUM Chain.
//!
//! Provides read/write access to account state with support for
//! state diffs (for reorg handling).

use std::sync::Arc;

use parking_lot::RwLock;
use sumchain_genesis::Genesis;
use sumchain_primitives::{Address, Balance, BlockHeight, ChainId, Hash, Nonce};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::journal::JournalRequirement;
use sumchain_storage::schema::{decode_account, encode_account, ACCOUNT_KEY_PREFIX};
use sumchain_storage::{cf, schema::AccountState, Database, StateStore};
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

        // Before a single row is written. The account-state commitment is folded
        // into the block state root once its gate opens, and two things must be
        // true of the height that opens it: it is above the legacy
        // root-compatibility window, where a mismatch is force-adopted rather
        // than refused, and the application journal is pinned at least one full
        // reorg horizon below it, so a reorg can actually restore the account
        // rows the root now commits to. Both are configuration facts, so they
        // are checked here — where a bad pair stops the chain being created —
        // rather than at the activation boundary, where it would stop a chain
        // that has already been publishing. See
        // [`crate::account_root::validate_account_root_activation`].
        crate::account_root::validate_runtime_activation(&genesis.params)?;

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
        //
        // This is the one active-archive snapshot written outside block
        // execution, so it commits here rather than staging into a candidate:
        // genesis has no block to abandon. The bytes are encoded by the node
        // registry, so the genesis row and every height-`n` snapshot share one
        // encoder.
        store.init_genesis_archive_snapshot(
            &crate::node_registry::NodeRegistryExecutor::genesis_archive_snapshot_bytes()?,
        )?;

        let state_root = genesis
            .compute_state_root()
            .map_err(|e| StateError::Genesis(e.to_string()))?;

        *self.state_root.write() = state_root;

        info!("Genesis state initialized, root: {}", state_root);
        Ok(state_root)
    }

    // ── Accounts, as this block's candidate sees them ───────────────────────
    //
    // Accounts are the row almost every transaction touches: the fee debit, the
    // proposer credit and the nonce bump run on 27 of the 30 dispatcher arms,
    // including nine of the twelve whose own subsystem rows are already on the
    // overlay. Three arms are explicitly fee-free — ComputePool, BeaconSetup
    // and BeaconSigning return `fee_paid: 0` on every path — and debit nothing.
    //
    // Reading or writing accounts through `StateStore` during execution commits
    // them immediately, so a block that is never accepted still moves balances.
    //
    // These are associated functions. Without a `self` receiver there is no
    // `Arc<Database>` to reach, so a committed account read on an execution
    // path is a compile error rather than a silent one. The `&self` accessors
    // below survive for genesis, snapshots, RPC diagnostics, mempool admission
    // and the reorg revert — none of which is block execution.

    /// Account state as the candidate sees it, distinguishing ABSENT from
    /// present-and-zero.
    ///
    /// The distinction is why this is the primitive and [`Self::v_get_account`]
    /// is derived from it. An undo journal reverting a block that CREATED an
    /// account has to delete the row; a pre-image captured as `Some(default)`
    /// can only write a zero row back, which is a different chain state.
    /// `ExecutionView` records the pre-image on first write, and it can only
    /// record `None` because this read can see absence.
    pub fn v_get_account_opt(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<AccountState>> {
        let key = StateStore::account_key(address);
        match view.get(cf::STATE, &key).map_err(StateError::Storage)? {
            Some(bytes) => Ok(Some(decode_account(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Account state as the candidate sees it, flattening absent to zero.
    ///
    /// Fine for execution, which needs a balance to debit. Not fine for a
    /// journal pre-image — use [`Self::v_get_account_opt`] there.
    pub fn v_get_account(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<AccountState> {
        Ok(Self::v_get_account_opt(view, address)?.unwrap_or_default())
    }

    pub fn v_get_balance(view: &ExecutionView<'_, '_>, address: &Address) -> Result<Balance> {
        Ok(Self::v_get_account(view, address)?.balance)
    }

    pub fn v_get_nonce(view: &ExecutionView<'_, '_>, address: &Address) -> Result<Nonce> {
        Ok(Self::v_get_account(view, address)?.nonce)
    }

    /// Stage an account row into this block's candidate.
    pub fn v_put_account(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        state: &AccountState,
    ) -> Result<()> {
        let key = StateStore::account_key(address);
        view.put(cf::STATE, &key, &encode_account(state)?)
            .map_err(StateError::Storage)
    }

    /// Apply a balance transfer (debit from, credit to) into the candidate.
    pub fn v_transfer(
        view: &mut ExecutionView<'_, '_>,
        from: &Address,
        to: &Address,
        amount: Balance,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        let mut sender_state = Self::v_get_account(view, from)?;
        let total_cost = amount.saturating_add(fee);

        if sender_state.balance < total_cost {
            return Err(StateError::InsufficientBalance {
                required: total_cost,
                available: sender_state.balance,
            });
        }

        sender_state.balance = sender_state.balance.saturating_sub(total_cost);
        sender_state.nonce += 1;
        Self::v_put_account(view, from, &sender_state)?;

        // Read AFTER the sender write: a self-transfer must see the debit it
        // just staged, or the credit restores what the debit removed.
        let mut recipient_state = Self::v_get_account(view, to)?;
        recipient_state.balance = recipient_state.balance.saturating_add(amount);
        Self::v_put_account(view, to, &recipient_state)?;

        if fee > 0 && !proposer.is_zero() {
            let mut proposer_state = Self::v_get_account(view, proposer)?;
            proposer_state.balance = proposer_state.balance.saturating_add(fee);
            Self::v_put_account(view, proposer, &proposer_state)?;
        }

        Ok(())
    }

    /// Increment an account's nonce without transfer.
    pub fn v_increment_nonce(view: &mut ExecutionView<'_, '_>, address: &Address) -> Result<()> {
        let mut state = Self::v_get_account(view, address)?;
        state.nonce += 1;
        Self::v_put_account(view, address, &state)
    }

    /// Deduct balance from an account.
    pub fn v_deduct(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        amount: Balance,
    ) -> Result<()> {
        let mut state = Self::v_get_account(view, address)?;
        if state.balance < amount {
            return Err(StateError::InsufficientBalance {
                required: amount,
                available: state.balance,
            });
        }
        state.balance = state.balance.saturating_sub(amount);
        Self::v_put_account(view, address, &state)
    }

    /// Credit balance to an account.
    pub fn v_credit(
        view: &mut ExecutionView<'_, '_>,
        address: &Address,
        amount: Balance,
    ) -> Result<()> {
        let mut state = Self::v_get_account(view, address)?;
        state.balance = state.balance.saturating_add(amount);
        Self::v_put_account(view, address, &state)
    }

    /// Every account as the candidate sees it, for the supply census.
    ///
    /// A read error ends the scan with an error: a short account census
    /// under-reports economic supply, and the correction would mint the
    /// difference into the reserve.
    pub fn v_iter_all_accounts(
        view: &ExecutionView<'_, '_>,
    ) -> Result<Vec<(Address, AccountState)>> {
        let mut accounts = Vec::new();
        for item in view
            .prefix_iter(cf::STATE, ACCOUNT_KEY_PREFIX)
            .map_err(StateError::Storage)?
        {
            let (key, value) = item.map_err(StateError::Storage)?;
            let Some(address) = StateStore::address_in_account_key(&key) else {
                continue;
            };
            accounts.push((address, decode_account(&value)?));
        }
        Ok(accounts)
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
    /// Account state, distinguishing absent from present-and-zero. See
    /// [`sumchain_storage::schema::StateStore::get_account_opt`]; used when
    /// capturing an undo journal's `old` value, where the difference decides
    /// whether a revert deletes the row or writes a zero row.
    pub fn get_account_opt(&self, address: &Address) -> Result<Option<AccountState>> {
        let store = StateStore::new(&self.db);
        Ok(store.get_account_opt(address)?)
    }

    pub fn get_account(&self, address: &Address) -> Result<AccountState> {
        let store = StateStore::new(&self.db);
        Ok(store.get_account(address)?)
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

    /// Store a state diff for potential reorg
    pub fn save_state_diff(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        diff: sumchain_storage::schema::StateDiff,
    ) -> Result<()> {
        let store = StateStore::new(&self.db);
        store.put_state_diff(height, block_hash, &diff)?;
        Ok(())
    }

    /// Revert state using a saved diff
    pub fn revert_state_diff(&self, height: BlockHeight, block_hash: &Hash) -> Result<()> {
        let store = StateStore::new(&self.db);

        if let Some(diff) = store.get_state_diff(height, block_hash)? {
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
            store.delete_state_diff(height, block_hash)?;
        }

        Ok(())
    }

    /// Store the per-block contract-state diff for potential reorg.
    pub fn save_contract_state_diff(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        diff: sumchain_storage::schema::ContractStateDiff,
    ) -> Result<()> {
        let store = StateStore::new(&self.db);
        store.put_contract_state_diff(height, block_hash, &diff)?;
        Ok(())
    }

    /// Atomically revert BOTH the account `StateDiff` and the contract
    /// `ContractStateDiff` for a block, as one logical operation.
    ///
    /// All restores — account old-states, contract CF restores/deletes (replayed
    /// in reverse record order) — and the deletion of both diff records are
    /// staged into a single [`Database::batch`] and committed together. Any
    /// error (e.g. an unknown `cf_kind`) returns before commit, so nothing is
    /// applied and both diffs remain intact for a clean retry. This avoids the
    /// inconsistent state where accounts revert but contract state is orphaned.
    ///
    /// # This is the PRE-ACTIVATION path, and the TYPE SYSTEM says so
    ///
    /// The argument is a [`crate::reorg_undo::PreActivationBlock`], which is
    /// constructible only by classifying a height against a resolved
    /// [`sumchain_storage::journal::JournalActivation`] and only when that
    /// classification comes back
    /// [`JournalRequirement::PreActivation`]. There is no post-activation case
    /// in this function because there is no way to name a post-activation block
    /// to it.
    ///
    /// That is a change from an earlier signature, which took a
    /// `JournalRequirement` and REFUSED `Required` at run time. A runtime
    /// refusal on a function nothing calls is a tripwire rather than a guard: it
    /// holds only for as long as the next caller remembers to classify, and it
    /// is the caller nobody has reviewed that it exists for. Removing the case
    /// is stronger than refusing it, and it costs nothing a real caller wanted.
    ///
    /// Below the boundary the four legacy per-subsystem journals are the only
    /// undo record the block has, so this reverts from them, and their joint
    /// absence is `Ok(())`: a block published by a binary that wrote no journal
    /// for a family it did not touch is indistinguishable from one whose record
    /// was lost, and there is no third thing to consult. That silence is the
    /// pre-activation policy, and this is the ONLY place it survives.
    ///
    /// At and above the boundary the path is
    /// [`crate::reorg_undo::ActivatedJournal`], which refuses a missing record
    /// instead of returning `Ok(())` over it.
    ///
    /// # Not reached from production
    ///
    /// Nothing in the workspace calls this outside tests; the live reorg path is
    /// `ActivatedJournal` through `sumchain_consensus::reorg::execute_reorg`.
    /// `crates/state/tests/application_journal.rs`'s
    /// `the_legacy_revert_path_has_no_production_caller_and_the_rollback_cli_has_its_own`
    /// scans for that and fails if it changes.
    pub fn revert_pre_activation_block_state_diffs(
        &self,
        block: &crate::reorg_undo::PreActivationBlock,
    ) -> Result<()> {
        use sumchain_storage::{cf, ContractStateDiff};

        let height = block.height();
        let block_hash = block.block_hash();
        let store = StateStore::new(&self.db);
        let account_diff = store.get_state_diff(height, block_hash)?;
        let contract_diff = store.get_contract_state_diff(height, block_hash)?;
        // Dormant C1 compute-pool subsystem (issue #130): the block-rollback
        // revert of C1 rows is folded into THIS same batch so account, contract,
        // AND compute-pool state revert atomically (all-or-none). The C1 branch is
        // driven purely by journal PRESENCE, not by the activation gate: under the
        // production `None` gate no C1 journal is ever written, so there is nothing
        // to revert and the dormant path is byte-for-byte unchanged.
        // The C1 and beacon journals are keyed by `(height, block_hash)`, like
        // account and contract. Neither could be, while `execute_block` wrote
        // them: at that
        // point the block hash is not final — the produce path builds the header
        // with `state_root: Hash::ZERO`, runs `execute_block` to obtain the
        // root, and only then fills the root in and signs — so keying by
        // `block.hash()` there would key by a hash no reader can reconstruct.
        // That was recorded here as a prerequisite for opening the gate.
        //
        // It is resolved. `execute_block` now returns both journals as artifacts
        // bound to the candidate, and the PUBLISHER writes them, after the root
        // is filled in and the block hash is final. The hash is therefore
        // reconstructible by every reader, and two blocks at the same height no
        // longer share one journal row.
        let cp_store = crate::compute_pool_store::ComputePoolStore::new(&self.db);
        let has_cp_journal = cp_store.has_journal(height, block_hash)?;
        // Dormant BR1 beacon subsystem (issue #127): its block-rollback revert folds
        // into THIS same batch so account, contract, compute-pool, AND beacon state
        // revert atomically (all-or-none). Driven by journal PRESENCE, not the gate:
        // under the production `None` gate no beacon journal is ever written, so
        // there is nothing to revert and the dormant path is byte-for-byte unchanged.
        let beacon_store = crate::beacon_store::BeaconStore::new(&self.db);
        let has_beacon_journal = beacon_store.has_journal(height, block_hash)?;
        if account_diff.is_none()
            && contract_diff.is_none()
            && !has_cp_journal
            && !has_beacon_journal
        {
            return Ok(());
        }

        let mut batch = self.db.batch();

        // Account restores. An account that did not exist before the block is
        // DELETED, not written back as a default row.
        //
        // `put`ting `AccountState::default()` reads the same through
        // `get_account`, which returns the default for a missing key — so the
        // two are indistinguishable today and the bug is invisible. They are not
        // the same on disk: one leaves a `{balance: 0, nonce: 0}` row where the
        // other leaves no row. `sum-node rollback`
        // (`crates/node/src/main.rs:874-883`) already deletes in this case, so
        // the two rollback paths disagreed byte-for-byte on identical input.
        //
        // That difference becomes a fork the moment anything hashes stored rows
        // — which is exactly what a real state commitment must do. Reverting the
        // difference now, while nothing hashes rows, costs nothing; discovering
        // it after activation would mean two honest nodes computing different
        // commitments from the same history.
        if let Some(diff) = &account_diff {
            for (addr, old_state, _new) in &diff.changes {
                let mut key = Vec::with_capacity(4 + 20);
                key.extend_from_slice(b"acct");
                key.extend_from_slice(addr.as_bytes());
                match old_state {
                    Some(state) => {
                        let bytes = bincode::serialize(state).map_err(|e| {
                            StateError::InvalidOperation(format!("account encode: {e}"))
                        })?;
                        batch.put(cf::STATE, &key, &bytes)?;
                    }
                    None => batch.delete(cf::STATE, &key)?,
                }
            }
        }

        // Contract restores in REVERSE record order. cf_kind is validated here,
        // BEFORE commit, so an unknown kind aborts the whole revert with nothing
        // applied and both diffs preserved.
        if let Some(diff) = &contract_diff {
            for record in diff.records.iter().rev() {
                let cf_name = ContractStateDiff::cf_name(record.cf_kind).ok_or_else(|| {
                    StateError::InvalidOperation(format!(
                        "contract revert: unknown cf_kind {} at height {}",
                        record.cf_kind, height
                    ))
                })?;
                match &record.old {
                    Some(v) => batch.put(cf_name, &record.key, v)?,
                    None => batch.delete(cf_name, &record.key)?,
                }
            }
        }

        // C1 compute-pool restores (reverse-replay of this block's journal) +
        // the journal's own deletion, staged into the SAME batch. Domain prefixes
        // are validated here BEFORE commit, so a corrupt C1 journal aborts the
        // WHOLE revert (nothing applied, every diff preserved for retry) — exactly
        // like the unknown-`cf_kind` guard above. No-op when no C1 journal exists.
        cp_store.stage_block_revert(&mut batch, height, block_hash)?;

        // BR1 beacon restores (reverse-replay of this block's journal) + the
        // journal's own deletion, staged into the SAME batch. Domain prefixes are
        // validated BEFORE commit, so a corrupt beacon journal aborts the WHOLE
        // revert (nothing applied, every diff preserved for retry). No-op when no
        // beacon journal exists (always, under the dormant gate).
        beacon_store.stage_block_revert(&mut batch, height, block_hash)?;

        // Delete both diff records in the SAME batch — applied only on commit.
        // Both the #253 key and the pre-#253 height-only key are removed, so a
        // journal written by an older binary cannot survive the revert that
        // consumed it.
        let hkey = sumchain_storage::schema::journal_key(height, block_hash);
        let legacy = height.to_be_bytes();
        if account_diff.is_some() {
            batch.delete(cf::STATE_DIFFS, &hkey)?;
            batch.delete(cf::STATE_DIFFS, &legacy)?;
        }
        if contract_diff.is_some() {
            batch.delete(cf::CONTRACT_STATE_DIFFS, &hkey)?;
            batch.delete(cf::CONTRACT_STATE_DIFFS, &legacy)?;
        }

        batch.commit()?;
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
        let state = StateManager::new(db.clone(), 1);

        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        // Initial balance is 0
        assert_eq!(state.get_balance(&addr).unwrap(), 0);

        // Set balance
        sumchain_storage::StateStore::new(&db).put_account(
                &addr,
                &AccountState {
                    balance: 1000,
                    nonce: 0,
                },
            )
            .unwrap();

        assert_eq!(state.get_balance(&addr).unwrap(), 1000);
    }

    /// A transfer moves balance and bumps the nonce, IN THE CANDIDATE.
    ///
    /// The committed `transfer` this replaces is gone: block execution stages,
    /// and a committed twin on the type execution holds would be reachable from
    /// anything with a `&StateManager`. The seed below is committed because it
    /// is the parent state the block starts from.
    #[test]
    fn test_transfer() {
        let (db, _dir) = setup();

        let from = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let to = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let proposer = Address::from_hex("0x0000000000000000000000000000000000000003").unwrap();

        // Fund sender
        StateStore::new(&db)
            .put_account(&from, &AccountState { balance: 1000, nonce: 0 })
            .unwrap();

        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let mut view = ExecutionView::new(&mut overlay);
        StateManager::v_transfer(&mut view, &from, &to, 500, 10, &proposer).unwrap();

        assert_eq!(StateManager::v_get_balance(&view, &from).unwrap(), 490); // 1000 - 500 - 10
        assert_eq!(StateManager::v_get_balance(&view, &to).unwrap(), 500);
        assert_eq!(StateManager::v_get_balance(&view, &proposer).unwrap(), 10);
        assert_eq!(StateManager::v_get_nonce(&view, &from).unwrap(), 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let (db, _dir) = setup();

        let from = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let to = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();

        StateStore::new(&db)
            .put_account(&from, &AccountState { balance: 100, nonce: 0 })
            .unwrap();

        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let mut view = ExecutionView::new(&mut overlay);
        let result = StateManager::v_transfer(&mut view, &from, &to, 200, 10, &Address::ZERO);
        assert!(matches!(result, Err(StateError::InsufficientBalance { .. })));
    }
}
