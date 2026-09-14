//! Smart contract execution integration for SUM Chain.
//!
//! Bridges the WASM runtime (sumc-runtime) with the state layer.

use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Balance};
use sumchain_primitives::transaction::{ContractCallData, ContractDeployData};
use sumchain_storage::Database;
use sumc_runtime::{
    ContractExecutor as WasmExecutor, ContractStorage, ExecutionContext, ExecutionResult,
    Gas, RocksDbStorage,
};
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

/// Result of contract deployment
#[derive(Debug, Clone)]
pub struct ContractDeployResult {
    /// Deployed contract address
    pub contract_address: Address,
    /// Code hash
    pub code_hash: [u8; 32],
    /// Gas used
    pub gas_used: Gas,
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Result of contract call
#[derive(Debug, Clone)]
pub struct ContractCallResult {
    /// Return data
    pub return_data: Vec<u8>,
    /// Gas used
    pub gas_used: Gas,
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Events emitted
    pub events: Vec<ContractEvent>,
}

/// Contract event emitted during execution
#[derive(Debug, Clone)]
pub struct ContractEvent {
    /// Contract that emitted the event
    pub contract: Address,
    /// Event topics
    pub topics: Vec<[u8; 32]>,
    /// Event data
    pub data: Vec<u8>,
}

/// Contract executor - handles deployment and calls
pub struct ContractExecutorState {
    /// WASM runtime executor
    wasm_executor: Arc<WasmExecutor>,
    /// Database reference
    db: Arc<Database>,
    /// Chain parameters
    params: ChainParams,
}

impl ContractExecutorState {
    /// Drain the per-block contract-state journal (committed code/storage/
    /// metadata mutations) for reorg-diff construction.
    pub fn take_journal(&self) -> Vec<sumchain_storage::ContractMutation> {
        self.wasm_executor.take_journal()
    }

    /// Whether a contract is visible to EXECUTION — this candidate's staged
    /// rows included.
    ///
    /// Not the RPC answer. `contract_exists` below reads committed state; this
    /// reads what the runtime's per-candidate caches hold, which is where an
    /// abandoned block's rows would survive if the session were not scoped.
    pub fn contract_exists_in_candidate(&self, address: &Address) -> Result<bool> {
        self.wasm_executor
            .contract_exists(address)
            .map_err(|e| StateError::ContractError(e.to_string()))
    }

    /// The metadata companion of [`Self::contract_exists_in_candidate`]:
    /// metadata lives in its own address-keyed map, cleared on the same signal.
    pub fn metadata_in_candidate(&self, address: &Address) -> bool {
        self.wasm_executor.get_metadata(address).is_some()
    }

    /// Whether writes remain queued, unstaged. See
    /// `BlockExecutor::contract_queue_is_non_empty`.
    pub fn queue_is_non_empty(&self) -> bool {
        self.wasm_executor.pending_len() > 0
    }

    /// How many writes are queued, unstaged. A count, not a copy.
    pub fn queued_write_count(&self) -> usize {
        self.wasm_executor.pending_len()
    }

    /// Whether the contract-state journal is empty, without draining it.
    pub fn journal_is_empty(&self) -> bool {
        self.wasm_executor.journal_is_empty()
    }

    /// Drop everything the runtime holds for the current candidate.
    ///
    /// Called by `BlockExecutor` when a block execution leaves its scope, on
    /// the normal and the error path both.
    pub fn clear_block(&self) {
        self.wasm_executor.clear_block();
    }

    /// Stage the runtime's queued contract-CF writes into the block's candidate.
    ///
    /// This is the commit point, moved. The runtime used to end a transaction
    /// by writing a `WriteBatch` to RocksDB — while the block was still being
    /// built, so an abandoned block left contract storage moved, and a deploy
    /// left its code behind whatever happened afterwards. The runtime queues
    /// now, and this drains the queue into the view.
    ///
    /// It runs after every deploy and every call, successful or not: a failed
    /// transaction has already rolled its write-cache back, so the queue is
    /// empty, and a failed DEPLOY has queued the code and metadata deletions
    /// its cleanup performed.
    fn stage_contract_writes(&self, view: &mut ExecutionView<'_, '_>) -> Result<()> {
        use sumc_runtime::storage::PendingWrite;
        // Borrowed entries, and the queue cleared only after the last one
        // lands. Copying the queue out first would duplicate the whole write
        // set — a deployed contract's code included — before the candidate had
        // charged a byte of it, and a refusal part-way would lose the rest.
        self.wasm_executor.stage_pending(|w| {
            match w {
                PendingWrite::Storage {
                    contract,
                    key,
                    value,
                } => {
                    // The same key builder the journal uses. A second one here
                    // would let the staged row and its journal entry disagree
                    // about which row was written.
                    let full = sumc_runtime::storage::storage_cf_key(contract, key);
                    match value {
                        Some(v) => view.put(cf::CONTRACT_STORAGE, &full, v),
                        None => view.delete(cf::CONTRACT_STORAGE, &full),
                    }
                }
                PendingWrite::Code { contract, value } => match value {
                    Some(v) => view.put(cf::CONTRACT_CODE, contract.as_bytes(), v),
                    None => view.delete(cf::CONTRACT_CODE, contract.as_bytes()),
                },
                PendingWrite::Metadata { contract, value } => match value {
                    Some(v) => view.put(cf::CONTRACT_METADATA, contract.as_bytes(), v),
                    None => view.delete(cf::CONTRACT_METADATA, contract.as_bytes()),
                },
            }
            .map_err(StateError::Storage)
        })
    }

    /// Create a new contract executor
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        // Persistent contract storage backed by RocksDB: code, storage, and
        // metadata live in dedicated CFs and survive restarts.
        let backend = Arc::new(RocksDbStorage::new(db.clone()));
        let storage = Arc::new(ContractStorage::new(backend));
        let wasm_executor = Arc::new(WasmExecutor::new(storage));

        Self {
            wasm_executor,
            db,
            params,
        }
    }

    /// Deploy a contract
    #[allow(clippy::too_many_arguments)]
    pub fn deploy(
        &self, view: &mut ExecutionView<'_, '_>,
        from: &Address,
        deploy_data: &ContractDeployData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<ContractDeployResult> {
        // Bind the runtime to this candidate before anything else. It is a
        // long-lived object and its caches are per-candidate; this is what stops
        // an abandoned block's contract rows reaching the block after it.
        self.wasm_executor.begin_candidate(view.candidate_id());

        info!(
            "Deploying contract from {} with {} bytes of code",
            from,
            deploy_data.code.len()
        );

        // Validate gas limit
        if deploy_data.gas_limit < self.params.min_contract_gas {
            return Ok(ContractDeployResult {
                contract_address: Address::ZERO,
                code_hash: [0u8; 32],
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Gas limit {} below minimum {}",
                    deploy_data.gas_limit, self.params.min_contract_gas
                )),
            });
        }

        if deploy_data.gas_limit > self.params.max_contract_gas {
            return Ok(ContractDeployResult {
                contract_address: Address::ZERO,
                code_hash: [0u8; 32],
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Gas limit {} exceeds maximum {}",
                    deploy_data.gas_limit, self.params.max_contract_gas
                )),
            });
        }

        // Check sender has enough balance for fee + value
        let total_cost = fee.saturating_add(deploy_data.value);
        let balance = StateManager::v_get_balance(view, from)?;
        if balance < total_cost {
            return Ok(ContractDeployResult {
                contract_address: Address::ZERO,
                code_hash: [0u8; 32],
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Insufficient balance: need {}, have {}",
                    total_cost, balance
                )),
            });
        }

        // Get current nonce for address computation
        let nonce = StateManager::v_get_nonce(view, from)?;

        // Create execution context
        let ctx = ExecutionContext {
            caller: *from,
            origin: *from,
            value: deploy_data.value,
            gas_limit: deploy_data.gas_limit,
            block_height,
            block_timestamp,
            chain_id: state.chain_id(),
        };

        // Execute deployment
        let deployed = self.wasm_executor.deploy(
            deploy_data.code.clone(),
            &deploy_data.init_method,
            deploy_data.init_args.clone(),
            ctx,
            nonce,
        );
        // Drain the runtime's queue into the candidate before interpreting the
        // result. A failed deploy has queued the code and metadata deletions
        // its cleanup performed, and those belong to this block too.
        self.stage_contract_writes(view)?;
        match deployed {
            Ok(result) => {
                info!(
                    "Contract deployed at {} (gas used: {})",
                    result.contract_address, result.gas_used
                );

                // Deduct value and fee from sender
                StateManager::v_deduct(view, from, total_cost)?;

                // Credit value to contract
                if deploy_data.value > 0 {
                    StateManager::v_credit(view, &result.contract_address, deploy_data.value)?;
                }

                // Credit fee to proposer
                StateManager::v_credit(view, proposer, fee)?;

                // Increment nonce
                StateManager::v_increment_nonce(view, from)?;

                Ok(ContractDeployResult {
                    contract_address: result.contract_address,
                    code_hash: result.code_hash,
                    gas_used: result.gas_used,
                    success: true,
                    error: None,
                })
            }
            Err(e) => {
                warn!("Contract deployment failed: {}", e);

                // Still charge fee on failure
                StateManager::v_deduct(view, from, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, from)?;

                Ok(ContractDeployResult {
                    contract_address: Address::ZERO,
                    code_hash: [0u8; 32],
                    gas_used: 0,
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Call a contract method
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self, view: &mut ExecutionView<'_, '_>,
        from: &Address,
        call_data: &ContractCallData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<ContractCallResult> {
        // See `deploy`: bind before use.
        self.wasm_executor.begin_candidate(view.candidate_id());

        debug!(
            "Calling contract {} method {} from {}",
            call_data.contract, call_data.method, from
        );

        // Validate gas limit
        if call_data.gas_limit < self.params.min_contract_gas {
            return Ok(ContractCallResult {
                return_data: Vec::new(),
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Gas limit {} below minimum {}",
                    call_data.gas_limit, self.params.min_contract_gas
                )),
                events: Vec::new(),
            });
        }

        if call_data.gas_limit > self.params.max_contract_gas {
            return Ok(ContractCallResult {
                return_data: Vec::new(),
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Gas limit {} exceeds maximum {}",
                    call_data.gas_limit, self.params.max_contract_gas
                )),
                events: Vec::new(),
            });
        }

        // Check contract exists
        if !self.wasm_executor.contract_exists(&call_data.contract)? {
            return Ok(ContractCallResult {
                return_data: Vec::new(),
                gas_used: 0,
                success: false,
                error: Some(format!("Contract {} not found", call_data.contract)),
                events: Vec::new(),
            });
        }

        // Check sender has enough balance for fee + value
        let total_cost = fee.saturating_add(call_data.value);
        let balance = StateManager::v_get_balance(view, from)?;
        if balance < total_cost {
            return Ok(ContractCallResult {
                return_data: Vec::new(),
                gas_used: 0,
                success: false,
                error: Some(format!(
                    "Insufficient balance: need {}, have {}",
                    total_cost, balance
                )),
                events: Vec::new(),
            });
        }

        // Create execution context
        let ctx = ExecutionContext {
            caller: *from,
            origin: *from,
            value: call_data.value,
            gas_limit: call_data.gas_limit,
            block_height,
            block_timestamp,
            chain_id: state.chain_id(),
        };

        // Execute call
        let called = self.wasm_executor.call(
            call_data.contract,
            &call_data.method,
            call_data.args.clone(),
            ctx,
        );
        // As in `deploy`: the runtime has rolled back a failed call's writes,
        // so the queue is empty; a successful one has queued them.
        self.stage_contract_writes(view)?;
        match called {
            Ok(result) => {
                if result.success {
                    debug!(
                        "Contract call succeeded (gas used: {})",
                        result.gas_used
                    );

                    // Deduct value and fee from sender
                    StateManager::v_deduct(view, from, total_cost)?;

                    // Credit value to contract
                    if call_data.value > 0 {
                        StateManager::v_credit(view, &call_data.contract, call_data.value)?;
                    }

                    // Credit fee to proposer
                    StateManager::v_credit(view, proposer, fee)?;

                    // Increment nonce
                    StateManager::v_increment_nonce(view, from)?;

                    // Convert events
                    let events = result
                        .events
                        .into_iter()
                        .map(|e| ContractEvent {
                            contract: e.contract,
                            topics: e.topics,
                            data: e.data,
                        })
                        .collect();

                    Ok(ContractCallResult {
                        return_data: result.return_value,
                        gas_used: result.gas_used,
                        success: true,
                        error: None,
                        events,
                    })
                } else {
                    warn!(
                        "Contract call failed: {}",
                        result.error.as_deref().unwrap_or("unknown")
                    );

                    // Still charge fee on failure
                    StateManager::v_deduct(view, from, fee)?;
                    StateManager::v_credit(view, proposer, fee)?;
                    StateManager::v_increment_nonce(view, from)?;

                    Ok(ContractCallResult {
                        return_data: Vec::new(),
                        gas_used: result.gas_used,
                        success: false,
                        error: result.error,
                        events: Vec::new(),
                    })
                }
            }
            Err(e) => {
                warn!("Contract call error: {}", e);

                // Charge fee on error
                StateManager::v_deduct(view, from, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, from)?;

                Ok(ContractCallResult {
                    return_data: Vec::new(),
                    gas_used: 0,
                    success: false,
                    error: Some(e.to_string()),
                    events: Vec::new(),
                })
            }
        }
    }

    /// View call (read-only, no state changes)
    #[allow(clippy::too_many_arguments)]
    pub fn view_call(
        &self,
        contract: &Address,
        method: &str,
        args: Vec<u8>,
        from: Option<Address>,
        block_height: u64,
        block_timestamp: u64,
        chain_id: u64,
    ) -> Result<Vec<u8>> {
        let caller = from.unwrap_or(Address::ZERO);

        let ctx = ExecutionContext {
            caller,
            origin: caller,
            value: 0,
            gas_limit: u64::MAX, // View calls have unlimited gas
            block_height,
            block_timestamp,
            chain_id,
        };

        self.wasm_executor
            .view(*contract, method, args, ctx)
            .map_err(|e| StateError::ContractError(e.to_string()))
    }

    /// Estimate gas for a call via a metered dry-run (executed up to the chain's
    /// `max_contract_gas`, then rolled back). Returns gas used, or `Err` on
    /// execution failure / out-of-gas.
    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        contract: &Address,
        method: &str,
        args: Vec<u8>,
        from: Option<Address>,
        block_height: u64,
        block_timestamp: u64,
        chain_id: u64,
    ) -> Result<u64> {
        let caller = from.unwrap_or(Address::ZERO);
        let ctx = ExecutionContext {
            caller,
            origin: caller,
            value: 0,
            gas_limit: self.params.max_contract_gas,
            block_height,
            block_timestamp,
            chain_id,
        };
        self.wasm_executor
            .estimate_gas(*contract, method, args, ctx)
            .map_err(|e| StateError::ContractError(e.to_string()))
    }

    /// Check if a contract exists, from COMMITTED state.
    ///
    /// No candidate is bound here: this is the RPC/diagnostic path, and it must
    /// answer about the chain rather than about whatever block the runtime last
    /// executed.
    pub fn contract_exists(&self, address: &Address) -> Result<bool> {
        self.wasm_executor
            .contract_exists_committed(address)
            .map_err(|e| StateError::ContractError(e.to_string()))
    }

    /// Contract metadata from COMMITTED state. See [`Self::contract_exists`].
    pub fn get_metadata(&self, address: &Address) -> Option<ContractMetadata> {
        self.wasm_executor.get_metadata_committed(address).map(|m| ContractMetadata {
            code_hash: m.code_hash,
            owner: m.owner,
            deployed_at: m.deployed_at,
            deployed_block: m.deployed_block,
            upgradeable: m.upgradeable,
        })
    }
}

/// Contract metadata
#[derive(Debug, Clone)]
pub struct ContractMetadata {
    /// Code hash
    pub code_hash: [u8; 32],
    /// Owner address
    pub owner: Address,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Deployment block
    pub deployed_block: u64,
    /// Whether the contract is upgradeable
    pub upgradeable: bool,
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, StateManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = StateManager::new(db.clone(), 1);
        (db, state, dir)
    }

    #[test]
    fn test_contract_executor_creation() {
        let (db, _state, _dir) = setup();
        let params = ChainParams::default();
        let executor = ContractExecutorState::new(db, params);

        // Should be able to check for non-existent contracts
        let fake_addr = Address::from_public_key(&[1u8; 32]);
        assert!(!executor.contract_exists(&fake_addr).unwrap());
    }
}
