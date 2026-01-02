//! WASM contract executor.
//!
//! Handles contract deployment and execution with gas metering.

use crate::{
    host::HostEnv, storage::ContractStorage, CallResult, CodeHash, ContractAddress,
    ContractEvent, ContractMetadata, DeployResult, Gas, GasMeter, LogEntry,
    Result, RuntimeError, MAX_CALL_DEPTH, MAX_CODE_SIZE,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use sumchain_primitives::Address;
use tracing::{debug, trace, warn};
use wasmer::{
    imports, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, MemoryType, Module, Store,
    TypedFunction, Value,
};
use wasmer_compiler_singlepass::Singlepass;

/// Execution context passed to contract calls
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Caller address
    pub caller: Address,
    /// Original transaction origin
    pub origin: Address,
    /// Value attached to call
    pub value: u128,
    /// Gas limit
    pub gas_limit: Gas,
    /// Current block height
    pub block_height: u64,
    /// Current block timestamp
    pub block_timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
}

/// Result of contract execution
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Return value
    pub return_value: Vec<u8>,
    /// Gas used
    pub gas_used: Gas,
    /// Events emitted
    pub events: Vec<ContractEvent>,
    /// Logs
    pub logs: Vec<LogEntry>,
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Compiled contract cache
struct CompiledContract {
    module: Module,
    code_hash: CodeHash,
}

/// WASM runtime environment for host function access
struct WasmEnv {
    host_env: Arc<RwLock<HostEnv>>,
    memory: Option<Memory>,
}

impl WasmEnv {
    fn new(host_env: Arc<RwLock<HostEnv>>) -> Self {
        Self {
            host_env,
            memory: None,
        }
    }
}

/// Contract executor - compiles and runs WASM contracts
pub struct ContractExecutor {
    /// WASM engine store
    store: RwLock<Store>,
    /// Compiled contract cache
    cache: RwLock<HashMap<CodeHash, Arc<CompiledContract>>>,
    /// Contract storage
    storage: Arc<ContractStorage>,
    /// Contract metadata
    metadata: RwLock<HashMap<ContractAddress, ContractMetadata>>,
}

impl ContractExecutor {
    /// Create a new contract executor
    pub fn new(storage: Arc<ContractStorage>) -> Self {
        let compiler = Singlepass::default();
        let store = Store::new(compiler);

        Self {
            store: RwLock::new(store),
            cache: RwLock::new(HashMap::new()),
            storage,
            metadata: RwLock::new(HashMap::new()),
        }
    }

    /// Compute code hash
    fn code_hash(code: &[u8]) -> CodeHash {
        *blake3::hash(code).as_bytes()
    }

    /// Compute contract address from deployer and nonce
    pub fn compute_address(deployer: &Address, nonce: u64) -> ContractAddress {
        let mut data = Vec::with_capacity(28);
        data.extend_from_slice(deployer.as_bytes());
        data.extend_from_slice(&nonce.to_be_bytes());
        Address::from_public_key(&blake3::hash(&data).as_bytes()[..32].try_into().unwrap())
    }

    /// Deploy a new contract
    pub fn deploy(
        &self,
        code: Vec<u8>,
        init_method: &str,
        init_args: Vec<u8>,
        ctx: ExecutionContext,
        deployer_nonce: u64,
    ) -> Result<DeployResult> {
        // Validate code size
        if code.len() > MAX_CODE_SIZE {
            return Err(RuntimeError::CodeTooLarge {
                size: code.len(),
                limit: MAX_CODE_SIZE,
            });
        }

        let code_hash = Self::code_hash(&code);
        let contract_address = Self::compute_address(&ctx.caller, deployer_nonce);

        debug!(
            "Deploying contract at {} with code hash {}",
            contract_address,
            hex::encode(code_hash)
        );

        // Compile and cache module
        let module = {
            let mut store = self.store.write();
            Module::new(&store, &code)?
        };

        // Store code
        self.storage.store_code(&contract_address, &code)?;

        // Cache compiled module
        {
            let mut cache = self.cache.write();
            cache.insert(
                code_hash,
                Arc::new(CompiledContract {
                    module: module.clone(),
                    code_hash,
                }),
            );
        }

        // Store metadata
        {
            let mut metadata = self.metadata.write();
            metadata.insert(
                contract_address,
                ContractMetadata {
                    code_hash,
                    owner: ctx.caller,
                    deployed_at: ctx.block_timestamp,
                    deployed_block: ctx.block_height,
                    upgradeable: false,
                },
            );
        }

        // Call init method
        let gas_meter = Arc::new(GasMeter::new(ctx.gas_limit));
        gas_meter.consume(gas_meter.costs().deploy_base)?;

        let result = self.call_internal(
            contract_address,
            init_method,
            init_args,
            ctx.clone(),
            gas_meter.clone(),
            0, // call depth
        )?;

        if !result.success {
            // Rollback storage on failed init
            self.storage.rollback();
            return Err(RuntimeError::Execution(
                result.error.unwrap_or_else(|| "Init failed".to_string()),
            ));
        }

        // Commit storage changes
        self.storage.commit()?;

        Ok(DeployResult {
            contract_address,
            code_hash,
            gas_used: gas_meter.used(),
            events: result.events,
        })
    }

    /// Call a contract method
    pub fn call(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<ExecutionResult> {
        let gas_meter = Arc::new(GasMeter::new(ctx.gas_limit));
        gas_meter.consume(gas_meter.costs().call_base)?;

        let result = self.call_internal(contract, method, args, ctx, gas_meter.clone(), 0)?;

        if result.success {
            self.storage.commit()?;
        } else {
            self.storage.rollback();
        }

        Ok(result)
    }

    /// View call (read-only, no gas limit)
    pub fn view(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<Vec<u8>> {
        // Use a large gas limit for view calls
        let gas_meter = Arc::new(GasMeter::new(u64::MAX));

        let result = self.call_internal(contract, method, args, ctx, gas_meter, 0)?;

        // Always rollback view calls
        self.storage.rollback();

        if result.success {
            Ok(result.return_value)
        } else {
            Err(RuntimeError::Execution(
                result.error.unwrap_or_else(|| "View call failed".to_string()),
            ))
        }
    }

    /// Internal call implementation
    fn call_internal(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
        gas_meter: Arc<GasMeter>,
        call_depth: u32,
    ) -> Result<ExecutionResult> {
        if call_depth >= MAX_CALL_DEPTH {
            return Err(RuntimeError::RecursionLimit);
        }

        trace!("Calling {}::{}", contract, method);

        // Get contract code
        let code = self
            .storage
            .get_code(&contract)?
            .ok_or_else(|| RuntimeError::ContractNotFound(contract.to_string()))?;

        let code_hash = Self::code_hash(&code);

        // Get or compile module
        let compiled = {
            let cache = self.cache.read();
            cache.get(&code_hash).cloned()
        };

        let module = match compiled {
            Some(c) => c.module.clone(),
            None => {
                let mut store = self.store.write();
                let module = Module::new(&store, &code)?;

                let mut cache = self.cache.write();
                cache.insert(
                    code_hash,
                    Arc::new(CompiledContract {
                        module: module.clone(),
                        code_hash,
                    }),
                );

                module
            }
        };

        // Create host environment
        let host_env = Arc::new(RwLock::new(HostEnv::new(
            contract,
            ctx.caller,
            ctx.origin,
            ctx.value,
            ctx.block_height,
            ctx.block_timestamp,
            ctx.chain_id,
            gas_meter.clone(),
            self.storage.clone(),
            0, // TODO: Load actual balance
        )));

        // Create WASM environment
        let wasm_env = WasmEnv::new(host_env.clone());

        // Create instance with imports
        let mut store = self.store.write();
        let function_env = FunctionEnv::new(&mut *store, wasm_env);

        let imports = self.create_imports(&mut *store, &function_env);

        let instance = Instance::new(&mut *store, &module, &imports)?;

        // Get memory and set in environment
        if let Ok(memory) = instance.exports.get_memory("memory") {
            function_env.as_mut(&mut *store).memory = Some(memory.clone());
        }

        // Find and call the method
        let func: TypedFunction<(i32, i32), i32> = instance
            .exports
            .get_typed_function(&*store, method)
            .map_err(|_| RuntimeError::MethodNotFound(method.to_string()))?;

        // Allocate args in WASM memory
        let (args_ptr, args_len) = self.write_to_memory(&instance, &mut *store, &args)?;

        // Call the function
        let result = func.call(&mut *store, args_ptr, args_len);

        // Get events and logs
        let events = host_env.read().take_events();
        let logs = host_env.read().take_logs();

        match result {
            Ok(ret_ptr) => {
                // Read return value from memory
                let return_value = if ret_ptr != 0 {
                    self.read_from_memory(&instance, &*store, ret_ptr)?
                } else {
                    Vec::new()
                };

                Ok(ExecutionResult {
                    return_value,
                    gas_used: gas_meter.used(),
                    events,
                    logs,
                    success: true,
                    error: None,
                })
            }
            Err(e) => {
                warn!("Contract execution failed: {}", e);
                Ok(ExecutionResult {
                    return_value: Vec::new(),
                    gas_used: gas_meter.used(),
                    events,
                    logs,
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Create WASM imports
    fn create_imports(
        &self,
        store: &mut Store,
        env: &FunctionEnv<WasmEnv>,
    ) -> wasmer::Imports {
        imports! {
            "env" => {
                // === Environment ===
                "caller" => Function::new_typed_with_env(store, env, host_caller),
                "self_address" => Function::new_typed_with_env(store, env, host_self_address),
                "origin" => Function::new_typed_with_env(store, env, host_origin),
                "attached_value" => Function::new_typed_with_env(store, env, host_attached_value),
                "block_height" => Function::new_typed_with_env(store, env, host_block_height),
                "block_timestamp" => Function::new_typed_with_env(store, env, host_block_timestamp),
                "chain_id" => Function::new_typed_with_env(store, env, host_chain_id),

                // === Storage ===
                "storage_read" => Function::new_typed_with_env(store, env, host_storage_read),
                "storage_write" => Function::new_typed_with_env(store, env, host_storage_write),
                "storage_remove" => Function::new_typed_with_env(store, env, host_storage_remove),

                // === Crypto ===
                "blake3" => Function::new_typed_with_env(store, env, host_blake3),
                "ed25519_verify" => Function::new_typed_with_env(store, env, host_ed25519_verify),

                // === Events ===
                "emit" => Function::new_typed_with_env(store, env, host_emit),
                "log" => Function::new_typed_with_env(store, env, host_log),

                // === Transfer ===
                "transfer" => Function::new_typed_with_env(store, env, host_transfer),

                // === Utils ===
                "abort" => Function::new_typed_with_env(store, env, host_abort),
            }
        }
    }

    /// Write data to WASM memory, returns (ptr, len)
    fn write_to_memory(
        &self,
        instance: &Instance,
        store: &mut Store,
        data: &[u8],
    ) -> Result<(i32, i32)> {
        if data.is_empty() {
            return Ok((0, 0));
        }

        // Call contract's alloc function
        let alloc: TypedFunction<i32, i32> = instance
            .exports
            .get_typed_function(store, "alloc")
            .map_err(|_| RuntimeError::MethodNotFound("alloc".to_string()))?;

        let ptr = alloc.call(store, data.len() as i32)?;

        // Write data to memory
        let memory = instance
            .exports
            .get_memory("memory")
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        let view = memory.view(store);
        view.write(ptr as u64, data)
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        Ok((ptr, data.len() as i32))
    }

    /// Read data from WASM memory
    fn read_from_memory(
        &self,
        instance: &Instance,
        store: &Store,
        ptr: i32,
    ) -> Result<Vec<u8>> {
        if ptr == 0 {
            return Ok(Vec::new());
        }

        let memory = instance
            .exports
            .get_memory("memory")
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        let view = memory.view(store);

        // Read length prefix (first 4 bytes)
        let mut len_bytes = [0u8; 4];
        view.read(ptr as u64, &mut len_bytes)
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        // Read data
        let mut data = vec![0u8; len];
        view.read((ptr + 4) as u64, &mut data)
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        Ok(data)
    }

    /// Check if a contract exists
    pub fn contract_exists(&self, address: &ContractAddress) -> Result<bool> {
        Ok(self.storage.get_code(address)?.is_some())
    }

    /// Get contract metadata
    pub fn get_metadata(&self, address: &ContractAddress) -> Option<ContractMetadata> {
        self.metadata.read().get(address).cloned()
    }
}

// === Host Function Implementations ===

fn host_caller(env: FunctionEnvMut<WasmEnv>) -> i32 {
    let host_env = env.data().host_env.read();
    // Return pointer to caller address (contract needs to read it)
    // For simplicity, return 0 and let contract use a separate call
    0
}

fn host_self_address(env: FunctionEnvMut<WasmEnv>) -> i32 {
    0
}

fn host_origin(env: FunctionEnvMut<WasmEnv>) -> i32 {
    0
}

fn host_attached_value(env: FunctionEnvMut<WasmEnv>) -> i64 {
    let host_env = env.data().host_env.read();
    host_env.attached_value as i64
}

fn host_block_height(env: FunctionEnvMut<WasmEnv>) -> i64 {
    let host_env = env.data().host_env.read();
    host_env.block_height as i64
}

fn host_block_timestamp(env: FunctionEnvMut<WasmEnv>) -> i64 {
    let host_env = env.data().host_env.read();
    host_env.block_timestamp as i64
}

fn host_chain_id(env: FunctionEnvMut<WasmEnv>) -> i64 {
    let host_env = env.data().host_env.read();
    host_env.chain_id as i64
}

fn host_storage_read(env: FunctionEnvMut<WasmEnv>, key_ptr: i32, key_len: i32) -> i32 {
    // Read key from memory, look up in storage, return pointer to value
    // Simplified: return 0 for not found
    0
}

fn host_storage_write(
    env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) {
    // Read key and value from memory, write to storage
}

fn host_storage_remove(env: FunctionEnvMut<WasmEnv>, key_ptr: i32, key_len: i32) {
    // Read key from memory, remove from storage
}

fn host_blake3(env: FunctionEnvMut<WasmEnv>, data_ptr: i32, data_len: i32) -> i32 {
    // Read data, compute blake3, return pointer to result
    0
}

fn host_ed25519_verify(
    env: FunctionEnvMut<WasmEnv>,
    msg_ptr: i32,
    msg_len: i32,
    sig_ptr: i32,
    pubkey_ptr: i32,
) -> i32 {
    // Verify signature, return 1 for valid, 0 for invalid
    0
}

fn host_emit(env: FunctionEnvMut<WasmEnv>, topics_ptr: i32, data_ptr: i32, data_len: i32) {
    // Emit event
}

fn host_log(env: FunctionEnvMut<WasmEnv>, data_ptr: i32, data_len: i32) {
    // Log message
}

fn host_transfer(env: FunctionEnvMut<WasmEnv>, to_ptr: i32, amount_lo: i64, amount_hi: i64) -> i32 {
    // Transfer Koppa
    0
}

fn host_abort(env: FunctionEnvMut<WasmEnv>, msg_ptr: i32, msg_len: i32) {
    // Abort execution with message
    panic!("Contract aborted");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_compute_address() {
        let deployer = Address::from_public_key(&[1u8; 32]);
        let addr1 = ContractExecutor::compute_address(&deployer, 0);
        let addr2 = ContractExecutor::compute_address(&deployer, 1);

        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_code_hash() {
        let code1 = b"contract code 1";
        let code2 = b"contract code 2";

        let hash1 = ContractExecutor::code_hash(code1);
        let hash2 = ContractExecutor::code_hash(code2);

        assert_ne!(hash1, hash2);
    }
}
