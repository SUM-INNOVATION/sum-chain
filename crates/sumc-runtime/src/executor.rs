//! WASM contract executor.
//!
//! Handles contract deployment and execution with gas metering.

use crate::{
    host::HostEnv,
    local_limits::LocalExecutionLimits,
    metering::{self, CostScheduleV1Provisional, MeteredModule},
    storage::ContractStorage,
    CallResult, CodeHash, ContractAddress, ContractEvent, ContractMetadata, DeployResult, Gas,
    GasMeter, LogEntry, Result, RuntimeError, MAX_CALL_DEPTH, MAX_CODE_SIZE,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use sumchain_primitives::Address;
use sumchain_storage::{contract_cf_kind, ContractMutation};
use tracing::{debug, trace, warn};
use wasmer::{
    imports, Function, FunctionEnv, FunctionEnvMut, Global, Instance, Memory, MemoryType, Module,
    Store, TypedFunction, Value,
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

/// Which engine and rules a deploy or call runs under.
///
/// Chosen by the caller per block height (`contract_metering_enabled_from_height`
/// in the state layer). [`ExecutionMode::Unmetered`] is the engine and
/// accounting every block below that gate was executed with, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// The original engine ([`crate::ENGINE_IDENTITY`]): gas on host calls only.
    Unmetered,
    /// Metering v1 under the PROVISIONAL schedule
    /// ([`crate::METERED_ENGINE_IDENTITY`]). See [`crate::metering`].
    MeteredV1Provisional,
}

/// Compiled contract cache
struct CompiledContract {
    module: Module,
    /// The engine `module` was compiled with; its stores come from here. The
    /// shared engine on the block executor, a per-module one on a local
    /// executor (see `local_limits::metered_engine`).
    engine: wasmer::Engine,
    code_hash: CodeHash,
}

/// WASM runtime environment for host function access
struct WasmEnv {
    host_env: Arc<RwLock<HostEnv>>,
    memory: Option<Memory>,
    /// Guest allocator export, used by host functions that must return a
    /// variable-length buffer to the guest (e.g. `storage_read`).
    alloc: Option<TypedFunction<i32, i32>>,
    /// Bytes host functions may still copy in this execution. `None` on the
    /// block executor: there the only bound is gas, as before.
    host_bytes_left: Option<u64>,
    /// The budget globals of a metered instance; `None` on the unmetered
    /// engine, whose host functions never read it.
    metering: Option<MeteredEnv>,
}

/// Handles a metered instance's host functions charge through.
#[derive(Clone)]
struct MeteredEnv {
    gas: Global,
    reason: Global,
    schedule: CostScheduleV1Provisional,
}

impl WasmEnv {
    fn new(host_env: Arc<RwLock<HostEnv>>, host_bytes_left: Option<u64>) -> Self {
        Self {
            host_env,
            memory: None,
            alloc: None,
            host_bytes_left,
            metering: None,
        }
    }

    /// Charge `n` bytes of host copying against the local budget, if any.
    fn charge_host_bytes(&mut self, n: u64) -> std::result::Result<(), wasmer::RuntimeError> {
        match self.host_bytes_left.as_mut() {
            None => Ok(()),
            Some(left) if *left >= n => {
                *left -= n;
                Ok(())
            }
            Some(_) => Err(wasmer::RuntimeError::new(LOCAL_HOST_BUDGET_EXHAUSTED)),
        }
    }
}

/// Error text when a local (RPC/view) execution exhausts its operator budget.
pub const LOCAL_FUEL_EXHAUSTED: &str = "local execution budget exhausted";
/// Error text when a local execution exhausts its host-copy budget.
pub const LOCAL_HOST_BUDGET_EXHAUSTED: &str = "local host copy budget exhausted";
/// Error text when a local execution exhausts its bulk-operation budget.
pub const LOCAL_BULK_EXHAUSTED: &str = "local bulk memory budget exhausted";

/// Charge `amount` against a metered instance's gas global, BEFORE the work it
/// pays for. Short: the global is zeroed, the reason recorded, and the call
/// traps.
fn charge_metered(
    metering: &MeteredEnv,
    store: &mut impl wasmer::AsStoreMut,
    amount: Gas,
) -> std::result::Result<(), wasmer::RuntimeError> {
    let remaining = metering.gas.get(store).unwrap_i64() as u64;
    if amount > remaining {
        metering.gas.set(store, Value::I64(0))?;
        metering
            .reason
            .set(store, Value::I32(metering::TRAP_OUT_OF_GAS))?;
        return Err(wasmer::RuntimeError::new(metering::OUT_OF_GAS_MESSAGE));
    }
    metering
        .gas
        .set(store, Value::I64((remaining - amount) as i64))
}

/// Bounds on the block executor's metered-module cache (#279).
///
/// Node-local and never consensus. A module evicted here is compiled again
/// the next time a block loads it, and that block's loaded-code measure (D8)
/// already counts it, so capacity and eviction change neither an outcome nor
/// the per-block bound on compilation. Eviction only happens between blocks
/// ([`ContractExecutor::clear_block`]), so a module the current block has
/// loaded is never evicted while that block runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeteredCacheCapacity {
    /// Total code bytes of the cached modules.
    pub max_code_bytes: u64,
    /// Number of cached modules. Each holds its own engine, so a count bound
    /// is needed besides the byte bound.
    pub max_modules: usize,
}

impl MeteredCacheCapacity {
    /// PROVISIONAL, like every #279 value: 32 MiB of code, which is 128 blocks
    /// at the provisional 256 KiB loaded-code cap, and 1024 modules.
    pub const DEFAULT: Self = Self {
        max_code_bytes: 32 * 1024 * 1024,
        max_modules: 1024,
    };
}

/// A cached metered module and what bounding the cache needs to know of it.
struct MeteredEntry {
    module: Arc<MeteredModule>,
    code_len: u64,
    /// When it was last inserted or used (`MeteredCache::uses`); the oldest
    /// is evicted first.
    last_used: AtomicU64,
}

/// The metered-module cache.
struct MeteredCache {
    entries: HashMap<CodeHash, MeteredEntry>,
    code_bytes: u64,
    /// Use counter that stamps `MeteredEntry::last_used`.
    uses: AtomicU64,
    /// `Some` on the block executor; `None` on a local executor, which empties
    /// the cache at `LocalExecutionLimits::max_cached_modules` instead.
    capacity: Option<MeteredCacheCapacity>,
}

impl MeteredCache {
    fn new(capacity: Option<MeteredCacheCapacity>) -> Self {
        Self {
            entries: HashMap::new(),
            code_bytes: 0,
            uses: AtomicU64::new(0),
            capacity,
        }
    }

    fn stamp(&self) -> u64 {
        self.uses.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn within(&self, cap: &MeteredCacheCapacity) -> bool {
        self.code_bytes <= cap.max_code_bytes && self.entries.len() <= cap.max_modules
    }

    /// Evict least recently used modules until the cache is within capacity.
    fn trim(&mut self) {
        let Some(cap) = self.capacity else { return };
        if self.within(&cap) {
            return;
        }
        let mut order: Vec<(u64, CodeHash)> = self
            .entries
            .iter()
            .map(|(h, e)| (e.last_used.load(Ordering::Relaxed), *h))
            .collect();
        order.sort_unstable();
        for (_, hash) in order {
            if self.within(&cap) {
                break;
            }
            if let Some(e) = self.entries.remove(&hash) {
                self.code_bytes -= e.code_len;
            }
        }
    }
}

/// Contract executor - compiles and runs WASM contracts
pub struct ContractExecutor {
    /// Shared compiler engine. We hold the `Engine` (Send+Sync) rather than a
    /// live `Store`, and clone it into a fresh, short-lived `Store` inside each
    /// synchronous deploy/call, never crossing an `.await`. This keeps
    /// `ContractExecutor` `Send` (a `Store` is `!Send` in modern wasmer — it
    /// carries VM handles and an on-called hook — which would make the executor
    /// and the async consensus path that owns it `!Send`). Cloned engines share
    /// the same engine id, so a `Module` compiled against one clone instantiates
    /// cleanly into a `Store` built from another — keeping the compiled-module
    /// cache valid. Engine-behavior-neutral: the determinism golden proves the
    /// consensus-visible output is byte-identical to the held-store design.
    engine: wasmer::Engine,
    /// Compiled contract cache
    cache: RwLock<HashMap<CodeHash, Arc<CompiledContract>>>,
    /// Contract storage
    storage: Arc<ContractStorage>,
    /// Contract metadata
    metadata: RwLock<HashMap<ContractAddress, ContractMetadata>>,
    /// Node-local budgets. `Some` only on an executor that never produces
    /// consensus state (the RPC/view instance); see `with_local_limits`.
    local_limits: Option<LocalExecutionLimits>,
    /// Modules compiled under metering v1, each with its own engine. Separate
    /// from `cache`: the same code hash compiles to different machine code
    /// under the two engines, and neither may be instantiated from the other.
    /// Bounded on the block executor; see [`MeteredCacheCapacity`].
    metered_cache: RwLock<MeteredCache>,
    /// Code bytes compiled under metering v1 so far (deploys and cache misses).
    /// Node-local and never consensus: it is how compilation work is checked
    /// against a block's loaded-code measure (#279, D8).
    metered_compiled_bytes: AtomicU64,
    /// The metering v1 schedule. PROVISIONAL.
    schedule: CostScheduleV1Provisional,
}

impl ContractExecutor {
    /// Create a new contract executor
    pub fn new(storage: Arc<ContractStorage>) -> Self {
        // Modern wasmer (5.x+) multi-backend API: a compiler config no longer
        // converts directly into an `Engine`; it goes through the sys
        // `EngineBuilder`. `Singlepass::default()` keeps the deterministic
        // single-pass backend (identical codegen policy to 4.x — the determinism
        // golden proves parity). Singlepass 5.0.6 is the last MIT release
        // (6.0.0+ is BUSL-1.1); pinned in the workspace Cargo.toml.
        let compiler = Singlepass::default();
        let engine: wasmer::Engine = wasmer::sys::EngineBuilder::new(compiler).engine().into();

        Self {
            engine,
            cache: RwLock::new(HashMap::new()),
            storage,
            metadata: RwLock::new(HashMap::new()),
            local_limits: None,
            metered_cache: RwLock::new(MeteredCache::new(Some(MeteredCacheCapacity::DEFAULT))),
            metered_compiled_bytes: AtomicU64::new(0),
            schedule: metering::METERED_COST_SCHEDULE,
        }
    }

    /// The metering v1 schedule this executor applies in
    /// [`ExecutionMode::MeteredV1Provisional`].
    pub fn metering_schedule(&self) -> &CostScheduleV1Provisional {
        &self.schedule
    }

    /// An executor for read-only local use (RPC `contract_call` and
    /// `contract_estimateGas`), bounded by `limits`.
    ///
    /// Not for block execution: its budgets are node-local, so a result from
    /// here can be a local-budget error that a block would not report. Gas
    /// accounting is unchanged, so an estimate within budget is the same number
    /// the block executor would charge.
    pub fn with_local_limits(storage: Arc<ContractStorage>, limits: LocalExecutionLimits) -> Self {
        Self {
            engine: crate::local_limits::metered_engine(&limits),
            cache: RwLock::new(HashMap::new()),
            storage,
            metadata: RwLock::new(HashMap::new()),
            local_limits: Some(limits),
            metered_cache: RwLock::new(MeteredCache::new(None)),
            metered_compiled_bytes: AtomicU64::new(0),
            schedule: metering::METERED_COST_SCHEDULE,
        }
    }

    /// The local budgets this executor enforces, if it is a local executor.
    pub fn local_limits(&self) -> Option<LocalExecutionLimits> {
        self.local_limits
    }

    /// Compile `code`, returning the module and the engine to instantiate it
    /// with.
    fn compile(&self, code: &[u8]) -> Result<(Module, wasmer::Engine)> {
        let engine = match &self.local_limits {
            Some(limits) => crate::local_limits::metered_engine(limits),
            None => self.engine.clone(),
        };
        let module = Module::new(&Store::new(engine.clone()), code)?;
        Ok((module, engine))
    }

    /// Insert into the compiled-module cache. A local executor empties it on
    /// reaching its bound; the block executor keeps its existing behaviour.
    fn cache_insert(&self, code_hash: CodeHash, compiled: Arc<CompiledContract>) {
        let mut cache = self.cache.write();
        if let Some(limits) = &self.local_limits {
            if cache.len() >= limits.max_cached_modules && !cache.contains_key(&code_hash) {
                cache.clear();
            }
        }
        cache.insert(code_hash, compiled);
    }

    /// Compile `code` under metering v1, counting its bytes.
    fn compile_metered(&self, code: &[u8]) -> Result<MeteredModule> {
        self.metered_compiled_bytes
            .fetch_add(code.len() as u64, Ordering::Relaxed);
        metering::compile(code, &self.schedule)
    }

    /// Code bytes this executor has compiled under metering v1: every metered
    /// deploy, and every metered call that missed the cache. Node-local.
    pub fn metered_compiled_bytes(&self) -> u64 {
        self.metered_compiled_bytes.load(Ordering::Relaxed)
    }

    /// Insert into the metered-module cache. A local executor empties it on
    /// reaching its bound, exactly as [`Self::cache_insert`] bounds the
    /// unmetered one. The block executor never evicts here: it trims between
    /// blocks ([`Self::clear_block`]).
    fn metered_cache_insert(
        &self,
        code_hash: CodeHash,
        compiled: Arc<MeteredModule>,
        code_len: u64,
    ) {
        let mut cache = self.metered_cache.write();
        if let Some(limits) = &self.local_limits {
            if cache.entries.len() >= limits.max_cached_modules
                && !cache.entries.contains_key(&code_hash)
            {
                cache.entries.clear();
                cache.code_bytes = 0;
            }
        }
        let entry = MeteredEntry {
            module: compiled,
            code_len,
            last_used: AtomicU64::new(cache.stamp()),
        };
        if let Some(old) = cache.entries.insert(code_hash, entry) {
            cache.code_bytes -= old.code_len;
        }
        cache.code_bytes += code_len;
    }

    /// The cached metered module for `code_hash`, marking it used.
    fn metered_cache_get(&self, code_hash: &CodeHash) -> Option<Arc<MeteredModule>> {
        let cache = self.metered_cache.read();
        let entry = cache.entries.get(code_hash)?;
        entry.last_used.store(cache.stamp(), Ordering::Relaxed);
        Some(entry.module.clone())
    }

    /// Modules and code bytes in the metered-module cache. Node-local.
    pub fn metered_cache_usage(&self) -> (usize, u64) {
        let cache = self.metered_cache.read();
        (cache.entries.len(), cache.code_bytes)
    }

    /// Replace the block executor's metered-cache bounds; `None` leaves it
    /// unbounded. Takes effect at the next block boundary. Has no effect on a
    /// local executor, which keeps its own bound.
    pub fn set_metered_cache_capacity(&self, capacity: Option<MeteredCacheCapacity>) {
        if self.local_limits.is_none() {
            self.metered_cache.write().capacity = capacity;
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

    /// Deploy a new contract on the unmetered engine.
    pub fn deploy(
        &self,
        code: Vec<u8>,
        init_method: &str,
        init_args: Vec<u8>,
        ctx: ExecutionContext,
        deployer_nonce: u64,
    ) -> Result<DeployResult> {
        self.deploy_with_mode(
            ExecutionMode::Unmetered,
            code,
            init_method,
            init_args,
            ctx,
            deployer_nonce,
        )
    }

    /// Deploy a new contract under `mode`.
    ///
    /// Metered: the deploy charge (base plus per code byte) is taken from the
    /// transaction's budget BEFORE the code is compiled, and the init method
    /// runs under the metered engine against what is left. Every failure,
    /// out-of-gas included, takes the same cleanup path as today's traps.
    pub fn deploy_with_mode(
        &self,
        mode: ExecutionMode,
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

        // Metered: charge the deploy before any compile work, against the one
        // budget the init call then continues to spend.
        let precharged = match mode {
            ExecutionMode::Unmetered => None,
            ExecutionMode::MeteredV1Provisional => {
                let meter = Arc::new(GasMeter::new(ctx.gas_limit));
                meter.consume(self.schedule.deploy_cost(code.len()))?;
                Some(meter)
            }
        };

        match mode {
            ExecutionMode::Unmetered => {
                // Compile and cache module (fresh store; the compiled `Module` outlives it).
                let (module, engine) = self.compile(&code)?;

                // Capture the pre-image of the code row for the reorg journal (None
                // for a fresh address), then store code.
                let old_code = self.storage.get_code(&contract_address)?;
                self.storage.store_code(&contract_address, &code)?;

                // Cache compiled module
                self.cache_insert(
                    code_hash,
                    Arc::new(CompiledContract {
                        module,
                        engine,
                        code_hash,
                    }),
                );
                self.deploy_finalize(
                    mode, code, code_hash, contract_address, old_code, init_method, init_args,
                    ctx, None,
                )
            }
            ExecutionMode::MeteredV1Provisional => {
                let compiled = Arc::new(self.compile_metered(&code)?);
                let old_code = self.storage.get_code(&contract_address)?;
                self.storage.store_code(&contract_address, &code)?;
                self.metered_cache_insert(code_hash, compiled, code.len() as u64);
                self.deploy_finalize(
                    mode, code, code_hash, contract_address, old_code, init_method, init_args,
                    ctx, precharged,
                )
            }
        }
    }

    /// Everything a deploy does after its code row is stored.
    #[allow(clippy::too_many_arguments)]
    fn deploy_finalize(
        &self,
        mode: ExecutionMode,
        code: Vec<u8>,
        code_hash: CodeHash,
        contract_address: ContractAddress,
        old_code: Option<Vec<u8>>,
        init_method: &str,
        init_args: Vec<u8>,
        ctx: ExecutionContext,
        precharged: Option<Arc<GasMeter>>,
    ) -> Result<DeployResult> {

        // Everything after `store_code` runs inside a guarded finalize: ANY
        // failure path (metadata encode/persist, init gas, init Err, init
        // success==false, storage commit) must leave NO persisted code,
        // metadata, storage, or unmetered cache entry behind. On `Err`, run
        // cleanup.
        let finalize = (|| -> Result<DeployResult> {
            // Capture metadata pre-image, then store metadata (backend + cache).
            let old_meta = self.storage.get_metadata(&contract_address)?;
            let meta = ContractMetadata {
                code_hash,
                owner: ctx.caller,
                deployed_at: ctx.block_timestamp,
                deployed_block: ctx.block_height,
                upgradeable: false,
            };
            let meta_bytes = bincode::serialize(&meta)
                .map_err(|e| RuntimeError::Storage(format!("metadata encode: {}", e)))?;
            self.storage.store_metadata(&contract_address, &meta_bytes)?;
            self.metadata.write().insert(contract_address, meta);

            // Call init method.
            let (gas_meter, result) = match precharged {
                None => {
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
                    (gas_meter, result)
                }
                Some(gas_meter) => {
                    debug_assert_eq!(mode, ExecutionMode::MeteredV1Provisional);
                    let result = self.call_internal_metered(
                        contract_address,
                        init_method,
                        init_args,
                        ctx.clone(),
                        gas_meter.clone(),
                        0,
                    )?;
                    (gas_meter, result)
                }
            };

            if !result.success {
                return Err(RuntimeError::Execution(
                    result.error.unwrap_or_else(|| "Init failed".to_string()),
                ));
            }

            // Commit storage changes (appends init's storage mutations to the
            // journal). Only after a fully successful deploy do we journal the
            // code + metadata rows, so a failed deploy leaves no journal trace.
            self.storage.commit()?;
            self.storage.record_raw(ContractMutation {
                cf_kind: contract_cf_kind::CODE,
                key: contract_address.as_bytes().to_vec(),
                old: old_code.clone(),
                new: Some(code.clone()),
            });
            self.storage.record_raw(ContractMutation {
                cf_kind: contract_cf_kind::METADATA,
                key: contract_address.as_bytes().to_vec(),
                old: old_meta,
                new: Some(meta_bytes),
            });

            Ok(DeployResult {
                contract_address,
                code_hash,
                gas_used: gas_meter.used(),
                events: result.events,
            })
        })();

        match finalize {
            Ok(r) => Ok(r),
            Err(e) => {
                self.cleanup_failed_deploy(&contract_address, &code_hash);
                Err(e)
            }
        }
    }

    /// Roll back every persisted/cached effect of a deploy that failed after
    /// `store_code`. Idempotent; deletes are best-effort.
    ///
    /// The metered module stays cached. It is keyed by its code under one
    /// fixed schedule, so it is the right module for any contract with that
    /// code, and removing it would let a failed deploy make a later call in the
    /// same block recompile code that the block's loaded-code measure (#279,
    /// D8) has already counted.
    fn cleanup_failed_deploy(&self, contract_address: &ContractAddress, code_hash: &CodeHash) {
        self.storage.rollback();
        let _ = self.storage.delete_code(contract_address);
        let _ = self.storage.delete_metadata(contract_address);
        self.metadata.write().remove(contract_address);
        self.cache.write().remove(code_hash);
    }

    /// Call a contract method on the unmetered engine, with the historical error
    /// handling.
    ///
    /// A call that FAILS (`success == false`, e.g. a trap) has its staged
    /// storage writes rolled back. A call that returns `Err` does not: whatever
    /// it staged before the error (an `alloc` that wrote and then failed, a
    /// method that wrote and then returned an unreadable value) stays in the
    /// write cache, visible to later calls and committed by the next
    /// successful one. That is consensus-visible, so it is kept here unchanged
    /// and corrected only by [`Self::call_with_error_rollback`], which block
    /// execution selects behind an activation gate.
    pub fn call(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<ExecutionResult> {
        self.call_with_error_rollback(contract, method, args, ctx, false)
    }

    /// Call a contract method under `mode`.
    ///
    /// Unmetered: [`Self::call`], the historical error handling. Block
    /// execution below the metering gate calls [`Self::call_with_error_rollback`]
    /// instead, so that `contract_error_rollback_enabled_from_height` applies.
    ///
    /// Metered: one budget, `ctx.gas_limit`, for the base charge, instruction
    /// fuel, instantiation and host work. Any failure — a trap, out of gas, the
    /// stack limit, a refused host length — fails the call and rolls its
    /// staged writes back, including failures that surface as `Err`.
    pub fn call_with_mode(
        &self,
        mode: ExecutionMode,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<ExecutionResult> {
        if mode == ExecutionMode::Unmetered {
            return self.call(contract, method, args, ctx);
        }
        let gas_meter = Arc::new(GasMeter::new(ctx.gas_limit));
        gas_meter.consume(gas_meter.costs().call_base)?;
        let result = match self.call_internal_metered(contract, method, args, ctx, gas_meter, 0) {
            Ok(r) => r,
            Err(e) => {
                self.storage.rollback();
                return Err(e);
            }
        };
        if result.success {
            self.storage.commit()?;
        } else {
            self.storage.rollback();
        }
        Ok(result)
    }

    /// Call a contract method. With `rollback_on_error`, a call that returns
    /// `Err` rolls back its staged storage writes exactly as a failed call
    /// does, so nothing it staged can be read or committed afterwards. Without
    /// it, this is [`Self::call`].
    ///
    /// Block execution passes `true` only at and above
    /// `contract_error_rollback_enabled_from_height`.
    pub fn call_with_error_rollback(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
        rollback_on_error: bool,
    ) -> Result<ExecutionResult> {
        let run = || -> Result<ExecutionResult> {
            let gas_meter = Arc::new(GasMeter::new(ctx.gas_limit));
            gas_meter.consume(gas_meter.costs().call_base)?;
            self.call_internal(contract, method, args, ctx, gas_meter, 0)
        };
        let result = match run() {
            Ok(result) => result,
            Err(e) => {
                if rollback_on_error {
                    self.storage.rollback();
                }
                return Err(e);
            }
        };

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
        // Unchanged on an executor without local limits; the local (RPC)
        // executor caps it.
        let gas_meter = Arc::new(GasMeter::new(
            self.local_limits.map_or(u64::MAX, |l| l.gas_cap),
        ));

        let result = self.call_internal(contract, method, args, ctx, gas_meter, 0);

        // Always rollback view calls -- on `Err` too, which used to return
        // before reaching this and leave the run's staged writes behind. A
        // view never commits and is served by the RPC's own executor, never by
        // block execution, so this changes no committed state.
        self.storage.rollback();
        let result = result?;

        if result.success {
            Ok(result.return_value)
        } else {
            Err(RuntimeError::Execution(
                result.error.unwrap_or_else(|| "View call failed".to_string()),
            ))
        }
    }

    /// Estimate gas for a call by metered dry-run: execute under
    /// `ctx.gas_limit`, then ALWAYS roll back (no commit, no journal). Returns
    /// the metered gas used on success; returns `Err` on execution failure or
    /// out-of-gas — callers must surface that, never a fabricated number.
    pub fn estimate_gas(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<u64> {
        let gas_meter = Arc::new(GasMeter::new(ctx.gas_limit));
        gas_meter.consume(gas_meter.costs().call_base)?;

        let result = self.call_internal(contract, method, args, ctx, gas_meter.clone(), 0);

        // Dry-run: never commit. Roll back only the staged writes from this
        // run. We must NOT touch the commit journal — `call_internal` does not
        // commit, so this run appends nothing, and any pre-existing committed
        // journal entries (e.g. from earlier txs in the block) must be
        // preserved for the reorg diff. `rollback` clears caches, not journal.
        self.storage.rollback();

        match result {
            Ok(r) if r.success => Ok(gas_meter.used()),
            Ok(r) => Err(RuntimeError::Execution(
                r.error.unwrap_or_else(|| "gas estimation failed".to_string()),
            )),
            Err(e) => Err(e),
        }
    }

    /// [`Self::view`] under `mode`.
    ///
    /// Metered: the call runs on metering v1 exactly as
    /// [`Self::call_with_mode`] would run it (base charge, instantiation, fuel,
    /// host work), against `ctx.gas_limit` capped by a local executor's
    /// `gas_cap`, and is always rolled back. The budget is finite, so a
    /// non-terminating view stops out of gas.
    pub fn view_with_mode(
        &self,
        mode: ExecutionMode,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<Vec<u8>> {
        if mode == ExecutionMode::Unmetered {
            return self.view(contract, method, args, ctx);
        }
        let (_, result) = self.metered_dry_run(contract, method, args, ctx);
        let result = result?;
        if result.success {
            Ok(result.return_value)
        } else {
            Err(RuntimeError::Execution(
                result.error.unwrap_or_else(|| "View call failed".to_string()),
            ))
        }
    }

    /// [`Self::estimate_gas`] under `mode`.
    ///
    /// Metered: the gas [`Self::call_with_mode`] would charge the same call
    /// with the same budget, from a dry run that is always rolled back; `Err`
    /// when that call would fail, out of gas included.
    pub fn estimate_gas_with_mode(
        &self,
        mode: ExecutionMode,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> Result<u64> {
        if mode == ExecutionMode::Unmetered {
            return self.estimate_gas(contract, method, args, ctx);
        }
        let (gas_meter, result) = self.metered_dry_run(contract, method, args, ctx);
        match result {
            Ok(r) if r.success => Ok(gas_meter.used()),
            Ok(r) => Err(RuntimeError::Execution(
                r.error.unwrap_or_else(|| "gas estimation failed".to_string()),
            )),
            Err(e) => Err(e),
        }
    }

    /// One metered call that never commits: the same charges as
    /// [`Self::call_with_mode`], then its staged writes rolled back, whatever
    /// the outcome.
    fn metered_dry_run(
        &self,
        contract: ContractAddress,
        method: &str,
        args: Vec<u8>,
        ctx: ExecutionContext,
    ) -> (Arc<GasMeter>, Result<ExecutionResult>) {
        let gas_limit = self
            .local_limits
            .map_or(ctx.gas_limit, |l| ctx.gas_limit.min(l.gas_cap));
        let ctx = ExecutionContext { gas_limit, ..ctx };
        let gas_meter = Arc::new(GasMeter::new(gas_limit));
        let result = gas_meter
            .consume(gas_meter.costs().call_base)
            .and_then(|_| {
                self.call_internal_metered(contract, method, args, ctx, gas_meter.clone(), 0)
            });
        self.storage.rollback();
        (gas_meter, result)
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

        let compiled = match compiled {
            Some(c) => c,
            None => {
                let (module, engine) = self.compile(&code)?;
                let compiled = Arc::new(CompiledContract {
                    module,
                    engine,
                    code_hash,
                });
                self.cache_insert(code_hash, compiled.clone());
                compiled
            }
        };
        let module = &compiled.module;

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
        let wasm_env = WasmEnv::new(
            host_env.clone(),
            self.local_limits.map(|l| l.max_host_bytes),
        );

        // Create instance with imports. Fresh, short-lived store (never held
        // across an await), cloned from the shared engine so `module` (possibly
        // compiled against another clone) stays compatible.
        let mut store = Store::new(compiled.engine.clone());
        let function_env = FunctionEnv::new(&mut store, wasm_env);

        let imports = self.create_imports(&mut store, &function_env);

        let instance = Instance::new(&mut store, module, &imports)?;
        if let Some(limits) = self.local_limits {
            crate::local_limits::set_local_budgets(&mut store, &instance, &limits)?;
        }

        // Get memory and set in environment
        if let Ok(memory) = instance.exports.get_memory("memory") {
            function_env.as_mut(&mut store).memory = Some(memory.clone());
        }
        // Get the guest allocator so host functions can return variable-length
        // buffers (e.g. storage_read) into guest memory.
        if let Ok(alloc) = instance
            .exports
            .get_typed_function::<i32, i32>(&store, "alloc")
        {
            function_env.as_mut(&mut store).alloc = Some(alloc);
        }

        // Find and call the method
        let func: TypedFunction<(i32, i32), i32> = instance
            .exports
            .get_typed_function(&store, method)
            .map_err(|_| RuntimeError::MethodNotFound(method.to_string()))?;

        // Allocate args in WASM memory
        let (args_ptr, args_len) = self.write_to_memory(&instance, &mut store, &args)?;

        // Call the function
        let result = func.call(&mut store, args_ptr, args_len);
        let local_exhausted = if self.local_limits.is_some() {
            crate::local_limits::exhausted_budget(&mut store, &instance)
        } else {
            None
        };

        // Get events and logs
        let events = host_env.read().take_events();
        let logs = host_env.read().take_logs();

        match result {
            Ok(ret_ptr) => {
                // Read return value from memory
                let return_value = if ret_ptr != 0 {
                    let max_len = function_env.as_ref(&store).host_bytes_left;
                    self.read_from_memory(&instance, &store, ret_ptr, max_len)?
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
                    error: Some(match local_exhausted {
                        Some(which) => which.to_string(),
                        None => e.to_string(),
                    }),
                })
            }
        }
    }

    /// [`Self::call_internal`] under metering v1.
    ///
    /// Same shape, with these differences, each deterministic:
    /// * the module comes from (or is compiled into) the metered cache, under
    ///   its own engine; compiling on a cache miss is NOT charged, so gas never
    ///   depends on what this node happens to have cached;
    /// * instantiation (initial pages, data-segment bytes) is charged before
    ///   it happens;
    /// * the instance's gas global is loaded from `gas_meter` before any guest
    ///   code runs (including `alloc`), and written back to it afterwards;
    /// * argument and return-data copies are charged per byte before copying,
    ///   and the guest-supplied return length is bounded and range-checked
    ///   before anything is allocated;
    /// * metering failures (out of gas, stack limit, refused lengths) are
    ///   `success: false`, never a panic.
    fn call_internal_metered(
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
        let schedule = self.schedule;

        let code = self
            .storage
            .get_code(&contract)?
            .ok_or_else(|| RuntimeError::ContractNotFound(contract.to_string()))?;
        let code_hash = Self::code_hash(&code);

        let compiled = match self.metered_cache_get(&code_hash) {
            Some(c) => c,
            None => {
                let c = Arc::new(self.compile_metered(&code)?);
                self.metered_cache_insert(code_hash, c.clone(), code.len() as u64);
                c
            }
        };

        let failed = |gas_meter: &GasMeter, error: String| ExecutionResult {
            return_value: Vec::new(),
            gas_used: gas_meter.used(),
            events: Vec::new(),
            logs: Vec::new(),
            success: false,
            error: Some(error),
        };

        // Instantiation work, charged before it is done.
        if gas_meter
            .consume(compiled.plan.instantiation_cost(&schedule))
            .is_err()
        {
            gas_meter.set_used(gas_meter.limit());
            return Ok(failed(&gas_meter, metering::OUT_OF_GAS_MESSAGE.to_string()));
        }

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
            0,
        )));

        let mut store = Store::new(compiled.engine.clone());
        // No node-local byte budget: metered host copies are charged as gas
        // (the metered host functions never read `host_bytes_left`).
        let function_env = FunctionEnv::new(&mut store, WasmEnv::new(host_env.clone(), None));
        let imports = self.create_imports_metered(&mut store, &function_env);
        let instance = Instance::new(&mut store, &compiled.module, &imports)?;

        let global = |name: &str| -> Result<Global> {
            instance
                .exports
                .get_global(name)
                .cloned()
                .map_err(|e| RuntimeError::Instantiation(format!("metering global {name}: {e}")))
        };
        let gas_global = global(metering::GAS_GLOBAL_EXPORT)?;
        let reason_global = global(metering::TRAP_REASON_EXPORT)?;
        gas_global.set(&mut store, Value::I64(gas_meter.remaining() as i64))?;
        let metered = MeteredEnv {
            gas: gas_global.clone(),
            reason: reason_global.clone(),
            schedule,
        };
        {
            let env = function_env.as_mut(&mut store);
            env.metering = Some(metered.clone());
        }
        if let Ok(memory) = instance.exports.get_memory("memory") {
            function_env.as_mut(&mut store).memory = Some(memory.clone());
        }
        if let Ok(alloc) = instance
            .exports
            .get_typed_function::<i32, i32>(&store, "alloc")
        {
            function_env.as_mut(&mut store).alloc = Some(alloc);
        }

        // Write the budget the guest left back into the meter. Out of gas
        // spends all of it.
        let settle = |store: &mut Store| {
            let reason = reason_global.get(store).i32().unwrap_or(0);
            let remaining = gas_global.get(store).i64().unwrap_or(0) as u64;
            if reason == metering::TRAP_OUT_OF_GAS {
                gas_meter.set_used(gas_meter.limit());
            } else {
                gas_meter.set_used(gas_meter.limit().saturating_sub(remaining));
            }
            reason
        };

        let func: TypedFunction<(i32, i32), i32> = instance
            .exports
            .get_typed_function(&store, method)
            .map_err(|_| RuntimeError::MethodNotFound(method.to_string()))?;

        // Arguments: charged per byte before the copy (the guest's `alloc`
        // then runs metered against the same budget).
        if charge_metered(
            &metered,
            &mut store,
            (args.len() as Gas).saturating_mul(schedule.host_copy_per_byte),
        )
        .is_err()
        {
            settle(&mut store);
            return Ok(failed(&gas_meter, metering::OUT_OF_GAS_MESSAGE.to_string()));
        }
        let (args_ptr, args_len) = match self.write_to_memory(&instance, &mut store, &args) {
            Ok(v) => v,
            Err(e) => {
                let reason = settle(&mut store);
                return Ok(failed(&gas_meter, metered_error(reason, e.to_string())));
            }
        };

        let result = func.call(&mut store, args_ptr, args_len);
        let events = host_env.read().take_events();
        let logs = host_env.read().take_logs();

        match result {
            Ok(ret_ptr) => {
                let return_value = if ret_ptr != 0 {
                    match self.read_return_metered(&instance, &mut store, &metered, ret_ptr) {
                        Ok(v) => v,
                        Err(e) => {
                            let reason = settle(&mut store);
                            return Ok(failed(&gas_meter, metered_error(reason, e)));
                        }
                    }
                } else {
                    Vec::new()
                };
                settle(&mut store);
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
                let reason = settle(&mut store);
                warn!("Metered contract execution failed: {}", e);
                Ok(ExecutionResult {
                    return_value: Vec::new(),
                    gas_used: gas_meter.used(),
                    events,
                    logs,
                    success: false,
                    error: Some(metered_error(reason, e.to_string())),
                })
            }
        }
    }

    /// Read a length-prefixed return value under metering v1: the length is
    /// bounded and range-checked, then charged per byte, before anything is
    /// allocated or copied.
    fn read_return_metered(
        &self,
        instance: &Instance,
        store: &mut Store,
        metered: &MeteredEnv,
        ptr: i32,
    ) -> std::result::Result<Vec<u8>, String> {
        let memory = instance
            .exports
            .get_memory("memory")
            .map_err(|e| format!("return data: {e}"))?;
        if ptr < 0 {
            return Err("return data: negative pointer".to_string());
        }
        let start = ptr as u64;
        let mut len_bytes = [0u8; 4];
        memory
            .view(store)
            .read(start, &mut len_bytes)
            .map_err(|e| format!("return data: {e}"))?;
        let len = u64::from(u32::from_le_bytes(len_bytes));
        if len > u64::from(metered.schedule.max_return_data_len) {
            return Err(format!(
                "return data of {len} bytes exceeds the limit of {}",
                metered.schedule.max_return_data_len
            ));
        }
        let end = start.saturating_add(4).saturating_add(len);
        if end > memory.view(store).data_size() {
            return Err("return data lies outside guest memory".to_string());
        }
        charge_metered(
            metered,
            store,
            len.saturating_mul(metered.schedule.host_copy_per_byte),
        )
        .map_err(|e| e.message())?;
        let mut data = vec![0u8; len as usize];
        memory
            .view(store)
            .read(start + 4, &mut data)
            .map_err(|e| format!("return data: {e}"))?;
        Ok(data)
    }

    /// Imports for a metered instance: the storage functions charge and
    /// bound before copying; the rest are the unmetered ones, none of which
    /// copies guest memory.
    fn create_imports_metered(
        &self,
        store: &mut Store,
        env: &FunctionEnv<WasmEnv>,
    ) -> wasmer::Imports {
        imports! {
            "env" => {
                "caller" => Function::new_typed_with_env(store, env, host_caller),
                "self_address" => Function::new_typed_with_env(store, env, host_self_address),
                "origin" => Function::new_typed_with_env(store, env, host_origin),
                "attached_value" => Function::new_typed_with_env(store, env, host_attached_value),
                "block_height" => Function::new_typed_with_env(store, env, host_block_height),
                "block_timestamp" => Function::new_typed_with_env(store, env, host_block_timestamp),
                "chain_id" => Function::new_typed_with_env(store, env, host_chain_id),

                "storage_read" => Function::new_typed_with_env(store, env, host_storage_read_metered),
                "storage_write" => Function::new_typed_with_env(store, env, host_storage_write_metered),
                "storage_remove" => Function::new_typed_with_env(store, env, host_storage_remove_metered),

                "blake3" => Function::new_typed_with_env(store, env, host_blake3),
                "ed25519_verify" => Function::new_typed_with_env(store, env, host_ed25519_verify),

                "emit" => Function::new_typed_with_env(store, env, host_emit),
                "log" => Function::new_typed_with_env(store, env, host_log),

                "transfer" => Function::new_typed_with_env(store, env, host_transfer),

                "abort" => Function::new_typed_with_env(store, env, host_abort),
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
        max_len: Option<u64>,
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
        let len = u32::from_le_bytes(len_bytes);
        // A local executor also holds the return copy to what is left of its
        // host-copy budget. Whether the range lies inside guest memory is
        // `check_guest_range` below, on every executor.
        if let Some(max) = max_len {
            if u64::from(len) > max {
                return Err(RuntimeError::MemoryAccess(format!(
                    "return data of {} bytes exceeds the local limit",
                    len
                )));
            }
        }

        // The payload starts after the prefix. `ptr + 4` overflowing `i32` can
        // only happen when the prefix itself was readable above 2 GiB; release
        // builds wrapped it to an offset no memory reaches, so the read failed
        // out of bounds, and it fails out of bounds here.
        let data_offset = match ptr.checked_add(4) {
            Some(p) => p as u64,
            None => {
                return Err(RuntimeError::MemoryAccess(
                    wasmer::MemoryAccessError::HeapOutOfBounds.to_string(),
                ))
            }
        };

        // Bounds before allocation: the guest controls `len` (up to 4 GiB), so
        // the host buffer is sized only once the range is known to be inside
        // guest memory. Same check, same error as the read below would give.
        check_guest_range(&view, data_offset, u64::from(len))
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        let mut data = vec![0u8; len as usize];
        view.read(data_offset, &mut data)
            .map_err(|e| RuntimeError::MemoryAccess(e.to_string()))?;

        Ok(data)
    }

    /// Check if a contract exists
    pub fn contract_exists(&self, address: &ContractAddress) -> Result<bool> {
        Ok(self.storage.get_code(address)?.is_some())
    }

    /// Whether a contract exists in COMMITTED state, ignoring any candidate.
    ///
    /// The RPC/diagnostic answer. `contract_exists` above is the one execution
    /// uses, and it deliberately sees the block's staged rows.
    pub fn contract_exists_committed(&self, address: &ContractAddress) -> Result<bool> {
        Ok(self.storage.get_code_committed(address)?.is_some())
    }

    /// Drain the accumulated contract-state journal (committed code/storage/
    /// metadata mutations). Called once per block to build the reorg diff.
    pub fn take_journal(&self) -> Vec<ContractMutation> {
        self.storage.take_journal()
    }

    /// Take the contract-CF writes this block has committed but not staged.
    ///
    /// The runtime no longer reaches the database during execution; it queues
    /// its writes and the caller stages them into the block's candidate. See
    /// `ContractStorage::take_pending`.
    pub fn take_pending_writes(&self) -> Vec<crate::storage::PendingWrite> {
        self.storage.take_pending()
    }

    /// Stage every queued write through `stage`, clearing the queue only if all
    /// of them succeed. The entries are borrowed, not copied. See
    /// `ContractStorage::stage_pending`.
    pub fn stage_pending<E>(
        &self,
        stage: impl FnMut(&crate::storage::PendingWrite) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E> {
        self.storage.stage_pending(stage)
    }

    /// How many writes are queued, without copying them.
    pub fn pending_len(&self) -> usize {
        self.storage.pending_len()
    }

    /// Whether the contract-state journal is empty, WITHOUT draining it.
    /// `take_journal` drains, which makes it useless for asking whether
    /// something was cleared.
    pub fn journal_is_empty(&self) -> bool {
        self.storage.journal_is_empty()
    }

    /// Drop the queue once the caller has staged all of it.
    pub fn clear_pending_writes(&self) {
        self.storage.clear_pending()
    }

    /// Bind this executor to `candidate`, discarding state held for another.
    ///
    /// Clears the storage caches AND this executor's address-keyed metadata
    /// map, which is per-candidate for the same reason: it answers "does this
    /// contract exist", and a deploy in an abandoned block must not be able to
    /// answer yes in the block after it.
    ///
    /// The compiled-code cache is deliberately kept. It is keyed by code HASH,
    /// not by address, so it can say what some bytes compile to but never that
    /// a contract exists — and recompiling every block would be expensive for
    /// no isolation gained.
    pub fn begin_candidate(&self, candidate: u64) {
        if self.storage.begin_candidate(candidate) {
            self.metadata.write().clear();
        }
    }

    /// Drop everything held for the current candidate, and unbind it.
    ///
    /// What a block execution calls when it leaves its scope, by either exit.
    /// `begin_candidate` above is the backstop for callers that have no block
    /// boundary to hook; this is the one that keeps a finished block's caches
    /// from sitting in memory until some later block happens to need them.
    /// Same treatment of the compiled-code cache, for the same reason.
    ///
    /// It is also the one place the metered-module cache is trimmed to its
    /// capacity, least recently used first. Block executions are serialized
    /// and nothing evicts while one runs, so every module a block loads stays
    /// cached until it ends: within a block each code is compiled at most once
    /// (deploys aside, which always compile and are always counted), whatever
    /// the capacity.
    pub fn clear_block(&self) {
        self.storage.end_candidate();
        self.metadata.write().clear();
        self.metered_cache.write().trim();
    }

    /// Get contract metadata from COMMITTED state, ignoring any candidate.
    ///
    /// The RPC/diagnostic answer. `get_metadata` below consults the
    /// address-keyed map first, which is per-candidate: a deploy in an
    /// abandoned block would otherwise keep answering questions that were not
    /// about that block.
    pub fn get_metadata_committed(&self, address: &ContractAddress) -> Option<ContractMetadata> {
        match self.storage.get_metadata_committed(address) {
            Ok(Some(bytes)) => bincode::deserialize::<ContractMetadata>(&bytes).ok(),
            _ => None,
        }
    }

    /// Get contract metadata as EXECUTION sees it — this block included.
    pub fn get_metadata(&self, address: &ContractAddress) -> Option<ContractMetadata> {
        if let Some(m) = self.metadata.read().get(address).cloned() {
            return Some(m);
        }
        // Cache miss (e.g. after a node restart): load from the backend.
        match self.storage.get_metadata(address) {
            Ok(Some(bytes)) => match bincode::deserialize::<ContractMetadata>(&bytes) {
                Ok(m) => {
                    self.metadata.write().insert(*address, m.clone());
                    Some(m)
                }
                Err(_) => None,
            },
            _ => None,
        }
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

/// Whether `[offset, offset + len)` lies inside guest memory, decided exactly
/// as `MemoryView::read` decides it (checked end, then `end > data_size`) and
/// with the same error, but before the caller allocates anything.
///
/// Callers check with this first so that a guest-chosen length never sizes a
/// host buffer for a range the read would refuse anyway. The outcome of an
/// in-bounds read is unchanged, and an out-of-bounds one fails with the error
/// the read itself returned.
fn check_guest_range(
    view: &wasmer::MemoryView<'_>,
    offset: u64,
    len: u64,
) -> std::result::Result<(), wasmer::MemoryAccessError> {
    let end = offset
        .checked_add(len)
        .ok_or(wasmer::MemoryAccessError::Overflow)?;
    if end > view.data_size() {
        return Err(wasmer::MemoryAccessError::HeapOutOfBounds);
    }
    Ok(())
}

/// Read `len` bytes at `ptr` from guest linear memory.
fn read_guest_bytes(
    memory: &Memory,
    store: &impl wasmer::AsStoreRef,
    ptr: i32,
    len: i32,
) -> std::result::Result<Vec<u8>, wasmer::RuntimeError> {
    if ptr < 0 || len < 0 {
        return Err(wasmer::RuntimeError::new("invalid guest memory range"));
    }
    let view = memory.view(store);
    // Bounds before allocation; see `check_guest_range`.
    check_guest_range(&view, ptr as u64, len as u64)
        .map_err(|e| wasmer::RuntimeError::new(format!("guest memory read: {}", e)))?;
    let mut buf = vec![0u8; len as usize];
    view.read(ptr as u64, &mut buf)
        .map_err(|e| wasmer::RuntimeError::new(format!("guest memory read: {}", e)))?;
    Ok(buf)
}

// === Host storage ABI v1 ===
//
// Keys and values are passed as `(ptr, len)` into guest linear memory.
// `storage_read` returns either `0` (absent) or a pointer to a host-allocated,
// length-prefixed buffer `[u32 LE length][bytes]` (allocated via the guest's
// exported `alloc`; the guest decodes the prefix — see `read_from_memory`).
// All three are deterministic and charge gas via `HostEnv`; a gas or memory
// error returns a trap (`Err`), which fails the call and rolls back its
// staged storage writes.

fn host_storage_read(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
) -> std::result::Result<i32, wasmer::RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let alloc = data.alloc.clone();
    let host_env = data.host_env.clone();

    data.charge_host_bytes(key_len.max(0) as u64)?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len)?;
    let value = host_env
        .read()
        .storage_read(&key)
        .map_err(|e| wasmer::RuntimeError::new(format!("storage_read: {}", e)))?;

    match value {
        None => Ok(0),
        Some(v) => {
            let (data, mut store) = env.data_and_store_mut();
            data.charge_host_bytes(4 + v.len() as u64)?;
            let alloc = alloc
                .ok_or_else(|| wasmer::RuntimeError::new("contract missing alloc export"))?;
            let total = 4usize.saturating_add(v.len());
            let ptr = alloc
                .call(&mut store, total as i32)
                .map_err(|e| wasmer::RuntimeError::new(format!("guest alloc: {}", e)))?;
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v);
            // Re-borrow the view AFTER alloc — memory may have grown.
            let view = memory.view(&store);
            view.write(ptr as u64, &buf)
                .map_err(|e| wasmer::RuntimeError::new(format!("guest memory write: {}", e)))?;
            Ok(ptr)
        }
    }
}

fn host_storage_write(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> std::result::Result<(), wasmer::RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let host_env = data.host_env.clone();
    data.charge_host_bytes((key_len.max(0) as u64).saturating_add(value_len.max(0) as u64))?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len)?;
    let value = read_guest_bytes(&memory, &store, value_ptr, value_len)?;
    let result = host_env.read().storage_write(&key, &value);
    result.map_err(|e| wasmer::RuntimeError::new(format!("storage_write: {}", e)))
}

fn host_storage_remove(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
) -> std::result::Result<(), wasmer::RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let host_env = data.host_env.clone();
    data.charge_host_bytes(key_len.max(0) as u64)?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len)?;
    let result = host_env.read().storage_remove(&key);
    result.map_err(|e| wasmer::RuntimeError::new(format!("storage_remove: {}", e)))
}

/// The error text of a metered failure: the metering reason if one was
/// recorded, otherwise what the engine reported.
fn metered_error(reason: i32, other: String) -> String {
    match reason {
        metering::TRAP_OUT_OF_GAS => metering::OUT_OF_GAS_MESSAGE.to_string(),
        metering::TRAP_STACK_LIMIT => metering::STACK_LIMIT_MESSAGE.to_string(),
        _ => other,
    }
}

/// A guest length, refused if negative or above `cap`, BEFORE anything is
/// read or charged against it.
fn bounded_len(len: i32, cap: u32, what: &str) -> std::result::Result<u64, wasmer::RuntimeError> {
    if len < 0 {
        return Err(wasmer::RuntimeError::new(format!("{what}: negative length")));
    }
    if len as u32 > cap {
        return Err(wasmer::RuntimeError::new(format!(
            "{what}: {len} bytes exceeds the limit of {cap}"
        )));
    }
    Ok(len as u64)
}

fn metering_of(data: &WasmEnv) -> std::result::Result<MeteredEnv, wasmer::RuntimeError> {
    data.metering
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("metered import without metering state"))
}

/// `storage_read` under metering v1: key bounded and charged (base + per key
/// byte) before it is copied; the value bounded and charged per byte before
/// it is copied into guest memory.
fn host_storage_read_metered(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
) -> std::result::Result<i32, wasmer::RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let metered = metering_of(data)?;
    let s = metered.schedule;
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let alloc = data.alloc.clone();
    let host_env = data.host_env.clone();

    let key_len = bounded_len(key_len, s.max_key_len, "storage_read key")?;
    charge_metered(
        &metered,
        &mut store,
        s.storage_read_base
            .saturating_add(key_len.saturating_mul(s.storage_read_per_key_byte)),
    )?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len as i32)?;
    let value = {
        let h = host_env.read();
        h.storage.read(&h.self_address, &key)
    }
    .map_err(|e| wasmer::RuntimeError::new(format!("storage_read: {}", e)))?;

    match value {
        None => Ok(0),
        Some(v) => {
            if v.len() as u64 > u64::from(s.max_value_len) {
                return Err(wasmer::RuntimeError::new(format!(
                    "storage_read: stored value of {} bytes exceeds the limit of {}",
                    v.len(),
                    s.max_value_len
                )));
            }
            charge_metered(
                &metered,
                &mut store,
                (v.len() as Gas).saturating_mul(s.storage_read_per_value_byte),
            )?;
            let alloc = alloc
                .ok_or_else(|| wasmer::RuntimeError::new("contract missing alloc export"))?;
            let total = 4usize + v.len();
            let ptr = alloc
                .call(&mut store, total as i32)
                .map_err(|e| wasmer::RuntimeError::new(format!("guest alloc: {}", e)))?;
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
            buf.extend_from_slice(&v);
            let view = memory.view(&store);
            view.write(ptr as u64, &buf)
                .map_err(|e| wasmer::RuntimeError::new(format!("guest memory write: {}", e)))?;
            Ok(ptr)
        }
    }
}

/// `storage_write` under metering v1: key and value bounded and the write
/// charged (unchanged prices) before either is copied.
fn host_storage_write_metered(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> std::result::Result<(), wasmer::RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let metered = metering_of(data)?;
    let s = metered.schedule;
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let host_env = data.host_env.clone();
    let key_len = bounded_len(key_len, s.max_key_len, "storage_write key")?;
    let value_len = bounded_len(value_len, s.max_value_len, "storage_write value")?;
    charge_metered(
        &metered,
        &mut store,
        s.storage_write_base.saturating_add(
            key_len
                .saturating_add(value_len)
                .saturating_mul(s.storage_write_per_byte),
        ),
    )?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len as i32)?;
    let value = read_guest_bytes(&memory, &store, value_ptr, value_len as i32)?;
    let h = host_env.read();
    h.storage
        .write(&h.self_address, &key, &value)
        .map_err(|e| wasmer::RuntimeError::new(format!("storage_write: {}", e)))
}

/// `storage_remove` under metering v1: key bounded and the removal plus the
/// key copy charged before the copy.
fn host_storage_remove_metered(
    mut env: FunctionEnvMut<WasmEnv>,
    key_ptr: i32,
    key_len: i32,
) -> std::result::Result<(), wasmer::RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let metered = metering_of(data)?;
    let s = metered.schedule;
    let memory = data
        .memory
        .clone()
        .ok_or_else(|| wasmer::RuntimeError::new("contract has no exported memory"))?;
    let host_env = data.host_env.clone();
    let key_len = bounded_len(key_len, s.max_key_len, "storage_remove key")?;
    charge_metered(
        &metered,
        &mut store,
        s.storage_remove
            .saturating_add(key_len.saturating_mul(s.host_copy_per_byte)),
    )?;
    let key = read_guest_bytes(&memory, &store, key_ptr, key_len as i32)?;
    let h = host_env.read();
    h.storage
        .delete(&h.self_address, &key)
        .map_err(|e| wasmer::RuntimeError::new(format!("storage_remove: {}", e)))
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

/// Abort the call with a trap, never a host panic: the call fails and its
/// staged writes roll back exactly as for any other trap. The guest message is
/// not read, so the failure is fixed text and costs no unmetered memory access.
fn host_abort(
    _env: FunctionEnvMut<WasmEnv>,
    _msg_ptr: i32,
    _msg_len: i32,
) -> std::result::Result<(), wasmer::RuntimeError> {
    Err(wasmer::RuntimeError::new("contract aborted"))
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
