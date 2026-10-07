//! Node-local execution limits for executors that never produce consensus
//! state: the RPC/view instance.
//!
//! Nothing here is consensus. An executor built with [`LocalExecutionLimits`]
//! compiles modules under its own engine (instruction metering, a memory cap),
//! so its compiled-module cache never mixes with the block executor's. The
//! block executor is built with [`crate::ContractExecutor::new`] and is
//! unaffected.

use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use wasmer::sys::BaseTunables;
use wasmer::vm::{
    MemoryStyle, TableStyle, VMMemory, VMMemoryDefinition, VMTable, VMTableDefinition,
};
use wasmer::wasmparser::{BlockType, Operator};
use wasmer::{
    CompilerConfig, ExportIndex, FunctionMiddleware, GlobalInit, GlobalType, LocalFunctionIndex,
    MemoryError, MemoryType, MiddlewareError, MiddlewareReaderState, ModuleMiddleware, Mutability,
    Pages, TableType, Target, Tunables, Type,
};
use wasmer_compiler_singlepass::Singlepass;
use wasmer_middlewares::Metering;
use wasmer_types::{GlobalIndex, ModuleInfo};

use crate::{Gas, MAX_MEMORY_PAGES};

/// Budgets for one local (RPC/view) execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalExecutionLimits {
    /// WASM operators one execution may run (1 point per operator).
    pub fuel: u64,
    /// Linear-memory ceiling in 64 KiB pages. A module's declared maximum is
    /// lowered to this; a module whose minimum exceeds it does not instantiate.
    pub max_memory_pages: u32,
    /// Bytes host functions may copy between guest memory and the host in one
    /// execution (keys, values, return data).
    pub max_host_bytes: u64,
    /// Bytes (or table elements) bulk operations (`memory.fill`, `memory.copy`,
    /// `memory.init`, `table.*`) may touch in one execution. They count as one
    /// operator against `fuel` whatever their length, so they need their own
    /// bound.
    pub max_bulk_bytes: u64,
    /// Gas ceiling for `view`, which otherwise meters against `u64::MAX`.
    pub gas_cap: Gas,
    /// Compiled modules kept per executor. Reaching it empties the cache; the
    /// next execution of a contract compiles it again.
    pub max_cached_modules: usize,
}

impl LocalExecutionLimits {
    /// Defaults sized for a public RPC endpoint: roughly a quarter of a second
    /// of operators, the runtime's own 16 MiB memory figure, 16 MiB of host
    /// copying, and the chain's default per-transaction gas ceiling.
    pub const DEFAULT: Self = Self {
        fuel: 200_000_000,
        max_memory_pages: MAX_MEMORY_PAGES,
        max_host_bytes: 16 * 1024 * 1024,
        max_bulk_bytes: 256 * 1024 * 1024,
        gas_cap: 10_000_000,
        max_cached_modules: 64,
    };
}

impl Default for LocalExecutionLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Every operator costs one point. The budget is a work bound, not a price.
fn one_point_per_operator(_: &wasmer::wasmparser::Operator) -> u64 {
    1
}

/// A Singlepass engine with instruction metering, bulk-operation metering and
/// a memory ceiling, for compiling ONE module.
///
/// One per module, not one per executor: a metering middleware records the
/// global indexes it added to the module it transformed, and wasmer's
/// `Metering` panics when asked to transform a second module. The executor
/// keeps each module's engine beside it and builds that module's stores from
/// it.
pub(crate) fn metered_engine(limits: &LocalExecutionLimits) -> wasmer::Engine {
    use wasmer::sys::NativeEngineExt;

    let mut compiler = Singlepass::default();
    // Bulk accounting first, so the operators it injects are metered too. The
    // initial budgets are replaced per execution (`set_local_budgets`).
    compiler.push_middleware(Arc::new(BulkMetering::new(limits.max_bulk_bytes)));
    compiler.push_middleware(Arc::new(Metering::new(limits.fuel, one_point_per_operator)));
    let mut engine: wasmer::Engine = wasmer::sys::EngineBuilder::new(compiler).engine().into();
    engine.set_tunables(LimitingTunables {
        limit: Pages(limits.max_memory_pages),
        base: BaseTunables::for_target(&Target::default()),
    });
    engine
}

/// Lowers every memory's maximum to `limit`, and refuses a memory whose
/// minimum is above it. Growth past the ceiling fails inside the guest
/// (`memory.grow` returns -1); it never reaches the host allocator.
struct LimitingTunables<T: Tunables> {
    limit: Pages,
    base: T,
}

impl<T: Tunables> LimitingTunables<T> {
    fn adjust(&self, requested: &MemoryType) -> MemoryType {
        let mut adjusted = *requested;
        adjusted.maximum = Some(match requested.maximum {
            Some(m) if m < self.limit => m,
            _ => self.limit,
        });
        adjusted
    }

    fn validate(&self, ty: &MemoryType) -> Result<(), MemoryError> {
        if ty.minimum > self.limit {
            return Err(MemoryError::Generic(format!(
                "memory minimum {} pages exceeds the local limit of {} pages",
                ty.minimum.0, self.limit.0
            )));
        }
        Ok(())
    }
}

impl<T: Tunables> Tunables for LimitingTunables<T> {
    fn memory_style(&self, memory: &MemoryType) -> MemoryStyle {
        self.base.memory_style(&self.adjust(memory))
    }

    fn table_style(&self, table: &TableType) -> TableStyle {
        self.base.table_style(table)
    }

    fn create_host_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
    ) -> Result<VMMemory, MemoryError> {
        let adjusted = self.adjust(ty);
        self.validate(&adjusted)?;
        self.base.create_host_memory(&adjusted, style)
    }

    unsafe fn create_vm_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
        vm_definition_location: NonNull<VMMemoryDefinition>,
    ) -> Result<VMMemory, MemoryError> {
        let adjusted = self.adjust(ty);
        self.validate(&adjusted)?;
        self.base
            .create_vm_memory(&adjusted, style, vm_definition_location)
    }

    fn create_host_table(&self, ty: &TableType, style: &TableStyle) -> Result<VMTable, String> {
        self.base.create_host_table(ty, style)
    }

    unsafe fn create_vm_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
        vm_definition_location: NonNull<VMTableDefinition>,
    ) -> Result<VMTable, String> {
        self.base.create_vm_table(ty, style, vm_definition_location)
    }
}

/// Export names of the bulk-operation budget globals.
pub(crate) const BULK_REMAINING: &str = "sumc_local_bulk_remaining";
pub(crate) const BULK_EXHAUSTED: &str = "sumc_local_bulk_exhausted";

/// Charges `memory.fill`/`memory.copy`/`memory.init` and `table.fill`/
/// `table.copy`/`table.init` by their length operand, BEFORE the operation
/// runs, against a per-execution budget held in a module global. A length
/// above the remaining budget traps without touching memory.
///
/// Injected before each such operator (`n` is on top of the stack):
///
/// ```text
/// global.set $n  global.get $n                      ;; keep n for the op
/// global.get $left  global.get $n  i64.extend_i32_u  i64.lt_u
/// if  i32.const 1  global.set $exhausted  unreachable  end
/// global.get $left  global.get $n  i64.extend_i32_u  i64.sub  global.set $left
/// ```
struct BulkMetering {
    initial: u64,
    globals: Mutex<Option<BulkGlobals>>,
}

#[derive(Clone, Copy)]
struct BulkGlobals {
    remaining: GlobalIndex,
    exhausted: GlobalIndex,
    scratch: GlobalIndex,
}

impl BulkMetering {
    fn new(initial: u64) -> Self {
        Self {
            initial,
            globals: Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for BulkMetering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkMetering")
            .field("initial", &self.initial)
            .finish()
    }
}

impl ModuleMiddleware for BulkMetering {
    fn generate_function_middleware(&self, _: LocalFunctionIndex) -> Box<dyn FunctionMiddleware> {
        let globals = self
            .globals
            .lock()
            .expect("bulk metering lock")
            .expect("transform_module_info runs before function middlewares");
        Box::new(FunctionBulkMetering { globals })
    }

    fn transform_module_info(&self, info: &mut ModuleInfo) -> Result<(), MiddlewareError> {
        let mut slot = self.globals.lock().expect("bulk metering lock");
        if slot.is_some() {
            return Err(MiddlewareError::new(
                "BulkMetering",
                "one BulkMetering instance per module",
            ));
        }
        let remaining = info
            .globals
            .push(GlobalType::new(Type::I64, Mutability::Var));
        info.global_initializers
            .push(GlobalInit::I64Const(self.initial as i64));
        info.exports
            .insert(BULK_REMAINING.to_string(), ExportIndex::Global(remaining));
        let exhausted = info
            .globals
            .push(GlobalType::new(Type::I32, Mutability::Var));
        info.global_initializers.push(GlobalInit::I32Const(0));
        info.exports
            .insert(BULK_EXHAUSTED.to_string(), ExportIndex::Global(exhausted));
        let scratch = info
            .globals
            .push(GlobalType::new(Type::I32, Mutability::Var));
        info.global_initializers.push(GlobalInit::I32Const(0));
        *slot = Some(BulkGlobals {
            remaining,
            exhausted,
            scratch,
        });
        Ok(())
    }
}

#[derive(Debug)]
struct FunctionBulkMetering {
    globals: BulkGlobals,
}

impl std::fmt::Debug for BulkGlobals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkGlobals").finish()
    }
}

fn is_bulk(op: &Operator) -> bool {
    matches!(
        op,
        Operator::MemoryFill { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryInit { .. }
            | Operator::TableFill { .. }
            | Operator::TableCopy { .. }
            | Operator::TableInit { .. }
    )
}

impl FunctionMiddleware for FunctionBulkMetering {
    fn feed<'a>(
        &mut self,
        operator: Operator<'a>,
        state: &mut MiddlewareReaderState<'a>,
    ) -> Result<(), MiddlewareError> {
        if is_bulk(&operator) {
            let g = self.globals;
            let (left, exhausted, n) = (
                g.remaining.as_u32(),
                g.exhausted.as_u32(),
                g.scratch.as_u32(),
            );
            state.extend(&[
                Operator::GlobalSet { global_index: n },
                Operator::GlobalGet { global_index: n },
                Operator::GlobalGet { global_index: left },
                Operator::GlobalGet { global_index: n },
                Operator::I64ExtendI32U,
                Operator::I64LtU,
                Operator::If {
                    blockty: BlockType::Empty,
                },
                Operator::I32Const { value: 1 },
                Operator::GlobalSet {
                    global_index: exhausted,
                },
                Operator::Unreachable,
                Operator::End,
                Operator::GlobalGet { global_index: left },
                Operator::GlobalGet { global_index: n },
                Operator::I64ExtendI32U,
                Operator::I64Sub,
                Operator::GlobalSet { global_index: left },
            ]);
        }
        state.push_operator(operator);
        Ok(())
    }
}

/// Reset an instance's local budgets for one execution.
pub(crate) fn set_local_budgets(
    store: &mut impl wasmer::AsStoreMut,
    instance: &wasmer::Instance,
    limits: &LocalExecutionLimits,
) -> Result<(), wasmer::RuntimeError> {
    wasmer_middlewares::metering::set_remaining_points(store, instance, limits.fuel);
    let g = instance
        .exports
        .get_global(BULK_REMAINING)
        .map_err(|e| wasmer::RuntimeError::new(e.to_string()))?;
    g.set(store, wasmer::Value::I64(limits.max_bulk_bytes as i64))
}

/// Which local budget, if any, an execution ran out of.
pub(crate) fn exhausted_budget(
    store: &mut impl wasmer::AsStoreMut,
    instance: &wasmer::Instance,
) -> Option<&'static str> {
    use wasmer_middlewares::metering::{get_remaining_points, MeteringPoints};
    if matches!(
        get_remaining_points(store, instance),
        MeteringPoints::Exhausted
    ) {
        return Some(crate::executor::LOCAL_FUEL_EXHAUSTED);
    }
    let bulk = instance
        .exports
        .get_global(BULK_EXHAUSTED)
        .ok()
        .and_then(|g| g.get(store).i32());
    if bulk == Some(1) {
        return Some(crate::executor::LOCAL_BULK_EXHAUSTED);
    }
    None
}
