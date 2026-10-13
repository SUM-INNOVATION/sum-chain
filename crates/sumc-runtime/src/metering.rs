//! Consensus contract metering, version 1 — PROVISIONAL (#279).
//!
//! Dormant. Nothing here runs unless the chain's
//! `contract_metering_enabled_from_height` gate is open at the executing
//! block's height, and that gate defaults to `None`. Below it the block
//! executor uses [`crate::ContractExecutor`]'s unmetered engine exactly as
//! before (identity [`crate::ENGINE_IDENTITY`]).
//!
//! # PROVISIONAL
//!
//! Every number in [`CostScheduleV1Provisional::PROVISIONAL`] is a placeholder
//! taken from the #279 design note (§7.3, "sumc-cost-v1"). None is ratified,
//! none is final, and none may be activated on a production chain until the
//! schedule is benchmarked on validator-class hardware and frozen under a new,
//! non-provisional identity. The mechanism is what this module provides.
//!
//! # What the metered engine does
//!
//! A module is compiled under its OWN engine (one middleware instance per
//! module: a middleware records the globals it added to the module it
//! transformed) after a deterministic pre-scan of its bytes:
//!
//! * **Fuel, charged before each basic block.** The pre-scan validates the
//!   module against a fixed feature set and splits every function body into
//!   basic blocks (a block ends at `block`, `loop`, `if`, `else`, `end`, `br`,
//!   `br_if`, `br_table`, `return`, `unreachable`). The middleware injects, at
//!   the START of each block, a check-and-subtract of that block's static cost
//!   against a gas global. A block whose cost exceeds the remaining gas traps
//!   before any of its operators run. A backward branch targets the code just
//!   after `loop`, which is where the loop body's charge sits, so every
//!   iteration pays.
//! * **Dynamic charges, before the operation.** `memory.fill/copy/init`,
//!   `table.fill/copy/init/grow` are charged per 16 bytes/elements of their
//!   length operand, `memory.grow` per page requested — the charge is injected
//!   ahead of the operator and traps before it touches memory.
//! * **Memory and table ceilings** through tunables (256 pages; a provisional
//!   table bound), and refused at pre-scan when a declared minimum is above it.
//! * **Deterministic stack height.** Each function has a static frame cost
//!   (overhead + params + locals + maximum operand-stack height, from the
//!   validator). Every call site adds the callee's cost to a stack global
//!   before the call, traps above [`CostScheduleV1Provisional::max_stack_units`],
//!   and subtracts it after the call returns. `call_indirect` charges the
//!   largest frame in the module; an imported (host) function a fixed cost.
//!   The limit therefore depends only on the module, never on how large the
//!   compiled native frames are on this machine.
//! * **One budget.** The gas global is loaded from the transaction's
//!   [`crate::GasMeter`] before guest code runs and written back after; host
//!   functions charge the SAME global, so instruction fuel and host gas are
//!   one budget bounded by the transaction's `gas_limit`.
//!
//! Start functions are refused at pre-scan (they would run during
//! instantiation, before the host has loaded the budget).

use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use wasmer::sys::{
    BaseTunables, CompilerConfig, FunctionMiddleware, MiddlewareReaderState, ModuleMiddleware,
    Tunables,
};
use wasmer::vm::{
    MemoryStyle, TableStyle, VMMemory, VMMemoryDefinition, VMTable, VMTableDefinition,
};
use wasmer::wasmparser::{
    BlockType, FuncValidatorAllocations, Operator, Parser, Payload, TypeRef, ValidPayload,
    Validator, WasmFeatures,
};
use wasmer::{
    ExportIndex, GlobalInit, GlobalType, LocalFunctionIndex, MemoryError, MemoryType,
    MiddlewareError, Module, Mutability, Pages, Store, TableType, Target, Type,
};
use wasmer_compiler_singlepass::Singlepass;
use wasmer_types::{GlobalIndex, ModuleInfo};

use crate::{Gas, Result, RuntimeError, MAX_MEMORY_PAGES};

/// Identity of the metered engine: the unmetered engine's identity plus the
/// cost-schedule version. A different schedule, feature set or injection rule
/// is a different identity. Distinct from [`crate::ENGINE_IDENTITY`], which
/// keeps naming the unmetered engine that runs below the gate.
///
/// PROVISIONAL: the suffix says so, and it must change when the schedule is
/// frozen.
pub const METERED_ENGINE_IDENTITY: &str = "wasmer-singlepass-5+sumc-cost-v1-provisional";

/// The cost schedule metered execution runs under, and the value the consensus
/// configuration commits as field 0x2717 (its [`CostScheduleV1Provisional::encode`])
/// once ratified. PROVISIONAL today: [`CostScheduleV1Provisional::PROVISIONAL`].
pub const METERED_COST_SCHEDULE: CostScheduleV1Provisional = CostScheduleV1Provisional::PROVISIONAL;

/// Whether [`METERED_ENGINE_IDENTITY`] and [`METERED_COST_SCHEDULE`] are
/// ratified. While `false`, no consensus configuration can contain them:
/// building one with `contract_metering_enabled_from_height` set is refused
/// before anything is recorded, so a node can neither start nor record a
/// baseline with them. Ratification is the change that sets the final identity,
/// the final schedule and this flag together.
pub const METERING_VALUES_RATIFIED: bool = false;

/// Export names of the globals the middleware adds. A module that already
/// exports one of these names is refused at compile.
pub const GAS_GLOBAL_EXPORT: &str = "__sumc_v1_gas_remaining";
/// Why the last trap was raised by metering (0 none, 1 out of gas, 2 stack).
pub const TRAP_REASON_EXPORT: &str = "__sumc_v1_trap_reason";
/// Current deterministic stack height in frame-cost units.
pub const STACK_GLOBAL_EXPORT: &str = "__sumc_v1_stack_height";

/// [`TRAP_REASON_EXPORT`] value: a fuel or host charge exceeded the budget.
pub const TRAP_OUT_OF_GAS: i32 = 1;
/// [`TRAP_REASON_EXPORT`] value: the deterministic stack limit was exceeded.
pub const TRAP_STACK_LIMIT: i32 = 2;

/// Error text of a metered out-of-gas failure.
pub const OUT_OF_GAS_MESSAGE: &str = "out of gas (metered)";
/// Error text of a deterministic stack-limit failure.
pub const STACK_LIMIT_MESSAGE: &str = "stack height limit exceeded (metered)";

/// The cost schedule of metering version 1. **PROVISIONAL — not ratified.**
///
/// One struct so the whole schedule is one value: reviewed together, encoded
/// together ([`Self::encode`]) and committed together. All values are in gas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostScheduleV1Provisional {
    // ── operators (static, charged per basic block before it runs) ──
    /// const, local/global access, ALU, compare, branch, load/store, and any
    /// operator not named below.
    pub op_default: Gas,
    /// `call`, `call_indirect`, `br_table`.
    pub op_call: Gas,
    /// i32/i64 div/rem, f32/f64 div/sqrt/min/max/nearest.
    pub op_heavy: Gas,
    /// `memory.size`.
    pub op_memory_size: Gas,
    /// `memory.grow`, static part.
    pub op_memory_grow: Gas,
    /// `memory.grow`, per page requested, charged before growth.
    pub memory_grow_per_page: Gas,
    /// bulk memory/table operators, static part.
    pub op_bulk: Gas,
    /// bulk operators: gas per `bulk_unit` bytes/elements of length, rounded
    /// up, charged before the operation.
    pub bulk_per_unit: Gas,
    /// bulk operators: bytes/elements per charged unit.
    pub bulk_unit: u64,
    // ── host functions (charged before copying) ──
    /// `storage_read` base.
    pub storage_read_base: Gas,
    /// `storage_read` per key byte.
    pub storage_read_per_key_byte: Gas,
    /// `storage_read` per value byte, charged before the value is copied into
    /// guest memory.
    pub storage_read_per_value_byte: Gas,
    /// `storage_write` base (unchanged from the unmetered schedule).
    pub storage_write_base: Gas,
    /// `storage_write` per key+value byte (unchanged).
    pub storage_write_per_byte: Gas,
    /// `storage_remove` (unchanged).
    pub storage_remove: Gas,
    /// Host copies not priced above (call arguments, `storage_remove` key,
    /// return data), per byte.
    pub host_copy_per_byte: Gas,
    // ── deploy and instantiation ──
    /// Deploy base, charged before compiling.
    pub deploy_base: Gas,
    /// Deploy per code byte, charged before compiling.
    pub deploy_per_code_byte: Gas,
    /// Per data-segment byte (rounded up to `bulk_unit`) at each
    /// instantiation; initial memory pages are charged at
    /// `memory_grow_per_page`.
    pub instantiate_per_data_unit: Gas,
    // ── deterministic limits ──
    /// Linear memory ceiling, pages.
    pub max_memory_pages: u32,
    /// Table ceiling, elements (per table).
    pub max_table_elements: u32,
    /// Tables a module may declare or import.
    pub max_tables: u32,
    /// Ceiling on the sum, over all tables, of each table's effective maximum
    /// (its declared maximum, or `max_table_elements` when it declares none,
    /// whichever is lower). Checked at deploy, so no sequence of `table.grow`
    /// can hold more than this many elements across the module's tables.
    pub max_total_table_elements: u32,
    /// Deterministic stack limit, frame-cost units.
    pub max_stack_units: u32,
    /// Fixed units every frame costs in addition to its locals and operands.
    pub frame_overhead_units: u32,
    /// Units charged for a call to an imported (host) function.
    pub host_frame_units: u32,
    /// Longest storage key a host function accepts.
    pub max_key_len: u32,
    /// Longest storage value a host function accepts or returns.
    pub max_value_len: u32,
    /// Longest return value a call may hand back.
    pub max_return_data_len: u32,
    /// Ceiling on the code one block LOADS: the summed code bytes of every
    /// contract the block deploys plus every distinct contract it calls, the
    /// latter measured in the block's parent state. Compilation on a metered
    /// cache miss is outside gas accounting (gas never depends on cache state),
    /// so this is what bounds a block's compilation work whatever a node's
    /// cache holds. Decided before anything executes: an importer refuses an
    /// over-cap block and a proposer leaves out what would not fit. Not a gas
    /// charge.
    pub max_block_loaded_code_bytes: u32,
}

impl CostScheduleV1Provisional {
    /// The provisional values, from design note §7.3 ("sumc-cost-v1") where
    /// it gives one, and labelled guesses where it does not
    /// (`instantiate_per_data_unit`, `max_table_elements`, the stack units).
    ///
    /// **PROVISIONAL. Not ratified, not frozen, not for activation.**
    pub const PROVISIONAL: Self = Self {
        op_default: 1,
        op_call: 2,
        op_heavy: 4,
        op_memory_size: 2,
        op_memory_grow: 8,
        memory_grow_per_page: 4_096,
        op_bulk: 2,
        bulk_per_unit: 1,
        bulk_unit: 16,
        storage_read_base: 200,
        storage_read_per_key_byte: 1,
        storage_read_per_value_byte: 1,
        storage_write_base: 5_000,
        storage_write_per_byte: 50,
        storage_remove: 500,
        host_copy_per_byte: 1,
        deploy_base: 10_000,
        deploy_per_code_byte: 100,
        instantiate_per_data_unit: 1,
        max_memory_pages: MAX_MEMORY_PAGES,
        max_table_elements: 8_192,
        max_tables: 4,
        max_total_table_elements: 16_384,
        max_stack_units: 16_384,
        frame_overhead_units: 8,
        host_frame_units: 512,
        max_key_len: 256,
        max_value_len: 64 * 1024,
        max_return_data_len: 64 * 1024,
        max_block_loaded_code_bytes: 256 * 1024,
    };

    /// Gas charged for a deploy of `code_len` bytes, before compiling.
    pub fn deploy_cost(&self, code_len: usize) -> Gas {
        self.deploy_base
            .saturating_add((code_len as Gas).saturating_mul(self.deploy_per_code_byte))
    }

    /// Gas for `n` bytes/elements of bulk work (rounded up to whole units).
    pub fn bulk_cost(&self, n: u64) -> Gas {
        n.div_ceil(self.bulk_unit)
            .saturating_mul(self.bulk_per_unit)
    }

    /// Canonical encoding, what the consensus configuration commits to as
    /// field 0x2717: `tag_len:u8 ‖ tag ‖ body`. The tag names this layout and
    /// version; the body is every field, declared order, big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let tag: &[u8] = b"sumc-cost-v1-provisional";
        let mut out = Vec::with_capacity(1 + tag.len() + 19 * 8 + 11 * 4);
        out.push(tag.len() as u8);
        out.extend_from_slice(tag);
        for v in [
            self.op_default,
            self.op_call,
            self.op_heavy,
            self.op_memory_size,
            self.op_memory_grow,
            self.memory_grow_per_page,
            self.op_bulk,
            self.bulk_per_unit,
            self.bulk_unit,
            self.storage_read_base,
            self.storage_read_per_key_byte,
            self.storage_read_per_value_byte,
            self.storage_write_base,
            self.storage_write_per_byte,
            self.storage_remove,
            self.host_copy_per_byte,
            self.deploy_base,
            self.deploy_per_code_byte,
            self.instantiate_per_data_unit,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        for v in [
            self.max_memory_pages,
            self.max_table_elements,
            self.max_tables,
            self.max_total_table_elements,
            self.max_stack_units,
            self.frame_overhead_units,
            self.host_frame_units,
            self.max_key_len,
            self.max_value_len,
            self.max_return_data_len,
            self.max_block_loaded_code_bytes,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// Static cost of one operator.
    pub fn op_cost(&self, op: &Operator<'_>) -> Gas {
        use Operator::*;
        match op {
            Call { .. } | CallIndirect { .. } | BrTable { .. } => self.op_call,
            I32DivS | I32DivU | I32RemS | I32RemU | I64DivS | I64DivU | I64RemS | I64RemU
            | F32Div | F64Div | F32Sqrt | F64Sqrt | F32Min | F32Max | F64Min | F64Max
            | F32Nearest | F64Nearest => self.op_heavy,
            MemorySize { .. } => self.op_memory_size,
            MemoryGrow { .. } => self.op_memory_grow,
            MemoryFill { .. }
            | MemoryCopy { .. }
            | MemoryInit { .. }
            | TableFill { .. }
            | TableCopy { .. }
            | TableInit { .. }
            | TableGrow { .. } => self.op_bulk,
            _ => self.op_default,
        }
    }
}

/// The wasm feature set metering v1 admits. MVP plus mutable globals,
/// saturating float-to-int, sign extension, multi-value, bulk memory and
/// reference types (current Rust toolchains emit the latter for
/// `call_indirect`). Refused: SIMD, threads, tail calls, multi-memory,
/// exceptions, memory64, extended-const, GC, function references, component
/// model. PROVISIONAL like the schedule.
pub fn admitted_features() -> WasmFeatures {
    WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SATURATING_FLOAT_TO_INT
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::BULK_MEMORY
        | WasmFeatures::REFERENCE_TYPES
        | WasmFeatures::FLOATS
        | WasmFeatures::GC_TYPES
}

/// Whether `op` ends a basic block.
fn ends_block(op: &Operator<'_>) -> bool {
    use Operator::*;
    matches!(
        op,
        Block { .. }
            | Loop { .. }
            | If { .. }
            | Else
            | End
            | Br { .. }
            | BrIf { .. }
            | BrTable { .. }
            | Return
            | Unreachable
    )
}

/// What the pre-scan learned about one module.
#[derive(Debug)]
pub struct ModulePlan {
    /// Per local function, the static cost of each basic block in order.
    blocks: Vec<Vec<Gas>>,
    /// Frame cost per function index (imports first, then local functions).
    frames: Vec<u32>,
    /// Largest frame in the module: what `call_indirect` charges.
    max_frame: u32,
    /// Initial linear-memory pages, summed over the module's memories.
    pub initial_pages: u64,
    /// Bytes in data segments.
    pub data_bytes: u64,
    /// Initial elements, summed over the module's tables.
    pub table_elements: u64,
    /// Items in all element segments (active, passive and declared).
    pub elem_items: u64,
}

impl ModulePlan {
    /// Frame cost of function `index` (imports first), in stack units.
    pub fn frame_units(&self, index: u32) -> Option<u32> {
        self.frames.get(index as usize).copied()
    }

    /// Static cost of each basic block of local function `local`, in order.
    pub fn block_costs(&self, local: u32) -> Option<&[Gas]> {
        self.blocks.get(local as usize).map(Vec::as_slice)
    }

    /// Gas charged at each instantiation, before it happens.
    pub fn instantiation_cost(&self, s: &CostScheduleV1Provisional) -> Gas {
        self.initial_pages
            .saturating_mul(s.memory_grow_per_page)
            .saturating_add(
                self.data_bytes
                    .div_ceil(s.bulk_unit)
                    .saturating_mul(s.instantiate_per_data_unit),
            )
            .saturating_add(
                self.table_elements
                    .saturating_add(self.elem_items)
                    .div_ceil(s.bulk_unit)
                    .saturating_mul(s.instantiate_per_data_unit),
            )
    }
}

fn invalid(msg: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::InvalidCode(format!("metering v1: {msg}"))
}

/// Validate `code` against [`admitted_features`] and the schedule's limits, and
/// compute the per-block costs and frame costs the middleware injects.
pub fn prescan(code: &[u8], s: &CostScheduleV1Provisional) -> Result<ModulePlan> {
    let mut validator = Validator::new_with_features(admitted_features());
    let mut allocs = FuncValidatorAllocations::default();
    let mut import_frames: Vec<u32> = Vec::new();
    let mut local_frames: Vec<u32> = Vec::new();
    let mut blocks: Vec<Vec<Gas>> = Vec::new();
    let mut initial_pages: u64 = 0;
    let mut data_bytes: u64 = 0;
    let mut table_elements: u64 = 0;
    let mut table_maxima: u64 = 0;
    let mut tables: u32 = 0;
    let mut elem_items: u64 = 0;
    let mut count_table = |initial: u64, maximum: Option<u64>| -> Result<()> {
        tables += 1;
        if tables > s.max_tables {
            return Err(invalid(format!("more than {} tables", s.max_tables)));
        }
        let cap = u64::from(s.max_table_elements);
        if initial > cap {
            return Err(invalid(format!(
                "table minimum {initial} above the ceiling of {cap}"
            )));
        }
        table_elements = table_elements.saturating_add(initial);
        // What this table can ever hold: the tunables clamp an absent or
        // larger maximum to the per-table ceiling.
        table_maxima = table_maxima.saturating_add(maximum.map_or(cap, |m| m.min(cap)));
        if table_maxima > u64::from(s.max_total_table_elements) {
            return Err(invalid(format!(
                "tables may hold more than {} elements in total",
                s.max_total_table_elements
            )));
        }
        Ok(())
    };

    for payload in Parser::new(0).parse_all(code) {
        let payload = payload.map_err(invalid)?;
        match &payload {
            Payload::ImportSection(reader) => {
                for import in reader.clone() {
                    match import.map_err(invalid)?.ty {
                        TypeRef::Func(_) => import_frames.push(s.host_frame_units),
                        TypeRef::Memory(m) if m.initial > u64::from(s.max_memory_pages) => {
                            return Err(invalid("imported memory above the page ceiling"))
                        }
                        TypeRef::Table(t) => count_table(t.initial, t.maximum)?,
                        _ => {}
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader.clone() {
                    let m = memory.map_err(invalid)?;
                    if m.initial > u64::from(s.max_memory_pages) {
                        return Err(invalid(format!(
                            "memory minimum {} pages above the ceiling of {}",
                            m.initial, s.max_memory_pages
                        )));
                    }
                    initial_pages = initial_pages.saturating_add(m.initial);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader.clone() {
                    let t = table.map_err(invalid)?.ty;
                    count_table(t.initial, t.maximum)?;
                }
            }
            Payload::ElementSection(reader) => {
                use wasmer::wasmparser::ElementItems;
                for element in reader.clone() {
                    let items = match element.map_err(invalid)?.items {
                        ElementItems::Functions(r) => r.count(),
                        ElementItems::Expressions(_, r) => r.count(),
                    };
                    elem_items = elem_items.saturating_add(u64::from(items));
                }
            }
            Payload::DataSection(reader) => {
                for data in reader.clone() {
                    data_bytes =
                        data_bytes.saturating_add(data.map_err(invalid)?.data.len() as u64);
                }
            }
            Payload::StartSection { .. } => {
                return Err(invalid("a start function is not admitted"));
            }
            _ => {}
        }

        if let ValidPayload::Func(to_validate, body) =
            validator.payload(&payload).map_err(invalid)?
        {
            let mut func = to_validate.into_validator(std::mem::take(&mut allocs));
            let mut locals = body.get_locals_reader().map_err(invalid)?;
            for _ in 0..locals.get_count() {
                let offset = locals.original_position();
                let (count, ty) = locals.read().map_err(invalid)?;
                func.define_locals(offset, count, ty).map_err(invalid)?;
            }
            let mut ops = body.get_operators_reader().map_err(invalid)?;
            let mut costs = Vec::new();
            let mut acc: Gas = 0;
            let mut max_stack: u32 = 0;
            while !ops.eof() {
                let offset = ops.original_position();
                let op = ops.read().map_err(invalid)?;
                func.op(offset, &op).map_err(invalid)?;
                max_stack = max_stack.max(func.operand_stack_height());
                acc = acc.saturating_add(s.op_cost(&op));
                if ends_block(&op) {
                    costs.push(acc);
                    acc = 0;
                }
            }
            func.finish(ops.original_position()).map_err(invalid)?;
            let frame = u64::from(s.frame_overhead_units)
                + u64::from(func.len_locals())
                + u64::from(max_stack);
            if frame > u64::from(s.max_stack_units) {
                return Err(invalid(format!(
                    "a function's frame ({frame} units) exceeds the stack limit of {}",
                    s.max_stack_units
                )));
            }
            local_frames.push(frame as u32);
            blocks.push(costs);
            allocs = func.into_allocations();
        }
    }

    let mut frames = import_frames;
    frames.extend(local_frames);
    let max_frame = frames.iter().copied().max().unwrap_or(0);
    Ok(ModulePlan {
        blocks,
        frames,
        max_frame,
        initial_pages,
        data_bytes,
        table_elements,
        elem_items,
    })
}

#[derive(Debug, Clone, Copy)]
struct MeterGlobals {
    gas: u32,
    reason: u32,
    stack: u32,
    scratch32: u32,
    scratch64: u32,
}

/// The metering middleware for ONE module. Refuses a second module.
#[derive(Debug)]
struct ConsensusMetering {
    plan: Arc<ModulePlan>,
    schedule: CostScheduleV1Provisional,
    globals: Mutex<Option<MeterGlobals>>,
}

impl ModuleMiddleware for ConsensusMetering {
    fn generate_function_middleware(
        &self,
        index: LocalFunctionIndex,
    ) -> Box<dyn FunctionMiddleware> {
        let globals = self
            .globals
            .lock()
            .expect("metering lock")
            .expect("transform_module_info runs before function middlewares");
        Box::new(FunctionMetering {
            plan: self.plan.clone(),
            schedule: self.schedule,
            globals,
            func: index.as_u32() as usize,
            block: 0,
            acc: 0,
            depth: 1,
            started: false,
        })
    }

    fn transform_module_info(
        &self,
        info: &mut ModuleInfo,
    ) -> std::result::Result<(), MiddlewareError> {
        let mut slot = self.globals.lock().expect("metering lock");
        if slot.is_some() {
            return Err(MiddlewareError::new(
                "ConsensusMetering",
                "one metering instance per module",
            ));
        }
        let local_functions = info.functions.len() - info.num_imported_functions;
        if local_functions != self.plan.blocks.len() {
            return Err(MiddlewareError::new(
                "ConsensusMetering",
                "pre-scan and module disagree on the function count",
            ));
        }
        for name in [GAS_GLOBAL_EXPORT, TRAP_REASON_EXPORT, STACK_GLOBAL_EXPORT] {
            if info.exports.contains_key(name) {
                return Err(MiddlewareError::new(
                    "ConsensusMetering",
                    format!("export name {name} is reserved"),
                ));
            }
        }
        let mut add = |ty: Type, init: GlobalInit| -> GlobalIndex {
            let index = info.globals.push(GlobalType::new(ty, Mutability::Var));
            info.global_initializers.push(init);
            index
        };
        let gas = add(Type::I64, GlobalInit::I64Const(0));
        let reason = add(Type::I32, GlobalInit::I32Const(0));
        let stack = add(Type::I32, GlobalInit::I32Const(0));
        let scratch32 = add(Type::I32, GlobalInit::I32Const(0));
        let scratch64 = add(Type::I64, GlobalInit::I64Const(0));
        info.exports
            .insert(GAS_GLOBAL_EXPORT.to_string(), ExportIndex::Global(gas));
        info.exports
            .insert(TRAP_REASON_EXPORT.to_string(), ExportIndex::Global(reason));
        info.exports
            .insert(STACK_GLOBAL_EXPORT.to_string(), ExportIndex::Global(stack));
        *slot = Some(MeterGlobals {
            gas: gas.as_u32(),
            reason: reason.as_u32(),
            stack: stack.as_u32(),
            scratch32: scratch32.as_u32(),
            scratch64: scratch64.as_u32(),
        });
        Ok(())
    }
}

#[derive(Debug)]
struct FunctionMetering {
    plan: Arc<ModulePlan>,
    schedule: CostScheduleV1Provisional,
    globals: MeterGlobals,
    func: usize,
    /// Index of the basic block now being fed.
    block: usize,
    /// Static cost of the operators fed so far in this block, recomputed and
    /// checked against the pre-scan at the block's end.
    acc: Gas,
    depth: u32,
    started: bool,
}

/// Trap with `reason` (set first, so the host can tell why).
fn trap<'a>(g: &MeterGlobals, reason: i32) -> [Operator<'a>; 3] {
    [
        Operator::I32Const { value: reason },
        Operator::GlobalSet {
            global_index: g.reason,
        },
        Operator::Unreachable,
    ]
}

/// Check the amount held in `scratch64` against the gas global and subtract
/// it; trap if short.
fn charge_scratch<'a>(g: &MeterGlobals) -> Vec<Operator<'a>> {
    let mut v = vec![
        Operator::GlobalGet {
            global_index: g.gas,
        },
        Operator::GlobalGet {
            global_index: g.scratch64,
        },
        Operator::I64LtU,
        Operator::If {
            blockty: BlockType::Empty,
        },
    ];
    v.extend(trap(g, TRAP_OUT_OF_GAS));
    v.extend([
        Operator::End,
        Operator::GlobalGet {
            global_index: g.gas,
        },
        Operator::GlobalGet {
            global_index: g.scratch64,
        },
        Operator::I64Sub,
        Operator::GlobalSet {
            global_index: g.gas,
        },
    ]);
    v
}

/// Check-and-subtract a static `cost`.
fn charge_static<'a>(g: &MeterGlobals, cost: Gas) -> Vec<Operator<'a>> {
    let mut v = vec![
        Operator::GlobalGet {
            global_index: g.gas,
        },
        Operator::I64Const { value: cost as i64 },
        Operator::I64LtU,
        Operator::If {
            blockty: BlockType::Empty,
        },
    ];
    v.extend(trap(g, TRAP_OUT_OF_GAS));
    v.extend([
        Operator::End,
        Operator::GlobalGet {
            global_index: g.gas,
        },
        Operator::I64Const { value: cost as i64 },
        Operator::I64Sub,
        Operator::GlobalSet {
            global_index: g.gas,
        },
    ]);
    v
}

/// Charge for the i32 length operand on top of the stack, leaving it there.
/// `per_unit` gas per `unit` (rounded up), computed in i64: a u32 length times
/// any schedule value below 2^31 cannot overflow.
fn charge_dynamic<'a>(g: &MeterGlobals, unit: u64, per_unit: Gas) -> Vec<Operator<'a>> {
    let mut v = vec![
        Operator::GlobalSet {
            global_index: g.scratch32,
        },
        Operator::GlobalGet {
            global_index: g.scratch32,
        },
        Operator::GlobalGet {
            global_index: g.scratch32,
        },
        Operator::I64ExtendI32U,
    ];
    if unit > 1 {
        v.extend([
            Operator::I64Const {
                value: (unit - 1) as i64,
            },
            Operator::I64Add,
            Operator::I64Const { value: unit as i64 },
            Operator::I64DivU,
        ]);
    }
    v.extend([
        Operator::I64Const {
            value: per_unit as i64,
        },
        Operator::I64Mul,
        Operator::GlobalSet {
            global_index: g.scratch64,
        },
    ]);
    v.extend(charge_scratch(g));
    v
}

/// Add `units` to the stack height and trap above `limit`.
fn stack_push<'a>(g: &MeterGlobals, units: u32, limit: u32) -> Vec<Operator<'a>> {
    let mut v = vec![
        Operator::GlobalGet {
            global_index: g.stack,
        },
        Operator::I32Const {
            value: units as i32,
        },
        Operator::I32Add,
        Operator::GlobalSet {
            global_index: g.stack,
        },
        Operator::GlobalGet {
            global_index: g.stack,
        },
        Operator::I32Const {
            value: limit as i32,
        },
        Operator::I32GtU,
        Operator::If {
            blockty: BlockType::Empty,
        },
    ];
    v.extend(trap(g, TRAP_STACK_LIMIT));
    v.push(Operator::End);
    v
}

fn stack_pop<'a>(g: &MeterGlobals, units: u32) -> [Operator<'a>; 4] {
    [
        Operator::GlobalGet {
            global_index: g.stack,
        },
        Operator::I32Const {
            value: units as i32,
        },
        Operator::I32Sub,
        Operator::GlobalSet {
            global_index: g.stack,
        },
    ]
}

impl FunctionMetering {
    fn block_cost(&self, index: usize) -> std::result::Result<Gas, MiddlewareError> {
        self.plan
            .blocks
            .get(self.func)
            .and_then(|b| b.get(index))
            .copied()
            .ok_or_else(|| MiddlewareError::new("ConsensusMetering", "pre-scan has no such block"))
    }

    fn open_block<'a>(
        &self,
        state: &mut MiddlewareReaderState<'a>,
    ) -> std::result::Result<(), MiddlewareError> {
        let cost = self.block_cost(self.block)?;
        if cost > 0 {
            state.extend(charge_static(&self.globals, cost));
        }
        Ok(())
    }
}

impl FunctionMiddleware for FunctionMetering {
    fn feed<'a>(
        &mut self,
        operator: Operator<'a>,
        state: &mut MiddlewareReaderState<'a>,
    ) -> std::result::Result<(), MiddlewareError> {
        if !self.started {
            self.started = true;
            self.open_block(state)?;
        }
        let s = self.schedule;
        let g = self.globals;
        self.acc = self.acc.saturating_add(s.op_cost(&operator));
        let boundary = ends_block(&operator);
        match operator {
            Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => self.depth += 1,
            Operator::End => self.depth -= 1,
            _ => {}
        }

        match &operator {
            Operator::Call { function_index } => {
                let units = *self
                    .plan
                    .frames
                    .get(*function_index as usize)
                    .ok_or_else(|| MiddlewareError::new("ConsensusMetering", "unknown callee"))?;
                state.extend(stack_push(&g, units, s.max_stack_units));
                state.push_operator(operator);
                state.extend(stack_pop(&g, units));
            }
            Operator::CallIndirect { .. } => {
                let units = self.plan.max_frame;
                state.extend(stack_push(&g, units, s.max_stack_units));
                state.push_operator(operator);
                state.extend(stack_pop(&g, units));
            }
            Operator::MemoryGrow { .. } => {
                state.extend(charge_dynamic(&g, 1, s.memory_grow_per_page));
                state.push_operator(operator);
            }
            Operator::MemoryFill { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryInit { .. }
            | Operator::TableFill { .. }
            | Operator::TableCopy { .. }
            | Operator::TableInit { .. }
            | Operator::TableGrow { .. } => {
                state.extend(charge_dynamic(&g, s.bulk_unit, s.bulk_per_unit));
                state.push_operator(operator);
            }
            _ => state.push_operator(operator),
        }

        if boundary {
            let expected = self.block_cost(self.block)?;
            if expected != self.acc {
                return Err(MiddlewareError::new(
                    "ConsensusMetering",
                    "basic-block cost disagrees with the pre-scan",
                ));
            }
            self.acc = 0;
            self.block += 1;
            if self.depth > 0 {
                self.open_block(state)?;
            }
        }
        Ok(())
    }
}

/// Clamps every memory to the schedule's page ceiling and every table to its
/// element ceiling; refuses one whose minimum is above it. Growth past the
/// ceiling fails inside the guest (`memory.grow` returns -1).
struct CeilingTunables<T: Tunables> {
    pages: Pages,
    elements: u32,
    base: T,
}

impl<T: Tunables> CeilingTunables<T> {
    fn memory(&self, requested: &MemoryType) -> std::result::Result<MemoryType, MemoryError> {
        if requested.minimum > self.pages {
            return Err(MemoryError::Generic(format!(
                "memory minimum {} pages exceeds the ceiling of {} pages",
                requested.minimum.0, self.pages.0
            )));
        }
        let mut adjusted = *requested;
        adjusted.maximum = Some(match requested.maximum {
            Some(m) if m < self.pages => m,
            _ => self.pages,
        });
        Ok(adjusted)
    }

    fn table(&self, requested: &TableType) -> std::result::Result<TableType, String> {
        if requested.minimum > self.elements {
            return Err(format!(
                "table minimum {} exceeds the ceiling of {}",
                requested.minimum, self.elements
            ));
        }
        let mut adjusted = *requested;
        adjusted.maximum = Some(match requested.maximum {
            Some(m) if m < self.elements => m,
            _ => self.elements,
        });
        Ok(adjusted)
    }
}

impl<T: Tunables> Tunables for CeilingTunables<T> {
    fn memory_style(&self, memory: &MemoryType) -> MemoryStyle {
        match self.memory(memory) {
            Ok(m) => self.base.memory_style(&m),
            Err(_) => self.base.memory_style(memory),
        }
    }

    fn table_style(&self, table: &TableType) -> TableStyle {
        self.base.table_style(table)
    }

    fn create_host_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
    ) -> std::result::Result<VMMemory, MemoryError> {
        self.base.create_host_memory(&self.memory(ty)?, style)
    }

    unsafe fn create_vm_memory(
        &self,
        ty: &MemoryType,
        style: &MemoryStyle,
        vm_definition_location: NonNull<VMMemoryDefinition>,
    ) -> std::result::Result<VMMemory, MemoryError> {
        self.base
            .create_vm_memory(&self.memory(ty)?, style, vm_definition_location)
    }

    fn create_host_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
    ) -> std::result::Result<VMTable, String> {
        self.base.create_host_table(&self.table(ty)?, style)
    }

    unsafe fn create_vm_table(
        &self,
        ty: &TableType,
        style: &TableStyle,
        vm_definition_location: NonNull<VMTableDefinition>,
    ) -> std::result::Result<VMTable, String> {
        self.base
            .create_vm_table(&self.table(ty)?, style, vm_definition_location)
    }
}

/// A module compiled under metering v1, with the engine its stores must come
/// from and the plan its instantiation is charged by.
pub(crate) struct MeteredModule {
    pub module: Module,
    pub engine: wasmer::Engine,
    pub plan: Arc<ModulePlan>,
}

/// Pre-scan and compile `code` under its own metered engine.
pub(crate) fn compile(code: &[u8], s: &CostScheduleV1Provisional) -> Result<MeteredModule> {
    use wasmer::sys::NativeEngineExt;

    let plan = Arc::new(prescan(code, s)?);
    let mut compiler = Singlepass::default();
    compiler.push_middleware(Arc::new(ConsensusMetering {
        plan: plan.clone(),
        schedule: *s,
        globals: Mutex::new(None),
    }));
    let mut engine: wasmer::Engine = wasmer::sys::EngineBuilder::new(compiler).engine().into();
    engine.set_tunables(CeilingTunables {
        pages: Pages(s.max_memory_pages),
        elements: s.max_table_elements,
        base: BaseTunables::for_target(&Target::default()),
    });
    let module = Module::new(&Store::new(engine.clone()), code)?;
    Ok(MeteredModule {
        module,
        engine,
        plan,
    })
}
