//! #279: metering v1 (PROVISIONAL schedule) in the runtime.
//!
//! Every assertion is on deterministic quantities — gas used, which failure,
//! which depth — never on time. The unmetered engine is exercised alongside
//! where the contrast is the point.

use std::sync::Arc;
use sumc_runtime::metering::{self, prescan, CostScheduleV1Provisional};
use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, ExecutionMode, LocalExecutionLimits,
    MemoryStorage, RuntimeError, ENGINE_IDENTITY, METERED_ENGINE_IDENTITY,
};
use sumchain_primitives::Address;

const S: CostScheduleV1Provisional = CostScheduleV1Provisional::PROVISIONAL;
const M: ExecutionMode = ExecutionMode::MeteredV1Provisional;
const U: ExecutionMode = ExecutionMode::Unmetered;

/// Five pages; `alloc` always hands out 196608, which leaves room for a
/// 64 KiB value plus its prefix inside memory.
const WAT: &str = r#"
(module
  (import "env" "storage_read"  (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 5)
  (func (export "alloc") (param i32) (result i32) (i32.const 196608))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "spin_1000") (param i32 i32) (result i32)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 1000))))
    (i32.const 0))
  (func (export "forever") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0))
  (func (export "grow") (param $p i32) (param $l i32) (result i32)
    (i32.store (i32.const 64) (i32.const 8))
    (i32.store (i32.const 68) (memory.grow (i32.load (local.get $p))))
    (i32.store (i32.const 72) (memory.size))
    (i32.const 64))
  (func (export "fill") (param $p i32) (param $l i32) (result i32)
    (memory.fill (i32.const 0) (i32.const 0) (i32.load (local.get $p)))
    (i32.const 0))
  (func (export "put") (param $p i32) (param $l i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (call $swrite (i32.const 16) (i32.const 1) (i32.const 65536) (i32.load (local.get $p)))
    (i32.const 0))
  (func (export "get") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (drop (call $sread (i32.const 16) (i32.const 1)))
    (i32.const 0))
  (func (export "write_key") (param $p i32) (param $l i32) (result i32)
    (call $swrite (i32.const 0x7ffffff0) (i32.load (local.get $p)) (i32.const 0) (i32.const 0))
    (i32.const 0))
  (func (export "read_key") (param $p i32) (param $l i32) (result i32)
    (drop (call $sread (i32.const 0x7ffffff0) (i32.load (local.get $p))))
    (i32.const 0))
  (func (export "huge_return") (param i32 i32) (result i32)
    (i32.store (i32.const 64) (i32.const 0xfffffff0))
    (i32.const 64))
)
"#;

const FOREVER_INIT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0)))
"#;

fn ctx(gas_limit: u64) -> ExecutionContext {
    let caller = Address::new([7u8; 20]);
    ExecutionContext {
        caller,
        origin: caller,
        value: 0,
        gas_limit,
        block_height: 1,
        block_timestamp: 1000,
        chain_id: 1,
    }
}

fn executor() -> ContractExecutor {
    ContractExecutor::new(Arc::new(ContractStorage::new(Arc::new(
        MemoryStorage::new(),
    ))))
}

/// Deploy `wat` under `mode` with a generous budget.
fn deployed(wat: &str, mode: ExecutionMode) -> (ContractExecutor, Address) {
    let ex = executor();
    let r = ex
        .deploy_with_mode(
            mode,
            wat::parse_str(wat).unwrap(),
            "new",
            vec![],
            ctx(10_000_000),
            0,
        )
        .expect("deploy");
    (ex, r.contract_address)
}

fn arg(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// What instantiating `WAT` costs: five initial pages, no data segments.
fn wat_instantiation() -> u64 {
    5 * S.memory_grow_per_page
}

#[test]
fn identities_are_distinct_and_the_schedule_is_labelled_provisional() {
    assert_eq!(ENGINE_IDENTITY, "wasmer-singlepass-5");
    assert_ne!(METERED_ENGINE_IDENTITY, ENGINE_IDENTITY);
    assert!(METERED_ENGINE_IDENTITY.ends_with("provisional"));
    let tag = b"sumc-cost-v1-provisional";
    let encoded = S.encode();
    assert_eq!(encoded[0] as usize, tag.len());
    assert_eq!(&encoded[1..=tag.len()], tag);
    assert_eq!(encoded.len(), 1 + tag.len() + 19 * 8 + 10 * 4);
    assert_eq!(S.encode(), CostScheduleV1Provisional::PROVISIONAL.encode());
}

#[test]
fn fuel_is_charged_per_basic_block_before_it_runs_and_exactly() {
    let code = wat::parse_str(WAT).unwrap();
    let plan = prescan(&code, &S).unwrap();
    // spin_1000 is local function 2: [loop] [body ... br_if] [end] [i32.const end].
    assert_eq!(plan.block_costs(2).unwrap(), &[1, 8, 1, 2]);

    let (ex, addr) = deployed(WAT, M);
    let r = ex
        .call_with_mode(M, addr, "spin_1000", vec![], ctx(10_000_000))
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let call_base = 1_000;
    assert_eq!(
        r.gas_used,
        call_base + wat_instantiation() + 1 + 1_000 * 8 + 1 + 2
    );

    // Below the gate: the same call costs only the base charge, as today.
    let (ux, uaddr) = deployed(WAT, U);
    let r = ux
        .call(uaddr, "spin_1000", vec![], ctx(10_000_000))
        .unwrap();
    assert!(r.success);
    assert_eq!(r.gas_used, 1_000);
}

#[test]
fn a_non_terminating_call_fails_out_of_gas_with_the_whole_budget_spent() {
    let (ex, addr) = deployed(WAT, M);
    for _ in 0..2 {
        let r = ex
            .call_with_mode(M, addr, "forever", vec![], ctx(50_000))
            .unwrap();
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some(metering::OUT_OF_GAS_MESSAGE));
        assert_eq!(r.gas_used, 50_000);
    }
}

#[test]
fn a_non_terminating_init_fails_the_deploy_and_leaves_no_contract() {
    let ex = executor();
    let err = ex
        .deploy_with_mode(
            M,
            wat::parse_str(FOREVER_INIT).unwrap(),
            "new",
            vec![],
            ctx(100_000),
            0,
        )
        .unwrap_err();
    assert!(
        err.to_string().contains(metering::OUT_OF_GAS_MESSAGE),
        "{err}"
    );
    let addr = ContractExecutor::compute_address(&ctx(0).caller, 0);
    assert!(!ex.contract_exists(&addr).unwrap());
}

#[test]
fn deploy_is_charged_per_code_byte_before_compiling() {
    let code = wat::parse_str(WAT).unwrap();
    let deploy = S.deploy_cost(code.len());
    assert_eq!(deploy, 10_000 + 100 * code.len() as u64);
    // init "new" is one block: [i32.const end] = 2.
    let exact = deploy + wat_instantiation() + 2;

    let ex = executor();
    let r = ex
        .deploy_with_mode(M, code.clone(), "new", vec![], ctx(exact), 0)
        .unwrap();
    assert_eq!(r.gas_used, exact);

    let ex = executor();
    assert!(ex
        .deploy_with_mode(M, code.clone(), "new", vec![], ctx(exact - 1), 0)
        .is_err());

    // Short of the code charge itself: refused before compiling — even code
    // that does not parse fails as out of gas, not as a compile error.
    let ex = executor();
    let garbage = vec![0xffu8; code.len()];
    match ex.deploy_with_mode(M, garbage, "new", vec![], ctx(deploy - 1), 0) {
        Err(RuntimeError::OutOfGas { .. }) => {}
        other => panic!("expected out of gas before compiling, got {other:?}"),
    }
    let addr = ContractExecutor::compute_address(&ctx(0).caller, 0);
    assert!(!ex.contract_exists(&addr).unwrap());
}

#[test]
fn memory_is_capped_at_256_pages_and_growth_is_charged_per_page() {
    let (ex, addr) = deployed(WAT, M);
    let grow = |n: u32| {
        let r = ex
            .call_with_mode(M, addr, "grow", arg(n), ctx(10_000_000))
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        let old = i32::from_le_bytes(r.return_value[0..4].try_into().unwrap());
        let size = i32::from_le_bytes(r.return_value[4..8].try_into().unwrap());
        (old, size, r.gas_used)
    };
    let (old, size, g251) = grow(251);
    assert_eq!((old, size), (5, 256));
    let (old, size, g252) = grow(252);
    assert_eq!((old, size), (-1, 5), "one page past the ceiling is refused");
    assert_eq!(
        g252 - g251,
        S.memory_grow_per_page,
        "charged per page requested"
    );

    // Below the gate growth is unbounded and free, as today.
    let (ux, uaddr) = deployed(WAT, U);
    let r = ux.call(uaddr, "grow", arg(300), ctx(10_000_000)).unwrap();
    assert!(r.success);
    let size = i32::from_le_bytes(r.return_value[4..8].try_into().unwrap());
    assert_eq!((size, r.gas_used), (305, 1_000));

    // Declaring more than the ceiling is refused at deploy.
    let ex = executor();
    let big = r#"(module (memory (export "memory") 300)
      (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#;
    assert!(matches!(
        ex.deploy_with_mode(
            M,
            wat::parse_str(big).unwrap(),
            "new",
            vec![],
            ctx(10_000_000),
            0
        ),
        Err(RuntimeError::InvalidCode(_))
    ));
}

#[test]
fn bulk_operations_are_charged_by_length_before_they_run() {
    let (ex, addr) = deployed(WAT, M);
    let fill = |n: u32, limit: u64| {
        ex.call_with_mode(M, addr, "fill", arg(n), ctx(limit))
            .unwrap()
    };
    let a = fill(0, 10_000_000);
    let b = fill(65_536, 10_000_000);
    assert!(a.success && b.success);
    assert_eq!(b.gas_used - a.gas_used, 65_536 / 16);

    // A length the budget cannot pay for traps as out of gas BEFORE the
    // operation; with budget it would have trapped out of bounds.
    let short = fill(0x7fff_ffff, 100_000);
    assert_eq!(short.error.as_deref(), Some(metering::OUT_OF_GAS_MESSAGE));
    let rich = fill(0x7fff_ffff, 1_000_000_000);
    assert!(!rich.success);
    assert_ne!(rich.error.as_deref(), Some(metering::OUT_OF_GAS_MESSAGE));
}

fn rec_module(locals: usize) -> String {
    let decl = "(local i64)".repeat(locals);
    format!(
        r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func $rec (param $n i32) (result i32) {decl}
    (if (result i32) (i32.eqz (local.get $n))
      (then (i32.const 0))
      (else (call $rec (i32.sub (local.get $n) (i32.const 1))))))
  (func (export "run") (param $p i32) (param $l i32) (result i32)
    (drop (call $rec (i32.load (local.get $p))))
    (i32.const 0)))"#
    )
}

/// The deepest `n` for which `run(n)` stays within the stack limit: `run`
/// makes n+1 nested calls to `$rec` (function index 2), each costing its
/// static frame.
fn max_depth(wat: &str) -> (u32, u32) {
    let frame = prescan(&wat::parse_str(wat).unwrap(), &S)
        .unwrap()
        .frame_units(2)
        .unwrap();
    (frame, S.max_stack_units / frame - 1)
}

#[test]
fn the_stack_limit_is_a_function_of_the_module_not_of_native_frame_size() {
    let mut frames = Vec::new();
    for locals in [0usize, 64] {
        let wat = rec_module(locals);
        let (frame, n) = max_depth(&wat);
        frames.push(frame);
        let (ex, addr) = deployed(&wat, M);
        let ok = ex
            .call_with_mode(M, addr, "run", arg(n), ctx(10_000_000))
            .unwrap();
        assert!(ok.success, "{locals} locals, depth {n}: {:?}", ok.error);
        let over = ex
            .call_with_mode(M, addr, "run", arg(n + 1), ctx(10_000_000))
            .unwrap();
        assert_eq!(
            over.error.as_deref(),
            Some(metering::STACK_LIMIT_MESSAGE),
            "{locals} locals, depth {}",
            n + 1
        );
    }
    // The frame accounts for the locals: 64 more units for 64 more locals.
    assert_eq!(frames[1] - frames[0], 64);

    // Below the gate the same depth runs: the unmetered engine is bounded by
    // the native stack only, unchanged.
    let wat = rec_module(0);
    let (_, n) = max_depth(&wat);
    let (ux, uaddr) = deployed(&wat, U);
    assert!(
        ux.call(uaddr, "run", arg(n + 1), ctx(10_000_000))
            .unwrap()
            .success
    );
}

#[test]
fn storage_read_is_charged_per_value_byte() {
    let get_after_put = |len: u32| {
        let (ex, addr) = deployed(WAT, M);
        let put = ex
            .call_with_mode(M, addr, "put", arg(len), ctx(10_000_000))
            .unwrap();
        assert!(put.success, "{:?}", put.error);
        let get = ex
            .call_with_mode(M, addr, "get", vec![], ctx(10_000_000))
            .unwrap();
        assert!(get.success, "{:?}", get.error);
        get.gas_used
    };
    assert_eq!(
        get_after_put(65_536) - get_after_put(1),
        65_535 * S.storage_read_per_value_byte
    );
}

#[test]
fn host_lengths_are_bounded_before_anything_is_copied() {
    let (ex, addr) = deployed(WAT, M);
    // Key pointer is out of bounds: had the copy come first the error would be
    // a memory error. The cap is checked first.
    for method in ["write_key", "read_key"] {
        for len in [S.max_key_len + 1, 0x7fff_ffff] {
            let r = ex
                .call_with_mode(M, addr, method, arg(len), ctx(10_000_000))
                .unwrap();
            assert!(!r.success);
            assert!(
                r.error.as_deref().unwrap().contains("exceeds the limit"),
                "{method}: {:?}",
                r.error
            );
        }
    }
    // A value above the cap is refused before it is read.
    let r = ex
        .call_with_mode(M, addr, "put", arg(S.max_value_len + 1), ctx(10_000_000))
        .unwrap();
    assert!(
        r.error.as_deref().unwrap().contains("exceeds the limit"),
        "{:?}",
        r.error
    );
    // A guest-claimed 4 GiB return value is refused before allocation.
    let r = ex
        .call_with_mode(M, addr, "huge_return", vec![], ctx(10_000_000))
        .unwrap();
    assert!(!r.success);
    assert!(
        r.error.as_deref().unwrap().contains("exceeds the limit"),
        "{:?}",
        r.error
    );
}

#[test]
fn a_call_refused_by_a_host_charge_leaves_stored_state_unchanged() {
    let (ex, addr) = deployed(WAT, M);
    // A second put cannot pay for its write: the charge is refused before the
    // write is staged, and the next call sees the first value.
    let r = ex
        .call_with_mode(M, addr, "put", arg(4), ctx(10_000_000))
        .unwrap();
    assert!(r.success);
    let before = ex
        .call_with_mode(M, addr, "get", vec![], ctx(10_000_000))
        .unwrap()
        .gas_used;
    let r = ex
        .call_with_mode(M, addr, "put", arg(65_536), ctx(30_000))
        .unwrap();
    assert_eq!(r.error.as_deref(), Some(metering::OUT_OF_GAS_MESSAGE));
    let after = ex
        .call_with_mode(M, addr, "get", vec![], ctx(10_000_000))
        .unwrap()
        .gas_used;
    assert_eq!(before, after, "the stored value is still the 4-byte one");
}

#[test]
fn modules_outside_the_admitted_feature_set_are_refused_at_deploy() {
    let cases = [
        // SIMD
        r#"(module (memory (export "memory") 1)
             (func (export "new") (param i32 i32) (result i32)
               (drop (v128.const i64x2 0 0)) (i32.const 0)))"#,
        // start function
        r#"(module (memory (export "memory") 1) (func $s) (start $s)
             (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#,
        // a reserved metering export name
        r#"(module (memory (export "memory") 1)
             (global (export "__sumc_v1_gas_remaining") i32 (i32.const 0))
             (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#,
    ];
    for wat in cases {
        let ex = executor();
        let r = ex.deploy_with_mode(
            M,
            wat::parse_str(wat).unwrap(),
            "new",
            vec![],
            ctx(10_000_000),
            0,
        );
        assert!(r.is_err(), "{wat}");
    }
}

/// Reference types under metering v1: every table and reference operator
/// compiles and runs; table.grow/fill/copy/init are charged per 16 elements
/// before they run; tables are capped at `max_table_elements`.
const REF_WAT: &str = r#"
(module
  (type $v (func (result i32)))
  (memory (export "memory") 1)
  (table $t0 2 2 funcref)
  (table $t1 1 8 funcref)
  (table $ext 4 externref)
  (elem (table $t0) (i32.const 0) func $one $two)
  (elem $passive func $two $one)
  (elem declare func $one)
  (func $one (result i32) (i32.const 1))
  (func $two (result i32) (i32.const 2))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "all_ops") (param i32 i32) (result i32) (local $r i32)
    ;; ref.func / table.set / table.get / ref.is_null / ref.null
    (table.set $t1 (i32.const 0) (ref.func $one))
    (local.set $r (call_indirect $t1 (type $v) (i32.const 0)))
    (local.set $r (i32.add (local.get $r) (ref.is_null (table.get $t0 (i32.const 1)))))
    (table.set $ext (i32.const 0) (ref.null extern))
    (local.set $r (i32.add (local.get $r) (ref.is_null (table.get $ext (i32.const 0)))))
    ;; table.size / table.grow / table.fill / table.copy / table.init / elem.drop
    (drop (table.grow $t1 (ref.null func) (i32.const 3)))
    (table.fill $t1 (i32.const 1) (ref.func $one) (i32.const 3))
    (table.copy $t1 $t0 (i32.const 0) (i32.const 0) (i32.const 2))
    (table.init $t0 $passive (i32.const 0) (i32.const 0) (i32.const 2))
    (elem.drop $passive)
    (local.set $r (i32.add (local.get $r) (call_indirect $t0 (type $v) (i32.const 0))))
    (local.set $r (i32.add (local.get $r) (table.size $t1)))
    ;; select with a reference type
    (drop (select (result funcref) (ref.null func) (ref.func $one) (i32.const 1)))
    (i32.store (i32.const 64) (i32.const 4))
    (i32.store (i32.const 68) (local.get $r))
    (i32.const 64))
  (func (export "grow_t1") (param $p i32) (param $l i32) (result i32)
    (i32.store (i32.const 64) (i32.const 4))
    (i32.store (i32.const 68) (table.grow $t1 (ref.null func) (i32.load (local.get $p))))
    (i32.const 64))
  (func (export "grow_ext") (param $p i32) (param $l i32) (result i32)
    (i32.store (i32.const 64) (i32.const 4))
    (i32.store (i32.const 68) (table.grow $ext (ref.null extern) (i32.load (local.get $p))))
    (i32.const 64))
)
"#;

#[test]
fn reference_type_operations_are_metered_and_tables_capped() {
    let (ex, addr) = deployed(REF_WAT, M);
    let r = ex
        .call_with_mode(M, addr, "all_ops", vec![], ctx(10_000_000))
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    // 1 (t1[0]=$one) + 0 + 1 (ext null) + 2 (t0[0]=$two after init) + 4 (size)
    assert_eq!(
        i32::from_le_bytes(r.return_value[..4].try_into().unwrap()),
        8
    );

    let grow = |method: &str, n: u32| {
        let r = ex
            .call_with_mode(M, addr, method, arg(n), ctx(10_000_000))
            .unwrap();
        assert!(r.success, "{:?}", r.error);
        (
            i32::from_le_bytes(r.return_value[..4].try_into().unwrap()),
            r.gas_used,
        )
    };
    // $t1 declares max 8: growth beyond it is refused inside the guest.
    assert_eq!(grow("grow_t1", 7).0, 1);
    assert_eq!(grow("grow_t1", 8).0, -1);
    // $ext declares no max: clamped to the schedule's table ceiling.
    let cap = S.max_table_elements;
    let (old, g_ok) = grow("grow_ext", cap - 4);
    assert_eq!(old, 4);
    let (old, g_over) = grow("grow_ext", cap - 3);
    assert_eq!(old, -1, "one element past the ceiling is refused");
    // Charged per 16 elements requested, before the operation.
    assert_eq!(
        g_over - g_ok,
        S.bulk_cost(u64::from(cap - 3)) - S.bulk_cost(u64::from(cap - 4))
    );

    // A table declared above the ceiling, or more tables than allowed, is
    // refused at deploy.
    let five = "(table 1 funcref)".repeat(S.max_tables as usize + 1);
    for tables in ["(table 9000 funcref)".to_string(), five] {
        let wat = format!(
            r#"(module (memory (export "memory") 1) {tables}
              (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#
        );
        assert!(matches!(
            executor().deploy_with_mode(
                M,
                wat::parse_str(&wat).unwrap(),
                "new",
                vec![],
                ctx(10_000_000),
                0
            ),
            Err(RuntimeError::InvalidCode(_))
        ));
    }
    // The sum of the tables' effective maxima is capped: two tables with no
    // declared maximum reach max_total_table_elements, a third exceeds it.
    let tables = |n: usize| {
        let wat = format!(
            r#"(module (memory (export "memory") 1) {}
              (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#,
            "(table 1 funcref)".repeat(n)
        );
        executor().deploy_with_mode(
            M,
            wat::parse_str(&wat).unwrap(),
            "new",
            vec![],
            ctx(10_000_000),
            0,
        )
    };
    assert_eq!(2 * S.max_table_elements, S.max_total_table_elements);
    assert!(tables(2).is_ok());
    assert!(matches!(tables(3), Err(RuntimeError::InvalidCode(_))));

    // Initial table elements and element-segment items are charged at each
    // instantiation: REF_WAT declares 2 + 1 + 4 elements, 2 + 2 + 1 segment
    // items and one page.
    let plan = prescan(&wat::parse_str(REF_WAT).unwrap(), &S).unwrap();
    assert_eq!((plan.table_elements, plan.elem_items), (7, 5));
    assert_eq!(
        plan.instantiation_cost(&S),
        S.memory_grow_per_page + S.bulk_cost(12) * S.instantiate_per_data_unit
    );
}

// ── views and estimates (the RPC paths) ─────────────────────────────────────

#[test]
fn a_metered_estimate_is_what_the_metered_call_charges_and_commits_nothing() {
    let (ex, addr) = deployed(WAT, M);
    for (method, args) in [("spin_1000", vec![]), ("put", arg(4)), ("get", vec![])] {
        let estimate = ex
            .estimate_gas_with_mode(M, addr, method, args.clone(), ctx(10_000_000))
            .unwrap();
        let charged = ex
            .call_with_mode(M, addr, method, args, ctx(10_000_000))
            .unwrap();
        assert!(charged.success, "{method}: {:?}", charged.error);
        assert_eq!(estimate, charged.gas_used, "{method}");
    }
    // Neither an estimate nor a view of a writing call leaves anything behind:
    // the next read still pays for the 4-byte value.
    let before = ex
        .call_with_mode(M, addr, "get", vec![], ctx(10_000_000))
        .unwrap()
        .gas_used;
    ex.estimate_gas_with_mode(M, addr, "put", arg(65_536), ctx(10_000_000))
        .unwrap();
    ex.view_with_mode(M, addr, "put", arg(65_536), ctx(10_000_000))
        .unwrap();
    let after = ex
        .call_with_mode(M, addr, "get", vec![], ctx(10_000_000))
        .unwrap()
        .gas_used;
    assert_eq!(before, after, "the stored value is still the 4-byte one");
}

#[test]
fn metered_views_and_estimates_stop_out_of_gas_and_unmetered_ones_are_unchanged() {
    let (ex, addr) = deployed(WAT, M);
    let err = ex
        .view_with_mode(M, addr, "forever", vec![], ctx(50_000))
        .unwrap_err()
        .to_string();
    assert!(err.contains(metering::OUT_OF_GAS_MESSAGE), "{err}");
    let err = ex
        .estimate_gas_with_mode(M, addr, "forever", vec![], ctx(50_000))
        .unwrap_err()
        .to_string();
    assert!(err.contains(metering::OUT_OF_GAS_MESSAGE), "{err}");

    // Unmetered: exactly the existing paths.
    let (ux, uaddr) = deployed(WAT, U);
    assert_eq!(
        ux.estimate_gas_with_mode(U, uaddr, "spin_1000", vec![], ctx(10_000_000))
            .unwrap(),
        ux.estimate_gas(uaddr, "spin_1000", vec![], ctx(10_000_000))
            .unwrap()
    );
    assert_eq!(
        ux.view_with_mode(U, uaddr, "spin_1000", vec![], ctx(10_000_000))
            .unwrap(),
        ux.view(uaddr, "spin_1000", vec![], ctx(10_000_000)).unwrap()
    );
}

#[test]
fn a_local_executor_runs_metered_views_under_its_gas_cap() {
    let storage = Arc::new(ContractStorage::new(Arc::new(MemoryStorage::new())));
    let ex = ContractExecutor::new(storage.clone());
    let addr = ex
        .deploy_with_mode(M, wat::parse_str(WAT).unwrap(), "new", vec![], ctx(10_000_000), 0)
        .unwrap()
        .contract_address;
    let local = |gas_cap| {
        ContractExecutor::with_local_limits(
            storage.clone(),
            LocalExecutionLimits {
                gas_cap,
                ..LocalExecutionLimits::DEFAULT
            },
        )
    };
    // An unbounded request is held to the cap.
    let err = local(50_000)
        .view_with_mode(M, addr, "forever", vec![], ctx(u64::MAX))
        .unwrap_err()
        .to_string();
    assert!(err.contains(metering::OUT_OF_GAS_MESSAGE), "{err}");
    // Within the cap, a local estimate is the block executor's.
    assert_eq!(
        local(10_000_000)
            .estimate_gas_with_mode(M, addr, "spin_1000", vec![], ctx(10_000_000))
            .unwrap(),
        ex.estimate_gas_with_mode(M, addr, "spin_1000", vec![], ctx(10_000_000))
            .unwrap()
    );
}
