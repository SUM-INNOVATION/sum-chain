//! #279: timing of metering v1 (PROVISIONAL schedule) — ignored by default.
//!
//! Run: `cargo test --release -p sumc-runtime --test metering_v1_bench -- --ignored --nocapture`
//!
//! Each workload runs to out-of-gas under one transaction budget, so the
//! printed `ns/gas` is the wall time one unit of gas buys for that operator
//! mix. Timing is machine evidence, never a test assertion.

use std::sync::Arc;
use std::time::Instant;
use sumc_runtime::metering::CostScheduleV1Provisional;
use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, ExecutionMode, MemoryStorage,
};
use sumchain_primitives::Address;

const M: ExecutionMode = ExecutionMode::MeteredV1Provisional;
const BUDGET: u64 = 10_000_000;

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

const WAT: &str = r#"
(module
  (import "env" "storage_read"  (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (type $v (func))
  (memory (export "memory") 256)
  (table 8192 8192 funcref)
  (elem (i32.const 0) $nop)
  (global $g (mut i64) (i64.const 7))
  (func $nop)
  (func (export "alloc") (param i32) (result i32) (i32.const 1048576))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "alu") (param i32 i32) (result i32) (local $x i32)
    (loop $l (local.set $x (i32.add (i32.xor (local.get $x) (i32.const 3)) (i32.const 1))) (br $l))
    (i32.const 0))
  (func (export "div") (param i32 i32) (result i32) (local $x i64)
    (local.set $x (i64.const 0x7fffffffffff))
    (loop $l (local.set $x (i64.add (i64.div_u (local.get $x) (i64.const 3)) (i64.const 0x7fffffffffff))) (br $l))
    (i32.const 0))
  (func (export "sqrt") (param i32 i32) (result i32) (local $x f64)
    (local.set $x (f64.const 12345.678))
    (loop $l (local.set $x (f64.add (f64.sqrt (local.get $x)) (f64.const 12345.678))) (br $l))
    (i32.const 0))
  (func (export "mem") (param i32 i32) (result i32) (local $a i32)
    (loop $l
      (local.set $a (i32.and (i32.add (local.get $a) (i32.const 4099)) (i32.const 0xfffff0)))
      (i64.store (local.get $a) (i64.add (i64.load (local.get $a)) (i64.const 1)))
      (br $l))
    (i32.const 0))
  (func (export "calls") (param i32 i32) (result i32)
    (loop $l (call $nop) (br $l)) (i32.const 0))
  (func (export "indirect") (param i32 i32) (result i32)
    (loop $l (call_indirect (type $v) (i32.const 0)) (br $l)) (i32.const 0))
  (func (export "fill") (param i32 i32) (result i32)
    (loop $l (memory.fill (i32.const 0) (i32.const 1) (i32.const 16777216)) (br $l)) (i32.const 0))
  (func (export "copy") (param i32 i32) (result i32)
    (loop $l (memory.copy (i32.const 0) (i32.const 8388608) (i32.const 8388608)) (br $l)) (i32.const 0))
  (func (export "grow_fail") (param i32 i32) (result i32)
    (loop $l (drop (memory.grow (i32.const 1))) (br $l)) (i32.const 0))
  (func (export "put64k") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (call $swrite (i32.const 16) (i32.const 1) (i32.const 65536) (i32.const 65536))
    (i32.const 0))
  (func (export "read64k") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (loop $l (drop (call $sread (i32.const 16) (i32.const 1))) (br $l)) (i32.const 0))
  (func (export "read_miss") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 120))
    (loop $l (drop (call $sread (i32.const 16) (i32.const 1))) (br $l)) (i32.const 0))
  (func (export "fadd") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.add (local.get $x) (f64.const 1))) (br $l)) (i32.const 0))
  (func (export "fmul") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.mul (local.get $x) (f64.const 1))) (br $l)) (i32.const 0))
  (func (export "fdiv") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.div (local.get $x) (f64.const 1))) (br $l)) (i32.const 0))
  (func (export "fsqrt") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.add (f64.sqrt (local.get $x)) (f64.const 12345.678))) (br $l)) (i32.const 0))
  (func (export "f32sqrt") (param i32 i32) (result i32) (local $x f32) (local $i i64)
    (local.set $x (f32.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f32.add (f32.sqrt (local.get $x)) (f32.const 12345.678))) (br $l)) (i32.const 0))
  (func (export "fmin") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.min (local.get $x) (f64.const 5))) (br $l)) (i32.const 0))
  (func (export "fnearest") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.add (f64.nearest (local.get $x)) (f64.const 0.5))) (br $l)) (i32.const 0))
  (func (export "fconv") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $x (f64.add (f64.convert_i64_s (local.get $i)) (local.get $x))) (br $l)) (i32.const 0))
  (func (export "ftrunc") (param i32 i32) (result i32) (local $x f64) (local $i i64)
    (local.set $x (f64.const 12345.678)) (local.set $i (i64.const 7))
    (loop $l (local.set $i (i64.add (i64.trunc_sat_f64_s (local.get $x)) (local.get $i))) (br $l)) (i32.const 0))
  (func (export "tfill") (param i32 i32) (result i32)
    (loop $l (table.fill 0 (i32.const 0) (ref.null func) (i32.const 8192)) (br $l)) (i32.const 0))
  (func (export "tcopy") (param i32 i32) (result i32)
    (loop $l (table.copy (i32.const 0) (i32.const 4096) (i32.const 4096)) (br $l)) (i32.const 0))
  (func (export "write32") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 119))
    (loop $l (call $swrite (i32.const 16) (i32.const 1) (i32.const 64) (i32.const 32)) (br $l))
    (i32.const 0))
)
"#;

/// A module of `funcs` small functions, as the design note's compile probe.
fn wide_module(funcs: usize) -> Vec<u8> {
    let mut w = String::from(
        "(module (memory (export \"memory\") 1)\n (func (export \"new\") (param i32 i32) (result i32) (i32.const 0))\n",
    );
    for i in 0..funcs {
        w.push_str(&format!(
            " (func (export \"f{i}\") (param i32) (result i32) (local i32) \
             (local.set 1 (i32.mul (local.get 0) (i32.const {i}))) \
             (if (result i32) (i32.gt_u (local.get 1) (i32.const 100)) \
               (then (i32.add (local.get 1) (i32.const 1))) (else (i32.sub (local.get 1) (i32.const 1)))))\n"
        ));
    }
    w.push(')');
    wat::parse_str(&w).unwrap()
}

#[test]
#[ignore]
fn metering_v1_ns_per_gas() {
    let ex = executor();
    let addr = ex
        .deploy_with_mode(
            M,
            wat::parse_str(WAT).unwrap(),
            "new",
            vec![],
            ctx(BUDGET),
            0,
        )
        .unwrap()
        .contract_address;
    let r = ex
        .call_with_mode(M, addr, "put64k", vec![], ctx(BUDGET))
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    for method in [
        "alu",
        "div",
        "sqrt",
        "mem",
        "calls",
        "indirect",
        "fill",
        "copy",
        "grow_fail",
        "read64k",
        "read_miss",
        "write32",
        "fadd",
        "fmul",
        "fdiv",
        "fsqrt",
        "f32sqrt",
        "fmin",
        "fnearest",
        "fconv",
        "ftrunc",
        "tfill",
        "tcopy",
    ] {
        let mut best = f64::MAX;
        let mut used = 0;
        for _ in 0..5 {
            let t = Instant::now();
            let r = ex
                .call_with_mode(M, addr, method, vec![], ctx(BUDGET))
                .unwrap();
            let ns = t.elapsed().as_nanos() as f64;
            assert!(!r.success, "{method} must run out of gas");
            used = r.gas_used;
            best = best.min(ns);
        }
        println!(
            "BENCH {method:<10} gas={used} ms={:.3} ns/gas={:.4}",
            best / 1e6,
            best / used as f64
        );
    }
}

#[test]
#[ignore]
fn metering_v1_compile_and_deploy() {
    let s = CostScheduleV1Provisional::PROVISIONAL;
    // Warm-up, discarded.
    executor()
        .deploy_with_mode(M, wide_module(500), "new", vec![], ctx(u64::MAX / 2), 0)
        .unwrap();
    // 22_000 functions is near the largest of this shape under MAX_CODE_SIZE.
    for funcs in [100usize, 1_000, 2_300, 10_000, 22_000] {
        let code = wide_module(funcs);
        let t = Instant::now();
        let plan = sumc_runtime::metering::prescan(&code, &s).unwrap();
        let prescan_ns = t.elapsed().as_nanos() as f64;
        drop(plan);
        let mut best_deploy = f64::MAX;
        let mut best_unmetered = f64::MAX;
        for _ in 0..3 {
            let ex = executor();
            let t = Instant::now();
            let r = ex.deploy_with_mode(M, code.clone(), "new", vec![], ctx(u64::MAX / 2), 0);
            best_deploy = best_deploy.min(t.elapsed().as_nanos() as f64);
            assert!(r.is_ok(), "{:?}", r.err());
            let ex = executor();
            let t = Instant::now();
            ex.deploy(code.clone(), "new", vec![], ctx(u64::MAX / 2), 0)
                .unwrap();
            best_unmetered = best_unmetered.min(t.elapsed().as_nanos() as f64);
        }
        let charged = s.deploy_cost(code.len());
        println!(
            "COMPILE funcs={funcs} bytes={} prescan_ms={:.2} metered_deploy_ms={:.2} \
             unmetered_deploy_ms={:.2} metered_ns/byte={:.1} charged_gas={charged} ns/charged_gas={:.3}",
            code.len(),
            prescan_ns / 1e6,
            best_deploy / 1e6,
            best_unmetered / 1e6,
            best_deploy / code.len() as f64,
            best_deploy / charged as f64
        );
    }
}

#[test]
#[ignore]
fn metering_v1_call_overhead() {
    let one_page = r#"(module (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "new") (param i32 i32) (result i32) (i32.const 0)))"#;
    let storage = Arc::new(ContractStorage::new(Arc::new(MemoryStorage::new())));
    let ex = ContractExecutor::new(storage.clone());
    let addr = ex
        .deploy_with_mode(
            M,
            wat::parse_str(one_page).unwrap(),
            "new",
            vec![],
            ctx(BUDGET),
            0,
        )
        .unwrap()
        .contract_address;
    let n = 2_000;
    let t = Instant::now();
    let mut gas = 0;
    for _ in 0..n {
        gas = ex
            .call_with_mode(M, addr, "new", vec![], ctx(BUDGET))
            .unwrap()
            .gas_used;
    }
    let per = t.elapsed().as_nanos() as f64 / n as f64;
    println!(
        "CALL trivial_call_1_page gas={gas} us={:.2} ns/gas={:.2}",
        per / 1e3,
        per / gas as f64
    );
    // First call on a fresh executor: compile on cache miss, unmetered.
    let cold = ContractExecutor::new(storage);
    let t = Instant::now();
    let r = cold
        .call_with_mode(M, addr, "new", vec![], ctx(BUDGET))
        .unwrap();
    println!(
        "CALL cache_miss_call_1_page gas={} us={:.2}",
        r.gas_used,
        t.elapsed().as_nanos() as f64 / 1e3
    );
}
