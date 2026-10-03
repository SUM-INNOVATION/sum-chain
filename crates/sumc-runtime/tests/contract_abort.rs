//! #279: a contract calling the `abort` host import must fail its call
//! deterministically, exactly as a WASM trap (`unreachable`) does, and never
//! take the process down. Covers deploy (init), call, view and estimate_gas.

use std::sync::Arc;
use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, PendingWrite, RocksDbStorage, RuntimeError,
};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

/// `write_then_X` stages k -> VAL, then aborts or traps; `get` reads k back.
const WAT: &str = r#"
(module
  (import "env" "storage_read"  (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (import "env" "abort"         (func $abort  (param i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (data (i32.const 16) "boom")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "new_abort") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (call $abort (i32.const 16) (i32.const 4))
    (i32.const 0))
  (func (export "new_unreachable") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (unreachable))
  (func (export "get") (param i32 i32) (result i32)
    (call $sread (i32.const 0) (i32.const 1)))
  (func (export "write_then_abort") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (call $abort (i32.const 16) (i32.const 4))
    (i32.const 0))
  (func (export "write_then_unreachable") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (unreachable))
)
"#;

fn ctx() -> ExecutionContext {
    let caller = Address::new([7u8; 20]);
    ExecutionContext {
        caller,
        origin: caller,
        value: 0,
        gas_limit: 100_000_000,
        block_height: 1,
        block_timestamp: 1000,
        chain_id: 1,
    }
}

fn executor() -> (ContractExecutor, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let backend = Arc::new(RocksDbStorage::new(db));
    (
        ContractExecutor::new(Arc::new(ContractStorage::new(backend))),
        dir,
    )
}

/// A deployed contract, with the deploy's queued writes already drained.
fn deployed() -> (ContractExecutor, Address, TempDir) {
    let (exec, dir) = executor();
    let dep = exec
        .deploy(wat::parse_str(WAT).unwrap(), "new", vec![], ctx(), 0)
        .unwrap();
    exec.take_pending_writes();
    (exec, dep.contract_address, dir)
}

fn storage_writes(w: &[PendingWrite]) -> usize {
    w.iter()
        .filter(|w| matches!(w, PendingWrite::Storage { .. }))
        .count()
}

#[test]
fn an_aborting_call_fails_like_a_trap_and_keeps_no_writes() {
    let (exec, addr, _d) = deployed();
    let aborted = exec.call(addr, "write_then_abort", vec![], ctx()).unwrap();
    let aborted_writes = exec.take_pending_writes();
    let trapped = exec
        .call(addr, "write_then_unreachable", vec![], ctx())
        .unwrap();
    let trapped_writes = exec.take_pending_writes();

    assert!(!aborted.success, "abort fails the call");
    assert!(
        aborted
            .error
            .as_deref()
            .unwrap_or("")
            .contains("contract aborted"),
        "{:?}",
        aborted.error
    );
    assert!(aborted.return_value.is_empty() && aborted.events.is_empty());
    assert!(!trapped.success);
    assert_eq!(
        aborted.gas_used, trapped.gas_used,
        "same gas as an existing trap"
    );
    assert_eq!(
        storage_writes(&aborted_writes),
        0,
        "the write staged before abort is rolled back"
    );
    assert_eq!(storage_writes(&trapped_writes), 0);

    let got = exec.call(addr, "get", vec![], ctx()).unwrap();
    assert!(
        got.success && got.return_value.is_empty(),
        "no partial write is visible afterwards"
    );
}

#[test]
fn a_deploy_whose_init_aborts_fails_like_a_trapping_init_and_leaves_nothing() {
    let run = |init: &str| {
        let (exec, _d) = executor();
        let res = exec.deploy(wat::parse_str(WAT).unwrap(), init, vec![], ctx(), 0);
        let addr = ContractExecutor::compute_address(&ctx().caller, 0);
        (
            res.map(|_| ()),
            exec.contract_exists(&addr).unwrap(),
            exec.get_metadata(&addr).is_some(),
            exec.take_pending_writes(),
        )
    };
    let (aborted, a_exists, a_meta, a_writes) = run("new_abort");
    let (trapped, t_exists, t_meta, t_writes) = run("new_unreachable");
    match &aborted {
        Err(RuntimeError::Execution(m)) => assert!(m.contains("contract aborted"), "{m}"),
        other => panic!("abort in init must be an execution failure, got {other:?}"),
    }
    assert!(matches!(trapped, Err(RuntimeError::Execution(_))));
    assert!(!a_exists && !a_meta, "no code or metadata survives");
    assert_eq!((a_exists, a_meta), (t_exists, t_meta));
    assert_eq!(
        storage_writes(&a_writes),
        0,
        "init's storage write is rolled back"
    );
    assert_eq!(
        a_writes.len(),
        t_writes.len(),
        "same cleanup as a trapping init"
    );
}

#[test]
fn view_and_estimate_gas_report_an_abort_as_an_error() {
    let (exec, addr, _d) = deployed();
    let view = exec.view(addr, "write_then_abort", vec![], ctx());
    assert!(
        matches!(&view, Err(RuntimeError::Execution(m)) if m.contains("contract aborted")),
        "{view:?}"
    );
    let est = exec.estimate_gas(addr, "write_then_abort", vec![], ctx());
    assert!(
        matches!(&est, Err(RuntimeError::Execution(m)) if m.contains("contract aborted")),
        "{est:?}"
    );
    assert_eq!(
        storage_writes(&exec.take_pending_writes()),
        0,
        "read-only paths keep nothing"
    );
    let got = exec.view(addr, "get", vec![], ctx()).unwrap();
    assert!(got.is_empty());
}

#[test]
fn an_abort_is_deterministic_across_independent_executors() {
    let outcome = || {
        let (exec, addr, _d) = deployed();
        let r = exec.call(addr, "write_then_abort", vec![], ctx()).unwrap();
        (
            r.success,
            r.gas_used,
            r.error,
            r.return_value,
            exec.take_pending_writes().len(),
        )
    };
    assert_eq!(outcome(), outcome());
}
