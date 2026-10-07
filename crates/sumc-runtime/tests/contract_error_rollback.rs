//! #279: a contract call that returns `Err` (rather than failing with
//! `success == false`) must not leave its staged storage writes behind.
//!
//! The `Err` paths that run guest code before failing are the guest `alloc`
//! (called to place the arguments) and the read of the length-prefixed return
//! value. Before the fix, `ContractExecutor::call` returned such an error
//! without rolling back, so the staged writes stayed in the write cache: later
//! calls read them, and the next successful call committed them.
//!
//! That is consensus-visible (contract storage, state root), so `call` keeps
//! it -- pinned below as the historical behaviour -- and the correction is
//! `call_with_error_rollback(.., true)`, which block execution selects only
//! above a dormant activation gate. `view` (RPC only, never commits) rolls back
//! on `Err` unconditionally; `estimate_gas` and `deploy` already did.

use std::sync::Arc;

use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, PendingWrite, RocksDbStorage,
    RuntimeError,
};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

/// `write_then_bad_return` stages k -> VAL and returns a pointer whose length
/// prefix (256) runs past the single page, so the return read is an `Err`.
const WAT: &str = r#"
(module
  (import "env" "storage_read"  (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (data (i32.const 16) "j")
  (data (i32.const 24) "OK")
  (data (i32.const 65520) "\00\01\00\00")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "new_bad_return") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 65520))
  (func (export "noop") (param i32 i32) (result i32) (i32.const 0))
  (func (export "write_j") (param i32 i32) (result i32)
    (call $swrite (i32.const 16) (i32.const 1) (i32.const 24) (i32.const 2))
    (i32.const 0))
  (func (export "get") (param i32 i32) (result i32)
    (call $sread (i32.const 0) (i32.const 1)))
  (func (export "write_then_bad_return") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 65520))
)
"#;

/// The guest `alloc` stages a -> ALLOC and returns the last byte of memory, so
/// placing any argument longer than one byte fails with `Err`.
const ALLOC_WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "a")
  (data (i32.const 8) "ALLOC")
  (func (export "alloc") (param $size i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 5))
    (i32.const 65535))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "noop") (param i32 i32) (result i32) (i32.const 0))
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
    let exec = ContractExecutor::new(Arc::new(ContractStorage::new(Arc::new(
        RocksDbStorage::new(db),
    ))));
    (exec, dir)
}

fn deployed(wat: &str) -> (ContractExecutor, Address, TempDir) {
    let (exec, dir) = executor();
    let dep = exec
        .deploy(wat::parse_str(wat).unwrap(), "new", vec![], ctx(), 0)
        .unwrap();
    exec.take_pending_writes();
    (exec, dep.contract_address, dir)
}

/// Storage rows queued for the block, as `key=value` text.
fn storage_rows(exec: &ContractExecutor) -> Vec<String> {
    exec.take_pending_writes()
        .into_iter()
        .filter_map(|w| match w {
            PendingWrite::Storage { key, value, .. } => Some(format!(
                "{}={}",
                String::from_utf8_lossy(&key),
                value.map(|v| String::from_utf8_lossy(&v).into_owned())
                    .unwrap_or_default()
            )),
            _ => None,
        })
        .collect()
}

/// What `get` returns: the length-prefixed value of `k`, or empty if absent.
fn read_k(exec: &ContractExecutor, addr: Address) -> Vec<u8> {
    let r = exec.call(addr, "get", vec![], ctx()).unwrap();
    assert!(r.success);
    r.return_value
}

/// Err call, then a successful call, then a read: everything observable.
fn sequence(rollback_on_error: bool, wat: &str, method: &str, args: Vec<u8>) -> String {
    let (exec, addr, _d) = deployed(wat);
    let err = exec.call_with_error_rollback(addr, method, args, ctx(), rollback_on_error);
    let ok = exec
        .call_with_error_rollback(addr, "noop", vec![], ctx(), rollback_on_error)
        .unwrap();
    format!(
        "err={:?} ok=({}, {}, {:?}) committed={:?}",
        err.map(|r| r.success),
        ok.success,
        ok.gas_used,
        ok.error,
        storage_rows(&exec)
    )
}

// ── Historical behaviour (`call`), byte-identical to 8744d861 ──

/// The issue, pinned: `call` leaves the write of an `Err` call staged, a later
/// call reads it, and the next successful call commits it. These assertions
/// hold on the unfixed executor and must keep holding: block execution below
/// the gate depends on them.
#[test]
fn call_keeps_the_historical_error_path_unchanged() {
    let (exec, addr, _d) = deployed(WAT);
    let err = exec.call(addr, "write_then_bad_return", vec![], ctx());
    assert!(
        matches!(&err, Err(RuntimeError::MemoryAccess(m)) if m == "memory access out of bounds"),
        "{err:?}"
    );
    assert_eq!(storage_rows(&exec), Vec::<String>::new(), "nothing committed yet");
    assert_eq!(
        read_k(&exec, addr),
        b"VAL".to_vec(),
        "a later call reads the failed call's write"
    );
    let ok = exec.call(addr, "noop", vec![], ctx()).unwrap();
    assert!(ok.success);
    assert_eq!(
        storage_rows(&exec),
        vec!["k=VAL".to_string()],
        "the next successful call commits it"
    );
}

#[test]
fn call_keeps_the_historical_alloc_error_path_unchanged() {
    let (exec, addr, _d) = deployed(ALLOC_WAT);
    let err = exec.call(addr, "noop", vec![1, 2], ctx());
    assert!(matches!(err, Err(RuntimeError::MemoryAccess(_))), "{err:?}");
    let ok = exec.call(addr, "noop", vec![], ctx()).unwrap();
    assert!(ok.success);
    assert_eq!(storage_rows(&exec), vec!["a=ALLOC".to_string()]);
}

/// `call` IS `call_with_error_rollback(.., false)`.
#[test]
fn without_the_flag_the_outcome_is_the_historical_one() {
    let legacy = |wat: &str, method: &str, args: Vec<u8>| {
        let (exec, addr, _d) = deployed(wat);
        let err = exec.call(addr, method, args, ctx());
        let ok = exec.call(addr, "noop", vec![], ctx()).unwrap();
        format!(
            "err={:?} ok=({}, {}, {:?}) committed={:?}",
            err.map(|r| r.success),
            ok.success,
            ok.gas_used,
            ok.error,
            storage_rows(&exec)
        )
    };
    for (wat, method, args) in [
        (WAT, "write_then_bad_return", vec![]),
        (ALLOC_WAT, "noop", vec![1, 2]),
        (WAT, "missing_method", vec![]),
        (WAT, "write_j", vec![]),
    ] {
        assert_eq!(
            sequence(false, wat, method, args.clone()),
            legacy(wat, method, args),
            "{method}"
        );
    }
}

// ── The fix (`call_with_error_rollback(.., true)`) ──

#[test]
fn with_the_flag_an_error_rolls_back_the_calls_staged_writes() {
    let (exec, addr, _d) = deployed(WAT);
    let err = exec.call_with_error_rollback(addr, "write_then_bad_return", vec![], ctx(), true);
    assert!(
        matches!(&err, Err(RuntimeError::MemoryAccess(m)) if m == "memory access out of bounds"),
        "the error itself is unchanged: {err:?}"
    );
    assert!(read_k(&exec, addr).is_empty(), "no later call reads it");
    let ok = exec
        .call_with_error_rollback(addr, "noop", vec![], ctx(), true)
        .unwrap();
    assert!(ok.success);
    assert_eq!(storage_rows(&exec), Vec::<String>::new(), "nothing is committed");
}

#[test]
fn with_the_flag_a_write_staged_by_alloc_is_rolled_back() {
    assert_eq!(
        sequence(true, ALLOC_WAT, "noop", vec![1, 2]),
        "err=Err(MemoryAccess(\"memory access out of bounds\")) ok=(true, 1000, None) committed=[]"
    );
}

/// Only the error path changes: writes committed earlier in the block stay,
/// and a successful call commits exactly what it did before.
#[test]
fn with_the_flag_committed_and_successful_writes_are_untouched() {
    let (exec, addr, _d) = deployed(WAT);
    let r = exec
        .call_with_error_rollback(addr, "write_j", vec![], ctx(), true)
        .unwrap();
    assert!(r.success);
    assert!(exec
        .call_with_error_rollback(addr, "write_then_bad_return", vec![], ctx(), true)
        .is_err());
    assert_eq!(storage_rows(&exec), vec!["j=OK".to_string()]);
    for method in ["write_j", "noop", "get"] {
        let a = sequence(true, WAT, method, vec![]);
        let b = sequence(false, WAT, method, vec![]);
        assert_eq!(a, b, "{method}: no Err, no difference");
    }
}

// ── view, estimate_gas, deploy ──

#[test]
fn view_rolls_back_on_error() {
    let (exec, addr, _d) = deployed(WAT);
    let v = exec.view(addr, "write_then_bad_return", vec![], ctx());
    assert!(
        matches!(&v, Err(RuntimeError::MemoryAccess(m)) if m == "memory access out of bounds"),
        "{v:?}"
    );
    assert!(read_k(&exec, addr).is_empty(), "the view's write is gone");
    assert!(exec.call(addr, "noop", vec![], ctx()).unwrap().success);
    assert_eq!(storage_rows(&exec), Vec::<String>::new());
}

#[test]
fn estimate_gas_rolls_back_on_error() {
    let (exec, addr, _d) = deployed(WAT);
    assert!(exec
        .estimate_gas(addr, "write_then_bad_return", vec![], ctx())
        .is_err());
    assert!(read_k(&exec, addr).is_empty());
    assert!(exec.call(addr, "noop", vec![], ctx()).unwrap().success);
    assert_eq!(storage_rows(&exec), Vec::<String>::new());
}

#[test]
fn deploy_rolls_back_on_an_init_error() {
    let (exec, _d) = executor();
    let res = exec.deploy(wat::parse_str(WAT).unwrap(), "new_bad_return", vec![], ctx(), 0);
    assert!(matches!(res, Err(RuntimeError::MemoryAccess(_))), "{res:?}");
    let addr = ContractExecutor::compute_address(&ctx().caller, 0);
    assert!(!exec.contract_exists(&addr).unwrap());
    assert_eq!(storage_rows(&exec), Vec::<String>::new());
    // A later successful deploy commits only its own rows.
    let dep = exec
        .deploy(wat::parse_str(WAT).unwrap(), "new", vec![], ctx(), 1)
        .unwrap();
    assert!(exec.contract_exists(&dep.contract_address).unwrap());
    assert_eq!(storage_rows(&exec), Vec::<String>::new());
}
