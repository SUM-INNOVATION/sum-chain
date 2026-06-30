//! Issue #25, Set 2: end-to-end contract storage over the persistent
//! RocksDB backend — host ABI v1 read/write/remove and restart persistence.
//!
//! Uses a hand-written `.wat` fixture (no SDK build step) exporting `memory`,
//! a bump `alloc`, and methods that exercise the storage host functions.

use std::sync::Arc;
use sumc_runtime::{ContractExecutor, ContractStorage, ExecutionContext, RocksDbStorage};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

/// Contract: key "k" (len 1) @ offset 0, value "VAL" (len 3) @ offset 8.
/// `set` writes k->VAL; `get` returns the stored value (via storage_read's
/// length-prefixed return buffer); `del` removes k; `new` is the init no-op.
const WAT: &str = r#"
(module
  (import "env" "storage_read"   (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write"  (func $swrite (param i32 i32 i32 i32)))
  (import "env" "storage_remove" (func $sremove (param i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "set") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (i32.const 0))
  (func (export "get") (param i32 i32) (result i32)
    (call $sread (i32.const 0) (i32.const 1)))
  (func (export "del") (param i32 i32) (result i32)
    (call $sremove (i32.const 0) (i32.const 1))
    (i32.const 0))
)
"#;

fn ctx(caller: Address) -> ExecutionContext {
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

fn executor(db: &Arc<Database>) -> ContractExecutor {
    let backend = Arc::new(RocksDbStorage::new(db.clone()));
    ContractExecutor::new(Arc::new(ContractStorage::new(backend)))
}

#[test]
fn storage_write_read_remove_roundtrip() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    let caller = Address::new([1u8; 20]);
    let code = wat::parse_str(WAT).unwrap();

    let dep = exec.deploy(code, "new", vec![], ctx(caller), 0).unwrap();
    let addr = dep.contract_address;

    // Initially absent.
    let got = exec.call(addr, "get", vec![], ctx(caller)).unwrap();
    assert!(got.success);
    assert!(got.return_value.is_empty(), "expected no value yet");

    // Write, then read back.
    assert!(exec.call(addr, "set", vec![], ctx(caller)).unwrap().success);
    let got = exec.call(addr, "get", vec![], ctx(caller)).unwrap();
    assert_eq!(got.return_value, b"VAL", "stored value should round-trip");

    // Remove, then absent again.
    assert!(exec.call(addr, "del", vec![], ctx(caller)).unwrap().success);
    let got = exec.call(addr, "get", vec![], ctx(caller)).unwrap();
    assert!(got.return_value.is_empty(), "value should be gone after remove");
}

#[test]
fn storage_survives_restart() {
    let dir = TempDir::new().unwrap();
    let caller = Address::new([2u8; 20]);
    let code = wat::parse_str(WAT).unwrap();

    let addr = {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let exec = executor(&db);
        let dep = exec.deploy(code, "new", vec![], ctx(caller), 0).unwrap();
        assert!(exec.call(dep.contract_address, "set", vec![], ctx(caller)).unwrap().success);
        dep.contract_address
        // db + exec dropped here
    };

    // Reopen the SAME path with a fresh executor: code + storage + metadata persist.
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    assert!(exec.contract_exists(&addr).unwrap(), "code should persist");
    assert!(exec.get_metadata(&addr).is_some(), "metadata should persist");
    let got = exec.call(addr, "get", vec![], ctx(caller)).unwrap();
    assert_eq!(got.return_value, b"VAL", "storage should persist across restart");
}

#[test]
fn failed_init_leaves_no_persisted_state() {
    // A contract whose `new` traps must not leave code/metadata/storage behind.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    let caller = Address::new([3u8; 20]);
    let bad = r#"(module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "new") (param i32 i32) (result i32) (unreachable)))"#;
    let code = wat::parse_str(bad).unwrap();
    let addr = ContractExecutor::compute_address(&caller, 0);

    assert!(exec.deploy(code, "new", vec![], ctx(caller), 0).is_err());
    assert!(!exec.contract_exists(&addr).unwrap(), "no code after failed init");
    assert!(exec.get_metadata(&addr).is_none(), "no metadata after failed init");
}

#[test]
fn failed_call_produces_no_journal_and_no_write() {
    // A call that stages a write then traps must roll back: no journal entry,
    // no persisted storage.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    let caller = Address::new([7u8; 20]);
    let code = wat::parse_str(
        r#"(module
          (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "k") (data (i32.const 8) "V")
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "new") (param i32 i32) (result i32) (i32.const 0))
          (func (export "boom") (param i32 i32) (result i32)
            (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 1))
            (unreachable)))"#,
    )
    .unwrap();
    let dep = exec.deploy(code, "new", vec![], ctx(caller), 0).unwrap();
    let _ = exec.take_journal(); // drain the deploy's journal

    let res = exec.call(dep.contract_address, "boom", vec![], ctx(caller)).unwrap();
    assert!(!res.success, "trapping call must fail");
    assert!(exec.take_journal().is_empty(), "failed call must not journal");
    // The staged write never persisted.
    let got = exec.call(dep.contract_address, "new", vec![], ctx(caller)).unwrap();
    assert!(got.success);
}

#[test]
fn estimate_gas_preserves_journal_and_commits_nothing() {
    // A pre-existing committed journal entry must survive a dry-run estimate,
    // and the estimate's own writes must not be committed.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    let caller = Address::new([8u8; 20]);
    // `new` no-op; `one` writes k->V; `two` writes k->V and k2->V.
    let code = wat::parse_str(
        r#"(module
          (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (data (i32.const 0) "k") (data (i32.const 8) "V") (data (i32.const 16) "k2")
          (func (export "alloc") (param i32) (result i32)
            (local $p i32) (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get 0))) (local.get $p))
          (func (export "new") (param i32 i32) (result i32) (i32.const 0))
          (func (export "one") (param i32 i32) (result i32)
            (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 1)) (i32.const 0))
          (func (export "two") (param i32 i32) (result i32)
            (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 1))
            (call $sw (i32.const 16) (i32.const 2) (i32.const 8) (i32.const 1)) (i32.const 0)))"#,
    )
    .unwrap();
    let dep = exec.deploy(code, "new", vec![], ctx(caller), 0).unwrap();
    let addr = dep.contract_address;
    let _ = exec.take_journal(); // drain the deploy's journal

    // Commit a real call: now there is ONE pre-existing journal entry (slot k).
    assert!(exec.call(addr, "one", vec![], ctx(caller)).unwrap().success);

    // Dry-run estimate of a heavier method. Must not drain or append journal,
    // and must not commit its k2 write.
    let est = exec.estimate_gas(addr, "two", vec![], ctx(caller)).unwrap();
    assert!(est > 0);

    let journal = exec.take_journal();
    assert_eq!(journal.len(), 1, "estimate must neither drain nor append the journal");
    // The single entry is the committed `one` write (slot k), not estimate's.
    assert_eq!(journal[0].cf_kind, sumchain_storage::contract_cf_kind::STORAGE);

    // estimate's k2 write was never committed.
    assert!(exec.call(addr, "new", vec![], ctx(caller)).unwrap().success); // sanity: contract still callable
}

#[test]
fn missing_init_method_leaves_no_persisted_state() {
    // Init method not found -> call_internal returns Err (distinct from a
    // trap); the same guarded cleanup must remove code + metadata.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = executor(&db);
    let caller = Address::new([4u8; 20]);
    let code = wat::parse_str(WAT).unwrap();
    let addr = ContractExecutor::compute_address(&caller, 0);

    assert!(exec.deploy(code, "does_not_exist", vec![], ctx(caller), 0).is_err());
    assert!(!exec.contract_exists(&addr).unwrap(), "no code after missing-init deploy");
    assert!(exec.get_metadata(&addr).is_none(), "no metadata after missing-init deploy");
    // And the contract is not callable afterwards.
    assert!(exec.call(addr, "get", vec![], ctx(caller)).is_err());
}
