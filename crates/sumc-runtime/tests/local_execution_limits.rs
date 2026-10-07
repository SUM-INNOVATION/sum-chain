//! #279: node-local budgets for the RPC/view executor. The same contracts as
//! `execution_bounds_baseline.rs`, on an executor built `with_local_limits`;
//! the consensus executor (`ContractExecutor::new`) is unchanged.

use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use sumc_runtime::executor::{
    LOCAL_BULK_EXHAUSTED, LOCAL_FUEL_EXHAUSTED, LOCAL_HOST_BUDGET_EXHAUSTED,
};
use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, LocalExecutionLimits, RocksDbStorage,
    MAX_MEMORY_PAGES,
};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

const WAT: &str = r#"
(module
  (import "env" "storage_read"  (func $sread  (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 4)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (if (i32.gt_u (global.get $bump) (i32.mul (memory.size) (i32.const 65536)))
      (then (drop (memory.grow (i32.add (i32.div_u (local.get $size) (i32.const 65536)) (i32.const 1))))))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "spin_10m") (param i32 i32) (result i32)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 10000000))))
    (i32.const 0))
  (func (export "forever") (param i32 i32) (result i32)
    (loop $l (br $l))
    (i32.const 0))
  ;; grow to 256 pages, then a 16 MiB memory.fill per iteration, forever:
  ;; a handful of operators per iteration, 16 MiB of work each
  (func (export "fill_forever") (param i32 i32) (result i32)
    (drop (memory.grow (i32.const 252)))
    (loop $l
      (memory.fill (i32.const 0) (i32.const 0) (i32.const 16777216))
      (br $l))
    (i32.const 0))
  (func (export "fill_once") (param i32 i32) (result i32)
    (memory.fill (i32.const 0) (i32.const 0) (i32.const 262144))
    (i32.const 0))
  (func (export "pages") (param i32 i32) (result i32)
    (drop (memory.grow (i32.const 1024)))
    (i32.store (i32.const 32) (i32.const 4))
    (i32.store (i32.const 36) (memory.size))
    (i32.const 32))
  ;; return-data header claiming 1 GiB
  (func (export "huge_return") (param i32 i32) (result i32)
    (i32.store (i32.const 32) (i32.const 1073741824))
    (i32.const 32))
  (func (export "put_big") (param i32 i32) (result i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (call $swrite (i32.const 16) (i32.const 1) (i32.const 65536) (i32.const 131072))
    (i32.const 0))
  (func (export "read_big_64x") (param i32 i32) (result i32)
    (local $i i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (loop $l
      (drop (call $sread (i32.const 16) (i32.const 1)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 64))))
    (i32.const 0))
  (func (export "read_big_256x") (param i32 i32) (result i32)
    (local $i i32)
    (i32.store8 (i32.const 16) (i32.const 107))
    (loop $l
      (drop (call $sread (i32.const 16) (i32.const 1)))
      (global.set $bump (i32.const 1024)) ;; reuse the buffer: memory stays small
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 256))))
    (i32.const 0))
)
"#;

const BIG_MIN_MEMORY: &str = r#"
(module
  (memory (export "memory") 300)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "get") (param i32 i32) (result i32) (i32.const 0)))
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

const TX_MAX: u64 = 10_000_000;

fn storage() -> (Arc<ContractStorage>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (
        Arc::new(ContractStorage::new(Arc::new(RocksDbStorage::new(db)))),
        dir,
    )
}

fn deploy(exec: &ContractExecutor, wat: &str) -> Address {
    let dep = exec
        .deploy(wat::parse_str(wat).unwrap(), "new", vec![], ctx(TX_MAX), 0)
        .unwrap();
    exec.take_pending_writes();
    dep.contract_address
}

fn local() -> (Arc<ContractExecutor>, Address, TempDir) {
    let (s, d) = storage();
    let exec = Arc::new(ContractExecutor::with_local_limits(
        s,
        LocalExecutionLimits::DEFAULT,
    ));
    let addr = deploy(&exec, WAT);
    (exec, addr, d)
}

fn err_text(r: sumc_runtime::Result<Vec<u8>>) -> String {
    r.expect_err("expected a local-limit error").to_string()
}

#[test]
fn a_non_terminating_view_stops_at_the_operator_budget() {
    let (exec, addr, _d) = local();
    let (tx, rx) = mpsc::channel();
    let e = exec.clone();
    std::thread::spawn(move || {
        let t = Instant::now();
        let r = e.view(addr, "forever", vec![], ctx(TX_MAX));
        let _ = tx.send((r.map_err(|e| e.to_string()), t.elapsed()));
    });
    let (r, wall) = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the view returned");
    let e = r.expect_err("budget exhausted");
    assert!(e.contains(LOCAL_FUEL_EXHAUSTED), "{e}");
    eprintln!(
        "forever: stopped after {:?} at fuel {}",
        wall,
        LocalExecutionLimits::DEFAULT.fuel
    );
}

#[test]
fn ordinary_work_fits_the_default_budget_and_gas_is_unchanged() {
    let (exec, addr, _d) = local();
    let t = Instant::now();
    assert!(exec.view(addr, "spin_10m", vec![], ctx(TX_MAX)).is_ok());
    eprintln!("spin_10m metered: {:?}", t.elapsed());

    // The estimate is consensus gas, identical on both executors.
    let (s, _d2) = storage();
    let consensus = ContractExecutor::new(s);
    let caddr = deploy(&consensus, WAT);
    for m in ["spin_10m", "put_big"] {
        let local_gas = exec.estimate_gas(addr, m, vec![], ctx(TX_MAX)).unwrap();
        let consensus_gas = consensus
            .estimate_gas(caddr, m, vec![], ctx(TX_MAX))
            .unwrap();
        assert_eq!(local_gas, consensus_gas, "{m}");
    }
}

#[test]
fn linear_memory_stops_at_the_local_ceiling() {
    let (exec, addr, _d) = local();
    let out = exec.view(addr, "pages", vec![], ctx(TX_MAX)).unwrap();
    let pages = u32::from_le_bytes(out[..4].try_into().unwrap());
    assert!(pages <= MAX_MEMORY_PAGES, "{pages}");
}

#[test]
fn a_module_whose_minimum_memory_exceeds_the_ceiling_does_not_instantiate_locally() {
    let (s, _d) = storage();
    let consensus = ContractExecutor::new(s.clone());
    let addr = deploy(&consensus, BIG_MIN_MEMORY);
    assert!(consensus.view(addr, "get", vec![], ctx(TX_MAX)).is_ok());
    let local = ContractExecutor::with_local_limits(s, LocalExecutionLimits::DEFAULT);
    assert!(local.view(addr, "get", vec![], ctx(TX_MAX)).is_err());
}

#[test]
fn host_copying_stops_at_the_local_byte_budget() {
    let (exec, addr, _d) = local();
    let w = exec.call(addr, "put_big", vec![], ctx(TX_MAX)).unwrap();
    assert!(w.success, "{:?}", w.error);
    exec.take_pending_writes();
    // 64 x 128 KiB = 8 MiB: within 16 MiB.
    assert!(exec.view(addr, "read_big_64x", vec![], ctx(TX_MAX)).is_ok());
    // 256 x 128 KiB = 32 MiB: over.
    let e = err_text(exec.view(addr, "read_big_256x", vec![], ctx(TX_MAX)));
    assert!(e.contains(LOCAL_HOST_BUDGET_EXHAUSTED), "{e}");
}

#[test]
fn a_guest_claimed_return_length_is_checked_before_allocation() {
    let (exec, addr, _d) = local();
    let e = err_text(exec.view(addr, "huge_return", vec![], ctx(TX_MAX)));
    assert!(e.contains("exceeds the local limit"), "{e}");
}

#[test]
fn view_gas_is_capped_locally() {
    let limits = LocalExecutionLimits {
        gas_cap: 5_000,
        ..LocalExecutionLimits::DEFAULT
    };
    let (s, _d) = storage();
    let capped = ContractExecutor::with_local_limits(s, limits);
    let addr = deploy(&capped, WAT);
    // 64 storage reads cost 1_000 + 64 * 201 gas, over a 5_000 cap.
    assert!(capped
        .view(addr, "read_big_64x", vec![], ctx(TX_MAX))
        .is_err());
}

#[test]
fn bulk_memory_work_stops_at_the_local_byte_budget() {
    let (exec, addr, _d) = local();
    assert!(exec.view(addr, "fill_once", vec![], ctx(TX_MAX)).is_ok());
    let t = Instant::now();
    let e = err_text(exec.view(addr, "fill_forever", vec![], ctx(TX_MAX)));
    assert!(e.contains(LOCAL_BULK_EXHAUSTED), "{e}");
    eprintln!("fill_forever: stopped after {:?}", t.elapsed());
}

#[test]
fn bulk_memory_is_not_bounded_by_operators_alone() {
    // Without a bulk budget, the same loop runs far past what its operator
    // count suggests: 2M operators of 16 MiB fills is over a terabyte of
    // memset.
    let limits = LocalExecutionLimits {
        fuel: 2_000_000,
        max_bulk_bytes: u64::MAX / 2,
        ..LocalExecutionLimits::DEFAULT
    };
    let (s, _d) = storage();
    let exec = Arc::new(ContractExecutor::with_local_limits(s, limits));
    let addr = deploy(&exec, WAT);
    let (tx, rx) = mpsc::channel();
    let e = exec.clone();
    std::thread::spawn(move || {
        let _ = tx.send(e.view(addr, "fill_forever", vec![], ctx(TX_MAX)).is_err());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_err(),
        "2M operators of memory.fill ran for 5 s"
    );
}

#[test]
fn one_local_executor_compiles_many_modules() {
    // A metering middleware instance transforms exactly one module; the
    // executor must give each module its own engine.
    let (s, _d) = storage();
    let exec = ContractExecutor::with_local_limits(s, LocalExecutionLimits::DEFAULT);
    let a = deploy(&exec, WAT);
    let b = exec
        .deploy(
            wat::parse_str(BIG_MIN_MEMORY.replace("300", "1")).unwrap(),
            "new",
            vec![],
            ctx(TX_MAX),
            1,
        )
        .unwrap()
        .contract_address;
    exec.take_pending_writes();
    assert_ne!(a, b);
    assert!(exec.view(a, "spin_10m", vec![], ctx(TX_MAX)).is_ok());
    assert!(exec.view(b, "get", vec![], ctx(TX_MAX)).is_ok());
    assert!(exec.view(a, "fill_once", vec![], ctx(TX_MAX)).is_ok());
}

#[test]
fn the_local_module_cache_is_bounded_and_recompiles_after_eviction() {
    let limits = LocalExecutionLimits {
        max_cached_modules: 1,
        ..LocalExecutionLimits::DEFAULT
    };
    let (s, _d) = storage();
    let exec = ContractExecutor::with_local_limits(s, limits);
    let a = deploy(&exec, WAT);
    let b = exec
        .deploy(
            wat::parse_str(BIG_MIN_MEMORY.replace("300", "1")).unwrap(),
            "new",
            vec![],
            ctx(TX_MAX),
            1,
        )
        .unwrap()
        .contract_address;
    exec.take_pending_writes();
    for _ in 0..3 {
        assert!(exec.view(a, "fill_once", vec![], ctx(TX_MAX)).is_ok());
        assert!(exec.view(b, "get", vec![], ctx(TX_MAX)).is_ok());
    }
}
