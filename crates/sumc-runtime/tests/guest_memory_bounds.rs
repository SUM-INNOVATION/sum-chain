//! #279: a length read from guest memory is checked against the guest memory
//! size before the host allocates a buffer of that length.
//!
//! `read_guest_bytes` (storage key/value arguments) and `read_from_memory`
//! (the length-prefixed return value) used to allocate `len` bytes first and
//! let the read fail afterwards, so a guest could make the host allocate up to
//! 2 GiB / 4 GiB per call for a range that was always going to be refused.
//!
//! The check reproduces `MemoryView::read`'s own bounds rule and error, so the
//! fix is not consensus-visible: every call below has the outcome it had
//! before (success flag, error text, gas, return value, staged writes). The
//! `OUTCOMES` pins were taken from the unfixed executor (8744d861) and are
//! asserted here against the fixed one; only the allocation differs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sumc_runtime::{
    ContractExecutor, ContractStorage, ExecutionContext, PendingWrite, RocksDbStorage,
    RuntimeError,
};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

/// Records the largest single allocation request.
struct LargestRequest;
static LARGEST: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for LargestRequest {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LARGEST.fetch_max(l.size(), Ordering::SeqCst);
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        LARGEST.fetch_max(l.size(), Ordering::SeqCst);
        System.alloc_zeroed(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LARGEST.fetch_max(n, Ordering::SeqCst);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static ALLOCATOR: LargestRequest = LargestRequest;

/// Serialises the tests, so one test's allocations are not charged to another.
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Nothing in these calls legitimately needs more than this in one piece.
const ALLOCATION_CEILING: usize = 16 << 20;

/// One 64 KiB page. `0x1_0000` is the first byte past it.
const WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (data (i32.const 32) "\ff\ff\ff\ff")
  (data (i32.const 40) "\d4\ff\00\00")
  (data (i32.const 48) "\cd\ff\00\00")
  (data (i32.const 65533) "END")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  ;; storage_write arguments
  (func (export "huge_value") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 0x7fffffff))
    (i32.const 0))
  (func (export "huge_key") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 0x7fffffff) (i32.const 8) (i32.const 3))
    (i32.const 0))
  (func (export "value_to_end") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 65533) (i32.const 3))
    (i32.const 0))
  (func (export "value_one_past_end") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 65533) (i32.const 4))
    (i32.const 0))
  (func (export "grown_value") (param i32 i32) (result i32)
    (drop (memory.grow (i32.const 1)))
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 131069) (i32.const 3))
    (i32.const 0))
  ;; length-prefixed return values
  (func (export "huge_return") (param i32 i32) (result i32) (i32.const 32))
  (func (export "return_to_end") (param i32 i32) (result i32) (i32.const 40))
  (func (export "return_one_past_end") (param i32 i32) (result i32) (i32.const 48))
  (func (export "return_prefix_past_end") (param i32 i32) (result i32) (i32.const 65534))
  (func (export "return_negative") (param i32 i32) (result i32) (i32.const -8))
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

fn deployed() -> (ContractExecutor, Address, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let exec = ContractExecutor::new(Arc::new(ContractStorage::new(Arc::new(
        RocksDbStorage::new(db),
    ))));
    let dep = exec
        .deploy(wat::parse_str(WAT).unwrap(), "new", vec![], ctx(), 0)
        .unwrap();
    exec.take_pending_writes();
    (exec, dep.contract_address, dir)
}

/// One trap-location line exactly as the runtime writes it after the message
/// (wasmer's `RuntimeError` Display): `    at <function> (<module>[<index>]:0x<offset>)`,
/// with a decimal index and a lowercase hex offset.
fn is_trap_location(line: &str) -> bool {
    let Some(rest) = line
        .strip_prefix("    at ")
        .and_then(|r| r.strip_suffix(')'))
    else {
        return false;
    };
    let Some((function, location)) = rest.rsplit_once(" (") else {
        return false;
    };
    let Some((module_index, offset)) = location.rsplit_once("]:0x") else {
        return false;
    };
    let Some((module, index)) = module_index.rsplit_once('[') else {
        return false;
    };
    !function.is_empty()
        && !module.is_empty()
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit())
        && !offset.is_empty()
        && offset
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The message without the trap-location lines the runtime appends on some
/// platforms (Linux x86_64, not macOS arm64). Only a trailing run of lines
/// that are each a trap location is removed; any other text, including text
/// after a location line, stays and is compared.
fn without_trap_location(error: &str) -> &str {
    let mut end = error.len();
    while let Some(i) = error[..end].rfind('\n') {
        if !is_trap_location(&error[i + 1..end]) {
            break;
        }
        end = i;
    }
    &error[..end]
}

#[test]
fn only_trailing_trap_locations_are_removed_from_an_error() {
    const MSG: &str = "RuntimeError: guest memory read: memory access out of bounds";
    // As recorded on Linux x86_64 release (huge_value, huge_key).
    for at in ["<module>[3]:0x13e", "<module>[4]:0x151"] {
        let e = format!("{MSG}\n    at <unnamed> ({at})");
        assert_eq!(without_trap_location(&e), MSG);
    }
    let two = format!("{MSG}\n    at <unnamed> (<module>[6]:0x173)\n    at run (<module>[0]:0x9)");
    assert_eq!(without_trap_location(&two), MSG);
    assert_eq!(without_trap_location(MSG), MSG);
    // Anything that is not a trap location is kept, and so still compared.
    for kept in [
        format!("{MSG}\n    at <unnamed> (<module>[3]:0x13e)\ncaused by: something else"),
        format!("{MSG}\n    at an unrelated explanation"),
        format!("{MSG}\n    at <unnamed> (<module>[3]:0x13E)"),
        format!("{MSG}\n    at <unnamed> (<module>[x]:0x13e)"),
        format!("{MSG}\n    at <unnamed> (<module>[3]:13e)"),
        format!("{MSG}\n    at  (<module>[3]:0x13e)"),
        format!("{MSG}\n  at <unnamed> (<module>[3]:0x13e)"),
        format!("{MSG}\n    at <unnamed> (<module>[3]:0x13e) "),
    ] {
        assert_eq!(without_trap_location(&kept), kept);
    }
    // Only the trailing location goes; a location-like line inside the
    // message that is not one stays.
    let inner =
        format!("{MSG}\n    at an unrelated explanation\n    at <unnamed> (<module>[3]:0x13e)");
    assert_eq!(
        without_trap_location(&inner),
        format!("{MSG}\n    at an unrelated explanation")
    );
}

/// Everything a call reports that execution could act on, as text.
fn outcome(exec: &ContractExecutor, addr: Address, method: &str) -> String {
    let r = exec.call(addr, method, vec![], ctx());
    let writes: Vec<String> = exec
        .take_pending_writes()
        .into_iter()
        .filter_map(|w| match w {
            PendingWrite::Storage { key, value, .. } => {
                Some(format!("{}={:?}", hex::encode(key), value.map(hex::encode)))
            }
            _ => None,
        })
        .collect();
    match r {
        Ok(r) => format!(
            "ok success={} gas={} error={:?} ret_len={} ret_blake3={} writes={:?}",
            r.success,
            r.gas_used,
            r.error.as_deref().map(without_trap_location),
            r.return_value.len(),
            &blake3::hash(&r.return_value).to_hex()[..16],
            writes
        ),
        Err(e) => format!("err {e:?} writes={writes:?}"),
    }
}

/// Outcomes of the unfixed executor (8744d861), method by method.
const OUTCOMES: &[(&str, &str)] = &[
    ("huge_value", "ok success=false gas=1000 error=Some(\"RuntimeError: guest memory read: memory access out of bounds\") ret_len=0 ret_blake3=af1349b9f5f9a1a6 writes=[]"),
    ("huge_key", "ok success=false gas=1000 error=Some(\"RuntimeError: guest memory read: memory access out of bounds\") ret_len=0 ret_blake3=af1349b9f5f9a1a6 writes=[]"),
    ("value_to_end", "ok success=true gas=6200 error=None ret_len=0 ret_blake3=af1349b9f5f9a1a6 writes=[\"6b=Some(\\\"454e44\\\")\"]"),
    ("value_one_past_end", "ok success=false gas=1000 error=Some(\"RuntimeError: guest memory read: memory access out of bounds\") ret_len=0 ret_blake3=af1349b9f5f9a1a6 writes=[]"),
    ("grown_value", "ok success=true gas=6200 error=None ret_len=0 ret_blake3=af1349b9f5f9a1a6 writes=[\"6b=Some(\\\"000000\\\")\"]"),
    ("huge_return", "err MemoryAccess(\"memory access out of bounds\") writes=[]"),
    ("return_to_end", "ok success=true gas=1000 error=None ret_len=65492 ret_blake3=84a1616520b65fad writes=[]"),
    ("return_one_past_end", "err MemoryAccess(\"memory access out of bounds\") writes=[]"),
    ("return_prefix_past_end", "err MemoryAccess(\"memory access out of bounds\") writes=[]"),
    ("return_negative", "err MemoryAccess(\"memory access out of bounds\") writes=[]"),
];

#[test]
fn every_outcome_is_the_unfixed_executors_outcome() {
    let _g = serial();
    let got: Vec<(&str, String)> = OUTCOMES
        .iter()
        .map(|(method, _)| {
            let (exec, addr, _d) = deployed();
            let o = outcome(&exec, addr, method);
            println!("    (\"{method}\", {o:?}),");
            (*method, o)
        })
        .collect();
    for ((method, got), (_, want)) in got.iter().zip(OUTCOMES) {
        assert_eq!(got, want, "{method}");
    }
}

#[test]
fn an_out_of_bounds_argument_length_allocates_nothing_of_that_size() {
    let _g = serial();
    for method in ["huge_value", "huge_key"] {
        let (exec, addr, _d) = deployed();
        LARGEST.store(0, Ordering::SeqCst);
        let r = exec.call(addr, method, vec![], ctx()).unwrap();
        let largest = LARGEST.load(Ordering::SeqCst);
        assert!(!r.success, "{method} still traps");
        assert_eq!(
            r.error.as_deref().map(without_trap_location),
            Some("RuntimeError: guest memory read: memory access out of bounds"),
            "{method}"
        );
        assert!(
            largest < ALLOCATION_CEILING,
            "{method}: largest host allocation {largest} bytes"
        );
    }
}

#[test]
fn an_out_of_bounds_return_length_allocates_nothing_of_that_size() {
    let _g = serial();
    for method in ["huge_return", "return_one_past_end"] {
        let (exec, addr, _d) = deployed();
        LARGEST.store(0, Ordering::SeqCst);
        let r = exec.call(addr, method, vec![], ctx());
        let largest = LARGEST.load(Ordering::SeqCst);
        assert!(
            matches!(&r, Err(RuntimeError::MemoryAccess(m)) if m == "memory access out of bounds"),
            "{method}: {r:?}"
        );
        assert!(
            largest < ALLOCATION_CEILING,
            "{method}: largest host allocation {largest} bytes"
        );
    }
}

#[test]
fn ranges_ending_exactly_at_the_memory_end_are_still_read() {
    let _g = serial();
    let (exec, addr, _d) = deployed();
    let r = exec.call(addr, "value_to_end", vec![], ctx()).unwrap();
    assert!(r.success, "{:?}", r.error);
    let (exec, addr, _d) = deployed();
    let r = exec.call(addr, "grown_value", vec![], ctx()).unwrap();
    assert!(r.success, "the bound follows memory growth: {:?}", r.error);
    let (exec, addr, _d) = deployed();
    let r = exec.call(addr, "return_to_end", vec![], ctx()).unwrap();
    assert!(r.success);
    assert_eq!(r.return_value.len(), 0xffd4, "prefix at 40, payload to the end");
}
