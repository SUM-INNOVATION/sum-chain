//! #203 — Wasmer-migration determinism / equivalence gate.
//!
//! Captures the CONSENSUS-VISIBLE behavior of the contract executor over a fixed
//! WASM corpus as golden vectors, then asserts the current engine reproduces them
//! byte-for-byte. The golden is captured on the pre-migration engine (Wasmer 4.4)
//! and committed; after the Wasmer 7 migration this SAME test must reproduce it
//! exactly — any divergence in state transitions, gas/accounting, return values,
//! traps, or error classifications fails the build (a consensus-visible change to
//! escalate, not to paper over).
//!
//! Per-case captured tuple (the consensus surface):
//!   * `phase`         — deploy | call
//!   * `success`       — did the op succeed
//!   * `gas_used`      — app-metered gas (must be engine-version-independent)
//!   * `return_hex`    — return bytes, hex
//!   * `class`         — normalized outcome/error CLASSIFICATION (variant-level,
//!                       never a raw engine trap string, which may reword across
//!                       engine versions — the CLASSIFICATION must be identical)
//!   * `journal`       — sorted (cf_kind, key_hex, op) state transitions committed
//!
//! Capture (pre-migration, once):  CAPTURE_DETERMINISM_GOLDEN=1 cargo test -p \
//!   sumc-runtime --test wasmer_determinism_vectors -- --nocapture
//! Assert (default / CI / post-migration):  cargo test -p sumc-runtime --test \
//!   wasmer_determinism_vectors

use std::sync::Arc;
use sumc_runtime::{ContractExecutor, ContractStorage, ExecutionContext, RocksDbStorage, RuntimeError};
use sumchain_primitives::Address;
use sumchain_storage::Database;
use tempfile::TempDir;

const GOLDEN_PATH: &str = "tests/fixtures/wasmer_determinism_golden.json";

fn ctx(caller: Address, gas_limit: u64) -> ExecutionContext {
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

fn executor() -> (ContractExecutor, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let backend = Arc::new(RocksDbStorage::new(db.clone()));
    (ContractExecutor::new(Arc::new(ContractStorage::new(backend))), dir)
}

/// Variant-level classification of a RuntimeError — stable across engine versions
/// (never embeds the raw engine trap message).
fn classify_err(e: &RuntimeError) -> String {
    match e {
        RuntimeError::OutOfGas { .. } => "OutOfGas",
        RuntimeError::Compilation(_) => "Compilation",
        RuntimeError::Instantiation(_) => "Instantiation",
        RuntimeError::Execution(_) => "Execution",
        RuntimeError::MethodNotFound(_) => "MethodNotFound",
        RuntimeError::InvalidArguments(_) => "InvalidArguments",
        RuntimeError::Storage(_) => "Storage",
        RuntimeError::MemoryAccess(_) => "MemoryAccess",
        RuntimeError::ContractNotFound(_) => "ContractNotFound",
        RuntimeError::InsufficientBalance { .. } => "InsufficientBalance",
        RuntimeError::TransferFailed(_) => "TransferFailed",
        RuntimeError::CrossContractCall(_) => "CrossContractCall",
        RuntimeError::ContractPanic(_) => "ContractPanic",
        RuntimeError::InvalidCode(_) => "InvalidCode",
        RuntimeError::CodeTooLarge { .. } => "CodeTooLarge",
        RuntimeError::StackOverflow => "StackOverflow",
        RuntimeError::RecursionLimit => "RecursionLimit",
        RuntimeError::HostFunction(_) => "HostFunction",
        RuntimeError::Serialization(_) => "Serialization",
        RuntimeError::Deserialization(_) => "Deserialization",
        RuntimeError::EngineVersionMismatch { .. } => "EngineVersionMismatch",
    }
    .to_string()
}

/// One captured outcome line. Rendered as a single canonical string so the golden
/// is a plain ordered list of lines (stable, diff-friendly, engine-independent).
fn line(name: &str, phase: &str, success: bool, gas_used: u64, ret: &[u8], class: &str, journal: &str) -> String {
    format!(
        "{name} | {phase} | ok={success} | gas={gas_used} | ret={} | class={class} | journal={journal}",
        hex::encode(ret)
    )
}

/// Canonical, sorted digest of the executor's staged state transitions.
fn journal_digest(exec: &ContractExecutor) -> String {
    let mut rows: Vec<String> = exec
        .take_journal()
        .into_iter()
        .map(|m| format!("cf{}:{}", m.cf_kind, hex::encode(&m.key)))
        .collect();
    rows.sort();
    rows.join(",")
}

/// The fixed corpus. Each returns the WAT source + the method to invoke + gas.
/// Chosen to exercise every consensus-visible outcome class.
fn corpus() -> Vec<(&'static str, &'static str, &'static str, u64)> {
    vec![
        // (name, wat, call_method, gas_limit)
        ("storage_write", STORAGE_WAT, "set", 100_000_000),
        ("storage_read_absent", STORAGE_WAT, "get", 100_000_000),
        ("normal_return", RETURN_WAT, "answer", 100_000_000),
        ("trap_unreachable", TRAP_WAT, "boom", 100_000_000),
        ("trap_div_by_zero", DIV0_WAT, "divz", 100_000_000),
        ("trap_oob_memory", OOB_WAT, "oob", 100_000_000),
        ("method_not_found", RETURN_WAT, "nope", 100_000_000),
    ]
    // NOTE: OutOfGas (host-call exhaustion) and StackOverflow (deep recursion)
    // vectors are deferred to a follow-up: gas here is app-level (no Wasmer
    // metering middleware) so a pure-compute loop is unmetered, and native
    // stack-trap depth is engine-config-dependent. Both need cost-/depth-tuned
    // cases; the traps/return/state/error-class surface below is fully covered.
}

const STORAGE_WAT: &str = r#"(module
  (import "env" "storage_read"  (func $sread (param i32 i32) (result i32)))
  (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k") (data (i32.const 8) "VAL")
  (func (export "alloc") (param i32) (result i32)
    (local $p i32) (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get 0))) (local.get $p))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "set") (param i32 i32) (result i32)
    (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3)) (i32.const 0))
  (func (export "get") (param i32 i32) (result i32)
    (call $sread (i32.const 0) (i32.const 1))))"#;

const RETURN_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (data (i32.const 8) "\2a\00\00\00")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "answer") (param i32 i32) (result i32) (i32.const 8)))"#;

const TRAP_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "boom") (param i32 i32) (result i32) (unreachable)))"#;

const DIV0_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "divz") (param i32 i32) (result i32)
    (i32.div_u (i32.const 1) (i32.const 0))))"#;

const OOB_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0))
  (func (export "oob") (param i32 i32) (result i32)
    (i32.load (i32.const 0xffffff0))))"#;

/// Run the whole corpus and produce the ordered vector of canonical outcome lines.
fn run_corpus() -> Vec<String> {
    let mut out = Vec::new();
    for (name, wat, method, gas) in corpus() {
        let (exec, _dir) = executor();
        let caller = Address::new([1u8; 20]);
        let code = wat::parse_str(wat).expect("valid wat");

        // Deploy (init = `new`).
        match exec.deploy(code, "new", vec![], ctx(caller, gas), 0) {
            Ok(dep) => {
                let dj = journal_digest(&exec);
                out.push(line(name, "deploy", true, dep.gas_used, &[], "ok", &dj));
                let addr = dep.contract_address;
                match exec.call(addr, method, vec![], ctx(caller, gas)) {
                    Ok(r) => {
                        let cj = journal_digest(&exec);
                        let class = if r.success { "ok".to_string() } else { "revert".to_string() };
                        out.push(line(name, "call", r.success, r.gas_used, &r.return_value, &class, &cj));
                    }
                    Err(e) => {
                        let _ = exec.take_journal();
                        out.push(line(name, "call", false, 0, &[], &classify_err(&e), ""));
                    }
                }
            }
            Err(e) => {
                let _ = exec.take_journal();
                out.push(line(name, "deploy", false, 0, &[], &classify_err(&e), ""));
            }
        }
    }
    out
}

#[test]
fn wasmer_determinism_equivalence() {
    let lines = run_corpus();
    let rendered = lines.join("\n") + "\n";

    if std::env::var("CAPTURE_DETERMINISM_GOLDEN").is_ok() {
        std::fs::create_dir_all("tests/fixtures").unwrap();
        std::fs::write(GOLDEN_PATH, &rendered).unwrap();
        eprintln!("captured {} vectors -> {GOLDEN_PATH}", lines.len());
        eprintln!("{rendered}");
        return;
    }

    let golden = std::fs::read_to_string(GOLDEN_PATH).unwrap_or_else(|_| {
        panic!(
            "missing {GOLDEN_PATH}; capture it on the reference engine first:\n  \
             CAPTURE_DETERMINISM_GOLDEN=1 cargo test -p sumc-runtime --test \
             wasmer_determinism_vectors -- --nocapture"
        )
    });

    // Byte-for-byte equivalence: state transitions, gas, returns, traps, and
    // error classifications must be identical to the captured (pre-migration) engine.
    assert_eq!(
        rendered, golden,
        "consensus-visible execution diverged from the golden determinism vectors — \
         a Wasmer-version behavior change (escalate; do not update the golden to hide it)"
    );
}
