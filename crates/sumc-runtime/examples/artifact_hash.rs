//! Compiled-artifact harness for dependency changes under the engine (#306).
//!
//! Compiles a WAT corpus with Singlepass and writes every
//! `Module::serialize()` output to `<out-dir>/<NNN>-<config>.bin`, plus
//! `<out-dir>/manifest.txt` with one line per module and configuration (id,
//! wasm hash, artifact length and blake3). The manifest is also printed.
//!
//! `scripts/compare-wasmer-artifacts.sh` builds this example at two revisions
//! and requires the outputs to be byte-identical; see the #306 section of
//! docs/security/DEPENDENCY-AUDIT.md.
//!
//! Corpus, in order: the built-in modules below (opcode breadth the tests do
//! not need), then every raw string literal (`r#"..."#`) that parses as a WAT
//! module in the `*.rs` files directly under each `<corpus-dir>`, files sorted
//! by path. Those are the modules the runtime, state, consensus and RPC tests
//! deploy. A raw string that starts with `(module` but does not parse (a
//! `format!` template) is listed as skipped.
//!
//! Configurations:
//!   * `singlepass`: `Singlepass::default()`, the block executor's engine
//!     (`ContractExecutor::new`).
//!   * `metering`: Singlepass with wasmer's `Metering` middleware, one point
//!     per operator, at `LocalExecutionLimits::DEFAULT.fuel` (the public part
//!     of the local executor's engine).
//!
//! Usage (from the directory the corpus paths are relative to):
//!   cargo run --release --locked -p sumc-runtime --example artifact_hash -- \
//!     <out-dir> [<corpus-dir>...]
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sumc_runtime::LocalExecutionLimits;
use wasmer::{sys::EngineBuilder, wasmparser::Operator, CompilerConfig, Module, Store};
use wasmer_compiler_singlepass::Singlepass;
use wasmer_middlewares::Metering;

const BUILTIN: &[(&str, &str)] = &[
    (
        "builtin:loop",
        r#"(module (func (export "spin") (param i32 i32) (result i32) (local $i i32)
    (loop $l (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 1000)))) (i32.const 0)))"#,
    ),
    (
        "builtin:i64",
        r#"(module (func (export "mix") (param i64 i64) (result i64)
    (i64.xor (i64.rotl (i64.mul (local.get 0) (local.get 1)) (i64.const 13))
             (i64.add (i64.popcnt (local.get 0)) (i64.rem_s (local.get 1) (i64.const 7))))))"#,
    ),
    (
        "builtin:float",
        r#"(module (func (export "f") (param f64 f32) (result f64)
    (f64.add (f64.sqrt (f64.abs (local.get 0)))
             (f64.promote_f32 (f32.mul (local.get 1) (f32.const 1.5))))))"#,
    ),
    (
        "builtin:table",
        r#"(module
  (type $t (func (param i32) (result i32)))
  (table 2 funcref) (elem (i32.const 0) $inc $dbl)
  (func $inc (type $t) (i32.add (local.get 0) (i32.const 1)))
  (func $dbl (type $t) (i32.mul (local.get 0) (i32.const 2)))
  (func (export "dispatch") (param i32 i32) (result i32)
    (call_indirect (type $t) (local.get 1) (local.get 0))))"#,
    ),
    (
        "builtin:bulk",
        r#"(module (memory (export "memory") 1)
  (func (export "fillcopy") (param i32 i32) (result i32)
    (memory.fill (i32.const 0) (i32.const 7) (local.get 0))
    (memory.copy (i32.const 4096) (i32.const 0) (local.get 0))
    (i32.load8_u (i32.const 4096))))"#,
    ),
];

/// Every `r#"..."#` literal in `src`, with the line it starts on.
fn raw_strings(src: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(i) = src[at..].find("r#\"") {
        let open = at + i;
        let start = open + 3;
        let Some(len) = src[start..].find("\"#") else {
            break;
        };
        found.push((
            src[..open].matches('\n').count() + 1,
            &src[start..start + len],
        ));
        at = start + len + 2;
    }
    found
}

fn engine(metered: bool) -> wasmer::Engine {
    let mut compiler = Singlepass::default();
    if metered {
        let fuel = LocalExecutionLimits::DEFAULT.fuel;
        compiler.push_middleware(Arc::new(Metering::new(fuel, |_: &Operator| 1u64)));
    }
    EngineBuilder::new(compiler).engine().into()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out = PathBuf::from(
        args.next()
            .expect("usage: artifact_hash <out-dir> [<corpus-dir>...]"),
    );
    std::fs::create_dir_all(&out).unwrap();

    let mut corpus: Vec<(String, String)> = BUILTIN
        .iter()
        .map(|(id, wat)| (id.to_string(), wat.to_string()))
        .collect();
    let mut manifest = String::new();
    let mut skipped = Vec::new();
    for dir in args {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{dir}: {e}"))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        files.sort();
        for file in files {
            let src = std::fs::read_to_string(&file).unwrap();
            for (line, text) in raw_strings(&src) {
                if !text.trim_start().starts_with("(module") {
                    continue;
                }
                let id = format!("{}:{line}", file.display());
                match wat::parse_str(text) {
                    Ok(_) => corpus.push((id, text.to_string())),
                    Err(_) => skipped.push(id),
                }
            }
        }
    }

    writeln!(manifest, "# wasmer Module::serialize() artifacts (#306)").unwrap();
    writeln!(
        manifest,
        "# host {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    )
    .unwrap();
    writeln!(
        manifest,
        "# {} modules x 2 configurations, {} skipped",
        corpus.len(),
        skipped.len()
    )
    .unwrap();
    for id in &skipped {
        writeln!(manifest, "skipped {id} (raw string is not WAT on its own)").unwrap();
    }
    for (n, (id, wat)) in corpus.iter().enumerate() {
        let wasm = wat::parse_str(wat).unwrap();
        let wasm_hash = blake3::hash(&wasm).to_hex();
        for (config, metered) in [("singlepass", false), ("metering", true)] {
            let store = Store::new(engine(metered));
            let line = match Module::new(&store, &wasm) {
                Ok(module) => {
                    let bytes = module.serialize().unwrap();
                    write_bin(&out, n, config, &bytes);
                    format!("len={} blake3={}", bytes.len(), blake3::hash(&bytes))
                }
                Err(e) => format!("compile-error={}", e.to_string().replace('\n', " ")),
            };
            writeln!(
                manifest,
                "{n:03} {config:10} {id} wasm={} {line}",
                &wasm_hash[..16]
            )
            .unwrap();
        }
    }
    std::fs::write(out.join("manifest.txt"), &manifest).unwrap();
    print!("{manifest}");
}

fn write_bin(out: &Path, n: usize, config: &str, bytes: &[u8]) {
    std::fs::write(out.join(format!("{n:03}-{config}.bin")), bytes).unwrap();
}
