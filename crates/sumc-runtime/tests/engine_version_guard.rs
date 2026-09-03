//! #203 — mixed-version refusal gate.
//!
//! Contract execution is only consensus-equivalent across nodes that run the
//! same WASM engine identity. This proves the node-local refusal primitive:
//! a caller that expects a different engine identity is refused, so a node
//! running a divergent engine cannot execute contracts and fork the chain.
//!
//! Network-wide enforcement (binding the expected identity to a ratified genesis
//! parameter so every validator agrees) is a consensus-policy decision left to
//! owner ratification and is intentionally NOT wired here — this gate covers the
//! mechanism, not the policy binding.

use sumc_runtime::{verify_engine, RuntimeError, ENGINE_IDENTITY};

#[test]
fn engine_identity_is_the_migration_target() {
    // The migration moved the engine identity from the 4.x line to the 5.x line
    // (5.0.6 = last MIT Singlepass; 6.0.0+ is BUSL-1.1). If this ever silently
    // reverts, mixed-version refusal would compare against the wrong baseline.
    assert_eq!(ENGINE_IDENTITY, "wasmer-singlepass-5");
}

#[test]
fn matching_engine_is_accepted() {
    verify_engine(ENGINE_IDENTITY).expect("matching engine identity must be accepted");
}

#[test]
fn divergent_engine_is_refused() {
    // A node still on the pre-migration engine (or any other) must be refused.
    let err = verify_engine("wasmer-singlepass-4")
        .expect_err("a divergent engine identity must be refused");
    match err {
        RuntimeError::EngineVersionMismatch { expected, found } => {
            assert_eq!(expected, "wasmer-singlepass-4");
            assert_eq!(found, ENGINE_IDENTITY);
        }
        other => panic!("expected EngineVersionMismatch, got {other:?}"),
    }
}

#[test]
fn empty_or_garbage_engine_is_refused() {
    assert!(verify_engine("").is_err());
    assert!(verify_engine("wasmer").is_err());
    assert!(verify_engine("wasmer-singlepass-8").is_err());
    assert!(verify_engine("cranelift-7").is_err());
}
