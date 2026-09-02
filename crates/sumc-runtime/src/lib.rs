//! # SUMC Runtime
//!
//! WebAssembly runtime for SUM Chain smart contracts.
//! Provides sandboxed execution with gas metering, host functions,
//! and contract storage management.

pub mod error;
pub mod executor;
pub mod gas;
pub mod host;
pub mod memory;
pub mod storage;
pub mod types;

pub use error::{RuntimeError, Result};
pub use executor::{ContractExecutor, ExecutionContext, ExecutionResult};
pub use gas::{Gas, GasCosts, GasMeter};
pub use storage::{ContractStorage, MemoryStorage, RocksDbStorage};
pub use types::*;

/// Stable identity of the WASM execution engine + backend + ABI major.
///
/// Consensus-critical (#203): contract execution is only *equivalent* across
/// nodes that share this identity. It is the discriminator for mixed-version
/// refusal — a node whose engine identity differs from the network-agreed value
/// must refuse to execute contracts rather than risk diverging and forking the
/// chain. Bump it whenever the engine, its backend, or any determinism-affecting
/// configuration changes (this migration moved it from `wasmer-singlepass-4` to
/// `wasmer-singlepass-7`; the committed determinism golden proves the two produce
/// byte-identical consensus output for the covered corpus, but the identity still
/// changes so operators cannot silently run a mix that has NOT been proven equal).
pub const ENGINE_IDENTITY: &str = "wasmer-singlepass-7";

/// Mixed-version refusal primitive (#203).
///
/// Returns `Ok(())` iff `expected` matches this binary's [`ENGINE_IDENTITY`],
/// otherwise [`RuntimeError::EngineVersionMismatch`]. This is the node-local
/// mechanism; binding `expected` to a *network-agreed* value (so every validator
/// enforces the same engine before contracts activate) is a consensus-policy
/// decision deferred to owner ratification — it is intentionally NOT wired into
/// `ChainParams`/genesis here. Call this before enabling contract execution.
pub fn verify_engine(expected: &str) -> Result<()> {
    if expected == ENGINE_IDENTITY {
        Ok(())
    } else {
        Err(RuntimeError::EngineVersionMismatch {
            expected: expected.to_string(),
            found: ENGINE_IDENTITY.to_string(),
        })
    }
}
