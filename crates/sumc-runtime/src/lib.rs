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
