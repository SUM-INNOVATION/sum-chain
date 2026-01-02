//! Runtime error types.

use thiserror::Error;

/// Runtime errors for contract execution
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("Out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("WASM compilation error: {0}")]
    Compilation(String),

    #[error("WASM instantiation error: {0}")]
    Instantiation(String),

    #[error("WASM execution error: {0}")]
    Execution(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Memory access error: {0}")]
    MemoryAccess(String),

    #[error("Contract not found: {0}")]
    ContractNotFound(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    #[error("Cross-contract call failed: {0}")]
    CrossContractCall(String),

    #[error("Contract panic: {0}")]
    ContractPanic(String),

    #[error("Invalid contract code: {0}")]
    InvalidCode(String),

    #[error("Code size exceeds limit: {size} > {limit}")]
    CodeTooLarge { size: usize, limit: usize },

    #[error("Stack overflow")]
    StackOverflow,

    #[error("Recursion limit exceeded")]
    RecursionLimit,

    #[error("Host function error: {0}")]
    HostFunction(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

impl From<wasmer::CompileError> for RuntimeError {
    fn from(e: wasmer::CompileError) -> Self {
        RuntimeError::Compilation(e.to_string())
    }
}

impl From<wasmer::InstantiationError> for RuntimeError {
    fn from(e: wasmer::InstantiationError) -> Self {
        RuntimeError::Instantiation(e.to_string())
    }
}

impl From<wasmer::RuntimeError> for RuntimeError {
    fn from(e: wasmer::RuntimeError) -> Self {
        RuntimeError::Execution(e.to_string())
    }
}

impl From<bincode::Error> for RuntimeError {
    fn from(e: bincode::Error) -> Self {
        RuntimeError::Serialization(e.to_string())
    }
}
