//! Error types for SUMC contracts.

use thiserror::Error;

/// Contract error type
#[derive(Debug, Error)]
pub enum Error {
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Overflow")]
    Overflow,

    #[error("Underflow")]
    Underflow,

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    #[error("Paused")]
    Paused,

    #[error("Not paused")]
    NotPaused,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Custom error: {0}")]
    Custom(String),
}

impl Error {
    /// Create a custom error
    pub fn custom(msg: impl Into<String>) -> Self {
        Error::Custom(msg.into())
    }

    /// Create an unauthorized error
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Error::Unauthorized(msg.into())
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }

    /// Create an already exists error
    pub fn already_exists(msg: impl Into<String>) -> Self {
        Error::AlreadyExists(msg.into())
    }

    /// Create an invalid argument error
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Error::InvalidArgument(msg.into())
    }
}

/// Result type for contract methods
pub type Result<T> = std::result::Result<T, Error>;
