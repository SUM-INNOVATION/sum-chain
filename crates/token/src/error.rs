//! SRC-20 Token error types

use thiserror::Error;

/// Result type for token operations
pub type Result<T> = std::result::Result<T, TokenError>;

/// Errors that can occur during token operations
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found: {0}")]
    TokenNotFound(String),

    #[error("Token already exists: {0}")]
    TokenAlreadyExists(String),

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("Insufficient allowance: have {have}, need {need}")]
    InsufficientAllowance { have: u128, need: u128 },

    #[error("Invalid token name: {0}")]
    InvalidName(String),

    #[error("Invalid token symbol: {0}")]
    InvalidSymbol(String),

    #[error("Invalid decimals: {0} (max {max})", max = crate::MAX_DECIMALS)]
    InvalidDecimals(u8),

    #[error("Token is paused")]
    TokenPaused,

    #[error("Token is not pausable")]
    NotPausable,

    #[error("Token is not mintable")]
    NotMintable,

    #[error("Token is not burnable")]
    NotBurnable,

    #[error("Exceeds max supply: would have {would_have}, max is {max_supply}")]
    ExceedsMaxSupply { would_have: u128, max_supply: u128 },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Cannot transfer to zero address")]
    TransferToZeroAddress,

    #[error("Cannot approve zero address")]
    ApproveZeroAddress,

    #[error("Self-transfer not allowed")]
    SelfTransfer,

    #[error("Overflow in token calculation")]
    Overflow,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}
