//! Bridge error types.

use thiserror::Error;

/// Bridge operation errors
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("Ethereum RPC error: {0}")]
    EthereumRpc(String),

    #[error("Contract call failed: {0}")]
    ContractCall(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Insufficient signatures: got {got}, need {required}")]
    InsufficientSignatures { got: usize, required: usize },

    #[error("Deposit not found: {0}")]
    DepositNotFound(String),

    #[error("Withdrawal not found: {0}")]
    WithdrawalNotFound(String),

    #[error("Token not supported: {0}")]
    TokenNotSupported(String),

    #[error("Amount too small: minimum {minimum}, got {got}")]
    AmountTooSmall { minimum: u128, got: u128 },

    #[error("Amount too large: maximum {maximum}, got {got}")]
    AmountTooLarge { maximum: u128, got: u128 },

    #[error("Bridge paused")]
    BridgePaused,

    #[error("Invalid Ethereum address: {0}")]
    InvalidEthAddress(String),

    #[error("Invalid SUM address: {0}")]
    InvalidSumAddress(String),

    #[error("Duplicate deposit: {0}")]
    DuplicateDeposit(String),

    #[error("Duplicate withdrawal: {0}")]
    DuplicateWithdrawal(String),

    #[error("Withdrawal already exists")]
    WithdrawalAlreadyExists,

    #[error("Unauthorized validator")]
    UnauthorizedValidator,

    #[error("Invalid amount")]
    InvalidAmount,

    #[error("Withdrawals disabled for this token")]
    WithdrawalsDisabled,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Timeout waiting for confirmations")]
    Timeout,

    #[error("Chain reorg detected")]
    ChainReorg,
}

pub type Result<T> = std::result::Result<T, BridgeError>;

// The provider is now a minimal reqwest JSON-RPC client (#206), so transport
// failures arrive as reqwest errors rather than a provider-crate error type.
impl From<reqwest::Error> for BridgeError {
    fn from(e: reqwest::Error) -> Self {
        BridgeError::EthereumRpc(e.to_string())
    }
}

// ABI encode/decode failures surface as contract-call errors.
impl From<ethabi::Error> for BridgeError {
    fn from(e: ethabi::Error) -> Self {
        BridgeError::ContractCall(e.to_string())
    }
}
