//! NFT-related errors

use thiserror::Error;

/// NFT operation errors
#[derive(Debug, Error)]
pub enum NftError {
    #[error("Collection not found: {0}")]
    CollectionNotFound(String),

    #[error("Token not found: collection={collection}, token={token}")]
    TokenNotFound { collection: String, token: u64 },

    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    #[error("Token already exists: collection={collection}, token={token}")]
    TokenAlreadyExists { collection: String, token: u64 },

    #[error("Collection already exists: {0}")]
    CollectionAlreadyExists(String),

    #[error("Cannot transfer: {0}")]
    TransferNotAllowed(String),

    #[error("Cannot burn: {0}")]
    BurnNotAllowed(String),

    #[error("Metadata update not allowed for this collection")]
    MetadataUpdateNotAllowed,

    #[error("Invalid collection config: {0}")]
    InvalidConfig(String),

    #[error("Max supply reached: {max}")]
    MaxSupplyReached { max: u64 },

    #[error("Royalty exceeds maximum: {rate}% > {max}%")]
    RoyaltyTooHigh { rate: u16, max: u16 },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Token is locked")]
    TokenLocked,
}

/// Result type for NFT operations
pub type Result<T> = std::result::Result<T, NftError>;
