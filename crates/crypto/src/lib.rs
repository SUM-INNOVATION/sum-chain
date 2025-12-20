//! # SUM Chain Crypto
//!
//! Cryptographic operations for SUM Chain.
//! Uses Ed25519 for signatures and Blake3 for hashing.
//!
//! All cryptographic operations use well-audited Rust crates:
//! - ed25519-dalek for Ed25519 signatures
//! - blake3 for hashing (reference implementation in Rust)

pub mod keypair;
pub mod signature;

pub use keypair::{KeyPair, PrivateKey, PublicKey};
pub use signature::{sign, verify, verify_bytes, Signature};

use thiserror::Error;

/// Cryptographic errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenFailed(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
