//! # SUM Chain Crypto
//!
//! Cryptographic operations for SUM Chain.
//! Uses Ed25519 for signatures and Blake3 for hashing.
//!
//! All cryptographic operations use well-audited Rust crates:
//! - ed25519-dalek for Ed25519 signatures
//! - blake3 for hashing (reference implementation in Rust)
//! - x25519-dalek for X25519 key exchange (SRC-201 messaging)
//! - chacha20poly1305 for AEAD encryption (SRC-201 messaging)

pub mod keypair;
pub mod messaging;
pub mod signature;

pub use keypair::{KeyPair, PrivateKey, PublicKey};
pub use messaging::{
    blake3_derive_key, decrypt_message, ed25519_pk_to_x25519, ed25519_sk_to_x25519,
    encrypt_message, recipient_hash, x25519_ecdh, DecryptedMessage,
};
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
