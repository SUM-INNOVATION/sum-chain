//! Ed25519 key pair management for SUM Chain.
//!
//! Provides secure key generation, serialization, and address derivation.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sumchain_primitives::Address;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// Ed25519 private key (32 bytes)
/// Zeroized on drop for security
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PrivateKey(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidPrivateKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(PrivateKey(bytes))
    }

    /// Get raw bytes (use carefully - exposes secret)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the public key
    pub fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        let verifying_key = signing_key.verifying_key();
        PublicKey(verifying_key.to_bytes())
    }

    /// Get the ed25519-dalek SigningKey
    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidPublicKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);

        // Validate it's a valid Ed25519 public key
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(PublicKey(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the address from this public key
    pub fn address(&self) -> Address {
        Address::from_public_key(&self.0)
    }

    /// Get the ed25519-dalek VerifyingKey
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Encode as base58
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decode from base58
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_slice(&bytes)
    }

    /// Encode as hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Decode from hex
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_slice(&bytes)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Ed25519 key pair (private + public key)
pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair using OS randomness
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let private = PrivateKey(signing_key.to_bytes());
        let public = PublicKey(signing_key.verifying_key().to_bytes());

        KeyPair { private, public }
    }

    /// Create from an existing private key
    pub fn from_private_key(private: PrivateKey) -> Self {
        let public = private.public_key();
        KeyPair { private, public }
    }

    /// Create from raw private key bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let private = PrivateKey::from_bytes(bytes);
        Self::from_private_key(private)
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get the address derived from the public key
    pub fn address(&self) -> Address {
        self.public.address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        // Different keypairs should have different public keys
        assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }

    #[test]
    fn test_private_to_public_deterministic() {
        let kp = KeyPair::generate();
        let private_bytes = *kp.private_key().as_bytes();

        let kp2 = KeyPair::from_bytes(private_bytes);

        assert_eq!(kp.public_key().as_bytes(), kp2.public_key().as_bytes());
    }

    #[test]
    fn test_public_key_base58_roundtrip() {
        let kp = KeyPair::generate();
        let b58 = kp.public_key().to_base58();
        let recovered = PublicKey::from_base58(&b58).unwrap();
        assert_eq!(kp.public_key(), &recovered);
    }

    #[test]
    fn test_address_derivation() {
        let kp = KeyPair::generate();
        let addr1 = kp.address();
        let addr2 = kp.public_key().address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_invalid_public_key() {
        // Wrong size is not a valid Ed25519 public key
        let result = PublicKey::from_slice(&[1u8; 31]);
        assert!(result.is_err());
    }
}
