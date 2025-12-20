//! Ed25519 signature operations for SUM Chain.
//!
//! Provides signing and verification of messages using Ed25519.

use ed25519_dalek::{Signature as DalekSignature, Signer, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_big_array::BigArray;

use crate::{CryptoError, PrivateKey, PublicKey, Result};

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

// Custom serde implementation for the newtype wrapper
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BigArray::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 64] = BigArray::deserialize(deserializer)?;
        Ok(Signature(bytes))
    }
}

impl Signature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Signature(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to array
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    /// Encode as hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Decode from hex
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidSignature)?;
        Self::from_slice(&bytes)
    }
}

impl From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Sign a message with a private key
pub fn sign(message: &[u8], private_key: &PrivateKey) -> Signature {
    let signing_key = private_key.signing_key();
    let signature = signing_key.sign(message);
    Signature(signature.to_bytes())
}

/// Verify a signature against a message and public key
pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<()> {
    let verifying_key = public_key.verifying_key()?;
    let dalek_sig =
        DalekSignature::from_bytes(&signature.0);

    verifying_key
        .verify(message, &dalek_sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Verify a signature using raw bytes (convenience function)
pub fn verify_bytes(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<()> {
    let sig = Signature::from_bytes(*signature);
    let pubkey = PublicKey::from_slice(public_key)?;
    verify(message, &sig, &pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_sign_and_verify() {
        let kp = KeyPair::generate();
        let message = b"Hello, SUM Chain!";

        let signature = sign(message, kp.private_key());
        let result = verify(message, &signature, kp.public_key());

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = KeyPair::generate();
        let message = b"Hello, SUM Chain!";
        let wrong_message = b"Wrong message";

        let signature = sign(message, kp.private_key());
        let result = verify(wrong_message, &signature, kp.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let message = b"Hello, SUM Chain!";

        let signature = sign(message, kp1.private_key());
        let result = verify(message, &signature, kp2.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_signature_deterministic() {
        let kp = KeyPair::generate();
        let message = b"Same message";

        // Ed25519 signatures are deterministic
        let sig1 = sign(message, kp.private_key());
        let sig2 = sign(message, kp.private_key());

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let kp = KeyPair::generate();
        let signature = sign(b"test", kp.private_key());

        let hex = signature.to_hex();
        let recovered = Signature::from_hex(&hex).unwrap();

        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_verify_bytes() {
        let kp = KeyPair::generate();
        let message = b"Test message";

        let signature = sign(message, kp.private_key());
        let result = verify_bytes(message, signature.as_bytes(), kp.public_key().as_bytes());

        assert!(result.is_ok());
    }
}
