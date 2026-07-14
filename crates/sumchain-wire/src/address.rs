//! Address type for SUM Chain accounts.
//!
//! Addresses are derived from Ed25519 public keys using Blake3,
//! taking the last 20 bytes. Displayed in base58 with a checksum.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{PrimitiveError, Result};

/// 20-byte address derived from public key
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address([u8; 20]);

impl Address {
    /// Size of address in bytes
    pub const SIZE: usize = 20;

    /// Zero address (for coinbase/system operations)
    pub const ZERO: Address = Address([0u8; 20]);

    /// Create address from raw bytes
    pub fn new(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Create address from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::SIZE {
            return Err(PrimitiveError::InvalidLength {
                expected: Self::SIZE,
                got: slice.len(),
            });
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }

    /// Derive address from a public key (32 bytes for Ed25519)
    /// Takes Blake3 hash of pubkey, then last 20 bytes
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let hash_bytes = hash.as_bytes();
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash_bytes[12..32]); // Last 20 bytes
        Address(bytes)
    }

    /// Parse address from base58 string with checksum
    /// Format: base58(address_bytes + checksum[0..4])
    pub fn from_base58(s: &str) -> Result<Self> {
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| PrimitiveError::InvalidBase58(e.to_string()))?;

        if decoded.len() != Self::SIZE + 4 {
            return Err(PrimitiveError::InvalidLength {
                expected: Self::SIZE + 4,
                got: decoded.len(),
            });
        }

        let (addr_bytes, checksum) = decoded.split_at(Self::SIZE);

        // Verify checksum: first 4 bytes of Blake3(Blake3(addr_bytes))
        let hash1 = blake3::hash(addr_bytes);
        let hash2 = blake3::hash(hash1.as_bytes());

        if &hash2.as_bytes()[0..4] != checksum {
            return Err(PrimitiveError::InvalidChecksum);
        }

        Self::from_slice(addr_bytes)
    }

    /// Convert to base58 string with checksum
    pub fn to_base58(&self) -> String {
        let hash1 = blake3::hash(&self.0);
        let hash2 = blake3::hash(hash1.as_bytes());

        let mut with_checksum = Vec::with_capacity(Self::SIZE + 4);
        with_checksum.extend_from_slice(&self.0);
        with_checksum.extend_from_slice(&hash2.as_bytes()[0..4]);

        bs58::encode(with_checksum).into_string()
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| PrimitiveError::InvalidHex(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Convert to hex string (with 0x prefix)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Check if this is the zero address
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_base58())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_public_key() {
        let pubkey = [0u8; 32];
        let addr = Address::from_public_key(&pubkey);
        assert!(!addr.is_zero()); // Hash of zeros is not zero
    }

    #[test]
    fn test_base58_roundtrip() {
        let addr = Address::from_public_key(&[42u8; 32]);
        let b58 = addr.to_base58();
        let addr2 = Address::from_base58(&b58).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let addr = Address::from_public_key(&[1u8; 32]);
        let hex = addr.to_hex();
        let addr2 = Address::from_hex(&hex).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_invalid_checksum() {
        let addr = Address::from_public_key(&[1u8; 32]);
        let mut b58 = addr.to_base58();

        // Corrupt the string
        let chars: Vec<char> = b58.chars().collect();
        let last = chars.last().unwrap();
        let new_last = if *last == 'a' { 'b' } else { 'a' };
        b58.pop();
        b58.push(new_last);

        let result = Address::from_base58(&b58);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_address() {
        assert!(Address::ZERO.is_zero());
    }
}
