//! Cryptographic hash types for SUM Chain.
//!
//! We use Blake3 for all hashing operations. Blake3 is:
//! - Extremely fast (faster than MD5 while being cryptographically secure)
//! - Designed by world-class cryptographers (same team as Blake2)
//! - The reference implementation is written in Rust
//! - Parallelizable and SIMD-optimized

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{PrimitiveError, Result};

/// 32-byte hash (Blake3 output)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

// `Hash::hash` is a long-standing public constructor named after the type;
// renaming it (the only self_named_constructors fix) would break every
// `Hash::hash(..)` call site across the workspace — a public-API break, not a
// wire change. Scoped to this impl block only.
#[allow(clippy::self_named_constructors)]
impl Hash {
    /// Size of the hash in bytes
    pub const SIZE: usize = 32;

    /// Zero hash (all zeros)
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Create a new hash from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create hash from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::SIZE {
            return Err(PrimitiveError::InvalidLength {
                expected: Self::SIZE,
                got: slice.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Hash(bytes))
    }

    /// Create hash from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| PrimitiveError::InvalidHex(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Hash arbitrary data using Blake3
    pub fn hash(data: &[u8]) -> Self {
        let result = blake3::hash(data);
        Hash(*result.as_bytes())
    }

    /// Hash multiple pieces of data
    pub fn hash_many(data: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for d in data {
            hasher.update(d);
        }
        let result = hasher.finalize();
        Hash(*result.as_bytes())
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string (with 0x prefix)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Check if this is the zero hash
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Compute merkle root from a list of hashes
    /// Uses a simple binary merkle tree construction
    pub fn merkle_root(hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return Hash::ZERO;
        }
        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level: Vec<Hash> = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let left = &chunk[0];
                let right = chunk.get(1).unwrap_or(left); // Duplicate last if odd

                let combined = Hash::hash_many(&[left.as_bytes(), right.as_bytes()]);
                next_level.push(combined);
            }

            current_level = next_level;
        }

        current_level[0]
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_consistency() {
        let data = b"hello world";
        let h1 = Hash::hash(data);
        let h2 = Hash::hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_data() {
        let h1 = Hash::hash(b"hello");
        let h2 = Hash::hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let h = Hash::hash(b"test data");
        let hex = h.to_hex();
        let h2 = Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(Hash::merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash::hash(b"single");
        assert_eq!(Hash::merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_multiple() {
        let hashes: Vec<Hash> = (0..4).map(|i| Hash::hash(&[i])).collect();
        let root = Hash::merkle_root(&hashes);
        assert_ne!(root, Hash::ZERO);

        // Verify determinism
        let root2 = Hash::merkle_root(&hashes);
        assert_eq!(root, root2);
    }
}
