//! Common types for SUMC contracts.

use serde::{Deserialize, Serialize};

/// 20-byte address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Address([u8; 20]);

impl Address {
    /// Zero address
    pub const ZERO: Address = Address([0u8; 20]);

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Some(Address(bytes))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        Self::from_slice(&bytes)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 32-byte hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Zero hash
    pub const ZERO: Hash = Hash([0u8; 32]);

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Balance type (128-bit unsigned integer)
pub type Balance = u128;

/// Block height type
pub type BlockHeight = u64;

/// Timestamp type (milliseconds since epoch)
pub type Timestamp = u64;

/// Token ID type
pub type TokenId = u64;

/// Event that can be emitted by contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event name/topic
    pub name: String,
    /// Indexed fields (for filtering)
    pub indexed: std::collections::HashMap<String, Vec<u8>>,
    /// Non-indexed data
    pub data: Vec<u8>,
}

impl Event {
    /// Create a new event
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            indexed: std::collections::HashMap::new(),
            data: Vec::new(),
        }
    }

    /// Add an indexed field
    pub fn indexed<T: Serialize>(mut self, key: &str, value: &T) -> Self {
        if let Ok(bytes) = bincode::serialize(value) {
            self.indexed.insert(key.to_string(), bytes);
        }
        self
    }

    /// Set event data
    pub fn data<T: Serialize>(mut self, value: &T) -> Self {
        if let Ok(bytes) = bincode::serialize(value) {
            self.data = bytes;
        }
        self
    }
}

/// Transfer event (commonly used)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEvent {
    pub from: Address,
    pub to: Address,
    pub amount: Balance,
}

impl TransferEvent {
    pub fn new(from: Address, to: Address, amount: Balance) -> Self {
        Self { from, to, amount }
    }
}

/// Approval event (commonly used)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub owner: Address,
    pub spender: Address,
    pub amount: Balance,
}
