//! NFT Collection types and management
//!
//! A collection is a group of related NFTs with shared configuration.
//! For certified documents, a collection might represent a type of certificate
//! (e.g., "University Degrees", "Property Deeds", "Professional Licenses").

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Hash, Timestamp};

/// Unique identifier for a collection (derived from creator + name + nonce)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CollectionId(pub [u8; 32]);

impl CollectionId {
    /// Create a new collection ID from creator address and name
    pub fn new(creator: &Address, name: &str, nonce: u64) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(creator.as_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        let hash = Hash::hash(&data);
        Self(*hash.as_bytes())
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Invalid length: expected 32, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for CollectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Collection configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionConfig {
    /// Maximum number of tokens (0 = unlimited)
    pub max_supply: u64,

    /// Whether tokens can be transferred
    pub transferable: bool,

    /// Whether tokens can be burned
    pub burnable: bool,

    /// Whether metadata can be updated after minting
    pub metadata_updatable: bool,

    /// Whether only the collection owner can mint
    pub owner_only_minting: bool,

    /// Royalty percentage (basis points, 100 = 1%)
    pub royalty_bps: u16,

    /// Royalty recipient address
    pub royalty_recipient: Address,
}

impl Default for CollectionConfig {
    fn default() -> Self {
        Self {
            max_supply: 0, // Unlimited
            transferable: true,
            burnable: true,
            metadata_updatable: false,
            owner_only_minting: true,
            royalty_bps: 0,
            royalty_recipient: Address::ZERO,
        }
    }
}

impl CollectionConfig {
    /// Configuration for certified documents (non-transferable by default)
    pub fn certified_document() -> Self {
        Self {
            max_supply: 0,
            transferable: false, // Certificates typically can't be transferred
            burnable: false,     // Certificates are permanent records
            metadata_updatable: false,
            owner_only_minting: true,
            royalty_bps: 0,
            royalty_recipient: Address::ZERO,
        }
    }

    /// Configuration for tradeable collectibles
    pub fn collectible() -> Self {
        Self {
            max_supply: 0,
            transferable: true,
            burnable: true,
            metadata_updatable: false,
            owner_only_minting: true,
            royalty_bps: 250, // 2.5% royalty
            royalty_recipient: Address::ZERO, // Set by creator
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Maximum royalty is 25%
        if self.royalty_bps > 2500 {
            return Err(format!("Royalty too high: {}bps > 2500bps", self.royalty_bps));
        }
        if self.royalty_bps > 0 && self.royalty_recipient.is_zero() {
            return Err("Royalty recipient required when royalty > 0".to_string());
        }
        Ok(())
    }
}

/// An NFT Collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    /// Unique collection identifier
    pub id: CollectionId,

    /// Collection name
    pub name: String,

    /// Collection symbol (e.g., "DEGREE", "DEED")
    pub symbol: String,

    /// Collection description
    pub description: String,

    /// Collection owner (can mint, update config)
    pub owner: Address,

    /// Configuration
    pub config: CollectionConfig,

    /// Current token count
    pub total_supply: u64,

    /// Next token ID to mint
    pub next_token_id: u64,

    /// Creation timestamp
    pub created_at: Timestamp,

    /// Base URI for metadata (optional)
    pub base_uri: Option<String>,
}

impl Collection {
    /// Create a new collection
    pub fn new(
        name: String,
        symbol: String,
        description: String,
        owner: Address,
        config: CollectionConfig,
        created_at: Timestamp,
        nonce: u64,
    ) -> Self {
        let id = CollectionId::new(&owner, &name, nonce);

        Self {
            id,
            name,
            symbol,
            description,
            owner,
            config,
            total_supply: 0,
            next_token_id: 1,
            created_at,
            base_uri: None,
        }
    }

    /// Check if more tokens can be minted
    pub fn can_mint(&self) -> bool {
        if self.config.max_supply == 0 {
            return true; // Unlimited
        }
        self.total_supply < self.config.max_supply
    }

    /// Check if an address can mint in this collection
    pub fn can_address_mint(&self, minter: &Address) -> bool {
        if self.config.owner_only_minting {
            minter == &self.owner
        } else {
            true
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Collection serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collection_id_creation() {
        let creator = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let id1 = CollectionId::new(&creator, "TestCollection", 0);
        let id2 = CollectionId::new(&creator, "TestCollection", 0);
        let id3 = CollectionId::new(&creator, "TestCollection", 1);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3); // Different nonce
    }

    #[test]
    fn test_collection_id_hex_roundtrip() {
        let creator = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let id = CollectionId::new(&creator, "Test", 0);
        let hex = id.to_hex();
        let id2 = CollectionId::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_collection_config_validate() {
        let mut config = CollectionConfig::default();
        assert!(config.validate().is_ok());

        // Royalty too high
        config.royalty_bps = 5000; // 50%
        assert!(config.validate().is_err());

        // Royalty without recipient
        config.royalty_bps = 250;
        config.royalty_recipient = Address::ZERO;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_certified_document_config() {
        let config = CollectionConfig::certified_document();
        assert!(!config.transferable);
        assert!(!config.burnable);
        assert!(!config.metadata_updatable);
    }
}
