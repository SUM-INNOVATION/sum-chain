//! NFT Token types
//!
//! Represents individual NFT tokens within a collection.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Hash, Timestamp};

use crate::collection::CollectionId;
use crate::metadata::{DocumentMetadata, Metadata};

/// Token ID within a collection
pub type TokenId = u64;

/// Token URI (where to find metadata)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenUri {
    /// Metadata stored on-chain
    OnChain,
    /// IPFS content identifier
    Ipfs(String),
    /// External URL
    Url(String),
}

impl TokenUri {
    /// Get the URI as a string (for API responses)
    pub fn to_string_uri(&self) -> String {
        match self {
            TokenUri::OnChain => "onchain://".to_string(),
            TokenUri::Ipfs(cid) => format!("ipfs://{}", cid),
            TokenUri::Url(url) => url.clone(),
        }
    }
}

/// Token type (general NFT or certified document)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    /// Standard NFT with general metadata
    Standard(Metadata),
    /// Certified document with specialized metadata
    Document(DocumentMetadata),
}

/// An individual NFT token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Collection this token belongs to
    pub collection_id: CollectionId,

    /// Token ID within the collection
    pub token_id: TokenId,

    /// Current owner
    pub owner: Address,

    /// Token type and metadata
    pub token_type: TokenType,

    /// Token URI for external metadata resolution
    pub token_uri: TokenUri,

    /// Original minter/creator
    pub creator: Address,

    /// Minting timestamp
    pub minted_at: Timestamp,

    /// Approved address for transfer (single approval)
    pub approved: Option<Address>,

    /// Whether the token is locked (e.g., used as collateral)
    pub locked: bool,

    /// Previous owners (for provenance tracking)
    pub transfer_count: u32,
}

impl Token {
    /// Create a new standard NFT
    pub fn new_standard(
        collection_id: CollectionId,
        token_id: TokenId,
        owner: Address,
        metadata: Metadata,
        minted_at: Timestamp,
    ) -> Self {
        Self {
            collection_id,
            token_id,
            owner,
            token_type: TokenType::Standard(metadata),
            token_uri: TokenUri::OnChain,
            creator: owner,
            minted_at,
            approved: None,
            locked: false,
            transfer_count: 0,
        }
    }

    /// Create a new certified document NFT
    pub fn new_document(
        collection_id: CollectionId,
        token_id: TokenId,
        owner: Address,
        metadata: DocumentMetadata,
        minted_at: Timestamp,
    ) -> Self {
        Self {
            collection_id,
            token_id,
            owner,
            token_type: TokenType::Document(metadata),
            token_uri: TokenUri::OnChain,
            creator: owner,
            minted_at,
            approved: None,
            locked: false,
            transfer_count: 0,
        }
    }

    /// Get the token's unique global identifier
    pub fn global_id(&self) -> TokenGlobalId {
        TokenGlobalId {
            collection_id: self.collection_id,
            token_id: self.token_id,
        }
    }

    /// Get the token hash (unique identifier)
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(self.collection_id.as_bytes());
        data.extend_from_slice(&self.token_id.to_le_bytes());
        Hash::hash(&data)
    }

    /// Check if an address can transfer this token
    pub fn can_transfer(&self, operator: &Address) -> bool {
        if self.locked {
            return false;
        }
        // Owner can always transfer
        if &self.owner == operator {
            return true;
        }
        // Approved address can transfer
        if let Some(approved) = &self.approved {
            if approved == operator {
                return true;
            }
        }
        false
    }

    /// Check if an address can approve transfers
    pub fn can_approve(&self, operator: &Address) -> bool {
        &self.owner == operator
    }

    /// Set approval for a specific address
    pub fn set_approval(&mut self, approved: Option<Address>) {
        self.approved = approved;
    }

    /// Transfer to a new owner
    pub fn transfer_to(&mut self, new_owner: Address) {
        self.owner = new_owner;
        self.approved = None; // Clear approval on transfer
        self.transfer_count += 1;
    }

    /// Lock the token
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the token
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    /// Get metadata (either standard or document)
    pub fn metadata(&self) -> &Metadata {
        match &self.token_type {
            TokenType::Standard(m) => m,
            TokenType::Document(d) => &d.base,
        }
    }

    /// Get document metadata if this is a document token
    pub fn document_metadata(&self) -> Option<&DocumentMetadata> {
        match &self.token_type {
            TokenType::Document(d) => Some(d),
            TokenType::Standard(_) => None,
        }
    }

    /// Check if this is a document token
    pub fn is_document(&self) -> bool {
        matches!(self.token_type, TokenType::Document(_))
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Token serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Global token identifier (collection + token ID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenGlobalId {
    pub collection_id: CollectionId,
    pub token_id: TokenId,
}

impl TokenGlobalId {
    /// Create a new global token ID
    pub fn new(collection_id: CollectionId, token_id: TokenId) -> Self {
        Self {
            collection_id,
            token_id,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(self.collection_id.as_bytes());
        bytes.extend_from_slice(&self.token_id.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 40 {
            return Err(format!("Invalid length: expected 40, got {}", bytes.len()));
        }
        let mut collection_bytes = [0u8; 32];
        collection_bytes.copy_from_slice(&bytes[0..32]);
        let token_id = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        Ok(Self {
            collection_id: CollectionId(collection_bytes),
            token_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Metadata;

    fn sample_collection_id() -> CollectionId {
        let creator = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        CollectionId::new(&creator, "Test", 0)
    }

    #[test]
    fn test_token_creation() {
        let collection_id = sample_collection_id();
        let owner = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let metadata = Metadata::simple("Test NFT".to_string(), "A test".to_string());

        let token = Token::new_standard(collection_id, 1, owner, metadata, 1700000000000);

        assert_eq!(token.token_id, 1);
        assert_eq!(token.owner, owner);
        assert_eq!(token.transfer_count, 0);
        assert!(!token.locked);
    }

    #[test]
    fn test_token_transfer() {
        let collection_id = sample_collection_id();
        let owner = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let new_owner = Address::from_hex("0x0000000000000000000000000000000000000003").unwrap();
        let metadata = Metadata::simple("Test".to_string(), "Test".to_string());

        let mut token = Token::new_standard(collection_id, 1, owner, metadata, 1700000000000);

        // Set approval
        token.set_approval(Some(new_owner));
        assert!(token.can_transfer(&new_owner));

        // Transfer
        token.transfer_to(new_owner);
        assert_eq!(token.owner, new_owner);
        assert_eq!(token.transfer_count, 1);
        assert!(token.approved.is_none()); // Approval cleared
    }

    #[test]
    fn test_locked_token() {
        let collection_id = sample_collection_id();
        let owner = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let metadata = Metadata::simple("Test".to_string(), "Test".to_string());

        let mut token = Token::new_standard(collection_id, 1, owner, metadata, 1700000000000);

        assert!(token.can_transfer(&owner));

        token.lock();
        assert!(!token.can_transfer(&owner));

        token.unlock();
        assert!(token.can_transfer(&owner));
    }

    #[test]
    fn test_global_id_serialization() {
        let collection_id = sample_collection_id();
        let global_id = TokenGlobalId::new(collection_id, 42);

        let bytes = global_id.to_bytes();
        let restored = TokenGlobalId::from_bytes(&bytes).unwrap();

        assert_eq!(global_id, restored);
    }
}
