//! NFT Transaction types
//!
//! Defines all NFT-related actions that can be included in transactions.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Hash};

use crate::collection::{CollectionConfig, CollectionId};
use crate::metadata::{DocumentMetadata, Metadata};
use crate::token::TokenId;

/// NFT transaction action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftAction {
    /// Create a new NFT collection
    CreateCollection {
        /// Collection name
        name: String,
        /// Collection symbol
        symbol: String,
        /// Collection description
        description: String,
        /// Collection configuration
        config: CollectionConfig,
        /// Optional base URI for metadata
        base_uri: Option<String>,
    },

    /// Mint a new standard NFT
    Mint {
        /// Collection to mint in
        collection_id: CollectionId,
        /// Recipient of the NFT
        to: Address,
        /// Token metadata
        metadata: Metadata,
    },

    /// Mint a certified document NFT
    MintDocument {
        /// Collection to mint in
        collection_id: CollectionId,
        /// Recipient of the document (subject)
        to: Address,
        /// Document metadata
        metadata: DocumentMetadata,
    },

    /// Batch mint multiple NFTs
    BatchMint {
        /// Collection to mint in
        collection_id: CollectionId,
        /// Recipients and their metadata
        tokens: Vec<MintRequest>,
    },

    /// Transfer an NFT
    Transfer {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID
        token_id: TokenId,
        /// Recipient
        to: Address,
    },

    /// Approve an address to transfer a specific NFT
    Approve {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID
        token_id: TokenId,
        /// Address to approve (None to revoke)
        approved: Option<Address>,
    },

    /// Set approval for all tokens in a collection
    SetApprovalForAll {
        /// Collection ID
        collection_id: CollectionId,
        /// Operator address
        operator: Address,
        /// Whether to approve or revoke
        approved: bool,
    },

    /// Burn an NFT
    Burn {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID to burn
        token_id: TokenId,
    },

    /// Update NFT metadata (if allowed by collection)
    UpdateMetadata {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID
        token_id: TokenId,
        /// New metadata
        new_metadata: Metadata,
    },

    /// Transfer collection ownership
    TransferCollectionOwnership {
        /// Collection ID
        collection_id: CollectionId,
        /// New owner
        new_owner: Address,
    },

    /// Update collection configuration (limited options)
    UpdateCollectionConfig {
        /// Collection ID
        collection_id: CollectionId,
        /// New royalty recipient (if changing)
        new_royalty_recipient: Option<Address>,
        /// New base URI
        new_base_uri: Option<String>,
    },

    /// Lock a token (e.g., for use as collateral)
    LockToken {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID
        token_id: TokenId,
    },

    /// Unlock a previously locked token
    UnlockToken {
        /// Collection ID
        collection_id: CollectionId,
        /// Token ID
        token_id: TokenId,
    },
}

/// Request for batch minting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintRequest {
    /// Recipient address
    pub to: Address,
    /// Token metadata
    pub metadata: Metadata,
}

/// Full NFT transaction with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTransaction {
    /// Chain ID
    pub chain_id: u64,
    /// Sender address
    pub from: Address,
    /// Transaction nonce
    pub nonce: u64,
    /// Transaction fee
    pub fee: u128,
    /// NFT action
    pub action: NftAction,
}

impl NftTransaction {
    /// Create a new NFT transaction
    pub fn new(chain_id: u64, from: Address, nonce: u64, fee: u128, action: NftAction) -> Self {
        Self {
            chain_id,
            from,
            nonce,
            fee,
            action,
        }
    }

    /// Compute the signing hash
    pub fn signing_hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("NftTransaction serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get a description of the action for logging/display
    pub fn action_description(&self) -> String {
        match &self.action {
            NftAction::CreateCollection { name, .. } => {
                format!("Create collection '{}'", name)
            }
            NftAction::Mint { collection_id, to, .. } => {
                format!("Mint to {} in {}", to, collection_id)
            }
            NftAction::MintDocument { collection_id, to, .. } => {
                format!("Mint document to {} in {}", to, collection_id)
            }
            NftAction::BatchMint { collection_id, tokens } => {
                format!("Batch mint {} tokens in {}", tokens.len(), collection_id)
            }
            NftAction::Transfer { collection_id, token_id, to } => {
                format!("Transfer {}:{} to {}", collection_id, token_id, to)
            }
            NftAction::Approve { collection_id, token_id, approved } => {
                match approved {
                    Some(addr) => format!("Approve {} for {}:{}", addr, collection_id, token_id),
                    None => format!("Revoke approval for {}:{}", collection_id, token_id),
                }
            }
            NftAction::SetApprovalForAll { collection_id, operator, approved } => {
                if *approved {
                    format!("Approve {} for all in {}", operator, collection_id)
                } else {
                    format!("Revoke {} for all in {}", operator, collection_id)
                }
            }
            NftAction::Burn { collection_id, token_id } => {
                format!("Burn {}:{}", collection_id, token_id)
            }
            NftAction::UpdateMetadata { collection_id, token_id, .. } => {
                format!("Update metadata for {}:{}", collection_id, token_id)
            }
            NftAction::TransferCollectionOwnership { collection_id, new_owner } => {
                format!("Transfer {} ownership to {}", collection_id, new_owner)
            }
            NftAction::UpdateCollectionConfig { collection_id, .. } => {
                format!("Update config for {}", collection_id)
            }
            NftAction::LockToken { collection_id, token_id } => {
                format!("Lock {}:{}", collection_id, token_id)
            }
            NftAction::UnlockToken { collection_id, token_id } => {
                format!("Unlock {}:{}", collection_id, token_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Metadata;

    fn sample_address() -> Address {
        Address::from_hex("0x0000000000000000000000000000000000000001").unwrap()
    }

    fn sample_collection_id() -> CollectionId {
        CollectionId::new(&sample_address(), "Test", 0)
    }

    #[test]
    fn test_create_collection_action() {
        let action = NftAction::CreateCollection {
            name: "Test Collection".to_string(),
            symbol: "TEST".to_string(),
            description: "A test collection".to_string(),
            config: CollectionConfig::default(),
            base_uri: None,
        };

        let tx = NftTransaction::new(1, sample_address(), 0, 1000, action);
        assert_eq!(tx.chain_id, 1);
        assert!(tx.action_description().contains("Create collection"));
    }

    #[test]
    fn test_mint_action() {
        let action = NftAction::Mint {
            collection_id: sample_collection_id(),
            to: sample_address(),
            metadata: Metadata::simple("NFT".to_string(), "Desc".to_string()),
        };

        let tx = NftTransaction::new(1, sample_address(), 0, 1000, action);
        assert!(tx.action_description().contains("Mint to"));
    }

    #[test]
    fn test_batch_mint_action() {
        let action = NftAction::BatchMint {
            collection_id: sample_collection_id(),
            tokens: vec![
                MintRequest {
                    to: sample_address(),
                    metadata: Metadata::simple("NFT 1".to_string(), "Desc".to_string()),
                },
                MintRequest {
                    to: sample_address(),
                    metadata: Metadata::simple("NFT 2".to_string(), "Desc".to_string()),
                },
            ],
        };

        let tx = NftTransaction::new(1, sample_address(), 0, 1000, action);
        assert!(tx.action_description().contains("Batch mint 2 tokens"));
    }

    #[test]
    fn test_transaction_serialization() {
        let action = NftAction::Transfer {
            collection_id: sample_collection_id(),
            token_id: 1,
            to: sample_address(),
        };

        let tx = NftTransaction::new(1, sample_address(), 0, 1000, action);
        let bytes = tx.to_bytes();
        let restored = NftTransaction::from_bytes(&bytes).unwrap();

        assert_eq!(tx.chain_id, restored.chain_id);
        assert_eq!(tx.nonce, restored.nonce);
        assert_eq!(tx.fee, restored.fee);
    }
}
