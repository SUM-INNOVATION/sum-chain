//! # SUM-721: Native NFT Standard
//!
//! SUM-721 is SUM Chain's native NFT standard for certified documents and digital assets.
//! It provides ERC-721 compatible functionality while being optimized for:
//!
//! - **Certified Documents**: Legal documents, certificates, credentials with issuer verification
//! - **Digital Assets**: Collectibles, art, and other unique tokens
//! - **Provenance Tracking**: Complete ownership history on-chain
//!
//! ## Key Features
//!
//! - Native blockchain support (no smart contract overhead)
//! - Document certification with issuer signatures
//! - Metadata stored on-chain or via content-addressed IPFS links
//! - Batch minting for efficiency
//! - Royalty support for creators
//!
//! ## Transaction Types
//!
//! - `CreateCollection`: Create a new NFT collection
//! - `Mint`: Mint a new NFT in a collection
//! - `Transfer`: Transfer NFT ownership
//! - `Burn`: Destroy an NFT
//! - `UpdateMetadata`: Update NFT metadata (if allowed by collection)
//! - `SetApproval`: Approve address to transfer NFT

pub mod collection;
pub mod error;
pub mod metadata;
pub mod token;
pub mod transaction;

pub use collection::{Collection, CollectionConfig, CollectionId};
pub use error::{NftError, Result};
pub use metadata::{DocumentMetadata, Metadata, MetadataType};
pub use token::{Token, TokenId, TokenUri};
pub use transaction::{NftAction, NftTransaction};

/// SUM-721 standard version
pub const SUM721_VERSION: &str = "1.0.0";
