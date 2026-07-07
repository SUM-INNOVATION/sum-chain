//! Public SUM-721 NFT operation payload structs (issue #89).
//!
//! Shared **single source of truth** for the bincode wire shape of `NftTxData.data`
//! for each `NftOperation`. Previously duplicated as private structs inside
//! `crates/state/src/nft_executor.rs`; promoted here **unchanged** so the executor
//! (which deserializes them) and the no-key RPC builders (which serialize them)
//! share one definition.
//!
//! They live in `sumchain_nft` (not `sumchain_primitives`) because
//! [`CreateCollectionData`] embeds [`crate::collection::CollectionConfig`], which is
//! defined here — placing these in primitives would require a primitives → nft
//! dependency.
//!
//! **Wire-frozen.** Field order and types are byte-identical to the historical
//! executor-private structs — do NOT reorder fields or change types. bincode is
//! positional. The round-trip fixtures in `crates/nft/tests/ops_fixtures.rs` lock
//! the byte layout.
//!
//! Ops with **no** `data` struct: `Burn`, `LockToken`, `UnlockToken` (operate on
//! `token_id` alone); `UpdateMetadata` (its `data` is the raw metadata bytes).
//! `SetApprovalForAll` is unimplemented in the executor (no builder, no struct).

use serde::{Deserialize, Serialize};
use sumchain_primitives::Address;

use crate::collection::CollectionConfig;

/// `NftOperation::CreateCollection` payload. (Was `nft_executor::CreateCollectionData`.)
/// No `PartialEq` — `CollectionConfig` does not implement it; fixtures compare bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCollectionData {
    pub name: String,
    pub symbol: String,
    pub description: String,
    pub config: CollectionConfig,
    pub base_uri: Option<String>,
}

/// `NftOperation::Mint` / `MintDocument` payload. (Was `nft_executor::MintData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftMintData {
    pub to: Address,
    pub metadata: Vec<u8>,
    pub uri_type: String,
    pub uri_value: Option<String>,
}

/// One entry of `NftBatchMintData::requests`. (Was `nft_executor::BatchMintRequest`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftBatchMintRequest {
    pub to: Address,
    pub metadata: Vec<u8>,
}

/// `NftOperation::BatchMint` payload. (Was `nft_executor::BatchMintData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftBatchMintData {
    pub requests: Vec<NftBatchMintRequest>,
}

/// `NftOperation::Transfer` payload. (Was `nft_executor::TransferData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTransferData {
    pub to: Address,
}

/// `NftOperation::Approve` payload. (Was `nft_executor::ApproveData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftApproveData {
    pub approved: Option<Address>,
}

/// `NftOperation::TransferCollectionOwnership` payload. (Was `nft_executor::TransferOwnerData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTransferCollectionOwnershipData {
    pub new_owner: Address,
}

/// `NftOperation::UpdateCollectionConfig` payload. (Was `nft_executor::ConfigUpdateData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftUpdateCollectionConfigData {
    pub new_royalty_recipient: Option<Address>,
    pub new_base_uri: Option<String>,
}
