//! Public SRC-20 token operation payload structs (issue #89).
//!
//! These are the **shared single source of truth** for the bincode wire shape of
//! `TokenTxData.data` for each `TokenOperation`. They were previously duplicated as
//! private structs inside `crates/state/src/token_executor.rs`; they are promoted
//! here **unchanged** so the executor (which deserializes them) and the no-key RPC
//! builders (which serialize them) share one definition.
//!
//! **Wire-frozen.** Field order and types are byte-identical to the historical
//! executor-private structs — do NOT reorder fields or change types. bincode is
//! positional, so field *names* do not affect the encoding, but order and type do.
//! The round-trip fixtures in `crates/primitives/tests/token_ops_fixtures.rs` lock
//! the byte layout.

use serde::{Deserialize, Serialize};

use crate::Address;

/// `TokenOperation::Create` payload. (Was `token_executor::CreateData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTokenData {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub max_supply: u128,
    pub mintable: bool,
    pub burnable: bool,
    pub pausable: bool,
}

/// `TokenOperation::Mint` payload. (Was `token_executor::MintData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMintData {
    pub to: Address,
    pub amount: u128,
}

/// `TokenOperation::Burn` payload. (Was `token_executor::BurnData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBurnData {
    pub amount: u128,
}

/// `TokenOperation::Transfer` payload. (Was `token_executor::TransferData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTransferData {
    pub to: Address,
    pub amount: u128,
}

/// `TokenOperation::Approve` payload. (Was `token_executor::ApproveData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenApproveData {
    pub spender: Address,
    pub amount: u128,
}

/// `TokenOperation::TransferFrom` payload. (Was `token_executor::TransferFromData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTransferFromData {
    pub from: Address,
    pub to: Address,
    pub amount: u128,
}

/// `TokenOperation::TransferOwnership` payload. (Was `token_executor::TransferOwnerData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTransferOwnershipData {
    pub new_owner: Address,
}

/// `TokenOperation::AddMinter` / `RemoveMinter` payload. (Was `token_executor::MinterData`.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMinterData {
    pub minter: Address,
}

// Note: `TokenOperation::Pause` and `Unpause` carry no `data` payload (the executor
// operates on `token_id` alone), so they have no struct here.
