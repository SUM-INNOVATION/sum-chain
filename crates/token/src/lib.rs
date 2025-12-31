//! # SRC-20: Native Fungible Token Standard
//!
//! SRC-20 is SUM Chain's native fungible token standard, similar to ERC-20 on Ethereum.
//! It provides native blockchain support for creating and managing fungible tokens.
//!
//! ## Key Features
//!
//! - Native blockchain support (no smart contract overhead)
//! - Full ERC-20 compatible interface
//! - Minting and burning capabilities
//! - Allowance system for delegated transfers
//! - Pausable tokens (optional)
//! - Capped supply (optional)
//!
//! ## Transaction Types
//!
//! - `CreateToken`: Create a new fungible token
//! - `Mint`: Mint new tokens (if mintable)
//! - `Burn`: Burn tokens from balance
//! - `Transfer`: Transfer tokens to another address
//! - `Approve`: Approve spending allowance
//! - `TransferFrom`: Transfer using allowance

pub mod error;
pub mod token;
pub mod transaction;

pub use error::{Result, TokenError};
pub use token::{Token, TokenConfig, TokenId, TokenInfo};
pub use transaction::{TokenAction, TokenOperation, TokenTxData};

/// SRC-20 standard version
pub const SRC20_VERSION: &str = "1.0.0";

/// Maximum token name length in bytes
pub const MAX_NAME_BYTES: usize = 64;

/// Maximum token symbol length in bytes
pub const MAX_SYMBOL_BYTES: usize = 16;

/// Maximum decimals (same as Koppa native currency)
pub const MAX_DECIMALS: u8 = 18;
