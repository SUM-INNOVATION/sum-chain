//! # SUM Chain Bridge
//!
//! Cross-chain bridge for transferring assets between Ethereum and SUM Chain.
//!
//! ## Architecture
//!
//! ```text
//! Ethereum                         SUM Chain
//! ┌────────────────┐               ┌────────────────┐
//! │ Bridge Contract│               │ Bridge Module  │
//! │                │               │                │
//! │ • Lock ETH/ERC │◄─────────────►│ • Mint Wrapped │
//! │ • Unlock assets│   Validators  │ • Burn Wrapped │
//! │                │   Attestation │                │
//! └────────────────┘               └────────────────┘
//! ```
//!
//! ## Supported Assets
//!
//! - ETH → sETH (wrapped Ether on SUM Chain)
//! - ERC-20 tokens → SRC-20 wrapped tokens
//! - ERC-721 NFTs → SUM-721 wrapped NFTs
//!
//! ## Security Model
//!
//! - Deposits: User locks assets on Ethereum, validators sign attestation
//! - Withdrawals: User burns wrapped assets on SUM, validators sign release
//! - Threshold: 2/3+ validator signatures required for any bridge operation

pub mod config;
pub mod error;
pub mod ethereum;
pub mod relayer;
pub mod types;
pub mod wrapped_tokens;

pub use config::BridgeConfig;
pub use error::{BridgeError, Result};
pub use ethereum::{EthereumClient, EthereumWatcher};
pub use relayer::BridgeRelayer;
pub use types::*;
pub use wrapped_tokens::WrappedTokenRegistry;
