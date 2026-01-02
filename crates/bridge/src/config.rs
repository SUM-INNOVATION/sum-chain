//! Bridge configuration.

use crate::types::EthAddress;
use serde::{Deserialize, Serialize};

/// Bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Ethereum RPC endpoint
    pub eth_rpc_url: String,

    /// Ethereum WebSocket endpoint (for event watching)
    pub eth_ws_url: Option<String>,

    /// Bridge contract address on Ethereum
    pub bridge_contract: EthAddress,

    /// Chain ID of Ethereum network
    pub eth_chain_id: u64,

    /// Number of Ethereum confirmations required
    pub eth_confirmations: u64,

    /// Start block for event scanning (0 = latest)
    pub start_block: u64,

    /// Minimum signatures required (should be 2/3 of validators)
    pub min_signatures: u32,

    /// Polling interval for Ethereum events (seconds)
    pub poll_interval_secs: u64,

    /// Maximum pending deposits before pausing
    pub max_pending_deposits: u64,

    /// Whether to enable automatic relaying
    pub auto_relay: bool,

    /// Gas price multiplier for Ethereum transactions
    pub gas_price_multiplier: f64,

    /// Maximum gas price (in Gwei)
    pub max_gas_price_gwei: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "http://localhost:8545".to_string(),
            eth_ws_url: None,
            bridge_contract: EthAddress::ZERO,
            eth_chain_id: 1,
            eth_confirmations: 12,
            start_block: 0,
            min_signatures: 2,
            poll_interval_secs: 15,
            max_pending_deposits: 1000,
            auto_relay: true,
            gas_price_multiplier: 1.1,
            max_gas_price_gwei: 100,
        }
    }
}

impl BridgeConfig {
    /// Configuration for Ethereum mainnet
    pub fn mainnet(bridge_contract: EthAddress) -> Self {
        Self {
            eth_rpc_url: "https://eth.llamarpc.com".to_string(),
            eth_ws_url: Some("wss://eth.llamarpc.com".to_string()),
            bridge_contract,
            eth_chain_id: 1,
            eth_confirmations: 12,
            min_signatures: 3, // For 5 validators
            ..Default::default()
        }
    }

    /// Configuration for Goerli testnet
    pub fn goerli(bridge_contract: EthAddress) -> Self {
        Self {
            eth_rpc_url: "https://goerli.infura.io/v3/YOUR_KEY".to_string(),
            eth_ws_url: None,
            bridge_contract,
            eth_chain_id: 5,
            eth_confirmations: 6,
            min_signatures: 2,
            ..Default::default()
        }
    }

    /// Configuration for Sepolia testnet
    pub fn sepolia(bridge_contract: EthAddress) -> Self {
        Self {
            eth_rpc_url: "https://sepolia.infura.io/v3/YOUR_KEY".to_string(),
            eth_ws_url: None,
            bridge_contract,
            eth_chain_id: 11155111,
            eth_confirmations: 6,
            min_signatures: 2,
            ..Default::default()
        }
    }

    /// Configuration for local development
    pub fn local() -> Self {
        Self {
            eth_rpc_url: "http://localhost:8545".to_string(),
            eth_ws_url: Some("ws://localhost:8545".to_string()),
            bridge_contract: EthAddress::ZERO,
            eth_chain_id: 31337, // Hardhat/Anvil
            eth_confirmations: 1,
            min_signatures: 1,
            poll_interval_secs: 2,
            ..Default::default()
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.eth_rpc_url.is_empty() {
            return Err("Ethereum RPC URL is required".to_string());
        }

        if self.bridge_contract == EthAddress::ZERO {
            return Err("Bridge contract address is required".to_string());
        }

        if self.eth_confirmations == 0 {
            return Err("At least 1 confirmation required".to_string());
        }

        if self.min_signatures == 0 {
            return Err("At least 1 signature required".to_string());
        }

        Ok(())
    }
}
