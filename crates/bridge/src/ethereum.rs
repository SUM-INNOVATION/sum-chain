//! Ethereum interaction - watching events and executing transactions.

use crate::{BridgeConfig, BridgeError, DepositEvent, EthAddress, Result, WithdrawalRequest};
use ethers::prelude::*;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Ethereum client for bridge operations
pub struct EthereumClient {
    provider: Arc<Provider<Http>>,
    /// Configuration (public for watcher access)
    pub config: BridgeConfig,
}

impl EthereumClient {
    /// Create a new Ethereum client (sync version, connection verified on first use)
    pub fn new(config: BridgeConfig) -> Result<Self> {
        let provider = Provider::<Http>::try_from(&config.eth_rpc_url)
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))?;

        Ok(Self {
            provider: Arc::new(provider),
            config,
        })
    }

    /// Verify connection and chain ID
    pub async fn verify_connection(&self) -> Result<()> {
        let chain_id = self.provider
            .get_chainid()
            .await
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))?;

        if chain_id.as_u64() != self.config.eth_chain_id {
            return Err(BridgeError::Config(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.config.eth_chain_id,
                chain_id.as_u64()
            )));
        }

        info!("Connected to Ethereum chain {}", chain_id);
        Ok(())
    }

    /// Get current block number
    pub async fn block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .map(|n| n.as_u64())
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))
    }

    /// Get ETH balance of an address
    pub async fn balance(&self, address: EthAddress) -> Result<U256> {
        self.provider
            .get_balance(ethers::types::Address::from(address), None)
            .await
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))
    }

    /// Check if a transaction is confirmed
    pub async fn is_confirmed(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let tx_hash = H256::from(tx_hash);

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))?;

        match receipt {
            Some(r) => {
                if let Some(block_num) = r.block_number {
                    let current_block = self.block_number().await?;
                    let confirmations = current_block.saturating_sub(block_num.as_u64());
                    Ok(confirmations >= self.config.eth_confirmations)
                } else {
                    Ok(false)
                }
            }
            None => Ok(false),
        }
    }

    /// Get gas price with multiplier
    pub async fn gas_price(&self) -> Result<U256> {
        let base_price = self
            .provider
            .get_gas_price()
            .await
            .map_err(|e| BridgeError::EthereumRpc(e.to_string()))?;

        let multiplied = base_price.as_u128() as f64 * self.config.gas_price_multiplier;
        let max_price = (self.config.max_gas_price_gwei as u128) * 1_000_000_000;

        Ok(U256::from((multiplied as u128).min(max_price)))
    }
}

/// Ethereum event watcher
pub struct EthereumWatcher {
    client: Arc<EthereumClient>,
    last_processed_block: u64,
}

impl EthereumWatcher {
    /// Create a new watcher
    pub fn new(client: Arc<EthereumClient>, start_block: u64) -> Self {
        Self {
            client,
            last_processed_block: start_block,
        }
    }

    /// Poll for new deposit events
    pub async fn poll_deposits(&mut self) -> Result<Vec<DepositEvent>> {
        let current_block = self.client.block_number().await?;

        // Only process finalized blocks
        let safe_block = current_block.saturating_sub(self.client.config.eth_confirmations);

        if safe_block <= self.last_processed_block {
            return Ok(Vec::new());
        }

        let from_block = self.last_processed_block + 1;
        let to_block = safe_block.min(from_block + 1000); // Max 1000 blocks per query

        debug!(
            "Scanning Ethereum blocks {} to {} for deposits",
            from_block, to_block
        );

        // In production, this would query the bridge contract's Deposit events
        // For now, return empty - actual implementation would use:
        // let filter = Filter::new()
        //     .address(self.client.config.bridge_contract.into())
        //     .event("Deposit(address,address,address,uint256)")
        //     .from_block(from_block)
        //     .to_block(to_block);
        //
        // let logs = self.client.provider.get_logs(&filter).await?;

        self.last_processed_block = to_block;

        Ok(Vec::new())
    }

    /// Get last processed block
    pub fn last_processed_block(&self) -> u64 {
        self.last_processed_block
    }

    /// Set last processed block (for recovery)
    pub fn set_last_processed_block(&mut self, block: u64) {
        self.last_processed_block = block;
    }
}

// Bridge contract ABI (simplified)
abigen!(
    SumBridge,
    r#"[
        function deposit(address token, uint256 amount, bytes32 sumRecipient) external payable
        function withdraw(address token, uint256 amount, address recipient, bytes[] signatures) external
        function paused() external view returns (bool)
        function totalLocked(address token) external view returns (uint256)
        event Deposit(address indexed sender, address indexed token, uint256 amount, bytes32 sumRecipient)
        event Withdrawal(address indexed recipient, address indexed token, uint256 amount)
    ]"#
);

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require a running Ethereum node
    // In production, use a mock provider
}
