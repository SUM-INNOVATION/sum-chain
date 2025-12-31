//! Wrapped token registry and management.

use crate::{BridgeError, EthAddress, Result, WrappedToken};
use parking_lot::RwLock;
use std::collections::HashMap;

/// Registry of wrapped tokens
pub struct WrappedTokenRegistry {
    /// Mapping from Ethereum address to wrapped token info
    by_eth_address: RwLock<HashMap<EthAddress, WrappedToken>>,
    /// Mapping from SUM token ID to wrapped token info
    by_sum_id: RwLock<HashMap<[u8; 32], WrappedToken>>,
}

impl WrappedTokenRegistry {
    /// Create a new registry with default tokens
    pub fn new() -> Self {
        let registry = Self {
            by_eth_address: RwLock::new(HashMap::new()),
            by_sum_id: RwLock::new(HashMap::new()),
        };

        // Register wrapped ETH by default
        registry.register(WrappedToken::eth()).ok();

        registry
    }

    /// Register a new wrapped token
    pub fn register(&self, token: WrappedToken) -> Result<()> {
        let mut by_eth = self.by_eth_address.write();
        let mut by_sum = self.by_sum_id.write();

        if by_eth.contains_key(&token.eth_address) {
            return Err(BridgeError::TokenNotSupported(format!(
                "Token {} already registered",
                token.eth_address
            )));
        }

        by_sum.insert(token.sum_token_id, token.clone());
        by_eth.insert(token.eth_address, token);

        Ok(())
    }

    /// Get wrapped token by Ethereum address
    pub fn get_by_eth(&self, eth_address: &EthAddress) -> Option<WrappedToken> {
        self.by_eth_address.read().get(eth_address).cloned()
    }

    /// Get wrapped token by SUM token ID
    pub fn get_by_sum_id(&self, sum_id: &[u8; 32]) -> Option<WrappedToken> {
        self.by_sum_id.read().get(sum_id).cloned()
    }

    /// Check if a token is supported
    pub fn is_supported(&self, eth_address: &EthAddress) -> bool {
        self.by_eth_address.read().contains_key(eth_address)
    }

    /// Get all registered tokens
    pub fn all_tokens(&self) -> Vec<WrappedToken> {
        self.by_eth_address.read().values().cloned().collect()
    }

    /// Convert amount from Ethereum decimals to SUM decimals
    pub fn convert_to_sum(&self, eth_address: &EthAddress, eth_amount: u128) -> Option<u128> {
        let token = self.get_by_eth(eth_address)?;

        if token.eth_decimals == token.sum_decimals {
            return Some(eth_amount);
        }

        if token.eth_decimals > token.sum_decimals {
            // Ethereum has more decimals, divide
            let divisor = 10u128.pow((token.eth_decimals - token.sum_decimals) as u32);
            Some(eth_amount / divisor)
        } else {
            // SUM has more decimals, multiply
            let multiplier = 10u128.pow((token.sum_decimals - token.eth_decimals) as u32);
            eth_amount.checked_mul(multiplier)
        }
    }

    /// Convert amount from SUM decimals to Ethereum decimals
    pub fn convert_to_eth(&self, sum_id: &[u8; 32], sum_amount: u128) -> Option<u128> {
        let token = self.get_by_sum_id(sum_id)?;

        if token.eth_decimals == token.sum_decimals {
            return Some(sum_amount);
        }

        if token.sum_decimals > token.eth_decimals {
            // SUM has more decimals, divide
            let divisor = 10u128.pow((token.sum_decimals - token.eth_decimals) as u32);
            Some(sum_amount / divisor)
        } else {
            // Ethereum has more decimals, multiply
            let multiplier = 10u128.pow((token.eth_decimals - token.sum_decimals) as u32);
            sum_amount.checked_mul(multiplier)
        }
    }

    /// Enable deposits for a token
    pub fn enable_deposits(&self, eth_address: &EthAddress) -> Result<()> {
        let mut by_eth = self.by_eth_address.write();
        let token = by_eth
            .get_mut(eth_address)
            .ok_or_else(|| BridgeError::TokenNotSupported(eth_address.to_hex()))?;

        token.deposits_enabled = true;

        // Also update by_sum_id
        let mut by_sum = self.by_sum_id.write();
        if let Some(t) = by_sum.get_mut(&token.sum_token_id) {
            t.deposits_enabled = true;
        }

        Ok(())
    }

    /// Disable deposits for a token
    pub fn disable_deposits(&self, eth_address: &EthAddress) -> Result<()> {
        let mut by_eth = self.by_eth_address.write();
        let token = by_eth
            .get_mut(eth_address)
            .ok_or_else(|| BridgeError::TokenNotSupported(eth_address.to_hex()))?;

        token.deposits_enabled = false;

        let mut by_sum = self.by_sum_id.write();
        if let Some(t) = by_sum.get_mut(&token.sum_token_id) {
            t.deposits_enabled = false;
        }

        Ok(())
    }

    /// Enable withdrawals for a token
    pub fn enable_withdrawals(&self, eth_address: &EthAddress) -> Result<()> {
        let mut by_eth = self.by_eth_address.write();
        let token = by_eth
            .get_mut(eth_address)
            .ok_or_else(|| BridgeError::TokenNotSupported(eth_address.to_hex()))?;

        token.withdrawals_enabled = true;

        let mut by_sum = self.by_sum_id.write();
        if let Some(t) = by_sum.get_mut(&token.sum_token_id) {
            t.withdrawals_enabled = true;
        }

        Ok(())
    }

    /// Disable withdrawals for a token
    pub fn disable_withdrawals(&self, eth_address: &EthAddress) -> Result<()> {
        let mut by_eth = self.by_eth_address.write();
        let token = by_eth
            .get_mut(eth_address)
            .ok_or_else(|| BridgeError::TokenNotSupported(eth_address.to_hex()))?;

        token.withdrawals_enabled = false;

        let mut by_sum = self.by_sum_id.write();
        if let Some(t) = by_sum.get_mut(&token.sum_token_id) {
            t.withdrawals_enabled = false;
        }

        Ok(())
    }
}

impl Default for WrappedTokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry() {
        let registry = WrappedTokenRegistry::new();

        // Wrapped ETH should be registered by default
        assert!(registry.is_supported(&EthAddress::ZERO));

        let weth = registry.get_by_eth(&EthAddress::ZERO).unwrap();
        assert_eq!(weth.symbol, "sETH");
    }

    #[test]
    fn test_decimal_conversion() {
        let registry = WrappedTokenRegistry::new();

        // ETH has 18 decimals, sETH has 9
        // 1 ETH (10^18) should become 1 sETH (10^9)
        let eth_amount = 1_000_000_000_000_000_000u128; // 1 ETH
        let sum_amount = registry.convert_to_sum(&EthAddress::ZERO, eth_amount).unwrap();
        assert_eq!(sum_amount, 1_000_000_000u128); // 1 sETH
    }
}
