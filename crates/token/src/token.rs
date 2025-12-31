//! SRC-20 Token types and management
//!
//! A token represents a fungible asset on SUM Chain.
//! Each token has its own supply, configuration, and holder balances.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Hash, Timestamp};

use crate::{MAX_DECIMALS, MAX_NAME_BYTES, MAX_SYMBOL_BYTES};

/// Unique identifier for a token (derived from creator + symbol + nonce)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    /// Create a new token ID from creator address and symbol
    pub fn new(creator: &Address, symbol: &str, nonce: u64) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(creator.as_bytes());
        data.extend_from_slice(symbol.as_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        let hash = Hash::hash(&data);
        Self(*hash.as_bytes())
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("Invalid length: expected 32, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Token configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Maximum supply (0 = unlimited)
    pub max_supply: u128,

    /// Whether new tokens can be minted
    pub mintable: bool,

    /// Whether tokens can be burned
    pub burnable: bool,

    /// Whether the token can be paused
    pub pausable: bool,

    /// List of addresses that can mint (empty = only owner)
    pub minters: Vec<Address>,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            max_supply: 0, // Unlimited
            mintable: true,
            burnable: true,
            pausable: false,
            minters: vec![],
        }
    }
}

impl TokenConfig {
    /// Fixed supply token (no minting after creation)
    pub fn fixed_supply(max_supply: u128) -> Self {
        Self {
            max_supply,
            mintable: false,
            burnable: true,
            pausable: false,
            minters: vec![],
        }
    }

    /// Stablecoin-style token (mintable, burnable, pausable)
    pub fn stablecoin() -> Self {
        Self {
            max_supply: 0,
            mintable: true,
            burnable: true,
            pausable: true,
            minters: vec![],
        }
    }

    /// Governance token with capped supply
    pub fn governance(max_supply: u128) -> Self {
        Self {
            max_supply,
            mintable: true,
            burnable: false,
            pausable: false,
            minters: vec![],
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // If not mintable, max_supply must be set
        if !self.mintable && self.max_supply == 0 {
            return Err("Non-mintable tokens must have a max_supply".to_string());
        }
        Ok(())
    }
}

/// An SRC-20 Token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique token identifier
    pub id: TokenId,

    /// Token name (e.g., "SUM Dollar")
    pub name: String,

    /// Token symbol (e.g., "SUMD")
    pub symbol: String,

    /// Number of decimal places (typically 9 for Koppa-pegged, 18 for ERC-20 compat)
    pub decimals: u8,

    /// Token owner (can mint, pause, update config)
    pub owner: Address,

    /// Configuration
    pub config: TokenConfig,

    /// Current total supply
    pub total_supply: u128,

    /// Whether token transfers are paused
    pub paused: bool,

    /// Creation timestamp
    pub created_at: Timestamp,

    /// Creation block height
    pub created_at_block: u64,
}

impl Token {
    /// Create a new token
    pub fn new(
        name: String,
        symbol: String,
        decimals: u8,
        owner: Address,
        config: TokenConfig,
        initial_supply: u128,
        created_at: Timestamp,
        created_at_block: u64,
        nonce: u64,
    ) -> Result<Self, String> {
        // Validate name
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(format!(
                "Name must be 1-{} bytes, got {}",
                MAX_NAME_BYTES,
                name.len()
            ));
        }

        // Validate symbol
        if symbol.is_empty() || symbol.len() > MAX_SYMBOL_BYTES {
            return Err(format!(
                "Symbol must be 1-{} bytes, got {}",
                MAX_SYMBOL_BYTES,
                symbol.len()
            ));
        }

        // Validate symbol characters (alphanumeric only)
        if !symbol.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("Symbol must be alphanumeric only".to_string());
        }

        // Validate decimals
        if decimals > MAX_DECIMALS {
            return Err(format!("Decimals must be 0-{}, got {}", MAX_DECIMALS, decimals));
        }

        // Validate config
        config.validate()?;

        // Validate initial supply against max supply
        if config.max_supply > 0 && initial_supply > config.max_supply {
            return Err(format!(
                "Initial supply {} exceeds max supply {}",
                initial_supply, config.max_supply
            ));
        }

        let id = TokenId::new(&owner, &symbol, nonce);

        Ok(Self {
            id,
            name,
            symbol,
            decimals,
            owner,
            config,
            total_supply: initial_supply,
            paused: false,
            created_at,
            created_at_block,
        })
    }

    /// Check if more tokens can be minted
    pub fn can_mint(&self, amount: u128) -> bool {
        if !self.config.mintable {
            return false;
        }
        if self.config.max_supply == 0 {
            return true; // Unlimited
        }
        self.total_supply.checked_add(amount)
            .map(|new_supply| new_supply <= self.config.max_supply)
            .unwrap_or(false)
    }

    /// Check if an address can mint
    pub fn can_address_mint(&self, minter: &Address) -> bool {
        if minter == &self.owner {
            return true;
        }
        self.config.minters.contains(minter)
    }

    /// Mint new tokens (updates total_supply)
    pub fn mint(&mut self, amount: u128) -> Result<(), String> {
        if !self.config.mintable {
            return Err("Token is not mintable".to_string());
        }

        let new_supply = self.total_supply.checked_add(amount)
            .ok_or("Overflow in mint")?;

        if self.config.max_supply > 0 && new_supply > self.config.max_supply {
            return Err(format!(
                "Would exceed max supply: {} + {} > {}",
                self.total_supply, amount, self.config.max_supply
            ));
        }

        self.total_supply = new_supply;
        Ok(())
    }

    /// Burn tokens (updates total_supply)
    pub fn burn(&mut self, amount: u128) -> Result<(), String> {
        if !self.config.burnable {
            return Err("Token is not burnable".to_string());
        }

        if amount > self.total_supply {
            return Err(format!(
                "Cannot burn {} from total supply {}",
                amount, self.total_supply
            ));
        }

        self.total_supply = self.total_supply.saturating_sub(amount);
        Ok(())
    }

    /// Pause the token
    pub fn pause(&mut self) -> Result<(), String> {
        if !self.config.pausable {
            return Err("Token is not pausable".to_string());
        }
        self.paused = true;
        Ok(())
    }

    /// Unpause the token
    pub fn unpause(&mut self) -> Result<(), String> {
        if !self.config.pausable {
            return Err("Token is not pausable".to_string());
        }
        self.paused = false;
        Ok(())
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

/// Token info for RPC responses (subset of Token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token ID (hex)
    pub token_id: String,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Decimals
    pub decimals: u8,
    /// Owner address
    pub owner: String,
    /// Total supply
    pub total_supply: String,
    /// Max supply (0 = unlimited)
    pub max_supply: String,
    /// Is mintable
    pub mintable: bool,
    /// Is burnable
    pub burnable: bool,
    /// Is pausable
    pub pausable: bool,
    /// Is currently paused
    pub paused: bool,
    /// Creation timestamp (ms)
    pub created_at: u64,
}

impl From<&Token> for TokenInfo {
    fn from(token: &Token) -> Self {
        Self {
            token_id: token.id.to_hex(),
            name: token.name.clone(),
            symbol: token.symbol.clone(),
            decimals: token.decimals,
            owner: token.owner.to_base58(),
            total_supply: token.total_supply.to_string(),
            max_supply: token.config.max_supply.to_string(),
            mintable: token.config.mintable,
            burnable: token.config.burnable,
            pausable: token.config.pausable,
            paused: token.paused,
            created_at: token.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from_hex("0x0000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_token_id_creation() {
        let creator = test_address();
        let id1 = TokenId::new(&creator, "TEST", 0);
        let id2 = TokenId::new(&creator, "TEST", 0);
        let id3 = TokenId::new(&creator, "TEST", 1);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3); // Different nonce
    }

    #[test]
    fn test_token_id_hex_roundtrip() {
        let creator = test_address();
        let id = TokenId::new(&creator, "TEST", 0);
        let hex = id.to_hex();
        let id2 = TokenId::from_hex(&hex).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_token_creation() {
        let token = Token::new(
            "Test Token".to_string(),
            "TEST".to_string(),
            9,
            test_address(),
            TokenConfig::default(),
            1_000_000_000, // 1 token with 9 decimals
            1000,
            1,
            0,
        )
        .unwrap();

        assert_eq!(token.name, "Test Token");
        assert_eq!(token.symbol, "TEST");
        assert_eq!(token.decimals, 9);
        assert_eq!(token.total_supply, 1_000_000_000);
        assert!(!token.paused);
    }

    #[test]
    fn test_token_validation() {
        // Empty name
        let result = Token::new(
            "".to_string(),
            "TEST".to_string(),
            9,
            test_address(),
            TokenConfig::default(),
            0,
            1000,
            1,
            0,
        );
        assert!(result.is_err());

        // Invalid symbol characters
        let result = Token::new(
            "Test".to_string(),
            "TEST-1".to_string(), // Hyphen not allowed
            9,
            test_address(),
            TokenConfig::default(),
            0,
            1000,
            1,
            0,
        );
        assert!(result.is_err());

        // Too many decimals
        let result = Token::new(
            "Test".to_string(),
            "TEST".to_string(),
            19, // Max is 18
            test_address(),
            TokenConfig::default(),
            0,
            1000,
            1,
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_token_mint_burn() {
        let mut token = Token::new(
            "Test Token".to_string(),
            "TEST".to_string(),
            9,
            test_address(),
            TokenConfig::default(),
            1_000_000_000,
            1000,
            1,
            0,
        )
        .unwrap();

        // Mint
        assert!(token.mint(500_000_000).is_ok());
        assert_eq!(token.total_supply, 1_500_000_000);

        // Burn
        assert!(token.burn(200_000_000).is_ok());
        assert_eq!(token.total_supply, 1_300_000_000);
    }

    #[test]
    fn test_fixed_supply_token() {
        let config = TokenConfig::fixed_supply(1_000_000_000_000);
        let mut token = Token::new(
            "Fixed Token".to_string(),
            "FIX".to_string(),
            9,
            test_address(),
            config,
            1_000_000_000_000, // Full supply minted at creation
            1000,
            1,
            0,
        )
        .unwrap();

        // Cannot mint more
        assert!(!token.can_mint(1));
        assert!(token.mint(1).is_err());
    }

    #[test]
    fn test_capped_supply() {
        let mut config = TokenConfig::default();
        config.max_supply = 1_000_000_000_000; // 1000 tokens

        let mut token = Token::new(
            "Capped Token".to_string(),
            "CAP".to_string(),
            9,
            test_address(),
            config,
            100_000_000_000, // 100 tokens
            1000,
            1,
            0,
        )
        .unwrap();

        // Can mint up to cap
        assert!(token.can_mint(900_000_000_000));
        assert!(token.mint(900_000_000_000).is_ok());

        // Cannot exceed cap
        assert!(!token.can_mint(1));
        assert!(token.mint(1).is_err());
    }

    #[test]
    fn test_pausable_token() {
        let mut token = Token::new(
            "Pausable Token".to_string(),
            "PAUSE".to_string(),
            9,
            test_address(),
            TokenConfig::stablecoin(),
            1_000_000_000,
            1000,
            1,
            0,
        )
        .unwrap();

        assert!(!token.paused);
        assert!(token.pause().is_ok());
        assert!(token.paused);
        assert!(token.unpause().is_ok());
        assert!(!token.paused);
    }

    #[test]
    fn test_non_pausable_token() {
        let mut token = Token::new(
            "Test Token".to_string(),
            "TEST".to_string(),
            9,
            test_address(),
            TokenConfig::default(), // Not pausable
            1_000_000_000,
            1000,
            1,
            0,
        )
        .unwrap();

        assert!(token.pause().is_err());
    }
}
