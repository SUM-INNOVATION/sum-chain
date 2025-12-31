//! SRC-20 Token transaction types
//!
//! Defines the operations that can be performed on fungible tokens.

use serde::{Deserialize, Serialize};
use sumchain_primitives::Address;

use crate::token::TokenConfig;

/// Token operation codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TokenOperation {
    /// Create a new token
    Create = 0,
    /// Mint new tokens
    Mint = 1,
    /// Burn tokens
    Burn = 2,
    /// Transfer tokens
    Transfer = 3,
    /// Approve spending allowance
    Approve = 4,
    /// Transfer using allowance
    TransferFrom = 5,
    /// Pause token transfers
    Pause = 6,
    /// Unpause token transfers
    Unpause = 7,
    /// Transfer token ownership
    TransferOwnership = 8,
    /// Add a minter
    AddMinter = 9,
    /// Remove a minter
    RemoveMinter = 10,
}

impl TokenOperation {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(TokenOperation::Create),
            1 => Some(TokenOperation::Mint),
            2 => Some(TokenOperation::Burn),
            3 => Some(TokenOperation::Transfer),
            4 => Some(TokenOperation::Approve),
            5 => Some(TokenOperation::TransferFrom),
            6 => Some(TokenOperation::Pause),
            7 => Some(TokenOperation::Unpause),
            8 => Some(TokenOperation::TransferOwnership),
            9 => Some(TokenOperation::AddMinter),
            10 => Some(TokenOperation::RemoveMinter),
            _ => None,
        }
    }

    /// Check if this operation requires token ownership
    pub fn requires_ownership(&self) -> bool {
        matches!(
            self,
            TokenOperation::Pause
                | TokenOperation::Unpause
                | TokenOperation::TransferOwnership
                | TokenOperation::AddMinter
                | TokenOperation::RemoveMinter
        )
    }

    /// Check if this operation requires minter role
    pub fn requires_minter(&self) -> bool {
        matches!(self, TokenOperation::Mint)
    }
}

/// Token-specific transaction data (embedded in TxPayload)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTxData {
    /// Token ID (32 bytes) - zero for Create operation
    pub token_id: [u8; 32],
    /// Token operation code
    pub operation: TokenOperation,
    /// Operation-specific data (serialized)
    pub data: Vec<u8>,
}

impl TokenTxData {
    /// Create a new Create token transaction
    pub fn create(
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u128,
        config: TokenConfig,
    ) -> Self {
        let action = TokenAction::Create {
            name,
            symbol,
            decimals,
            initial_supply,
            config,
        };
        Self {
            token_id: [0u8; 32], // Will be computed on execution
            operation: TokenOperation::Create,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Create a Mint transaction
    pub fn mint(token_id: [u8; 32], to: Address, amount: u128) -> Self {
        let action = TokenAction::Mint { to, amount };
        Self {
            token_id,
            operation: TokenOperation::Mint,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Create a Burn transaction
    pub fn burn(token_id: [u8; 32], amount: u128) -> Self {
        let action = TokenAction::Burn { amount };
        Self {
            token_id,
            operation: TokenOperation::Burn,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Create a Transfer transaction
    pub fn transfer(token_id: [u8; 32], to: Address, amount: u128) -> Self {
        let action = TokenAction::Transfer { to, amount };
        Self {
            token_id,
            operation: TokenOperation::Transfer,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Create an Approve transaction
    pub fn approve(token_id: [u8; 32], spender: Address, amount: u128) -> Self {
        let action = TokenAction::Approve { spender, amount };
        Self {
            token_id,
            operation: TokenOperation::Approve,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Create a TransferFrom transaction
    pub fn transfer_from(token_id: [u8; 32], from: Address, to: Address, amount: u128) -> Self {
        let action = TokenAction::TransferFrom { from, to, amount };
        Self {
            token_id,
            operation: TokenOperation::TransferFrom,
            data: bincode::serialize(&action).expect("TokenAction serialization should not fail"),
        }
    }

    /// Deserialize the action from data
    pub fn action(&self) -> Result<TokenAction, bincode::Error> {
        bincode::deserialize(&self.data)
    }
}

/// Token action details (deserialized from TokenTxData.data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenAction {
    /// Create a new token
    Create {
        /// Token name
        name: String,
        /// Token symbol
        symbol: String,
        /// Decimal places
        decimals: u8,
        /// Initial supply (minted to creator)
        initial_supply: u128,
        /// Token configuration
        config: TokenConfig,
    },

    /// Mint new tokens
    Mint {
        /// Recipient of minted tokens
        to: Address,
        /// Amount to mint
        amount: u128,
    },

    /// Burn tokens
    Burn {
        /// Amount to burn (from sender's balance)
        amount: u128,
    },

    /// Transfer tokens
    Transfer {
        /// Recipient address
        to: Address,
        /// Amount to transfer
        amount: u128,
    },

    /// Approve spending allowance
    Approve {
        /// Spender address
        spender: Address,
        /// Allowance amount (replaces existing)
        amount: u128,
    },

    /// Transfer tokens using allowance
    TransferFrom {
        /// Owner address
        from: Address,
        /// Recipient address
        to: Address,
        /// Amount to transfer
        amount: u128,
    },

    /// Pause token
    Pause,

    /// Unpause token
    Unpause,

    /// Transfer token ownership
    TransferOwnership {
        /// New owner address
        new_owner: Address,
    },

    /// Add a minter
    AddMinter {
        /// Minter address to add
        minter: Address,
    },

    /// Remove a minter
    RemoveMinter {
        /// Minter address to remove
        minter: Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from_hex("0x0000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_operation_from_byte() {
        assert_eq!(TokenOperation::from_byte(0), Some(TokenOperation::Create));
        assert_eq!(TokenOperation::from_byte(3), Some(TokenOperation::Transfer));
        assert_eq!(TokenOperation::from_byte(100), None);
    }

    #[test]
    fn test_token_tx_data_create() {
        let tx = TokenTxData::create(
            "Test Token".to_string(),
            "TEST".to_string(),
            9,
            1_000_000_000,
            TokenConfig::default(),
        );

        assert_eq!(tx.operation, TokenOperation::Create);
        assert_eq!(tx.token_id, [0u8; 32]);

        let action = tx.action().unwrap();
        match action {
            TokenAction::Create { name, symbol, decimals, initial_supply, .. } => {
                assert_eq!(name, "Test Token");
                assert_eq!(symbol, "TEST");
                assert_eq!(decimals, 9);
                assert_eq!(initial_supply, 1_000_000_000);
            }
            _ => panic!("Wrong action type"),
        }
    }

    #[test]
    fn test_token_tx_data_transfer() {
        let token_id = [1u8; 32];
        let tx = TokenTxData::transfer(token_id, test_address(), 500_000_000);

        assert_eq!(tx.operation, TokenOperation::Transfer);
        assert_eq!(tx.token_id, token_id);

        let action = tx.action().unwrap();
        match action {
            TokenAction::Transfer { to, amount } => {
                assert_eq!(to, test_address());
                assert_eq!(amount, 500_000_000);
            }
            _ => panic!("Wrong action type"),
        }
    }

    #[test]
    fn test_operation_permissions() {
        assert!(TokenOperation::Pause.requires_ownership());
        assert!(TokenOperation::TransferOwnership.requires_ownership());
        assert!(!TokenOperation::Transfer.requires_ownership());
        assert!(!TokenOperation::Burn.requires_ownership());

        assert!(TokenOperation::Mint.requires_minter());
        assert!(!TokenOperation::Transfer.requires_minter());
    }
}
