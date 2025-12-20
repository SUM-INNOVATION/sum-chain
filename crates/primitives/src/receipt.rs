//! Transaction receipts for SUM Chain.
//!
//! Receipts record the outcome of transaction execution,
//! including success/failure status and any fees paid.

use serde::{Deserialize, Serialize};

use crate::{Balance, BlockHeight, Hash};

/// Status of a transaction after execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction executed successfully
    Success,
    /// Transaction failed - invalid signature
    InvalidSignature,
    /// Transaction failed - wrong nonce
    InvalidNonce,
    /// Transaction failed - insufficient balance
    InsufficientBalance,
    /// Transaction failed - invalid chain ID
    InvalidChainId,
    /// Transaction failed - other reason
    Failed(u32),
}

impl TxStatus {
    /// Check if transaction succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, TxStatus::Success)
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            TxStatus::Success => "success",
            TxStatus::InvalidSignature => "invalid signature",
            TxStatus::InvalidNonce => "invalid nonce",
            TxStatus::InsufficientBalance => "insufficient balance",
            TxStatus::InvalidChainId => "invalid chain id",
            TxStatus::Failed(_) => "failed",
        }
    }
}

/// Receipt for an executed transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction
    pub tx_hash: Hash,
    /// Block height where tx was included
    pub block_height: BlockHeight,
    /// Index of tx within the block
    pub tx_index: u32,
    /// Execution status
    pub status: TxStatus,
    /// Fee actually paid (may differ if tx failed early)
    pub fee_paid: Balance,
}

impl Receipt {
    /// Create a new receipt
    pub fn new(
        tx_hash: Hash,
        block_height: BlockHeight,
        tx_index: u32,
        status: TxStatus,
        fee_paid: Balance,
    ) -> Self {
        Self {
            tx_hash,
            block_height,
            tx_index,
            status,
            fee_paid,
        }
    }

    /// Create a success receipt
    pub fn success(
        tx_hash: Hash,
        block_height: BlockHeight,
        tx_index: u32,
        fee_paid: Balance,
    ) -> Self {
        Self::new(tx_hash, block_height, tx_index, TxStatus::Success, fee_paid)
    }

    /// Check if the transaction succeeded
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Receipt serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_is_success() {
        assert!(TxStatus::Success.is_success());
        assert!(!TxStatus::InvalidNonce.is_success());
        assert!(!TxStatus::InsufficientBalance.is_success());
    }

    #[test]
    fn test_receipt_serialization() {
        let receipt = Receipt::success(Hash::hash(b"tx"), 100, 0, 10);
        let bytes = receipt.to_bytes();
        let receipt2 = Receipt::from_bytes(&bytes).unwrap();
        assert_eq!(receipt, receipt2);
    }
}
