//! Transaction types for SUM Chain.
//!
//! Transactions represent transfers of the native SUM token.
//! Each transaction must be signed by the sender's private key.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, Balance, ChainId, Hash, Nonce};

/// Unsigned transaction data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Chain ID to prevent replay across networks
    pub chain_id: ChainId,
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Amount to transfer (in smallest unit)
    pub amount: Balance,
    /// Transaction fee paid to validator
    pub fee: Balance,
    /// Sender's nonce (must match account nonce)
    pub nonce: Nonce,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        chain_id: ChainId,
        from: Address,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: Nonce,
    ) -> Self {
        Self {
            chain_id,
            from,
            to,
            amount,
            fee,
            nonce,
        }
    }

    /// Compute the signing hash for this transaction
    /// This is what gets signed by the sender
    pub fn signing_hash(&self) -> Hash {
        // Deterministic serialization using bincode
        let bytes = bincode::serialize(self).expect("Transaction serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Serialize transaction to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serialization should not fail")
    }

    /// Deserialize transaction from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Total cost to sender (amount + fee)
    pub fn total_cost(&self) -> Balance {
        self.amount.saturating_add(self.fee)
    }
}

/// Signed transaction (transaction + signature)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The unsigned transaction
    pub tx: Transaction,
    /// Ed25519 signature (64 bytes)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    /// Signer's public key (for verification)
    pub public_key: [u8; 32],
}

impl SignedTransaction {
    /// Create a new signed transaction
    pub fn new(tx: Transaction, signature: [u8; 64], public_key: [u8; 32]) -> Self {
        Self {
            tx,
            signature,
            public_key,
        }
    }

    /// Compute the transaction hash (unique identifier)
    pub fn hash(&self) -> Hash {
        let bytes =
            bincode::serialize(self).expect("SignedTransaction serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Get the transaction signing hash
    pub fn signing_hash(&self) -> Hash {
        self.tx.signing_hash()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SignedTransaction serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from hex string
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        Self::from_bytes(&bytes).map_err(|e| e.to_string())
    }

    /// Get sender address
    pub fn sender(&self) -> Address {
        self.tx.from
    }

    /// Get the expected address from the public key
    pub fn signer_address(&self) -> Address {
        Address::from_public_key(&self.public_key)
    }

    /// Verify that the signer matches the from address
    pub fn verify_signer(&self) -> bool {
        self.signer_address() == self.tx.from
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        Transaction::new(
            1, // chain_id
            Address::from_hex("0x0000000000000000000000000000000000000001").unwrap(),
            Address::from_hex("0x0000000000000000000000000000000000000002").unwrap(),
            1000,
            10,
            0,
        )
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = sample_tx();
        let h1 = tx.signing_hash();
        let h2 = tx.signing_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let tx1 = sample_tx();
        let mut tx2 = sample_tx();
        tx2.nonce = 1;
        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
    }

    #[test]
    fn test_total_cost() {
        let tx = sample_tx();
        assert_eq!(tx.total_cost(), 1010);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.to_bytes();
        let tx2 = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, tx2);
    }

    #[test]
    fn test_signed_tx_hex_roundtrip() {
        let tx = sample_tx();
        let signed = SignedTransaction::new(tx, [0u8; 64], [0u8; 32]);
        let hex = signed.to_hex();
        let signed2 = SignedTransaction::from_hex(&hex).unwrap();
        assert_eq!(signed, signed2);
    }
}
