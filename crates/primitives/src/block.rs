//! Block and BlockHeader types for SUM Chain.
//!
//! Blocks contain a header with metadata and a list of transactions.
//! The header includes the proposer's signature for PoA validation.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{BlockHeight, Hash, SignedTransaction, Timestamp};

/// Block header containing metadata and proposer signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Hash of the parent block (zero for genesis)
    pub parent_hash: Hash,
    /// Block height (0 for genesis)
    pub height: BlockHeight,
    /// Block creation timestamp (ms since epoch)
    pub timestamp: Timestamp,
    /// Merkle root of transactions
    pub tx_root: Hash,
    /// Root hash of state after applying this block
    pub state_root: Hash,
    /// Proposer's Ed25519 public key
    pub proposer_pubkey: [u8; 32],
    /// Proposer's signature over the header hash (excluding this field)
    #[serde(with = "BigArray")]
    pub proposer_sig: [u8; 64],
}

impl BlockHeader {
    /// Create a new block header (signature must be added separately)
    pub fn new(
        parent_hash: Hash,
        height: BlockHeight,
        timestamp: Timestamp,
        tx_root: Hash,
        state_root: Hash,
        proposer_pubkey: [u8; 32],
    ) -> Self {
        Self {
            parent_hash,
            height,
            timestamp,
            tx_root,
            state_root,
            proposer_pubkey,
            proposer_sig: [0u8; 64], // Will be filled after signing
        }
    }

    /// Compute the hash that the proposer signs
    /// This excludes the signature field itself to avoid circular dependency
    pub fn signing_hash(&self) -> Hash {
        // Create a copy without signature for hashing
        let signable = SignableHeader {
            parent_hash: self.parent_hash,
            height: self.height,
            timestamp: self.timestamp,
            tx_root: self.tx_root,
            state_root: self.state_root,
            proposer_pubkey: self.proposer_pubkey,
        };
        let bytes = bincode::serialize(&signable).expect("Header serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Compute the full block header hash (includes signature)
    /// This is the hash used to reference the block
    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(self).expect("Header serialization should not fail");
        Hash::hash(&bytes)
    }

    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.parent_hash.is_zero()
    }

    /// Set the proposer signature
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.proposer_sig = signature;
    }
}

/// Header data that gets signed (excludes the signature itself)
#[derive(Serialize)]
struct SignableHeader {
    parent_hash: Hash,
    height: BlockHeight,
    timestamp: Timestamp,
    tx_root: Hash,
    state_root: Hash,
    proposer_pubkey: [u8; 32],
}

/// A complete block with header and transactions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<SignedTransaction>,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Create a genesis block
    pub fn genesis(state_root: Hash, proposer_pubkey: [u8; 32], timestamp: Timestamp) -> Self {
        let header = BlockHeader::new(
            Hash::ZERO,
            0,
            timestamp,
            Hash::ZERO, // No transactions in genesis
            state_root,
            proposer_pubkey,
        );

        Self {
            header,
            transactions: Vec::new(),
        }
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get block height
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Compute the transaction root from the block's transactions
    pub fn compute_tx_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return Hash::ZERO;
        }

        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        Hash::merkle_root(&tx_hashes)
    }

    /// Verify that tx_root matches the transactions
    pub fn verify_tx_root(&self) -> bool {
        self.header.tx_root == self.compute_tx_root()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Block serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Get the number of transactions
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader::new(
            Hash::ZERO,
            1,
            1000,
            Hash::ZERO,
            Hash::hash(b"state"),
            [0u8; 32],
        )
    }

    #[test]
    fn test_signing_hash_excludes_signature() {
        let mut header1 = sample_header();
        let mut header2 = sample_header();

        header1.proposer_sig = [1u8; 64];
        header2.proposer_sig = [2u8; 64];

        // Signing hash should be the same regardless of signature
        assert_eq!(header1.signing_hash(), header2.signing_hash());
    }

    #[test]
    fn test_block_hash_includes_signature() {
        let mut header1 = sample_header();
        let mut header2 = sample_header();

        header1.proposer_sig = [1u8; 64];
        header2.proposer_sig = [2u8; 64];

        // Full hash should differ with different signatures
        assert_ne!(header1.hash(), header2.hash());
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(Hash::hash(b"genesis_state"), [0u8; 32], 0);
        assert!(genesis.header.is_genesis());
        assert_eq!(genesis.height(), 0);
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn test_tx_root_empty() {
        let block = Block::new(sample_header(), vec![]);
        assert_eq!(block.compute_tx_root(), Hash::ZERO);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let block = Block::genesis(Hash::hash(b"state"), [42u8; 32], 12345);
        let bytes = block.to_bytes();
        let block2 = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block, block2);
    }
}
