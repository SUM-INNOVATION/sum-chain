//! RPC type definitions for JSON serialization.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{BlockHeight, Nonce, Timestamp};

/// Block info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub hash: String,
    pub height: BlockHeight,
    pub parent_hash: String,
    pub timestamp: Timestamp,
    pub tx_root: String,
    pub state_root: String,
    pub proposer: String,
    pub tx_count: usize,
    pub transactions: Vec<String>, // Transaction hashes
}

/// Transaction info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub fee: String,
    pub nonce: Nonce,
    pub chain_id: u64,
    pub signature: String,
    pub block_height: Option<BlockHeight>,
    pub status: Option<String>,
}

/// Account info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub balance: String,
    pub nonce: Nonce,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub chain_id: u64,
    pub height: BlockHeight,
    pub peer_count: usize,
    pub is_validator: bool,
    pub is_synced: bool,
}

/// Send transaction response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTxResponse {
    pub tx_hash: String,
}

/// Receipt info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInfo {
    pub tx_hash: String,
    pub block_height: BlockHeight,
    pub tx_index: u32,
    pub status: String,
    pub fee_paid: String,
}

/// Validator info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub public_key: String,
    pub address: String,
    pub is_current_proposer: bool,
}

/// Validator set info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetInfo {
    pub validators: Vec<ValidatorInfo>,
    pub current_height: BlockHeight,
    pub current_proposer_index: usize,
}

/// Node info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node version
    pub version: String,
    /// Chain ID
    pub chain_id: u64,
    /// Network name
    pub network: String,
    /// Local peer ID (if P2P is enabled)
    pub peer_id: Option<String>,
    /// Whether running as validator
    pub is_validator: bool,
    /// Current block height
    pub current_height: BlockHeight,
    /// Connected peer count
    pub peer_count: usize,
    /// Mempool size
    pub mempool_size: usize,
    /// Node uptime in seconds
    pub uptime_seconds: u64,
}

/// Finality info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityInfo {
    /// Last finalized block height
    pub finalized_height: BlockHeight,
    /// Last finalized block hash
    pub finalized_hash: String,
    /// Current block height (head)
    pub current_height: BlockHeight,
    /// Finality depth (number of confirmations required)
    pub finality_depth: u64,
    /// Number of blocks awaiting finality
    pub pending_finality: u64,
}

/// Peer info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPeerInfo {
    /// Peer ID
    pub peer_id: String,
    /// Known addresses
    pub addresses: Vec<String>,
    /// Connection state
    pub state: String,
    /// Connection direction (inbound/outbound)
    pub direction: Option<String>,
    /// Reputation score
    pub score: i64,
    /// Seconds since first seen
    pub first_seen_secs: u64,
    /// Seconds since last seen
    pub last_seen_secs: u64,
    /// Number of successful connections
    pub successful_connections: u32,
    /// Number of failed connections
    pub failed_connections: u32,
    /// Whether peer is banned
    pub is_banned: bool,
    /// Tags/labels for this peer
    pub tags: Vec<String>,
}

/// P2P network stats for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pStats {
    /// Total known peers
    pub total_known_peers: usize,
    /// Currently connected peers
    pub connected_peers: usize,
    /// Inbound connections
    pub inbound_connections: usize,
    /// Outbound connections
    pub outbound_connections: usize,
    /// Banned peers count
    pub banned_peers: usize,
    /// Maximum total connections allowed
    pub max_connections: usize,
    /// Maximum inbound connections allowed
    pub max_inbound: usize,
    /// Maximum outbound connections allowed
    pub max_outbound: usize,
}
