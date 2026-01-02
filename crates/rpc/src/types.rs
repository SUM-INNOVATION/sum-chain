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

// ============================================================================
// NFT (SUM-721) Types
// ============================================================================

/// NFT collection info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCollectionInfo {
    /// Collection ID (hex)
    pub collection_id: String,
    /// Collection name
    pub name: String,
    /// Collection symbol
    pub symbol: String,
    /// Collection description
    pub description: String,
    /// Owner address
    pub owner: String,
    /// Maximum supply (0 = unlimited)
    pub max_supply: u64,
    /// Current total supply
    pub total_supply: u64,
    /// Whether tokens can be transferred
    pub transferable: bool,
    /// Whether tokens can be burned
    pub burnable: bool,
    /// Whether metadata can be updated
    pub metadata_updatable: bool,
    /// Royalty in basis points (100 = 1%)
    pub royalty_bps: u16,
    /// Royalty recipient address
    pub royalty_recipient: String,
    /// Base URI for metadata
    pub base_uri: Option<String>,
    /// Creation timestamp (milliseconds)
    pub created_at: u64,
}

/// NFT token info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTokenInfo {
    /// Collection ID (hex)
    pub collection_id: String,
    /// Token ID
    pub token_id: u64,
    /// Current owner address
    pub owner: String,
    /// Original creator address
    pub creator: String,
    /// Token metadata (JSON string or hex for binary)
    pub metadata: String,
    /// Whether this is a certified document
    pub is_document: bool,
    /// Token URI type (onchain, ipfs, url)
    pub uri_type: String,
    /// Token URI value
    pub uri_value: Option<String>,
    /// Approved address for transfer
    pub approved: Option<String>,
    /// Whether token is locked
    pub locked: bool,
    /// Number of transfers
    pub transfer_count: u32,
    /// Minting timestamp (milliseconds)
    pub minted_at: u64,
}

/// List of tokens owned by an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftOwnerTokens {
    /// Owner address
    pub owner: String,
    /// Total count of tokens owned
    pub count: u64,
    /// List of (collection_id, token_id) pairs
    pub tokens: Vec<NftTokenRef>,
}

/// Reference to an NFT token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTokenRef {
    /// Collection ID (hex)
    pub collection_id: String,
    /// Token ID
    pub token_id: u64,
}

/// NFT operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftOperationResult {
    /// Transaction hash
    pub tx_hash: String,
    /// Whether operation succeeded
    pub success: bool,
    /// Collection ID (if applicable)
    pub collection_id: Option<String>,
    /// Token ID (if applicable)
    pub token_id: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// SRC-20 Token Types
// ============================================================================

/// SRC-20 token info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token ID (hex)
    pub token_id: String,
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Decimal places
    pub decimals: u8,
    /// Token owner address
    pub owner: String,
    /// Current total supply
    pub total_supply: String,
    /// Maximum supply (0 = unlimited)
    pub max_supply: String,
    /// Whether new tokens can be minted
    pub mintable: bool,
    /// Whether tokens can be burned
    pub burnable: bool,
    /// Whether the token can be paused
    pub pausable: bool,
    /// Whether token transfers are currently paused
    pub paused: bool,
    /// Creation timestamp (milliseconds)
    pub created_at: u64,
    /// Creation block height
    pub created_at_block: u64,
}

/// Token balance for a specific holder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token ID (hex)
    pub token_id: String,
    /// Token symbol
    pub symbol: String,
    /// Decimal places
    pub decimals: u8,
    /// Balance in base units
    pub balance: String,
}

/// Token allowance info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAllowance {
    /// Token ID (hex)
    pub token_id: String,
    /// Owner address
    pub owner: String,
    /// Spender address
    pub spender: String,
    /// Allowance amount in base units
    pub allowance: String,
}

/// List of tokens owned by an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHoldings {
    /// Owner address
    pub owner: String,
    /// Total count of different tokens held
    pub count: u64,
    /// List of token balances
    pub tokens: Vec<TokenBalance>,
}

/// Token transfer event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferEvent {
    /// Token ID (hex)
    pub token_id: String,
    /// From address
    pub from: String,
    /// To address
    pub to: String,
    /// Amount transferred
    pub amount: String,
    /// Block height
    pub block_height: u64,
    /// Transaction hash
    pub tx_hash: String,
}

/// Token operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenOperationResult {
    /// Transaction hash
    pub tx_hash: String,
    /// Whether operation succeeded
    pub success: bool,
    /// Token ID (if applicable)
    pub token_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

// ============================================================================
// Smart Contract (SUMC) Types
// ============================================================================

/// Contract info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    /// Contract address
    pub address: String,
    /// Code hash (hex)
    pub code_hash: String,
    /// Owner address
    pub owner: String,
    /// Contract balance in Koppa
    pub balance: String,
    /// Whether the contract is upgradeable
    pub upgradeable: bool,
    /// Deployment timestamp (milliseconds)
    pub deployed_at: u64,
    /// Deployment block height
    pub deployed_at_block: u64,
}

/// Contract deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployResult {
    /// Transaction hash
    pub tx_hash: String,
    /// Deployed contract address
    pub contract_address: String,
    /// Code hash (hex)
    pub code_hash: String,
    /// Gas used
    pub gas_used: u64,
    /// Whether deployment succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Contract call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCallResult {
    /// Transaction hash (for write calls)
    pub tx_hash: Option<String>,
    /// Return data (hex encoded)
    pub return_data: String,
    /// Gas used
    pub gas_used: u64,
    /// Whether call succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Events emitted during execution
    pub events: Vec<ContractEventInfo>,
}

/// Contract event info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEventInfo {
    /// Contract that emitted the event
    pub contract: String,
    /// Event topics (hex encoded)
    pub topics: Vec<String>,
    /// Event data (hex encoded)
    pub data: String,
}

/// View call request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewCallRequest {
    /// Contract address
    pub contract: String,
    /// Method name to call
    pub method: String,
    /// Arguments (hex encoded)
    pub args: String,
    /// Optional caller address (for access control)
    pub from: Option<String>,
}

/// Contract storage query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStorageResult {
    /// Contract address
    pub contract: String,
    /// Storage key (hex)
    pub key: String,
    /// Storage value (hex), None if not found
    pub value: Option<String>,
}

/// Gas estimation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimateResult {
    /// Estimated gas needed
    pub gas_estimate: u64,
    /// Gas price in Koppa per gas unit
    pub gas_price: String,
    /// Total estimated cost in Koppa
    pub total_cost: String,
}
