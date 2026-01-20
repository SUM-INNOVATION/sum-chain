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

// ============================================================================
// Staking Types
// ============================================================================

/// Staking validator info for RPC responses (includes stake info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingValidatorInfo {
    /// Validator's public key (hex)
    pub pubkey: String,
    /// Validator's address (base58)
    pub address: String,
    /// Self-staked amount in base units
    pub stake: String,
    /// Commission rate in basis points (100 = 1%)
    pub commission_bps: u16,
    /// Validator status (Active, Inactive, Jailed, Unbonding)
    pub status: String,
    /// Block height when validator joined
    pub joined_at: u64,
    /// Block height when validator can unjail (0 if not jailed)
    pub jailed_until: u64,
    /// Number of times this validator has been slashed
    pub slash_count: u32,
    /// Accumulated rewards (not yet claimed)
    pub pending_rewards: String,
    /// Optional metadata (e.g., name, website)
    pub metadata: Option<String>,
}

/// Staking summary for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingSummary {
    /// Total number of validators
    pub total_validators: usize,
    /// Number of active validators
    pub active_validators: usize,
    /// Total staked amount across all validators
    pub total_stake: String,
    /// Minimum stake required to be a validator
    pub min_validator_stake: String,
    /// Maximum number of validators allowed
    pub max_validators: u32,
    /// Current unbonding period in blocks
    pub unbonding_period: u64,
}

/// Staking parameters info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingParamsInfo {
    /// Minimum stake required to be a validator
    pub min_validator_stake: String,
    /// Maximum number of active validators
    pub max_validators: u32,
    /// Unbonding period in blocks
    pub unbonding_period: u64,
    /// Maximum commission rate in basis points
    pub max_commission_bps: u16,
    /// Slash penalty for double signing (basis points)
    pub double_sign_slash_bps: u16,
    /// Slash penalty for downtime (basis points)
    pub downtime_slash_bps: u16,
    /// Jail duration for double signing (blocks)
    pub double_sign_jail_duration: u64,
    /// Jail duration for downtime (blocks)
    pub downtime_jail_duration: u64,
    /// Number of missed blocks before downtime slash
    pub downtime_threshold: u64,
}

// ============================================================================
// Delegation Types
// ============================================================================

/// Delegation info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRpcInfo {
    /// Delegator address (base58)
    pub delegator: String,
    /// Validator address (base58)
    pub validator_address: String,
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Delegated amount in base units
    pub amount: String,
    /// Pending rewards in base units
    pub pending_rewards: String,
    /// Block height when delegation started
    pub delegated_at: u64,
}

/// Unbonding delegation info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingDelegationRpcInfo {
    /// Delegator address (base58)
    pub delegator: String,
    /// Validator address (base58)
    pub validator_address: String,
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Amount being unbonded in base units
    pub amount: String,
    /// Block height when unbonding completes
    pub completion_height: u64,
    /// Whether unbonding is complete
    pub is_complete: bool,
}

/// Delegator summary for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatorSummary {
    /// Delegator address (base58)
    pub delegator: String,
    /// Total amount delegated across all validators
    pub total_delegated: String,
    /// Total pending rewards across all validators
    pub total_pending_rewards: String,
    /// Total amount in unbonding
    pub total_unbonding: String,
    /// Number of active delegations
    pub delegation_count: usize,
    /// Number of pending unbondings
    pub unbonding_count: usize,
}

/// Validator delegation summary for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorDelegationSummary {
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Validator address (base58)
    pub validator_address: String,
    /// Total delegated to this validator
    pub total_delegated: String,
    /// Number of delegators
    pub delegator_count: usize,
}

// ============================================================================
// Slashing Types
// ============================================================================

/// Slashing record info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecordRpcInfo {
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Validator address (base58)
    pub validator_address: String,
    /// Evidence type (DoubleSign or Downtime)
    pub evidence_type: String,
    /// Block height when slashing occurred
    pub slashed_at: u64,
    /// Amount slashed from validator stake
    pub validator_slash_amount: String,
    /// Amount slashed from delegations
    pub delegation_slash_amount: String,
    /// Block height until validator is jailed
    pub jailed_until: u64,
    /// Whether validator is permanently jailed (tombstoned)
    pub tombstoned: bool,
    /// Slash fraction in basis points (100 = 1%)
    pub slash_fraction_bps: u16,
}

/// Validator signing info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSigningRpcInfo {
    /// Validator public key (hex)
    pub validator_pubkey: String,
    /// Validator address (base58)
    pub validator_address: String,
    /// Block height when validator started signing
    pub start_height: u64,
    /// Index offset for missed blocks tracking
    pub index_offset: u64,
    /// Number of missed blocks in current window
    pub missed_blocks_counter: u64,
    /// Whether validator is tombstoned (permanently jailed)
    pub tombstoned: bool,
    /// Block height until validator is jailed (0 if not jailed)
    pub jailed_until: u64,
}

/// Slashing summary for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingSummary {
    /// Total number of slashing events
    pub total_slashing_events: usize,
    /// Total amount slashed from validators
    pub total_validator_slashed: String,
    /// Total amount slashed from delegations
    pub total_delegation_slashed: String,
    /// Number of tombstoned validators
    pub tombstoned_count: usize,
    /// Number of currently jailed validators
    pub jailed_count: usize,
}

// ============================================================================
// Validator Set Types
// ============================================================================

/// Validator entry in a validator set for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetEntryRpcInfo {
    /// Validator public key (hex)
    pub pubkey: String,
    /// Validator address (base58)
    pub address: String,
    /// Total voting power (stake + delegations)
    pub voting_power: String,
    /// Commission rate in basis points
    pub commission_bps: u16,
    /// Voting power percentage in basis points (100 = 1%)
    pub power_percentage_bps: u16,
}

/// Active validator set for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetRpcInfo {
    /// Epoch number
    pub epoch: u64,
    /// Block height when set became active
    pub active_from: u64,
    /// List of validators
    pub validators: Vec<ValidatorSetEntryRpcInfo>,
    /// Total voting power in the set
    pub total_voting_power: String,
    /// Proposer seed (hex)
    pub proposer_seed: String,
}

/// Epoch info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInfo {
    /// Current epoch number
    pub current_epoch: u64,
    /// Current block height
    pub current_height: u64,
    /// Epoch length in blocks
    pub epoch_length: u64,
    /// First block of current epoch
    pub epoch_start_height: u64,
    /// Last block of current epoch
    pub epoch_end_height: u64,
    /// Blocks remaining in current epoch
    pub blocks_remaining: u64,
    /// Whether stake-weighted selection is enabled
    pub stake_weighted_selection: bool,
}

// ============================================================================
// SRC-201 Messaging RPC Types
// ============================================================================

/// Messaging quota info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingQuotaInfo {
    /// Sender address
    pub address: String,
    /// Daily quota limit
    pub daily_quota: u32,
    /// Messages used today
    pub used_today: u32,
    /// Remaining messages
    pub remaining: u32,
    /// Whether sender has trust stake
    pub has_trust_stake: bool,
    /// Trust stake amount (if any)
    pub trust_stake: Option<String>,
}

/// Registered public key info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// The Ed25519 public key (hex)
    pub public_key: String,
    /// Address that registered this key
    pub address: String,
    /// Block height when registered
    pub registered_at_block: u64,
    /// Timestamp when registered
    pub registered_at: u64,
    /// Block height when last updated (0 if never updated)
    pub updated_at_block: u64,
}

/// Messaging configuration info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingConfigInfo {
    /// Daily message quota per sender
    pub daily_quota: u32,
    /// Maximum message size in bytes
    pub max_message_size: u32,
    /// Minimum trust stake amount
    pub min_trust_stake: String,
    /// Whether gas sponsorship is enabled
    pub sponsorship_enabled: bool,
}

/// Inbox filter info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxFilterInfo {
    /// Filter mode: "accept_all", "contacts_only", "staked_only"
    pub mode: String,
}

/// Message event info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEventInfo {
    /// Transaction hash that created this message
    pub tx_hash: String,
    /// Block height
    pub block_height: u64,
    /// Sender address
    pub sender: String,
    /// Recipient hash (BLAKE3 of recipient address)
    pub recipient_hash: String,
    /// Content type code
    pub content_type: u8,
    /// Message flags
    pub flags: u16,
    /// Whether message has payment attached
    pub has_payment: bool,
    /// Payment amount (if has_payment)
    pub payment_amount: Option<String>,
}

/// Message data info for RPC responses (includes encrypted payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDataInfo {
    /// Transaction hash
    pub tx_hash: String,
    /// Block height
    pub block_height: u64,
    /// Sender address (base58)
    pub sender: String,
    /// Recipient hash (hex with 0x prefix)
    pub recipient_hash: String,
    /// Encrypted message data (hex with 0x prefix)
    pub message_data: String,
    /// Sender's public key (hex with 0x prefix)
    pub sender_pubkey: String,
    /// Whether message has payment attached
    pub has_payment: bool,
    /// Payment amount (if has_payment)
    pub payment_amount: Option<String>,
}

/// Pending payment info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPaymentInfo {
    /// Message ID (tx hash)
    pub message_id: String,
    /// Sender address
    pub sender: String,
    /// Recipient hash (hex)
    pub recipient_hash: String,
    /// Payment amount
    pub amount: String,
    /// Expiry timestamp
    pub expiry: u64,
}

/// Submit sponsored message request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitSponsoredMessageRequest {
    /// Encoded SRC-201 message (hex)
    pub message_data: String,
    /// Recipient hash (hex)
    pub recipient_hash: String,
    /// Sender's signature (hex)
    pub signature: String,
    /// Sender's public key (hex)
    pub sender_pubkey: String,
    /// Sender's message nonce
    pub nonce: u64,
    /// Expiry timestamp
    pub expiry: u64,
    /// Optional koppa amount
    pub koppa_amount: Option<String>,
}

/// Sponsored registration request - allows users to register their public key
/// without needing any Koppa balance (gas sponsored by the chain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsoredRegistrationRequest {
    /// Ed25519 public key (hex, 32 bytes)
    pub public_key: String,
    /// Signature of "SUMCHAIN_REGISTER:{public_key_hex}" using the private key (hex)
    pub signature: String,
}

/// Sponsored registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsoredRegistrationResponse {
    /// The derived address from the public key
    pub address: String,
    /// Whether registration was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Spam report info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamReportInfo {
    /// Address of the reported sender
    pub sender: String,
    /// Current spam score
    pub spam_score: u32,
    /// Number of reports
    pub report_count: u32,
    /// Whether sender is restricted
    pub is_restricted: bool,
}

// ============================================================================
// DocClass Types (SRC-80X/81X)
// ============================================================================

/// DocClass identity root info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassIdentityInfo {
    /// Identity ID (hex)
    pub identity_id: String,
    /// Subject commitment (hex)
    pub subject_commitment: String,
    /// Primary controller address
    pub controller: String,
    /// Additional controller addresses
    pub additional_controllers: Vec<String>,
    /// Active keys
    pub keys: Vec<DocClassKeyInfo>,
    /// Service endpoints
    pub services: Vec<DocClassServiceInfo>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Identity status
    pub status: String,
}

/// DocClass key info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassKeyInfo {
    /// Key ID
    pub key_id: String,
    /// Key type
    pub key_type: String,
    /// Public key (hex)
    pub public_key: String,
    /// Key purposes
    pub purposes: Vec<String>,
    /// When key was added
    pub added_at: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: u64,
    /// Whether key is active
    pub active: bool,
}

/// DocClass service endpoint info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassServiceInfo {
    /// Service ID
    pub service_id: String,
    /// Service type
    pub service_type: String,
    /// Endpoint URL
    pub endpoint: String,
    /// Optional description
    pub description: Option<String>,
}

/// DocClass credential info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassCredentialInfo {
    /// Credential ID (hex)
    pub credential_id: String,
    /// Document subcode (e.g., 802, 810)
    pub subcode: u16,
    /// Subcode name
    pub subcode_name: String,
    /// Subject commitment (hex)
    pub subject_commitment: String,
    /// Issuer address
    pub issuer: String,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Schema hash (hex)
    pub schema_hash: String,
    /// Content commitment (hex)
    pub content_commitment: String,
    /// Issuance timestamp
    pub issued_at: u64,
    /// Valid from timestamp
    pub valid_from: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: u64,
    /// Revocation status
    pub revocation_status: String,
    /// If superseded, the new credential ID
    pub superseded_by: Option<String>,
    /// Credential metadata (if applicable)
    pub metadata: Option<DocClassCredentialMetadata>,
}

/// DocClass credential metadata for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassCredentialMetadata {
    /// Credential title
    pub title: String,
    /// Credential type
    pub credential_type: String,
    /// Program/field (if applicable)
    pub program: Option<String>,
    /// Issue date
    pub issue_date: String,
    /// Completion date (if applicable)
    pub completion_date: Option<String>,
}

/// DocClass issuer info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassIssuerInfo {
    /// Issuer address
    pub address: String,
    /// Issuer name
    pub name: String,
    /// Issuer type
    pub issuer_type: String,
    /// Authorized jurisdictions
    pub jurisdictions: Vec<String>,
    /// Authorized document subcodes
    pub authorized_subcodes: Vec<u16>,
    /// Active keys
    pub keys: Vec<DocClassIssuerKeyInfo>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Issuer status
    pub status: String,
    /// Stake amount
    pub stake_amount: String,
}

/// DocClass issuer key info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassIssuerKeyInfo {
    /// Key ID
    pub key_id: String,
    /// Public key (hex)
    pub public_key: String,
    /// Key type
    pub key_type: String,
    /// When key was added
    pub added_at: u64,
    /// Expiry timestamp
    pub expires_at: u64,
    /// Whether key is active
    pub active: bool,
    /// Whether this is the primary key
    pub is_primary: bool,
}

/// DocClass configuration info for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassConfigInfo {
    /// Minimum issuer stake required
    pub min_issuer_stake: String,
    /// Whether issuer stake is required
    pub require_issuer_stake: bool,
    /// Maximum credential validity duration (seconds)
    pub max_credential_validity: u64,
    /// Admin address (if any)
    pub admin: Option<String>,
}

/// DocClass summary for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassSummary {
    /// Total identity roots
    pub total_identities: u64,
    /// Total credentials issued
    pub total_credentials: u64,
    /// Total active issuers
    pub total_issuers: u64,
    /// Total revocations
    pub total_revocations: u64,
}

// ============================================================================
// Transaction History Types
// ============================================================================

/// Transaction history entry for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    /// Transaction hash
    pub tx_hash: String,
    /// Block height where transaction was included
    pub block_height: BlockHeight,
    /// Transaction index within the block
    pub tx_index: u32,
    /// Sender address
    pub from: String,
    /// Recipient address (empty for contract creation)
    pub to: String,
    /// Amount transferred
    pub amount: String,
    /// Fee paid
    pub fee: String,
    /// Transaction status (success/failed)
    pub status: String,
    /// Block timestamp
    pub timestamp: Timestamp,
}

/// Transaction history response with pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryResponse {
    /// Address queried
    pub address: String,
    /// List of transactions
    pub transactions: Vec<TransactionHistoryEntry>,
    /// Total count of transactions for this address
    pub total_count: u64,
    /// Whether there are more transactions
    pub has_more: bool,
    /// Current page offset
    pub offset: u64,
    /// Page limit
    pub limit: u32,
}

// =============================================================================
// SRC-88X Employment & HR RPC Types
// =============================================================================

/// Employment issuer info for RPC responses (SRC-881)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentIssuerInfo {
    /// Issuer address
    pub issuer_address: String,
    /// Issuer class
    pub issuer_class: String,
    /// Display name (public, e.g., "SUM INNOVATION INC")
    pub display_name: String,
    /// Issuer commitment (hex)
    pub issuer_commitment: String,
    /// Jurisdiction code
    pub jurisdiction: String,
    /// Policy ID (hex)
    pub policy_id: String,
    /// Issuer status
    pub status: String,
    /// Risk level
    pub risk_level: String,
    /// Registered at block height
    pub registered_at_height: u64,
    /// Created timestamp
    pub created_at: u64,
    /// Updated timestamp
    pub updated_at: u64,
}

/// Employment credential info for RPC responses (SRC-882)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentCredentialInfo {
    /// Employment ID (hex)
    pub employment_id: String,
    /// Employee wallet address (token owner)
    pub employee_address: String,
    /// Employee reference/commitment (hex)
    pub employee_ref: String,
    /// Employer reference/commitment (hex)
    pub employer_ref: String,
    /// Employment status
    pub status: String,
    /// Tenure commitment (hex)
    pub tenure_commitment: String,
    /// Role commitment (hex, optional)
    pub role_commitment: Option<String>,
    /// Employment type
    pub employment_type: String,
    /// Valid from timestamp
    pub valid_from: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expiry: u64,
    /// Policy ID (hex)
    pub policy_id: String,
    /// Revocation reference (hex, optional)
    pub revocation_ref: Option<String>,
    /// Issuer address
    pub issuer_address: String,
    /// Issuer display name (public, e.g., "SUM INNOVATION INC")
    pub issuer_name: String,
    /// Issuer class
    pub issuer_class: String,
    /// Is currently valid
    pub is_valid: bool,
    /// Created timestamp
    pub created_at: u64,
    /// Updated timestamp
    pub updated_at: u64,
}

/// Income attestation info for RPC responses (SRC-883)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomeAttestationInfo {
    /// Attestation ID (hex)
    pub attestation_id: String,
    /// Holder wallet address (token owner)
    pub holder_address: String,
    /// Subject reference (hex)
    pub subject_ref: String,
    /// Employment ID (hex, optional)
    pub employment_id: Option<String>,
    /// Income bracket commitment (hex)
    pub bracket_commitment: String,
    /// Period commitment (hex)
    pub period_commitment: String,
    /// Currency code
    pub currency_code: String,
    /// Attestation type
    pub attestation_type: String,
    /// Valid from timestamp
    pub valid_from: u64,
    /// Expiry timestamp
    pub expiry: u64,
    /// Policy ID (hex)
    pub policy_id: String,
    /// Issuer address
    pub issuer_address: String,
    /// Is currently valid
    pub is_valid: bool,
    /// Created timestamp
    pub created_at: u64,
}

/// Employment verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentVerificationResult {
    /// Is the employee currently employed
    pub is_employed: bool,
    /// Matching credential (if employed)
    pub credential: Option<EmploymentCredentialInfo>,
    /// Verification timestamp
    pub verified_at: u64,
}

/// Employment summary for an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmploymentSummary {
    /// Employee reference (hex)
    pub employee_ref: String,
    /// Total credentials
    pub total_credentials: u32,
    /// Active credentials
    pub active_credentials: u32,
    /// Ended credentials
    pub ended_credentials: u32,
    /// List of active employment
    pub active_employment: Vec<EmploymentCredentialInfo>,
}

// =============================================================================
// SRC-88X Employment Write Operation Request/Response Types
// =============================================================================

/// Request to register as an employment issuer (SRC-881)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEmploymentIssuerRequest {
    /// Issuer's private key (hex, 32 bytes) - used to sign the transaction
    pub private_key: String,
    /// Issuer class (e.g., "Employer", "PayrollProcessor", "GigPlatform")
    pub issuer_class: String,
    /// Display name (public, e.g., "SUM INNOVATION INC")
    pub display_name: String,
    /// Issuer commitment (hex, 32 bytes) - commitment to company info
    pub issuer_commitment: String,
    /// Jurisdiction code (ISO 3166-1 alpha-2, e.g., "US", "GB")
    pub jurisdiction_code: String,
    /// Policy ID (hex, 32 bytes) - governing policy for this issuer
    pub policy_id: String,
}

/// Response for issuer registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEmploymentIssuerResponse {
    /// Whether registration was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Issuer address (derived from private key)
    pub issuer_address: String,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Request to create an employment credential (SRC-882)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEmploymentCredentialRequest {
    /// Issuer's private key (hex, 32 bytes) - must be registered issuer
    pub private_key: String,
    /// Employee wallet address (base58) - will own the credential token
    pub employee_address: String,
    /// Employee reference (hex, 32 bytes) - commitment to employee identity
    pub employee_ref: String,
    /// Employer reference (hex, 32 bytes) - commitment to employer identity
    pub employer_ref: String,
    /// Tenure commitment (hex, 32 bytes) - commitment to start date
    pub tenure_commitment: String,
    /// Optional role commitment (hex, 32 bytes)
    pub role_commitment: Option<String>,
    /// Employment type (e.g., "FullTime", "PartTime", "Contract")
    pub employment_type: String,
    /// Valid from timestamp (milliseconds)
    pub valid_from: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expiry: u64,
    /// Policy ID (hex, 32 bytes)
    pub policy_id: String,
}

/// Response for credential creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEmploymentCredentialResponse {
    /// Whether creation was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Employment ID (hex, if successful)
    pub employment_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Request to revoke an employment credential (SRC-882)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeEmploymentCredentialRequest {
    /// Issuer's private key (hex, 32 bytes) - must be the original issuer
    pub private_key: String,
    /// Employment ID to revoke (hex, 32 bytes)
    pub employment_id: String,
    /// Revocation reason (optional, for audit trail)
    pub reason: Option<String>,
}

/// Response for credential revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeEmploymentCredentialResponse {
    /// Whether revocation was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Revocation reference (hex, 32 bytes - hash of revocation data)
    pub revocation_ref: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}
