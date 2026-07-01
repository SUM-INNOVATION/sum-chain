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

/// OmniNode `InferenceAttestation` record as exposed over RPC.
/// Wire-stable; all binary fields are hex-encoded with `0x` prefix
/// except `session_id` (UTF-8 string, OmniNode-defined) and addresses
/// (base58, chain default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceAttestationInfo {
    /// OmniNode-supplied session identifier (UTF-8 string).
    pub session_id: String,
    /// Verifier's chain Address (base58 with checksum).
    pub verifier_address: String,
    /// `0x` + 64 hex chars of the model identity hash.
    pub model_hash: String,
    /// `0x` + 64 hex chars of the SNIP V2 Merkle root of the manifest blob.
    pub manifest_root: String,
    /// `0x` + 64 hex chars of the canonical response hash.
    pub response_hash: String,
    /// `0x` + 64 hex chars of the SNIP V2 Merkle root of the proof blob.
    pub proof_root: String,
    /// `0x` + 128 hex chars of the verifier's Ed25519 signature over
    /// `STAGE4_DOMAIN || bincode(digest)`.
    pub verifier_signature: String,
    /// Block height at which the chain included this attestation.
    pub included_at_height: u64,
    /// `0x` + 64 hex chars of the tx hash that committed this attestation.
    pub tx_hash: String,
    /// True iff `current_height >= included_at_height + finality_depth`.
    pub finalized: bool,
}

/// Status of a specific `InferenceAttestation` tx, queried by tx hash.
///
/// **Re-exported from `sumchain-primitives`** — the type and the pure
/// classifier function ([`sumchain_primitives::inference_attestation::classify_inference_attestation_status`])
/// live in primitives so the classifier can be unit-tested without
/// pulling in the storage / rocksdb transitive dependency chain. The
/// RPC layer just plumbs the chain's stored inputs into the classifier
/// and returns the result.
pub use sumchain_primitives::inference_attestation::InferenceAttestationStatusInfo;

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

/// One access-list entry in `StorageFileInfoV2.access_list` (Plan v3.2 §3.1, §4).
/// Wire-shape mirror of `sumchain_primitives::AccessEntryV2` with the address
/// rendered as a base58 string and the encrypted bundle as `0x`-prefixed hex
/// (`None` → JSON `null` for Public files).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntryRpcV2 {
    /// Recipient address, base58.
    pub address: String,
    /// `Some("0x…")` for Private; `None` for Public. Always 80 bytes when Some.
    pub encrypted_key_bundle: Option<String>,
    /// Optional access expiry (block height); `None` = never expires.
    pub expires_at: Option<u64>,
}

/// Wire-shape response for `storage_getFileInfoV2` (Plan v3.2 §4, Ask 6).
/// Pagination on `access_list` lets very-Private files (~148-recipient cap)
/// fit comfortably under default RPC body limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFileInfoV2 {
    /// Hex-encoded merkle root.
    pub merkle_root: String,
    /// Base58 owner.
    pub owner: String,
    pub plaintext_size_bytes: u64,
    pub stored_size_bytes: u64,
    pub chunk_count: u32,
    /// Locked Koppa for PoR settlement / abandonment refund.
    pub fee_pool: u64,
    /// Block height of `RegisterFilePendingV2`.
    pub created_at: u64,
    /// `Some(height)` once `ActivateFileV2` lands; `None` while Pending or Abandoned.
    pub activated_at_height: Option<u64>,
    /// `Some(height)` once `AbandonFileV2` lands; `None` while Pending or Active.
    /// Surfaced for off-chain indexers (SNIP `IngestOutcome::AbandonedOnChain`).
    pub abandoned_at_height: Option<u64>,
    /// Block height of the active-archive snapshot used for chunk assignment.
    pub assignment_height: u64,
    /// `0` = Public, `1` = Private.
    pub visibility: u8,
    /// `0` = Pending, `1` = Active, `2` = Abandoned.
    pub lifecycle: u8,
    /// Window of access-list entries from `[access_offset .. access_offset + access_limit)`.
    pub access_list: Vec<AccessEntryRpcV2>,
    /// Total entries in the file's access list (independent of the returned window).
    pub access_total: u32,
    /// Echoed back from the request.
    pub access_offset: u32,
    /// Reserved for `Ask 10` (file rotation); always JSON `null` in V2.
    pub predecessor_root: Option<String>,
}

/// One row of `storage_getPushableFilesV2` (Plan v3.2 §4, Ask 9). Slim — just
/// what an archive node needs to decide whether a push is worth accepting
/// without a follow-up `storage_getFileInfoV2` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushableFileInfoV2 {
    pub merkle_root: String,
    pub chunk_count: u32,
    /// `0` = Pending (still ramping up), `1` = Active (resync push).
    /// Abandoned files are excluded from this RPC.
    pub lifecycle: u8,
    pub created_at: u64,
}

/// Wire-shape response for `storage_getAssignmentCoverageV2` (Plan v3.2 §4).
/// SNIP V2 Phase 1b — surfaces the per-file coverage state that
/// `AcceptAssignmentV2` builds up and that `ActivateFileV2` gates on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignmentCoverageV2 {
    pub chunk_count: u32,
    /// Popcount over the OR of all snapshot-active archive bitmaps.
    pub covered_count: u32,
    /// `covered_count == chunk_count && lifecycle == Pending`.
    pub can_activate_now: bool,
    /// `chunk_count - covered_count` over the whole file (not just the window).
    pub missing_total: u32,
    /// Echoed back. `missing_offset` is a chunk-index lower bound (NOT an
    /// offset into the filtered missing list) — see plan §4.
    pub missing_offset: u32,
    /// Ascending list of `i >= missing_offset` where coverage[i] == 0,
    /// capped at `missing_limit` from the request.
    pub missing_indices: Vec<u32>,
    /// One entry per archive in the file's snapshot. `per_archive` is always
    /// returned in full (bounded by snapshot size, typically O(10) entries).
    pub per_archive: Vec<ArchiveCoverageSummaryV2>,
}

/// One row of `AssignmentCoverageV2.per_archive`. Popcount summaries only;
/// raw bitmaps are never serialized into the RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveCoverageSummaryV2 {
    /// Base58-encoded archive address.
    pub archive: String,
    /// Number of chunks assigned to this archive by the deterministic
    /// rendezvous-hash assignment function. `Some(n)` when the chain
    /// computed it (chunk_count <= `MAX_ASSIGNED_COUNT_CHUNK_COUNT`,
    /// currently 16,384); `None` for files large enough that the chain
    /// declines to compute — clients must run the assignment function
    /// locally for those files. Bounds RPC-call cost.
    pub assigned_count: Option<u32>,
    /// Popcount of this archive's attestation bitmap row, or 0 if no row yet.
    pub attested_count: u32,
    /// True iff this archive's node-registry status is currently `Active`.
    /// Snapshot-Slashed archives don't count toward `covered_count`.
    pub currently_active: bool,
}

/// Live consensus parameters as configured at this node, returned by
/// `chain_getChainParams`. Matches the chain's actual `ChainParams` —
/// reads from the node's live config, NOT hardcoded defaults — so SNIP
/// clients can pin their `assignment_replication_factor` etc. to whatever
/// the chain is actually using right now.
///
/// Wire shape is intentionally flat (no nested `staking`/`messaging`/`docclass`
/// sub-configs) since SNIP V2 clients don't use those. They can be added
/// later if needed without breaking the existing fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainParamsInfo {
    pub chain_id: u64,
    pub block_time_ms: u64,
    pub max_block_bytes: u64,
    pub max_txs_per_block: u32,
    pub min_fee: u128,
    pub finality_depth: u64,
    pub storage_fee_per_byte: u128,
    pub max_metadata_bytes: u64,
    // SNIP V2 params (Plan v3.2 §3.4).
    pub max_access_list_bytes: u64,
    pub activation_grace_blocks: u64,
    pub abandonment_fee_percent: u64,
    pub max_chunk_count_per_file: u32,
    pub max_chunk_indices_per_tx: u32,
    pub assignment_replication_factor: u32,
    /// Block height at which V2 storage ops become valid. `null` (JSON) or
    /// `None` (Rust) means V2 is disabled — every V2 tx receipts as
    /// `Failed(40)` at this chain. Clients use this to know whether to
    /// even attempt V2 ops, and (for hosted environments) at what height
    /// V2 will activate.
    pub v2_enabled_from_height: Option<u64>,
    /// Block height at which the OmniNode `InferenceAttestation` subprotocol
    /// activates.
    ///
    /// `null` (JSON) or `None` (Rust) means OmniNode is disabled.
    /// User-submitted `InferenceAttestation` txs are rejected at mempool
    /// admission with `OmniNodeNotActivated` and produce no receipt; any tx
    /// that bypasses admission and reaches executor dispatch receipts as
    /// `Failed(50)`.
    ///
    /// OmniNode clients read this to decide whether to attempt attestation
    /// submission, and (for hosted environments) at what height the
    /// subprotocol will activate. Additive field — appended after
    /// `v2_enabled_from_height`.
    pub omninode_enabled_from_height: Option<u64>,

    /// Block height at which the SRC-817/818 Education suite activates.
    ///
    /// `null` (JSON) / `None` (Rust) = education dormant: education txs
    /// are rejected at mempool admission (`EducationNotActivated`) /
    /// executor dispatch (`Failed(70)`). A height value means education
    /// ops are executable from that block onward.
    ///
    /// Operators read this to verify activation state on each validator
    /// post runtime-`genesis.json` edit (see
    /// `docs/SUBPROTOCOLS/EDUCATION-ACTIVATION.md`). Additive field —
    /// appended after `omninode_enabled_from_height`.
    pub education_enabled_from_height: Option<u64>,
}

/// One archive-node record as returned by `storage_getActiveNodesAtHeight`
/// (Phase 0b, SNIP V2 Ask 15). Mirrors `sumchain_primitives::NodeRecord` with
/// fields rendered for JSON consumers — addresses base58-encoded, balance as
/// a native `u64` (no string wrapping), role/status as Rust `Debug`-cased
/// strings (`"ArchiveNode"`, `"Active"`, `"Slashed"`).
///
/// Lookup contract is the SNIP-facing one, locked by JSON shape tests in
/// [crate::server] — adding fields requires bumping the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecordInfo {
    /// Operator address, base58-encoded.
    pub address: String,
    /// Role string — currently always `"ArchiveNode"` here, but kept generic
    /// so we don't have to bump the wire shape if other roles join later.
    pub role: String,
    /// Staked balance in Koppa base units.
    pub staked_balance: u64,
    /// Status string: `"Active"` or `"Slashed"`.
    pub status: String,
    /// Block height the node was registered at (post Phase 0a fix; will be
    /// non-zero for archives registered after that fix landed).
    pub registered_at: BlockHeight,
}

/// Block-height info for `chain_getBlockHeight` (Phase 0b, SNIP V2 Ask 8).
///
/// Returns the requested height (latest or finalized) along with a tag echoing
/// which view was returned. Callers that don't care can leave `finality` unset
/// in the request and will get the latest height.
///
/// **Consensus-mode caveat:** PoA and BFT engines have different `current_height()`
/// semantics. PoA returns the height of the most recently produced block (head).
/// BFT returns the next view height (one past head). So under BFT,
/// `chain_getBlockHeight("latest")` returns `head + 1`, while `("finalized")`
/// returns `head` (immediate finality). For uses that need a height matching
/// an actual produced block (e.g. expiry calculations against block contents),
/// **prefer `"finalized"`** — it returns a real block height under both engines.
/// This matches the behavior of pre-existing chain RPCs (`eth_blockNumber`,
/// `sum_blockNumber`) which also pass `current_height()` straight through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeightInfo {
    pub height: BlockHeight,
    /// "finalized" or "latest" — echoes which view the caller asked for.
    pub finality: String,
}

/// Transaction status V2 for `chain_getTransactionStatus` (Phase 0b, SNIP V2 Ask 11).
///
/// Distinguishes mempool / included-but-unfinalized / finalized states so
/// clients don't have to compose `get_receipt` + `is_block_finalized` themselves.
///
/// Note: `Dropped` is reserved for mempool evictions but not currently
/// returned — current mempool does not track eviction history, so an evicted
/// tx returns `Unknown`. Distinguishing the two requires future mempool work.
///
/// `Failed { block_height }` reports the block in which the failure was
/// recorded but does **not** encode whether that block is finalized. Under
/// PoA (depth=3 by default) a `Failed` receipt in an unfinalized block can
/// still disappear on reorg — even though the failure modes are deterministic
/// against pre-state, a reorg replaces the entire block, so the failed receipt
/// goes with it (the same tx might re-enter the mempool or land in a
/// successor block).
///
/// **SNIP guidance:** treat `Failed` as terminal only once
/// `block_height <= chain_getBlockHeight("finalized").height`. Until that
/// inequality holds, `Failed` should be treated as a *probable* terminal
/// state that may revert to `Pending` or `Unknown` after a reorg.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TxStatusV2 {
    /// We have no record of this hash (never seen, or evicted from mempool without trace).
    Unknown,
    /// In the mempool, awaiting inclusion.
    Pending,
    /// Included in a block but not yet finalized — may reorg under PoA.
    Included { block_height: BlockHeight },
    /// Finalized per consensus (depth-aware: depth=3 PoA, depth=0 BFT).
    Finalized { block_height: BlockHeight },
    /// Executed and reverted, or rejected pre-execution.
    Failed { block_height: Option<BlockHeight>, reason: String },
    /// Evicted from mempool without inclusion. Reserved; not currently emitted.
    Dropped,
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
    /// Payload hash (hex) - encrypted document reference
    pub payload_hash: Option<String>,
    /// Payload hint - storage location (e.g., IPFS CID)
    pub payload_hint: Option<String>,
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

/// Request to revoke an academic credential (SRC-810/811/812)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAcademicCredentialRequest {
    /// Issuer's private key (hex, 32 bytes) - must be the original issuer
    pub private_key: String,
    /// Credential ID to revoke (hex, 32 bytes)
    pub credential_id: String,
    /// Revocation reason code (0=Unspecified, 1=KeyCompromise, 2=IssuerCompromise,
    /// 3=AffiliationChanged, 4=Superseded, 5=CessationOfOperation, 6=CertificateHold,
    /// 7=PrivilegeWithdrawn)
    pub reason: Option<u8>,
    /// Optional reason details (human-readable)
    pub reason_details: Option<String>,
}

/// Response for academic credential revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAcademicCredentialResponse {
    /// Whether revocation was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Credential ID (hex)
    pub credential_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

// =============================================================================
// SRC-81X Academic Credential RPC Types
// =============================================================================

/// Request to register as an academic issuer (educational institution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAcademicIssuerRequest {
    /// Issuer's private key (hex, 32 bytes) - used to sign the transaction
    pub private_key: String,
    /// Institution name (e.g., "SUM Hypothesis Institute Technology")
    pub institution_name: String,
    /// Institution type (e.g., "University", "College", "CertificationBody")
    pub institution_type: String,
    /// Jurisdiction code (ISO 3166-1 alpha-2, e.g., "US", "GB")
    pub jurisdiction_code: String,
    /// Authorized document subcodes (e.g., [810, 811, 812] for transcript, diploma, enrollment)
    pub authorized_subcodes: Vec<u16>,
    /// Stake amount (must be >= 1000 Ϙ)
    pub stake_amount: String,
}

/// Response for academic issuer registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAcademicIssuerResponse {
    /// Whether registration was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Issuer address (derived from private key)
    pub issuer_address: String,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Credential attribute for academic credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAttributeRpc {
    /// Attribute name (e.g., "program", "degree", "gpa")
    pub name: String,
    /// Attribute value commitment (hex, 32 bytes)
    pub value_commitment: String,
    /// Whether the attribute is private
    pub is_private: bool,
}

/// Academic credential metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcademicCredentialMetadata {
    /// Credential title (e.g., "Bachelor of Science in Computer Science")
    pub title: Option<String>,
    /// Program name
    pub program: Option<String>,
    /// Degree type (e.g., "Bachelor", "Master", "PhD")
    pub degree_type: Option<String>,
    /// Issue date (ISO 8601 format)
    pub issue_date: Option<String>,
    /// Completion date (ISO 8601 format)
    pub completion_date: Option<String>,
    /// IPFS CID for encrypted credential data (optional)
    pub ipfs_cid: Option<String>,
}

/// Request to issue an academic credential (SRC-810/811/812)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueAcademicCredentialRequest {
    /// Issuer's private key (hex, 32 bytes) - must be registered issuer
    pub private_key: String,
    /// Document subcode (810=Transcript, 811=Diploma, 812=Enrollment)
    pub subcode: u16,
    /// Student/holder address (base58) - recipient of the credential
    pub holder_address: String,
    /// Subject commitment (hex, 32 bytes) - commitment to student identity
    pub subject_commitment: String,
    /// Schema hash (hex, 32 bytes) - commitment to credential schema
    pub schema_hash: String,
    /// Content commitment (hex, 32 bytes) - commitment to credential content
    pub content_commitment: String,
    /// Credential attributes (name-value pairs with commitments)
    pub attributes: Vec<CredentialAttributeRpc>,
    /// Metadata (optional human-readable info)
    pub metadata: Option<AcademicCredentialMetadata>,
    /// Valid from timestamp (milliseconds)
    pub valid_from: u64,
    /// Expiry timestamp (0 = no expiry)
    pub expires_at: u64,
}

/// Response for academic credential issuance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueAcademicCredentialResponse {
    /// Whether issuance was successful
    pub success: bool,
    /// Transaction hash (if successful)
    pub tx_hash: Option<String>,
    /// Credential ID (hex, if successful)
    pub credential_id: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

// ============================================================================
// SRC-817/818 Education suite — read-only RPC views (Phase 4)
//
// RPC-facing projections of the Phase 2 stored records. Decoupled from
// internal bincode layout so storage can evolve without breaking the
// public JSON contract. Privacy: every byte field is a commitment /
// ref / institutional address; the ONLY student identifier is
// `student_commitment` (a hash, never an address). No raw grade,
// submission body, answer key, decryption material, or PII.
// 32-byte fields => `0x` + 64 hex. Addresses => base58 (chain
// canonical, same as other RPC types). Status => numeric code + label.
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAccessPolicyInfo {
    pub opens_at: Option<u64>,
    pub closes_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub audience_kind: u8,
    pub audience_label: String,
    /// Present only for the `IndividualStudent` audience — a
    /// `student_commitment` (hash), never a raw address.
    pub audience_student_commitment: Option<String>,
    pub revoke_on_course_archive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSnipRefInfo {
    /// `0x` + 64 hex — SNIP object content root. Pointer only; no
    /// payload or decryption material is ever exposed.
    pub content_root: String,
    pub snip_file_id: Option<String>,
    pub size_bytes: u64,
    pub schema_version: u32,
    pub access_policy: ContentAccessPolicyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntryInfo {
    pub catalog_id: String,
    pub institution_id: String,
    pub department: String,
    pub course_code: String,
    pub course_title: Option<String>,
    pub title_commitment: Option<String>,
    pub course_level: u8,
    pub credit_hours: Option<u16>,
    pub credit_commitment: Option<String>,
    pub prerequisites_count: u32,
    pub prerequisites_root: String,
    pub accreditation_count: u32,
    pub accreditation_root: String,
    pub status_code: u8,
    pub status_label: String,
    pub version: u32,
    pub supersedes: Option<String>,
    pub superseded_by: Option<String>,
    /// Sponsoring institution/admin address (base58). NOT a student.
    pub owner: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogContentRefInfo {
    pub kind: u8,
    pub kind_label: String,
    pub r#ref: ManagedSnipRefInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferingInfo {
    pub offering_id: String,
    pub catalog_id: String,
    pub term: String,
    pub section: String,
    pub instruction_start_at: u64,
    pub instruction_end_at: u64,
    pub final_grade_submission_deadline: u64,
    /// Sponsoring institution/admin address (base58). NOT a student.
    pub owner: String,
    pub status_code: u8,
    pub status_label: String,
    pub instructor_count: u32,
    pub instructor_root: String,
    pub content_count: u32,
    pub content_root: String,
    pub assessment_count: u32,
    pub assessment_root: String,
    pub enrollment_count: u32,
    pub enrollment_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentInfo {
    pub offering_id: String,
    pub assessment_id: String,
    pub kind: u8,
    pub kind_label: String,
    pub instructions: ManagedSnipRefInfo,
    pub spec_commitment: String,
    pub opens_at: u64,
    pub due_at: u64,
    pub max_attempts: u16,
    pub weight_bps: u16,
    /// Commitment only — the answer key plaintext is never on-chain.
    pub answer_key_commitment: Option<String>,
    pub answer_key_access: Option<ContentAccessPolicyInfo>,
    pub status_code: u8,
    pub status_label: String,
    pub created_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentLinkInfo {
    /// Scoped pseudonym (hash), never a raw address.
    pub student_commitment: String,
    pub enrollment_ref: String,
    pub linked_at_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionReceiptInfo {
    pub offering_id: String,
    pub assessment_id: String,
    pub student_commitment: String,
    pub attempt: u16,
    pub submission_commitment: String,
    /// SNIP pointer to the student-owned work — no payload exposed.
    pub work: ManagedSnipRefInfo,
    pub student_auth_commitment: Option<String>,
    pub enrollment_ref: String,
    /// Sponsor/relayer/LMS submitter address (base58). NOT the student.
    pub submitter: String,
    pub late: bool,
    pub submitted_at_height: u64,
    pub submitted_at_ts: u64,
    pub status_code: u8,
    pub status_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradeRecordInfo {
    pub offering_id: String,
    pub assessment_id: String,
    pub student_commitment: String,
    /// Commitment ONLY — the raw grade value is never on-chain.
    pub grade_commitment: String,
    pub feedback: Option<ManagedSnipRefInfo>,
    /// Grader institutional address (base58). NOT a student.
    pub grader: String,
    pub grader_role: u8,
    pub graded_at_height: u64,
    pub status_code: u8,
    pub status_label: String,
    pub finalized: bool,
}

// =============================================================================
// SRC-82X Tax registry read DTOs (issue #26 — registry-only, no subject data)
// =============================================================================

/// Public view of a Tax claim-type registry entry. Administrative metadata
/// only; `schema_hash` is an opaque BLAKE3 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxClaimTypeInfo {
    pub claim_type: String,
    pub schema_hash: String,
    pub risk_level: String,
    pub recommended_validity_secs: u64,
    pub required_issuer_classes: Vec<Vec<String>>,
    pub status: String,
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

impl From<&sumchain_primitives::tax::TaxClaimTypeEntry> for TaxClaimTypeInfo {
    fn from(e: &sumchain_primitives::tax::TaxClaimTypeEntry) -> Self {
        Self {
            claim_type: e.claim_type.clone(),
            schema_hash: format!("0x{}", hex::encode(e.schema_hash)),
            risk_level: format!("{:?}", e.risk_level),
            recommended_validity_secs: e.recommended_validity_secs,
            required_issuer_classes: e
                .required_issuer_classes
                .iter()
                .map(|g| g.iter().map(|c| format!("{:?}", c)).collect())
                .collect(),
            status: format!("{:?}", e.status),
            version: e.version,
            created_at: e.created_at,
            updated_at: e.updated_at,
        }
    }
}

/// Public view of a Tax issuer registry entry. `address` is public by design;
/// `attributes_hash`/`attributes_schema_hash` are opaque hashes (not decoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxIssuerInfo {
    pub address: String,
    pub tax_class: String,
    pub jurisdictions: Vec<String>,
    pub attributes_hash: String,
    pub attributes_schema_hash: String,
    pub registered_at: u64,
    pub updated_at: u64,
    pub status: String,
    pub expires_at: Option<u64>,
}

impl From<&sumchain_primitives::tax::TaxIssuer> for TaxIssuerInfo {
    fn from(i: &sumchain_primitives::tax::TaxIssuer) -> Self {
        Self {
            address: i.address.to_base58(),
            tax_class: format!("{:?}", i.tax_class),
            jurisdictions: i.jurisdictions.clone(),
            attributes_hash: format!("0x{}", hex::encode(i.attributes_hash)),
            attributes_schema_hash: format!("0x{}", hex::encode(i.attributes_schema_hash)),
            registered_at: i.registered_at,
            updated_at: i.updated_at,
            status: format!("{:?}", i.status),
            expires_at: i.expires_at,
        }
    }
}

/// Issuer-class requirements for a Tax policy (class groups + quorum rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxIssuerRequirementsInfo {
    pub groups: Vec<Vec<String>>,
    pub quorum: String,
}

impl From<&sumchain_primitives::tax::IssuerRequirements> for TaxIssuerRequirementsInfo {
    fn from(r: &sumchain_primitives::tax::IssuerRequirements) -> Self {
        Self {
            groups: r
                .groups
                .iter()
                .map(|g| g.iter().map(|c| format!("{:?}", c)).collect())
                .collect(),
            quorum: format!("{:?}", r.quorum),
        }
    }
}

/// Public view of a Tax policy template. `policy_id` is an opaque hash;
/// `creator` is public by design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxPolicyInfo {
    pub policy_id: String,
    pub template: String,
    pub claim_types: Vec<String>,
    pub issuer_requirements: TaxIssuerRequirementsInfo,
    pub jurisdictions: Vec<String>,
    pub tax_years: Vec<u32>,
    pub max_age_secs: u64,
    pub revocation_check: bool,
    pub creator: String,
    pub created_at: u64,
}

impl From<&sumchain_primitives::tax::TaxPolicy> for TaxPolicyInfo {
    fn from(p: &sumchain_primitives::tax::TaxPolicy) -> Self {
        Self {
            policy_id: format!("0x{}", hex::encode(p.policy_id)),
            template: format!("{:?}", p.template),
            claim_types: p.claim_types.clone(),
            issuer_requirements: TaxIssuerRequirementsInfo::from(&p.issuer_requirements),
            jurisdictions: p.jurisdictions.clone(),
            tax_years: p.tax_years.clone(),
            max_age_secs: p.max_age_secs,
            revocation_check: p.revocation_check,
            creator: p.creator.to_base58(),
            created_at: p.created_at,
        }
    }
}

// =============================================================================
// SRC-83X Equity registry read DTOs (issue #26 — registry/admin records only;
// NO holder/balance/ownership/proof/snapshot/governance/corporate-action data,
// and NO issued_shares/aggregate ownership).
// =============================================================================

/// On-chain entity service endpoint (admin metadata; endpoint is not
/// validated, resolved, enriched, or labeled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityServiceInfo {
    pub service_id: String,
    pub service_type: String,
    pub endpoint: String,
}

impl From<&sumchain_primitives::equity::EntityService> for EquityServiceInfo {
    fn from(s: &sumchain_primitives::equity::EntityService) -> Self {
        Self {
            service_id: s.service_id.clone(),
            service_type: format!("{:?}", s.service_type),
            endpoint: s.endpoint.clone(),
        }
    }
}

/// Public view of an SRC-831 entity profile. `subject_id`, `name_commitment`,
/// `registration_commitment`, `metadata_hash` are opaque hashes (not decoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityEntityInfo {
    pub subject_id: String,
    pub org_type: String,
    pub name_commitment: String,
    pub jurisdiction: Option<String>,
    pub registration_commitment: Option<String>,
    pub controller_model: String,
    pub controllers: Vec<String>,
    pub multisig_threshold: Option<u8>,
    pub services: Vec<EquityServiceInfo>,
    pub metadata_hash: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
}

impl From<&sumchain_primitives::equity::EntityProfile> for EquityEntityInfo {
    fn from(e: &sumchain_primitives::equity::EntityProfile) -> Self {
        Self {
            subject_id: format!("0x{}", hex::encode(e.subject_id)),
            org_type: format!("{:?}", e.org_type),
            name_commitment: format!("0x{}", hex::encode(e.name_commitment)),
            jurisdiction: e.jurisdiction.clone(),
            registration_commitment: e
                .registration_commitment
                .map(|h| format!("0x{}", hex::encode(h))),
            controller_model: format!("{:?}", e.controller_model),
            controllers: e.controllers.iter().map(|a| a.to_base58()).collect(),
            multisig_threshold: e.multisig_threshold,
            services: e.services.iter().map(EquityServiceInfo::from).collect(),
            metadata_hash: format!("0x{}", hex::encode(e.metadata_hash)),
            created_at: e.created_at,
            updated_at: e.updated_at,
            status: format!("{:?}", e.status),
        }
    }
}

/// Public view of an SRC-833 share class. Aggregate/holder data is excluded:
/// no `issued_shares`, balances, or holders. Rights hashes are opaque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityShareClassInfo {
    pub issuer_subject: String,
    pub class_id: String,
    pub share_class_type: String,
    pub name: String,
    pub symbol: String,
    pub authorized_shares: String,
    pub votes_per_share: u64,
    pub economic_rights_hash: String,
    pub liquidation_preference_hash: Option<String>,
    pub dividend_policy_hash: Option<String>,
    pub conversion_rules_hash: Option<String>,
    pub controller: String,
    pub par_value: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
}

impl From<&sumchain_primitives::equity::EquityToken> for EquityShareClassInfo {
    fn from(t: &sumchain_primitives::equity::EquityToken) -> Self {
        Self {
            issuer_subject: format!("0x{}", hex::encode(t.issuer_subject)),
            class_id: format!("0x{}", hex::encode(t.class_id)),
            share_class_type: format!("{:?}", t.share_class_type),
            name: t.name.clone(),
            symbol: t.symbol.clone(),
            authorized_shares: t.authorized_shares.to_string(),
            votes_per_share: t.votes_per_share,
            economic_rights_hash: format!("0x{}", hex::encode(t.economic_rights_hash)),
            liquidation_preference_hash: t
                .liquidation_preference_hash
                .map(|h| format!("0x{}", hex::encode(h))),
            dividend_policy_hash: t.dividend_policy_hash.map(|h| format!("0x{}", hex::encode(h))),
            conversion_rules_hash: t.conversion_rules_hash.map(|h| format!("0x{}", hex::encode(h))),
            controller: t.controller.to_base58(),
            par_value: t.par_value.map(|v| v.to_string()),
            created_at: t.created_at,
            updated_at: t.updated_at,
            status: format!("{:?}", t.status),
        }
    }
}

/// Class-level controller config (SRC-834). Control policy only — no whitelist
/// entries, lockups, or per-holder restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityTradingWindowInfo {
    pub start_day: u8,
    pub end_day: u8,
    pub months: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityControllerConfigInfo {
    pub address: String,
    pub whitelist_enabled: bool,
    pub trading_windows: Vec<EquityTradingWindowInfo>,
    pub transfer_limit: String,
    pub governance_policy_id: String,
    pub paused: bool,
}

impl From<&sumchain_primitives::equity::EquityControllerConfig> for EquityControllerConfigInfo {
    fn from(c: &sumchain_primitives::equity::EquityControllerConfig) -> Self {
        Self {
            address: c.address.to_base58(),
            whitelist_enabled: c.whitelist_enabled,
            trading_windows: c
                .trading_windows
                .iter()
                .map(|w| EquityTradingWindowInfo {
                    start_day: w.start_day,
                    end_day: w.end_day,
                    months: w.months,
                })
                .collect(),
            transfer_limit: c.transfer_limit.to_string(),
            governance_policy_id: format!("0x{}", hex::encode(c.governance_policy_id)),
            paused: c.paused,
        }
    }
}

// =============================================================================
// SRC-84X Agreement executor-link read DTO (issue #26 — executor links only;
// NO agreement commitments, parties, attachments, signatures, attestations,
// IP actions, proofs, events, or off-chain content).
// =============================================================================

/// Public view of an SRC-846 executor link: the executor/automation binding
/// for an agreement. Ids/commitments are opaque `0x` hashes; `executor_contract`
/// is a contract address. `activation_proof_id` is an opaque reference only —
/// no proof content is read or exposed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorLinkInfo {
    pub link_id: String,
    pub agreement_id: String,
    pub executor_contract: String,
    pub executor_interface_id: String,
    pub terms_commitment: String,
    pub activation_policy_id: String,
    pub state: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub created_at_height: u64,
    pub activation_proof_id: Option<String>,
}

impl From<&sumchain_primitives::agreement::ExecutorLink> for ExecutorLinkInfo {
    fn from(l: &sumchain_primitives::agreement::ExecutorLink) -> Self {
        Self {
            link_id: format!("0x{}", hex::encode(l.link_id)),
            agreement_id: format!("0x{}", hex::encode(l.agreement_id)),
            executor_contract: l.executor_contract.to_base58(),
            executor_interface_id: format!("0x{}", hex::encode(l.executor_interface_id)),
            terms_commitment: format!("0x{}", hex::encode(l.terms_commitment)),
            activation_policy_id: format!("0x{}", hex::encode(l.activation_policy_id)),
            state: format!("{:?}", l.state),
            created_at: l.created_at,
            updated_at: l.updated_at,
            created_at_height: l.created_at_height,
            activation_proof_id: l.activation_proof_id.map(|p| format!("0x{}", hex::encode(p))),
        }
    }
}

// =============================================================================
// SRC-86X Property asset-anchor read DTO (issue #26 — asset registry/admin
// records only; NO title events, encumbrances, coverage, claims, proofs,
// system events, owner/holder/insured/claimant identities, off-chain content,
// public_reference, or payout/loss/premium amounts).
// =============================================================================

/// Public view of an SRC-861 asset anchor: the property/asset identity record.
/// Ids/commitments are opaque `0x` hashes; `issuer_address` is the registrant
/// address (public by design). `public_reference` and `attachments` are
/// deliberately omitted — the asset anchor carries no party/owner identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    pub asset_id: String,
    pub asset_commitment: String,
    pub asset_type: String,
    pub jurisdiction_code: String,
    pub policy_id: String,
    pub issuer_class: String,
    pub issuer_address: String,
    pub status: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub anchored_at_height: u64,
    pub related_assets: Vec<String>,
}

impl From<&sumchain_primitives::property::AssetAnchor> for AssetInfo {
    fn from(a: &sumchain_primitives::property::AssetAnchor) -> Self {
        Self {
            asset_id: format!("0x{}", hex::encode(a.asset_id)),
            asset_commitment: format!("0x{}", hex::encode(a.asset_commitment)),
            asset_type: format!("{:?}", a.asset_type),
            jurisdiction_code: a.jurisdiction_code.clone(),
            policy_id: format!("0x{}", hex::encode(a.policy_id)),
            issuer_class: format!("{:?}", a.issuer_class),
            issuer_address: a.issuer_address.to_base58(),
            status: format!("{:?}", a.status),
            created_at: a.created_at,
            updated_at: a.updated_at,
            anchored_at_height: a.anchored_at_height,
            related_assets: a.related_assets.iter().map(|id| format!("0x{}", hex::encode(id))).collect(),
        }
    }
}

// =============================================================================
// SRC-89X Finance issuer-registry read DTO (issue #26 — institution issuer
// profiles only; NO address proofs, bank-standing credentials, KYC
// attestations, proofs, events, subject/holder records, balances/brackets,
// account/identity/methods commitments, or any by-subject query).
// =============================================================================

/// Public view of an SRC-891 finance issuer profile: a financial
/// institution / utility issuer registration. `issuer_address` is the
/// institution address (public by design); `issuer_commitment` and `policy_id`
/// are opaque `0x` hashes. This record carries no subject/customer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinanceIssuerInfo {
    pub issuer_address: String,
    pub issuer_class: String,
    pub issuer_commitment: String,
    pub jurisdiction_code: String,
    pub policy_id: String,
    pub status: String,
    pub registered_at_height: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

impl From<&sumchain_primitives::finance::FinanceIssuerProfile> for FinanceIssuerInfo {
    fn from(i: &sumchain_primitives::finance::FinanceIssuerProfile) -> Self {
        Self {
            issuer_address: i.issuer_address.to_base58(),
            issuer_class: format!("{:?}", i.issuer_class),
            issuer_commitment: format!("0x{}", hex::encode(i.issuer_commitment)),
            jurisdiction_code: i.jurisdiction_code.clone(),
            policy_id: format!("0x{}", hex::encode(i.policy_id)),
            status: format!("{:?}", i.status),
            registered_at_height: i.registered_at_height,
            created_at: i.created_at,
            updated_at: i.updated_at,
        }
    }
}
