//! # SUM Chain Genesis
//!
//! Genesis configuration for initializing a new SUM Chain network.
//! Includes chain parameters, initial validators, and prefunded accounts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sumchain_crypto::PublicKey;
use sumchain_primitives::{
    Address, Balance, Block, ChainId, GovernanceParams, Hash, StakingParams, Timestamp,
    DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
};
use thiserror::Error;

/// Genesis configuration errors
#[derive(Debug, Error)]
pub enum GenesisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid validator public key: {0}")]
    InvalidValidator(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("No validators specified")]
    NoValidators,

    #[error("Genesis already initialized")]
    AlreadyInitialized,
}

pub type Result<T> = std::result::Result<T, GenesisError>;

/// Chain parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainParams {
    /// Target block time in milliseconds
    pub block_time_ms: u64,
    /// Maximum block size in bytes
    pub max_block_bytes: u64,
    /// Maximum transactions per block
    pub max_txs_per_block: u32,
    /// Minimum transaction fee
    pub min_fee: Balance,
    /// Finality depth - blocks are considered final after this many confirmations
    /// For PoA, this should be at least 2/3 of validator count
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
    /// Storage fee per byte for NFT metadata (prevents state bloat attacks)
    #[serde(default = "default_storage_fee_per_byte")]
    pub storage_fee_per_byte: Balance,
    /// Maximum metadata size in bytes for NFT tokens
    #[serde(default = "default_max_metadata_bytes")]
    pub max_metadata_bytes: u64,
    /// Minimum gas limit for contract transactions
    #[serde(default = "default_min_contract_gas")]
    pub min_contract_gas: u64,
    /// Maximum gas limit for contract transactions
    #[serde(default = "default_max_contract_gas")]
    pub max_contract_gas: u64,
    /// Staking parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub staking: Option<StakingParams>,
    /// SRC-201 Messaging parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub messaging: Option<MessagingParams>,
    /// SRC-80X/81X DocClass parameters (optional - uses defaults if not specified)
    #[serde(default)]
    pub docclass: Option<DocClassParams>,
    // ─── SNIP V2 (Phase 1) parameters ──────────────────────────────────────
    /// Maximum bincode-serialized size of a V2 file's `access_list` (bytes).
    /// Plan v3.1 §3.4 — 200 Private entries = ~22 KB, so the cap drives the
    /// effective recipient limit (~148 Private at default).
    #[serde(default = "default_max_access_list_bytes")]
    pub max_access_list_bytes: u64,
    /// Grace period after `ActivateFileV2` (in blocks) during which PoR
    /// challenges are suppressed for that file. Plan §3.5, Ask 12.
    #[serde(default = "default_activation_grace_blocks")]
    pub activation_grace_blocks: u64,
    /// Percentage (0–100) of `fee_pool` retained on `AbandonFileV2`. The
    /// remainder is refunded to the owner. Plan §3.5, Ask 13.
    #[serde(default = "default_abandonment_fee_percent")]
    pub abandonment_fee_percent: u64,
    /// Cap on `chunk_count` per V2 file. Bounds the per-`(file, archive)`
    /// `AcceptAssignmentV2` bitmap row size at `ceil(N/8)` bytes — at the
    /// default of 1,048,576 chunks that's 128 KB worst-case per archive.
    /// Plan v3.2 §3.4.
    #[serde(default = "default_max_chunk_count_per_file")]
    pub max_chunk_count_per_file: u32,
    /// Cap on `chunk_indices.len()` in a single `AcceptAssignmentV2` tx.
    /// Bounds tx size; archives with larger assignments split across multiple
    /// txs (the bitmap OR-merge means partial submissions accumulate cleanly).
    /// Plan v3.2 §3.4.
    #[serde(default = "default_max_chunk_indices_per_tx")]
    pub max_chunk_indices_per_tx: u32,
    /// Number of archive nodes assigned to each chunk by the deterministic
    /// rendezvous-hash assignment function. The actual replication factor
    /// is `min(assignment_replication_factor, snapshot.len())`, so genesis
    /// chains with fewer archives still produce coherent assignments.
    /// Plan v3.2 §3.6.
    #[serde(default = "default_assignment_replication_factor")]
    pub assignment_replication_factor: u32,
    /// Block height at which V2 storage operations (`NodeRegistryV2`,
    /// `StorageMetadataV2`) become valid. `None` (the default) means V2 is
    /// disabled entirely — every V2 tx receipts as `TxStatus::Failed(40)`
    /// without consuming the sender's fee.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a V2-aware
    /// binary stays V2-disabled until the operator explicitly sets a
    /// future activation height.
    ///
    /// To enable V2 from genesis (dev / SNIP local-mirror): set to `Some(0)`.
    /// To activate at a future block on a live chain: set to `Some(target_height)`.
    #[serde(default)]
    pub v2_enabled_from_height: Option<u64>,

    /// Block height at which the OmniNode `InferenceAttestation` subprotocol
    /// activates. `None` = disabled forever; `Some(h)` = ops from block `h`
    /// onward. Mirrors the SNIP V2 activation pattern above.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to an
    /// OmniNode-aware binary stays disabled until the operator explicitly
    /// sets a future activation height.
    ///
    /// Dev / OmniNode Stage 5: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub omninode_enabled_from_height: Option<u64>,

    /// Block height at which the SRC-817/818 Education-LMS suite
    /// activates. `None` = disabled forever; `Some(h)` = education txs
    /// executable from block `h` onward. Mirrors the OmniNode/SNIP V2
    /// activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field
    /// to `None`, so an existing mainnet `genesis.json` upgraded to an
    /// Education-aware binary stays disabled until the operator
    /// explicitly sets a future activation height.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub education_enabled_from_height: Option<u64>,

    /// Block height at which production-capable smart contracts activate
    /// (persistent storage, reorg-reversible contract state, root-committed).
    /// `None` = disabled forever; `Some(h)` = `ContractDeploy`/`ContractCall`
    /// execute from block `h` onward. Below the gate they are rejected free
    /// (no fee, no state). Mirrors the V2/OmniNode/Education activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a
    /// contract-aware binary stays disabled until operators coordinate an
    /// explicit activation height. Activation changes the block state-root
    /// formula, so it is a consensus-breaking, validator-coordinated upgrade.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub contracts_enabled_from_height: Option<u64>,

    /// Block height at which on-chain governance v1 activates. `None` =
    /// disabled forever; `Some(h)` = `TxPayload::Governance` operations
    /// execute from block `h` onward. Below the gate they are rejected free
    /// (no fee, no state). Mirrors the V2/OmniNode/Education/Contracts
    /// activation pattern.
    ///
    /// Production safety: `#[serde(default)]` resolves a missing field to
    /// `None`, so an existing mainnet `genesis.json` upgraded to a
    /// governance-aware binary stays dormant until operators coordinate an
    /// explicit activation height (a consensus-relevant, validator-coordinated
    /// upgrade). See docs/specs/GOVERNANCE-V1.md.
    ///
    /// Dev: set to `Some(0)` to activate from genesis.
    #[serde(default)]
    pub governance_enabled_from_height: Option<u64>,

    /// On-chain governance v1 network parameters (council authority + tally
    /// params + snapshot bound). `None` = not configured (governance operations
    /// are rejected even above the height gate). No mainnet defaults; set only
    /// for a coordinated activation or in tests. See docs/specs/GOVERNANCE-V1.md.
    #[serde(default)]
    pub governance: Option<GovernanceParams>,
}

fn default_finality_depth() -> u64 {
    3 // Default: 3 blocks for finality
}

fn default_storage_fee_per_byte() -> Balance {
    100 // 100 base units per byte (~0.0000001 Koppa per byte)
}

fn default_max_metadata_bytes() -> u64 {
    16384 // 16 KB max metadata size
}

fn default_min_contract_gas() -> u64 {
    21000 // Similar to Ethereum's base gas
}

fn default_max_contract_gas() -> u64 {
    10_000_000 // 10M gas limit per transaction
}

fn default_max_access_list_bytes() -> u64 {
    16_384 // matches max_metadata_bytes; ~148 Private recipients per file
}

fn default_activation_grace_blocks() -> u64 {
    50 // ~100s at 2s blocks; SNIP can request 150 if 5min wall-clock is needed
}

fn default_abandonment_fee_percent() -> u64 {
    10 // 10% of fee_pool retained on abandonment
}

fn default_max_chunk_count_per_file() -> u32 {
    1_048_576 // 1 TB at CHUNK_SIZE = 1 MB; 128 KB bitmap row max
}

fn default_max_chunk_indices_per_tx() -> u32 {
    65_536 // bounds AcceptAssignmentV2 tx size; multi-tx OR-merge handles larger sets
}

fn default_assignment_replication_factor() -> u32 {
    3 // baseline R=3; effective R is min(this, active_snapshot_size)
}

/// SRC-201 Messaging Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagingParams {
    /// Daily free message quota per address
    #[serde(default = "default_msg_daily_quota")]
    pub daily_quota: u32,
    /// Maximum message size in bytes
    #[serde(default = "default_msg_max_size")]
    pub max_message_size: u32,
    /// Minimum stake for trusted sender tier
    #[serde(default = "default_msg_min_stake")]
    pub min_trust_stake: Balance,
    /// Enable gas sponsorship for messages
    #[serde(default = "default_sponsorship_enabled")]
    pub sponsorship_enabled: bool,
    /// Initial sponsorship fund (Koppa)
    #[serde(default)]
    pub initial_sponsorship_fund: Balance,
    /// Registry admin address (optional)
    #[serde(default)]
    pub registry_admin: Option<String>,
    /// Spam score threshold for restrictions
    #[serde(default = "default_spam_threshold")]
    pub spam_threshold: u32,
    /// High spam score requiring stake
    #[serde(default = "default_high_spam_threshold")]
    pub high_spam_threshold: u32,
    /// Cooldown blocks before stake withdrawal
    #[serde(default = "default_stake_cooldown")]
    pub stake_cooldown_blocks: u64,
}

fn default_msg_daily_quota() -> u32 {
    DEFAULT_DAILY_QUOTA
}

fn default_msg_max_size() -> u32 {
    DEFAULT_MAX_MESSAGE_SIZE
}

fn default_msg_min_stake() -> Balance {
    DEFAULT_MIN_TRUST_STAKE
}

fn default_sponsorship_enabled() -> bool {
    true
}

fn default_spam_threshold() -> u32 {
    50
}

fn default_high_spam_threshold() -> u32 {
    80
}

fn default_stake_cooldown() -> u64 {
    50400 // ~7 days at 12s blocks
}

impl Default for MessagingParams {
    fn default() -> Self {
        Self {
            daily_quota: default_msg_daily_quota(),
            max_message_size: default_msg_max_size(),
            min_trust_stake: default_msg_min_stake(),
            sponsorship_enabled: default_sponsorship_enabled(),
            initial_sponsorship_fund: 0,
            registry_admin: None,
            spam_threshold: default_spam_threshold(),
            high_spam_threshold: default_high_spam_threshold(),
            stake_cooldown_blocks: default_stake_cooldown(),
        }
    }
}

/// SRC-80X/81X DocClass Parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocClassParams {
    /// Minimum stake required for issuer registration
    #[serde(default = "default_docclass_min_issuer_stake")]
    pub min_issuer_stake: Balance,
    /// DocClass admin address (optional)
    #[serde(default)]
    pub admin: Option<String>,
    /// Initial registered issuers (for bootstrapping)
    #[serde(default)]
    pub initial_issuers: Vec<String>,
    /// Credential validity period limits (in seconds, 0 = no limit)
    #[serde(default)]
    pub max_credential_validity: u64,
    /// Whether to require issuer stake for registration
    #[serde(default = "default_require_issuer_stake")]
    pub require_issuer_stake: bool,
}

fn default_docclass_min_issuer_stake() -> Balance {
    1_000_000_000_000 // 1000 Koppa (10^12 base units)
}

fn default_require_issuer_stake() -> bool {
    true
}

impl Default for DocClassParams {
    fn default() -> Self {
        Self {
            min_issuer_stake: default_docclass_min_issuer_stake(),
            admin: None,
            initial_issuers: Vec::new(),
            max_credential_validity: 0, // No limit
            require_issuer_stake: default_require_issuer_stake(),
        }
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        Self {
            block_time_ms: 2000,           // 2 seconds
            max_block_bytes: 1_000_000,    // 1 MB
            max_txs_per_block: 1000,
            min_fee: 1,
            finality_depth: default_finality_depth(),
            storage_fee_per_byte: default_storage_fee_per_byte(),
            max_metadata_bytes: default_max_metadata_bytes(),
            min_contract_gas: default_min_contract_gas(),
            max_contract_gas: default_max_contract_gas(),
            staking: Some(StakingParams::default()),
            messaging: Some(MessagingParams::default()),
            docclass: Some(DocClassParams::default()),
            max_access_list_bytes: default_max_access_list_bytes(),
            activation_grace_blocks: default_activation_grace_blocks(),
            abandonment_fee_percent: default_abandonment_fee_percent(),
            max_chunk_count_per_file: default_max_chunk_count_per_file(),
            max_chunk_indices_per_tx: default_max_chunk_indices_per_tx(),
            assignment_replication_factor: default_assignment_replication_factor(),
            // Production-safe default: V2 disabled. Tests and dev genesis
            // (snip-mirror, local) opt in via `with_v2_enabled()` or by
            // setting the field explicitly in their genesis JSON.
            v2_enabled_from_height: None,
            // Production-safe default: OmniNode subprotocol disabled.
            // Activation is coordinated separately, after the chain has
            // shipped Phase 2-4 of the InferenceAttestation work.
            omninode_enabled_from_height: None,
            // Production-safe default: Education-LMS suite disabled.
            // Activation is coordinated separately, post Phase 2-6.
            education_enabled_from_height: None,
            // Production-safe default: smart contracts dormant. Activation is a
            // coordinated, consensus-breaking validator upgrade (changes the
            // state-root formula); never set in default/mainnet config.
            contracts_enabled_from_height: None,
            // Production-safe default: on-chain governance dormant. Activation
            // is a coordinated validator upgrade; never set in default/mainnet
            // config. See docs/specs/GOVERNANCE-V1.md.
            governance_enabled_from_height: None,
            // No governance parameters configured by default.
            governance: None,
        }
    }
}

impl ChainParams {
    /// Convenience for tests + dev genesis JSONs where V2 should be enabled
    /// from genesis. Production chains MUST NOT use this — they should set
    /// `v2_enabled_from_height` explicitly to a chosen activation height
    /// (or leave it `None`) in their `genesis.json`.
    pub fn with_v2_enabled() -> Self {
        Self {
            v2_enabled_from_height: Some(0),
            ..Self::default()
        }
    }

    /// Convenience for tests + dev genesis where smart contracts should be
    /// enabled from genesis (also enables V2, since contract txs are V2).
    /// Production chains MUST NOT use this — set `contracts_enabled_from_height`
    /// explicitly to a coordinated activation height.
    pub fn with_contracts_enabled() -> Self {
        Self {
            v2_enabled_from_height: Some(0),
            contracts_enabled_from_height: Some(0),
            ..Self::default()
        }
    }
}

impl ChainParams {
    /// Calculate required fee for storing NFT metadata
    /// Returns base_fee + (metadata_bytes * storage_fee_per_byte)
    pub fn calculate_nft_storage_fee(&self, metadata_bytes: usize) -> Balance {
        let storage_fee = (metadata_bytes as u128).saturating_mul(self.storage_fee_per_byte);
        self.min_fee.saturating_add(storage_fee)
    }

    /// Validate metadata size against limits
    pub fn validate_metadata_size(&self, metadata_bytes: usize) -> bool {
        metadata_bytes as u64 <= self.max_metadata_bytes
    }
}

/// Genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Genesis timestamp (milliseconds since epoch)
    pub genesis_time: Timestamp,
    /// Validator public keys (base58 encoded)
    pub validators: Vec<String>,
    /// Initial account allocations (address -> balance)
    pub alloc: HashMap<String, Balance>,
    /// Chain parameters
    pub params: ChainParams,
}

impl Genesis {
    /// Create a new genesis configuration
    pub fn new(
        chain_id: ChainId,
        genesis_time: Timestamp,
        validators: Vec<String>,
        alloc: HashMap<String, Balance>,
        params: ChainParams,
    ) -> Self {
        Self {
            chain_id,
            genesis_time,
            validators,
            alloc,
            params,
        }
    }

    /// Load genesis from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let genesis: Genesis = serde_json::from_str(&contents)?;
        genesis.validate()?;
        Ok(genesis)
    }

    /// Save genesis to a JSON file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let genesis: Genesis = serde_json::from_str(json)?;
        genesis.validate()?;
        Ok(genesis)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Validate the genesis configuration
    pub fn validate(&self) -> Result<()> {
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }

        // Validate all validator public keys
        for (i, v) in self.validators.iter().enumerate() {
            PublicKey::from_base58(v)
                .map_err(|_| GenesisError::InvalidValidator(format!("validator[{}]: {}", i, v)))?;
        }

        // Validate all addresses in alloc
        for addr in self.alloc.keys() {
            Address::from_base58(addr)
                .or_else(|_| Address::from_hex(addr))
                .map_err(|_| GenesisError::InvalidAddress(addr.clone()))?;
        }

        Ok(())
    }

    /// Get validator public keys as bytes
    pub fn validator_pubkeys(&self) -> Result<Vec<[u8; 32]>> {
        self.validators
            .iter()
            .map(|v| {
                PublicKey::from_base58(v)
                    .map(|pk| *pk.as_bytes())
                    .map_err(|_| GenesisError::InvalidValidator(v.clone()))
            })
            .collect()
    }

    /// Get the first validator (proposer of genesis block)
    pub fn genesis_proposer(&self) -> Result<[u8; 32]> {
        let pubkeys = self.validator_pubkeys()?;
        Ok(pubkeys[0])
    }

    /// Parse allocations into addresses and balances
    pub fn parsed_alloc(&self) -> Result<Vec<(Address, Balance)>> {
        self.alloc
            .iter()
            .map(|(addr_str, balance)| {
                let addr = Address::from_base58(addr_str)
                    .or_else(|_| Address::from_hex(addr_str))
                    .map_err(|_| GenesisError::InvalidAddress(addr_str.clone()))?;
                Ok((addr, *balance))
            })
            .collect()
    }

    /// Compute the initial state root from allocations
    pub fn compute_state_root(&self) -> Result<Hash> {
        let alloc = self.parsed_alloc()?;

        // Simple state root: hash of sorted (address, balance) pairs
        // In production, this would be a proper merkle patricia trie
        let mut sorted_alloc = alloc.clone();
        sorted_alloc.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut data = Vec::new();
        for (addr, balance) in sorted_alloc {
            data.extend_from_slice(addr.as_bytes());
            data.extend_from_slice(&balance.to_be_bytes());
        }

        Ok(Hash::hash(&data))
    }

    /// Create the genesis block
    pub fn create_genesis_block(&self) -> Result<Block> {
        let state_root = self.compute_state_root()?;
        let proposer = self.genesis_proposer()?;

        let block = Block::genesis(state_root, proposer, self.genesis_time);

        // Genesis block doesn't need a real signature in PoA
        // (it's trusted as the starting point)

        Ok(block)
    }

    /// Create a default local development genesis
    pub fn local_dev(validator_pubkeys: &[&str], prefund_addresses: &[(&str, Balance)]) -> Self {
        let validators: Vec<String> = validator_pubkeys.iter().map(|s| s.to_string()).collect();

        let alloc: HashMap<String, Balance> = prefund_addresses
            .iter()
            .map(|(addr, bal)| (addr.to_string(), *bal))
            .collect();

        Self {
            chain_id: 1337, // Local dev chain ID
            genesis_time: 0,
            validators,
            alloc,
            params: ChainParams::default(),
        }
    }
}

/// Node configuration for connecting to a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name/identifier
    pub name: String,
    /// Path to node data directory
    pub data_dir: String,
    /// Listen address for P2P
    pub listen_addr: String,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<String>,
    /// Path to node private key (for P2P identity)
    pub node_key_path: Option<String>,
    /// Whether this node is a validator
    pub is_validator: bool,
    /// Path to validator key (if is_validator)
    pub validator_key_path: Option<String>,
    /// RPC listen address
    pub rpc_addr: String,
    /// Enable RPC
    pub rpc_enabled: bool,
    /// Log level
    pub log_level: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "sumchain-node".to_string(),
            data_dir: "data".to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
            bootnodes: Vec::new(),
            node_key_path: None,
            is_validator: false,
            validator_key_path: None,
            rpc_addr: "127.0.0.1:8545".to_string(),
            rpc_enabled: true,
            log_level: "info".to_string(),
        }
    }
}

impl NodeConfig {
    /// Load from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        // Using serde_json for simplicity; in production use toml crate
        let config: NodeConfig = serde_json::from_str(&contents)
            .map_err(|e| GenesisError::Json(e))?;
        Ok(config)
    }

    /// Save to file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::KeyPair;

    /// Plan v3.2 — existing `genesis.json` files (without the new V2 fields)
    /// must still deserialize cleanly. Any of the SNIP V2 params landing
    /// without `#[serde(default)]` would break old-genesis loads — this test
    /// catches that by deserializing a minimal-shape genesis and asserting the
    /// V2 fields fall back to their declared defaults.
    #[test]
    fn test_genesis_deserializes_without_v2_fields() {
        let json = r#"{
            "chain_id": 1337,
            "genesis_time": 0,
            "validators": [],
            "alloc": {},
            "params": {
                "block_time_ms": 2000,
                "max_block_bytes": 1000000,
                "max_txs_per_block": 1000,
                "min_fee": 1
            }
        }"#;
        let g: Genesis = serde_json::from_str(json).expect("old-shape genesis must deserialize");
        // Phase 1 v3.0 params.
        assert_eq!(g.params.max_access_list_bytes, default_max_access_list_bytes());
        assert_eq!(g.params.activation_grace_blocks, default_activation_grace_blocks());
        assert_eq!(
            g.params.abandonment_fee_percent,
            default_abandonment_fee_percent()
        );
        // v3.2 bitmap-attestation params.
        assert_eq!(
            g.params.max_chunk_count_per_file,
            default_max_chunk_count_per_file()
        );
        assert_eq!(
            g.params.max_chunk_indices_per_tx,
            default_max_chunk_indices_per_tx()
        );
        assert_eq!(
            g.params.assignment_replication_factor,
            default_assignment_replication_factor()
        );
        // v3.3 V2 activation gate: production-safe default is `None`
        // (V2 disabled). An old mainnet genesis upgraded to a V2-aware binary
        // must NOT auto-enable V2 — operator must set the field explicitly.
        assert_eq!(g.params.v2_enabled_from_height, None);
    }

    #[test]
    fn test_genesis_validation() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            0,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_no_validators() {
        let genesis = Genesis::new(
            1,
            0,
            vec![],
            HashMap::new(),
            ChainParams::default(),
        );

        assert!(matches!(genesis.validate(), Err(GenesisError::NoValidators)));
    }

    #[test]
    fn test_invalid_validator() {
        let genesis = Genesis::new(
            1,
            0,
            vec!["not-a-valid-pubkey".to_string()],
            HashMap::new(),
            ChainParams::default(),
        );

        assert!(matches!(genesis.validate(), Err(GenesisError::InvalidValidator(_))));
    }

    #[test]
    fn test_genesis_json_roundtrip() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();

        let genesis = Genesis::new(
            1337,
            12345,
            vec![validator],
            HashMap::new(),
            ChainParams::default(),
        );

        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();

        assert_eq!(genesis.chain_id, parsed.chain_id);
        assert_eq!(genesis.genesis_time, parsed.genesis_time);
        assert_eq!(genesis.validators, parsed.validators);
    }

    #[test]
    fn test_create_genesis_block() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            1000,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        let block = genesis.create_genesis_block().unwrap();

        assert_eq!(block.height(), 0);
        assert!(block.header.parent_hash.is_zero());
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn test_state_root_deterministic() {
        let kp = KeyPair::generate();
        let validator = kp.public_key().to_base58();
        let addr = kp.address().to_base58();

        let genesis = Genesis::new(
            1,
            0,
            vec![validator],
            HashMap::from([(addr, 1_000_000)]),
            ChainParams::default(),
        );

        let root1 = genesis.compute_state_root().unwrap();
        let root2 = genesis.compute_state_root().unwrap();

        assert_eq!(root1, root2);
    }
}
