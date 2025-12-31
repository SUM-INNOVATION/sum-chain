//! # SUM Chain Genesis
//!
//! Genesis configuration for initializing a new SUM Chain network.
//! Includes chain parameters, initial validators, and prefunded accounts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sumchain_crypto::PublicKey;
use sumchain_primitives::{Address, Balance, Block, ChainId, Hash, Timestamp};
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
