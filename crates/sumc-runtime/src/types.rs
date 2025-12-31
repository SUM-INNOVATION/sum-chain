//! Common types for the SUMC runtime.

use serde::{Deserialize, Serialize};
use sumchain_primitives::Address;

/// Contract address (same as regular address)
pub type ContractAddress = Address;

/// Contract code hash (Blake3 hash of WASM bytecode)
pub type CodeHash = [u8; 32];

/// Event emitted by a contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    /// Contract that emitted the event
    pub contract: ContractAddress,
    /// Event topics (indexed fields for filtering)
    pub topics: Vec<[u8; 32]>,
    /// Event data (non-indexed)
    pub data: Vec<u8>,
}

/// Log entry from contract execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub contract: ContractAddress,
    pub data: Vec<u8>,
}

/// Contract metadata stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    /// Code hash (to look up actual WASM bytecode)
    pub code_hash: CodeHash,
    /// Contract owner (can upgrade if mutable)
    pub owner: Address,
    /// Timestamp of deployment
    pub deployed_at: u64,
    /// Block height of deployment
    pub deployed_block: u64,
    /// Whether the contract can be upgraded
    pub upgradeable: bool,
}

/// Result of a contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    /// Return value (serialized)
    pub return_value: Vec<u8>,
    /// Gas used
    pub gas_used: u64,
    /// Events emitted
    pub events: Vec<ContractEvent>,
    /// Logs
    pub logs: Vec<LogEntry>,
}

/// Contract deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    /// Deployed contract address
    pub contract_address: ContractAddress,
    /// Code hash
    pub code_hash: CodeHash,
    /// Gas used for deployment
    pub gas_used: u64,
    /// Events emitted during init
    pub events: Vec<ContractEvent>,
}

/// Maximum contract code size (1 MB)
pub const MAX_CODE_SIZE: usize = 1024 * 1024;

/// Maximum memory pages for a contract (64 KB per page, 256 pages = 16 MB)
pub const MAX_MEMORY_PAGES: u32 = 256;

/// Maximum call stack depth
pub const MAX_CALL_DEPTH: u32 = 64;

/// Maximum events per execution
pub const MAX_EVENTS: usize = 256;

/// Maximum log entries per execution
pub const MAX_LOGS: usize = 1024;
