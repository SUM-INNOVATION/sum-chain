//! Node configuration with TOML file support.
//!
//! Configuration can be loaded from a TOML file and/or overridden by CLI flags.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Complete node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// Node identity and basic settings
    pub node: NodeSettings,
    /// Consensus settings
    pub consensus: ConsensusSettings,
    /// Network/P2P settings
    pub network: NetworkSettings,
    /// RPC server settings
    pub rpc: RpcSettings,
    /// Health/readiness HTTP server settings
    pub health: HealthSettings,
    /// Logging settings
    pub logging: LoggingSettings,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node: NodeSettings::default(),
            consensus: ConsensusSettings::default(),
            network: NetworkSettings::default(),
            rpc: RpcSettings::default(),
            health: HealthSettings::default(),
            logging: LoggingSettings::default(),
        }
    }
}

impl NodeConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: NodeConfig = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;

        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;

        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;

        Ok(())
    }

    /// Generate an example configuration with comments
    pub fn example_config() -> String {
        r#"# SUM Chain Node Configuration
# All settings have sensible defaults, so you only need to specify what you want to change.

[node]
# Path to the genesis file (required)
genesis = "genesis.json"

# Data directory for blockchain storage
data_dir = "data"

# Path to validator key file (optional, only for validators)
# validator_key = "validator.key"

[consensus]
# Consensus engine: "poa" or "bft"
engine = "poa"

# BFT consensus settings (only used if engine = "bft")
[consensus.bft]
propose_timeout_ms = 3000
prevote_timeout_ms = 1000
precommit_timeout_ms = 1000
timeout_multiplier = 1.5

[network]
# P2P listen address
listen_addr = "/ip4/0.0.0.0/tcp/30303"

# Bootstrap nodes to connect to (comma-separated multiaddrs)
# bootnodes = ["/ip4/1.2.3.4/tcp/30303/p2p/QmPeerID"]

# Enable mDNS for local peer discovery
mdns = true

# Maximum number of connected peers
max_peers = 50

[rpc]
# RPC server listen address
addr = "127.0.0.1:8545"

# Enable RPC authentication (set API key to enable)
# api_key = "your-api-key-here"

# Enable rate limiting
rate_limit_enabled = false

# Requests per second per IP (when rate limiting is enabled)
rate_limit_rps = 100

# Burst size for rate limiting
rate_limit_burst = 200

[health]
# Health/readiness HTTP server listen address.
# Serves GET /health (liveness) and GET /ready (readiness). Bound separately
# from the JSON-RPC server so container/orchestrator probes never contend with
# RPC traffic. Defaults to 0.0.0.0:8546.
addr = "0.0.0.0:8546"

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Output logs in JSON format (useful for log aggregation)
json = false
"#.to_string()
    }
}

/// Basic node settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSettings {
    /// Path to genesis file
    pub genesis: PathBuf,
    /// Data directory
    pub data_dir: PathBuf,
    /// Validator key file (optional)
    pub validator_key: Option<PathBuf>,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            genesis: PathBuf::from("genesis.json"),
            data_dir: PathBuf::from("data"),
            validator_key: None,
        }
    }
}

/// Network/P2P settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    /// P2P listen address (multiaddr format)
    pub listen_addr: String,
    /// Bootstrap nodes
    pub bootnodes: Vec<String>,
    /// Enable mDNS discovery
    pub mdns: bool,
    /// Maximum connected peers
    pub max_peers: usize,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
            bootnodes: Vec::new(),
            mdns: true,
            max_peers: 50,
        }
    }
}

/// RPC server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcSettings {
    /// RPC listen address
    pub addr: String,
    /// API key for authentication (None = disabled)
    pub api_key: Option<String>,
    /// Enable rate limiting
    pub rate_limit_enabled: bool,
    /// Requests per second per IP
    pub rate_limit_rps: u32,
    /// Burst size
    pub rate_limit_burst: u32,
}

impl Default for RpcSettings {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8545".to_string(),
            api_key: None,
            rate_limit_enabled: false,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
        }
    }
}

/// Health/readiness HTTP server settings.
///
/// The health server is bound separately from the JSON-RPC server so that
/// container healthchecks and orchestrator readiness probes never contend with
/// RPC traffic. It serves `GET /health` (liveness) and `GET /ready`
/// (readiness); see `crates/rpc/src/health.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthSettings {
    /// Health/readiness server listen address
    pub addr: String,
}

impl Default for HealthSettings {
    fn default() -> Self {
        Self {
            // Bind on all interfaces so the in-container healthcheck and
            // external orchestrator probes both reach it. Distinct port from
            // the JSON-RPC server (8545).
            addr: "0.0.0.0:8546".to_string(),
        }
    }
}

/// Logging settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingSettings {
    /// Log level
    pub level: String,
    /// JSON output format
    pub json: bool,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json: false,
        }
    }
}

/// Consensus engine type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConsensusEngine {
    /// Proof of Authority (simple round-robin)
    Poa,
    /// Byzantine Fault Tolerant consensus
    Bft,
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::Poa
    }
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsensusSettings {
    /// Consensus engine type
    pub engine: ConsensusEngine,
    /// BFT-specific settings
    pub bft: BftSettings,
}

impl Default for ConsensusSettings {
    fn default() -> Self {
        Self {
            engine: ConsensusEngine::Poa,
            bft: BftSettings::default(),
        }
    }
}

/// BFT consensus settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BftSettings {
    /// Timeout for propose step (milliseconds)
    pub propose_timeout_ms: u64,
    /// Timeout for prevote step (milliseconds)
    pub prevote_timeout_ms: u64,
    /// Timeout for precommit step (milliseconds)
    pub precommit_timeout_ms: u64,
    /// Timeout multiplier for each round
    pub timeout_multiplier: f64,
}

impl Default for BftSettings {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 3000,
            prevote_timeout_ms: 1000,
            precommit_timeout_ms: 1000,
            timeout_multiplier: 1.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.node.data_dir, PathBuf::from("data"));
        assert_eq!(config.rpc.addr, "127.0.0.1:8545");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_health_addr_default() {
        // The [health] section defaults to 0.0.0.0:8546, independent of the
        // JSON-RPC addr (which stays 127.0.0.1:8545).
        let config = NodeConfig::default();
        assert_eq!(config.health.addr, "0.0.0.0:8546");
        assert_eq!(config.rpc.addr, "127.0.0.1:8545");
    }

    #[test]
    fn test_health_addr_override_and_default_when_omitted() {
        // Explicit [health] addr overrides the default.
        let with_override = r#"
[health]
addr = "127.0.0.1:9999"
"#;
        let config: NodeConfig = toml::from_str(with_override).unwrap();
        assert_eq!(config.health.addr, "127.0.0.1:9999");

        // Omitting [health] entirely falls back to the default.
        let without = r#"
[rpc]
addr = "0.0.0.0:8545"
"#;
        let config: NodeConfig = toml::from_str(without).unwrap();
        assert_eq!(config.health.addr, "0.0.0.0:8546");
    }

    #[test]
    fn test_config_roundtrip() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.toml");

        let config = NodeConfig::default();
        config.to_file(&config_path).unwrap();

        let loaded = NodeConfig::from_file(&config_path).unwrap();
        assert_eq!(loaded.node.data_dir, config.node.data_dir);
        assert_eq!(loaded.rpc.addr, config.rpc.addr);
    }

    #[test]
    fn test_parse_example_config() {
        let example = NodeConfig::example_config();
        let _config: NodeConfig = toml::from_str(&example).unwrap();
    }

    #[test]
    fn test_partial_config() {
        let partial = r#"
[node]
genesis = "my_genesis.json"

[rpc]
addr = "0.0.0.0:9000"
"#;
        let config: NodeConfig = toml::from_str(partial).unwrap();
        assert_eq!(config.node.genesis, PathBuf::from("my_genesis.json"));
        assert_eq!(config.rpc.addr, "0.0.0.0:9000");
        // Defaults should be used for unspecified fields
        assert_eq!(config.logging.level, "info");
    }
}
