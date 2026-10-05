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
    /// Node-local mempool policy
    pub mempool: MempoolSettings,
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
            mempool: MempoolSettings::default(),
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
# Consensus engine. Only "poa" is accepted. "bft" is refused at startup: the
# experimental BFT engine is unavailable pending the certified-finality protocol.
engine = "poa"

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

# Contract RPC budgets (contract_call, contract_estimateGas). Local to this
# node; block execution is unaffected.
# contract_exec_fuel = 200000000
# contract_exec_max_memory_pages = 256
# contract_exec_max_host_bytes = 16777216
# contract_exec_concurrency = 1

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

/// Node-local mempool policy. Not consensus: it decides what this node admits
/// and proposes, never which blocks are valid.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MempoolSettings {
    /// Refuse `ContractDeploy` and `ContractCall` transactions: at admission
    /// from every source, among those already held, and at block selection.
    pub refuse_contract_transactions: bool,
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
    /// Contract RPC (`contract_call`, `contract_estimateGas`) budgets. Local
    /// to this node; they never affect block execution.
    ///
    /// WASM operators one execution may run.
    pub contract_exec_fuel: u64,
    /// Linear-memory ceiling for one execution, in 64 KiB pages.
    pub contract_exec_max_memory_pages: u32,
    /// Bytes host functions may copy in one execution.
    pub contract_exec_max_host_bytes: u64,
    /// Executions allowed at once; further requests wait briefly, then get a
    /// busy error.
    pub contract_exec_concurrency: usize,
}

impl RpcSettings {
    /// The contract RPC budgets as the runtime takes them. The view gas cap is
    /// filled in from the chain's `max_contract_gas` where the executor is built.
    pub fn contract_exec_limits(&self) -> sumc_runtime::LocalExecutionLimits {
        sumc_runtime::LocalExecutionLimits {
            fuel: self.contract_exec_fuel,
            max_memory_pages: self.contract_exec_max_memory_pages,
            max_host_bytes: self.contract_exec_max_host_bytes,
            ..sumc_runtime::LocalExecutionLimits::DEFAULT
        }
    }
}

impl Default for RpcSettings {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8545".to_string(),
            api_key: None,
            rate_limit_enabled: false,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            contract_exec_fuel: sumc_runtime::LocalExecutionLimits::DEFAULT.fuel,
            contract_exec_max_memory_pages: sumc_runtime::LocalExecutionLimits::DEFAULT
                .max_memory_pages,
            contract_exec_max_host_bytes: sumc_runtime::LocalExecutionLimits::DEFAULT
                .max_host_bytes,
            contract_exec_concurrency: 1,
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
    /// The experimental BFT engine. Still parsed, so that a config naming it
    /// gets the refusal below rather than a generic "unknown variant" error,
    /// and never run: see [`ConsensusSettings::production_engine`].
    Bft,
}

/// Why a node configured with `engine = "bft"` does not start.
///
/// The BFT engine under `crates/consensus/src/bft` is a prototype and does not
/// provide the guarantees the certified-finality protocol will (#270). It is
/// refused outright rather than downgraded: an operator who asked for BFT and
/// silently got PoA would believe the chain has finality it does not have.
pub const BFT_ENGINE_UNAVAILABLE: &str = "consensus engine \"bft\" is refused: the experimental \
     BFT engine is unavailable pending the certified-finality protocol (#270). This node does \
     not fall back to another engine; set `[consensus] engine = \"poa\"` or remove the line";

/// The engines a production node may construct.
///
/// Deliberately narrower than [`ConsensusEngine`]: `Node::with_rpc_config`
/// can only build what this enum names, so an engine that is not here cannot
/// be instantiated by a production entry point at all, whatever the config
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionEngine {
    /// Proof of Authority (simple round-robin)
    Poa,
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

impl ConsensusSettings {
    /// The engine this node will run, or the reason it will not start.
    ///
    /// The only way from a configured engine to a constructed one. There is
    /// no fallback: `Bft` is an error, never `Poa`.
    pub fn production_engine(&self) -> Result<ProductionEngine> {
        match self.engine {
            ConsensusEngine::Poa => Ok(ProductionEngine::Poa),
            ConsensusEngine::Bft => Err(anyhow::anyhow!(BFT_ENGINE_UNAVAILABLE)),
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
    fn mempool_contract_refusal_defaults_off_and_parses() {
        let cfg: NodeConfig = toml::from_str("[node]\ngenesis = \"g.json\"\n").unwrap();
        assert!(!cfg.mempool.refuse_contract_transactions);
        let cfg: NodeConfig =
            toml::from_str("[mempool]\nrefuse_contract_transactions = true\n").unwrap();
        assert!(cfg.mempool.refuse_contract_transactions);
    }

    #[test]
    fn test_parse_example_config() {
        let example = NodeConfig::example_config();
        let _config: NodeConfig = toml::from_str(&example).unwrap();
    }

    fn engine_config(value: &str) -> String {
        format!("[consensus]\nengine = {value}\n")
    }

    #[test]
    fn contract_exec_limits_defaults_and_overrides() {
        // Omitted: default RPC budgets, one execution slot.
        let cfg: NodeConfig = toml::from_str("[node]\ngenesis = \"g.json\"\n").unwrap();
        assert_eq!(
            cfg.rpc.contract_exec_limits(),
            sumc_runtime::LocalExecutionLimits::DEFAULT
        );
        assert_eq!(cfg.rpc.contract_exec_concurrency, 1);

        let cfg: NodeConfig =
            toml::from_str("[rpc]\ncontract_exec_fuel = 1000\ncontract_exec_concurrency = 3\n")
                .unwrap();
        assert_eq!(cfg.rpc.contract_exec_limits().fuel, 1000);
        assert_eq!(cfg.rpc.contract_exec_concurrency, 3);
    }

    #[test]
    fn default_engine_is_poa() {
        assert_eq!(ConsensusEngine::default(), ConsensusEngine::Poa);
        assert_eq!(ConsensusSettings::default().engine, ConsensusEngine::Poa);
        assert_eq!(NodeConfig::default().consensus.engine, ConsensusEngine::Poa);
        let omitted: NodeConfig = toml::from_str("[rpc]\naddr = \"0.0.0.0:9000\"\n").unwrap();
        assert_eq!(omitted.consensus.engine, ConsensusEngine::Poa);
        assert_eq!(
            omitted.consensus.production_engine().unwrap(),
            ProductionEngine::Poa
        );
    }

    #[test]
    fn explicit_poa_is_accepted() {
        let config: NodeConfig = toml::from_str(&engine_config("\"poa\"")).unwrap();
        assert_eq!(config.consensus.engine, ConsensusEngine::Poa);
        assert_eq!(
            config.consensus.production_engine().unwrap(),
            ProductionEngine::Poa
        );
    }

    /// Parsed, then refused, with the reason and no fallback.
    #[test]
    fn bft_is_refused_not_downgraded() {
        let config: NodeConfig = toml::from_str(&engine_config("\"bft\"")).unwrap();
        assert_eq!(config.consensus.engine, ConsensusEngine::Bft);
        let err = config
            .consensus
            .production_engine()
            .expect_err("BFT must be refused, not mapped to another engine")
            .to_string();
        assert_eq!(err, BFT_ENGINE_UNAVAILABLE);
        assert!(err.contains("unavailable pending the certified-finality protocol"));
        assert!(err.contains("does not fall back"));
    }

    /// Every spelling that is not exactly `poa` or `bft` fails to load, so none
    /// can reach a node as either engine — in particular not as the default.
    #[test]
    fn malformed_engine_values_fail_to_load() {
        let dir = TempDir::new().unwrap();
        for value in [
            "\"BFT\"",
            "\"Bft\"",
            "\"bFt\"",
            "\" bft\"",
            "\"bft \"",
            "\"bft\\u0000\"",
            "\"POA\"",
            "\"Poa\"",
            "\"\"",
            "\"tendermint\"",
            "1",
            "true",
            "[\"bft\"]",
            "{ bft = true }",
        ] {
            let text = engine_config(value);
            assert!(
                toml::from_str::<NodeConfig>(&text).is_err(),
                "engine = {value} must not parse"
            );
            let path = dir.path().join("config.toml");
            std::fs::write(&path, &text).unwrap();
            assert!(
                NodeConfig::from_file(&path).is_err(),
                "engine = {value} must not load"
            );
        }
    }

    /// The example `sumchain-node` writes for operators names PoA and does
    /// not present BFT as an option.
    #[test]
    fn example_config_does_not_offer_bft() {
        let example = NodeConfig::example_config();
        let config: NodeConfig = toml::from_str(&example).unwrap();
        assert_eq!(
            config.consensus.production_engine().unwrap(),
            ProductionEngine::Poa
        );
        assert!(!example.contains("[consensus.bft]"));
        assert!(!example.contains("\"poa\" or \"bft\""));
    }

    /// No config shipped in the repository selects the BFT engine.
    #[test]
    fn no_shipped_config_selects_bft() {
        let configs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        let mut stack = vec![configs];
        let mut seen = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                seen += 1;
                let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
                let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
                assert!(
                    !squeezed.contains("engine=\"bft\"")
                        && !squeezed.contains("\"engine\":\"bft\""),
                    "{} selects the BFT engine",
                    path.display()
                );
            }
        }
        assert!(seen > 0, "the configs directory was not found");
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
