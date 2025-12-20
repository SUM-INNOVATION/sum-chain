//! SUM Chain Node
//!
//! Full node implementation that ties together all components.

use std::panic;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use sumchain_consensus::ConsensusEngine; // Used via trait object
use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_p2p::NetworkConfig;
use sumchain_rpc::{RateLimitConfig, RpcAuthConfig};
use sumchain_state::StateManager;
use sumchain_storage::Database;
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;
mod consensus_wrapper;
mod node;
mod tx_broadcaster;

use config::NodeConfig;
use consensus_wrapper::ConsensusWrapper;
use node::Node;
pub use tx_broadcaster::{TxBroadcaster, TxBroadcasterConfig, TxBroadcasterStats};

/// Node version from Cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Git commit hash (set at build time, or "unknown")
pub const GIT_HASH: &str = match option_env!("GIT_HASH") {
    Some(hash) => hash,
    None => "unknown",
};

#[derive(Parser)]
#[command(name = "sumchain")]
#[command(about = "SUM Chain Node", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full node
    Run {
        /// Path to node config file (TOML format)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to genesis file (overrides config)
        #[arg(short, long)]
        genesis: Option<PathBuf>,

        /// Data directory (overrides config)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,

        /// RPC listen address (overrides config)
        #[arg(long)]
        rpc_addr: Option<String>,

        /// P2P listen address (overrides config)
        #[arg(long)]
        p2p_addr: Option<String>,

        /// Bootstrap nodes (overrides config)
        #[arg(long)]
        bootnodes: Option<Vec<String>>,

        /// Validator key file (overrides config)
        #[arg(long)]
        validator_key: Option<PathBuf>,

        /// RPC API key for authentication (overrides config)
        #[arg(long)]
        rpc_api_key: Option<String>,

        /// Enable RPC rate limiting (overrides config)
        #[arg(long)]
        rpc_rate_limit: Option<bool>,

        /// RPC rate limit: requests per second per IP (overrides config)
        #[arg(long)]
        rpc_rps: Option<u32>,

        /// RPC rate limit: burst size (overrides config)
        #[arg(long)]
        rpc_burst: Option<u32>,

        /// Log level (overrides config)
        #[arg(long)]
        log_level: Option<String>,

        /// Output logs in JSON format (overrides config)
        #[arg(long)]
        log_json: Option<bool>,
    },

    /// Initialize a new chain from genesis
    Init {
        /// Path to genesis file
        #[arg(short, long)]
        genesis: PathBuf,

        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,
    },

    /// Generate a new keypair
    Keygen {
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Show node info
    Info {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,
    },

    /// Generate a new RPC API key
    GenApiKey,

    /// Generate an example configuration file
    GenConfig {
        /// Output file path
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
    },

    /// Create a backup of the database
    Backup {
        /// Data directory to backup
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Backup destination directory
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Restore database from a backup
    Restore {
        /// Backup directory to restore from
        #[arg(short, long)]
        backup: PathBuf,

        /// Target data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Force restore even if target exists
        #[arg(long)]
        force: bool,
    },

    /// List available backups
    ListBackups {
        /// Directory containing backups
        #[arg(short, long, default_value = "backups")]
        backups_dir: PathBuf,
    },

    /// Compact database to reclaim space
    Compact {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up panic hook for better crash reporting
    setup_panic_hook();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            genesis,
            data_dir,
            rpc_addr,
            p2p_addr,
            bootnodes,
            validator_key,
            rpc_api_key,
            rpc_rate_limit,
            rpc_rps,
            rpc_burst,
            log_level,
            log_json,
        } => {
            // Load config file if provided, otherwise use defaults
            let mut cfg = match &config {
                Some(path) => {
                    NodeConfig::from_file(path)
                        .with_context(|| format!("Failed to load config from {:?}", path))?
                }
                None => NodeConfig::default(),
            };

            // Apply CLI overrides (CLI takes precedence over config file)
            if let Some(g) = genesis {
                cfg.node.genesis = g;
            }
            if let Some(d) = data_dir {
                cfg.node.data_dir = d;
            }
            if let Some(v) = validator_key {
                cfg.node.validator_key = Some(v);
            }
            if let Some(addr) = p2p_addr {
                cfg.network.listen_addr = addr;
            }
            if let Some(nodes) = bootnodes {
                cfg.network.bootnodes = nodes;
            }
            if let Some(addr) = rpc_addr {
                cfg.rpc.addr = addr;
            }
            if let Some(key) = rpc_api_key {
                cfg.rpc.api_key = Some(key);
            }
            if let Some(enabled) = rpc_rate_limit {
                cfg.rpc.rate_limit_enabled = enabled;
            }
            if let Some(rps) = rpc_rps {
                cfg.rpc.rate_limit_rps = rps;
            }
            if let Some(burst) = rpc_burst {
                cfg.rpc.rate_limit_burst = burst;
            }
            if let Some(level) = log_level {
                cfg.logging.level = level;
            }
            if let Some(json) = log_json {
                cfg.logging.json = json;
            }

            // Initialize logging
            init_logging(&cfg.logging.level, cfg.logging.json)?;

            // Print startup banner
            print_banner();

            if config.is_some() {
                info!("Loaded configuration from {:?}", config.as_ref().unwrap());
            }

            // Load genesis
            let genesis_file = &cfg.node.genesis;
            let genesis = Genesis::from_file(genesis_file)
                .with_context(|| format!("Failed to load genesis from {:?}", genesis_file))?;

            info!("Loaded genesis for chain {}", genesis.chain_id);

            // Load validator key if provided
            let validator_key = if let Some(key_path) = &cfg.node.validator_key {
                let key_json = std::fs::read_to_string(key_path)
                    .with_context(|| format!("Failed to read validator key from {:?}", key_path))?;
                let key_bytes: [u8; 32] = serde_json::from_str(&key_json)
                    .with_context(|| "Failed to parse validator key")?;
                Some(KeyPair::from_bytes(key_bytes))
            } else {
                None
            };

            // Setup RPC authentication
            let rpc_auth_config = match &cfg.rpc.api_key {
                Some(key) => {
                    info!("RPC authentication enabled");
                    RpcAuthConfig::with_api_key(key.clone())
                }
                None => RpcAuthConfig::disabled(),
            };

            // Setup RPC rate limiting
            let rpc_rate_limit_config = if cfg.rpc.rate_limit_enabled {
                info!("RPC rate limiting enabled: {} req/s, burst {}",
                    cfg.rpc.rate_limit_rps, cfg.rpc.rate_limit_burst);
                RateLimitConfig::with_limits(cfg.rpc.rate_limit_rps, cfg.rpc.rate_limit_burst)
            } else {
                RateLimitConfig::disabled()
            };

            // Create node with persistent node key
            let node_key_file = cfg.node.data_dir.join("node.key");
            let mut node = Node::with_rpc_config(
                cfg.node.data_dir.clone(),
                genesis,
                validator_key,
                NetworkConfig {
                    listen_addr: cfg.network.listen_addr,
                    bootnodes: cfg.network.bootnodes,
                    node_key_file: Some(node_key_file),
                    ..Default::default()
                },
                cfg.rpc.addr.parse().context("Invalid RPC address")?,
                rpc_auth_config,
                rpc_rate_limit_config,
                cfg.consensus,
            )?;

            // Run node
            node.run().await?;
        }

        Commands::Init { genesis, data_dir } => {
            init_logging("info", false)?;

            info!("Initializing chain from genesis");

            let genesis = Genesis::from_file(&genesis)
                .with_context(|| format!("Failed to load genesis from {:?}", genesis))?;

            // Create data directory
            std::fs::create_dir_all(&data_dir)?;

            // Open database
            let db = Database::open_default(&data_dir)?;
            let state = StateManager::new(Arc::new(db), genesis.chain_id);

            // Initialize state from genesis
            state.init_from_genesis(&genesis)?;

            info!("Chain initialized successfully");
            info!("Chain ID: {}", genesis.chain_id);
            info!("Validators: {}", genesis.validators.len());
            info!("Prefunded accounts: {}", genesis.alloc.len());
        }

        Commands::Keygen { output } => {
            let keypair = KeyPair::generate();

            // Save private key as JSON
            let key_json = serde_json::to_string_pretty(keypair.private_key().as_bytes())?;
            std::fs::write(&output, &key_json)?;

            println!("Generated new keypair");
            println!("Public key: {}", keypair.public_key().to_base58());
            println!("Address: {}", keypair.address().to_base58());
            println!("Private key saved to: {:?}", output);
        }

        Commands::Info { data_dir } => {
            init_logging("info", false)?;

            let db = Database::open_default(&data_dir)?;
            let block_store = sumchain_storage::BlockStore::new(&db);

            match block_store.get_latest()? {
                Some(block) => {
                    println!("SUM Chain Node v{}", VERSION);
                    println!();
                    println!("Chain info:");
                    println!("  Latest height: {}", block.height());
                    println!("  Latest hash:   {}", block.hash());
                    println!("  State root:    {}", block.header.state_root);

                    // Show finality info if available
                    if let Ok(Some(finalized_height)) = block_store.get_finalized_height() {
                        let finalized_hash = block_store.get_finalized_hash()?.unwrap_or_default();
                        println!();
                        println!("Finality:");
                        println!("  Finalized height: {}", finalized_height);
                        println!("  Finalized hash:   {}", finalized_hash);
                        println!("  Pending blocks:   {}", block.height().saturating_sub(finalized_height));
                    }
                }
                None => {
                    println!("Chain not initialized. Run 'sumchain init' first.");
                }
            }
        }

        Commands::GenApiKey => {
            let api_key = sumchain_rpc::generate_api_key();
            println!("Generated RPC API key:");
            println!("{}", api_key);
            println!();
            println!("Use it with: sumchain run --rpc-api-key {}", api_key);
        }

        Commands::GenConfig { output } => {
            let config = NodeConfig::example_config();
            std::fs::write(&output, &config)
                .with_context(|| format!("Failed to write config to {:?}", output))?;
            println!("Example configuration written to: {:?}", output);
            println!();
            println!("Edit the file to customize your node settings, then run:");
            println!("  sumchain run --config {:?}", output);
        }

        Commands::Backup { data_dir, output } => {
            init_logging("info", false)?;

            info!("Creating database backup");

            // Open database in read-only mode
            let db = Database::open_default(&data_dir)?;

            // Create backup
            let backup_info = db.create_backup(&output)?;

            println!("Backup created successfully!");
            println!("  Path: {:?}", backup_info.path);
            println!("  Size: {}", backup_info.size_human());
        }

        Commands::Restore {
            backup,
            data_dir,
            force,
        } => {
            init_logging("info", false)?;

            // Check if target exists
            if data_dir.exists() && !force {
                anyhow::bail!(
                    "Target directory {:?} already exists. Use --force to overwrite.",
                    data_dir
                );
            }

            info!("Restoring database from backup");

            Database::restore_from_backup(&backup, &data_dir)?;

            println!("Database restored successfully!");
            println!("  From: {:?}", backup);
            println!("  To:   {:?}", data_dir);
        }

        Commands::ListBackups { backups_dir } => {
            let backups = Database::list_backups(&backups_dir)?;

            if backups.is_empty() {
                println!("No backups found in {:?}", backups_dir);
            } else {
                println!("Available backups in {:?}:", backups_dir);
                println!();
                for (i, backup) in backups.iter().enumerate() {
                    let datetime = chrono_format_timestamp(backup.timestamp);
                    println!(
                        "  {}. {:?}",
                        i + 1,
                        backup.path.file_name().unwrap_or_default()
                    );
                    println!("     Size: {}", backup.size_human());
                    println!("     Created: {}", datetime);
                    println!();
                }
            }
        }

        Commands::Compact { data_dir } => {
            init_logging("info", false)?;

            info!("Compacting database");

            let db = Database::open_default(&data_dir)?;

            // Get size before
            let size_before = db.approximate_size();

            // Compact
            db.compact()?;

            // Get size after
            let size_after = db.approximate_size();

            println!("Database compacted successfully!");
            println!("  Size before: {} bytes", size_before);
            println!("  Size after:  {} bytes", size_after);
            if size_before > size_after {
                println!(
                    "  Saved:       {} bytes",
                    size_before.saturating_sub(size_after)
                );
            }
        }
    }

    Ok(())
}

/// Format a Unix timestamp as a human-readable date string
fn chrono_format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp))
        .map(|time| {
            let datetime: std::time::SystemTime = time;
            // Simple formatting without chrono dependency
            format!("{:?}", datetime)
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Print startup banner with version info
fn print_banner() {
    info!("================================================");
    info!("  SUM Chain Node v{}", VERSION);
    info!("  Commit: {}", GIT_HASH);
    info!("================================================");
}

/// Initialize logging with optional JSON output and env filter support
fn init_logging(level: &str, json: bool) -> Result<()> {
    // Build filter from RUST_LOG env var, or fall back to provided level
    // Example: RUST_LOG=sumchain=debug,libp2p=warn
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // Default filter: set global level and reduce noise from dependencies
            EnvFilter::new(format!(
                "{},libp2p=warn,libp2p_gossipsub=warn,libp2p_mdns=warn,yamux=warn,multistream_select=warn",
                level
            ))
        });

    if json {
        // JSON logging for production/log aggregation
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .try_init()
            .context("Failed to set tracing subscriber")?;
    } else {
        // Human-readable logging for development
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false),
            )
            .try_init()
            .context("Failed to set tracing subscriber")?;
    }

    Ok(())
}

/// Set up a custom panic hook for better crash reporting
fn setup_panic_hook() {
    let default_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        // Get location information
        let location = panic_info.location().map_or_else(
            || "unknown location".to_string(),
            |loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()),
        );

        // Get the panic message
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic payload".to_string()
        };

        // Log the panic using tracing (if initialized) or stderr
        let crash_report = format!(
            "\n\
            ╔══════════════════════════════════════════════════════════════════╗\n\
            ║                    SUM CHAIN NODE CRASH REPORT                   ║\n\
            ╠══════════════════════════════════════════════════════════════════╣\n\
            ║ Version: {:<55} ║\n\
            ║ Commit:  {:<55} ║\n\
            ╠══════════════════════════════════════════════════════════════════╣\n\
            ║ Location: {:<54} ║\n\
            ║ Message:  {:<54} ║\n\
            ╠══════════════════════════════════════════════════════════════════╣\n\
            ║ Please report this issue at:                                     ║\n\
            ║ https://github.com/sumchain/sum-chain/issues                     ║\n\
            ╚══════════════════════════════════════════════════════════════════╝\n",
            VERSION,
            GIT_HASH,
            truncate_str(&location, 54),
            truncate_str(&message, 54),
        );

        // Try to log via tracing, fall back to stderr
        error!("{}", crash_report);
        eprintln!("{}", crash_report);

        // Call the default hook for backtrace etc.
        default_hook(panic_info);
    }));
}

/// Truncate a string to a maximum length, adding "..." if truncated
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len > 3 {
        format!("{}...", &s[..max_len - 3])
    } else {
        s[..max_len].to_string()
    }
}
