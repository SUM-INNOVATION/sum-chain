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
use sumchain_crypto::{sign, KeyPair};
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

    /// Show key info (public key and address) from a key file
    KeyInfo {
        /// Path to key file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Transfer Koppa to another address
    Transfer {
        /// Sender's key file
        #[arg(short, long)]
        key: PathBuf,

        /// Recipient address (base58)
        #[arg(short, long)]
        to: String,

        /// Amount in Koppa (e.g., "100" or "1.5")
        #[arg(short, long)]
        amount: String,

        /// RPC endpoint URL
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,

        /// Transaction fee in base units (default: 1000000 = 0.001 Koppa)
        #[arg(long, default_value = "1000000")]
        fee: u128,
    },

    /// Wipe employment data (SRC-88X) from the database
    WipeEmployment {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Roll back the chain tip to a target height (recovery tool).
    /// Node must be stopped. Reverts state diffs, deletes blocks above target,
    /// and resets latest_block_hash / latest_block_height.
    Rollback {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Target height to roll back to (must be < current tip)
        #[arg(long)]
        to_height: u64,

        /// Maximum number of blocks allowed to roll back (safety guard)
        #[arg(long, default_value = "10")]
        max_blocks: u64,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Export every registered SRC-201 messaging public key to NDJSON.
    /// Used to migrate registrations from one validator to another after
    /// `messaging_registerSponsored` direct-write divergence (recovery tool).
    /// Node must be stopped on the source data dir.
    ExportRegisteredKeys {
        /// Data directory to read from
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Output file path. Use "-" or omit to write to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import SRC-201 messaging public keys from NDJSON.
    /// Reads each registration record and writes it to MESSAGING_PUBLIC_KEYS.
    /// Node must be stopped on the target data dir.
    ImportRegisteredKeys {
        /// Data directory to write to
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Input file path. Use "-" or omit to read from stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Skip records whose address is already registered locally
        #[arg(long, default_value = "true")]
        skip_existing: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Inspect SNIP V2 metadata rows in the database (read-only). Used as a
    /// pre-flight before deploying any V2 schema-bump binary: a non-zero file
    /// or owner-index count means the positional bincode shape on disk must
    /// match the binary, so a schema-changing upgrade is unsafe without a
    /// versioned-row migration. Safe to run on a stopped node; opens the DB
    /// read-only.
    InspectV2Rows {
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
                cfg.health.addr.parse().context("Invalid health address")?,
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

        Commands::KeyInfo { key } => {
            let key_json = std::fs::read_to_string(&key)
                .with_context(|| format!("Failed to read key file: {:?}", key))?;
            let key_bytes: [u8; 32] = serde_json::from_str(&key_json)
                .with_context(|| "Failed to parse key file (expected JSON array of 32 bytes)")?;

            let keypair = KeyPair::from_bytes(key_bytes);

            println!("Key Info:");
            println!("  File:       {:?}", key);
            println!("  Public Key: {}", keypair.public_key().to_base58());
            println!("  Address:    {}", keypair.address().to_base58());
        }

        Commands::Transfer {
            key,
            to,
            amount,
            rpc,
            fee,
        } => {
            use sumchain_primitives::{Address, SignedTransaction, TransactionV2};

            // Load sender key
            let key_json = std::fs::read_to_string(&key)
                .with_context(|| format!("Failed to read key file: {:?}", key))?;
            let key_bytes: [u8; 32] = serde_json::from_str(&key_json)
                .with_context(|| "Failed to parse key file")?;
            let keypair = KeyPair::from_bytes(key_bytes);

            // Parse recipient address
            let to_addr = Address::from_base58(&to)
                .or_else(|_| Address::from_hex(&to))
                .with_context(|| format!("Invalid recipient address: {}", to))?;

            // Parse amount (Koppa to base units, 9 decimals)
            let amount_base: u128 = if amount.contains('.') {
                let parts: Vec<&str> = amount.split('.').collect();
                let whole: u128 = parts[0].parse().with_context(|| "Invalid amount")?;
                let frac_str = parts.get(1).unwrap_or(&"0");
                let frac_padded = format!("{:0<9}", frac_str);
                let frac: u128 = frac_padded[..9].parse().with_context(|| "Invalid amount")?;
                whole * 1_000_000_000 + frac
            } else {
                let whole: u128 = amount.parse().with_context(|| "Invalid amount")?;
                whole * 1_000_000_000
            };

            println!("Transfer Details:");
            println!("  From:   {}", keypair.address().to_base58());
            println!("  To:     {}", to_addr.to_base58());
            println!("  Amount: {} Koppa ({} base units)", amount, amount_base);
            println!("  Fee:    {} base units", fee);
            println!("  RPC:    {}", rpc);
            println!();

            // Query chain ID and nonce from RPC
            let client = reqwest::blocking::Client::new();

            // Get chain ID
            let chain_id_resp: serde_json::Value = client
                .post(&rpc)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_id",
                    "params": [],
                    "id": 1
                }))
                .send()
                .with_context(|| "Failed to connect to RPC")?
                .json()
                .with_context(|| "Failed to parse chain_id response")?;

            let chain_id = chain_id_resp["result"]
                .as_u64()
                .with_context(|| "Invalid chain_id response")?;

            // Get nonce
            let nonce_resp: serde_json::Value = client
                .post(&rpc)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "get_nonce",
                    "params": [keypair.address().to_base58()],
                    "id": 2
                }))
                .send()
                .with_context(|| "Failed to get nonce")?
                .json()
                .with_context(|| "Failed to parse nonce response")?;

            let nonce = nonce_resp["result"]
                .as_u64()
                .with_context(|| "Invalid nonce response")?;

            println!("  Chain ID: {}", chain_id);
            println!("  Nonce:    {}", nonce);
            println!();

            // Build transaction
            let tx = TransactionV2::transfer(
                chain_id,
                keypair.address(),
                to_addr,
                amount_base,
                fee,
                nonce,
            );

            // Sign transaction
            let signing_hash = tx.signing_hash();
            let signature = sign(signing_hash.as_bytes(), keypair.private_key());
            let signed_tx = SignedTransaction::new_v2(
                tx,
                signature.to_bytes(),
                *keypair.public_key().as_bytes(),
            );

            // Send transaction
            let tx_hex = signed_tx.to_hex();
            let send_resp: serde_json::Value = client
                .post(&rpc)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "send_raw_transaction",
                    "params": [tx_hex],
                    "id": 3
                }))
                .send()
                .with_context(|| "Failed to send transaction")?
                .json()
                .with_context(|| "Failed to parse send response")?;

            if let Some(error) = send_resp.get("error") {
                anyhow::bail!("Transaction failed: {}", error);
            }

            let tx_hash = send_resp["result"]["tx_hash"]
                .as_str()
                .with_context(|| "Missing tx_hash in response")?;

            println!("Transaction sent successfully!");
            println!("  TX Hash: {}", tx_hash);
        }

        Commands::WipeEmployment { data_dir, yes } => {
            use sumchain_storage::cf;

            init_logging("info", false)?;

            // Employment column families to wipe
            let employment_cfs = [
                cf::EMPLOYMENT_ISSUERS,
                cf::EMPLOYMENT_CREDENTIALS,
                cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                cf::EMPLOYMENT_PROOFS,
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                cf::EMPLOYMENT_SYSTEM_EVENTS,
            ];

            println!("WARNING: This will wipe all employment data (SRC-88X) from the database!");
            println!("Data directory: {:?}", data_dir);
            println!();
            println!("Column families to wipe:");
            for cf_name in &employment_cfs {
                println!("  - {}", cf_name);
            }
            println!();

            if !yes {
                println!("Are you sure you want to proceed? Type 'yes' to confirm:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim().to_lowercase() != "yes" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            info!("Opening database at {:?}", data_dir);
            let db = Database::open_default(&data_dir)?;

            info!("Wiping employment column families...");
            let deleted = db.wipe_column_families(&employment_cfs)?;

            println!();
            println!("Employment data wiped successfully!");
            println!("  Total entries deleted: {}", deleted);
        }

        Commands::Rollback {
            data_dir,
            to_height,
            max_blocks,
            yes,
        } => {
            use sumchain_storage::cf;
            use sumchain_storage::schema::{BlockStore, StateStore};

            init_logging("info", false)?;

            info!("Opening database at {:?}", data_dir);
            let db = Database::open_default(&data_dir)?;

            let block_store = BlockStore::new(&db);
            let state_store = StateStore::new(&db);

            let current_height = block_store
                .get_latest_height()?
                .context("No latest block height found in DB (chain not initialized?)")?;

            if to_height >= current_height {
                anyhow::bail!(
                    "Target height {} must be strictly less than current tip {}",
                    to_height,
                    current_height
                );
            }

            let to_rollback = current_height - to_height;
            if to_rollback > max_blocks {
                anyhow::bail!(
                    "Refusing to roll back {} blocks (max allowed: {}). \
                     Raise --max-blocks if you really mean to do this.",
                    to_rollback,
                    max_blocks
                );
            }

            let target_block = block_store
                .get_by_height(to_height)?
                .with_context(|| format!("No block found at target height {}", to_height))?;
            let target_hash = target_block.hash();

            println!("WARNING: Rolling back {} block(s).", to_rollback);
            println!("  Data directory: {:?}", data_dir);
            println!("  Current tip:    {}", current_height);
            println!("  Target tip:     {} (hash {})", to_height, target_hash);
            println!();
            println!("This will:");
            println!("  - Revert account state using stored state diffs");
            println!("  - Delete blocks, height->hash index, and state diffs above target");
            println!("  - Reset LATEST_BLOCK_HASH / LATEST_BLOCK_HEIGHT to the target");
            println!();
            println!("The node must be stopped before running this command.");
            println!();

            if !yes {
                println!("Type 'yes' to proceed:");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if input.trim().to_lowercase() != "yes" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Walk from tip down to target+1, reverting each block.
            for height in (to_height + 1..=current_height).rev() {
                let block = block_store.get_by_height(height)?.with_context(|| {
                    format!("Missing block at height {} during rollback", height)
                })?;
                let block_hash = block.hash();

                // 1. Revert account state using the stored state diff.
                if let Some(diff) = state_store.get_state_diff(height)? {
                    for (address, old_state, _new_state) in diff.changes.iter().rev() {
                        match old_state {
                            Some(prev) => state_store.put_account(address, prev)?,
                            None => {
                                // Account did not exist before this block — delete it.
                                let mut key = Vec::with_capacity(4 + 20);
                                key.extend_from_slice(b"acct");
                                key.extend_from_slice(address.as_bytes());
                                db.delete(cf::STATE, &key)?;
                            }
                        }
                    }
                } else {
                    info!("No state diff found for height {} (skipping revert)", height);
                }

                // 2. Delete receipts for this block.
                for tx in block.transactions.iter() {
                    db.delete(cf::RECEIPTS, tx.hash().as_bytes())?;
                }

                // 3. Delete the state diff.
                state_store.delete_state_diff(height)?;

                // 4. Delete the height -> hash index entry.
                db.delete(cf::BLOCK_HEIGHT, &height.to_be_bytes())?;

                // 5. Delete the block itself.
                db.delete(cf::BLOCKS, block_hash.as_bytes())?;

                info!("Reverted block {} ({})", height, block_hash);
            }

            // Reset chain tip.
            block_store.set_latest_hash(&target_hash)?;
            block_store.set_latest_height(to_height)?;

            // Bring finalized height back down if it had advanced past target.
            if let Some(fin_height) = block_store.get_finalized_height()? {
                if fin_height > to_height {
                    block_store.set_finalized_height(to_height)?;
                    block_store.set_finalized_hash(&target_hash)?;
                    info!("Finalized height pulled back to {}", to_height);
                }
            }

            println!();
            println!("Rollback complete.");
            println!("  New tip: {} ({})", to_height, target_hash);
            println!();
            println!("Start the node to resume block production.");
        }

        Commands::ExportRegisteredKeys { data_dir, output } => {
            use std::io::Write;
            use sumchain_storage::messaging_store::MessagingStore;

            init_logging("info", false)?;

            info!("Opening database at {:?}", data_dir);
            let db = Database::open_default(&data_dir)?;
            let store = MessagingStore::new(&db);

            let entries = store
                .iter_all_pubkeys()
                .context("Failed to iterate registered public keys")?;

            // Stable order — sort by address bytes — so diffs across snapshots are clean.
            let mut entries = entries;
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

            let mut writer: Box<dyn Write> = match output.as_deref() {
                None => Box::new(std::io::stdout()),
                Some(p) if p.as_os_str() == "-" => Box::new(std::io::stdout()),
                Some(p) => Box::new(std::fs::File::create(p).with_context(|| {
                    format!("Failed to create output file {:?}", p)
                })?),
            };

            for (address, key) in &entries {
                let record = serde_json::json!({
                    "address": address.to_base58(),
                    "public_key": format!("0x{}", hex::encode(key.public_key)),
                    "registered_at_block": key.registered_at_block,
                    "registered_at": key.registered_at,
                    "updated_at_block": key.updated_at_block,
                });
                writeln!(writer, "{}", serde_json::to_string(&record)?)
                    .context("Failed to write output")?;
            }

            // If we wrote to stdout, just flush. If file, also report count to stderr.
            writer.flush().ok();
            eprintln!("Exported {} registered public key(s).", entries.len());
        }

        Commands::ImportRegisteredKeys {
            data_dir,
            input,
            skip_existing,
            yes,
        } => {
            use std::io::BufRead;
            use sumchain_primitives::{Address, RegisteredPublicKey};
            use sumchain_storage::messaging_store::MessagingStore;

            init_logging("info", false)?;

            // Read all records up front so we can show a count and prompt before mutating.
            let reader: Box<dyn std::io::Read> = match input.as_deref() {
                None => Box::new(std::io::stdin()),
                Some(p) if p.as_os_str() == "-" => Box::new(std::io::stdin()),
                Some(p) => Box::new(std::fs::File::open(p).with_context(|| {
                    format!("Failed to open input file {:?}", p)
                })?),
            };
            let buf = std::io::BufReader::new(reader);

            #[derive(serde::Deserialize)]
            struct Record {
                address: String,
                public_key: String,
                registered_at_block: u64,
                registered_at: u64,
                updated_at_block: u64,
            }

            let mut records: Vec<(Address, RegisteredPublicKey)> = Vec::new();
            for (lineno, line) in buf.lines().enumerate() {
                let line = line.context("Failed to read input line")?;
                if line.trim().is_empty() {
                    continue;
                }
                let r: Record = serde_json::from_str(&line).with_context(|| {
                    format!("Failed to parse JSON on line {}", lineno + 1)
                })?;

                let address = Address::from_base58(&r.address)
                    .or_else(|_| Address::from_hex(&r.address))
                    .map_err(|e| {
                        anyhow::anyhow!("Invalid address on line {}: {}", lineno + 1, e)
                    })?;

                let pubkey_hex = r.public_key.strip_prefix("0x").unwrap_or(&r.public_key);
                let pubkey_bytes = hex::decode(pubkey_hex).with_context(|| {
                    format!("Invalid public_key hex on line {}", lineno + 1)
                })?;
                if pubkey_bytes.len() != 32 {
                    anyhow::bail!(
                        "Public key on line {} is {} bytes, expected 32",
                        lineno + 1,
                        pubkey_bytes.len()
                    );
                }
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pubkey_bytes);

                // Sanity: the address in the record must match the address derived from the pubkey.
                let derived = Address::from_public_key(&pubkey);
                if derived != address {
                    anyhow::bail!(
                        "Address/pubkey mismatch on line {}: record address {} but pubkey derives to {}",
                        lineno + 1,
                        address.to_base58(),
                        derived.to_base58()
                    );
                }

                records.push((
                    address,
                    RegisteredPublicKey {
                        public_key: pubkey,
                        address,
                        registered_at_block: r.registered_at_block,
                        registered_at: r.registered_at,
                        updated_at_block: r.updated_at_block,
                    },
                ));
            }

            println!("WARNING: This will write {} registered public key record(s)", records.len());
            println!("  to MESSAGING_PUBLIC_KEYS in data dir {:?}.", data_dir);
            println!("  skip_existing = {}", skip_existing);
            println!();
            println!("The node must be stopped before running this command.");
            println!();

            if !yes {
                println!("Type 'yes' to proceed:");
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                if s.trim().to_lowercase() != "yes" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            info!("Opening database at {:?}", data_dir);
            let db = Database::open_default(&data_dir)?;
            let store = MessagingStore::new(&db);

            let mut wrote = 0u64;
            let mut skipped = 0u64;
            for (address, key) in &records {
                if skip_existing && store.has_public_key(address).unwrap_or(false) {
                    skipped += 1;
                    continue;
                }
                store.set_public_key(address, key)?;
                wrote += 1;
            }

            println!();
            println!("Import complete.");
            println!("  Wrote:   {}", wrote);
            println!("  Skipped: {} (already registered locally)", skipped);
            println!();
            println!("Start the node and the chain should accept previously-diverged blocks.");
        }

        Commands::InspectV2Rows { data_dir } => {
            // Reports counts of every V2 keyspace prefix the chain writes, so
            // the operator can decide whether a schema-changing binary swap
            // is safe (zero file rows + zero owner-index rows = no positional
            // bincode rows on disk to break). Only the file-row prefix is
            // deserialized; owner-index and attestation entries are tallied
            // by prefix-iterating their key prefixes.
            init_logging("info", false)?;

            info!("Opening database (read-only) at {:?}", data_dir);
            let cf_metadata = sumchain_storage::cf::STORAGE_METADATA_V2;
            let cf_attestations = sumchain_storage::cf::ASSIGNMENT_ATTESTATIONS_V2;

            // True read-only open: no CF creation, no repair, no WAL writes.
            // Opens every CF that exists on disk — V2 CFs absent on pre-V2
            // DBs surface as `NotFound` from `prefix_iter` below and are
            // reported as zero rows.
            let db = Database::open_read_only(&data_dir)?;

            // Treat a missing CF (pre-V2 DB) as "zero rows for this prefix".
            // Any other storage error is fatal — we don't want to silently
            // under-count an existing V2 row.
            fn iter_or_empty<'a>(
                db: &'a Database,
                cf: &str,
                prefix: &[u8],
            ) -> Result<Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a>> {
                match db.prefix_iter(cf, prefix) {
                    Ok(it) => Ok(Box::new(it)),
                    Err(sumchain_storage::StorageError::NotFound(_)) => {
                        Ok(Box::new(std::iter::empty()))
                    }
                    Err(e) => Err(e).context("prefix_iter on read-only DB"),
                }
            }

            // File rows: [b'F', b'2', merkle_root_32] = 34 bytes.
            let mut file_total: u64 = 0;
            let mut pending: u64 = 0;
            let mut active: u64 = 0;
            let mut abandoned: u64 = 0;
            let mut undeserializable: u64 = 0;
            for (key, value) in iter_or_empty(&db, cf_metadata, &[b'F', b'2'])? {
                if key.len() != 34 || key[0] != b'F' || key[1] != b'2' {
                    continue;
                }
                file_total += 1;
                match bincode::deserialize::<sumchain_primitives::StorageMetadataV2>(&value) {
                    Ok(row) => match row.lifecycle {
                        sumchain_primitives::FileLifecycleV2::Pending => pending += 1,
                        sumchain_primitives::FileLifecycleV2::Active => active += 1,
                        sumchain_primitives::FileLifecycleV2::Abandoned => abandoned += 1,
                    },
                    Err(_) => undeserializable += 1,
                }
            }

            // Owner index: [b'O', b'2', owner_20, merkle_root_32] = 54 bytes.
            // Counted only — never deserialized; the value is `[1]` sentinel.
            let mut owner_index: u64 = 0;
            for (key, _) in iter_or_empty(&db, cf_metadata, &[b'O', b'2'])? {
                if key.len() == 54 && key[0] == b'O' && key[1] == b'2' {
                    owner_index += 1;
                }
            }

            // Attestations CF (separate CF). Counted only.
            let mut attestation_rows: u64 = 0;
            for (_key, _value) in iter_or_empty(&db, cf_attestations, &[b'A'])? {
                attestation_rows += 1;
            }

            println!("SNIP V2 row inventory for {:?}", data_dir);
            println!("  CF '{}'", cf_metadata);
            println!("    file rows (prefix [b'F', b'2']):           {}", file_total);
            println!("      lifecycle = Pending:                     {}", pending);
            println!("      lifecycle = Active:                      {}", active);
            println!("      lifecycle = Abandoned:                   {}", abandoned);
            if undeserializable > 0 {
                println!(
                    "      undeserializable (schema mismatch?):     {}",
                    undeserializable
                );
            }
            println!("    owner-index rows (prefix [b'O', b'2']):    {}", owner_index);
            println!("  CF '{}'", cf_attestations);
            println!("    attestation rows (prefix [b'A']):          {}", attestation_rows);

            // Tripwire summary the operator's runbook keys off.
            let total_v2_rows = file_total
                .saturating_add(owner_index)
                .saturating_add(attestation_rows);
            if total_v2_rows == 0 {
                println!();
                println!(
                    "Result: SAFE_TO_BUMP_SCHEMA — zero V2 rows on disk; \
                     a positional-bincode field addition is safe."
                );
            } else {
                println!();
                println!(
                    "Result: UNSAFE_TO_BUMP_SCHEMA — {} V2 row(s) present. \
                     Do NOT deploy a binary that changes the StorageMetadataV2 layout.",
                    total_v2_rows
                );
                // Non-zero exit so a script can branch on the result.
                std::process::exit(2);
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
