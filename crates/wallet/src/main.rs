//! SUM Chain CLI Wallet
//!
//! Command-line wallet for key management and transaction signing.
//! Native currency: Koppa (Ϙ)

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;

mod currency;
mod display;
mod keystore;
mod tx;

use currency::{format_koppa, parse_koppa, KOPPA_SYMBOL};
use display::*;
use keystore::Keystore;
use std::path::Path;

/// Load keystore - for raw keys no password needed, for encrypted will prompt
fn load_keystore(path: &Path) -> Result<Keystore> {
    // First try to load as raw key (no password needed)
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read key file: {:?}", path))?;

    // Check if it's a raw byte array (unencrypted dev key)
    if let Ok(raw_bytes) = serde_json::from_str::<Vec<u8>>(&contents) {
        if raw_bytes.len() == 32 {
            // It's a raw key, load without password
            return Keystore::load(path, "");
        }
    }

    // It's encrypted, prompt for password
    let password = rpassword::prompt_password("🔐 Enter keystore password: ")?;
    Keystore::load(path, &password)
}

#[derive(Parser)]
#[command(name = "sumchain-wallet")]
#[command(about = "SUM Chain CLI Wallet - Native currency: Koppa (Ϙ)", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Output file path for encrypted keystore
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Show address for a key file
    Address {
        /// Path to key file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Show public key
    Pubkey {
        /// Path to key file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Sign a transaction (offline)
    SignTx {
        /// Path to key file
        #[arg(short, long)]
        key: PathBuf,

        /// Recipient address
        #[arg(long)]
        to: String,

        /// Amount to send in Koppa (e.g., "1.5" or "1.5 Ϙ")
        #[arg(long)]
        amount: String,

        /// Transaction fee in Koppa (e.g., "0.001")
        #[arg(long)]
        fee: String,

        /// Sender nonce
        #[arg(long)]
        nonce: u64,

        /// Chain ID
        #[arg(long)]
        chain_id: u64,
    },

    /// Send a raw signed transaction
    Send {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Raw transaction hex
        #[arg(long)]
        raw: String,
    },

    /// Query account balance
    Balance {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to query
        #[arg(long)]
        address: String,

        /// Output raw value in base units
        #[arg(long)]
        raw: bool,
    },

    /// Query account nonce
    Nonce {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to query
        #[arg(long)]
        address: String,
    },

    /// Transfer Koppa tokens (sign + send in one command)
    Transfer {
        /// Path to key file
        #[arg(short, long)]
        key: PathBuf,

        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Recipient address
        #[arg(long)]
        to: String,

        /// Amount to send in Koppa (e.g., "1.5" or "1.5 Ϙ")
        #[arg(long)]
        amount: String,

        /// Transaction fee in Koppa (e.g., "0.001")
        #[arg(long, default_value = "0.001")]
        fee: String,

        /// Chain ID
        #[arg(long)]
        chain_id: u64,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Get current block height
    BlockNumber {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get block by height
    Block {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Block height (omit for latest)
        #[arg(long)]
        height: Option<u64>,
    },

    /// Get validator set
    Validators {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get pending transactions in mempool
    Pending {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get transaction by hash
    Tx {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Transaction hash
        #[arg(long)]
        hash: String,
    },

    /// Get transaction receipt
    Receipt {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Transaction hash
        #[arg(long)]
        hash: String,
    },

    /// Get node health status
    Status {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Show wallet info (banner and version)
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Disable colors if requested
    if cli.no_color {
        colored::control::set_override(false);
    }

    match cli.command {
        Commands::Info => {
            print_banner();
            println!("  {}: {}", "Version".dimmed(), env!("CARGO_PKG_VERSION"));
            println!("  {}: Koppa ({})", "Currency".dimmed(), KOPPA_SYMBOL);
            println!("  {}: 9 decimal places", "Precision".dimmed());
            println!();
        }

        Commands::Keygen { output } => {
            print_header("Generate New Keypair");
            println!();

            // Prompt for password
            let password = rpassword::prompt_password("🔐 Enter password for keystore: ")?;
            let confirm = rpassword::prompt_password("🔐 Confirm password: ")?;

            if password != confirm {
                print_error("Passwords do not match");
                anyhow::bail!("Passwords do not match");
            }

            if password.len() < 8 {
                print_warning("Password is less than 8 characters. Consider using a stronger password.");
            }

            let keystore = Keystore::generate(&password)?;
            keystore.save(&output)?;

            println!();
            print_success("Keypair generated successfully!");
            println!();
            print_field("Public Key", &keystore.public_key().to_base58());
            print_field("Address", &keystore.address().to_base58());
            print_field("Saved to", &format!("{:?}", output));
            println!();
            print_warning("Back up your keystore file and remember your password!");
        }

        Commands::Address { key } => {
            let keystore = load_keystore(&key)?;
            println!("{}", keystore.address().to_base58().cyan());
        }

        Commands::Pubkey { key } => {
            let keystore = load_keystore(&key)?;
            println!("{}", keystore.public_key().to_base58().cyan());
        }

        Commands::SignTx {
            key,
            to,
            amount,
            fee,
            nonce,
            chain_id,
        } => {
            let keystore = load_keystore(&key)?;

            let amount_units = parse_koppa(&amount)
                .context("Invalid amount format. Use e.g., '1.5' for 1.5 Koppa")?;
            let fee_units = parse_koppa(&fee)
                .context("Invalid fee format. Use e.g., '0.001' for 0.001 Koppa")?;

            let to_addr = sumchain_primitives::Address::from_base58(&to)
                .or_else(|_| sumchain_primitives::Address::from_hex(&to))
                .context("Invalid recipient address")?;

            print_transaction_summary(
                &keystore.address().to_base58(),
                &to,
                amount_units,
                fee_units,
                nonce,
            );

            let signed_tx = tx::sign_transaction(
                &keystore,
                to_addr,
                amount_units,
                fee_units,
                nonce,
                chain_id,
            )?;

            print_success("Transaction signed!");
            println!();
            print_field("Hash", &signed_tx.hash().to_hex());
            print_field("Raw TX", &signed_tx.to_hex());
        }

        Commands::Send { rpc, raw } => {
            print_info(&format!("Sending transaction to {}...", rpc));
            let tx_hash = tx::send_raw_transaction(&rpc, &raw).await?;
            println!();
            print_success("Transaction sent!");
            print_field("Hash", &tx_hash);
        }

        Commands::Balance { rpc, address, raw } => {
            let balance_str = tx::get_balance(&rpc, &address).await?;
            let balance: u128 = balance_str.parse().unwrap_or(0);

            if raw {
                println!("{}", balance);
            } else {
                print_field("Address", &address);
                print_field("Balance", &format_koppa(balance).green().to_string());
            }
        }

        Commands::Nonce { rpc, address } => {
            let nonce = tx::get_nonce(&rpc, &address).await?;
            print_field("Address", &address);
            print_field("Nonce", &nonce.to_string());
        }

        Commands::Transfer {
            key,
            rpc,
            to,
            amount,
            fee,
            chain_id,
            yes,
        } => {
            let keystore = load_keystore(&key)?;

            let amount_units = parse_koppa(&amount)
                .context("Invalid amount format. Use e.g., '1.5' for 1.5 Koppa")?;
            let fee_units = parse_koppa(&fee)
                .context("Invalid fee format. Use e.g., '0.001' for 0.001 Koppa")?;

            let to_addr = sumchain_primitives::Address::from_base58(&to)
                .or_else(|_| sumchain_primitives::Address::from_hex(&to))
                .context("Invalid recipient address")?;

            // Get current nonce
            let nonce = tx::get_nonce(&rpc, &keystore.address().to_base58()).await?;

            // Get current balance for display
            let balance_str = tx::get_balance(&rpc, &keystore.address().to_base58()).await?;
            let balance: u128 = balance_str.parse().unwrap_or(0);

            print_header(&format!("Transfer {} Koppa", KOPPA_SYMBOL));
            println!();
            print_field("From", &keystore.address().to_base58());
            print_field("Current Balance", &format_koppa(balance));
            print_separator();
            print_field("To", &to);
            print_koppa_field("Amount", amount_units);
            print_koppa_field("Fee", fee_units);
            print_koppa_field("Total Cost", amount_units + fee_units);
            print_field("Nonce", &nonce.to_string());
            println!();

            // Check balance
            if balance < amount_units + fee_units {
                print_error(&format!(
                    "Insufficient balance! Need {} but have {}",
                    format_koppa(amount_units + fee_units),
                    format_koppa(balance)
                ));
                anyhow::bail!("Insufficient balance");
            }

            // Confirm unless --yes
            if !yes {
                if !confirm("Proceed with transfer?") {
                    print_warning("Transfer cancelled.");
                    return Ok(());
                }
            }

            println!();
            print_info("Signing transaction...");

            let signed_tx = tx::sign_transaction(
                &keystore,
                to_addr,
                amount_units,
                fee_units,
                nonce,
                chain_id,
            )?;

            print_info("Broadcasting transaction...");

            let tx_hash = tx::send_raw_transaction(&rpc, &signed_tx.to_hex()).await?;

            println!();
            print_success("Transfer successful!");
            print_field("Transaction Hash", &tx_hash);
            println!();
            print_info("Use 'sumchain-wallet receipt --hash <hash>' to check status.");
        }

        Commands::BlockNumber { rpc } => {
            let height = tx::get_block_number(&rpc).await?;
            println!("{} {}", "Block Height:".dimmed(), height.to_string().cyan().bold());
        }

        Commands::Block { rpc, height } => {
            let block = match height {
                Some(h) => tx::get_block(&rpc, h).await?,
                None => Some(tx::get_latest_block(&rpc).await?),
            };

            match block {
                Some(b) => {
                    print_block_header(b.height, &b.hash);
                    println!();
                    print_field("Hash", &b.hash);
                    print_field("Parent", &b.parent_hash);
                    print_field("Timestamp", &format_timestamp(b.timestamp));
                    print_field("State Root", &b.state_root);
                    print_field("Tx Root", &b.tx_root);
                    print_field("Proposer", &b.proposer);
                    print_field("Tx Count", &b.tx_count.to_string());

                    if !b.transactions.is_empty() {
                        println!();
                        println!("  {}:", "Transactions".dimmed());
                        for (i, tx_hash) in b.transactions.iter().enumerate() {
                            print_list_item(i, tx_hash);
                        }
                    }
                }
                None => print_warning("Block not found"),
            }
        }

        Commands::Validators { rpc } => {
            let info = tx::get_validators(&rpc).await?;

            print_header(&format!("Validators (Height {})", info.current_height));
            println!();
            print_field("Current Proposer Index", &info.current_proposer_index.to_string());
            println!();

            for (i, v) in info.validators.iter().enumerate() {
                let marker = if v.is_current_proposer {
                    " ← proposer".green().bold().to_string()
                } else {
                    String::new()
                };
                println!(
                    "  {} {}{}",
                    format!("[{}]", i).dimmed(),
                    v.address.cyan(),
                    marker
                );
                println!("      {}: {}", "Pubkey".dimmed(), v.public_key);
            }
        }

        Commands::Pending { rpc } => {
            let txs = tx::get_pending_transactions(&rpc).await?;

            if txs.is_empty() {
                print_info("No pending transactions in mempool");
            } else {
                print_header(&format!("Pending Transactions ({})", txs.len()));
                println!();

                for t in &txs {
                    let amount: u128 = t.amount.parse().unwrap_or(0);
                    let fee: u128 = t.fee.parse().unwrap_or(0);

                    println!(
                        "  {} {} → {}",
                        format_address_short(&t.hash).yellow(),
                        format_address_short(&t.from),
                        format_address_short(&t.to).cyan()
                    );
                    println!(
                        "      {} {} (fee: {})",
                        "Amount:".dimmed(),
                        format_koppa(amount),
                        format_koppa(fee)
                    );
                }
            }
        }

        Commands::Tx { rpc, hash } => {
            let tx_info = tx::get_transaction(&rpc, &hash).await?;

            match tx_info {
                Some(t) => {
                    let amount: u128 = t.amount.parse().unwrap_or(0);
                    let fee: u128 = t.fee.parse().unwrap_or(0);

                    print_header("Transaction");
                    println!();
                    print_field("Hash", &t.hash);
                    print_field("From", &t.from);
                    print_field("To", &t.to);
                    print_koppa_field("Amount", amount);
                    print_koppa_field("Fee", fee);
                    print_field("Nonce", &t.nonce.to_string());
                    print_field("Chain ID", &t.chain_id.to_string());

                    if let Some(height) = t.block_height {
                        print_field("Block", &height.to_string());
                    }
                    if let Some(status) = &t.status {
                        let status_display = match status.as_str() {
                            "success" | "Success" => status.green().to_string(),
                            "failed" | "Failed" => status.red().to_string(),
                            "pending" | "Pending" => status.yellow().to_string(),
                            _ => status.clone(),
                        };
                        print_field_colored("Status", &status_display, Color::White);
                    }
                }
                None => print_warning("Transaction not found"),
            }
        }

        Commands::Receipt { rpc, hash } => {
            let receipt = tx::get_receipt(&rpc, &hash).await?;

            match receipt {
                Some(r) => {
                    let fee_paid: u128 = r.fee_paid.parse().unwrap_or(0);

                    print_header("Transaction Receipt");
                    println!();
                    print_field("Tx Hash", &r.tx_hash);
                    print_field("Block", &r.block_height.to_string());
                    print_field("Index", &r.tx_index.to_string());

                    let status_display = match r.status.as_str() {
                        "success" | "Success" => r.status.green().to_string(),
                        "failed" | "Failed" => r.status.red().to_string(),
                        _ => r.status.clone(),
                    };
                    println!(
                        "  {}: {}",
                        "Status".dimmed(),
                        status_display
                    );

                    print_koppa_field("Fee Paid", fee_paid);
                }
                None => {
                    print_warning("Receipt not found");
                    print_info("Transaction may be pending or not yet included in a block.");
                }
            }
        }

        Commands::Status { rpc } => {
            let health = tx::get_health(&rpc).await?;

            print_header("Node Status");
            println!();

            let status_color = if health.status == "healthy" {
                health.status.green().bold()
            } else {
                health.status.red().bold()
            };

            println!("  {}: {}", "Status".dimmed(), status_color);
            print_field("Chain ID", &health.chain_id.to_string());
            print_field("Height", &health.height.to_string());
            print_field("Peer Count", &health.peer_count.to_string());
            print_status_indicator("Validator", health.is_validator);
            print_status_indicator("Synced", health.is_synced);
        }
    }

    Ok(())
}
