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

    // ========================================================================
    // Archive-node stake withdrawal (issue #20)
    //
    // These operate on an ArchiveNode's STORAGE stake in the node registry —
    // distinct from validator staking (see the `staking-*` commands). v1 is
    // full-exit only: begin-unstake unbonds the node's entire staked balance.
    // ========================================================================

    /// Begin unbonding an archive node's storage stake (full exit).
    ///
    /// Archive-node stake only — this is NOT validator unstaking. Submits a
    /// NodeRegistry `BeginUnstake` for the node's full staked balance (v1 is
    /// full-exit only), moving it to `Unbonding`. After the unbonding period
    /// elapses, run `archive-withdraw` to reclaim the stake. Requires the
    /// archive-unbonding upgrade to be active on the target chain.
    ArchiveBeginUnstake {
        /// Path to the archive operator's key file
        #[arg(short, long)]
        key: PathBuf,

        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

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

    /// Withdraw an archive node's unbonded storage stake after the unbonding
    /// period has elapsed.
    ///
    /// Archive-node stake only — this is NOT validator withdrawal. Submits a
    /// NodeRegistry `WithdrawUnbonded`, crediting the remaining (post-slash)
    /// stake back to the operator's balance and marking the node `Withdrawn`.
    ArchiveWithdraw {
        /// Path to the archive operator's key file
        #[arg(short, long)]
        key: PathBuf,

        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

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

    /// Show an archive node's pending stake-unbonding record (issue #20).
    ///
    /// Archive-node stake only. Displays the unbonding amount, the withdrawable
    /// remaining amount (reduced by any slashes during unbonding), and the
    /// unlock height at/after which `archive-withdraw` is permitted.
    ArchiveUnbonding {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Archive operator address to query
        #[arg(long)]
        address: String,
    },

    // ========================================================================
    // NFT (SUM-721) Commands
    // ========================================================================

    /// Get NFT collection info
    NftCollection {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Collection ID (hex, with or without 0x prefix)
        #[arg(long)]
        id: String,
    },

    /// Get NFT token info
    NftToken {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Collection ID (hex)
        #[arg(long)]
        collection: String,

        /// Token ID
        #[arg(long)]
        token_id: u64,
    },

    /// List all NFTs owned by an address
    NftList {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Owner address
        #[arg(long)]
        owner: String,
    },

    /// Get NFT balance (count of tokens) for an address
    NftBalance {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Owner address
        #[arg(long)]
        owner: String,
    },

    /// Get owner of a specific NFT token
    NftOwner {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Collection ID (hex)
        #[arg(long)]
        collection: String,

        /// Token ID
        #[arg(long)]
        token_id: u64,
    },

    // ========================================================================
    // Smart Contract (SUMC) Commands
    // ========================================================================

    /// Get smart contract info by address
    Contract {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        address: String,
    },

    /// Check if an address is a smart contract
    IsContract {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to check
        #[arg(long)]
        address: String,
    },

    /// Call a contract method (read-only view call)
    ContractCall {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        contract: String,

        /// Method name to call
        #[arg(long)]
        method: String,

        /// Arguments (hex encoded, with or without 0x prefix)
        #[arg(long, default_value = "")]
        args: String,

        /// Optional caller address (for access control checks)
        #[arg(long)]
        from: Option<String>,
    },

    /// Estimate gas for a contract call
    ContractEstimateGas {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        contract: String,

        /// Method name to call
        #[arg(long)]
        method: String,

        /// Arguments (hex encoded)
        #[arg(long, default_value = "")]
        args: String,

        /// Optional caller address
        #[arg(long)]
        from: Option<String>,
    },

    /// Get contract code hash
    ContractCodeHash {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        address: String,
    },

    /// Get contract storage at a specific key
    ContractStorage {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        address: String,

        /// Storage key (hex encoded)
        #[arg(long)]
        key: String,
    },

    /// Get contract balance
    ContractBalance {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Contract address
        #[arg(long)]
        address: String,
    },

    // ========================================================================
    // Staking Commands
    // ========================================================================

    /// Get staking validators list
    StakingValidators {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Show only active validators
        #[arg(long)]
        active_only: bool,
    },

    /// Get staking validator info by public key or address
    StakingValidator {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Validator public key (hex) or address (base58)
        #[arg(long)]
        validator: String,
    },

    /// Get staking summary
    StakingSummary {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get staking parameters
    StakingParams {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get total staked amount
    StakingTotalStake {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    // ========================================================================
    // Delegation Commands
    // ========================================================================

    /// Get all delegations for a delegator address
    Delegations {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Delegator address (base58)
        #[arg(long)]
        delegator: String,
    },

    /// Get specific delegation to a validator
    Delegation {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Delegator address (base58)
        #[arg(long)]
        delegator: String,

        /// Validator public key (hex)
        #[arg(long)]
        validator: String,
    },

    /// Get delegator summary (total delegated, rewards, unbonding)
    DelegatorSummary {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Delegator address (base58)
        #[arg(long)]
        delegator: String,
    },

    /// Get unbonding delegations for a delegator
    Unbondings {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Delegator address (base58)
        #[arg(long)]
        delegator: String,
    },

    /// Get all delegations to a validator
    ValidatorDelegations {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Validator public key (hex)
        #[arg(long)]
        validator: String,
    },

    /// Get validator delegation summary (total delegated, delegator count)
    ValidatorDelegationSummary {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Validator public key (hex)
        #[arg(long)]
        validator: String,
    },

    // ========================================================================
    // SRC-201 Messaging Commands
    // ========================================================================

    /// Get messaging configuration
    MsgConfig {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },

    /// Get sender's messaging quota
    MsgQuota {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to check quota for
        #[arg(long)]
        address: String,
    },

    /// Get inbox filter for an address
    MsgInbox {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to check filter for
        #[arg(long)]
        address: String,
    },

    /// Get messages for a recipient (by hash)
    MsgList {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Recipient hash (hex) or address (calculates hash)
        #[arg(long)]
        recipient: String,

        /// Maximum number of messages to fetch
        #[arg(long, default_value = "20")]
        limit: u32,
    },

    /// Get trust stake for an address
    MsgStake {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to check stake for
        #[arg(long)]
        address: String,
    },

    /// Get spam score for an address
    MsgSpamScore {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Address to check spam score for
        #[arg(long)]
        address: String,
    },

    /// Check if an address is a contact
    MsgIsContact {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Owner address
        #[arg(long)]
        owner: String,

        /// Contact address to check
        #[arg(long)]
        contact: String,
    },

    /// Check if an address is blocked
    MsgIsBlocked {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Owner address
        #[arg(long)]
        owner: String,

        /// Sender address to check if blocked
        #[arg(long)]
        sender: String,
    },

    /// Get pending payment info for a message
    MsgPendingPayment {
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,

        /// Message ID (transaction hash, hex)
        #[arg(long)]
        message_id: String,
    },
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

        Commands::ArchiveBeginUnstake {
            key,
            rpc,
            fee,
            chain_id,
            yes,
        } => {
            let keystore = load_keystore(&key)?;
            let addr_b58 = keystore.address().to_base58();

            let fee_units = parse_koppa(&fee)
                .context("Invalid fee format. Use e.g., '0.001' for 0.001 Koppa")?;

            // v1 is full-exit only: the on-chain check requires the amount to
            // equal the node's full staked balance, so read it from the registry
            // rather than asking the operator to restate it.
            let record = tx::storage_get_node_record(&rpc, &addr_b58)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} is not a registered node — nothing to unstake",
                        addr_b58
                    )
                })?;
            let role = record.get("role").and_then(|v| v.as_str()).unwrap_or("");
            let status = record.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let staked_balance = record
                .get("staked_balance")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if role != "ArchiveNode" {
                anyhow::bail!(
                    "{} is a {} node, not an ArchiveNode — this command unbonds archive-node stake only",
                    addr_b58, role
                );
            }
            if status != "Active" {
                anyhow::bail!(
                    "archive node status is {} (must be Active to begin unbonding)",
                    status
                );
            }

            let nonce = tx::get_nonce(&rpc, &addr_b58).await?;

            print_header("Begin Archive-Node Unbonding (full exit)");
            println!();
            print_field("Archive Node", &addr_b58);
            print_field("Status", status);
            print_koppa_field("Unbonding Stake", staked_balance as u128);
            print_koppa_field("Fee", fee_units);
            print_field("Nonce", &nonce.to_string());
            println!();
            print_warning(
                "This unbonds the archive node's ENTIRE storage stake (v1 is full-exit only).",
            );
            print_info(
                "Run 'sumchain-wallet archive-withdraw' after the unbonding period to reclaim it.",
            );
            println!();

            if !yes && !confirm("Proceed with archive-node begin-unstake?") {
                print_warning("Begin-unstake cancelled.");
                return Ok(());
            }

            println!();
            print_info("Signing transaction...");
            let signed_tx = tx::sign_node_registry_tx(
                &keystore,
                sumchain_primitives::NodeRegistryOperation::BeginUnstake {
                    amount: staked_balance,
                },
                fee_units,
                nonce,
                chain_id,
            )?;

            print_info("Broadcasting transaction...");
            let tx_hash = tx::send_raw_transaction(&rpc, &signed_tx.to_hex()).await?;

            println!();
            print_success("Archive-node begin-unstake submitted!");
            print_field("Transaction Hash", &tx_hash);
            println!();
            print_info("Use 'sumchain-wallet receipt --hash <hash>' to check status.");
            print_info("Use 'sumchain-wallet archive-unbonding --address <addr>' to track the unlock height.");
        }

        Commands::ArchiveWithdraw {
            key,
            rpc,
            fee,
            chain_id,
            yes,
        } => {
            let keystore = load_keystore(&key)?;
            let addr_b58 = keystore.address().to_base58();

            let fee_units = parse_koppa(&fee)
                .context("Invalid fee format. Use e.g., '0.001' for 0.001 Koppa")?;

            let nonce = tx::get_nonce(&rpc, &addr_b58).await?;

            // Surface the current unbonding record (if any) so the operator sees
            // what will be withdrawn and whether the period has elapsed.
            let unbonding = tx::storage_get_archive_unbonding(&rpc, &addr_b58).await?;

            print_header("Withdraw Unbonded Archive-Node Stake");
            println!();
            print_field("Archive Node", &addr_b58);
            match &unbonding {
                Some(u) => {
                    print_koppa_field("Withdrawable", u.remaining_amount as u128);
                    print_field("Unlock Height", &u.unlock_height.to_string());
                }
                None => {
                    print_warning(
                        "No unbonding record found for this address — the withdraw will be rejected unless one exists on-chain.",
                    );
                }
            }
            print_koppa_field("Fee", fee_units);
            print_field("Nonce", &nonce.to_string());
            println!();

            if !yes && !confirm("Proceed with archive-node withdraw?") {
                print_warning("Withdraw cancelled.");
                return Ok(());
            }

            println!();
            print_info("Signing transaction...");
            let signed_tx = tx::sign_node_registry_tx(
                &keystore,
                sumchain_primitives::NodeRegistryOperation::WithdrawUnbonded,
                fee_units,
                nonce,
                chain_id,
            )?;

            print_info("Broadcasting transaction...");
            let tx_hash = tx::send_raw_transaction(&rpc, &signed_tx.to_hex()).await?;

            println!();
            print_success("Archive-node withdraw submitted!");
            print_field("Transaction Hash", &tx_hash);
            println!();
            print_info("Use 'sumchain-wallet receipt --hash <hash>' to check status.");
        }

        Commands::ArchiveUnbonding { rpc, address } => {
            let unbonding = tx::storage_get_archive_unbonding(&rpc, &address).await?;

            print_header("Archive-Node Unbonding Status");
            println!();
            print_field("Archive Node", &address);
            match unbonding {
                Some(u) => {
                    print_koppa_field("Unbonding Amount", u.amount as u128);
                    print_koppa_field("Withdrawable Remaining", u.remaining_amount as u128);
                    print_field("Started Height", &u.started_height.to_string());
                    print_field("Unlock Height", &u.unlock_height.to_string());
                    println!();
                    print_info(
                        "Run 'sumchain-wallet archive-withdraw' once the chain height reaches the unlock height.",
                    );
                }
                None => {
                    println!();
                    print_info("No unbonding in progress for this address.");
                }
            }
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

        // ====================================================================
        // NFT (SUM-721) Commands
        // ====================================================================

        Commands::NftCollection { rpc, id } => {
            let collection = tx::nft_get_collection(&rpc, &id).await?;

            match collection {
                Some(c) => {
                    print_header(&format!("NFT Collection: {}", c.name));
                    println!();
                    print_field("Collection ID", &c.collection_id);
                    print_field("Name", &c.name);
                    print_field("Symbol", &c.symbol);
                    print_field("Description", &c.description);
                    print_field("Owner", &c.owner);
                    print_separator();
                    print_field("Max Supply", &if c.max_supply == 0 {
                        "Unlimited".to_string()
                    } else {
                        c.max_supply.to_string()
                    });
                    print_field("Total Supply", &c.total_supply.to_string());
                    print_separator();
                    print_status_indicator("Transferable", c.transferable);
                    print_status_indicator("Burnable", c.burnable);
                    print_status_indicator("Metadata Updatable", c.metadata_updatable);
                    print_separator();
                    if c.royalty_bps > 0 {
                        print_field("Royalty", &format!("{}% ({})", c.royalty_bps as f64 / 100.0, c.royalty_recipient));
                    } else {
                        print_field("Royalty", "None");
                    }
                    if let Some(uri) = &c.base_uri {
                        print_field("Base URI", uri);
                    }
                    print_field("Created", &format_timestamp(c.created_at));
                }
                None => print_warning("Collection not found"),
            }
        }

        Commands::NftToken { rpc, collection, token_id } => {
            let token = tx::nft_get_token(&rpc, &collection, token_id).await?;

            match token {
                Some(t) => {
                    print_header(&format!("NFT Token #{}", t.token_id));
                    println!();
                    print_field("Collection", &t.collection_id);
                    print_field("Token ID", &t.token_id.to_string());
                    print_separator();
                    print_field("Owner", &t.owner);
                    print_field("Creator", &t.creator);
                    if let Some(approved) = &t.approved {
                        print_field("Approved", approved);
                    }
                    print_separator();
                    print_status_indicator("Document", t.is_document);
                    print_status_indicator("Locked", t.locked);
                    print_field("Transfer Count", &t.transfer_count.to_string());
                    print_separator();
                    print_field("URI Type", &t.uri_type);
                    if let Some(uri) = &t.uri_value {
                        print_field("URI Value", uri);
                    }
                    if !t.metadata.is_empty() && t.metadata.len() < 200 {
                        print_field("Metadata", &t.metadata);
                    } else if !t.metadata.is_empty() {
                        print_field("Metadata", &format!("[{} bytes]", t.metadata.len()));
                    }
                    print_field("Minted", &format_timestamp(t.minted_at));
                }
                None => print_warning("Token not found"),
            }
        }

        Commands::NftList { rpc, owner } => {
            let result = tx::nft_get_tokens_by_owner(&rpc, &owner).await?;

            if result.tokens.is_empty() {
                print_info(&format!("No NFTs found for {}", owner));
            } else {
                print_header(&format!("NFTs owned by {}", format_address_short(&owner)));
                println!();
                print_field("Owner", &result.owner);
                print_field("Total NFTs", &result.count.to_string());
                println!();

                for (i, token) in result.tokens.iter().enumerate() {
                    println!(
                        "  {} {}:{}",
                        format!("[{}]", i + 1).dimmed(),
                        format_address_short(&token.collection_id).cyan(),
                        token.token_id.to_string().yellow()
                    );
                }
            }
        }

        Commands::NftBalance { rpc, owner } => {
            let count = tx::nft_balance_of(&rpc, &owner).await?;
            print_field("Address", &owner);
            print_field("NFT Balance", &count.to_string().cyan().to_string());
        }

        Commands::NftOwner { rpc, collection, token_id } => {
            let owner = tx::nft_owner_of(&rpc, &collection, token_id).await?;

            match owner {
                Some(o) => {
                    print_field("Collection", &collection);
                    print_field("Token ID", &token_id.to_string());
                    print_field("Owner", &o.cyan().to_string());
                }
                None => print_warning("Token not found"),
            }
        }

        // ====================================================================
        // Smart Contract (SUMC) Commands
        // ====================================================================

        Commands::Contract { rpc, address } => {
            let info = tx::contract_get_info(&rpc, &address).await?;

            match info {
                Some(c) => {
                    print_header("Smart Contract");
                    println!();
                    print_field("Address", &c.address);
                    print_field("Code Hash", &c.code_hash);
                    print_field("Owner", &c.owner);
                    print_separator();
                    let balance: u128 = c.balance.parse().unwrap_or(0);
                    print_koppa_field("Balance", balance);
                    print_status_indicator("Upgradeable", c.upgradeable);
                    print_separator();
                    print_field("Deployed At", &format_timestamp(c.deployed_at));
                    print_field("Deployed Block", &c.deployed_at_block.to_string());
                }
                None => print_warning("Contract not found at this address"),
            }
        }

        Commands::IsContract { rpc, address } => {
            let is_contract = tx::contract_is_contract(&rpc, &address).await?;

            print_field("Address", &address);
            if is_contract {
                println!("  {}: {}", "Is Contract".dimmed(), "Yes".green().bold());
            } else {
                println!("  {}: {}", "Is Contract".dimmed(), "No".yellow());
            }
        }

        Commands::ContractCall { rpc, contract, method, args, from } => {
            let from_ref = from.as_deref();
            let result = tx::contract_call(&rpc, &contract, &method, &args, from_ref).await?;

            print_header("Contract Call Result");
            println!();
            print_field("Contract", &contract);
            print_field("Method", &method);
            if !args.is_empty() {
                print_field("Args", &args);
            }
            print_separator();

            if result.success {
                println!("  {}: {}", "Status".dimmed(), "Success".green().bold());
                if !result.return_data.is_empty() {
                    print_field("Return Data", &result.return_data);
                }
            } else {
                println!("  {}: {}", "Status".dimmed(), "Failed".red().bold());
                if let Some(err) = &result.error {
                    print_field("Error", err);
                }
            }

            print_field("Gas Used", &result.gas_used.to_string());

            if !result.events.is_empty() {
                println!();
                println!("  {}:", "Events".dimmed());
                for (i, event) in result.events.iter().enumerate() {
                    print_list_item(i, &format!("Contract: {}", event.contract));
                    for topic in &event.topics {
                        println!("      Topic: {}", topic);
                    }
                    if !event.data.is_empty() {
                        println!("      Data: {}", event.data);
                    }
                }
            }
        }

        Commands::ContractEstimateGas { rpc, contract, method, args, from } => {
            let from_ref = from.as_deref();
            let result = tx::contract_estimate_gas(&rpc, &contract, &method, &args, from_ref).await?;

            print_header("Gas Estimate");
            println!();
            print_field("Contract", &contract);
            print_field("Method", &method);
            print_separator();
            print_field("Estimated Gas", &result.gas_estimate.to_string());
            print_field("Gas Price", &result.gas_price);
            let total: u128 = result.total_cost.parse().unwrap_or(0);
            print_koppa_field("Total Cost", total);
        }

        Commands::ContractCodeHash { rpc, address } => {
            let hash = tx::contract_get_code_hash(&rpc, &address).await?;

            match hash {
                Some(h) => {
                    print_field("Address", &address);
                    print_field("Code Hash", &h.cyan().to_string());
                }
                None => {
                    print_field("Address", &address);
                    print_warning("No contract found at this address");
                }
            }
        }

        Commands::ContractStorage { rpc, address, key } => {
            let value = tx::contract_get_storage(&rpc, &address, &key).await?;

            print_field("Contract", &address);
            print_field("Key", &key);
            match value {
                Some(v) => {
                    print_field("Value", &v.cyan().to_string());
                }
                None => {
                    print_info("Storage slot is empty or not set");
                }
            }
        }

        Commands::ContractBalance { rpc, address } => {
            let balance_str = tx::contract_get_balance(&rpc, &address).await?;
            let balance: u128 = balance_str.parse().unwrap_or(0);

            print_field("Contract", &address);
            print_koppa_field("Balance", balance);
        }

        // ====================================================================
        // Staking Commands
        // ====================================================================

        Commands::StakingValidators { rpc, active_only } => {
            let validators = if active_only {
                tx::staking_get_active_validators(&rpc).await?
            } else {
                tx::staking_get_validators(&rpc).await?
            };

            if validators.is_empty() {
                print_info("No validators found");
            } else {
                let title = if active_only {
                    format!("Active Staking Validators ({})", validators.len())
                } else {
                    format!("All Staking Validators ({})", validators.len())
                };
                print_header(&title);
                println!();

                for (i, v) in validators.iter().enumerate() {
                    let stake: u128 = v.stake.parse().unwrap_or(0);
                    let status_color = match v.status.as_str() {
                        "Active" => v.status.green().to_string(),
                        "Jailed" => v.status.red().to_string(),
                        "Inactive" => v.status.yellow().to_string(),
                        "Unbonding" => v.status.yellow().to_string(),
                        _ => v.status.clone(),
                    };

                    println!(
                        "  {} {} [{}]",
                        format!("[{}]", i + 1).dimmed(),
                        format_address_short(&v.address).cyan(),
                        status_color
                    );
                    println!(
                        "      {}: {} | {}: {}%",
                        "Stake".dimmed(),
                        format_koppa(stake),
                        "Commission".dimmed(),
                        v.commission_bps as f64 / 100.0
                    );
                }
            }
        }

        Commands::StakingValidator { rpc, validator } => {
            // Try to get by address first, then by pubkey
            let v = if validator.starts_with("0x") {
                tx::staking_get_validator(&rpc, &validator).await?
            } else {
                tx::staking_get_validator_by_address(&rpc, &validator).await?
            };

            match v {
                Some(v) => {
                    let stake: u128 = v.stake.parse().unwrap_or(0);
                    let rewards: u128 = v.pending_rewards.parse().unwrap_or(0);

                    let status_color = match v.status.as_str() {
                        "Active" => v.status.green().to_string(),
                        "Jailed" => v.status.red().to_string(),
                        "Inactive" => v.status.yellow().to_string(),
                        "Unbonding" => v.status.yellow().to_string(),
                        _ => v.status.clone(),
                    };

                    print_header("Staking Validator");
                    println!();
                    print_field("Address", &v.address);
                    print_field("Public Key", &v.pubkey);
                    print_separator();
                    println!("  {}: {}", "Status".dimmed(), status_color);
                    print_koppa_field("Stake", stake);
                    print_field("Commission", &format!("{}%", v.commission_bps as f64 / 100.0));
                    print_separator();
                    print_field("Joined At Block", &v.joined_at.to_string());
                    if v.jailed_until > 0 {
                        print_field("Jailed Until Block", &v.jailed_until.to_string());
                    }
                    print_field("Slash Count", &v.slash_count.to_string());
                    print_koppa_field("Pending Rewards", rewards);
                    if let Some(metadata) = &v.metadata {
                        if !metadata.is_empty() {
                            print_field("Metadata", metadata);
                        }
                    }
                }
                None => print_warning("Validator not found"),
            }
        }

        Commands::StakingSummary { rpc } => {
            let summary = tx::staking_get_summary(&rpc).await?;
            let total_stake: u128 = summary.total_stake.parse().unwrap_or(0);
            let min_stake: u128 = summary.min_validator_stake.parse().unwrap_or(0);

            print_header("Staking Summary");
            println!();
            print_field("Total Validators", &summary.total_validators.to_string());
            print_field("Active Validators", &summary.active_validators.to_string().green().to_string());
            print_koppa_field("Total Staked", total_stake);
            print_separator();
            print_koppa_field("Min Validator Stake", min_stake);
            print_field("Max Validators", &summary.max_validators.to_string());
            print_field("Unbonding Period", &format!("{} blocks (~{:.1} days)",
                summary.unbonding_period,
                summary.unbonding_period as f64 * 6.0 / 86400.0 // Assuming 6s blocks
            ));
        }

        Commands::StakingParams { rpc } => {
            let params = tx::staking_get_params(&rpc).await?;
            let min_stake: u128 = params.min_validator_stake.parse().unwrap_or(0);

            print_header("Staking Parameters");
            println!();
            print_koppa_field("Min Validator Stake", min_stake);
            print_field("Max Validators", &params.max_validators.to_string());
            print_field("Unbonding Period", &format!("{} blocks", params.unbonding_period));
            print_field("Max Commission", &format!("{}%", params.max_commission_bps as f64 / 100.0));
            print_separator();
            println!("  {}:", "Slashing Penalties".dimmed());
            print_field("  Double Sign Slash", &format!("{}%", params.double_sign_slash_bps as f64 / 100.0));
            print_field("  Downtime Slash", &format!("{}%", params.downtime_slash_bps as f64 / 100.0));
            print_separator();
            println!("  {}:", "Jail Durations".dimmed());
            print_field("  Double Sign Jail", &format!("{} blocks", params.double_sign_jail_duration));
            print_field("  Downtime Jail", &format!("{} blocks", params.downtime_jail_duration));
            print_field("  Downtime Threshold", &format!("{} missed blocks", params.downtime_threshold));
        }

        Commands::StakingTotalStake { rpc } => {
            let total_stake_str = tx::staking_get_total_stake(&rpc).await?;
            let total_stake: u128 = total_stake_str.parse().unwrap_or(0);

            print_koppa_field("Total Staked", total_stake);
        }

        // ====================================================================
        // Delegation Commands
        // ====================================================================

        Commands::Delegations { rpc, delegator } => {
            let delegations = tx::delegation_get_delegations_by_delegator(&rpc, &delegator).await?;

            if delegations.is_empty() {
                print_info(&format!("No delegations found for {}", delegator));
            } else {
                print_header(&format!("Delegations for {}", format_address_short(&delegator)));
                println!();

                for (i, d) in delegations.iter().enumerate() {
                    let amount: u128 = d.amount.parse().unwrap_or(0);
                    let rewards: u128 = d.pending_rewards.parse().unwrap_or(0);

                    println!(
                        "  {} → {}",
                        format!("[{}]", i + 1).dimmed(),
                        format_address_short(&d.validator_address).cyan()
                    );
                    println!(
                        "      {}: {} | {}: {}",
                        "Delegated".dimmed(),
                        format_koppa(amount),
                        "Rewards".dimmed(),
                        format_koppa(rewards).green()
                    );
                }
            }
        }

        Commands::Delegation { rpc, delegator, validator } => {
            let delegation = tx::delegation_get_delegation(&rpc, &delegator, &validator).await?;

            match delegation {
                Some(d) => {
                    let amount: u128 = d.amount.parse().unwrap_or(0);
                    let rewards: u128 = d.pending_rewards.parse().unwrap_or(0);

                    print_header("Delegation");
                    println!();
                    print_field("Delegator", &d.delegator);
                    print_field("Validator Address", &d.validator_address);
                    print_field("Validator Pubkey", &d.validator_pubkey);
                    print_separator();
                    print_koppa_field("Delegated Amount", amount);
                    print_koppa_field("Pending Rewards", rewards);
                    print_field("Delegated At Block", &d.delegated_at.to_string());
                }
                None => print_warning("Delegation not found"),
            }
        }

        Commands::DelegatorSummary { rpc, delegator } => {
            let summary = tx::delegation_get_delegator_summary(&rpc, &delegator).await?;
            let total_delegated: u128 = summary.total_delegated.parse().unwrap_or(0);
            let total_rewards: u128 = summary.total_pending_rewards.parse().unwrap_or(0);
            let total_unbonding: u128 = summary.total_unbonding.parse().unwrap_or(0);

            print_header("Delegator Summary");
            println!();
            print_field("Delegator", &summary.delegator);
            print_separator();
            print_koppa_field("Total Delegated", total_delegated);
            print_koppa_field("Pending Rewards", total_rewards);
            print_koppa_field("Total Unbonding", total_unbonding);
            print_separator();
            print_field("Active Delegations", &summary.delegation_count.to_string());
            print_field("Pending Unbondings", &summary.unbonding_count.to_string());
        }

        Commands::Unbondings { rpc, delegator } => {
            let unbondings = tx::delegation_get_unbonding_delegations(&rpc, &delegator).await?;

            if unbondings.is_empty() {
                print_info(&format!("No unbonding delegations for {}", delegator));
            } else {
                print_header(&format!("Unbonding Delegations for {}", format_address_short(&delegator)));
                println!();

                for (i, u) in unbondings.iter().enumerate() {
                    let amount: u128 = u.amount.parse().unwrap_or(0);
                    let status = if u.is_complete {
                        "Ready to withdraw".green().to_string()
                    } else {
                        format!("Completes at block {}", u.completion_height).yellow().to_string()
                    };

                    println!(
                        "  {} → {}",
                        format!("[{}]", i + 1).dimmed(),
                        format_address_short(&u.validator_address).cyan()
                    );
                    println!(
                        "      {}: {} | {}",
                        "Amount".dimmed(),
                        format_koppa(amount),
                        status
                    );
                }
            }
        }

        Commands::ValidatorDelegations { rpc, validator } => {
            let delegations = tx::delegation_get_delegations_by_validator(&rpc, &validator).await?;

            if delegations.is_empty() {
                print_info("No delegations to this validator");
            } else {
                print_header(&format!("Delegations to Validator ({})", delegations.len()));
                println!();

                let mut total: u128 = 0;
                for (i, d) in delegations.iter().enumerate() {
                    let amount: u128 = d.amount.parse().unwrap_or(0);
                    total += amount;

                    println!(
                        "  {} {} delegated {}",
                        format!("[{}]", i + 1).dimmed(),
                        format_address_short(&d.delegator).cyan(),
                        format_koppa(amount)
                    );
                }

                println!();
                print_koppa_field("Total Delegated", total);
            }
        }

        Commands::ValidatorDelegationSummary { rpc, validator } => {
            let summary = tx::delegation_get_validator_delegation_summary(&rpc, &validator).await?;
            let total_delegated: u128 = summary.total_delegated.parse().unwrap_or(0);

            print_header("Validator Delegation Summary");
            println!();
            print_field("Validator Pubkey", &summary.validator_pubkey);
            print_field("Validator Address", &summary.validator_address);
            print_separator();
            print_koppa_field("Total Delegated", total_delegated);
            print_field("Delegator Count", &summary.delegator_count.to_string());
        }

        // ====================================================================
        // SRC-201 Messaging Commands
        // ====================================================================

        Commands::MsgConfig { rpc } => {
            let config = tx::messaging_get_config(&rpc).await?;

            print_header("Messaging Configuration");
            println!();
            print_field("Daily Quota", &config.daily_quota.to_string());
            print_field("Max Message Size", &format!("{} bytes", config.max_message_size));
            let min_stake: u128 = config.min_trust_stake.parse().unwrap_or(0);
            print_koppa_field("Min Trust Stake", min_stake);
            print_field(
                "Sponsorship",
                if config.sponsorship_enabled { "Enabled" } else { "Disabled" },
            );
        }

        Commands::MsgQuota { rpc, address } => {
            let quota = tx::messaging_get_quota(&rpc, &address).await?;

            print_header("Messaging Quota");
            println!();
            print_field("Address", &quota.address);
            print_separator();
            print_field("Daily Quota", &quota.daily_quota.to_string());
            print_field("Used Today", &quota.used_today.to_string());
            print_field("Remaining", &quota.remaining.to_string());
            print_separator();
            print_field(
                "Trust Stake Status",
                if quota.has_trust_stake {
                    "Staked (5x quota)"
                } else {
                    "Not staked"
                },
            );
            if let Some(stake) = quota.trust_stake {
                let stake_amount: u128 = stake.parse().unwrap_or(0);
                print_koppa_field("Stake Amount", stake_amount);
            }
        }

        Commands::MsgInbox { rpc, address } => {
            let filter = tx::messaging_get_inbox_filter(&rpc, &address).await?;

            print_header("Inbox Filter");
            println!();
            print_field("Address", &address);
            match filter {
                Some(f) => {
                    print_field("Mode", &f.mode);
                }
                None => {
                    print_field("Mode", "accept_all (default)");
                }
            }
        }

        Commands::MsgList { rpc, recipient, limit } => {
            let messages = tx::messaging_get_messages(&rpc, &recipient, limit).await?;

            if messages.is_empty() {
                print_info("No messages found for this recipient");
            } else {
                print_header(&format!("Messages ({} found)", messages.len()));
                println!();

                for (i, msg) in messages.iter().enumerate() {
                    println!(
                        "  {} Block {} | {}",
                        format!("[{}]", i + 1).dimmed(),
                        msg.block_height,
                        format_address_short(&msg.sender).cyan()
                    );
                    println!(
                        "      {}: {} | Payment: {}",
                        "TX".dimmed(),
                        format_address_short(&msg.tx_hash),
                        if msg.has_payment { "Yes".green().to_string() } else { "No".dimmed().to_string() }
                    );
                }
            }
        }

        Commands::MsgStake { rpc, address } => {
            let stake = tx::messaging_get_trust_stake(&rpc, &address).await?;
            let stake_amount: u128 = stake.parse().unwrap_or(0);

            print_header("Trust Stake");
            println!();
            print_field("Address", &address);
            print_koppa_field("Stake Amount", stake_amount);
        }

        Commands::MsgSpamScore { rpc, address } => {
            let info = tx::messaging_get_spam_score(&rpc, &address).await?;

            print_header("Spam Score");
            println!();
            print_field("Address", &info.sender);
            print_field("Score", &info.spam_score.to_string());
            print_field("Report Count", &info.report_count.to_string());
            print_field(
                "Status",
                if info.is_restricted {
                    "Restricted".red().to_string()
                } else {
                    "Good".green().to_string()
                }.as_str(),
            );
        }

        Commands::MsgIsContact { rpc, owner, contact } => {
            let is_contact = tx::messaging_is_contact(&rpc, &owner, &contact).await?;

            if is_contact {
                print_success(&format!("{} is a contact of {}", contact, owner));
            } else {
                print_info(&format!("{} is NOT a contact of {}", contact, owner));
            }
        }

        Commands::MsgIsBlocked { rpc, owner, sender } => {
            let is_blocked = tx::messaging_is_blocked(&rpc, &owner, &sender).await?;

            if is_blocked {
                print_warning(&format!("{} is BLOCKED by {}", sender, owner));
            } else {
                print_info(&format!("{} is not blocked by {}", sender, owner));
            }
        }

        Commands::MsgPendingPayment { rpc, message_id } => {
            let payment = tx::messaging_get_pending_payment(&rpc, &message_id).await?;

            match payment {
                Some(p) => {
                    let amount: u128 = p.amount.parse().unwrap_or(0);

                    print_header("Pending Payment");
                    println!();
                    print_field("Message ID", &p.message_id);
                    print_field("Sender", &p.sender);
                    print_field("Recipient Hash", &p.recipient_hash);
                    print_separator();
                    print_koppa_field("Amount", amount);
                    print_field("Expiry", &format!("Timestamp {}", p.expiry));
                }
                None => print_info("No pending payment found for this message"),
            }
        }
    }

    Ok(())
}
