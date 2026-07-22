//! Devnet provisioner for the SUM Chain local/smoke testnets.
//!
//! Modes (`--mode`):
//!   * `local`     — DEFAULT, legacy behaviour, UNCHANGED. Generates three
//!                   validators + a test account and writes the tracked-name
//!                   `genesis/local_genesis.json` + `keys/` relative to the
//!                   working directory. This is what the `deploy/health-e2e-
//!                   harness.sh` (#120) harness invokes with no arguments, so it
//!                   is preserved verbatim for backward compatibility.
//!   * `smoke`     — issue #119. Generates EXACTLY ONE validator plus all funded
//!                   roles (three archives, one verifier, one client, one funder)
//!                   and a runnable genesis, ALL under an explicit `--output-dir`
//!                   (required). Never writes a tracked genesis file. Chain id
//!                   1337; compute-pool + beacon gates dormant (`None`).
//!   * `ecosystem` — issue #119, DEFERRED. Hard-fails with an explicit blocker
//!                   message and generates nothing.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_scripts::{provision_smoke, ECOSYSTEM_DEFERRED_MSG};

/// Provisioning mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Legacy three-validator local testnet (writes genesis/local_genesis.json).
    Local,
    /// Issue #119 single-validator smoke devnet (writes into --output-dir).
    Smoke,
    /// Issue #119 five-validator pool — DEFERRED, hard-fails.
    Ecosystem,
}

#[derive(Parser, Debug)]
#[command(
    name = "setup-local-testnet",
    about = "Provision a SUM Chain local/smoke devnet (issue #119)"
)]
struct Cli {
    /// Provisioning mode.
    #[arg(long, value_enum, default_value = "local")]
    mode: Mode,

    /// Number of validators to generate. Only meaningful for `smoke` (must be 1,
    /// its default). REJECTED for `local` (always exactly 3) and `ecosystem`
    /// (deferred) rather than silently ignored.
    #[arg(long)]
    validator_count: Option<usize>,

    /// Output directory for ALL generated keys + the runnable genesis.
    /// REQUIRED for `smoke` (its keys/genesis are written only here, never a
    /// tracked path). REJECTED for `local` (which uses ./genesis + ./keys).
    #[arg(long)]
    output_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Ecosystem => {
            // Hard-fail BEFORE creating anything, with the blockers named.
            bail!("{ECOSYSTEM_DEFERRED_MSG}");
        }
        Mode::Smoke => run_smoke(cli.output_dir, cli.validator_count.unwrap_or(1)),
        Mode::Local => {
            // Fail closed: `local` is the fixed legacy 3-validator mode. Reject
            // arguments it does not support instead of silently ignoring them.
            if cli.output_dir.is_some() {
                bail!(
                    "--output-dir is not supported with --mode local (it always writes \
                     ./genesis/local_genesis.json + ./keys). Use --mode smoke --output-dir \
                     <dir> for an out-of-repo devnet."
                );
            }
            if cli.validator_count.is_some() {
                bail!(
                    "--validator-count is not supported with --mode local (it always \
                     generates exactly 3 validators). Use --mode smoke (1 validator) or \
                     --mode ecosystem (deferred five-validator pool)."
                );
            }
            run_local()
        }
    }
}

/// Issue #119 smoke provisioning. `--output-dir` is required so the hardcoded
/// tracked path can never be taken.
fn run_smoke(output_dir: Option<PathBuf>, validator_count: usize) -> Result<()> {
    let output_dir = output_dir.ok_or_else(|| {
        anyhow::anyhow!(
            "smoke mode requires --output-dir <path>: all keys and the runnable \
             genesis are written there (point it at a mktemp dir OUTSIDE the repo). \
             Smoke mode never writes a tracked genesis file."
        )
    })?;

    println!("=== SUM Chain Smoke Devnet Setup (issue #119) ===\n");
    println!("Output directory: {}", output_dir.display());

    let artifacts = provision_smoke(&output_dir, validator_count)?;

    println!(
        "\nGenerated 1 validator + {} funded roles:",
        artifacts.roles.len()
    );
    println!("  validator: {}", artifacts.validator_pubkey_b58);
    println!("    address: {}", artifacts.validator_address_b58);
    for role in &artifacts.roles {
        println!("  {:<9} address: {}", role.name, role.address_b58);
    }
    println!(
        "\n  chain id:          {}",
        sumchain_scripts::DEVNET_CHAIN_ID
    );
    println!("  compute-pool gate: None (dormant)");
    println!("  beacon gate:       None (dormant)");
    println!("\n  Runnable genesis: {}", artifacts.genesis_path.display());
    println!("  Manifest:         {}", artifacts.manifest_path.display());
    println!(
        "  Keys:             {}/keys/ (private material — do not commit)",
        output_dir.display()
    );
    println!("\nBoot the single validator with:");
    println!("  sumchain run \\");
    println!("    --genesis {} \\", artifacts.genesis_path.display());
    println!("    --data-dir {}/data \\", output_dir.display());
    println!(
        "    --validator-key {} \\",
        artifacts.validator_key_path.display()
    );
    println!("    --p2p-addr /ip4/127.0.0.1/tcp/30301 \\");
    println!("    --rpc-addr 127.0.0.1:8545");

    Ok(())
}

/// Legacy three-validator local testnet — UNCHANGED behaviour. Writes
/// `genesis/local_genesis.json` + `keys/` relative to the working directory.
/// Always generates exactly three validators (no `--validator-count` knob).
fn run_local() -> Result<()> {
    println!("=== SUM Chain Local Testnet Setup ===\n");

    // Create directories
    fs::create_dir_all("keys")?;
    fs::create_dir_all("genesis")?;

    // Generate validator keys
    println!("Generating validator keys...");
    let mut validators = Vec::new();
    let mut alloc = HashMap::new();

    for i in 1..=3 {
        let keypair = KeyPair::generate();
        let pubkey = keypair.public_key().to_base58();
        let address = keypair.address().to_base58();

        // Save private key
        let key_path = format!("keys/validator{}.json", i);
        let key_json = serde_json::to_string_pretty(keypair.private_key().as_bytes())?;
        fs::write(&key_path, &key_json)?;

        println!("  Validator {}: {}", i, pubkey);
        println!("    Address: {}", address);
        println!("    Key saved to: {}", key_path);

        validators.push(pubkey);
        alloc.insert(address, 1_000_000_000_000_000_000u128); // 1e18 SUM tokens
    }

    // Generate an extra account for testing
    println!("\nGenerating test account...");
    let test_keypair = KeyPair::generate();
    let _test_pubkey = test_keypair.public_key().to_base58();
    let test_address = test_keypair.address().to_base58();

    let key_json = serde_json::to_string_pretty(test_keypair.private_key().as_bytes())?;
    fs::write("keys/test_account.json", &key_json)?;

    println!("  Test account: {}", test_address);
    println!("    Key saved to: keys/test_account.json");

    alloc.insert(test_address, 1_000_000_000_000_000_000u128);

    // Create genesis
    println!("\nCreating genesis file...");
    let genesis = Genesis::new(
        1337, // Local testnet chain ID
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        validators,
        alloc,
        ChainParams {
            block_time_ms: 2000,
            max_block_bytes: 1_000_000,
            max_txs_per_block: 1000,
            min_fee: 1,
            finality_depth: 3,             // 3 block confirmations for finality
            storage_fee_per_byte: 100,     // 100 base units per byte
            max_metadata_bytes: 16384,     // 16 KB max metadata
            min_contract_gas: 21000,       // Minimum gas for contract transactions
            max_contract_gas: 10_000_000,  // Maximum gas limit per transaction
            staking: None,                 // Use default staking params
            messaging: None,               // Use default messaging params
            docclass: None,                // Use default docclass params
            max_access_list_bytes: 16_384, // SNIP V2: 16 KB byte cap
            activation_grace_blocks: 50,   // SNIP V2: ~100s at 2s blocks
            abandonment_fee_percent: 10,   // SNIP V2: 10% retained on abandonment
            max_chunk_count_per_file: 1_048_576, // SNIP V2 v3.2: 1 TB at CHUNK_SIZE = 1 MB
            max_chunk_indices_per_tx: 65_536, // SNIP V2 v3.2: AcceptAssignmentV2 tx cap
            assignment_replication_factor: 3, // SNIP V2 v3.2: baseline R=3
            v2_enabled_from_height: Some(0), // local testnet: V2 active from genesis
            omninode_enabled_from_height: None, // OmniNode subprotocol off by default; opt in per-genesis
            education_enabled_from_height: Some(0), // local/dev: SRC-817/818 Education active from genesis (local only; mainnet/testnet stay None)
            contracts_enabled_from_height: None, // smart contracts dormant; coordinated consensus-breaking activation only
            governance_enabled_from_height: None, // on-chain governance dormant; coordinated activation only
            governance: None,                     // no governance params configured
            archive_unbonding_enabled_from_height: None, // issue #20: archive withdrawal dormant
            archive_unbonding_period_blocks: 201_600, // ~7 days at 3s blocks
            archive_reassignment_enabled_from_height: None, // issue #62: chunk reassignment dormant
            por_assignment_targeting_enabled_from_height: None, // issue #97: legacy PoR targeting
            service_grants_enabled_from_height: None, // 800B correction: claiming dormant
            monetary_policy_enabled_from_height: None, // 800B correction: gov release/mint dormant
            validator_inactivity_window_blocks: 20_160, // dormant design param
            validator_inactivity_warn_bps: 1_000, // dormant
            validator_inactivity_inactive_bps: 3_300, // dormant
            validator_inactivity_removal_bps: 5_000, // dormant
            validator_reclaim_delay_blocks: 201_600, // dormant
            assignment_aware_por_scheduler_enabled_from_height: None, // issue #100: scheduler dormant
            max_assignment_aware_challenges_per_block: 16,            // issue #100
            max_files_sampled_per_interval: 8,                        // issue #100
            max_chunks_sampled_per_file: 4,                           // issue #100
            inference_settlement_enabled_from_height: None, // issue #61: settlement dormant
            inference_settlement_max_dispute_window_blocks: 201_600,
            inference_settlement_max_session_duration_blocks: 2_592_000,
            inference_settlement_dispute_threshold_bps: None,
            inference_settlement_consistency_enabled_from_height: None, // issue #77: dormant
            inference_verifier_bonding_enabled_from_height: None,       // issue #78: dormant
            inference_verifier_unbonding_period_blocks: 201_600,
            omninode_sponsored_attestation_enabled_from_height: None, // issue #79: dormant
            compute_pool_enabled_from_height: None, // issue #118: compute-pool gate dormant (fail-closed until ComputePoolParams exists)
            beacon_enabled_from_height: None, // issue #118: beacon gate dormant (fail-closed until BeaconParams exists)
            messaging_sponsored_registration_enabled_from_height: None, // issue #145: sponsored registration dormant (coordinated activation only)
        },
    );

    genesis.to_file("genesis/local_genesis.json")?;
    println!("  Genesis saved to: genesis/local_genesis.json");

    println!("\n=== Setup Complete ===");
    println!("\nTo start the testnet, run:");
    println!("  # Terminal 1 - Validator 1");
    println!("  cargo run --bin sumchain -- run \\");
    println!("    --genesis genesis/local_genesis.json \\");
    println!("    --data-dir data/validator1 \\");
    println!("    --validator-key keys/validator1.json \\");
    println!("    --p2p-addr /ip4/0.0.0.0/tcp/30301 \\");
    println!("    --rpc-addr 127.0.0.1:8545");
    println!();
    println!("  # Terminal 2 - Validator 2");
    println!("  cargo run --bin sumchain -- run \\");
    println!("    --genesis genesis/local_genesis.json \\");
    println!("    --data-dir data/validator2 \\");
    println!("    --validator-key keys/validator2.json \\");
    println!("    --p2p-addr /ip4/0.0.0.0/tcp/30302 \\");
    println!("    --rpc-addr 127.0.0.1:8546 \\");
    println!("    --bootnodes /ip4/127.0.0.1/tcp/30301");
    println!();
    println!("  # Terminal 3 - Validator 3");
    println!("  cargo run --bin sumchain -- run \\");
    println!("    --genesis genesis/local_genesis.json \\");
    println!("    --data-dir data/validator3 \\");
    println!("    --validator-key keys/validator3.json \\");
    println!("    --p2p-addr /ip4/0.0.0.0/tcp/30303 \\");
    println!("    --rpc-addr 127.0.0.1:8547 \\");
    println!("    --bootnodes /ip4/127.0.0.1/tcp/30301");
    println!();
    println!("  # Terminal 4 - Full Node (non-validator)");
    println!("  cargo run --bin sumchain -- run \\");
    println!("    --genesis genesis/local_genesis.json \\");
    println!("    --data-dir data/fullnode \\");
    println!("    --p2p-addr /ip4/0.0.0.0/tcp/30304 \\");
    println!("    --rpc-addr 127.0.0.1:8548 \\");
    println!("    --bootnodes /ip4/127.0.0.1/tcp/30301");

    Ok(())
}
