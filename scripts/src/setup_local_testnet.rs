//! Setup script for local testnet.
//! Generates validator keys and creates a genesis file.

use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

fn main() -> Result<()> {
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
            finality_depth: 3, // 3 block confirmations for finality
            storage_fee_per_byte: 100, // 100 base units per byte
            max_metadata_bytes: 16384, // 16 KB max metadata
            min_contract_gas: 21000, // Minimum gas for contract transactions
            max_contract_gas: 10_000_000, // Maximum gas limit per transaction
            staking: None, // Use default staking params
            messaging: None, // Use default messaging params
            docclass: None, // Use default docclass params
            max_access_list_bytes: 16_384,         // SNIP V2: 16 KB byte cap
            activation_grace_blocks: 50,           // SNIP V2: ~100s at 2s blocks
            abandonment_fee_percent: 10,           // SNIP V2: 10% retained on abandonment
            max_chunk_count_per_file: 1_048_576,   // SNIP V2 v3.2: 1 TB at CHUNK_SIZE = 1 MB
            max_chunk_indices_per_tx: 65_536,      // SNIP V2 v3.2: AcceptAssignmentV2 tx cap
            assignment_replication_factor: 3,      // SNIP V2 v3.2: baseline R=3
            v2_enabled_from_height: Some(0),       // local testnet: V2 active from genesis
            omninode_enabled_from_height: None,    // OmniNode subprotocol off by default; opt in per-genesis
            education_enabled_from_height: Some(0), // local/dev: SRC-817/818 Education active from genesis (local only; mainnet/testnet stay None)
            contracts_enabled_from_height: None,   // smart contracts dormant; coordinated consensus-breaking activation only
            governance_enabled_from_height: None,  // on-chain governance dormant; coordinated activation only
            governance: None,                      // no governance params configured
            archive_unbonding_enabled_from_height: None, // issue #20: archive withdrawal dormant
            archive_unbonding_period_blocks: 201_600,    // ~7 days at 3s blocks
            archive_reassignment_enabled_from_height: None, // issue #62: chunk reassignment dormant
            inference_settlement_enabled_from_height: None, // issue #61: settlement dormant
            inference_settlement_max_dispute_window_blocks: 201_600,
            inference_settlement_max_session_duration_blocks: 2_592_000,
            inference_settlement_dispute_resolver: None,
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
