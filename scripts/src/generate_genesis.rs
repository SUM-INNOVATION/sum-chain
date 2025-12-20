//! Generate a genesis file with custom parameters.

use std::collections::HashMap;

use anyhow::Result;
use sumchain_genesis::{ChainParams, Genesis};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: generate-genesis <output_file> <validator_pubkey1> [<validator_pubkey2> ...]");
        eprintln!("\nExample:");
        eprintln!("  generate-genesis genesis.json 3WZrxEjTLHqLr... 4XAsyFjUMIqMs...");
        std::process::exit(1);
    }

    let output_file = &args[1];
    let validators: Vec<String> = args[2..].iter().cloned().collect();

    println!("Generating genesis with {} validators", validators.len());

    let genesis = Genesis::new(
        1337,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        validators.clone(),
        HashMap::new(), // No prefunded accounts
        ChainParams::default(),
    );

    // Validate
    genesis.validate()?;

    // Save
    genesis.to_file(output_file)?;
    println!("Genesis saved to: {}", output_file);

    Ok(())
}
