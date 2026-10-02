//! #276 through the real binary: the CLI refuses an ambiguous genesis exactly
//! as the library does, before creating anything.

use std::collections::HashMap;
use std::process::Command;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

#[test]
fn init_refuses_a_duplicate_allocation_like_the_library() {
    let validator = KeyPair::from_bytes([43u8; 32]);
    let account = KeyPair::from_bytes([44u8; 32]).address();
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (account.to_base58(), 5u128),
            (
                format!("0x{}", hex::encode(account.as_bytes()).to_uppercase()),
                6u128,
            ),
        ]),
        ChainParams::default(),
    );
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("genesis.json");
    std::fs::write(&file, genesis.to_json().unwrap()).unwrap();
    let data = dir.path().join("data");

    let library = Genesis::from_file(&file).unwrap_err().to_string();
    assert!(
        library.starts_with("Duplicate genesis allocation"),
        "{library}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "init",
            "--genesis",
            file.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(
        text.contains(&library),
        "CLI and library disagree:\n{text}\n{library}"
    );
    assert!(
        !data.exists(),
        "init created a data directory before refusing"
    );
}
