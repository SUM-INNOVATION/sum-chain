//! Genesis allocations have one interpretation (#276): each account once,
//! whatever its spelling, in address order.
//!
//! Before #276 one address could be allocated under several spellings, and the
//! stored balance, genesis state root, genesis block hash and activation digest
//! all depended on `HashMap` iteration order — a single genesis file loaded 300
//! times produced 24 distinct genesis block hashes. These tests pin the refusal
//! and the determinism that replace it.

use std::collections::{BTreeSet, HashMap};
use std::process::Command;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{alloc_from_entries, ChainParams, Genesis, GenesisError};

fn validator() -> KeyPair {
    KeyPair::from_bytes([31u8; 32])
}

fn account(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

/// Every spelling `Address::from_base58` / `from_hex` accept for one account.
fn spellings(kp: &KeyPair) -> Vec<String> {
    let a = kp.address();
    let hex = hex::encode(a.as_bytes());
    vec![
        a.to_base58(),
        format!("0x{hex}"),
        hex.clone(),
        hex.to_uppercase(),
    ]
}

/// A genesis JSON whose `alloc` object holds exactly `entries`, in that order
/// (including repeated keys, which a `HashMap` could not represent).
fn genesis_json(entries: &[(String, u128)]) -> String {
    let base = Genesis::new(
        1,
        1_000,
        vec![validator().public_key().to_base58()],
        HashMap::new(),
        ChainParams::default(),
    );
    let json = base.to_json().unwrap();
    let alloc: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!("{}: {v}", serde_json::to_string(k).unwrap()))
        .collect();
    let empty = "\"alloc\": {}";
    assert!(json.contains(empty), "fixture shape changed");
    json.replace(empty, &format!("\"alloc\": {{{}}}", alloc.join(", ")))
}

fn duplicate(err: GenesisError) -> (String, String, String) {
    match err {
        GenesisError::DuplicateAllocation {
            address,
            first,
            second,
        } => (address, first, second),
        other => panic!("expected DuplicateAllocation, got {other}"),
    }
}

#[test]
fn hex_and_base58_of_one_address_are_refused() {
    let kp = account(1);
    let s = spellings(&kp);
    let json = genesis_json(&[(s[0].clone(), 100), (s[1].clone(), 200)]);
    let (address, ..) = duplicate(Genesis::from_json(&json).unwrap_err());
    assert_eq!(address, kp.address().to_base58());
}

#[test]
fn a_duplicate_with_equal_balances_is_refused() {
    let s = spellings(&account(2));
    let json = genesis_json(&[(s[0].clone(), 500), (s[2].clone(), 500)]);
    duplicate(Genesis::from_json(&json).unwrap_err());
}

#[test]
fn a_duplicate_with_different_balances_is_refused() {
    let s = spellings(&account(3));
    let json = genesis_json(&[(s[2].clone(), 1), (s[3].clone(), 2)]);
    duplicate(Genesis::from_json(&json).unwrap_err());
}

#[test]
fn an_exactly_repeated_key_is_refused_not_overwritten() {
    let s = spellings(&account(4));
    let json = genesis_json(&[(s[0].clone(), 1), (s[0].clone(), 2)]);
    let err = Genesis::from_json(&json).unwrap_err();
    assert!(
        matches!(err, GenesisError::Json(_))
            && err.to_string().contains("duplicate genesis allocation key"),
        "{err}"
    );
}

#[test]
fn an_invalid_address_is_still_refused_as_invalid() {
    let json = genesis_json(&[("not-an-address".into(), 1)]);
    assert!(matches!(
        Genesis::from_json(&json).unwrap_err(),
        GenesisError::InvalidAddress(a) if a == "not-an-address"
    ));
}

#[test]
fn every_consumer_sees_the_refusal_on_a_programmatic_genesis() {
    // A genesis built in code skips `from_json`; every reader still refuses.
    let s = spellings(&account(5));
    let g = Genesis::new(
        1,
        1_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(s[0].clone(), 1), (s[1].clone(), 1)]),
        ChainParams::default(),
    );
    duplicate(g.validate().unwrap_err());
    duplicate(g.canonical_alloc().unwrap_err());
    duplicate(g.parsed_alloc().unwrap_err());
    duplicate(g.compute_state_root().unwrap_err());
    duplicate(g.create_genesis_block().unwrap_err());
    duplicate(g.activation_digest().unwrap_err());
}

#[test]
fn the_refusal_names_the_same_pair_every_time() {
    let s = spellings(&account(6));
    let entries: Vec<(String, u128)> = s
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), i as u128))
        .collect();
    let json = genesis_json(&entries);
    let reports: BTreeSet<String> = (0..300)
        .map(|_| Genesis::from_json(&json).unwrap_err().to_string())
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
}

#[test]
fn unique_allocations_in_any_input_order_give_one_genesis() {
    let entries: Vec<(String, u128)> = (1..=8u8)
        .map(|i| (account(i).address().to_base58(), 1_000 * i as u128))
        .collect();
    let mut seen = BTreeSet::new();
    for rotation in 0..entries.len() {
        let mut e = entries.clone();
        e.rotate_left(rotation);
        if rotation % 2 == 1 {
            e.reverse();
        }
        let g = Genesis::from_json(&genesis_json(&e)).unwrap();
        let alloc = g.canonical_alloc().unwrap();
        assert!(alloc
            .windows(2)
            .all(|w| w[0].0.as_bytes() < w[1].0.as_bytes()));
        seen.insert((
            g.create_genesis_block().unwrap().hash(),
            g.compute_state_root().unwrap(),
            g.activation_digest().unwrap(),
            format!("{alloc:?}"),
        ));
    }
    assert_eq!(seen.len(), 1);
}

#[test]
fn the_tooling_builder_refuses_instead_of_overwriting() {
    let s = spellings(&account(7));
    duplicate(alloc_from_entries([(s[0].clone(), 1), (s[3].clone(), 1)]).unwrap_err());
    duplicate(alloc_from_entries([(s[1].clone(), 1), (s[1].clone(), 2)]).unwrap_err());
    let ok =
        alloc_from_entries([(s[0].clone(), 1), (account(8).address().to_base58(), 2)]).unwrap();
    assert_eq!(ok.len(), 2);
}

// ── separate processes ──────────────────────────────────────────────────────

/// Child half of the cross-process tests: loads `GENESIS_276_JSON` and prints
/// what a node would derive from it.
#[test]
#[ignore]
fn child_load_and_print() {
    let Ok(path) = std::env::var("GENESIS_276_JSON") else {
        return;
    };
    match Genesis::from_file(&path) {
        Ok(g) => println!(
            "RESULT ok {} {} {:?}",
            g.create_genesis_block().unwrap().hash(),
            g.activation_digest().unwrap(),
            g.canonical_alloc().unwrap()
        ),
        Err(e) => println!("RESULT err {e}"),
    }
}

fn in_separate_processes(json: &str, runs: usize) -> BTreeSet<String> {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("genesis.json");
    std::fs::write(&path, json).unwrap();
    (0..runs)
        .map(|_| {
            let out = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "child_load_and_print",
                    "--nocapture",
                ])
                .env("GENESIS_276_JSON", &path)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            stdout
                .lines()
                .find(|l| l.starts_with("RESULT "))
                .unwrap_or_else(|| panic!("child printed no result: {stdout}"))
                .to_string()
        })
        .collect()
}

#[test]
fn separate_processes_agree_on_a_valid_genesis() {
    let entries: Vec<(String, u128)> = (1..=6u8)
        .map(|i| (account(i).address().to_base58(), 7 * i as u128))
        .collect();
    let results = in_separate_processes(&genesis_json(&entries), 8);
    assert_eq!(results.len(), 1, "{results:?}");
    assert!(results.iter().next().unwrap().starts_with("RESULT ok "));
}

#[test]
fn separate_processes_all_refuse_the_ambiguous_genesis_identically() {
    // The #276 input: one account, four spellings, four balances. On the old
    // loader this produced 24 distinct genesis block hashes across loads.
    let s = spellings(&account(9));
    let entries: Vec<(String, u128)> = s
        .iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), 1_000 * (i as u128 + 1)))
        .collect();
    let results = in_separate_processes(&genesis_json(&entries), 8);
    assert_eq!(results.len(), 1, "{results:?}");
    let only = results.into_iter().next().unwrap();
    assert!(
        only.starts_with("RESULT err Duplicate genesis allocation"),
        "{only}"
    );
}
