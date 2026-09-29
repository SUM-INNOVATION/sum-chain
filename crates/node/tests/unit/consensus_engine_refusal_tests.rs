//! The consensus engine a node will run, decided through the REAL boot.
//!
//! `Node::with_rpc_config` is where a configured engine becomes a constructed
//! one, and `sumchain-node` has no library target, so this is a unit-test
//! module included by `#[path]` for the same reason as
//! `node_activation_boot_tests`.
//!
//! What is asserted:
//!
//! * `engine = "bft"` is refused, with the reason, before the data directory
//!   is created — so before the database, the network service or any consensus
//!   engine exists — and with or without a validator key.
//! * The refusal is final. It is an `Err`, never a node that quietly runs PoA.
//! * The default engine and an explicit `engine = "poa"` still boot.
//!
//! Like `node_activation_boot_tests`, it does not run `Node::run`: the decision
//! under test is made in `with_rpc_config`, before any of that exists.

use std::net::SocketAddr;
use std::path::Path;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

use super::Node;
use crate::config::{ConsensusEngine, ConsensusSettings, BFT_ENGINE_UNAVAILABLE};

fn genesis(validator: &KeyPair) -> Genesis {
    let mut alloc = std::collections::HashMap::new();
    alloc.insert(validator.address().to_base58(), 100_000_000u128);
    let g = Genesis::new(
        1,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        ChainParams::with_v2_enabled(),
    );
    Genesis::from_json(&g.to_json().expect("serialize")).expect("genesis must validate")
}

fn settings(engine: ConsensusEngine) -> ConsensusSettings {
    ConsensusSettings {
        engine,
        ..ConsensusSettings::default()
    }
}

fn boot(
    dir: &Path,
    genesis: &Genesis,
    key: Option<KeyPair>,
    consensus: ConsensusSettings,
) -> Result<Node, anyhow::Error> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Node::with_rpc_config(
        dir.to_path_buf(),
        genesis.clone(),
        key,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        consensus,
    )
}

fn assert_refused(result: Result<Node, anyhow::Error>, data_dir: &Path) {
    let err = match result {
        Ok(_) => panic!("a node configured for BFT must not start, on any engine"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains(BFT_ENGINE_UNAVAILABLE), "wrong refusal: {err}");
    assert!(
        err.contains("certified-finality protocol"),
        "refusal must say why: {err}"
    );
    assert!(
        !data_dir.exists(),
        "the refusal must come before the data directory, database and network exist"
    );
}

#[test]
fn bft_engine_is_refused_before_anything_is_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let validator = KeyPair::from_bytes([0x42; 32]);
    let genesis = genesis(&validator);

    let dir = tmp.path().join("bft-validator");
    let result = boot(
        &dir,
        &genesis,
        Some(validator),
        settings(ConsensusEngine::Bft),
    );
    assert_refused(result, &dir);

    let dir = tmp.path().join("bft-follower");
    let result = boot(&dir, &genesis, None, settings(ConsensusEngine::Bft));
    assert_refused(result, &dir);
}

/// The same refusal on a data directory that already holds a PoA chain: the
/// engine is not a property of the database, and a node that has run PoA does
/// not get to switch.
#[test]
fn bft_engine_is_refused_on_an_existing_poa_database() {
    let tmp = tempfile::tempdir().unwrap();
    let validator = KeyPair::from_bytes([0x43; 32]);
    let genesis = genesis(&validator);
    let dir = tmp.path().join("node");

    drop(
        boot(
            &dir,
            &genesis,
            Some(KeyPair::from_bytes([0x43; 32])),
            settings(ConsensusEngine::Poa),
        )
        .expect("PoA boots"),
    );
    assert!(dir.exists());

    let err = match boot(
        &dir,
        &genesis,
        Some(validator),
        settings(ConsensusEngine::Bft),
    ) {
        Ok(_) => panic!("BFT must be refused on an existing PoA database too"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains(BFT_ENGINE_UNAVAILABLE), "wrong refusal: {err}");
}

#[test]
fn default_and_explicit_poa_boot() {
    let tmp = tempfile::tempdir().unwrap();
    let validator = KeyPair::from_bytes([0x44; 32]);
    let genesis = genesis(&validator);

    let dir = tmp.path().join("default");
    let node = boot(
        &dir,
        &genesis,
        Some(KeyPair::from_bytes([0x44; 32])),
        ConsensusSettings::default(),
    )
    .expect("the default engine boots");
    assert!(
        node.consensus.as_poa().is_some(),
        "the default engine is PoA"
    );
    drop(node);

    let dir = tmp.path().join("explicit");
    let node = boot(
        &dir,
        &genesis,
        Some(validator),
        settings(ConsensusEngine::Poa),
    )
    .expect("an explicit PoA engine boots");
    assert!(node.consensus.as_poa().is_some());
    drop(node);

    let dir = tmp.path().join("follower");
    let node =
        boot(&dir, &genesis, None, settings(ConsensusEngine::Poa)).expect("a PoA follower boots");
    assert!(node.consensus.as_poa().is_some());
}
