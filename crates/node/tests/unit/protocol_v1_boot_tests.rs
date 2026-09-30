//! Protocol v1 proposer and membership rules, through the REAL boot (#267).
//!
//! `Node::with_rpc_config` checks the genesis before it creates the data
//! directory, so a genesis asking for stake-weighted proposers or dynamic staking
//! epochs is refused with nothing opened, and a static genesis still boots. The
//! genesis is built with `Genesis::new`, which does not validate, so this is the
//! node's own check under test rather than the JSON loader's. Keys are
//! synthetic. Like the other unit modules here, it does not run `Node::run`.

use std::net::SocketAddr;
use std::path::Path;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::StakingParams;

use super::Node;

fn genesis(staking: Option<StakingParams>) -> Genesis {
    let validators: Vec<String> = (1u8..=2)
        .map(|i| KeyPair::from_bytes([i; 32]).public_key().to_base58())
        .collect();
    let params = ChainParams {
        staking,
        ..ChainParams::with_v2_enabled()
    };
    Genesis::new(1, 0, validators, std::collections::HashMap::new(), params)
}

fn boot(dir: &Path, genesis: Genesis) -> Result<Node, anyhow::Error> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Node::with_rpc_config(
        dir.to_path_buf(),
        genesis,
        Some(KeyPair::from_bytes([1; 32])),
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
}

fn assert_refused(dir: &Path, genesis: Genesis, needle: &str) {
    let err = match boot(dir, genesis) {
        Ok(_) => panic!("this genesis must not boot"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains(needle), "{err}");
    assert!(
        !dir.exists(),
        "refused before the data directory, database and network exist"
    );
}

#[test]
fn stake_weighted_selection_is_refused_before_anything_is_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let staking = StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    };
    assert_refused(
        &tmp.path().join("node"),
        genesis(Some(staking)),
        "stake-weighted proposer selection is unavailable in protocol v1",
    );
}

#[test]
fn dynamic_epochs_are_refused_before_anything_is_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let staking = StakingParams {
        epoch_length: 14_400,
        ..StakingParams::default()
    };
    assert_refused(
        &tmp.path().join("node"),
        genesis(Some(staking)),
        "dynamic staking epochs",
    );
}

#[test]
fn static_membership_boots() {
    let tmp = tempfile::tempdir().unwrap();
    drop(boot(&tmp.path().join("none"), genesis(None)).expect("no staking section boots"));
    drop(
        boot(
            &tmp.path().join("static"),
            genesis(Some(StakingParams::default())),
        )
        .expect("the default, static staking section boots"),
    );
}

/// Both early checks are present and run in order: a node configured for BFT
/// on a genesis that also asks for stake-weighted proposers hears about the
/// engine first, and either way nothing is opened. Neither check stands in for
/// the other: BFT on a valid genesis is refused, and PoA on an unsafe genesis is
/// refused.
#[test]
fn the_engine_refusal_runs_first_and_neither_check_replaces_the_other() {
    use crate::config::{ConsensusEngine, ConsensusSettings};
    let tmp = tempfile::tempdir().unwrap();
    let bft = ConsensusSettings {
        engine: ConsensusEngine::Bft,
        ..ConsensusSettings::default()
    };
    let boot_with = |dir: &Path, genesis: Genesis, consensus: ConsensusSettings| {
        let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
        match Node::with_rpc_config(
            dir.to_path_buf(),
            genesis,
            Some(KeyPair::from_bytes([1; 32])),
            sumchain_p2p::NetworkConfig::default(),
            rpc,
            health,
            sumchain_rpc::RpcAuthConfig::disabled(),
            sumchain_rpc::RateLimitConfig::disabled(),
            consensus,
        ) {
            Ok(_) => panic!("this configuration must not boot"),
            Err(e) => format!("{e:#}"),
        }
    };
    let stake_weighted = StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    };

    let dir = tmp.path().join("both");
    let err = boot_with(&dir, genesis(Some(stake_weighted.clone())), bft.clone());
    assert!(err.contains(crate::config::BFT_ENGINE_UNAVAILABLE), "{err}");
    assert!(!dir.exists());

    let dir = tmp.path().join("bft-only");
    let err = boot_with(&dir, genesis(None), bft);
    assert!(err.contains(crate::config::BFT_ENGINE_UNAVAILABLE), "{err}");
    assert!(!dir.exists());

    let dir = tmp.path().join("staking-only");
    let err = boot_with(
        &dir,
        genesis(Some(stake_weighted)),
        ConsensusSettings::default(),
    );
    assert!(
        err.contains("stake-weighted proposer selection is unavailable"),
        "{err}"
    );
    assert!(!dir.exists());
}
