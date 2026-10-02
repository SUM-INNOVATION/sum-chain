//! The consensus-configuration baseline (#268) through the REAL boot sequence.
//!
//! `Node::with_rpc_config` is where the baseline is recorded and compared; these
//! tests construct real nodes on real directories, so construction succeeding or
//! failing is the gate's verdict, exactly as in `node_activation_boot_tests.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use sumchain_consensus::consensus_config::{self as ccfg, record::RECORD_KEY, TransitionKind};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_storage::{cf, Database};

use super::Node;

fn validator() -> KeyPair {
    KeyPair::from_bytes([11u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

fn boot(dir: &Path, genesis: &Genesis) -> Result<(), String> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Node::with_rpc_config(
        dir.to_path_buf(),
        genesis.clone(),
        None,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .map(drop)
    .map_err(|e| format!("{e:#}"))
}

fn record(dir: &Path) -> Option<ccfg::BaselineRecord> {
    let db = Database::open_default(dir).unwrap();
    ccfg::read_record(&db).unwrap()
}

#[test]
fn the_first_boot_records_a_baseline_and_the_next_boot_matches_it() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let r = record(dir.path()).expect("recorded at first boot");
    assert_eq!(r.status, ccfg::BaselineStatus::UnverifiedLocalBaseline);
    assert_eq!(r.commitment, ccfg::build(&g).unwrap().commitment());
    assert_eq!(r.baseline_height, 0);
    boot(dir.path(), &g).unwrap();
    assert_eq!(record(dir.path()).unwrap(), r);
}

#[test]
fn a_boot_under_a_changed_rule_is_refused_with_the_field_named() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let mut changed = g.clone();
    changed.params.max_metadata_bytes += 1;
    let err = boot(dir.path(), &changed).unwrap_err();
    assert!(err.contains("max_metadata_bytes"), "{err}");
    assert!(err.contains("acknowledge-consensus-config"), "{err}");
    // Still refused on the next attempt: nothing was rewritten.
    assert!(boot(dir.path(), &changed).is_err());
    assert!(boot(dir.path(), &g).is_ok());
}

#[test]
fn a_boot_that_reschedules_a_future_gate_records_the_transition() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let mut later = g.clone();
    later.params.education_enabled_from_height = Some(1_000);
    boot(dir.path(), &later).unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, TransitionKind::GateReschedule);
}

#[test]
fn a_boot_over_a_damaged_baseline_is_refused_and_does_not_recreate_it() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let mut raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        *raw.last_mut().unwrap() ^= 1;
        db.put(cf::META, RECORD_KEY, &raw).unwrap();
    }
    let damaged = {
        let db = Database::open_default(dir.path()).unwrap();
        db.get(cf::META, RECORD_KEY).unwrap()
    };
    let err = boot(dir.path(), &g).unwrap_err();
    assert!(
        err.contains("refusing to start rather than recreate it"),
        "{err}"
    );
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(db.get(cf::META, RECORD_KEY).unwrap(), damaged);
}

/// The baseline step sits after the activation-height check and before
/// anything that processes a block is built.
#[test]
fn the_baseline_runs_after_the_gate_check_and_before_consensus_exists() {
    let src = include_str!("../../src/node.rs");
    let production = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    let at = |needle: &str| {
        production
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found in node.rs"))
    };
    let gate = at("Self::check_activation_parameters(&db, &genesis, initial_height)?;");
    let baseline = at("Self::check_consensus_config(&db, &genesis, initial_height)?;");
    let mempool = at("Mempool::new(MempoolConfig {");
    let engine = at("ConsensusWrapper::new_poa(");
    assert!(gate < baseline, "the gate check must run first");
    assert!(
        baseline < mempool && baseline < engine,
        "nothing may process a block first"
    );
}
