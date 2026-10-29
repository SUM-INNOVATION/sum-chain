//! The certified-finality start-up audit (#341, #350) through the REAL boot
//! sequence.
//!
//! Fork choice consults the certified-crossing guard, which trusts the stored
//! pointer only once `certified_guard::audit_at_start` (`recover_v1`) has
//! passed. `Node::with_rpc_config` runs it before the consensus engine exists.
//! This binary verifies no certificate, so the audit passes exactly when the
//! database holds no certified-finality record, and refuses anything else
//! without changing it. All records here are synthetic.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Block;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::{certificate_key, FINALIZED_POINTER_KEY};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::schema::meta_keys;
use sumchain_storage::{cf, Database};

use super::Node;

fn validator() -> KeyPair {
    KeyPair::from_bytes([23u8; 32])
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

/// A data directory holding the genesis block, written by the engine itself,
/// and booted once, so every record a first boot writes already exists.
fn initialized(g: &Genesis) -> (tempfile::TempDir, Block) {
    let dir = tempfile::TempDir::new().unwrap();
    let genesis_block = {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), g.chain_id));
        let engine = PoAEngine::new(
            db.clone(),
            state,
            Arc::new(Mempool::new(MempoolConfig::default())),
            g,
            None,
        )
        .unwrap();
        engine.init_genesis(g).unwrap()
    };
    boot(dir.path(), g).expect("a database with no certified record boots");
    (dir, genesis_block)
}

fn with_db(dir: &Path, f: impl FnOnce(&Database)) {
    let db = Database::open_default(dir).unwrap();
    f(&db);
}

type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

fn rows(dir: &Path) -> Rows {
    let db = Database::open_default(dir).unwrap();
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

/// Boot, expect the audit's refusal naming `needle`, and prove the boot changed
/// nothing and is refused again.
fn refused_unchanged(dir: &Path, g: &Genesis, needle: &str) {
    let before = rows(dir);
    let err = boot(dir, g).expect_err("the start-up audit must refuse");
    assert!(
        err.contains("refusing to start")
            && err.contains("did not pass the start-up audit")
            && err.contains(needle),
        "the refusal must say why: {err}"
    );
    assert_eq!(rows(dir), before, "a refused boot changed the database");
    assert!(boot(dir, g).is_err(), "and it stays refused");
}

#[test]
fn a_database_with_no_certified_record_boots_as_before() {
    let g = genesis();
    let (dir, genesis_block) = initialized(&g);
    // The legacy local-depth record is not certified finality.
    with_db(dir.path(), |db| {
        db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &0u64.to_be_bytes())
            .unwrap();
        db.put(
            cf::META,
            meta_keys::FINALIZED_HASH,
            genesis_block.hash().as_bytes(),
        )
        .unwrap();
    });
    boot(dir.path(), &g).expect("no certified record: the boot is unchanged");
    boot(dir.path(), &g).expect("and again");
}

#[test]
fn certificate_rows_without_a_pointer_refuse_the_boot() {
    let g = genesis();
    let (dir, genesis_block) = initialized(&g);
    with_db(dir.path(), |db| {
        db.put(
            cf::META,
            &certificate_key(0, &genesis_block.hash()),
            b"synthetic",
        )
        .unwrap();
    });
    refused_unchanged(dir.path(), &g, "CertificateWithoutPointer");
}

#[test]
fn an_undecodable_pointer_refuses_the_boot() {
    let g = genesis();
    let (dir, _) = initialized(&g);
    with_db(dir.path(), |db| {
        db.put(cf::META, FINALIZED_POINTER_KEY, &[7u8; 12]).unwrap();
    });
    refused_unchanged(dir.path(), &g, "finalized pointer");
}

/// A pointer naming the real head, with its certificate row: well-formed, but
/// this binary cannot re-verify a certificate, so it does not trust it.
#[test]
fn a_certified_record_this_binary_cannot_verify_refuses_the_boot() {
    let g = genesis();
    let (dir, genesis_block) = initialized(&g);
    with_db(dir.path(), |db| {
        let mut pointer = 0u64.to_le_bytes().to_vec();
        pointer.extend_from_slice(genesis_block.hash().as_bytes());
        db.put(cf::META, FINALIZED_POINTER_KEY, &pointer).unwrap();
        db.put(
            cf::META,
            &certificate_key(0, &genesis_block.hash()),
            b"synthetic",
        )
        .unwrap();
    });
    refused_unchanged(dir.path(), &g, "no finality-certificate verifier");
}

/// The audit runs before anything that processes a block is built.
#[test]
fn the_audit_runs_before_consensus_exists() {
    let src = include_str!("../../src/node.rs");
    let production = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    let at = |needle: &str| {
        production
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found in node.rs"))
    };
    let audit = at("sumchain_storage::certified_guard::audit_at_start(&db)");
    assert!(audit < at("Mempool::new(MempoolConfig {"));
    assert!(audit < at("ConsensusWrapper::new_poa("));
}
