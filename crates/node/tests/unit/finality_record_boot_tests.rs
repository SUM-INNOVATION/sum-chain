//! The local-depth finality record (#350) through the REAL start sequence:
//! `Node::with_rpc_config` + `init_chain`, which loads the chain through
//! `PoAEngine::load_chain`.
//!
//! A whole record is restored and the node starts; a record that is half
//! present or names another block refuses the start, with the database left as
//! it was, rather than restarting from finalized height 0.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::schema::meta_keys;
use sumchain_storage::{cf, BlockStore, Database};

use super::Node;

fn validator() -> KeyPair {
    KeyPair::from_bytes([29u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams {
            finality_depth: 2,
            ..ChainParams::default()
        },
    )
}

/// A data directory with genesis and five produced blocks, so blocks up to
/// height 3 are finalized and recorded.
async fn produced(dir: &Path) {
    let g = genesis();
    let db = Arc::new(Database::open_default(dir).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), g.chain_id));
    let engine = PoAEngine::new(
        db.clone(),
        state,
        Arc::new(Mempool::new(MempoolConfig::default())),
        &g,
        Some(validator()),
    )
    .unwrap();
    engine.init_genesis(&g).unwrap();
    for _ in 0..5 {
        engine.propose_block(Vec::new()).await.unwrap();
    }
    assert_eq!(engine.finalized_height(), 3);
}

/// Construct the node and load its chain, as `run` does first.
fn start(dir: &Path) -> Result<(), String> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node = Node::with_rpc_config(
        dir.to_path_buf(),
        genesis(),
        None,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .map_err(|e| format!("{e:#}"))?;
    node.init_chain().map_err(|e| format!("{e:#}"))
}

fn rows(dir: &Path) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
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

#[tokio::test]
async fn a_whole_record_is_restored_and_the_node_starts() {
    let dir = tempfile::TempDir::new().unwrap();
    produced(dir.path()).await;
    start(dir.path()).expect("a whole record starts");
    start(dir.path()).expect("and again");
}

#[tokio::test]
async fn a_damaged_record_refuses_the_start_and_is_left_as_it_was() {
    // `None` deletes the recorded hash; `Some` replaces it.
    let cases: [(Option<[u8; 32]>, &str); 2] = [
        (None, "finalized_hash is absent"),
        (Some([0x11; 32]), "the canonical block at that height"),
    ];
    for (hash, needle) in cases {
        let dir = tempfile::TempDir::new().unwrap();
        produced(dir.path()).await;
        start(dir.path()).expect("a first start records what a start records");
        {
            let db = Database::open_default(dir.path()).unwrap();
            let record = BlockStore::new(&db).checked_finality_record().unwrap();
            assert_eq!(record.map(|(height, _)| height), Some(3));
            match hash {
                None => db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap(),
                Some(bytes) => db.put(cf::META, meta_keys::FINALIZED_HASH, &bytes).unwrap(),
            }
        }
        let before = rows(dir.path());
        let err = start(dir.path()).expect_err("a damaged record must refuse the start");
        assert!(
            err.contains("refusing to start") && err.contains(needle),
            "{needle}: {err}"
        );
        assert_eq!(rows(dir.path()), before, "a refused start wrote");
    }
}
