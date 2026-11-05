//! `storage_getActiveChallenges` returns only the challenges whose target is
//! the queried archive (#369).
//!
//! The node index is keyed `[b'N', target_node, challenge_id]`. Its prefix
//! scan runs past the queried archive's keys, so before #369 the RPC also
//! returned the open challenges of every archive whose address sorts after
//! the queried one. These tests drive the RPC method itself against committed
//! challenge rows.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Hash, StorageChallenge};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::storage_metadata::{
    challenge_expiry_index_key, challenge_key, challenge_node_index_key, CF_ACTIVE_CHALLENGES,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tokio::sync::mpsc;

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}

/// A server over a fresh chain, and its database.
fn serve() -> (tempfile::TempDir, Arc<Database>, RpcServer) {
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    );
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), genesis.chain_id));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let engine: Arc<dyn ConsensusQuery> = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            &genesis,
            Some(validator()),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize))
        .with_chain_params(genesis.params.clone());
    (dir, db, server)
}

/// Write an open challenge's three rows as `v_put_challenge` lays them out.
fn seed_challenge(db: &Database, tag: &[u8], target: Address) -> StorageChallenge {
    let challenge = StorageChallenge {
        challenge_id: Hash::hash(tag),
        merkle_root: Hash::hash(b"file"),
        chunk_index: 0,
        target_node: target,
        created_at_height: 1,
        expires_at_height: 1_000,
    };
    let mut batch = db.batch();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_key(&challenge.challenge_id),
            &bincode::serialize(&challenge).unwrap(),
        )
        .unwrap();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_node_index_key(&challenge.target_node, &challenge.challenge_id),
            &[1],
        )
        .unwrap();
    batch
        .put(
            CF_ACTIVE_CHALLENGES,
            &challenge_expiry_index_key(challenge.expires_at_height, &challenge.challenge_id),
            &[1],
        )
        .unwrap();
    batch.commit().unwrap();
    challenge
}

fn ids(results: &[serde_json::Value]) -> Vec<String> {
    let mut ids: Vec<String> = results
        .iter()
        .map(|r| r["challenge_id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

fn hex_id(c: &StorageChallenge) -> String {
    format!("0x{}", hex::encode(c.challenge_id.as_bytes()))
}

/// The archive whose address sorts lower is not handed a challenge of the
/// one whose address sorts higher.
#[tokio::test]
async fn a_lower_address_does_not_see_a_higher_addresss_challenge() {
    let (_dir, db, server) = serve();
    let low = Address::new([0x11; 20]);
    let high = Address::new([0xA1; 20]);
    let on_high = seed_challenge(&db, b"on-high", high);

    let for_low = server
        .storage_get_active_challenges(low.to_base58())
        .await
        .unwrap();
    assert!(for_low.is_empty(), "the lower address gets {for_low:?}");

    let for_high = server
        .storage_get_active_challenges(high.to_base58())
        .await
        .unwrap();
    assert_eq!(ids(&for_high), vec![hex_id(&on_high)]);
    assert_eq!(for_high[0]["target_node"], high.to_base58());
}

/// With challenges on both archives, each gets exactly its own, and every
/// returned challenge names the queried archive as its target.
#[tokio::test]
async fn each_archive_gets_exactly_its_own_challenges() {
    let (_dir, db, server) = serve();
    let low = Address::new([0x11; 20]);
    let high = Address::new([0xA1; 20]);
    let low_1 = seed_challenge(&db, b"low-1", low);
    let low_2 = seed_challenge(&db, b"low-2", low);
    let high_1 = seed_challenge(&db, b"high-1", high);

    for (addr, own) in [(low, vec![&low_1, &low_2]), (high, vec![&high_1])] {
        let got = server
            .storage_get_active_challenges(addr.to_base58())
            .await
            .unwrap();
        let mut want: Vec<String> = own.iter().map(|c| hex_id(c)).collect();
        want.sort();
        assert_eq!(ids(&got), want, "{addr}");
        for r in &got {
            assert_eq!(r["target_node"], addr.to_base58());
        }
    }
}
