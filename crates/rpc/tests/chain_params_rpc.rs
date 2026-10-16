//! `chain_getChainParams` (#135): the sponsored inference-attestation gate
//! (`omninode_sponsored_attestation_enabled_from_height`, issue #79) is emitted
//! from the chain's live `ChainParams`, through the RPC surface itself — `null`
//! while unset, the configured height once set — alongside the settlement gates
//! #122 exposed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tokio::sync::mpsc;

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}

/// A server whose live `ChainParams` are exactly `params`.
fn serve(params: ChainParams) -> (tempfile::TempDir, RpcServer) {
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        params,
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
    let server = RpcServer::new(db, state, mempool, engine, tx_sender, Arc::new(|| 0usize))
        .with_chain_params(genesis.params.clone());
    (dir, server)
}

#[tokio::test]
async fn an_unset_sponsored_attestation_gate_is_emitted_as_null() {
    let params = ChainParams::default();
    assert_eq!(
        params.omninode_sponsored_attestation_enabled_from_height,
        None
    );
    let (_dir, server) = serve(params);

    let info = server.chain_get_chain_params().await.unwrap();
    assert_eq!(
        info.omninode_sponsored_attestation_enabled_from_height,
        None
    );

    let json = serde_json::to_value(&info).unwrap();
    let obj = json.as_object().unwrap();
    assert!(
        obj.contains_key("omninode_sponsored_attestation_enabled_from_height"),
        "the key is present even while the gate is unset"
    );
    assert_eq!(
        obj["omninode_sponsored_attestation_enabled_from_height"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn a_set_sponsored_attestation_gate_is_emitted_from_live_params() {
    // Distinct neighbouring gates, so a crossed wire would show.
    let params = ChainParams {
        omninode_sponsored_attestation_enabled_from_height: Some(9_200_000),
        inference_settlement_enabled_from_height: Some(8_900_000),
        inference_verifier_bonding_enabled_from_height: Some(9_300_000),
        ..ChainParams::default()
    };
    let (_dir, server) = serve(params);

    let info = server.chain_get_chain_params().await.unwrap();
    assert_eq!(
        info.omninode_sponsored_attestation_enabled_from_height,
        Some(9_200_000)
    );
    assert_eq!(
        info.inference_settlement_enabled_from_height,
        Some(8_900_000)
    );
    assert_eq!(
        info.inference_verifier_bonding_enabled_from_height,
        Some(9_300_000)
    );

    let json = serde_json::to_value(&info).unwrap();
    assert_eq!(
        json["omninode_sponsored_attestation_enabled_from_height"],
        serde_json::json!(9_200_000)
    );
    // The three fields #135's criterion names are all present keys.
    for key in [
        "inference_settlement_enabled_from_height",
        "inference_verifier_bonding_enabled_from_height",
        "omninode_sponsored_attestation_enabled_from_height",
    ] {
        assert!(json.as_object().unwrap().contains_key(key), "missing {key}");
    }
}
