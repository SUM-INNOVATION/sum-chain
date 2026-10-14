//! #270: every RPC response that says "finalized" names the rule that made it
//! so, and nothing a response already said changes.
//!
//! The rule is this node's local confirmation depth (consensus-configuration
//! finality rule `0x0011` = `FINALITY_LOCAL_DEPTH`), not certified network
//! finality. The label is ADDED beside the existing fields: `"latest"` and
//! `"finalized"` keep their tokens, every existing key keeps its name and value,
//! and the responses that make no finality claim are byte-for-byte unchanged.
//!
//! Driven through the real `PoAEngine` and the RPC handlers themselves, on a
//! chain long enough for the local-depth rule to have finalized something.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use sumchain_consensus::consensus_config as ccfg;
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, FinalityMechanism, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Hash, Receipt, TxStatus};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tokio::sync::mpsc;

/// Blocks produced on top of genesis. With the default `finality_depth` of 3
/// the local-depth rule has finalized up to `HEAD - 3`.
const HEAD: u64 = 5;

struct Served {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    engine: Arc<PoAEngine>,
    server: RpcServer,
    genesis: Genesis,
}

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}

async fn serve() -> Served {
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
    let engine = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            &genesis,
            Some(validator()),
        )
        .unwrap(),
    );
    engine.init_genesis(&genesis).unwrap();
    for _ in 0..HEAD {
        // A single validator is the round-robin proposer at every height.
        engine.propose_block(Vec::new()).await.unwrap();
    }
    let query: Arc<dyn ConsensusQuery> = engine.clone();
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db.clone(),
        state,
        mempool,
        query,
        tx_sender,
        Arc::new(|| 0usize),
        Arc::new(|| None),
        Arc::new(|| true),
        RpcAuthConfig::disabled(),
        RateLimitConfig::disabled(),
        Arc::new(Metrics::new()),
    )
    .with_chain_params(genesis.params.clone())
    .with_genesis(&genesis);
    Served {
        _dir: dir,
        db,
        engine,
        server,
        genesis,
    }
}

#[tokio::test]
async fn the_chain_under_test_has_local_finality_to_report() {
    let s = serve().await;
    let depth = s.genesis.params.finality_depth;
    assert_eq!(
        depth, 3,
        "the default the expected values below are written for"
    );
    assert_eq!(s.engine.current_height(), HEAD);
    assert_eq!(s.engine.finalized_height(), HEAD - depth);
    assert_eq!(s.engine.finality_mechanism(), FinalityMechanism::LocalDepth);
}

/// The label is the consensus configuration's own name for finality rule
/// `0x0011`, from the same engine that answers the heights: one name for one
/// rule across `chain_getConsensusConfig` and every finality-bearing response.
#[tokio::test]
async fn the_label_is_the_engines_finality_rule_by_its_configuration_name() {
    let s = serve().await;
    let mechanism = s.engine.finality_mechanism();
    assert_eq!(
        mechanism.rule_code(),
        Some(ccfg::fields::FINALITY_LOCAL_DEPTH)
    );
    assert_eq!(
        ccfg::build(&s.genesis).unwrap().get(0x0011),
        Some(&ccfg::Value::U8(ccfg::fields::FINALITY_LOCAL_DEPTH)),
        "the configuration commits the rule the engine reports"
    );
    let rules = s.server.chain_get_consensus_config().await.unwrap().rules;
    assert_eq!(rules.finality, mechanism.name());
    assert_eq!(mechanism.name(), "local-depth");
}

#[tokio::test]
async fn get_finality_adds_the_label_and_keeps_every_field() {
    let s = serve().await;
    let info = s.server.get_finality().await.unwrap();
    assert_eq!(
        serde_json::to_value(&info).unwrap(),
        json!({
            "finalized_height": HEAD - 3,
            "finalized_hash": s.engine.finalized_hash().to_hex(),
            "current_height": HEAD,
            "finality_depth": 3,
            "pending_finality": 3,
            "finality_mechanism": "local-depth",
        })
    );
    assert_eq!(
        info.finalized_hash,
        s.engine
            .get_block_by_height(HEAD - 3)
            .unwrap()
            .hash()
            .to_hex(),
        "the hash is the finalized block's"
    );
}

#[tokio::test]
async fn chain_get_block_height_labels_only_the_finalized_view() {
    let s = serve().await;

    let finalized = s
        .server
        .chain_get_block_height(Some("finalized".to_string()))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&finalized).unwrap(),
        json!({ "height": HEAD - 3, "finality": "finalized", "finality_mechanism": "local-depth" })
    );

    // "latest" makes no finality claim: exactly the pre-#270 shape, whether
    // asked for by name or by default.
    for param in [None, Some("latest".to_string())] {
        let latest = s.server.chain_get_block_height(param).await.unwrap();
        assert_eq!(
            serde_json::to_value(&latest).unwrap(),
            json!({ "height": HEAD, "finality": "latest" })
        );
    }

    // The accepted tokens are unchanged, and so is the refusal of any other.
    let err = s
        .server
        .chain_get_block_height(Some("safe".to_string()))
        .await
        .unwrap_err();
    assert!(
        err.message()
            .contains("finality must be \"latest\" or \"finalized\", got \"safe\""),
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn chain_get_transaction_status_labels_only_finalized() {
    let s = serve().await;
    let store = ReceiptStore::new(&s.db);
    let in_finalized = Hash::hash(b"in a finalized block");
    let in_head = Hash::hash(b"in the head block");
    let failed = Hash::hash(b"failed in a finalized block");
    store
        .put(&Receipt::new(
            in_finalized,
            HEAD - 3,
            0,
            TxStatus::Success,
            10,
        ))
        .unwrap();
    store
        .put(&Receipt::new(in_head, HEAD, 0, TxStatus::Success, 10))
        .unwrap();
    store
        .put(&Receipt::new(failed, 1, 0, TxStatus::InvalidNonce, 10))
        .unwrap();

    let status = |h: Hash| {
        let server = &s.server;
        async move {
            serde_json::to_value(
                server
                    .chain_get_transaction_status(h.to_hex())
                    .await
                    .unwrap(),
            )
            .unwrap()
        }
    };
    assert_eq!(
        status(in_finalized).await,
        json!({ "kind": "finalized", "block_height": HEAD - 3, "finality_mechanism": "local-depth" })
    );
    // Unchanged shapes: no finality claim, no label.
    assert_eq!(
        status(in_head).await,
        json!({ "kind": "included", "block_height": HEAD })
    );
    assert_eq!(
        status(failed).await,
        json!({ "kind": "failed", "block_height": 1, "reason": "invalid nonce" })
    );
    assert_eq!(
        status(Hash::hash(b"never seen")).await,
        json!({ "kind": "unknown" })
    );
}
