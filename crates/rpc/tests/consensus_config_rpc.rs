//! `chain_getConsensusConfig` (#268): what an operator can read about the
//! consensus configuration a node runs and the baseline its database recorded,
//! through the RPC surface itself — and what it must never reveal or change.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::consensus_config as ccfg;
use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database};
use tokio::sync::mpsc;

struct Served {
    dir: tempfile::TempDir,
    db: Arc<Database>,
    server: RpcServer,
}

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
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

fn serve(genesis: &Genesis) -> Served {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), genesis.chain_id));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let engine: Arc<dyn ConsensusQuery> = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            genesis,
            Some(validator()),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
        Arc::new(|| None),
        Arc::new(|| true),
        RpcAuthConfig::disabled(),
        RateLimitConfig::disabled(),
        Arc::new(Metrics::new()),
    )
    .with_chain_params(genesis.params.clone())
    .with_genesis(genesis);
    Served { dir, db, server }
}

type Row = (Box<[u8]>, Box<[u8]>);

fn meta_snapshot(db: &Database) -> Vec<Row> {
    db.prefix_iter_checked(cf::META, b"consensus_config/")
        .unwrap()
        .map(Result::unwrap)
        .take_while(|(k, _)| k.starts_with(b"consensus_config/"))
        .collect()
}

#[tokio::test]
async fn before_a_baseline_the_rpc_says_so_and_reports_the_running_rules() {
    let g = genesis();
    let s = serve(&g);
    let info = s.server.chain_get_consensus_config().await.unwrap();
    assert_eq!(info.status, "not-recorded");
    assert!(!info.network_agreement);
    assert_eq!(info.commitment, None);
    assert_eq!(
        info.running_commitment,
        Some(ccfg::build(&g).unwrap().commitment().to_string())
    );
    assert_eq!(info.matches_baseline, None);
    assert_eq!(info.rules.engine, "proof-of-authority");
    assert_eq!(info.rules.finality, "local-depth");
}

#[tokio::test]
async fn the_rpc_reports_the_recorded_baseline_and_its_history() {
    let g = genesis();
    let s = serve(&g);
    ccfg::check_at_startup(&s.db, &g, 42).unwrap();

    let info = s.server.chain_get_consensus_config().await.unwrap();
    let c = ccfg::build(&g).unwrap().commitment().to_string();
    assert_eq!(info.schema, ccfg::SCHEMA_V1);
    assert_eq!(info.status, "unverified-local-baseline");
    assert!(!info.network_agreement);
    assert_eq!(info.commitment.as_deref(), Some(c.as_str()));
    assert_eq!(info.initial_commitment.as_deref(), Some(c.as_str()));
    assert_eq!(info.baseline_height, Some(42));
    assert_eq!(info.matches_baseline, Some(true));
    assert_eq!(info.fields.len(), ccfg::SCHEMA_V1_FIELDS.len());
    assert_eq!(info.rules.quorum, "none");
    assert_eq!(info.rules.membership, "static-genesis");
    assert_eq!(info.rules.unfinalized_production, "unbounded");
    assert_eq!(info.rules.finality_depth, Some(g.params.finality_depth));
    assert!(info.transitions.is_empty());

    // A recorded transition is listed by kind and field name.
    let mut changed = g.clone();
    changed.params.max_contract_gas += 1;
    let new = ccfg::build(&changed).unwrap().commitment();
    ccfg::acknowledge(
        &s.db,
        &changed,
        42,
        ccfg::build(&g).unwrap().commitment(),
        new,
    )
    .unwrap();
    let info = s.server.chain_get_consensus_config().await.unwrap();
    assert_eq!(info.transitions.len(), 1);
    assert_eq!(info.transitions[0].kind, "operator-acknowledged");
    assert_eq!(info.transitions[0].changed_fields, vec!["max_contract_gas"]);
    // This server still runs the original genesis, and says it no longer
    // matches what the database records.
    assert_eq!(info.matches_baseline, Some(false));
}

#[tokio::test]
async fn the_rpc_reveals_no_keys_addresses_or_paths_and_writes_nothing() {
    let g = genesis();
    let s = serve(&g);
    ccfg::check_at_startup(&s.db, &g, 0).unwrap();
    let before = meta_snapshot(&s.db);

    let info = s.server.chain_get_consensus_config().await.unwrap();
    let json = serde_json::to_string(&info).unwrap();
    for secretish in [
        validator().public_key().to_base58(),
        hex::encode(validator().public_key().as_bytes()),
        validator().address().to_base58(),
        hex::encode(validator().address().as_bytes()),
        s.dir.path().to_string_lossy().to_string(),
    ] {
        assert!(!json.contains(&secretish), "response carries {secretish}");
    }
    assert_eq!(meta_snapshot(&s.db), before, "a read changed the record");
}
