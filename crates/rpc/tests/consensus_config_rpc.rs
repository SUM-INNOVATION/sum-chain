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
    let server = server_over(&db, genesis);
    Served { dir, db, server }
}

/// Another server over `s`'s database, running `genesis`.
fn serve_on(s: &Served, genesis: &Genesis) -> RpcServer {
    server_over(&s.db, genesis)
}

fn server_over(db: &Arc<Database>, genesis: &Genesis) -> RpcServer {
    let db = db.clone();
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
    RpcServer::with_full_config(
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
    .with_genesis(genesis)
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
    assert_eq!(info.schema, 3, "a fresh baseline is recorded in schema 3");
    assert_eq!(info.status, "unverified-local-baseline");
    assert!(!info.network_agreement);
    assert_eq!(info.commitment.as_deref(), Some(c.as_str()));
    assert_eq!(info.initial_commitment.as_deref(), Some(c.as_str()));
    assert_eq!(info.baseline_height, Some(42));
    assert_eq!(info.matches_baseline, Some(true));
    assert_eq!(info.fields.len(), ccfg::SCHEMA_3.specs().len());
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

/// A baseline an older release recorded (schema 1 or 2) is reported in the
/// schema it holds until its operator moves it, and matches the running rules
/// as the startup check sees them — compared in the record's schema — although
/// its commitment differs from the schema-3 running commitment. A real
/// difference in rules still does not match.
#[tokio::test]
async fn the_rpc_reports_an_older_schema_baseline_as_recorded() {
    // Know schema 3 only because this binary's genesis carries the schema-3
    // gate; unset, it adds nothing to the record written.
    static SCHEMA_1_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
        reads: &[&ccfg::SCHEMA_1],
        writes: &ccfg::SCHEMA_1,
        knows: &ccfg::SCHEMA_3,
    };
    static SCHEMA_2_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
        reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2],
        writes: &ccfg::SCHEMA_2,
        knows: &ccfg::SCHEMA_3,
    };
    for (policy, schema, fields) in [
        (
            &SCHEMA_1_RELEASE,
            ccfg::SCHEMA_V1,
            ccfg::SCHEMA_V1_FIELDS.len(),
        ),
        (&SCHEMA_2_RELEASE, 2, ccfg::SCHEMA_2.specs().len()),
    ] {
        let g = genesis();
        let s = serve(&g);
        ccfg::record::check_at_startup_with(&s.db, &g, 42, policy).unwrap();
        let info = s.server.chain_get_consensus_config().await.unwrap();
        assert_eq!(info.schema, schema);
        assert_eq!(info.fields.len(), fields);
        let recorded = ccfg::read_record(&s.db).unwrap().unwrap().commitment;
        assert_eq!(info.commitment, Some(recorded.to_string()));
        let running = ccfg::build(&g).unwrap().commitment().to_string();
        assert_eq!(info.running_commitment.as_deref(), Some(running.as_str()));
        assert_ne!(info.commitment.as_deref(), Some(running.as_str()));
        assert_eq!(info.matches_baseline, Some(true), "schema {schema}");

        // A server running a genesis with a different rule does not match.
        let mut changed = g.clone();
        changed.params.max_contract_gas += 1;
        let other = serve_on(&s, &changed);
        let info = other.chain_get_consensus_config().await.unwrap();
        assert_eq!(info.matches_baseline, Some(false), "schema {schema}");
    }
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
