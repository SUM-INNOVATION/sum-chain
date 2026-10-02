//! `docclass_getConfig` reports the rules execution applies (#280), with what
//! genesis configures alongside.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, DocClassParams, Genesis};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::DocClassConfigInfo;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tokio::sync::mpsc;

const ONE_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

fn serve(params: ChainParams) -> (tempfile::TempDir, RpcServer) {
    let validator = KeyPair::from_bytes([7u8; 32]);
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
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
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db,
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
    .with_genesis(&genesis);
    (dir, server)
}

fn configured(gates: Option<u64>) -> ChainParams {
    ChainParams {
        docclass: Some(DocClassParams {
            min_issuer_stake: 1_000,
            require_issuer_stake: true,
            max_credential_validity: ONE_YEAR_MS,
            ..DocClassParams::default()
        }),
        docclass_issuer_stake_requirement_enabled_from_height: gates,
        docclass_credential_validity_bound_enabled_from_height: gates,
        ..ChainParams::default()
    }
}

#[tokio::test]
async fn unset_docclass_reports_no_rules_instead_of_defaults() {
    let (_dir, server) = serve(ChainParams {
        docclass: None,
        ..ChainParams::default()
    });
    let info = server.docclass_get_config().await.unwrap();
    assert_eq!(info.min_issuer_stake, "0");
    assert!(!info.require_issuer_stake);
    assert_eq!(info.max_credential_validity, 0);
    assert_eq!(info.admin, None);
    assert!(!info.configured);
    assert!(info.configured_values.is_none());
    assert_eq!(info.effective_at_height, 1, "the next block after genesis");
}

#[tokio::test]
async fn configured_values_and_effective_rules_are_reported_separately() {
    // Validity gate closed: the configured bound is reported as configured
    // but not as enforced.
    let (_dir, server) = serve(configured(None));
    let info = server.docclass_get_config().await.unwrap();
    assert!(info.configured);
    assert_eq!(info.min_issuer_stake, "1000");
    assert!(info.require_issuer_stake);
    assert_eq!(
        info.max_credential_validity, 0,
        "no bound is enforced below the gate"
    );
    let c = info.configured_values.unwrap();
    assert_eq!(c.max_credential_validity, ONE_YEAR_MS);
    assert_eq!(c.min_issuer_stake, "1000");

    // Gates open from genesis: the bound is enforced and reported.
    let (_dir, server) = serve(configured(Some(0)));
    let info = server.docclass_get_config().await.unwrap();
    assert_eq!(info.max_credential_validity, ONE_YEAR_MS);
}

#[test]
fn a_client_reading_only_the_original_four_fields_still_parses() {
    let old = r#"{"min_issuer_stake":"0","require_issuer_stake":false,"max_credential_validity":0,"admin":null}"#;
    let parsed: DocClassConfigInfo = serde_json::from_str(old).unwrap();
    assert!(!parsed.configured);
    assert!(parsed.configured_values.is_none());
}

// ── the next block's rules at a gate boundary ───────────────────────────────

const G: u64 = 5;

/// A served chain whose canonical head is `head`, produced block by block by
/// the real engine (single validator, so it proposes every height).
async fn serve_at_head(params: ChainParams, head: u64) -> (tempfile::TempDir, RpcServer, Genesis) {
    use sumchain_consensus::ConsensusEngine;
    let validator = KeyPair::from_bytes([7u8; 32]);
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
        params,
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
            Some(validator),
        )
        .unwrap(),
    );
    engine.init_genesis(&genesis).unwrap();
    for _ in 0..head {
        engine.propose_block(vec![]).await.unwrap();
    }
    assert_eq!(engine.current_height(), head, "canonical head");
    let query: Arc<dyn ConsensusQuery> = engine;
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db,
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
    (dir, server, genesis)
}

fn gated(docclass: Option<DocClassParams>) -> ChainParams {
    ChainParams {
        docclass,
        docclass_issuer_stake_requirement_enabled_from_height: Some(G),
        docclass_credential_validity_bound_enabled_from_height: Some(G),
        peer_protocol_declaration_required_from_height: Some(G),
        ..ChainParams::default()
    }
}

fn configured_with(require_issuer_stake: bool) -> Option<DocClassParams> {
    Some(DocClassParams {
        min_issuer_stake: 1_000,
        require_issuer_stake,
        max_credential_validity: ONE_YEAR_MS,
        ..DocClassParams::default()
    })
}

/// The response must be exactly the rules execution applies at `at`.
fn assert_reports_rules_at(info: &DocClassConfigInfo, params: &ChainParams, at: u64) {
    let r = sumchain_state::DocClassExecutor::effective_rules(params, at);
    assert_eq!(info.effective_at_height, at);
    assert_eq!(info.configured, r.configured);
    assert_eq!(info.min_issuer_stake, r.min_issuer_stake.to_string());
    assert_eq!(info.require_issuer_stake, r.issuer_stake_required);
    assert_eq!(
        info.max_credential_validity,
        r.max_credential_validity.unwrap_or(0)
    );
}

#[tokio::test]
async fn at_head_g_minus_one_the_rules_of_block_g_are_reported() {
    // Configured, flag unset: below G a non-zero minimum is enforced whatever
    // the flag says; from G the flag decides, so the stake rule switches OFF
    // exactly at G. The validity bound switches ON at G.
    let params = gated(configured_with(false));
    let (_d, server, _) = serve_at_head(params.clone(), G - 1).await;
    let info = server.docclass_get_config().await.unwrap();
    assert_reports_rules_at(&info, &params, G);
    assert_eq!(info.min_issuer_stake, "0", "stake rule off from G");
    assert!(!info.require_issuer_stake);
    assert_eq!(
        info.max_credential_validity, ONE_YEAR_MS,
        "validity bound on from G"
    );

    // One block earlier the next block is G-1, under the old rules.
    let (_d, server, _) = serve_at_head(params.clone(), G - 2).await;
    let info = server.docclass_get_config().await.unwrap();
    assert_reports_rules_at(&info, &params, G - 1);
    assert_eq!(info.min_issuer_stake, "1000", "minimum enforced below G");
    assert!(info.require_issuer_stake);
    assert_eq!(info.max_credential_validity, 0, "no bound below G");

    // Configured, flag set: the stake rule holds on both sides; only the
    // validity bound changes at G.
    let params = gated(configured_with(true));
    let (_d, server, _) = serve_at_head(params.clone(), G - 1).await;
    let info = server.docclass_get_config().await.unwrap();
    assert_reports_rules_at(&info, &params, G);
    assert!(info.require_issuer_stake);
    assert_eq!(info.max_credential_validity, ONE_YEAR_MS);
}

#[tokio::test]
async fn at_head_g_minus_one_unset_docclass_reports_no_rules_on_either_side() {
    let params = gated(None);
    for head in [G - 2, G - 1] {
        let (_d, server, _) = serve_at_head(params.clone(), head).await;
        let info = server.docclass_get_config().await.unwrap();
        assert_reports_rules_at(&info, &params, head + 1);
        assert!(!info.configured);
        assert_eq!(info.min_issuer_stake, "0");
        assert!(!info.require_issuer_stake);
        assert_eq!(info.max_credential_validity, 0);
        assert!(info.configured_values.is_none());
    }
}
