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
use sumchain_primitives::inference_attestation::{
    inference_attestation_key, session_index_key, InferenceAttestationDigest,
    InferenceAttestationRecord, InferenceAttestationTxData,
};
use sumchain_primitives::inference_settlement::{
    session_key, InferenceSession, InferenceSessionStatus,
};
use sumchain_primitives::{
    Address, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database, ReceiptStore, TxStore};
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

/// `is_block_finalized` keeps its bare boolean: a label would change its type,
/// so the rule it answers from is named by `get_finality` instead.
#[tokio::test]
async fn is_block_finalized_stays_a_bare_boolean_answered_by_the_labelled_rule() {
    let s = serve().await;
    for (height, expected) in [(HEAD - 3, true), (HEAD - 2, false), (HEAD, false)] {
        let answer = s.server.is_block_finalized(height).await.unwrap();
        assert_eq!(serde_json::to_value(answer).unwrap(), json!(expected));
        assert_eq!(answer, s.engine.is_finalized(height));
    }
    assert_eq!(
        s.server.get_finality().await.unwrap().finality_mechanism,
        "local-depth",
        "the rule is_block_finalized answers from is named where a label fits"
    );
}

const SESSION: &str = "finality-label-session";

fn verifier(byte: u8) -> Address {
    Address::new([byte; 20])
}

fn digest(tuple: u8) -> InferenceAttestationDigest {
    InferenceAttestationDigest {
        session_id: SESSION.to_string(),
        model_hash: [tuple; 32],
        manifest_root: [tuple; 32],
        response_hash: [tuple; 32],
        proof_root: [tuple; 32],
    }
}

/// Commit an attestation row and its session-index entry, the pair the
/// committed readers under test read.
fn put_attestation(db: &Database, verifier: Address, included_at_height: u64) {
    let record = InferenceAttestationRecord {
        digest: digest(1),
        verifier_signature: [0u8; 64],
        included_at_height,
        tx_hash: Hash::hash(&[verifier.as_bytes().as_slice(), b"tx"].concat()),
    };
    let mut batch = db.batch();
    batch
        .put(
            cf::INFERENCE_ATTESTATIONS,
            &inference_attestation_key(SESSION, &verifier),
            &bincode::serialize(&record).unwrap(),
        )
        .unwrap();
    batch
        .put(
            cf::INFERENCE_ATTESTATIONS_BY_SESSION,
            &session_index_key(SESSION, &verifier),
            &[],
        )
        .unwrap();
    batch.commit().unwrap();
}

/// Commit an open settlement session with a one-block dispute window.
fn put_session(db: &Database) {
    let session = InferenceSession {
        session_id: SESSION.to_string(),
        funder: verifier(0x99),
        reward_per_verifier: 100,
        max_verifiers: 4,
        remaining_escrow: 400,
        claims_count: 0,
        dispute_window_blocks: 1,
        status: InferenceSessionStatus::Open,
        created_at_height: 0,
        expires_at_height: 1_000,
        consistency: None,
        bond_requirement: None,
    };
    let mut batch = db.batch();
    batch
        .put(
            cf::INFERENCE_SESSIONS,
            &session_key(SESSION),
            &bincode::serialize(&session).unwrap(),
        )
        .unwrap();
    batch.commit().unwrap();
}

#[tokio::test]
async fn inference_attestation_records_label_finalized_beside_every_field() {
    let s = serve().await;
    let (deep, recent) = (verifier(0x11), verifier(0x22));
    put_attestation(&s.db, deep, HEAD - 3);
    put_attestation(&s.db, recent, HEAD);

    let read = |v: Address| {
        let server = &s.server;
        async move {
            serde_json::to_value(
                server
                    .sum_get_inference_attestation(SESSION.to_string(), v.to_base58())
                    .await
                    .unwrap()
                    .expect("committed"),
            )
            .unwrap()
        }
    };
    let expected = |v: Address, height: u64, finalized: bool| {
        json!({
            "session_id": SESSION,
            "verifier_address": v.to_base58(),
            "model_hash": format!("0x{}", "01".repeat(32)),
            "manifest_root": format!("0x{}", "01".repeat(32)),
            "response_hash": format!("0x{}", "01".repeat(32)),
            "proof_root": format!("0x{}", "01".repeat(32)),
            "verifier_signature": format!("0x{}", "00".repeat(64)),
            "included_at_height": height,
            "tx_hash": Hash::hash(&[v.as_bytes().as_slice(), b"tx"].concat()).to_hex(),
            "finalized": finalized,
            "finality_mechanism": "local-depth",
        })
    };
    // `finalized` keeps its value either way; the label says what it means.
    assert_eq!(read(deep).await, expected(deep, HEAD - 3, true));
    assert_eq!(read(recent).await, expected(recent, HEAD, false));

    let listed = s
        .server
        .sum_list_inference_attestations(SESSION.to_string())
        .await
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|a| a.finality_mechanism == "local-depth"));
}

/// A V2 `InferenceAttestation` tx. The status classifier checks only the
/// payload variant, so the signatures are placeholders.
fn attestation_tx(nonce: u64) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: 1,
        from: verifier(0x33),
        fee: 1_000,
        nonce,
        payload: TxPayload::InferenceAttestation(InferenceAttestationTxData {
            digest: digest(2),
            verifier_signature: [0u8; 64],
        }),
    };
    SignedTransaction::new_v2(tx, [0u8; 64], [0u8; 32])
}

#[tokio::test]
async fn inference_attestation_status_labels_only_finalized() {
    let s = serve().await;
    let (finalized, included, failed, pending) = (
        attestation_tx(0),
        attestation_tx(1),
        attestation_tx(2),
        attestation_tx(3),
    );
    let txs = TxStore::new(&s.db);
    let receipts = ReceiptStore::new(&s.db);
    for tx in [&finalized, &included, &failed, &pending] {
        txs.put(tx).unwrap();
    }
    receipts
        .put(&Receipt::new(
            finalized.hash(),
            HEAD - 3,
            0,
            TxStatus::Success,
            10,
        ))
        .unwrap();
    receipts
        .put(&Receipt::new(
            included.hash(),
            HEAD,
            0,
            TxStatus::Success,
            10,
        ))
        .unwrap();
    receipts
        .put(&Receipt::new(
            failed.hash(),
            HEAD - 3,
            1,
            TxStatus::Failed(51),
            10,
        ))
        .unwrap();

    let status = |h: Hash| {
        let server = &s.server;
        async move {
            serde_json::to_value(
                server
                    .sum_get_inference_attestation_status(h.to_hex())
                    .await
                    .unwrap(),
            )
            .unwrap()
        }
    };
    assert_eq!(
        status(finalized.hash()).await,
        json!({
            "status": "finalized",
            "included_at_height": HEAD - 3,
            "reason": null,
            "finality_mechanism": "local-depth",
        })
    );
    // Unchanged shapes: no finality claim, no label.
    assert_eq!(
        status(included.hash()).await,
        json!({ "status": "included", "included_at_height": HEAD, "reason": null })
    );
    let failed_status = status(failed.hash()).await;
    assert_eq!(failed_status["status"], "failed");
    assert!(failed_status.get("finality_mechanism").is_none());
    // Stored, no receipt and not in the mempool: no longer recognised.
    assert_eq!(
        status(pending.hash()).await,
        json!({ "status": "unknown", "included_at_height": null, "reason": null })
    );
}

#[tokio::test]
async fn claimable_reward_labels_every_maturity_height() {
    let s = serve().await;
    let claim = |v: Address| {
        let server = &s.server;
        async move {
            serde_json::to_value(
                server
                    .omninode_get_claimable_reward(SESSION.to_string(), v.to_base58())
                    .await
                    .unwrap(),
            )
            .unwrap()
        }
    };
    let (mature, immature) = (verifier(0x11), verifier(0x22));

    // No maturity height, no finality claim: the pre-#270 shape.
    assert_eq!(
        claim(mature).await,
        json!({
            "session_id": SESSION,
            "verifier": mature.to_base58(),
            "eligible": false,
            "amount": null,
            "unlock_height": null,
            "reason": "session not found",
            "consistency": null,
            "bond": null,
        })
    );
    put_session(&s.db);
    let no_attestation = claim(mature).await;
    assert_eq!(no_attestation["reason"], "no attestation for verifier");
    assert!(no_attestation.get("finality_mechanism").is_none());

    // Maturity = included + finality_depth (3) + dispute window (1).
    put_attestation(&s.db, mature, 1);
    put_attestation(&s.db, immature, HEAD - 1);
    assert_eq!(
        claim(mature).await,
        json!({
            "session_id": SESSION,
            "verifier": mature.to_base58(),
            "eligible": true,
            "amount": 100,
            "unlock_height": 1 + 3 + 1,
            "reason": "eligible",
            "consistency": null,
            "bond": null,
            "finality_mechanism": "local-depth",
        })
    );
    assert_eq!(
        claim(immature).await,
        json!({
            "session_id": SESSION,
            "verifier": immature.to_base58(),
            "eligible": false,
            "amount": 100,
            "unlock_height": HEAD - 1 + 3 + 1,
            "reason": "not yet mature",
            "consistency": null,
            "bond": null,
            "finality_mechanism": "local-depth",
        })
    );
}

#[tokio::test]
async fn inference_consistency_names_the_rule_behind_eligible_count() {
    let s = serve().await;
    put_attestation(&s.db, verifier(0x11), HEAD - 3);
    put_attestation(&s.db, verifier(0x22), HEAD);

    let report = s
        .server
        .omninode_get_inference_consistency(SESSION.to_string())
        .await
        .unwrap();
    assert_eq!(report.finality_mechanism, "local-depth");
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].verifier_count, 2);
    assert_eq!(
        report.groups[0].eligible_count, 1,
        "only the attestation finality_depth blocks deep counts"
    );
    let j = serde_json::to_value(&report).unwrap();
    assert_eq!(j["finality_mechanism"], "local-depth");
    let mut keys: Vec<&str> = j.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "consistency",
            "finality_mechanism",
            "groups",
            "max_verifiers",
            "session_id"
        ],
        "the label is the only key added"
    );
}
