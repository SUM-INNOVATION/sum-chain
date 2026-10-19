//! `docclass_buildTransaction`: the no-key DocClass builder.
//!
//! For every operation the node's builder and a client's local build produce
//! the same bytes and the same signing hash, given the same explicit request.
//! The builder reads state (nonce, chain id, latest timestamp, the sender's
//! issuer record) and writes none, signs nothing and leaves the mempool empty.
//! Every key here is synthetic, derived from a fixed test seed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::docclass_build::{build_docclass_tx, DocClassTxContext};
use sumchain_primitives::{
    DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocSubcode,
    TransactionV2, TxPayload,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::docclass_build::{op_from_request, DocClassRequestDefaults};
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    DocClassAttributeRecord, DocClassBuildOpRequest, DocClassBuildRequest,
    DocClassCredentialMetadataRecord, DocClassIssuerKeyRecord, DocClassIssuerRecord,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, DocClassIssuerStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const NOW: u64 = 1_750_000_000_000;

struct Node {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    server: RpcServer,
}

fn serve() -> Node {
    let validator = KeyPair::from_bytes([7u8; 32]);
    let genesis = Genesis::new(
        CHAIN_ID,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
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
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let server = RpcServer::with_full_config(
        db.clone(),
        state.clone(),
        mempool.clone(),
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
    Node {
        _dir: dir,
        db,
        state,
        mempool,
        server,
    }
}

fn issuer() -> KeyPair {
    KeyPair::from_bytes([0x11; 32])
}

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

fn issuer_record(addr: &str) -> DocClassIssuerRecord {
    DocClassIssuerRecord {
        address: addr.to_string(),
        name: "Example Institute".to_string(),
        issuer_type: "Educational".to_string(),
        jurisdictions: vec!["US".to_string()],
        authorized_subcodes: vec![811],
        keys: vec![DocClassIssuerKeyRecord {
            key_id: "primary".to_string(),
            public_key: hex::encode(issuer().public_key().as_bytes()),
            key_type: "Ed25519".to_string(),
            added_at: NOW,
            expires_at: 0,
            active: true,
            is_primary: true,
        }],
        registered_at: NOW,
        updated_at: NOW + 1,
        status: "Active".to_string(),
        stake_amount: 0,
        metadata: Some("{}".to_string()),
    }
}

/// One explicit request per operation, with the operation it must decode to.
fn every_operation() -> Vec<(DocClassBuildOpRequest, DocClassOperation)> {
    let kp = issuer();
    let from = kp.address().to_base58();
    let holder = KeyPair::from_bytes([0x13; 32]).address().to_base58();
    vec![
        (
            DocClassBuildOpRequest::RegisterAcademicIssuer {
                name: "Example Institute".into(),
                jurisdiction: "US".into(),
                subcodes: vec![810, 811],
                stake_amount: 1_000,
                public_key: hex::encode(kp.public_key().as_bytes()),
                registered_at: Some(NOW),
                metadata: None,
            },
            DocClassOperation::RegisterIssuer,
        ),
        (
            DocClassBuildOpRequest::IssueAcademicCredential {
                holder_address: holder,
                subcode: 811,
                subject_commitment: hex32(0x31),
                schema_hash: hex32(0x32),
                content_commitment: hex32(0x33),
                institution_id: Some("Example Institute".into()),
                jurisdiction: Some("US".into()),
                metadata: DocClassCredentialMetadataRecord {
                    title: "Bachelor of Science".into(),
                    credential_type: "undergraduate_degree".into(),
                    program: None,
                    issue_date: "2026-05-15".into(),
                    completion_date: None,
                    attributes: vec![DocClassAttributeRecord {
                        name: "degree_level".into(),
                        value: "undergraduate".into(),
                    }],
                },
                issued_at: Some(NOW),
                valid_from: NOW,
                expires_at: 0,
                payload_hash: None,
                payload_hint: None,
            },
            DocClassOperation::IssueCredential,
        ),
        (
            DocClassBuildOpRequest::RevokeCredential {
                credential_id: hex32(0x41),
                reason: 1,
            },
            DocClassOperation::RevokeCredential,
        ),
        (
            DocClassBuildOpRequest::SuspendCredential {
                credential_id: hex32(0x41),
                reason: 6,
            },
            DocClassOperation::SuspendCredential,
        ),
        (
            DocClassBuildOpRequest::ReactivateCredential {
                credential_id: hex32(0x41),
            },
            DocClassOperation::ReactivateCredential,
        ),
        (
            DocClassBuildOpRequest::SupersedeCredential {
                old_credential_id: hex32(0x41),
                new_credential_id: hex32(0x42),
            },
            DocClassOperation::SupersedeCredential,
        ),
        (
            DocClassBuildOpRequest::UpdateIssuer {
                issuer: issuer_record(&from),
            },
            DocClassOperation::UpdateIssuer,
        ),
        (
            DocClassBuildOpRequest::RotateIssuerKey {
                new_key: DocClassIssuerKeyRecord {
                    key_id: "rotated".into(),
                    public_key: hex::encode(
                        KeyPair::from_bytes([0x14; 32]).public_key().as_bytes(),
                    ),
                    key_type: "Ed25519".into(),
                    added_at: NOW,
                    expires_at: 0,
                    active: true,
                    is_primary: true,
                },
                old_key_id: "primary".into(),
            },
            DocClassOperation::RotateIssuerKey,
        ),
        (
            DocClassBuildOpRequest::DeactivateIssuer {
                issuer_address: from,
            },
            DocClassOperation::DeactivateIssuer,
        ),
    ]
}

fn decode(hex_tx: &str) -> TransactionV2 {
    bincode::deserialize(&hex::decode(hex_tx.strip_prefix("0x").unwrap()).unwrap()).unwrap()
}

#[tokio::test]
async fn the_builder_and_a_local_build_agree_for_every_operation() {
    let node = serve();
    let kp = issuer();
    for (op, expected) in every_operation() {
        let request = DocClassBuildRequest {
            from: kp.address().to_base58(),
            fee: Some(1_000_000),
            nonce: Some(12),
            chain_id: Some(CHAIN_ID),
            op: op.clone(),
        };
        let reply = node
            .server
            .docclass_build_transaction(request)
            .await
            .unwrap();

        let local_op = op_from_request(&op, &DocClassRequestDefaults::default()).unwrap();
        let local = build_docclass_tx(
            &DocClassTxContext {
                chain_id: CHAIN_ID,
                from: kp.address(),
                nonce: 12,
                fee: 1_000_000,
            },
            &local_op,
        )
        .unwrap();
        assert_eq!(
            reply.tx.unsigned_tx,
            format!("0x{}", hex::encode(local.tx.to_bytes())),
            "{expected:?}: bytes"
        );
        assert_eq!(
            reply.tx.signing_hash,
            format!("0x{}", hex::encode(local.tx.signing_hash().as_bytes())),
            "{expected:?}: signing hash"
        );
        assert_eq!(
            reply.credential_id,
            local
                .credential_id
                .map(|id| format!("0x{}", hex::encode(id)))
        );

        let tx = decode(&reply.tx.unsigned_tx);
        assert_eq!(tx.from, kp.address());
        match tx.payload {
            TxPayload::DocClass(d) => assert_eq!(d.operation, expected),
            other => panic!("{expected:?}: wrong payload {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_builder_reads_state_and_writes_none() {
    let node = serve();
    let kp = issuer();
    let nonce_before = node.state.get_nonce(&kp.address()).unwrap();
    for (op, _) in every_operation() {
        let reply = node
            .server
            .docclass_build_transaction(DocClassBuildRequest {
                from: kp.address().to_base58(),
                fee: None,
                nonce: None,
                chain_id: None,
                op,
            })
            .await
            .unwrap();
        assert_eq!(reply.tx.nonce, nonce_before, "the current nonce, unchanged");
        assert_eq!(reply.tx.chain_id, CHAIN_ID);
    }
    assert_eq!(node.state.get_nonce(&kp.address()).unwrap(), nonce_before);
    assert!(node.mempool.is_empty(), "nothing was admitted");
    assert!(DocClassIssuerStore::new(&node.db)
        .get(&kp.address())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_issue_takes_omitted_fields_from_the_senders_issuer_record() {
    let node = serve();
    let kp = issuer();
    let (op, _) = every_operation().remove(1);
    let DocClassBuildOpRequest::IssueAcademicCredential { .. } = &op else {
        unreachable!()
    };
    let mut omitted = op.clone();
    if let DocClassBuildOpRequest::IssueAcademicCredential {
        institution_id,
        jurisdiction,
        ..
    } = &mut omitted
    {
        *institution_id = None;
        *jurisdiction = None;
    }
    let request = || DocClassBuildRequest {
        from: kp.address().to_base58(),
        fee: Some(1_000_000),
        nonce: Some(3),
        chain_id: Some(CHAIN_ID),
        op: omitted.clone(),
    };

    // No record: refused, naming the field.
    let err = node
        .server
        .docclass_build_transaction(request())
        .await
        .unwrap_err();
    assert!(
        err.message().contains("institution_id"),
        "{}",
        err.message()
    );

    // With a record: filled from it, and equal to the explicit request.
    DocClassIssuerStore::new(&node.db)
        .put(&DocClassIssuer {
            address: kp.address(),
            name: "Example Institute".to_string(),
            issuer_type: DocClassIssuerType::Educational,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::Diploma],
            keys: vec![],
            registered_at: NOW,
            updated_at: NOW,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        })
        .unwrap();
    let filled = node
        .server
        .docclass_build_transaction(request())
        .await
        .unwrap();
    let explicit = node
        .server
        .docclass_build_transaction(DocClassBuildRequest { op, ..request() })
        .await
        .unwrap();
    assert_eq!(filled.tx.signing_hash, explicit.tx.signing_hash);
}

#[tokio::test]
async fn refusals_name_the_rule_and_not_the_value() {
    let node = serve();
    let kp = issuer();

    // A public key that is not the sender's.
    let err = node
        .server
        .docclass_build_transaction(DocClassBuildRequest {
            from: kp.address().to_base58(),
            fee: None,
            nonce: None,
            chain_id: None,
            op: DocClassBuildOpRequest::RegisterAcademicIssuer {
                name: "Example Institute".into(),
                jurisdiction: "US".into(),
                subcodes: vec![811],
                stake_amount: 0,
                public_key: hex32(0x44),
                registered_at: None,
                metadata: None,
            },
        })
        .await
        .unwrap_err();
    assert!(
        err.message().contains("does not derive to the sender"),
        "{}",
        err.message()
    );
    assert!(!err.message().contains(&hex32(0x44)));

    // Malformed hex: the field is named, the value is not repeated.
    let bad = "not-hex-value-zz";
    let err = node
        .server
        .docclass_build_transaction(DocClassBuildRequest {
            from: kp.address().to_base58(),
            fee: None,
            nonce: None,
            chain_id: None,
            op: DocClassBuildOpRequest::RevokeCredential {
                credential_id: bad.into(),
                reason: 0,
            },
        })
        .await
        .unwrap_err();
    assert!(err.message().contains("credential_id"), "{}", err.message());
    assert!(!err.message().contains(bad));
}

#[test]
fn the_request_uses_the_documented_json_shape() {
    let request = DocClassBuildRequest {
        from: issuer().address().to_base58(),
        fee: None,
        nonce: Some(1),
        chain_id: None,
        op: DocClassBuildOpRequest::DeactivateIssuer {
            issuer_address: issuer().address().to_base58(),
        },
    };
    let v = serde_json::to_value(&request).unwrap();
    assert_eq!(v["op"], "deactivate_issuer");
    assert!(v.get("private_key").is_none());
    let back: DocClassBuildRequest = serde_json::from_value(v).unwrap();
    assert_eq!(back, request);
}
