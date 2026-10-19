//! `employment_buildTransaction`: the no-key Employment builder.
//!
//! For every operation the node's builder and a client's local build produce
//! the same bytes and the same signing hash, given the same explicit request.
//! The builder reads state (nonce, chain id, latest block, the sender's issuer
//! record, a stored credential) and writes none, signs nothing and leaves the
//! mempool empty. It is served with the custodial methods off, the default.
//! Every key here is synthetic, derived from a fixed test seed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::employment_build::{
    build_employment_tx, derive_revocation_ref, EmploymentTxContext, RevokeEmploymentPayload,
};
use sumchain_primitives::{
    EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentIssuerStatus,
    EmploymentOperation, EmploymentStatus, EmploymentType, TransactionV2, TxPayload,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::employment_build::{op_from_request, EmploymentRequestDefaults};
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{EmploymentBuildOpRequest, EmploymentBuildRequest};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, EmploymentCredentialStore, EmploymentIssuerStore};
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
    // Custodial signing methods are left at their default: off.
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

fn employee() -> KeyPair {
    KeyPair::from_bytes([0x13; 32])
}

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

/// One explicit request per operation, with the operation it must decode to.
fn every_operation() -> Vec<(EmploymentBuildOpRequest, EmploymentOperation)> {
    vec![
        (
            EmploymentBuildOpRequest::RegisterIssuer {
                issuer_class: "PayrollProcessor".into(),
                display_name: "Example Payroll Ltd".into(),
                issuer_commitment: hex32(0x41),
                jurisdiction_code: "GB".into(),
                policy_id: hex32(0x42),
                registered_at_height: Some(12),
                registered_at: Some(NOW),
            },
            EmploymentOperation::RegisterIssuer,
        ),
        (
            EmploymentBuildOpRequest::CreateEmployment {
                employee_address: employee().address().to_base58(),
                employee_ref: hex32(0x31),
                employer_ref: hex32(0x32),
                tenure_commitment: hex32(0x33),
                role_commitment: Some(hex32(0x34)),
                employment_type: "Contract".into(),
                valid_from: NOW,
                expiry: NOW + 1,
                policy_id: hex32(0x35),
                issuer_name: Some("Example Payroll Ltd".into()),
                issuer_class: Some("PayrollProcessor".into()),
                created_at: Some(NOW),
            },
            EmploymentOperation::CreateEmployment,
        ),
        (
            EmploymentBuildOpRequest::RevokeEmployment {
                employment_id: hex32(0x51),
                employee_address: Some(employee().address().to_base58()),
                revocation_ref: Some(hex32(0x52)),
                revoked_at: None,
                reason: None,
            },
            EmploymentOperation::RevokeEmployment,
        ),
    ]
}

fn decode(hex_tx: &str) -> TransactionV2 {
    bincode::deserialize(&hex::decode(hex_tx.strip_prefix("0x").unwrap()).unwrap()).unwrap()
}

fn request(op: EmploymentBuildOpRequest, nonce: Option<u64>) -> EmploymentBuildRequest {
    EmploymentBuildRequest {
        from: issuer().address().to_base58(),
        fee: Some(1_000_000),
        nonce,
        chain_id: Some(CHAIN_ID),
        op,
    }
}

#[tokio::test]
async fn the_builder_and_a_local_build_agree_for_every_operation() {
    let node = serve();
    let kp = issuer();
    for (op, expected) in every_operation() {
        let reply = node
            .server
            .employment_build_transaction(request(op.clone(), Some(12)))
            .await
            .unwrap();

        let local_op = op_from_request(&op, &EmploymentRequestDefaults::default()).unwrap();
        let local = build_employment_tx(
            &EmploymentTxContext {
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
            reply.employment_id,
            local
                .employment_id
                .map(|id| format!("0x{}", hex::encode(id)))
        );

        let tx = decode(&reply.tx.unsigned_tx);
        assert_eq!(tx.from, kp.address());
        match tx.payload {
            TxPayload::Employment(d) => assert_eq!(d.operation, expected),
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
            .employment_build_transaction(EmploymentBuildRequest {
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
        assert_eq!(reply.tx.fee, 1_000_000, "the custodial methods' fee");
    }
    assert_eq!(node.state.get_nonce(&kp.address()).unwrap(), nonce_before);
    assert!(node.mempool.is_empty(), "nothing was admitted");
    assert!(EmploymentIssuerStore::new(&node.db)
        .get(&kp.address())
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_create_takes_omitted_fields_from_the_senders_issuer_record() {
    let node = serve();
    let kp = issuer();
    let (op, _) = every_operation().remove(1);
    let mut omitted = op.clone();
    if let EmploymentBuildOpRequest::CreateEmployment {
        issuer_name,
        issuer_class,
        ..
    } = &mut omitted
    {
        *issuer_name = None;
        *issuer_class = None;
    }

    // No record: refused, naming the field.
    let err = node
        .server
        .employment_build_transaction(request(omitted.clone(), Some(3)))
        .await
        .unwrap_err();
    assert!(err.message().contains("issuer_name"), "{}", err.message());

    // With a record: filled from it, and equal to the explicit request.
    EmploymentIssuerStore::new(&node.db)
        .put(&EmploymentIssuerProfile {
            issuer_address: kp.address(),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            display_name: "Example Payroll Ltd".to_string(),
            issuer_commitment: [0x41; 32],
            jurisdiction_code: "GB".to_string(),
            policy_id: [0x42; 32],
            status: EmploymentIssuerStatus::Active,
            registered_at_height: 1,
            created_at: NOW,
            updated_at: NOW,
        })
        .unwrap();
    let filled = node
        .server
        .employment_build_transaction(request(omitted, Some(3)))
        .await
        .unwrap();
    let explicit = node
        .server
        .employment_build_transaction(request(op, Some(3)))
        .await
        .unwrap();
    assert_eq!(filled.tx.signing_hash, explicit.tx.signing_hash);
    assert_eq!(filled.employment_id, explicit.employment_id);
}

#[tokio::test]
async fn a_revocation_takes_its_employee_from_the_stored_credential() {
    let node = serve();
    let id = [0x51; 32];
    let omitted = EmploymentBuildOpRequest::RevokeEmployment {
        employment_id: hex::encode(id),
        employee_address: None,
        revocation_ref: None,
        revoked_at: Some(NOW),
        reason: Some("contract ended".into()),
    };

    let err = node
        .server
        .employment_build_transaction(request(omitted.clone(), Some(3)))
        .await
        .unwrap_err();
    assert!(
        err.message().contains("employee_address"),
        "{}",
        err.message()
    );

    EmploymentCredentialStore::new(&node.db)
        .put(&EmploymentCredential {
            employment_id: id,
            employee_address: employee().address(),
            employee_ref: [0x31; 32],
            employer_ref: [0x32; 32],
            status: EmploymentStatus::Active,
            tenure_commitment: [0x33; 32],
            role_commitment: None,
            employment_type: EmploymentType::FullTime,
            valid_from: NOW,
            expiry: 0,
            policy_id: [0x35; 32],
            revocation_ref: None,
            issuer_address: issuer().address(),
            issuer_name: "Example Payroll Ltd".to_string(),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            created_at: NOW,
            updated_at: NOW,
        })
        .unwrap();
    let reply = node
        .server
        .employment_build_transaction(request(omitted, Some(3)))
        .await
        .unwrap();
    let tx = decode(&reply.tx.unsigned_tx);
    let TxPayload::Employment(d) = tx.payload else {
        panic!("not an Employment payload")
    };
    assert_eq!(d.recipient, employee().address());
    let p: RevokeEmploymentPayload = bincode::deserialize(&d.data).unwrap();
    assert_eq!(p.employment_id, id);
    assert_eq!(
        p.revocation_ref,
        derive_revocation_ref(&id, NOW, Some("contract ended"))
    );
}

#[tokio::test]
async fn refusals_name_the_field_and_not_the_value() {
    let node = serve();

    let bad = "not-hex-value-zz";
    let (mut op, _) = every_operation().remove(1);
    if let EmploymentBuildOpRequest::CreateEmployment { employee_ref, .. } = &mut op {
        *employee_ref = bad.into();
    }
    let err = node
        .server
        .employment_build_transaction(request(op, None))
        .await
        .unwrap_err();
    assert!(err.message().contains("employee_ref"), "{}", err.message());
    assert!(!err.message().contains(bad));

    let (mut op, _) = every_operation().remove(0);
    if let EmploymentBuildOpRequest::RegisterIssuer { issuer_class, .. } = &mut op {
        *issuer_class = "NotAClass-secretlooking".into();
    }
    let err = node
        .server
        .employment_build_transaction(request(op, None))
        .await
        .unwrap_err();
    assert!(err.message().contains("issuer_class"), "{}", err.message());
    assert!(!err.message().contains("secretlooking"));

    let (mut op, _) = every_operation().remove(0);
    if let EmploymentBuildOpRequest::RegisterIssuer { display_name, .. } = &mut op {
        *display_name = String::new();
    }
    let err = node
        .server
        .employment_build_transaction(request(op, None))
        .await
        .unwrap_err();
    assert!(err.message().contains("display name"), "{}", err.message());
}

#[test]
fn the_request_uses_the_documented_json_shape() {
    let request = EmploymentBuildRequest {
        from: issuer().address().to_base58(),
        fee: None,
        nonce: Some(1),
        chain_id: None,
        op: EmploymentBuildOpRequest::RevokeEmployment {
            employment_id: hex32(0x51),
            employee_address: None,
            revocation_ref: None,
            revoked_at: None,
            reason: None,
        },
    };
    let v = serde_json::to_value(&request).unwrap();
    assert_eq!(v["op"], "revoke_employment");
    assert!(v.get("private_key").is_none());
    let back: EmploymentBuildRequest = serde_json::from_value(v).unwrap();
    assert_eq!(back, request);
}
