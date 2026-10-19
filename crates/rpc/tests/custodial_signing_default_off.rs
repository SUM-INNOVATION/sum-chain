//! The six custodial signing methods (they take a caller's raw private key)
//! are off by default.
//!
//! Off, each answers with one fixed error (-32005) before it uses the key or
//! any other field, queues nothing and broadcasts nothing; the message names
//! the client-side replacement and carries nothing from the request. The two
//! families are enabled separately, and on, the methods still serve existing
//! clients. A malformed key gets a fixed message that repeats nothing from it,
//! and no request type's `Debug` output shows its key.
//!
//! Every key here is synthetic, derived from a fixed test seed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::SignedTransaction;
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::custodial::{
    CustodialKeyHex, CustodialSigningMethods, CUSTODIAL_KEY_NOT_HEX, CUSTODIAL_KEY_WRONG_LENGTH,
    DOCCLASS_CUSTODIAL_DISABLED, EMPLOYMENT_CUSTODIAL_DISABLED,
};
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    CreateEmploymentCredentialRequest, IssueAcademicCredentialRequest,
    RegisterAcademicIssuerRequest, RegisterEmploymentIssuerRequest,
    RevokeAcademicCredentialRequest, RevokeEmploymentCredentialRequest,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::schema::AccountState;
use sumchain_storage::{Database, StateStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const DISABLED: i32 = -32005;

/// Synthetic issuer key: a fixed test seed, never a real key.
const SEED: [u8; 32] = [0x21; 32];

fn key_hex() -> String {
    hex::encode(SEED)
}

fn issuer() -> KeyPair {
    KeyPair::from_bytes(SEED)
}

struct Node {
    _dir: tempfile::TempDir,
    mempool: Arc<Mempool>,
    rx: mpsc::Receiver<SignedTransaction>,
    server: RpcServer,
}

fn serve(custodial: Option<CustodialSigningMethods>) -> Node {
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
    // The issuer can pay a stake and fees.
    StateStore::new(&db)
        .put_account(
            &issuer().address(),
            &AccountState {
                balance: 10_000_000_000_000,
                nonce: 0,
            },
        )
        .unwrap();
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
    let (tx_sender, rx) = mpsc::channel(8);
    let mut server = RpcServer::with_full_config(
        db,
        state,
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
    if let Some(c) = custodial {
        server = server.with_custodial_signing_methods(c);
    }
    Node {
        _dir: dir,
        mempool,
        rx,
        server,
    }
}

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

fn register_academic(key: &str) -> RegisterAcademicIssuerRequest {
    RegisterAcademicIssuerRequest {
        private_key: CustodialKeyHex::from(key),
        institution_name: "Example Institute".to_string(),
        institution_type: "University".to_string(),
        jurisdiction_code: "US".to_string(),
        authorized_subcodes: vec![811],
        stake_amount: "1000000000".to_string(),
    }
}

fn issue_academic(key: &str) -> IssueAcademicCredentialRequest {
    IssueAcademicCredentialRequest {
        private_key: CustodialKeyHex::from(key),
        subcode: 811,
        holder_address: KeyPair::from_bytes([0x23; 32]).address().to_base58(),
        subject_commitment: hex32(0x31),
        schema_hash: hex32(0x32),
        content_commitment: hex32(0x33),
        attributes: vec![],
        metadata: None,
        valid_from: 0,
        expires_at: 0,
    }
}

fn revoke_academic(key: &str) -> RevokeAcademicCredentialRequest {
    RevokeAcademicCredentialRequest {
        private_key: CustodialKeyHex::from(key),
        credential_id: hex32(0x41),
        reason: Some(0),
        reason_details: None,
    }
}

fn register_employment(key: &str) -> RegisterEmploymentIssuerRequest {
    RegisterEmploymentIssuerRequest {
        private_key: CustodialKeyHex::from(key),
        issuer_class: "Employer".to_string(),
        display_name: "Example Employer".to_string(),
        issuer_commitment: hex32(0x51),
        jurisdiction_code: "US".to_string(),
        policy_id: hex32(0x52),
    }
}

fn create_employment(key: &str) -> CreateEmploymentCredentialRequest {
    CreateEmploymentCredentialRequest {
        private_key: CustodialKeyHex::from(key),
        employee_address: KeyPair::from_bytes([0x24; 32]).address().to_base58(),
        employee_ref: hex32(0x61),
        employer_ref: hex32(0x62),
        tenure_commitment: hex32(0x63),
        role_commitment: None,
        employment_type: "FullTime".to_string(),
        valid_from: 0,
        expiry: 0,
        policy_id: hex32(0x52),
    }
}

fn revoke_employment(key: &str) -> RevokeEmploymentCredentialRequest {
    RevokeEmploymentCredentialRequest {
        private_key: CustodialKeyHex::from(key),
        employment_id: hex32(0x71),
        reason: None,
    }
}

/// Call all six with `key`, returning (method, family message expected when
/// off, the error each returned, if any).
async fn call_all(
    server: &RpcServer,
    key: &str,
) -> Vec<(&'static str, &'static str, Option<(i32, String)>)> {
    fn err<T>(r: Result<T, jsonrpsee::types::ErrorObjectOwned>) -> Option<(i32, String)> {
        r.err().map(|e| (e.code(), e.message().to_string()))
    }
    vec![
        (
            "docclass_registerAcademicIssuer",
            DOCCLASS_CUSTODIAL_DISABLED,
            err(server
                .docclass_register_academic_issuer(register_academic(key))
                .await),
        ),
        (
            "docclass_issueAcademicCredential",
            DOCCLASS_CUSTODIAL_DISABLED,
            err(server
                .docclass_issue_academic_credential(issue_academic(key))
                .await),
        ),
        (
            "docclass_revokeAcademicCredential",
            DOCCLASS_CUSTODIAL_DISABLED,
            err(server
                .docclass_revoke_academic_credential(revoke_academic(key))
                .await),
        ),
        (
            "employment_registerIssuer",
            EMPLOYMENT_CUSTODIAL_DISABLED,
            err(server
                .employment_register_issuer(register_employment(key))
                .await),
        ),
        (
            "employment_createCredential",
            EMPLOYMENT_CUSTODIAL_DISABLED,
            err(server
                .employment_create_credential(create_employment(key))
                .await),
        ),
        (
            "employment_revokeCredential",
            EMPLOYMENT_CUSTODIAL_DISABLED,
            err(server
                .employment_revoke_credential(revoke_employment(key))
                .await),
        ),
    ]
}

#[tokio::test]
async fn every_custodial_method_is_refused_by_default() {
    let mut node = serve(None);
    assert_eq!(
        node.server.custodial_signing_methods(),
        CustodialSigningMethods::default()
    );
    // A well-formed key, a malformed one and an empty one: the refusal comes
    // first, so it is the same for all three.
    for key in [key_hex(), "zz".repeat(32), String::new()] {
        for (method, expected, got) in call_all(&node.server, &key).await {
            let (code, message) = got.unwrap_or_else(|| panic!("{method} answered while disabled"));
            assert_eq!(code, DISABLED, "{method}");
            assert_eq!(message, expected, "{method}: the refusal text is fixed");
            if !key.is_empty() {
                assert!(
                    !message.contains(&key[..8]),
                    "{method}: the refusal must not repeat the key"
                );
            }
        }
    }
    assert_eq!(node.mempool.len(), 0, "nothing was queued");
    assert!(node.rx.try_recv().is_err(), "nothing was broadcast");
}

#[test]
fn the_disabled_messages_name_the_replacement_and_nothing_else() {
    assert!(DOCCLASS_CUSTODIAL_DISABLED.contains("docclass_buildTransaction"));
    assert!(DOCCLASS_CUSTODIAL_DISABLED.contains("sumchain docclass"));
    assert!(DOCCLASS_CUSTODIAL_DISABLED.contains("send_raw_transaction"));
    assert!(EMPLOYMENT_CUSTODIAL_DISABLED.contains("no client-side builder yet"));
    assert!(EMPLOYMENT_CUSTODIAL_DISABLED.contains("unsafe_custodial_employment_methods"));
    for m in [DOCCLASS_CUSTODIAL_DISABLED, EMPLOYMENT_CUSTODIAL_DISABLED] {
        assert!(!m.contains("{}"), "fixed text, no formatting slot");
    }
}

#[tokio::test]
async fn the_two_families_are_enabled_separately() {
    let mut node = serve(Some(CustodialSigningMethods {
        docclass: true,
        employment: false,
    }));
    for (method, expected, got) in call_all(&node.server, &key_hex()).await {
        if method.starts_with("employment_") {
            let (code, message) = got.expect("employment stays off");
            assert_eq!((code, message.as_str()), (DISABLED, expected), "{method}");
        } else if let Some((code, _)) = got {
            assert_ne!(code, DISABLED, "{method}: docclass is on");
        }
    }
    // The DocClass registration went through to the mempool and the network.
    let sent = node
        .rx
        .try_recv()
        .expect("the docclass registration was broadcast");
    assert_eq!(sent.sender(), issuer().address());

    let node = serve(Some(CustodialSigningMethods {
        docclass: false,
        employment: true,
    }));
    for (method, expected, got) in call_all(&node.server, &key_hex()).await {
        if method.starts_with("docclass_") {
            let (code, message) = got.expect("docclass stays off");
            assert_eq!((code, message.as_str()), (DISABLED, expected), "{method}");
        } else if let Some((code, _)) = got {
            assert_ne!(code, DISABLED, "{method}: employment is on");
        }
    }
}

#[tokio::test]
async fn with_the_flag_on_existing_clients_are_still_served() {
    let mut node = serve(Some(CustodialSigningMethods {
        docclass: true,
        employment: true,
    }));
    let r = node
        .server
        .docclass_register_academic_issuer(register_academic(&key_hex()))
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    assert_eq!(r.issuer_address, issuer().address().to_base58());
    let sent = node.rx.try_recv().unwrap();
    assert_eq!(sent.sender(), issuer().address());
    assert!(sumchain_crypto::verify_bytes(
        sent.signing_hash().as_bytes(),
        &sent.signature,
        &sent.public_key
    )
    .is_ok());

    let r = node
        .server
        .employment_register_issuer(register_employment(&key_hex()))
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    assert_eq!(r.issuer_address, issuer().address().to_base58());
    assert_eq!(node.mempool.len(), 2);
}

#[tokio::test]
async fn malformed_keys_get_fixed_messages_that_repeat_nothing() {
    let node = serve(Some(CustodialSigningMethods {
        docclass: true,
        employment: true,
    }));
    // Not hex: one fixed -32602 message whatever the bad character and its
    // position.
    let not_hex = [
        "zz".repeat(32),
        format!("{}Q{}", "21".repeat(10), "2".repeat(43)),
        format!("0x{}", "21".repeat(31)) + "2",
    ];
    for key in &not_hex {
        for (method, _, got) in call_all(&node.server, key).await {
            let (code, message) =
                got.unwrap_or_else(|| panic!("{method} accepted a malformed key"));
            assert_eq!(code, -32602, "{method}");
            assert_eq!(message, CUSTODIAL_KEY_NOT_HEX, "{method}");
        }
    }
    // Hex of the wrong length: the response shape these methods always used,
    // with fixed text.
    let short = "21".repeat(31);
    let r = node
        .server
        .docclass_register_academic_issuer(register_academic(&short))
        .await
        .unwrap();
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some(CUSTODIAL_KEY_WRONG_LENGTH));
    let r = node
        .server
        .employment_revoke_credential(revoke_employment(&short))
        .await
        .unwrap();
    assert!(!r.success);
    assert_eq!(r.error.as_deref(), Some(CUSTODIAL_KEY_WRONG_LENGTH));
}

#[test]
fn no_request_type_shows_its_key_in_debug_output() {
    let k = key_hex();
    let shown = [
        format!("{:?}", register_academic(&k)),
        format!("{:?}", issue_academic(&k)),
        format!("{:?}", revoke_academic(&k)),
        format!("{:?}", register_employment(&k)),
        format!("{:?}", create_employment(&k)),
        format!("{:?}", revoke_employment(&k)),
    ];
    for s in &shown {
        assert!(!s.contains(&k[..8]), "key material in Debug output: {s}");
        assert!(s.contains("CustodialKeyHex(<redacted>)"), "{s}");
    }
}

#[test]
fn the_wire_format_of_existing_requests_is_unchanged() {
    // An existing client's JSON, with the key as a plain hex string, still
    // deserializes, and serializes back to the same JSON.
    let json = serde_json::json!({
        "private_key": key_hex(),
        "institution_name": "Example Institute",
        "institution_type": "University",
        "jurisdiction_code": "US",
        "authorized_subcodes": [811],
        "stake_amount": "1000000000",
    });
    let req: RegisterAcademicIssuerRequest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&req).unwrap(), json);
}
