//! The client-side path is a drop-in replacement for the Employment custodial
//! methods: on the same chain state, each produces the same on-chain effect.
//!
//! For each operation, two identical worlds are set up. In one, the custodial
//! method (flag on) builds and signs the transaction on the server; in the
//! other, the client builds it with `build_employment_tx` and signs it locally,
//! taking the fields the server chose (clock readings, the registered issuer
//! name and class) from the custodial transaction or the shared state. Both
//! transactions run through a real `BlockExecutor`, and the resulting issuer,
//! credential and balance state is compared.
//!
//! - **Register and create:** the unsigned transactions are byte-identical.
//! - **Revoke:** the client payload is the executor's two fields (employment
//!   id, revocation reference). The custodial method appends a timestamp and
//!   the optional reason text, which the executor never reads, so its payload
//!   is the client's followed by those bytes. With the reference derived the
//!   same way, the stored credential is identical.
//!
//! Every key here is synthetic, derived from a fixed test seed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::employment_build::{
    build_employment_tx, derive_revocation_ref, EmploymentBuildOp, EmploymentCredentialInput,
    EmploymentTxContext,
};
use sumchain_primitives::{
    Address, EmploymentCredential, EmploymentIssuerClass, EmploymentIssuerProfile,
    EmploymentIssuerStatus, EmploymentStatus, EmploymentType, SignedTransaction, TransactionV2,
    TxInner, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::custodial::{CustodialKeyHex, CustodialSigningMethods};
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    CreateEmploymentCredentialRequest, RegisterEmploymentIssuerRequest,
    RevokeEmploymentCredentialRequest,
};
use sumchain_state::{BlockExecutor, EmploymentExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::AccountState;
use sumchain_storage::{Database, EmploymentCredentialStore, EmploymentIssuerStore, StateStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const FEE: u128 = 1_000_000;
const NOW: u64 = 1_750_000_000_000;
const FUNDS: u128 = 10_000_000_000_000_000;

/// Synthetic issuer key: a fixed test seed, never a real key.
const SEED: [u8; 32] = [0x21; 32];

fn issuer() -> KeyPair {
    KeyPair::from_bytes(SEED)
}
fn employee() -> Address {
    KeyPair::from_bytes([0x23; 32]).address()
}

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

struct World {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    executor: BlockExecutor,
    rx: mpsc::Receiver<SignedTransaction>,
    server: RpcServer,
}

fn world() -> World {
    let validator = KeyPair::from_bytes([7u8; 32]);
    let genesis = Genesis::new(
        CHAIN_ID,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
        params(),
    );
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    StateStore::new(&db)
        .put_account(
            &issuer().address(),
            &AccountState {
                balance: FUNDS,
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
    let server = RpcServer::with_full_config(
        db.clone(),
        state.clone(),
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
    .with_genesis(&genesis)
    .with_custodial_signing_methods(CustodialSigningMethods {
        docclass: false,
        employment: true,
    });
    let executor = BlockExecutor::new(state, db.clone(), params());
    World {
        _dir: dir,
        db,
        executor,
        rx,
        server,
    }
}

/// Run `tx` as the only transaction of a candidate block, then read from the
/// candidate's state.
fn execute<R>(
    w: &World,
    tx: &SignedTransaction,
    read: impl FnOnce(&ExecutionView<'_, '_>) -> R,
) -> R {
    let mut overlay = ApplicationOverlay::new(&w.db, sumchain_state::MAX_BLOCK_WRITE_SET_BYTES);
    let mut view = ExecutionView::new(&mut overlay);
    let r = w
        .executor
        .execute_tx(&mut view, tx, &Address::new([9; 20]), 1, NOW)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    read(&view)
}

fn client_signed(nonce: u64, op: &EmploymentBuildOp) -> (SignedTransaction, Option<[u8; 32]>) {
    let kp = issuer();
    let ctx = EmploymentTxContext {
        chain_id: CHAIN_ID,
        from: kp.address(),
        nonce,
        fee: FEE,
    };
    let built = build_employment_tx(&ctx, op).unwrap();
    let sig = sign(built.tx.signing_hash().as_bytes(), kp.private_key());
    (
        SignedTransaction::new_v2(built.tx, *sig.as_bytes(), *kp.public_key().as_bytes()),
        built.employment_id,
    )
}

fn unsigned(tx: &SignedTransaction) -> &TransactionV2 {
    match &tx.inner {
        TxInner::V2(t) => t,
        other => panic!("not V2: {other:?}"),
    }
}

fn payload(tx: &SignedTransaction) -> Vec<u8> {
    match &unsigned(tx).payload {
        TxPayload::Employment(d) => d.data.clone(),
        other => panic!("not an Employment payload: {other:?}"),
    }
}

fn balance(view: &ExecutionView<'_, '_>) -> u128 {
    StateManager::v_get_balance(view, &issuer().address()).unwrap()
}

/// An issuer profile already on chain, identical in both worlds.
fn seed_issuer(w: &World) -> EmploymentIssuerProfile {
    let profile = EmploymentIssuerProfile {
        issuer_address: issuer().address(),
        issuer_class: EmploymentIssuerClass::Employer,
        display_name: "Example Employer Inc".to_string(),
        issuer_commitment: [0x41; 32],
        jurisdiction_code: "US".to_string(),
        policy_id: [0x42; 32],
        status: EmploymentIssuerStatus::Active,
        registered_at_height: 1,
        created_at: NOW,
        updated_at: NOW,
    };
    EmploymentIssuerStore::new(&w.db).put(&profile).unwrap();
    profile
}

/// A credential already on chain, identical in both worlds.
fn seed_credential(w: &World) -> EmploymentCredential {
    let credential = EmploymentCredential {
        employment_id: [0x51; 32],
        employee_address: employee(),
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
        issuer_name: "Example Employer Inc".to_string(),
        issuer_class: EmploymentIssuerClass::Employer,
        created_at: NOW,
        updated_at: NOW,
    };
    EmploymentCredentialStore::new(&w.db)
        .put(&credential)
        .unwrap();
    credential
}

#[tokio::test]
async fn register_issuer_is_byte_identical_and_has_the_same_effect() {
    let kp = issuer();

    let mut custodial = world();
    let r = custodial
        .server
        .employment_register_issuer(RegisterEmploymentIssuerRequest {
            private_key: CustodialKeyHex::new(hex::encode(SEED)),
            issuer_class: "Employer".to_string(),
            display_name: "Example Employer Inc".to_string(),
            issuer_commitment: hex::encode([0x41; 32]),
            jurisdiction_code: "US".to_string(),
            policy_id: hex::encode([0x42; 32]),
        })
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let a_tx = custodial.rx.try_recv().unwrap();
    // The fields the server filled from its own clock and chain head.
    let chosen: EmploymentIssuerProfile = bincode::deserialize(&payload(&a_tx)).unwrap();
    let (a_issuer, a_balance) = execute(&custodial, &a_tx, |v| {
        (
            EmploymentExecutor::v_get_issuer(v, &kp.address())
                .unwrap()
                .expect("registered"),
            balance(v),
        )
    });

    let client = world();
    let (b_tx, _) = client_signed(
        0,
        &EmploymentBuildOp::RegisterIssuer {
            issuer_class: EmploymentIssuerClass::Employer,
            display_name: "Example Employer Inc".to_string(),
            issuer_commitment: [0x41; 32],
            jurisdiction_code: "US".to_string(),
            policy_id: [0x42; 32],
            registered_at_height: chosen.registered_at_height,
            registered_at: chosen.created_at,
        },
    );
    assert_eq!(
        unsigned(&a_tx),
        unsigned(&b_tx),
        "the same unsigned transaction"
    );
    assert_eq!(
        unsigned(&a_tx).signing_hash(),
        unsigned(&b_tx).signing_hash()
    );
    let (b_issuer, b_balance) = execute(&client, &b_tx, |v| {
        (
            EmploymentExecutor::v_get_issuer(v, &kp.address())
                .unwrap()
                .expect("registered"),
            balance(v),
        )
    });

    assert_eq!(a_issuer, b_issuer);
    assert_eq!(a_issuer.status, EmploymentIssuerStatus::Active);
    assert_eq!(a_balance, b_balance, "the same fee left the account");
    assert!(a_balance < FUNDS);
}

#[tokio::test]
async fn create_credential_is_byte_identical_and_has_the_same_effect() {
    let mut custodial = world();
    let profile = seed_issuer(&custodial);
    let r = custodial
        .server
        .employment_create_credential(CreateEmploymentCredentialRequest {
            private_key: CustodialKeyHex::new(hex::encode(SEED)),
            employee_address: employee().to_base58(),
            employee_ref: hex::encode([0x31; 32]),
            employer_ref: hex::encode([0x32; 32]),
            tenure_commitment: hex::encode([0x33; 32]),
            role_commitment: Some(hex::encode([0x34; 32])),
            employment_type: "FullTime".to_string(),
            valid_from: NOW,
            expiry: 0,
            policy_id: hex::encode([0x35; 32]),
        })
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let a_id: [u8; 32] = hex::decode(r.employment_id.unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let a_tx = custodial.rx.try_recv().unwrap();
    let chosen: EmploymentCredential = bincode::deserialize(&payload(&a_tx)).unwrap();
    let a_cred = execute(&custodial, &a_tx, |v| {
        EmploymentExecutor::v_get_credential(v, &a_id)
            .unwrap()
            .expect("stored")
    });

    let client = world();
    seed_issuer(&client);
    let (b_tx, b_id) = client_signed(
        0,
        &EmploymentBuildOp::CreateEmployment(EmploymentCredentialInput {
            employee_address: employee(),
            employee_ref: [0x31; 32],
            employer_ref: [0x32; 32],
            tenure_commitment: [0x33; 32],
            role_commitment: Some([0x34; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: NOW,
            expiry: 0,
            policy_id: [0x35; 32],
            // What a client reads with employment_getIssuer.
            issuer_name: profile.display_name.clone(),
            issuer_class: profile.issuer_class,
            created_at: chosen.created_at,
        }),
    );
    let b_id = b_id.unwrap();
    assert_eq!(a_id, b_id, "both paths derive the same employment id");
    assert_eq!(
        unsigned(&a_tx),
        unsigned(&b_tx),
        "the same unsigned transaction"
    );
    let b_cred = execute(&client, &b_tx, |v| {
        EmploymentExecutor::v_get_credential(v, &b_id)
            .unwrap()
            .expect("stored")
    });

    assert_eq!(a_cred, b_cred);
    assert_eq!(a_cred.status, EmploymentStatus::Active);
}

#[tokio::test]
async fn revoke_credential_has_the_same_effect() {
    let reason = "contract ended";

    let mut custodial = world();
    seed_issuer(&custodial);
    let credential = seed_credential(&custodial);
    let id = credential.employment_id;
    let r = custodial
        .server
        .employment_revoke_credential(RevokeEmploymentCredentialRequest {
            private_key: CustodialKeyHex::new(hex::encode(SEED)),
            employment_id: hex::encode(id),
            reason: Some(reason.to_string()),
        })
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let a_ref: [u8; 32] = hex::decode(r.revocation_ref.unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let a_tx = custodial.rx.try_recv().unwrap();
    let a_payload = payload(&a_tx);
    // The custodial payload: id, reference, then the server's timestamp (u64 LE)
    // and the optional reason, which the executor does not read.
    let server_time = u64::from_le_bytes(a_payload[64..72].try_into().unwrap());
    let a_cred = execute(&custodial, &a_tx, |v| {
        EmploymentExecutor::v_get_credential(v, &id)
            .unwrap()
            .expect("stored")
    });

    let client = world();
    seed_issuer(&client);
    seed_credential(&client);
    let b_ref = derive_revocation_ref(&id, server_time, Some(reason));
    assert_eq!(a_ref, b_ref, "the same derivation as the custodial method");
    let (b_tx, _) = client_signed(
        0,
        &EmploymentBuildOp::RevokeEmployment {
            employment_id: id,
            employee_address: credential.employee_address,
            revocation_ref: b_ref,
        },
    );
    let b_payload = payload(&b_tx);
    assert_eq!(b_payload.len(), 64);
    assert_eq!(
        &a_payload[..64],
        &b_payload[..],
        "the custodial payload is the client's followed by fields the executor ignores"
    );
    assert!(
        !b_payload
            .windows(reason.len())
            .any(|w| w == reason.as_bytes()),
        "the client transaction does not carry the reason text"
    );
    let b_cred = execute(&client, &b_tx, |v| {
        EmploymentExecutor::v_get_credential(v, &id)
            .unwrap()
            .expect("stored")
    });

    assert_eq!(a_cred, b_cred);
    assert_eq!(a_cred.status, EmploymentStatus::Ended);
    assert_eq!(a_cred.revocation_ref, Some(b_ref));
}
