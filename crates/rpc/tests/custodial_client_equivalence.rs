//! The client-side path is a drop-in replacement for the DocClass custodial
//! methods: on the same chain state, each produces the same on-chain effect.
//!
//! For each operation, two identical worlds are set up. In one, the custodial
//! method (flag on) builds and signs the transaction on the server; in the
//! other, the client builds it with `build_docclass_tx` and signs it locally.
//! Both transactions run through a real `BlockExecutor`, and the resulting
//! issuer, credential, revocation and balance state is compared.
//!
//! What differs, by design, and is not compared:
//! - the issuer key id: the custodial path records `"primary-key"`, the
//!   builder `"primary"`;
//! - credential ids: the custodial path derived its own; the builder uses the
//!   chain's `generate_credential_id`. The chain stores whichever id the
//!   signed payload carries, and each path reports the id it used;
//! - fields the custodial path filled from the server clock (timestamps, a
//!   synthesized title and issue date) and the empty-signature claim.
//!
//! Every key here is synthetic, derived from a fixed test seed.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::docclass_build::{
    build_docclass_tx, AcademicCredentialInput, DocClassBuildOp, DocClassTxContext,
};
use sumchain_primitives::{
    AcademicCredential, Address, CredentialMetadata, DocClassIssuer, DocClassIssuerStatus,
    DocClassIssuerType, DocSubcode, IssuerKey, KeyType, RevocationReason, RevocationStatus,
    SignedTransaction, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::custodial::{CustodialKeyHex, CustodialSigningMethods};
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    IssueAcademicCredentialRequest, RegisterAcademicIssuerRequest, RevokeAcademicCredentialRequest,
};
use sumchain_state::{BlockExecutor, DocClassExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::AccountState;
use sumchain_storage::{CredentialStore, Database, DocClassIssuerStore, StateStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const FEE: u128 = 1_000_000;
/// The chain's default minimum issuer stake (`DocClassParams::default`), which
/// also clears the custodial method's own, lower, check.
const STAKE: u128 = 1_000_000_000_000;
const NOW: u64 = 1_750_000_000_000;
const FUNDS: u128 = 10_000_000_000_000_000;

/// Synthetic issuer key: a fixed test seed, never a real key.
const SEED: [u8; 32] = [0x21; 32];

fn issuer() -> KeyPair {
    KeyPair::from_bytes(SEED)
}
fn holder() -> Address {
    KeyPair::from_bytes([0x23; 32]).address()
}

/// DocClass activations closed, as a chain that has not scheduled them, with
/// the default DocClass parameters.
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
        docclass: true,
        employment: false,
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

fn client_signed(nonce: u64, op: &DocClassBuildOp) -> (SignedTransaction, Option<[u8; 32]>) {
    let kp = issuer();
    let ctx = DocClassTxContext {
        chain_id: CHAIN_ID,
        from: kp.address(),
        nonce,
        fee: FEE,
    };
    let built = build_docclass_tx(&ctx, op).unwrap();
    let sig = sign(built.tx.signing_hash().as_bytes(), kp.private_key());
    (
        SignedTransaction::new_v2(built.tx, *sig.as_bytes(), *kp.public_key().as_bytes()),
        built.credential_id,
    )
}

/// The parts of an issuer record both paths set from the same input.
fn issuer_effect(i: &DocClassIssuer) -> impl PartialEq + std::fmt::Debug {
    (
        i.address,
        i.name.clone(),
        i.issuer_type,
        i.jurisdictions.clone(),
        i.authorized_subcodes.clone(),
        i.status,
        i.stake_amount,
        i.keys
            .iter()
            .map(|k| {
                (
                    k.public_key,
                    k.key_type,
                    k.active,
                    k.is_primary,
                    k.expires_at,
                )
            })
            .collect::<Vec<_>>(),
    )
}

/// The parts of a credential both paths set from the same input.
fn credential_effect(c: &AcademicCredential) -> impl PartialEq + std::fmt::Debug {
    (
        c.issuer,
        c.subject_address,
        c.subcode,
        c.subject_commitment,
        c.institution_id.clone(),
        c.jurisdiction.clone(),
        c.schema_hash,
        c.content_commitment,
        c.valid_from,
        c.expires_at,
        c.revocation_status,
        c.superseded_by,
    )
}

fn balance(view: &ExecutionView<'_, '_>) -> u128 {
    StateManager::v_get_balance(view, &issuer().address()).unwrap()
}

/// An issuer record already on chain, identical in both worlds.
fn seed_issuer(w: &World) -> DocClassIssuer {
    let kp = issuer();
    let record = DocClassIssuer {
        address: kp.address(),
        name: "Example Institute".to_string(),
        issuer_type: DocClassIssuerType::Educational,
        jurisdictions: vec!["US".to_string()],
        authorized_subcodes: vec![DocSubcode::Diploma],
        keys: vec![IssuerKey {
            key_id: "primary".to_string(),
            public_key: *kp.public_key().as_bytes(),
            key_type: KeyType::Ed25519,
            added_at: NOW,
            expires_at: 0,
            active: true,
            is_primary: true,
        }],
        registered_at: NOW,
        updated_at: NOW,
        status: DocClassIssuerStatus::Active,
        stake_amount: 0,
        metadata: None,
    };
    DocClassIssuerStore::new(&w.db).put(&record).unwrap();
    record
}

fn issue_request() -> IssueAcademicCredentialRequest {
    IssueAcademicCredentialRequest {
        private_key: CustodialKeyHex::new(hex::encode(SEED)),
        subcode: 811,
        holder_address: holder().to_base58(),
        subject_commitment: hex::encode([0x31; 32]),
        schema_hash: hex::encode([0x32; 32]),
        content_commitment: hex::encode([0x33; 32]),
        attributes: vec![],
        metadata: None,
        valid_from: NOW,
        expires_at: 0,
    }
}

fn issue_input() -> AcademicCredentialInput {
    AcademicCredentialInput {
        holder: holder(),
        subcode: DocSubcode::Diploma,
        subject_commitment: [0x31; 32],
        institution_id: "Example Institute".to_string(),
        jurisdiction: "US".to_string(),
        schema_hash: [0x32; 32],
        content_commitment: [0x33; 32],
        metadata: CredentialMetadata {
            title: "Credential 811".to_string(),
            credential_type: "diploma".to_string(),
            program: None,
            issue_date: "2026-01-01".to_string(),
            completion_date: None,
            attributes: vec![],
        },
        issued_at: NOW,
        valid_from: NOW,
        expires_at: 0,
        payload_hash: None,
        payload_hint: None,
    }
}

#[tokio::test]
async fn register_issuer_has_the_same_effect_either_way() {
    let kp = issuer();

    let mut custodial = world();
    let r = custodial
        .server
        .docclass_register_academic_issuer(RegisterAcademicIssuerRequest {
            private_key: CustodialKeyHex::new(hex::encode(SEED)),
            institution_name: "Example Institute".to_string(),
            institution_type: "University".to_string(),
            jurisdiction_code: "US".to_string(),
            authorized_subcodes: vec![811],
            stake_amount: STAKE.to_string(),
        })
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let tx = custodial.rx.try_recv().unwrap();
    let (a_issuer, a_balance) = execute(&custodial, &tx, |v| {
        (
            DocClassExecutor::v_get_docclass_issuer(v, &kp.address())
                .unwrap()
                .expect("registered"),
            balance(v),
        )
    });

    let client = world();
    let (tx, _) = client_signed(
        0,
        &DocClassBuildOp::RegisterAcademicIssuer {
            name: "Example Institute".to_string(),
            jurisdiction: "US".to_string(),
            subcodes: vec![DocSubcode::Diploma],
            stake_amount: STAKE,
            public_key: *kp.public_key().as_bytes(),
            registered_at: NOW,
            metadata: None,
        },
    );
    let (b_issuer, b_balance) = execute(&client, &tx, |v| {
        (
            DocClassExecutor::v_get_docclass_issuer(v, &kp.address())
                .unwrap()
                .expect("registered"),
            balance(v),
        )
    });

    assert_eq!(issuer_effect(&a_issuer), issuer_effect(&b_issuer));
    assert_eq!(a_issuer.status, DocClassIssuerStatus::Active);
    assert_eq!(
        a_balance, b_balance,
        "the same fee and stake left the account"
    );
    assert!(a_balance < FUNDS);
}

#[tokio::test]
async fn issue_credential_has_the_same_effect_either_way() {
    let mut custodial = world();
    seed_issuer(&custodial);
    let r = custodial
        .server
        .docclass_issue_academic_credential(issue_request())
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let a_id: [u8; 32] = hex::decode(r.credential_id.unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let tx = custodial.rx.try_recv().unwrap();
    let (a_cred, a_status, a_balance) = execute(&custodial, &tx, |v| {
        (
            DocClassExecutor::v_get_credential(v, &a_id)
                .unwrap()
                .expect("stored"),
            DocClassExecutor::v_get_revocation_status(v, &a_id).unwrap(),
            balance(v),
        )
    });

    let client = world();
    seed_issuer(&client);
    let (tx, b_id) = client_signed(0, &DocClassBuildOp::IssueAcademicCredential(issue_input()));
    let b_id = b_id.unwrap();
    let (b_cred, b_status, b_balance) = execute(&client, &tx, |v| {
        (
            DocClassExecutor::v_get_credential(v, &b_id)
                .unwrap()
                .expect("stored"),
            DocClassExecutor::v_get_revocation_status(v, &b_id).unwrap(),
            balance(v),
        )
    });

    assert_eq!(credential_effect(&a_cred), credential_effect(&b_cred));
    assert_eq!(
        (a_status, b_status),
        (RevocationStatus::Active, RevocationStatus::Active)
    );
    assert_eq!(a_balance, b_balance, "the same fee left the account");
    // Each path stored the credential under the id it reported.
    assert_eq!(a_cred.credential_id, a_id);
    assert_eq!(b_cred.credential_id, b_id);
}

#[tokio::test]
async fn revoke_credential_has_the_same_effect_either_way() {
    // A credential already on chain, identical in both worlds.
    let credential = |w: &World| {
        let (tx, id) = client_signed(0, &DocClassBuildOp::IssueAcademicCredential(issue_input()));
        let id = id.unwrap();
        let stored = execute(w, &tx, |v| {
            DocClassExecutor::v_get_credential(v, &id).unwrap().unwrap()
        });
        CredentialStore::new(&w.db).put(&stored).unwrap();
        id
    };

    let mut custodial = world();
    seed_issuer(&custodial);
    let id = credential(&custodial);
    let r = custodial
        .server
        .docclass_revoke_academic_credential(RevokeAcademicCredentialRequest {
            private_key: CustodialKeyHex::new(hex::encode(SEED)),
            credential_id: hex::encode(id),
            reason: Some(0),
            reason_details: None,
        })
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.error);
    let tx = custodial.rx.try_recv().unwrap();
    let (a_status, a_balance) = execute(&custodial, &tx, |v| {
        (
            DocClassExecutor::v_get_revocation_status(v, &id).unwrap(),
            balance(v),
        )
    });

    let client = world();
    seed_issuer(&client);
    let same_id = credential(&client);
    assert_eq!(same_id, id);
    let (tx, _) = client_signed(
        0,
        &DocClassBuildOp::RevokeCredential {
            credential_id: id,
            reason: RevocationReason::Unspecified,
        },
    );
    let (b_status, b_balance) = execute(&client, &tx, |v| {
        (
            DocClassExecutor::v_get_revocation_status(v, &id).unwrap(),
            balance(v),
        )
    });

    assert_eq!(a_status, RevocationStatus::Revoked);
    assert_eq!(a_status, b_status);
    assert_eq!(a_balance, b_balance, "the same fee left the account");
}
