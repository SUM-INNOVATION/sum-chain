//! `messaging_submitSponsored` applies the envelope form of the block the
//! relayed transaction would land in: the string form below
//! `messaging_sponsored_envelope_verification_enabled_from_height`, the
//! version-2 envelope (strict signature, no amount, the sender's current
//! messaging nonce) from it on, judged at the next block's height. And
//! `messaging_getSenderNonce` reports the committed messaging nonce a client
//! must put in that envelope.
//!
//! One test function: the relay reads its sponsor key from the
//! `SUMAIL_SPONSOR_KEY` environment variable, which is process-wide.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, RegisteredPublicKey, SRC201_MAGIC, SRC201_NONCE_SIZE,
    SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{sponsored_send_v2_signing_preimage, SponsoredMessage};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::SubmitSponsoredMessageRequest;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
/// Far in the future, in Unix seconds.
const EXPIRY: u64 = 4_000_000_000;

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}
fn admin() -> KeyPair {
    KeyPair::from_bytes([0x61; 32])
}
/// The registered sender whose envelopes are relayed.
fn carol() -> KeyPair {
    KeyPair::from_bytes([0x64; 32])
}
fn bob() -> KeyPair {
    KeyPair::from_bytes([0x63; 32])
}
/// The relay's own key, read from `SUMAIL_SPONSOR_KEY`.
fn sponsor() -> KeyPair {
    KeyPair::from_bytes([0x65; 32])
}

fn params(envelope_gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p.messaging_sponsored_envelope_verification_enabled_from_height = envelope_gate;
    p
}

fn genesis(envelope_gate: Option<u64>) -> Genesis {
    Genesis::new(
        CHAIN_ID,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([
            (validator().address().to_base58(), 1_000_000u128),
            (sponsor().address().to_base58(), 1_000_000_000u128),
        ]),
        params(envelope_gate),
    )
}

struct Served {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    server: RpcServer,
}

/// A server over a fresh database with no block: the next block is height 1.
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
    let (tx_sender, rx) = mpsc::channel(64);
    // Keep the receiver alive for the server's lifetime, so a broadcast is
    // never refused for want of a listener.
    std::mem::forget(rx);
    let server = RpcServer::with_full_config(
        db.clone(),
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
    .with_genesis(genesis);
    // Carol is registered, as every relayed sender must be.
    MessagingStore::new(&db)
        .set_public_key(
            &carol().address(),
            &RegisteredPublicKey {
                public_key: *carol().public_key().as_bytes(),
                address: carol().address(),
                registered_at_block: 0,
                registered_at: 0,
                updated_at_block: 0,
            },
        )
        .unwrap();
    Served {
        _dir: dir,
        db,
        mempool,
        server,
    }
}

fn valid_message(rh: [u8; 32]) -> Vec<u8> {
    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash: rh,
        ephemeral_pubkey: [2u8; 32],
    };
    let mut v = header.to_bytes().to_vec();
    v.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    v
}

/// Carol's envelope to bob at `nonce`, unsigned; `salt` varies the message so
/// two envelopes at one nonce are different transactions.
fn envelope(nonce: u64, salt: u8, amount: Option<u128>) -> SponsoredMessage {
    let rh = recipient_hash(&bob().address());
    let mut message_data = valid_message(rh);
    message_data.push(salt);
    SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *carol().public_key().as_bytes(),
        nonce,
        expiry: EXPIRY,
        koppa_amount: amount,
    }
}

/// Signed over the version-2 preimage.
fn v2(mut m: SponsoredMessage) -> SponsoredMessage {
    let preimage = sponsored_send_v2_signing_preimage(CHAIN_ID, &m);
    m.signature = *sign(&preimage, carol().private_key()).as_bytes();
    m
}

/// Signed over the string form the relay checked before the gate.
fn v1(mut m: SponsoredMessage) -> SponsoredMessage {
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        hex::encode(m.recipient_hash),
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    );
    m.signature = *sign(preimage.as_bytes(), carol().private_key()).as_bytes();
    m
}

/// The request a client sends for `m`.
fn request(m: &SponsoredMessage) -> SubmitSponsoredMessageRequest {
    SubmitSponsoredMessageRequest {
        message_data: format!("0x{}", hex::encode(&m.message_data)),
        recipient_hash: format!("0x{}", hex::encode(m.recipient_hash)),
        signature: format!("0x{}", hex::encode(m.signature)),
        sender_pubkey: format!("0x{}", hex::encode(m.sender_pubkey)),
        nonce: m.nonce,
        expiry: m.expiry,
        koppa_amount: m.koppa_amount.map(|a| a.to_string()),
    }
}

/// The relayed transaction's envelope, decoded from the pool.
fn relayed_envelopes(s: &Served) -> Vec<SponsoredMessage> {
    use sumchain_primitives::{TxInner, TxPayload};
    s.mempool
        .select_for_block(100)
        .iter()
        .map(|tx| match &tx.inner {
            TxInner::V2(v2) => match &v2.payload {
                TxPayload::Messaging(d) => bincode::deserialize(&d.data).unwrap(),
                other => panic!("not a messaging payload: {other:?}"),
            },
            other => panic!("not a V2 transaction: {other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn the_relay_applies_the_envelope_form_of_the_next_block() {
    // The relay's sponsor key, as `SUMAIL_SPONSOR_KEY` names it.
    let key_dir = tempfile::TempDir::new().unwrap();
    let key_path = key_dir.path().join("sumail.json");
    std::fs::write(
        &key_path,
        serde_json::to_string(sponsor().private_key().as_bytes()).unwrap(),
    )
    .unwrap();
    std::env::set_var("SUMAIL_SPONSOR_KEY", &key_path);

    // ── the gate absent: the string form, as before ─────────────────────────
    {
        let s = serve(&genesis(None));
        let ok = s
            .server
            .messaging_submit_sponsored(request(&v1(envelope(0, 1, None))))
            .await;
        assert!(ok.is_ok(), "{ok:?}");
        let err = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(0, 2, None))))
            .await
            .expect_err("a version-2 signature is not the string form");
        assert!(err.message().contains("Invalid sender signature"), "{err}");
        // The nonce is not read: any value relays.
        let ok = s
            .server
            .messaging_submit_sponsored(request(&v1(envelope(42, 3, None))))
            .await;
        assert!(ok.is_ok(), "{ok:?}");
        let relayed = relayed_envelopes(&s);
        assert_eq!(relayed.len(), 2);
        assert_eq!(
            relayed
                .iter()
                .map(|m| m.nonce)
                .collect::<std::collections::BTreeSet<_>>(),
            [0, 42].into_iter().collect()
        );
        let nonce = s
            .server
            .messaging_get_sender_nonce(carol().address().to_base58())
            .await
            .unwrap();
        assert_eq!(
            (nonce.address, nonce.nonce),
            (carol().address().to_base58(), 0)
        );
    }

    // ── the gate at the next block: the version-2 envelope ──────────────────
    {
        let s = serve(&genesis(Some(1)));
        let err = s
            .server
            .messaging_submit_sponsored(request(&v1(envelope(0, 1, None))))
            .await
            .expect_err("the string form is not a version-2 signature");
        assert!(err.message().contains("version-2"), "{err}");
        let err = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(1, 2, None))))
            .await
            .expect_err("not the sender's current nonce");
        assert!(
            err.message()
                .contains("is not the sender's current messaging nonce 0"),
            "{err}"
        );
        let err = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(0, 3, Some(5)))))
            .await
            .expect_err("an amount is refused");
        assert!(err.message().contains("koppa_amount"), "{err}");
        let err = s
            .server
            .messaging_submit_sponsored(request(&envelope(0, 4, None)))
            .await
            .expect_err("unsigned");
        assert!(err.message().contains("Invalid sender signature"), "{err}");
        assert!(relayed_envelopes(&s).is_empty(), "nothing relayed so far");

        let ok = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(0, 5, None))))
            .await;
        assert!(ok.is_ok(), "{ok:?}");
        let relayed = relayed_envelopes(&s);
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].nonce, 0);
        assert_eq!(relayed[0], v2(envelope(0, 5, None)), "relayed as signed");

        // The committed nonce moves (as a block carrying the envelope would
        // move it); the RPC reports it and the relay requires it.
        MessagingStore::new(&s.db)
            .increment_sender_nonce(&carol().address())
            .unwrap();
        let nonce = s
            .server
            .messaging_get_sender_nonce(carol().address().to_base58())
            .await
            .unwrap();
        assert_eq!(nonce.nonce, 1);
        let err = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(0, 6, None))))
            .await
            .expect_err("nonce 0 is spent");
        assert!(
            err.message()
                .contains("is not the sender's current messaging nonce 1"),
            "{err}"
        );
        let ok = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(1, 7, None))))
            .await;
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(relayed_envelopes(&s).len(), 2);
    }

    // ── the gate above the next block: still the string form ────────────────
    {
        let s = serve(&genesis(Some(2)));
        let ok = s
            .server
            .messaging_submit_sponsored(request(&v1(envelope(0, 1, None))))
            .await;
        assert!(ok.is_ok(), "{ok:?}");
        let err = s
            .server
            .messaging_submit_sponsored(request(&v2(envelope(0, 2, None))))
            .await
            .expect_err("not yet the version-2 form");
        assert!(err.message().contains("Invalid sender signature"), "{err}");
    }
}
