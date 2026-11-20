//! Every existing messaging RPC method's response, pinned byte for byte, and
//! parsed by a strict client of its shape.
//!
//! One history, with both messaging gates absent so that execution is the
//! same on every binary that knows them (sponsored registration open): registrations, a stake, a quota, a
//! paid send claimed and one left in escrow, a direct message, a relayed
//! message whose envelope names an amount (executed under the earlier rule),
//! a contact, a block and a spam report. Then every read method, and both
//! write methods, answer, and each response must serialize to exactly the
//! bytes recorded here. The pins were produced by this file's first version,
//! with `TRACK_A_PRINT_PINS=1`, before any method was added: a response that
//! gains a field, loses one, or changes a value fails here.
//!
//! Each response is also parsed by a struct of its shape at that commit with
//! `deny_unknown_fields`, as a strict client of the earlier response would.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ClaimPaymentData, ContactData, ContentType, MessageFlags, MessageHeader,
    MessagingTxData, RegisterPublicKeyData, ReportSpamData, SendMessageData,
    SendMessageWithPaymentData, SetDailyQuotaData, SetSponsorshipEnabledData, StakeForTrustData,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_register_v1_signing_preimage, sponsored_send_v2_signing_preimage, Block, BlockHeader,
    Hash, MessagingOperation, Receipt, SignedTransaction, SponsoredMessage, TransactionV2,
    TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{SponsoredRegistrationRequest, SubmitSponsoredMessageRequest};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 7;
const FEE: u128 = 1_000_000;
const FUNDS: u128 = 1_000_000_000_000_000;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}
fn validator() -> KeyPair {
    key(0x51)
}
fn admin() -> KeyPair {
    key(0x61)
}
fn alice() -> KeyPair {
    key(0x62)
}
fn bob() -> KeyPair {
    key(0x63)
}
fn carol() -> KeyPair {
    key(0x64)
}
fn sponsor() -> KeyPair {
    key(0x65)
}
fn dave() -> KeyPair {
    key(0x66)
}
fn grace() -> KeyPair {
    key(0x69)
}

/// The relay's sponsor key, written once for the whole binary.
fn sponsor_key_configured() {
    static KEY_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    KEY_DIR.get_or_init(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sumail.json");
        std::fs::write(
            &path,
            serde_json::to_string(sponsor().private_key().as_bytes()).unwrap(),
        )
        .unwrap();
        std::env::set_var("SUMAIL_SPONSOR_KEY", &path);
        dir
    });
}

fn genesis() -> Genesis {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        spam_threshold: 3,
        high_spam_threshold: 5,
        ..MessagingParams::default()
    });
    p.messaging_sponsored_registration_enabled_from_height = Some(0);
    let mut alloc = HashMap::new();
    for k in [
        validator(),
        admin(),
        alice(),
        bob(),
        carol(),
        sponsor(),
        dave(),
    ] {
        alloc.insert(k.address().to_base58(), FUNDS);
    }
    Genesis::new(
        CHAIN_ID,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        alloc,
        p,
    )
}

/// The engine's view, except the chain's height and its final height, which
/// are read from the block store (blocks are published here without driving
/// the engine).
struct StoredChain {
    engine: Arc<dyn ConsensusQuery>,
    db: Arc<Database>,
}

impl StoredChain {
    fn tip(&self) -> u64 {
        sumchain_storage::BlockStore::new(&self.db)
            .get_latest_height()
            .unwrap()
            .unwrap_or(0)
    }
}

impl ConsensusQuery for StoredChain {
    fn is_validator(&self) -> bool {
        self.engine.is_validator()
    }
    fn current_height(&self) -> u64 {
        self.tip()
    }
    fn validators(&self) -> Vec<[u8; 32]> {
        self.engine.validators()
    }
    fn get_proposer(&self, height: u64) -> [u8; 32] {
        self.engine.get_proposer(height)
    }
    fn finalized_height(&self) -> u64 {
        self.tip()
    }
    fn finalized_hash(&self) -> Hash {
        sumchain_storage::BlockStore::new(&self.db)
            .get_by_height(self.finalized_height())
            .unwrap()
            .map(|b| b.hash())
            .unwrap_or(Hash::ZERO)
    }
    fn is_finalized(&self, height: u64) -> bool {
        height <= self.finalized_height()
    }
    fn finality_depth(&self) -> u64 {
        0
    }
    fn finality_mechanism(&self) -> sumchain_consensus::FinalityMechanism {
        self.engine.finality_mechanism()
    }
}

struct Served {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    params: ChainParams,
    server: RpcServer,
}

fn serve(g: &Genesis) -> Served {
    sponsor_key_configured();
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), g.chain_id));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let engine: Arc<dyn ConsensusQuery> = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            g,
            Some(validator()),
        )
        .unwrap(),
    );
    let engine: Arc<dyn ConsensusQuery> = Arc::new(StoredChain {
        engine,
        db: db.clone(),
    });
    let (tx_sender, rx) = mpsc::channel(256);
    std::mem::forget(rx);
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
    .with_chain_params(g.params.clone())
    .with_genesis(g);
    for (kp, balance) in [
        (validator(), FUNDS),
        (admin(), FUNDS),
        (alice(), FUNDS),
        (bob(), FUNDS),
        (carol(), FUNDS),
        (sponsor(), FUNDS),
        (dave(), FUNDS),
    ] {
        sumchain_storage::StateStore::new(&db)
            .put_account(
                &kp.address(),
                &sumchain_storage::schema::AccountState { balance, nonce: 0 },
            )
            .unwrap();
    }
    Served {
        _dir: dir,
        db,
        state,
        mempool,
        params: g.params.clone(),
        server,
    }
}

impl Served {
    fn publish(&self, height: u64, txs: Vec<SignedTransaction>) -> Vec<Receipt> {
        let header = BlockHeader::new(
            Hash::ZERO,
            height,
            1_000 + height,
            Hash::ZERO,
            Hash::ZERO,
            *validator().public_key().as_bytes(),
        );
        let mut block = Block::new(header, txs.clone());
        let executor = BlockExecutor::new(self.state.clone(), self.db.clone(), self.params.clone());
        let exec = executor
            .execute_block(&block, self.state.state_root(), &[])
            .expect("execute_block");
        block.header.state_root = exec.computed_root();
        let (executed, _, _) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let acc = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(acc);
        sumchain_storage::BlockStore::new(&self.db)
            .put(&block)
            .expect("store the block");
        for tx in &txs {
            self.mempool.remove(&tx.hash());
        }
        receipts
    }

    fn tx(&self, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
        let nonce = self.state.get_nonce(&kp.address()).unwrap();
        self.tx_at(kp, nonce, data)
    }

    fn tx_at(&self, kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
        let tx = TransactionV2::messaging(CHAIN_ID, kp.address(), FEE, nonce, data);
        let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }
}

fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
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

fn register(kp: &KeyPair) -> MessagingTxData {
    op(
        MessagingOperation::RegisterPublicKey,
        &RegisterPublicKeyData {
            public_key: *kp.public_key().as_bytes(),
        },
    )
}

fn paid(to: &KeyPair, amount: u128) -> MessagingTxData {
    let rh = recipient_hash(&to.address());
    op(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: valid_message(rh),
            recipient_hash: rh,
            koppa_amount: amount,
        },
    )
}

/// `sender`'s version-2 envelope to `to` at `nonce`.
fn envelope(sender: &KeyPair, to: &KeyPair, nonce: u64, amount: Option<u128>) -> SponsoredMessage {
    let rh = recipient_hash(&to.address());
    let mut m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *sender.public_key().as_bytes(),
        nonce,
        expiry: 4_000_000_000,
        koppa_amount: amount,
    };
    m.signature = *sign(
        &sponsored_send_v2_signing_preimage(CHAIN_ID, &m),
        sender.private_key(),
    )
    .as_bytes();
    m
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

// ── the earlier shapes, for a strict client ─────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct MessagingConfigInfo {
    daily_quota: u32,
    max_message_size: u32,
    min_trust_stake: String,
    sponsorship_enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct MessagingQuotaInfo {
    address: String,
    daily_quota: u32,
    used_today: u32,
    remaining: u32,
    has_trust_stake: bool,
    trust_stake: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct MessagingSenderNonceInfo {
    address: String,
    nonce: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct InboxFilterInfo {
    mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct MessageEventInfo {
    tx_hash: String,
    block_height: u64,
    sender: String,
    recipient_hash: String,
    content_type: u8,
    flags: u16,
    has_payment: bool,
    payment_amount: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct MessageDataInfo {
    tx_hash: String,
    block_height: u64,
    sender: String,
    recipient_hash: String,
    message_data: String,
    sender_pubkey: String,
    has_payment: bool,
    payment_amount: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SponsoredEnvelopeInfo {
    tx_hash: String,
    block_height: u64,
    sender_pubkey: String,
    recipient_hash: String,
    message_data: String,
    envelope_signature: String,
    envelope_nonce: u64,
    envelope_expiry: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct PendingPaymentInfo {
    message_id: String,
    sender: String,
    recipient_hash: String,
    amount: String,
    expiry: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SpamReportInfo {
    sender: String,
    spam_score: u32,
    report_count: u32,
    is_restricted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SendTxResponse {
    tx_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SponsoredRegistrationResponse {
    address: String,
    success: bool,
    tx_hash: Option<String>,
    error: Option<String>,
}

/// The strict parse of one pinned response: the type of its old shape,
/// named by the method.
fn parse_strict(method: &str, json: &str) {
    let r = match method {
        "messaging_getConfig" => serde_json::from_str::<MessagingConfigInfo>(json).map(|_| ()),
        "messaging_getQuota" => serde_json::from_str::<MessagingQuotaInfo>(json).map(|_| ()),
        "messaging_getSenderNonce" => {
            serde_json::from_str::<MessagingSenderNonceInfo>(json).map(|_| ())
        }
        "messaging_getInboxFilter" => {
            serde_json::from_str::<Option<InboxFilterInfo>>(json).map(|_| ())
        }
        "messaging_getMessages" | "messaging_getSentMessages" | "messaging_getMessagesInBlock" => {
            serde_json::from_str::<Vec<MessageEventInfo>>(json).map(|_| ())
        }
        "messaging_getMessageByTxHash" => {
            serde_json::from_str::<Option<MessageEventInfo>>(json).map(|_| ())
        }
        "messaging_getMessageData" => {
            serde_json::from_str::<Option<MessageDataInfo>>(json).map(|_| ())
        }
        "messaging_getSponsoredEnvelope" => {
            serde_json::from_str::<Option<SponsoredEnvelopeInfo>>(json).map(|_| ())
        }
        "messaging_getPendingPayment" => {
            serde_json::from_str::<Option<PendingPaymentInfo>>(json).map(|_| ())
        }
        "messaging_getPendingPayments" => {
            serde_json::from_str::<Vec<PendingPaymentInfo>>(json).map(|_| ())
        }
        "messaging_getTrustStake" => serde_json::from_str::<String>(json).map(|_| ()),
        "messaging_getSpamScore" => serde_json::from_str::<SpamReportInfo>(json).map(|_| ()),
        "messaging_isContact" | "messaging_isBlocked" => {
            serde_json::from_str::<bool>(json).map(|_| ())
        }
        "messaging_submitSponsored" => serde_json::from_str::<SendTxResponse>(json).map(|_| ()),
        "messaging_registerSponsored" => {
            serde_json::from_str::<SponsoredRegistrationResponse>(json).map(|_| ())
        }
        other => panic!("no strict shape for {other}"),
    };
    r.unwrap_or_else(|e| {
        panic!("{method}: a strict client of the earlier shape refuses {json}: {e}")
    });
}

fn to_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

/// Build the history and ask every method; `(label, method, response JSON)`.
async fn responses() -> Vec<(String, &'static str, String)> {
    let g = genesis();
    let s = serve(&g);
    let srv = &s.server;

    // h1: sponsorship on, a quota, registrations, alice stakes.
    let h1 = vec![
        s.tx(
            &admin(),
            op(
                MessagingOperation::SetSponsorshipEnabled,
                &SetSponsorshipEnabledData { enabled: true },
            ),
        ),
        s.tx(&alice(), register(&alice())),
        s.tx(&bob(), register(&bob())),
        s.tx(&carol(), register(&carol())),
        s.tx(&dave(), register(&dave())),
    ];
    let r = s.publish(1, h1);
    assert!(r.iter().all(|r| r.status == TxStatus::Success), "{r:?}");
    let h2 = vec![
        s.tx(
            &admin(),
            op(
                MessagingOperation::SetDailyQuota,
                &SetDailyQuotaData { quota: 50 },
            ),
        ),
        s.tx(
            &alice(),
            op(
                MessagingOperation::StakeForTrust,
                &StakeForTrustData {
                    amount: 200_000_000_000,
                },
            ),
        ),
        s.tx(
            &bob(),
            op(
                MessagingOperation::AddContact,
                &ContactData {
                    contact_hash: recipient_hash(&alice().address()),
                },
            ),
        ),
    ];
    let r = s.publish(2, h2);
    assert!(r.iter().all(|r| r.status == TxStatus::Success), "{r:?}");

    // h3: two paid sends, a direct message, a relayed message naming an
    // amount, a block and a report.
    // Below the accounting gate the account nonces move as before.
    let n = s.state.get_nonce(&alice().address()).unwrap();
    let pay_kept = s.tx_at(&alice(), n, paid(&bob(), 500));
    let pay_claimed = s.tx_at(&alice(), n + 1, paid(&bob(), 300));
    let direct = s.tx_at(&alice(), n + 2, {
        let rh = recipient_hash(&bob().address());
        op(
            MessagingOperation::SendMessageDirect,
            &SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            },
        )
    });
    let relayed = s.tx(
        &sponsor(),
        op(
            MessagingOperation::SendMessage,
            &envelope(&carol(), &bob(), 0, Some(5_000)),
        ),
    );
    let blocks = s.tx(
        &bob(),
        op(
            MessagingOperation::BlockSender,
            &BlockSenderData {
                sender: dave().address(),
            },
        ),
    );
    let report = s.tx_at(
        &alice(),
        n + 3,
        op(
            MessagingOperation::ReportSpam,
            &ReportSpamData {
                message_id: Hash::hash(b"a message"),
                spammer: dave().address(),
            },
        ),
    );
    let r = s.publish(
        3,
        vec![
            pay_kept.clone(),
            pay_claimed.clone(),
            direct.clone(),
            relayed.clone(),
            blocks,
            report,
        ],
    );
    assert!(r.iter().all(|r| r.status == TxStatus::Success), "{r:?}");

    // h4: bob claims one payment.
    let claim = s.tx(
        &bob(),
        op(
            MessagingOperation::ClaimPayment,
            &ClaimPaymentData {
                message_id: pay_claimed.hash(),
                recipient_address: bob().address(),
            },
        ),
    );
    let r = s.publish(4, vec![claim]);
    assert!(r.iter().all(|r| r.status == TxStatus::Success), "{r:?}");

    let alice_b58 = alice().address().to_base58();
    let bob_b58 = bob().address().to_base58();
    let carol_b58 = carol().address().to_base58();
    let dave_b58 = dave().address().to_base58();
    let bob_rh = hex32(&recipient_hash(&bob().address()));
    let hx = |t: &SignedTransaction| t.hash().to_hex();
    let mut out: Vec<(String, &'static str, String)> = Vec::new();
    macro_rules! ask {
        ($label:expr, $method:expr, $call:expr) => {{
            let v = $call.await.unwrap();
            out.push(($label.to_string(), $method, to_json(&v)));
        }};
    }
    ask!("config", "messaging_getConfig", srv.messaging_get_config());
    ask!(
        "quota alice",
        "messaging_getQuota",
        srv.messaging_get_quota(alice_b58.clone())
    );
    ask!(
        "sender nonce carol",
        "messaging_getSenderNonce",
        srv.messaging_get_sender_nonce(carol_b58.clone())
    );
    ask!(
        "sender nonce alice",
        "messaging_getSenderNonce",
        srv.messaging_get_sender_nonce(alice_b58.clone())
    );
    ask!(
        "inbox filter bob",
        "messaging_getInboxFilter",
        srv.messaging_get_inbox_filter(bob_b58.clone())
    );
    ask!(
        "messages to bob",
        "messaging_getMessages",
        srv.messaging_get_messages(bob_rh.clone(), None, None)
    );
    ask!(
        "sent by alice",
        "messaging_getSentMessages",
        srv.messaging_get_sent_messages(alice_b58.clone(), None, None)
    );
    ask!(
        "sent by carol",
        "messaging_getSentMessages",
        srv.messaging_get_sent_messages(carol_b58.clone(), None, None)
    );
    ask!(
        "message relayed",
        "messaging_getMessageByTxHash",
        srv.messaging_get_message_by_tx_hash(hx(&relayed))
    );
    ask!(
        "message paid",
        "messaging_getMessageByTxHash",
        srv.messaging_get_message_by_tx_hash(hx(&pay_kept))
    );
    ask!(
        "messages in block 3",
        "messaging_getMessagesInBlock",
        srv.messaging_get_messages_in_block(3, None)
    );
    ask!(
        "message data relayed",
        "messaging_getMessageData",
        srv.messaging_get_message_data(hx(&relayed))
    );
    ask!(
        "envelope relayed",
        "messaging_getSponsoredEnvelope",
        srv.messaging_get_sponsored_envelope(hx(&relayed))
    );
    ask!(
        "pending kept",
        "messaging_getPendingPayment",
        srv.messaging_get_pending_payment(hx(&pay_kept))
    );
    ask!(
        "pending claimed",
        "messaging_getPendingPayment",
        srv.messaging_get_pending_payment(hx(&pay_claimed))
    );
    ask!(
        "pending of bob",
        "messaging_getPendingPayments",
        srv.messaging_get_pending_payments(bob_b58.clone())
    );
    ask!(
        "trust stake alice",
        "messaging_getTrustStake",
        srv.messaging_get_trust_stake(alice_b58.clone())
    );
    ask!(
        "spam score dave",
        "messaging_getSpamScore",
        srv.messaging_get_spam_score(dave_b58.clone())
    );
    ask!(
        "bob has alice",
        "messaging_isContact",
        srv.messaging_is_contact(bob_b58.clone(), alice_b58.clone())
    );
    ask!(
        "bob blocks dave",
        "messaging_isBlocked",
        srv.messaging_is_blocked(bob_b58.clone(), dave_b58.clone())
    );
    let m = envelope(&carol(), &bob(), 1, None);
    ask!(
        "relay carol 1",
        "messaging_submitSponsored",
        srv.messaging_submit_sponsored(SubmitSponsoredMessageRequest {
            message_data: format!("0x{}", hex::encode(&m.message_data)),
            recipient_hash: hex32(&m.recipient_hash),
            signature: format!("0x{}", hex::encode(m.signature)),
            sender_pubkey: hex32(&m.sender_pubkey),
            nonce: m.nonce,
            expiry: m.expiry,
            koppa_amount: None,
        })
    );
    let preimage = sponsored_register_v1_signing_preimage(
        CHAIN_ID,
        &sponsor().address(),
        grace().public_key().as_bytes(),
    );
    ask!(
        "register grace",
        "messaging_registerSponsored",
        srv.messaging_register_sponsored(SponsoredRegistrationRequest {
            public_key: hex32(grace().public_key().as_bytes()),
            signature: format!(
                "0x{}",
                hex::encode(sign(&preimage, grace().private_key()).as_bytes())
            ),
        })
    );
    out
}

/// Produced before any method was added (see the module doc).
#[rustfmt::skip]
const PINS: &[(&str, &str)] = &[
    (
        "config",
        r##"{"daily_quota":50,"max_message_size":65535,"min_trust_stake":"100000000000","sponsorship_enabled":true}"##,
    ),
    (
        "quota alice",
        r##"{"address":"KyKTaSfvu56fmhEBe18zAky125zPxrsjE","daily_quota":250,"used_today":0,"remaining":250,"has_trust_stake":true,"trust_stake":"200000000000"}"##,
    ),
    (
        "sender nonce carol",
        r##"{"address":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","nonce":1}"##,
    ),
    (
        "sender nonce alice",
        r##"{"address":"KyKTaSfvu56fmhEBe18zAky125zPxrsjE","nonce":3}"##,
    ),
    (
        "inbox filter bob",
        r##"{"mode":"accept_all"}"##,
    ),
    (
        "messages to bob",
        r##"[{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}]"##,
    ),
    (
        "sent by alice",
        r##"[{"tx_hash":"0x51650c069766666fb11b65a55420a87f13e67afc0667a4dd85c950d8ef6f5fa7","block_height":3,"sender":"KyKTaSfvu56fmhEBe18zAky125zPxrsjE","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}]"##,
    ),
    (
        "sent by carol",
        r##"[{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}]"##,
    ),
    (
        "message relayed",
        r##"{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}"##,
    ),
    (
        "message paid",
        r##"null"##,
    ),
    (
        "messages in block 3",
        r##"[{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}]"##,
    ),
    (
        "message data relayed",
        r##"{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender":"PoQbmPz4oYeKtHMmM4Hpgfwf5CjEr1ZdA","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","message_data":"0x533230310101010097d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c80202020202020202020202020202020202020202020202020202020202020202000000000000000000000000000000000000000000000000000000000000000000000000000000000000","sender_pubkey":"0x2bc2800b3316e009209ffd757dab19ccf0ae84bc7ae90654e1e81712d270f653","has_payment":false,"payment_amount":null}"##,
    ),
    (
        "envelope relayed",
        r##"{"tx_hash":"0xf1919033fc5c4c9d1288ce0ae3a2a417c067a1419651078a946090cf8d32dd2b","block_height":3,"sender_pubkey":"0x2bc2800b3316e009209ffd757dab19ccf0ae84bc7ae90654e1e81712d270f653","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","message_data":"0x533230310101010097d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c80202020202020202020202020202020202020202020202020202020202020202000000000000000000000000000000000000000000000000000000000000000000000000000000000000","envelope_signature":"0x8a15a785014c2f96d3cf35f7a9a739fe72213aaec740aa9c71b7857e0588557ceddabea040366c8ce98d0e8283895e6d5881ffd22e312c9dc70eeaf55be30307","envelope_nonce":0,"envelope_expiry":4000000000}"##,
    ),
    (
        "pending kept",
        r##"{"message_id":"0x9fe95c3fd4889800f837df070bf425e21f0838aa64bec96065634c954f309a8b","sender":"KyKTaSfvu56fmhEBe18zAky125zPxrsjE","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","amount":"500","expiry":604800}"##,
    ),
    (
        "pending claimed",
        r##"null"##,
    ),
    (
        "pending of bob",
        r##"[{"message_id":"0x9fe95c3fd4889800f837df070bf425e21f0838aa64bec96065634c954f309a8b","sender":"KyKTaSfvu56fmhEBe18zAky125zPxrsjE","recipient_hash":"0x97d6fce1d73e8f550635a91a51da227f9c67d749a1c7a2f5aea5736d831e95c8","amount":"500","expiry":604800}]"##,
    ),
    (
        "trust stake alice",
        r##""200000000000""##,
    ),
    (
        "spam score dave",
        r##"{"sender":"NNezAuKKXfPrAx1ozxXiiNy3cJ2v9BZEv","spam_score":5,"report_count":0,"is_restricted":false}"##,
    ),
    (
        "bob has alice",
        r##"true"##,
    ),
    (
        "bob blocks dave",
        r##"true"##,
    ),
    (
        "relay carol 1",
        r##"{"tx_hash":"0xcaff06ee1c70ecae8b086d70b51c16acee834e3e8b929708d53d5d5d0c1b8157"}"##,
    ),
    (
        "register grace",
        r##"{"address":"FMsWJe7bj5wrzEwdb81rkuGZoFkkgiHHZ","success":true,"tx_hash":"0x1a5bf3d02f20b4127c0aa5d90c502af573c379323c3c34b085c3c5a0bd164344","error":null}"##,
    ),
];

#[tokio::test]
async fn every_existing_messaging_response_is_byte_identical_and_parses_strictly() {
    let got = responses().await;
    if std::env::var("TRACK_A_PRINT_PINS").is_ok() {
        for (label, _, json) in &got {
            println!("PIN\t{label}\t{json}");
        }
    }
    for (label, method, json) in &got {
        parse_strict(method, json);
        let _ = label;
    }
    let methods: std::collections::BTreeSet<&str> = got.iter().map(|(_, m, _)| *m).collect();
    assert_eq!(
        methods.len(),
        18,
        "every existing messaging method is asked: {methods:?}"
    );
    if std::env::var("TRACK_A_PRINT_PINS").is_ok() {
        return;
    }
    assert_eq!(got.len(), PINS.len());
    for ((label, _, json), (pin_label, pin)) in got.iter().zip(PINS) {
        assert_eq!(label, pin_label);
        assert_eq!(json, pin, "{label}: the response moved");
    }
}
