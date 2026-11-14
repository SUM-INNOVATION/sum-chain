//! The two read-only methods for sponsored payments and envelope outcomes,
//! `messaging_getPaymentStatus` and `messaging_getEnvelopeOutcome`, and the
//! values the existing methods report for a real sponsored payment.
//!
//! Both gates at 3 on chain 7, the transaction-index gate open from genesis
//! (each message keeps its own event row): a relayed message naming an amount
//! below the gates (the earlier rule), then at the gates two sponsored
//! payments (one claimed, one left in escrow), a sponsored message without an
//! amount, an unaffordable sponsored payment (refused, its nonce spent) and a
//! paid send that is claimed. Existing responses keep the shape a strict
//! client of the earlier response parses; their payment fields describe an
//! actual, successfully funded payment: a sponsored payment executed at or
//! above the gate (still after its claim or refund), never a failed
//! transaction, never an amount named below the gate.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ClaimPaymentData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageData, SendMessageWithPaymentData, SetSponsorshipEnabledData,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, BlockHeader, Hash, MessagingOperation, Receipt,
    SignedTransaction, SponsoredMessage, TransactionV2, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 7;
const FEE: u128 = 1_000_000;
const FUNDS: u128 = 1_000_000_000_000_000;
/// Both gates open from this height.
const GATE: u64 = 3;

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
    genesis_with(false)
}

/// `genesis()`, with both clock gates open from genesis when `clocked` (the
/// rules then read whole seconds of the block timestamp, so an escrow can
/// expire). A test chain only.
fn genesis_with(clocked: bool) -> Genesis {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        spam_threshold: 3,
        high_spam_threshold: 5,
        ..MessagingParams::default()
    });
    p.subsystem_tx_index_enabled_from_height = Some(0);
    p.messaging_sponsored_envelope_verification_enabled_from_height = Some(GATE);
    p.messaging_fee_nonce_accounting_enabled_from_height = Some(GATE);
    p.peer_protocol_declaration_required_from_height = Some(1);
    if clocked {
        p.subsystem_block_timestamp_enabled_from_height = Some(0);
        p.messaging_timestamp_units_enabled_from_height = Some(0);
    }
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
        self.publish_at(height, 1_000 + height, txs)
    }

    /// `publish` with the block timestamp `timestamp_ms`.
    fn publish_at(
        &self,
        height: u64,
        timestamp_ms: u64,
        txs: Vec<SignedTransaction>,
    ) -> Vec<Receipt> {
        let header = BlockHeader::new(
            Hash::ZERO,
            height,
            timestamp_ms,
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

// ── strict shapes: the new methods, and the existing ones that report
//    payments ──────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct PaymentStatus {
    message_id: String,
    status: String,
    amount: Option<String>,
    sender: Option<String>,
    recipient_hash: Option<String>,
    escrow_expiry: Option<u64>,
    included_at_height: Option<u64>,
    receipt_status: Option<String>,
    legacy_amount_unbacked: bool,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct EnvelopeOutcome {
    sender: String,
    nonce: u64,
    tx_hash: String,
    outcome: String,
    receipt_code: u32,
    escrowed_amount: String,
    block_height: Option<u64>,
}

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
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

/// Through JSON, as a client receives it.
fn strict<T: serde::de::DeserializeOwned>(v: &impl serde::Serialize) -> T {
    serde_json::from_str(&serde_json::to_string(v).unwrap()).unwrap()
}

fn relayed_by(s: &Served, relayer: &KeyPair, m: &SponsoredMessage) -> SignedTransaction {
    s.tx(relayer, op(MessagingOperation::SendMessage, m))
}

fn relayed_at(
    s: &Served,
    relayer: &KeyPair,
    nonce: u64,
    m: &SponsoredMessage,
) -> SignedTransaction {
    s.tx_at(relayer, nonce, op(MessagingOperation::SendMessage, m))
}

fn claim(s: &Served, id: Hash) -> SignedTransaction {
    s.tx(
        &bob(),
        op(
            MessagingOperation::ClaimPayment,
            &ClaimPaymentData {
                message_id: id,
                recipient_address: bob().address(),
            },
        ),
    )
}

#[tokio::test]
async fn payment_status_and_envelope_outcomes_report_what_the_chain_executed() {
    let g = genesis();
    let s = serve(&g);
    let srv = &s.server;
    let bob_rh = hex32(&recipient_hash(&bob().address()));
    let carol_b58 = carol().address().to_base58();
    let dave_b58 = dave().address().to_base58();
    let alice_b58 = alice().address().to_base58();

    // h1: below the gates.
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
    assert!(s
        .publish(1, h1)
        .iter()
        .all(|r| r.status == TxStatus::Success));
    // h2: below the gates, a relayed message naming an amount.
    let legacy = relayed_by(&s, &sponsor(), &envelope(&carol(), &bob(), 0, Some(5_000)));
    assert!(s
        .publish(2, vec![legacy.clone()])
        .iter()
        .all(|r| r.status == TxStatus::Success));

    // h3: at the gates.
    let sp = s.state.get_nonce(&sponsor().address()).unwrap();
    let pay_claimed = relayed_at(
        &s,
        &sponsor(),
        sp,
        &envelope(&carol(), &bob(), 1, Some(7_000)),
    );
    let plain = relayed_at(&s, &sponsor(), sp + 1, &envelope(&carol(), &bob(), 2, None));
    let pay_kept = relayed_at(
        &s,
        &sponsor(),
        sp + 2,
        &envelope(&carol(), &bob(), 3, Some(1_000)),
    );
    let unaffordable = relayed_at(
        &s,
        &sponsor(),
        sp + 3,
        &envelope(&dave(), &bob(), 0, Some(FUNDS * 2)),
    );
    let paid_send = s.tx(&alice(), paid(&bob(), 500));
    let r = s.publish(
        3,
        vec![
            pay_claimed.clone(),
            plain.clone(),
            pay_kept.clone(),
            unaffordable.clone(),
            paid_send.clone(),
        ],
    );
    assert_eq!(
        r.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![
            TxStatus::Success,
            TxStatus::Success,
            TxStatus::Success,
            TxStatus::Failed(7),
            TxStatus::Success
        ]
    );
    // h4: bob claims carol's first payment and alice's paid send.
    let c1 = claim(&s, pay_claimed.hash());
    let c2 = s.tx_at(
        &bob(),
        s.state.get_nonce(&bob().address()).unwrap() + 1,
        op(
            MessagingOperation::ClaimPayment,
            &ClaimPaymentData {
                message_id: paid_send.hash(),
                recipient_address: bob().address(),
            },
        ),
    );
    assert!(s
        .publish(4, vec![c1.clone(), c2])
        .iter()
        .all(|r| r.status == TxStatus::Success));

    let status = |h: String| async move {
        let v = srv.messaging_get_payment_status(h).await.unwrap();
        strict::<PaymentStatus>(&v)
    };
    let hx = |t: &SignedTransaction| t.hash().to_hex();
    let id = |t: &SignedTransaction| format!("0x{}", hex::encode(t.hash().as_bytes()));

    // escrowed: carol's second payment, amount and expiry from the escrow row.
    let st = status(hx(&pay_kept)).await;
    assert_eq!(
        st,
        PaymentStatus {
            message_id: id(&pay_kept),
            status: "escrowed".into(),
            amount: Some("1000".into()),
            sender: Some(carol_b58.clone()),
            recipient_hash: Some(bob_rh.clone()),
            escrow_expiry: Some(7 * 24 * 3600),
            included_at_height: Some(3),
            receipt_status: Some("success".into()),
            legacy_amount_unbacked: false,
        }
    );
    // settled: carol's first payment and alice's paid send, after the claims.
    for (tx, amount, sender) in [
        (&pay_claimed, "7000", &carol_b58),
        (&paid_send, "500", &alice_b58),
    ] {
        let st = status(hx(tx)).await;
        assert_eq!(
            (
                st.status.as_str(),
                st.amount.as_deref(),
                st.sender.as_ref(),
                st.escrow_expiry
            ),
            ("settled", Some(amount), Some(sender), None),
            "{}",
            hx(tx)
        );
    }
    // none: a sponsored message without an amount.
    let st = status(hx(&plain)).await;
    assert_eq!(
        (st.status.as_str(), st.amount, st.legacy_amount_unbacked),
        ("none", None, false)
    );
    // none, with the legacy flag: below the gates the amount moved nothing.
    let st = status(hx(&legacy)).await;
    assert_eq!(
        (
            st.status.as_str(),
            st.amount,
            st.legacy_amount_unbacked,
            st.included_at_height
        ),
        ("none", None, true, Some(2))
    );
    // refused.
    let st = status(hx(&unaffordable)).await;
    assert_eq!(
        (st.status.as_str(), st.receipt_status.as_deref(), st.amount),
        ("refused", Some(TxStatus::Failed(7).description()), None)
    );
    // not_included: never carried; and stored without a canonical receipt.
    let st = status(Hash::hash(b"never carried").to_hex()).await;
    assert_eq!(
        (st.status.as_str(), st.included_at_height),
        ("not_included", None)
    );
    let side = relayed_by(&s, &grace(), &envelope(&carol(), &bob(), 4, Some(1)));
    sumchain_storage::TxStore::new(&s.db).put(&side).unwrap();
    assert_eq!(
        status(hx(&side)).await.status,
        "not_included",
        "a side-branch copy"
    );
    // Not a message transaction.
    assert!(srv.messaging_get_payment_status(hx(&c1)).await.is_err());

    // ── envelope outcomes ───────────────────────────────────────────────────
    let outcome = |sender: String, nonce: u64| async move {
        srv.messaging_get_envelope_outcome(sender, nonce)
            .await
            .unwrap()
            .map(|v| strict::<EnvelopeOutcome>(&v))
    };
    assert_eq!(
        outcome(carol_b58.clone(), 0).await,
        None,
        "spent below the gates: no row"
    );
    assert_eq!(
        outcome(carol_b58.clone(), 1).await,
        Some(EnvelopeOutcome {
            sender: carol_b58.clone(),
            nonce: 1,
            tx_hash: id(&pay_claimed),
            outcome: "executed".into(),
            receipt_code: 0,
            escrowed_amount: "7000".into(),
            block_height: Some(3),
        })
    );
    let o = outcome(carol_b58.clone(), 2).await.unwrap();
    assert_eq!(
        (o.outcome.as_str(), o.escrowed_amount.as_str()),
        ("executed", "0")
    );
    assert_eq!(
        outcome(dave_b58.clone(), 0).await,
        Some(EnvelopeOutcome {
            sender: dave_b58.clone(),
            nonce: 0,
            tx_hash: id(&unaffordable),
            outcome: "refused".into(),
            receipt_code: 7,
            escrowed_amount: "0".into(),
            block_height: Some(3),
        })
    );
    assert_eq!(outcome(carol_b58.clone(), 4).await, None, "unspent");
    assert!(srv
        .messaging_get_envelope_outcome("not an address".into(), 0)
        .await
        .is_err());

    // ── the existing methods: earlier shape; payments as executed ──────────
    // A relayed message executed at the envelope gate reports the payment it
    // made, in every existing method; below the gate, none; a paid send
    // reports its payment, as before.
    let events: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_sent_messages(carol_b58.clone(), None, None)
            .await
            .unwrap(),
    );
    assert_eq!(events.len(), 4);
    for e in &events {
        let paid = e.tx_hash == id(&pay_claimed) || e.tx_hash == id(&pay_kept);
        assert_eq!(e.has_payment, paid, "{}", e.tx_hash);
        assert!(e.payment_amount.is_none());
    }
    let to_bob: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_messages(bob_rh.clone(), None, None)
            .await
            .unwrap(),
    );
    for e in &to_bob {
        let paid = [&paid_send, &pay_claimed, &pay_kept]
            .iter()
            .any(|t| e.tx_hash == id(t));
        assert_eq!(e.has_payment, paid, "{}", e.tx_hash);
    }
    let in_block: Vec<MessageEventInfo> =
        strict(&srv.messaging_get_messages_in_block(3, None).await.unwrap());
    assert_eq!(in_block.len(), 4);
    let one: Option<MessageEventInfo> = strict(
        &srv.messaging_get_message_by_tx_hash(hx(&pay_kept))
            .await
            .unwrap(),
    );
    assert!(one.unwrap().has_payment);
    let data: Option<MessageDataInfo> =
        strict(&srv.messaging_get_message_data(hx(&pay_kept)).await.unwrap());
    let data = data.unwrap();
    assert_eq!(
        (data.has_payment, data.payment_amount.as_deref()),
        (true, Some("1000"))
    );
    let data: Option<MessageDataInfo> =
        strict(&srv.messaging_get_message_data(hx(&legacy)).await.unwrap());
    let data = data.unwrap();
    assert_eq!(
        (data.has_payment, data.payment_amount),
        (false, None),
        "below the gate the named amount moved nothing"
    );
    // The escrow itself is reported, as before, by the escrow methods.
    let pending = srv
        .messaging_get_pending_payment(hx(&pay_kept))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (pending.amount.as_str(), pending.sender),
        ("1000", carol_b58)
    );
}

// ── the payment fields of the existing methods, one test per rule ─────────
//
// The rules for `has_payment` / `payment_amount` in the existing
// methods: they describe an actual, successfully funded payment; a sponsored
// payment executed at or above the gate is included; a historical sponsored
// amount without an escrow remains "no payment"; a failed transaction never
// reports a payment; a payment remains a payment after its claim or refund
// (where it stands is `messaging_getPaymentStatus`'s); shapes and unaffected
// historical responses are preserved exactly (also the byte pins of
// `messaging_rpc_response_pins.rs`).

/// The payment fields one method reports for one message; `None` where the
/// method has no message for it.
type Fields = Option<(bool, Option<String>)>;

/// A payment of `amount`: the flag in the four event methods (an event row
/// stores no amount, as for a paid send), the flag and the amount in
/// `getMessageData`.
fn payment(amount: &str) -> Vec<Fields> {
    let mut v = vec![Some((true, None)); 4];
    v.push(Some((true, Some(amount.to_string()))));
    v
}

/// An executed relayed message without a payment.
fn no_payment() -> Vec<Fields> {
    vec![Some((false, None)); 5]
}

/// No message at all, which is what a failed transaction leaves.
fn no_message() -> Vec<Fields> {
    vec![None; 5]
}

/// The four event methods' payment fields for the message `t` from `sender`
/// to `to`, carried at `height`: `getMessageByTxHash`, `getSentMessages`,
/// `getMessages`, `getMessagesInBlock`. Each response is parsed strictly, as
/// a client of the earlier shape parses it.
async fn event_fields(
    srv: &RpcServer,
    t: &SignedTransaction,
    sender: &KeyPair,
    to: &KeyPair,
    height: u64,
) -> Vec<Fields> {
    let id = format!("0x{}", hex::encode(t.hash().as_bytes()));
    let pick = |events: Vec<MessageEventInfo>| -> Fields {
        let mut found = events.into_iter().filter(|e| e.tx_hash == id);
        let one = found.next().map(|e| (e.has_payment, e.payment_amount));
        assert!(found.next().is_none(), "one row per message");
        one
    };
    let one: Option<MessageEventInfo> = strict(
        &srv.messaging_get_message_by_tx_hash(t.hash().to_hex())
            .await
            .unwrap(),
    );
    let sent: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_sent_messages(sender.address().to_base58(), None, None)
            .await
            .unwrap(),
    );
    let received: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_messages(hex32(&recipient_hash(&to.address())), None, None)
            .await
            .unwrap(),
    );
    let in_block: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_messages_in_block(height, None)
            .await
            .unwrap(),
    );
    vec![
        one.map(|e| (e.has_payment, e.payment_amount)),
        pick(sent),
        pick(received),
        pick(in_block),
    ]
}

/// `event_fields`, then `getMessageData`, for a relayed message.
async fn relayed_fields(
    srv: &RpcServer,
    t: &SignedTransaction,
    sender: &KeyPair,
    to: &KeyPair,
    height: u64,
) -> Vec<Fields> {
    let mut v = event_fields(srv, t, sender, to, height).await;
    let data: Option<MessageDataInfo> = strict(
        &srv.messaging_get_message_data(t.hash().to_hex())
            .await
            .unwrap(),
    );
    v.push(data.map(|d| (d.has_payment, d.payment_amount)));
    v
}

async fn status_of(srv: &RpcServer, t: &SignedTransaction) -> PaymentStatus {
    strict(
        &srv.messaging_get_payment_status(t.hash().to_hex())
            .await
            .unwrap(),
    )
}

/// The escrow row's amount for `t`, read from storage.
fn escrow(s: &Served, t: &SignedTransaction) -> Option<u128> {
    MessagingStore::new(&s.db)
        .get_pending_payment(&t.hash())
        .unwrap()
        .map(|p| p.amount)
}

/// The event row's stored payment flag for `t`, read from storage.
fn stored_flag(s: &Served, t: &SignedTransaction) -> Option<bool> {
    MessagingStore::new(&s.db)
        .get_message_by_tx_hash(t.hash().as_bytes())
        .unwrap()
        .map(|e| e.has_payment)
}

fn balance(s: &Served, kp: &KeyPair) -> u128 {
    s.state.get_balance(&kp.address()).unwrap()
}

fn all_ok(r: &[Receipt]) -> bool {
    r.iter().all(|r| r.status == TxStatus::Success)
}

/// Sponsorship on, and every sender's key registered.
fn setup(s: &Served) -> Vec<SignedTransaction> {
    vec![
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
    ]
}

fn direct(to: &KeyPair) -> MessagingTxData {
    let rh = recipient_hash(&to.address());
    op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

/// Included: a sponsored payment executed at or above the gate, exactly at
/// the boundary. The gate is H = 3. At H−1 a relayed message naming an
/// amount reports no payment (its stored flag is set; nothing was
/// escrowed). At H and at H+1 a positive amount reports the payment in every
/// method, as its escrow holds it; at H an amount of zero and no amount
/// report none.
#[tokio::test]
async fn a_sponsored_payment_is_reported_from_the_gate_at_h_minus_1_h_and_h_plus_1() {
    let s = serve(&genesis());
    let srv = &s.server;
    assert!(all_ok(&s.publish(1, setup(&s))));
    let below = relayed_by(&s, &sponsor(), &envelope(&carol(), &bob(), 0, Some(5_000)));
    assert!(all_ok(&s.publish(GATE - 1, vec![below.clone()])));
    let sp = s.state.get_nonce(&sponsor().address()).unwrap();
    let at = relayed_at(
        &s,
        &sponsor(),
        sp,
        &envelope(&carol(), &bob(), 1, Some(7_000)),
    );
    let zero = relayed_at(
        &s,
        &sponsor(),
        sp + 1,
        &envelope(&carol(), &bob(), 2, Some(0)),
    );
    let none = relayed_at(&s, &sponsor(), sp + 2, &envelope(&carol(), &bob(), 3, None));
    assert!(all_ok(
        &s.publish(GATE, vec![at.clone(), zero.clone(), none.clone()])
    ));
    let above = relayed_by(&s, &sponsor(), &envelope(&carol(), &bob(), 4, Some(9_000)));
    assert!(all_ok(&s.publish(GATE + 1, vec![above.clone()])));

    assert_eq!(stored_flag(&s, &below), Some(true));
    assert_eq!(escrow(&s, &below), None);
    assert_eq!(
        relayed_fields(srv, &below, &carol(), &bob(), GATE - 1).await,
        no_payment(),
        "H-1"
    );
    assert_eq!(escrow(&s, &at), Some(7_000));
    assert_eq!(
        relayed_fields(srv, &at, &carol(), &bob(), GATE).await,
        payment("7000"),
        "H"
    );
    for t in [&zero, &none] {
        assert_eq!(escrow(&s, t), None);
        assert_eq!(
            relayed_fields(srv, t, &carol(), &bob(), GATE).await,
            no_payment(),
            "H, no positive amount"
        );
    }
    assert_eq!(escrow(&s, &above), Some(9_000));
    assert_eq!(
        relayed_fields(srv, &above, &carol(), &bob(), GATE + 1).await,
        payment("9000"),
        "H+1"
    );
}

/// No escrow, no payment: amounts named below the gate stay "no payment" in
/// every method, also once the chain has passed the gate. One exceeds what
/// its named sender holds; below the gate nothing moved, so it executed and
/// both named senders keep their balances.
#[tokio::test]
async fn an_amount_named_below_the_gate_remains_no_payment() {
    let s = serve(&genesis());
    let srv = &s.server;
    assert!(all_ok(&s.publish(1, setup(&s))));
    let (carol_before, dave_before) = (balance(&s, &carol()), balance(&s, &dave()));
    // Two relayers: below the accounting gate a relayed message does not
    // advance its relayer's account nonce (the earlier rule).
    let named = relayed_by(&s, &sponsor(), &envelope(&carol(), &bob(), 0, Some(5_000)));
    let beyond = relayed_by(&s, &admin(), &envelope(&dave(), &bob(), 0, Some(FUNDS * 2)));
    let r = s.publish(2, vec![named.clone(), beyond.clone()]);
    assert!(all_ok(&r), "{r:?}");
    assert!(s.publish(GATE, vec![]).is_empty());
    assert!(s.publish(GATE + 1, vec![]).is_empty());
    assert_eq!(
        (balance(&s, &carol()), balance(&s, &dave())),
        (carol_before, dave_before)
    );
    for (t, sender) in [(&named, carol()), (&beyond, dave())] {
        assert_eq!(stored_flag(&s, t), Some(true));
        assert_eq!(escrow(&s, t), None);
        assert_eq!(
            relayed_fields(srv, t, &sender, &bob(), 2).await,
            no_payment()
        );
        let st = status_of(srv, t).await;
        assert_eq!(
            (st.status.as_str(), st.amount, st.legacy_amount_unbacked),
            ("none", None, true)
        );
    }
}

/// Never for a failed transaction, at H and at H+1: an unaffordable
/// sponsored payment (an authenticated refusal; its nonce is spent), an
/// envelope whose signature fails, and one at a nonce that is not its
/// sender's. Each is a charged failed receipt; no method reports a message
/// or a payment for it, nothing is escrowed and the named senders keep
/// their balances. A sponsored payment in the same block is reported.
#[tokio::test]
async fn a_failed_transaction_never_reports_a_payment() {
    let s = serve(&genesis());
    let srv = &s.server;
    assert!(all_ok(&s.publish(1, setup(&s))));
    for (i, height) in [GATE, GATE + 1].into_iter().enumerate() {
        let i = i as u64;
        let (carol_before, dave_before) = (balance(&s, &carol()), balance(&s, &dave()));
        let sp = s.state.get_nonce(&sponsor().address()).unwrap();
        let control = relayed_at(
            &s,
            &sponsor(),
            sp,
            &envelope(&alice(), &bob(), i, Some(2_000)),
        );
        let unaffordable = relayed_at(
            &s,
            &sponsor(),
            sp + 1,
            &envelope(&dave(), &bob(), i, Some(FUNDS * 2)),
        );
        let mut tampered = envelope(&carol(), &bob(), 0, Some(1_000));
        tampered.signature[0] ^= 1;
        let tampered = relayed_at(&s, &sponsor(), sp + 2, &tampered);
        let wrong_nonce = relayed_at(
            &s,
            &sponsor(),
            sp + 3,
            &envelope(&carol(), &bob(), 99, Some(1_000)),
        );
        let r = s.publish(
            height,
            vec![
                control.clone(),
                unaffordable.clone(),
                tampered.clone(),
                wrong_nonce.clone(),
            ],
        );
        assert_eq!(
            r.iter().map(|r| r.status).collect::<Vec<_>>(),
            vec![
                TxStatus::Success,
                TxStatus::Failed(7),
                TxStatus::Failed(7),
                TxStatus::Failed(7)
            ],
            "{height}"
        );
        assert_eq!(
            relayed_fields(srv, &control, &alice(), &bob(), height).await,
            payment("2000"),
            "{height}"
        );
        for (t, sender) in [
            (&unaffordable, dave()),
            (&tampered, carol()),
            (&wrong_nonce, carol()),
        ] {
            assert_eq!(stored_flag(&s, t), None, "{height}");
            assert_eq!(escrow(&s, t), None, "{height}");
            assert_eq!(
                relayed_fields(srv, t, &sender, &bob(), height).await,
                no_message(),
                "{height}"
            );
            let st = status_of(srv, t).await;
            assert_eq!(
                (st.status.as_str(), st.amount),
                ("refused", None),
                "{height}"
            );
        }
        assert_eq!(
            (balance(&s, &carol()), balance(&s, &dave())),
            (carol_before, dave_before),
            "{height}"
        );
    }
}

/// Still a payment after its claim and after its refund. With the clock
/// gates open (a test chain), two sponsored payments at the gate; the
/// recipient claims one at H+1, and the other eight days later, when its
/// escrow has expired and the claim refunds the sender (a success from the
/// accounting gate). Both escrow rows are gone; every method still reports
/// each payment; `messaging_getPaymentStatus` reports them settled.
#[tokio::test]
async fn a_payment_stays_a_payment_after_its_claim_and_its_refund() {
    const T_MS: u64 = 1_760_000_000_000;
    const MINUTE_MS: u64 = 60_000;
    const DAY_MS: u64 = 24 * 3600 * 1000;
    let at = |h: u64| T_MS + h * MINUTE_MS;
    let s = serve(&genesis_with(true));
    let srv = &s.server;
    assert!(all_ok(&s.publish_at(1, at(1), setup(&s))));
    assert!(s.publish_at(2, at(2), vec![]).is_empty());
    let sp = s.state.get_nonce(&sponsor().address()).unwrap();
    let claimed = relayed_at(
        &s,
        &sponsor(),
        sp,
        &envelope(&carol(), &bob(), 0, Some(7_000)),
    );
    let refunded = relayed_at(
        &s,
        &sponsor(),
        sp + 1,
        &envelope(&carol(), &bob(), 1, Some(3_000)),
    );
    assert!(all_ok(&s.publish_at(
        GATE,
        at(GATE),
        vec![claimed.clone(), refunded.clone()]
    )));
    for (t, amount) in [(&claimed, "7000"), (&refunded, "3000")] {
        assert_eq!(status_of(srv, t).await.status, "escrowed");
        assert_eq!(
            relayed_fields(srv, t, &carol(), &bob(), GATE).await,
            payment(amount),
            "escrowed"
        );
    }

    let bob_before = balance(&s, &bob());
    let r = s.publish_at(GATE + 1, at(GATE + 1), vec![claim(&s, claimed.hash())]);
    assert_eq!(r[0].status, TxStatus::Success);
    assert_eq!(balance(&s, &bob()), bob_before + 7_000 - r[0].fee_paid);

    let carol_before = balance(&s, &carol());
    let r = s.publish_at(
        GATE + 2,
        at(GATE + 2) + 8 * DAY_MS,
        vec![claim(&s, refunded.hash())],
    );
    assert_eq!(r[0].status, TxStatus::Success, "the refund is the outcome");
    assert_eq!(balance(&s, &carol()), carol_before + 3_000, "refunded");

    for (t, amount) in [(&claimed, "7000"), (&refunded, "3000")] {
        assert_eq!(escrow(&s, t), None, "the escrow row is gone");
        let st = status_of(srv, t).await;
        assert_eq!(
            (st.status.as_str(), st.amount.as_deref()),
            ("settled", Some(amount))
        );
        assert_eq!(
            relayed_fields(srv, t, &carol(), &bob(), GATE).await,
            payment(amount),
            "after settlement"
        );
    }
}

/// Unaffected responses keep their earlier values, below and at the gate,
/// with each message on its own event row: a paid send reports its payment
/// (the flag; no amount, as before), a direct message and a relayed message
/// without an amount report none. The byte pins hold every existing
/// response of a history below the gates.
#[tokio::test]
async fn messages_the_rule_does_not_concern_keep_their_earlier_values() {
    let s = serve(&genesis());
    let srv = &s.server;
    assert!(all_ok(&s.publish(1, setup(&s))));
    for (height, carol_nonce) in [(GATE - 1, 0), (GATE, 1)] {
        let n = s.state.get_nonce(&alice().address()).unwrap();
        let paid_send = s.tx_at(&alice(), n, paid(&bob(), 500));
        let direct_send = s.tx_at(&alice(), n + 1, direct(&bob()));
        let plain = relayed_by(
            &s,
            &sponsor(),
            &envelope(&carol(), &bob(), carol_nonce, None),
        );
        assert!(all_ok(&s.publish(
            height,
            vec![paid_send.clone(), direct_send.clone(), plain.clone()]
        )));
        assert_eq!(
            event_fields(srv, &paid_send, &alice(), &bob(), height).await,
            vec![Some((true, None)); 4],
            "{height}"
        );
        assert_eq!(
            event_fields(srv, &direct_send, &alice(), &bob(), height).await,
            vec![Some((false, None)); 4],
            "{height}"
        );
        assert_eq!(
            relayed_fields(srv, &plain, &carol(), &bob(), height).await,
            no_payment(),
            "{height}"
        );
    }
}
