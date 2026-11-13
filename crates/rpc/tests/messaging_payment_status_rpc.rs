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
//! client of the earlier response parses and the values the earlier code
//! gives (a relayed message reports no payment).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;
use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ClaimPaymentData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageWithPaymentData, SetSponsorshipEnabledData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
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
use sumchain_storage::Database;
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

    // ── the existing methods: earlier shape, earlier values ────────────────
    // A relayed message reports no payment in every existing method, a real
    // sponsored payment included; a paid send reports its payment, as before.
    let events: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_sent_messages(carol_b58.clone(), None, None)
            .await
            .unwrap(),
    );
    assert_eq!(events.len(), 4);
    assert!(events
        .iter()
        .all(|e| !e.has_payment && e.payment_amount.is_none()));
    let to_bob: Vec<MessageEventInfo> = strict(
        &srv.messaging_get_messages(bob_rh.clone(), None, None)
            .await
            .unwrap(),
    );
    for e in &to_bob {
        assert_eq!(e.has_payment, e.tx_hash == id(&paid_send), "{}", e.tx_hash);
    }
    let in_block: Vec<MessageEventInfo> =
        strict(&srv.messaging_get_messages_in_block(3, None).await.unwrap());
    assert_eq!(in_block.len(), 4);
    let one: Option<MessageEventInfo> = strict(
        &srv.messaging_get_message_by_tx_hash(hx(&pay_kept))
            .await
            .unwrap(),
    );
    assert!(!one.unwrap().has_payment);
    let data: Option<MessageDataInfo> =
        strict(&srv.messaging_get_message_data(hx(&pay_kept)).await.unwrap());
    let data = data.unwrap();
    assert_eq!((data.has_payment, data.payment_amount), (false, None));
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
