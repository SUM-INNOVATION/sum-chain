//! A sponsored envelope in the string form that names an amount, at H−1, H
//! and H+1.
//!
//! Both messaging gates are at H = 3 on chain 7, and the transaction-index
//! gate is open from genesis, so each message keeps its own event row. The
//! rules:
//!
//! - **Below H, historical execution and presentation are preserved.**
//!   - The envelope executes as before: a success, with the relayer's
//!     balance, account nonce and receipt as before.
//!   - No escrow; the named sender's balance does not move.
//!   - The sender's messaging nonce advances by one, as before.
//!   - Every existing method's response is pinned byte for byte, and the
//!     same bytes hold once the chain is past H: the rule follows the
//!     inclusion height.
//! - **At H and H+1, a refusal.** A `Failed(7)` receipt; exactly one fee
//!   charged to the relayer, and exactly one advance of its account nonce;
//!   the named sender's balance unchanged, with no escrow row; the sender's
//!   messaging (envelope) nonce not consumed; no message stored.
//!
//! Only methods that exist before the payment methods are added are used, so
//! this file can be compiled unchanged against that earlier code to show that
//! the pinned bytes are its bytes.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Block, BlockHeader, Hash, MessagingOperation, Receipt, SignedTransaction, SponsoredMessage,
    TransactionV2, TxStatus,
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
/// Both messaging gates open from this height.
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
fn bob() -> KeyPair {
    key(0x63)
}
fn carol() -> KeyPair {
    key(0x64)
}
fn sponsor() -> KeyPair {
    key(0x65)
}

fn genesis() -> Genesis {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p.subsystem_tx_index_enabled_from_height = Some(0);
    p.messaging_sponsored_envelope_verification_enabled_from_height = Some(GATE);
    p.messaging_fee_nonce_accounting_enabled_from_height = Some(GATE);
    p.peer_protocol_declaration_required_from_height = Some(1);
    let mut alloc = HashMap::new();
    for k in [validator(), admin(), bob(), carol(), sponsor()] {
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
    params: ChainParams,
    server: RpcServer,
}

fn serve(g: &Genesis) -> Served {
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
    .with_chain_params(g.params.clone())
    .with_genesis(g);
    for kp in [validator(), admin(), bob(), carol(), sponsor()] {
        sumchain_storage::StateStore::new(&db)
            .put_account(
                &kp.address(),
                &sumchain_storage::schema::AccountState {
                    balance: FUNDS,
                    nonce: 0,
                },
            )
            .unwrap();
    }
    Served {
        _dir: dir,
        db,
        state,
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
        let mut block = Block::new(header, txs);
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
        receipts
    }

    fn tx(&self, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
        let nonce = self.state.get_nonce(&kp.address()).unwrap();
        let tx = TransactionV2::messaging(CHAIN_ID, kp.address(), FEE, nonce, data);
        let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    fn balance(&self, kp: &KeyPair) -> u128 {
        self.state.get_balance(&kp.address()).unwrap()
    }

    fn account_nonce(&self, kp: &KeyPair) -> u64 {
        self.state.get_nonce(&kp.address()).unwrap()
    }

    fn messaging_nonce(&self, kp: &KeyPair) -> u64 {
        MessagingStore::new(&self.db)
            .get_sender_nonce(&kp.address())
            .unwrap()
    }

    fn escrow(&self, t: &SignedTransaction) -> Option<u128> {
        MessagingStore::new(&self.db)
            .get_pending_payment(&t.hash())
            .unwrap()
            .map(|p| p.amount)
    }

    fn stored_flag(&self, t: &SignedTransaction) -> Option<bool> {
        MessagingStore::new(&self.db)
            .get_message_by_tx_hash(t.hash().as_bytes())
            .unwrap()
            .map(|e| e.has_payment)
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

/// `sender`'s envelope to `to` at `nonce` naming `amount`, signed over the
/// string form the relay checked before the envelope gate, which does not
/// cover the amount.
fn string_form(sender: &KeyPair, to: &KeyPair, nonce: u64, amount: u128) -> SponsoredMessage {
    let rh = recipient_hash(&to.address());
    let mut m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *sender.public_key().as_bytes(),
        nonce,
        expiry: 4_000_000_000,
        koppa_amount: Some(amount),
    };
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        hex::encode(m.recipient_hash),
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    );
    m.signature = *sign(preimage.as_bytes(), sender.private_key()).as_bytes();
    m
}

/// The existing methods' responses for the message `id` from `sender` to
/// `to`, carried at `height`, each serialized as a client receives it:
/// `get_receipt`, `getMessageByTxHash`, `getMessageData`, `getSentMessages`,
/// `getMessages`, `getMessagesInBlock`, `getPendingPayment`.
async fn existing_responses(
    srv: &RpcServer,
    id: &str,
    sender: &KeyPair,
    to: &KeyPair,
    height: u64,
) -> Vec<String> {
    let rh = format!("0x{}", hex::encode(recipient_hash(&to.address())));
    vec![
        serde_json::to_string(&srv.get_receipt(id.to_string()).await.unwrap()).unwrap(),
        serde_json::to_string(
            &srv.messaging_get_message_by_tx_hash(id.to_string())
                .await
                .unwrap(),
        )
        .unwrap(),
        serde_json::to_string(
            &srv.messaging_get_message_data(id.to_string())
                .await
                .unwrap(),
        )
        .unwrap(),
        serde_json::to_string(
            &srv.messaging_get_sent_messages(sender.address().to_base58(), None, None)
                .await
                .unwrap(),
        )
        .unwrap(),
        serde_json::to_string(&srv.messaging_get_messages(rh, None, None).await.unwrap()).unwrap(),
        serde_json::to_string(
            &srv.messaging_get_messages_in_block(height, None)
                .await
                .unwrap(),
        )
        .unwrap(),
        serde_json::to_string(
            &srv.messaging_get_pending_payment(id.to_string())
                .await
                .unwrap(),
        )
        .unwrap(),
    ]
}

#[tokio::test]
async fn a_string_form_amount_never_moves_value_or_reports_a_payment() {
    let s = serve(&genesis());
    let srv = &s.server;
    let setup = vec![
        s.tx(
            &admin(),
            op(
                MessagingOperation::SetSponsorshipEnabled,
                &SetSponsorshipEnabledData { enabled: true },
            ),
        ),
        s.tx(
            &carol(),
            op(
                MessagingOperation::RegisterPublicKey,
                &RegisterPublicKeyData {
                    public_key: *carol().public_key().as_bytes(),
                },
            ),
        ),
        s.tx(
            &bob(),
            op(
                MessagingOperation::RegisterPublicKey,
                &RegisterPublicKeyData {
                    public_key: *bob().public_key().as_bytes(),
                },
            ),
        ),
    ];
    assert!(s
        .publish(1, setup)
        .iter()
        .all(|r| r.status == TxStatus::Success));

    // ── H−1: historical execution and presentation ─────────────────────────
    let height = GATE - 1;
    let (carol_before, sponsor_before) = (s.balance(&carol()), s.balance(&sponsor()));
    let (sponsor_nonce, carol_nonce) = (s.account_nonce(&sponsor()), s.messaging_nonce(&carol()));
    let below = string_form(&carol(), &bob(), carol_nonce, 5_000);
    let t = s.tx(&sponsor(), op(MessagingOperation::SendMessage, &below));
    let r = s.publish(height, vec![t.clone()]);
    assert_eq!((r[0].status, r[0].fee_paid), (TxStatus::Success, FEE));
    // Below the accounting gate the relayer's balance and nonce are as before.
    assert_eq!(
        s.balance(&sponsor()),
        sponsor_before,
        "below the accounting gate the relayer's balance is as before"
    );
    assert_eq!(
        s.account_nonce(&sponsor()),
        sponsor_nonce,
        "below the accounting gate the relayer's nonce is as before"
    );
    assert_eq!(s.balance(&carol()), carol_before, "nothing moved");
    assert_eq!(s.escrow(&t), None);
    assert_eq!(s.messaging_nonce(&carol()), carol_nonce + 1);
    assert_eq!(
        s.stored_flag(&t),
        Some(true),
        "the stored row is kept as before"
    );

    let id = t.hash().to_hex();
    let carol_b58 = carol().address().to_base58();
    let bob_rh = format!("0x{}", hex::encode(recipient_hash(&bob().address())));
    let event = format!(
        r#"{{"tx_hash":"{id}","block_height":{height},"sender":"{carol_b58}","recipient_hash":"{bob_rh}","content_type":0,"flags":0,"has_payment":false,"payment_amount":null}}"#
    );
    let pinned = [
        (
            "get_receipt",
            format!(
                r#"{{"tx_hash":"{id}","block_height":{height},"tx_index":0,"status":"{}","fee_paid":"{FEE}"}}"#,
                TxStatus::Success.description()
            ),
        ),
        ("messaging_getMessageByTxHash", event.clone()),
        (
            "messaging_getMessageData",
            format!(
                r#"{{"tx_hash":"{id}","block_height":{height},"sender":"{carol_b58}","recipient_hash":"{bob_rh}","message_data":"0x{}","sender_pubkey":"0x{}","has_payment":false,"payment_amount":null}}"#,
                hex::encode(&below.message_data),
                hex::encode(below.sender_pubkey)
            ),
        ),
        ("messaging_getSentMessages", format!("[{event}]")),
        ("messaging_getMessages", format!("[{event}]")),
        ("messaging_getMessagesInBlock", format!("[{event}]")),
        ("messaging_getPendingPayment", "null".to_string()),
    ];
    let got = existing_responses(srv, &id, &carol(), &bob(), height).await;
    for ((method, want), got) in pinned.iter().zip(&got) {
        assert_eq!(got, want, "{method} at H-1");
    }

    // ── H and H+1: refused; one fee and one account nonce; nothing else ─────
    for height in [GATE, GATE + 1] {
        let (carol_before, sponsor_before) = (s.balance(&carol()), s.balance(&sponsor()));
        let (sponsor_nonce, carol_nonce) =
            (s.account_nonce(&sponsor()), s.messaging_nonce(&carol()));
        let t = s.tx(
            &sponsor(),
            op(
                MessagingOperation::SendMessage,
                &string_form(&carol(), &bob(), carol_nonce, 5_000),
            ),
        );
        let r = s.publish(height, vec![t.clone()]);
        assert_eq!(
            (r[0].status, r[0].fee_paid),
            (TxStatus::Failed(7), FEE),
            "{height}: a charged refusal"
        );
        assert_eq!(
            s.balance(&sponsor()),
            sponsor_before - FEE,
            "{height}: one fee"
        );
        assert_eq!(
            s.account_nonce(&sponsor()),
            sponsor_nonce + 1,
            "{height}: one account nonce"
        );
        assert_eq!(
            s.balance(&carol()),
            carol_before,
            "{height}: no value debit"
        );
        assert_eq!(s.escrow(&t), None, "{height}: no escrow row");
        assert_eq!(
            s.messaging_nonce(&carol()),
            carol_nonce,
            "{height}: the envelope nonce is not consumed"
        );
        assert_eq!(s.stored_flag(&t), None, "{height}: no message stored");
        let id = t.hash().to_hex();
        assert!(srv
            .messaging_get_message_by_tx_hash(id.clone())
            .await
            .unwrap()
            .is_none());
        assert!(srv
            .messaging_get_message_data(id.clone())
            .await
            .unwrap()
            .is_none());
        assert!(srv
            .messaging_get_pending_payment(id)
            .await
            .unwrap()
            .is_none());
    }

    // The H−1 responses are unchanged once the chain is past the gate.
    let got = existing_responses(srv, &id, &carol(), &bob(), GATE - 1).await;
    for ((method, want), got) in pinned.iter().zip(&got) {
        assert_eq!(got, want, "{method} after H+1");
    }
}
