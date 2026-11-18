//! `messaging_submitSponsored` applies the envelope forms of the block the
//! relayed transaction would land in, judged at the next block's height: below
//! `messaging_sponsored_envelope_verification_enabled_from_height`, either the
//! string form or the version-2 envelope; from it on, the version-2 envelope
//! only (strict signature, no amount, the sender's next messaging nonce). It
//! signs
//! each relayed transaction at the sponsor's next free account nonce, so
//! several relayed messages land in one block. And `messaging_getSenderNonce`
//! reports the committed messaging nonce a client must put in that envelope.
//!
//! The relay reads its sponsor key from the `SUMAIL_SPONSOR_KEY` environment
//! variable, which is process-wide: every test here goes through
//! [`sponsor_key_configured`], which writes one key file and sets the variable
//! once for the whole binary.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};

use sumchain_consensus::{ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, RegisteredPublicKey, SRC201_MAGIC, SRC201_NONCE_SIZE,
    SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_register_v1_signing_preimage, sponsored_send_v2_signing_preimage, Block, BlockHeader,
    Hash, Receipt, SignedTransaction, SponsoredMessage, TxInner, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    SponsoredRegistrationRequest, SponsoredRegistrationResponse, SubmitSponsoredMessageRequest,
};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore};
use tokio::sync::mpsc;

mod relay_retry_client;
use relay_retry_client::{Form, Intent, Outcome, Step, Tracker, MAX_WRAPPERS};

const CHAIN_ID: u64 = 1;
/// Far in the future, in Unix seconds.
const EXPIRY: u64 = 4_000_000_000;
/// The relay's fixed outer fee (`messaging_submitSponsored`).
const RELAY_FEE: u128 = 1_000_000;
const SPONSOR_FUNDS: u128 = 1_000_000_000;

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}
fn admin() -> KeyPair {
    KeyPair::from_bytes([0x61; 32])
}
/// Registered senders whose envelopes are relayed.
fn alice() -> KeyPair {
    KeyPair::from_bytes([0x62; 32])
}
fn carol() -> KeyPair {
    KeyPair::from_bytes([0x64; 32])
}
fn dave() -> KeyPair {
    KeyPair::from_bytes([0x66; 32])
}
fn bob() -> KeyPair {
    KeyPair::from_bytes([0x63; 32])
}
/// The relay's own key, read from `SUMAIL_SPONSOR_KEY`.
fn sponsor() -> KeyPair {
    KeyPair::from_bytes([0x65; 32])
}
/// Another sponsor, which submits outer transactions directly.
fn erin() -> KeyPair {
    KeyPair::from_bytes([0x67; 32])
}
/// Two more registered senders.
fn grace() -> KeyPair {
    KeyPair::from_bytes([0x69; 32])
}
fn heidi() -> KeyPair {
    KeyPair::from_bytes([0x6A; 32])
}
/// What alice, carol and erin hold, for the transactions they sign themselves.
const ACCOUNT_FUNDS: u128 = 1_000_000_000;

/// Writes the sponsor key file and points `SUMAIL_SPONSOR_KEY` at it, once
/// for the whole test binary.
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

fn params(envelope_gate: Option<u64>, accounting_gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p.messaging_sponsored_envelope_verification_enabled_from_height = envelope_gate;
    p.messaging_fee_nonce_accounting_enabled_from_height = accounting_gate;
    p
}

fn genesis_on(chain_id: u64, envelope_gate: Option<u64>, accounting_gate: Option<u64>) -> Genesis {
    Genesis::new(
        chain_id,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        params(envelope_gate, accounting_gate),
    )
}

fn genesis(envelope_gate: Option<u64>) -> Genesis {
    genesis_on(CHAIN_ID, envelope_gate, None)
}

struct Served {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    params: ChainParams,
    server: Arc<RpcServer>,
    /// The depth below the stored tip at which the server reports blocks
    /// final (0: every stored block is final).
    finality_depth: Arc<std::sync::atomic::AtomicU64>,
}

/// The engine's view, except the chain's height and its final height, which
/// are read from the block store: these tests publish blocks to the store
/// without driving the engine. A block `depth` or more below the stored tip
/// is reported final.
struct StoredChain {
    engine: Arc<dyn ConsensusQuery>,
    db: Arc<Database>,
    depth: Arc<std::sync::atomic::AtomicU64>,
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
            .saturating_sub(self.depth.load(std::sync::atomic::Ordering::SeqCst))
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
        self.depth.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn finality_mechanism(&self) -> sumchain_consensus::FinalityMechanism {
        self.engine.finality_mechanism()
    }
}

/// A server over a fresh database with no block: the next block is height 1.
/// The sponsor, alice, carol and erin are funded, alice, carol, dave, grace
/// and heidi are registered, and sponsorship is enabled, all in committed
/// state.
fn serve(genesis: &Genesis) -> Served {
    sponsor_key_configured();
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
    let finality_depth = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let engine: Arc<dyn ConsensusQuery> = Arc::new(StoredChain {
        engine,
        db: db.clone(),
        depth: finality_depth.clone(),
    });
    let (tx_sender, rx) = mpsc::channel(256);
    // Keep the receiver alive for the server's lifetime, so a broadcast is
    // never refused for want of a listener.
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
    .with_chain_params(genesis.params.clone())
    .with_genesis(genesis);
    let store = MessagingStore::new(&db);
    for kp in [alice(), carol(), dave(), grace(), heidi()] {
        store
            .set_public_key(
                &kp.address(),
                &RegisteredPublicKey {
                    public_key: *kp.public_key().as_bytes(),
                    address: kp.address(),
                    registered_at_block: 0,
                    registered_at: 0,
                    updated_at_block: 0,
                },
            )
            .unwrap();
    }
    store.set_sponsorship_enabled(true).unwrap();
    for (kp, balance) in [
        (sponsor(), SPONSOR_FUNDS),
        (alice(), ACCOUNT_FUNDS),
        (carol(), ACCOUNT_FUNDS),
        (erin(), ACCOUNT_FUNDS),
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
        params: genesis.params.clone(),
        server: Arc::new(server),
        finality_depth,
    }
}

impl Served {
    /// What the producer would carry next, executed and published as the
    /// block at `height` through the real block path; the carried
    /// transactions leave the pool, as the node removes them.
    fn publish_pool(&self, height: u64) -> (Vec<SignedTransaction>, Vec<Receipt>) {
        let txs = self.mempool.select_for_block(1_000);
        let receipts = self.publish(height, txs.clone());
        (txs, receipts)
    }

    /// `txs`, in this order, executed and published as the block at `height`,
    /// and stored as the chain's latest block, so the relay judges the next
    /// block to be `height + 1`. The carried transactions leave the pool.
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
        let accumulator = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(accumulator);
        sumchain_storage::BlockStore::new(&self.db)
            .put(&block)
            .expect("store the block");
        for tx in &txs {
            self.mempool.remove(&tx.hash());
        }
        receipts
    }

    /// `kp`'s outer messaging transaction at `nonce`, outside the relay.
    fn outer(
        &self,
        kp: &KeyPair,
        nonce: u64,
        fee: u128,
        data: sumchain_primitives::MessagingTxData,
    ) -> SignedTransaction {
        let tx = sumchain_primitives::TransactionV2::messaging(
            self.state.chain_id(),
            kp.address(),
            fee,
            nonce,
            data,
        );
        let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    /// `m` relayed by `kp` directly, at `kp`'s account nonce `nonce`.
    fn relayed_by(&self, kp: &KeyPair, nonce: u64, m: &SponsoredMessage) -> SignedTransaction {
        self.outer(
            kp,
            nonce,
            RELAY_FEE,
            sumchain_primitives::MessagingTxData {
                operation: sumchain_primitives::MessagingOperation::SendMessage,
                data: bincode::serialize(m).unwrap(),
            },
        )
    }

    fn balance(&self, kp: &KeyPair) -> u128 {
        self.state.get_balance(&kp.address()).unwrap()
    }

    fn account_nonce(&self, kp: &KeyPair) -> u64 {
        self.state.get_nonce(&kp.address()).unwrap()
    }

    fn sent_by(&self, kp: &KeyPair) -> usize {
        MessagingStore::new(&self.db)
            .get_messages_by_sender(&kp.address(), 1_000, 0)
            .unwrap()
            .len()
    }

    fn sponsor_nonce(&self) -> u64 {
        self.state.get_nonce(&sponsor().address()).unwrap()
    }

    fn messaging_nonce(&self, kp: &KeyPair) -> u64 {
        MessagingStore::new(&self.db)
            .get_sender_nonce(&kp.address())
            .unwrap()
    }

    /// The sponsor nonces of the relayed transactions this node holds.
    fn pending_sponsor_nonces(&self) -> Vec<u64> {
        let mut n: Vec<u64> = self
            .mempool
            .get_by_sender(&sponsor().address())
            .iter()
            .map(|tx| tx.nonce())
            .collect();
        n.sort_unstable();
        n
    }

    async fn relay(
        &self,
        m: &SponsoredMessage,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.server
            .messaging_submit_sponsored(request(m))
            .await
            .map(|r| r.tx_hash)
    }

    /// `kp`'s sponsored registration, requested of this relay.
    async fn register(&self, kp: &KeyPair) -> SponsoredRegistrationResponse {
        self.server
            .messaging_register_sponsored(registration_request(kp))
            .await
            .unwrap()
    }

    fn is_registered(&self, kp: &KeyPair) -> bool {
        MessagingStore::new(&self.db)
            .has_public_key(&kp.address())
            .unwrap()
    }
}

/// `g` with sponsored registration open from genesis.
fn with_registration(mut g: Genesis) -> Genesis {
    g.params
        .messaging_sponsored_registration_enabled_from_height = Some(0);
    g
}

/// The request a client sends to register `kp`'s key through this relay: its
/// signature over the registration preimage for this chain and the relay's
/// sponsor.
fn registration_request(kp: &KeyPair) -> SponsoredRegistrationRequest {
    let preimage = sponsored_register_v1_signing_preimage(
        CHAIN_ID,
        &sponsor().address(),
        kp.public_key().as_bytes(),
    );
    SponsoredRegistrationRequest {
        public_key: format!("0x{}", hex::encode(kp.public_key().as_bytes())),
        signature: format!(
            "0x{}",
            hex::encode(sign(&preimage, kp.private_key()).as_bytes())
        ),
    }
}

fn status_only(receipts: &[Receipt]) -> Vec<TxStatus> {
    receipts.iter().map(|r| r.status).collect()
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

/// `sender`'s envelope to bob at `nonce`, unsigned; `salt` varies the message
/// so two envelopes at one nonce are different transactions.
fn envelope_from(sender: &KeyPair, nonce: u64, salt: u8, amount: Option<u128>) -> SponsoredMessage {
    let rh = recipient_hash(&bob().address());
    let mut message_data = valid_message(rh);
    message_data.push(salt);
    SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *sender.public_key().as_bytes(),
        nonce,
        expiry: EXPIRY,
        koppa_amount: amount,
    }
}

/// Carol's envelope to bob at `nonce`, unsigned.
fn envelope(nonce: u64, salt: u8, amount: Option<u128>) -> SponsoredMessage {
    envelope_from(&carol(), nonce, salt, amount)
}

/// Signed by `signer` over the version-2 preimage for `chain_id`.
fn v2_by(mut m: SponsoredMessage, signer: &KeyPair, chain_id: u64) -> SponsoredMessage {
    let preimage = sponsored_send_v2_signing_preimage(chain_id, &m);
    m.signature = *sign(&preimage, signer.private_key()).as_bytes();
    m
}

/// Signed by carol over the version-2 preimage for this chain.
fn v2(m: SponsoredMessage) -> SponsoredMessage {
    v2_by(m, &carol(), CHAIN_ID)
}

/// Signed by carol over the string form the relay checked before the gate.
fn v1(m: SponsoredMessage) -> SponsoredMessage {
    v1_by(m, &carol())
}

/// Signed by `signer` over the string form the relay checked before the gate.
fn v1_by(mut m: SponsoredMessage, signer: &KeyPair) -> SponsoredMessage {
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        hex::encode(m.recipient_hash),
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    );
    m.signature = *sign(preimage.as_bytes(), signer.private_key()).as_bytes();
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

/// The relayed transactions' envelopes, decoded from the pool.
fn relayed_envelopes(s: &Served) -> Vec<SponsoredMessage> {
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

fn statuses(receipts: &[Receipt]) -> Vec<(TxStatus, u128)> {
    receipts.iter().map(|r| (r.status, r.fee_paid)).collect()
}

#[tokio::test]
async fn the_relay_applies_the_envelope_form_of_the_next_block() {
    // ── the gate absent: the string form as before, or version 2 ───────────
    {
        let s = serve(&genesis(None));
        let ok = s.relay(&v1(envelope(0, 1, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        // The version-2 form is accepted too, at the sender's next nonce; a
        // string-form envelope claims no place in that sequence.
        let ok = s.relay(&v2(envelope(0, 2, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        let err = s
            .relay(&v2(envelope(5, 3, None)))
            .await
            .expect_err("a version-2 envelope follows the sequence below the gate too");
        assert!(
            err.message()
                .contains("is not the sender's next messaging nonce 1"),
            "{err}"
        );
        let err = s
            .relay(&v2(envelope(1, 4, Some(5))))
            .await
            .expect_err("a version-2 envelope carries no amount below the gate too");
        assert!(err.message().contains("koppa_amount"), "{err}");
        // The string form has no nonce rule at the relay: any value relays.
        let ok = s.relay(&v1(envelope(42, 5, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        // Neither form.
        let err = s.relay(&envelope(0, 6, None)).await.expect_err("unsigned");
        assert!(
            err.message()
                .contains("neither the version-2 envelope preimage nor the string form"),
            "{err}"
        );
        let relayed = relayed_envelopes(&s);
        assert_eq!(relayed.len(), 3);
        assert_eq!(
            relayed.iter().map(|m| m.nonce).collect::<BTreeSet<_>>(),
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
            .relay(&v1(envelope(0, 1, None)))
            .await
            .expect_err("the string form is not a version-2 signature");
        assert!(err.message().contains("version-2"), "{err}");
        let err = s
            .relay(&v2(envelope(1, 2, None)))
            .await
            .expect_err("not the sender's next nonce");
        assert!(
            err.message()
                .contains("is not the sender's next messaging nonce 0"),
            "{err}"
        );
        let err = s
            .relay(&v2(envelope(0, 3, Some(ACCOUNT_FUNDS + 1))))
            .await
            .expect_err("an amount the named sender cannot fund is refused");
        assert!(err.message().contains("koppa_amount"), "{err}");
        let err = s.relay(&envelope(0, 4, None)).await.expect_err("unsigned");
        assert!(err.message().contains("Invalid sender signature"), "{err}");
        assert!(relayed_envelopes(&s).is_empty(), "nothing relayed so far");

        let ok = s.relay(&v2(envelope(0, 5, None))).await;
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
            .relay(&v2(envelope(0, 6, None)))
            .await
            .expect_err("nonce 0 is spent");
        assert!(
            err.message()
                .contains("Envelope nonce 0 is already used: the sender's messaging nonce is 1"),
            "{err}"
        );
        let ok = s.relay(&v2(envelope(1, 7, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(relayed_envelopes(&s).len(), 2);
    }

    // ── the gate above the next block: either form ──────────────────────────
    {
        let s = serve(&genesis(Some(2)));
        let ok = s.relay(&v1(envelope(0, 1, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        let ok = s.relay(&v2(envelope(0, 2, None))).await;
        assert!(ok.is_ok(), "{ok:?}");
        assert_eq!(relayed_envelopes(&s).len(), 2);
    }
}

/// Across the envelope gate H (= 2 here): relayed while the next block is
/// H-1 (the tip at H-2), a string-form envelope and a version-2 envelope are
/// both accepted by the relay. Carried at H-1 both succeed. Carried late, at
/// H, the string-form envelope is refused (`Failed(7)`) and the version-2
/// envelope succeeds: the version-2 form is the one that is valid on both
/// sides. With the accounting gate also at H, the late string-form envelope
/// costs the sponsor its fee and a nonce.
#[tokio::test]
async fn an_envelope_relayed_before_the_gate_and_carried_at_or_after_it() {
    // Carried on time, at H-1.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(2), None));
        let string_form = s.relay(&v1(envelope(0, 1, None))).await.unwrap();
        let alice_v2 = s
            .relay(&v2_by(
                envelope_from(&alice(), 0, 2, None),
                &alice(),
                CHAIN_ID,
            ))
            .await
            .unwrap();
        let (carried, receipts) = s.publish_pool(1);
        let by_hash: HashMap<String, (TxStatus, u128)> = carried
            .iter()
            .zip(&receipts)
            .map(|(t, r)| (t.hash().to_hex(), (r.status, r.fee_paid)))
            .collect();
        assert_eq!(by_hash[&string_form].0, TxStatus::Success);
        assert_eq!(by_hash[&alice_v2].0, TxStatus::Success);
    }
    // Carried late, at H, with the accounting gate absent: nothing charged
    // for the refusal.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(2), None));
        let string_form = s.relay(&v1(envelope(0, 1, None))).await.unwrap();
        let alice_v2 = s
            .relay(&v2_by(
                envelope_from(&alice(), 0, 2, None),
                &alice(),
                CHAIN_ID,
            ))
            .await
            .unwrap();
        let (carried, receipts) = s.publish_pool(2);
        let by_hash: HashMap<String, (TxStatus, u128)> = carried
            .iter()
            .zip(&receipts)
            .map(|(t, r)| (t.hash().to_hex(), (r.status, r.fee_paid)))
            .collect();
        assert_eq!(by_hash[&string_form], (TxStatus::Failed(7), 0));
        assert_eq!(by_hash[&alice_v2], (TxStatus::Success, RELAY_FEE));
        assert_eq!(
            (s.messaging_nonce(&carol()), s.messaging_nonce(&alice())),
            (0, 1)
        );
    }
    // Carried late, at H, with the accounting gate at H as well: the refusal
    // costs the sponsor the fee and a nonce.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(2), Some(2)));
        s.relay(&v1(envelope(0, 1, None))).await.unwrap();
        let (_, receipts) = s.publish_pool(2);
        assert_eq!(statuses(&receipts), vec![(TxStatus::Failed(7), RELAY_FEE)]);
        assert_eq!(s.sponsor_nonce(), 1);
        assert_eq!(
            s.state.get_balance(&sponsor().address()).unwrap(),
            SPONSOR_FUNDS - RELAY_FEE
        );
        assert_eq!(s.messaging_nonce(&carol()), 0);
    }
}

/// With both gates open at the next block, five relayed messages (three
/// senders, two of them sending twice) are signed at five consecutive sponsor
/// nonces, carried in nonce order and all succeed in one block. A second
/// envelope at a (sender, nonce) the relay already holds, and one that skips a
/// nonce, are refused. The next block continues from the sponsor's new nonce.
#[tokio::test]
async fn several_relayed_messages_land_in_one_block_with_the_accounting_gate_open() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let sends = [
        v2(envelope(0, 1, None)),
        v2_by(envelope_from(&alice(), 0, 2, None), &alice(), CHAIN_ID),
        v2_by(envelope_from(&dave(), 0, 3, None), &dave(), CHAIN_ID),
        v2(envelope(1, 4, None)),
        v2_by(envelope_from(&alice(), 1, 5, None), &alice(), CHAIN_ID),
    ];
    for m in &sends {
        let ok = s.relay(m).await;
        assert!(ok.is_ok(), "{ok:?}");
    }
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 1, 2, 3, 4]);

    let err = s
        .relay(&v2(envelope(1, 6, None)))
        .await
        .expect_err("carol's nonce 1 is already pending");
    assert!(
        err.message()
            .contains("An envelope from this sender at nonce 1 is already pending"),
        "{err}"
    );
    let err = s
        .relay(&v2(envelope(3, 7, None)))
        .await
        .expect_err("carol's next is 2");
    assert!(
        err.message()
            .contains("is not the sender's next messaging nonce 2"),
        "{err}"
    );
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 1, 2, 3, 4]);

    let (carried, receipts) = s.publish_pool(1);
    assert_eq!(
        carried.iter().map(|t| t.nonce()).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4],
        "carried in nonce order"
    );
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE); 5]);
    assert_eq!(s.sponsor_nonce(), 5);
    assert_eq!(
        s.state.get_balance(&sponsor().address()).unwrap(),
        SPONSOR_FUNDS - 5 * RELAY_FEE
    );
    assert_eq!(
        (
            s.messaging_nonce(&carol()),
            s.messaging_nonce(&alice()),
            s.messaging_nonce(&dave())
        ),
        (2, 2, 1)
    );

    // The next block continues from the sponsor's new nonce.
    let ok = s.relay(&v2(envelope(2, 8, None))).await;
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(s.pending_sponsor_nonces(), vec![5]);
    let (_, receipts) = s.publish_pool(2);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE)]);
    assert_eq!((s.sponsor_nonce(), s.messaging_nonce(&carol())), (6, 3));
}

/// Below the accounting gate a relayed message does not advance the sponsor's
/// nonce, so every relay is signed at the committed nonce, exactly as before,
/// and all of them succeed in one block; the sponsor's nonce stays where it
/// was and nothing is charged.
#[tokio::test]
async fn below_the_accounting_gate_relays_share_the_committed_sponsor_nonce() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), None));
    for m in [
        v2(envelope(0, 1, None)),
        v2_by(envelope_from(&alice(), 0, 2, None), &alice(), CHAIN_ID),
        v2(envelope(1, 3, None)),
    ] {
        let ok = s.relay(&m).await;
        assert!(ok.is_ok(), "{ok:?}");
    }
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 0, 0]);
    let (_, receipts) = s.publish_pool(1);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE); 3]);
    assert_eq!(s.sponsor_nonce(), 0);
    assert_eq!(
        s.state.get_balance(&sponsor().address()).unwrap(),
        SPONSOR_FUNDS
    );
    assert_eq!(
        (s.messaging_nonce(&carol()), s.messaging_nonce(&alice())),
        (2, 1)
    );
}

/// `messaging_getMessageData` reports only a message the canonical chain
/// executed, and never a payment for a relayed message:
/// - an accepted version-2 envelope: its sender and content, no payment;
/// - an envelope naming a sender who did not sign it and carrying an
///   amount, refused in the block: nothing (no sender, no payment);
/// - a transaction stored with no canonical receipt (as a block that lost
///   fork choice leaves it): nothing;
/// - below the envelope gate, an executed string-form envelope carrying an
///   amount: its sender and content, and no payment, because none moved.
#[tokio::test]
async fn message_data_reports_only_an_executed_message_and_no_payment() {
    use sumchain_primitives::{MessagingOperation, MessagingTxData, TransactionV2};

    // Both gates at the next block.
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let accepted = s
        .relay(&v2_by(
            envelope_from(&alice(), 0, 1, None),
            &alice(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    // An outer transaction by the sponsor key, carrying an envelope that
    // names carol, carries an amount and is signed by someone else.
    let refused_envelope = v2_by(envelope(0, 2, Some(5_000)), &dave(), CHAIN_ID);
    let refused_tx = {
        let tx = TransactionV2::messaging(
            CHAIN_ID,
            sponsor().address(),
            RELAY_FEE,
            1,
            MessagingTxData {
                operation: MessagingOperation::SendMessage,
                data: bincode::serialize(&refused_envelope).unwrap(),
            },
        );
        let sig = sign(tx.signing_hash().as_bytes(), sponsor().private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *sponsor().public_key().as_bytes())
    };
    s.mempool.add(refused_tx.clone()).unwrap();
    let (carried, receipts) = s.publish_pool(1);
    let by_hash: HashMap<String, (TxStatus, u128)> = carried
        .iter()
        .zip(&receipts)
        .map(|(t, r)| (t.hash().to_hex(), (r.status, r.fee_paid)))
        .collect();
    assert_eq!(by_hash[&accepted], (TxStatus::Success, RELAY_FEE));
    assert_eq!(
        by_hash[&refused_tx.hash().to_hex()],
        (TxStatus::Failed(7), RELAY_FEE)
    );

    let data = s
        .server
        .messaging_get_message_data(accepted.clone())
        .await
        .unwrap()
        .expect("an executed message");
    assert_eq!(data.sender, alice().address().to_base58());
    assert_eq!(data.block_height, 1);
    assert!(!data.has_payment);
    assert_eq!(data.payment_amount, None);

    let none = s
        .server
        .messaging_get_message_data(refused_tx.hash().to_hex())
        .await
        .unwrap();
    assert!(none.is_none(), "a refused envelope is no message: {none:?}");

    // Stored, but no canonical receipt.
    let unreceipted = v2_by(envelope_from(&alice(), 1, 3, None), &alice(), CHAIN_ID);
    let side_tx = {
        let tx = TransactionV2::messaging(
            CHAIN_ID,
            sponsor().address(),
            RELAY_FEE,
            9,
            MessagingTxData {
                operation: MessagingOperation::SendMessage,
                data: bincode::serialize(&unreceipted).unwrap(),
            },
        );
        let sig = sign(tx.signing_hash().as_bytes(), sponsor().private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *sponsor().public_key().as_bytes())
    };
    sumchain_storage::TxStore::new(&s.db).put(&side_tx).unwrap();
    let none = s
        .server
        .messaging_get_message_data(side_tx.hash().to_hex())
        .await
        .unwrap();
    assert!(none.is_none(), "no canonical receipt, no message: {none:?}");

    // Below the envelope gate: an executed envelope that carried an amount.
    let s = serve(&genesis_on(CHAIN_ID, None, None));
    let with_amount = s.relay(&v1(envelope(0, 4, Some(5_000)))).await.unwrap();
    let (_, receipts) = s.publish_pool(1);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE)]);
    let data = s
        .server
        .messaging_get_message_data(with_amount)
        .await
        .unwrap()
        .expect("an executed message");
    assert_eq!(data.sender, carol().address().to_base58());
    assert!(!data.has_payment, "no amount moved");
    assert_eq!(data.payment_amount, None);
}

/// On a chain whose id is not 1, the relay checks the envelope against that
/// chain: an envelope signed for chain 7 relays and succeeds there, one
/// signed for chain 1 is refused.
#[tokio::test]
async fn the_relay_binds_the_envelope_to_its_own_chain() {
    const CHAIN_7: u64 = 7;
    let s = serve(&genesis_on(CHAIN_7, Some(1), Some(1)));
    let err = s
        .relay(&v2_by(envelope(0, 1, None), &carol(), CHAIN_ID))
        .await
        .expect_err("signed for chain 1");
    assert!(err.message().contains("Invalid sender signature"), "{err}");
    let ok = s
        .relay(&v2_by(envelope(0, 2, None), &carol(), CHAIN_7))
        .await;
    assert!(ok.is_ok(), "{ok:?}");
    let (_, receipts) = s.publish_pool(1);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE)]);
    assert_eq!(s.messaging_nonce(&carol()), 1);
}

/// Each carried transaction's (status, fee), by its hash as the relay
/// reports it.
fn by_hash(
    carried: &[SignedTransaction],
    receipts: &[Receipt],
) -> HashMap<String, (TxStatus, u128)> {
    carried
        .iter()
        .zip(receipts)
        .map(|(t, r)| (t.hash().to_hex(), (r.status, r.fee_paid)))
        .collect()
}

/// The pool's copies of the transactions `hashes` names, in that order.
fn pooled(s: &Served, hashes: &[&String]) -> Vec<SignedTransaction> {
    hashes
        .iter()
        .map(|h| s.mempool.get(&Hash::from_hex(h).unwrap()).expect("pending"))
        .collect()
}

/// Relay requests arriving at once, from interleaved senders, on separate
/// threads, each take a distinct sponsor nonce; a request the relay refuses
/// takes none, so the nonces stay contiguous. All of them are carried in
/// nonce order and succeed in one block with the accounting gate open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_relays_each_take_a_distinct_sponsor_nonce() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let senders = [carol(), alice(), dave(), grace(), heidi()];
    for wave in 0..2u64 {
        let mut accepted = Vec::new();
        for (i, kp) in senders.iter().enumerate() {
            let m = v2_by(
                envelope_from(kp, wave, (10 * wave) as u8 + i as u8, None),
                kp,
                CHAIN_ID,
            );
            let server = s.server.clone();
            accepted.push(tokio::spawn(async move {
                server.messaging_submit_sponsored(request(&m)).await
            }));
        }
        // Among them, a request without a version-2 signature.
        let unsigned = envelope_from(&heidi(), 9, 99, None);
        let server = s.server.clone();
        let refused =
            tokio::spawn(
                async move { server.messaging_submit_sponsored(request(&unsigned)).await },
            );
        for task in accepted {
            let r = task.await.unwrap();
            assert!(r.is_ok(), "{r:?}");
        }
        assert!(refused.await.unwrap().is_err());
        assert_eq!(
            s.pending_sponsor_nonces(),
            (0..5 * (wave + 1)).collect::<Vec<_>>(),
            "wave {wave}: distinct and contiguous"
        );
    }
    let (carried, receipts) = s.publish_pool(1);
    assert_eq!(
        carried.iter().map(|t| t.nonce()).collect::<Vec<_>>(),
        (0..10).collect::<Vec<_>>(),
        "carried in nonce order"
    );
    assert_eq!(
        statuses(&receipts),
        vec![(TxStatus::Success, RELAY_FEE); 10]
    );
    assert_eq!(s.sponsor_nonce(), 10);
    for kp in &senders {
        assert_eq!(s.messaging_nonce(kp), 2);
    }
}

/// A failure does not strand the relays after it:
/// - a relayed transaction that leaves the pool without being carried (as an
///   eviction would) leaves a gap, and the next relay fills it;
/// - an envelope refused in the block (its sender's own direct message,
///   carried first, moved her messaging nonce) is charged and spends its
///   sponsor nonce, so the relayed transactions after it still execute.
#[tokio::test]
async fn a_failure_does_not_strand_the_relays_after_it() {
    use sumchain_primitives::messaging::SendMessageData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let carol_env = s.relay(&v2(envelope(0, 1, None))).await.unwrap();
    let alice_env = s
        .relay(&v2_by(
            envelope_from(&alice(), 0, 2, None),
            &alice(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let dave_env = s
        .relay(&v2_by(
            envelope_from(&dave(), 0, 3, None),
            &dave(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 1, 2]);

    assert!(s
        .mempool
        .remove(&Hash::from_hex(&alice_env).unwrap())
        .is_some());
    let heidi_env = s
        .relay(&v2_by(
            envelope_from(&heidi(), 0, 4, None),
            &heidi(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    assert_eq!(
        s.pending_sponsor_nonces(),
        vec![0, 1, 2],
        "the gap is filled"
    );

    let rh = recipient_hash(&bob().address());
    let direct = s.outer(
        &carol(),
        0,
        2 * RELAY_FEE,
        MessagingTxData {
            operation: MessagingOperation::SendMessageDirect,
            data: bincode::serialize(&SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            })
            .unwrap(),
        },
    );
    s.mempool.add(direct.clone()).unwrap();
    let (carried, receipts) = s.publish_pool(1);
    assert_eq!(
        carried[0].hash(),
        direct.hash(),
        "the higher fee is carried first"
    );
    let by = by_hash(&carried, &receipts);
    assert_eq!(
        by[&direct.hash().to_hex()],
        (TxStatus::Success, 2 * RELAY_FEE)
    );
    assert_eq!(by[&carol_env], (TxStatus::Failed(7), RELAY_FEE));
    assert_eq!(by[&heidi_env], (TxStatus::Success, RELAY_FEE));
    assert_eq!(by[&dave_env], (TxStatus::Success, RELAY_FEE));
    assert_eq!(s.sponsor_nonce(), 3);
    assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS - 3 * RELAY_FEE);
    assert_eq!(
        (
            s.messaging_nonce(&carol()),
            s.messaging_nonce(&heidi()),
            s.messaging_nonce(&dave()),
            s.messaging_nonce(&alice())
        ),
        (1, 1, 1, 0)
    );
}

/// The envelope gate at H = 3, the accounting gate absent. At each height the
/// relay accepts what the next block will execute: at H-1 both forms, at H
/// and H+1 only the version-2 envelope; every envelope it accepted and that is
/// carried at the height it judged succeeds. Two envelopes relayed at H-1 are
/// left pending across H: carried at H, the string-form one is refused
/// (`Failed(7)`, no fee with this gate absent) and the version-2 one
/// succeeds.
#[tokio::test]
async fn the_envelope_boundary_at_h_minus_1_h_and_h_plus_1() {
    const H: u64 = 3;
    let s = serve(&genesis_on(CHAIN_ID, Some(H), None));
    s.publish(1, Vec::new());

    // The next block is H-1.
    let s_a = s.relay(&v1(envelope(0, 1, None))).await.unwrap();
    let v_a = s
        .relay(&v2_by(
            envelope_from(&alice(), 0, 2, None),
            &alice(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let s_x = s.relay(&v1(envelope(0, 3, None))).await.unwrap();
    let v_x = s
        .relay(&v2_by(
            envelope_from(&dave(), 0, 4, None),
            &dave(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let r = s.publish(H - 1, pooled(&s, &[&s_a, &v_a]));
    assert_eq!(
        statuses(&r),
        vec![(TxStatus::Success, RELAY_FEE); 2],
        "at H-1"
    );

    // The next block is H.
    let err = s
        .relay(&v1(envelope(0, 5, None)))
        .await
        .expect_err("the string form is refused from H");
    assert!(err.message().contains("version-2"), "{err}");
    let v_b = s
        .relay(&v2_by(
            envelope_from(&alice(), 1, 6, None),
            &alice(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let r = s.publish(H, pooled(&s, &[&s_x, &v_x, &v_b]));
    assert_eq!(
        statuses(&r),
        vec![
            (TxStatus::Failed(7), 0),
            (TxStatus::Success, RELAY_FEE),
            (TxStatus::Success, RELAY_FEE)
        ],
        "at H: the string-form envelope relayed at H-1 is refused, the version-2 ones succeed"
    );

    // The next block is H+1.
    let err = s
        .relay(&v1(envelope(1, 7, None)))
        .await
        .expect_err("the string form is refused after H");
    assert!(err.message().contains("version-2"), "{err}");
    let v_c = s
        .relay(&v2_by(
            envelope_from(&dave(), 1, 8, None),
            &dave(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let r = s.publish(H + 1, pooled(&s, &[&v_c]));
    assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE)], "at H+1");

    assert_eq!(
        (
            s.messaging_nonce(&carol()),
            s.messaging_nonce(&alice()),
            s.messaging_nonce(&dave())
        ),
        (1, 2, 2)
    );
}

/// Both gates at H = 3. Relayed at H-1, below the accounting gate, relayed
/// messages share the committed sponsor nonce, as they always have; two of
/// them carried at H-1 succeed. Three more relayed at H-1 are left pending
/// across H, all at sponsor nonce 0. From H a messaging transaction advances
/// the sponsor's nonce, so in the block at H only the first of the three
/// carried executes (the string-form one would be refused and charged); the
/// other two take `InvalidNonce`, uncharged, and their messages are not
/// delivered. A message relayed at H takes sponsor nonce 1 and succeeds.
/// This is the boundary cost of the accounting gate for relays in flight.
#[tokio::test]
async fn relays_in_flight_across_both_gates() {
    const H: u64 = 3;
    let s = serve(&genesis_on(CHAIN_ID, Some(H), Some(H)));
    s.publish(1, Vec::new());

    // The next block is H-1.
    let on_time_string = s.relay(&v1(envelope(0, 1, None))).await.unwrap();
    let on_time_v2 = s
        .relay(&v2_by(
            envelope_from(&grace(), 0, 2, None),
            &grace(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    let crossing = [
        s.relay(&v1(envelope(0, 3, None))).await.unwrap(),
        s.relay(&v2_by(
            envelope_from(&dave(), 0, 4, None),
            &dave(),
            CHAIN_ID,
        ))
        .await
        .unwrap(),
        s.relay(&v2_by(
            envelope_from(&alice(), 0, 5, None),
            &alice(),
            CHAIN_ID,
        ))
        .await
        .unwrap(),
    ];
    assert_eq!(s.pending_sponsor_nonces(), vec![0; 5]);
    let r = s.publish(H - 1, pooled(&s, &[&on_time_string, &on_time_v2]));
    assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE); 2]);
    assert_eq!(s.sponsor_nonce(), 0);
    assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS);

    // The next block is H.
    assert!(s.relay(&v1(envelope(1, 6, None))).await.is_err());
    let at_h = s
        .relay(&v2_by(
            envelope_from(&heidi(), 0, 7, None),
            &heidi(),
            CHAIN_ID,
        ))
        .await
        .unwrap();
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 0, 0, 1]);
    let (carried, receipts) = s.publish_pool(H);
    let by = by_hash(&carried, &receipts);
    let executed: Vec<&String> = crossing
        .iter()
        .filter(|h| by[*h].0 != TxStatus::InvalidNonce)
        .collect();
    assert_eq!(executed.len(), 1, "one of the three spends sponsor nonce 0");
    let expected = if *executed[0] == crossing[0] {
        (TxStatus::Failed(7), RELAY_FEE)
    } else {
        (TxStatus::Success, RELAY_FEE)
    };
    assert_eq!(by[executed[0]], expected);
    for h in crossing.iter().filter(|h| *h != executed[0]) {
        assert_eq!(by[h], (TxStatus::InvalidNonce, 0));
    }
    assert_eq!(by[&at_h], (TxStatus::Success, RELAY_FEE));
    assert_eq!(s.sponsor_nonce(), 2);
    assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS - 2 * RELAY_FEE);
}

/// Every messaging RPC that shows a payment agrees with the executed outcome
/// (the receipt and the escrow rows), case by case: an accepted relayed
/// message; relayed envelopes refused in the block for an amount, for a
/// signature by another key and for a nonce out of sequence; a paid send,
/// which escrows its amount; and, below the envelope gate, an executed
/// relayed message whose envelope claimed an amount.
#[tokio::test]
async fn payment_display_agrees_with_the_executed_outcome() {
    use sumchain_primitives::messaging::SendMessageWithPaymentData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    // The transaction-index gate open from genesis, so each message in one
    // block keeps its own event row (below that gate every row in a block is
    // keyed by index 0, and the last message to a recipient replaces the
    // earlier ones).
    let indexed = |envelope_gate: Option<u64>, accounting_gate: Option<u64>| {
        let mut g = genesis_on(CHAIN_ID, envelope_gate, accounting_gate);
        g.params.subsystem_tx_index_enabled_from_height = Some(0);
        g
    };
    let s = serve(&indexed(Some(1), Some(1)));
    let accepted = s.relay(&v2(envelope(0, 1, None))).await.unwrap();
    let with_amount = s.relayed_by(
        &erin(),
        0,
        &v2_by(envelope_from(&dave(), 0, 2, Some(5_000)), &dave(), CHAIN_ID),
    );
    let wrong_signer = s.relayed_by(
        &erin(),
        1,
        &v2_by(envelope_from(&grace(), 0, 3, None), &heidi(), CHAIN_ID),
    );
    let wrong_nonce = s.relayed_by(
        &erin(),
        2,
        &v2_by(envelope_from(&heidi(), 7, 4, None), &heidi(), CHAIN_ID),
    );
    let rh = recipient_hash(&bob().address());
    let paid = s.outer(
        &alice(),
        0,
        RELAY_FEE,
        MessagingTxData {
            operation: MessagingOperation::SendMessageWithPayment,
            data: bincode::serialize(&SendMessageWithPaymentData {
                message_data: valid_message(rh),
                recipient_hash: rh,
                koppa_amount: 500,
            })
            .unwrap(),
        },
    );
    for tx in [&with_amount, &wrong_signer, &wrong_nonce, &paid] {
        s.mempool.add(tx.clone()).unwrap();
    }
    let (carried, receipts) = s.publish_pool(1);
    let by = by_hash(&carried, &receipts);
    let refused = [
        with_amount.hash().to_hex(),
        wrong_signer.hash().to_hex(),
        wrong_nonce.hash().to_hex(),
    ];
    let paid_hash = paid.hash().to_hex();
    assert_eq!(by[&accepted], (TxStatus::Success, RELAY_FEE));
    for h in &refused {
        assert_eq!(by[h], (TxStatus::Failed(7), RELAY_FEE), "{h}");
    }
    assert_eq!(by[&paid_hash], (TxStatus::Success, RELAY_FEE));
    let srv = &s.server;

    // messaging_getMessageData: relayed messages only; never a payment.
    let d = srv
        .messaging_get_message_data(accepted.clone())
        .await
        .unwrap()
        .expect("executed");
    assert!(!d.has_payment && d.payment_amount.is_none());
    for h in &refused {
        assert!(srv
            .messaging_get_message_data(h.clone())
            .await
            .unwrap()
            .is_none());
    }
    assert!(srv
        .messaging_get_message_data(paid_hash.clone())
        .await
        .is_err());

    // messaging_getMessageByTxHash.
    let e = srv
        .messaging_get_message_by_tx_hash(accepted.clone())
        .await
        .unwrap()
        .expect("an event");
    assert!(!e.has_payment);
    for h in &refused {
        assert!(srv
            .messaging_get_message_by_tx_hash(h.clone())
            .await
            .unwrap()
            .is_none());
    }
    let e = srv
        .messaging_get_message_by_tx_hash(paid_hash.clone())
        .await
        .unwrap()
        .expect("an event");
    assert!(e.has_payment);

    // messaging_getPendingPayment and messaging_getPendingPayments: the
    // escrow rows.
    for h in refused.iter().chain([&accepted]) {
        assert!(srv
            .messaging_get_pending_payment(h.clone())
            .await
            .unwrap()
            .is_none());
    }
    let p = srv
        .messaging_get_pending_payment(paid_hash.clone())
        .await
        .unwrap()
        .expect("escrowed");
    assert_eq!(
        (p.amount.as_str(), p.sender),
        ("500", alice().address().to_base58())
    );
    let all = srv
        .messaging_get_pending_payments(bob().address().to_base58())
        .await
        .unwrap();
    assert_eq!(
        all.iter().map(|p| p.message_id.clone()).collect::<Vec<_>>(),
        vec![paid_hash.clone()]
    );

    // The listings: the accepted relayed message without a payment, the
    // paid send with one, nothing for the refused envelopes.
    let listed = |events: Vec<sumchain_rpc::types::MessageEventInfo>| -> HashMap<String, bool> {
        events
            .into_iter()
            .map(|e| (e.tx_hash, e.has_payment))
            .collect()
    };
    let to_bob = listed(
        srv.messaging_get_messages(format!("0x{}", hex::encode(rh)), None, None)
            .await
            .unwrap(),
    );
    let in_block = listed(srv.messaging_get_messages_in_block(1, None).await.unwrap());
    for view in [&to_bob, &in_block] {
        assert_eq!(view.len(), 2, "{view:?}");
        assert!(!view[&accepted]);
        assert!(view[&paid_hash]);
    }
    let from_carol = listed(
        srv.messaging_get_sent_messages(carol().address().to_base58(), None, None)
            .await
            .unwrap(),
    );
    assert_eq!(from_carol, HashMap::from([(accepted.clone(), false)]));
    let from_alice = listed(
        srv.messaging_get_sent_messages(alice().address().to_base58(), None, None)
            .await
            .unwrap(),
    );
    assert_eq!(from_alice, HashMap::from([(paid_hash.clone(), true)]));

    // Below the envelope gate: an executed relayed message whose envelope
    // names an amount. The stored row is kept as before; no amount moved,
    // and no RPC reports a payment.
    let s = serve(&indexed(None, None));
    let claimed = s.relay(&v1(envelope(0, 5, Some(5_000)))).await.unwrap();
    let (_, r) = s.publish_pool(1);
    assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE)]);
    let stored = MessagingStore::new(&s.db)
        .get_message_by_tx_hash(Hash::from_hex(&claimed).unwrap().as_bytes())
        .unwrap()
        .expect("stored");
    assert!(stored.has_payment, "the stored row is kept as before");
    let srv = &s.server;
    assert!(
        !srv.messaging_get_message_by_tx_hash(claimed.clone())
            .await
            .unwrap()
            .unwrap()
            .has_payment
    );
    assert!(
        !srv.messaging_get_message_data(claimed.clone())
            .await
            .unwrap()
            .unwrap()
            .has_payment
    );
    assert_eq!(
        listed(
            srv.messaging_get_sent_messages(carol().address().to_base58(), None, None)
                .await
                .unwrap()
        ),
        HashMap::from([(claimed.clone(), false)])
    );
    assert!(srv
        .messaging_get_pending_payment(claimed)
        .await
        .unwrap()
        .is_none());
}

/// Duplicates, front-running and who pays (the sponsor is not bound into the
/// envelope):
/// - the same envelope relayed twice through this relay: the second request
///   is refused while the first is pending, and refused again once it is
///   carried; one fee in all;
/// - another sponsor's copy already in this node's pool: the relay refuses
///   its own copy; the other sponsor's is carried and it pays;
/// - front-running in a block this node did not build: the other sponsor's
///   copy is carried first and it pays; this relay's copy is then refused in
///   the block and, with the accounting gate open, this sponsor pays its fee;
///   the message is delivered once, and the client pays nothing;
/// - the same below the accounting gate: the refused copy costs nothing.
#[tokio::test]
async fn duplicates_front_running_and_who_pays() {
    // The same envelope twice through this relay.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
        let m = v2(envelope(0, 1, None));
        s.relay(&m).await.unwrap();
        let err = s.relay(&m).await.expect_err("already pending");
        assert!(
            err.message()
                .contains("already pending in this node's pool"),
            "{err}"
        );
        let (_, r) = s.publish_pool(1);
        assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE)]);
        let err = s.relay(&m).await.expect_err("already used");
        assert!(err.message().contains("already used"), "{err}");
        assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS - RELAY_FEE);
        assert_eq!(s.sent_by(&carol()), 1);
    }
    // Another sponsor's copy already in the pool.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
        let m = v2(envelope(0, 2, None));
        s.mempool.add(s.relayed_by(&erin(), 0, &m)).unwrap();
        let err = s.relay(&m).await.expect_err("pending from another sponsor");
        assert!(
            err.message()
                .contains("already pending in this node's pool"),
            "{err}"
        );
        let (_, r) = s.publish_pool(1);
        assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE)]);
        assert_eq!(s.balance(&erin()), ACCOUNT_FUNDS - RELAY_FEE);
        assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS);
        assert_eq!(s.sent_by(&carol()), 1);
    }
    // Front-running in a block this node did not build, with the accounting
    // gate open and absent.
    for (accounting, our_receipt, our_cost, their_cost) in [
        (
            Some(1),
            (TxStatus::Failed(7), RELAY_FEE),
            RELAY_FEE,
            RELAY_FEE,
        ),
        (None, (TxStatus::Failed(7), 0), 0, 0),
    ] {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), accounting));
        let m = v2(envelope(0, 3, None));
        s.relay(&m).await.unwrap();
        let r = s.publish(1, vec![s.relayed_by(&erin(), 0, &m)]);
        assert_eq!(statuses(&r), vec![(TxStatus::Success, RELAY_FEE)]);
        assert_eq!(
            s.pending_sponsor_nonces(),
            vec![0],
            "this relay's copy is still pending"
        );
        let (_, r) = s.publish_pool(2);
        assert_eq!(statuses(&r), vec![our_receipt], "accounting {accounting:?}");
        assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS - our_cost);
        assert_eq!(s.balance(&erin()), ACCOUNT_FUNDS - their_cost);
        assert_eq!(s.account_nonce(&sponsor()), u64::from(accounting.is_some()));
        assert_eq!(s.sent_by(&carol()), 1, "delivered once");
    }
}

/// Many relay requests released at once, from as many senders, on eight
/// threads: each takes its own sponsor nonce. The relay reads the pool to
/// choose a nonce and adds its transaction afterwards; `relay_lock` keeps
/// that read and that add together, so two requests never read the same
/// pending set and are never given the same nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn simultaneous_relays_never_share_a_sponsor_nonce() {
    const N: usize = 48;
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let senders: Vec<KeyPair> = (0..N)
        .map(|i| KeyPair::from_bytes([0x80 + i as u8; 32]))
        .collect();
    let store = MessagingStore::new(&s.db);
    for kp in &senders {
        store
            .set_public_key(
                &kp.address(),
                &RegisteredPublicKey {
                    public_key: *kp.public_key().as_bytes(),
                    address: kp.address(),
                    registered_at_block: 0,
                    registered_at: 0,
                    updated_at_block: 0,
                },
            )
            .unwrap();
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut tasks = Vec::new();
    for (i, kp) in senders.iter().enumerate() {
        let m = v2_by(envelope_from(kp, 0, i as u8, None), kp, CHAIN_ID);
        let server = s.server.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            server.messaging_submit_sponsored(request(&m)).await
        }));
    }
    for task in tasks {
        let r = task.await.unwrap();
        assert!(r.is_ok(), "{r:?}");
    }
    assert_eq!(
        s.pending_sponsor_nonces(),
        (0..N as u64).collect::<Vec<_>>(),
        "every request its own nonce"
    );
    let (_, receipts) = s.publish_pool(1);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE); N]);
}

/// A sponsored registration of an address that is already registered, or
/// whose sponsored registration is already pending in this node's pool, is
/// refused before it takes a sponsor nonce. Such a registration would be
/// refused in the block, free and advancing nothing, and the message relayed
/// after it, at the next sponsor nonce, would take `InvalidNonce`. With both
/// gates absent and with both open, the relayed messages are delivered.
#[tokio::test]
async fn a_registration_already_made_or_pending_is_refused_before_it_takes_a_nonce() {
    for (envelope_gate, accounting_gate) in [(None, None), (Some(1), Some(1))] {
        let label = format!("envelope gate {envelope_gate:?}, accounting gate {accounting_gate:?}");
        let s = serve(&with_registration(genesis_on(
            CHAIN_ID,
            envelope_gate,
            accounting_gate,
        )));
        let carol_message = |nonce: u64| {
            let m = envelope(nonce, nonce as u8, None);
            if envelope_gate.is_some() {
                v2(m)
            } else {
                v1(m)
            }
        };

        // alice is registered: the request carrying her registration is refused.
        let r = s.register(&alice()).await;
        assert!(!r.success && r.tx_hash.is_none(), "{label}: {r:?}");
        assert!(
            r.error.as_deref().unwrap().contains("already registered"),
            "{label}: {r:?}"
        );
        assert!(s.mempool.is_empty(), "{label}");
        s.relay(&carol_message(0)).await.unwrap();
        assert_eq!(s.pending_sponsor_nonces(), vec![0], "{label}");
        let (_, receipts) = s.publish_pool(1);
        assert_eq!(status_only(&receipts), vec![TxStatus::Success], "{label}");
        assert_eq!(s.sent_by(&carol()), 1, "{label}");

        // A new address: its registration is taken once; the same request
        // again, while the first is pending, is refused.
        let newcomer = KeyPair::from_bytes([0xB0; 32]);
        let r = s.register(&newcomer).await;
        assert!(r.success, "{label}: {r:?}");
        let again = s.register(&newcomer).await;
        assert!(
            !again.success && again.tx_hash.is_none(),
            "{label}: {again:?}"
        );
        assert!(
            again.error.as_deref().unwrap().contains("already pending"),
            "{label}: {again:?}"
        );
        let next = s.sponsor_nonce();
        s.relay(&carol_message(1)).await.unwrap();
        assert_eq!(s.pending_sponsor_nonces(), vec![next, next + 1], "{label}");
        let (_, receipts) = s.publish_pool(2);
        assert_eq!(
            status_only(&receipts),
            vec![TxStatus::Success; 2],
            "{label}"
        );
        assert!(s.is_registered(&newcomer), "{label}");
        assert_eq!(s.sent_by(&carol()), 2, "{label}");

        // Once it has executed, the same request is refused as registered.
        let late = s.register(&newcomer).await;
        assert!(
            !late.success
                && late
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("already registered"),
            "{label}: {late:?}"
        );
        s.relay(&carol_message(2)).await.unwrap();
        let (_, receipts) = s.publish_pool(3);
        assert_eq!(status_only(&receipts), vec![TxStatus::Success], "{label}");
        assert_eq!(s.sent_by(&carol()), 3, "{label}");
    }
}

/// A sponsored registration is refused while the registrant's own
/// `RegisterPublicKey` is pending in this node's pool: that one would execute
/// first, the sponsored one would be refused in the block (free, advancing
/// nothing), and the message relayed after it would take `InvalidNonce`. With
/// both gates absent and with both open, the relayed message is delivered and
/// the address registered once, by its own transaction.
#[tokio::test]
async fn a_registration_is_refused_while_the_registrants_own_is_pending() {
    use sumchain_primitives::messaging::RegisterPublicKeyData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    for (envelope_gate, accounting_gate) in [(None, None), (Some(1), Some(1))] {
        let label = format!("envelope gate {envelope_gate:?}, accounting gate {accounting_gate:?}");
        let s = serve(&with_registration(genesis_on(
            CHAIN_ID,
            envelope_gate,
            accounting_gate,
        )));
        let newcomer = KeyPair::from_bytes([0xB2; 32]);
        sumchain_storage::StateStore::new(&s.db)
            .put_account(
                &newcomer.address(),
                &sumchain_storage::schema::AccountState {
                    balance: ACCOUNT_FUNDS,
                    nonce: 0,
                },
            )
            .unwrap();
        let own = s.outer(
            &newcomer,
            0,
            2 * RELAY_FEE,
            MessagingTxData {
                operation: MessagingOperation::RegisterPublicKey,
                data: bincode::serialize(&RegisterPublicKeyData {
                    public_key: *newcomer.public_key().as_bytes(),
                })
                .unwrap(),
            },
        );
        s.mempool.add(own).unwrap();

        let r = s.register(&newcomer).await;
        assert!(!r.success && r.tx_hash.is_none(), "{label}: {r:?}");
        assert!(
            r.error.as_deref().unwrap().contains("own registration"),
            "{label}: {r:?}"
        );
        let m = envelope(0, 1, None);
        s.relay(&if envelope_gate.is_some() {
            v2(m)
        } else {
            v1(m)
        })
        .await
        .unwrap();
        assert_eq!(s.pending_sponsor_nonces(), vec![0], "{label}");
        let (_, receipts) = s.publish_pool(1);
        assert_eq!(
            status_only(&receipts),
            vec![TxStatus::Success; 2],
            "{label}"
        );
        assert!(s.is_registered(&newcomer), "{label}");
        assert_eq!(s.sent_by(&carol()), 1, "{label}");
        let late = s.register(&newcomer).await;
        assert!(
            !late.success
                && late
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("already registered"),
            "{label}: {late:?}"
        );
    }
}

/// Below the accounting gate a relayed message and a sponsored registration
/// relayed after it share the sponsor's committed nonce: the relayed message
/// leaves that nonce where it is, the registration advances it. The producer
/// carries the relayed message first at that nonce, so both execute, in every
/// one of sixteen cases, among them cases where the fee-then-hash order puts
/// the registration first.
#[tokio::test]
async fn a_relayed_message_and_a_registration_at_one_sponsor_nonce() {
    let mut registration_first_by_hash = 0;
    for salt in 0..16u8 {
        let s = serve(&with_registration(genesis_on(CHAIN_ID, None, None)));
        let newcomer = KeyPair::from_bytes([0xC0 + salt; 32]);
        let relayed = s.relay(&v1(envelope(0, salt, None))).await.unwrap();
        let r = s.register(&newcomer).await;
        assert!(r.success, "{r:?}");
        let registration = r.tx_hash.unwrap();
        assert_eq!(s.pending_sponsor_nonces(), vec![0, 0]);
        if Hash::from_hex(&registration).unwrap() < Hash::from_hex(&relayed).unwrap() {
            registration_first_by_hash += 1;
        }

        let (carried, receipts) = s.publish_pool(1);
        assert_eq!(
            carried
                .iter()
                .map(|t| t.hash().to_hex())
                .collect::<Vec<_>>(),
            vec![relayed, registration],
            "salt {salt}: the relayed message first"
        );
        assert_eq!(
            status_only(&receipts),
            vec![TxStatus::Success; 2],
            "salt {salt}"
        );
        assert_eq!(s.sent_by(&carol()), 1, "salt {salt}");
        assert!(s.is_registered(&newcomer), "salt {salt}");
        assert_eq!(s.sponsor_nonce(), 1, "salt {salt}");
    }
    assert!(
        registration_first_by_hash > 0,
        "the cases include ones the fee-then-hash order alone would carry the other way"
    );
}

/// Relayed messages and sponsored registrations released at once, on eight
/// threads, with one registration requested twice: every message and every
/// registration takes its own sponsor nonce, the second request for the same
/// registration is refused, and all of them execute in one block with both
/// gates open. The registration path chooses its nonce, checks what is
/// pending and adds its transaction under the same `relay_lock` as the
/// message relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn simultaneous_relays_and_registrations_never_share_a_sponsor_nonce() {
    const MESSAGES: usize = 24;
    const REGISTRATIONS: usize = 24;
    let s = serve(&with_registration(genesis_on(CHAIN_ID, Some(1), Some(1))));
    let senders: Vec<KeyPair> = (0..MESSAGES)
        .map(|i| KeyPair::from_bytes([0x80 + i as u8; 32]))
        .collect();
    let newcomers: Vec<KeyPair> = (0..REGISTRATIONS)
        .map(|i| KeyPair::from_bytes([0xD0 + i as u8; 32]))
        .collect();
    let store = MessagingStore::new(&s.db);
    for kp in &senders {
        store
            .set_public_key(
                &kp.address(),
                &RegisteredPublicKey {
                    public_key: *kp.public_key().as_bytes(),
                    address: kp.address(),
                    registered_at_block: 0,
                    registered_at: 0,
                    updated_at_block: 0,
                },
            )
            .unwrap();
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(MESSAGES + REGISTRATIONS + 1));
    let mut messages = Vec::new();
    for (i, kp) in senders.iter().enumerate() {
        let m = v2_by(envelope_from(kp, 0, i as u8, None), kp, CHAIN_ID);
        let server = s.server.clone();
        let barrier = barrier.clone();
        messages.push(tokio::spawn(async move {
            barrier.wait().await;
            server.messaging_submit_sponsored(request(&m)).await
        }));
    }
    let mut registrations = Vec::new();
    for kp in newcomers.iter().chain(std::iter::once(&newcomers[0])) {
        let req = registration_request(kp);
        let server = s.server.clone();
        let barrier = barrier.clone();
        registrations.push(tokio::spawn(async move {
            barrier.wait().await;
            server.messaging_register_sponsored(req).await.unwrap()
        }));
    }
    for task in messages {
        let r = task.await.unwrap();
        assert!(r.is_ok(), "{r:?}");
    }
    let mut taken = 0;
    for task in registrations {
        let r = task.await.unwrap();
        if r.success {
            taken += 1;
        } else {
            assert!(
                r.error.as_deref().unwrap().contains("already pending"),
                "{r:?}"
            );
        }
    }
    assert_eq!(taken, REGISTRATIONS, "the repeated request is refused");
    assert_eq!(
        s.pending_sponsor_nonces(),
        (0..(MESSAGES + REGISTRATIONS) as u64).collect::<Vec<_>>(),
        "every message and every registration its own nonce"
    );
    let (_, receipts) = s.publish_pool(1);
    assert_eq!(
        statuses(&receipts),
        vec![(TxStatus::Success, RELAY_FEE); MESSAGES + REGISTRATIONS]
    );
    assert_eq!(s.sponsor_nonce(), (MESSAGES + REGISTRATIONS) as u64);
    for kp in &newcomers {
        assert!(s.is_registered(kp));
    }
}

// ── The client retry protocol (`relay_retry_client`) ─────────────────────────

/// The chain tip's height (0 before the first block).
fn tip(s: &Served) -> u64 {
    sumchain_storage::BlockStore::new(&s.db)
        .get_latest_height()
        .unwrap()
        .unwrap_or(0)
}

/// `kp`'s version-2 envelope to bob at `nonce`, as an intent signed now.
async fn v2_intent(s: &Served, kp: &KeyPair, nonce: u64, salt: u8) -> Intent {
    let m = v2_by(envelope_from(kp, nonce, salt, None), kp, CHAIN_ID);
    Intent::signed_now(&s.server, m, Form::Version2).await
}

/// `kp`'s string-form envelope to bob, as an intent signed now.
async fn legacy_intent(s: &Served, kp: &KeyPair, nonce: u64, salt: u8) -> Intent {
    let m = v1_by(envelope_from(kp, nonce, salt, None), kp);
    Intent::signed_now(&s.server, m, Form::Legacy).await
}

/// Registered senders beyond the five `serve` registers.
fn registered(s: &Served, first: u8, count: u8) -> Vec<KeyPair> {
    let store = MessagingStore::new(&s.db);
    (0..count)
        .map(|i| {
            let kp = KeyPair::from_bytes([first + i; 32]);
            store
                .set_public_key(
                    &kp.address(),
                    &RegisteredPublicKey {
                        public_key: *kp.public_key().as_bytes(),
                        address: kp.address(),
                        registered_at_block: 0,
                        registered_at: 0,
                        updated_at_block: 0,
                    },
                )
                .unwrap();
            kp
        })
        .collect()
}

/// How many transactions of the canonical chain delivered `intent`'s exact
/// signed envelope: every block read from the block store, each relayed
/// `SendMessage` decoded and its receipt read (not through the client, and
/// not through the message index, which below the transaction-index gate
/// keeps one row per sender per block).
fn deliveries(s: &Served, intent: &Intent) -> usize {
    use sumchain_primitives::MessagingOperation;
    let m = &intent.envelope;
    let blocks = sumchain_storage::BlockStore::new(&s.db);
    let receipts = sumchain_storage::ReceiptStore::new(&s.db);
    let mut n = 0;
    for height in 1..=tip(s) {
        let Some(block) = blocks.get_by_height(height).unwrap() else {
            continue;
        };
        for tx in &block.transactions {
            let carried: Option<SponsoredMessage> = match &tx.inner {
                TxInner::V2(v2) => match &v2.payload {
                    TxPayload::Messaging(d) if d.operation == MessagingOperation::SendMessage => {
                        bincode::deserialize(&d.data).ok()
                    }
                    _ => None,
                },
                _ => None,
            };
            let executed = receipts
                .get(&tx.hash())
                .unwrap()
                .is_some_and(|r| r.status == TxStatus::Success);
            if executed
                && carried.is_some_and(|c| {
                    c.signature == m.signature
                        && c.nonce == m.nonce
                        && c.expiry == m.expiry
                        && c.sender_pubkey == m.sender_pubkey
                        && c.recipient_hash == m.recipient_hash
                        && c.message_data == m.message_data
                })
            {
                n += 1;
            }
        }
    }
    n
}

/// The receipts of every wrapper the trackers obtained: (executed and
/// charged, refused with `InvalidNonce`).
fn wrapper_receipts(s: &Served, trackers: &[Tracker]) -> (Vec<TxStatus>, usize) {
    let mut executed = Vec::new();
    let mut invalid_nonce = 0;
    for t in trackers {
        for h in &t.wrappers {
            match sumchain_storage::ReceiptStore::new(&s.db)
                .get(&Hash::from_hex(h).unwrap())
                .unwrap()
            {
                Some(r) if r.status == TxStatus::InvalidNonce => {
                    assert_eq!(r.fee_paid, 0, "InvalidNonce costs nothing");
                    invalid_nonce += 1;
                }
                Some(r) => executed.push(r.status),
                None => {}
            }
        }
    }
    (executed, invalid_nonce)
}

/// Steps every tracker without an outcome, then publishes what the pool
/// holds as the next block; until every tracker has an outcome, at most
/// `rounds` times. Returns the next block height.
async fn drive(s: &Served, trackers: &mut [Tracker], mut height: u64, rounds: usize) -> u64 {
    for _ in 0..rounds {
        let mut open = false;
        for t in trackers.iter_mut() {
            if !matches!(t.step(&s.server).await, Step::Done(_)) {
                open = true;
            }
        }
        if !open {
            break;
        }
        s.publish_pool(height);
        height += 1;
    }
    height
}

/// Both gates at H = 4; run with the transaction-index gate unset, as in
/// production (one message row per sender per block), and set. Eight intents relayed for
/// H-2 are left uncarried until H (a backlog across the accounting gate):
/// six version-2 envelopes, carol's version-2 envelope (her own direct
/// message, carried at H-1, then spends her messaging nonce 0), and dave's
/// string-form envelope. At H all eight wrappers hold sponsor nonce 0: one
/// executes, the others take `InvalidNonce`. Each client then follows the
/// protocol: the six are delivered once each, by a fresh wrapper of the same
/// envelope; carol's and dave's end as needing the user's signature (the
/// nonce moved past; the string form), never as delivered and never resent
/// without a new signature. Signed anew, both are delivered. Every intent
/// ends with an outcome; each delivered message is on the chain once; the
/// sponsor pays one fee per executed wrapper, at most `MAX_WRAPPERS` per
/// intent, and nothing for a wrapper refused with `InvalidNonce`.
#[tokio::test]
async fn a_burst_pending_across_the_accounting_gate_ends_delivered_or_reported() {
    for tx_index_gate in [None, Some(0)] {
        burst_across_the_accounting_gate(tx_index_gate).await;
    }
}

async fn burst_across_the_accounting_gate(tx_index_gate: Option<u64>) {
    use sumchain_primitives::messaging::SendMessageData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    const H: u64 = 4;
    let mut g = genesis_on(CHAIN_ID, Some(H), Some(H));
    g.params.subsystem_tx_index_enabled_from_height = tx_index_gate;
    let s = serve(&g);
    let others = registered(&s, 0x90, 3);
    s.publish(1, Vec::new());

    // The next block is H-2: the burst.
    let mut trackers: Vec<Tracker> = Vec::new();
    for (i, kp) in [alice(), grace(), heidi()]
        .iter()
        .chain(others.iter())
        .enumerate()
    {
        trackers.push(Tracker::new(v2_intent(&s, kp, 0, i as u8).await));
    }
    trackers.push(Tracker::new(v2_intent(&s, &carol(), 0, 20).await));
    trackers.push(Tracker::new(legacy_intent(&s, &dave(), 0, 21).await));
    for t in trackers.iter_mut() {
        assert!(matches!(t.submit(&s.server).await, Step::Resubmitted(_)));
    }
    assert_eq!(s.pending_sponsor_nonces(), vec![0; 8]);
    s.publish(H - 2, Vec::new());

    // H-1 carries only carol's own direct message.
    let rh = recipient_hash(&bob().address());
    let direct = s.outer(
        &carol(),
        0,
        RELAY_FEE,
        MessagingTxData {
            operation: MessagingOperation::SendMessageDirect,
            data: bincode::serialize(&SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            })
            .unwrap(),
        },
    );
    assert_eq!(
        status_only(&s.publish(H - 1, vec![direct])),
        vec![TxStatus::Success]
    );
    assert_eq!(s.messaging_nonce(&carol()), 1);

    // H carries the backlog: one executes, seven take InvalidNonce.
    let (_, receipts) = s.publish_pool(H);
    assert_eq!(
        receipts
            .iter()
            .filter(|r| r.status == TxStatus::InvalidNonce)
            .count(),
        7
    );

    let next = drive(&s, &mut trackers, H + 1, 6).await;
    for t in &trackers[..6] {
        assert!(
            matches!(t.outcome, Some(Outcome::Delivered { .. })),
            "{:?}",
            t.outcome
        );
        assert_eq!(deliveries(&s, &t.intent), 1);
        assert!(t.wrappers.len() <= MAX_WRAPPERS);
    }
    for t in &trackers[6..] {
        assert!(
            matches!(t.outcome, Some(Outcome::NeedsUserSignature(_))),
            "{:?}",
            t.outcome
        );
        assert_eq!(deliveries(&s, &t.intent), 0);
    }
    let (executed, _) = wrapper_receipts(&s, &trackers);
    assert_eq!(
        executed
            .iter()
            .filter(|st| **st == TxStatus::Success)
            .count(),
        6,
        "one execution per delivered intent"
    );
    assert!(
        executed.len() <= 7,
        "at most the H block's first is refused"
    );
    let spent = SPONSOR_FUNDS - s.balance(&sponsor());
    assert_eq!(spent, RELAY_FEE * executed.len() as u128);

    // The users sign anew: carol at her committed nonce, dave in version 2.
    let mut resigned = vec![
        Tracker::new(v2_intent(&s, &carol(), 1, 22).await),
        Tracker::new(v2_intent(&s, &dave(), 0, 23).await),
    ];
    for t in resigned.iter_mut() {
        assert!(matches!(t.submit(&s.server).await, Step::Resubmitted(_)));
    }
    drive(&s, &mut resigned, next, 4).await;
    for t in &resigned {
        assert!(
            matches!(t.outcome, Some(Outcome::Delivered { .. })),
            "{:?}",
            t.outcome
        );
        assert_eq!(deliveries(&s, &t.intent), 1);
    }
    assert_eq!(
        (s.messaging_nonce(&carol()), s.messaging_nonce(&dave())),
        (2, 1)
    );
}

/// The accounting gate at H = 3 (the envelope gate open from 1, the
/// transaction-index gate unset, as in production). Twelve intents relayed for H-2 are carried only at H, where
/// one executes and eleven take `InvalidNonce`. All twelve clients then step
/// at once on eight threads, and two of them run a second instance of their
/// client at the same time (the same envelope, the same wrappers): the
/// eleven stranded envelopes each get exactly one fresh wrapper, at distinct
/// sponsor nonces; a second instance's request for an envelope already
/// pending is refused, and that instance waits. The next block delivers all
/// eleven; every instance ends delivered; each message is on the chain once;
/// the sponsor paid twelve fees.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_retries_deliver_each_message_once() {
    const H: u64 = 3;
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(H)));
    let senders = registered(&s, 0xA0, 12);
    let mut trackers: Vec<Tracker> = Vec::new();
    for (i, kp) in senders.iter().enumerate() {
        trackers.push(Tracker::new(v2_intent(&s, kp, 0, i as u8).await));
    }
    for t in trackers.iter_mut() {
        assert!(matches!(t.submit(&s.server).await, Step::Resubmitted(_)));
    }
    assert_eq!(s.pending_sponsor_nonces(), vec![0; 12]);
    s.publish(1, Vec::new());
    s.publish(2, Vec::new());
    s.publish_pool(H);

    // Every client, and two second instances, at once.
    let mut instances: Vec<Tracker> = trackers.clone();
    instances.push(trackers[0].clone());
    instances.push(trackers[1].clone());
    let barrier = Arc::new(tokio::sync::Barrier::new(instances.len()));
    let mut tasks = Vec::new();
    for mut t in instances {
        let server = s.server.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let step = t.step(&server).await;
            (t, step)
        }));
    }
    let mut instances = Vec::new();
    let mut fresh = 0;
    for task in tasks {
        let (t, step) = task.await.unwrap();
        match &step {
            Step::Resubmitted(_) => fresh += 1,
            Step::Done(Outcome::Delivered { .. }) | Step::Wait => {}
            other => panic!("{other:?}"),
        }
        instances.push(t);
    }
    assert_eq!(fresh, 11, "one fresh wrapper per stranded envelope");
    assert_eq!(s.pending_sponsor_nonces(), (1..=11).collect::<Vec<_>>());

    drive(&s, &mut instances, H + 1, 3).await;
    for t in &instances {
        assert!(
            matches!(t.outcome, Some(Outcome::Delivered { .. })),
            "{:?}",
            t.outcome
        );
        assert_eq!(deliveries(&s, &t.intent), 1);
    }
    for kp in &senders {
        assert_eq!(s.messaging_nonce(kp), 1);
    }
    assert_eq!(s.balance(&sponsor()), SPONSOR_FUNDS - 12 * RELAY_FEE);
}

/// With both gates open, each block carries first another transaction of the
/// sponsor at the nonce of alice's wrapper (as a second relay with the same
/// key would), so each wrapper takes `InvalidNonce`. The client asks for a
/// fresh wrapper each time, and after `MAX_WRAPPERS` it stops and reports the
/// message undeliverable: it is not resent without bound, it is not reported
/// delivered, and its wrappers cost the sponsor nothing. The client is
/// restarted between steps, reading its tracker back from its store (the
/// request count, written before each request, the first-submission height
/// and the wrappers), and the bound still holds across the restarts.
#[tokio::test]
async fn the_retries_of_one_message_are_bounded() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let store = tempfile::TempDir::new().unwrap();
    let path = store.path().join("intent.json");
    let mut t = Tracker::persisted(v2_intent(&s, &alice(), 0, 1).await, &path);
    assert!(matches!(t.submit(&s.server).await, Step::Resubmitted(_)));
    let first_submitted_at = t.first_submitted_at;
    assert_eq!(first_submitted_at, Some(0));
    let mut height = 1;
    let mut step = Step::Wait;
    for k in 0..(MAX_WRAPPERS as u64 + 1) {
        if let Step::Done(_) = step {
            break;
        }
        let other = s.relayed_by(
            &sponsor(),
            k,
            &v2_by(
                envelope_from(&dave(), k, 50 + k as u8, None),
                &dave(),
                CHAIN_ID,
            ),
        );
        let mut first = other.clone();
        // A higher fee, so it is carried first at that nonce.
        if let TxInner::V2(v2) = &mut first.inner {
            v2.fee = 2 * RELAY_FEE;
        }
        let first = {
            let TxInner::V2(v2) = &first.inner else {
                unreachable!()
            };
            let sig = sign(v2.signing_hash().as_bytes(), sponsor().private_key());
            SignedTransaction::new_v2(
                v2.clone(),
                *sig.as_bytes(),
                *sponsor().public_key().as_bytes(),
            )
        };
        s.mempool.add(first).unwrap();
        s.publish_pool(height);
        height += 1;
        // A restart: the client reads back what it persisted.
        let before = (t.requests, t.wrappers.clone());
        drop(t);
        t = Tracker::load(&path);
        assert_eq!((t.requests, t.wrappers.clone()), before);
        assert_eq!(t.first_submitted_at, first_submitted_at);
        step = t.step(&s.server).await;
    }
    assert_eq!(
        step,
        Step::Done(Outcome::Undeliverable(format!(
            "the retry bound ({MAX_WRAPPERS} wrappers) is reached"
        )))
    );
    assert_eq!(t.wrappers.len(), MAX_WRAPPERS);
    assert_eq!(Tracker::load(&path).requests, MAX_WRAPPERS);
    assert_eq!(Tracker::load(&path).outcome, t.outcome);
    let (executed, invalid_nonce) = wrapper_receipts(&s, std::slice::from_ref(&t));
    assert!(executed.is_empty());
    assert_eq!(invalid_nonce, MAX_WRAPPERS);
    assert_eq!(deliveries(&s, &t.intent), 0);
    assert_eq!(s.messaging_nonce(&alice()), 0);
}

/// A delivery the sender's message listing does not show is still found,
/// because the client searches the blocks since the envelope was signed.
/// carol signs an envelope and asks this relay for a wrapper; another
/// sponsor's copy of the same envelope delivers it first, in a block this
/// node did not build. The listing misses it in two ways:
/// - with the transaction-index gate unset (production), carol's own direct
///   message in the same block replaces the copy's row (one row per sender
///   per block);
/// - with 1,200 older rows for carol (recorded below the first block), the
///   listing's one page (the oldest 1,000) ends before it.
/// In both, carol's messaging nonce has moved past the envelope's, and this
/// relay's wrapper is refused in the block. The client reports the message
/// delivered, by the copy, and never asks the user to sign it again: a
/// re-signed envelope would deliver it twice.
#[tokio::test]
async fn a_delivery_missing_from_the_message_listing_is_still_found() {
    use sumchain_primitives::messaging::SendMessageData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    for older_rows in [false, true] {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
        if older_rows {
            let store = MessagingStore::new(&s.db);
            for i in 0..1_200u32 {
                store
                    .store_message_event(
                        &sumchain_primitives::MessageEvent {
                            sender: carol().address(),
                            recipient_hash: recipient_hash(&bob().address()),
                            message_id: Hash::hash(&i.to_be_bytes()),
                            size: 1,
                            has_payment: false,
                            block_height: 0,
                            timestamp: 0,
                        },
                        i,
                    )
                    .unwrap();
            }
        }
        let height = 1;
        let intent = v2_intent(&s, &carol(), 0, 7).await;
        let mut t = Tracker::new(intent.clone());
        let Step::Resubmitted(own) = t.submit(&s.server).await else {
            panic!("relayed");
        };

        // A block this node did not build: the copy, and (without older
        // rows) carol's own direct message after it.
        let copy = s.relayed_by(&erin(), 0, &intent.envelope);
        let mut block = vec![copy.clone()];
        if !older_rows {
            let rh = recipient_hash(&bob().address());
            block.push(
                s.outer(
                    &carol(),
                    0,
                    RELAY_FEE,
                    MessagingTxData {
                        operation: MessagingOperation::SendMessageDirect,
                        data: bincode::serialize(&SendMessageData {
                            message_data: valid_message(rh),
                            recipient_hash: rh,
                        })
                        .unwrap(),
                    },
                ),
            );
        }
        let receipts = s.publish(height, block);
        assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
        let listed = s
            .server
            .messaging_get_sent_messages(carol().address().to_base58(), Some(1_000), None)
            .await
            .unwrap();
        assert!(
            !listed
                .iter()
                .any(|e| strip_0x(&e.tx_hash) == strip_0x(&copy.hash().to_hex())),
            "the listing does not show the copy (older rows: {older_rows})"
        );

        // The client finds it; this relay's wrapper, carried next, is refused.
        let delivered = Step::Done(Outcome::Delivered {
            tx_hash: copy.hash().to_hex(),
        });
        assert_eq!(
            t.step(&s.server).await,
            delivered,
            "older rows: {older_rows}"
        );
        let (carried, receipts) = s.publish_pool(height + 1);
        assert_eq!(strip_0x(&carried[0].hash().to_hex()), strip_0x(&own));
        assert_ne!(receipts[0].status, TxStatus::Success);
        assert_eq!(
            t.step(&s.server).await,
            delivered,
            "older rows: {older_rows}"
        );
        assert_eq!(deliveries(&s, &intent), 1);
    }
}

fn strip_0x(h: &str) -> String {
    h.strip_prefix("0x").unwrap_or(h).to_string()
}

/// Two intents with the same content: carol sends the same message twice,
/// signing it at messaging nonces 0 and 1. Both wrappers are relayed; the
/// first executes, and the second is carried in a block whose first
/// transaction is another wrapper at the same sponsor nonce, so it takes
/// `InvalidNonce`. A check on the content alone would report the second
/// intent delivered by the first one's execution, and the message would be
/// lost. The client matches the exact signed envelope (nonce and signature
/// included): the second is not delivered, so it asks for a fresh wrapper of
/// the same envelope, and it is delivered. Each intent is on the chain once.
#[tokio::test]
async fn two_intents_with_the_same_content_are_told_apart() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let same = |nonce: u64| {
        let mut m = envelope_from(&carol(), nonce, 7, None);
        m.message_data = valid_message(recipient_hash(&bob().address()));
        v2(m)
    };
    let first = Intent::signed_now(&s.server, same(0), Form::Version2).await;
    let second = Intent::signed_now(&s.server, same(1), Form::Version2).await;
    assert_eq!(first.envelope.message_data, second.envelope.message_data);
    let mut a = Tracker::new(first.clone());
    let mut b = Tracker::new(second.clone());
    assert!(matches!(a.submit(&s.server).await, Step::Resubmitted(_)));
    assert!(matches!(b.submit(&s.server).await, Step::Resubmitted(_)));
    assert_eq!(s.pending_sponsor_nonces(), vec![0, 1]);

    // Block 1 carries the first; block 2 carries, ahead of the second, another
    // transaction of the sponsor at nonce 1 (a higher fee).
    let first_wrapper = s
        .mempool
        .get(&Hash::from_hex(&a.wrappers[0]).unwrap())
        .unwrap();
    assert_eq!(
        status_only(&s.publish(1, vec![first_wrapper])),
        vec![TxStatus::Success]
    );
    let ahead = {
        let m = v2_by(envelope_from(&dave(), 0, 60, None), &dave(), CHAIN_ID);
        let mut tx = s.relayed_by(&sponsor(), 1, &m);
        let TxInner::V2(v2) = &mut tx.inner else {
            unreachable!()
        };
        v2.fee = 2 * RELAY_FEE;
        let sig = sign(v2.signing_hash().as_bytes(), sponsor().private_key());
        SignedTransaction::new_v2(
            v2.clone(),
            *sig.as_bytes(),
            *sponsor().public_key().as_bytes(),
        )
    };
    s.mempool.add(ahead).unwrap();
    let (_, receipts) = s.publish_pool(2);
    assert_eq!(
        status_only(&receipts),
        vec![TxStatus::Success, TxStatus::InvalidNonce]
    );

    assert!(matches!(
        a.step(&s.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));
    let fresh = match b.step(&s.server).await {
        Step::Resubmitted(h) => h,
        other => panic!("the second intent is not delivered yet: {other:?}"),
    };
    let (_, receipts) = s.publish_pool(3);
    assert_eq!(status_only(&receipts), vec![TxStatus::Success]);
    assert_eq!(
        b.step(&s.server).await,
        Step::Done(Outcome::Delivered { tx_hash: fresh })
    );
    assert_eq!((deliveries(&s, &first), deliveries(&s, &second)), (1, 1));
    assert_eq!(s.messaging_nonce(&carol()), 2);
}

/// An incomplete search is uncertain, never "not delivered".
/// - A range not yet final (blocks are final 2 below the tip): carol's own
///   direct message and then her relayed envelope at nonce 0 are carried in
///   one block; the envelope is refused there and her nonce has moved past
///   it. While that block is not final the client reports `Uncertain`, asks
///   for no signature and reports nothing lost; once it is final, the user is
///   asked to sign again.
/// - A block that is not available: a gap in the stored chain inside the
///   range searched gives `Uncertain`, naming the block, and no outcome.
#[tokio::test]
async fn an_incomplete_search_is_uncertain_never_not_delivered() {
    use sumchain_primitives::messaging::SendMessageData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};
    // A range not yet final.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
        s.finality_depth
            .store(2, std::sync::atomic::Ordering::SeqCst);
        let mut t = Tracker::new(v2_intent(&s, &carol(), 0, 1).await);
        let Step::Resubmitted(wrapper) = t.submit(&s.server).await else {
            panic!("relayed");
        };
        let rh = recipient_hash(&bob().address());
        let direct = s.outer(
            &carol(),
            0,
            RELAY_FEE,
            MessagingTxData {
                operation: MessagingOperation::SendMessageDirect,
                data: bincode::serialize(&SendMessageData {
                    message_data: valid_message(rh),
                    recipient_hash: rh,
                })
                .unwrap(),
            },
        );
        let carried = s.mempool.get(&Hash::from_hex(&wrapper).unwrap()).unwrap();
        let receipts = s.publish(1, vec![direct, carried]);
        assert_eq!(receipts[0].status, TxStatus::Success);
        assert_ne!(receipts[1].status, TxStatus::Success);
        assert_eq!(s.messaging_nonce(&carol()), 1);

        for height in 2..=3 {
            let step = t.step(&s.server).await;
            assert!(matches!(step, Step::Uncertain(_)), "{step:?}");
            assert_eq!(t.outcome, None);
            s.publish(height, Vec::new());
        }
        let step = t.step(&s.server).await;
        assert!(
            matches!(step, Step::Done(Outcome::NeedsUserSignature(_))),
            "once block 1 is final: {step:?}"
        );
        assert_eq!(t.requests, 1, "no request while uncertain");
    }
    // A block that is not available.
    {
        let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
        let mut t = Tracker::new(v2_intent(&s, &alice(), 0, 2).await);
        assert!(matches!(t.submit(&s.server).await, Step::Resubmitted(_)));
        s.publish(2, Vec::new());
        let step = t.step(&s.server).await;
        assert_eq!(
            step,
            Step::Uncertain("block 1 is not available".to_string())
        );
        assert_eq!((t.outcome.clone(), t.requests), (None, 1));
    }
}

/// A client that crashes after the relay accepted its request, before it
/// recorded the wrapper, makes no second wrapper. On restart the request is
/// counted and in flight; the client waits for a block, then asks again,
/// and the relay refuses: an envelope already pending (by its nonce for the
/// version-2 envelope; as the identical signed envelope for the string form
/// below the envelope gate). The string form runs with the accounting gate
/// open, where a second wrapper would take the next sponsor nonce and be a
/// different transaction (below that gate it would be byte-identical, and
/// the pool would refuse it anyway). The one wrapper is carried and the
/// message is delivered once; the count is one.
#[tokio::test]
async fn a_crash_after_the_relay_accepted_makes_no_second_wrapper() {
    for form in [Form::Version2, Form::Legacy] {
        let gates = if form == Form::Version2 {
            (Some(1), Some(1))
        } else {
            (None, Some(1))
        };
        let s = serve(&genesis_on(CHAIN_ID, gates.0, gates.1));
        let intent = if form == Form::Version2 {
            v2_intent(&s, &carol(), 0, 3).await
        } else {
            legacy_intent(&s, &carol(), 0, 3).await
        };
        let store = tempfile::TempDir::new().unwrap();
        let path = store.path().join("intent.json");
        let mut t = Tracker::persisted(intent.clone(), &path);
        let made = t.submit_then_crash(&s.server).await.expect("a wrapper");
        drop(t);

        let mut t = Tracker::load(&path);
        assert_eq!((t.requests, t.in_flight, t.wrappers.len()), (1, Some(0), 0));
        assert_eq!(
            t.step(&s.server).await,
            Step::Wait,
            "{form:?}: a block first"
        );
        s.publish(1, Vec::new());
        assert_eq!(
            t.step(&s.server).await,
            Step::Wait,
            "{form:?}: the relay refuses a second wrapper"
        );
        assert_eq!(s.pending_sponsor_nonces(), vec![0], "{form:?}: one wrapper");
        assert_eq!(t.requests, 1, "{form:?}: the refusal is not counted");

        s.publish_pool(2);
        assert_eq!(
            t.step(&s.server).await,
            Step::Done(Outcome::Delivered { tx_hash: made }),
            "{form:?}"
        );
        assert_eq!(deliveries(&s, &intent), 1, "{form:?}");
    }
}

/// `messaging_getMessageData` keeps its earlier response exactly: the same
/// fields, in the same order, with the same values, serialized byte for byte
/// as before (pinned here against the expected JSON), and a strict client of
/// that shape parses it. The envelope's signature, nonce and expiry come from
/// a separate read-only method, `messaging_getSponsoredEnvelope`: every field
/// is the stored transaction's own envelope bytes; it answers only for an
/// executed relayed message (`None` for one not yet carried, or refused in
/// the block); any other transaction is refused (`-32602`), as
/// `messaging_getMessageData` refuses it.
#[tokio::test]
async fn message_data_keeps_its_shape_and_the_envelope_has_its_own_method() {
    use serde::Deserialize;
    use sumchain_primitives::messaging::SendMessageData;
    use sumchain_primitives::{MessagingOperation, MessagingTxData};

    #[allow(dead_code)]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictEarlierShape {
        tx_hash: String,
        block_height: u64,
        sender: String,
        recipient_hash: String,
        message_data: String,
        sender_pubkey: String,
        has_payment: bool,
        payment_amount: Option<String>,
    }
    #[allow(dead_code)]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictEnvelope {
        tx_hash: String,
        block_height: u64,
        sender_pubkey: String,
        recipient_hash: String,
        message_data: String,
        envelope_signature: String,
        envelope_nonce: u64,
        envelope_expiry: u64,
    }

    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let m = v2(envelope(0, 9, None));
    let relayed = s.relay(&m).await.unwrap();
    let rh = recipient_hash(&bob().address());
    let direct = s.outer(
        &alice(),
        0,
        RELAY_FEE,
        MessagingTxData {
            operation: MessagingOperation::SendMessageDirect,
            data: bincode::serialize(&SendMessageData {
                message_data: valid_message(rh),
                recipient_hash: rh,
            })
            .unwrap(),
        },
    );
    s.mempool.add(direct.clone()).unwrap();
    // Not carried yet: neither method has an answer.
    assert!(s
        .server
        .messaging_get_sponsored_envelope(relayed.clone())
        .await
        .unwrap()
        .is_none());
    let (_, receipts) = s.publish_pool(1);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));

    // getMessageData: its earlier response, byte for byte.
    let info = s
        .server
        .messaging_get_message_data(relayed.clone())
        .await
        .unwrap()
        .expect("an executed relayed message");
    let expected = format!(
        "{{\"tx_hash\":\"0x{}\",\"block_height\":1,\"sender\":\"{}\",\"recipient_hash\":\"0x{}\",\
         \"message_data\":\"0x{}\",\"sender_pubkey\":\"0x{}\",\"has_payment\":false,\
         \"payment_amount\":null}}",
        strip_0x(&relayed),
        carol().address().to_base58(),
        hex::encode(m.recipient_hash),
        hex::encode(&m.message_data),
        hex::encode(m.sender_pubkey),
    );
    assert_eq!(serde_json::to_string(&info).unwrap(), expected);
    assert!(serde_json::from_str::<StrictEarlierShape>(&expected).is_ok());

    // getSponsoredEnvelope: the stored envelope's bytes.
    let env = s
        .server
        .messaging_get_sponsored_envelope(relayed.clone())
        .await
        .unwrap()
        .expect("an executed relayed message");
    assert_eq!(strip_0x(&env.tx_hash), strip_0x(&relayed));
    assert_eq!(env.block_height, 1);
    assert_eq!(
        env.sender_pubkey,
        format!("0x{}", hex::encode(m.sender_pubkey))
    );
    assert_eq!(
        env.recipient_hash,
        format!("0x{}", hex::encode(m.recipient_hash))
    );
    assert_eq!(
        env.message_data,
        format!("0x{}", hex::encode(&m.message_data))
    );
    assert_eq!(
        env.envelope_signature,
        format!("0x{}", hex::encode(m.signature))
    );
    assert_eq!(
        (env.envelope_nonce, env.envelope_expiry),
        (m.nonce, m.expiry)
    );
    assert!(serde_json::from_value::<StrictEnvelope>(serde_json::to_value(&env).unwrap()).is_ok());

    // A non-relayed message: refused by both, as before.
    for err in [
        s.server
            .messaging_get_message_data(direct.hash().to_hex())
            .await
            .expect_err("not a relayed message"),
        s.server
            .messaging_get_sponsored_envelope(direct.hash().to_hex())
            .await
            .expect_err("not a relayed message"),
    ] {
        assert_eq!(err.code(), -32602);
        assert_eq!(err.message(), "Not a sponsored message transaction");
    }

    // A relayed message refused in the block: no answer.
    let refused = s.relayed_by(
        &erin(),
        0,
        &v2_by(envelope_from(&dave(), 5, 10, None), &dave(), CHAIN_ID),
    );
    let r = s.publish(2, vec![refused.clone()]);
    assert_ne!(r[0].status, TxStatus::Success);
    assert!(s
        .server
        .messaging_get_sponsored_envelope(refused.hash().to_hex())
        .await
        .unwrap()
        .is_none());
}

/// A relay refusing a first request because its pool has no room for the
/// sponsor (`TxRejected`) is transient: the client waits, counts nothing,
/// and once a block has made room it obtains a wrapper.
#[tokio::test]
async fn a_full_pool_at_the_first_request_is_waited_out() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    // The sponsor's place in the pool, filled by carol's envelopes.
    for nonce in 0..100u64 {
        s.relay(&v2(envelope(nonce, nonce as u8, None)))
            .await
            .unwrap();
    }
    let mut t = Tracker::new(v2_intent(&s, &alice(), 0, 1).await);
    assert_eq!(t.submit(&s.server).await, Step::Wait);
    assert_eq!(
        (t.requests, t.in_flight, t.outcome.clone()),
        (0, None, None)
    );
    s.publish_pool(1);
    assert!(matches!(t.step(&s.server).await, Step::Resubmitted(_)));
    s.publish_pool(2);
    assert!(matches!(
        t.step(&s.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));
    assert_eq!(t.requests, 1);
}

/// A connection lost after the relay accepted a request (an ambiguous
/// error, not a refusal) leaves the request counted and in flight: the relay
/// may have made a wrapper, and it did. The client waits for a block, asks
/// again and is refused (the envelope is pending), and finds the message
/// delivered by that wrapper once it is carried. One wrapper, one request
/// counted.
#[tokio::test]
async fn an_ambiguous_error_after_acceptance_stays_counted() {
    let s = serve(&genesis_on(CHAIN_ID, Some(1), Some(1)));
    let intent = v2_intent(&s, &alice(), 0, 1).await;
    let mut t = Tracker::new(intent.clone());
    t.fail_after_accept = true;
    assert_eq!(t.submit(&s.server).await, Step::Wait);
    assert_eq!((t.requests, t.in_flight, t.wrappers.len()), (1, Some(0), 0));
    assert_eq!(
        s.pending_sponsor_nonces(),
        vec![0],
        "the relay made a wrapper"
    );

    assert_eq!(t.step(&s.server).await, Step::Wait, "a block first");
    s.publish(1, Vec::new());
    assert_eq!(t.step(&s.server).await, Step::Wait, "refused: pending");
    assert_eq!(t.requests, 1);
    s.publish_pool(2);
    assert!(matches!(
        t.step(&s.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));
    assert_eq!((t.requests, deliveries(&s, &intent)), (1, 1));
}

// ── payments: a positive amount from the envelope gate, "0" as none ─────────

/// The envelope gate (and the accounting gate) in the payment cases.
const PAY_GATE: u64 = 3;

/// The chain's blocks up to `tip`, empty, so the relay judges the next block
/// to be `tip + 1`.
fn up_to(s: &Served, tip: u64) {
    let mut h = sumchain_storage::BlockStore::new(&s.db)
        .get_latest_height()
        .unwrap()
        .unwrap_or(0);
    while h < tip {
        h += 1;
        s.publish(h, vec![]);
    }
}

/// The relay relays a positive amount only for a block at or above the
/// envelope gate, judged at the next block's height: refused for `H - 1`,
/// relayed for `H` (carried there: the named sender pays it into escrow, the
/// sponsor pays the fee) and for `H + 1`.
#[tokio::test]
async fn the_relay_relays_a_payment_only_for_a_block_at_or_above_the_envelope_gate() {
    let s = serve(&genesis_on(CHAIN_ID, Some(PAY_GATE), Some(PAY_GATE)));
    up_to(&s, PAY_GATE - 2);
    let err = s
        .relay(&v2(envelope(0, 1, Some(5_000))))
        .await
        .expect_err("next block H - 1: no amount moves there");
    assert!(err.message().contains("koppa_amount"), "{err}");
    assert!(relayed_envelopes(&s).is_empty());

    up_to(&s, PAY_GATE - 1);
    let (carol_before, sponsor_before) = (s.balance(&carol()), s.balance(&sponsor()));
    let paid = s.relay(&v2(envelope(0, 2, Some(5_000)))).await.unwrap();
    let (_, receipts) = s.publish_pool(PAY_GATE);
    assert_eq!(statuses(&receipts), vec![(TxStatus::Success, RELAY_FEE)]);
    let escrow = MessagingStore::new(&s.db)
        .get_pending_payment(&Hash::from_hex(&paid).unwrap())
        .unwrap()
        .map(|p| (p.amount, p.sender));
    assert_eq!(escrow, Some((5_000, carol().address())));
    assert_eq!(s.balance(&carol()), carol_before - 5_000);
    assert_eq!(s.balance(&sponsor()), sponsor_before - RELAY_FEE);

    // Next block H + 1.
    s.relay(&v2(envelope(1, 3, Some(7_000))))
        .await
        .expect("next block H + 1");
}

/// `"0"` names no amount at every height: relayed for `H - 1`, `H` and
/// `H + 1` as an envelope naming none, and carried as one.
#[tokio::test]
async fn an_amount_of_zero_relays_as_no_amount_at_every_height() {
    let s = serve(&genesis_on(CHAIN_ID, Some(PAY_GATE), Some(PAY_GATE)));
    for (i, tip) in [PAY_GATE - 2, PAY_GATE - 1, PAY_GATE]
        .into_iter()
        .enumerate()
    {
        up_to(&s, tip);
        let nonce = s.messaging_nonce(&carol());
        s.relay(&v2(envelope(nonce, 10 + i as u8, Some(0))))
            .await
            .unwrap_or_else(|e| panic!("next block {}: {e}", tip + 1));
        let relayed = relayed_envelopes(&s);
        assert_eq!(relayed.len(), 1, "next block {}", tip + 1);
        assert_eq!(relayed[0].koppa_amount, None, "relayed as none");
        let (_, receipts) = s.publish_pool(tip + 1);
        assert_eq!(status_only(&receipts), vec![TxStatus::Success]);
    }
}

/// The relay's preflight for a payment: the named sender's balance must cover
/// the amount beyond what its envelopes already pending in this node's pool
/// name, and beyond this wrapper's fee when the sender is the relay's own
/// key. Advice only: the block re-checks.
#[tokio::test]
async fn the_relay_refuses_a_payment_its_named_sender_cannot_fund() {
    let s = serve(&genesis_on(CHAIN_ID, Some(PAY_GATE), Some(PAY_GATE)));
    up_to(&s, PAY_GATE - 1);
    let err = s
        .relay(&v2(envelope(0, 1, Some(ACCOUNT_FUNDS + 1))))
        .await
        .expect_err("more than carol holds");
    assert!(err.message().contains("cannot fund"), "{err}");
    s.relay(&v2(envelope(0, 2, Some(ACCOUNT_FUNDS - 10))))
        .await
        .expect("within carol's balance");
    let err = s
        .relay(&v2(envelope(1, 3, Some(11))))
        .await
        .expect_err("the pending envelope already names most of it");
    assert!(err.message().contains("cannot fund"), "{err}");
    s.relay(&v2(envelope(1, 4, Some(10))))
        .await
        .expect("exactly what is left");

    // The relay's own key as the named sender: the fee comes first.
    let store = MessagingStore::new(&s.db);
    store
        .set_public_key(
            &sponsor().address(),
            &RegisteredPublicKey {
                public_key: *sponsor().public_key().as_bytes(),
                address: sponsor().address(),
                registered_at_block: 0,
                registered_at: 0,
                updated_at_block: 0,
            },
        )
        .unwrap();
    let own = |nonce, salt, amount| {
        v2_by(
            envelope_from(&sponsor(), nonce, salt, Some(amount)),
            &sponsor(),
            CHAIN_ID,
        )
    };
    let err = s
        .relay(&own(0, 5, SPONSOR_FUNDS - RELAY_FEE + 1))
        .await
        .expect_err("the amount and the fee exceed the sponsor's balance");
    assert!(err.message().contains("cannot fund"), "{err}");
    s.relay(&own(0, 6, SPONSOR_FUNDS - RELAY_FEE))
        .await
        .expect("the amount after the fee");
}
