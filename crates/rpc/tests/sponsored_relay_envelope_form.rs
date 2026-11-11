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
    sponsored_send_v2_signing_preimage, Block, BlockHeader, Hash, Receipt, SignedTransaction,
    SponsoredMessage, TxInner, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::SubmitSponsoredMessageRequest;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore};
use tokio::sync::mpsc;

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
            .relay(&v2(envelope(0, 3, Some(5))))
            .await
            .expect_err("an amount is refused");
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
        assert_eq!(view[&accepted], false);
        assert_eq!(view[&paid_hash], true);
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
