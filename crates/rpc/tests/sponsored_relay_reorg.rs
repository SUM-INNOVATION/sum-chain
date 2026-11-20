//! The relay across a chain switch, on a real engine.
//!
//! The node under test runs a `PoAEngine` and serves `messaging_submitSponsored`
//! over the same database and pool. Two off-node builders share block 1 and
//! then produce competing branches. Relayed transactions carried by one branch
//! are unwound when the node switches to the other: the engine offers them
//! back to the pool, the relay's view of what is pending (its sponsor nonces
//! and each sender's envelope sequence) is consistent with the new branch, the
//! relay continues from it, and the returned transactions are included again.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, BlockHeader, Hash, MessagingOperation,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::auth::RpcAuthConfig;
use sumchain_rpc::metrics::Metrics;
use sumchain_rpc::rate_limit::RateLimitConfig;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::SubmitSponsoredMessageRequest;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;
use tokio::sync::mpsc;

mod relay_retry_client;
use relay_retry_client::{Form, Intent, Outcome, Step, Tracker, MAX_WRAPPERS};

const CHAIN_ID: u64 = 1;
const FEE: u128 = 1_000_000;
const FUNDS: u128 = 1_000_000_000;
const NEVER: u64 = u64::MAX;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
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
/// The relay's own key, read from `SUMAIL_SPONSOR_KEY`.
fn sponsor() -> KeyPair {
    key(0x65)
}

fn sponsor_key_configured() {
    static KEY_DIR: OnceLock<TempDir> = OnceLock::new();
    KEY_DIR.get_or_init(|| {
        let dir = TempDir::new().unwrap();
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

/// Two validators, static membership, journals required from height 1,
/// finality out of reach, V2 open, both messaging gates open from height 1.
fn genesis(validators: &[KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        messaging: Some(MessagingParams {
            registry_admin: Some(admin().address().to_base58()),
            ..MessagingParams::default()
        }),
        messaging_sponsored_envelope_verification_enabled_from_height: Some(1),
        messaging_fee_nonce_accounting_enabled_from_height: Some(1),
        // A remediation gate set obliges the peer declaration at or below it.
        peer_protocol_declaration_required_from_height: Some(1),
        ..ChainParams::with_v2_enabled()
    };
    let mut alloc = HashMap::new();
    for k in validators
        .iter()
        .chain([admin(), alice(), carol(), sponsor()].iter())
    {
        alloc.insert(k.address().to_base58(), FUNDS);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    )
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

fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
    }
}

fn messaging_tx(kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(kp))
}

/// `sender`'s version-2 envelope to bob at `nonce`.
fn envelope(sender: &KeyPair, nonce: u64, salt: u8) -> SponsoredMessage {
    let rh = recipient_hash(&bob().address());
    let mut message_data = valid_message(rh);
    message_data.push(salt);
    let mut m = SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(sender),
        nonce,
        expiry: NEVER,
        koppa_amount: None,
    };
    let preimage = sponsored_send_v2_signing_preimage(CHAIN_ID, &m);
    m.signature = *sign(&preimage, sender.private_key()).as_bytes();
    m
}

fn request(m: &SponsoredMessage) -> SubmitSponsoredMessageRequest {
    SubmitSponsoredMessageRequest {
        message_data: format!("0x{}", hex::encode(&m.message_data)),
        recipient_hash: format!("0x{}", hex::encode(m.recipient_hash)),
        signature: format!("0x{}", hex::encode(m.signature)),
        sender_pubkey: format!("0x{}", hex::encode(m.sender_pubkey)),
        nonce: m.nonce,
        expiry: m.expiry,
        koppa_amount: None,
    }
}

/// A block builder off the node under test: its own database, real execution.
struct Builder {
    _dir: TempDir,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    keys: Vec<KeyPair>,
    validators: Vec<[u8; 32]>,
    head: Block,
}

impl Builder {
    fn new(g: &Genesis, keys: &[KeyPair]) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            g,
            None,
        )
        .unwrap();
        let head = engine.init_genesis(g).unwrap();
        drop(engine);
        let executor = BlockExecutor::new(state.clone(), db, g.params.clone());
        Self {
            _dir: dir,
            state,
            executor,
            keys: keys
                .iter()
                .map(|k| KeyPair::from_bytes(*k.private_key().as_bytes()))
                .collect(),
            validators: g.validator_pubkeys().unwrap(),
            head,
        }
    }

    fn proposer(&self, height: u64) -> &KeyPair {
        let want = self.validators[(height % self.validators.len() as u64) as usize];
        self.keys.iter().find(|k| pk(k) == want).unwrap()
    }

    /// Produce, publish and return the next block, signed by its rightful
    /// proposer. `salt` is added to the timestamp, so two builders on the
    /// same parent produce different blocks from the same transactions, and
    /// the same block with the same salt.
    fn produce(&mut self, salt: u64, txs: Vec<SignedTransaction>) -> Block {
        let height = self.head.height() + 1;
        let proposer = KeyPair::from_bytes(*self.proposer(height).private_key().as_bytes());
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10 + salt,
                Hash::ZERO,
                Hash::ZERO,
                pk(&proposer),
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &self.validators)
            .unwrap();
        b.header.state_root = exec.computed_root();
        let s = sign(b.header.signing_hash().as_bytes(), proposer.private_key());
        b.header.set_signature(*s.as_bytes());
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        b
    }
}

/// The node under test: an engine importing blocks, and the relay over the
/// same database and pool.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
    server: RpcServer,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        sponsor_key_configured();
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine =
            Arc::new(PoAEngine::new(db.clone(), state.clone(), mempool.clone(), g, None).unwrap());
        engine.init_genesis(g).unwrap();
        let (tx_sender, rx) = mpsc::channel(64);
        std::mem::forget(rx);
        let server = RpcServer::with_full_config(
            db.clone(),
            state.clone(),
            mempool.clone(),
            engine.clone() as Arc<dyn ConsensusQuery>,
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
        Self {
            _dir: dir,
            db,
            state,
            mempool,
            engine,
            server,
        }
    }

    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.unwrap();
    }

    async fn relay(&self, m: &SponsoredMessage) -> Result<Hash, String> {
        self.server
            .messaging_submit_sponsored(request(m))
            .await
            .map(|r| Hash::from_hex(&r.tx_hash).unwrap())
            .map_err(|e| e.message().to_string())
    }

    fn receipt(&self, h: &Hash) -> Option<(TxStatus, u128)> {
        ReceiptStore::new(&self.db)
            .get(h)
            .unwrap()
            .map(|r| (r.status, r.fee_paid))
    }

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

    fn sponsor_nonce(&self) -> u64 {
        self.state.get_nonce(&sponsor().address()).unwrap()
    }

    fn messaging_nonce(&self, kp: &KeyPair) -> u64 {
        MessagingStore::new(&self.db)
            .get_sender_nonce(&kp.address())
            .unwrap()
    }
}

/// Branch A carries two relayed messages and the node imports it; branch B,
/// longer, carries none, and the node switches to it. The engine offers the
/// two relayed transactions back to the pool, where they are valid again on
/// B: the sponsor's nonce and both senders' messaging nonces are back at the
/// fork point. The relay's view follows: the next relayed message takes the
/// sponsor nonce after the two returned ones and the sender's next envelope
/// nonce after her returned envelope, and a copy of a returned envelope is
/// refused as pending. The next block on B carries all three, in nonce order,
/// and all succeed.
#[tokio::test]
async fn a_chain_switch_returns_relayed_transactions_and_the_relay_continues() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    assert_eq!(a.head.hash(), b.head.hash(), "one genesis");

    // Block 1, shared: sponsorship on, carol and alice registered.
    let block_1 = || {
        vec![
            messaging_tx(
                &admin(),
                0,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
            messaging_tx(
                &alice(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&alice()),
                    },
                ),
            ),
        ]
    };
    let a1 = a.produce(0, block_1());
    let b1 = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;

    // Two relayed messages through the node's relay.
    let carol_0 = node.relay(&envelope(&carol(), 0, 1)).await.unwrap();
    let alice_0 = node.relay(&envelope(&alice(), 0, 2)).await.unwrap();
    assert_eq!(node.pending_sponsor_nonces(), vec![0, 1]);

    // Branch A carries them.
    let a2 = a.produce(1, node.mempool.select_for_block(100));
    node.import(&a2).await;
    assert_eq!(node.engine.best_block_hash(), a2.hash());
    assert_eq!(node.receipt(&carol_0), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&alice_0), Some((TxStatus::Success, FEE)));
    assert!(node.mempool.is_empty(), "carried, so removed");
    assert_eq!(node.sponsor_nonce(), 2);

    // Branch B, longer, without them: the node switches.
    let b2 = b.produce(2, Vec::new());
    let b3 = b.produce(2, Vec::new());
    node.import(&b2).await;
    assert_eq!(node.engine.best_block_hash(), a2.hash(), "a side branch");
    node.import(&b3).await;
    assert_eq!(node.engine.best_block_hash(), b3.hash(), "switched");

    // Unwound: no receipts, back in the pool, valid again on B.
    assert_eq!(node.receipt(&carol_0), None);
    assert_eq!(node.receipt(&alice_0), None);
    assert!(node.mempool.contains(&carol_0) && node.mempool.contains(&alice_0));
    assert_eq!(node.sponsor_nonce(), 0);
    assert_eq!(
        (
            node.messaging_nonce(&carol()),
            node.messaging_nonce(&alice())
        ),
        (0, 0)
    );
    assert_eq!(node.pending_sponsor_nonces(), vec![0, 1]);

    // The relay continues from the pending view.
    let err = node
        .relay(&envelope(&alice(), 0, 2))
        .await
        .expect_err("the returned envelope is pending");
    assert!(err.contains("already pending"), "{err}");
    let carol_1 = node.relay(&envelope(&carol(), 1, 3)).await.unwrap();
    assert_eq!(node.pending_sponsor_nonces(), vec![0, 1, 2]);

    // The next block on B carries all three, in nonce order.
    let carried = node.mempool.select_for_block(100);
    assert_eq!(
        carried.iter().map(|t| t.nonce()).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let b4 = b.produce(2, carried);
    node.import(&b4).await;
    assert_eq!(node.engine.best_block_hash(), b4.hash());
    for h in [&carol_0, &alice_0, &carol_1] {
        assert_eq!(node.receipt(h), Some((TxStatus::Success, FEE)), "{h}");
    }
    assert!(node.mempool.is_empty());
    assert_eq!(node.sponsor_nonce(), 3);
    assert_eq!(
        (
            node.messaging_nonce(&carol()),
            node.messaging_nonce(&alice())
        ),
        (2, 1)
    );
}

/// How many transactions of the node's canonical chain delivered exactly
/// the signed envelope `m`: every block read by height from the block store, each relayed
/// `SendMessage` decoded and its receipt read (not through the message
/// index, which below the transaction-index gate keeps one row per sender
/// per block).
fn deliveries(node: &Node, m: &SponsoredMessage) -> usize {
    let blocks = sumchain_storage::BlockStore::new(&node.db);
    let tip = blocks.get_latest_height().unwrap().unwrap_or(0);
    let mut n = 0;
    for height in 1..=tip {
        let Some(block) = blocks.get_by_height(height).unwrap() else {
            continue;
        };
        for tx in &block.transactions {
            let carried: Option<SponsoredMessage> = match &tx.inner {
                sumchain_primitives::TxInner::V2(v2) => match &v2.payload {
                    TxPayload::Messaging(d) if d.operation == MessagingOperation::SendMessage => {
                        bincode::deserialize(&d.data).ok()
                    }
                    _ => None,
                },
                _ => None,
            };
            if node.receipt(&tx.hash()).map(|r| r.0) == Some(TxStatus::Success)
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

/// The client retry protocol across a chain switch. Branch A carries, at
/// sponsor nonce 0, alice's message in a wrapper from another relay with the
/// same key, and then carol's wrapper, which takes `InvalidNonce`. carol's
/// client asks for a fresh wrapper of the same envelope (sponsor nonce 1);
/// alice's client finds her message delivered. Branch B, longer, carries
/// carol's original wrapper alone, and the node switches: alice's wrapper is
/// abandoned and, its sponsor nonce spent on B, dropped from the pool. carol's
/// client finds her message delivered by the original and stops; her fresh
/// wrapper is still pending and is refused in the next block, at one fee.
/// alice's client, checking again, no longer finds her message, finds no
/// wrapper pending and her messaging nonce still at the envelope's, and asks
/// for a fresh wrapper, which delivers it. Each message is on the adopted
/// chain once; no delivery is read from a nonce; the sponsor paid one fee per
/// executed wrapper.
#[tokio::test]
async fn the_client_retry_protocol_across_a_chain_switch() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let block_1 = || {
        vec![
            messaging_tx(
                &admin(),
                0,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
            messaging_tx(
                &alice(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&alice()),
                    },
                ),
            ),
        ]
    };
    let a1 = a.produce(0, block_1());
    let b1 = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;

    let mut carol_client = Tracker::new(
        Intent::signed_now(&node.server, envelope(&carol(), 0, 1), Form::Version2).await,
    );
    let Step::Resubmitted(original) = carol_client.submit(&node.server).await else {
        panic!("relayed");
    };
    let original_tx = node
        .mempool
        .get(&Hash::from_hex(&original).unwrap())
        .unwrap();
    // alice's message, wrapped at sponsor nonce 0 by another relay holding
    // the sponsor key; her client holds that wrapper's hash.
    let alice_envelope = envelope(&alice(), 0, 2);
    let alice_wrapper = messaging_tx(
        &sponsor(),
        0,
        op(MessagingOperation::SendMessage, &alice_envelope),
    );
    let mut alice_client = Tracker::new(
        Intent::signed_now(&node.server, alice_envelope.clone(), Form::Version2).await,
    );
    alice_client.wrappers.push(alice_wrapper.hash().to_hex());

    // Branch A: alice's wrapper first at sponsor nonce 0, then carol's.
    let a2 = a.produce(1, vec![alice_wrapper.clone(), original_tx.clone()]);
    node.import(&a2).await;
    assert_eq!(
        node.receipt(&alice_wrapper.hash()),
        Some((TxStatus::Success, FEE))
    );
    assert_eq!(
        node.receipt(&original_tx.hash()),
        Some((TxStatus::InvalidNonce, 0))
    );
    let fresh = match carol_client.step(&node.server).await {
        Step::Resubmitted(h) => h,
        other => panic!("{other:?}"),
    };
    assert_eq!(node.pending_sponsor_nonces(), vec![1]);
    assert!(matches!(
        alice_client.step(&node.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));

    // Branch B, longer, carries carol's original alone: the node switches.
    let b2 = b.produce(2, vec![original_tx.clone()]);
    let b3 = b.produce(2, Vec::new());
    node.import(&b2).await;
    node.import(&b3).await;
    assert_eq!(node.engine.best_block_hash(), b3.hash(), "switched");
    assert_eq!(
        node.receipt(&original_tx.hash()),
        Some((TxStatus::Success, FEE))
    );
    assert_eq!(node.receipt(&alice_wrapper.hash()), None, "unwound");
    assert!(
        !node.mempool.contains(&alice_wrapper.hash()),
        "its sponsor nonce is spent on B"
    );
    assert_eq!(
        node.pending_sponsor_nonces(),
        vec![1],
        "carol's fresh wrapper"
    );

    // carol's client: delivered by the original; it stops.
    assert_eq!(
        carol_client.step(&node.server).await,
        Step::Done(Outcome::Delivered {
            tx_hash: original_tx.hash().to_hex()
        })
    );
    // alice's client: not delivered on B, nothing pending, nonce unspent.
    let alice_fresh = match alice_client.step(&node.server).await {
        Step::Resubmitted(h) => h,
        other => panic!("{other:?}"),
    };
    assert_eq!(node.pending_sponsor_nonces(), vec![1, 2]);

    let b4 = b.produce(2, node.mempool.select_for_block(100));
    node.import(&b4).await;
    let refused = node.receipt(&Hash::from_hex(&fresh).unwrap()).unwrap();
    assert_ne!(refused.0, TxStatus::Success, "the envelope executes once");
    assert_eq!(refused.1, FEE, "the extra wrapper costs one fee");
    assert_eq!(
        node.receipt(&Hash::from_hex(&alice_fresh).unwrap()),
        Some((TxStatus::Success, FEE))
    );
    assert_eq!(
        alice_client.step(&node.server).await,
        Step::Done(Outcome::Delivered {
            tx_hash: alice_fresh.clone()
        })
    );
    assert!(matches!(
        carol_client.step(&node.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));
    assert_eq!(deliveries(&node, &carol_client.intent.envelope), 1);
    assert_eq!(deliveries(&node, &alice_envelope), 1);
    assert_eq!(
        (
            node.messaging_nonce(&carol()),
            node.messaging_nonce(&alice())
        ),
        (1, 1)
    );
    assert!(carol_client.wrappers.len() <= MAX_WRAPPERS);
    assert!(alice_client.wrappers.len() <= MAX_WRAPPERS);
    assert_eq!(
        node.state.get_balance(&sponsor().address()).unwrap(),
        FUNDS - 3 * FEE
    );
}

/// A chain switch that removes a delivery. Branch A carries carol's wrapper,
/// and her client finds the message delivered. Branch B, longer, does not
/// carry it, and the node switches: the wrapper returns to the pool, valid on
/// B. The client no longer finds the message (not delivered), finds its
/// wrapper pending, and waits; it does not ask for another. The next block on
/// B carries the wrapper, and the client finds the message delivered again:
/// on the adopted chain once, by one wrapper, at one fee. (A switch that adds
/// a delivery is in `the_client_retry_protocol_across_a_chain_switch`.)
#[tokio::test]
async fn a_chain_switch_that_removes_a_delivery() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let block_1 = || {
        vec![
            messaging_tx(
                &admin(),
                0,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
        ]
    };
    let a1 = a.produce(0, block_1());
    let b1 = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;

    let message = envelope(&carol(), 0, 1);
    let mut client =
        Tracker::new(Intent::signed_now(&node.server, message.clone(), Form::Version2).await);
    let Step::Resubmitted(wrapper) = client.submit(&node.server).await else {
        panic!("relayed");
    };
    let wrapper_hash = Hash::from_hex(&wrapper).unwrap();

    // Branch A carries it: delivered.
    let a2 = a.produce(1, node.mempool.select_for_block(100));
    node.import(&a2).await;
    let delivered = Step::Done(Outcome::Delivered {
        tx_hash: wrapper.clone(),
    });
    assert_eq!(client.step(&node.server).await, delivered);

    // Branch B, longer, without it: the node switches, the wrapper returns.
    let b2 = b.produce(2, Vec::new());
    let b3 = b.produce(2, Vec::new());
    node.import(&b2).await;
    node.import(&b3).await;
    assert_eq!(node.engine.best_block_hash(), b3.hash(), "switched");
    assert_eq!(node.receipt(&wrapper_hash), None, "unwound");
    assert!(node.mempool.contains(&wrapper_hash), "returned to the pool");
    assert_eq!(deliveries(&node, &message), 0);

    // Not delivered; its wrapper is pending: the client waits.
    assert_eq!(client.step(&node.server).await, Step::Wait);
    assert_eq!(client.outcome, None);
    assert_eq!(client.wrappers.len(), 1, "no second wrapper");

    // B carries it: delivered once.
    let b4 = b.produce(2, node.mempool.select_for_block(100));
    node.import(&b4).await;
    assert_eq!(client.step(&node.server).await, delivered);
    assert_eq!(deliveries(&node, &message), 1);
    assert_eq!(node.messaging_nonce(&carol()), 1);
    assert_eq!(
        node.state.get_balance(&sponsor().address()).unwrap(),
        FUNDS - FEE
    );
}

/// A chain switch whose fork lies below the height at which the envelope was
/// signed, and whose adopted branch carries the envelope (a copy another
/// relay held) at a height at or below that one. Blocks are final 2 below
/// the head. carol signs at tip 3, when block 1 is final; her client asks
/// this relay for a wrapper. Branch B forks at block 1, carries the copy at
/// height 2, grows past A, and the node switches. The client searches from
/// the height final at signing, so it finds the copy at height 2 and reports
/// the message delivered; it never asks the user to sign again. (Searching
/// from the signing height, it would miss the copy and, its own wrapper
/// refused, ask for a new signature: the message would be delivered twice.)
/// Its own wrapper is refused in the next block, at one fee; the message is
/// on the adopted chain once.
#[tokio::test]
async fn a_delivery_below_the_signing_height_adopted_by_a_chain_switch() {
    let validators = [key(1), key(2)];
    let mut g = genesis(&validators);
    g.params.finality_depth = 2;
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let block_1 = || {
        vec![
            messaging_tx(
                &admin(),
                0,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
        ]
    };
    let a1 = a.produce(0, block_1());
    let b1 = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;
    let a2 = a.produce(1, Vec::new());
    let a3 = a.produce(1, Vec::new());
    node.import(&a2).await;
    node.import(&a3).await;

    let message = envelope(&carol(), 0, 1);
    let intent = Intent::signed_now(&node.server, message.clone(), Form::Version2).await;
    assert_eq!((intent.signed_at, intent.final_at_signing), (3, 1));
    let mut client = Tracker::new(intent);
    let Step::Resubmitted(wrapper) = client.submit(&node.server).await else {
        panic!("relayed");
    };

    // Branch B: the copy at height 2, below the signing height; B grows past A.
    let copy = messaging_tx(&alice(), 0, op(MessagingOperation::SendMessage, &message));
    let mut b_blocks = vec![b.produce(2, vec![copy.clone()])];
    for _ in 0..3 {
        b_blocks.push(b.produce(2, Vec::new()));
    }
    for block in &b_blocks {
        node.import(block).await;
    }
    assert_eq!(
        node.engine.best_block_hash(),
        b_blocks.last().unwrap().hash(),
        "switched to B"
    );
    assert_eq!(node.receipt(&copy.hash()), Some((TxStatus::Success, FEE)));

    assert_eq!(
        client.step(&node.server).await,
        Step::Done(Outcome::Delivered {
            tx_hash: copy.hash().to_hex()
        })
    );
    let next = b.produce(2, node.mempool.select_for_block(100));
    node.import(&next).await;
    let own = node.receipt(&Hash::from_hex(&wrapper).unwrap()).unwrap();
    assert_ne!(own.0, TxStatus::Success, "the envelope executes once");
    assert!(matches!(
        client.step(&node.server).await,
        Step::Done(Outcome::Delivered { .. })
    ));
    assert_eq!(deliveries(&node, &message), 1);
}

/// A negative outcome's anchor across chain switches (finality 2 below the
/// head). On branch A carol's own direct message moves her messaging nonce
/// at height 2 and her wrapper is refused at 3: the client is uncertain,
/// anchored at block 3. The node switches to B, which forks at 1 and has the
/// direct message at 4 and the wrapper at 5: block 3 is not A's any more, so
/// the anchor moves to B's tip, and with block 3 final but block 4 (the
/// cause on B) not, the client is still uncertain, not asking for a new
/// signature. The node switches to C, which forks at 3 (above the final
/// height) and carries a copy of the envelope at 4: the client finds it
/// delivered. At no step does it ask for a new signature; the message is on
/// the chain once.
#[tokio::test]
async fn a_negative_anchor_follows_chain_switches() {
    use sumchain_primitives::messaging::SendMessageData;
    let validators = [key(1), key(2)];
    let mut g = genesis(&validators);
    g.params.finality_depth = 2;
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let mut c = Builder::new(&g, &validators);
    let block_1 = || {
        vec![
            messaging_tx(
                &admin(),
                0,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                0,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
        ]
    };
    let carol_direct = || {
        let rh = recipient_hash(&bob().address());
        messaging_tx(
            &carol(),
            1,
            op(
                MessagingOperation::SendMessageDirect,
                &SendMessageData {
                    message_data: valid_message(rh),
                    recipient_hash: rh,
                },
            ),
        )
    };
    let a1 = a.produce(0, block_1());
    assert_eq!(a1.hash(), b.produce(0, block_1()).hash());
    assert_eq!(a1.hash(), c.produce(0, block_1()).hash());
    node.import(&a1).await;

    let message = envelope(&carol(), 0, 1);
    let mut client =
        Tracker::new(Intent::signed_now(&node.server, message.clone(), Form::Version2).await);
    let Step::Resubmitted(w) = client.submit(&node.server).await else {
        panic!("relayed");
    };
    let wrapper = node.mempool.get(&Hash::from_hex(&w).unwrap()).unwrap();
    let mut steps = Vec::new();

    // A: the direct message at 2, the wrapper refused at 3.
    let a2 = a.produce(1, vec![carol_direct()]);
    let a3 = a.produce(1, vec![wrapper.clone()]);
    node.import(&a2).await;
    node.import(&a3).await;
    steps.push(client.step(&node.server).await);
    assert!(matches!(steps[0], Step::Uncertain(_)), "{steps:?}");
    assert_eq!(client.negative_since.clone().unwrap().0, 3);

    // B forks at 1: empty 2 and 3, the direct message at 4, the wrapper at 5.
    let b2 = b.produce(2, Vec::new());
    let b3 = b.produce(2, Vec::new());
    let b4 = b.produce(2, vec![carol_direct()]);
    let b5 = b.produce(2, vec![wrapper.clone()]);
    for block in [&b2, &b3, &b4, &b5] {
        node.import(block).await;
    }
    assert_eq!(node.engine.best_block_hash(), b5.hash(), "switched to B");
    assert_eq!(
        node.server.get_finality().await.unwrap().finalized_height,
        3
    );
    steps.push(client.step(&node.server).await);
    assert!(matches!(steps[1], Step::Uncertain(_)), "{steps:?}");
    assert_eq!(
        client.negative_since.clone().unwrap().0,
        5,
        "moved to B's tip"
    );

    // C forks at 3 and carries a copy of the envelope at 4.
    let c2 = c.produce(2, Vec::new());
    let c3 = c.produce(2, Vec::new());
    assert_eq!((c2.hash(), c3.hash()), (b2.hash(), b3.hash()));
    let copy = messaging_tx(&alice(), 0, op(MessagingOperation::SendMessage, &message));
    let c_blocks = [
        c.produce(3, vec![copy.clone()]),
        c.produce(3, Vec::new()),
        c.produce(3, Vec::new()),
    ];
    for block in &c_blocks {
        node.import(block).await;
    }
    assert_eq!(
        node.engine.best_block_hash(),
        c_blocks[2].hash(),
        "switched to C"
    );
    steps.push(client.step(&node.server).await);
    assert_eq!(
        steps[2],
        Step::Done(Outcome::Delivered {
            tx_hash: copy.hash().to_hex()
        })
    );
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, Step::Done(Outcome::NeedsUserSignature(_)))),
        "{steps:?}"
    );
    assert_eq!(deliveries(&node, &message), 1);
}
