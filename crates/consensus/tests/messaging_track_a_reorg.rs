//! Authenticated sponsored payments and exactly-once messaging accounting
//! across chain switches, on a real engine.
//!
//! Two off-node builders on their own databases over one genesis produce
//! competing branches; the node under test only imports. After every switch
//! the node's account and messaging rows (escrow, envelope nonces, outcome
//! rows, events) must be the adopted builder's, row for row, its receipts the
//! adopted branch's, and the value in balances plus escrow unchanged. Same
//! shape as `messaging_gates_reorg.rs`, on chain 7.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ClaimPaymentData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE,
    SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, BlockHeader, Hash, MessagingOperation,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 7;
const FEE: u128 = 100;
const FUNDS: u128 = 1_000_000_000;
const NEVER: u64 = u64::MAX;
const AMOUNT: u128 = 5_000;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
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
fn erin() -> KeyPair {
    key(0x67)
}
fn frank() -> KeyPair {
    key(0x68)
}
fn funded() -> [KeyPair; 6] {
    [admin(), bob(), carol(), sponsor(), erin(), frank()]
}

/// Two validators, static membership, journals from height 1, finality out
/// of reach, V2 open, both messaging gates at `gate` (the peer declaration
/// at 1).
fn genesis(validators: &[KeyPair], gate: u64) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        messaging: Some(MessagingParams {
            registry_admin: Some(admin().address().to_base58()),
            ..MessagingParams::default()
        }),
        messaging_sponsored_envelope_verification_enabled_from_height: Some(gate),
        messaging_fee_nonce_accounting_enabled_from_height: Some(gate),
        peer_protocol_declaration_required_from_height: Some(1),
        ..ChainParams::with_v2_enabled()
    };
    let mut alloc = HashMap::new();
    for k in validators.iter().chain(funded().iter()) {
        alloc.insert(k.address().to_base58(), FUNDS);
    }
    let g = Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    );
    g.validate()
        .expect("both gates at one height: a valid genesis");
    g
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

/// Carol's version-2 envelope to bob at `nonce`, signed by carol.
fn carol_pays(nonce: u64, amount: Option<u128>) -> SponsoredMessage {
    let rh = recipient_hash(&bob().address());
    let mut m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(&carol()),
        nonce,
        expiry: NEVER,
        koppa_amount: amount,
    };
    m.signature = *sign(
        &sponsored_send_v2_signing_preimage(CHAIN_ID, &m),
        carol().private_key(),
    )
    .as_bytes();
    m
}

fn relayed(relayer: &KeyPair, nonce: u64, m: &SponsoredMessage) -> SignedTransaction {
    messaging_tx(relayer, nonce, op(MessagingOperation::SendMessage, m))
}

fn claim(nonce: u64, message_id: Hash) -> SignedTransaction {
    messaging_tx(
        &bob(),
        nonce,
        op(
            MessagingOperation::ClaimPayment,
            &ClaimPaymentData {
                message_id,
                recipient_address: bob().address(),
            },
        ),
    )
}

fn set_sponsorship(nonce: u64, enabled: bool) -> SignedTransaction {
    messaging_tx(
        &admin(),
        nonce,
        op(
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled },
        ),
    )
}

/// Block 1: sponsorship on, carol registered (both below or at the gate).
fn block_1() -> Vec<SignedTransaction> {
    vec![
        set_sponsorship(0, true),
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
}

/// A block builder off the node under test: its own database, real execution.
struct Builder {
    _dir: TempDir,
    db: Arc<Database>,
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
        let executor = BlockExecutor::new(state.clone(), db.clone(), g.params.clone());
        Self {
            _dir: dir,
            db,
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

    /// Produce, publish and return the next block, signed by its proposer;
    /// `salt` makes two builders' blocks on one parent differ.
    fn produce(&mut self, salt: u64, txs: Vec<SignedTransaction>) -> (Block, Vec<TxStatus>) {
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
        let statuses = executed.receipts().iter().map(|r| r.status).collect();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        (b, statuses)
    }
}

/// The node under test: a follower on a real database.
struct Node {
    dir: TempDir,
    db: Arc<Database>,
    engine: Arc<PoAEngine>,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine = Arc::new(PoAEngine::new(db.clone(), state, mempool, g, None).unwrap());
        engine.init_genesis(g).unwrap();
        Self { dir, db, engine }
    }

    /// Close every handle and reopen the database, as a restarted node does.
    fn restart(self, g: &Genesis) -> Self {
        let Node { dir, db, engine } = self;
        drop(engine);
        drop(db);
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine = Arc::new(PoAEngine::new(db.clone(), state, mempool, g, None).unwrap());
        Self { dir, db, engine }
    }

    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.unwrap();
    }

    fn receipt(&self, tx: &SignedTransaction) -> Option<(TxStatus, u128)> {
        ReceiptStore::new(&self.db)
            .get(&tx.hash())
            .unwrap()
            .map(|r| (r.status, r.fee_paid))
    }
}

/// The account family and every messaging family.
const FAMILIES: &[&str] = &[
    cf::STATE,
    cf::MESSAGING_CONFIG,
    cf::MESSAGING_SENDER_NONCES,
    cf::MESSAGING_DAILY_COUNTS,
    cf::MESSAGING_STAKES,
    cf::MESSAGING_SPAM_SCORES,
    cf::MESSAGING_INBOX_FILTERS,
    cf::MESSAGING_CONTACTS,
    cf::MESSAGING_BLOCKED,
    cf::MESSAGING_PENDING_PAYMENTS,
    cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
    cf::MESSAGING_EVENTS,
    cf::MESSAGING_SENDER_EVENTS,
    cf::MESSAGING_PUBLIC_KEYS,
];

fn rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for family in FAMILIES {
        for (k, v) in db.iter(family).unwrap() {
            out.insert((family.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

fn store(db: &Database) -> MessagingStore<'_> {
    MessagingStore::new(db)
}

fn balance(db: &Database, kp: &KeyPair) -> u128 {
    sumchain_storage::StateStore::new(db)
        .get_account(&kp.address())
        .unwrap()
        .balance
}

/// Every account balance (the funded keys and both validators) plus every
/// escrowed amount: what a payment, a claim, a refusal or a switch must not
/// change.
fn total_value(db: &Database, validators: &[KeyPair]) -> u128 {
    let balances: u128 = funded()
        .iter()
        .chain(validators.iter())
        .map(|k| balance(db, k))
        .sum();
    let escrowed: u128 = db
        .iter(cf::MESSAGING_PENDING_PAYMENTS)
        .unwrap()
        .map(|(_, v)| {
            sumchain_storage::messaging_store::decode_pending_payment(&v)
                .unwrap()
                .amount
        })
        .sum();
    balances + escrowed
}

/// Gates at 1. Branch A: carol's payment of 5,000 (h2),
/// then bob claims it (h3). Branch B: the same payment through another
/// relayer (h2), a refusal that spends carol's nonce 1 (sponsorship off, h3),
/// and an empty block (h4). The node adopts A, switches to B (the claim is
/// unwound: the escrow is back; the payment re-executes under B's relayer),
/// and back to A (B's consumed refusal is unwound: carol's nonce is A's).
/// After each switch the node's rows are the adopted builder's, the
/// abandoned receipts are gone, and the value is conserved.
#[tokio::test]
async fn payments_claims_and_spent_nonces_follow_a_chain_switch() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators, 1);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let total = total_value(&node.db, &validators);

    let (a1, _) = a.produce(0, block_1());
    let (b1, _) = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;

    // ── branch A: pay, then claim ───────────────────────────────────────────
    let pay = carol_pays(0, Some(AMOUNT));
    let a_pay = relayed(&sponsor(), 0, &pay);
    let (a2, s) = a.produce(1, vec![a_pay.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    let a_claim = claim(0, a_pay.hash());
    let (a3, s) = a.produce(1, vec![a_claim.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    assert!(store(&a.db)
        .get_pending_payment(&a_pay.hash())
        .unwrap()
        .is_none());

    // ── branch B: the same envelope through erin; a spent refusal ───────────
    let b_pay = relayed(&erin(), 0, &pay);
    let (b2, s) = b.produce(2, vec![b_pay.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    let b_off = set_sponsorship(1, false);
    let b_refused = relayed(&sponsor(), 0, &carol_pays(1, None));
    let (b3, s) = b.produce(2, vec![b_off, b_refused.clone()]);
    assert_eq!(s, vec![TxStatus::Success, TxStatus::Failed(7)]);
    let (b4, _) = b.produce(2, Vec::new());
    assert_eq!(
        store(&b.db).get_sender_nonce(&carol().address()).unwrap(),
        2
    );
    assert!(store(&b.db)
        .get_pending_payment(&b_pay.hash())
        .unwrap()
        .is_some());

    // ── A canonical ─────────────────────────────────────────────────────────
    node.import(&a2).await;
    node.import(&a3).await;
    assert_eq!(node.engine.best_block_hash(), a3.hash());
    assert_eq!(rows(&node.db), rows(&a.db), "the node holds A's state");
    assert_eq!(total_value(&node.db, &validators), total);

    // ── the switch to B: the claim and A's payment unwind, B's apply ────────
    for blk in [&b2, &b3, &b4] {
        node.import(blk).await;
    }
    assert_eq!(node.engine.best_block_hash(), b4.hash(), "switched");
    assert_eq!(rows(&node.db), rows(&b.db), "the node holds B's state");
    assert_eq!(node.receipt(&a_pay), None);
    assert_eq!(node.receipt(&a_claim), None);
    assert_eq!(node.receipt(&b_pay), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&b_refused), Some((TxStatus::Failed(7), FEE)));
    let escrow = store(&node.db)
        .get_pending_payment(&b_pay.hash())
        .unwrap()
        .expect("escrowed on B, keyed by B's transaction");
    assert_eq!(escrow.amount, AMOUNT);
    assert!(store(&node.db)
        .get_pending_payment(&a_pay.hash())
        .unwrap()
        .is_none());
    assert_eq!(
        store(&node.db)
            .get_sender_nonce(&carol().address())
            .unwrap(),
        2
    );
    assert_eq!(total_value(&node.db, &validators), total);

    // ── and back: A grows past B ────────────────────────────────────────────
    let (a4, _) = a.produce(1, Vec::new());
    let (a5, _) = a.produce(1, Vec::new());
    node.import(&a4).await;
    node.import(&a5).await;
    assert_eq!(node.engine.best_block_hash(), a5.hash(), "switched back");
    assert_eq!(
        rows(&node.db),
        rows(&a.db),
        "the node holds A's state again"
    );
    assert_eq!(node.receipt(&b_pay), None);
    assert_eq!(node.receipt(&b_refused), None);
    assert_eq!(node.receipt(&a_claim), Some((TxStatus::Success, FEE)));
    assert_eq!(
        store(&node.db)
            .get_sender_nonce(&carol().address())
            .unwrap(),
        1,
        "B's spent refusal is unwound"
    );
    assert_eq!(total_value(&node.db, &validators), total);
}

/// The fork point (height 1) is below the gates (3), and both
/// branches cross them. A: carol's envelope with an amount below the gate
/// (h2: the earlier rule, no debit, the legacy flag) and the same envelope
/// form at the gate (h3: a payment). B: an empty block below the gate (h2),
/// then the payment at h3 and a refusal at h4. Switching unwinds blocks on
/// both sides of the gate together; rows, receipts and value follow.
#[tokio::test]
async fn a_switch_whose_branches_cross_the_gates() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators, 3);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let total = total_value(&node.db, &validators);
    let (a1, _) = a.produce(0, block_1());
    let (b1, _) = b.produce(0, block_1());
    assert_eq!(a1.hash(), b1.hash());
    node.import(&a1).await;

    let a_below = relayed(&sponsor(), 0, &carol_pays(9, Some(AMOUNT)));
    let (a2, s) = a.produce(1, vec![a_below.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    assert!(
        store(&a.db)
            .get_pending_payment(&a_below.hash())
            .unwrap()
            .is_none(),
        "no escrow below"
    );
    assert_eq!(balance(&a.db, &carol()), FUNDS, "no debit below");
    let a_at = relayed(&erin(), 0, &carol_pays(1, Some(AMOUNT)));
    let (a3, s) = a.produce(1, vec![a_at.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    assert!(store(&a.db)
        .get_pending_payment(&a_at.hash())
        .unwrap()
        .is_some());

    let (b2, _) = b.produce(2, Vec::new());
    let b_at = relayed(&frank(), 0, &carol_pays(0, Some(AMOUNT)));
    let (b3, s) = b.produce(2, vec![b_at.clone()]);
    assert_eq!(s, vec![TxStatus::Success]);
    let b_refused = relayed(&sponsor(), 0, &carol_pays(1, Some(FUNDS)));
    let (b4, s) = b.produce(2, vec![b_refused.clone()]);
    assert_eq!(s, vec![TxStatus::Failed(7)], "unaffordable: refused, spent");

    node.import(&a2).await;
    node.import(&a3).await;
    assert_eq!(rows(&node.db), rows(&a.db));
    for blk in [&b2, &b3, &b4] {
        node.import(blk).await;
    }
    assert_eq!(node.engine.best_block_hash(), b4.hash());
    assert_eq!(
        rows(&node.db),
        rows(&b.db),
        "B's state, both sides of the gate"
    );
    assert_eq!(node.receipt(&a_below), None);
    assert_eq!(node.receipt(&a_at), None);
    assert_eq!(node.receipt(&b_refused), Some((TxStatus::Failed(7), FEE)));
    assert_eq!(total_value(&node.db, &validators), total);

    let (a4, _) = a.produce(1, Vec::new());
    let (a5, _) = a.produce(1, Vec::new());
    for blk in [&a4, &a5] {
        node.import(blk).await;
    }
    assert_eq!(node.engine.best_block_hash(), a5.hash());
    assert_eq!(rows(&node.db), rows(&a.db), "A's state again");
    assert_eq!(total_value(&node.db, &validators), total);
}

/// A restart keeps the escrow, the spent nonces and the outcome rows:
/// after the node's database is closed and reopened its rows are unchanged,
/// and the next block imports on top of them.
#[tokio::test]
async fn escrow_and_spent_nonces_survive_a_restart() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators, 1);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let (a1, _) = a.produce(0, block_1());
    let pay = relayed(&sponsor(), 0, &carol_pays(0, Some(AMOUNT)));
    let (a2, _) = a.produce(0, vec![pay.clone()]);
    let (a3, s) = a.produce(
        0,
        vec![
            set_sponsorship(1, false),
            relayed(&sponsor(), 1, &carol_pays(1, None)),
        ],
    );
    assert_eq!(s, vec![TxStatus::Success, TxStatus::Failed(7)]);
    for blk in [&a1, &a2, &a3] {
        node.import(blk).await;
    }
    let before = rows(&node.db);
    let node = node.restart(&g);
    assert_eq!(rows(&node.db), before, "unchanged by the restart");
    assert_eq!(
        store(&node.db)
            .get_sender_nonce(&carol().address())
            .unwrap(),
        2
    );
    assert!(store(&node.db)
        .get_pending_payment(&pay.hash())
        .unwrap()
        .is_some());
    let (a4, _) = a.produce(0, vec![claim(0, pay.hash())]);
    node.import(&a4).await;
    assert_eq!(node.engine.best_block_hash(), a4.hash());
    assert_eq!(rows(&node.db), rows(&a.db));
}
