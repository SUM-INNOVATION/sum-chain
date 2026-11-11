//! The sponsored-envelope verification gate and the messaging fee-accounting
//! gate across a chain switch, on a real engine.
//!
//! Two off-node builders, each on its own database over the same genesis,
//! produce competing branches. In the first test they share a two-block
//! prefix below the gates and fork at and above them: relayed envelopes
//! accepted under the version-2 rule, one refused and charged, each branch
//! moving the named sender's messaging nonce and the relayers' accounts
//! differently. In the second they fork below the gates and each branch
//! crosses them, so a switch unwinds and re-executes blocks on both sides of
//! the gate height together. The node under test only imports. After each
//! switch its messaging and account state must be, row for row, the state of
//! the builder whose branch it adopted, with the abandoned branch's receipts
//! gone and the adopted branch's receipts, fees included, present. Same shape
//! as `branch_state_reorg.rs`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

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
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const FEE: u128 = 100;
const FUNDS: u128 = 1_000_000_000;
/// Both gates open from this height; blocks 1 and 2 are below it.
const GATE: u64 = 3;
/// An envelope expiry that never passes.
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
fn bob() -> KeyPair {
    key(0x63)
}

/// Two validators, static membership, journals required from height 1,
/// finality out of reach, V2 open, `admin` the messaging registry admin, both
/// messaging gates at `GATE`.
fn genesis(validators: &[KeyPair], funded: &[&KeyPair]) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        messaging: Some(MessagingParams {
            registry_admin: Some(admin().address().to_base58()),
            ..MessagingParams::default()
        }),
        messaging_sponsored_envelope_verification_enabled_from_height: Some(GATE),
        messaging_fee_nonce_accounting_enabled_from_height: Some(GATE),
        // A remediation gate set obliges the peer declaration at or below it.
        peer_protocol_declaration_required_from_height: Some(1),
        ..ChainParams::with_v2_enabled()
    };
    let mut alloc = HashMap::new();
    for k in validators.iter().chain(funded.iter().copied()) {
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

/// `kp` signs a V2 messaging transaction at `nonce`.
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

/// Carol's envelope to bob at `nonce`, unsigned.
fn carol_to_bob(nonce: u64) -> SponsoredMessage {
    let rh = recipient_hash(&bob().address());
    SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(&carol()),
        nonce,
        expiry: NEVER,
        koppa_amount: None,
    }
}

/// Signed by carol over the version-2 preimage.
fn v2(mut m: SponsoredMessage) -> SponsoredMessage {
    let preimage = sponsored_send_v2_signing_preimage(CHAIN_ID, &m);
    m.signature = *sign(&preimage, carol().private_key()).as_bytes();
    m
}

fn relayed(relayer: &KeyPair, nonce: u64, m: &SponsoredMessage) -> SignedTransaction {
    messaging_tx(relayer, nonce, op(MessagingOperation::SendMessage, m))
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

    /// Produce, publish and return the next block, signed by its rightful
    /// proposer. `salt` is added to the timestamp, so two builders on the same
    /// parent produce different blocks from the same transactions, and the
    /// same block from the same transactions with the same salt.
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
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        // Every block here is built to be published: a refused transaction
        // would be a mistake in the fixture, not a scenario.
        assert_eq!(receipts.len(), b.transactions.len());
        b
    }

    fn account_nonce(&self, kp: &KeyPair) -> u64 {
        self.state.get_nonce(&kp.address()).unwrap()
    }
}

/// The node under test: a follower on a real database.
struct Node {
    _dir: TempDir,
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
        Self {
            _dir: dir,
            db,
            engine,
        }
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

/// The messaging families and the account family: what the two rules decide.
const CONVERGENT: &[&str] = &[
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

/// Every row of the convergent families.
fn rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for family in CONVERGENT {
        for (k, v) in db.iter(family).unwrap() {
            out.insert((family.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

fn msg_nonce(db: &Database) -> u64 {
    MessagingStore::new(db)
        .get_sender_nonce(&carol().address())
        .unwrap()
}

/// Branch A (two blocks at and above the gates) is adopted, then branch B
/// (three blocks) wins and the node switches, then branch A grows past B and
/// the node switches back. After every switch the node's messaging and account
/// state is the adopted builder's, row for row; the abandoned branch's
/// receipts are gone and the adopted branch's present, fees included; carol's
/// messaging nonce and every relayer's account nonce are the adopted branch's.
#[tokio::test]
async fn the_envelope_and_accounting_rules_follow_a_chain_switch() {
    let validators = [key(1), key(2)];
    let funded = [admin(), carol(), sponsor(), erin(), frank()];
    let g = genesis(&validators, &funded.iter().collect::<Vec<_>>());

    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    assert_eq!(a.head.hash(), b.head.hash(), "one genesis");

    // ── the shared prefix, below the gates ──────────────────────────────────
    // Block 1: sponsorship on, carol registered. Block 2: an envelope without
    // a version-2 signature, at a nonce outside carol's sequence, executed
    // under the earlier rule (carol's messaging nonce becomes 1; the sponsor
    // is not charged).
    let block_1 = |nonce_admin: u64, nonce_carol: u64| {
        vec![
            messaging_tx(
                &admin(),
                nonce_admin,
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            messaging_tx(
                &carol(),
                nonce_carol,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: pk(&carol()),
                    },
                ),
            ),
        ]
    };
    let pre_gate = relayed(&sponsor(), 0, &carol_to_bob(9));
    let a1 = a.produce(0, block_1(0, 0));
    let b1 = b.produce(0, block_1(0, 0));
    assert_eq!(a1.hash(), b1.hash(), "the same block from the same bytes");
    let a2 = a.produce(0, vec![pre_gate.clone()]);
    let b2 = b.produce(0, vec![pre_gate.clone()]);
    assert_eq!(a2.hash(), b2.hash());
    assert_eq!(msg_nonce(&a.db), 1);
    assert_eq!(
        a.account_nonce(&sponsor()),
        0,
        "below the gates: not charged"
    );
    node.import(&a1).await;
    node.import(&a2).await;
    assert_eq!(node.engine.best_block_hash(), a2.hash());
    assert_eq!(node.receipt(&pre_gate), Some((TxStatus::Success, FEE)));

    // ── branch A: two accepted envelopes, one per block ─────────────────────
    let a_first = relayed(&sponsor(), 0, &v2(carol_to_bob(1)));
    let a_second = relayed(&erin(), 0, &v2(carol_to_bob(2)));
    let a3 = a.produce(1, vec![a_first.clone()]);
    let a4 = a.produce(1, vec![a_second.clone()]);
    assert_eq!(msg_nonce(&a.db), 3);
    assert_eq!(
        (a.account_nonce(&sponsor()), a.account_nonce(&erin())),
        (1, 1),
        "at the gates: each relayer charged once"
    );

    // ── branch B: the same first envelope by another relayer, a refused
    //    envelope that is charged, then the second envelope ─────────────────
    let b_first = relayed(&erin(), 0, &v2(carol_to_bob(1)));
    let b_refused = relayed(&sponsor(), 0, &carol_to_bob(2));
    let b_second = relayed(&frank(), 0, &v2(carol_to_bob(2)));
    let b3 = b.produce(2, vec![b_first.clone()]);
    let b4 = b.produce(2, vec![b_refused.clone()]);
    let b5 = b.produce(2, vec![b_second.clone()]);
    assert_eq!(msg_nonce(&b.db), 3);
    assert_eq!(
        (
            b.account_nonce(&sponsor()),
            b.account_nonce(&erin()),
            b.account_nonce(&frank())
        ),
        (1, 1, 1),
        "the refused envelope cost its relayer a nonce too"
    );
    assert_ne!(rows(&a.db), rows(&b.db), "the branches differ in state");

    // ── A is canonical ──────────────────────────────────────────────────────
    node.import(&a3).await;
    node.import(&a4).await;
    assert_eq!(node.engine.best_block_hash(), a4.hash());
    assert_eq!(node.engine.current_height(), 4);
    assert_eq!(rows(&node.db), rows(&a.db), "the node holds A's state");
    assert_eq!(node.receipt(&a_first), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a_second), Some((TxStatus::Success, FEE)));

    // ── the switch to B ─────────────────────────────────────────────────────
    node.import(&b3).await;
    assert_eq!(node.engine.best_block_hash(), a4.hash(), "a side branch");
    node.import(&b4).await;
    node.import(&b5).await;
    assert_eq!(node.engine.best_block_hash(), b5.hash(), "switched");
    assert_eq!(node.engine.current_height(), 5);
    assert_eq!(rows(&node.db), rows(&b.db), "the node holds B's state");
    assert_eq!(msg_nonce(&node.db), 3);
    assert_eq!(node.receipt(&a_first), None, "unwound");
    assert_eq!(node.receipt(&a_second), None, "unwound");
    assert_eq!(node.receipt(&b_first), Some((TxStatus::Success, FEE)));
    assert_eq!(
        node.receipt(&b_refused),
        Some((TxStatus::Failed(7), FEE)),
        "refused, and the receipt reports the fee it cost"
    );
    assert_eq!(node.receipt(&b_second), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&pre_gate), Some((TxStatus::Success, FEE)));

    // ── and back: A grows past B ────────────────────────────────────────────
    let a_third = relayed(&frank(), 0, &v2(carol_to_bob(3)));
    let a5 = a.produce(1, vec![a_third.clone()]);
    let a6 = a.produce(1, Vec::new());
    node.import(&a5).await;
    node.import(&a6).await;
    assert_eq!(node.engine.best_block_hash(), a6.hash());
    assert_eq!(node.engine.current_height(), 6);
    assert_eq!(
        rows(&node.db),
        rows(&a.db),
        "the node holds A's state again"
    );
    assert_eq!(msg_nonce(&node.db), 4);
    assert_eq!(node.receipt(&a_first), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a_second), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a_third), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&b_first), None);
    assert_eq!(node.receipt(&b_refused), None);
    assert_eq!(node.receipt(&b_second), None);
}

/// The fork point (height 1) is below the gates (`GATE` = 3), and each branch
/// crosses them: a block below the gates (height 2, an envelope without a
/// version-2 signature executed under the earlier rule, uncharged) and blocks
/// at and above them (a version-2 envelope accepted; on branch A also one
/// without a version-2 signature, refused and charged). Switching from A to B
/// and back unwinds a block below the gates and a block at them together, and
/// re-executes the other branch's. After each switch the node's state is the
/// adopted builder's, row for row, its receipts are the adopted branch's, and
/// carol's messaging nonce is the adopted branch's.
#[tokio::test]
async fn a_chain_switch_whose_branches_cross_the_gates() {
    let validators = [key(1), key(2)];
    let funded = [admin(), carol(), sponsor(), erin(), frank()];
    let g = genesis(&validators, &funded.iter().collect::<Vec<_>>());
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators);
    let mut b = Builder::new(&g, &validators);
    let block_1 = vec![
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
    ];
    let a1 = a.produce(0, block_1.clone());
    let b1 = b.produce(0, block_1);
    assert_eq!(a1.hash(), b1.hash(), "the same block from the same bytes");
    node.import(&a1).await;

    // Branch A: height 2 below the gates, height 3 at them.
    let a2_below = relayed(&sponsor(), 0, &carol_to_bob(9));
    let a3_accepted = relayed(&erin(), 0, &v2(carol_to_bob(1)));
    let a3_refused = relayed(&frank(), 0, &carol_to_bob(1));
    let a2 = a.produce(1, vec![a2_below.clone()]);
    let a3 = a.produce(1, vec![a3_accepted.clone(), a3_refused.clone()]);
    // Branch B: height 2 below the gates (another envelope, by another
    // relayer), heights 3 and 4 at and above them.
    let b2_below = relayed(&erin(), 0, &carol_to_bob(7));
    let b3_accepted = relayed(&frank(), 0, &v2(carol_to_bob(1)));
    let b4_accepted = relayed(&sponsor(), 0, &v2(carol_to_bob(2)));
    let b2 = b.produce(2, vec![b2_below.clone()]);
    let b3 = b.produce(2, vec![b3_accepted.clone()]);
    let b4 = b.produce(2, vec![b4_accepted.clone()]);

    // ── A is canonical ──────────────────────────────────────────────────────
    node.import(&a2).await;
    node.import(&a3).await;
    assert_eq!(node.engine.best_block_hash(), a3.hash());
    assert_eq!(rows(&node.db), rows(&a.db), "the node holds A's state");
    assert_eq!(node.receipt(&a2_below), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a3_accepted), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a3_refused), Some((TxStatus::Failed(7), FEE)));
    assert_eq!(
        a.account_nonce(&sponsor()),
        0,
        "below the gates: not charged"
    );
    assert_eq!(msg_nonce(&node.db), 2);

    // ── the switch to B ─────────────────────────────────────────────────────
    for block in [&b2, &b3, &b4] {
        node.import(block).await;
    }
    assert_eq!(node.engine.best_block_hash(), b4.hash(), "switched");
    assert_eq!(rows(&node.db), rows(&b.db), "the node holds B's state");
    for tx in [&a2_below, &a3_accepted, &a3_refused] {
        assert_eq!(node.receipt(tx), None, "unwound");
    }
    assert_eq!(node.receipt(&b2_below), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&b3_accepted), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&b4_accepted), Some((TxStatus::Success, FEE)));
    assert_eq!(msg_nonce(&node.db), 3);

    // ── and back: A grows past B ────────────────────────────────────────────
    // Height 4 on A carries the very transaction B carried at height 4.
    let a4_accepted = relayed(&sponsor(), 0, &v2(carol_to_bob(2)));
    assert_eq!(a4_accepted.hash(), b4_accepted.hash());
    let a4 = a.produce(1, vec![a4_accepted.clone()]);
    let a5 = a.produce(1, Vec::new());
    let a6 = a.produce(1, Vec::new());
    for block in [&a4, &a5, &a6] {
        node.import(block).await;
    }
    assert_eq!(node.engine.best_block_hash(), a6.hash(), "switched back");
    assert_eq!(rows(&node.db), rows(&a.db), "the node holds A's state again");
    assert_eq!(node.receipt(&b2_below), None);
    assert_eq!(node.receipt(&b3_accepted), None);
    assert_eq!(node.receipt(&a2_below), Some((TxStatus::Success, FEE)));
    assert_eq!(node.receipt(&a3_refused), Some((TxStatus::Failed(7), FEE)));
    assert_eq!(node.receipt(&a4_accepted), Some((TxStatus::Success, FEE)));
    assert_eq!(msg_nonce(&node.db), 3);
}
