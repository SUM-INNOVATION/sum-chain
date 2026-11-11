//! Which of a relay's sponsored envelopes a producer carries when one of them
//! cannot be executed.
//!
//! `messaging_submitSponsored` wraps every envelope in a transaction FROM the
//! relay's sponsor account, at that account's committed nonce and the relay's
//! fixed fee; executing it advances no account nonce. So every relayed
//! envelope has the same `tx.sender()`, and envelopes of equal fee are ordered
//! by hash.
//!
//! An envelope can be impossible to execute against the current state: its
//! named sender has used its messaging quota (while the messaging clock gates
//! are closed the quota counts in one bucket), or its recipient does not
//! accept the sender. `check_rate_limit` and the recipient filters return an
//! error rather than a failed receipt, so the producer's screening leaves the
//! envelope out of the proposal and in the pool (`TxFailureClass::Transient`).
//! The named sender's later envelopes, which follow it in that sender's
//! messaging-nonce sequence, are left out with it; every other sender's
//! envelopes through the same relay are carried.
//!
//! These tests drive the real producer (`select_for_block` → `create_block`)
//! over a real database, in production's shape: V2 open, the inclusion policy
//! wired, sponsorship enabled by the registry admin, the clock gates closed.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SetDailyQuotaData, SetSponsorshipEnabledData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Block, Hash, MessagingOperation, SignedTransaction, SponsoredMessage, TransactionV2,
    TxPayload, TxStatus,
};
use sumchain_state::mempool::{InclusionPolicy, MessagingQuotaAdmission};
use sumchain_state::{Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// What `messaging_submitSponsored` charges every envelope it relays.
const RELAY_FEE: u128 = 1_000_000;
/// The fee of every other transaction here.
const FEE: u128 = 1_000;
/// Three messages per sender, so a sender reaches its quota in one block.
const QUOTA: u32 = 3;
/// How many envelopes B and C each have pending: exactly their quota, so every
/// one of them can succeed.
const RUN: u64 = 3;
/// A far-future expiry, as a client sets it.
const EXPIRY: u64 = 4_000_000_000;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn validator_p() -> KeyPair {
    key(1)
}
fn validator_q() -> KeyPair {
    key(2)
}
/// The messaging registry admin.
fn admin() -> KeyPair {
    key(20)
}
/// The relay's sponsor account (`SUMAIL_SPONSOR_KEY`).
fn sponsor() -> KeyPair {
    key(21)
}
/// The sender that reaches its quota.
fn alice() -> KeyPair {
    key(22)
}
/// Two unrelated senders.
fn bob() -> KeyPair {
    key(23)
}
fn carol() -> KeyPair {
    key(24)
}
fn recipient() -> KeyPair {
    key(25)
}
/// A sender under its quota whose first envelope goes to a recipient that has
/// blocked it.
fn dave() -> KeyPair {
    key(26)
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn genesis(validators: &[KeyPair]) -> Genesis {
    let mut params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_v2_enabled()
    };
    params.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    let mut alloc = HashMap::new();
    for k in validators.iter().chain(
        [
            admin(),
            sponsor(),
            alice(),
            bob(),
            carol(),
            recipient(),
            dave(),
        ]
        .iter(),
    ) {
        alloc.insert(k.address().to_base58(), 1_000_000_000_000u128);
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

// ── transactions ────────────────────────────────────────────────────────────

fn signed(kp: &KeyPair, nonce: u64, fee: u128, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(kp))
}

fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
    }
}

fn admin_tx(
    nonce: u64,
    operation: MessagingOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    signed(&admin(), nonce, FEE, op(operation, payload))
}

fn set_quota(admin_nonce: u64, quota: u32) -> SignedTransaction {
    admin_tx(
        admin_nonce,
        MessagingOperation::SetDailyQuota,
        &SetDailyQuotaData { quota },
    )
}

fn register(kp: &KeyPair) -> SignedTransaction {
    signed(
        kp,
        0,
        FEE,
        op(
            MessagingOperation::RegisterPublicKey,
            &RegisterPublicKeyData { public_key: pk(kp) },
        ),
    )
}

/// `by` blocks `whom` from its inbox.
fn block_sender(by: &KeyPair, nonce: u64, whom: &KeyPair) -> SignedTransaction {
    signed(
        by,
        nonce,
        FEE,
        op(
            MessagingOperation::BlockSender,
            &BlockSenderData {
                sender: whom.address(),
            },
        ),
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

/// `user`'s envelope to `to` at messaging nonce `nonce`, signed by `user` over
/// the relay preimage, wrapped exactly as `messaging_submitSponsored` wraps it:
/// from the sponsor, at the sponsor's committed account nonce (always 0 here:
/// a relayed envelope advances no account nonce), at the relay's fee.
fn relayed_to(user: &KeyPair, to: &Address, nonce: u64, expiry: u64) -> SignedTransaction {
    let rh = recipient_hash(to);
    let message_data = valid_message(rh);
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        nonce,
        expiry,
        hex::encode(rh),
        hex::encode(Hash::hash(&message_data).as_bytes())
    );
    let m = SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: *sign(preimage.as_bytes(), user.private_key()).as_bytes(),
        sender_pubkey: pk(user),
        nonce,
        expiry,
        koppa_amount: None,
    };
    signed(
        &sponsor(),
        0,
        RELAY_FEE,
        op(MessagingOperation::SendMessage, &m),
    )
}

fn relayed(user: &KeyPair, nonce: u64, expiry: u64) -> SignedTransaction {
    relayed_to(user, &recipient().address(), nonce, expiry)
}

/// B's and C's runs of `RUN` envelopes each.
fn others() -> Vec<SignedTransaction> {
    let mut v = Vec::new();
    for user in [bob(), carol()] {
        for n in 0..RUN {
            v.push(relayed(&user, n, EXPIRY));
        }
    }
    v
}

/// A's envelope at `nonce`, with an expiry chosen so that its hash sorts
/// BEFORE every transaction in `behind` — so the fee-then-hash selection order
/// puts it first among the sponsored messages.
fn relayed_first(user: &KeyPair, nonce: u64, behind: &[SignedTransaction]) -> SignedTransaction {
    let floor = behind.iter().map(|t| t.hash()).min().expect("non-empty");
    (0..10_000u64)
        .map(|i| relayed(user, nonce, EXPIRY + 1 + i))
        .find(|t| t.hash() < floor)
        .expect("an expiry whose envelope sorts first")
}

fn hashes(txs: &[SignedTransaction]) -> HashSet<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

// ── the node ────────────────────────────────────────────────────────────────

/// A validator wired as `Node::new` wires one: the inclusion policy over its
/// own database, the pool's production configuration — with or without the
/// policy's quota rule (`with_messaging_quota_admission`). Without it, the
/// pool is a node that does not have the rule, or a pool that admitted an
/// envelope before its sender's count moved.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
    key: KeyPair,
    /// The live height the quota rule reads, as `Node::new` shares it.
    chain_height: Arc<AtomicU64>,
}

impl Node {
    fn new(g: &Genesis, key: KeyPair, quota_rule: bool) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let chain_height = Arc::new(AtomicU64::new(0));
        let mut pool = Mempool::new(MempoolConfig {
            min_fee: g.params.min_fee,
            max_tx_bytes: g.params.max_block_bytes,
            ..MempoolConfig::default()
        })
        .with_inclusion_policy(InclusionPolicy { db: db.clone() });
        if quota_rule {
            pool = pool.with_messaging_quota_admission(MessagingQuotaAdmission {
                params: Arc::new(g.params.clone()),
                current_height: chain_height.clone(),
            });
        }
        let mempool = Arc::new(pool);
        let engine = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                g,
                Some(KeyPair::from_bytes(*key.private_key().as_bytes())),
            )
            .unwrap(),
        );
        engine.init_genesis(g).unwrap();
        Self {
            _dir: dir,
            db,
            state,
            mempool,
            engine,
            key,
            chain_height,
        }
    }

    fn is_proposer(&self, height: u64) -> bool {
        self.engine.get_proposer(height) == pk(&self.key)
    }

    /// One production tick, as `run_block_producer` runs it.
    async fn tick(&self) -> Block {
        let txs = self.mempool.select_for_block(1_000);
        self.engine.propose_block(txs).await.expect("a block")
    }

    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.unwrap();
    }

    fn try_submit(&self, t: &SignedTransaction) -> Result<Hash, StateError> {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        self.mempool.add(t.clone())
    }

    fn submit(&self, txs: &[SignedTransaction]) {
        for t in txs {
            self.try_submit(t).expect("admitted");
        }
    }

    fn pending(&self, txs: &[SignedTransaction]) -> usize {
        txs.iter()
            .filter(|t| self.mempool.contains(&t.hash()))
            .count()
    }

    fn status(&self, t: &SignedTransaction) -> Option<TxStatus> {
        ReceiptStore::new(&self.db)
            .get(&t.hash())
            .unwrap()
            .map(|r| r.status)
    }

    fn messaging_nonce(&self, k: &KeyPair) -> u64 {
        MessagingStore::new(&self.db)
            .get_sender_nonce(&k.address())
            .unwrap()
    }

    fn height(&self) -> u64 {
        self.engine.current_height()
    }

    fn account_nonce(&self, k: &KeyPair) -> u64 {
        self.state.get_nonce(&k.address()).unwrap()
    }
}

/// A chain of validators, each block produced by its rightful proposer and
/// imported by every other node.
struct Net {
    nodes: Vec<Node>,
}

impl Net {
    /// Pools without the quota rule.
    fn new(validators: Vec<KeyPair>) -> Self {
        Self::build(validators, false)
    }

    /// Pools wired exactly as `Node::new` wires them, quota rule included.
    fn wired(validators: Vec<KeyPair>) -> Self {
        Self::build(validators, true)
    }

    fn build(validators: Vec<KeyPair>, quota_rule: bool) -> Self {
        let g = genesis(&validators);
        let nodes = validators
            .into_iter()
            .map(|k| Node::new(&g, k, quota_rule))
            .collect();
        Self { nodes }
    }

    fn proposer(&self) -> usize {
        let h = self.nodes[0].height() + 1;
        self.nodes
            .iter()
            .position(|n| n.is_proposer(h))
            .expect("a proposer")
    }

    async fn spread(&self, from: usize, b: &Block) {
        for (i, n) in self.nodes.iter().enumerate() {
            if i != from {
                n.import(b).await;
            }
        }
    }

    /// The next block from the given list, whoever proposes it.
    async fn produce(&self, txs: Vec<SignedTransaction>) -> Block {
        let p = self.proposer();
        let b = self.nodes[p].engine.propose_block(txs).await.unwrap();
        self.spread(p, &b).await;
        b
    }

    /// The next block from its proposer's pool; returns it with the index of
    /// the node that produced it.
    async fn tick(&self) -> (usize, Block) {
        let p = self.proposer();
        let b = self.nodes[p].tick().await;
        self.spread(p, &b).await;
        (p, b)
    }

    /// Sponsorship on, the quota at `QUOTA`, A, B, C and D registered, and A
    /// at its quota.
    async fn ready(&self) {
        let enable = admin_tx(
            0,
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        );
        self.produce(vec![enable.clone()]).await;
        // A messaging admin operation advances no account nonce.
        let quota = set_quota(self.nodes[0].account_nonce(&admin()), QUOTA);
        self.produce(vec![quota.clone()]).await;
        let regs: Vec<_> = [alice(), bob(), carol(), dave()]
            .iter()
            .map(register)
            .collect();
        self.produce(regs.clone()).await;
        let used: Vec<_> = (0..QUOTA as u64)
            .map(|n| relayed(&alice(), n, EXPIRY))
            .collect();
        self.produce(used.clone()).await;
        let n = &self.nodes[0];
        for t in [enable, quota].iter().chain(regs.iter()).chain(used.iter()) {
            assert_eq!(n.status(t), Some(TxStatus::Success), "setup");
        }
        assert_eq!(
            n.messaging_nonce(&alice()),
            QUOTA as u64,
            "A is at its quota"
        );
    }
}

// ── 1. the refused envelope leaves the proposal alone ───────────────────────

/// A's next envelope is over quota and sorts first among the sponsored
/// messages; B and C have runs pending through the same sponsor.
///
/// The first block carries every envelope of B and C. A's envelope is refused
/// at screening, left in the pool and never carried; the blocks after that are
/// empty.
#[tokio::test]
async fn an_envelope_over_its_senders_quota_is_left_out_alone() {
    let net = Net::new(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];

    let others = others();
    let held = relayed_first(&alice(), QUOTA as u64, &others);
    node.submit(&[held.clone()]);
    node.submit(&others);

    let (_, b) = net.tick().await;
    assert_eq!(
        hashes(&b.transactions),
        hashes(&others),
        "every envelope of B and C, and nothing else"
    );
    for t in &others {
        assert_eq!(node.status(t), Some(TxStatus::Success));
    }
    assert_eq!(node.messaging_nonce(&bob()), RUN);
    assert_eq!(node.messaging_nonce(&carol()), RUN);

    let start = node.height();
    for _ in 0..3 {
        let (_, b) = net.tick().await;
        assert!(b.transactions.is_empty());
    }
    assert_eq!(node.height(), start + 3, "the chain never stops");
    assert!(node.mempool.contains(&held.hash()), "A's envelope is held");
    assert_eq!(node.status(&held), None, "and never carried");
    assert_eq!(node.messaging_nonce(&alice()), QUOTA as u64);
}

/// The same, with the refused envelope in the MIDDLE of the sponsored order:
/// what sorts before it and what sorts after it are both carried.
#[tokio::test]
async fn senders_on_both_sides_of_the_refused_envelope_are_carried() {
    let net = Net::new(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];

    let others = others();
    let mut sorted: Vec<Hash> = others.iter().map(|t| t.hash()).collect();
    sorted.sort();
    let (low, high) = (sorted[0], sorted[sorted.len() - 1]);
    let held = (0..10_000u64)
        .map(|i| relayed(&alice(), QUOTA as u64, EXPIRY + 1 + i))
        .find(|t| low < t.hash() && t.hash() < high)
        .expect("an envelope that sorts between B's and C's");
    node.submit(&[held.clone()]);
    node.submit(&others);

    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&others));
    assert!(node.mempool.contains(&held.hash()));
}

// ── 2. the refused sender's own later envelopes wait with it ────────────────

/// D's envelope 0 goes to a recipient that has blocked D, which cannot be
/// executed; D's envelope 1 goes to someone else and could be. Envelope 1 is
/// NOT carried: carried alone it would move D's committed messaging nonce past
/// envelope 0, and the inclusion policy would then evict envelope 0 as stale.
/// Both stay pending, D's nonce stays where it was — and B and C, through the
/// same sponsor, are carried.
#[tokio::test]
async fn the_refused_senders_later_envelopes_wait_with_it() {
    let net = Net::new(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];
    net.produce(vec![block_sender(
        &recipient(),
        node.account_nonce(&recipient()),
        &dave(),
    )])
    .await;

    let others = others();
    let d0 = relayed_to(&dave(), &recipient().address(), 0, EXPIRY);
    let d1 = relayed_to(&dave(), &bob().address(), 0 + 1, EXPIRY);
    node.submit(&[d0.clone(), d1.clone()]);
    node.submit(&others);

    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&others));
    assert!(node.mempool.contains(&d0.hash()));
    assert!(
        node.mempool.contains(&d1.hash()),
        "D's next envelope waits for D's first"
    );
    assert_eq!(node.status(&d1), None);
    assert_eq!(node.messaging_nonce(&dave()), 0);
    let (_, b) = net.tick().await;
    assert!(b.transactions.is_empty());
    assert_eq!(node.pending(&[d0, d1]), 2);
}

// ── 3. the held envelope goes through once its sender has quota ─────────────

/// While the other senders' envelopes are carried, A's envelope is held. The
/// registry admin raises the quota; the next block carries A's held envelope,
/// and A's next one after it. Nothing is resubmitted.
#[tokio::test]
async fn the_held_envelope_is_carried_once_its_sender_has_quota_again() {
    let net = Net::new(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];

    let others = others();
    let held = relayed_first(&alice(), QUOTA as u64, &others);
    node.submit(&[held.clone()]);
    node.submit(&others);
    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&others));

    let raise = set_quota(node.account_nonce(&admin()), QUOTA + 10);
    node.submit(&[raise.clone()]);
    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&[raise.clone()]));
    assert_eq!(node.status(&raise), Some(TxStatus::Success));

    let next = relayed(&alice(), QUOTA as u64 + 1, EXPIRY);
    node.submit(&[next.clone()]);
    let (_, b) = net.tick().await;
    assert_eq!(
        hashes(&b.transactions),
        hashes(&[held.clone(), next.clone()])
    );
    assert_eq!(node.status(&held), Some(TxStatus::Success));
    assert_eq!(node.status(&next), Some(TxStatus::Success));
    assert_eq!(node.messaging_nonce(&alice()), QUOTA as u64 + 2);
    assert!(node.mempool.is_empty());
}

// ── 4. two producers ────────────────────────────────────────────────────────

/// Two validators in rotation. P holds A's envelope (it reached P and not Q);
/// both hold B's and C's. P's own block carries all of
/// B and C; Q imports it and evicts its copies as included. Both end on the
/// same head.
#[tokio::test]
async fn with_two_producers_the_one_holding_the_envelope_carries_the_others() {
    let net = Net::new(vec![validator_p(), validator_q()]);
    net.ready().await;

    let others = others();
    let held = relayed_first(&alice(), QUOTA as u64, &others);
    let p = net
        .nodes
        .iter()
        .position(|n| pk(&n.key) == pk(&validator_p()))
        .unwrap();
    let q = 1 - p;
    // P proposes the next height.
    if net.proposer() != p {
        net.produce(Vec::new()).await;
    }
    assert_eq!(net.proposer(), p);
    net.nodes[p].submit(&[held.clone()]);
    for n in &net.nodes {
        n.submit(&others);
    }

    let (who, p_block) = net.tick().await;
    assert_eq!(who, p);
    assert_eq!(hashes(&p_block.transactions), hashes(&others));
    let (who, q_block) = net.tick().await;
    assert_eq!(who, q);
    assert!(q_block.transactions.is_empty(), "nothing left for Q");
    for n in &net.nodes {
        assert_eq!(n.messaging_nonce(&bob()), RUN);
        assert_eq!(n.messaging_nonce(&carol()), RUN);
        assert_eq!(n.status(&held), None);
        assert_eq!(n.pending(&others), 0);
    }
    assert!(net.nodes[p].mempool.contains(&held.hash()));
    assert_eq!(
        net.nodes[p].engine.best_block_hash(),
        net.nodes[q].engine.best_block_hash()
    );
}

// ── 5. the node's full wiring ───────────────────────────────────────────────

/// With the pool wired as the node wires it, A's over-quota envelope is refused
/// at admission with the count, and the pool never holds it.
///
/// An envelope admitted while its sender had quota, whose sender's count then
/// moved before it was carried — here the registry admin lowers the quota in
/// between — is still possible. That one is held at selection alone, as
/// above, and B's and C's are carried.
#[tokio::test]
async fn wired_as_the_node_wires_it_the_over_quota_envelope_is_refused_at_admission() {
    let net = Net::wired(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];

    let (b0, c0) = (relayed(&bob(), 0, EXPIRY), relayed(&carol(), 0, EXPIRY));
    let (b1, c1) = (relayed(&bob(), 1, EXPIRY), relayed(&carol(), 1, EXPIRY));
    let over = relayed_first(&alice(), QUOTA as u64, &[b1.clone(), c1.clone()]);
    match node.try_submit(&over) {
        Err(StateError::SponsoredEnvelopeRefused(why)) => {
            assert!(why.contains("used 3 of its 3"), "{why}")
        }
        other => panic!("refused for its quota, not {other:?}"),
    }
    node.submit(&[b0.clone(), c0.clone()]);
    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&[b0, c0]));

    // Room for one more: A's envelope is admitted, and B's and C's next.
    net.produce(vec![set_quota(node.account_nonce(&admin()), QUOTA + 1)])
        .await;
    node.submit(&[over.clone(), b1.clone(), c1.clone()]);
    // The quota goes back down before any of them is carried: A is over it
    // again, B and C are not. (A different fee from the setup's identical
    // `SetDailyQuota`, which the policy would refuse as already included.)
    let lower = signed(
        &admin(),
        node.account_nonce(&admin()),
        FEE + 1,
        op(
            MessagingOperation::SetDailyQuota,
            &SetDailyQuotaData { quota: QUOTA },
        ),
    );
    let b = net.produce(vec![lower.clone()]).await;
    assert_eq!(hashes(&b.transactions), hashes(&[lower]));

    let (_, b) = net.tick().await;
    assert_eq!(
        hashes(&b.transactions),
        hashes(&[b1, c1]),
        "B and C carried; A's envelope held, alone"
    );
    assert!(node.mempool.contains(&over.hash()));
    assert_eq!(node.status(&over), None);
    assert_eq!(node.messaging_nonce(&alice()), QUOTA as u64);
}

// ── 6. per-sender allowance ────────────────────────────────────────────────

/// The pool caps pending transactions per sender (`max_per_sender`, 100). An
/// envelope the policy admitted counts against the sender it NAMES. D's first
/// envelope cannot be executed for a reason the quota rule does not see — its
/// recipient has blocked D — so it is held, and D's later envelopes are
/// admitted behind it in sequence, up to D's own allowance. Another sender's
/// envelope through the same relay is admitted and carried, and so is a
/// transaction of the sponsor's own.
#[tokio::test]
async fn a_held_run_uses_its_own_senders_allowance() {
    let net = Net::wired(vec![validator_p()]);
    net.ready().await;
    let node = &net.nodes[0];
    // The production quota, and D blocked by the recipient of its first send.
    net.produce(vec![set_quota(node.account_nonce(&admin()), 100)])
        .await;
    net.produce(vec![block_sender(
        &recipient(),
        node.account_nonce(&recipient()),
        &dave(),
    )])
    .await;

    let mut run = vec![relayed_to(&dave(), &recipient().address(), 0, EXPIRY)];
    run.extend((1..100).map(|n| relayed_to(&dave(), &bob().address(), n, EXPIRY)));
    node.submit(&run);
    assert!(
        matches!(
            node.try_submit(&relayed_to(&dave(), &bob().address(), 100, EXPIRY)),
            Err(StateError::SponsoredEnvelopeRefused(_)) | Err(StateError::MempoolFull)
        ),
        "D has no room left of its own"
    );

    let b0 = relayed(&bob(), 0, EXPIRY);
    node.submit(&[b0.clone()]);
    let own = register(&sponsor());
    node.submit(&[own.clone()]);
    let (_, b) = net.tick().await;
    assert_eq!(hashes(&b.transactions), hashes(&[b0.clone(), own.clone()]));
    assert_eq!(node.status(&b0), Some(TxStatus::Success));
    assert_eq!(node.pending(&run), 100, "D's run is held");
}
