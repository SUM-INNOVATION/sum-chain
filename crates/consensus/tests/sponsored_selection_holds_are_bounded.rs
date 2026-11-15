//! What selection holds back never takes the block from anyone else, on a
//! real producer, across the messaging gates.
//!
//! - A transaction above a gap in its account's nonces, or an envelope beyond
//!   its sender's first missing envelope nonce, and whatever depends on them,
//!   is decided before the pool is cut to a block's size: with more such
//!   transactions than a block carries, at a higher fee, honest transactions
//!   are carried in every block.
//! - What is held above a gap does not keep its place in the pool: at its
//!   `GAP_HOLD_SELECTIONS`-th selection it is evicted, with no receipt, and
//!   its place is free again; under sustained load the pool holds at most
//!   that many selections' worth of it, and a full pool admits honest
//!   transactions again. Below the gates an envelope above its relay's gap
//!   goes the same way, with its sender's later envelopes, and the sender's
//!   re-sent envelope is delivered.
//! - From the accounting gate, a sponsor whose envelope waits on another
//!   account's gap is carried to that envelope's refusal within
//!   `CROSS_ACCOUNT_WAIT_SELECTIONS` selections, and its queue moves; the
//!   other account's envelope above its own gap is evicted.
//! - The cycle's victim is the later head on the cycle when a non-head pays
//!   the lowest fee, and the cycle's other transactions are delivered once
//!   the victim's nonce is filled.
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, Hash, MessagingOperation, Receipt,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::mempool::{
    advances_nonce_below_accounting_gate, InclusionGates, InclusionPolicy,
    CROSS_ACCOUNT_WAIT_SELECTIONS, GAP_HOLD_SELECTIONS,
};
use sumchain_state::{Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
const FUNDS: u128 = 1_000_000_000_000;
const NEVER: u64 = u64::MAX;
/// The block each case turns on: block 1 sets the chain up, block 2 carries
/// an unrelated transfer, and the case's transactions are offered from block
/// 3 on.
const CASE_BLOCK: u64 = 3;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}
fn validator() -> KeyPair {
    key(0x81)
}
fn admin() -> KeyPair {
    key(0x82)
}
fn recipient() -> KeyPair {
    key(0x83)
}
/// Sponsors, `0x90..`; the senders they relay for, `0xa0..`.
fn sponsor(i: u8) -> KeyPair {
    key(0x90 + i)
}
fn sender(i: u8) -> KeyPair {
    key(0xa0 + i)
}
/// A sponsor and a user unrelated to every case's cycle or gap.
fn unrelated_sponsor() -> KeyPair {
    key(0xb0)
}
fn unrelated_user() -> KeyPair {
    key(0xb1)
}
/// An account that only sends transfers.
fn bystander() -> KeyPair {
    key(0xb2)
}

/// One configuration of the two messaging gates
/// (`messaging_sponsored_envelope_verification_enabled_from_height`, `0x1048`,
/// and `messaging_fee_nonce_accounting_enabled_from_height`, `0x1049`).
#[derive(Clone, Copy, Debug)]
struct Gates {
    name: &'static str,
    verification: Option<u64>,
    accounting: Option<u64>,
}

impl Gates {
    fn accounting_at(&self, height: u64) -> bool {
        self.accounting.is_some_and(|gate| height >= gate)
    }
    fn verification_at(&self, height: u64) -> bool {
        self.verification.is_some_and(|gate| height >= gate)
    }
}

/// The gates absent; set above the chain's history; set inside it; and
/// `0x1049`, `0x1048` and both at the case's block `H`, one below (`H-1`:
/// the case's first block is below the gate, the next at it) and one above
/// (`H+1`).
fn matrix() -> Vec<Gates> {
    let h = CASE_BLOCK;
    let g = |name, verification, accounting| Gates {
        name,
        verification,
        accounting,
    };
    vec![
        g("absent", None, None),
        g("above history", Some(1_000_000), Some(1_000_000)),
        g("inside history", Some(1), Some(1)),
        g("both at H-1", Some(h + 1), Some(h + 1)),
        g("both at H", Some(h), Some(h)),
        g("both at H+1", Some(h - 1), Some(h - 1)),
        g("0x1049 at H-1", Some(1), Some(h + 1)),
        g("0x1049 at H", Some(1), Some(h)),
        g("0x1049 at H+1", Some(1), Some(h - 1)),
        g("0x1049 only, at H", None, Some(h)),
        g("0x1048 at H-1", Some(h + 1), Some(1)),
        g("0x1048 at H", Some(h), Some(1)),
        g("0x1048 at H+1", Some(h - 1), Some(1)),
        g("0x1048 only, at H", Some(h), None),
    ]
}

fn genesis(gates: Gates) -> Genesis {
    let any_gate = gates.verification.is_some() || gates.accounting.is_some();
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        messaging: Some(MessagingParams {
            registry_admin: Some(admin().address().to_base58()),
            ..MessagingParams::default()
        }),
        messaging_sponsored_envelope_verification_enabled_from_height: gates.verification,
        messaging_fee_nonce_accounting_enabled_from_height: gates.accounting,
        // A remediation gate set obliges the peer declaration at or below it.
        peer_protocol_declaration_required_from_height: any_gate.then_some(1),
        ..ChainParams::with_v2_enabled()
    };
    let mut alloc = HashMap::new();
    let mut accounts = vec![
        validator(),
        admin(),
        recipient(),
        unrelated_sponsor(),
        unrelated_user(),
        bystander(),
    ];
    accounts.extend((0..4).map(sponsor));
    accounts.extend((0..4).map(sender));
    for k in accounts {
        alloc.insert(k.address().to_base58(), FUNDS);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        vec![validator().public_key().to_base58()],
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
    let mut m = header.to_bytes().to_vec();
    m.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    m.extend_from_slice(&[0u8, 0u8]);
    m.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    m
}

fn signed(kp: &KeyPair, nonce: u64, fee: u128, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(kp))
}

fn messaging(
    kp: &KeyPair,
    nonce: u64,
    fee: u128,
    operation: MessagingOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    signed(
        kp,
        nonce,
        fee,
        TxPayload::Messaging(MessagingTxData {
            operation,
            data: bincode::serialize(payload).unwrap(),
        }),
    )
}

fn transfer(from: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    signed(
        from,
        nonce,
        fee,
        TxPayload::Transfer {
            to: recipient().address(),
            amount: 1,
        },
    )
}

/// `user`'s version-2 envelope at envelope nonce `envelope_nonce`, relayed
/// by `sponsor` at account nonce `nonce` with fee `fee`.
fn relayed(
    sponsor: &KeyPair,
    nonce: u64,
    fee: u128,
    user: &KeyPair,
    envelope_nonce: u64,
) -> SignedTransaction {
    let rh = recipient_hash(&recipient().address());
    let mut m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(user),
        nonce: envelope_nonce,
        expiry: NEVER,
        koppa_amount: None,
    };
    m.signature = *sign(
        &sponsored_send_v2_signing_preimage(CHAIN_ID, &m),
        user.private_key(),
    )
    .as_bytes();
    messaging(sponsor, nonce, fee, MessagingOperation::SendMessage, &m)
}

/// A validator wired as `Node::new` wires its pool: the inclusion policy over
/// its own database and the next-block rules at its live height.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
    chain_height: Arc<AtomicU64>,
    gates: Gates,
}

impl Node {
    fn new(gates: Gates) -> Self {
        Self::with_pool(gates, |c| c)
    }

    /// [`Node::new`], with the pool's configuration tuned by `tune`.
    fn with_pool(gates: Gates, tune: impl FnOnce(MempoolConfig) -> MempoolConfig) -> Self {
        let g = genesis(gates);
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let chain_height = Arc::new(AtomicU64::new(0));
        let mempool = Arc::new(
            Mempool::new(tune(MempoolConfig {
                min_fee: g.params.min_fee,
                max_tx_bytes: g.params.max_block_bytes,
                ..MempoolConfig::default()
            }))
            .with_inclusion_policy(InclusionPolicy { db: db.clone() })
            .with_inclusion_gates(InclusionGates {
                params: Arc::new(g.params.clone()),
                chain_id: g.chain_id,
                current_height: chain_height.clone(),
            }),
        );
        let engine = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                &g,
                Some(validator()),
            )
            .unwrap(),
        );
        engine.init_genesis(&g).unwrap();
        Self {
            _dir: dir,
            db,
            state,
            mempool,
            engine,
            chain_height,
            gates,
        }
    }

    fn submit(&self, txs: &[&SignedTransaction]) {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        for t in txs {
            self.mempool
                .add((*t).clone())
                .unwrap_or_else(|e| panic!("{}: admitted: {e}", self.gates.name));
        }
    }

    /// `t` offered to the pool: whether admission takes it.
    fn try_submit(&self, t: &SignedTransaction) -> Result<(), StateError> {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        self.mempool.add(t.clone()).map(|_| ())
    }

    /// One production tick, as `run_block_producer` runs it.
    async fn tick(&self) -> Block {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        let txs = self.mempool.select_for_block(1_000);
        self.engine.propose_block(txs).await.expect("a block")
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

    fn account_nonce(&self, k: &KeyPair) -> u64 {
        self.state.get_nonce(&k.address()).unwrap()
    }

    /// The next block's height.
    fn next_height(&self) -> u64 {
        self.engine.current_height() + 1
    }

    /// Block 1: sponsorship on, the senders and the unrelated user
    /// registered. Block 2: an unrelated transfer. The case starts at block 3.
    async fn set_up(&self) {
        let mut txs = vec![messaging(
            &admin(),
            0,
            1_000,
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        )];
        for k in (0..4).map(sender).chain([unrelated_user()]) {
            txs.push(messaging(
                &k,
                0,
                1_000,
                MessagingOperation::RegisterPublicKey,
                &RegisterPublicKeyData { public_key: pk(&k) },
            ));
        }
        self.submit(&txs.iter().collect::<Vec<_>>());
        let b1 = self.tick().await;
        assert_eq!(b1.height(), 1);
        for t in &txs {
            assert_eq!(
                self.status(t),
                Some(TxStatus::Success),
                "{}",
                self.gates.name
            );
        }
        let filler = transfer(&bystander(), 0, 1_000);
        self.submit(&[&filler]);
        let b2 = self.tick().await;
        assert_eq!(hashes(&b2.transactions), vec![filler.hash()]);
        assert_eq!(self.next_height(), CASE_BLOCK);
    }

    fn receipt(&self, t: &SignedTransaction) -> Option<Receipt> {
        ReceiptStore::new(&self.db).get(&t.hash()).unwrap()
    }

    fn held(&self, t: &SignedTransaction) -> bool {
        self.mempool.contains(&t.hash())
    }
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

fn carries(b: &Block, t: &SignedTransaction) -> bool {
    b.transactions.iter().any(|x| x.hash() == t.hash())
}

/// An unfunded key no genesis account or registration knows.
fn stranger(i: u8) -> KeyPair {
    let mut b = [0xc5u8; 32];
    b[31] = i;
    KeyPair::from_bytes(b)
}

fn transfer_amount(from: &KeyPair, nonce: u64, fee: u128, amount: u128) -> SignedTransaction {
    signed(
        from,
        nonce,
        fee,
        TxPayload::Transfer {
            to: recipient().address(),
            amount,
        },
    )
}

/// The account nonce a relay signs `k`'s next transaction at for the next
/// block (`relay_sponsor_nonce`).
fn relay_nonce(node: &Node, k: &KeyPair) -> u64 {
    let accounting = node.gates.accounting_at(node.next_height());
    let committed = node.account_nonce(k);
    let held: BTreeSet<u64> = node
        .mempool
        .get_by_sender(&k.address())
        .iter()
        .filter(|tx| accounting || advances_nonce_below_accounting_gate(tx))
        .map(|tx| tx.nonce())
        .filter(|n| *n >= committed)
        .collect();
    let mut nonce = committed;
    while held.contains(&nonce) {
        nonce += 1;
    }
    nonce
}

/// How many of this node's selections an envelope waits on another account
/// before it is carried to its refusal.
const BOUND: u64 = CROSS_ACCOUNT_WAIT_SELECTIONS as u64;

/// How many of this node's selections a transaction is held above a gap
/// before it is evicted.
const GAP_BOUND: u64 = GAP_HOLD_SELECTIONS as u64;

/// The block's transaction limit (`max_txs_per_block`, which `tick` selects
/// up to).
const LIMIT: usize = 1_000;

/// Twelve unfunded keys each submit their nonces 1 to 100 (never 0) at a fee
/// far above honest traffic: 1,200 transactions above a gap, more than a
/// block carries. Over five consecutive blocks a fresh honest transfer at a
/// normal fee is submitted before each, and each is carried in its block at
/// every configuration: what waits above a gap is decided before the pool is
/// cut to the block's limit and never takes a place in the block. None of the
/// gapped transactions is carried, and none takes a receipt. They are held
/// for `GAP_BOUND - 1` selections and evicted at the `GAP_BOUND`-th, and the
/// pool is empty after it.
#[tokio::test]
async fn gapped_transactions_never_take_the_block_from_others() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let mut gapped = Vec::new();
        for a in 0..12u8 {
            let k = stranger(a);
            for n in 1..=100u64 {
                let t = transfer_amount(&k, n, 1_000_000_000, 1);
                node.submit(&[&t]);
                gapped.push(t);
            }
        }
        assert!(gapped.len() > LIMIT);
        for round in 0..5 {
            let honest = transfer(&bystander(), relay_nonce(&node, &bystander()), 1_000);
            node.submit(&[&honest]);
            let b = node.tick().await;
            assert!(
                carries(&b, &honest),
                "{name}: block {}, round {round}",
                b.height()
            );
            assert_eq!(node.status(&honest), Some(TxStatus::Success), "{name}");
            assert!(
                gapped.iter().all(|t| !carries(&b, t)),
                "{name}: round {round}"
            );
            let selections = round + 1;
            let held = selections < GAP_BOUND;
            assert!(
                gapped.iter().all(|t| node.held(t) == held),
                "{name}: selection {selections}"
            );
            assert_eq!(
                node.mempool.len(),
                if held { gapped.len() } else { 0 },
                "{name}: selection {selections}"
            );
            if held {
                assert_eq!(
                    node.mempool.gap_hold_count(&gapped[0].hash()),
                    selections as u32,
                    "{name}"
                );
            }
        }
        assert!(gapped.iter().all(|t| node.receipt(t).is_none()), "{name}");
    }
}

/// Sustained load over repeated blocks: before each of `GAP_BOUND + 2`
/// blocks a fresh batch of 1,100 transactions above a gap (eleven new unfunded
/// keys, nonces 1 to 100, at a fee far above honest traffic) is submitted with
/// an honest transfer, so that every selection sees more gapped transactions
/// than a block carries. Every block carries its honest transfer, none of the
/// gapped transactions is carried or takes a receipt, each batch is evicted at
/// its `GAP_BOUND`-th selection, and the pool never holds more than
/// `GAP_BOUND` batches. At every configuration.
#[tokio::test]
async fn sustained_gapped_load_never_takes_the_block_or_keeps_the_pool() {
    const KEYS_PER_BATCH: u8 = 11;
    const PER_KEY: u64 = 100;
    let batch_len = usize::from(KEYS_PER_BATCH) * PER_KEY as usize;
    assert!(batch_len > LIMIT);
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let mut batches: Vec<Vec<SignedTransaction>> = Vec::new();
        for round in 0..(GAP_BOUND + 2) {
            let mut batch = Vec::with_capacity(batch_len);
            for a in 0..KEYS_PER_BATCH {
                let k = stranger(round as u8 * KEYS_PER_BATCH + a);
                for n in 1..=PER_KEY {
                    let t = transfer_amount(&k, n, 1_000_000_000, 1);
                    node.submit(&[&t]);
                    batch.push(t);
                }
            }
            batches.push(batch);
            let honest = transfer(&bystander(), relay_nonce(&node, &bystander()), 1_000);
            node.submit(&[&honest]);
            let b = node.tick().await;
            assert!(carries(&b, &honest), "{name}: round {round}");
            assert_eq!(node.status(&honest), Some(TxStatus::Success), "{name}");
            let mut live = 0;
            for (i, batch) in batches.iter().enumerate() {
                let selections = round - i as u64 + 1;
                let held = selections < GAP_BOUND;
                assert!(
                    batch
                        .iter()
                        .all(|t| !carries(&b, t) && node.held(t) == held),
                    "{name}: round {round}, batch {i}"
                );
                if held {
                    live += batch.len();
                }
            }
            assert_eq!(node.mempool.len(), live, "{name}: round {round}");
            assert!(
                live <= GAP_BOUND as usize * batch_len,
                "{name}: round {round}"
            );
        }
        assert!(
            batches.iter().flatten().all(|t| node.receipt(t).is_none()),
            "{name}"
        );
    }
}

/// A pool scaled down (40 places, 10 per sender) filled with
/// transactions above a gap at a high fee. Admission is unchanged, so an
/// honest transfer at a normal fee is refused while the pool is full, for
/// `GAP_BOUND - 1` selections; at the `GAP_BOUND`-th the gapped transactions
/// are evicted with no receipt, their places are free, and the honest
/// transfer is admitted and carried. At every configuration.
#[tokio::test]
async fn gapped_transactions_do_not_keep_the_pool() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::with_pool(gates, |c| MempoolConfig {
            max_size: 40,
            max_per_sender: 10,
            ..c
        });
        node.set_up().await;
        let mut gapped = Vec::new();
        for a in 0..4u8 {
            let k = stranger(a);
            for n in 1..=10u64 {
                let t = transfer_amount(&k, n, 1_000_000_000, 1);
                node.submit(&[&t]);
                gapped.push(t);
            }
        }
        assert_eq!(node.mempool.len(), 40, "{name}");
        let honest = transfer(&bystander(), relay_nonce(&node, &bystander()), 1_000);
        for n in 1..GAP_BOUND {
            assert!(
                matches!(node.try_submit(&honest), Err(StateError::MempoolFull)),
                "{name}: the pool is full, selection {n}"
            );
            let b = node.tick().await;
            assert!(b.transactions.is_empty(), "{name}");
        }
        assert!(
            matches!(node.try_submit(&honest), Err(StateError::MempoolFull)),
            "{name}: the pool is full"
        );
        let b = node.tick().await;
        assert!(b.transactions.is_empty(), "{name}");
        assert!(
            gapped
                .iter()
                .all(|t| !node.held(t) && node.receipt(t).is_none()),
            "{name}: evicted at the bound, with no receipt"
        );
        assert_eq!(node.mempool.len(), 0, "{name}: the places are free");
        node.try_submit(&honest)
            .unwrap_or_else(|e| panic!("{name}: admitted: {e}"));
        let b = node.tick().await;
        assert!(carries(&b, &honest), "{name}");
        assert_eq!(node.status(&honest), Some(TxStatus::Success), "{name}");
    }
}

/// Below every gate (the gates absent and set above history).
/// `r1`'s transfer at nonce 0 ends with a receipt that does not advance its
/// nonce (it cannot pay the amount); the relay had signed `s`'s envelope 0 at
/// `r1`'s nonce 1 while the transfer was pending, and that envelope reaches
/// the producer after the block: it is above `r1`'s gap, which no relay
/// request fills below the gate. `s`'s envelope 1 goes through `r2`. Both are
/// held for `GAP_BOUND - 1` selections; at the `GAP_BOUND`-th the envelope
/// above the gap is evicted, and with it `s`'s envelope 1, which nothing in
/// the pool can bring into sequence any more; neither takes a receipt and
/// `r1`'s nonce does not move. `s` re-sends its envelope 0 through `r2`, and
/// it is delivered in the next block.
#[tokio::test]
async fn below_the_gates_an_envelope_above_a_gap_is_held_at_most_the_bound() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| ["absent", "above history"].contains(&g.name))
        .collect();
    assert_eq!(configs.len(), 2);
    for gates in configs {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2, s) = (sponsor(0), sponsor(1), sender(0));
        let failing = transfer_amount(&r1, 0, 1_000, FUNDS * 2);
        node.submit(&[&failing]);
        let allocated = relay_nonce(&node, &r1);
        assert_eq!(allocated, 1, "{name}");
        let e_s0 = relayed(&r1, allocated, 2_000, &s, 0);
        node.tick().await;
        let f = node.receipt(&failing).expect("carried");
        assert_ne!(f.status, TxStatus::Success, "{name}");
        assert_eq!(node.account_nonce(&r1), 0, "{name}: the nonce did not move");
        node.submit(&[&e_s0]);
        let r2_s1 = relayed(&r2, relay_nonce(&node, &r2), 2_000, &s, 1);
        node.submit(&[&r2_s1]);
        for n in 1..GAP_BOUND {
            let b = node.tick().await;
            assert!(!carries(&b, &e_s0) && !carries(&b, &r2_s1), "{name}");
            assert!(
                node.held(&e_s0) && node.held(&r2_s1),
                "{name}: selection {n}"
            );
        }
        let b = node.tick().await;
        assert!(!carries(&b, &e_s0) && !carries(&b, &r2_s1), "{name}");
        for t in [&e_s0, &r2_s1] {
            assert!(!node.held(t), "{name}: evicted at the bound");
            assert!(node.receipt(t).is_none(), "{name}: no receipt");
        }
        assert_eq!(node.account_nonce(&r1), 0, "{name}");
        assert_eq!(node.messaging_nonce(&s), 0, "{name}");
        let resent = relayed(&r2, relay_nonce(&node, &r2), 2_000, &s, 0);
        node.submit(&[&resent]);
        let b = node.tick().await;
        assert!(carries(&b, &resent), "{name}");
        assert_eq!(node.status(&resent), Some(TxStatus::Success), "{name}");
        assert_eq!(node.messaging_nonce(&s), 1, "{name}");
    }
}

/// `r1` holds only its nonce 1 (`s`'s envelope 0) and its nonce
/// 0 never comes; `s`'s envelope 1, `u`'s envelope 0 and a transfer go
/// through `r2` at the nonces its relay allocates. From the accounting gate
/// `s`'s envelope 1 holds `r2`'s queue behind `r1`'s gap; within the bound it
/// is carried to its refusal and `r2`'s other two transactions are delivered,
/// and a later user's envelope through `r2` in the block after. Below the gate
/// `r2`'s envelopes advance nothing and its other two are delivered at once.
/// `r1`'s own envelope, above `r1`'s own gap, is evicted at its
/// `GAP_BOUND`-th selection with no receipt. At every configuration.
#[tokio::test]
async fn a_gap_never_holds_another_sponsors_queue_beyond_the_bound() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2) = (sponsor(0), sponsor(1));
        let (s, u, v) = (sender(0), sender(1), sender(2));
        let r1_s0 = relayed(&r1, 1, 2_000, &s, 0);
        node.submit(&[&r1_s0]);
        let r2_s1 = relayed(&r2, relay_nonce(&node, &r2), 2_000, &s, 1);
        node.submit(&[&r2_s1]);
        let r2_u0 = relayed(&r2, relay_nonce(&node, &r2), 2_000, &u, 0);
        node.submit(&[&r2_u0]);
        let r2_t = transfer(&r2, relay_nonce(&node, &r2), 1_000);
        node.submit(&[&r2_t]);
        for _ in 0..BOUND {
            node.tick().await;
        }
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        let r2_v0 = relayed(&r2, relay_nonce(&node, &r2), 2_000, &v, 0);
        node.submit(&[&r2_v0]);
        let b = node.tick().await;
        assert!(carries(&b, &r2_v0), "{name}");
        assert_eq!(node.status(&r2_v0), Some(TxStatus::Success), "{name}");
        // r1's own envelope, above r1's own gap, is evicted with no receipt.
        assert!(BOUND + 1 >= GAP_BOUND);
        assert_eq!(node.status(&r1_s0), None, "{name}");
        assert!(!node.held(&r1_s0), "{name}: evicted, capacity released");
    }
}

/// Where both bounds would meet. A full pool (6 places) evicts `v`'s
/// envelope 0 (through `r1`, the lowest fee) for a gapped transaction at a
/// higher fee; `v`'s envelope 1, relayed by `r2` at its nonce 0 with `r2`'s
/// transfer at nonce 1 behind it, is then beyond `v`'s first missing
/// envelope nonce, held directly and counted toward `GAP_BOUND`. Under the
/// selection oracle its required predecessor is missing (row 3, which takes
/// precedence): it is never counted toward `BOUND`, so the two bounds never
/// meet on it, and at the third selection it is evicted with the gapped
/// transactions, never carried or charged; `r2`'s transfer, above `r2`'s own
/// nonce 0 from then on (row 1), is not carried either. At every
/// configuration where the accounting gate is open at the case's block.
#[tokio::test]
async fn where_both_bounds_meet_the_envelope_is_carried_to_its_refusal() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    assert_eq!(BOUND, GAP_BOUND);
    for gates in configs {
        let name = gates.name;
        let node = Node::with_pool(gates, |c| MempoolConfig { max_size: 6, ..c });
        node.set_up().await;
        let (r1, r2, v) = (sponsor(0), sponsor(1), sender(1));
        let r1_v0 = relayed(&r1, 0, 1_000, &v, 0);
        let r2_v1 = relayed(&r2, 0, 2_200, &v, 1);
        let r2_t = transfer(&r2, 1, 2_100);
        node.submit(&[&r1_v0, &r2_v1, &r2_t]);
        let k = stranger(0);
        let gapped: Vec<SignedTransaction> = (1..=4u64)
            .map(|n| transfer_amount(&k, n, 1_000_000_000, 1))
            .collect();
        node.submit(&gapped[..3].iter().collect::<Vec<_>>());
        assert_eq!(node.mempool.len(), 6, "{name}: the pool is full");
        node.submit(&[&gapped[3]]);
        assert!(!node.held(&r1_v0), "{name}: evicted for a higher fee");
        for n in 1..BOUND {
            let b = node.tick().await;
            assert!(b.transactions.is_empty(), "{name}: selection {n}");
            assert_eq!(
                node.mempool.cross_account_wait_count(&r2_v1.hash()),
                0,
                "{name}: row 3, never counted"
            );
            assert_eq!(
                node.mempool.gap_hold_count(&r2_v1.hash()),
                n as u32,
                "{name}"
            );
        }
        let b = node.tick().await;
        for t in [&r2_v1, &r2_t] {
            assert!(!carries(&b, t), "{name}: never carried");
            assert!(node.receipt(t).is_none(), "{name}: nothing charged");
        }
        assert!(
            !node.held(&r2_v1),
            "{name}: row 3, evicted at the gap bound"
        );
        assert!(node.mempool.evicted_above_a_gap(&r2_v1.hash()), "{name}");
        assert_eq!(node.account_nonce(&r2), 0, "{name}");
        assert!(
            gapped
                .iter()
                .all(|t| !node.held(t) && node.receipt(t).is_none()),
            "{name}: the gapped transactions evicted"
        );
    }
}

/// The four-transaction cycle with fees that put a non-head (`r2`'s nonce 1)
/// lowest. The producer's screen carries each envelope after its sender's
/// earlier ones, so the latest cycle member it hands the order is a head
/// all the same (the head filter itself is pinned on the order alone, by
/// `mempool::tests::the_victim_is_a_head_even_when_a_later_cycle_member_is_not`).
/// The victim is `r2_v1`, the later head; once `r2`'s relay fills its nonce 0
/// the other three are delivered and nothing takes a receipt other than
/// `Success`. At every configuration where the accounting gate is open at the
/// case's block.
#[tokio::test]
async fn the_later_head_is_the_victim_when_a_non_head_pays_least() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    for gates in configs {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2) = (sponsor(0), sponsor(1));
        let (u, v, s) = (sender(0), sender(1), sender(2));
        let r1_u1 = relayed(&r1, 0, 2_400, &u, 1);
        let r2_v1 = relayed(&r2, 0, 2_300, &v, 1);
        let r1_v0 = relayed(&r1, 1, 2_200, &v, 0);
        let r2_u0 = relayed(&r2, 1, 2_100, &u, 0);
        let cycle = [&r1_u1, &r2_v1, &r1_v0, &r2_u0];
        // Admitted in each sender's envelope order; the fee order is the fees'.
        node.submit(&[&r1_v0, &r2_u0, &r1_u1, &r2_v1]);
        let b = node.tick().await;
        assert!(cycle.iter().all(|t| !carries(&b, t)), "{name}");
        let gone: Vec<Hash> = cycle
            .iter()
            .filter(|t| node.status(t).is_none() && !node.held(t))
            .map(|t| t.hash())
            .collect();
        assert_eq!(
            gone,
            vec![r2_v1.hash()],
            "{name}: the later head is the victim"
        );
        let fill = relayed(&r2, relay_nonce(&node, &r2), 1_500, &s, 0);
        assert_eq!(
            fill.nonce(),
            0,
            "{name}: the relay fills the victim's nonce"
        );
        node.submit(&[&fill]);
        let b = node.tick().await;
        for t in [&r1_u1, &r1_v0, &r2_u0, &fill] {
            assert!(carries(&b, t), "{name}");
            assert_eq!(node.status(t), Some(TxStatus::Success), "{name}");
        }
        // u's envelopes 0 and 1, v's envelope 0 and s's envelope 0 delivered;
        // v's envelope 1 was the victim.
        assert_eq!(node.messaging_nonce(&u), 2, "{name}");
        assert_eq!(node.messaging_nonce(&v), 1, "{name}");
        assert_eq!(node.messaging_nonce(&s), 1, "{name}");
    }
}
