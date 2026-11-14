//! What selection holds back never takes the block from anyone else, on a
//! real producer, across the messaging gates.
//!
//! - A transaction above a gap in its account's nonces, or an envelope beyond
//!   its sender's first missing envelope nonce, and whatever depends on them,
//!   is decided before the pool is cut to a block's size: with more such
//!   transactions than a block carries, at a higher fee, honest transactions
//!   are carried in every block.
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
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
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

/// The block's transaction limit (`max_txs_per_block`, which `tick` selects
/// up to).
const LIMIT: usize = 1_000;

/// Twelve unfunded keys each submit their nonces 1 to 100 (never 0) at a fee
/// far above honest traffic: 1,200 transactions above a gap, more than a
/// block carries. Over five consecutive blocks a fresh honest transfer at a
/// normal fee is submitted before each, and each is carried in its block at
/// every configuration: what waits above a gap is decided before the pool is
/// cut to the block's limit and never takes a place in the block. None of the
/// gapped transactions is carried, and none takes a receipt.
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
        }
        assert!(gapped.iter().all(|t| node.receipt(t).is_none()), "{name}");
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
