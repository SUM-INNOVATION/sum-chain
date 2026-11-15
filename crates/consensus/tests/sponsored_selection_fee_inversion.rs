//! What a block carries is cut account by account and named sender by named
//! sender, never ahead of a predecessor, on a real producer, across the
//! messaging gates.
//!
//! - Fee inversion through an account: eleven unfunded keys each submit their
//!   nonce 0 and, at a fee far above honest traffic, their nonces 1 to 99 —
//!   more than a block carries. The nonce-0 transactions cannot pay. Whether
//!   they are priced at the minimum fee or above honest traffic, an honest
//!   transfer is carried in every block; each nonce 0 is offered once and
//!   leaves with its uncharged `InsufficientBalance` receipt, as on main; no
//!   later nonce is offered into the gap it leaves, and the later nonces leave
//!   the pool at their `GAP_HOLD_SELECTIONS`-th head.
//! - Fee inversion through a named sender, from the accounting gate: each of
//!   eleven senders' envelope 0 goes through an unfunded relay at the minimum
//!   fee; its envelope 1 goes through a second unfunded relay at that relay's
//!   nonce 0, ahead of 99 of that relay's transfers, all far above honest
//!   traffic. An honest transfer is carried in every block, nothing is offered
//!   ahead of its named predecessor, and the submissions leave the pool within
//!   the bounds, each offered transaction with an uncharged
//!   `InsufficientBalance` receipt.
//! - A funded account's run whose first nonce pays the minimum fee and whose
//!   later nonces pay more is carried whole, in nonce order, in one block.
//!
//! Every case runs under the 14 gate configurations of [`matrix`], or says
//! why it runs under fewer.
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
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// Senders registered by `set_up`.
const SENDERS: u8 = 11;
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
    let validators = [validator()];
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
    let mut accounts: Vec<KeyPair> = validators
        .iter()
        .map(|k| KeyPair::from_bytes(*k.private_key().as_bytes()))
        .collect();
    accounts.extend([
        admin(),
        recipient(),
        unrelated_sponsor(),
        unrelated_user(),
        bystander(),
    ]);
    accounts.extend((0..4).map(sponsor));
    accounts.extend((0..SENDERS).map(sender));
    for k in accounts {
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
        Self::build(genesis(gates), gates, Some(validator()), tune)
    }

    fn build(
        g: Genesis,
        gates: Gates,
        key: Option<KeyPair>,
        tune: impl FnOnce(MempoolConfig) -> MempoolConfig,
    ) -> Self {
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
        let engine =
            Arc::new(PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &g, key).unwrap());
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
        for k in (0..SENDERS).map(sender).chain([unrelated_user()]) {
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

/// How many blocks a transaction is held above a gap before it is evicted.
const GAP_BOUND: u64 = GAP_HOLD_SELECTIONS as u64;

/// The block's transaction limit (`max_txs_per_block`, which `tick` selects
/// up to).
const LIMIT: usize = 1_000;

/// A fee far above honest traffic.
const HIGH: u128 = 1_000_000_000;

fn min_fee(gates: Gates) -> u128 {
    genesis(gates).params.min_fee
}

/// Both ways round: eleven unfunded keys, each with its nonce 0 at the
/// minimum fee (then above honest traffic) and its nonces 1 to 99 at a fee
/// far above it, 1,100 transactions in all. Before each block an honest
/// transfer at a normal fee. Every block carries its honest transfer. The
/// first block carries each nonce 0, which takes an uncharged
/// `InsufficientBalance` receipt and leaves; no later nonce is ever carried
/// or takes a receipt; above the gap their predecessor leaves, they are held
/// for `GAP_BOUND - 1` blocks and evicted at the `GAP_BOUND`-th, and the
/// pool is then empty. At every configuration.
#[tokio::test]
async fn an_unfunded_predecessor_never_lets_its_later_nonces_take_the_block() {
    for gates in matrix() {
        for first_fee in [min_fee(gates), HIGH] {
            let name = format!("{}, nonce 0 at fee {first_fee}", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let mut firsts = Vec::new();
            let mut later = Vec::new();
            for a in 0..11u8 {
                let k = stranger(0x40 + a);
                let t = transfer_amount(&k, 0, first_fee, 1);
                node.submit(&[&t]);
                firsts.push(t);
                for n in 1..=99u64 {
                    let t = transfer_amount(&k, n, HIGH, 1);
                    node.submit(&[&t]);
                    later.push(t);
                }
            }
            assert!(firsts.len() + later.len() > LIMIT);
            for round in 0..=GAP_BOUND {
                let honest = transfer(&bystander(), relay_nonce(&node, &bystander()), 1_000);
                node.submit(&[&honest]);
                let b = node.tick().await;
                assert!(carries(&b, &honest), "{name}: round {round}");
                assert_eq!(node.status(&honest), Some(TxStatus::Success), "{name}");
                let carried = firsts.iter().filter(|t| carries(&b, t)).count();
                assert_eq!(
                    carried,
                    if round == 0 { firsts.len() } else { 0 },
                    "{name}: round {round}"
                );
                assert!(
                    later.iter().all(|t| !carries(&b, t)),
                    "{name}: round {round}: nothing offered into a gap"
                );
                let held = round < GAP_BOUND;
                assert!(
                    later
                        .iter()
                        .all(|t| node.held(t) == held && node.receipt(t).is_none()),
                    "{name}: round {round}"
                );
            }
            for t in &firsts {
                let r = node.receipt(t).expect("offered once");
                assert_eq!(r.status, TxStatus::InsufficientBalance, "{name}");
                assert_eq!(r.fee_paid, 0, "{name}: uncharged");
                assert!(!node.held(t), "{name}");
            }
            assert_eq!(node.mempool.len(), 0, "{name}: the pool is empty");
        }
    }
}

/// The same through named senders, from the accounting gate (below it a
/// relayed envelope advances no nonce, so a relay's later nonces never wait
/// on it). For each of eleven senders `s`: `s`'s envelope 0 through an
/// unfunded relay `u` at the minimum fee; `s`'s envelope 1 through a second
/// unfunded relay `r` at `r`'s nonce 0, and `r`'s transfers at nonces 1 to
/// 99, all far above honest traffic: 1,111 transactions. Every block carries
/// its honest transfer. Nothing is carried ahead of its account's or its
/// named sender's predecessor. The first block carries each sender's
/// envelope 0 and then, its turn come, envelope 1 (through another account,
/// so not held back for envelope 0): both take an uncharged
/// `InsufficientBalance` receipt, neither relay being able to pay. No
/// transfer of `r`'s is ever carried or takes a receipt: above the gap its
/// unpayable envelope leaves, they are evicted at the gap bound. Within
/// `BOUND + GAP_BOUND + 1` blocks nothing of the submissions is held.
#[tokio::test]
async fn an_unfunded_envelope_predecessor_never_lets_another_relays_later_nonces_take_the_block() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    for gates in configs {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let mut envelopes = Vec::new();
        let mut runs = Vec::new();
        for k in 0..11u8 {
            let s = sender(k);
            let (u, r) = (stranger(0x60 + k), stranger(0x80 + k));
            let e0 = relayed(&u, 0, min_fee(gates), &s, 0);
            let e1 = relayed(&r, 0, HIGH, &s, 1);
            node.submit(&[&e0, &e1]);
            envelopes.extend([e0, e1]);
            for n in 1..=99u64 {
                let t = transfer_amount(&r, n, HIGH, 1);
                node.submit(&[&t]);
                runs.push(t);
            }
        }
        assert!(envelopes.len() + runs.len() > LIMIT);
        for round in 0..=(BOUND + GAP_BOUND) {
            let honest = transfer(&bystander(), relay_nonce(&node, &bystander()), 1_000);
            node.submit(&[&honest]);
            let b = node.tick().await;
            assert!(carries(&b, &honest), "{name}: round {round}");
            if round == 0 {
                assert!(
                    envelopes.iter().all(|t| carries(&b, t)),
                    "{name}: each sender's envelopes 0 and 1"
                );
            }
            assert_eq!(node.status(&honest), Some(TxStatus::Success), "{name}");
            assert!(
                runs.iter().all(|t| !carries(&b, t)),
                "{name}: round {round}: nothing offered into a gap"
            );
            for t in envelopes.iter().filter(|t| carries(&b, t)) {
                let r = node.receipt(t).expect("carried");
                assert_eq!(
                    r.status,
                    TxStatus::InsufficientBalance,
                    "{name}: round {round}"
                );
                assert_eq!(r.fee_paid, 0, "{name}: uncharged");
            }
        }
        assert!(
            envelopes.iter().chain(runs.iter()).all(|t| !node.held(t)),
            "{name}: the submissions left the pool within the bounds"
        );
        assert!(runs.iter().all(|t| node.receipt(t).is_none()), "{name}");
        for (k, pair) in envelopes.chunks(2).enumerate() {
            assert_eq!(
                node.messaging_nonce(&sender(k as u8)),
                0,
                "{name}: nothing of the sender was delivered"
            );
            for t in pair {
                assert!(node.receipt(t).is_some(), "{name}: offered once");
            }
        }
    }
}

/// A funded account (`unrelated_sponsor`) sends nonce 0 at the minimum fee
/// and nonces 1 to 9 at a fee far above honest traffic. Its run is carried
/// whole, in nonce order, in one block, and every transaction of it
/// succeeds: the cut neither splits a run that can pay nor holds it behind
/// its cheap first nonce. At every configuration.
#[tokio::test]
async fn a_funded_run_with_a_cheap_first_nonce_is_carried_whole() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let k = unrelated_sponsor();
        let run: Vec<SignedTransaction> = (0..10u64)
            .map(|n| transfer(&k, n, if n == 0 { min_fee(gates) } else { HIGH }))
            .collect();
        node.submit(&run.iter().collect::<Vec<_>>());
        let b = node.tick().await;
        let at: Vec<usize> = run
            .iter()
            .map(|t| {
                b.transactions
                    .iter()
                    .position(|x| x.hash() == t.hash())
                    .unwrap_or_else(|| panic!("{name}: carried"))
            })
            .collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{name}: in nonce order");
        assert!(
            run.iter()
                .all(|t| node.status(t) == Some(TxStatus::Success)),
            "{name}"
        );
    }
}

/// An account's run stops at the first transaction it cannot pay for. `w` is
/// funded with 2,500 by a transfer in the case's first block; its nonces 0 to
/// 3 each cost 1,001 (amount 1, fee 1,000). The next block carries its nonces
/// 0 and 1 (they succeed) and its nonce 2, which takes an uncharged
/// `InsufficientBalance` receipt, as on main; its nonce 3 is never offered
/// into the gap that leaves (no `InvalidNonce`), and is evicted with no
/// receipt in the `GAP_BOUND`-th block after. At every configuration.
#[tokio::test]
async fn a_run_stops_at_the_first_transaction_its_account_cannot_pay_for() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let w = stranger(0x21);
        let fund = signed(
            &bystander(),
            relay_nonce(&node, &bystander()),
            1_000,
            TxPayload::Transfer {
                to: w.address(),
                amount: 2_500,
            },
        );
        node.submit(&[&fund]);
        node.tick().await;
        assert_eq!(node.status(&fund), Some(TxStatus::Success), "{name}");
        let run: Vec<SignedTransaction> = (0..4u64).map(|n| transfer(&w, n, 1_000)).collect();
        node.submit(&run.iter().collect::<Vec<_>>());
        let b = node.tick().await;
        for t in &run[..2] {
            assert!(carries(&b, t), "{name}");
            assert_eq!(node.status(t), Some(TxStatus::Success), "{name}");
        }
        assert!(carries(&b, &run[2]), "{name}");
        let r = node.receipt(&run[2]).expect("offered");
        assert_eq!(r.status, TxStatus::InsufficientBalance, "{name}");
        assert_eq!(r.fee_paid, 0, "{name}");
        assert!(!carries(&b, &run[3]), "{name}: not offered into the gap");
        for n in 1..=GAP_BOUND {
            let b = node.tick().await;
            assert!(!carries(&b, &run[3]), "{name}");
            assert_eq!(node.held(&run[3]), n < GAP_BOUND, "{name}: block {n}");
        }
        assert!(node.receipt(&run[3]).is_none(), "{name}");
    }
}

/// A run paid for by a transfer earlier in the same block is carried whole.
/// `bystander` pays `w` 5,000 at a high fee; `w`'s nonces 0 to 2 (1,001 each)
/// are in the pool at a lower fee. One block carries the payment and then all
/// three of `w`'s, and every one succeeds. At every configuration.
#[tokio::test]
async fn a_run_paid_for_earlier_in_the_block_is_carried_whole() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let w = stranger(0x22);
        let fund = signed(
            &bystander(),
            relay_nonce(&node, &bystander()),
            HIGH,
            TxPayload::Transfer {
                to: w.address(),
                amount: 5_000,
            },
        );
        let run: Vec<SignedTransaction> = (0..3u64).map(|n| transfer(&w, n, 1_000)).collect();
        node.submit(&[&fund]);
        node.submit(&run.iter().collect::<Vec<_>>());
        let b = node.tick().await;
        let at = |t: &SignedTransaction| {
            b.transactions
                .iter()
                .position(|x| x.hash() == t.hash())
                .unwrap_or_else(|| panic!("{name}: carried"))
        };
        assert!(run.iter().all(|t| at(&fund) < at(t)), "{name}: paid first");
        assert!(
            std::iter::once(&fund)
                .chain(run.iter())
                .all(|t| node.status(t) == Some(TxStatus::Success)),
            "{name}"
        );
    }
}

/// Bounded progress under repeated resubmission.
/// An unfunded key relays `s`'s envelope 0 at the minimum fee before every
/// block, with a fresh fee each time; before every block the honest relay
/// `r2` also relays `s`'s envelope 1 (a fresh wrapper), `v`'s next envelope
/// and its own transfer. For `ROUNDS` blocks — well past both bounds —
/// every one of `r2`'s transactions is carried in the block of the selection
/// right after its submission (the bound asserted, `PROGRESS` selections):
/// `s`'s envelope 1 takes the outcome its envelope nonce meets (from the
/// verification gate a `Failed` refusal, charged from the accounting gate and
/// uncharged below it), `v`'s envelope and the transfer are delivered, and
/// each resend of `s`'s envelope 0 takes an uncharged `InsufficientBalance`.
/// `r2`'s account nonce moves every block from the accounting gate. Below the
/// verification gate `s`'s envelope 1 executes out of sequence in the first
/// block, as on main, `s`'s nonce moves past envelope 0, and the resend is
/// no longer admitted: the case ends there. At every configuration.
#[tokio::test]
async fn an_unpayable_envelope_resent_before_every_block_never_holds_another_relays_queue() {
    /// Blocks of resubmission: three times the larger bound, and more.
    const ROUNDS: u64 = 3 * if BOUND > GAP_BOUND { BOUND } else { GAP_BOUND } + 3;
    /// Selections from a transaction's submission to the block carrying it.
    const PROGRESS: u64 = 1;
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r2, s, v) = (sponsor(1), sender(0), sender(1));
        let unfunded = stranger(0x5a);
        for round in 0..ROUNDS {
            let h = node.next_height();
            if round > 0 && node.messaging_nonce(&s) != 0 {
                break;
            }
            let e0 = relayed(&unfunded, 0, min_fee(gates) + u128::from(round), &s, 0);
            node.submit(&[&e0]);
            let r2_s1 = relayed(
                &r2,
                relay_nonce(&node, &r2),
                2_000 + u128::from(round),
                &s,
                1,
            );
            node.submit(&[&r2_s1]);
            let r2_v = relayed(
                &r2,
                relay_nonce(&node, &r2),
                2_000,
                &v,
                node.messaging_nonce(&v),
            );
            node.submit(&[&r2_v]);
            let r2_t = transfer(&r2, relay_nonce(&node, &r2), 1_000);
            node.submit(&[&r2_t]);
            let r2_before = node.account_nonce(&r2);
            let mut carried_after = None;
            for n in 1..=PROGRESS {
                let b = node.tick().await;
                if [&r2_s1, &r2_v, &r2_t].iter().all(|t| carries(&b, t)) {
                    assert!(carries(&b, &e0), "{name}: round {round}");
                    carried_after = Some(n);
                    break;
                }
            }
            assert!(
                carried_after.is_some(),
                "{name}: round {round}: r2's transactions within {PROGRESS} selection(s)"
            );
            let r = node.receipt(&e0).expect("offered");
            assert_eq!(
                r.status,
                TxStatus::InsufficientBalance,
                "{name}: round {round}"
            );
            assert_eq!(r.fee_paid, 0, "{name}");
            let r = node.receipt(&r2_s1).expect("offered");
            if gates.verification_at(h) {
                assert!(
                    matches!(r.status, TxStatus::Failed(_)),
                    "{name}: round {round}: {:?}",
                    r.status
                );
                assert_eq!(
                    r.fee_paid > 0,
                    gates.accounting_at(h),
                    "{name}: charged from 0x1049"
                );
            } else {
                assert_eq!(
                    r.status,
                    TxStatus::Success,
                    "{name}: out of sequence, as on main"
                );
            }
            assert_eq!(
                node.status(&r2_v),
                Some(TxStatus::Success),
                "{name}: round {round}"
            );
            assert_eq!(
                node.status(&r2_t),
                Some(TxStatus::Success),
                "{name}: round {round}"
            );
            let advanced = if gates.accounting_at(h) { 3 } else { 1 };
            assert_eq!(
                node.account_nonce(&r2),
                r2_before + advanced,
                "{name}: round {round}"
            );
        }
    }
}
