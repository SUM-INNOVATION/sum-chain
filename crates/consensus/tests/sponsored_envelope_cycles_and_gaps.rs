//! Cycles of account and envelope nonces, and nonce gaps, on a real producer,
//! across the messaging gates.
//!
//! From the messaging fee-and-nonce accounting gate on, a relayed
//! `SendMessage` advances its sponsor's account nonce, so a block keeps two
//! sequences at once: each sponsor's account nonces and each named sender's
//! envelope nonces. When two sponsors relay two senders' envelopes crosswise
//! the sequences wait on each other in a cycle, and the producer leaves one
//! transaction of the cycle out as its victim (evicted) and holds what depends
//! on it. These tests pin, on a real producer (`select_for_block` →
//! `propose_block`):
//!
//! - the victim is a transaction on the cycle, never one that only waits on
//!   it;
//! - nothing above a gap in an account's nonces is offered (the gap a victim
//!   leaves, or any other): it waits in the pool, with what depends on it,
//!   and is carried once the gap is filled, so nothing takes `InvalidNonce`
//!   or a refusal for an envelope out of its sender's sequence;
//! - an unrelated sponsor and its user are carried throughout.
//!
//! Every case runs under each gate configuration of [`matrix`]: the gates
//! absent, set above the chain's history, set inside it, and with each gate
//! at the case's block, one below it and one above it. Below the accounting
//! gate the same submissions are judged by that rule (a relayed envelope
//! advances no nonce there), and the assertions that hold everywhere are
//! asserted everywhere: no transaction of a case ever takes a receipt other
//! than `Success`, at most one is evicted and it is the cycle's victim, and
//! every other one is delivered once its sponsor's nonce is filled.
use std::collections::{HashMap, HashSet};
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
    sponsored_send_v2_signing_preimage, Block, Hash, MessagingOperation, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::mempool::{InclusionGates, InclusionPolicy};
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
        let g = genesis(gates);
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let chain_height = Arc::new(AtomicU64::new(0));
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                min_fee: g.params.min_fee,
                max_tx_bytes: g.params.max_block_bytes,
                ..MempoolConfig::default()
            })
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
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

/// The unrelated sponsor's transfer at its nonce 0 and its user's envelope 0
/// at its nonce 1: valid at every gate configuration (below the accounting
/// gate the transfer takes the sponsor to nonce 1, where the envelope
/// executes without advancing it).
fn unrelated_pair() -> [SignedTransaction; 2] {
    [
        transfer(&unrelated_sponsor(), 0, 2_000),
        relayed(&unrelated_sponsor(), 1, 2_000, &unrelated_user(), 0),
    ]
}

/// What happened to the transactions of one case, block by block.
struct Watch<'a> {
    node: &'a Node,
    /// The case's transactions, by name.
    case: Vec<(&'static str, SignedTransaction)>,
    /// The block in which each evicted transaction left the pool.
    evicted: Vec<(&'static str, u64)>,
}

impl<'a> Watch<'a> {
    fn new(node: &'a Node, case: Vec<(&'static str, SignedTransaction)>) -> Self {
        Self {
            node,
            case,
            evicted: Vec::new(),
        }
    }

    fn add(&mut self, name: &'static str, tx: SignedTransaction) {
        self.case.push((name, tx));
    }

    fn tx(&self, name: &str) -> &SignedTransaction {
        &self.case.iter().find(|(n, _)| *n == name).unwrap().1
    }

    /// One tick, then the invariants every configuration keeps: no
    /// transaction of the case has a receipt other than `Success` (nothing
    /// was offered into a gap or out of its sender's sequence, and nothing
    /// was charged for a refusal), and each is held, delivered or evicted
    /// without a receipt, which is recorded. Returns the names carried.
    async fn tick(&mut self) -> (u64, Vec<&'static str>) {
        let node = self.node;
        let block = node.tick().await;
        let height = block.height();
        let carried: HashSet<Hash> = block.transactions.iter().map(|t| t.hash()).collect();
        let mut names = Vec::new();
        for (name, tx) in &self.case {
            let status = node.status(tx);
            assert!(
                matches!(status, None | Some(TxStatus::Success)),
                "{}: block {height}: {name} took {status:?}",
                node.gates.name
            );
            if carried.contains(&tx.hash()) {
                names.push(*name);
            }
            if status.is_none()
                && !node.mempool.contains(&tx.hash())
                && !self.evicted.iter().any(|(n, _)| n == name)
            {
                self.evicted.push((name, height));
            }
        }
        (height, names)
    }

    fn held(&self, name: &str) -> bool {
        self.node.mempool.contains(&self.tx(name).hash())
    }

    fn delivered(&self, name: &str) -> bool {
        self.node.status(self.tx(name)) == Some(TxStatus::Success)
    }
}

/// The four-transaction cycle, with fees that fix the victim: the
/// latest of the cycle's sponsor heads in the fee order is `r2_v1`.
///
/// - `r1_u1`: `r1`'s nonce 0, `u`'s envelope 1 (waits on `u`'s envelope 0);
/// - `r1_v0`: `r1`'s nonce 1, `v`'s envelope 0;
/// - `r2_v1`: `r2`'s nonce 0, `v`'s envelope 1 (waits on `v`'s envelope 0);
/// - `r2_u0`: `r2`'s nonce 1, `u`'s envelope 0.
fn two_sponsor_cycle() -> Vec<(&'static str, SignedTransaction)> {
    let (r1, r2, u, v) = (sponsor(0), sponsor(1), sender(0), sender(1));
    vec![
        ("r2_u0", relayed(&r2, 1, 2_400, &u, 0)),
        ("r1_v0", relayed(&r1, 1, 2_300, &v, 0)),
        ("r1_u1", relayed(&r1, 0, 2_200, &u, 1)),
        ("r2_v1", relayed(&r2, 0, 2_100, &v, 1)),
    ]
}

/// Submits, for each of `sponsors` whose nonce 0 nothing pending advances at
/// the next block's rule, a transfer at its nonce 0: from the accounting gate
/// a relayed envelope advances its sponsor's nonce, below it only the transfer
/// does. Returns the transfers, named `fill_<i>`.
fn fill_nonce_zero(
    watch: &mut Watch<'_>,
    sponsors: &[(u8, Option<&'static str>)],
) -> Vec<&'static str> {
    const NAMES: [&str; 4] = ["fill_0", "fill_1", "fill_2", "fill_3"];
    let node = watch.node;
    let accounting = node.gates.accounting_at(node.next_height());
    let mut names = Vec::new();
    for &(i, head) in sponsors {
        let head_pending = head.is_some_and(|h| watch.held(h));
        if accounting && head_pending {
            continue;
        }
        assert_eq!(node.account_nonce(&sponsor(i)), 0);
        let fill = transfer(&sponsor(i), 0, 1_000);
        node.submit(&[&fill]);
        watch.add(NAMES[i as usize], fill);
        names.push(NAMES[i as usize]);
    }
    names
}

/// The cycle and the block after it. Where the accounting gate is open at the
/// block, the cycle's victim (`r2_v1`) is evicted and the three that depend
/// on it are held; the next block offers none of them (none takes
/// `InvalidNonce` or a refusal: `r2`'s nonce 0 is the gap); once `r2` fills
/// its nonce 0 within the bound they are delivered, in order (the bound on a
/// wait for another account, `CROSS_ACCOUNT_WAIT_SELECTIONS`, counts from the
/// victim's block, so the gap is filled in the block after the next one).
/// Below the gate the same
/// submissions leave both sponsors' nonce-1 envelopes beyond a gap (a relayed
/// envelope advances nothing there), so all four are held, and nothing is
/// evicted until both sponsors fill their nonce 0, when the cycle forms at the
/// shared nonce and loses the same victim. Everywhere: the unrelated pair is
/// carried in the case's first block, the only transaction evicted is
/// `r2_v1`, and every other one is delivered.
#[tokio::test]
async fn the_block_after_a_cycle_offers_nothing_into_the_victims_gap() {
    for gates in matrix() {
        let node = Node::new(gates);
        node.set_up().await;
        let unrelated = unrelated_pair();
        let mut case = two_sponsor_cycle();
        case.push(("unrelated_transfer", unrelated[0].clone()));
        case.push(("unrelated_envelope", unrelated[1].clone()));
        let mut watch = Watch::new(&node, case);
        let all: Vec<SignedTransaction> = watch.case.iter().map(|(_, t)| t.clone()).collect();
        node.submit(&all.iter().collect::<Vec<_>>());

        let (h, carried) = watch.tick().await;
        assert_eq!(h, CASE_BLOCK);
        assert_eq!(
            carried,
            vec!["unrelated_transfer", "unrelated_envelope"],
            "{}",
            gates.name
        );
        assert!(watch.delivered("unrelated_envelope"), "{}", gates.name);
        // One more block with nothing new to offer, inside the bound.
        for _ in 0..1 {
            let (h, carried) = watch.tick().await;
            assert!(carried.is_empty(), "{}: block {h}: {carried:?}", gates.name);
        }
        let cycle = ["r2_u0", "r1_v0", "r1_u1", "r2_v1"];
        match watch.evicted.as_slice() {
            [] => {
                // Below the accounting gate throughout: all four held.
                assert!(!gates.accounting_at(CASE_BLOCK + 1), "{}", gates.name);
                for name in cycle {
                    assert!(watch.held(name), "{}: {name}", gates.name);
                }
            }
            [("r2_v1", at)] => {
                // The cycle formed at the first block at the gate, and the
                // blocks after it offered nothing of the three left.
                let first_open = (CASE_BLOCK..).find(|h| gates.accounting_at(*h)).unwrap();
                assert_eq!(*at, first_open, "{}", gates.name);
                for name in ["r2_u0", "r1_v0", "r1_u1"] {
                    assert!(watch.held(name), "{}: {name}", gates.name);
                }
                assert_eq!(node.account_nonce(&sponsor(0)), 0, "{}", gates.name);
                assert_eq!(node.account_nonce(&sponsor(1)), 0, "{}", gates.name);
            }
            other => panic!("{}: evicted {other:?}", gates.name),
        }
        assert_eq!(node.messaging_nonce(&sender(0)), 0, "{}", gates.name);
        assert_eq!(node.messaging_nonce(&sender(1)), 0, "{}", gates.name);

        // The gap is filled: `r2`'s nonce 0 (and below the gate `r1`'s too).
        let fills = fill_nonce_zero(&mut watch, &[(0, Some("r1_u1")), (1, None)]);
        assert!(!fills.is_empty());
        let (h, carried) = watch.tick().await;
        let mut expected: Vec<&str> = fills.clone();
        expected.extend(["r2_u0", "r1_u1", "r1_v0"]);
        let mut got = carried.clone();
        got.sort_unstable();
        expected.sort_unstable();
        assert_eq!(got, expected, "{}: block {h}", gates.name);
        assert_eq!(watch.evicted.len(), 1, "{}", gates.name);
        assert_eq!(watch.evicted[0].0, "r2_v1", "{}", gates.name);
        for name in ["r2_u0", "r1_u1", "r1_v0"].into_iter().chain(fills) {
            assert!(watch.delivered(name), "{}: {name}", gates.name);
        }
        // `u`'s envelopes 0 and 1 and `v`'s envelope 0 delivered; `v`'s
        // envelope 1 was the victim, for its client to send again.
        assert_eq!(node.messaging_nonce(&sender(0)), 2, "{}", gates.name);
        assert_eq!(node.messaging_nonce(&sender(1)), 1, "{}", gates.name);
        assert!(node.mempool.is_empty(), "{}", gates.name);
    }
}

/// `w` (a third sponsor) relays `u`'s envelope 2 at the lowest
/// fee: it waits on the cycle (through `u`'s envelope 1) but is not on it,
/// and is never the victim. Where the cycle forms, `r2_v1` is evicted and
/// `w`'s envelope is held with the others; once the gap is filled, within the
/// bound, it is delivered after `u`'s envelope 1.
#[tokio::test]
async fn a_transaction_that_only_waits_on_a_cycle_is_never_evicted() {
    for gates in matrix() {
        let node = Node::new(gates);
        node.set_up().await;
        let w = sponsor(2);
        let mut watch = Watch::new(&node, two_sponsor_cycle());
        watch.add("w_u2", relayed(&w, 0, 1_000, &sender(0), 2));
        let all: Vec<SignedTransaction> = watch.case.iter().map(|(_, t)| t.clone()).collect();
        node.submit(&all.iter().collect::<Vec<_>>());
        for _ in 0..2 {
            let (h, carried) = watch.tick().await;
            assert!(carried.is_empty(), "{}: block {h}: {carried:?}", gates.name);
        }
        assert!(watch.held("w_u2"), "{}", gates.name);
        assert!(
            watch.evicted.iter().all(|(name, _)| *name == "r2_v1"),
            "{}: {:?}",
            gates.name,
            watch.evicted
        );
        assert_eq!(
            watch.evicted.len(),
            usize::from(gates.accounting_at(CASE_BLOCK + 1)),
            "{}",
            gates.name
        );

        let fills = fill_nonce_zero(&mut watch, &[(0, Some("r1_u1")), (1, None)]);
        let (h, carried) = watch.tick().await;
        let mut expected: Vec<&str> = fills;
        expected.extend(["r2_u0", "r1_u1", "r1_v0", "w_u2"]);
        let mut got = carried;
        got.sort_unstable();
        expected.sort_unstable();
        assert_eq!(got, expected, "{}: block {h}", gates.name);
        assert_eq!(watch.evicted.len(), 1, "{}", gates.name);
        assert_eq!(watch.evicted[0].0, "r2_v1", "{}", gates.name);
        assert!(watch.delivered("w_u2"), "{}", gates.name);
        assert_eq!(node.messaging_nonce(&sender(0)), 3, "{}", gates.name);
        assert_eq!(node.messaging_nonce(&sender(1)), 1, "{}", gates.name);
        assert!(node.mempool.is_empty(), "{}", gates.name);
    }
}

/// Genuine cycles through one, two, three and four sponsors (two, four, six
/// and eight transactions; a cycle alternates a sponsor's head and a
/// transaction behind one, so no cycle has an odd length): sponsor `k`
/// relays sender `k`'s envelope 1 at its nonce 0 and sender `k + 1`'s
/// envelope 0 at its nonce 1. The heads' fees fall with `k`, so the victim
/// is the last sponsor's nonce 0. Everywhere: the unrelated pair is carried
/// in the case's first block; exactly one transaction is ever evicted, that
/// victim; nothing is offered into its gap; once the nonce-0 slots are
/// filled, within the bound, every other transaction is delivered.
#[tokio::test]
async fn each_genuine_cycle_loses_only_its_victim() {
    const NAMES: [[&str; 2]; 4] = [
        ["s0_head", "s0_next"],
        ["s1_head", "s1_next"],
        ["s2_head", "s2_next"],
        ["s3_head", "s3_next"],
    ];
    for n in 1..=4u8 {
        for gates in matrix() {
            let node = Node::new(gates);
            node.set_up().await;
            let mut case = Vec::new();
            for k in 0..n {
                let next = (k + 1) % n;
                case.push((
                    NAMES[k as usize][1],
                    relayed(&sponsor(k), 1, 3_000 + u128::from(k), &sender(next), 0),
                ));
            }
            let unrelated = unrelated_pair();
            case.push(("unrelated_transfer", unrelated[0].clone()));
            case.push(("unrelated_envelope", unrelated[1].clone()));
            for k in 0..n {
                case.push((
                    NAMES[k as usize][0],
                    relayed(&sponsor(k), 0, 1_500 - u128::from(k) * 10, &sender(k), 1),
                ));
            }
            let mut watch = Watch::new(&node, case);
            let all: Vec<SignedTransaction> = watch.case.iter().map(|(_, t)| t.clone()).collect();
            node.submit(&all.iter().collect::<Vec<_>>());
            let label = format!("{} sponsor(s), {}", n, gates.name);

            let (_, carried) = watch.tick().await;
            assert_eq!(
                carried,
                vec!["unrelated_transfer", "unrelated_envelope"],
                "{label}"
            );
            for _ in 0..1 {
                let (h, carried) = watch.tick().await;
                assert!(carried.is_empty(), "{label}: block {h}: {carried:?}");
            }
            let victim = NAMES[(n - 1) as usize][0];
            assert!(
                watch.evicted.iter().all(|(name, _)| *name == victim),
                "{label}: {:?}",
                watch.evicted
            );

            let heads: Vec<(u8, Option<&'static str>)> =
                (0..n).map(|k| (k, Some(NAMES[k as usize][0]))).collect();
            let fills = fill_nonce_zero(&mut watch, &heads);
            let mut rounds = 0;
            while !node.mempool.is_empty() && rounds < 3 {
                watch.tick().await;
                rounds += 1;
            }
            assert!(node.mempool.is_empty(), "{label}");
            assert_eq!(watch.evicted.len(), 1, "{label}: {:?}", watch.evicted);
            assert_eq!(watch.evicted[0].0, victim, "{label}");
            for (name, _) in &watch.case {
                if *name != victim {
                    assert!(watch.delivered(name), "{label}: {name}");
                }
            }
            for name in fills {
                assert!(watch.delivered(name), "{label}: {name}");
            }
        }
    }
}

/// A gap that is not a victim's: `r1` holds only its nonce 1 (`v`'s envelope
/// 0), and `v`'s envelope 1 and then `u`'s envelope 0 go through `r2`. Nothing
/// of the three is offered (none takes `InvalidNonce` or a refusal), nothing
/// is evicted, and an unrelated sponsor, its user and a bystander's transfer
/// are carried. Once `r1` fills its nonce 0 within the bound (and below the
/// accounting gate `r2` its own, which a relayed envelope does not advance
/// there) the three are delivered. (Left unfilled, `r2`'s envelope is
/// carried to its refusal at the bound and `r2`'s queue moves: see
/// `sponsored_selection_holds_are_bounded.rs`.)
#[tokio::test]
async fn nothing_above_a_nonce_gap_is_offered_and_the_rest_is_carried() {
    for gates in matrix() {
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2, u, v) = (sponsor(0), sponsor(1), sender(0), sender(1));
        let unrelated = unrelated_pair();
        let mut watch = Watch::new(
            &node,
            vec![
                ("r1_v0", relayed(&r1, 1, 2_300, &v, 0)),
                ("r2_v1", relayed(&r2, 0, 2_200, &v, 1)),
                ("r2_u0", relayed(&r2, 1, 2_100, &u, 0)),
                ("unrelated_transfer", unrelated[0].clone()),
                ("unrelated_envelope", unrelated[1].clone()),
                ("bystander", transfer(&bystander(), 1, 1_000)),
            ],
        );
        let all: Vec<SignedTransaction> = watch.case.iter().map(|(_, t)| t.clone()).collect();
        node.submit(&all.iter().collect::<Vec<_>>());

        let (_, carried) = watch.tick().await;
        let mut carried = carried;
        carried.sort_unstable();
        assert_eq!(
            carried,
            vec!["bystander", "unrelated_envelope", "unrelated_transfer"],
            "{}",
            gates.name
        );
        for _ in 0..1 {
            let (h, carried) = watch.tick().await;
            assert!(carried.is_empty(), "{}: block {h}: {carried:?}", gates.name);
        }
        assert!(
            watch.evicted.is_empty(),
            "{}: {:?}",
            gates.name,
            watch.evicted
        );
        for name in ["r1_v0", "r2_v1", "r2_u0"] {
            assert!(watch.held(name), "{}: {name}", gates.name);
        }

        let fills = fill_nonce_zero(&mut watch, &[(0, None), (1, Some("r2_v1"))]);
        let (h, carried) = watch.tick().await;
        let mut expected: Vec<&str> = fills;
        expected.extend(["r1_v0", "r2_v1", "r2_u0"]);
        let mut got = carried;
        got.sort_unstable();
        expected.sort_unstable();
        assert_eq!(got, expected, "{}: block {h}", gates.name);
        assert!(watch.evicted.is_empty(), "{}", gates.name);
        assert_eq!(node.messaging_nonce(&u), 1, "{}", gates.name);
        assert_eq!(node.messaging_nonce(&v), 2, "{}", gates.name);
        assert!(node.mempool.is_empty(), "{}", gates.name);
    }
}
