//! One sponsor's refused transaction never holds another sponsor's queue, on
//! a real producer, across the messaging gates.
//!
//! When the producer drops a transaction from a candidate block (a refusal it
//! acts on), the later transactions of the same account leave with it, and
//! below the messaging fee-and-nonce accounting gate so do the later envelopes
//! naming the same sender as a dropped envelope (main's rule). From the gate
//! a dropped envelope also takes its own sponsor's later transactions. Nothing
//! leaves because it follows a transaction that itself only left with a run,
//! and from the gate an envelope relayed by another account is carried, to the
//! outcome its envelope nonce meets in the block, so that account's queue
//! keeps moving.
//!
//! - `r1` relays `x`'s envelope (the
//!   recipient blocks `x`, so the executor refuses it with an error and the
//!   producer holds it) and then `s`'s envelope 0; `r2` relays `s`'s
//!   envelope 1, `u`'s envelope 0 and its own transfer. `r2`'s queue is
//!   carried in the case's first block and a later user's envelope through
//!   `r2` in the next, at every gate configuration.
//! - `r1`'s own direct message is refused (the recipient blocks
//!   `r1`), `r1` relays `s`'s envelope 0 behind it, `r2` relays `s`'s
//!   envelope 1. Below the gates the producer builds main's block; at and
//!   above them `r2`'s envelope is carried and `r2`'s queue moves.
//!
//! Every case runs under the 14 gate configurations of [`matrix`] (the gates
//! absent, set above the chain's history, set inside it, and each gate and
//! both at the case's block, one below and one above), with the submissions a
//! relay would sign at the case's block: [`relay_nonce`].
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageData, SetSponsorshipEnabledData, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, MessagingOperation, Receipt, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload, TxStatus,
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
/// The block each case turns on: block 1 sets the chain up, block 2 has the
/// recipient block a sender, and the case's transactions are offered from
/// block 3 on.
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
/// A recipient that blocks nobody.
fn other_recipient() -> KeyPair {
    key(0x84)
}
/// Sponsors, `0x90..`; the senders they relay for, `0xa0..`.
fn sponsor(i: u8) -> KeyPair {
    key(0x90 + i)
}
fn sender(i: u8) -> KeyPair {
    key(0xa0 + i)
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
    let mut accounts = vec![validator(), admin(), recipient(), bystander()];
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
    relayed_to(sponsor, nonce, fee, user, envelope_nonce, &recipient())
}

/// [`relayed`], to `to`.
fn relayed_to(
    sponsor: &KeyPair,
    nonce: u64,
    fee: u128,
    user: &KeyPair,
    envelope_nonce: u64,
    to: &KeyPair,
) -> SignedTransaction {
    let rh = recipient_hash(&to.address());
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

    /// Block 1: sponsorship on, the senders registered. Block 2: `blocks`
    /// is blocked by the recipient. The case starts at block 3.
    async fn set_up(&self, blocks: &KeyPair) {
        let mut txs = vec![messaging(
            &admin(),
            0,
            1_000,
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        )];
        for k in (0..4).map(sender) {
            txs.push(messaging(
                &k,
                0,
                1_000,
                MessagingOperation::RegisterPublicKey,
                &RegisterPublicKeyData { public_key: pk(&k) },
            ));
        }
        self.submit(&txs.iter().collect::<Vec<_>>());
        assert_eq!(self.tick().await.height(), 1);
        for t in &txs {
            assert_eq!(
                self.status(t),
                Some(TxStatus::Success),
                "{}",
                self.gates.name
            );
        }
        let block = messaging(
            &recipient(),
            self.account_nonce(&recipient()),
            1_000,
            MessagingOperation::BlockSender,
            &BlockSenderData {
                sender: blocks.address(),
            },
        );
        self.submit(&[&block]);
        assert_eq!(self.tick().await.height(), 2);
        assert_eq!(
            self.status(&block),
            Some(TxStatus::Success),
            "{}",
            self.gates.name
        );
        assert_eq!(self.next_height(), CASE_BLOCK);
    }

    fn receipt(&self, t: &SignedTransaction) -> Option<Receipt> {
        ReceiptStore::new(&self.db).get(&t.hash()).unwrap()
    }

    fn held(&self, t: &SignedTransaction) -> bool {
        self.mempool.contains(&t.hash())
    }

    /// Admits `tx(nonce)` at the account nonce a relay signs at for the next
    /// block ([`relay_nonce`]) and returns it.
    fn relay(&self, k: &KeyPair, tx: impl FnOnce(u64) -> SignedTransaction) -> SignedTransaction {
        let t = tx(relay_nonce(self, k));
        self.submit(&[&t]);
        t
    }
}

/// The account nonce a relay signs `k`'s next transaction at for the next
/// block, as `relay_sponsor_nonce` allocates it: the first nonce at or above
/// the committed one that no pending transaction of `k` takes, a pending
/// transaction taking its nonce when it advances the nonce at the next
/// block's rule (below the accounting gate a relayed envelope does not).
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

fn direct(from: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    let rh = recipient_hash(&recipient().address());
    messaging(
        from,
        nonce,
        fee,
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

/// At every configuration: `x`'s envelope is held (refused with an
/// error, never in a block); `r2`'s envelope for `u` and `r2`'s transfer are
/// delivered in the case's first block, and a later user's envelope through
/// `r2` in the next. `s`'s envelope 1 through `r2` is carried in the first
/// block too, to the outcome its envelope nonce meets: below the accounting
/// gate `r1`'s envelope for `s` leaves nothing behind (main's rule) and both
/// of `s`'s envelopes are delivered in sequence; from the gate `s`'s envelope
/// 0 waits behind `x`'s with `r1`'s queue, and `s`'s envelope 1 takes a
/// charged refusal (from `0x1048`) or, below `0x1048`, executes out of
/// sequence and `s`'s envelope 0 is then evicted as stale.
#[tokio::test]
async fn one_sponsors_refused_envelope_never_holds_another_sponsors_queue() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        let (r1, r2, s, u, v, x) = (
            sponsor(0),
            sponsor(1),
            sender(0),
            sender(1),
            sender(2),
            sender(3),
        );
        node.set_up(&x).await;
        let accounting = gates.accounting_at(CASE_BLOCK);
        let verification = gates.verification_at(CASE_BLOCK);

        let r1_x0 = node.relay(&r1, |n| relayed(&r1, n, 3_000, &x, 0));
        let r1_s0 = node.relay(&r1, |n| relayed(&r1, n, 2_000, &s, 0));
        let r2_s1 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &s, 1));
        let r2_u0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &u, 0));
        let r2_t = node.relay(&r2, |n| transfer(&r2, n, 1_000));
        let r2_before = node.account_nonce(&r2);

        let b3 = node.tick().await;
        assert_eq!(b3.height(), CASE_BLOCK);
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        assert!(!carried.contains(&r1_x0.hash()), "{name}");
        for t in [&r2_s1, &r2_u0, &r2_t] {
            assert!(carried.contains(&t.hash()), "{name}: {} carried", t.hash());
        }
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        let s1 = node.receipt(&r2_s1).expect("r2_s1 has a receipt");
        if accounting && verification {
            assert!(
                matches!(s1.status, TxStatus::Failed(_)),
                "{name}: {:?}",
                s1.status
            );
            assert!(s1.fee_paid > 0, "{name}: charged");
            assert_eq!(node.status(&r1_s0), None, "{name}");
            assert!(node.held(&r1_s0), "{name}: with r1's queue");
        } else {
            assert_eq!(s1.status, TxStatus::Success, "{name}");
        }
        if !accounting {
            assert_eq!(node.status(&r1_s0), Some(TxStatus::Success), "{name}");
        }
        // r2's queue moved: every transaction it carried advanced its nonce
        // from the accounting gate on; below it only the transfer does.
        let advanced = if accounting { 3 } else { 1 };
        assert_eq!(node.account_nonce(&r2), r2_before + advanced, "{name}");

        // A later user's envelope through r2 is delivered in the next block.
        let r2_v0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &v, 0));
        let b4 = node.tick().await;
        assert!(
            b4.transactions.iter().any(|t| t.hash() == r2_v0.hash()),
            "{name}"
        );
        assert_eq!(node.status(&r2_v0), Some(TxStatus::Success), "{name}");

        // x's envelope stays held (its refusal is an error, never a receipt).
        assert_eq!(node.status(&r1_x0), None, "{name}");
        assert!(node.held(&r1_x0), "{name}");
        let s_nonce = node.messaging_nonce(&s);
        match (accounting, verification) {
            (false, _) => assert_eq!(s_nonce, 2, "{name}"),
            (true, true) => {
                assert_eq!(s_nonce, 0, "{name}");
                assert!(node.held(&r1_s0), "{name}");
            }
            (true, false) => {
                assert_eq!(s_nonce, 1, "{name}");
                assert_eq!(node.status(&r1_s0), None, "{name}");
                assert!(!node.held(&r1_s0), "{name}: stale, evicted");
            }
        }
    }
}

/// `r1`'s own direct message is refused (the recipient blocks
/// `r1`) and held; `r1`'s envelope for `s` behind it leaves with `r1`'s run.
/// At every configuration `r2`'s envelope for `s` is carried in the case's
/// first block with an unrelated transfer, and `r2`'s next transaction in the
/// next block. Below `0x1048` `s`'s envelope 1 executes out of sequence and
/// `s`'s envelope 0 is then evicted as stale (main's behaviour below the
/// gates); from `0x1048` it is refused (charged from the accounting gate) and
/// `s`'s envelope 0 waits with `r1`'s queue.
#[tokio::test]
async fn a_refused_direct_message_holds_nothing_of_another_sponsor() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        let (r1, r2, s) = (sponsor(0), sponsor(1), sender(0));
        node.set_up(&r1).await;
        let accounting = gates.accounting_at(CASE_BLOCK);
        let verification = gates.verification_at(CASE_BLOCK);

        let d0 = node.relay(&r1, |n| direct(&r1, n, 5_000));
        let e_s0 = node.relay(&r1, |n| relayed(&r1, n, 2_000, &s, 0));
        let e_s1 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &s, 1));
        let wt = node.relay(&bystander(), |n| transfer(&bystander(), n, 1_000));
        assert_eq!(d0.nonce(), 0);
        assert_eq!(e_s0.nonce(), 1, "{name}: signed behind r1's direct message");

        let b3 = node.tick().await;
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        assert_eq!(carried.len(), 2, "{name}: {carried:?}");
        assert!(carried.contains(&e_s1.hash()), "{name}");
        assert!(carried.contains(&wt.hash()), "{name}");
        assert_eq!(node.status(&wt), Some(TxStatus::Success), "{name}");
        let s1 = node.receipt(&e_s1).expect("e_s1 has a receipt");
        if verification {
            assert!(
                matches!(s1.status, TxStatus::Failed(_)),
                "{name}: {:?}",
                s1.status
            );
            assert_eq!(s1.fee_paid > 0, accounting, "{name}: charged from 0x1049");
        } else {
            assert_eq!(s1.status, TxStatus::Success, "{name}");
        }

        let r2_next = node.relay(&r2, |n| transfer(&r2, n, 1_000));
        let b4 = node.tick().await;
        assert!(
            b4.transactions.iter().any(|t| t.hash() == r2_next.hash()),
            "{name}"
        );
        assert_eq!(node.status(&r2_next), Some(TxStatus::Success), "{name}");

        assert_eq!(node.status(&d0), None, "{name}");
        assert!(node.held(&d0), "{name}");
        assert_eq!(node.status(&e_s0), None, "{name}");
        if verification {
            assert!(node.held(&e_s0), "{name}: waits with r1's queue");
            assert_eq!(node.messaging_nonce(&s), 0, "{name}");
        } else {
            assert!(!node.held(&e_s0), "{name}: stale, evicted, as on main");
            assert_eq!(node.messaging_nonce(&s), 1, "{name}");
        }
    }
}

/// A refused sender's later envelope through another sponsor: `s`'s envelope 0 through `r1` is refused (the
/// recipient blocks `s`) and held, and `s`'s envelope 1, to a recipient that
/// blocks nobody, goes through `r2`, followed by `r2`'s envelope for `u` and
/// its transfer. Below the accounting gate `s`'s envelope 1 waits with `s`'s
/// envelope 0 (main's rule; it holds nothing of `r2` there). From the gate it
/// is carried: refused and charged from `0x1048`, or below it executed out
/// of sequence, `s`'s envelope 0 then evicted as stale. At every
/// configuration `r2`'s other two are delivered in the case's first block and
/// a later user's envelope through `r2` in the next.
#[tokio::test]
async fn a_refused_senders_later_envelope_through_another_sponsor_never_holds_that_sponsor() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        let (r1, r2, s, u, v) = (sponsor(0), sponsor(1), sender(0), sender(1), sender(2));
        node.set_up(&s).await;
        let accounting = gates.accounting_at(CASE_BLOCK);
        let verification = gates.verification_at(CASE_BLOCK);

        let r1_s0 = node.relay(&r1, |n| relayed(&r1, n, 3_000, &s, 0));
        let r2_s1 = node.relay(&r2, |n| {
            relayed_to(&r2, n, 2_000, &s, 1, &other_recipient())
        });
        let r2_u0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &u, 0));
        let r2_t = node.relay(&r2, |n| transfer(&r2, n, 1_000));
        let r2_before = node.account_nonce(&r2);

        let b3 = node.tick().await;
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        assert!(!carried.contains(&r1_s0.hash()), "{name}");
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        match (accounting, verification) {
            (false, _) => {
                assert_eq!(node.status(&r2_s1), None, "{name}");
                assert!(node.held(&r2_s1), "{name}: waits with s's envelope 0");
            }
            (true, true) => {
                let s1 = node.receipt(&r2_s1).expect("carried");
                assert!(
                    matches!(s1.status, TxStatus::Failed(_)),
                    "{name}: {:?}",
                    s1.status
                );
                assert!(s1.fee_paid > 0, "{name}: charged");
            }
            (true, false) => {
                assert_eq!(node.status(&r2_s1), Some(TxStatus::Success), "{name}");
            }
        }
        let advanced = if accounting { 3 } else { 1 };
        assert_eq!(node.account_nonce(&r2), r2_before + advanced, "{name}");

        let r2_v0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &v, 0));
        node.tick().await;
        assert_eq!(node.status(&r2_v0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r1_s0), None, "{name}");
        if accounting && !verification {
            assert!(!node.held(&r1_s0), "{name}: stale, evicted");
            assert_eq!(node.messaging_nonce(&s), 1, "{name}");
        } else {
            assert!(node.held(&r1_s0), "{name}: refused, held");
            assert_eq!(node.messaging_nonce(&s), 0, "{name}");
        }
    }
}
