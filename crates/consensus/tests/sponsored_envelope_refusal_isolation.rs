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
//! keeps moving. From the accounting gate the messaging refusals these cases
//! use (a recipient who blocks the sender) are charged failed receipts in the
//! block, not executor errors, so the producer drops nothing for them; an
//! authenticated envelope's refusal spends its sender's envelope nonce.
//!
//! - `r1` relays `x`'s envelope (the
//!   recipient blocks `x`: below the accounting gate the executor refuses it
//!   with an error and the producer holds it; from the gate it is a charged
//!   failed receipt) and then `s`'s envelope 0; `r2` relays `s`'s
//!   envelope 1, `u`'s envelope 0 and its own transfer. `r2`'s queue is
//!   carried in the case's first block and a later user's envelope through
//!   `r2` in the next, at every gate configuration.
//! - `r1`'s own direct message is refused (the recipient blocks
//!   `r1`), `r1` relays `s`'s envelope 0 behind it, `r2` relays `s`'s
//!   envelope 1. Below the gates the producer builds main's block; at and
//!   above them the refusal is a charged failed receipt, `r1`'s run follows
//!   in sequence, and `r2`'s envelope is carried and `r2`'s queue moves.
//!
//! Every case runs under the 6 gate configurations of [`matrix`] (the gates
//! absent, set above the chain's history, set inside it, and both at the
//! case's block, one below and one above), with the submissions a relay would
//! sign at the case's block: [`relay_nonce`]. The 8 that set the two gates
//! apart are refused at genesis ([`apart_configurations`]).
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

/// The gates absent; set above the chain's history; set inside it; and both
/// at the case's block `H`, one below (`H-1`: the case's first block is below
/// the gates, the next at them) and one above (`H+1`). A node runs only a
/// chain whose two messaging gates are unset or at one height; the
/// configurations that set them apart are [`apart_configurations`], each
/// refused at genesis.
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
    ]
}

/// `0x1049` and `0x1048` each at the case's block `H`, one below and one
/// above, with the other gate inside the chain's history, and each alone at
/// `H`. The two gates name one rule and must be unset or at one height,
/// so a node refuses each of these genesis files and no case runs on
/// them: [`apart_gate_configurations_are_refused_at_genesis`].
fn apart_configurations() -> Vec<Gates> {
    let h = CASE_BLOCK;
    let g = |name, verification, accounting| Gates {
        name,
        verification,
        accounting,
    };
    vec![
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

    fn balance(&self, k: &KeyPair) -> u128 {
        self.state.get_balance(&k.address()).unwrap()
    }

    /// Whether a message event is stored for `t`.
    fn message_stored(&self, t: &SignedTransaction) -> bool {
        MessagingStore::new(&self.db)
            .get_message_by_tx_hash(t.hash().as_bytes())
            .unwrap()
            .is_some()
    }

    /// The envelope-outcome row of `k`'s envelope nonce `nonce`: the
    /// transaction that spent it and its receipt code.
    fn envelope_outcome(&self, k: &KeyPair, nonce: u64) -> Option<(Hash, u32)> {
        MessagingStore::new(&self.db)
            .get_envelope_outcome(&k.address(), nonce)
            .unwrap()
            .map(|o| (o.tx_hash, o.outcome_code))
    }

    /// What a charged refusal may change, read before the block that
    /// carries it: the payer's balance and account and messaging nonces, the
    /// named sender's balance and envelope nonce, the recipient's balance.
    fn around(&self, payer: &KeyPair, sender: &KeyPair) -> Around {
        Around {
            payer: self.balance(payer),
            payer_nonce: self.account_nonce(payer),
            payer_messaging_nonce: self.messaging_nonce(payer),
            sender: self.balance(sender),
            sender_nonce: self.messaging_nonce(sender),
            recipient: self.balance(&recipient()),
        }
    }
}

/// [`Node::around`].
#[derive(Clone, Copy)]
struct Around {
    payer: u128,
    payer_nonce: u64,
    payer_messaging_nonce: u64,
    sender: u128,
    sender_nonce: u64,
    recipient: u128,
}

/// The checks for a charged refusal, on `t`
/// carried in a block, with `before` read before that block:
/// - `t` pays its fee exactly once: its receipt is `Failed(7)` with `fee`,
///   and its payer's balance falls by exactly `payer_fees`, the fees of the
///   payer's transactions in that block (`t`'s among them, each once);
/// - the payer's account nonce moves by exactly `payer_txs`, one for each
///   of its transactions in the block;
/// - for an authenticated envelope (`envelope`: the named sender, its
///   envelope nonce, and how far the block moves that sender's envelope
///   nonce in all), `t` spends the envelope nonce (its outcome row names
///   `t`), and the named sender's balance does not move; for a direct
///   message (`None`), no messaging nonce moves;
/// - nothing else of the inner operation happens: no message is stored for
///   `t`, and the recipient's balance moves only by `recipient_in`, from the
///   block's other transactions.
#[allow(clippy::too_many_arguments)]
fn assert_charged_refusal(
    node: &Node,
    name: &str,
    t: &SignedTransaction,
    fee: u128,
    payer: &KeyPair,
    before: Around,
    payer_fees: u128,
    payer_txs: u64,
    envelope: Option<(&KeyPair, u64, u64)>,
    recipient_in: u128,
) {
    let r = node.receipt(t).expect("a receipt");
    assert_eq!(
        (r.status, r.fee_paid),
        (TxStatus::Failed(7), fee),
        "{name}: one fee"
    );
    assert_eq!(
        before.payer - node.balance(payer),
        payer_fees,
        "{name}: each of the payer's fees once"
    );
    assert_eq!(
        node.account_nonce(payer),
        before.payer_nonce + payer_txs,
        "{name}: one account nonce each"
    );
    assert!(!node.message_stored(t), "{name}: no message");
    assert_eq!(
        node.balance(&recipient()),
        before.recipient + recipient_in,
        "{name}: no payment to the recipient"
    );
    match envelope {
        Some((sender, nonce, moves)) => {
            assert_eq!(
                node.envelope_outcome(sender, nonce),
                Some((t.hash(), 7)),
                "{name}: the authenticated attempt spends its envelope nonce"
            );
            assert_eq!(
                node.messaging_nonce(sender),
                before.sender_nonce + moves,
                "{name}"
            );
            assert_eq!(
                node.balance(sender),
                before.sender,
                "{name}: no value from the named sender"
            );
        }
        None => assert_eq!(
            node.messaging_nonce(payer),
            before.payer_messaging_nonce,
            "{name}: the refused direct message moves no messaging nonce"
        ),
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

/// At every configuration `r2`'s envelope for `u` and `r2`'s
/// transfer are delivered in the case's first block, and a later user's
/// envelope through `r2` in the next; `s`'s envelope 1 through `r2` is
/// carried in the first block too, to the outcome its envelope nonce meets.
/// Below the gates `x`'s envelope is held (refused with an error, never in a
/// block), `r1`'s envelope for `s` leaves nothing behind (main's rule) and
/// both of `s`'s envelopes are delivered in sequence. From the gates `x`'s
/// envelope is carried to a charged failed receipt that spends `x`'s envelope
/// nonce, so `r1`'s envelope for `s` follows in `r1`'s sequence and
/// `s`'s envelope 1 meets `s`'s nonce 1: both of `s`'s envelopes are
/// delivered in the case's first block. At `both at H-1` the gates open at
/// the second block, where `x`'s envelope, held after the case's block, is
/// refused and charged in the same way.
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

        let before_b3 = node.around(&r1, &x);
        let b3 = node.tick().await;
        assert_eq!(b3.height(), CASE_BLOCK);
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        // From the accounting gate x's refusal is a charged failed receipt in
        // the block; below it, an executor error, and it is held.
        assert_eq!(carried.contains(&r1_x0.hash()), accounting, "{name}");
        for t in [&r2_s1, &r2_u0, &r2_t] {
            assert!(carried.contains(&t.hash()), "{name}: {} carried", t.hash());
        }
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        let s1 = node.receipt(&r2_s1).expect("r2_s1 has a receipt");
        if accounting && verification {
            // x's refusal spends x's envelope nonce and r1's account
            // nonce, so r1's envelope for s follows in r1's sequence and s's
            // envelope 1 meets s's nonce 1: both execute in this block. r1
            // pays x's fee and s's once each; r2's transfer is the only value
            // the recipient receives.
            assert_charged_refusal(
                &node,
                name,
                &r1_x0,
                3_000,
                &r1,
                before_b3,
                3_000 + 2_000,
                2,
                Some((&x, 0, 1)),
                1,
            );
            assert_eq!(s1.status, TxStatus::Success, "{name}");
            assert!(s1.fee_paid > 0, "{name}: charged");
            assert_eq!(node.status(&r1_s0), Some(TxStatus::Success), "{name}");
            assert!(!node.held(&r1_s0), "{name}: carried in r1's sequence");
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
        let before_b4 = node.around(&r1, &x);
        let b4 = node.tick().await;
        assert!(
            b4.transactions.iter().any(|t| t.hash() == r2_v0.hash()),
            "{name}"
        );
        assert_eq!(node.status(&r2_v0), Some(TxStatus::Success), "{name}");

        // At `both at H-1` the second block crosses activation: the gates open there.
        if gates.accounting_at(CASE_BLOCK + 1) {
            // x's envelope: refused in a block, charged, its nonce spent.
            if !accounting {
                // Refused in the second block, r1's only transaction there.
                assert_charged_refusal(
                    &node,
                    name,
                    &r1_x0,
                    3_000,
                    &r1,
                    before_b4,
                    3_000,
                    1,
                    Some((&x, 0, 1)),
                    0,
                );
            }
            let x0 = node.receipt(&r1_x0).expect("r1_x0 has a receipt");
            assert_eq!(x0.status, TxStatus::Failed(7), "{name}");
            assert!(x0.fee_paid > 0, "{name}: charged to r1");
            assert!(!node.held(&r1_x0), "{name}");
            assert_eq!(node.messaging_nonce(&x), 1, "{name}: x's nonce spent");
        } else {
            // x's envelope stays held (its refusal is an error, never a receipt).
            assert_eq!(node.status(&r1_x0), None, "{name}");
            assert!(node.held(&r1_x0), "{name}");
        }
        let s_nonce = node.messaging_nonce(&s);
        match (accounting, verification) {
            (false, _) => assert_eq!(s_nonce, 2, "{name}"),
            (true, true) => {
                assert_eq!(s_nonce, 2, "{name}: both of s's envelopes, in sequence");
                assert!(!node.held(&r1_s0), "{name}");
            }
            (true, false) => {
                assert_eq!(s_nonce, 1, "{name}");
                assert_eq!(node.status(&r1_s0), None, "{name}");
                assert!(!node.held(&r1_s0), "{name}: stale, evicted");
            }
        }
    }
}

/// The fitting loop's own drops, at the block that opens the accounting
/// gate as at every other. The first case with the proposer's
/// screening pass skipped (`Failpoint::SkipProposalScreening`): the refusal
/// of `x`'s envelope reaches `create_block`'s fitting loop. Below the gates
/// it is an error, which the loop drops with the runs it breaks as the block
/// being built judges them, not as its parent would; from the gates it is a
/// charged failed receipt, which the loop keeps and drops nothing for. The
/// case's first block carries what the first case's does: `r2`'s three transactions;
/// below the gates never `x`'s envelope, and `r1`'s envelope for `s` is
/// delivered; from them `x`'s refusal and `r1`'s envelope for `s` in
/// sequence. At every configuration.
#[tokio::test]
async fn the_fitting_loop_drops_a_refused_envelopes_runs_as_the_block_being_built_judges_them() {
    use sumchain_consensus::branch_switch::failpoints::{arm, Failpoint};
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        let (r1, r2, s, u, x) = (sponsor(0), sponsor(1), sender(0), sender(1), sender(3));
        node.set_up(&x).await;
        let accounting = gates.accounting_at(CASE_BLOCK);
        let verification = gates.verification_at(CASE_BLOCK);

        let r1_x0 = node.relay(&r1, |n| relayed(&r1, n, 3_000, &x, 0));
        let r1_s0 = node.relay(&r1, |n| relayed(&r1, n, 2_000, &s, 0));
        let r2_s1 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &s, 1));
        let r2_u0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &u, 0));
        let r2_t = node.relay(&r2, |n| transfer(&r2, n, 1_000));
        let r2_before = node.account_nonce(&r2);

        let before_b3 = node.around(&r1, &x);
        arm(Some(Failpoint::SkipProposalScreening));
        let b3 = node.tick().await;
        arm(None);
        assert_eq!(b3.height(), CASE_BLOCK);
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        // From the accounting gate x's refusal is a charged failed receipt in
        // the block; below it, an executor error, and it is held.
        assert_eq!(carried.contains(&r1_x0.hash()), accounting, "{name}");
        for t in [&r2_s1, &r2_u0, &r2_t] {
            assert!(carried.contains(&t.hash()), "{name}: {} carried", t.hash());
        }
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        let s1 = node.receipt(&r2_s1).expect("r2_s1 has a receipt");
        // From the gates the fitting loop meets a charged receipt, not an
        // error, and drops nothing: r1's run is carried in sequence and s's
        // envelope 1 meets s's nonce 1. Below them s's
        // envelope 1 executes as before.
        assert_eq!(s1.status, TxStatus::Success, "{name}");
        if accounting && verification {
            assert_eq!(node.status(&r1_s0), Some(TxStatus::Success), "{name}");
            assert!(!node.held(&r1_s0), "{name}: carried in r1's sequence");
        } else if accounting {
            assert_eq!(node.status(&r1_s0), None, "{name}: no receipt");
            assert!(
                node.held(&r1_s0) || !verification,
                "{name}: left with r1's run"
            );
        } else {
            assert_eq!(node.status(&r1_s0), Some(TxStatus::Success), "{name}");
        }
        if accounting {
            assert_charged_refusal(
                &node,
                name,
                &r1_x0,
                3_000,
                &r1,
                before_b3,
                3_000 + 2_000,
                2,
                Some((&x, 0, 1)),
                1,
            );
            assert!(!node.held(&r1_x0), "{name}");
        } else {
            assert_eq!(node.status(&r1_x0), None, "{name}");
            assert!(node.held(&r1_x0), "{name}: left in the pool");
        }
        let advanced = if accounting { 3 } else { 1 };
        assert_eq!(node.account_nonce(&r2), r2_before + advanced, "{name}");
    }
}

/// `r1`'s own direct message is refused (the recipient blocks
/// `r1`). At every configuration `r2`'s envelope for `s` is carried in the
/// case's first block with an unrelated transfer, and `r2`'s next transaction
/// in the next block. Below the gates the refused message is held, `r1`'s
/// envelope for `s` behind it leaves with `r1`'s run, `s`'s envelope 1
/// executes out of sequence and `s`'s envelope 0 is then evicted as stale
/// (main's behaviour). From the gates the refusal is a charged failed receipt
/// in the block, so `r1`'s envelope for `s` follows in sequence and
/// `s`'s envelope 1 meets `s`'s nonce 1: four transactions are carried. At
/// `both at H-1` the gates open at the second block, where the direct
/// message, held after the case's block, is refused and charged.
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

        let before_b3 = node.around(&r1, &r1);
        let b3 = node.tick().await;
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        if accounting {
            // From the accounting gate r1's refused direct message is a
            // charged failed receipt in the block: r1's account
            // nonce moves, r1's envelope for s follows in sequence, and s's
            // envelope 1 through r2 meets s's nonce 1.
            assert_eq!(carried.len(), 4, "{name}: {carried:?}");
            assert!(carried.contains(&d0.hash()), "{name}");
            assert!(carried.contains(&e_s0.hash()), "{name}");
        } else {
            assert_eq!(carried.len(), 2, "{name}: {carried:?}");
        }
        assert!(carried.contains(&e_s1.hash()), "{name}");
        assert!(carried.contains(&wt.hash()), "{name}");
        assert_eq!(node.status(&wt), Some(TxStatus::Success), "{name}");
        let s1 = node.receipt(&e_s1).expect("e_s1 has a receipt");
        if verification && !accounting {
            assert!(
                matches!(s1.status, TxStatus::Failed(_)),
                "{name}: {:?}",
                s1.status
            );
            assert_eq!(s1.fee_paid > 0, accounting, "{name}: charged from 0x1049");
        } else {
            assert_eq!(s1.status, TxStatus::Success, "{name}");
        }
        if accounting {
            assert!(s1.fee_paid > 0, "{name}: charged from 0x1049");
            // r1 pays d0's fee and its envelope for s's once each; the
            // bystander's transfer is the only value the recipient receives.
            assert_charged_refusal(
                &node,
                name,
                &d0,
                5_000,
                &r1,
                before_b3,
                5_000 + 2_000,
                2,
                None,
                1,
            );
        }

        let r2_next = node.relay(&r2, |n| transfer(&r2, n, 1_000));
        let before_b4 = node.around(&r1, &r1);
        let b4 = node.tick().await;
        assert!(
            b4.transactions.iter().any(|t| t.hash() == r2_next.hash()),
            "{name}"
        );
        assert_eq!(node.status(&r2_next), Some(TxStatus::Success), "{name}");

        if accounting {
            assert_eq!(node.status(&d0), Some(TxStatus::Failed(7)), "{name}");
            assert!(!node.held(&d0), "{name}");
            assert_eq!(node.status(&e_s0), Some(TxStatus::Success), "{name}");
            assert!(!node.held(&e_s0), "{name}: carried in r1's sequence");
            assert_eq!(node.messaging_nonce(&s), 2, "{name}");
        } else if gates.accounting_at(CASE_BLOCK + 1) {
            // At `both at H-1` the second block crosses activation: d0, held
            // after the case's block, is refused and charged there;
            // s's envelope 0 was evicted as stale after the case's block. d0
            // is r1's only transaction there; r2's transfer is the only value
            // the recipient receives.
            assert_charged_refusal(&node, name, &d0, 5_000, &r1, before_b4, 5_000, 1, None, 1);
            assert!(!node.held(&d0), "{name}");
            assert_eq!(node.status(&e_s0), None, "{name}");
            assert!(!node.held(&e_s0), "{name}: stale, evicted, as on main");
            assert_eq!(node.messaging_nonce(&s), 1, "{name}");
        } else {
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
}

/// A refused sender's later envelope through another sponsor: `s`'s envelope 0 through `r1` is refused (the
/// recipient blocks `s`), and `s`'s envelope 1, to a recipient that blocks
/// nobody, goes through `r2`, followed by `r2`'s envelope for `u` and its
/// transfer. Below the gates `s`'s envelope 0 is held and `s`'s envelope 1
/// waits with it (main's rule; it holds nothing of `r2` there). From the
/// gates `s`'s envelope 0 is a charged failed receipt in the block that
/// spends `s`'s envelope nonce, so it is held nowhere and `s`'s
/// envelope 1 through `r2` meets `s`'s nonce 1 and executes. At `both at
/// H-1` the gates open at the second block: `s`'s envelope 0 is refused and
/// charged there, and `s`'s envelope 1, whose wrapper `r2` signed below the
/// accounting gate at the account nonce its transfer then used, is offered
/// stale and takes an uncharged `InvalidNonce`. At every configuration `r2`'s
/// other two are delivered in the case's first block and a later user's
/// envelope through `r2` in the next: nothing of `r2`'s is held.
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

        let before_b3 = node.around(&r1, &s);
        let b3 = node.tick().await;
        let carried: Vec<_> = b3.transactions.iter().map(|t| t.hash()).collect();
        // From the accounting gate s's refused envelope 0 is a charged failed
        // receipt in the block; below it, an executor error, held.
        assert_eq!(carried.contains(&r1_s0.hash()), accounting, "{name}");
        assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
        match (accounting, verification) {
            (false, _) => {
                assert_eq!(node.status(&r2_s1), None, "{name}");
                assert!(node.held(&r2_s1), "{name}: waits with s's envelope 0");
            }
            (true, true) => {
                // s's refusal spends s's envelope nonce, so s's
                // envelope 1 through r2 meets s's nonce 1 and executes: r2 is
                // held by nothing of r1's or s's.
                // r1's only transaction in the block; s's envelope nonce moves
                // twice (its refusal, then envelope 1); r2's transfer is the
                // only value the recipient receives.
                assert_charged_refusal(
                    &node,
                    name,
                    &r1_s0,
                    3_000,
                    &r1,
                    before_b3,
                    3_000,
                    1,
                    Some((&s, 0, 2)),
                    1,
                );
                let s1 = node.receipt(&r2_s1).expect("carried");
                assert_eq!(s1.status, TxStatus::Success, "{name}");
                assert!(s1.fee_paid > 0, "{name}: charged");
            }
            (true, false) => {
                assert_eq!(node.status(&r2_s1), Some(TxStatus::Success), "{name}");
            }
        }
        let advanced = if accounting { 3 } else { 1 };
        assert_eq!(node.account_nonce(&r2), r2_before + advanced, "{name}");
        // At every configuration s's refused envelope 0 holds nothing of
        // another sponsor's: r2's envelope for u and its transfer are
        // delivered in the case's block and left in no pool.
        for t in [&r2_u0, &r2_t] {
            assert_eq!(node.status(t), Some(TxStatus::Success), "{name}");
            assert!(!node.held(t), "{name}");
        }

        let r2_v0 = node.relay(&r2, |n| relayed(&r2, n, 2_000, &v, 0));
        let before_b4 = node.around(&r1, &s);
        node.tick().await;
        // ...and r2's next envelope is delivered in the next block.
        assert_eq!(node.status(&r2_v0), Some(TxStatus::Success), "{name}");
        assert!(!node.held(&r2_v0), "{name}");
        // At `both at H-1` the second block crosses activation: the gates open there.
        if gates.accounting_at(CASE_BLOCK + 1) && gates.verification_at(CASE_BLOCK + 1) {
            // Refused in a block, so not held: no indefinite hold. s's
            // envelope 0 spends its nonce.
            if !accounting {
                // Refused in the second block, r1's only transaction there;
                // s's envelope nonce moves by exactly one there, spent by the
                // refusal; no transfer to the recipient in that block.
                assert_charged_refusal(
                    &node,
                    name,
                    &r1_s0,
                    3_000,
                    &r1,
                    before_b4,
                    3_000,
                    1,
                    Some((&s, 0, 1)),
                    0,
                );
                // At `both at H-1` the relay account-nonce rule activates at b4, so r2_s1's wrapper, signed at r2 nonce 0 below the gate, is stale.
                // r2's transfer took nonce 0 in the case's block. The pool
                // offers a transaction below its account's committed nonce
                // (mempool.rs, `in_combined_order`; `a_gap_the_block_fills_is_no_gap`),
                // after s's envelope 0 in s's sequence, and it takes an
                // uncharged `InvalidNonce` before its envelope is read.
                let w = node.receipt(&r2_s1).expect("r2_s1 offered in b4");
                assert_eq!(
                    (w.status, w.fee_paid),
                    (TxStatus::InvalidNonce, 0),
                    "{name}"
                );
                assert!(!node.held(&r2_s1), "{name}");
                assert_eq!(node.messaging_nonce(&s), 1, "{name}");
            } else {
                // s's envelope 1 through r2 met s's nonce 1 in the case's
                // block and executed.
                assert_eq!(
                    (node.status(&r2_s1), node.messaging_nonce(&s)),
                    (Some(TxStatus::Success), 2),
                    "{name}"
                );
            }
            let s0 = node.receipt(&r1_s0).expect("r1_s0 has a receipt");
            assert_eq!(s0.status, TxStatus::Failed(7), "{name}");
            assert!(s0.fee_paid > 0, "{name}: charged to r1");
            assert!(!node.held(&r1_s0), "{name}: refused in a block");
        } else {
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
}

/// Each configuration that sets `0x1048` and `0x1049` apart is refused when
/// the node initialises its genesis, with the error naming both gates:
/// such a chain cannot be run, so no case runs on it.
#[tokio::test]
async fn apart_gate_configurations_are_refused_at_genesis() {
    let apart = apart_configurations();
    assert_eq!(apart.len(), 8);
    for gates in apart {
        let g = genesis(gates);
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let engine = PoAEngine::new(db, state, mempool, &g, Some(validator())).unwrap();
        let want = sumchain_genesis::GenesisError::MessagingEnvelopeAndAccountingGatesApart {
            envelope: gates.verification,
            accounting: gates.accounting,
        }
        .to_string();
        match engine.init_genesis(&g) {
            Err(sumchain_consensus::ConsensusError::State(
                sumchain_state::StateError::ActivationParams(m),
            )) => assert_eq!(m, want, "{}", gates.name),
            other => panic!("{}: expected the refusal, got {other:?}", gates.name),
        }
    }
}
