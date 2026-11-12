//! One named sender's envelopes carried by two sponsors, on a real producer.
//!
//! From the messaging fee-and-nonce accounting gate on, a relayed
//! `SendMessage` advances its sponsor's account nonce, and from the envelope
//! verification gate on its envelope nonce must be the named sender's current
//! messaging nonce. A block then has to keep two sequences at once: each
//! sponsor's account nonces and each named sender's envelope nonces. With one
//! sender's envelopes through two sponsors they cross, and ordering by
//! account nonce alone puts the sender's envelope 1 ahead of envelope 0,
//! which the block then refuses. The producer (`select_for_block` →
//! `propose_block`) carries them in one order that keeps both, and every
//! transaction succeeds. Where the two sequences wait on each other in a
//! cycle, no order can carry them: one is evicted, the ones that depend on it
//! wait in the pool, and everything else is carried.
//!
//! Production's shape: V2 open, the inclusion policy and the next-block rules
//! wired, sponsorship enabled by the registry admin, both gates at 2.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE,
    SRC201_TAG_SIZE, SRC201_VERSION,
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
/// Both gates open from this height; block 1 sets the chain up below them.
const GATE: u64 = 2;
const NEVER: u64 = u64::MAX;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}
fn validator() -> KeyPair {
    key(0x71)
}
fn admin() -> KeyPair {
    key(0x72)
}
/// Two sponsors.
fn r1() -> KeyPair {
    key(0x73)
}
fn r2() -> KeyPair {
    key(0x74)
}
/// Senders whose envelopes the sponsors relay.
fn s() -> KeyPair {
    key(0x75)
}
fn u() -> KeyPair {
    key(0x76)
}
fn v() -> KeyPair {
    key(0x77)
}
fn recipient() -> KeyPair {
    key(0x78)
}
/// An account unrelated to the sponsors.
fn w() -> KeyPair {
    key(0x79)
}
/// A sender the recipient blocks.
fn x() -> KeyPair {
    key(0x7a)
}

fn genesis() -> Genesis {
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
    for k in [
        validator(),
        admin(),
        r1(),
        r2(),
        s(),
        u(),
        v(),
        recipient(),
        w(),
        x(),
    ] {
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
}

impl Node {
    fn new(g: &Genesis) -> Self {
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
                g,
                Some(validator()),
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
            chain_height,
        }
    }

    fn submit(&self, txs: &[&SignedTransaction]) {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        for t in txs {
            self.mempool.add((*t).clone()).expect("admitted");
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

    /// Block 1, below the gates: sponsorship on, the senders registered.
    async fn set_up(&self) {
        let mut txs = vec![messaging(
            &admin(),
            0,
            1_000,
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        )];
        for k in [s(), u(), v()] {
            txs.push(messaging(
                &k,
                0,
                1_000,
                MessagingOperation::RegisterPublicKey,
                &RegisterPublicKeyData { public_key: pk(&k) },
            ));
        }
        self.submit(&txs.iter().collect::<Vec<_>>());
        let b = self.tick().await;
        assert_eq!(b.height(), 1);
        for t in &txs {
            assert_eq!(self.status(t), Some(TxStatus::Success));
        }
    }
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

/// `s`'s envelope 0 relayed by `r1` at its nonce 1, envelope 1 by `r2` at its
/// nonce 0, and `r1`'s transfer at its nonce 0, with fees that put envelope 0
/// first and the transfer last. Ordered by account nonce alone, `r1`'s
/// transfer and envelope 0 would swap places and envelope 1 would land
/// before envelope 0. The block carries the transfer, envelope 0 and
/// envelope 1, in that order, and all three succeed.
#[tokio::test]
async fn one_senders_envelopes_through_two_sponsors_are_carried_in_both_orders() {
    let g = genesis();
    let node = Node::new(&g);
    node.set_up().await;

    let r1_transfer = transfer(&r1(), 0, 1_000);
    let r1_s0 = relayed(&r1(), 1, 3_000, &s(), 0);
    let r2_s1 = relayed(&r2(), 0, 2_000, &s(), 1);
    node.submit(&[&r1_transfer, &r1_s0, &r2_s1]);

    let block = node.tick().await;
    assert_eq!(block.height(), GATE);
    assert_eq!(
        hashes(&block.transactions),
        hashes(&[r1_transfer.clone(), r1_s0.clone(), r2_s1.clone()])
    );
    for t in [&r1_transfer, &r1_s0, &r2_s1] {
        assert_eq!(node.status(t), Some(TxStatus::Success), "{}", t.hash());
    }
    assert_eq!(node.messaging_nonce(&s()), 2);
    assert_eq!(node.account_nonce(&r1()), 2);
    assert_eq!(node.account_nonce(&r2()), 1);
    assert!(node.mempool.is_empty());
}

/// `r1` relays `u`'s envelope 1 and then `v`'s envelope 0; `r2` relays `v`'s
/// envelope 1 and then `u`'s envelope 0. Each waits on the other: no order
/// carries any of the four. One of them is evicted, the three that depend on
/// it stay in the pool, and an unrelated transfer is carried and succeeds.
#[tokio::test]
async fn a_cycle_between_two_sponsors_is_not_carried_and_the_rest_is() {
    let g = genesis();
    let node = Node::new(&g);
    node.set_up().await;

    let r2_u0 = relayed(&r2(), 1, 2_000, &u(), 0);
    let r1_v0 = relayed(&r1(), 1, 2_000, &v(), 0);
    let r1_u1 = relayed(&r1(), 0, 2_000, &u(), 1);
    let r2_v1 = relayed(&r2(), 0, 2_000, &v(), 1);
    let w_transfer = transfer(&w(), 0, 1_000);
    node.submit(&[&r2_u0, &r1_v0, &r1_u1, &r2_v1, &w_transfer]);

    let block = node.tick().await;
    assert_eq!(hashes(&block.transactions), vec![w_transfer.hash()]);
    assert_eq!(node.status(&w_transfer), Some(TxStatus::Success));
    let cycle = [&r2_u0, &r1_v0, &r1_u1, &r2_v1];
    for t in cycle {
        assert_eq!(node.status(t), None, "not carried");
    }
    let held = cycle
        .iter()
        .filter(|t| node.mempool.contains(&t.hash()))
        .count();
    assert_eq!(held, 3, "one evicted, the three that depend on it held");
    assert_eq!(node.messaging_nonce(&u()), 0);
    assert_eq!(node.messaging_nonce(&v()), 0);
    assert_eq!(node.account_nonce(&r1()), 0);
    assert_eq!(node.account_nonce(&r2()), 0);
}

/// From the accounting gate on, a relayed envelope advances its sponsor's
/// account nonce. When the producer leaves one out of the block (here its
/// recipient has blocked its sender, which the executor refuses with an
/// error rather than a receipt), the sponsor's later transaction leaves with
/// it: carried alone it would take `InvalidNonce` and be deleted from the
/// pool. Both wait in the pool, and the sponsor's nonce has not moved.
#[tokio::test]
async fn a_left_out_envelope_takes_its_sponsors_later_transactions() {
    let g = genesis();
    let node = Node::new(&g);
    node.set_up().await;
    let register = messaging(
        &x(),
        0,
        1_000,
        MessagingOperation::RegisterPublicKey,
        &RegisterPublicKeyData {
            public_key: pk(&x()),
        },
    );
    let blocks_x = messaging(
        &recipient(),
        node.account_nonce(&recipient()),
        1_000,
        MessagingOperation::BlockSender,
        &BlockSenderData {
            sender: x().address(),
        },
    );
    node.submit(&[&register, &blocks_x]);
    node.tick().await;
    assert_eq!(node.status(&register), Some(TxStatus::Success));
    assert_eq!(node.status(&blocks_x), Some(TxStatus::Success));

    let r1_x0 = relayed(&r1(), 0, 3_000, &x(), 0);
    let r1_s0 = relayed(&r1(), 1, 2_000, &s(), 0);
    node.submit(&[&r1_x0, &r1_s0]);
    let block = node.tick().await;
    assert!(
        block.transactions.is_empty(),
        "{:?}",
        hashes(&block.transactions)
    );
    for t in [&r1_x0, &r1_s0] {
        assert_eq!(node.status(t), None, "not carried");
        assert!(node.mempool.contains(&t.hash()), "held");
    }
    assert_eq!(node.account_nonce(&r1()), 0);
    assert_eq!(node.messaging_nonce(&s()), 0);
}
