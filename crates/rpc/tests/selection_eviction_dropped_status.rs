//! `chain_getTransactionStatus` reports `{"kind":"dropped"}` for a transaction
//! this node's pool evicted above a gap (`GAP_HOLD_SELECTIONS`) and has not
//! admitted since, from a bounded, in-memory history.
//!
//! Precedence: a canonical receipt, then a place in the pool (`pending`),
//! then the eviction history (`dropped`), then `unknown`. The history holds
//! at most as many entries as the pool has places, the oldest forgotten
//! first, and is empty after a restart. Only a successful admission clears an
//! entry. `dropped` is a local observation: another node may report the same
//! transaction differently, or carry it in a block. With the gates absent and
//! inside the chain's history.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    sponsored_send_v2_signing_preimage, Block, MessagingOperation, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::mempool::{InclusionGates, InclusionPolicy, GAP_HOLD_SELECTIONS};
use sumchain_state::{Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const FUNDS: u128 = 1_000_000_000_000;

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
fn recipient() -> KeyPair {
    key(0x73)
}
fn user() -> KeyPair {
    key(0x74)
}
fn relay_one() -> KeyPair {
    key(0x75)
}
fn relay_two() -> KeyPair {
    key(0x76)
}
fn sender() -> KeyPair {
    key(0x77)
}

fn genesis(gate: Option<u64>) -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        messaging: Some(MessagingParams {
            registry_admin: Some(admin().address().to_base58()),
            ..MessagingParams::default()
        }),
        messaging_sponsored_envelope_verification_enabled_from_height: gate,
        messaging_fee_nonce_accounting_enabled_from_height: gate,
        // A remediation gate set obliges the peer declaration at or below it.
        peer_protocol_declaration_required_from_height: gate.map(|_| 1),
        ..ChainParams::with_v2_enabled()
    };
    let alloc = [
        validator(),
        admin(),
        recipient(),
        user(),
        relay_one(),
        relay_two(),
        sender(),
    ]
    .iter()
    .map(|k| (k.address().to_base58(), FUNDS))
    .collect::<HashMap<_, _>>();
    Genesis::new(
        CHAIN_ID,
        0,
        vec![validator().public_key().to_base58()],
        alloc,
        params,
    )
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
    operation: MessagingOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    signed(
        kp,
        nonce,
        1_000,
        TxPayload::Messaging(MessagingTxData {
            operation,
            data: bincode::serialize(payload).unwrap(),
        }),
    )
}

fn transfer(from: &KeyPair, nonce: u64) -> SignedTransaction {
    signed(
        from,
        nonce,
        1_000,
        TxPayload::Transfer {
            to: recipient().address(),
            amount: 1,
        },
    )
}

/// A valid encrypted message body for recipient hash `rh`.
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

/// `named`'s version-2 envelope at envelope nonce `envelope_nonce`, relayed
/// by `relay` at account nonce `nonce` with fee 2,000.
fn relayed(relay: &KeyPair, nonce: u64, named: &KeyPair, envelope_nonce: u64) -> SignedTransaction {
    let rh = recipient_hash(&recipient().address());
    let mut m = SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(named),
        nonce: envelope_nonce,
        expiry: u64::MAX,
        koppa_amount: None,
    };
    m.signature = *sign(
        &sponsored_send_v2_signing_preimage(CHAIN_ID, &m),
        named.private_key(),
    )
    .as_bytes();
    signed(
        relay,
        nonce,
        2_000,
        TxPayload::Messaging(MessagingTxData {
            operation: MessagingOperation::SendMessage,
            data: bincode::serialize(&m).unwrap(),
        }),
    )
}

struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
    chain_height: Arc<AtomicU64>,
    server: RpcServer,
}

impl Node {
    fn new(gate: Option<u64>) -> Self {
        Self::build(gate, Some(validator()), usize::MAX)
    }

    /// A node that never proposes (no validator key): it only imports.
    fn follower(gate: Option<u64>) -> Self {
        Self::build(gate, None, usize::MAX)
    }

    /// [`Node::follower`], with a pool of `places` places.
    fn small_follower(gate: Option<u64>, places: usize) -> Self {
        Self::build(gate, None, places)
    }

    fn build(gate: Option<u64>, key: Option<KeyPair>, places: usize) -> Self {
        let g = genesis(gate);
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let chain_height = Arc::new(AtomicU64::new(0));
        let mempool = Arc::new(
            Mempool::new({
                let c = MempoolConfig {
                    min_fee: g.params.min_fee,
                    max_tx_bytes: g.params.max_block_bytes,
                    ..MempoolConfig::default()
                };
                MempoolConfig {
                    max_size: places.min(c.max_size),
                    ..c
                }
            })
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
        let (tx_sender, _rx) = mpsc::channel(8);
        let server = RpcServer::new(
            db.clone(),
            state,
            mempool.clone(),
            engine.clone(),
            tx_sender,
            Arc::new(|| 0usize),
        );
        Self {
            _dir: dir,
            db,
            mempool,
            engine,
            chain_height,
            server,
        }
    }

    fn submit(&self, txs: &[&SignedTransaction]) {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        for t in txs {
            self.mempool.add((*t).clone()).expect("admitted");
        }
    }

    /// `b`, imported as gossip delivers it, with the pool's view of the
    /// height moved to the new head as the node's event loop moves it.
    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.expect("imports");
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
    }

    /// The block this node produced last.
    fn head(&self) -> Block {
        self.engine
            .get_block_by_height(self.engine.current_height())
            .expect("its head")
    }

    /// What this node reports after a restart on its own database: a new
    /// pool, with no eviction history, behind the same RPC.
    fn restarted_server(&self, gate: Option<u64>) -> RpcServer {
        let g = genesis(gate);
        let state = Arc::new(StateManager::new(self.db.clone(), CHAIN_ID));
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                min_fee: g.params.min_fee,
                max_tx_bytes: g.params.max_block_bytes,
                ..MempoolConfig::default()
            })
            .with_inclusion_policy(InclusionPolicy {
                db: self.db.clone(),
            })
            .with_inclusion_gates(InclusionGates {
                params: Arc::new(g.params.clone()),
                chain_id: g.chain_id,
                current_height: self.chain_height.clone(),
            }),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        RpcServer::new(
            self.db.clone(),
            state,
            mempool,
            self.engine.clone(),
            tx_sender,
            Arc::new(|| 0usize),
        )
    }

    /// One production tick, as `run_block_producer` runs it.
    async fn tick(&self) {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        let txs = self.mempool.select_for_block(1_000);
        self.engine.propose_block(txs).await.expect("a block");
    }

    async fn status(&self, t: &SignedTransaction) -> Value {
        serde_json::to_value(
            self.server
                .chain_get_transaction_status(t.hash().to_hex())
                .await
                .unwrap(),
        )
        .unwrap()
    }
}

fn set_up_transactions() -> [SignedTransaction; 2] {
    [
        messaging(
            &admin(),
            0,
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        ),
        messaging(
            &sender(),
            0,
            MessagingOperation::RegisterPublicKey,
            &RegisterPublicKeyData {
                public_key: pk(&sender()),
            },
        ),
    ]
}

/// `p` produces block 1, and every node in `followers` imports it.
async fn set_up(p: &Node, followers: &[&Node]) {
    let setup = set_up_transactions();
    p.submit(&setup.iter().collect::<Vec<_>>());
    p.tick().await;
    for q in followers {
        q.import(&p.head()).await;
    }
}

/// `p` produces the next block, and every node in `followers` imports it.
async fn next_block(p: &Node, followers: &[&Node]) {
    p.tick().await;
    for q in followers {
        q.import(&p.head()).await;
    }
}

/// Different observations of one transaction, and a receipt over a
/// `dropped`. Only the follower `q` holds `user`'s nonce 1 (its nonce 0 is
/// nowhere); `q` reports it `pending` for `GAP_HOLD_SELECTIONS - 1` blocks
/// and `dropped` from the `GAP_HOLD_SELECTIONS`-th, while the producer `p`,
/// which never held it, reports `unknown`. Then `p` takes `user`'s nonces 0
/// and 1 and carries both: `q`, importing the block, reports the receipt
/// (`included`) over its eviction entry, as `p` does.
#[tokio::test]
async fn dropped_is_a_local_observation_and_a_receipt_takes_precedence() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let p = Node::new(gate);
        let q = Node::follower(gate);
        set_up(&p, &[&q]).await;
        let y0 = transfer(&user(), 0);
        let y1 = transfer(&user(), 1);
        q.submit(&[&y1]);
        for n in 1..=GAP_HOLD_SELECTIONS {
            next_block(&p, &[&q]).await;
            let expected = if n < GAP_HOLD_SELECTIONS {
                json!({ "kind": "pending" })
            } else {
                json!({ "kind": "dropped" })
            };
            assert_eq!(q.status(&y1).await, expected, "{name}: block {n}");
            assert_eq!(
                p.status(&y1).await,
                json!({ "kind": "unknown" }),
                "{name}: the producer never held it"
            );
        }
        p.submit(&[&y0, &y1]);
        next_block(&p, &[&q]).await;
        let height = p.engine.current_height();
        for node in [&p, &q] {
            assert_eq!(
                node.status(&y1).await,
                json!({ "kind": "included", "block_height": height }),
                "{name}: the receipt first"
            );
        }
    }
}

/// Only a successful readmission clears `dropped`. A follower with a pool of
/// two places evicts `user`'s nonce 1 and reports it `dropped`. With two
/// other transactions at the same fee filling its pool, the same signed
/// transaction offered again is refused (`MempoolFull`) and it still reports
/// `dropped`; with a place free it is admitted and reports `pending`, and
/// `dropped` again once evicted again.
#[tokio::test]
async fn only_a_successful_readmission_clears_dropped() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let p = Node::new(gate);
        let q = Node::small_follower(gate, 2);
        set_up(&p, &[&q]).await;
        let y1 = transfer(&user(), 1);
        q.submit(&[&y1]);
        for _ in 0..GAP_HOLD_SELECTIONS {
            next_block(&p, &[&q]).await;
        }
        assert_eq!(q.status(&y1).await, json!({ "kind": "dropped" }), "{name}");
        let fillers = [transfer(&relay_one(), 0), transfer(&relay_two(), 0)];
        q.submit(&fillers.iter().collect::<Vec<_>>());
        assert!(
            matches!(q.mempool.add(y1.clone()), Err(StateError::MempoolFull)),
            "{name}: refused"
        );
        assert_eq!(
            q.status(&y1).await,
            json!({ "kind": "dropped" }),
            "{name}: a refused readmission clears nothing"
        );
        q.mempool.remove(&fillers[0].hash());
        q.submit(&[&y1]);
        assert_eq!(q.status(&y1).await, json!({ "kind": "pending" }), "{name}");
        for _ in 0..GAP_HOLD_SELECTIONS {
            next_block(&p, &[&q]).await;
        }
        assert_eq!(q.status(&y1).await, json!({ "kind": "dropped" }), "{name}");
    }
}

/// The history is first in, first out, and holds at most as many entries as
/// the pool has places. A follower with a pool of two places evicts two
/// gapped transfers, then two more: the first two read `unknown`, the last
/// two `dropped`.
#[tokio::test]
async fn the_eviction_history_keeps_the_newest_up_to_the_pool_capacity() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let p = Node::new(gate);
        let q = Node::small_follower(gate, 2);
        set_up(&p, &[&q]).await;
        let first = [transfer(&user(), 1), transfer(&relay_one(), 1)];
        let second = [transfer(&relay_two(), 1), transfer(&sender(), 2)];
        for batch in [&first, &second] {
            q.submit(&batch.iter().collect::<Vec<_>>());
            for _ in 0..GAP_HOLD_SELECTIONS {
                next_block(&p, &[&q]).await;
            }
        }
        for t in &first {
            assert_eq!(q.status(t).await, json!({ "kind": "unknown" }), "{name}");
        }
        for t in &second {
            assert_eq!(q.status(t).await, json!({ "kind": "dropped" }), "{name}");
        }
    }
}

/// After a restart the history is empty: the follower, restarted on its own
/// database with a new pool, reports the evicted transaction `unknown`, and
/// a transaction with a receipt as before.
#[tokio::test]
async fn a_restarted_node_reports_unknown() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let p = Node::new(gate);
        let q = Node::follower(gate);
        set_up(&p, &[&q]).await;
        let y1 = transfer(&user(), 1);
        q.submit(&[&y1]);
        for _ in 0..GAP_HOLD_SELECTIONS {
            next_block(&p, &[&q]).await;
        }
        assert_eq!(q.status(&y1).await, json!({ "kind": "dropped" }), "{name}");
        let restarted = q.restarted_server(gate);
        let status = |t: &SignedTransaction| {
            let hash = t.hash().to_hex();
            let server = &restarted;
            async move {
                serde_json::to_value(server.chain_get_transaction_status(hash).await.unwrap())
                    .unwrap()
            }
        };
        assert_eq!(status(&y1).await, json!({ "kind": "unknown" }), "{name}");
        let setup = set_up_transactions();
        assert_eq!(
            status(&setup[0]).await,
            json!({ "kind": "included", "block_height": 1 }),
            "{name}"
        );
    }
}

/// Row 3 of the selection oracle: from the accounting gate, a cycle within one sponsor above a
/// missing envelope is not released.
/// `sender`'s envelope 0 is admitted through `relay_two` and then leaves the
/// pool (it is in no block); `relay_one` relays `sender`'s envelope 2 at its
/// nonce 0 and envelope 1 at its nonce 1. Both read `pending` for
/// `GAP_HOLD_SELECTIONS - 1` blocks and `dropped` from the
/// `GAP_HOLD_SELECTIONS`-th while the eviction history holds them: neither
/// is carried or has a receipt, and `relay_one`'s balance and nonce and
/// `sender`'s messaging nonce are unchanged. With the gates inside the
/// chain's history and at the case's first block.
#[tokio::test]
async fn a_cycle_within_one_sponsor_above_a_missing_envelope_reads_dropped_for_both() {
    for (name, gate) in [
        ("inside history", Some(1)),
        ("at the case's block", Some(2)),
    ] {
        let p = Node::new(gate);
        set_up(&p, &[]).await;
        let (r, s) = (relay_one(), sender());
        let balance = p.server.get_balance(r.address().to_base58()).await.unwrap();
        let s0 = relayed(&relay_two(), 0, &s, 0);
        let r_s1 = relayed(&r, 1, &s, 1);
        let r_s2 = relayed(&r, 0, &s, 2);
        p.submit(&[&s0, &r_s1, &r_s2]);
        p.mempool.remove(&s0.hash());
        for n in 1..=(GAP_HOLD_SELECTIONS + 2) {
            p.tick().await;
            let expected = if n < GAP_HOLD_SELECTIONS {
                json!({ "kind": "pending" })
            } else {
                json!({ "kind": "dropped" })
            };
            for t in [&r_s1, &r_s2] {
                assert_eq!(p.status(t).await, expected, "{name}: block {n}");
                assert!(
                    !p.head().transactions.iter().any(|x| x.hash() == t.hash()),
                    "{name}: never carried, block {n}"
                );
            }
        }
        for t in [&r_s1, &r_s2] {
            assert!(
                ReceiptStore::new(&p.db).get(&t.hash()).unwrap().is_none(),
                "{name}: no receipt"
            );
        }
        assert_eq!(
            p.server.get_balance(r.address().to_base58()).await.unwrap(),
            balance,
            "{name}: nothing charged"
        );
        assert_eq!(
            p.server.get_nonce(r.address().to_base58()).await.unwrap(),
            0,
            "{name}"
        );
        assert_eq!(
            MessagingStore::new(&p.db)
                .get_sender_nonce(&s.address())
                .unwrap(),
            0,
            "{name}: no envelope nonce consumed"
        );
    }
}
