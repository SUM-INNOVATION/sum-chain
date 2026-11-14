//! What a client reads, on a node that only imports blocks (an RPC or relay
//! node without a validator key), for a transaction the producer's selection
//! evicts above a gap (`GAP_HOLD_SELECTIONS`).
//!
//! The follower serves the RPC over its own database and pool and imports the
//! producer's blocks. A transfer above its account's nonce gap and an
//! envelope above its relay's gap are in both pools. At every height until
//! the `GAP_HOLD_SELECTIONS`-th head the follower reports them `pending` and
//! `sum_getTransaction` finds them; from that head on it reports `unknown`,
//! never `pending` again, and finds neither: no receipt was written, as on
//! the producer. With the gates absent and inside the chain's history.

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
    SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::mempool::{InclusionGates, InclusionPolicy, GAP_HOLD_SELECTIONS};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tempfile::TempDir;
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1;
const FUNDS: u128 = 1_000_000_000_000;
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

/// `sender`'s version-2 envelope at `envelope_nonce`, relayed by `relay` at
/// account nonce `nonce`.
fn relayed(relay: &KeyPair, nonce: u64, envelope_nonce: u64) -> SignedTransaction {
    let rh = recipient_hash(&recipient().address());
    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash: rh,
        ephemeral_pubkey: [2u8; 32],
    };
    let mut message_data = header.to_bytes().to_vec();
    message_data.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    message_data.extend_from_slice(&[0u8, 0u8]);
    message_data.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    let mut m = SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: pk(&sender()),
        nonce: envelope_nonce,
        expiry: NEVER,
        koppa_amount: None,
    };
    m.signature = *sign(
        &sponsored_send_v2_signing_preimage(CHAIN_ID, &m),
        sender().private_key(),
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
        Self::build(gate, Some(validator()))
    }

    /// A node that never proposes (no validator key): it only imports.
    fn follower(gate: Option<u64>) -> Self {
        Self::build(gate, None)
    }

    fn build(gate: Option<u64>, key: Option<KeyPair>) -> Self {
        let g = genesis(gate);
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

    async fn found(&self, t: &SignedTransaction) -> bool {
        self.server
            .sum_get_transaction(t.hash().to_hex())
            .await
            .unwrap()
            .is_some()
    }
}

#[tokio::test]
async fn a_node_that_only_imports_reports_the_eviction_at_the_same_head() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let p = Node::new(gate);
        let q = Node::follower(gate);
        let setup = [
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
        ];
        p.submit(&setup.iter().collect::<Vec<_>>());
        p.tick().await;
        q.import(&p.head()).await;
        for t in &setup {
            let r = ReceiptStore::new(&q.db).get(&t.hash()).unwrap();
            assert_eq!(r.map(|r| r.status), Some(TxStatus::Success), "{name}");
        }
        let gapped = transfer(&user(), 1);
        let above = relayed(&relay_one(), 1, 0);
        for node in [&p, &q] {
            node.submit(&[&gapped, &above]);
        }
        for t in [&gapped, &above] {
            assert_eq!(q.status(t).await, json!({ "kind": "pending" }), "{name}");
        }
        for n in 1..=(GAP_HOLD_SELECTIONS + 2) {
            p.tick().await;
            q.import(&p.head()).await;
            let height = q.engine.current_height();
            let held = n < GAP_HOLD_SELECTIONS;
            for t in [&gapped, &above] {
                let expected = if held {
                    json!({ "kind": "pending" })
                } else {
                    json!({ "kind": "unknown" })
                };
                assert_eq!(q.status(t).await, expected, "{name}: height {height}");
                assert_eq!(q.found(t).await, held, "{name}: height {height}");
                assert_eq!(
                    p.found(t).await,
                    held,
                    "{name}: the producer, height {height}"
                );
                assert!(
                    ReceiptStore::new(&q.db).get(&t.hash()).unwrap().is_none(),
                    "{name}: height {height}: no receipt"
                );
            }
        }
    }
}
