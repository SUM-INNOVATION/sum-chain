//! What a client reads for a transaction the producer's selection evicts
//! above a gap (`GAP_HOLD_SELECTIONS`), on the node that evicts it.
//!
//! The node under test runs a `PoAEngine` and serves the RPC over the same
//! database and pool. A transfer above its account's nonce gap and an
//! envelope above its relay's gap are held for `GAP_HOLD_SELECTIONS - 1` of
//! this node's selections and evicted at the next, with no receipt. At every
//! height until then `chain_getTransactionStatus` reports `pending` and
//! `sum_getTransaction` finds the transaction; from the eviction on the
//! status is `dropped` (never `pending` again; this node's local
//! observation, from its bounded eviction history) and the transaction is
//! not found. The envelope has no `messaging_getSponsoredEnvelope` answer at
//! any height, and the sender's messaging nonce stays where it was: those,
//! not `dropped`, tell a client the message was not delivered.
//!
//! The sender's later envelope, through another relay, goes with it below
//! the accounting gate (the gates absent): evicted, `dropped`. From the gate
//! (the gates inside the chain's history) it waits on the other relay's
//! account and is carried to its refusal at the
//! `CROSS_ACCOUNT_WAIT_SELECTIONS`-th selection instead: `failed`, at the
//! block that carries it.

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
    sponsored_send_v2_signing_preimage, MessagingOperation, SignedTransaction, SponsoredMessage,
    TransactionV2, TxPayload, TxStatus,
};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::mempool::{
    InclusionGates, InclusionPolicy, CROSS_ACCOUNT_WAIT_SELECTIONS, GAP_HOLD_SELECTIONS,
};
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

    async fn envelope_answer(&self, t: &SignedTransaction) -> bool {
        self.server
            .messaging_get_sponsored_envelope(t.hash().to_hex())
            .await
            .unwrap()
            .is_some()
    }

    async fn sender_nonce(&self) -> Value {
        serde_json::to_value(
            self.server
                .messaging_get_sender_nonce(sender().address().to_base58())
                .await
                .unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn an_evicted_transaction_is_never_reported_pending_again() {
    for (name, gate) in [("absent", None), ("inside history", Some(1))] {
        let node = Node::new(gate);
        // Block 1: sponsorship on, the sender registered.
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
        node.submit(&setup.iter().collect::<Vec<_>>());
        node.tick().await;
        for t in &setup {
            let r = ReceiptStore::new(&node.db).get(&t.hash()).unwrap();
            assert_eq!(r.map(|r| r.status), Some(TxStatus::Success), "{name}");
        }
        let nonce_before = node.sender_nonce().await;

        // The user's nonce 0 never comes; relay one's nonce 0 never comes.
        let gapped = transfer(&user(), 1);
        let above = relayed(&relay_one(), 1, 0);
        let later = relayed(&relay_two(), 0, 1);
        let case = [&gapped, &above, &later];
        node.submit(&case);
        for t in case {
            assert_eq!(node.status(t).await, json!({ "kind": "pending" }), "{name}");
            assert!(node.found(t).await, "{name}");
        }

        assert_eq!(CROSS_ACCOUNT_WAIT_SELECTIONS, GAP_HOLD_SELECTIONS);
        let mut refused_at = None;
        for n in 1..=(GAP_HOLD_SELECTIONS + 2) {
            node.tick().await;
            let height = node.engine.current_height();
            let held = n < GAP_HOLD_SELECTIONS;
            if gate.is_some() && n == CROSS_ACCOUNT_WAIT_SELECTIONS {
                refused_at = Some(height);
            }
            if let Some(at) = refused_at {
                let s = node.status(&later).await;
                assert_eq!(s["kind"], "failed", "{name}: height {height}: {s}");
                assert_eq!(s["block_height"], at, "{name}: height {height}");
                let r = ReceiptStore::new(&node.db).get(&later.hash()).unwrap();
                assert!(r.is_some_and(|r| r.fee_paid > 0), "{name}: charged");
            }
            let evicted: &[&SignedTransaction] = if gate.is_some() {
                &[&gapped, &above]
            } else {
                &case
            };
            for &t in evicted {
                let expected = if held {
                    json!({ "kind": "pending" })
                } else {
                    json!({ "kind": "dropped" })
                };
                assert_eq!(
                    node.status(t).await,
                    expected,
                    "{name}: height {height}, selection {n}"
                );
                assert_eq!(node.found(t).await, held, "{name}: height {height}");
                assert!(
                    ReceiptStore::new(&node.db)
                        .get(&t.hash())
                        .unwrap()
                        .is_none(),
                    "{name}: height {height}: no receipt"
                );
            }
            for t in [&above, &later] {
                assert!(!node.envelope_answer(t).await, "{name}: height {height}");
            }
            if gate.is_some() && refused_at.is_none() {
                assert_eq!(
                    node.status(&later).await,
                    json!({ "kind": "pending" }),
                    "{name}: height {height}"
                );
            }
            assert_eq!(node.sender_nonce().await, nonce_before, "{name}");
        }
    }
}
