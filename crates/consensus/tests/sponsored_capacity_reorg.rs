//! A node's per-sender accounting of sponsored envelopes across chain switches.
//!
//! The pool counts an envelope its inclusion policy admitted against the
//! sender the envelope NAMES, and keeps a per-relay count of such envelopes so
//! that the relaying account's own transactions are held to the limit
//! without them. A chain switch moves envelopes in both directions: the ones
//! only the abandoned branch carried are offered back through `Mempool::add`
//! (`reconcile_mempool_after_switch`), and the ones the adopted branch carries
//! are removed. Each must be counted exactly once while it is held — no place
//! leaked, none counted twice.
//!
//! Two off-node builders, each on its own database over the same genesis,
//! produce the competing branches; the node under test only imports. Same
//! shape as `proposal_policy_reorg.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, RegisterPublicKeyData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Block, BlockHeader, Hash, MessagingOperation, SignedTransaction, SponsoredMessage,
    TransactionV2, TxPayload,
};
use sumchain_state::mempool::InclusionPolicy;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}
fn admin() -> KeyPair {
    key(20)
}
fn relayer() -> KeyPair {
    key(21)
}
fn sender() -> KeyPair {
    key(22)
}
fn recipient() -> KeyPair {
    key(23)
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn genesis(validators: &[KeyPair]) -> Genesis {
    let mut params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_v2_enabled()
    };
    params.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    let mut alloc = HashMap::new();
    for k in validators
        .iter()
        .chain([admin(), relayer(), sender(), recipient()].iter())
    {
        alloc.insert(k.address().to_base58(), 1_000_000_000_000u128);
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
    operation: MessagingOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    signed(
        kp,
        0,
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
    let mut v = header.to_bytes().to_vec();
    v.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    v
}

/// `sender()`'s envelope at messaging nonce `nonce`, signed by the sender
/// over the relay preimage and wrapped by `relayer()` at its committed account
/// nonce (0: relaying advances no account nonce).
fn envelope(nonce: u64) -> SignedTransaction {
    let user = sender();
    let rh = recipient_hash(&recipient().address());
    let message_data = valid_message(rh);
    let expiry = u64::MAX;
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        nonce,
        expiry,
        hex::encode(rh),
        hex::encode(Hash::hash(&message_data).as_bytes())
    );
    let m = SponsoredMessage {
        message_data,
        recipient_hash: rh,
        signature: *sign(preimage.as_bytes(), user.private_key()).as_bytes(),
        sender_pubkey: pk(&user),
        nonce,
        expiry,
        koppa_amount: None,
    };
    signed(
        &relayer(),
        0,
        1_000_000,
        TxPayload::Messaging(MessagingTxData {
            operation: MessagingOperation::SendMessage,
            data: bincode::serialize(&m).unwrap(),
        }),
    )
}

/// A block builder off the node under test: its own database, real execution.
struct Builder {
    _dir: TempDir,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    keys: Vec<KeyPair>,
    validators: Vec<[u8; 32]>,
    head: Block,
    salt: u64,
}

impl Builder {
    fn new(g: &Genesis, keys: &[KeyPair], salt: u64) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            g,
            None,
        )
        .unwrap();
        let head = engine.init_genesis(g).unwrap();
        drop(engine);
        let executor = BlockExecutor::new(state.clone(), db.clone(), g.params.clone());
        Self {
            _dir: dir,
            state,
            executor,
            keys: keys
                .iter()
                .map(|k| KeyPair::from_bytes(*k.private_key().as_bytes()))
                .collect(),
            validators: g.validator_pubkeys().unwrap(),
            head,
            salt,
        }
    }

    fn produce(&mut self, txs: Vec<SignedTransaction>) -> Block {
        let height = self.head.height() + 1;
        let want = self.validators[(height % self.validators.len() as u64) as usize];
        let proposer = self.keys.iter().find(|k| pk(k) == want).unwrap();
        let proposer = KeyPair::from_bytes(*proposer.private_key().as_bytes());
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10 + self.salt,
                Hash::ZERO,
                Hash::ZERO,
                pk(&proposer),
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &self.validators)
            .unwrap();
        b.header.state_root = exec.computed_root();
        let s = sign(b.header.signing_hash().as_bytes(), proposer.private_key());
        b.header.set_signature(*s.as_bytes());
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        b
    }
}

/// The node under test: a follower whose pool has the inclusion policy and a
/// per-sender allowance of two.
struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    mempool: Arc<Mempool>,
    engine: Arc<PoAEngine>,
}

impl Node {
    fn new(g: &Genesis) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                max_per_sender: 2,
                ..MempoolConfig::default()
            })
            .with_inclusion_policy(InclusionPolicy { db: db.clone() }),
        );
        let engine = Arc::new(PoAEngine::new(db.clone(), state, mempool.clone(), g, None).unwrap());
        engine.init_genesis(g).unwrap();
        Self {
            _dir: dir,
            db,
            mempool,
            engine,
        }
    }

    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.unwrap();
    }

    fn has_receipt(&self, tx: &SignedTransaction) -> bool {
        ReceiptStore::new(&self.db).contains(&tx.hash()).unwrap()
    }

    fn full(&self, tx: SignedTransaction) -> bool {
        matches!(self.mempool.add(tx), Err(StateError::MempoolFull))
    }
}

/// Branch A carries the sender's envelope 0; branch B does not. The node holds
/// envelopes 0 and 1, imports A (0 leaves the pool as included), switches to B
/// (0 is offered back and counted again), and switches back to A (0 leaves
/// again). After each move the sender's and the relayer's places are exactly
/// what the pool holds.
#[tokio::test]
async fn envelopes_moved_by_chain_switches_are_counted_once() {
    let validators = [key(1), key(2)];
    let g = genesis(&validators);
    let node = Node::new(&g);
    let mut a = Builder::new(&g, &validators, 0);
    let mut b = Builder::new(&g, &validators, 1);

    let setup = vec![
        messaging(
            &admin(),
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        ),
        messaging(
            &sender(),
            MessagingOperation::RegisterPublicKey,
            &RegisterPublicKeyData {
                public_key: pk(&sender()),
            },
        ),
    ];
    let (e0, e1, e2) = (envelope(0), envelope(1), envelope(2));

    // ── branch A: e0 is carried ─────────────────────────────────────────────
    let a1 = a.produce(setup.clone());
    node.import(&a1).await;
    node.mempool.add(e0.clone()).expect("e0");
    node.mempool.add(e1.clone()).expect("e1");
    let a2 = a.produce(vec![e0.clone()]);
    node.import(&a2).await;
    assert!(node.has_receipt(&e0));
    assert!(!node.mempool.contains(&e0.hash()), "removed as included");
    assert!(node.mempool.contains(&e1.hash()));

    // ── branch B wins: e0 comes back ────────────────────────────────────────
    let b1 = b.produce(setup.clone());
    let b2 = b.produce(Vec::new());
    let b3 = b.produce(Vec::new());
    for blk in [&b1, &b2, &b3] {
        node.import(blk).await;
    }
    assert_eq!(node.engine.best_block_hash(), b3.hash(), "switched to B");
    assert!(!node.has_receipt(&e0));
    assert!(
        node.mempool.contains(&e0.hash()),
        "offered back and admitted"
    );
    assert!(node.mempool.contains(&e1.hash()));
    assert!(
        node.full(e2.clone()),
        "the sender holds e0 and e1: exactly two places, e0 counted once"
    );
    node.mempool
        .add(transfer(&relayer(), 0))
        .expect("relayer's own");
    node.mempool
        .add(transfer(&relayer(), 1))
        .expect("relayer's own");
    assert!(
        node.full(transfer(&relayer(), 2)),
        "the relayer's own two fill its allowance: its two envelopes are \
         subtracted once each"
    );

    // ── branch A wins again: e0 leaves again ────────────────────────────────
    let a3 = a.produce(Vec::new());
    let a4 = a.produce(Vec::new());
    node.import(&a3).await;
    node.import(&a4).await;
    assert_eq!(
        node.engine.best_block_hash(),
        a4.hash(),
        "switched back to A"
    );
    assert!(node.has_receipt(&e0));
    assert!(
        !node.mempool.contains(&e0.hash()),
        "removed as included again"
    );
    node.mempool
        .add(e2.clone())
        .expect("e0's place came back to the sender");
    assert!(node.full(envelope(3)), "e1 and e2: two places");
    assert!(
        node.full(transfer(&relayer(), 2)),
        "still exactly the relayer's own two"
    );
    node.mempool.remove_batch(&[transfer(&relayer(), 0).hash()]);
    node.mempool
        .add(transfer(&relayer(), 2))
        .expect("one of the relayer's own places came back");
}
