//! Blocks built by a producer that leaves a cycle's victim's dependents and
//! anything above a nonce gap in the pool import, below the messaging gates,
//! on a node that re-executes them, with the producer's state roots and
//! receipt rows, and blocks built by a producer that offers them import the
//! same way.
//!
//! The selection rules are node-local: they decide which valid block a
//! proposer builds, never what a block means. Below the gates (both unset, as
//! in production, or set above the chain's history) the case here is the
//! four-transaction cycle of two sponsors and a sponsor's nonce gap, which
//! this producer holds and a producer without those rules offers into
//! `InvalidNonce`.
//!
//! By default each configuration is produced and imported in this binary.
//! For the cross-binary check (a producer built without the rules, importing
//! this binary's blocks and the reverse) set `SUMCHAIN_SELECTION_COMPAT_OUT`
//! to a directory to write each configuration's blocks and the producer's
//! rows there, and `SUMCHAIN_SELECTION_COMPAT_IN` to such a directory to
//! import the blocks written there and compare the rows written with them.
use std::collections::HashMap;
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
    sponsored_send_v2_signing_preimage, Block, MessagingOperation, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload,
};
use sumchain_state::mempool::{InclusionGates, InclusionPolicy};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

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
    key(0x81)
}
fn admin() -> KeyPair {
    key(0x82)
}
fn recipient() -> KeyPair {
    key(0x83)
}
fn sponsor(i: u8) -> KeyPair {
    key(0x90 + i)
}
fn sender(i: u8) -> KeyPair {
    key(0xa0 + i)
}
fn bystander() -> KeyPair {
    key(0xb2)
}
fn accounts() -> Vec<KeyPair> {
    let mut all = vec![validator(), admin(), recipient(), bystander()];
    all.extend((0..4).map(sponsor));
    all.extend((0..4).map(sender));
    all
}

/// Both messaging gates unset, as in production, or set above every block
/// produced here.
fn below_the_gates() -> Vec<(&'static str, Option<u64>)> {
    vec![("absent", None), ("above-history", Some(1_000_000))]
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
        peer_protocol_declaration_required_from_height: gate.map(|_| 1),
        ..ChainParams::with_v2_enabled()
    };
    let alloc = accounts()
        .into_iter()
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

    async fn tick(&self) -> Block {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        let txs = self.mempool.select_for_block(1_000);
        self.engine.propose_block(txs).await.expect("a block")
    }

    /// The rows compared: each carried transaction's receipt, then every
    /// account's nonce and balance and every sender's messaging nonce.
    fn rows(&self, blocks: &[Block]) -> Vec<Vec<u8>> {
        let receipts = ReceiptStore::new(&self.db);
        let mut rows: Vec<Vec<u8>> = blocks
            .iter()
            .flat_map(|b| b.transactions.iter())
            .map(|t| bincode::serialize(&receipts.get(&t.hash()).unwrap()).unwrap())
            .collect();
        let messaging = MessagingStore::new(&self.db);
        for k in accounts() {
            let a = k.address();
            rows.push(
                bincode::serialize(&(
                    self.state.get_nonce(&a).unwrap(),
                    self.state.get_balance(&a).unwrap(),
                    messaging.get_sender_nonce(&a).unwrap(),
                ))
                .unwrap(),
            );
        }
        rows
    }
}

/// The case, produced by this binary's producer: set-up, then the cycle of
/// two sponsors (`r1` relays `u`'s envelope 1 at nonce 0 and `v`'s envelope 0
/// at nonce 1; `r2` relays `v`'s envelope 1 at nonce 0 and `u`'s envelope 0 at
/// nonce 1) and a third sponsor holding only its nonce 1; three blocks; then
/// each sponsor's nonce 0 filled, and two more blocks.
async fn produce(node: &Node) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut setup = vec![messaging(
        &admin(),
        0,
        1_000,
        MessagingOperation::SetSponsorshipEnabled,
        &SetSponsorshipEnabledData { enabled: true },
    )];
    for k in (0..4).map(sender) {
        setup.push(messaging(
            &k,
            0,
            1_000,
            MessagingOperation::RegisterPublicKey,
            &RegisterPublicKeyData { public_key: pk(&k) },
        ));
    }
    node.submit(&setup.iter().collect::<Vec<_>>());
    blocks.push(node.tick().await);

    let (r1, r2, r3) = (sponsor(0), sponsor(1), sponsor(2));
    let (u, v, w) = (sender(0), sender(1), sender(2));
    let case = [
        relayed(&r2, 1, 2_400, &u, 0),
        relayed(&r1, 1, 2_300, &v, 0),
        relayed(&r1, 0, 2_200, &u, 1),
        relayed(&r2, 0, 2_100, &v, 1),
        relayed(&r3, 1, 2_000, &w, 0),
        transfer(&bystander(), 0, 1_000),
    ];
    node.submit(&case.iter().collect::<Vec<_>>());
    for _ in 0..3 {
        blocks.push(node.tick().await);
    }
    let fills: Vec<SignedTransaction> = [&r1, &r2, &r3]
        .into_iter()
        .map(|s| transfer(s, 0, 1_000))
        .collect();
    node.submit(&fills.iter().collect::<Vec<_>>());
    for _ in 0..2 {
        blocks.push(node.tick().await);
    }
    blocks
}

/// Imports `blocks` into a fresh node: each must import, at the producer's
/// state root, and the importer's rows must be `rows`.
async fn import_and_compare(g: &Genesis, blocks: &[Block], rows: &[Vec<u8>], label: &str) {
    let importer = Node::new(g);
    for b in blocks {
        importer
            .engine
            .import_block(b.clone())
            .await
            .unwrap_or_else(|e| panic!("{label}: block {} imports: {e}", b.height()));
        assert_eq!(importer.engine.best_block_hash(), b.hash(), "{label}");
    }
    assert_eq!(
        importer.engine.current_height(),
        blocks.last().unwrap().height(),
        "{label}"
    );
    assert_eq!(importer.rows(blocks), rows, "{label}: rows");
}

fn write(path: &std::path::Path, blocks: &[Block], rows: &[Vec<u8>]) {
    let encoded: Vec<Vec<u8>> = blocks.iter().map(|b| b.to_bytes()).collect();
    std::fs::write(path, bincode::serialize(&(encoded, rows)).unwrap()).unwrap();
}

fn read(path: &std::path::Path) -> (Vec<Block>, Vec<Vec<u8>>) {
    let (encoded, rows): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
        bincode::deserialize(&std::fs::read(path).unwrap()).unwrap();
    let blocks = encoded
        .iter()
        .map(|b| Block::from_bytes(b).unwrap())
        .collect();
    (blocks, rows)
}

/// Below the gates, the blocks this producer builds import on a fresh node
/// with the producer's roots and rows; with the environment set, blocks and
/// rows are also written for, or read from, a producer built without the
/// selection rules.
#[tokio::test]
async fn blocks_built_with_and_without_the_selection_rules_import_alike() {
    let out = std::env::var_os("SUMCHAIN_SELECTION_COMPAT_OUT").map(std::path::PathBuf::from);
    let input = std::env::var_os("SUMCHAIN_SELECTION_COMPAT_IN").map(std::path::PathBuf::from);
    for (name, gate) in below_the_gates() {
        let g = genesis(gate);
        let producer = Node::new(&g);
        let blocks = produce(&producer).await;
        let rows = producer.rows(&blocks);
        for b in &blocks {
            println!(
                "selection compat {name}: produced block {} {} root {} carrying {}",
                b.height(),
                b.hash(),
                b.header.state_root,
                b.transactions.len()
            );
        }
        import_and_compare(&g, &blocks, &rows, &format!("{name}, this producer")).await;
        if let Some(dir) = &out {
            write(&dir.join(format!("{name}.bin")), &blocks, &rows);
        }
        if let Some(dir) = &input {
            let (theirs, their_rows) = read(&dir.join(format!("{name}.bin")));
            for b in &theirs {
                println!(
                    "selection compat {name}: importing block {} {} root {} carrying {}",
                    b.height(),
                    b.hash(),
                    b.header.state_root,
                    b.transactions.len()
                );
            }
            import_and_compare(
                &g,
                &theirs,
                &their_rows,
                &format!("{name}, the other producer"),
            )
            .await;
        }
    }
}
