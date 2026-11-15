//! A node that only imports blocks holds what selection holds, evicts it at
//! the same bound, and releases its pool's places, as a producer does; across
//! a chain switch too.
//!
//! A gapped transaction leaves a pool in its `GAP_HOLD_SELECTIONS`-th block,
//! counted once per block on every node: by the selection of a node that
//! proposes the block, and otherwise at the head the node commits (a block it
//! imports, a chain switch's new head, counted once). On main such a
//! transaction leaves a follower's pool when the producer's block carrying
//! its `InvalidNonce` is imported; here no block names it, so the follower
//! must count and evict it itself.
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
    sponsored_send_v2_signing_preimage, Block, BlockHeader, Hash, MessagingOperation, Receipt,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::mempool::{
    advances_nonce_below_accounting_gate, InclusionGates, InclusionPolicy,
    CROSS_ACCOUNT_WAIT_SELECTIONS, GAP_HOLD_SELECTIONS,
};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateError, StateManager};
use sumchain_storage::{Database, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// Senders registered by `set_up`.
const SENDERS: u8 = 4;
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
    genesis_with(gates, &[validator()])
}

/// [`genesis`], with `validators` as the validator set.
fn genesis_with(gates: Gates, validators: &[KeyPair]) -> Genesis {
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

    /// A node on `g` that never proposes (no validator key), wired as
    /// `Node::new` wires its pool: it only imports blocks.
    fn follower(
        g: Genesis,
        gates: Gates,
        tune: impl FnOnce(MempoolConfig) -> MempoolConfig,
    ) -> Self {
        Self::build(g, gates, None, tune)
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

    /// `t` offered to the pool: whether admission takes it.
    fn try_submit(&self, t: &SignedTransaction) -> Result<(), StateError> {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        self.mempool.add(t.clone()).map(|_| ())
    }

    /// `b`, imported as gossip delivers it, with the pool's view of the
    /// height moved to the new head as the node's event loop moves it.
    async fn import(&self, b: &Block) {
        self.engine.import_block(b.clone()).await.expect("imports");
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
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

/// How many blocks a transaction is held above a gap before it is evicted.
const GAP_BOUND: u64 = GAP_HOLD_SELECTIONS as u64;

/// How many of this node's selections an envelope waits on another account
/// before it is carried to its refusal.
const BOUND: u64 = CROSS_ACCOUNT_WAIT_SELECTIONS as u64;

/// A producer `p` and a follower `q` (no validator key, a pool of 32
/// places) on one genesis. Both pools take the same 32 transactions above a
/// gap: three unfunded keys' nonces 1 to 10, `s`'s envelope 0 through `r1`
/// at `r1`'s nonce 1 (nothing at its nonce 0), and `s`'s envelope 1 through
/// `r2`. `p` produces, `q` imports. On `q`, as on `p`: held for
/// `GAP_BOUND - 1` blocks, with `q`'s pool full (a fresh honest transfer is
/// refused, as admission refuses it); in the `GAP_BOUND`-th block the 30
/// transfers and `r1`'s envelope are gone from `q`'s pool, none of the 31
/// with a receipt; `s`'s envelope 1 is gone by the block after (from the
/// accounting gate `p` carries it to its refusal at its cross-account bound
/// and `q` drops it with that block, as it is not stranded with `r1`'s;
/// below the gate both evict it with `r1`'s), and `q` admits the honest
/// transfer. At every configuration.
#[tokio::test]
async fn a_node_that_only_imports_blocks_evicts_at_the_same_bound() {
    for gates in matrix() {
        let name = gates.name;
        let p = Node::new(gates);
        let q = Node::follower(genesis(gates), gates, |c| MempoolConfig {
            max_size: 32,
            ..c
        });
        p.set_up().await;
        for h in 1..=p.engine.current_height() {
            q.import(&p.engine.get_block_by_height(h).unwrap()).await;
        }
        let (r1, r2, s) = (sponsor(0), sponsor(1), sender(0));
        let mut gapped = Vec::new();
        for a in 0..3u8 {
            let k = stranger(0x20 + a);
            for n in 1..=10u64 {
                gapped.push(transfer_amount(&k, n, 1_000_000, 1));
            }
        }
        let r1_s0 = relayed(&r1, 1, 2_000, &s, 0);
        let r2_s1 = relayed(&r2, relay_nonce(&p, &r2), 2_000, &s, 1);
        for node in [&p, &q] {
            node.submit(&gapped.iter().collect::<Vec<_>>());
            node.submit(&[&r1_s0, &r2_s1]);
        }
        assert_eq!(q.mempool.len(), 32, "{name}: q's pool is full");
        let honest = transfer(&unrelated_user(), relay_nonce(&q, &unrelated_user()), 1_000);
        for n in 1..=(GAP_BOUND + 1) {
            let b = p.tick().await;
            q.import(&b).await;
            let held = n < GAP_BOUND;
            assert!(
                gapped
                    .iter()
                    .chain([&r1_s0])
                    .all(|t| q.held(t) == held && q.receipt(t).is_none()),
                "{name}: head {n} after the case"
            );
            if held {
                assert!(
                    matches!(q.try_submit(&honest), Err(StateError::MempoolFull)),
                    "{name}: q's pool is still full at head {n}"
                );
                assert!(q.held(&r2_s1), "{name}: head {n}");
            }
            assert_eq!(
                gapped.iter().chain([&r1_s0]).filter(|t| p.held(t)).count(),
                if held { 31 } else { 0 },
                "{name}: the producer at head {n}"
            );
        }
        assert!(!q.held(&r2_s1), "{name}: gone by the end");
        q.try_submit(&honest)
            .unwrap_or_else(|e| panic!("{name}: q admits it once the places are free: {e}"));
        // From the accounting gate `p` carries `s`'s envelope 1 at its
        // cross-account bound (the gap bound neither evicts nor strands it);
        // below the gate it was evicted with `r1`'s.
        assert_eq!(
            p.receipt(&r2_s1).is_some(),
            gates.accounting_at(CASE_BLOCK + 1),
            "{name}"
        );
    }
}

/// Where the gap bound comes first, the cross-account bound still governs.
/// The accounting gate opens one block after the case's first (`H-1`). A
/// full pool (6 places) evicts `v`'s envelope 0 (through `r1`, the lowest
/// fee) for a gapped transfer at a higher fee; `v`'s envelope 1, relayed by
/// `r2` at its nonce 0, is then beyond `v`'s first missing envelope nonce.
/// Its gap-hold count starts at the case's first block, below the gate; its
/// wait on another account is counted only from the gate's first selection.
/// In the `GAP_BOUND`-th block the gapped transfers are evicted but the
/// envelope stays, and at its `BOUND`-th counted selection it is carried to
/// its charged refusal. At both configurations where the accounting gate
/// opens at `H+1` (the verification gate is open by then).
#[tokio::test]
async fn where_the_gap_bound_comes_first_the_wait_on_another_account_still_ends_in_a_refusal() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| ["both at H-1", "0x1049 at H-1"].contains(&g.name))
        .collect();
    assert_eq!(configs.len(), 2);
    for gates in configs {
        let name = gates.name;
        let node = Node::with_pool(gates, |c| MempoolConfig { max_size: 6, ..c });
        node.set_up().await;
        let (r1, r2, v) = (sponsor(0), sponsor(1), sender(1));
        let r1_v0 = relayed(&r1, 0, 1_000, &v, 0);
        let r2_v1 = relayed(&r2, 0, 2_200, &v, 1);
        node.submit(&[&r1_v0, &r2_v1]);
        let k = stranger(0x10);
        let gapped: Vec<SignedTransaction> = (1..=5u64)
            .map(|n| transfer_amount(&k, n, 1_000_000_000, 1))
            .collect();
        node.submit(&gapped[..4].iter().collect::<Vec<_>>());
        assert_eq!(node.mempool.len(), 6, "{name}: the pool is full");
        node.submit(&[&gapped[4]]);
        assert!(!node.held(&r1_v0), "{name}: evicted for a higher fee");
        assert!(!gates.accounting_at(CASE_BLOCK) && gates.accounting_at(CASE_BLOCK + 1));
        for n in 1..=GAP_BOUND {
            let b = node.tick().await;
            assert!(b.transactions.is_empty(), "{name}: head {n}");
        }
        assert!(
            gapped.iter().all(|t| !node.held(t)),
            "{name}: evicted at the gap bound"
        );
        assert!(
            node.held(&r2_v1),
            "{name}: governed by the cross-account bound"
        );
        assert_eq!(
            node.mempool.gap_hold_count(&r2_v1.hash()),
            GAP_BOUND as u32,
            "{name}"
        );
        let mut carried_at = None;
        for _ in 0..BOUND {
            let b = node.tick().await;
            if carries(&b, &r2_v1) {
                carried_at = Some(b.height());
                break;
            }
        }
        let at = carried_at.expect("carried within the cross-account bound");
        assert_eq!(
            at,
            CASE_BLOCK + 1 + BOUND - 1,
            "{name}: at its BOUND-th counted selection"
        );
        let r = node.receipt(&r2_v1).expect("carried");
        assert!(
            matches!(r.status, TxStatus::Failed(_)),
            "{name}: {:?}",
            r.status
        );
        assert!(r.fee_paid > 0, "{name}: one fee, to the sponsor");
    }
}

/// A block builder off the nodes under test: its own database over the same
/// genesis, real execution (as `sponsored_capacity_reorg.rs` builds them).
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

/// A chain switch on a node that only imports. Two validators; two off-node
/// builders produce competing branches. The follower holds `g` (a funded
/// account's nonce 1, its nonce 0 never sent, so the switch's revalidation
/// keeps it), `x`'s nonces 0 and 1 and `y`'s nonce 1 (`y`'s nonce 0 is not in
/// its pool). Branch A carries `x`'s nonce 0 in its first block; the
/// follower imports A's two blocks, and `g` and `y`'s nonce 1 are counted at
/// each. Branch B carries `y`'s nonce 0 in its first block; its blocks that
/// lose fork choice count nothing, and the one that wins it switches the
/// chain. At the switch (one new head): `g` reaches the bound and is evicted
/// with no receipt; `y`'s nonce 1 is no longer above a gap, so its count is
/// gone and it stays; `x`'s nonce 0 is offered back and both of `x`'s are
/// held, counted from nothing. One more of B's blocks changes nothing of
/// that. With the gates absent and inside the chain's history.
#[tokio::test]
async fn a_chain_switch_counts_at_its_new_head_and_keeps_what_the_new_branch_unblocks() {
    for gates in matrix()
        .into_iter()
        .filter(|g| ["absent", "inside history"].contains(&g.name))
    {
        let name = gates.name;
        let validators = [validator(), key(0x84)];
        let g = genesis_with(gates, &validators);
        let q = Node::follower(g.clone(), gates, |c| c);
        let mut a = Builder::new(&g, &validators, 0);
        let mut b = Builder::new(&g, &validators, 1);
        let (x, y) = (sponsor(2), sponsor(3));
        let stray = transfer(&sponsor(0), 1, 1_000);
        let (x0, x1, y0, y1) = (
            transfer(&x, 0, 1_000),
            transfer(&x, 1, 1_000),
            transfer(&y, 0, 1_000),
            transfer(&y, 1, 1_000),
        );
        q.submit(&[&stray, &x0, &x1, &y1]);
        let count = |t: &SignedTransaction| q.mempool.gap_hold_count(&t.hash());

        let a1 = a.produce(vec![x0.clone()]);
        q.import(&a1).await;
        assert!(!q.held(&x0), "{name}: carried by A");
        assert_eq!((count(&stray), count(&y1), count(&x1)), (1, 1, 0), "{name}");
        let a2 = a.produce(Vec::new());
        q.import(&a2).await;
        assert_eq!((count(&stray), count(&y1)), (2, 2), "{name}");

        let b1 = b.produce(vec![y0.clone()]);
        let b2 = b.produce(Vec::new());
        let b3 = b.produce(Vec::new());
        // B's blocks lose fork choice until one wins it: no head moves and
        // nothing is counted for them. The block that wins it switches the
        // chain, and the switch is counted once, at its new head.
        let mut switched = false;
        for blk in [&b1, &b2, &b3] {
            q.import(blk).await;
            if q.engine.best_block_hash() != blk.hash() {
                assert_eq!(q.engine.best_block_hash(), a2.hash(), "{name}");
                assert!(q.held(&stray), "{name}: a losing block counts nothing");
                assert_eq!(count(&stray), 2, "{name}");
                continue;
            }
            if !switched {
                switched = true;
                assert!(!q.held(&stray), "{name}: evicted at the switch's head");
                assert!(q.receipt(&stray).is_none(), "{name}");
                for t in [&y1, &x0, &x1] {
                    assert!(q.held(t), "{name}");
                    assert_eq!(count(t), 0, "{name}");
                }
            }
        }
        assert!(switched, "{name}: switched to B");
        assert_eq!(q.engine.best_block_hash(), b3.hash(), "{name}");
        for t in [&y1, &x0, &x1] {
            assert!(q.held(t), "{name}");
            assert_eq!(count(t), 0, "{name}");
        }
        let b4 = b.produce(Vec::new());
        q.import(&b4).await;
        for t in [&y1, &x0, &x1] {
            assert!(q.held(t), "{name}");
            assert_eq!(count(t), 0, "{name}");
        }
    }
}
