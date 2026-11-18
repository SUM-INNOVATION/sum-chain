//! A wait on another account counts toward `CROSS_ACCOUNT_WAIT_SELECTIONS`
//! only while it is a hold, on a real producer.
//!
//! An envelope left out only because the block is full — its named sender's
//! earlier envelope is in the pool, held by nothing, just below the block's
//! limit — waits on nothing but room, and is never released for it. Its count
//! stays at zero, so when the wait later becomes a hold — its earlier
//! envelope leaves the pool, or is left above its own relay's gap — it gets
//! the whole bound before it is carried to its refusal.
//!
//! Runs where the accounting gate is open at the case's block, under the
//! gate configurations of [`matrix`].
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
    sponsored_send_v2_signing_preimage, Block, Hash, MessagingOperation, Receipt,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::mempool::{
    advances_nonce_below_accounting_gate, InclusionGates, InclusionPolicy,
    CROSS_ACCOUNT_WAIT_SELECTIONS,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
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
    let validators = [validator()];
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
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

fn carries(b: &Block, t: &SignedTransaction) -> bool {
    b.transactions.iter().any(|x| x.hash() == t.hash())
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

/// How many of this node's selections an envelope waits on another account
/// before it is carried to its refusal.
const BOUND: u64 = CROSS_ACCOUNT_WAIT_SELECTIONS as u64;

/// A block of at most `LIMIT` transactions.
const LIMIT: usize = 4;

impl Node {
    /// One production tick with a block limit of `limit`.
    async fn tick_within(&self, limit: usize) -> Block {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        let txs = self.mempool.select_for_block(limit);
        self.engine.propose_block(txs).await.expect("a block")
    }
}

/// What turns the wait for room into a hold.
#[derive(Clone, Copy, Debug)]
enum Hold {
    /// `s`'s envelope 0 leaves the pool (as a lowest-fee eviction would
    /// remove it): envelope 1 waits on an envelope no account carries.
    Missing,
    /// `r1`'s transaction at its nonce 0, ahead of `s`'s envelope 0 at `r1`'s
    /// nonce 1, leaves the pool: envelope 0 is above `r1`'s gap, and envelope
    /// 1 waits on another account's hold.
    BehindAnotherAccount,
}

/// For both causes of a hold. A block limit of 4. `s`'s envelope 0 goes
/// through `r1` at a low fee (behind `r1`'s own transfer at its nonce 0, at
/// a lower fee, for [`Hold::BehindAnotherAccount`]); `s`'s envelope 1 goes
/// through `r2` at a high fee. Before each of four blocks four funded
/// transfers at a middle fee fill the block, so `s`'s envelope 0 stays below
/// the limit and its envelope 1 waits behind it for room only: neither is
/// carried, and envelope 1's count toward the cross-account bound stays at
/// zero through all four. Then the wait becomes a hold, and `r2` sends its
/// next transaction behind its envelope. Envelope 1 has the whole bound of
/// its row in the selection oracle. Behind another account (row 4): it is
/// not carried at the first or the second held selection (its count 1, then
/// 2), and is carried to its charged refusal at the third, with `r2`'s next
/// transaction behind it. Missing (row 3): it is never counted toward the
/// cross-account bound; its gap-hold count is 1, then 2, and at the third
/// held selection it is evicted, never carried or charged, and `r2`'s next
/// transaction is not carried. Where both messaging gates are open at the
/// case's block.
#[tokio::test]
async fn a_wait_behind_a_full_block_is_not_counted_toward_the_cross_account_bound() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK) && g.verification.is_some_and(|v| v <= CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    assert!(BOUND >= 3);
    for gates in configs {
        for hold in [Hold::Missing, Hold::BehindAnotherAccount] {
            let name = format!("{}, {hold:?}", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let (r1, r2, s) = (sponsor(0), sponsor(1), sender(0));
            let r1_t = transfer(&r1, relay_nonce(&node, &r1), 1_000);
            if matches!(hold, Hold::BehindAnotherAccount) {
                node.submit(&[&r1_t]);
            }
            let r1_s0 = relayed(&r1, relay_nonce(&node, &r1), 1_500, &s, 0);
            node.submit(&[&r1_s0]);
            let r2_s1 = relayed(&r2, relay_nonce(&node, &r2), 5_000, &s, 1);
            node.submit(&[&r2_s1]);
            let fillers = [bystander(), unrelated_sponsor(), sponsor(2), sponsor(3)];
            for round in 1..=4 {
                for k in &fillers {
                    let t = transfer(k, relay_nonce(&node, k), 3_000);
                    node.submit(&[&t]);
                }
                let b = node.tick_within(LIMIT).await;
                assert_eq!(
                    b.transactions.len(),
                    LIMIT,
                    "{name}: round {round}: a full block"
                );
                for t in [&r1_t, &r1_s0, &r2_s1] {
                    assert!(!carries(&b, t), "{name}: round {round}");
                }
                assert_eq!(
                    node.mempool.cross_account_wait_count(&r2_s1.hash()),
                    0,
                    "{name}: round {round}: a wait for room is not counted"
                );
            }
            // The wait becomes a hold; `r2` sends its next transaction.
            match hold {
                Hold::Missing => node.mempool.remove(&r1_s0.hash()),
                Hold::BehindAnotherAccount => node.mempool.remove(&r1_t.hash()),
            };
            let r2_t = transfer(&r2, relay_nonce(&node, &r2), 4_000);
            node.submit(&[&r2_t]);
            let missing = matches!(hold, Hold::Missing);
            for n in 1..BOUND {
                let b = node.tick_within(LIMIT).await;
                assert!(
                    !carries(&b, &r2_s1),
                    "{name}: not released at held selection {n}"
                );
                assert_eq!(
                    node.mempool.cross_account_wait_count(&r2_s1.hash()),
                    if missing { 0 } else { n as u32 },
                    "{name}: held selection {n}"
                );
                if missing {
                    assert_eq!(
                        node.mempool.gap_hold_count(&r2_s1.hash()),
                        n as u32,
                        "{name}: row 3, held selection {n}"
                    );
                }
                assert!(node.receipt(&r2_s1).is_none(), "{name}");
            }
            let b = node.tick_within(LIMIT).await;
            if missing {
                for t in [&r2_s1, &r2_t] {
                    assert!(!carries(&b, t), "{name}: row 3, never carried");
                    assert!(node.receipt(t).is_none(), "{name}: nothing charged");
                }
                assert!(
                    !node.mempool.contains(&r2_s1.hash()),
                    "{name}: evicted at held selection {BOUND}"
                );
                continue;
            }
            assert!(
                carries(&b, &r2_s1),
                "{name}: released at held selection {BOUND}"
            );
            assert!(carries(&b, &r2_t), "{name}: r2's next transaction follows");
            let r = node.receipt(&r2_s1).expect("carried");
            assert!(
                matches!(r.status, TxStatus::Failed(_)),
                "{name}: {:?}",
                r.status
            );
            assert!(r.fee_paid > 0, "{name}: one fee, to the sponsor");
            assert_eq!(node.status(&r2_t), Some(TxStatus::Success), "{name}");
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
