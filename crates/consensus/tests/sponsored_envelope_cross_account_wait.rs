//! From the messaging fee-and-nonce accounting gate on, a sponsored envelope
//! waits on another account's transaction for at most
//! `CROSS_ACCOUNT_WAIT_SELECTIONS` of this node's selections, on a real
//! producer, across the messaging gates.
//!
//! From the gate on every relayed envelope advances its sponsor's account
//! nonce, so an envelope that cannot be carried because its named sender's
//! earlier envelope is missing, or held with another account (above that
//! account's nonce gap, or with a cycle's victim), holds its own sponsor's
//! whole queue. The producer counts the selections in a row that leave such an
//! envelope out while every earlier transaction of its own account is
//! carried; at `CROSS_ACCOUNT_WAIT_SELECTIONS` of them it carries the envelope
//! at its place in its own account's sequence, where it takes its canonical
//! refusal (from the envelope verification gate a charged failed receipt;
//! below it, it executes out of its sender's sequence), and its account's
//! later transactions follow. The count lives in this node's pool only.
//! Below the accounting gate nothing is counted.
//!
//! The transaction the wait is on, above its own account's gap, is held
//! directly and is evicted at its `GAP_HOLD_SELECTIONS`-th selection (at
//! every height); each case says where that bound comes first.
//!
//! Every case runs under the 6 gate configurations of [`matrix`] (the two
//! messaging gates unset or at one height), or says why it runs under fewer;
//! the 8 that set the gates apart are refused at genesis
//! ([`apart_configurations`]).
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
    sponsored_send_v2_signing_preimage, Block, Hash, MessagingOperation, Receipt,
    SignedTransaction, SponsoredMessage, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::mempool::{
    InclusionGates, InclusionPolicy, CROSS_ACCOUNT_WAIT_SELECTIONS, GAP_HOLD_SELECTIONS,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
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
    let mut accounts = vec![
        validator(),
        admin(),
        recipient(),
        unrelated_sponsor(),
        unrelated_user(),
        bystander(),
    ];
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
        for k in (0..4).map(sender).chain([unrelated_user()]) {
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

    fn count(&self, t: &SignedTransaction) -> u32 {
        self.mempool.cross_account_wait_count(&t.hash())
    }

    fn gap_count(&self, t: &SignedTransaction) -> u32 {
        self.mempool.gap_hold_count(&t.hash())
    }

    /// `t` leaves the pool and is admitted again, as a re-sent transaction
    /// is: its counts start from nothing.
    fn resent(&self, t: &SignedTransaction) {
        self.mempool.remove(&t.hash());
        self.submit(&[t]);
    }

    /// One selection, as `run_block_producer` makes it, without proposing a
    /// block: what it offers.
    fn select(&self) -> Vec<Hash> {
        self.chain_height
            .store(self.engine.current_height(), Ordering::Relaxed);
        hashes(&self.mempool.select_for_block(1_000))
    }

    /// The node restarted on its own database: a new pool and engine, the
    /// chain loaded from disk, and the transactions the old pool held
    /// admitted again (as gossip would bring them back).
    fn restarted(self) -> Node {
        let g = genesis(self.gates);
        let pending = self.mempool.get_all();
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
        let engine = Arc::new(
            PoAEngine::new(
                self.db.clone(),
                self.state.clone(),
                mempool.clone(),
                &g,
                Some(validator()),
            )
            .unwrap(),
        );
        engine.load_chain().unwrap();
        let node = Node {
            _dir: self._dir,
            db: self.db,
            state: self.state,
            mempool,
            engine,
            chain_height: self.chain_height,
            gates: self.gates,
        };
        // Admitted again in passes, as gossip brings them back: an envelope
        // ahead of its sender's pending sequence is admitted once the one
        // before it is.
        node.chain_height
            .store(node.engine.current_height(), Ordering::Relaxed);
        let mut pending = pending;
        while !pending.is_empty() {
            let before = pending.len();
            pending.retain(|tx| node.mempool.add(tx.clone()).is_err());
            assert!(
                pending.len() < before,
                "the pool takes its transactions back"
            );
        }
        node
    }
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

const K: u32 = CROSS_ACCOUNT_WAIT_SELECTIONS;
const B: u32 = GAP_HOLD_SELECTIONS;

/// The first block, from the case's, at which the accounting gate is open.
fn first_open(gates: &Gates) -> Option<u64> {
    (CASE_BLOCK..CASE_BLOCK + 20).find(|h| gates.accounting_at(*h))
}

fn carries(b: &Block, t: &SignedTransaction) -> bool {
    b.transactions.iter().any(|x| x.hash() == t.hash())
}

/// A wait on another account, with both causes. `r1` relays `u`'s envelope
/// 1 at nonce 0 and `v`'s envelope 0 at nonce 1; `r2` relays `v`'s envelope 1
/// at nonce 0 and `u`'s envelope 0 at nonce 1 (a cycle, whose victim is
/// `r2_v1`); `r3` relays `v`'s envelope 2 at nonce 0 and sends a transfer at
/// nonce 1. Nobody fills `r2`'s nonce 0 and `v` never sends its envelope 1
/// again. Where the accounting gate is open, from the first block at the gate
/// (the selection oracle's rows 4 and 3): `r1`'s queue waits behind `r2`'s
/// gap through `u`'s envelope 0, which is in the pool (row 4), counted once
/// per block; at the `K`-th block `u`'s envelope 1 is carried to its refusal
/// (charged, from the verification gate) or executes out of sequence (below
/// it), and `r1`'s next transaction follows in the same block. `r3`'s
/// envelope for `v` has `v`'s envelope 1, the cycle's victim, missing (row 3):
/// it is never counted, carried or charged, and is evicted within the gap
/// bound, leaving `r3`'s transfer above `r3`'s own gap (row 1), never carried.
/// `r2`'s own envelope waits for `r2`'s own nonce 0 and is then
/// delivered (or, after `u`'s envelope 1 executed out of sequence, evicted as
/// stale). Below the gate nothing is counted or carried: `r2`'s envelope for
/// `u`, `r1`'s for `v` and `r3`'s transfer are above their own accounts' gaps
/// (no relayed envelope advances a nonce there), and at their `B`-th
/// selection they are evicted with `u`'s and `v`'s later envelopes, all with
/// no receipt.
#[tokio::test]
async fn a_wait_on_another_account_ends_within_the_bound_for_both_causes() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2, r3, u, v) = (sponsor(0), sponsor(1), sponsor(2), sender(0), sender(1));
        let r2_u0 = relayed(&r2, 1, 2_400, &u, 0);
        let r1_v0 = relayed(&r1, 1, 2_300, &v, 0);
        let r1_u1 = relayed(&r1, 0, 2_200, &u, 1);
        let r2_v1 = relayed(&r2, 0, 2_100, &v, 1);
        let r3_v2 = relayed(&r3, 0, 1_900, &v, 2);
        let r3_t = transfer(&r3, 1, 1_800);
        let case = [&r2_u0, &r1_v0, &r1_u1, &r2_v1, &r3_v2, &r3_t];
        node.submit(&case);

        let Some(open) = first_open(&gates) else {
            for n in 1..=(K + 3) {
                let b = node.tick().await;
                assert!(case.iter().all(|t| !carries(&b, t)), "{name}");
                for t in case {
                    assert_eq!(node.held(t), n < B, "{name}: selection {n}");
                }
            }
            for t in case {
                assert_eq!(node.status(t), None, "{name}");
                assert_eq!(
                    node.count(t),
                    0,
                    "{name}: nothing is counted below the gate"
                );
            }
            continue;
        };
        let release = open + u64::from(K) - 1;
        while node.next_height() < release {
            let h = node.next_height();
            let b = node.tick().await;
            assert!(case.iter().all(|t| !carries(&b, t)), "{name}: block {h}");
            let expected = if h >= open { (h - open + 1) as u32 } else { 0 };
            assert_eq!(node.count(&r1_u1), expected, "{name}: block {h}");
            assert_eq!(node.count(&r3_v2), 0, "{name}: block {h}: row 3");
            assert_eq!(node.count(&r1_v0), 0, "{name}: behind its own account");
            assert_eq!(node.count(&r2_u0), 0, "{name}: behind its own account");
        }
        assert_eq!(node.status(&r2_v1), None, "{name}");
        assert!(!node.held(&r2_v1), "{name}: the cycle's victim");

        let b = node.tick().await;
        assert_eq!(b.height(), release, "{name}");
        let mut carried: Vec<Hash> = hashes(&b.transactions);
        carried.sort();
        let mut expected = hashes(&[r1_u1.clone(), r1_v0.clone()]);
        expected.sort();
        assert_eq!(carried, expected, "{name}: block {release}");
        let verification = gates.verification_at(release);
        {
            let t = &r1_u1;
            let r = node.receipt(t).expect("carried");
            if verification {
                assert!(
                    matches!(r.status, TxStatus::Failed(_)),
                    "{name}: {:?}",
                    r.status
                );
                assert!(r.fee_paid > 0, "{name}: one fee, to the sponsor");
            } else {
                assert_eq!(r.status, TxStatus::Success, "{name}");
            }
            assert_eq!(node.count(t), 0, "{name}: left the pool");
        }
        // `r1`'s later transaction follows in the same block.
        assert_eq!(node.status(&r1_v0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.account_nonce(&r1), 2, "{name}");
        // r2's own envelope waits for r2's own nonce 0.
        assert_eq!(node.status(&r2_u0), None, "{name}");
        let fill = transfer(&r2, 0, 1_000);
        node.submit(&[&fill]);
        node.tick().await;
        assert_eq!(node.status(&fill), Some(TxStatus::Success), "{name}");
        if verification {
            assert_eq!(node.status(&r2_u0), Some(TxStatus::Success), "{name}");
            assert_eq!(node.messaging_nonce(&u), 1, "{name}");
        } else {
            assert_eq!(node.status(&r2_u0), None, "{name}");
            assert!(
                !node.held(&r2_u0),
                "{name}: stale once u's envelope 1 executed"
            );
        }
        // Row 3 for `r3`'s envelope, row 1 then for its transfer.
        assert!(!node.held(&r3_v2), "{name}: evicted within the gap bound");
        assert!(node.mempool.evicted_above_a_gap(&r3_v2.hash()), "{name}");
        for t in [&r3_v2, &r3_t] {
            assert!(
                node.receipt(t).is_none(),
                "{name}: never carried or charged"
            );
        }
        assert_eq!(node.account_nonce(&r3), 0, "{name}");
    }
}

/// `r1` holds only its nonce 1 (`v`'s envelope 0); `v`'s envelope 1 and then
/// `u`'s envelope 0 go through `r2`. From the accounting gate `v`'s envelope 1
/// waits on `r1`'s gap and is counted; `r1`'s envelope is above `r1`'s own
/// gap from the case's first block and is counted toward `B` at every height.
/// When `r1` fills its nonce 0 one block before the earlier of the two
/// bounds, all three are delivered in sequence and nothing is refused or
/// evicted. Below the gate (where `r2`'s envelopes advance no nonce, so `r2`
/// fills its nonce 0 too) nothing is counted toward `K` and all three are
/// delivered.
#[tokio::test]
async fn an_earlier_envelope_carried_within_the_bound_leaves_nothing_refused() {
    for gates in matrix() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2, u, v) = (sponsor(0), sponsor(1), sender(0), sender(1));
        let r1_v0 = relayed(&r1, 1, 2_300, &v, 0);
        let r2_v1 = relayed(&r2, 0, 2_200, &v, 1);
        let r2_u0 = relayed(&r2, 1, 2_100, &u, 0);
        let case = [&r1_v0, &r2_v1, &r2_u0];
        node.submit(&case);
        let open = first_open(&gates);
        let last_wait = open
            .map_or(CASE_BLOCK + 1, |f| f + u64::from(K) - 2)
            .min(CASE_BLOCK + u64::from(B) - 2);
        while node.next_height() <= last_wait {
            let h = node.next_height();
            let b = node.tick().await;
            assert!(case.iter().all(|t| !carries(&b, t)), "{name}: block {h}");
            let expected = match open {
                Some(f) if h >= f => (h - f + 1) as u32,
                _ => 0,
            };
            assert_eq!(node.count(&r2_v1), expected, "{name}: block {h}");
            assert_eq!(
                node.gap_count(&r1_v0),
                (h - CASE_BLOCK + 1) as u32,
                "{name}: block {h}"
            );
        }
        let mut fills = vec![transfer(&r1, 0, 1_000)];
        if !gates.accounting_at(node.next_height()) {
            fills.push(transfer(&r2, 0, 1_000));
        }
        node.submit(&fills.iter().collect::<Vec<_>>());
        let b = node.tick().await;
        for t in case.into_iter().chain(fills.iter()) {
            assert!(carries(&b, t), "{name}");
            assert_eq!(node.status(t), Some(TxStatus::Success), "{name}");
            assert_eq!(node.count(t), 0, "{name}");
        }
        assert_eq!(node.messaging_nonce(&v), 2, "{name}");
        assert_eq!(node.messaging_nonce(&u), 1, "{name}");
    }
}

/// The count, selection by selection, without proposing blocks: `r1` holds
/// only its nonce 1 (`v`'s envelope 0); `r2` sends a transfer at nonce 0 and
/// relays `v`'s envelope 1 at nonce 1 (`e`). Inside history, `e` is counted
/// once per selection. Its count is dropped when it stops waiting on another
/// account (`r2`'s transfer leaves the pool, so `e` is above its own
/// account's gap) and when it leaves the pool; after either, it is released
/// only `K` selections later. At `K` it is offered (out of `v`'s sequence),
/// after `r2`'s transfer. Once `r1` fills its gap, a block carries `e` in
/// sequence and its count is gone. Below the gate (the gates absent) nothing
/// is counted and `e` is never offered before `v`'s envelope 0. `r1`'s
/// envelope, above `r1`'s own gap, is re-sent before every selection (its own
/// count toward `B` starts again; `e`'s count is what this case follows).
#[tokio::test]
async fn the_count_resets_on_carry_on_leaving_the_pool_and_when_the_wait_stops() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| ["inside history", "absent"].contains(&g.name))
        .collect();
    for gates in configs {
        let name = gates.name;
        let counting = gates.accounting_at(CASE_BLOCK);
        let node = Node::new(gates);
        node.set_up().await;
        let (r1, r2, v) = (sponsor(0), sponsor(1), sender(1));
        let r1_v0 = relayed(&r1, 1, 2_300, &v, 0);
        let t = transfer(&r2, 0, 3_000);
        let e = relayed(&r2, if counting { 1 } else { 0 }, 2_000, &v, 1);
        node.submit(&[&r1_v0, &t, &e]);
        let c = |n: u32| if counting { n } else { 0 };

        for n in 1..K {
            node.resent(&r1_v0);
            let offered = node.select();
            assert!(!offered.contains(&e.hash()), "{name}: selection {n}");
            assert_eq!(node.count(&e), c(n), "{name}: selection {n}");
        }
        // It stops waiting on another account: r2's transfer leaves the pool.
        node.mempool.remove(&t.hash());
        node.resent(&r1_v0);
        let offered = node.select();
        assert!(!offered.contains(&e.hash()), "{name}");
        assert_eq!(node.count(&e), 0, "{name}: reset, no longer waiting");
        node.submit(&[&t]);
        for n in 1..K {
            node.resent(&r1_v0);
            let offered = node.select();
            assert!(!offered.contains(&e.hash()), "{name}: again, selection {n}");
            assert_eq!(node.count(&e), c(n), "{name}: again, selection {n}");
        }
        // It leaves the pool and is admitted again.
        node.mempool.remove(&e.hash());
        assert_eq!(node.count(&e), 0, "{name}: reset, left the pool");
        node.submit(&[&e]);
        for n in 1..=K {
            node.resent(&r1_v0);
            let offered = node.select();
            assert_eq!(node.count(&e), c(n), "{name}: once more, selection {n}");
            let released = counting && n == K;
            assert_eq!(
                offered.contains(&e.hash()),
                released,
                "{name}: selection {n}"
            );
            if released {
                let at = |h: &Hash| offered.iter().position(|x| x == h).unwrap();
                assert!(
                    at(&t.hash()) < at(&e.hash()),
                    "{name}: after its account's transfer"
                );
            }
        }
        // r1 fills its gap; a block carries e in sequence; the count is gone.
        let fill = transfer(&r1, 0, 1_000);
        node.submit(&[&fill]);
        let b = node.tick().await;
        for x in [&fill, &r1_v0, &t, &e] {
            assert!(carries(&b, x), "{name}");
            assert_eq!(node.status(x), Some(TxStatus::Success), "{name}");
        }
        assert_eq!(node.count(&e), 0, "{name}: carried");
        assert_eq!(node.messaging_nonce(&v), 2, "{name}");
    }
}

/// The counts are not persisted. Inside history, `r2`'s envelope for `v`
/// waits on `r1`'s gap for `K - 1` blocks, and `r1`'s envelope is held above
/// that gap as long; the node restarts on its own database and its pool takes
/// the same transactions back; both counts start from nothing, so the
/// envelope is carried to its refusal only at the `K`-th block after the
/// restart, with `r2`'s next transaction behind it, and `r1`'s envelope is
/// evicted, with no receipt, only at the `B`-th.
#[tokio::test]
async fn a_restarted_node_counts_from_nothing() {
    let gates = matrix()
        .into_iter()
        .find(|g| g.name == "inside history")
        .unwrap();
    let node = Node::new(gates);
    node.set_up().await;
    let (r1, r2, u, v) = (sponsor(0), sponsor(1), sender(0), sender(1));
    let r1_v0 = relayed(&r1, 1, 2_300, &v, 0);
    let r2_v1 = relayed(&r2, 0, 2_200, &v, 1);
    let r2_u0 = relayed(&r2, 1, 2_100, &u, 0);
    node.submit(&[&r1_v0, &r2_v1, &r2_u0]);
    assert_eq!(K, B, "the case follows both counts together");
    for n in 1..K {
        node.tick().await;
        assert_eq!(node.count(&r2_v1), n);
        assert_eq!(node.gap_count(&r1_v0), n);
    }
    let node = node.restarted();
    assert_eq!(node.engine.current_height(), CASE_BLOCK + u64::from(K) - 2);
    assert_eq!(node.count(&r2_v1), 0, "a new pool counts from nothing");
    assert_eq!(node.gap_count(&r1_v0), 0, "a new pool counts from nothing");
    for n in 1..K {
        let b = node.tick().await;
        assert!(!carries(&b, &r2_v1), "after the restart, block {n}");
        assert_eq!(node.count(&r2_v1), n);
        assert!(node.held(&r1_v0), "after the restart, block {n}");
        assert_eq!(node.gap_count(&r1_v0), n);
    }
    let b = node.tick().await;
    assert!(carries(&b, &r2_v1));
    assert!(carries(&b, &r2_u0), "r2's next transaction follows");
    let r = node.receipt(&r2_v1).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(_)), "{:?}", r.status);
    assert!(r.fee_paid > 0);
    assert_eq!(node.status(&r2_u0), Some(TxStatus::Success));
    assert_eq!(node.status(&r1_v0), None);
    assert!(
        !node.held(&r1_v0),
        "r1's own envelope, above r1's own gap, is evicted at the B-th block"
    );
}

/// How the outer transactions of [`cycle_above_another_gap`]'s sponsor `r` stand.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Outer {
    /// `r` is funded and its nonces 0 and 1 carry `s`'s envelopes 2 and 1.
    Valid,
    /// Control A: `r`'s nonce 0 is missing (`s`'s envelope 2 goes at its
    /// nonce 2): a genuine gap in `r`'s own nonces.
    AboveItsOwnGap,
    /// Control B: `r` cannot pay (an unfunded key relays).
    Unpayable,
}

/// A cycle within one sponsor above another sponsor's gap. `s`'s envelope 0 is relayed by `r2` at its nonce 1,
/// with nothing at `r2`'s nonce 0: it is above `r2`'s gap. `r` relays `t`'s
/// envelope 0 at its nonce 0 and `s`'s envelope 1 at its nonce 1; `t`'s
/// envelope leaves the pool, and `r` relays `s`'s envelope 2 at the nonce it
/// freed (at its nonce 2 for [`Outer::AboveItsOwnGap`]). Returns
/// `(r, r2's envelope, r's envelope 1, r's envelope 2)` once admitted.
fn cycle_above_another_gap(
    node: &Node,
    outer: Outer,
) -> (
    KeyPair,
    SignedTransaction,
    SignedTransaction,
    SignedTransaction,
) {
    let (r2, s, t) = (sponsor(1), sender(0), sender(2));
    let r = match outer {
        Outer::Unpayable => KeyPair::from_bytes([0xd7; 32]),
        _ => sponsor(0),
    };
    let r2_s0 = relayed(&r2, 1, 2_000, &s, 0);
    let r_t0 = relayed(&r, 0, 2_000, &t, 0);
    let r_s1 = relayed(&r, 1, 2_000, &s, 1);
    node.submit(&[&r2_s0, &r_t0, &r_s1]);
    node.mempool.remove(&r_t0.hash());
    let refill = if outer == Outer::AboveItsOwnGap { 2 } else { 0 };
    let r_s2 = relayed(&r, refill, 2_000, &s, 2);
    node.submit(&[&r_s2]);
    (r, r2_s0, r_s1, r_s2)
}

/// From the accounting gate, a valid,
/// funded outer transaction is never stranded solely by another account's
/// envelope dependency. In [`cycle_above_another_gap`]'s shape `s`'s envelopes 2 and 1 wait on
/// `s`'s envelope 0, held at `r2`'s gap, and on each other inside `r`'s own
/// account (a cycle within one sponsor, never reaching a block). `r`'s
/// envelope 2, at `r`'s nonce 0, is counted from the first selection and is
/// carried at the `K`-th to its charged refusal (`Failed(7)`, its whole fee);
/// in that selection `s`'s envelope 0 reaches the gap bound and is evicted
/// with no receipt (row 4 when the release was decided: X is charged). From
/// then on `s`'s envelope 0 is missing, so `r`'s envelope 1 is row 3 of the
/// selection oracle: not
/// stranded at once, but never counted, carried or charged, and evicted
/// within the gap bound with no receipt. `s`'s messaging nonce does not move.
/// Where both messaging gates are open at the case's block.
#[tokio::test]
async fn a_one_sponsor_cycle_inside_another_accounts_hold_is_released_to_charged_refusals() {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK) && g.verification_at(CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    assert_eq!(K, B, "the case reads both bounds together");
    for gates in configs {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r, r2_s0, r_s1, r_s2) = cycle_above_another_gap(&node, Outer::Valid);
        for n in 1..K {
            let b = node.tick().await;
            for x in [&r2_s0, &r_s1, &r_s2] {
                assert!(!carries(&b, x), "{name}: block {n}");
            }
            assert_eq!(node.count(&r_s2), n, "{name}: block {n}");
        }
        let b = node.tick().await;
        assert!(carries(&b, &r_s2), "{name}: released at the K-th selection");
        assert!(
            !node.held(&r2_s0),
            "{name}: s's envelope 0 at the gap bound"
        );
        assert_eq!(node.status(&r2_s0), None, "{name}");
        assert!(node.held(&r_s1), "{name}: not stranded");
        let refusal = node.receipt(&r_s2).expect("carried");
        assert_eq!(refusal.status, TxStatus::Failed(7), "{name}");
        assert_eq!(
            refusal.fee_paid, 2_000,
            "{name}: its whole fee, to the sponsor"
        );
        assert_eq!(node.account_nonce(&r), 1, "{name}");
        let mut gone_at = None;
        for n in 1..=B {
            let b = node.tick().await;
            assert!(!carries(&b, &r_s1), "{name}: row 3, never carried");
            assert_eq!(node.count(&r_s1), 0, "{name}: row 3, never counted");
            if gone_at.is_none() && !node.held(&r_s1) {
                gone_at = Some(n);
            }
        }
        assert!(gone_at.is_some(), "{name}: evicted within the gap bound");
        assert!(node.receipt(&r_s1).is_none(), "{name}: no receipt");
        assert!(node.mempool.evicted_above_a_gap(&r_s1.hash()), "{name}");
        assert_eq!(node.account_nonce(&r), 1, "{name}: only X charged");
        assert_eq!(node.messaging_nonce(&s_of()), 0, "{name}");
    }
}

/// Controls for the previous case, rows 1 and 2 of the selection oracle (a
/// genuine account-nonce gap or inability to pay never authorises charging or
/// skipping validation), and the same shape below the accounting gate
/// (main's behaviour).
/// - Control A, from the gate: `r`'s nonce 0 is missing. Neither of `r`'s
///   envelopes is ever counted, carried or charged; at the gap bound `s`'s
///   envelope 0 is evicted, and `r`'s two, above `r`'s own gap, at theirs;
///   no receipt; `r`'s nonce does not move.
/// - Control B, from the gate: `r` cannot pay. Nothing of `r`'s is ever
///   charged and no check is skipped: `r`'s envelope 2 takes at most an
///   uncharged `InsufficientBalance` (it is released like a valid one, and
///   the executor refuses it before anything is charged); `r`'s envelope 1,
///   above `r`'s own gap once envelope 2 has not executed, is evicted with
///   no receipt.
/// - Below the gate (the gates absent, above history, `0x1048` only): nothing
///   is counted; at the gap bound `s`'s envelope 0 is evicted and `s`'s later
///   envelopes with it, stranded, in the same block: no receipt, nothing
///   charged.
#[tokio::test]
async fn controls_for_the_one_sponsor_cycle_inside_another_accounts_hold() {
    for gates in matrix() {
        let open = gates.accounting_at(CASE_BLOCK) && gates.verification_at(CASE_BLOCK);
        let closed = (CASE_BLOCK..CASE_BLOCK + 20).all(|h| !gates.accounting_at(h));
        let cases: &[Outer] = if open {
            &[Outer::AboveItsOwnGap, Outer::Unpayable]
        } else if closed {
            &[Outer::Valid]
        } else {
            &[]
        };
        for &outer in cases {
            let name = format!("{}, {outer:?}", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let (r, r2_s0, r_s1, r_s2) = cycle_above_another_gap(&node, outer);
            for n in 1..=(3 * B) {
                let b = node.tick().await;
                for x in [&r2_s0, &r_s1] {
                    assert!(!carries(&b, x), "{name}");
                }
                if outer == Outer::Valid && n == B {
                    for x in [&r2_s0, &r_s1, &r_s2] {
                        assert!(
                            !node.held(x),
                            "{name}: stranded at the gap bound, as on main"
                        );
                    }
                }
                if outer != Outer::Unpayable {
                    assert!(!carries(&b, &r_s2), "{name}");
                    assert_eq!(node.count(&r_s2), 0, "{name}: not counted");
                }
            }
            for x in [&r2_s0, &r_s1, &r_s2] {
                assert!(!node.held(x), "{name}: gone within the bounds");
            }
            assert_eq!(node.status(&r2_s0), None, "{name}");
            assert_eq!(node.status(&r_s1), None, "{name}: never charged");
            match outer {
                Outer::Unpayable => assert!(
                    node.receipt(&r_s2).map_or(true, |r| {
                        r.status == TxStatus::InsufficientBalance && r.fee_paid == 0
                    }),
                    "{name}: nothing charged, no check skipped"
                ),
                _ => assert_eq!(node.status(&r_s2), None, "{name}: never charged"),
            }
            assert_eq!(node.account_nonce(&r), 0, "{name}");
            assert_eq!(node.messaging_nonce(&s_of()), 0, "{name}");
        }
    }
}

/// Row 4: the gap bound never strands an envelope released
/// toward its charged refusal in the same selection, also one relayed by the
/// evicted envelope's own relay. `r` relays `s`'s envelope 0 at its nonce 2,
/// with nothing at its nonce 1 (above `r`'s own gap: row 1); `q` relays `s`'s
/// envelope 1 at its nonce 0, and `r` relays `s`'s envelope 2 at its nonce 0.
/// Every required predecessor is in the pool. `q`'s envelope 1 and `r`'s
/// envelope 2, each at its account's next nonce, are row 4 (held through
/// another sponsor: `q`'s behind `r`'s envelope 0, `r`'s behind `q`'s
/// envelope 1), counted from the first selection. At the `K`-th both are
/// released, and in that selection `r`'s envelope 0 reaches the gap bound
/// and is evicted with no receipt; `r`'s envelope 2, `s`'s later envelope
/// through the same relay, is not stranded with it. Both released envelopes
/// are carried to their charged refusals (`Failed(7)`, the whole fee). Where
/// both messaging gates are open at the case's block.
#[tokio::test]
async fn an_envelope_the_cross_account_bound_governs_is_not_stranded_through_its_own_relay() {
    assert_eq!(K, B, "the case reads both bounds together");
    for gates in both_gates_open() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r, q, s) = (sponsor(0), sponsor(1), s_of());
        let r_s0 = relayed(&r, 2, 2_000, &s, 0);
        let q_s1 = relayed(&q, 0, 2_000, &s, 1);
        let r_s2 = relayed(&r, 0, 2_000, &s, 2);
        node.submit(&[&r_s0, &q_s1, &r_s2]);
        for n in 1..K {
            let b = node.tick().await;
            for t in [&r_s0, &q_s1, &r_s2] {
                assert!(!carries(&b, t), "{name}: block {n}");
            }
            assert_eq!(node.count(&r_s2), n, "{name}: row 4, block {n}");
            assert_eq!(node.count(&q_s1), n, "{name}: row 4, block {n}");
            assert_eq!(node.count(&r_s0), 0, "{name}: row 1");
            assert_eq!(node.gap_count(&r_s0), n, "{name}: block {n}");
        }
        let b = node.tick().await;
        assert!(!node.held(&r_s0), "{name}: r's envelope 0 at the gap bound");
        assert!(node.receipt(&r_s0).is_none(), "{name}");
        for t in [&r_s2, &q_s1] {
            assert!(carries(&b, t), "{name}: released, not stranded");
            let refusal = node.receipt(t).expect("carried");
            assert_eq!(refusal.status, TxStatus::Failed(7), "{name}");
            assert_eq!(refusal.fee_paid, 2_000, "{name}: its whole fee");
        }
        assert_eq!(node.account_nonce(&r), 1, "{name}");
        assert_eq!(node.account_nonce(&q), 1, "{name}");
        assert_eq!(node.messaging_nonce(&s), 0, "{name}");
    }
}

/// Where `s`'s envelope 0 stands in [`one_sponsor_cycle`]'s shape.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Env0 {
    /// Admitted through `r2` and then gone from the pool, and not in the
    /// chain: missing, in this node's view.
    Missing,
    /// Relayed by `r2` at its nonce 1, with nothing at `r2`'s nonce 0:
    /// present, held through another sponsor.
    HeldAtAnotherSponsor,
}

/// A cycle within one sponsor, from `s`'s next envelope nonce `base`
/// (`base` envelopes of `s`'s already consumed): `r` relays `s`'s envelope
/// `base + 2` at its nonce 0 and envelope `base + 1` at its nonce 1. `s`'s
/// envelope `base` ("envelope 0") is admitted through `r2` at its nonce 1
/// and stays in the pool or leaves it as `env0` says. Returns `(r, r2's
/// envelope, r's envelope base + 1, r's envelope base + 2)`.
fn one_sponsor_cycle(
    node: &Node,
    env0: Env0,
    base: u64,
) -> (
    KeyPair,
    SignedTransaction,
    SignedTransaction,
    SignedTransaction,
) {
    let (r, r2, s) = (sponsor(0), sponsor(1), s_of());
    assert_eq!(node.messaging_nonce(&s), base, "s's next envelope nonce");
    let r2_s0 = relayed(&r2, 1, 2_000, &s, base);
    let r_s1 = relayed(&r, 1, 2_000, &s, base + 1);
    let r_s2 = relayed(&r, 0, 2_000, &s, base + 2);
    node.submit(&[&r2_s0, &r_s1, &r_s2]);
    if env0 == Env0::Missing {
        node.mempool.remove(&r2_s0.hash());
    }
    (r, r2_s0, r_s1, r_s2)
}

/// The configurations where both messaging gates are open at the case's
/// block.
fn both_gates_open() -> Vec<Gates> {
    let configs: Vec<Gates> = matrix()
        .into_iter()
        .filter(|g| g.accounting_at(CASE_BLOCK) && g.verification_at(CASE_BLOCK))
        .collect();
    assert!(!configs.is_empty());
    configs
}

/// A missing predecessor, and one held through another sponsor: the
/// same cycle within one sponsor ([`one_sponsor_cycle`]), differing only in
/// whether `s`'s envelope 0 is missing or present, held through another
/// sponsor; each with none of `s`'s envelopes consumed, and with one
/// consumed first (delivered through `x`), which is never a missing
/// predecessor. From the accounting gate:
/// - Missing (row 3 of the selection oracle): neither of `r`'s envelopes is counted toward `K`. Both are held
///   directly above the missing envelope and evicted at the `B`-th block,
///   never carried: no receipt, `r`'s balance and nonce and `s`'s messaging
///   nonce unchanged, and both in this node's eviction history (the status
///   method reads `dropped` for them).
/// - Held at another sponsor (row 4): `r`'s envelope 2, at `r`'s nonce 0, is counted
///   from the first selection and carried at the `K`-th to its charged
///   refusal (`Failed(7)`, its whole fee), in the selection in which `s`'s
///   envelope 0 reaches the gap bound at `r2`'s gap and is evicted with no
///   receipt. What then becomes of `r`'s envelope 1 is not read here.
///
/// Where both messaging gates are open at the case's block.
#[tokio::test]
async fn a_cycle_within_one_sponsor_is_released_only_above_another_sponsors_envelope() {
    assert_eq!(K, B, "the case reads both bounds together");
    for gates in both_gates_open() {
        for (env0, consumed) in [
            (Env0::Missing, 0),
            (Env0::HeldAtAnotherSponsor, 0),
            (Env0::Missing, 1),
            (Env0::HeldAtAnotherSponsor, 1),
        ] {
            let name = format!("{}, {env0:?}, {consumed} consumed", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let s = s_of();
            if consumed == 1 {
                let x_s0 = relayed(&sponsor(2), 0, 2_000, &s, 0);
                node.submit(&[&x_s0]);
                node.tick().await;
                assert_eq!(node.status(&x_s0), Some(TxStatus::Success), "{name}");
            }
            let (r, r2_s0, r_s1, r_s2) = one_sponsor_cycle(&node, env0, consumed);
            let balance = |k: &KeyPair| node.state.get_balance(&k.address()).unwrap();
            let funds = balance(&r);
            for n in 1..B {
                let b = node.tick().await;
                for x in [&r2_s0, &r_s1, &r_s2] {
                    assert!(!carries(&b, x), "{name}: block {n}");
                }
                let counted = if env0 == Env0::Missing { 0 } else { n };
                assert_eq!(node.count(&r_s2), counted, "{name}: block {n}");
                assert_eq!(node.count(&r_s1), 0, "{name}: behind r's nonce 0");
                assert!(node.held(&r_s1) && node.held(&r_s2), "{name}: block {n}");
            }
            let b = node.tick().await;
            assert!(!node.held(&r2_s0), "{name}");
            assert_eq!(node.status(&r2_s0), None, "{name}");
            match env0 {
                Env0::Missing => {
                    for x in [&r_s1, &r_s2] {
                        assert!(!carries(&b, x), "{name}");
                        assert!(!node.held(x), "{name}: evicted at the gap bound");
                    }
                    for n in 1..=B {
                        let b = node.tick().await;
                        for x in [&r_s1, &r_s2] {
                            assert!(!carries(&b, x), "{name}: never carried, block {n}");
                        }
                    }
                    for x in [&r_s1, &r_s2] {
                        assert!(node.receipt(x).is_none(), "{name}: no receipt");
                        assert!(
                            node.mempool.evicted_above_a_gap(&x.hash()),
                            "{name}: in the eviction history"
                        );
                    }
                    assert_eq!(balance(&r), funds, "{name}: nothing charged");
                    assert_eq!(node.account_nonce(&r), 0, "{name}");
                }
                Env0::HeldAtAnotherSponsor => {
                    assert!(carries(&b, &r_s2), "{name}: released at the K-th selection");
                    assert!(!carries(&b, &r_s1), "{name}");
                    let refusal = node.receipt(&r_s2).expect("carried");
                    assert_eq!(refusal.status, TxStatus::Failed(7), "{name}");
                    assert_eq!(refusal.fee_paid, 2_000, "{name}: its whole fee");
                    assert_eq!(balance(&r), funds - refusal.fee_paid, "{name}");
                    assert_eq!(node.account_nonce(&r), 1, "{name}");
                }
            }
            assert_eq!(node.messaging_nonce(&s), consumed, "{name}");
        }
    }
}

/// Node-local recomputation ("missing" is this node's view at each
/// selection): row 3 becomes row 5 when the missing envelope arrives.
/// In [`one_sponsor_cycle`]'s missing case, `s`'s envelope
/// 0 reaches the pool after the case's first block, before the gap bound,
/// relayed by `x` at its nonce 0. In the next selection nothing is above a
/// gap any more: `x`'s envelope is delivered, `r`'s envelopes are no longer
/// counted toward the gap bound, and the existing rules for the cycle within
/// `r` apply — its victim, `r`'s envelope 2 at `r`'s nonce 0 (the head on the
/// cycle), is evicted with no receipt (not a gap-bound eviction), and `r`'s
/// envelope 1 stays, now above `r`'s own free nonce 0. When `r` fills that
/// nonce, `r`'s envelope 1 is delivered in sequence. Where both messaging
/// gates are open at the case's block.
#[tokio::test]
async fn a_missing_envelope_that_arrives_before_the_gap_bound_is_recomputed() {
    for gates in both_gates_open() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (x, s) = (sponsor(2), s_of());
        let (r, _, r_s1, r_s2) = one_sponsor_cycle(&node, Env0::Missing, 0);
        node.tick().await;
        for t in [&r_s1, &r_s2] {
            assert_eq!(node.gap_count(t), 1, "{name}: above the missing envelope");
            assert_eq!(node.count(t), 0, "{name}");
        }
        let x_s0 = relayed(&x, 0, 2_000, &s, 0);
        node.submit(&[&x_s0]);
        let b = node.tick().await;
        assert!(carries(&b, &x_s0), "{name}");
        assert_eq!(node.status(&x_s0), Some(TxStatus::Success), "{name}");
        assert_eq!(node.messaging_nonce(&s), 1, "{name}");
        assert!(
            !carries(&b, &r_s2) && !node.held(&r_s2),
            "{name}: the cycle's victim"
        );
        assert!(node.receipt(&r_s2).is_none(), "{name}");
        assert!(
            !node.mempool.evicted_above_a_gap(&r_s2.hash()),
            "{name}: not a gap-bound eviction"
        );
        assert!(node.held(&r_s1), "{name}");
        assert_eq!(node.gap_count(&r_s1), 0, "{name}: recomputed");
        node.tick().await;
        assert!(node.held(&r_s1), "{name}");
        assert_eq!(node.gap_count(&r_s1), 1, "{name}: above r's free nonce 0");
        let fill = transfer(&r, 0, 1_000);
        node.submit(&[&fill]);
        let b = node.tick().await;
        assert!(carries(&b, &fill) && carries(&b, &r_s1), "{name}");
        assert_eq!(node.status(&r_s1), Some(TxStatus::Success), "{name}");
        assert_eq!(node.messaging_nonce(&s), 2, "{name}");
        assert_eq!(node.account_nonce(&r), 2, "{name}");
    }
}

/// A trace pair (rows 4 and 3: no classification is sticky). The
/// shape ([`one_sponsor_cycle`], `s`'s envelope 0 held at `r2`'s gap), the
/// two cases differing only in when `s`'s envelope 0 arrives: with `r`'s
/// envelopes, or one block before them.
/// - With them: `r`'s envelope 2 (X) is counted from the first
///   selection; at the `K`-th, the selection in which `s`'s envelope 0
///   reaches the gap bound and is evicted, X is released (row 4 when that was
///   decided) and charged (`Failed(7)`, the whole fee).
/// - One block before: `s`'s envelope 0 reaches the gap bound while X has
///   been counted once; from then on X's required predecessor is missing
///   (row 3): X's count is gone, and it is never released, carried or
///   charged, and is evicted within the gap bound.
///
/// In both, what remains of `r`'s envelopes once `s`'s envelope 0 is gone is
/// row 3: never counted or carried, evicted within the gap bound with no
/// receipt, into the eviction history. Where both messaging gates are open
/// at the case's block.
#[tokio::test]
async fn the_trace_charges_x_only_while_its_required_predecessors_are_complete() {
    assert_eq!(K, B, "the case reads both bounds together");
    for gates in both_gates_open() {
        for ahead in [0u32, 1] {
            let name = format!("{}, envelope 0 {ahead} block(s) ahead", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let (r, r2, s) = (sponsor(0), sponsor(1), s_of());
            let r2_s0 = relayed(&r2, 1, 2_000, &s, 0);
            let r_s1 = relayed(&r, 1, 2_000, &s, 1);
            let r_s2 = relayed(&r, 0, 2_000, &s, 2);
            node.submit(&[&r2_s0]);
            for _ in 0..ahead {
                node.tick().await;
            }
            node.submit(&[&r_s1, &r_s2]);
            for n in 1..(B - ahead) {
                let b = node.tick().await;
                for x in [&r2_s0, &r_s1, &r_s2] {
                    assert!(!carries(&b, x), "{name}: block {n}");
                }
                assert_eq!(node.count(&r_s2), n, "{name}: row 4, block {n}");
            }
            let b = node.tick().await;
            assert!(
                !node.held(&r2_s0),
                "{name}: s's envelope 0 at the gap bound"
            );
            assert!(node.receipt(&r2_s0).is_none(), "{name}");
            let remaining = if ahead == 0 {
                assert!(carries(&b, &r_s2), "{name}: X released");
                let refusal = node.receipt(&r_s2).expect("carried");
                assert_eq!(refusal.status, TxStatus::Failed(7), "{name}");
                assert_eq!(refusal.fee_paid, 2_000, "{name}: its whole fee");
                vec![&r_s1]
            } else {
                assert!(!carries(&b, &r_s2), "{name}: X not released");
                assert_eq!(node.count(&r_s2), 0, "{name}: row 3, its count gone");
                vec![&r_s1, &r_s2]
            };
            for n in 1..=B {
                let b = node.tick().await;
                for x in &remaining {
                    assert!(!carries(&b, x), "{name}: row 3, block {n} after");
                    assert_eq!(node.count(x), 0, "{name}: row 3, block {n} after");
                }
            }
            for x in &remaining {
                assert!(!node.held(x), "{name}: evicted within the gap bound");
                assert!(node.receipt(x).is_none(), "{name}: no receipt");
                assert!(node.mempool.evicted_above_a_gap(&x.hash()), "{name}");
            }
            assert_eq!(node.account_nonce(&r), u64::from(ahead == 0), "{name}");
            assert_eq!(node.messaging_nonce(&s), 0, "{name}");
        }
    }
}

/// A pair (rows 3 and 4: a missing envelope takes precedence over one
/// held elsewhere). `s`'s envelopes 1 to 3 go through `r` (envelope 1 at its
/// nonce 1, envelope 3 at its nonce 0: a cycle within one sponsor) and
/// through `q` (envelope 2 at its nonce 0). The two cases differ only in
/// `s`'s envelope 0, relayed by `x` at its nonce 1 with nothing at its nonce
/// 0:
/// - Missing (it leaves the pool once the others are admitted): each of the
///   three has a required predecessor missing locally, row 3 even though
///   envelope 2 is held at another relay: none is counted, carried or
///   charged; all three are evicted at the gap bound, into the eviction
///   history; no account or envelope nonce moves.
/// - Held at another sponsor (it stays, above `x`'s gap): the sequence is
///   complete, and `q`'s envelope 2 and `r`'s envelope 3, at their accounts'
///   next nonces, are row 4: counted from the first selection and carried at
///   the `K`-th to their charged refusals (`Failed(7)`, the whole fee), in
///   the selection in which `x`'s envelope reaches the gap bound and is
///   evicted.
///
/// Where both messaging gates are open at the case's block.
#[tokio::test]
async fn a_missing_envelope_takes_precedence_over_one_held_at_another_relay() {
    assert_eq!(K, B, "the case reads both bounds together");
    for gates in both_gates_open() {
        for env0 in [Env0::Missing, Env0::HeldAtAnotherSponsor] {
            let name = format!("{}, {env0:?}", gates.name);
            let node = Node::new(gates);
            node.set_up().await;
            let (r, q, x, s) = (sponsor(0), sponsor(1), sponsor(2), s_of());
            let x_s0 = relayed(&x, 1, 2_000, &s, 0);
            let r_s1 = relayed(&r, 1, 2_000, &s, 1);
            let q_s2 = relayed(&q, 0, 2_000, &s, 2);
            let r_s3 = relayed(&r, 0, 2_000, &s, 3);
            node.submit(&[&x_s0, &r_s1, &q_s2, &r_s3]);
            if env0 == Env0::Missing {
                node.mempool.remove(&x_s0.hash());
            }
            let balance = |k: &KeyPair| node.state.get_balance(&k.address()).unwrap();
            let funds = (balance(&r), balance(&q));
            for n in 1..B {
                let b = node.tick().await;
                for t in [&x_s0, &r_s1, &q_s2, &r_s3] {
                    assert!(!carries(&b, t), "{name}: block {n}");
                }
                let counted = if env0 == Env0::Missing { 0 } else { n };
                assert_eq!(node.count(&r_s3), counted, "{name}: block {n}");
                assert_eq!(node.count(&q_s2), counted, "{name}: block {n}");
                assert_eq!(node.count(&r_s1), 0, "{name}: behind r's nonce 0");
            }
            let b = node.tick().await;
            assert!(!node.held(&x_s0), "{name}");
            assert!(node.receipt(&x_s0).is_none(), "{name}");
            match env0 {
                Env0::Missing => {
                    for t in [&r_s1, &q_s2, &r_s3] {
                        assert!(!carries(&b, t), "{name}: row 3, never carried");
                        assert!(!node.held(t), "{name}: evicted at the gap bound");
                        assert!(node.receipt(t).is_none(), "{name}: no receipt");
                        assert!(node.mempool.evicted_above_a_gap(&t.hash()), "{name}");
                    }
                    assert_eq!((balance(&r), balance(&q)), funds, "{name}: nothing charged");
                    assert_eq!(node.account_nonce(&r), 0, "{name}");
                    assert_eq!(node.account_nonce(&q), 0, "{name}");
                }
                Env0::HeldAtAnotherSponsor => {
                    for t in [&q_s2, &r_s3] {
                        assert!(carries(&b, t), "{name}: row 4, released");
                        let refusal = node.receipt(t).expect("carried");
                        assert_eq!(refusal.status, TxStatus::Failed(7), "{name}");
                        assert_eq!(refusal.fee_paid, 2_000, "{name}: its whole fee");
                    }
                    assert_eq!(node.account_nonce(&r), 1, "{name}");
                    assert_eq!(node.account_nonce(&q), 1, "{name}");
                }
            }
            assert_eq!(node.messaging_nonce(&s), 0, "{name}");
        }
    }
}

/// The selection oracle's work is bounded by the pool, never by a nonce
/// (rows 3 and 1), on the selection path. Admission evidence
/// first: admission takes a transaction far above its account's nonce, but
/// refuses an envelope ahead of its sender's next envelope nonce, so the far
/// envelope is refused at `s`'s canonical next envelope nonce 0. It is then
/// admitted while that nonce is 2^60, and the nonce moves back to 0, as a
/// chain switch can move it back (test state only; nothing in admission or
/// selection is bypassed): every one of the envelope's 2^60 required
/// predecessors is missing (row 3). The helper's own bounded-work evidence
/// is `mempool::tests::the_gap_check_visits_only_the_index_entries_in_range`. `r` relays it at its nonce 0; `x` sends a transfer at its
/// nonce 2^60 (row 1). Each selection reads only what the pool holds: both
/// are held directly, never counted or carried, and evicted at the `B`-th
/// block with no receipt, the `B` selections taking well under a few
/// seconds. Where both messaging gates are open at the case's block.
#[tokio::test]
async fn a_far_future_nonce_costs_a_selection_only_what_the_pool_holds() {
    const FAR: u64 = 1 << 60;
    for gates in both_gates_open() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r, x, s) = (sponsor(0), sponsor(2), s_of());
        let messaging = MessagingStore::new(&node.db);
        let far_envelope = relayed(&r, 0, 2_000, &s, FAR);
        assert!(
            node.mempool.add(far_envelope.clone()).is_err(),
            "{name}: admission refuses an envelope ahead of its sender's next nonce"
        );
        messaging.set_sender_nonce(&s.address(), FAR).unwrap();
        let far_transfer = transfer(&x, FAR, 1_000);
        node.submit(&[&far_envelope, &far_transfer]);
        messaging.set_sender_nonce(&s.address(), 0).unwrap();
        let started = std::time::Instant::now();
        for n in 1..=B {
            let b = node.tick().await;
            for t in [&far_envelope, &far_transfer] {
                assert!(!carries(&b, t), "{name}: block {n}");
                assert_eq!(node.held(t), n < B, "{name}: block {n}");
            }
            assert_eq!(node.count(&far_envelope), 0, "{name}: row 3");
        }
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "{name}: {took:?}"
        );
        for t in [&far_envelope, &far_transfer] {
            assert!(node.receipt(t).is_none(), "{name}");
            assert!(node.mempool.evicted_above_a_gap(&t.hash()), "{name}");
        }
        assert_eq!(node.account_nonce(&r), 0, "{name}");
        assert_eq!(node.account_nonce(&x), 0, "{name}");
        assert_eq!(node.messaging_nonce(&s), 0, "{name}");
    }
}

/// Duplicates cannot conceal a missing predecessor (row 3). `s`'s envelope 0 leaves the pool once
/// `s`'s envelope 1 (through `q1`) and envelope 2 (through `r`, at its nonce
/// 0) are admitted; a second copy of envelope 1 through `q2` is refused at
/// admission ("already pending"), and the pool's index holds one entry per
/// envelope nonce whatever is offered. Envelope 2 waits on envelope 1, held
/// at another relay, which would make it row 4 were envelope 0's absence
/// hidden; it is row 3: never counted, carried or charged, and evicted at
/// the gap bound with envelope 1. Where both messaging gates are open at the
/// case's block.
#[tokio::test]
async fn a_second_copy_of_an_envelope_never_conceals_a_missing_predecessor() {
    for gates in both_gates_open() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r, q1, q2, x, s) = (sponsor(0), sponsor(1), sponsor(3), sponsor(2), s_of());
        let x_s0 = relayed(&x, 0, 2_000, &s, 0);
        let q1_s1 = relayed(&q1, 0, 2_000, &s, 1);
        let q2_s1 = relayed(&q2, 0, 2_100, &s, 1);
        let r_s2 = relayed(&r, 0, 2_000, &s, 2);
        node.submit(&[&x_s0, &q1_s1]);
        assert!(
            node.mempool.add(q2_s1.clone()).is_err(),
            "{name}: a second pending copy of envelope 1 is refused"
        );
        node.submit(&[&r_s2]);
        node.mempool.remove(&x_s0.hash());
        for n in 1..=B {
            let b = node.tick().await;
            for t in [&q1_s1, &r_s2] {
                assert!(!carries(&b, t), "{name}: row 3, block {n}");
                assert_eq!(node.count(t), 0, "{name}: row 3, block {n}");
                assert_eq!(node.held(t), n < B, "{name}: block {n}");
            }
        }
        for t in [&q1_s1, &r_s2] {
            assert!(node.receipt(t).is_none(), "{name}: nothing charged");
            assert!(node.mempool.evicted_above_a_gap(&t.hash()), "{name}");
        }
        assert_eq!(node.account_nonce(&r), 0, "{name}");
        assert_eq!(node.messaging_nonce(&s), 0, "{name}");
    }
}

/// Row 5 of the selection oracle: an
/// envelope whose required predecessors are complete and held only through
/// its own sponsor is never counted or charged. `r` relays `s`'s envelope 0
/// (Y) at its nonce 2, above `r`'s own gap (its nonce 1 never comes: row 1),
/// and `s`'s envelope 1 (X) at its nonce 0: X's only required predecessor, Y,
/// is in the pool and relayed by X's own sponsor. X is never counted toward
/// `K`. Y is evicted at the gap bound; X, its predecessor then missing (row
/// 3), leaves within the gap bound after it. Neither is carried or charged,
/// both are in the eviction history, and no nonce moves. Where both messaging
/// gates are open at the case's block.
#[tokio::test]
async fn an_envelope_held_only_through_its_own_sponsor_is_never_counted_or_charged() {
    for gates in both_gates_open() {
        let name = gates.name;
        let node = Node::new(gates);
        node.set_up().await;
        let (r, s) = (sponsor(0), s_of());
        let y = relayed(&r, 2, 2_000, &s, 0);
        let x = relayed(&r, 0, 2_000, &s, 1);
        node.submit(&[&y, &x]);
        let funds = node.state.get_balance(&r.address()).unwrap();
        for n in 1..=(2 * B) {
            let b = node.tick().await;
            for t in [&x, &y] {
                assert!(!carries(&b, t), "{name}: block {n}");
            }
            assert_eq!(node.count(&x), 0, "{name}: row 5, never counted, block {n}");
            assert_eq!(
                node.held(&y),
                n < B,
                "{name}: Y at the gap bound, block {n}"
            );
        }
        for t in [&x, &y] {
            assert!(!node.held(t), "{name}: evicted");
            assert!(
                node.receipt(t).is_none(),
                "{name}: never carried or charged"
            );
            assert!(node.mempool.evicted_above_a_gap(&t.hash()), "{name}");
        }
        assert_eq!(
            node.state.get_balance(&r.address()).unwrap(),
            funds,
            "{name}"
        );
        assert_eq!(node.account_nonce(&r), 0, "{name}");
        assert_eq!(node.messaging_nonce(&s), 0, "{name}");
    }
}

/// The sender of [`cycle_above_another_gap`]'s envelopes.
fn s_of() -> KeyPair {
    sender(0)
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
