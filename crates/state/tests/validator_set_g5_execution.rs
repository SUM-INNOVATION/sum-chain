//! The dormant G5 validator-set wiring in the executor (#351).
//!
//! With a configuration (`BlockExecutor::with_dormant_membership`), each
//! boundary block's row is staged through that block's own candidate and is
//! committed by its publication batch; nothing else writes one. Without one
//! (`BlockExecutor::new`, which every production path uses), execution stages
//! and reads no row, and everything it does commit is what it committed
//! before.
//!
//! Every schedule, stake and key here is synthetic; nothing selects an epoch
//! length, activation height, stake minimum or `max_validators` for any chain.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::staking::{DelegateData, StakingOperation, StakingTxData};
use sumchain_primitives::{
    Block, BlockHeader, Hash, SignedTransaction, TransactionV2, ValidatorInfo,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::StateError;
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::schema::StakingStore;
use sumchain_storage::validator_set_g5::{resolve_set, EpochSchedule, G5Membership, VsetLayout};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

use common::CHAIN_ID;

/// N_min = 5, ratified 2026-10-21. The engine passes
/// `pool_topology::PRODUCT_MINIMUM`; the executor takes it from the
/// configuration.
const RATIFIED_N_MIN: usize = 5;

fn anchor() -> Vec<[u8; 32]> {
    vec![[1u8; 32], [2u8; 32]]
}

/// A synthetic configuration: minimum stake 1, at most five members.
fn membership(l: u64, a: u64) -> Arc<G5Membership> {
    Arc::new(
        G5Membership::new(
            EpochSchedule::new(l, a).unwrap(),
            RATIFIED_N_MIN,
            5,
            1,
            anchor(),
        )
        .unwrap(),
    )
}

fn delegator() -> KeyPair {
    KeyPair::from_bytes([0x41; 32])
}

/// Six staking validators, `[0x31; 32]` to `[0x36; 32]`, self-stake 100 each.
fn seeded() -> Vec<[u8; 32]> {
    (0x31..=0x36u8).map(|b| [b; 32]).collect()
}

/// The five smallest seeded keys, in key order: Q4's choice among equal totals.
fn smallest_five() -> Vec<[u8; 32]> {
    seeded()[..5].to_vec()
}

fn delegate(nonce: u64, validator: [u8; 32], amount: u128) -> SignedTransaction {
    let from = delegator();
    let data = bincode::serialize(&DelegateData {
        validator_pubkey: validator,
        amount,
    })
    .unwrap();
    let tx = TransactionV2::staking(
        CHAIN_ID,
        from.address(),
        1_000,
        nonce,
        StakingTxData {
            operation: StakingOperation::Delegate,
            data,
        },
    );
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// One node's chain: its database, the executor under test, and its head.
struct Chain {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    head: Block,
}

impl Chain {
    fn new(membership: Option<Arc<G5Membership>>) -> Self {
        let (state, db, dir, executor) = common::setup_with_params(ChainParams::with_v2_enabled());
        let executor = match membership {
            None => executor,
            Some(m) => executor.with_dormant_membership(m),
        };
        let store = StakingStore::new(&db);
        for pubkey in seeded() {
            store
                .put_validator(&ValidatorInfo::new(pubkey, 100, 0, 0))
                .unwrap();
        }
        common::fund(&db, &delegator(), 1_000_000_000);
        let genesis = Block::new(
            BlockHeader::new(Hash::ZERO, 0, 1_000, Hash::ZERO, Hash::ZERO, anchor()[0]),
            Vec::new(),
        );
        Self {
            _dir: dir,
            db,
            state,
            executor,
            head: genesis,
        }
    }

    fn draft(&self, txs: Vec<SignedTransaction>) -> Block {
        let height = self.head.height() + 1;
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10,
                Hash::ZERO,
                Hash::ZERO,
                anchor()[(height % 2) as usize],
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        b
    }

    /// Execute and publish the next block, as a proposer does.
    fn produce(&mut self, txs: Vec<SignedTransaction>) -> Block {
        let mut b = self.draft(txs);
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &anchor())
            .unwrap();
        b.header.state_root = exec.computed_root();
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        b
    }

    /// Execute the next block and drop the result: nothing is published.
    fn execute_and_drop(&self, txs: Vec<SignedTransaction>) -> Result<(), StateError> {
        let b = self.draft(txs);
        self.executor
            .execute_block(&b, self.state.state_root(), &anchor())
            .map(drop)
    }

    /// The epochs of every stored `vset/` row.
    fn stored_epochs(&self) -> Vec<u64> {
        let prefix = VsetLayout::prefix();
        self.db
            .iter_checked_from(cf::STATE, Some(prefix))
            .unwrap()
            .map(|e| e.unwrap().0.into_vec())
            .take_while(|k| k.starts_with(prefix))
            .map(|k| u64::from_be_bytes(k[prefix.len()..].try_into().unwrap()))
            .collect()
    }

    /// The set that governs `height`, read from committed state.
    fn set_at(&self, height: u64, m: &G5Membership) -> Vec<[u8; 32]> {
        resolve_set(&*self.db, m.anchor(), height, m.schedule()).unwrap()
    }
}

type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

fn rows(db: &Database) -> Rows {
    let mut out = BTreeMap::new();
    for family in ALL_CFS {
        for entry in db.iter_checked_from(family, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((family.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

// ── without a configuration: nothing new ────────────────────────────────────

#[test]
fn without_a_configuration_execution_stages_and_reads_no_row() {
    let mut chain = Chain::new(None);
    // A row execution would refuse if it read it: undecodable, for epoch 1.
    chain
        .db
        .put(cf::STATE, &VsetLayout::row_key(1), b"not a row")
        .unwrap();
    for h in 1..=12u64 {
        let txs = if h == 3 {
            vec![delegate(0, seeded()[5], 1_000)]
        } else {
            Vec::new()
        };
        chain.produce(txs);
    }
    assert_eq!(chain.stored_epochs(), vec![1], "only the planted row");
    assert_eq!(
        chain.db.get(cf::STATE, &VsetLayout::row_key(1)).unwrap(),
        Some(b"not a row".to_vec())
    );
}

#[test]
fn with_a_configuration_only_the_rows_and_their_undo_records_differ() {
    let mut plain = Chain::new(None);
    let mut wired = Chain::new(Some(membership(4, 0)));
    for h in 1..=9u64 {
        let txs = |n| {
            if h == 3 {
                vec![delegate(n, seeded()[5], 1_000)]
            } else {
                Vec::new()
            }
        };
        let a = plain.produce(txs(0));
        let b = wired.produce(txs(0));
        // The same block, to the byte: the row is not folded into the root.
        assert_eq!(a, b, "block {h}");
    }
    assert_eq!(plain.stored_epochs(), Vec::<u64>::new());
    assert_eq!(wired.stored_epochs(), vec![1, 2]);

    let strip = |r: Rows| -> Rows {
        r.into_iter()
            .filter(|((family, key), _)| {
                !(family == cf::STATE && key.starts_with(VsetLayout::prefix()))
                    && family != cf::APPLICATION_JOURNAL
            })
            .collect()
    };
    let (p, w) = (rows(&plain.db), rows(&wired.db));
    let journal_keys = |r: &Rows| -> Vec<Vec<u8>> {
        r.keys()
            .filter(|(f, _)| f == cf::APPLICATION_JOURNAL)
            .map(|(_, k)| k.clone())
            .collect()
    };
    assert_eq!(
        journal_keys(&p),
        journal_keys(&w),
        "one undo record per block"
    );
    assert!(strip(p) == strip(w), "every other row is identical");
}

// ── with a configuration: the publication batch ─────────────────────────────

#[test]
fn a_boundary_row_is_staged_in_its_block_and_committed_only_by_its_publication() {
    let m = membership(4, 0);
    let mut chain = Chain::new(Some(m.clone()));
    chain.produce(Vec::new());
    chain.produce(Vec::new());
    // Block 3 executed and dropped: no row.
    chain.execute_and_drop(Vec::new()).unwrap();
    assert_eq!(chain.stored_epochs(), Vec::<u64>::new());
    // Published: the row lands with it, and its undo record names the row.
    let b3 = chain.produce(Vec::new());
    assert_eq!(chain.stored_epochs(), vec![1]);
    assert_eq!(chain.set_at(4, &m), smallest_five());
    let journal = chain
        .db
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(3, &b3.hash()),
        )
        .unwrap()
        .unwrap();
    let journal =
        sumchain_storage::journal::ApplicationJournal::decode_for(&journal, 3, &b3.hash()).unwrap();
    assert!(journal
        .entries()
        .iter()
        .any(|e| e.cf() == cf::STATE && e.key() == VsetLayout::row_key(1).as_slice()));
    // Blocks 4..=6 write nothing; block 7 writes row[2].
    for _ in 4..=6 {
        chain.produce(Vec::new());
        assert_eq!(chain.stored_epochs(), vec![1]);
    }
    chain.produce(Vec::new());
    assert_eq!(chain.stored_epochs(), vec![1, 2]);
}

#[test]
fn q4_reads_the_transition_blocks_own_transactions() {
    let m = membership(4, 0);
    // The delegation in the transition block itself: key 0x36 joins, first.
    let mut chain = Chain::new(Some(m.clone()));
    chain.produce(Vec::new());
    chain.produce(Vec::new());
    chain.produce(vec![delegate(0, seeded()[5], 1_000)]);
    let mut want = vec![seeded()[5]];
    want.extend_from_slice(&seeded()[..4]);
    assert_eq!(chain.set_at(4, &m), want);

    // One block later: it is not in the transition block's post-state.
    let mut later = Chain::new(Some(m.clone()));
    for _ in 1..=3 {
        later.produce(Vec::new());
    }
    later.produce(vec![delegate(0, seeded()[5], 1_000)]);
    assert_eq!(later.set_at(4, &m), smallest_five());
}

#[test]
fn a_failing_transition_fails_its_block_and_no_other() {
    let mut chain = Chain::new(Some(membership(4, 0)));
    chain
        .db
        .put(cf::VALIDATORS, &[0x40; 32], b"not a validator")
        .unwrap();
    chain.produce(Vec::new());
    chain.produce(Vec::new());
    let err = chain.execute_and_drop(Vec::new()).unwrap_err();
    assert!(
        err.to_string().contains("validator-set transition"),
        "{err}"
    );
    assert_eq!(chain.stored_epochs(), Vec::<u64>::new());
}

/// S1(a) and S2(a) through the executor, with activation immediately before,
/// exactly on and immediately after a boundary, for L = 1 and L = 10, plus
/// A = 0. The blocks that write, and the epochs they write, are by hand.
#[test]
fn activation_immediately_before_exactly_on_and_after_a_boundary_including_l1() {
    // (L, A, [(the block that writes, the epoch it writes); 2]), by hand.
    type Case = (u64, u64, [(u64, u64); 2]);
    #[rustfmt::skip]
    let cases: [Case; 8] = [
        (1, 0, [(1, 2), (2, 3)]),
        (1, 4, [(4, 5), (5, 6)]),
        (1, 5, [(5, 6), (6, 7)]),
        (1, 6, [(6, 7), (7, 8)]),
        (10, 0, [(9, 1), (19, 2)]),
        (10, 29, [(29, 3), (39, 4)]),
        (10, 30, [(39, 4), (49, 5)]),
        (10, 31, [(39, 4), (49, 5)]),
    ];
    for (l, a, writes) in cases {
        let m = membership(l, a);
        let mut chain = Chain::new(Some(m.clone()));
        let mut want = Vec::new();
        for h in 1..=writes[1].0 {
            chain.produce(Vec::new());
            if let Some((_, e)) = writes.iter().find(|(t, _)| *t == h) {
                want.push(*e);
            }
            assert_eq!(chain.stored_epochs(), want, "L={l} A={a} after block {h}");
        }
        let first = writes[0].0;
        for h in 0..=first {
            assert_eq!(chain.set_at(h, &m), anchor(), "L={l} A={a} h={h}");
        }
        assert_eq!(chain.set_at(first + 1, &m), smallest_five(), "L={l} A={a}");
    }
}
