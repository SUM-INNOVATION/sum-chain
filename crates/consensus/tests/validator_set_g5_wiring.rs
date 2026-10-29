//! The dormant G5 validator-set wiring in the engine (#351), on real on-disk
//! RocksDB, through the live import and proposer paths.
//!
//! `PoAEngine::new_with_dormant_membership` is constructed here, and only in
//! tests: no production path calls it. With it:
//! * the anchor membership is field 0x0003 of the node's ConsensusConfig
//!   record;
//! * the stored rows are checked before the rules govern the database, and
//!   again on every load, and a database that cannot be proven canonical is
//!   refused with the resynchronization requirement;
//! * header validation and the proposer resolve the set for block H from the
//!   canonical ancestry of H's parent, and a set governs only once its
//!   transition block is certified (Q2);
//! * a chain switch removes the abandoned blocks' rows and applies the adopted
//!   ones in its one batch;
//! * a restart resolves membership from the canonical head.
//!
//! `PoAEngine::new` (every production path) is checked to be unchanged on the
//! same data.
//!
//! Certification is simulated by writing the certified-commit layout's
//! finalized pointer directly: nothing in consensus writes it yet. Every key,
//! stake, schedule and value is synthetic; nothing selects an epoch length,
//! activation height, stake minimum or `max_validators` for any chain.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::consensus_config::check_at_startup;
use sumchain_consensus::membership::DormantMembershipRules;
use sumchain_consensus::reorg::{execute_rollback, plan_rollback};
use sumchain_consensus::{ConsensusEngine, ConsensusError, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::staking::{DelegateData, StakingOperation, StakingParams, StakingTxData};
use sumchain_primitives::{
    Block, BlockHeader, Hash, SignedTransaction, TransactionV2, ValidatorInfo, ValidatorSet,
    ValidatorSetEntry,
};
use sumchain_state::reorg_undo::ActivatedJournal;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::{decode_pointer, FINALIZED_POINTER_KEY};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::journal::ActivationSource;
use sumchain_storage::schema::{StakingStore, ValidatorSetStore};
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::validator_set_g5::{resolve_set, EpochSchedule, G5Membership, VsetLayout};
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// N_min = 5, ratified 2026-10-21; the engine passes
/// `pool_topology::PRODUCT_MINIMUM` itself. Here only for the builder.
const RATIFIED_N_MIN: usize = 5;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn copy(k: &KeyPair) -> KeyPair {
    KeyPair::from_bytes(*k.private_key().as_bytes())
}

/// The genesis validators: the anchor membership.
fn anchor_keys() -> Vec<KeyPair> {
    vec![key(1), key(2)]
}

fn anchor() -> Vec<[u8; 32]> {
    anchor_keys().iter().map(pk).collect()
}

/// Six staking validators with real keys, seeded into committed staking state
/// before genesis, self-stake 100 each.
fn staking_keys() -> Vec<KeyPair> {
    (0x21..=0x26).map(key).collect()
}

fn delegator() -> KeyPair {
    key(0x41)
}

/// The staking validator Q4 leaves out when all six totals are equal: the
/// largest key.
fn left_out() -> [u8; 32] {
    staking_keys().iter().map(pk).max().unwrap()
}

/// Q4 over the seeded state with equal totals: the five smallest keys.
fn equal_stake_set() -> Vec<[u8; 32]> {
    let mut all: Vec<[u8; 32]> = staking_keys().iter().map(pk).collect();
    all.sort();
    all.truncate(5);
    all
}

/// Q4 after the delegator moves 1,000 to [`left_out`]: it first, then the four
/// smallest of the rest.
fn delegated_set() -> Vec<[u8; 32]> {
    let mut rest: Vec<[u8; 32]> = staking_keys()
        .iter()
        .map(pk)
        .filter(|k| *k != left_out())
        .collect();
    rest.sort();
    let mut set = vec![left_out()];
    set.extend_from_slice(&rest[..4]);
    set
}

fn params() -> ChainParams {
    ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_v2_enabled()
    }
}

fn genesis_with(validators: &[KeyPair], params: ChainParams) -> Genesis {
    let mut alloc = HashMap::new();
    for k in validators.iter().chain([&delegator()]) {
        alloc.insert(k.address().to_base58(), 1_000_000_000u128);
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

fn genesis() -> Genesis {
    genesis_with(&anchor_keys(), params())
}

fn rules(l: u64, a: u64) -> DormantMembershipRules {
    DormantMembershipRules {
        epoch_length: l,
        activation: a,
        min_stake: 1,
        max_validators: 5,
    }
}

/// The configuration the engine builds from `rules(l, a)`, for the builder.
fn builder_membership(l: u64, a: u64) -> Arc<G5Membership> {
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

fn seed(db: &Database) {
    let store = StakingStore::new(db);
    for k in staking_keys() {
        store
            .put_validator(&ValidatorInfo::new(pk(&k), 100, 0, 0))
            .unwrap();
    }
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
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(&from))
}

/// Simulated certification of `b`: the certified-commit layout's finalized
/// pointer (height LE ‖ hash), which nothing in consensus writes yet.
fn certify(db: &Database, b: &Block) {
    let mut v = b.height().to_le_bytes().to_vec();
    v.extend_from_slice(b.hash().as_bytes());
    assert_eq!(decode_pointer(&v).unwrap().height, b.height());
    db.put(cf::META, FINALIZED_POINTER_KEY, &v).unwrap();
}

/// Re-sign `b` by `signer`, as that signer's proposal.
fn resign(b: &mut Block, signer: &KeyPair) {
    b.header.proposer_pubkey = pk(signer);
    let s = sign(b.header.signing_hash().as_bytes(), signer.private_key());
    b.header.set_signature(*s.as_bytes());
}

/// Put `b` in the block archive directly, as `archive_noncanonical` would.
fn archive(db: &Database, b: &Block) {
    db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
        .unwrap();
    for tx in &b.transactions {
        db.put(cf::TRANSACTIONS, tx.hash().as_bytes(), &tx.to_bytes())
            .unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A block builder off the node under test: its own database, real execution,
// its own configuration (or none).
// ─────────────────────────────────────────────────────────────────────────────

struct Builder {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    membership: Option<Arc<G5Membership>>,
    head: Block,
}

impl Builder {
    fn new(g: &Genesis, membership: Option<Arc<G5Membership>>) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        seed(&db);
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
        let executor = match &membership {
            None => executor,
            Some(m) => executor.with_dormant_membership(m.clone()),
        };
        Self {
            _dir: dir,
            db,
            state,
            executor,
            membership,
            head,
        }
    }

    /// The set for `height`, from this builder's committed rows (no Q2: a
    /// builder is not a validating node).
    fn set_at(&self, height: u64) -> Vec<[u8; 32]> {
        match &self.membership {
            None => anchor(),
            Some(m) => resolve_set(&*self.db, m.anchor(), height, m.schedule()).unwrap(),
        }
    }

    fn signer(&self, height: u64) -> KeyPair {
        let set = self.set_at(height);
        let want = set[(height % set.len() as u64) as usize];
        anchor_keys()
            .into_iter()
            .chain(staking_keys())
            .find(|k| pk(k) == want)
            .unwrap()
    }

    /// The next block, executed and signed by its rightful proposer, NOT
    /// published. `salt` shifts the timestamp.
    fn draft(&self, txs: Vec<SignedTransaction>, salt: u64) -> Block {
        self.draft_by(txs, salt, &self.signer(self.head.height() + 1))
    }

    /// [`Self::draft`], proposed and signed by `signer`, rightful or not.
    fn draft_by(&self, txs: Vec<SignedTransaction>, salt: u64, signer: &KeyPair) -> Block {
        let height = self.head.height() + 1;
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10 + salt,
                Hash::ZERO,
                Hash::ZERO,
                pk(signer),
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let validators = self.set_at(height);
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &validators)
            .unwrap();
        b.header.state_root = exec.computed_root();
        drop(exec);
        resign(&mut b, signer);
        b
    }

    /// Execute and publish a block produced elsewhere (or drafted here).
    fn follow(&mut self, b: &Block) {
        let validators = self.set_at(b.height());
        let exec = self
            .executor
            .execute_block(b, self.state.state_root(), &validators)
            .unwrap();
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_imported(b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
    }

    fn produce(&mut self, txs: Vec<SignedTransaction>) -> Block {
        let b = self.draft(txs, 0);
        self.follow(&b);
        b
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The node under test: a real engine on a real on-disk database, reopenable.
// ─────────────────────────────────────────────────────────────────────────────

struct Node {
    dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    rules: Option<DormantMembershipRules>,
    engine: Arc<PoAEngine>,
}

fn engine_on(
    db: &Arc<Database>,
    state: &Arc<StateManager>,
    g: &Genesis,
    rules: Option<DormantMembershipRules>,
    key: Option<KeyPair>,
) -> sumchain_consensus::Result<PoAEngine> {
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    match rules {
        None => PoAEngine::new(db.clone(), state.clone(), mempool, g, key),
        Some(r) => {
            PoAEngine::new_with_dormant_membership(db.clone(), state.clone(), mempool, g, key, r)
        }
    }
}

impl Node {
    /// A fresh node: staking seeded, the consensus-configuration baseline
    /// recorded (as node start does, before the engine), genesis initialized.
    fn new(g: &Genesis, rules: Option<DormantMembershipRules>) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        seed(&db);
        check_at_startup(&db, g, 0).unwrap();
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = Arc::new(engine_on(&db, &state, g, rules, None).unwrap());
        engine.init_genesis(g).unwrap();
        Self {
            dir,
            db,
            state,
            rules,
            engine,
        }
    }

    /// Close every handle and reopen the same directory: construction, then
    /// `load_chain`, with the node's configuration (or `rules`).
    fn restart(
        self,
        g: &Genesis,
        rules: Option<DormantMembershipRules>,
    ) -> Result<Self, (TempDir, ConsensusError)> {
        let Node {
            dir,
            db,
            state,
            engine,
            ..
        } = self;
        drop(engine);
        drop(state);
        assert_eq!(Arc::strong_count(&db), 1, "every database handle is closed");
        drop(db);
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = match engine_on(&db, &state, g, rules, None) {
            Ok(e) => Arc::new(e),
            Err(e) => {
                drop(state);
                drop(db);
                return Err((dir, e));
            }
        };
        if let Err(e) = engine.load_chain() {
            drop(engine);
            drop(state);
            drop(db);
            return Err((dir, e));
        }
        Ok(Self {
            dir,
            db,
            state,
            rules,
            engine,
        })
    }

    /// An engine over this node's database holding `key`, loaded from it: how
    /// a validator with that key would propose here.
    fn proposer(&self, g: &Genesis, key: &KeyPair) -> PoAEngine {
        let e = engine_on(&self.db, &self.state, g, self.rules, Some(copy(key))).unwrap();
        e.load_chain().unwrap();
        e
    }

    async fn import(&self, b: &Block) -> sumchain_consensus::Result<()> {
        self.engine.import_block(b.clone()).await
    }

    fn head(&self) -> Block {
        BlockStore::new(&self.db).get_latest().unwrap().unwrap()
    }

    /// The set for `height` from committed rows, without Q2.
    fn rows_set(&self, height: u64, l: u64, a: u64) -> Vec<[u8; 32]> {
        let m = builder_membership(l, a);
        resolve_set(&*self.db, m.anchor(), height, m.schedule()).unwrap()
    }

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

/// The whole database is equal, except for the archive rows (`BLOCKS[hash]`,
/// `TRANSACTIONS[hash]`) of blocks only `left` has seen.
fn assert_same_database(left: &Database, right: &Database, left_only: &[Block], what: &str) {
    let mut extra = BTreeSet::new();
    for b in left_only {
        extra.insert((cf::BLOCKS.to_string(), b.hash().as_bytes().to_vec()));
        for tx in &b.transactions {
            extra.insert((cf::TRANSACTIONS.to_string(), tx.hash().as_bytes().to_vec()));
        }
    }
    let r = rows(right);
    let mut l = rows(left);
    for k in &extra {
        if !r.contains_key(k) {
            assert!(l.remove(k).is_some(), "{what}: expected archive row {k:?}");
        }
    }
    if l != r {
        let lk: BTreeSet<_> = l.keys().collect();
        let rk: BTreeSet<_> = r.keys().collect();
        let only_l: Vec<_> = lk.difference(&rk).take(3).collect();
        let only_r: Vec<_> = rk.difference(&lk).take(3).collect();
        let differ: Vec<_> = lk
            .intersection(&rk)
            .filter(|k| l[**k] != r[**k])
            .take(3)
            .collect();
        panic!("{what}: databases differ. only left: {only_l:?}; only right: {only_r:?}; values differ: {differ:?}");
    }
}

fn is_membership(r: &sumchain_consensus::Result<()>) -> bool {
    matches!(r, Err(ConsensusError::Membership(_)))
}

// ── construction: the anchor and protocol v1's refusals ─────────────────────

#[tokio::test]
async fn the_anchor_is_the_consensus_configuration_records_validator_list() {
    let g = genesis();
    let open = |record_from: Option<&Genesis>| {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        if let Some(r) = record_from {
            check_at_startup(&db, r, 0).unwrap();
        }
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let made = engine_on(&db, &state, &g, Some(rules(4, 0)), None);
        (dir, made)
    };

    // No record: refused; the production constructor needs none.
    let (_d, made) = open(None);
    let err = made.err().expect("no record, no anchor");
    assert!(
        matches!(&err, ConsensusError::Membership(m) if m.contains("holds no record")),
        "{err}"
    );

    // A record of another validator list: refused.
    let other = genesis_with(&[key(9), key(10)], params());
    let (_d, made) = open(Some(&other));
    let err = made.err().expect("a record of another list");
    assert!(
        matches!(&err, ConsensusError::Membership(m) if m.contains("differs from the genesis list")),
        "{err}"
    );

    // The node's own record: the anchor governs epoch 0.
    let (_d, made) = open(Some(&g));
    let engine = made.unwrap();
    engine.init_genesis(&g).unwrap();
    assert_eq!(engine.validators(), anchor());
    for h in 0..4 {
        assert_eq!(engine.get_proposer(h), anchor()[(h % 2) as usize]);
    }
}

#[tokio::test]
async fn protocol_v1_refusals_still_apply_and_the_values_are_checked() {
    // staking.epoch_length != 0 is refused by both constructors.
    let mut p = params();
    p.staking = Some(StakingParams {
        epoch_length: 4,
        ..StakingParams::default()
    });
    let g = genesis_with(&anchor_keys(), p);
    for r in [None, Some(rules(4, 0))] {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        assert!(
            matches!(
                engine_on(&db, &state, &g, r, None),
                Err(ConsensusError::Genesis(_))
            ),
            "{r:?}"
        );
        drop(dir);
    }
    // L = 0 and max_validators above 29,127 are refused.
    let g = genesis();
    for bad in [
        DormantMembershipRules {
            epoch_length: 0,
            ..rules(4, 0)
        },
        DormantMembershipRules {
            max_validators: 29_128,
            ..rules(4, 0)
        },
    ] {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        check_at_startup(&db, &g, 0).unwrap();
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        assert!(
            matches!(
                engine_on(&db, &state, &g, Some(bad), None),
                Err(ConsensusError::Membership(_))
            ),
            "{bad:?}"
        );
    }
}

// ── startup: a database that cannot be proven canonical ─────────────────────

#[tokio::test]
async fn startup_refuses_a_database_it_cannot_prove_canonical_and_production_is_unchanged() {
    let g = genesis();
    let r = Some(rules(4, 0));
    let legacy = |db: &Database| {
        let set = ValidatorSet::new(
            1,
            4,
            vec![ValidatorSetEntry::new(anchor()[0], 10, 0)],
            [0; 32],
        );
        ValidatorSetStore::new(db).put_validator_set(&set).unwrap();
    };
    let rowless = |db: &Database| {
        db.put(cf::STATE, &VsetLayout::row_key(0), b"x").unwrap();
    };
    let malformed = |db: &Database| {
        db.put(cf::STATE, &[VsetLayout::prefix(), b"abc"].concat(), b"x")
            .unwrap();
    };
    type Plant<'a> = (&'a str, &'a dyn Fn(&Database));
    let cases: [Plant; 3] = [
        ("legacy epoch set", &legacy),
        ("row for a rowless epoch", &rowless),
        ("malformed row key", &malformed),
    ];
    for (what, plant) in cases {
        let node = Node::new(&g, None);
        plant(&node.db);
        // Under the configuration: refused at construction, with the
        // resynchronization requirement.
        let (dir, err) = match node.restart(&g, r) {
            Ok(_) => panic!("{what}: a database with a {what} was accepted"),
            Err(x) => x,
        };
        assert!(matches!(&err, ConsensusError::Genesis(_)), "{what}: {err}");
        assert!(
            err.to_string().contains("resynchronize from genesis"),
            "{what}: {err}"
        );

        // Production: exactly what it did before. The legacy row is refused by
        // the engine's own check; a `vset/` row is never read.
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = engine_on(&db, &state, &g, None, None).unwrap();
        let loaded = engine.load_chain();
        if what == "legacy epoch set" {
            let err = loaded.unwrap_err();
            assert!(err.to_string().contains("(#266)"), "{err}");
        } else {
            loaded.unwrap().unwrap();
            assert_eq!(engine.validators(), anchor());
        }
        drop(engine);
        drop(state);
        drop(db);

        // Before the rules first govern a database: a fresh one, with no
        // block yet, is refused at construction, before genesis.
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        check_at_startup(&db, &g, 0).unwrap();
        plant(&db);
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let err = engine_on(&db, &state, &g, r, None)
            .err()
            .unwrap_or_else(|| panic!("{what}: a fresh database with a {what} was accepted"));
        assert!(
            err.to_string().contains("resynchronize from genesis"),
            "{what}: {err}"
        );
    }
}

// ── the proposer and import paths around the first transition ───────────────

/// S1(a) and S2(a) on the live paths, with activation immediately before,
/// exactly on and immediately after a boundary, for L = 1 and L = 10, plus
/// A = 0. Each case proposes every block through `propose_block` (the
/// proposer's own engine) and imports it into a follower:
/// * through the first transition block the anchor proposes, with no
///   certificate;
/// * the first transition block writes its row in its publication batch, on
///   both nodes;
/// * the next height has no proposer and is refused on import until that
///   block is certified (Q2), and then the new set's proposer proposes it.
#[tokio::test]
async fn activation_immediately_before_exactly_on_and_after_a_boundary_on_the_live_paths() {
    // (L, A, the first transition block, the row it writes), by hand.
    #[rustfmt::skip]
    let cases: [(u64, u64, u64, u64); 8] = [
        (1, 0, 1, 2),
        (1, 4, 4, 5),
        (1, 5, 5, 6),
        (1, 6, 6, 7),
        (10, 0, 9, 1),
        (10, 29, 29, 3),
        (10, 30, 39, 4),
        (10, 31, 39, 4),
    ];
    let g = genesis();
    for (l, a, first, row) in cases {
        let what = format!("L={l} A={a}");
        let p = Node::new(&g, Some(rules(l, a)));
        let f = Node::new(&g, Some(rules(l, a)));
        let mut first_block = None;
        for h in 1..=first {
            let signer = &anchor_keys()[(h % 2) as usize];
            let e = p.proposer(&g, signer);
            assert!(e.is_proposer(h), "{what} h={h}");
            let b = e.propose_block(Vec::new()).await.unwrap();
            assert_eq!(b.height(), h);
            f.import(&b).await.unwrap();
            assert_eq!(
                f.stored_epochs(),
                if h == first { vec![row] } else { vec![] },
                "{what} h={h}"
            );
            first_block = Some(b);
        }
        let first_block = first_block.unwrap();
        assert_eq!(p.stored_epochs(), vec![row], "{what}");
        assert_eq!(p.rows_set(first + 1, l, a), equal_stake_set(), "{what}");

        // The next height: the new set, which does not govern yet.
        let next = first + 1;
        let set = equal_stake_set();
        let signer = staking_keys()
            .into_iter()
            .find(|k| pk(k) == set[(next % 5) as usize])
            .unwrap();
        let e = p.proposer(&g, &signer);
        assert!(!e.is_proposer(next), "{what}");
        assert_eq!(e.get_proposer(next), [0u8; 32], "{what}");
        assert!(e.propose_block(Vec::new()).await.is_err(), "{what}");
        drop(e);
        certify(&p.db, &first_block);
        let e = p.proposer(&g, &signer);
        assert!(e.is_proposer(next), "{what}");
        let b = e.propose_block(Vec::new()).await.unwrap();
        assert_eq!(b.header.proposer_pubkey, pk(&signer), "{what}");

        // The follower refuses it until it too has the certificate.
        assert!(is_membership(&f.import(&b).await), "{what}");
        assert_eq!(f.head().height(), first, "{what}");
        certify(&f.db, &first_block);
        f.import(&b).await.unwrap();
        assert_eq!(f.head().hash(), b.hash(), "{what}");
    }
}

// ── the chain switch: apply A, revert A, apply B ────────────────────────────

/// A shared prefix (blocks 1, 2), then two competing transition blocks at
/// height 3. A carries a delegation that changes Q4's set; B does not, and
/// wins the hash tiebreak. A is imported first (a direct extension), then B
/// (a chain switch).
struct Fork {
    g: Genesis,
    prefix: Vec<Block>,
    a3: Block,
    b3: Block,
    b: Builder,
}

fn fork() -> Fork {
    let g = genesis();
    let mut a = Builder::new(&g, Some(builder_membership(4, 0)));
    let mut b = Builder::new(&g, Some(builder_membership(4, 0)));
    let prefix = vec![a.produce(Vec::new()), a.produce(Vec::new())];
    for blk in &prefix {
        b.follow(blk);
    }
    let a3 = a.produce(vec![delegate(0, left_out(), 1_000)]);
    let b3 = (0..10_000)
        .map(|salt| b.draft(Vec::new(), salt))
        .find(|blk| blk.hash() < a3.hash())
        .expect("a block 3 that wins the tiebreak");
    b.follow(&b3);
    assert_eq!(a.set_at(4), delegated_set());
    assert_eq!(b.set_at(4), equal_stake_set());
    assert_ne!(delegated_set(), equal_stake_set());
    Fork {
        g,
        prefix,
        a3,
        b3,
        b,
    }
}

#[tokio::test]
async fn apply_a_revert_a_apply_b_leaves_exactly_b_on_the_live_import_path() {
    let mut w = fork();
    let x = Node::new(&w.g, Some(rules(4, 0)));
    for blk in &w.prefix {
        x.import(blk).await.unwrap();
    }
    assert_eq!(x.stored_epochs(), Vec::<u64>::new());

    // Apply A: its row lands with it.
    x.import(&w.a3).await.unwrap();
    assert_eq!(x.head().hash(), w.a3.hash());
    assert_eq!(x.rows_set(4, 4, 0), delegated_set());

    // Revert A, apply B, in one switch.
    x.import(&w.b3).await.unwrap();
    assert_eq!(x.head().hash(), w.b3.hash());
    assert_eq!(x.stored_epochs(), vec![1]);
    assert_eq!(x.rows_set(4, 4, 0), equal_stake_set());

    // B only: the whole database equals a node that never saw A.
    let only_b = Node::new(&w.g, Some(rules(4, 0)));
    for blk in w.prefix.iter().chain([&w.b3]) {
        only_b.import(blk).await.unwrap();
    }
    assert_same_database(
        &x.db,
        &only_b.db,
        &[w.a3.clone()],
        "apply A, revert A, apply B",
    );

    // B's set governs block 4, once block 3 is certified; A's never does.
    let b4 = w.b.produce(Vec::new());
    assert!(is_membership(&x.import(&b4).await));
    assert_eq!(x.engine.get_proposer(4), [0u8; 32]);
    certify(&x.db, &w.b3);
    assert_eq!(x.engine.get_proposer(4), equal_stake_set()[4]);
    assert_eq!(x.engine.validators(), equal_stake_set());
    let mut by_a = b4.clone();
    let a_signer = staking_keys()
        .into_iter()
        .find(|k| pk(k) == delegated_set()[4])
        .unwrap();
    assert_ne!(pk(&a_signer), b4.header.proposer_pubkey);
    resign(&mut by_a, &a_signer);
    assert!(
        x.import(&by_a).await.is_err(),
        "A's proposer for height 4 is refused"
    );
    x.import(&b4).await.unwrap();
    assert_eq!(x.head().hash(), b4.hash());
}

/// A block of a replacement branch is validated, inside the switch, against
/// the set its own parent state resolves: a branch block that never passed
/// import (archived directly, executed honestly, proposed by the wrong key)
/// refuses the whole switch, and nothing canonical changes.
#[tokio::test]
async fn a_replacement_block_is_validated_against_its_own_parent_states_set() {
    let g = genesis();
    let mut a = Builder::new(&g, Some(builder_membership(4, 0)));
    let mut b = Builder::new(&g, Some(builder_membership(4, 0)));
    let b1 = a.produce(Vec::new());
    b.follow(&b1);
    let a2 = a.produce(Vec::new());
    let a3 = a.produce(Vec::new());
    // Height 2's proposer is anchor[0]; this one is anchor[1].
    let wrong = &anchor_keys()[1];
    let b2 = b.draft_by(Vec::new(), 1, wrong);
    assert_ne!(b2.header.proposer_pubkey, a2.header.proposer_pubkey);
    b.follow(&b2);
    let b3 = (0..10_000)
        .map(|salt| b.draft(Vec::new(), salt))
        .find(|blk| blk.hash() < a3.hash())
        .expect("a block 3 that wins the tiebreak");

    let x = Node::new(&g, Some(rules(4, 0)));
    for blk in [&b1, &a2, &a3] {
        x.import(blk).await.unwrap();
    }
    let before = rows(&x.db);
    archive(&x.db, &b2);
    let refused = x.import(&b3).await;
    assert!(
        matches!(&refused, Err(ConsensusError::InvalidBlock(m)) if m.contains("Invalid proposer")),
        "{refused:?}"
    );
    assert_eq!(x.head().hash(), a3.hash());
    assert!(x.engine.halted_reason().is_none());
    let mut after = rows(&x.db);
    for blk in [&b2, &b3] {
        after.remove(&(cf::BLOCKS.to_string(), blk.hash().as_bytes().to_vec()));
    }
    assert!(after == before, "nothing but the archive changed");
}

/// Under Q2 capped at the fork point, a block whose ancestry left the
/// canonical chain below its epoch's transition block is not governed, even
/// when the canonical transition is certified: the row the canonical chain
/// holds is not on that block's ancestry.
#[tokio::test]
async fn a_block_whose_ancestry_left_the_canonical_chain_below_its_transition_is_not_governed() {
    let w = fork();
    let x = Node::new(&w.g, Some(rules(4, 0)));
    // Canonical: 1, 2, 3A (certified).
    for blk in w.prefix.iter().chain([&w.a3]) {
        x.import(blk).await.unwrap();
    }
    certify(&x.db, &w.a3);
    // Side: 3B archived, then 4B on it, proposed by B's set.
    archive(&x.db, &w.b3);
    let mut b = w.b;
    let b4 = b.produce(Vec::new());
    let refused = x.import(&b4).await;
    assert!(is_membership(&refused), "{refused:?}");
    assert_eq!(x.head().hash(), w.a3.hash());
}

// ── restart: membership from the canonical head ─────────────────────────────

#[tokio::test]
async fn a_restart_resolves_membership_from_the_canonical_head() {
    let mut w = fork();
    let g = w.g.clone();
    let x = Node::new(&g, Some(rules(4, 0)));
    for blk in w.prefix.iter().chain([&w.b3]) {
        x.import(blk).await.unwrap();
    }
    certify(&x.db, &w.b3);
    let b4 = w.b.produce(Vec::new());
    x.import(&b4).await.unwrap();
    let proposers =
        |n: &Node| -> Vec<[u8; 32]> { (0..16).map(|h| n.engine.get_proposer(h)).collect() };
    let before = (proposers(&x), x.engine.validators());
    assert_eq!(before.1, equal_stake_set());
    // Heights 8.. need row[2], which block 7 has not written: no proposer.
    assert_eq!(before.0[8], [0u8; 32]);

    let x = x
        .restart(&g, Some(rules(4, 0)))
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!((proposers(&x), x.engine.validators()), before);
    let b5 = w.b.produce(Vec::new());
    x.import(&b5).await.unwrap();

    // The head's governing row lost: refused, never the anchor.
    x.db.delete(cf::STATE, &VsetLayout::row_key(1)).unwrap();
    let (dir, err) = match x.restart(&g, Some(rules(4, 0))) {
        Ok(_) => panic!("a database missing the head's row was accepted"),
        Err(x) => x,
    };
    assert!(
        err.to_string().contains("resynchronize from genesis"),
        "{err}"
    );
    assert!(
        err.to_string().contains("no validator-set row") || err.to_string().contains("required"),
        "{err}"
    );
    drop(dir);
}

/// The operator rollback unwinds a transition block's row with the rest of
/// its state, in its one batch; the restarted node resolves membership from
/// the new head, and the height can be filled again by another transition.
#[tokio::test]
async fn an_operator_rollback_removes_the_rows_of_the_blocks_it_unwinds() {
    let w = fork();
    let g = w.g.clone();
    let x = Node::new(&g, Some(rules(4, 0)));
    for blk in w.prefix.iter().chain([&w.b3]) {
        x.import(blk).await.unwrap();
    }
    assert_eq!(x.stored_epochs(), vec![1]);
    let journals = ActivatedJournal::resolve(
        &x.db,
        ActivationSource::from_configured_height(g.params.application_journal_enabled_from_height),
        SubsystemGates {
            compute_pool: None,
            beacon: None,
        },
    )
    .unwrap();
    let plan = plan_rollback(&BlockStore::new(&x.db), 2, 10, &journals.activation()).unwrap();
    execute_rollback(&x.db, &x.state, &plan, &journals, journals.policy()).unwrap();
    assert_eq!(x.stored_epochs(), Vec::<u64>::new());

    let x = x
        .restart(&g, Some(rules(4, 0)))
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(x.head().height(), 2);
    assert_eq!(x.engine.validators(), anchor());
    x.import(&w.a3).await.unwrap();
    assert_eq!(x.rows_set(4, 4, 0), delegated_set());
}

// ── production: unchanged ───────────────────────────────────────────────────

/// `PoAEngine::new` on the same world: static round robin, no `vset/` row,
/// no consensus-configuration record needed, and a planted `vset/` row
/// never read.
#[tokio::test]
async fn the_production_constructor_writes_and_reads_no_row() {
    let g = genesis();
    let mut b = Builder::new(&g, None);
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    seed(&db);
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let x = engine_on(&db, &state, &g, None, None).unwrap();
    x.init_genesis(&g).unwrap();
    db.put(cf::STATE, &VsetLayout::row_key(1), b"never read")
        .unwrap();
    for h in 1..=12u64 {
        let txs = if h == 3 {
            vec![delegate(0, left_out(), 1_000)]
        } else {
            Vec::new()
        };
        let blk = b.produce(txs);
        x.import_block(blk).await.unwrap();
    }
    let prefix = VsetLayout::prefix();
    let keys: Vec<Vec<u8>> = db
        .iter_checked_from(cf::STATE, Some(prefix))
        .unwrap()
        .map(|e| e.unwrap().0.into_vec())
        .take_while(|k| k.starts_with(prefix))
        .collect();
    assert_eq!(keys, vec![VsetLayout::row_key(1)], "only the planted row");
    for h in 0..40 {
        assert_eq!(x.get_proposer(h), anchor()[(h % 2) as usize]);
    }
    assert_eq!(x.validators(), anchor());
}
