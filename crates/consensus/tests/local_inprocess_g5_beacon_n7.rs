//! LOCAL IN-PROCESS TEST (#351, from #127): seven engines, two beacon DKGs
//! across a G5 validator-set change, with a reorg and a restart.
//!
//! # What this is NOT
//!
//! * **Not a devnet run, and not #351's devnet acceptance.** There is no
//!   network: blocks are handed from the proposing engine to the six others
//!   directly, in one process.
//! * **Not DKG or production acceptance** for #351, #127 or #352. Nothing here
//!   is audited, measured or ratified. The window lengths, the epoch lengths,
//!   the stakes and every key are test fixtures.
//! * **Not certified finality.** Nothing in consensus writes a certificate
//!   yet (#350). Q2 is satisfied by writing the certified-commit layout's
//!   finalized pointer directly into each node's database ([`certify`]), as
//!   #361's own tests do. A real node would also refuse to boot on such a
//!   pointer once #358's start-up audit lands, which is why every restart here
//!   reopens the engine in-process rather than through `Node::run`.
//! * **Not transaction-registered validator keys.** Staking rows are seeded with
//!   real keys before genesis: today `CreateValidator` registers a zero-padded
//!   address that cannot sign (B9-a,
//!   `state/tests/staking_padded_key_selection.rs`).
//! * The beacon gate and schedule are opened in test-local `ChainParams` built
//!   in code (`Genesis::new`, which validates nothing). The genesis loader
//!   refuses `beacon_enabled_from_height` on every network, and so does
//!   `StateManager::init_from_genesis` (it runs `ChainParams::validate`). So
//!   each node creates its chain with [`for_chain_creation`], the same genesis
//!   with the beacon fields cleared: the genesis block and state do not depend
//!   on `params`, so the chain is the same, and the engines then execute under
//!   the open gate. This is a test-only genesis path; nothing in production
//!   creates or runs a chain this way. Protocol v1 still refuses
//!   `staking.epoch_length != 0`; the G5 configuration carries its own epoch
//!   length.
//!
//! # What it shows, on real RocksDB databases and the engines' own propose and
//! import paths (`PoAEngine::new_with_dormant_membership`)
//!
//! Seven validators V0..V6. The anchor (genesis) set is S0 = V0..V4. Staking
//! rows: V0..V3 and V5 at 1,000, V4 at 500, V6 at 100. G5: L = 20, A = 1,
//! `max_validators` 5, N_min 5. Beacon profile f = 1, c = 1, T = 2, Q_dkg = 3,
//! n = 5; beacon epochs of 30 blocks from height 1.
//!
//! 1. Beacon epoch 0 over S0: four members register (V4 never acts in the
//!    beacon), deal, one dealing is corrupt and proven by complaint, QUAL is the
//!    three honest dealers, and two chained rounds finalize under the group key
//!    computed here from their polynomials.
//! 2. The transition at block 19, with a reorg. Two competing blocks 19A and
//!    19B by V4: A carries a delegation that puts V6 into the next set, B does
//!    not. Six nodes import A and then B; V5 imports only B. B wins, row 1 is
//!    B's set S1 = {V0, V1, V2, V3, V5} on every node, and V6 (which saw A then
//!    B) holds byte for byte what V5 (which saw only B) holds, except A's
//!    archive rows.
//! 3. Q2: height 20 has no proposer on any node until block 19 is certified;
//!    then S1's proposer produces it, and the same block re-signed by V4 (now
//!    outside the set) is refused on import.
//! 4. Beacon epoch 1 snapshots S1 at its first block (31): V4's registration
//!    is refused, all five S1 members register and deal, QUAL is all five, and
//!    two chained rounds finalize under PK₁ ≠ PK₀.
//! 5. V2 is closed and reopened in the middle of the epoch-1 DKG (after the
//!    deals); it resolves S1 from its rows, keeps importing and proposing, and
//!    ends with what every other node holds.
//! 6. Throughout: every node holds the same block at every height, the same
//!    `vset/` rows and the same beacon rows, and reports the same validators.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_beacon_crypto::{
    aggregate_g1, combine, dleq_prove, ecies_open, ecies_seal, eval_share_le, feldman_check,
    verify, DleqContext, EciesContext, G1Point, PartialSignature, PublicKey, SecretScalar,
    Signature, SCALAR_SIZE,
};
use sumchain_beacon_runtime::wire::{beacon_output, genesis_seed, round_message, ChainInput};
use sumchain_consensus::consensus_config::check_at_startup;
use sumchain_consensus::membership::DormantMembershipRules;
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{BeaconParamsConfig, ChainParams, Genesis};
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::beacon_wire::{
    BeaconFinalizeV1, BeaconOperation, BeaconPartialV1, DkgComplaintV1, DkgDealV1,
    RegisterBeaconKeyV1,
};
use sumchain_primitives::staking::{DelegateData, StakingOperation, StakingTxData};
use sumchain_primitives::{
    BeaconTxData, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
    ValidatorInfo,
};
use sumchain_state::beacon_manager::{committed_group_key, CommittedGroupKey};
use sumchain_state::beacon_store::BeaconStore;
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::FINALIZED_POINTER_KEY;
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::validator_set_g5::{EpochSchedule, G5Membership, VsetLayout};
use sumchain_storage::{cf, BlockStore, Database, ReceiptStore, StakingStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;
/// G5: epoch length and activation height. Test fixtures.
const L: u64 = 20;
const A: u64 = 1;
/// Beacon membership size and threshold profile (the ratified v1 profile).
const N: u32 = 5;
/// The index of V6, a pure follower: it is in no set this run produces, so it
/// never proposes, and it is the node the run reads the chain's view from.
const V6: usize = 6;
const V5: usize = 5;
const V4: usize = 4;
const V2: usize = 2;

// Beacon epoch 0 (start 1): keys 1..=3, deals 4..=6, complaints 7..=9,
// signing 10..=30. Epoch 1 (start 31): keys 31..=33, deals 34..=36,
// complaints 37..=39, signing 40..=60.
const E0_KEYS_AT: u64 = 1;
const E0_DEALS_AT: u64 = 4;
const E0_COMPLAINTS_AT: u64 = 7;
const E0_ROUNDS_AT: [u64; 2] = [10, 11];
const TRANSITION: u64 = 19;
const E1_KEYS_AT: u64 = 31;
const E1_DEALS_AT: u64 = 34;
const SECOND_TRANSITION: u64 = 39;
const E1_ROUNDS_AT: [u64; 2] = [40, 41];

/// Epoch 0: the member that deals one corrupt share, its victim, and the
/// member that never acts in the beacon (anchor indices).
const INVALID_DEALER: u32 = 3;
const VICTIM: u32 = 1;
const CRASHED: u32 = 4;

fn params() -> ChainParams {
    ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        beacon_enabled_from_height: Some(0),
        beacon_params: Some(BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: N,
        }),
        beacon_schedule: Some(BeaconSchedule {
            start_height: 1,
            epoch_length: 30,
            key_cutoff_offset: 2,
            deal_start_offset: 3,
            deal_cutoff_offset: 5,
            complaint_start_offset: 6,
            complaint_deadline_offset: 8,
        }),
        ..ChainParams::with_v2_enabled()
    }
}

fn rules() -> DormantMembershipRules {
    DormantMembershipRules {
        epoch_length: L,
        activation: A,
        min_stake: 1,
        max_validators: 5,
    }
}

/// A canonical scalar (top byte zero, so below `r`), distinct per label.
fn secret(label: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut out =
        *Hash::hash(&[b"sumchain-local-g5-beacon:".as_slice(), label].concat()).as_bytes();
    out[SCALAR_SIZE - 1] = 0;
    out
}

fn scalar(label: &[u8]) -> SecretScalar {
    SecretScalar::from_bytes_le(&secret(label)).unwrap()
}

fn validator_key(i: usize) -> KeyPair {
    KeyPair::from_bytes(secret(&[b'v', i as u8]))
}

fn delegator() -> KeyPair {
    KeyPair::from_bytes(secret(b"delegator"))
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn copy(k: &KeyPair) -> KeyPair {
    KeyPair::from_bytes(*k.private_key().as_bytes())
}

fn s0() -> Vec<[u8; 32]> {
    (0..5).map(|i| pk(&validator_key(i))).collect()
}

/// Q4 over the seeded stakes (block 19B): the five at 1,000, by key.
fn s1() -> Vec<[u8; 32]> {
    let mut set: Vec<[u8; 32]> = [0, 1, 2, 3, 5]
        .iter()
        .map(|&i| pk(&validator_key(i)))
        .collect();
    set.sort();
    set
}

/// Q4 after block 19A's delegation of 2,000 to V6: V6 first, then the four
/// smallest keys of the five at 1,000.
fn s1_with_delegation() -> Vec<[u8; 32]> {
    let mut rest = s1();
    rest.truncate(4);
    let mut set = vec![pk(&validator_key(V6))];
    set.extend(rest);
    set
}

fn genesis() -> Genesis {
    let mut alloc = HashMap::new();
    for i in 0..7 {
        alloc.insert(
            validator_key(i).address().to_base58(),
            1_000_000_000_000u128,
        );
    }
    alloc.insert(delegator().address().to_base58(), 1_000_000_000_000u128);
    Genesis::new(
        CHAIN_ID,
        0,
        (0..5)
            .map(|i| validator_key(i).public_key().to_base58())
            .collect(),
        alloc,
        params(),
    )
}

/// The genesis a node creates its chain from: `g` with the beacon fields
/// cleared, because chain creation validates `params` and refuses an open
/// beacon gate (module docs). The genesis block and the genesis state are
/// functions of the chain id, time, validators and allocations only, so they
/// are the same as `g`'s; the engines run under `g`.
fn for_chain_creation(g: &Genesis) -> Genesis {
    let mut c = g.clone();
    c.params.beacon_enabled_from_height = None;
    c.params.beacon_params = None;
    c.params.beacon_schedule = None;
    assert_eq!(
        c.create_genesis_block().unwrap().hash(),
        g.create_genesis_block().unwrap().hash()
    );
    c
}

fn seed(db: &Database) {
    let store = StakingStore::new(db);
    for (i, stake) in [
        (0, 1_000),
        (1, 1_000),
        (2, 1_000),
        (3, 1_000),
        (4, 500),
        (5, 1_000),
        (6, 100),
    ] {
        store
            .put_validator(&ValidatorInfo::new(pk(&validator_key(i)), stake, 0, 0))
            .unwrap();
    }
}

/// Simulated certification of `b` (module docs): the finalized pointer,
/// height (LE) ‖ hash, which nothing in consensus writes yet.
fn certify(db: &Database, b: &Block) {
    let mut v = b.height().to_le_bytes().to_vec();
    v.extend_from_slice(b.hash().as_bytes());
    db.put(cf::META, FINALIZED_POINTER_KEY, &v).unwrap();
}

fn resign(b: &mut Block, signer: &KeyPair) {
    b.header.proposer_pubkey = pk(signer);
    let s = sign(b.header.signing_hash().as_bytes(), signer.private_key());
    b.header.set_signature(*s.as_bytes());
}

// ── nodes ───────────────────────────────────────────────────────────────────

struct Node {
    dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    engine: Arc<PoAEngine>,
    key: KeyPair,
}

fn engine_on(
    db: &Arc<Database>,
    state: &Arc<StateManager>,
    g: &Genesis,
    key: &KeyPair,
) -> PoAEngine {
    PoAEngine::new_with_dormant_membership(
        db.clone(),
        state.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        g,
        Some(copy(key)),
        rules(),
    )
    .unwrap()
}

impl Node {
    fn new(g: &Genesis, key: KeyPair) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        seed(&db);
        check_at_startup(&db, g, 0).unwrap();
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = Arc::new(engine_on(&db, &state, g, &key));
        engine.init_genesis(&for_chain_creation(g)).unwrap();
        Self {
            dir,
            db,
            state,
            engine,
            key,
        }
    }

    /// Close every handle, reopen the same directory, construct and load.
    fn restart(self, g: &Genesis) -> Self {
        let Node {
            dir,
            db,
            state,
            engine,
            key,
        } = self;
        drop(engine);
        drop(state);
        assert_eq!(Arc::strong_count(&db), 1, "every database handle is closed");
        drop(db);
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = Arc::new(engine_on(&db, &state, g, &key));
        engine.load_chain().unwrap();
        Self {
            dir,
            db,
            state,
            engine,
            key,
        }
    }

    fn head(&self) -> Block {
        BlockStore::new(&self.db).get_latest().unwrap().unwrap()
    }

    fn vset_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let prefix = VsetLayout::prefix();
        self.db
            .iter_checked_from(cf::STATE, Some(prefix))
            .unwrap()
            .map(|e| e.unwrap())
            .map(|(k, v)| (k.into_vec(), v.into_vec()))
            .take_while(|(k, _)| k.starts_with(prefix))
            .collect()
    }

    fn beacon_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.db
            .iter_checked_from(cf::BEACON_STATE, None)
            .unwrap()
            .map(|e| e.unwrap())
            .map(|(k, v)| (k.into_vec(), v.into_vec()))
            .collect()
    }

    fn status(&self, tx: &SignedTransaction) -> Option<TxStatus> {
        ReceiptStore::new(&self.db)
            .get(&tx.hash())
            .unwrap()
            .map(|r| r.status)
    }
}

/// The next block: proposed by the rightful proposer's own engine, imported
/// by every other node. Every node's head is that block afterwards.
async fn step(nodes: &[Node], txs: Vec<SignedTransaction>) -> Block {
    let height = nodes[V6].engine.current_height() + 1;
    let want = nodes[V6].engine.get_proposer(height);
    assert_ne!(want, [0u8; 32], "height {height} has a proposer");
    let p = nodes
        .iter()
        .position(|n| pk(&n.key) == want)
        .expect("the proposer is one of the seven");
    let b = nodes[p].engine.propose_block(txs).await.unwrap();
    assert_eq!(b.height(), height);
    for (i, n) in nodes.iter().enumerate() {
        if i != p {
            n.engine
                .import_block(b.clone())
                .await
                .unwrap_or_else(|e| panic!("node {i} imports block {height}: {e}"));
        }
    }
    for n in nodes {
        assert_eq!(n.head().hash(), b.hash(), "height {height}");
    }
    b
}

/// [`step`] for a block whose transactions must all have been included and
/// succeeded (read from V6's receipts).
async fn step_ok(nodes: &[Node], txs: Vec<SignedTransaction>) -> Block {
    let b = step(nodes, txs.clone()).await;
    for (n, tx) in txs.iter().enumerate() {
        assert_eq!(
            nodes[V6].status(tx),
            Some(TxStatus::Success),
            "height {}, transaction {n}",
            b.height()
        );
    }
    b
}

/// Empty blocks up to and including `height`.
async fn until(nodes: &[Node], height: u64) {
    while nodes[V6].engine.current_height() < height {
        step(nodes, Vec::new()).await;
    }
}

fn assert_all_agree(nodes: &[Node], what: &str) {
    let reference = &nodes[V6];
    let head = reference.head().height();
    let store = BlockStore::new(&reference.db);
    for (i, n) in nodes.iter().enumerate() {
        let other = BlockStore::new(&n.db);
        for h in 0..=head {
            assert_eq!(
                other.get_hash_by_height(h).unwrap(),
                store.get_hash_by_height(h).unwrap(),
                "{what}: node {i}, height {h}"
            );
        }
        assert_eq!(
            n.vset_rows(),
            reference.vset_rows(),
            "{what}: node {i}, vset rows"
        );
        assert_eq!(
            n.beacon_rows(),
            reference.beacon_rows(),
            "{what}: node {i}, beacon rows"
        );
        assert_eq!(
            n.engine.validators(),
            reference.engine.validators(),
            "{what}: node {i}, validators"
        );
    }
}

/// Every row of every family is equal, except the archive rows of blocks only
/// `left` has seen.
fn assert_same_database(left: &Database, right: &Database, left_only: &[Block], what: &str) {
    fn rows(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
        let mut out = BTreeMap::new();
        for family in ALL_CFS {
            for entry in db.iter_checked_from(family, None).unwrap() {
                let (k, v) = entry.unwrap();
                out.insert((family.to_string(), k.into_vec()), v.into_vec());
            }
        }
        out
    }
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
    let lk: BTreeSet<_> = l.keys().cloned().collect();
    let rk: BTreeSet<_> = r.keys().cloned().collect();
    let only_l: Vec<_> = lk.difference(&rk).take(3).collect();
    let only_r: Vec<_> = rk.difference(&lk).take(3).collect();
    let differ: Vec<_> = lk
        .intersection(&rk)
        .filter(|k| l[*k] != r[*k])
        .take(3)
        .collect();
    assert!(
        only_l.is_empty() && only_r.is_empty() && differ.is_empty(),
        "{what}: databases differ. only left: {only_l:?}; only right: {only_r:?}; values differ: {differ:?}"
    );
}

// ── the beacon's carriers, per epoch ────────────────────────────────────────

/// A beacon epoch's members in membership order: index `j` signs as `keys[j]`.
struct Members {
    epoch: u64,
    keys: Vec<KeyPair>,
}

impl Members {
    fn of(epoch: u64, set: &[[u8; 32]]) -> Self {
        let keys = set
            .iter()
            .map(|p| {
                (0..7)
                    .map(validator_key)
                    .find(|k| pk(k) == *p)
                    .expect("a member is one of the seven")
            })
            .collect();
        Members { epoch, keys }
    }

    fn ek(&self, j: u32) -> SecretScalar {
        scalar(&[b'e', self.epoch as u8, j as u8])
    }

    fn registration(&self, j: u32) -> RegisterBeaconKeyV1 {
        let k = self.ek(j);
        RegisterBeaconKeyV1 {
            chain_id: CHAIN_ID,
            epoch: self.epoch,
            ek_j: k.public_g1().to_compressed(),
            pop: k.pop_prove().to_compressed(),
        }
    }

    fn setup_tx(&self, signer: &KeyPair, op: BeaconOperation) -> SignedTransaction {
        beacon_tx(
            signer,
            TxPayload::BeaconSetup(BeaconTxData::from_operation(&op).unwrap()),
        )
    }

    fn signing_tx(&self, signer: &KeyPair, op: BeaconOperation) -> SignedTransaction {
        beacon_tx(
            signer,
            TxPayload::BeaconSigning(BeaconTxData::from_operation(&op).unwrap()),
        )
    }

    fn registrations(&self, registrants: &[u32]) -> Vec<SignedTransaction> {
        registrants
            .iter()
            .map(|&j| {
                self.setup_tx(
                    &self.keys[j as usize],
                    BeaconOperation::RegisterBeaconKey(self.registration(j)),
                )
            })
            .collect()
    }

    fn deal(&self, dealer: &Dealer, i: u32, j: u32, corrupt: bool) -> DkgDealV1 {
        let e = self.epoch as u8;
        let ek_j = self.ek(j).public_g1();
        let r = scalar(&[b'r', e, i as u8, j as u8]);
        let r_ij = r.public_g1();
        let share = if corrupt {
            secret(&[b'x', e, i as u8, j as u8])
        } else {
            dealer.share(j)
        };
        let ctx = EciesContext {
            chain_id: CHAIN_ID,
            epoch: self.epoch,
            dealer_i: i,
            recipient_j: j,
            r_ij,
            ek_j,
        };
        DkgDealV1 {
            chain_id: CHAIN_ID,
            epoch: self.epoch,
            dealer_i: i,
            recipient_j: j,
            commitments: dealer
                .commitment_points()
                .iter()
                .map(|c| c.to_compressed())
                .collect(),
            r_ij: r_ij.to_compressed(),
            ct_ij: ecies_seal(&r.ecdh(&ek_j).unwrap(), &ctx, &share).unwrap(),
        }
    }

    fn deal_txs(&self, deals: &Deals) -> Vec<SignedTransaction> {
        deals
            .values()
            .map(|d| {
                self.setup_tx(
                    &self.keys[d.dealer_i as usize],
                    BeaconOperation::DkgDeal(d.clone()),
                )
            })
            .collect()
    }

    /// Recipient `j`'s reading of its deal: the share and whether it agrees
    /// with the dealer's commitments.
    fn open(&self, deal: &DkgDealV1) -> ([u8; SCALAR_SIZE], bool) {
        let j = deal.recipient_j;
        let r_ij = G1Point::from_compressed(&deal.r_ij).unwrap();
        let ctx = EciesContext {
            chain_id: CHAIN_ID,
            epoch: self.epoch,
            dealer_i: deal.dealer_i,
            recipient_j: j,
            r_ij,
            ek_j: self.ek(j).public_g1(),
        };
        let share = *ecies_open(&self.ek(j).ecdh(&r_ij).unwrap(), &ctx, &deal.ct_ij).unwrap();
        let commitments: Vec<G1Point> = deal
            .commitments
            .iter()
            .map(|c| G1Point::from_compressed(c).unwrap())
            .collect();
        let consistent = feldman_check(&commitments, u64::from(j) + 1, &share).unwrap();
        (share, consistent)
    }

    fn complaint(&self, deal: &DkgDealV1) -> DkgComplaintV1 {
        let (i, j) = (deal.dealer_i, deal.recipient_j);
        let ek_j = self.ek(j);
        let r_ij = G1Point::from_compressed(&deal.r_ij).unwrap();
        let d_ij = ek_j.ecdh(&r_ij).unwrap();
        let ctx = DleqContext {
            chain_id: CHAIN_ID.to_le_bytes().to_vec(),
            epoch: self.epoch,
            dealer_index: i,
            recipient_index: j,
        };
        let proof = dleq_prove(
            &ctx,
            &G1Point::generator(),
            &ek_j.public_g1(),
            &r_ij,
            &d_ij,
            &ek_j,
            &secret(&[b'k', self.epoch as u8, i as u8, j as u8]),
        )
        .unwrap()
        .to_bytes();
        let mut dleq_c = [0u8; SCALAR_SIZE];
        let mut dleq_z = [0u8; SCALAR_SIZE];
        dleq_c.copy_from_slice(&proof[..SCALAR_SIZE]);
        dleq_z.copy_from_slice(&proof[SCALAR_SIZE..]);
        DkgComplaintV1 {
            chain_id: CHAIN_ID,
            epoch: self.epoch,
            i,
            j,
            r_ij: deal.r_ij,
            d_ij: d_ij.to_compressed(),
            dleq_c,
            dleq_z,
        }
    }

    /// `sk_j = Σ_{i∈QUAL} s_ij` for each recipient, from what it decrypted.
    fn signing_shares(
        &self,
        deals: &Deals,
        qual: &[u32],
        recipients: &[u32],
    ) -> BTreeMap<u32, SecretScalar> {
        recipients
            .iter()
            .map(|&j| {
                let sk_j = qual
                    .iter()
                    .map(|&i| {
                        let (share, consistent) = self.open(&deals[&(i, j)]);
                        assert!(consistent, "a QUAL dealer's share to {j} is consistent");
                        SecretScalar::from_bytes_le(&share).unwrap()
                    })
                    .reduce(|acc, s| acc.add(&s))
                    .unwrap();
                (j, sk_j)
            })
            .collect()
    }

    fn message(&self, round: u64, prev: Option<&Signature>) -> Vec<u8> {
        match prev {
            None => round_message(
                CHAIN_ID,
                self.epoch,
                round,
                &ChainInput::GenesisSeed(genesis_seed(CHAIN_ID, &[0u8; 32])),
            ),
            Some(sigma) => round_message(CHAIN_ID, self.epoch, round, &ChainInput::Previous(sigma)),
        }
    }

    /// One round's transactions: a partial from every member holding a share,
    /// then a finalize by member 0 whose `Σ_r` combines `witness`'s partials.
    fn round_txs(
        &self,
        round: u64,
        msg: &[u8],
        shares: &BTreeMap<u32, SecretScalar>,
        witness: [u32; 2],
    ) -> (Vec<SignedTransaction>, Signature) {
        let mut txs = Vec::new();
        for (&j, sk_j) in shares {
            let partial = BeaconPartialV1 {
                chain_id: CHAIN_ID,
                epoch: self.epoch,
                round,
                j,
                sigma_j: sk_j.sign(msg).to_compressed(),
            };
            txs.push(self.signing_tx(
                &self.keys[j as usize],
                BeaconOperation::BeaconPartial(partial),
            ));
        }
        let sigma = combine(
            &witness.map(|j| PartialSignature::new(u64::from(j) + 1, shares[&j].sign(msg))),
        )
        .unwrap();
        txs.push(self.signing_tx(
            &self.keys[0],
            BeaconOperation::BeaconFinalize(BeaconFinalizeV1 {
                chain_id: CHAIN_ID,
                epoch: self.epoch,
                round,
                sigma_r: sigma.to_compressed(),
                witness: witness.to_vec(),
            }),
        ));
        (txs, sigma)
    }
}

/// A signed V2 transaction. Beacon transactions charge no fee and leave the
/// nonce alone, so every one of them is nonce 0.
fn beacon_tx(signer: &KeyPair, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: signer.address(),
        fee: params().min_fee,
        nonce: 0,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), signer.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(signer))
}

fn delegate_to_v6(amount: u128) -> SignedTransaction {
    let from = delegator();
    let data = bincode::serialize(&DelegateData {
        validator_pubkey: pk(&validator_key(V6)),
        amount,
    })
    .unwrap();
    let tx = TransactionV2::staking(
        CHAIN_ID,
        from.address(),
        1_000,
        0,
        StakingTxData {
            operation: StakingOperation::Delegate,
            data,
        },
    );
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), pk(&from))
}

/// Accepted deals by `(dealer, recipient)`.
type Deals = BTreeMap<(u32, u32), DkgDealV1>;

/// One dealer's secret polynomial `f_i(x) = a_0 + a_1·x` (degree `T − 1`).
struct Dealer {
    coeffs: [[u8; SCALAR_SIZE]; 2],
}

impl Dealer {
    fn new(epoch: u64, i: u32) -> Self {
        Dealer {
            coeffs: [
                secret(&[b'a', epoch as u8, i as u8, 0]),
                secret(&[b'a', epoch as u8, i as u8, 1]),
            ],
        }
    }

    fn commitment_points(&self) -> Vec<G1Point> {
        self.coeffs
            .iter()
            .map(|c| SecretScalar::from_bytes_le(c).unwrap().public_g1())
            .collect()
    }

    fn share(&self, j: u32) -> [u8; SCALAR_SIZE] {
        *eval_share_le(&self.coeffs, u64::from(j) + 1).unwrap()
    }
}

fn group_key(dealers: &[&Dealer]) -> PublicKey {
    let constants: Vec<G1Point> = dealers.iter().map(|d| d.commitment_points()[0]).collect();
    PublicKey::from_g1_point(aggregate_g1(&constants).unwrap())
}

/// Two chained rounds at `heights`: each `Σ` verifies under `pk_e`, and every
/// node holds the same finalized round and output; the two outputs differ.
async fn two_rounds(
    nodes: &[Node],
    m: &Members,
    heights: [u64; 2],
    shares: &BTreeMap<u32, SecretScalar>,
    witness: [u32; 2],
    pk_e: &PublicKey,
) {
    let mut prev: Option<Signature> = None;
    let mut outputs = Vec::new();
    for (round, height) in [(0u64, heights[0]), (1, heights[1])] {
        until(nodes, height - 1).await;
        let msg = m.message(round, prev.as_ref());
        let (txs, sigma) = m.round_txs(round, &msg, shares, witness);
        step_ok(nodes, txs).await;
        assert!(
            verify(pk_e, &msg, &sigma),
            "epoch {} Σ_{round} verifies",
            m.epoch
        );
        for n in nodes {
            let held = BeaconStore::new(&n.db)
                .get_finalized_round(m.epoch, round)
                .unwrap()
                .expect("the round is finalized");
            assert_eq!(held.sigma_r, sigma.to_compressed());
            assert_eq!(held.output, beacon_output(CHAIN_ID, m.epoch, round, &sigma));
        }
        outputs.push(beacon_output(CHAIN_ID, m.epoch, round, &sigma));
        prev = Some(sigma);
    }
    assert_ne!(outputs[0], outputs[1], "chained rounds differ");
}

#[tokio::test]
async fn local_inprocess_seven_engines_two_dkgs_across_a_g5_set_change() {
    let g = genesis();
    let mut nodes: Vec<Node> = (0..7).map(|i| Node::new(&g, validator_key(i))).collect();
    let config = G5Membership::new(EpochSchedule::new(L, A).unwrap(), 5, 5, 1, s0()).unwrap();
    assert_ne!(s1(), s0());
    assert_ne!(s1_with_delegation(), s1());

    // ── 1. Beacon epoch 0 over S0 ──────────────────────────────────────────
    let m0 = Members::of(0, &s0());
    let live0: Vec<u32> = (0..N).filter(|&j| j != CRASHED).collect();
    until(&nodes, E0_KEYS_AT - 1).await;
    step_ok(&nodes, m0.registrations(&live0)).await;
    for n in &nodes {
        assert_eq!(
            BeaconStore::new(&n.db).get_membership(0).unwrap(),
            Some(s0())
        );
    }

    let dealers0: BTreeMap<u32, Dealer> = live0.iter().map(|&i| (i, Dealer::new(0, i))).collect();
    let mut deals0 = Deals::new();
    for &i in &live0 {
        for &j in &live0 {
            let corrupt = (i, j) == (INVALID_DEALER, VICTIM);
            deals0.insert((i, j), m0.deal(&dealers0[&i], i, j, corrupt));
        }
    }
    until(&nodes, E0_DEALS_AT - 1).await;
    step_ok(&nodes, m0.deal_txs(&deals0)).await;
    for ((i, j), d) in &deals0 {
        assert_eq!(
            m0.open(d).1,
            (*i, *j) != (INVALID_DEALER, VICTIM),
            "deal {i} -> {j}"
        );
    }

    until(&nodes, E0_COMPLAINTS_AT - 1).await;
    let bad = &deals0[&(INVALID_DEALER, VICTIM)];
    step_ok(
        &nodes,
        vec![m0.setup_tx(
            &m0.keys[VICTIM as usize],
            BeaconOperation::DkgComplaint(m0.complaint(bad)),
        )],
    )
    .await;
    for n in &nodes {
        let t = BeaconStore::new(&n.db).get_dkg_transcript(0).unwrap();
        assert_eq!(
            t.disqualified
                .iter()
                .map(|d| d.dealer_i)
                .collect::<Vec<_>>(),
            vec![INVALID_DEALER]
        );
    }

    let qual0: Vec<u32> = live0
        .iter()
        .copied()
        .filter(|&i| i != INVALID_DEALER)
        .collect();
    let pk0 = group_key(&qual0.iter().map(|i| &dealers0[i]).collect::<Vec<_>>());
    let shares0 = m0.signing_shares(&deals0, &qual0, &live0);
    two_rounds(&nodes, &m0, E0_ROUNDS_AT, &shares0, [0, 2], &pk0).await;
    for n in &nodes {
        assert_eq!(
            committed_group_key(&n.db, &params(), CHAIN_ID, 0).unwrap(),
            Some(CommittedGroupKey {
                qual: qual0.clone(),
                group_key: pk0.to_compressed(),
            })
        );
    }
    assert_all_agree(&nodes, "after beacon epoch 0");

    // ── 2. The transition block 19, with a reorg ───────────────────────────
    until(&nodes, TRANSITION - 1).await;
    assert!(
        nodes[V6].vset_rows().is_empty(),
        "no row before the first transition"
    );
    let parent = nodes[V6].head();
    let v4 = validator_key(V4);
    assert_eq!(nodes[V6].engine.get_proposer(TRANSITION), pk(&v4));
    // Drafted off V4's node by an executor under the same configuration;
    // executing a draft publishes nothing.
    let drafter = BlockExecutor::new(
        nodes[V4].state.clone(),
        nodes[V4].db.clone(),
        g.params.clone(),
    )
    .with_dormant_membership(Arc::new(config.clone()));
    let draft = |txs: Vec<SignedTransaction>, salt: u64| {
        let mut b = Block::new(
            BlockHeader::new(
                parent.hash(),
                TRANSITION,
                parent.header.timestamp + 1 + salt,
                Hash::ZERO,
                Hash::ZERO,
                pk(&v4),
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let exec = drafter
            .execute_block(&b, nodes[V4].state.state_root(), &s0())
            .unwrap();
        b.header.state_root = exec.computed_root();
        drop(exec);
        resign(&mut b, &v4);
        b
    };
    let a19 = draft(vec![delegate_to_v6(2_000)], 0);
    let b19 = (1..10_000)
        .map(|salt| draft(Vec::new(), salt))
        .find(|b| b.hash() < a19.hash())
        .expect("a block 19 that wins the tiebreak");
    drop(drafter);

    for (i, n) in nodes.iter().enumerate() {
        if i == V5 {
            continue;
        }
        n.engine.import_block(a19.clone()).await.unwrap();
        assert_eq!(n.head().hash(), a19.hash());
    }
    let row_set = |n: &Node| {
        sumchain_storage::validator_set_g5::resolve_set(
            &*n.db,
            &s0(),
            TRANSITION + 1,
            config.schedule(),
        )
        .unwrap()
    };
    assert_eq!(
        row_set(&nodes[V6]),
        s1_with_delegation(),
        "A's row names V6"
    );
    for n in &nodes {
        n.engine.import_block(b19.clone()).await.unwrap();
        assert_eq!(n.head().hash(), b19.hash(), "B wins");
        assert_eq!(row_set(n), s1(), "B's row on every node");
    }
    assert_same_database(
        &nodes[V6].db,
        &nodes[V5].db,
        &[a19.clone()],
        "A then B equals B only",
    );

    // ── 3. Q2: nothing governs height 20 until block 19 is certified ───────
    for n in &nodes {
        assert_eq!(n.engine.get_proposer(TRANSITION + 1), [0u8; 32]);
        assert!(n.engine.validators().is_empty());
    }
    let would_be = nodes
        .iter()
        .position(|n| pk(&n.key) == s1()[((TRANSITION + 1) % 5) as usize])
        .unwrap();
    assert!(nodes[would_be]
        .engine
        .propose_block(Vec::new())
        .await
        .is_err());
    for n in &nodes {
        certify(&n.db, &b19);
    }
    for n in &nodes {
        assert_eq!(n.engine.validators(), s1());
    }
    // Block 20 by S1's proposer; first, the same block re-signed by V4 (now
    // outside the set) is refused by a follower.
    let p20 = nodes
        .iter()
        .position(|n| pk(&n.key) == s1()[((TRANSITION + 1) % 5) as usize])
        .unwrap();
    let b20 = nodes[p20].engine.propose_block(Vec::new()).await.unwrap();
    let mut by_v4 = b20.clone();
    resign(&mut by_v4, &v4);
    assert!(
        nodes[V6].engine.import_block(by_v4).await.is_err(),
        "V4 no longer proposes"
    );
    for (i, n) in nodes.iter().enumerate() {
        if i != p20 {
            n.engine.import_block(b20.clone()).await.unwrap();
        }
    }
    assert_all_agree(&nodes, "after the set change");

    // ── 4. Beacon epoch 1 snapshots S1 ──────────────────────────────────────
    until(&nodes, E1_KEYS_AT - 1).await;
    let m1 = Members::of(1, &s1());
    let all1: Vec<u32> = (0..N).collect();
    // V4's registration for epoch 1, as if it were still a member.
    let outsider = Members {
        epoch: 1,
        keys: vec![copy(&v4)],
    };
    // Its own encryption key (label 9), distinct from every member's.
    let v4_registration = outsider.setup_tx(
        &v4,
        BeaconOperation::RegisterBeaconKey(outsider.registration(9)),
    );
    let mut txs = m1.registrations(&all1);
    txs.push(v4_registration.clone());
    step(&nodes, txs.clone()).await;
    for tx in &txs[..all1.len()] {
        assert_eq!(nodes[V6].status(tx), Some(TxStatus::Success));
    }
    // Refused: either not carried, or carried and failed. Printed so a run
    // with --nocapture shows which.
    println!(
        "V4's epoch-1 registration: {:?}",
        nodes[V6].status(&v4_registration)
    );
    assert_ne!(
        nodes[V6].status(&v4_registration),
        Some(TxStatus::Success),
        "V4 is not a member of beacon epoch 1"
    );
    for n in &nodes {
        let store = BeaconStore::new(&n.db);
        assert_eq!(
            store.get_membership(1).unwrap(),
            Some(s1()),
            "the epoch-1 snapshot is S1"
        );
        let keys = store.get_dkg_transcript(1).unwrap().keys;
        assert_eq!(
            keys.iter().map(|k| k.validator_index).collect::<Vec<_>>(),
            all1
        );
        let v4_ek = outsider.ek(9).public_g1().to_compressed().to_vec();
        assert!(keys.iter().all(|k| k.ek != v4_ek));
    }

    let dealers1: BTreeMap<u32, Dealer> = all1.iter().map(|&i| (i, Dealer::new(1, i))).collect();
    let mut deals1 = Deals::new();
    for &i in &all1 {
        for &j in &all1 {
            deals1.insert((i, j), m1.deal(&dealers1[&i], i, j, false));
        }
    }
    until(&nodes, E1_DEALS_AT - 1).await;
    step_ok(&nodes, m1.deal_txs(&deals1)).await;

    // ── 5. V2 restarts in the middle of the epoch-1 DKG ─────────────────────
    let v2 = nodes.remove(V2);
    nodes.insert(V2, v2.restart(&g));
    assert_eq!(nodes[V2].engine.validators(), s1(), "S1 from V2's rows");
    assert_eq!(nodes[V2].head().height(), E1_DEALS_AT);

    // The second transition (block 39) carries S1 forward on its stakes; its
    // set governs from 40 once it is certified.
    until(&nodes, SECOND_TRANSITION).await;
    let b39 = nodes[V6].head();
    for n in &nodes {
        assert_eq!(n.engine.get_proposer(SECOND_TRANSITION + 1), [0u8; 32]);
        certify(&n.db, &b39);
    }

    let qual1 = all1.clone();
    let pk1 = group_key(&qual1.iter().map(|i| &dealers1[i]).collect::<Vec<_>>());
    assert_ne!(
        pk1.to_compressed(),
        pk0.to_compressed(),
        "a fresh group key"
    );
    let shares1 = m1.signing_shares(&deals1, &qual1, &all1);
    two_rounds(&nodes, &m1, E1_ROUNDS_AT, &shares1, [0, 1], &pk1).await;
    for n in &nodes {
        assert_eq!(
            committed_group_key(&n.db, &params(), CHAIN_ID, 1).unwrap(),
            Some(CommittedGroupKey {
                qual: qual1.clone(),
                group_key: pk1.to_compressed(),
            })
        );
        let t = BeaconStore::new(&n.db).get_dkg_transcript(1).unwrap();
        assert!(t.disqualified.is_empty() && t.false_accusers.is_empty());
    }

    // ── 6. Every node holds the same chain, rows and beacon state ──────────
    assert_all_agree(&nodes, "at the end");
    let vset = nodes[V6].vset_rows();
    let epochs: Vec<u64> = vset
        .iter()
        .map(|(k, _)| u64::from_be_bytes(k[VsetLayout::prefix().len()..].try_into().unwrap()))
        .collect();
    assert_eq!(epochs, vec![1, 2], "rows written by blocks 19 and 39 only");
    for epoch_height in [TRANSITION + 1, SECOND_TRANSITION + 1] {
        assert_eq!(
            sumchain_storage::validator_set_g5::resolve_set(
                &*nodes[V6].db,
                &s0(),
                epoch_height,
                config.schedule()
            )
            .unwrap(),
            s1()
        );
    }
    assert_eq!(nodes[V6].engine.validators(), s1());
}
