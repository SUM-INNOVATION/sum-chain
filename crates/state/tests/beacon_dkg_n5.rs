//! BR1 (#127): a synthetic n = 5 DKG and chained beacon, driven through blocks
//! that are executed and published the way a proposer publishes them.
//!
//! Library level, one process. This is not the multi-validator devnet the
//! issue's activation conditions name: it is the state machine those validators
//! would run, fed real carriers through `execute_block` -> `accept_produced` ->
//! `publish`, under the ratified profile `f = 1, c = 1, T = 2, Q_dkg = 3,
//! n = 5`. Every secret is derived from a fixed label, so the run is the same
//! on every machine.
//!
//! The beacon gate is opened in test-local `ChainParams` only. Genesis
//! validation refuses `beacon_enabled_from_height` on every network.
//!
//! * [`n5_dkg_survives_an_invalid_dealer_and_a_crash`] — one member deals a
//!   share that decrypts cleanly but contradicts its own commitments, and one
//!   member never acts at all. The victim proves the bad share with a complaint
//!   and the dealer is disqualified; the crashed member is not penalised; the
//!   DKG completes with `|QUAL| = Q_dkg = 3` and two chained rounds finalize
//!   under a group key computed here, independently, from the honest dealers'
//!   polynomials — the key the node derives from its committed rows once the
//!   complaint window has closed, and not before.
//! * [`different_dealings_on_two_forks_give_different_beacons_and_a_reverted_fork_leaves_no_trace`]
//!   — two branches over the same registrations carry different dealings and
//!   produce different beacons. Reverting the first through the reorg unwind
//!   restores the pre-fork state exactly, and the node then holds byte for byte
//!   what a node that only ever saw the second branch holds.
//!
//! Not covered: resharing across an epoch boundary. It needs a validator set
//! that changes between epochs, and protocol v1 refuses dynamic membership
//! (#266), so there is no committed transition to reshare across.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use sumchain_beacon_crypto::{
    aggregate_g1, combine, commitment_poly_eval, dleq_prove, ecies_open, ecies_seal, eval_share_le,
    feldman_check, verify, DleqContext, EciesContext, G1Point, PartialSignature, PublicKey,
    SecretScalar, Signature, SCALAR_SIZE,
};
use sumchain_beacon_runtime::wire::{beacon_output, genesis_seed, round_message, ChainInput};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{BeaconParamsConfig, ChainParams};
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::beacon_wire::{
    BeaconFinalizeV1, BeaconOperation, BeaconPartialV1, DkgComplaintV1, DkgDealV1,
    RegisterBeaconKeyV1,
};
use sumchain_primitives::{BeaconTxData, Block, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::beacon_manager::{committed_group_key, CommittedGroupKey};
use sumchain_state::beacon_store::{BeaconStore, StoredDkgTranscript};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::reorg_undo::{stage_branch_unwind, MissingJournalPolicy, SubsystemJournals};
use sumchain_state::state::StateManager;
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::{cf, Database};

use common::CHAIN_ID;

const EPOCH: u64 = 0;
const N: u32 = 5;

/// The member that deals one corrupted share.
const INVALID_DEALER: u32 = 3;
/// The member that receives it and complains.
const VICTIM: u32 = 1;
/// The member that has crashed: it never registers, deals or signs.
const CRASHED: u32 = 4;

// Heights, against the schedule in `params`: key window 1..=101, deal window
// 201..=301, complaint window 401..=501, signing from 502.
const KEYS_AT: u64 = 1;
const DEALS_AT: u64 = 201;
const COMPLAINTS_AT: u64 = 401;
const ROUND0_AT: u64 = 502;
const ROUND1_AT: u64 = 503;

/// Labels separating the secrets of independent dealings.
const MAIN: u8 = 0x4D;
const FORK_A: u8 = 0x41;
const FORK_B: u8 = 0x42;

/// Test-local: genesis validation refuses an open beacon gate on any network.
fn params() -> ChainParams {
    ChainParams {
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
            epoch_length: 1000,
            key_cutoff_offset: 100,
            deal_start_offset: 200,
            deal_cutoff_offset: 300,
            complaint_start_offset: 400,
            complaint_deadline_offset: 500,
        }),
        ..ChainParams::with_v2_enabled()
    }
}

const GATES: SubsystemGates = SubsystemGates {
    compute_pool: None,
    beacon: Some(0),
};

/// A canonical scalar derived from a label: below `r` because its top byte is
/// zero, and distinct per label.
fn secret(label: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut h = blake3::Hasher::new();
    h.update(b"sumchain-beacon-n5-test:");
    h.update(label);
    let mut out = *h.finalize().as_bytes();
    out[SCALAR_SIZE - 1] = 0;
    out
}

fn scalar(label: &[u8]) -> SecretScalar {
    SecretScalar::from_bytes_le(&secret(label)).unwrap()
}

/// Accepted deals by `(dealer, recipient)`.
type Deals = BTreeMap<(u32, u32), DkgDealV1>;

/// The validators, in membership order: index `j` is `keys[j]`.
struct Members {
    keys: Vec<KeyPair>,
    pubs: Vec<[u8; 32]>,
}

impl Members {
    fn new() -> Self {
        let keys: Vec<KeyPair> = (0..N)
            .map(|i| KeyPair::from_bytes(secret(&[b'v', i as u8])))
            .collect();
        let pubs = keys.iter().map(|k| *k.public_key().as_bytes()).collect();
        Members { keys, pubs }
    }
}

/// Member `j`'s epoch encryption secret `ek_j`.
fn ek(j: u32) -> SecretScalar {
    scalar(&[b'e', j as u8])
}

/// One dealer's secret polynomial `f_i(x) = a_0 + a_1·x` (degree `T − 1`).
struct Dealer {
    coeffs: [[u8; SCALAR_SIZE]; 2],
}

impl Dealer {
    fn new(dealing: u8, i: u32) -> Self {
        Dealer {
            coeffs: [
                secret(&[b'a', dealing, i as u8, 0]),
                secret(&[b'a', dealing, i as u8, 1]),
            ],
        }
    }

    fn commitment_points(&self) -> Vec<G1Point> {
        self.coeffs
            .iter()
            .map(|c| SecretScalar::from_bytes_le(c).unwrap().public_g1())
            .collect()
    }

    /// `f_i(x_j)` with `x_j = j + 1`.
    fn share(&self, j: u32) -> [u8; SCALAR_SIZE] {
        *eval_share_le(&self.coeffs, u64::from(j) + 1).unwrap()
    }
}

fn registration(j: u32) -> RegisterBeaconKeyV1 {
    let k = ek(j);
    RegisterBeaconKeyV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        ek_j: k.public_g1().to_compressed(),
        pop: k.pop_prove().to_compressed(),
    }
}

/// Dealer `i`'s deal to recipient `j`. With `corrupt`, the ciphertext carries a
/// well-formed scalar that is not `f_i(x_j)`: it opens cleanly and fails the
/// Feldman check against the dealer's own commitments.
fn deal(dealing: u8, dealer: &Dealer, i: u32, j: u32, corrupt: bool) -> DkgDealV1 {
    let ek_j = ek(j).public_g1();
    let r = scalar(&[b'r', dealing, i as u8, j as u8]);
    let r_ij = r.public_g1();
    let share = if corrupt {
        secret(&[b'x', dealing, i as u8, j as u8])
    } else {
        dealer.share(j)
    };
    let ctx = EciesContext {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: i,
        recipient_j: j,
        r_ij,
        ek_j,
    };
    DkgDealV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
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

/// What recipient `j` reads out of a deal it was sent: the decrypted share, and
/// whether it agrees with the commitments the deal published.
fn open(deal: &DkgDealV1) -> ([u8; SCALAR_SIZE], bool) {
    let j = deal.recipient_j;
    let r_ij = G1Point::from_compressed(&deal.r_ij).unwrap();
    let ctx = EciesContext {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        dealer_i: deal.dealer_i,
        recipient_j: j,
        r_ij,
        ek_j: ek(j).public_g1(),
    };
    let share = *ecies_open(&ek(j).ecdh(&r_ij).unwrap(), &ctx, &deal.ct_ij).unwrap();
    let commitments: Vec<G1Point> = deal
        .commitments
        .iter()
        .map(|c| G1Point::from_compressed(c).unwrap())
        .collect();
    let consistent = feldman_check(&commitments, u64::from(j) + 1, &share).unwrap();
    (share, consistent)
}

/// Recipient `j`'s public complaint against deal `(i, j)`: the ECDH secret it
/// derived, with a DLEQ proof that it is the right one.
fn complaint(deal: &DkgDealV1) -> DkgComplaintV1 {
    let (i, j) = (deal.dealer_i, deal.recipient_j);
    let ek_j = ek(j);
    let r_ij = G1Point::from_compressed(&deal.r_ij).unwrap();
    let d_ij = ek_j.ecdh(&r_ij).unwrap();
    let ctx = DleqContext {
        chain_id: CHAIN_ID.to_le_bytes().to_vec(),
        epoch: EPOCH,
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
        &secret(&[b'k', i as u8, j as u8]),
    )
    .unwrap()
    .to_bytes();
    let mut dleq_c = [0u8; SCALAR_SIZE];
    let mut dleq_z = [0u8; SCALAR_SIZE];
    dleq_c.copy_from_slice(&proof[..SCALAR_SIZE]);
    dleq_z.copy_from_slice(&proof[SCALAR_SIZE..]);
    DkgComplaintV1 {
        chain_id: CHAIN_ID,
        epoch: EPOCH,
        i,
        j,
        r_ij: deal.r_ij,
        d_ij: d_ij.to_compressed(),
        dleq_c,
        dleq_z,
    }
}

/// A signed V2 transaction from `signer`. Beacon transactions charge no fee and
/// leave the nonce alone, so every one of them is nonce 0.
fn tx(signer: &KeyPair, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: signer.address(),
        fee: params().min_fee,
        nonce: 0,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), signer.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *signer.public_key().as_bytes())
}

fn setup_tx(signer: &KeyPair, op: BeaconOperation) -> SignedTransaction {
    tx(
        signer,
        TxPayload::BeaconSetup(BeaconTxData::from_operation(&op).unwrap()),
    )
}

fn signing_tx(signer: &KeyPair, op: BeaconOperation) -> SignedTransaction {
    tx(
        signer,
        TxPayload::BeaconSigning(BeaconTxData::from_operation(&op).unwrap()),
    )
}

/// The round message `m_r`. Round 0 chains on the genesis seed the executor
/// anchors every epoch at; later rounds on the previous round's `Σ`.
fn message(round: u64, prev: Option<&Signature>) -> Vec<u8> {
    match prev {
        None => round_message(
            CHAIN_ID,
            EPOCH,
            round,
            &ChainInput::GenesisSeed(genesis_seed(CHAIN_ID, &[0u8; 32])),
        ),
        Some(sigma) => round_message(CHAIN_ID, EPOCH, round, &ChainInput::Previous(sigma)),
    }
}

/// One node: its own database and executor.
struct Node {
    state: Arc<StateManager>,
    db: Arc<Database>,
    executor: BlockExecutor,
    _dir: tempfile::TempDir,
}

impl Node {
    fn new(m: &Members) -> Self {
        let (state, db, dir, executor) = common::setup_with_params(params());
        for k in &m.keys {
            common::fund(&db, k, params().min_fee + 1_000_000);
        }
        Node {
            state,
            db,
            executor,
            _dir: dir,
        }
    }

    fn store(&self) -> BeaconStore<'_> {
        BeaconStore::new(&self.db)
    }

    /// The group key the node derives from its committed rows at its head.
    fn derived_group_key(&self) -> Option<CommittedGroupKey> {
        committed_group_key(&self.db, &params(), CHAIN_ID, EPOCH).unwrap()
    }

    /// Execute and publish one block; every transaction in it must succeed.
    fn publish(&self, m: &Members, height: u64, txs: Vec<SignedTransaction>) -> Block {
        let (receipts, block) = common::publish_block_returning(
            &self.state,
            &self.executor,
            height,
            m.keys[0].public_key().as_bytes(),
            txs,
            &m.pubs,
        );
        for (n, r) in receipts.iter().enumerate() {
            assert!(
                r.is_success(),
                "height {height}, transaction {n}: {:?}",
                r.status
            );
        }
        block
    }

    /// Registrations from `registrants`, at the epoch boundary.
    fn register(&self, m: &Members, registrants: &[u32]) -> Block {
        let txs = registrants
            .iter()
            .map(|&j| {
                setup_tx(
                    &m.keys[j as usize],
                    BeaconOperation::RegisterBeaconKey(registration(j)),
                )
            })
            .collect();
        self.publish(m, KEYS_AT, txs)
    }

    /// Publish every deal in one block.
    fn deal(&self, m: &Members, deals: &Deals) -> Block {
        let txs = deals
            .values()
            .map(|d| {
                setup_tx(
                    &m.keys[d.dealer_i as usize],
                    BeaconOperation::DkgDeal(d.clone()),
                )
            })
            .collect();
        self.publish(m, DEALS_AT, txs)
    }

    /// One signing round at `height`: a partial from every member holding a
    /// share, then a finalize whose `Σ_r` is the exactly-`T` combination of the
    /// partials of `witness`. Returns the block and `Σ_r`.
    fn sign_round(
        &self,
        m: &Members,
        height: u64,
        round: u64,
        msg: &[u8],
        shares: &BTreeMap<u32, SecretScalar>,
        witness: [u32; 2],
    ) -> (Block, Signature) {
        let mut txs = Vec::new();
        for (&j, sk_j) in shares {
            let partial = BeaconPartialV1 {
                chain_id: CHAIN_ID,
                epoch: EPOCH,
                round,
                j,
                sigma_j: sk_j.sign(msg).to_compressed(),
            };
            txs.push(signing_tx(
                &m.keys[j as usize],
                BeaconOperation::BeaconPartial(partial),
            ));
        }
        let sigma = combine(
            &witness.map(|j| PartialSignature::new(u64::from(j) + 1, shares[&j].sign(msg))),
        )
        .unwrap();
        txs.push(signing_tx(
            &m.keys[0],
            BeaconOperation::BeaconFinalize(BeaconFinalizeV1 {
                chain_id: CHAIN_ID,
                epoch: EPOCH,
                round,
                sigma_r: sigma.to_compressed(),
                witness: witness.to_vec(),
            }),
        ));
        (self.publish(m, height, txs), sigma)
    }
}

/// `sk_j = Σ_{i∈QUAL} s_ij` for each recipient, from the shares it decrypted.
fn signing_shares(deals: &Deals, qual: &[u32], recipients: &[u32]) -> BTreeMap<u32, SecretScalar> {
    recipients
        .iter()
        .map(|&j| {
            let sk_j = qual
                .iter()
                .map(|&i| {
                    let (share, consistent) = open(&deals[&(i, j)]);
                    assert!(
                        consistent,
                        "a QUAL dealer's share to {j} must be consistent"
                    );
                    SecretScalar::from_bytes_le(&share).unwrap()
                })
                .reduce(|acc, s| acc.add(&s))
                .unwrap();
            (j, sk_j)
        })
        .collect()
}

/// `PK_E = Σ_{i∈dealers} C_{i,0}`.
fn group_key(dealers: &[&Dealer]) -> PublicKey {
    let constants: Vec<G1Point> = dealers.iter().map(|d| d.commitment_points()[0]).collect();
    PublicKey::from_g1_point(aggregate_g1(&constants).unwrap())
}

#[test]
fn n5_dkg_survives_an_invalid_dealer_and_a_crash() {
    let m = Members::new();
    let node = Node::new(&m);
    let store = node.store();
    let live: Vec<u32> = (0..N).filter(|&j| j != CRASHED).collect();

    // ── Keys. The crashed member never registers, but it is still a member:
    // the boundary snapshot is the validator set, and absence does not
    // remove anyone from it.
    node.register(&m, &live);
    assert_eq!(store.get_membership(EPOCH).unwrap(), Some(m.pubs.clone()));

    // ── Deals, from every live member to every live member. One of them is
    // corrupt. Nothing on chain can see inside a ciphertext, so it is accepted
    // like the others; detecting it is the recipient's job.
    let dealers: BTreeMap<u32, Dealer> = live.iter().map(|&i| (i, Dealer::new(MAIN, i))).collect();
    let mut deals = BTreeMap::new();
    for &i in &live {
        for &j in &live {
            let corrupt = (i, j) == (INVALID_DEALER, VICTIM);
            deals.insert((i, j), deal(MAIN, &dealers[&i], i, j, corrupt));
        }
    }
    node.deal(&m, &deals);

    // ── Each recipient opens what it was dealt. Exactly the corrupt share
    // fails the dealer's own commitments.
    for ((i, j), d) in &deals {
        let (_, consistent) = open(d);
        assert_eq!(
            consistent,
            (*i, *j) != (INVALID_DEALER, VICTIM),
            "deal {i} -> {j}"
        );
    }

    // ── The victim proves it. Adjudication opens the ciphertext with the
    // revealed ECDH secret, finds the Feldman check failing, and disqualifies.
    let bad = &deals[&(INVALID_DEALER, VICTIM)];
    node.publish(
        &m,
        COMPLAINTS_AT,
        vec![setup_tx(
            &m.keys[VICTIM as usize],
            BeaconOperation::DkgComplaint(complaint(bad)),
        )],
    );
    let t = store.get_dkg_transcript(EPOCH).unwrap();
    assert_eq!(
        t.disqualified
            .iter()
            .map(|d| d.dealer_i)
            .collect::<Vec<_>>(),
        vec![INVALID_DEALER]
    );
    assert_eq!(
        t.adjudicated
            .iter()
            .map(|a| (a.dealer_i, a.recipient_j))
            .collect::<Vec<_>>(),
        vec![(INVALID_DEALER, VICTIM)]
    );
    assert!(t.false_accusers.is_empty(), "the complaint was true");
    assert_eq!(
        node.derived_group_key(),
        None,
        "the complaint window is still open"
    );

    // ── QUAL is the three honest dealers: exactly Q_dkg. The group key is
    // computed here from their polynomials alone, not read from the node.
    let qual: Vec<u32> = live
        .iter()
        .copied()
        .filter(|&i| i != INVALID_DEALER)
        .collect();
    assert_eq!(qual, vec![0, 1, 2]);
    let pk_e = group_key(&qual.iter().map(|i| &dealers[i]).collect::<Vec<_>>());
    let pk_with_invalid = group_key(&dealers.values().collect::<Vec<_>>());

    // Each live member recovers a scalar share, and its public key is the
    // verification key the published commitments give it.
    let shares = signing_shares(&deals, &qual, &live);
    for (&j, sk_j) in &shares {
        let terms: Vec<G1Point> = qual
            .iter()
            .map(|i| {
                commitment_poly_eval(&dealers[i].commitment_points(), u64::from(j) + 1).unwrap()
            })
            .collect();
        assert_eq!(
            sk_j.public_key(),
            PublicKey::from_g1_point(aggregate_g1(&terms).unwrap()),
            "vk_{j} from the commitments"
        );
    }

    // ── Two chained rounds. The four live members send partials, which the
    // executor verifies one by one; the crashed member sends nothing and is
    // not needed. The witness is a T-subset that skips index 1.
    let mut prev: Option<Signature> = None;
    let mut outputs = Vec::new();
    for (round, height) in [(0u64, ROUND0_AT), (1, ROUND1_AT)] {
        let msg = message(round, prev.as_ref());
        let (_, sigma) = node.sign_round(&m, height, round, &msg, &shares, [0, 2]);

        let held = store
            .get_finalized_round(EPOCH, round)
            .unwrap()
            .expect("the round is finalized");
        assert_eq!(held.sigma_r, sigma.to_compressed());
        assert!(verify(&pk_e, &msg, &sigma), "Σ_{round} verifies under PK_E");
        assert!(
            !verify(&pk_with_invalid, &msg, &sigma),
            "the disqualified dealer is not part of the group key"
        );
        assert_eq!(held.output, beacon_output(CHAIN_ID, EPOCH, round, &sigma));
        outputs.push(held.output);
        prev = Some(sigma);
    }
    assert_ne!(
        outputs[0], outputs[1],
        "chaining gives each round its own output"
    );
    assert_eq!(store.get_finalized_round(EPOCH, 2).unwrap(), None);

    // ── The key the node derives from its committed rows is the one computed
    // above: the executor verified every partial against QUAL's commitments
    // and both rounds' Σ under it.
    assert_eq!(
        node.derived_group_key(),
        Some(CommittedGroupKey {
            qual: qual.clone(),
            group_key: pk_e.to_compressed(),
        })
    );

    // ── Absence is not misconduct: the crashed member holds no key and no
    // deal, and no verdict names it.
    let t = store.get_dkg_transcript(EPOCH).unwrap();
    assert_eq!(
        t.keys.iter().map(|k| k.validator_index).collect::<Vec<_>>(),
        live
    );
    assert!(t
        .deals
        .iter()
        .all(|d| d.dealer_i != CRASHED && d.recipient_j != CRASHED));
    assert!(t.disqualified.iter().all(|d| d.dealer_i != CRASHED));
    assert!(t.false_accusers.iter().all(|f| f.recipient_j != CRASHED));
    assert!(t.key_equivocations.is_empty() && t.deal_equivocations.is_empty());
}

/// Every row of the families a reorg must restore, plus the beacon undo
/// records, so a revert that left a journal behind is caught too.
fn snapshot(db: &Database) -> BTreeMap<(&'static str, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for family in [cf::STATE, cf::BEACON_STATE, cf::BEACON_STATE_DIFFS] {
        for (k, v) in db.full_iter(family).unwrap() {
            out.insert((family, k.to_vec()), v.to_vec());
        }
    }
    out
}

/// Unwind `branch` (ancestor first) the way the consensus reorg does, and
/// commit it.
fn unwind(db: &Database, branch: &[Block]) {
    let mut batch = db.batch();
    let journals = SubsystemJournals::new(db, GATES);
    stage_branch_unwind(
        db,
        &mut batch,
        branch,
        &journals,
        MissingJournalPolicy::ToleratedEverywhere,
    )
    .expect("the branch unwinds");
    batch.commit().unwrap();
}

/// One branch after the shared registrations: dealers 0..=3 deal to
/// recipients 0..=3 with polynomials labelled `dealing`, then round 0 is
/// signed and finalized. Returns the branch's blocks, its deals and the round's
/// output.
fn run_branch(node: &Node, m: &Members, dealing: u8) -> (Vec<Block>, Deals, [u8; 32]) {
    let members: Vec<u32> = (0..N).filter(|&j| j != CRASHED).collect();
    let dealers: Vec<Dealer> = members.iter().map(|&i| Dealer::new(dealing, i)).collect();
    let mut deals = BTreeMap::new();
    for &i in &members {
        for &j in &members {
            deals.insert((i, j), deal(dealing, &dealers[i as usize], i, j, false));
        }
    }
    let deal_block = node.deal(m, &deals);

    let shares = signing_shares(&deals, &members, &members);
    let msg = message(0, None);
    let (round_block, sigma) = node.sign_round(m, ROUND0_AT, 0, &msg, &shares, [0, 1]);
    assert!(verify(
        &group_key(&dealers.iter().collect::<Vec<_>>()),
        &msg,
        &sigma
    ));

    let held = node.store().get_finalized_round(EPOCH, 0).unwrap().unwrap();
    assert_eq!(held.output, beacon_output(CHAIN_ID, EPOCH, 0, &sigma));
    (vec![deal_block, round_block], deals, held.output)
}

fn commitments_in(t: &StoredDkgTranscript) -> Vec<Vec<u8>> {
    t.deals.iter().flat_map(|d| d.commitments.clone()).collect()
}

#[test]
fn different_dealings_on_two_forks_give_different_beacons_and_a_reverted_fork_leaves_no_trace() {
    let m = Members::new();
    let registrants: Vec<u32> = (0..N).filter(|&j| j != CRASHED).collect();

    // `x` follows fork A, abandons it for fork B. `y` only ever sees fork B.
    let x = Node::new(&m);
    let y = Node::new(&m);
    let prefix_x = x.register(&m, &registrants);
    let prefix_y = y.register(&m, &registrants);
    assert_eq!(prefix_x.hash(), prefix_y.hash(), "one shared parent");
    let parent = snapshot(&x.db);
    let parent_root = x.state.state_root();

    // ── Fork A on x.
    let (a_blocks, a_deals, a_output) = run_branch(&x, &m, FORK_A);
    let a_commitments = commitments_in(&x.store().get_dkg_transcript(EPOCH).unwrap());
    assert!(!a_commitments.is_empty());
    let a_key = x
        .derived_group_key()
        .expect("fork A is past its complaint window");

    // ── Reorg away from A. Every row and every undo record A wrote is gone:
    // the node is exactly at the parent again.
    unwind(&x.db, &a_blocks);
    assert_eq!(snapshot(&x.db), parent, "fork A left no trace");
    assert_eq!(x.store().get_finalized_round(EPOCH, 0).unwrap(), None);
    let t = x.store().get_dkg_transcript(EPOCH).unwrap();
    assert!(t.deals.is_empty(), "no deal of fork A survives");
    assert_eq!(
        t.keys.len(),
        registrants.len(),
        "the shared registrations stay"
    );
    x.state.set_state_root(parent_root);

    // ── Fork B on both nodes.
    let (bx_blocks, b_deals, bx_output) = run_branch(&x, &m, FORK_B);
    let (by_blocks, _, by_output) = run_branch(&y, &m, FORK_B);

    assert_ne!(
        a_deals, b_deals,
        "the forks carry different dealings over the same registrations"
    );
    assert_ne!(a_output, bx_output, "different dealings, different beacon");
    assert_eq!(bx_output, by_output, "a branch's beacon is deterministic");
    let b_key = x
        .derived_group_key()
        .expect("fork B is past its complaint window");
    assert_eq!(
        Some(b_key.clone()),
        y.derived_group_key(),
        "and so is its group key"
    );
    assert_eq!(
        a_key.qual, b_key.qual,
        "the same dealers qualified on both forks"
    );
    assert_ne!(
        a_key.group_key, b_key.group_key,
        "different dealings, different group key"
    );
    assert_eq!(
        bx_blocks.iter().map(Block::hash).collect::<Vec<_>>(),
        by_blocks.iter().map(Block::hash).collect::<Vec<_>>(),
        "identical blocks, so identical state roots"
    );
    assert_eq!(
        snapshot(&x.db),
        snapshot(&y.db),
        "x holds exactly what y holds"
    );
    assert_eq!(
        x.store().state_digest().unwrap(),
        y.store().state_digest().unwrap()
    );

    let b_commitments = commitments_in(&x.store().get_dkg_transcript(EPOCH).unwrap());
    assert!(
        a_commitments.iter().all(|c| !b_commitments.contains(c)),
        "no commitment of fork A leaks into fork B's transcript"
    );
}
