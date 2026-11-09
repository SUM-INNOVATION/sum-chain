//! C1 compute pool (#130): ComputePool transactions through blocks executed
//! and published the way a proposer publishes them.
//!
//! The compute-pool gate is opened in test-local `ChainParams` only. Genesis
//! validation refuses `compute_pool_enabled_from_height` on every network.
//!
//! * [`gate_unset_compute_pool_transactions_change_nothing`]: with the gate
//!   unset, ComputePool transactions, valid operations among them, fail free
//!   and change nothing, with the parameters absent or declared. Their roots
//!   and receipts are pinned to the values computed before routing existed.
//! * [`gate_open_refuses_what_has_no_execution_rules`]: the operations whose
//!   rules are undecided, and bytes that decode as nothing, are refused free
//!   with the gate open, and the block still publishes its empty C1 record.
//! * Each block rebuilds the model from the stored rows, so a parent that
//!   already holds C1 rows no longer makes every later block fail at the
//!   apply seam: [`blocks_over_existing_c1_rows_rebuild_the_model_and_publish`].
//! * `PublishBondedOfferV1`: [`a_published_offer_locks_b_offer_under_its_derived_id`],
//!   [`an_identity_holds_one_active_offer`],
//!   [`an_unpayable_or_unpriced_offer_is_refused_free`],
//!   [`a_reorg_reverts_the_offer_and_its_bond_together`] and
//!   [`the_same_blocks_give_the_same_rows_and_roots`].
//! * `DeclineWorkUnitV1`: [`the_assigned_worker_declines_and_nothing_is_slashed`],
//!   [`a_decline_from_anyone_else_or_for_anything_else_is_refused_free`],
//!   [`a_reorg_reverts_a_decline`] and
//!   [`the_same_decline_gives_the_same_rows_and_roots`]. Job creation and
//!   assignment do not execute, so the assigned unit these start from is
//!   seeded.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::{fund, publish_block_returning, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::compute_pool_params::ComputePoolParamsV1;
use sumchain_primitives::transaction::ComputePoolTxData;
use sumchain_primitives::{
    Address, Block, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::compute_pool::{
    AssignmentIndexEntry, BondedOffer, ComputePoolModel, ExposureInputs, JobId, OfferBondId,
    UnitId, UnitKey, UnitSizing, UnitState, WorkItemKey, WorkUnit,
};
use sumchain_state::compute_pool_store::{unit_key_bytes, ComputePoolStore};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::reorg_undo::{stage_branch_unwind, MissingJournalPolicy, SubsystemJournals};
use sumchain_state::state::StateManager;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::{cf, Database};
use sumchain_wire::compute_pool_wire::{
    AcceptWorkUnitV1, AssignWorkUnitV1, CancelJobV1, ComputePoolOperation, CreateComputePoolJobV1,
    DeclineWorkUnitV1, ExpireWorkUnitV1, PublishBondedOfferV1, ReassignWorkUnitV1, WorkItemRef,
};

const FEE: u128 = 1_000;
const FUNDS: u128 = 1_000_000;
const B_OFFER: u128 = 50_000;

/// Deterministic keys: the same blocks produce the same bytes on every run.
fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}

fn pool_tx(kp: &KeyPair, nonce: u64, op_bytes: Vec<u8>) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::ComputePool(ComputePoolTxData { op_bytes }),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn op_tx(kp: &KeyPair, nonce: u64, op: ComputePoolOperation) -> SignedTransaction {
    pool_tx(kp, nonce, op.try_encode().unwrap())
}

fn publish(offer_seq: u64, offered_bytes: u128, payment: &KeyPair) -> ComputePoolOperation {
    ComputePoolOperation::PublishOffer(PublishBondedOfferV1 {
        offer_seq,
        offered_bytes,
        payment_addr: payment.address(),
    })
}

fn decline(job: [u8; 32], unit: [u8; 32], generation: u64) -> ComputePoolOperation {
    ComputePoolOperation::DeclineUnit(DeclineWorkUnitV1 {
        work_item: WorkItemRef {
            job_id: job,
            unit_id: unit,
            generation,
        },
    })
}

/// `(balance, nonce)` of an account, from committed state.
fn account(db: &Database, kp: &KeyPair) -> (u128, u64) {
    let a = sumchain_storage::StateStore::new(db)
        .get_account(&kp.address())
        .unwrap();
    (a.balance, a.nonce)
}

/// One hash over a run: every root and every receipt, bincode-encoded.
fn run_digest(run: &[(Hash, Vec<Receipt>)]) -> Hash {
    let mut data = Vec::new();
    for (root, receipts) in run {
        data.extend_from_slice(root.as_bytes());
        data.extend_from_slice(&bincode::serialize(receipts).unwrap());
    }
    Hash::hash(&data)
}

/// `run_digest` of the gate-unset run below, computed with this file's run,
/// unchanged, on the commit that added it: before ComputePool transactions
/// were routed anywhere, when execution refused every one without reading
/// its operation.
const GATE_UNSET_DIGEST: &str = "793cf656edbf83abefca308f7160e3985210cafa9eaf32d777422ef4ac5333b7";

/// TEST_ONLY parameters: every `max_*` cap 1, `output_availability_blocks` on
/// the #129 relation-1 floor (200), `B_offer` = [`B_OFFER`] and everything
/// else 0. Not a proposed value.
fn declared() -> ComputePoolParamsV1 {
    let mut p: ComputePoolParamsV1 = serde_json::from_str(
        r#"{
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 200,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    }"#,
    )
    .unwrap();
    p.b_offer = B_OFFER;
    p
}

/// Two blocks of ComputePool transactions under `params`, whose gate is
/// unset: every operation a gate-open node executes or refuses, plus bytes
/// that decode as nothing. Asserts that each fails free and that nothing is
/// written, and returns the roots and receipts.
fn gate_unset_run(params: ChainParams) -> Vec<(Hash, Vec<Receipt>)> {
    assert_eq!(params.compute_pool_enabled_from_height, None);
    let (state, db, _dir, executor) = setup_with_params(params);
    let worker = key(0x41);
    let other = key(0x42);
    let proposer = key(0x50);
    fund(&db, &worker, FUNDS);
    fund(&db, &other, FUNDS);

    // None of these advances a nonce, so each sender stays at nonce 0.
    let blocks = vec![
        vec![
            op_tx(&worker, 0, publish(0, 1 << 30, &worker)),
            op_tx(&other, 0, decline([1; 32], [2; 32], 0)),
        ],
        vec![
            op_tx(
                &worker,
                0,
                ComputePoolOperation::CreateJob(CreateComputePoolJobV1 {
                    client_job_salt: [3; 32],
                    graph_definition_root: [4; 32],
                    unit_count: 1,
                }),
            ),
            op_tx(
                &other,
                0,
                ComputePoolOperation::CancelJob(CancelJobV1 { job_id: [1; 32] }),
            ),
            pool_tx(&other, 0, vec![0xff; 3]),
        ],
    ];

    let mut run = Vec::new();
    for (i, txs) in blocks.into_iter().enumerate() {
        let height = i as u64 + 1;
        let (receipts, block) = publish_block_returning(
            &state,
            &executor,
            height,
            proposer.public_key().as_bytes(),
            txs,
            &[],
        );
        for r in &receipts {
            assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(0), 0));
        }
        let store = ComputePoolStore::new(&db);
        assert!(!store.has_journal(height, &block.hash()).unwrap());
        run.push((state.state_root(), receipts));
    }

    assert_eq!(account(&db, &worker), (FUNDS, 0));
    assert_eq!(account(&db, &other), (FUNDS, 0));
    assert_eq!(account(&db, &proposer), (0, 0));
    assert!(ComputePoolStore::new(&db)
        .load_state_map()
        .unwrap()
        .is_empty());
    run
}

#[test]
fn gate_unset_compute_pool_transactions_change_nothing() {
    let absent = ChainParams::with_v2_enabled();
    assert_eq!(absent.compute_pool_params, None);
    let run = gate_unset_run(absent);
    assert_eq!(hex::encode(run_digest(&run).as_bytes()), GATE_UNSET_DIGEST);

    // Declaring the parameters, `B_offer` included, changes nothing while the
    // gate is unset.
    let mut declared_params = ChainParams::with_v2_enabled();
    declared_params.compute_pool_params = Some(declared());
    declared_params.validate().unwrap();
    assert_eq!(gate_unset_run(declared_params), run);
}

// ── gate open, in test-local parameters ────────────────────────────────────

const WORKER: u8 = 0x41;
const OTHER: u8 = 0x42;
const PROPOSER: u8 = 0x50;

/// Test-local: genesis validation refuses an open compute-pool gate on every
/// network.
fn params_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.compute_pool_enabled_from_height = Some(0);
    p.compute_pool_params = Some(declared());
    p
}

/// One node: its own database and executor, with the worker and the other
/// sender funded.
struct Node {
    state: Arc<StateManager>,
    db: Arc<Database>,
    executor: BlockExecutor,
    _dir: tempfile::TempDir,
}

impl Node {
    fn new(params: ChainParams) -> Self {
        let (state, db, dir, executor) = setup_with_params(params);
        fund(&db, &key(WORKER), FUNDS);
        fund(&db, &key(OTHER), FUNDS);
        Node {
            state,
            db,
            executor,
            _dir: dir,
        }
    }

    /// Execute and publish one block; its receipts as `(status, fee)`.
    fn block(&self, height: u64, txs: Vec<SignedTransaction>) -> (Vec<(TxStatus, u128)>, Block) {
        let (receipts, block) = publish_block_returning(
            &self.state,
            &self.executor,
            height,
            key(PROPOSER).public_key().as_bytes(),
            txs,
            &[],
        );
        let outcomes = receipts.iter().map(|r| (r.status, r.fee_paid)).collect();
        (outcomes, block)
    }

    fn store(&self) -> ComputePoolStore<'_> {
        ComputePoolStore::new(&self.db)
    }
}

/// A model holding one job of one blocked unit, requested by `requester`.
fn one_job(job: JobId, unit: UnitId, requester: Address) -> ComputePoolModel {
    let mut m = ComputePoolModel::new();
    add_one_job(&mut m, job, unit, requester);
    m
}

/// Add a job of one blocked unit, at generation 0, to `m`.
fn add_one_job(m: &mut ComputePoolModel, job: JobId, unit: UnitId, requester: Address) {
    m.create_job(
        job,
        requester,
        1,
        vec![WorkUnit {
            job_id: job,
            unit_id: unit,
            predecessors: vec![],
            required_inputs: vec![],
            generation: 0,
            state: UnitState::Blocked,
        }],
        &[UnitSizing { slots: 0 }],
        1,
        0,
        1_000,
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0,
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        },
        1_000_000,
    )
    .unwrap();
}

/// Write `model`'s rows into committed state, as the blocks that built it
/// would have left them.
///
/// SEEDING, not publishing. Job creation and assignment do not execute
/// (their rules are not decided), so no block can produce these rows; a
/// parent that holds them is seeded instead.
fn seed_rows(db: &Database, model: &ComputePoolModel) {
    let rows = ComputePoolStore::materialize(model).unwrap();
    let mut batch = db.batch();
    for (k, v) in &rows {
        batch.put(cf::COMPUTE_POOL_STATE, k, v).unwrap();
    }
    batch.commit().unwrap();
}

/// With the gate open, the operations whose execution rules are undecided,
/// and bytes that decode as nothing, are refused free and write nothing. The
/// block still publishes its C1 record, empty, as every gate-open block does.
#[test]
fn gate_open_refuses_what_has_no_execution_rules() {
    let node = Node::new(params_open());
    let (worker, other) = (key(WORKER), key(OTHER));
    let item = WorkItemRef {
        job_id: [1; 32],
        unit_id: [2; 32],
        generation: 0,
    };
    let undecided = vec![
        ComputePoolOperation::CreateJob(CreateComputePoolJobV1 {
            client_job_salt: [3; 32],
            graph_definition_root: [4; 32],
            unit_count: 1,
        }),
        ComputePoolOperation::AcceptUnit(AcceptWorkUnitV1 {
            work_item: item,
            commit_bond_id: [5; 32],
            accepted_bytes: 1,
        }),
        ComputePoolOperation::ExpireUnit(ExpireWorkUnitV1 { work_item: item }),
        ComputePoolOperation::CancelJob(CancelJobV1 { job_id: [1; 32] }),
        ComputePoolOperation::AssignUnit(AssignWorkUnitV1 { work_item: item }),
        ComputePoolOperation::ReassignUnit(ReassignWorkUnitV1 { work_item: item }),
    ];
    // A refusal advances no nonce, so every one of these is nonce 0.
    let mut txs: Vec<SignedTransaction> = undecided
        .into_iter()
        .map(|op| op_tx(&worker, 0, op))
        .collect();
    txs.push(pool_tx(&other, 0, vec![0xff; 3]));

    let (receipts, block) = node.block(1, txs);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0); 7]);
    assert_eq!(account(&node.db, &worker), (FUNDS, 0));
    assert_eq!(account(&node.db, &other), (FUNDS, 0));
    assert!(node.store().load_state_map().unwrap().is_empty());
    let record = node.store().load_journal(1, &block.hash()).unwrap();
    assert!(record
        .expect("a gate-open block publishes a record")
        .is_empty());
}

/// Each block rebuilds the model from the stored rows. Before it did, the
/// manager started every block empty, and once a parent held a C1 row,
/// staging against that empty predecessor was refused, so every later block
/// failed at the apply seam, even an empty one.
#[test]
fn blocks_over_existing_c1_rows_rebuild_the_model_and_publish() {
    let node = Node::new(params_open());
    seed_rows(
        &node.db,
        &one_job(
            JobId::from_bytes([1; 32]),
            UnitId::from_bytes([2; 32]),
            key(OTHER).address(),
        ),
    );
    let rows = node.store().load_state_map().unwrap();
    assert!(!rows.is_empty());

    let (receipts, empty) = node.block(1, vec![]);
    assert!(receipts.is_empty());
    let (receipts, refused) = node.block(2, vec![pool_tx(&key(OTHER), 0, vec![0xff; 3])]);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0)]);

    assert_eq!(node.store().load_state_map().unwrap(), rows);
    for (height, block) in [(1, &empty), (2, &refused)] {
        let record = node.store().load_journal(height, &block.hash()).unwrap();
        assert!(record.unwrap().is_empty());
    }
}

// ── PublishBondedOfferV1 ────────────────────────────────────────────────────

/// The id a publish from `kp` with `offer_seq` derives on this chain.
fn offer_id(kp: &KeyPair, offer_seq: u64) -> OfferBondId {
    OfferBondId::derive(CHAIN_ID, &kp.address(), offer_seq)
}

const GATES: SubsystemGates = SubsystemGates {
    compute_pool: Some(0),
    beacon: None,
};

/// Every row of the families a reorg must restore, plus the C1 undo records,
/// so a revert that left a journal behind is caught too.
fn snapshot(db: &Database) -> BTreeMap<(&'static str, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for family in [
        cf::STATE,
        cf::COMPUTE_POOL_STATE,
        cf::COMPUTE_POOL_STATE_DIFFS,
    ] {
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

#[test]
fn a_published_offer_locks_b_offer_under_its_derived_id() {
    let node = Node::new(params_open());
    let (worker, other, proposer) = (key(WORKER), key(OTHER), key(PROPOSER));
    let (receipts, block) = node.block(1, vec![op_tx(&worker, 0, publish(3, 1 << 30, &other))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);

    // The sender paid the fee and `B_offer`; the proposer was paid the fee.
    assert_eq!(account(&node.db, &worker), (FUNDS - FEE - B_OFFER, 1));
    assert_eq!(account(&node.db, &proposer), (FEE, 0));

    // The offer sits under the ratified derivation of (chain id, sender,
    // offer_seq), with the sender as its identity and `B_offer` locked.
    let id = offer_id(&worker, 3);
    assert_eq!(
        *id.as_bytes(),
        sumchain_wire::compute_pool_graph::offer_bond_id(CHAIN_ID, &worker.address(), 3)
    );
    let offer = node.store().get_offer(&id).unwrap().expect("published");
    assert_eq!(
        offer.to_model(),
        BondedOffer {
            offer_bond_id: id,
            identity: worker.address(),
            payment_addr: other.address(),
            offered_bytes: 1 << 30,
            offer_seq: 3,
            bond_locked: B_OFFER,
            active: true,
        }
    );
    assert_eq!(
        node.store().active_offer_of(&worker.address()).unwrap(),
        Some(id)
    );
    assert_eq!(
        node.store().load_state_map().unwrap().len(),
        2,
        "the offer and its index row, nothing else"
    );

    // The block published the record that undoes both rows.
    let record = node
        .store()
        .load_journal(1, &block.hash())
        .unwrap()
        .unwrap();
    assert_eq!(record.records.len(), 2);
}

/// One active offer per identity: enforced against the model the block's
/// earlier transactions left, and against the stored rows in later blocks.
/// A refused publish pays nothing, not even its fee.
#[test]
fn an_identity_holds_one_active_offer() {
    let node = Node::new(params_open());
    let (worker, other) = (key(WORKER), key(OTHER));
    let (receipts, _) = node.block(
        1,
        vec![
            op_tx(&worker, 0, publish(0, 100, &worker)),
            op_tx(&worker, 1, publish(1, 200, &worker)),
            op_tx(&other, 0, publish(0, 300, &other)),
        ],
    );
    assert_eq!(
        receipts,
        vec![
            (TxStatus::Success, FEE),
            (TxStatus::Failed(0), 0),
            (TxStatus::Success, FEE),
        ]
    );
    let (receipts, _) = node.block(2, vec![op_tx(&worker, 1, publish(2, 400, &worker))]);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0)]);

    assert_eq!(account(&node.db, &worker), (FUNDS - FEE - B_OFFER, 1));
    assert_eq!(account(&node.db, &other), (FUNDS - FEE - B_OFFER, 1));
    assert_eq!(
        node.store().load_state_map().unwrap().len(),
        4,
        "two offers and their index rows"
    );
    for refused in [1, 2] {
        assert!(node
            .store()
            .get_offer(&offer_id(&worker, refused))
            .unwrap()
            .is_none());
    }
}

/// A publish whose sender cannot pay the fee and `B_offer` together, or one
/// on a chain that declares no `B_offer`, is refused free and writes nothing.
#[test]
fn an_unpayable_or_unpriced_offer_is_refused_free() {
    let node = Node::new(params_open());
    let poor = key(0x43);
    fund(&node.db, &poor, FEE + B_OFFER - 1);
    let (receipts, _) = node.block(1, vec![op_tx(&poor, 0, publish(0, 100, &poor))]);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0)]);
    assert_eq!(account(&node.db, &poor), (FEE + B_OFFER - 1, 0));
    assert!(node.store().load_state_map().unwrap().is_empty());

    // One more unit and the same publish is paid for exactly.
    common::credit_committed(&node.db, &poor.address(), 1);
    let (receipts, _) = node.block(2, vec![op_tx(&poor, 0, publish(0, 100, &poor))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);
    assert_eq!(account(&node.db, &poor), (0, 1));

    // The gate open with no parameters declared: `B_offer` has no value.
    let mut unpriced = params_open();
    unpriced.compute_pool_params = None;
    let node = Node::new(unpriced);
    let worker = key(WORKER);
    let (receipts, _) = node.block(1, vec![op_tx(&worker, 0, publish(0, 100, &worker))]);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0)]);
    assert_eq!(account(&node.db, &worker), (FUNDS, 0));
    assert!(node.store().load_state_map().unwrap().is_empty());
}

/// Reverting a block that published an offer restores the sender's balance,
/// removes the offer and its index row, and consumes the C1 record, in one
/// unwind. The replacement block is then decided against the restored parent.
#[test]
fn a_reorg_reverts_the_offer_and_its_bond_together() {
    let node = Node::new(params_open());
    let (worker, other) = (key(WORKER), key(OTHER));
    node.block(1, vec![op_tx(&other, 0, publish(0, 100, &other))]);
    let parent = snapshot(&node.db);
    let parent_root = node.state.state_root();

    let (receipts, fork) = node.block(2, vec![op_tx(&worker, 0, publish(0, 200, &worker))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);
    assert_ne!(snapshot(&node.db), parent);

    unwind(&node.db, &[fork]);
    assert_eq!(snapshot(&node.db), parent, "the fork left no trace");
    assert_eq!(account(&node.db, &worker), (FUNDS, 0));
    assert!(node
        .store()
        .get_offer(&offer_id(&worker, 0))
        .unwrap()
        .is_none());
    assert_eq!(
        node.store().active_offer_of(&worker.address()).unwrap(),
        None
    );
    node.state.set_state_root(parent_root);

    let (receipts, _) = node.block(2, vec![op_tx(&worker, 0, publish(0, 300, &worker))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);
    let offer = node.store().get_offer(&offer_id(&worker, 0)).unwrap();
    assert_eq!(offer.unwrap().offered_bytes, 300);
}

/// Two nodes executing the same blocks hold the same C1 rows and compute the
/// same roots, into which the C1 digest is folded.
#[test]
fn the_same_blocks_give_the_same_rows_and_roots() {
    let (worker, other) = (key(WORKER), key(OTHER));
    let blocks = || {
        vec![
            vec![
                op_tx(&worker, 0, publish(7, 1 << 20, &other)),
                op_tx(&other, 0, publish(0, 5, &other)),
            ],
            vec![
                op_tx(&worker, 1, publish(8, 1, &worker)),
                pool_tx(&other, 1, vec![1, 2, 3]),
            ],
        ]
    };
    let run = |node: &Node| -> Vec<(Vec<(TxStatus, u128)>, Hash)> {
        blocks()
            .into_iter()
            .enumerate()
            .map(|(i, txs)| (node.block(i as u64 + 1, txs).0, node.state.state_root()))
            .collect()
    };
    let (x, y) = (Node::new(params_open()), Node::new(params_open()));
    let on_x = run(&x);
    assert_eq!(on_x, run(&y));
    assert_eq!(
        x.store().load_state_map().unwrap(),
        y.store().load_state_map().unwrap()
    );
    assert_eq!(
        x.store().state_digest().unwrap(),
        y.store().state_digest().unwrap()
    );
    assert_eq!(on_x[1].0, vec![(TxStatus::Failed(0), 0); 2]);
}

// ── DeclineWorkUnitV1 ───────────────────────────────────────────────────────

fn decline_of(item: &WorkItemKey) -> ComputePoolOperation {
    decline(
        *item.job_id.as_bytes(),
        *item.unit_id.as_bytes(),
        item.generation,
    )
}

/// The model the committed rows encode.
fn committed_model(db: &Database) -> ComputePoolModel {
    let mut overlay = ApplicationOverlay::new(db, common::TEST_CANDIDATE_LIMIT);
    let view = ExecutionView::new(&mut overlay);
    ComputePoolStore::v_load_model(&view).unwrap()
}

/// Seed, beside the committed rows, a job whose one unit is assigned at
/// generation 0 to `offer`: what job creation and assignment would leave.
/// Neither executes yet (their rules are not decided), so this parent is
/// seeded rather than produced.
fn seed_assigned(node: &Node, offer: OfferBondId, payment: Address) -> WorkItemKey {
    let (job, unit) = (
        JobId::from_bytes([0x10; 32]),
        UnitId::from_bytes([0x20; 32]),
    );
    let mut model = committed_model(&node.db);
    add_one_job(&mut model, job, unit, key(OTHER).address());
    for to in [UnitState::Eligible, UnitState::Assigned] {
        model.transition_unit(&UnitKey::new(job, unit), to).unwrap();
    }
    let item = WorkItemKey::new(job, unit, 0);
    model
        .put_assignment(AssignmentIndexEntry {
            key: item,
            winner_offer_bond_id: offer,
            winner_payment_addr: payment,
        })
        .unwrap();
    seed_rows(&node.db, &model);
    item
}

fn unit_state(node: &Node, item: &WorkItemKey) -> UnitState {
    let unit = node.store().get_unit(&item.job_id, &item.unit_id).unwrap();
    unit.expect("the unit is held").state().unwrap()
}

#[test]
fn the_assigned_worker_declines_and_nothing_is_slashed() {
    let node = Node::new(params_open());
    let (worker, other) = (key(WORKER), key(OTHER));
    node.block(1, vec![op_tx(&worker, 0, publish(0, 1 << 20, &other))]);
    let item = seed_assigned(&node, offer_id(&worker, 0), other.address());
    let rows = node.store().load_state_map().unwrap();
    let offer = node.store().get_offer(&offer_id(&worker, 0)).unwrap();
    let assignment = node.store().get_assignment(&item).unwrap();
    assert!(offer.is_some() && assignment.is_some());

    let (receipts, block) = node.block(2, vec![op_tx(&worker, 1, decline_of(&item))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);

    // The unit is back in the pool, at the same generation.
    assert_eq!(unit_state(&node, &item), UnitState::Reassignable);

    // Nothing else moved: the bond is still locked in the offer, the
    // assignment record stays, and the worker paid the fee and nothing more.
    assert_eq!(
        node.store().get_offer(&offer_id(&worker, 0)).unwrap(),
        offer
    );
    assert_eq!(node.store().get_assignment(&item).unwrap(), assignment);
    assert_eq!(account(&node.db, &worker), (FUNDS - B_OFFER - 2 * FEE, 2));
    let after = node.store().load_state_map().unwrap();
    let changed: Vec<&Vec<u8>> = after
        .iter()
        .filter(|(k, v)| rows.get(*k) != Some(*v))
        .map(|(k, _)| k)
        .collect();
    assert_eq!(after.len(), rows.len());
    assert_eq!(changed, vec![&unit_key_bytes(&item.job_id, &item.unit_id)]);
    let record = node
        .store()
        .load_journal(2, &block.hash())
        .unwrap()
        .unwrap();
    assert_eq!(record.records.len(), 1);
}

/// Only the identity behind the winning offer declines, only at the unit's
/// current generation, and only while the unit is assigned. Every refusal is
/// free and changes nothing.
#[test]
fn a_decline_from_anyone_else_or_for_anything_else_is_refused_free() {
    let node = Node::new(params_open());
    let (worker, other) = (key(WORKER), key(OTHER));
    node.block(1, vec![op_tx(&worker, 0, publish(0, 1 << 20, &worker))]);
    let item = seed_assigned(&node, offer_id(&worker, 0), worker.address());
    let rows = node.store().load_state_map().unwrap();

    let stale = WorkItemKey {
        generation: 1,
        ..item
    };
    let unknown = WorkItemKey {
        unit_id: UnitId::from_bytes([0x77; 32]),
        ..item
    };
    let (receipts, _) = node.block(
        2,
        vec![
            // The job's requester, not the assigned worker.
            op_tx(&other, 0, decline_of(&item)),
            op_tx(&worker, 1, decline_of(&stale)),
            op_tx(&worker, 1, decline_of(&unknown)),
        ],
    );
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0); 3]);
    assert_eq!(node.store().load_state_map().unwrap(), rows);
    assert_eq!(account(&node.db, &other), (FUNDS, 0));
    assert_eq!(account(&node.db, &worker), (FUNDS - FEE - B_OFFER, 1));

    // Declined once, the unit is no longer assigned: a second decline is
    // refused, in the same block and in a later one.
    let (receipts, _) = node.block(
        3,
        vec![
            op_tx(&worker, 1, decline_of(&item)),
            op_tx(&worker, 2, decline_of(&item)),
        ],
    );
    assert_eq!(
        receipts,
        vec![(TxStatus::Success, FEE), (TxStatus::Failed(0), 0)]
    );
    let (receipts, _) = node.block(4, vec![op_tx(&worker, 2, decline_of(&item))]);
    assert_eq!(receipts, vec![(TxStatus::Failed(0), 0)]);
    assert_eq!(unit_state(&node, &item), UnitState::Reassignable);
}

/// Reverting the block that declined restores the assigned unit and the
/// worker's fee in one unwind; the same decline then applies again, to the
/// same rows.
#[test]
fn a_reorg_reverts_a_decline() {
    let node = Node::new(params_open());
    let worker = key(WORKER);
    node.block(1, vec![op_tx(&worker, 0, publish(0, 1 << 20, &worker))]);
    let item = seed_assigned(&node, offer_id(&worker, 0), worker.address());
    let parent = snapshot(&node.db);
    let parent_root = node.state.state_root();

    let (receipts, fork) = node.block(2, vec![op_tx(&worker, 1, decline_of(&item))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);
    assert_eq!(unit_state(&node, &item), UnitState::Reassignable);
    let declined = node.store().load_state_map().unwrap();

    unwind(&node.db, &[fork]);
    assert_eq!(snapshot(&node.db), parent, "the decline left no trace");
    assert_eq!(unit_state(&node, &item), UnitState::Assigned);
    assert_eq!(account(&node.db, &worker), (FUNDS - FEE - B_OFFER, 1));
    node.state.set_state_root(parent_root);

    let (receipts, _) = node.block(2, vec![op_tx(&worker, 1, decline_of(&item))]);
    assert_eq!(receipts, vec![(TxStatus::Success, FEE)]);
    assert_eq!(node.store().load_state_map().unwrap(), declined);
}

/// Two nodes that decline the same work item in the same blocks hold the
/// same rows and compute the same roots.
#[test]
fn the_same_decline_gives_the_same_rows_and_roots() {
    let (worker, other) = (key(WORKER), key(OTHER));
    let run = |node: &Node| {
        let mut roots = Vec::new();
        node.block(1, vec![op_tx(&worker, 0, publish(0, 1 << 20, &worker))]);
        roots.push(node.state.state_root());
        let item = seed_assigned(node, offer_id(&worker, 0), worker.address());
        let (receipts, _) = node.block(
            2,
            vec![
                op_tx(&other, 0, decline_of(&item)),
                op_tx(&worker, 1, decline_of(&item)),
            ],
        );
        assert_eq!(
            receipts,
            vec![(TxStatus::Failed(0), 0), (TxStatus::Success, FEE)]
        );
        roots.push(node.state.state_root());
        roots
    };
    let (x, y) = (Node::new(params_open()), Node::new(params_open()));
    assert_eq!(run(&x), run(&y));
    assert_eq!(
        x.store().load_state_map().unwrap(),
        y.store().load_state_map().unwrap()
    );
}
