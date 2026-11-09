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

mod common;

use common::{fund, publish_block_returning, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::compute_pool_params::ComputePoolParamsV1;
use sumchain_primitives::transaction::ComputePoolTxData;
use sumchain_primitives::{Hash, Receipt, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::compute_pool_store::ComputePoolStore;
use sumchain_storage::Database;
use sumchain_wire::compute_pool_wire::{
    CancelJobV1, ComputePoolOperation, CreateComputePoolJobV1, DeclineWorkUnitV1,
    PublishBondedOfferV1, WorkItemRef,
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
