//! #215 dormancy: `ComputePoolParamsV1` introduces no value, no behaviour and
//! no state-root change while the compute-pool gate is unset.
//!
//! * No invented defaults: the type has no `Default`, every field is required
//!   when declared, and `ChainParams` defaults to "not declared".
//! * Compute-pool transactions are refused exactly as before: mempool
//!   admission rejects them and execution returns `Failed(0)` with no fee, with
//!   or without declared parameters.
//! * A block sequence produces the same roots and receipts as `main` at
//!   8744d861 with the parameters absent AND with them declared. The expected
//!   digest below was computed by running this file's sequence, unchanged, on
//!   `main` (where the parameter field does not exist).

mod common;

use common::{fund, publish_block, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::compute_pool_params::ComputePoolParamsV1;
use sumchain_primitives::transaction::ComputePoolTxData;
use sumchain_primitives::TxStatus;
use sumchain_primitives::{Address, Hash, Receipt, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::{Mempool, MempoolConfig, StateError};

// ── the block sequence (identical source on main and on this branch) ─────────

/// Deterministic keys: the same sequence produces the same bytes on every run.
fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}

fn sign_v2(kp: &KeyPair, t: TransactionV2) -> SignedTransaction {
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn transfer(kp: &KeyPair, nonce: u64, to: Address, amount: u128) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::Transfer { to, amount },
        },
    )
}

/// A ComputePool (TxType 27) transaction. Its operation bytes are opaque to a
/// dormant node; any bytes exercise the refusal path.
fn compute_pool_tx(kp: &KeyPair, nonce: u64, op_bytes: Vec<u8>) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::ComputePool(ComputePoolTxData { op_bytes }),
        },
    )
}

/// What one run of the sequence produced: the state root after each block and
/// each block's receipts.
type Run = Vec<(Hash, Vec<Receipt>)>;

/// Four published blocks: transfers, ComputePool transactions mixed in, and an
/// empty block. Runs on a fresh database under `params`.
fn run_sequence(params: ChainParams) -> Run {
    let (state, db, _dir, executor) = setup_with_params(params);
    let alice = key(0x41);
    let bob = key(0x42);
    let proposer = key(0x50);
    fund(&db, &alice, 10_000_000);
    fund(&db, &bob, 10_000_000);
    let blocks: Vec<Vec<SignedTransaction>> = vec![
        vec![
            transfer(&alice, 0, bob.address(), 5_000),
            compute_pool_tx(&alice, 1, vec![0u8; 41]),
        ],
        vec![
            compute_pool_tx(&bob, 0, b"CPJBv1\0".to_vec()),
            transfer(&bob, 0, alice.address(), 7),
        ],
        vec![],
        vec![
            transfer(&alice, 1, proposer.address(), 1),
            compute_pool_tx(&alice, 2, Vec::new()),
        ],
    ];
    let mut out = Vec::new();
    for (i, txs) in blocks.into_iter().enumerate() {
        let receipts = publish_block(
            &state,
            &executor,
            i as u64 + 1,
            proposer.public_key().as_bytes(),
            txs,
            &[],
        );
        out.push((state.state_root(), receipts));
    }
    out
}

/// One hash over a whole run: every root and every receipt, bincode-encoded.
fn run_digest(run: &Run) -> Hash {
    let mut data = Vec::new();
    for (root, receipts) in run {
        data.extend_from_slice(root.as_bytes());
        data.extend_from_slice(&bincode::serialize(receipts).unwrap());
    }
    Hash::hash(&data)
}

/// `run_digest(run_sequence(ChainParams::with_v2_enabled()))` computed on
/// `main` at 8744d8612a072ad4c24229df2b844cedc6cb5a5a.
const MAIN_SEQUENCE_DIGEST: &str =
    "e31624046d7b5e2a291072cdb791dbb759a6ea006c3cac8a6ea1afb4a70774b8";

/// TEST_ONLY declaration: every `max_*` cap 1, everything else 0. Not a
/// proposed value.
fn declared() -> ComputePoolParamsV1 {
    serde_json::from_str(
        r#"{
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 0,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    }"#,
    )
    .unwrap()
}

fn params_with(declared_params: Option<ComputePoolParamsV1>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.compute_pool_params = declared_params;
    p
}

// ── no invented defaults ────────────────────────────────────────────────────

/// Resolves to the inherent `true` only when `T: Default`; otherwise the
/// blanket trait's `false`.
struct DefaultProbe<T>(std::marker::PhantomData<T>);
trait NoDefault {
    fn has_default() -> bool {
        false
    }
}
impl<T> NoDefault for DefaultProbe<T> {}
impl<T: Default> DefaultProbe<T> {
    #[allow(dead_code)]
    fn has_default() -> bool {
        true
    }
}

#[test]
fn the_parameters_have_no_default_values() {
    assert!(!DefaultProbe::<ComputePoolParamsV1>::has_default());
    // The probe does detect a Default when one exists.
    assert!(DefaultProbe::<ChainParams>::has_default());
    // Not declared by default, in code and in JSON.
    assert_eq!(ChainParams::default().compute_pool_params, None);
    assert_eq!(ChainParams::with_v2_enabled().compute_pool_params, None);
    let mut v = serde_json::to_value(ChainParams::default()).unwrap();
    v.as_object_mut().unwrap().remove("compute_pool_params");
    let omitted: ChainParams = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(omitted.compute_pool_params, None);
    // An empty or partial declaration does not parse: no field is filled in.
    assert!(serde_json::from_str::<ComputePoolParamsV1>("{}").is_err());
    assert!(serde_json::from_str::<ComputePoolParamsV1>(r#"{"b_offer":0}"#).is_err());
    v["compute_pool_params"] = serde_json::Value::Null;
    let explicit_null: ChainParams = serde_json::from_value(v).unwrap();
    assert_eq!(explicit_null.compute_pool_params, None);
}

// ── refusal unchanged ───────────────────────────────────────────────────────

#[test]
fn mempool_refuses_compute_pool_transactions_as_before() {
    // Admission takes no chain parameters: the refusal cannot depend on them.
    let pool = Mempool::new(MempoolConfig::default());
    let tx = compute_pool_tx(&key(0x41), 0, vec![0u8; 41]);
    assert!(matches!(
        pool.add(tx.clone()),
        Err(StateError::ComputePoolNotActivated)
    ));
    assert!(!pool.contains(&tx.hash()));
}

#[test]
fn execution_refuses_compute_pool_transactions_with_or_without_parameters() {
    for p in [None, Some(declared())] {
        let run = run_sequence(params_with(p));
        let statuses: Vec<Vec<(TxStatus, u128)>> = run
            .iter()
            .map(|(_, rs)| rs.iter().map(|r| (r.status, r.fee_paid)).collect())
            .collect();
        assert_eq!(
            statuses,
            vec![
                vec![(TxStatus::Success, 1_000), (TxStatus::Failed(0), 0)],
                vec![(TxStatus::Failed(0), 0), (TxStatus::Success, 1_000)],
                vec![],
                vec![(TxStatus::Success, 1_000), (TxStatus::Failed(0), 0)],
            ],
            "declared: {}",
            p.is_some()
        );
    }
}

// ── roots and receipts identical to main ───────────────────────────────────

#[test]
fn parameters_absent_reproduce_main_roots_and_receipts() {
    let run = run_sequence(params_with(None));
    assert_eq!(
        hex::encode(run_digest(&run).as_bytes()),
        MAIN_SEQUENCE_DIGEST
    );
    let run_default = run_sequence(ChainParams::default());
    assert_eq!(run_default, run);
}

#[test]
fn parameters_declared_with_the_gate_unset_reproduce_main_roots_and_receipts() {
    let p = params_with(Some(declared()));
    assert_eq!(p.compute_pool_enabled_from_height, None);
    p.validate().unwrap();
    let run = run_sequence(p);
    assert_eq!(run, run_sequence(params_with(None)));
    assert_eq!(
        hex::encode(run_digest(&run).as_bytes()),
        MAIN_SEQUENCE_DIGEST
    );
}
