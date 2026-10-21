//! C5 registry ingress (#242), PROPOSED and dormant: governance-v1 operations
//! 8 (`RegistryRegister`) and 9 (`RegistryDisable`) through the block executor.
//!
//! Every parameter value below is a TEST FIXTURE, not a proposal: the named
//! parameters are unvalued (`REGISTRY_INGRESS_PARAMS` is UNSET), and nothing
//! here suggests a value for them. Specification and vectors:
//! `docs/proposals/c5-registry-ingress/`.

mod common;

use std::sync::Arc;

use common::{candidate, fund};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{GovernanceOperation, GovernanceParams, GovernanceTxData};
use sumchain_primitives::validator_authority::{required_approvals, ValidatorApproval};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::executor::{BlockExecutor, TxExecutionResult};
use sumchain_state::registry_ingress::{v_check_commit, v_get_record, REGISTRY_INGRESS_PARAMS};
use sumchain_state::state::StateManager;
use sumchain_storage::candidate::CandidateExecution;
use sumchain_storage::Database;
use sumchain_wire::registry_ingress::{
    registry_disable_signing_bytes, registry_register_signing_bytes, RegistryCommitRefusal,
    RegistryDisableV1, RegistryIngressParams, RegistryRegisterV1, RegistryThresholdSource,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};
use tempfile::TempDir;

/// Synthetic chain identity of these tests and of the vectors.
const CHAIN: u64 = 4242;
const GENESIS: [u8; 32] = [0x47; 32];
/// Fixture governance threshold: 4 validators need 3 approvals, 1 needs 1.
const GOV_BPS: u16 = 6_667;
/// Fixture named parameters (NOT proposed values).
const T_MIN: u64 = 10;
const WINDOW: u64 = 100;
const H: u64 = 100;
const FEE: u128 = 100;

fn fixture_params() -> RegistryIngressParams {
    RegistryIngressParams {
        registry_min_timelock_blocks: Some(T_MIN),
        registry_threshold_source: Some(RegistryThresholdSource::GovernanceThenRecord),
        registry_record_default_approval_threshold_bps: Some(GOV_BPS),
        registry_max_approval_window: Some(WINDOW),
    }
}

fn chain_params(gov_bps: u16) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.governance_enabled_from_height = Some(0);
    p.governance = Some(GovernanceParams {
        validator_authority_threshold_bps: gov_bps,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 0,
    });
    p
}

struct Node {
    db: Arc<Database>,
    _dir: TempDir,
    exec: BlockExecutor,
}

fn node_with(params: ChainParams, registry: Option<RegistryIngressParams>) -> Node {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN));
    let mut exec = BlockExecutor::new(state, db.clone(), params);
    if let Some(p) = registry {
        exec = exec.with_registry_ingress(p, GENESIS);
    }
    Node { db, _dir: dir, exec }
}

fn node() -> Node {
    node_with(chain_params(GOV_BPS), Some(fixture_params()))
}

/// Validator `i` (1-based), from the synthetic seed `[i; 32]`.
fn validator(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn vset(ids: &[u8]) -> Vec<[u8; 32]> {
    ids.iter().map(|&i| *validator(i).public_key().as_bytes()).collect()
}

fn record(id: u8) -> RegistryRecordV1 {
    RegistryRecordV1 {
        id: [id; 32],
        proof_system_id: 2,
        audit_commitment: [0xA1; 32],
        source_commitment: [0xB2; 32],
        ceremony_commitment: [0xC3; 32],
        verifier_binary_version: 1,
        activation_height: 200,
        status: RegistryStatus::Enabled,
        approval_threshold_bps: GOV_BPS,
    }
}

/// Approvals by `signers` over `msg`, in the canonical ascending order.
fn approvals(signers: &[u8], msg: &[u8]) -> Vec<ValidatorApproval> {
    let mut out: Vec<ValidatorApproval> = signers
        .iter()
        .map(|&i| {
            let kp = validator(i);
            ValidatorApproval {
                pubkey: *kp.public_key().as_bytes(),
                signature: sign(msg, kp.private_key()).to_bytes(),
            }
        })
        .collect();
    out.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
    out
}

fn register_bytes(
    chain: u64,
    genesis: &[u8; 32],
    valid_until: u64,
    rec: &RegistryRecordV1,
    signers: &[u8],
) -> Vec<u8> {
    let msg = registry_register_signing_bytes(chain, genesis, valid_until, rec).unwrap();
    RegistryRegisterV1 {
        valid_until,
        record: rec.clone(),
        approvals: approvals(signers, &msg),
    }
    .try_encode()
    .unwrap()
}

fn register(valid_until: u64, rec: &RegistryRecordV1, signers: &[u8]) -> Vec<u8> {
    register_bytes(CHAIN, &GENESIS, valid_until, rec, signers)
}

fn disable_bytes(chain: u64, genesis: &[u8; 32], valid_until: u64, id: u8, signers: &[u8]) -> Vec<u8> {
    let msg = registry_disable_signing_bytes(chain, genesis, valid_until, &[id; 32]);
    RegistryDisableV1 {
        valid_until,
        id: [id; 32],
        approvals: approvals(signers, &msg),
    }
    .try_encode()
    .unwrap()
}

fn disable(valid_until: u64, id: u8, signers: &[u8]) -> Vec<u8> {
    disable_bytes(CHAIN, &GENESIS, valid_until, id, signers)
}

fn payload(op: GovernanceOperation, data: Vec<u8>) -> TxPayload {
    TxPayload::Governance(GovernanceTxData { operation: op, data })
}

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload,
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// A fee payer that is not a validator: authority comes from the approvals.
struct Submitter {
    kp: KeyPair,
    nonce: u64,
}

impl Submitter {
    fn new(db: &Database) -> Self {
        let kp = KeyPair::from_bytes([0x5A; 32]);
        fund(db, &kp, 1_000_000);
        Self { kp, nonce: 0 }
    }

    /// Execute one operation at `height` against `active`, checking the fee
    /// policy: 302 is pre-semantic (no fee, no nonce), every other outcome
    /// charges the fee and advances the nonce.
    fn run(
        &mut self,
        n: &Node,
        c: &mut CandidateExecution<'_>,
        op: GovernanceOperation,
        data: Vec<u8>,
        height: u64,
        active: &[[u8; 32]],
    ) -> TxStatus {
        let before = StateManager::v_get_nonce(&c.view(), &self.kp.address()).unwrap();
        let tx = signed(&self.kp, self.nonce, payload(op, data));
        let r: TxExecutionResult = n
            .exec
            .execute_tx_with_validators(
                &mut c.view(),
                &tx,
                &Address::new([0x99; 20]),
                height,
                1_000,
                0,
                active,
            )
            .unwrap();
        let after = StateManager::v_get_nonce(&c.view(), &self.kp.address()).unwrap();
        if matches!(r.status, TxStatus::Failed(300..=302)) {
            assert_eq!(r.fee_paid, 0, "{:?} must be free", r.status);
            assert_eq!(after, before, "{:?} must not advance the nonce", r.status);
        } else {
            assert_eq!(r.fee_paid, FEE, "{:?} must charge the fee", r.status);
            assert_eq!(after, before + 1, "{:?} must advance the nonce", r.status);
            self.nonce += 1;
        }
        r.status
    }
}

use GovernanceOperation::{RegistryDisable as DIS, RegistryRegister as REG};

fn stored(c: &mut CandidateExecution<'_>, id: u8) -> Option<RegistryRecordV1> {
    v_get_record(&c.view(), &[id; 32]).unwrap()
}

// ── Dormancy ────────────────────────────────────────────────────────────────

#[test]
fn production_defaults_refuse_both_operations_free_and_write_nothing() {
    assert_eq!(REGISTRY_INGRESS_PARAMS, RegistryIngressParams::UNSET);
    // `BlockExecutor::new` alone: the parameters this binary ships, no genesis hash.
    let n = node_with(chain_params(GOV_BPS), None);
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let active = vset(&[1]);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &active),
        TxStatus::Failed(302)
    );
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1]), H, &active),
        TxStatus::Failed(302)
    );
    assert_eq!(stored(&mut c, 1), None);
}

#[test]
fn any_single_missing_named_parameter_refuses_free() {
    let full = fixture_params();
    for missing in [
        RegistryIngressParams { registry_min_timelock_blocks: None, ..full },
        RegistryIngressParams { registry_threshold_source: None, ..full },
        RegistryIngressParams { registry_record_default_approval_threshold_bps: None, ..full },
        RegistryIngressParams { registry_max_approval_window: None, ..full },
    ] {
        let n = node_with(chain_params(GOV_BPS), Some(missing));
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        let active = vset(&[1]);
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &active),
            TxStatus::Failed(302),
            "{missing:?}"
        );
        assert_eq!(stored(&mut c, 1), None);
    }
}

#[test]
fn governance_gate_and_params_still_come_first() {
    let mut closed = chain_params(GOV_BPS);
    closed.governance_enabled_from_height = None;
    let n = node_with(closed, Some(fixture_params()));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let active = vset(&[1]);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &active),
        TxStatus::Failed(300)
    );

    let mut unconfigured = chain_params(GOV_BPS);
    unconfigured.governance = None;
    let n = node_with(unconfigured, Some(fixture_params()));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1]), H, &active),
        TxStatus::Failed(301)
    );
}

#[test]
fn undecodable_payloads_refuse_free() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let active = vset(&[1, 2, 3, 4]);
    let good = register(H + 50, &record(1), &[1, 2, 3]);

    let mut bad_magic = good.clone();
    bad_magic[0] ^= 0xFF;
    let mut bad_schema = good.clone();
    bad_schema[7] = 2;
    let mut trailing = good.clone();
    trailing.push(0);
    let truncated = good[..good.len() - 1].to_vec();
    // Approvals 2 and 3 exchanged (descending), and approval 2 repeated.
    let (a, b) = (173 + 96..173 + 192, 173 + 192..173 + 288);
    let mut descending = good.clone();
    descending[a.clone()].copy_from_slice(&good[b.clone()]);
    descending[b.clone()].copy_from_slice(&good[a.clone()]);
    let mut repeated = good.clone();
    repeated[b].copy_from_slice(&good[a]);
    let disable_as_register = disable(H + 50, 1, &[1, 2, 3]);

    for (what, data) in [
        ("magic", bad_magic),
        ("schema", bad_schema),
        ("trailing", trailing),
        ("truncated", truncated),
        ("descending", descending),
        ("repeated", repeated),
        ("disable bytes as register", disable_as_register),
    ] {
        assert_eq!(
            s.run(&n, &mut c, REG, data, H, &active),
            TxStatus::Failed(302),
            "{what}"
        );
    }
    assert_eq!(
        s.run(&n, &mut c, DIS, good, H, &active),
        TxStatus::Failed(302),
        "register bytes as disable"
    );
    assert_eq!(stored(&mut c, 1), None);
}

// ── Positive paths ──────────────────────────────────────────────────────────

#[test]
fn register_then_disable_at_k_1_and_k_q() {
    // k = 1: a single-validator set.
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let one = vset(&[1]);
    assert_eq!(required_approvals(1, GOV_BPS), 1);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &one),
        TxStatus::Success
    );
    assert_eq!(stored(&mut c, 1), Some(record(1)));
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1]), H + 1, &one),
        TxStatus::Success
    );
    let mut disabled = record(1);
    disabled.status = RegistryStatus::Disabled;
    assert_eq!(stored(&mut c, 1), Some(disabled));

    // k = q(4) = 3.
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    assert_eq!(required_approvals(4, GOV_BPS), 3);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(2), &[1, 2, 4]), H, &four),
        TxStatus::Success
    );
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 2, &[2, 3, 4]), H, &four),
        TxStatus::Success
    );
    assert_eq!(stored(&mut c, 2).unwrap().status, RegistryStatus::Disabled);
}

// ── Register refusals (303, fee charged) ────────────────────────────────────

/// `record(1)` with one change.
fn with(f: impl Fn(&mut RegistryRecordV1)) -> RegistryRecordV1 {
    let mut r = record(1);
    f(&mut r);
    r
}

#[test]
fn register_refusals() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    let q = [1u8, 2, 3];
    let until = H + 50;
    let rec = record(1);

    let disable_msg = registry_disable_signing_bytes(CHAIN, &GENESIS, until, &rec.id);
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        // Domain confusion: disable approvals presented on a register.
        (
            "disable-domain approvals",
            RegistryRegisterV1 { valid_until: until, record: rec.clone(), approvals: approvals(&q, &disable_msg) }
                .try_encode()
                .unwrap(),
        ),
        ("stale chain_id", register_bytes(CHAIN + 1, &GENESIS, until, &rec, &q)),
        ("stale genesis", register_bytes(CHAIN, &[0x48; 32], until, &rec, &q)),
        ("expired valid_until", register(H - 1, &rec, &q)),
        ("window exceeded", register(H + WINDOW + 1, &rec, &q)),
        ("below threshold", register(until, &rec, &[1, 2])),
        ("no approvals", register(until, &rec, &[])),
        ("outsider approval", register(until, &rec, &[1, 2, 3, 5])),
        ("proof system not admitted", register(until, &with(|r| r.proof_system_id = 1), &q)),
        ("status disabled", register(until, &with(|r| r.status = RegistryStatus::Disabled), &q)),
        ("threshold 0", register(until, &with(|r| r.approval_threshold_bps = 0), &q)),
        ("threshold 10001", register(until, &with(|r| r.approval_threshold_bps = 10_001), &q)),
        (
            "record threshold below governance",
            register(until, &with(|r| r.approval_threshold_bps = GOV_BPS - 1), &q),
        ),
        (
            "activation below h + T_min",
            register(until, &with(|r| r.activation_height = H + T_MIN - 1), &q),
        ),
    ];
    // A signature over other bytes (one byte of the record changed after signing).
    let mut tampered = RegistryRegisterV1::decode_exact(&register(until, &rec, &q)).unwrap();
    tampered.record.verifier_binary_version += 1;
    cases.push(("signature over other bytes", tampered.try_encode().unwrap()));

    for (what, data) in cases {
        assert_eq!(s.run(&n, &mut c, REG, data, H, &four), TxStatus::Failed(303), "{what}");
        assert_eq!(stored(&mut c, 1), None, "{what}");
    }

    // The boundaries themselves are accepted: valid_until = h + window,
    // activation_height = h + T_min, record threshold = governance threshold.
    let edge = with(|r| r.activation_height = H + T_MIN);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + WINDOW, &edge, &q), H, &four),
        TxStatus::Success
    );
    let mut at_until = record(3);
    at_until.activation_height = H + T_MIN;
    assert_eq!(
        s.run(&n, &mut c, REG, register(H, &at_until, &q), H, &four),
        TxStatus::Success,
        "valid_until = h"
    );
}

#[test]
fn an_approval_from_a_departed_validator_refuses_the_operation() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let until = H + 50;
    // Signed while 1..=4 were active; 4 has left by the execution height. The
    // remaining three still meet q(3) = 3 by themselves, but the departed
    // approval is not dropped: the quorum rule refuses it outright.
    let at_execution = vset(&[1, 2, 3]);
    let data = register(until, &record(1), &[1, 2, 3, 4]);
    assert_eq!(s.run(&n, &mut c, REG, data, H, &at_execution), TxStatus::Failed(303));
    // The threshold is over the set at execution: without the departed
    // approval, the same signatures succeed.
    let data = register(until, &record(1), &[1, 2, 3]);
    assert_eq!(s.run(&n, &mut c, REG, data, H, &at_execution), TxStatus::Success);
}

#[test]
fn an_id_is_registered_once_and_never_again() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    let q = [1u8, 2, 3];
    let data = register(H + 50, &record(1), &q);
    assert_eq!(s.run(&n, &mut c, REG, data.clone(), H, &four), TxStatus::Success);
    // The same approvals again, from the same payer under a new nonce.
    assert_eq!(s.run(&n, &mut c, REG, data, H, &four), TxStatus::Failed(303));
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &q), H, &four),
        TxStatus::Success
    );
    // Disabled is terminal: a fresh, valid register of the id is refused.
    let mut again = record(1);
    again.activation_height = 500;
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 60, &again, &q), H + 1, &four),
        TxStatus::Failed(303)
    );
    assert_eq!(stored(&mut c, 1).unwrap().status, RegistryStatus::Disabled);
}

// ── Disable refusals (303, fee charged) ─────────────────────────────────────

#[test]
fn disable_refusals() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    let q = [1u8, 2, 3];
    let until = H + 50;
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(until, 7, &q), H, &four),
        TxStatus::Failed(303),
        "unknown id"
    );
    assert_eq!(
        s.run(&n, &mut c, REG, register(until, &record(1), &q), H, &four),
        TxStatus::Success
    );
    let register_msg = registry_register_signing_bytes(CHAIN, &GENESIS, until, &record(1)).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "register-domain approvals",
            RegistryDisableV1 { valid_until: until, id: [1; 32], approvals: approvals(&q, &register_msg) }
                .try_encode()
                .unwrap(),
        ),
        ("stale chain_id", disable_bytes(CHAIN + 1, &GENESIS, until, 1, &q)),
        ("stale genesis", disable_bytes(CHAIN, &[0x48; 32], until, 1, &q)),
        ("expired valid_until", disable(H - 1, 1, &q)),
        ("window exceeded", disable(H + WINDOW + 1, 1, &q)),
        ("below threshold", disable(until, 1, &[1, 2])),
        ("outsider approval", disable(until, 1, &[1, 2, 3, 5])),
    ];
    for (what, data) in cases {
        assert_eq!(s.run(&n, &mut c, DIS, data, H, &four), TxStatus::Failed(303), "{what}");
        assert_eq!(stored(&mut c, 1).unwrap().status, RegistryStatus::Enabled, "{what}");
    }
    assert_eq!(s.run(&n, &mut c, DIS, disable(until, 1, &q), H, &four), TxStatus::Success);
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(until, 1, &[2, 3, 4]), H, &four),
        TxStatus::Failed(303),
        "already disabled"
    );
}

#[test]
fn disable_is_authorized_at_the_stored_record_threshold() {
    // Governance needs 1 of 2; this record asks for both.
    let n = node_with(chain_params(5_000), Some(fixture_params()));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let two = vset(&[1, 2]);
    let mut rec = record(1);
    rec.approval_threshold_bps = 10_000;
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &rec, &[1]), H, &two),
        TxStatus::Success,
        "register is authorized at the governance threshold"
    );
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1]), H, &two),
        TxStatus::Failed(303),
        "a governance-sized quorum cannot disable it"
    );
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1, 2]), H, &two),
        TxStatus::Success
    );
}

// ── Commit side (#128) ──────────────────────────────────────────────────────

#[test]
fn commit_side_timelock_and_disable_after_semantics() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    let q = [1u8, 2, 3];
    let id = [1u8; 32];
    assert_eq!(
        v_check_commit(&c.view(), &id, H).unwrap(),
        Err(RegistryCommitRefusal::Unknown)
    );
    let mut rec = record(1);
    rec.activation_height = H + T_MIN;
    assert_eq!(s.run(&n, &mut c, REG, register(H + 50, &rec, &q), H, &four), TxStatus::Success);

    // Pre-timelock: refused until activation_height, accepted from it.
    assert_eq!(
        v_check_commit(&c.view(), &id, H + T_MIN - 1).unwrap(),
        Err(RegistryCommitRefusal::BeforeActivation {
            activation_height: H + T_MIN,
            height: H + T_MIN - 1
        })
    );
    let d = H + T_MIN;
    assert_eq!(v_check_commit(&c.view(), &id, d).unwrap(), Ok(()));

    // One block at height d: a commit before the disable is judged against the
    // Enabled record; one after it, in the same block, against Disabled.
    let mut block = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    // Re-register in this fresh candidate (the earlier one was never published).
    let mut rec = record(1);
    rec.activation_height = H + T_MIN;
    assert_eq!(s.run(&n, &mut block, REG, register(H + 50, &rec, &q), H, &four), TxStatus::Success);
    assert_eq!(v_check_commit(&block.view(), &id, d).unwrap(), Ok(()), "before the disable");
    assert_eq!(
        s.run(&n, &mut block, DIS, disable(d + 50, 1, &q), d, &four),
        TxStatus::Success
    );
    assert_eq!(
        v_check_commit(&block.view(), &id, d).unwrap(),
        Err(RegistryCommitRefusal::Disabled),
        "after the disable, same block"
    );
    assert_eq!(
        v_check_commit(&block.view(), &id, d + 1).unwrap(),
        Err(RegistryCommitRefusal::Disabled),
        "later blocks"
    );
}

// ── Signature verification convention ───────────────────────────────────────

/// Approvals are verified by `verify_validator_quorum`, the governance-v1
/// convention (`sumchain_crypto::verify_bytes`, ed25519-dalek `verify`). This
/// pins the property the specification states for `S`.
#[test]
fn signature_convention_refuses_a_non_canonical_s() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let one = vset(&[1]);
    let until = H + 50;
    let good = RegistryRegisterV1::decode_exact(&register(until, &record(1), &[1])).unwrap();

    // S + ℓ (ℓ = 2^252 + 27742317777372353535851937790883648493), little-endian.
    const ELL: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut high_s = good.clone();
    let sig = &mut high_s.approvals[0].signature;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + ELL[i] as u16 + carry;
        sig[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        s.run(&n, &mut c, REG, high_s.try_encode().unwrap(), H, &one),
        TxStatus::Failed(303),
        "non-canonical S"
    );

    assert_eq!(s.run(&n, &mut c, REG, good.try_encode().unwrap(), H, &one), TxStatus::Success);
}

// ── Vectors ─────────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Build the vector file's content. Every value is synthetic.
fn vectors() -> String {
    let until = H + 50;
    let rec = record(0x11);
    let mut out = String::new();
    let mut line = |k: &str, v: String| out.push_str(&format!("{k} = {v}\n"));
    line("chain_id", CHAIN.to_string());
    line("genesis_block_hash", hex(&GENESIS));
    line("execution_height", H.to_string());
    line("valid_until", until.to_string());
    line("fixture.validator_authority_threshold_bps", GOV_BPS.to_string());
    line("fixture.registry_min_timelock_blocks", T_MIN.to_string());
    line("fixture.registry_max_approval_window", WINDOW.to_string());
    for i in 1..=4u8 {
        line(&format!("validator.{i}.seed"), hex(&[i; 32]));
        line(&format!("validator.{i}.pubkey"), hex(validator(i).public_key().as_bytes()));
    }
    line("record", hex(&rec.try_encode().unwrap()));
    line(
        "register.signing_bytes",
        hex(&registry_register_signing_bytes(CHAIN, &GENESIS, until, &rec).unwrap()),
    );
    line(
        "disable.signing_bytes",
        hex(&registry_disable_signing_bytes(CHAIN, &GENESIS, until, &rec.id)),
    );
    for (name, signers) in [("k1", &[1u8][..]), ("k3", &[1u8, 2, 3][..])] {
        for (op, opname, data) in [
            (REG, "register", register(until, &rec, signers)),
            (DIS, "disable", disable(until, 0x11, signers)),
        ] {
            let g = GovernanceTxData { operation: op, data: data.clone() };
            line(&format!("{opname}.{name}.data"), hex(&data));
            line(
                &format!("{opname}.{name}.governance_tx_data"),
                hex(&bincode::serialize(&g).unwrap()),
            );
            line(
                &format!("{opname}.{name}.tx_payload"),
                hex(&bincode::serialize(&TxPayload::Governance(g)).unwrap()),
            );
        }
    }
    out
}

const VECTORS_PATH: &str = "../../docs/proposals/c5-registry-ingress/vectors.txt";

/// The committed vectors are exactly what the code produces, and each vector
/// payload executes as specified: k = 1 over a one-validator set, k = 3 = q(4)
/// over four.
#[test]
fn vectors_are_reproduced_and_execute() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS_PATH);
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    let body: String = committed
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| format!("{l}\n"))
        .collect();
    let generated = vectors();
    assert!(
        body == generated,
        "{} differs from the generated vectors:\n{generated}",
        path.display()
    );

    // Envelope framing (bincode 1, fixint little-endian).
    let field = |k: &str| -> String {
        body.lines()
            .find_map(|l| l.strip_prefix(&format!("{k} = ")).map(str::to_string))
            .unwrap()
    };
    assert!(field("register.k1.governance_tx_data").starts_with("08000000"));
    assert!(field("disable.k1.governance_tx_data").starts_with("09000000"));
    assert!(field("register.k3.tx_payload").starts_with("1700000008000000"));
    assert_eq!(field("register.k1.data").len(), 2 * (173 + 96));
    assert_eq!(field("register.k3.data").len(), 2 * (173 + 3 * 96));
    assert_eq!(field("disable.k3.data").len(), 2 * (51 + 3 * 96));

    for (signers, ids) in [(&[1u8][..], &[1u8][..]), (&[1u8, 2, 3][..], &[1u8, 2, 3, 4][..])] {
        let n = node();
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        let active = vset(ids);
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &record(0x11), signers), H, &active),
            TxStatus::Success
        );
        assert_eq!(
            s.run(&n, &mut c, DIS, disable(H + 50, 0x11, signers), H, &active),
            TxStatus::Success
        );
    }
}
