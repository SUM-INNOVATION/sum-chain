//! C5 registry ingress (#242), PROPOSED and dormant: the proposed governance-v1
//! operations 8 (register) and 9 (disable), run through
//! `governance_executor::execute_registry_ingress` by direct call. No
//! transaction decodes to them (`governance_fixtures.rs` pins that), so these
//! tests are the only way in.
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
use sumchain_primitives::governance::GovernanceParams;
use sumchain_primitives::validator_authority::{required_approvals, ValidatorApproval};
use sumchain_primitives::{Address, Hash, TxPayload, TxStatus};
use sumchain_state::governance_executor::execute_registry_ingress;
use sumchain_state::registry_ingress::{
    registry_record_key, v_check_commit, v_count_records_up_to, v_get_record,
    RegistryIngressContext, RegistryIngressOp, MAX_REGISTRY_FOLDED_BYTES, MAX_REGISTRY_RECORDS,
    REGISTRY_INGRESS_PARAMS, REGISTRY_RECORD_KEY_PREFIX,
};
use sumchain_storage::cf;
use sumchain_state::state::StateManager;
use sumchain_storage::candidate::CandidateExecution;
use sumchain_storage::Database;
use sumchain_wire::registry_ingress::{
    registry_disable_signing_bytes, registry_register_signing_bytes, unset_commitments,
    RegistryCommitRefusal, RegistryDisableV1, RegistryIngressParams, RegistryRegisterV1,
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
    params: ChainParams,
    registry: RegistryIngressParams,
    genesis: Option<[u8; 32]>,
}

/// `registry: None` is what this binary has: every parameter unset and no
/// genesis block hash.
fn node_with(params: ChainParams, registry: Option<RegistryIngressParams>) -> Node {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let (registry, genesis) = match registry {
        Some(p) => (p, Some(GENESIS)),
        None => (REGISTRY_INGRESS_PARAMS, None),
    };
    Node {
        db,
        _dir: dir,
        params,
        registry,
        genesis,
    }
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

/// A fee payer that is not a validator: authority comes from the approvals.
struct Submitter {
    kp: KeyPair,
}

impl Submitter {
    fn new(db: &Database) -> Self {
        let kp = KeyPair::from_bytes([0x5A; 32]);
        fund(db, &kp, 1_000_000);
        Self { kp }
    }

    /// Execute one operation at `height` against `active`, checking the fee
    /// policy: 302 is pre-semantic (no fee, no nonce), every other outcome
    /// charges the fee and advances the nonce.
    fn run(
        &mut self,
        n: &Node,
        c: &mut CandidateExecution<'_>,
        op: RegistryIngressOp,
        data: Vec<u8>,
        height: u64,
        active: &[[u8; 32]],
    ) -> TxStatus {
        let before = StateManager::v_get_nonce(&c.view(), &self.kp.address()).unwrap();
        let r = execute_registry_ingress(
            &mut c.view(),
            CHAIN,
            &n.params,
            op,
            &data,
            &self.kp.address(),
            FEE,
            &Address::new([0x99; 20]),
            height,
            Hash::ZERO,
            active,
            RegistryIngressContext {
                params: &n.registry,
                genesis_block_hash: n.genesis.as_ref(),
            },
        )
        .unwrap();
        let after = StateManager::v_get_nonce(&c.view(), &self.kp.address()).unwrap();
        if matches!(r.status, TxStatus::Failed(300..=302)) {
            assert_eq!(r.fee_paid, 0, "{:?} must be free", r.status);
            assert_eq!(after, before, "{:?} must not advance the nonce", r.status);
        } else {
            assert_eq!(r.fee_paid, FEE, "{:?} must charge the fee", r.status);
            assert_eq!(after, before + 1, "{:?} must advance the nonce", r.status);
        }
        r.status
    }
}

use RegistryIngressOp::{Disable as DIS, Register as REG};

fn stored(c: &mut CandidateExecution<'_>, id: u8) -> Option<RegistryRecordV1> {
    v_get_record(&c.view(), &[id; 32]).unwrap()
}

// ── Dormancy ────────────────────────────────────────────────────────────────

#[test]
fn production_defaults_refuse_both_operations_free_and_write_nothing() {
    assert_eq!(REGISTRY_INGRESS_PARAMS, RegistryIngressParams::UNSET);
    // What this binary has: every parameter unset, no genesis block hash.
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

/// The `GovernanceTxData` bytes operation `op` WOULD have once the activation
/// change adds its wire variant: u32 variant index ‖ u64 length ‖ data
/// (bincode 1, fixint little-endian). Built by hand: no type encodes it today.
fn prospective_governance_tx_data(op: u32, data: &[u8]) -> Vec<u8> {
    [&op.to_le_bytes()[..], &(data.len() as u64).to_le_bytes(), data].concat()
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
    line("test_only.validator_authority_threshold_bps", GOV_BPS.to_string());
    line("test_only.registry_min_timelock_blocks", T_MIN.to_string());
    line("test_only.registry_max_approval_window", WINDOW.to_string());
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
            (8u32, "register", register(until, &rec, signers)),
            (9u32, "disable", disable(until, 0x11, signers)),
        ] {
            let g = prospective_governance_tx_data(op, &data);
            line(&format!("{opname}.{name}.data"), hex(&data));
            line(&format!("{opname}.{name}.prospective_governance_tx_data"), hex(&g));
            line(
                &format!("{opname}.{name}.prospective_tx_payload"),
                hex(&[&23u32.to_le_bytes()[..], &g].concat()),
            );
        }
    }
    // A register whose one approval is validator 1's identity-R signature over
    // the register preimage: governance-v1 `verify` accepts that signature,
    // `verify_strict` (operations 8 and 9) refuses it.
    let msg = registry_register_signing_bytes(CHAIN, &GENESIS, until, &rec).unwrap();
    let identity_r = RegistryRegisterV1 {
        valid_until: until,
        record: rec.clone(),
        approvals: vec![ValidatorApproval {
            pubkey: *validator(1).public_key().as_bytes(),
            signature: identity_r_signature(1, &msg),
        }],
    };
    line(
        "prospective_strict_refused.identity_r.register.k1.data",
        hex(&identity_r.try_encode().unwrap()),
    );
    let noncanonical_r = RegistryRegisterV1 {
        approvals: vec![ValidatorApproval {
            pubkey: *validator(1).public_key().as_bytes(),
            signature: noncanonical_identity_r_signature(1, &msg),
        }],
        ..identity_r
    };
    line(
        "prospective_both_refuse.noncanonical_r.register.k1.data",
        hex(&noncanonical_r.try_encode().unwrap()),
    );
    // The registry size bound (owner, 2026-10-23; value PROPOSED), README §12.1.
    line("prospective_registry_bound.max_records", MAX_REGISTRY_RECORDS.to_string());
    line(
        "prospective_registry_bound.max_folded_bytes",
        MAX_REGISTRY_FOLDED_BYTES.to_string(),
    );
    // The proposed quorum rule's required approval counts at its boundaries
    // (Q17): `required_approvals`, `validator_authority.rs:119-123`.
    for (n, bps) in QUORUM_BOUNDARIES {
        line(
            &format!("prospective_quorum.n{n}.bps{bps}.required"),
            required_approvals(n, bps).to_string(),
        );
    }
    out
}

/// (n, bps) boundaries of the quorum rule: n = 1, the effective validator cap
/// 29,127 (VS-6(a)) and `u32::MAX` (the type's limit); bps at 1 and 10000.
const QUORUM_BOUNDARIES: [(u32, u16); 9] = [
    (1, 1),
    (1, 10_000),
    (4, 1),
    (4, 6_667),
    (4, 10_000),
    (29_127, 1),
    (29_127, 10_000),
    (u32::MAX, 1),
    (u32::MAX, 10_000),
];

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
    assert!(field("register.k1.prospective_governance_tx_data").starts_with("08000000"));
    assert!(field("disable.k1.prospective_governance_tx_data").starts_with("09000000"));
    assert!(field("register.k3.prospective_tx_payload").starts_with("1700000008000000"));
    // Prospective only: on this binary every such envelope is refused at
    // decode, exactly as an unknown operation always was.
    for op in ["register", "disable"] {
        for k in ["k1", "k3"] {
            let hexed = field(&format!("{op}.{k}.prospective_tx_payload"));
            let bytes: Vec<u8> = (0..hexed.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).unwrap())
                .collect();
            let err = bincode::deserialize::<TxPayload>(&bytes).unwrap_err();
            assert!(
                err.to_string().contains("expected variant index 0 <= i < 8"),
                "{op}.{k}: {err}"
            );
        }
    }
    assert_eq!(field("register.k1.data").len(), 2 * (173 + 96));
    assert_eq!(field("register.k3.data").len(), 2 * (173 + 3 * 96));
    assert_eq!(field("disable.k3.data").len(), 2 * (51 + 3 * 96));

    // The identity-R and non-canonical-R registers execute as 303.
    for key in [
        "prospective_strict_refused.identity_r.register.k1.data",
        "prospective_both_refuse.noncanonical_r.register.k1.data",
    ] {
        let hexed = field(key);
        let bytes: Vec<u8> = (0..hexed.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).unwrap())
            .collect();
        let n = node();
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        assert_eq!(s.run(&n, &mut c, REG, bytes, H, &vset(&[1])), TxStatus::Failed(303), "{key}");
    }

    // The size bound: the k = 1 register is accepted with MAX - 1 records
    // stored and refused (303) with MAX stored.
    assert_eq!(
        field("prospective_registry_bound.max_records"),
        MAX_REGISTRY_RECORDS.to_string()
    );
    assert_eq!(
        field("prospective_registry_bound.max_folded_bytes"),
        MAX_REGISTRY_FOLDED_BYTES.to_string()
    );
    for (stored_records, want) in [
        (MAX_REGISTRY_RECORDS - 1, TxStatus::Success),
        (MAX_REGISTRY_RECORDS, TxStatus::Failed(303)),
    ] {
        let n = node();
        fill_registry(&n.db, stored_records);
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        let hexed = field("register.k1.data");
        let bytes: Vec<u8> = (0..hexed.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(s.run(&n, &mut c, REG, bytes, H, &vset(&[1])), want, "{stored_records} stored");
    }

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

// ── Registry size bound (owner, 2026-10-23; value PROPOSED) ─────────────────

/// Store `n` filler records directly in committed state, every other one
/// Disabled, under ids no other test record uses: `F0 ‖ i (u32 BE) ‖ 0…`.
fn fill_registry(db: &Database, n: u64) {
    for i in 0..n {
        let mut rec = record(0);
        rec.id = [0; 32];
        rec.id[0] = 0xF0;
        rec.id[1..5].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        if i % 2 == 1 {
            rec.status = RegistryStatus::Disabled;
        }
        db.put(cf::STATE, &registry_record_key(&rec.id), &rec.try_encode().unwrap())
            .unwrap();
    }
}

/// Every stored record, as the candidate sees it.
fn count(c: &mut CandidateExecution<'_>) -> u64 {
    v_count_records_up_to(&c.view(), u64::MAX).unwrap()
}

/// The bound and the folded bytes it implies.
#[test]
fn the_size_bound_constants() {
    assert_eq!(MAX_REGISTRY_RECORDS, 4_096);
    // id (32) and the frozen record (154) per row, the proposed fold domain
    // (27 bytes) and the u64 count.
    assert_eq!(RegistryRecordV1::LEN, 154);
    assert_eq!("SUMCHAIN/REGISTRY/STATE/v1\u{0}".len(), 27);
    assert_eq!(MAX_REGISTRY_FOLDED_BYTES, 4_096 * 186 + 35);
    assert_eq!(MAX_REGISTRY_FOLDED_BYTES, 761_891);
}

/// MAX − 1 stored: a register is accepted and the count reaches MAX. At MAX
/// the next register is refused with 303 (fee charged, nothing stored; fee 0
/// when underfunded). Disabled records count, and disable stays allowed. A
/// disabled id is still present, so it cannot be registered again. A register
/// staged earlier in the same block counts.
#[test]
fn the_size_bound_refuses_the_register_that_would_exceed_it() {
    let n = node();
    fill_registry(&n.db, MAX_REGISTRY_RECORDS - 1);
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let one = vset(&[1]);
    assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS - 1);
    // Bounded: the scan never reads past its limit.
    assert_eq!(v_count_records_up_to(&c.view(), 10).unwrap(), 10);
    assert_eq!(v_count_records_up_to(&c.view(), 0).unwrap(), 0);

    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &one),
        TxStatus::Success
    );
    assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS, "the staged register counts");

    // At the limit (MAX stored, half of the fillers Disabled): refused.
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(2), &[1]), H, &one),
        TxStatus::Failed(303)
    );
    assert_eq!(stored(&mut c, 2), None);
    assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS);

    // Underfunded at the limit: 303 with fee 0, the nonce unchanged.
    let poor = KeyPair::from_bytes([0x5C; 32]);
    fund(&n.db, &poor, FEE - 1);
    let r = execute_registry_ingress(
        &mut c.view(),
        CHAIN,
        &n.params,
        REG,
        &register(H + 50, &record(3), &[1]),
        &poor.address(),
        FEE,
        &Address::new([0x98; 20]),
        H,
        Hash::ZERO,
        &one,
        RegistryIngressContext {
            params: &n.registry,
            genesis_block_hash: n.genesis.as_ref(),
        },
    )
    .unwrap();
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(303), 0));
    assert_eq!(StateManager::v_get_nonce(&c.view(), &poor.address()).unwrap(), 0);
    assert_eq!(stored(&mut c, 3), None);

    // Disable adds no record: allowed at the limit, and the count is unchanged.
    assert_eq!(
        s.run(&n, &mut c, DIS, disable(H + 50, 1, &[1]), H, &one),
        TxStatus::Success
    );
    assert_eq!(stored(&mut c, 1).unwrap().status, RegistryStatus::Disabled);
    assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS);
    // A disabled id is still present: re-registering it is refused (rule 7).
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &one),
        TxStatus::Failed(303)
    );
}

/// A published register is undone through the generic application journal,
/// and the count returns to MAX − 1, so a register is accepted again.
#[test]
fn rolling_back_a_register_restores_the_count() {
    use sumchain_primitives::{Block, BlockHeader};
    use sumchain_storage::candidate::{BlockJournals, ExecutionSubject, JournalRecord};
    use sumchain_storage::journal::ApplicationJournal;
    use sumchain_storage::schema::journal_key;

    let n = node();
    fill_registry(&n.db, MAX_REGISTRY_RECORDS - 1);
    let one = vset(&[1]);
    // One payer, funded once, so nothing is written outside a block between
    // the publication and the undo.
    let mut s = Submitter::new(&n.db);
    let block = Block::new(
        BlockHeader::new(Hash::ZERO, H, 1_000, Hash::hash(b"txs"), Hash::hash(b"root"), [0; 32]),
        Vec::new(),
    );
    {
        let mut c = candidate(&n.db);
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &one),
            TxStatus::Success
        );
        c.finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            block.header.state_root,
            Vec::new(),
            BlockJournals {
                account: JournalRecord::NothingToUndo,
                contract: JournalRecord::NothingToUndo,
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(&block)
        .unwrap()
        .publish()
        .unwrap();
    }
    {
        // Not published: the refused register's fee stays in this candidate.
        let mut c = candidate(&n.db);
        assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS);
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &record(2), &[1]), H, &one),
            TxStatus::Failed(303),
            "committed state is at the limit"
        );
    }
    let bytes = n
        .db
        .get(cf::APPLICATION_JOURNAL, &journal_key(H, &block.hash()))
        .unwrap()
        .expect("a published block leaves a journal");
    let journal = ApplicationJournal::decode_for(&bytes, H, &block.hash()).unwrap();
    journal.undo_batch(&n.db).unwrap().commit().unwrap();

    let mut c = candidate(&n.db);
    assert_eq!(count(&mut c), MAX_REGISTRY_RECORDS - 1);
    assert_eq!(stored(&mut c, 1), None);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(2), &[1]), H, &one),
        TxStatus::Success
    );
}

/// Seed one raw `cf::STATE` row before any candidate exists (committed state,
/// not a publication).
fn seed_state_row(db: &Database, key: &[u8], value: &[u8]) {
    db.put(cf::STATE, key, value).unwrap();
}

/// Run one operation through the dormant entry in a fresh candidate (never
/// published), returning the entry's result and the payer's nonce after it.
fn run_entry(n: &Node, op: RegistryIngressOp, data: Vec<u8>) -> (sumchain_state::Result<TxStatus>, u64) {
    let mut c = candidate(&n.db);
    let s = Submitter::new(&n.db);
    let r = execute_registry_ingress(
        &mut c.view(),
        CHAIN,
        &n.params,
        op,
        &data,
        &s.kp.address(),
        FEE,
        &Address::new([0x99; 20]),
        H,
        Hash::ZERO,
        &vset(&[1]),
        RegistryIngressContext {
            params: &n.registry,
            genesis_block_hash: n.genesis.as_ref(),
        },
    );
    (r.map(|r| r.status), StateManager::v_get_nonce(&c.view(), &s.kp.address()).unwrap())
}

/// A read the registry cannot trust is an execution error, never a receipt:
/// a node-local failure must not become a consensus-visible outcome. Three
/// failing reads, each through the dormant entry:
/// - a row that does not decode;
/// - a row whose record names another id;
/// - a key under `registry/v1/` of the wrong length.
///
/// Each returns `Err` and charges nothing; no receipt is produced.
#[test]
fn a_failing_registry_read_is_an_execution_error_not_a_receipt() {
    // Every row is seeded before any candidate exists.
    let undecodable = node();
    seed_state_row(&undecodable.db, &registry_record_key(&[1; 32]), b"not a record");
    let foreign = node();
    seed_state_row(&foreign.db, &registry_record_key(&[1; 32]), &record(2).try_encode().unwrap());
    let malformed = node();
    let mut short = REGISTRY_RECORD_KEY_PREFIX.to_vec();
    short.extend_from_slice(&[0; 31]);
    seed_state_row(&malformed.db, &short, &record(9).try_encode().unwrap());

    // An undecodable row under the register's own id, and under the disabled id.
    let (r, nonce) = run_entry(&undecodable, REG, register(H + 50, &record(1), &[1]));
    assert!(r.is_err(), "register over an undecodable row: {r:?}");
    assert_eq!(nonce, 0, "no fee, no nonce: there is no receipt");
    let (r, _) = run_entry(&undecodable, DIS, disable(H + 50, 1, &[1]));
    assert!(r.is_err(), "disable of an undecodable row: {r:?}");

    // A row whose record names another id.
    let (r, _) = run_entry(&foreign, DIS, disable(H + 50, 1, &[1]));
    assert!(r.is_err(), "a record stored under another id: {r:?}");

    // A key of the wrong shape under the prefix, met by the size-bound scan
    // of an otherwise valid register for another id.
    let (r, nonce) = run_entry(&malformed, REG, register(H + 50, &record(1), &[1]));
    assert!(r.is_err(), "a malformed registry key is an error, not counted: {r:?}");
    assert_eq!(nonce, 0);
    // The same row through the counting function itself.
    let mut c = candidate(&malformed.db);
    assert!(v_count_records_up_to(&c.view(), MAX_REGISTRY_RECORDS).is_err());
}

// ── Storage: no new column family ───────────────────────────────────────────

/// `ALL_CFS` on `e3b8ff81`, names and order. A family a binary does not name
/// makes the volume unopenable by that binary, so C5 adds none: records live
/// in the existing `cf::STATE` under `registry/v1/` (adopted 2026-10-23).
const MAIN_ALL_CFS: &[&str] = &[
    "blocks",
    "block_height",
    "state",
    "transactions",
    "receipts",
    "meta",
    "state_diffs",
    "nft_collections",
    "nft_tokens",
    "nft_owner_index",
    "nft_collection_index",
    "issuer_registry",
    "tokens",
    "token_balances",
    "token_allowances",
    "token_holder_index",
    "validators",
    "delegations",
    "unbonding_delegations",
    "delegation_validator_index",
    "slashing_records",
    "validator_signing_info",
    "missed_blocks",
    "validator_sets",
    "account_encryption_keys",
    "active_archive_nodes_history",
    "archive_unbonding",
    "challengeable_files_v2",
    "supply",
    "storage_metadata_v2",
    "assignment_attestations_v2",
    "file_reassignments",
    "assignment_attestations_v2_epoch",
    "inference_attestations",
    "inference_attestations_by_session",
    "inference_attestation_sponsors",
    "inference_sessions",
    "inference_claims",
    "inference_disputes",
    "inference_verifiers",
    "edu_catalog_entries",
    "edu_catalog_prerequisites",
    "edu_catalog_accreditation",
    "edu_catalog_content_items",
    "edu_catalog_by_institution",
    "edu_catalog_by_code",
    "edu_catalog_by_status",
    "edu_offerings",
    "edu_instructor_bindings",
    "edu_content_items",
    "edu_assessments",
    "edu_enrollment_links",
    "edu_submissions",
    "edu_grades",
    "edu_offering_by_catalog",
    "edu_offering_by_status",
    "edu_submission_by_student_commitment",
    "docclass_identity_roots",
    "docclass_eligibility",
    "docclass_credentials",
    "docclass_revocations",
    "docclass_issuers",
    "docclass_subject_index",
    "docclass_issuer_index",
    "docclass_events",
    "messaging_config",
    "messaging_sender_nonces",
    "messaging_daily_counts",
    "messaging_stakes",
    "messaging_spam_scores",
    "messaging_inbox_filters",
    "messaging_contacts",
    "messaging_blocked",
    "messaging_pending_payments",
    "messaging_events",
    "messaging_sender_events",
    "messaging_payments_by_recipient",
    "messaging_public_keys",
    "contract_code",
    "contract_storage",
    "contract_metadata",
    "contract_state_diffs",
    "tax_claim_types",
    "tax_issuers",
    "tax_policies",
    "tax_proofs",
    "tax_disclosures",
    "tax_subject_index",
    "tax_issuer_index",
    "tax_events",
    "equity_entities",
    "equity_governance",
    "equity_tokens",
    "equity_balances",
    "equity_controllers",
    "equity_corporate_actions",
    "equity_snapshots",
    "equity_proofs",
    "equity_entity_index",
    "equity_holder_index",
    "equity_events",
    "agreement_commitments",
    "agreement_signatures",
    "agreement_attestations",
    "agreement_ip_actions",
    "agreement_executor_links",
    "agreement_proofs",
    "agreement_party_index",
    "agreement_executor_index",
    "agreement_events",
    "legal_cases",
    "legal_events",
    "legal_orders",
    "legal_benefits",
    "legal_proofs",
    "legal_case_event_index",
    "legal_case_order_index",
    "legal_jurisdiction_index",
    "legal_system_events",
    "property_assets",
    "property_title_events",
    "property_encumbrances",
    "property_coverage",
    "property_claims",
    "property_proofs",
    "property_asset_title_index",
    "property_asset_encumbrance_index",
    "property_asset_coverage_index",
    "property_coverage_claim_index",
    "property_jurisdiction_index",
    "property_system_events",
    "healthcare_providers",
    "healthcare_memberships",
    "healthcare_consents",
    "healthcare_prescriptions",
    "healthcare_proofs",
    "healthcare_provider_network_index",
    "healthcare_member_index",
    "healthcare_subject_consent_index",
    "healthcare_patient_rx_index",
    "healthcare_prescriber_rx_index",
    "healthcare_system_events",
    "healthcare_member_address_index",
    "healthcare_subject_address_index",
    "healthcare_patient_address_index",
    "employment_issuers",
    "employment_credentials",
    "employment_income_attestations",
    "employment_proofs",
    "employment_employee_index",
    "employment_employee_address_index",
    "employment_income_holder_address_index",
    "employment_employer_index",
    "employment_subject_income_index",
    "employment_system_events",
    "finance_issuers",
    "finance_address_proofs",
    "finance_bank_standings",
    "finance_kyc_attestations",
    "finance_proofs",
    "finance_subject_address_index",
    "finance_subject_bank_index",
    "finance_subject_kyc_index",
    "finance_holder_address_proof_index",
    "finance_holder_bank_index",
    "finance_holder_kyc_index",
    "finance_jurisdiction_index",
    "finance_system_events",
    "policy_accounts",
    "policy_proposals",
    "gov_registry",
    "gov_proposals",
    "gov_votes",
    "gov_snapshots",
    "gov_proposal_index",
    "gov_qualifying_assets",
    "gov_equity_class_roots",
    "gov_equity_used_commitments",
    "node_registry",
    "storage_metadata",
    "active_challenges",
    "tx_by_sender",
    "tx_by_recipient",
    "compute_pool_state",
    "compute_pool_state_diffs",
    "beacon_state",
    "beacon_state_diffs",
    "application_journal",
];

#[test]
fn the_column_families_are_exactly_mains() {
    assert_eq!(sumchain_storage::db::ALL_CFS, MAIN_ALL_CFS);
}

#[test]
fn a_record_is_one_state_row_under_its_prefix() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1, 2, 3]), H, &four),
        TxStatus::Success
    );
    let view = c.view();
    // `prefix_iter` seeks to the prefix; a reader stops where the prefix ends,
    // as the account fold does (`account_root.rs` `AccountDigest::fold`).
    let rows: Vec<(Vec<u8>, Vec<u8>)> = view
        .prefix_iter(cf::STATE, REGISTRY_RECORD_KEY_PREFIX)
        .unwrap()
        .map(|r| r.unwrap())
        .take_while(|(k, _)| k.starts_with(REGISTRY_RECORD_KEY_PREFIX))
        .collect();
    assert_eq!(rows.len(), 1);
    let (key, value) = &rows[0];
    assert_eq!(key, &registry_record_key(&[1; 32]));
    assert_eq!(key.len(), 12 + 32);
    assert_eq!(value, &record(1).try_encode().unwrap());
    // Nothing went to `meta`. The account scan (the account root, the snapshot
    // export, the legacy revert) stops at the end of `acct`, before any
    // registry row: `registry/` sorts after `acct`.
    assert_eq!(view.get(cf::META, &registry_record_key(&[1; 32])).unwrap(), None);
    let acct = sumchain_storage::schema::ACCOUNT_KEY_PREFIX;
    let mut accounts = 0;
    for entry in view.prefix_iter(cf::STATE, acct).unwrap() {
        let (key, _) = entry.unwrap();
        if !key.starts_with(acct) {
            assert!(key.as_slice() > acct, "the scan ends after the prefix");
            break;
        }
        assert!(!key.starts_with(REGISTRY_RECORD_KEY_PREFIX));
        accounts += 1;
    }
    assert!(accounts >= 2, "the payer and the proposer");
}

/// Every `b"…"` literal in `src` (simple escapes only), as
/// `storage/tests/certified_meta_v1.rs` collects them.
fn byte_literals(src: &str) -> Vec<Vec<u8>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let starts = bytes[i] == b'b'
            && bytes[i + 1] == b'"'
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'));
        if !starts {
            i += 1;
            continue;
        }
        let mut j = i + 2;
        let mut lit = Vec::new();
        while j < bytes.len() && bytes[j] != b'"' {
            if bytes[j] == b'\\' && j + 1 < bytes.len() {
                match bytes[j + 1] {
                    b'0' => lit.push(0),
                    b'n' => lit.push(b'\n'),
                    b't' => lit.push(b'\t'),
                    b'x' if j + 3 < bytes.len() => {
                        let h = std::str::from_utf8(&bytes[j + 2..j + 4]).unwrap_or("00");
                        lit.push(u8::from_str_radix(h, 16).unwrap_or(0));
                        j += 2;
                    }
                    c => lit.push(c),
                }
                j += 2;
            } else {
                lit.push(bytes[j]);
                j += 1;
            }
        }
        out.push(lit);
        i = j + 1;
    }
    out
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every key family of `cf::STATE`, on main and in the open PRs (checked
/// 2026-10-23): `acct` (account rows, `storage/src/schema.rs` `ACCOUNT_KEY_PREFIX`,
/// the only family any production code scans) and `vset/` (G5's validator-set
/// rows, #342, not yet merged). No other open PR writes `cf::STATE`.
const STATE_KEY_FAMILIES: [&[u8]; 2] = [sumchain_storage::schema::ACCOUNT_KEY_PREFIX, b"vset/"];

/// The registry prefix is prefix-free with every other `cf::STATE` key family,
/// in both directions, and the `registry/` namespace is this module's alone.
/// No existing exact read or prefix scan can see a registry row, and no
/// registry scan can see another row.
#[test]
fn the_record_prefix_is_disjoint_from_every_state_key_family() {
    let p = REGISTRY_RECORD_KEY_PREFIX;
    assert_eq!(p, b"registry/v1/");
    assert_eq!(sumchain_storage::schema::ACCOUNT_KEY_PREFIX, b"acct");
    for family in STATE_KEY_FAMILIES {
        assert!(
            !family.starts_with(p) && !p.starts_with(family),
            "{} overlaps the registry prefix",
            String::from_utf8_lossy(family)
        );
    }

    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        for sub in ["src", "tests"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    assert!(files.len() > 100, "the scan found too few files to mean anything");
    let own = ["state/src/registry_ingress.rs", "state/tests/registry_ingress.rs"];
    let mut literals = std::collections::BTreeSet::new();
    for f in &files {
        if own.iter().any(|o| f.ends_with(o)) {
            continue;
        }
        literals.extend(byte_literals(&std::fs::read_to_string(f).unwrap()));
    }
    let reserved: Vec<String> = literals
        .iter()
        .filter(|l| l.starts_with(b"registry/"))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    assert!(reserved.is_empty(), "other literals in registry/: {reserved:?}");
    let prefixes: Vec<String> = literals
        .iter()
        .filter(|l| !l.is_empty() && l.ends_with(b"/") && p.starts_with(l))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    assert!(prefixes.is_empty(), "literals that prefix {p:?}: {prefixes:?}");
}

// ── Q17: the quorum rule at its boundaries ───────────────────────────────────

/// The rule register uses, verbatim (`validator_authority.rs:119-123`,
/// `validator_quorum.rs:99-130`): `required = (n·bps + 9999) div 10000` in
/// `u64`, accepted iff `1 ≤ bps ≤ 10000`, n ≥ 1, every approval valid, and
/// `k ≥ required`.
#[test]
fn quorum_arithmetic_at_its_boundaries() {
    use sumchain_state::validator_quorum::check_threshold_bps;
    let expected: [u32; 9] = [1, 1, 1, 3, 4, 3, 29_127, 429_497, u32::MAX];
    for ((n, bps), want) in QUORUM_BOUNDARIES.into_iter().zip(expected) {
        assert_eq!(required_approvals(n, bps), want, "n {n}, bps {bps}");
        // Exact: the smallest k with k·10000 ≥ n·bps, computed in u128.
        let exact = ((n as u128) * (bps as u128)).div_ceil(10_000) as u32;
        assert_eq!(want, exact, "n {n}, bps {bps}");
    }
    // No overflow at the type's limits: n·bps + 9999 < 2^46.
    assert!((u32::MAX as u64) * 10_000 + 9_999 < 1u64 << 46);
    // bps outside 1..=10000 is refused before any counting.
    assert!(check_threshold_bps(0).is_err());
    assert!(check_threshold_bps(10_001).is_err());
    assert!(check_threshold_bps(1).is_ok());
    assert!(check_threshold_bps(10_000).is_ok());
}

/// k = required − 1 is refused (`303`, fee charged), k = required accepted, at
/// n = 1 and n = 4, with the governance threshold at 1 and at 10000 bps.
#[test]
fn register_refuses_one_approval_short_and_accepts_exactly_required() {
    for (ids, bps) in [
        (&[1u8][..], 1u16),
        (&[1u8][..], 10_000),
        (&[1u8, 2, 3, 4][..], 1),
        (&[1u8, 2, 3, 4][..], 10_000),
    ] {
        let n = node_with(chain_params(bps), Some(fixture_params()));
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        let active = vset(ids);
        let required = required_approvals(ids.len() as u32, bps) as usize;
        let mut rec = record(1);
        rec.approval_threshold_bps = bps;
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &rec, &ids[..required - 1]), H, &active),
            TxStatus::Failed(303),
            "n {}, bps {bps}, k = required - 1",
            ids.len()
        );
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &rec, &ids[..required]), H, &active),
            TxStatus::Success,
            "n {}, bps {bps}, k = required",
            ids.len()
        );
    }
}

/// The largest set (29,127, VS-6(a)). Three real validators sign; the other
/// entries are distinct synthetic keys that never sign, so they are never
/// parsed. Non-signers stay in the denominator.
#[test]
fn the_largest_validator_set_counts_every_member() {
    let mut active = vset(&[1, 2, 3]);
    for i in 0..29_124u32 {
        let mut k = [0xEE; 32];
        k[28..].copy_from_slice(&i.to_be_bytes());
        active.push(k);
    }
    assert_eq!(active.len(), 29_127);

    // 1 bps: required 3. Two approvals are refused; three are accepted.
    let n = node_with(chain_params(1), Some(fixture_params()));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let mut rec = record(1);
    rec.approval_threshold_bps = 1;
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &rec, &[1, 2]), H, &active),
        TxStatus::Failed(303)
    );
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &rec, &[1, 2, 3]), H, &active),
        TxStatus::Success
    );

    // 10000 bps: required 29,127; three approvals are refused.
    let n = node_with(chain_params(10_000), Some(fixture_params()));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let mut rec = record(2);
    rec.approval_threshold_bps = 10_000;
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &rec, &[1, 2, 3]), H, &active),
        TxStatus::Failed(303)
    );
}

// ── Q9: all-zero commitments ────────────────────────────────────────────────

/// A register whose record has any all-zero commitment is refused: `303`,
/// fee charged and nonce advanced (Policy-B, checked by `Submitter::run`), and
/// no record. `unset_commitments` is also what `registry_dryRunAdmit` reports
/// (`crates/rpc/tests/registry_dry_run_agrees.rs`).
#[test]
fn register_refuses_any_all_zero_commitment() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let four = vset(&[1, 2, 3, 4]);
    let q = [1u8, 2, 3];
    let cases: [(&str, RegistryRecordV1); 4] = [
        ("audit", with(|r| r.audit_commitment = [0; 32])),
        ("source", with(|r| r.source_commitment = [0; 32])),
        ("ceremony", with(|r| r.ceremony_commitment = [0; 32])),
        (
            "all three",
            with(|r| {
                r.audit_commitment = [0; 32];
                r.source_commitment = [0; 32];
                r.ceremony_commitment = [0; 32];
            }),
        ),
    ];
    for (what, rec) in cases {
        assert!(!unset_commitments(&rec).is_empty());
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &rec, &q), H, &four),
            TxStatus::Failed(303),
            "{what}"
        );
        assert_eq!(stored(&mut c, 1), None, "{what}");
    }
    // One non-zero byte is a set commitment.
    let rec = with(|r| {
        r.audit_commitment = [0; 32];
        r.audit_commitment[0] = 1;
    });
    assert_eq!(
        s.run(&n, &mut c, REG, register(H + 50, &rec, &q), H, &four),
        TxStatus::Success
    );
}

/// Q9's underfunded branch: a sender who cannot cover the fee gets `303` with
/// fee 0 (`governance_executor.rs:356-363`). Nothing is charged, the nonce is
/// unchanged, and no record is written.
#[test]
fn an_underfunded_zero_commitment_register_is_303_with_no_fee() {
    let n = node();
    let mut c = candidate(&n.db);
    let poor = KeyPair::from_bytes([0x5B; 32]);
    fund(&n.db, &poor, FEE - 1);
    let proposer = Address::new([0x99; 20]);
    let rec = with(|r| r.audit_commitment = [0; 32]);
    let r = execute_registry_ingress(
        &mut c.view(),
        CHAIN,
        &n.params,
        REG,
        &register(H + 50, &rec, &[1, 2, 3]),
        &poor.address(),
        FEE,
        &proposer,
        H,
        Hash::ZERO,
        &vset(&[1, 2, 3, 4]),
        RegistryIngressContext {
            params: &n.registry,
            genesis_block_hash: n.genesis.as_ref(),
        },
    )
    .unwrap();
    assert_eq!(r.status, TxStatus::Failed(303));
    assert_eq!(r.fee_paid, 0);
    assert_eq!(StateManager::v_get_nonce(&c.view(), &poor.address()).unwrap(), 0);
    assert_eq!(StateManager::v_get_balance(&c.view(), &poor.address()).unwrap(), FEE - 1);
    assert_eq!(StateManager::v_get_balance(&c.view(), &proposer).unwrap(), 0);
    assert_eq!(stored(&mut c, 1), None);
}

// ── Guards: no tooling default, no reachable consumer ───────────────────────

/// Every workspace member's non-test source, as (repo-relative path, text).
///
/// The members are read from the workspace `Cargo.toml`, so a new member is
/// scanned without editing this list. Skipped: `tests/` and `target/`
/// directories, and in Rust files each `#[cfg(test)]` item by its own brace
/// span (not everything after the first one) and `//` comment lines. Shell
/// and Python files (the `scripts` member's) are kept whole.
fn production_code() -> Vec<(String, String)> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(repo.join("Cargo.toml")).unwrap();
    let start = manifest.find("members = [").expect("workspace members");
    let end = start + manifest[start..].find(']').unwrap();
    let members: Vec<&str> = manifest[start..end].split('"').skip(1).step_by(2).collect();
    assert!(members.len() > 20 && members.contains(&"scripts"), "{members:?}");
    let mut files = Vec::new();
    for member in &members {
        member_files(&repo.join(member), &mut files);
    }
    files.sort();
    assert!(files.len() > 100, "the scan found too few files to mean anything");
    files
        .into_iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap();
            let code = if f.extension().is_some_and(|e| e == "rs") {
                without_test_items(&text)
            } else {
                text
            };
            let rel = f.strip_prefix(&repo).unwrap().to_string_lossy().into_owned();
            (rel, code)
        })
        .collect()
}

fn member_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if !path.file_name().is_some_and(|n| n == "target" || n == "tests") {
                member_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs" || e == "sh" || e == "py") {
            out.push(path);
        }
    }
}

/// `src` without its `#[cfg(test)]` items and `//` comment lines. An item
/// is skipped from its first line to the line that closes the braces that
/// line opened (or just that line, for `mod tests;`).
fn without_test_items(src: &str) -> String {
    let is_test_attr = |t: &str| {
        t.starts_with("#[cfg(test)]")
            || t.starts_with("#[cfg(any(test")
            || t.starts_with("#[cfg(all(test")
    };
    let mut out = String::new();
    let mut depth: i64 = 0;
    let mut skip_to: Option<i64> = None;
    let mut pending = false;
    for line in src.lines() {
        let t = line.trim_start();
        let delta = line.matches('{').count() as i64 - line.matches('}').count() as i64;
        if let Some(d) = skip_to {
            depth += delta;
            if depth <= d {
                skip_to = None;
            }
            continue;
        }
        let item = if is_test_attr(t) {
            let rest = t[t.find(']').unwrap() + 1..].trim();
            if rest.is_empty() {
                pending = true;
                continue;
            }
            true
        } else if pending && !(t.is_empty() || t.starts_with("#[") || t.starts_with("//")) {
            pending = false;
            true
        } else {
            false
        };
        if item {
            if delta > 0 {
                skip_to = Some(depth);
            }
            depth += delta;
            continue;
        }
        depth += delta;
        if !pending && !t.starts_with("//") {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Every reference to `name` as a whole identifier: a call, an import or a path.
fn references(code: &str, name: &str) -> usize {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(name)
        .filter(|(i, _)| {
            code[..*i].chars().next_back().is_none_or(|c| !ident(c))
                && code[*i + name.len()..].chars().next().is_none_or(|c| !ident(c))
        })
        .count()
}

#[test]
fn the_test_item_filter_keeps_production_and_drops_only_test_spans() {
    let src = "fn a() {}\n#[cfg(test)]\nmod t {\n    fn hidden() {}\n}\nfn b() {}\n#[cfg(test)]\nfn c() {\n}\nfn d() {}\n// note e\n";
    let kept = without_test_items(src);
    assert_eq!(kept, "fn a() {}\nfn b() {}\nfn d() {}\n");
    assert_eq!(references("x v_check_commit check_commit(y) check_commits", "check_commit"), 1);
}

/// Q3 (owner, 2026-10-22): the record default threshold is a tooling-only
/// default. No production code of any crate names one, and the parameter set
/// is exactly T_min and W (this literal does not compile with a third field).
#[test]
fn no_consensus_path_reads_a_tooling_default() {
    let p = RegistryIngressParams {
        registry_min_timelock_blocks: Some(1),
        registry_max_approval_window: Some(1),
    };
    assert!(p.complete().is_some());
    for (file, code) in production_code() {
        for needle in [
            "record_default",
            "default_approval_threshold",
            "threshold_source",
            "ThresholdSource",
        ] {
            assert!(!code.contains(needle), "{file} names {needle}");
        }
    }
}

/// Q8/Q18 (owner, 2026-10-22): commit-side checks are decided with the first
/// proof consumer (#128), so nothing in production may reach one yet. Every
/// reference to these names (a call, an import, a path) in any workspace
/// member's non-test source is counted. Each occurs only at its definition,
/// plus `check_commit`'s import and single call inside `v_check_commit`. A new
/// reference anywhere fails this test.
#[test]
fn no_production_code_calls_the_commit_check_or_the_registry_entry() {
    let allowed: [(&str, &str, usize); 4] = [
        ("crates/sumchain-wire/src/registry_ingress.rs", "check_commit", 1),
        ("crates/state/src/registry_ingress.rs", "v_check_commit", 1),
        ("crates/state/src/registry_ingress.rs", "check_commit", 2),
        ("crates/state/src/governance_executor.rs", "execute_registry_ingress", 1),
    ];
    for (file, code) in production_code() {
        for name in ["check_commit", "v_check_commit", "execute_registry_ingress"] {
            let want = allowed
                .iter()
                .find(|(f, n, _)| *f == file && *n == name)
                .map_or(0, |(_, _, k)| *k);
            assert_eq!(references(&code, name), want, "{file}: {name}");
        }
    }
}

// ── Signatures: strict for operations 8 and 9 (owner, 2026-10-23) ─────────────

use curve25519_dalek::{EdwardsPoint, Scalar};
use ed25519_dalek::hazmat::ExpandedSecretKey;
use sha2::{Digest, Sha512};

/// The compressed identity point: y = 1, sign bit 0.
const IDENTITY: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};

/// k = SHA-512(R ‖ A ‖ M) mod ℓ, as RFC 8032 and ed25519-dalek compute it.
fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// Validator `i`'s signature on `msg` with R = identity and s = k·a mod ℓ.
/// Then [s]B − [k]A = [k·a]B − [k·a]B = identity = R, so `verify` accepts it.
/// Any key holder can produce one; `verify_strict` refuses it because R is a
/// small-order point. VS-5 checks keys, not R, so this holds for an honest,
/// canonical, prime-order key.
fn identity_r_signature(i: u8, msg: &[u8]) -> [u8; 64] {
    let a = *validator(i).public_key().as_bytes();
    let secret = ExpandedSecretKey::from(&[i; 32]);
    let s = challenge(&IDENTITY, &a, msg) * secret.scalar;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&IDENTITY);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// The identity point's non-canonical encoding: y = p + 1 (EE FF … FF 7F).
const IDENTITY_NONCANONICAL: [u8; 32] = {
    let mut b = [0xFF; 32];
    b[0] = 0xEE;
    b[31] = 0x7F;
    b
};

/// Validator `i`'s signature on `msg` with R = the identity's NON-canonical
/// encoding, and s recomputed over those R bytes: k = H(R' ‖ A ‖ M), s = k·a.
/// The equation holds ([s]B − [k]A is the identity), so only R's encoding is
/// wrong. `verify` refuses it because it compares the canonical encoding of
/// the recomputed point with R's bytes. `verify_strict` refuses it earlier:
/// R' decodes, because the high bit is masked and canonicity is not checked,
/// to the identity, a small-order point.
fn noncanonical_identity_r_signature(i: u8, msg: &[u8]) -> [u8; 64] {
    let a = *validator(i).public_key().as_bytes();
    let secret = ExpandedSecretKey::from(&[i; 32]);
    let s = challenge(&IDENTITY_NONCANONICAL, &a, msg) * secret.scalar;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&IDENTITY_NONCANONICAL);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// A small-order public key (the identity point, which VS-5 would refuse at
/// genesis) and a signature `verify` accepts under it for ANY message:
/// [k]A = identity, so R = [s]B for an arbitrary s.
fn small_order_key_and_signature() -> ([u8; 32], [u8; 64]) {
    let s = Scalar::from_bytes_mod_order([7; 32]);
    let r = EdwardsPoint::mul_base(&s).compress().to_bytes();
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(s.as_bytes());
    (IDENTITY, sig)
}

/// ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
const ELL: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `sig` with S replaced by S + ℓ: the same scalar, non-canonically encoded.
fn with_s_plus_ell(mut sig: [u8; 64]) -> [u8; 64] {
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + ELL[i] as u16 + carry;
        sig[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    sig
}

/// What each rule accepts. `verify_bytes` is governance-v1's `verify`;
/// `verify_bytes_strict` is `verify_strict`, used by operations 8 and 9 only.
#[test]
fn the_two_rules_on_each_distinguishing_signature() {
    use sumchain_crypto::{verify_bytes, verify_bytes_strict};
    let msg = b"c5 strict verification";
    let a = *validator(1).public_key().as_bytes();
    let honest = sign(msg, validator(1).private_key()).to_bytes();
    let identity_r = identity_r_signature(1, msg);
    let (weak_key, weak_sig) = small_order_key_and_signature();
    // Non-canonical R, with s recomputed over the non-canonical bytes, so the
    // equation holds and only the encoding is wrong.
    let noncanon_r = noncanonical_identity_r_signature(1, msg);
    {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::traits::IsIdentity;
        let point_a = CompressedEdwardsY(a).decompress().unwrap();
        let k = challenge(&IDENTITY_NONCANONICAL, &a, msg);
        let s = Scalar::from_canonical_bytes(noncanon_r[32..].try_into().unwrap()).unwrap();
        let recomputed = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-point_a), &s);
        // `verify`'s comparison: the recomputed point's canonical encoding is
        // the identity's, 01 00 … 00, not R's bytes.
        assert!(recomputed.is_identity());
        assert_eq!(recomputed.compress().to_bytes(), IDENTITY);
        assert_ne!(IDENTITY, IDENTITY_NONCANONICAL);
        // `verify_strict`'s earlier check: R decodes to the identity, which is
        // small-order.
        let r = CompressedEdwardsY(IDENTITY_NONCANONICAL).decompress().unwrap();
        assert!(r.is_identity() && r.is_small_order());
    }

    // A small-order R other than the identity: the point of order 2,
    // y = p - 1 (bytes EC FF ... FF 7F). With a prime-order A, [s]B - [k]A is
    // in the prime-order subgroup, so it is never this point.
    let mut order_two_r = honest;
    order_two_r[..32].copy_from_slice(&[0xFF; 32]);
    order_two_r[0] = 0xEC;
    order_two_r[31] = 0x7F;
    // A public key that does not decompress to a curve point.
    let undecodable = (2u8..)
        .map(|y| {
            let mut k = [0u8; 32];
            k[0] = y;
            k
        })
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
        .unwrap();

    // (what, message, signature, key, `verify` accepts, `verify_strict` accepts)
    type Case<'a> = (&'a str, &'a [u8], [u8; 64], [u8; 32], bool, bool);
    let cases: [Case; 8] = [
        ("ordinary signature", msg, honest, a, true, true),
        ("identity R, real key", msg, identity_r, a, true, false),
        ("small-order R other than identity", msg, order_two_r, a, false, false),
        ("small-order public key", b"any message at all", weak_sig, weak_key, true, false),
        ("non-canonical S (S + l)", msg, with_s_plus_ell(honest), a, false, false),
        ("non-canonical R (y = p + 1, s over those bytes)", msg, noncanon_r, a, false, false),
        ("wrong message", b"another message", honest, a, false, false),
        ("undecodable public key", msg, honest, undecodable, false, false),
    ];
    for (what, m, sig, key, v1, strict) in cases {
        assert_eq!(verify_bytes(m, &sig, &key).is_ok(), v1, "verify: {what}");
        assert_eq!(verify_bytes_strict(m, &sig, &key).is_ok(), strict, "verify_strict: {what}");
    }
}

/// Through the dormant registry entry: an approval that only the
/// governance-v1 rule accepts is refused with `303`. The fee is charged when
/// the balance covers it (checked by `Submitter::run`); otherwise it is `303`
/// with fee 0, the nonce unchanged and no state change.
#[test]
fn operations_8_and_9_refuse_approvals_only_the_old_rule_accepts() {
    let n = node();
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let one = vset(&[1]);
    let until = H + 50;
    let rec = record(1);
    let msg = registry_register_signing_bytes(CHAIN, &GENESIS, until, &rec).unwrap();
    let with_sig = |pubkey: [u8; 32], signature: [u8; 64]| {
        RegistryRegisterV1 {
            valid_until: until,
            record: rec.clone(),
            approvals: vec![ValidatorApproval { pubkey, signature }],
        }
        .try_encode()
        .unwrap()
    };
    let a = *validator(1).public_key().as_bytes();
    let honest = sign(&msg, validator(1).private_key()).to_bytes();
    // The identity-R signature from the real, honest key.
    assert_eq!(
        s.run(&n, &mut c, REG, with_sig(a, identity_r_signature(1, &msg)), H, &one),
        TxStatus::Failed(303)
    );
    // A small-order key, outside VS-5, in a test-built active set.
    let (weak_key, weak_sig) = small_order_key_and_signature();
    assert_eq!(
        s.run(&n, &mut c, REG, with_sig(weak_key, weak_sig), H, &[weak_key]),
        TxStatus::Failed(303)
    );
    // The non-canonical identity R, s recomputed over its bytes.
    assert_eq!(
        s.run(&n, &mut c, REG, with_sig(a, noncanonical_identity_r_signature(1, &msg)), H, &one),
        TxStatus::Failed(303)
    );
    // Non-canonical S, and a signature over another message.
    assert_eq!(
        s.run(&n, &mut c, REG, with_sig(a, with_s_plus_ell(honest)), H, &one),
        TxStatus::Failed(303)
    );
    let other = sign(b"not the preimage", validator(1).private_key()).to_bytes();
    assert_eq!(s.run(&n, &mut c, REG, with_sig(a, other), H, &one), TxStatus::Failed(303));
    assert_eq!(stored(&mut c, 1), None);
    // A malformed approval encoding (one byte short) never reaches a
    // signature: `302`, no fee, no nonce (checked by `Submitter::run`).
    let mut short = with_sig(a, honest);
    short.pop();
    assert_eq!(s.run(&n, &mut c, REG, short, H, &one), TxStatus::Failed(302));
    // The honest signature is accepted.
    assert_eq!(s.run(&n, &mut c, REG, with_sig(a, honest), H, &one), TxStatus::Success);

    // Disable is under the same rule.
    let dmsg = registry_disable_signing_bytes(CHAIN, &GENESIS, until, &rec.id);
    let disable_with = |signature: [u8; 64]| {
        RegistryDisableV1 {
            valid_until: until,
            id: rec.id,
            approvals: vec![ValidatorApproval { pubkey: a, signature }],
        }
        .try_encode()
        .unwrap()
    };
    assert_eq!(
        s.run(&n, &mut c, DIS, disable_with(identity_r_signature(1, &dmsg)), H, &one),
        TxStatus::Failed(303)
    );
    assert_eq!(stored(&mut c, 1).unwrap().status, RegistryStatus::Enabled);

    // Underfunded: the same refusal is `303` with fee 0.
    let poor = KeyPair::from_bytes([0x5C; 32]);
    fund(&n.db, &poor, FEE - 1);
    let proposer = Address::new([0x98; 20]);
    let r = execute_registry_ingress(
        &mut c.view(),
        CHAIN,
        &n.params,
        REG,
        &with_sig(a, identity_r_signature(1, &msg)),
        &poor.address(),
        FEE,
        &proposer,
        H,
        Hash::ZERO,
        &one,
        RegistryIngressContext {
            params: &n.registry,
            genesis_block_hash: n.genesis.as_ref(),
        },
    )
    .unwrap();
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(303), 0));
    assert_eq!(StateManager::v_get_nonce(&c.view(), &poor.address()).unwrap(), 0);
    assert_eq!(StateManager::v_get_balance(&c.view(), &poor.address()).unwrap(), FEE - 1);
    assert_eq!(StateManager::v_get_balance(&c.view(), &proposer).unwrap(), 0);
}

/// Existing governance operations keep governance-v1 `verify`: `RegisterAsset`
/// still accepts the identity-R approval that the registry operations refuse.
#[test]
fn existing_governance_operations_keep_the_governance_v1_rule() {
    use sumchain_primitives::governance::{
        GovernanceOperation, GovernanceTxData, RegisterAssetRequest,
    };
    use sumchain_primitives::validator_authority::register_asset_signing_bytes;
    use sumchain_storage::schema::Src20TokenData;
    use sumchain_storage::TokenStore;

    let n = node();
    let token = [0x7A; 32];
    TokenStore::new(&n.db)
        .put_token(
            &token,
            &Src20TokenData {
                name: "Gov".into(),
                symbol: "GOV".into(),
                decimals: 0,
                owner: Address::new([0xC0; 20]),
                total_supply: 1_000,
                max_supply: 1_000,
                mintable: false,
                burnable: false,
                pausable: false,
                paused: false,
                minters: vec![],
                created_at: 0,
                created_at_block: 0,
            },
        )
        .unwrap();
    let mut c = candidate(&n.db);
    let s = Submitter::new(&n.db);
    let msg = register_asset_signing_bytes(CHAIN, &token, 1, 0);
    let a = *validator(1).public_key().as_bytes();
    let signature = identity_r_signature(1, &msg);
    assert!(sumchain_crypto::verify_bytes(&msg, &signature, &a).is_ok());
    assert!(sumchain_crypto::verify_bytes_strict(&msg, &signature, &a).is_err());
    let request = RegisterAssetRequest {
        token_id: token,
        create_threshold: 1,
        effective_height: 0,
        approvals: vec![ValidatorApproval { pubkey: a, signature }],
    };
    let r = sumchain_state::governance_executor::execute(
        &mut c.view(),
        CHAIN,
        &n.params,
        &GovernanceTxData {
            operation: GovernanceOperation::RegisterAsset,
            data: bincode::serialize(&request).unwrap(),
        },
        &s.kp.address(),
        0,
        FEE,
        &Address::new([0x99; 20]),
        H,
        1_000,
        Hash::ZERO,
        &vset(&[1]),
    )
    .unwrap();
    assert_eq!(r.status, TxStatus::Success, "governance-v1 verify, unchanged");
}

// ── Parameters: paired presence, range, overflow (owner, 2026-10-23) ─────────

/// A partial or out-of-range parameter set is unready: `302`, no fee, exactly
/// like an unset one.
#[test]
fn invalid_parameter_sets_refuse_free() {
    let top = u32::MAX as u64;
    for params in [
        RegistryIngressParams { registry_min_timelock_blocks: Some(0), ..fixture_params() },
        RegistryIngressParams { registry_max_approval_window: Some(0), ..fixture_params() },
        RegistryIngressParams { registry_min_timelock_blocks: Some(top + 1), ..fixture_params() },
        RegistryIngressParams { registry_max_approval_window: Some(top + 1), ..fixture_params() },
    ] {
        let n = node_with(chain_params(GOV_BPS), Some(params));
        let mut c = candidate(&n.db);
        let mut s = Submitter::new(&n.db);
        assert_eq!(
            s.run(&n, &mut c, REG, register(H + 50, &record(1), &[1]), H, &vset(&[1])),
            TxStatus::Failed(302),
            "{params:?}"
        );
    }
}

/// With T_min at its maximum, `h + T_min` passes `u64::MAX` near the end of
/// the height range. No activation height can satisfy the timelock, so the
/// register is refused: `303`, fee charged, no state change.
#[test]
fn a_timelock_past_u64_max_refuses_with_303() {
    let top = u32::MAX as u64;
    let params = RegistryIngressParams {
        registry_min_timelock_blocks: Some(top),
        registry_max_approval_window: Some(top),
    };
    let n = node_with(chain_params(GOV_BPS), Some(params));
    let mut c = candidate(&n.db);
    let mut s = Submitter::new(&n.db);
    let h = u64::MAX - 10;
    let mut rec = record(1);
    rec.activation_height = u64::MAX;
    assert_eq!(
        s.run(&n, &mut c, REG, register(u64::MAX, &rec, &[1]), h, &vset(&[1])),
        TxStatus::Failed(303)
    );
    assert_eq!(stored(&mut c, 1), None);
    // The largest timelock that still fits is accepted at its boundary.
    let h = u64::MAX - top;
    assert_eq!(
        s.run(&n, &mut c, REG, register(u64::MAX, &rec, &[1]), h, &vset(&[1])),
        TxStatus::Success
    );
}

// ── B2: a record keeps the threshold accepted at its registration ────────────

/// Disable requires the stored record's threshold, which register made ≥ the
/// governance threshold of its time. A later change to the governance
/// threshold does not touch existing records: after an increase, an older
/// record is still disabled at its lower stored threshold. New registrations
/// meet the new floor.
#[test]
fn a_governance_threshold_change_does_not_move_an_existing_record() {
    let n = node();
    let mut c = candidate(&n.db);
    let s = Submitter::new(&n.db);
    let two = vset(&[1, 2]);
    let proposer = Address::new([0x99; 20]);
    let ctx = RegistryIngressContext {
        params: &n.registry,
        genesis_block_hash: n.genesis.as_ref(),
    };
    let run = |c: &mut CandidateExecution<'_>, gov_bps: u16, op, data: Vec<u8>| {
        execute_registry_ingress(
            &mut c.view(),
            CHAIN,
            &chain_params(gov_bps),
            op,
            &data,
            &s.kp.address(),
            FEE,
            &proposer,
            H,
            Hash::ZERO,
            &two,
            ctx,
        )
        .unwrap()
        .status
    };
    // Registered while governance required 5000 bps (1 of 2).
    let mut rec = record(1);
    rec.approval_threshold_bps = 5_000;
    assert_eq!(run(&mut c, 5_000, REG, register(H + 50, &rec, &[1])), TxStatus::Success);
    // Governance rises to 10000 bps (2 of 2). A new record must meet it.
    let mut newer = record(2);
    newer.approval_threshold_bps = 5_000;
    assert_eq!(
        run(&mut c, 10_000, REG, register(H + 50, &newer, &[1, 2])),
        TxStatus::Failed(303),
        "the floor is the governance threshold at registration"
    );
    // The older record is still disabled at its stored 5000 bps: 1 of 2.
    assert_eq!(run(&mut c, 10_000, DIS, disable(H + 50, 1, &[1])), TxStatus::Success);
    assert_eq!(stored(&mut c, 1).unwrap().status, RegistryStatus::Disabled);
}
