//! Issue #61 — OmniNode Inference Settlement v1 integration tests.
//!
//! Covers the activation gate (350, no fee), escrow lifecycle (open/fund/claim/
//! refund), claim maturity + attestation reference, dispute record/withhold/deny
//! (never slash), refund gating, that attestation records are never mutated, and
//! restart persistence of the new CFs.

mod common;
use common::{build_signed_attestation_tx, fund, params_omninode_enabled, sample_digest,
    setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::inference_attestation::InferenceAttestationDigest;
use sumchain_primitives::inference_settlement::*;
use sumchain_primitives::{
    Address, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::inference_settlement_executor::InferenceSettlementExecutor;
use sumchain_storage::Database;

const FEE: u128 = 1_000;
const REWARD: u128 = 1_000_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// omninode + settlement enabled; `resolver` configured as the neutral dispute
/// resolver.
/// finality_depth pinned to 3 so maturity math is deterministic in tests:
/// maturity = attestation.included_at_height + 3 + dispute_window_blocks.
const FINALITY: u64 = 3;

fn params_enabled(dispute_bps: Option<u16>) -> ChainParams {
    let mut p = params_omninode_enabled();
    p.finality_depth = FINALITY;
    p.inference_settlement_enabled_from_height = Some(0);
    p.inference_settlement_dispute_threshold_bps = dispute_bps;
    p
}

/// Validator approval over the resolve-dispute signing bytes.
fn resolve_approval(v: &KeyPair, session: &str, verifier: &Address, allow: bool) -> sumchain_primitives::ValidatorApproval {
    let msg = sumchain_primitives::validator_authority::resolve_dispute_signing_bytes(
        CHAIN_ID, session, verifier, allow,
    );
    sumchain_primitives::ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(&msg, v.private_key()).to_bytes(),
    }
}

fn settlement_tx(
    kp: &KeyPair,
    nonce: u64,
    op: InferenceSettlementOperation,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::InferenceSettlement(InferenceSettlementTxData { operation: op }),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn open_op(session: &str, max_verifiers: u32, deposit: u128, dispute_window: u64, expires: u64) -> InferenceSettlementOperation {
    InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
        session_id: session.to_string(),
        reward_per_verifier: REWARD,
        max_verifiers,
        dispute_window_blocks: dispute_window,
        expires_at_height: expires,
        deposit,
        consistency: None,
    })
}

/// Like `open_op` but opts into a consistency/plurality rule (issue #77).
fn open_op_consistency(
    session: &str,
    max_verifiers: u32,
    deposit: u128,
    dispute_window: u64,
    expires: u64,
    min_matching: u32,
    threshold_bps: u16,
) -> InferenceSettlementOperation {
    InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
        session_id: session.to_string(),
        reward_per_verifier: REWARD,
        max_verifiers,
        dispute_window_blocks: dispute_window,
        expires_at_height: expires,
        deposit,
        consistency: Some(InferenceConsistencyConfig { min_matching_verifiers: min_matching, threshold_bps }),
    })
}

/// Register an attestation carrying a fully custom digest tuple for
/// (session, verifier) at `height`. Lets a test craft split groups and
/// response_hash-only-matches. `tuple` = (model_hash, manifest_root,
/// response_hash, proof_root) fill bytes.
fn attest_digest(
    executor: &sumchain_state::executor::BlockExecutor,
    proposer: &Address,
    verifier: &KeyPair,
    session: &str,
    height: u64,
    nonce: u64,
    tuple: (u8, u8, u8, u8),
) {
    let digest = InferenceAttestationDigest {
        session_id: session.to_string(),
        model_hash: [tuple.0; 32],
        manifest_root: [tuple.1; 32],
        response_hash: [tuple.2; 32],
        proof_root: [tuple.3; 32],
    };
    let tx = build_signed_attestation_tx(verifier, nonce, FEE, digest, false);
    let r = executor.execute_tx(&tx, proposer, height, 1000).unwrap();
    assert!(r.status.is_success(), "attestation failed: {:?}", r.status);
}

/// Self-claim op for `session`.
fn claim_op(session: &str) -> InferenceSettlementOperation {
    InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: session.to_string() })
}

fn sexec(db: &Arc<Database>) -> InferenceSettlementExecutor {
    InferenceSettlementExecutor::new(db.clone())
}

// ── Gate ─────────────────────────────────────────────────────────────────────

#[test]
fn defaults_leave_settlement_dormant() {
    let p = ChainParams::default();
    assert_eq!(p.inference_settlement_enabled_from_height, None);
    assert_eq!(p.inference_settlement_dispute_threshold_bps, None);
}

#[test]
fn gate_closed_open_session_rejects_350_no_mutation() {
    // omninode on, settlement dormant.
    let mut p = params_omninode_enabled();
    p.inference_settlement_enabled_from_height = None;
    let (state, db, _dir, executor) = setup_with_params(p);
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    let bal = state.get_balance(&funder.address()).unwrap();

    let res = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(350)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    assert_eq!(state.get_balance(&funder.address()).unwrap(), bal);
    assert!(sexec(&db).get_session("s").unwrap().is_none());
}

// ── Open / fund escrow ───────────────────────────────────────────────────────

#[test]
fn open_session_deducts_escrow_and_duplicate_rejected() {
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);

    let r = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(r.status.is_success(), "got {:?}", r.status);
    // funder debited deposit + fee.
    assert_eq!(state.get_balance(&funder.address()).unwrap(), 10_000_000 - 2 * REWARD - FEE);
    let s = sexec(&db).get_session("s").unwrap().unwrap();
    assert_eq!(s.funder, funder.address());
    assert_eq!(s.remaining_escrow, 2 * REWARD);
    assert_eq!(s.status, InferenceSessionStatus::Open);

    // duplicate → 352.
    let dup = executor
        .execute_tx(&settlement_tx(&funder, 1, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 2, 1000)
        .unwrap();
    assert!(matches!(dup.status, TxStatus::Failed(352)), "got {:?}", dup.status);
}

#[test]
fn open_session_invalid_terms_354() {
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);

    // reward=0 via a hand-built op (open_op uses REWARD; build a zero-reward op).
    let zero = InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
        session_id: "z".to_string(),
        reward_per_verifier: 0,
        max_verifiers: 1,
        dispute_window_blocks: 10,
        expires_at_height: 1000,
        deposit: 0,
        consistency: None,
    });
    let r = executor.execute_tx(&settlement_tx(&funder, 0, zero), &proposer.address(), 1, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(354)), "got {:?}", r.status);

    // expires in the past.
    let past = open_op("p", 2, 2 * REWARD, 10, 1);
    let r2 = executor.execute_tx(&settlement_tx(&funder, 1, past), &proposer.address(), 5, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(354)), "got {:?}", r2.status);
}

#[test]
fn open_session_deposit_bounds_355() {
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    // deposit below one reward → 355.
    let low = open_op("s", 2, REWARD - 1, 10, 1000);
    let r = executor.execute_tx(&settlement_tx(&funder, 0, low), &proposer.address(), 1, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(355)), "got {:?}", r.status);
    // deposit above cap → 355.
    let high = open_op("s2", 2, 3 * REWARD, 10, 1000);
    let r2 = executor.execute_tx(&settlement_tx(&funder, 1, high), &proposer.address(), 1, 1000).unwrap();
    assert!(matches!(r2.status, TxStatus::Failed(355)), "got {:?}", r2.status);
}

// ── Claim lifecycle ──────────────────────────────────────────────────────────

/// Register an attestation for (session, verifier) at `height` with `nonce`.
fn attest(executor: &sumchain_state::executor::BlockExecutor, proposer: &Address, verifier: &KeyPair, session: &str, height: u64, nonce: u64) {
    let tx = build_signed_attestation_tx(verifier, nonce, FEE, sample_digest(session), false);
    let r = executor.execute_tx(&tx, proposer, height, 1000).unwrap();
    assert!(r.status.is_success(), "attestation failed: {:?}", r.status);
}

#[test]
fn claim_requires_attestation_then_pays_after_maturity() {
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);

    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000).unwrap();

    // No attestation yet → 356.
    let no_att = executor
        .execute_tx(&settlement_tx(&verifier, 0, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 2, 1000)
        .unwrap();
    assert!(matches!(no_att.status, TxStatus::Failed(356)), "got {:?}", no_att.status);

    // Attest at height 5 → maturity = 15. (verifier nonce 1 — the failed claim above bumped it.)
    attest(&executor, &proposer.address(), &verifier, "s", 5, 1);

    // Claim before maturity (height 10) → 357.
    let early = executor
        .execute_tx(&settlement_tx(&verifier, 2, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 10, 1000)
        .unwrap();
    assert!(matches!(early.status, TxStatus::Failed(357)), "got {:?}", early.status);

    // Claim at maturity (height 20) → paid.
    let vbal = state.get_balance(&verifier.address()).unwrap();
    let paid = executor
        .execute_tx(&settlement_tx(&verifier, 3, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 20, 1000)
        .unwrap();
    assert!(paid.status.is_success(), "got {:?}", paid.status);
    assert_eq!(state.get_balance(&verifier.address()).unwrap(), vbal - FEE + REWARD);
    let s = sexec(&db).get_session("s").unwrap().unwrap();
    assert_eq!(s.remaining_escrow, REWARD);
    assert_eq!(s.claims_count, 1);
    assert!(sexec(&db).get_claim("s", &verifier.address()).unwrap().is_some());

    // Duplicate claim → 358.
    let dup = executor
        .execute_tx(&settlement_tx(&verifier, 4, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 21, 1000)
        .unwrap();
    assert!(matches!(dup.status, TxStatus::Failed(358)), "got {:?}", dup.status);
}

#[test]
fn claim_maturity_requires_finality_and_dispute_window() {
    // Attest at height 5, dispute_window 10, finality 3 → maturity = 5+3+10 = 18.
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0);

    let claim = |nonce: u64, height: u64| {
        executor
            .execute_tx(&settlement_tx(&verifier, nonce, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), height, 1000)
            .unwrap()
            .status
    };
    // Not finalized yet (height 7 < 5+3=8) → 357.
    assert!(matches!(claim(1, 7), TxStatus::Failed(357)), "not finalized");
    // Finalized but dispute window not elapsed (8 <= 10 < 18) → 357.
    assert!(matches!(claim(2, 10), TxStatus::Failed(357)), "window not elapsed");
    // Finalized + dispute window elapsed (height 18) → success.
    assert!(claim(3, 18).is_success(), "should be mature at 18");
}

#[test]
fn fund_top_up_increases_escrow() {
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 3, REWARD, 10, 1000)), &proposer.address(), 1, 1000).unwrap();
    let r = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::FundSession(FundInferenceSessionRequest { session_id: "s".into(), amount: 2 * REWARD })), &proposer.address(), 2, 1000)
        .unwrap();
    assert!(r.status.is_success(), "got {:?}", r.status);
    assert_eq!(sexec(&db).get_session("s").unwrap().unwrap().remaining_escrow, 3 * REWARD);
}

// ── Refund ───────────────────────────────────────────────────────────────────

#[test]
fn refund_after_expiry_credits_funder() {
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 100)), &proposer.address(), 1, 1000).unwrap();

    // Before expiry (height 50 < 100), not fully claimed → 360.
    let early = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 50, 1000)
        .unwrap();
    assert!(matches!(early.status, TxStatus::Failed(360)), "got {:?}", early.status);

    // After expiry (height 101) → refund.
    let bal = state.get_balance(&funder.address()).unwrap();
    let r = executor
        .execute_tx(&settlement_tx(&funder, 2, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 101, 1000)
        .unwrap();
    assert!(r.status.is_success(), "got {:?}", r.status);
    assert_eq!(state.get_balance(&funder.address()).unwrap(), bal - FEE + 2 * REWARD);
    let s = sexec(&db).get_session("s").unwrap().unwrap();
    assert_eq!(s.status, InferenceSessionStatus::Refunded);
    assert_eq!(s.remaining_escrow, 0);
}

#[test]
fn open_session_too_early_expiry_rejected_354() {
    // dispute_window 10, finality 3, created height 1 → min expiry = 14.
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    // expires 13 < 14 → 354.
    let r = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 13)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(354)), "got {:?}", r.status);
    // expires 14 == min → accepted.
    let ok = executor
        .execute_tx(&settlement_tx(&funder, 1, open_op("s2", 2, 2 * REWARD, 10, 14)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(ok.status.is_success(), "got {:?}", ok.status);
}

#[test]
fn refund_blocked_while_attestation_within_maturity_then_succeeds() {
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    // Open at height 1: dispute_window 10, expires 20 (>= min 14).
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 20)), &proposer.address(), 1, 1000).unwrap();
    // A LATE attestation at height 18 → maturity = 18+3+10 = 31, past expiry (20).
    attest(&executor, &proposer.address(), &verifier, "s", 18, 0);

    // Refund at height 21 (>= expiry) is blocked: verifier still within maturity, unclaimed → 360.
    let blocked = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 21, 1000)
        .unwrap();
    assert!(matches!(blocked.status, TxStatus::Failed(360)), "got {:?}", blocked.status);

    // After maturity (height 32), unclaimed + no dispute → refund succeeds.
    let ok = executor
        .execute_tx(&settlement_tx(&funder, 2, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 32, 1000)
        .unwrap();
    assert!(ok.status.is_success(), "got {:?}", ok.status);
    assert_eq!(sexec(&db).get_session("s").unwrap().unwrap().remaining_escrow, 0);
}

// ── Fee accounting ───────────────────────────────────────────────────────────

#[test]
fn gate_closed_failure_charges_no_fee_no_nonce_no_proposer() {
    let mut p = params_omninode_enabled();
    p.inference_settlement_enabled_from_height = None;
    let (state, _db, _dir, executor) = setup_with_params(p);
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    let bal = state.get_balance(&funder.address()).unwrap();
    let nonce = state.get_nonce(&funder.address()).unwrap();

    let res = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(350)));
    assert_eq!(res.fee_paid, 0);
    assert_eq!(state.get_balance(&funder.address()).unwrap(), bal, "no fee charged");
    assert_eq!(state.get_nonce(&funder.address()).unwrap(), nonce, "no nonce bump");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), 0, "proposer not credited");
}

#[test]
fn gate_open_semantic_failure_charges_fee_and_reports_it() {
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    // Open once (success).
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000).unwrap();
    let bal = state.get_balance(&funder.address()).unwrap();
    let nonce = state.get_nonce(&funder.address()).unwrap();
    let prop_before = state.get_balance(&proposer.address()).unwrap();

    // Duplicate open (semantic failure 352) — fee is charged and reported.
    let dup = executor
        .execute_tx(&settlement_tx(&funder, 1, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 2, 1000)
        .unwrap();
    assert!(matches!(dup.status, TxStatus::Failed(352)), "got {:?}", dup.status);
    assert_eq!(dup.fee_paid, FEE, "receipt fee_paid == fee");
    assert_eq!(state.get_balance(&funder.address()).unwrap(), bal - FEE, "sender debited fee");
    assert_eq!(state.get_nonce(&funder.address()).unwrap(), nonce + 1, "nonce incremented");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), prop_before + FEE, "proposer credited");
}

// ── Disputes ─────────────────────────────────────────────────────────────────

#[test]
fn disputes_disabled_without_resolver_353() {
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(None)); // no resolver
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 50, 1000)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0);

    let r = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), evidence_commitment: [9u8; 32] })), &proposer.address(), 8, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(353)), "got {:?}", r.status);
}

#[test]
fn dispute_deny_blocks_claim_and_allows_refund() {
    let resolver = KeyPair::generate();
    let (state, db, _dir, executor) = setup_with_params(params_enabled(Some(5_000)));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    fund(&state, &resolver, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 50, 100)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0); // maturity = 55

    // Funder opens dispute during window (height 8).
    let od = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), evidence_commitment: [9u8; 32] })), &proposer.address(), 8, 1000)
        .unwrap();
    assert!(od.status.is_success(), "open dispute: {:?}", od.status);

    // Refund blocked while dispute unresolved (height 101 >= expiry) → 359.
    let rblocked = executor
        .execute_tx(&settlement_tx(&funder, 2, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 101, 1000)
        .unwrap();
    assert!(matches!(rblocked.status, TxStatus::Failed(359)), "got {:?}", rblocked.status);

    // Validator quorum denies the claim (height 9). `resolver` is the single
    // active validator; the submitter carries its approval.
    let vset = [*resolver.public_key().as_bytes()];
    let ap = resolve_approval(&resolver, "s", &verifier.address(), false);
    let rd = executor
        .execute_tx_with_validators(&settlement_tx(&resolver, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: false, approvals: vec![ap] })), &proposer.address(), 9, 1000, &vset)
        .unwrap();
    assert!(rd.status.is_success(), "resolve: {:?}", rd.status);

    // Verifier claim after maturity is denied → 359.
    let claim = executor
        .execute_tx(&settlement_tx(&verifier, 1, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 60, 1000)
        .unwrap();
    assert!(matches!(claim.status, TxStatus::Failed(359)), "got {:?}", claim.status);

    // Now refund succeeds (dispute resolved, expired).
    let refund = executor
        .execute_tx(&settlement_tx(&funder, 3, InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest { session_id: "s".into() })), &proposer.address(), 102, 1000)
        .unwrap();
    assert!(refund.status.is_success(), "refund: {:?}", refund.status);
    assert_eq!(sexec(&db).get_session("s").unwrap().unwrap().remaining_escrow, 0);
}

#[test]
fn dispute_allow_lets_claim_proceed() {
    let resolver = KeyPair::generate();
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(Some(5_000)));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    fund(&state, &resolver, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 50, 1000)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0); // maturity = 55

    executor.execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), evidence_commitment: [9u8; 32] })), &proposer.address(), 8, 1000).unwrap();
    // validator quorum allows.
    let vset = [*resolver.public_key().as_bytes()];
    let ap = resolve_approval(&resolver, "s", &verifier.address(), true);
    executor.execute_tx_with_validators(&settlement_tx(&resolver, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: true, approvals: vec![ap] })), &proposer.address(), 9, 1000, &vset).unwrap();
    // claim proceeds after maturity.
    let vbal = state.get_balance(&verifier.address()).unwrap();
    let claim = executor
        .execute_tx(&settlement_tx(&verifier, 1, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 60, 1000)
        .unwrap();
    assert!(claim.status.is_success(), "got {:?}", claim.status);
    assert_eq!(state.get_balance(&verifier.address()).unwrap(), vbal - FEE + REWARD);
}

#[test]
fn resolve_requires_validator_quorum_353() {
    let validator = KeyPair::generate();
    let vset = [*validator.public_key().as_bytes()];
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(Some(5_000)));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let stranger = KeyPair::generate();
    let proposer = KeyPair::generate();
    for kp in [&funder, &verifier, &stranger] {
        fund(&state, kp, 10_000_000);
    }
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 50, 1000)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0);
    executor.execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), evidence_commitment: [9u8; 32] })), &proposer.address(), 8, 1000).unwrap();

    // A non-validator's approval does not count → quorum unmet → 353. Submitter
    // (stranger) is irrelevant; the approval is from a non-validator.
    let bad = resolve_approval(&stranger, "s", &verifier.address(), true);
    let r = executor
        .execute_tx_with_validators(&settlement_tx(&stranger, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: true, approvals: vec![bad] })), &proposer.address(), 9, 1000, &vset)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(353)), "non-validator approval: {:?}", r.status);

    // A valid validator quorum (submitted by a non-validator) → success.
    let ap = resolve_approval(&validator, "s", &verifier.address(), true);
    let r = executor
        .execute_tx_with_validators(&settlement_tx(&stranger, 1, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: true, approvals: vec![ap] })), &proposer.address(), 9, 1000, &vset)
        .unwrap();
    assert!(r.status.is_success(), "valid quorum by non-validator submitter: {:?}", r.status);
}

// ── Attestation immutability + restart ───────────────────────────────────────

#[test]
fn settlement_never_mutates_attestation_record() {
    use sumchain_primitives::inference_attestation::inference_attestation_key;
    let (state, db, _dir, executor) = setup_with_params(params_enabled(None));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);

    attest(&executor, &proposer.address(), &verifier, "s", 5, 0);
    let aexec = sumchain_state::inference_attestation_executor::InferenceAttestationExecutor::new(db.clone());
    let before = aexec.get(&inference_attestation_key("s", &verifier.address())).unwrap().unwrap();

    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 6, 1000).unwrap();
    executor.execute_tx(&settlement_tx(&verifier, 1, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 20, 1000).unwrap();

    let after = aexec.get(&inference_attestation_key("s", &verifier.address())).unwrap().unwrap();
    assert_eq!(before, after, "settlement must not mutate the attestation record");
}

#[test]
fn settlement_state_survives_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(sumchain_state::StateManager::new(db.clone(), CHAIN_ID));
        let executor = sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params_enabled(None));
        fund(&state, &funder, 10_000_000);
        executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 10, 1000)), &proposer.address(), 1, 1000).unwrap();
    }
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let s = InferenceSettlementExecutor::new(db.clone()).get_session("s").unwrap();
    assert!(s.is_some(), "session persisted across restart");
    assert_eq!(s.unwrap().remaining_escrow, 2 * REWARD);
}

// ── Consistency / plurality mode (issue #77) ─────────────────────────────────

/// settlement enabled + consistency gate open; `dispute_bps` optional. Dispute
/// window defaults to 0 in most consistency tests so maturity = included + FINALITY.
fn params_consistency(dispute_bps: Option<u16>) -> ChainParams {
    let mut p = params_enabled(dispute_bps);
    p.inference_settlement_consistency_enabled_from_height = Some(0);
    p
}

/// Submit a `ClaimReward` for `session` and return the resulting status.
fn claim_status(
    executor: &sumchain_state::executor::BlockExecutor,
    proposer: &Address,
    verifier: &KeyPair,
    session: &str,
    nonce: u64,
    height: u64,
) -> TxStatus {
    executor
        .execute_tx(&settlement_tx(verifier, nonce, claim_op(session)), proposer, height, 1000)
        .unwrap()
        .status
}

#[test]
fn consistency_gate_closed_open_rejects_361_no_session() {
    // Settlement enabled, consistency gate CLOSED. A session that requests a
    // consistency config is rejected 361 (fee-paid semantic failure) with no
    // session written.
    let mut p = params_enabled(None);
    p.inference_settlement_consistency_enabled_from_height = None;
    let (state, db, _dir, executor) = setup_with_params(p);
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);

    let r = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op_consistency("s", 3, 3 * REWARD, 0, 1000, 2, 0)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(361)), "got {:?}", r.status);
    assert_eq!(r.fee_paid, FEE, "consistency-gate-closed is a gate-open semantic failure; fee paid");
    assert!(sexec(&db).get_session("s").unwrap().is_none(), "no session written");

    // A session WITHOUT consistency still opens fine while the consistency gate is closed.
    let ok = executor
        .execute_tx(&settlement_tx(&funder, 1, open_op("s2", 2, 2 * REWARD, 0, 1000)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(ok.status.is_success(), "v1 session unaffected by consistency gate: {:?}", ok.status);
}

#[test]
fn consistency_invalid_config_363() {
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    // min_matching_verifiers = 0 → 363.
    let zero = executor
        .execute_tx(&settlement_tx(&funder, 0, open_op_consistency("a", 3, 3 * REWARD, 0, 1000, 0, 0)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(zero.status, TxStatus::Failed(363)), "min=0: {:?}", zero.status);
    // min > max_verifiers → 363.
    let too_big = executor
        .execute_tx(&settlement_tx(&funder, 1, open_op_consistency("b", 3, 3 * REWARD, 0, 1000, 4, 0)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(too_big.status, TxStatus::Failed(363)), "min>max: {:?}", too_big.status);
    // threshold_bps > 10000 → 363.
    let bad_bps = executor
        .execute_tx(&settlement_tx(&funder, 2, open_op_consistency("c", 3, 3 * REWARD, 0, 1000, 2, 10_001)), &proposer.address(), 1, 1000)
        .unwrap();
    assert!(matches!(bad_bps.status, TxStatus::Failed(363)), "bps>10000: {:?}", bad_bps.status);
}

#[test]
fn consistency_full_tuple_match_passes() {
    // Three verifiers attest the SAME full tuple; min=3 → the claim qualifies.
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let (v1, v2, v3) = (KeyPair::generate(), KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1, &v2, &v3] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();

    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("s", 3, 3 * REWARD, 0, 1000, 3, 0)), &p, 1, 1000).unwrap();
    let tuple = (1, 2, 3, 4);
    attest_digest(&executor, &p, &v1, "s", 5, 0, tuple);
    attest_digest(&executor, &p, &v2, "s", 5, 0, tuple);
    attest_digest(&executor, &p, &v3, "s", 5, 0, tuple);

    // maturity = 5 + FINALITY(3) + window(0) = 8; peers finalized at 8.
    assert!(claim_status(&executor, &p, &v1, "s", 1, 8).is_success(), "3/3 matching should pass");
}

#[test]
fn consistency_response_hash_only_match_is_not_enough() {
    // Peer shares response_hash but differs in model/manifest/proof — it must NOT
    // count. Claimant's exact-tuple group is only itself → min=2 fails 362.
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let (v1, v2) = (KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1, &v2] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();

    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("s", 3, 3 * REWARD, 0, 1000, 2, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "s", 5, 0, (1, 2, 3, 4));
    // Same response_hash (3), everything else different.
    attest_digest(&executor, &p, &v2, "s", 5, 0, (9, 8, 3, 7));

    assert!(matches!(claim_status(&executor, &p, &v1, "s", 1, 8), TxStatus::Failed(362)),
        "response_hash-only agreement must not satisfy consistency");
}

#[test]
fn consistency_split_groups_fail_under_min_pass_at_min() {
    // Two groups of two. min=3 → neither group qualifies; min=2 → each group's
    // members qualify within their own group.
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let (a1, a2, b1, b2) = (KeyPair::generate(), KeyPair::generate(), KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &a1, &a2, &b1, &b2] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();
    let (ta, tb) = ((1, 1, 1, 1), (2, 2, 2, 2));

    // Nonces are per-account (global), not per-session — track them as verifiers
    // are reused across the two sessions below.
    // Session with min=3.
    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("sf", 4, 4 * REWARD, 0, 1000, 3, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &a1, "sf", 5, 0, ta); // a1 nonce 0
    attest_digest(&executor, &p, &a2, "sf", 5, 0, ta); // a2 nonce 0
    attest_digest(&executor, &p, &b1, "sf", 5, 0, tb); // b1 nonce 0
    attest_digest(&executor, &p, &b2, "sf", 5, 0, tb); // b2 nonce 0
    assert!(matches!(claim_status(&executor, &p, &a1, "sf", 1, 8), TxStatus::Failed(362)), "group A size 2 < min 3"); // a1 nonce 1

    // Session with min=2 (attestations are keyed per session; a1 is now at nonce 2).
    executor.execute_tx(&settlement_tx(&funder, 1, open_op_consistency("sp", 4, 4 * REWARD, 0, 1000, 2, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &a1, "sp", 5, 2, ta); // a1 nonce 2
    attest_digest(&executor, &p, &a2, "sp", 5, 1, ta); // a2 nonce 1
    attest_digest(&executor, &p, &b1, "sp", 5, 1, tb); // b1 nonce 1
    attest_digest(&executor, &p, &b2, "sp", 5, 1, tb); // b2 nonce 1
    assert!(claim_status(&executor, &p, &a1, "sp", 3, 8).is_success(), "group A size 2 >= min 2"); // a1 nonce 3
}

#[test]
fn consistency_threshold_bps_denominator_is_max_verifiers() {
    // Two matching verifiers, max_verifiers = 4. threshold 6000 needs
    // matching*10000 >= 4*6000 = 24000 → 2 fails (20000 < 24000). If the
    // denominator were the LIVE attestation count (2), 2/2 = 100% would pass —
    // so this failure proves the denominator is the fixed max_verifiers.
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let (v1, v2) = (KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1, &v2] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();
    let tuple = (1, 2, 3, 4);

    // 6000 bps over max_verifiers 4 → 2 matching is insufficient. (per-account nonces)
    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("hi", 4, 4 * REWARD, 0, 1000, 1, 6000)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "hi", 5, 0, tuple); // v1 nonce 0
    attest_digest(&executor, &p, &v2, "hi", 5, 0, tuple); // v2 nonce 0
    assert!(matches!(claim_status(&executor, &p, &v1, "hi", 1, 8), TxStatus::Failed(362)), "2/4 = 50% < 60%"); // v1 nonce 1

    // 5000 bps over max_verifiers 4 → 2 matching (20000 >= 20000) passes.
    executor.execute_tx(&settlement_tx(&funder, 1, open_op_consistency("lo", 4, 4 * REWARD, 0, 1000, 1, 5000)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "lo", 5, 2, tuple); // v1 nonce 2
    attest_digest(&executor, &p, &v2, "lo", 5, 1, tuple); // v2 nonce 1
    assert!(claim_status(&executor, &p, &v1, "lo", 3, 8).is_success(), "2/4 = 50% >= 50%"); // v1 nonce 3
}

#[test]
fn consistency_single_verifier_min1_passes_min2_fails() {
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let v1 = KeyPair::generate();
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();
    let tuple = (1, 2, 3, 4);

    // min=1 → lone verifier qualifies. (per-account nonces tracked across sessions)
    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("one", 2, 2 * REWARD, 0, 1000, 1, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "one", 5, 0, tuple); // v1 nonce 0
    assert!(claim_status(&executor, &p, &v1, "one", 1, 8).is_success(), "min=1 lone verifier passes"); // v1 nonce 1

    // min=2 → lone verifier blocked.
    executor.execute_tx(&settlement_tx(&funder, 1, open_op_consistency("two", 2, 2 * REWARD, 0, 1000, 2, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "two", 5, 2, tuple); // v1 nonce 2
    assert!(matches!(claim_status(&executor, &p, &v1, "two", 3, 8), TxStatus::Failed(362)), "min=2 lone verifier fails"); // v1 nonce 3
}

#[test]
fn consistency_unfinalized_peer_excluded_then_counts() {
    // A matching peer that is not yet finalized at claim height must not count,
    // then counts once it finalizes.
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let (v1, v2) = (KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1, &v2] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();
    let tuple = (1, 2, 3, 4);

    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("s", 2, 2 * REWARD, 0, 1000, 2, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "s", 5, 0, tuple); // v1 finalized at 8, mature at 8
    attest_digest(&executor, &p, &v2, "s", 7, 0, tuple); // v2 finalized at 10

    // At height 8: v2 not finalized (10 > 8) → group = {v1} = 1 < 2 → 362.
    assert!(matches!(claim_status(&executor, &p, &v1, "s", 1, 8), TxStatus::Failed(362)), "unfinalized peer excluded");
    // At height 10: v2 finalized → group = 2 → success.
    assert!(claim_status(&executor, &p, &v1, "s", 2, 10).is_success(), "peer counts once finalized");
}

#[test]
fn consistency_open_disputed_peer_excluded() {
    // A matching peer under an OPEN dispute lends no consistency weight.
    let resolver = KeyPair::generate();
    let (state, _db, _dir, executor) = setup_with_params(params_consistency(Some(5_000)));
    let funder = KeyPair::generate();
    let (v1, v2) = (KeyPair::generate(), KeyPair::generate());
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1, &v2, &resolver] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();
    let tuple = (1, 2, 3, 4);

    // window 50 → maturity = 5 + 3 + 50 = 58; expires 100.
    executor.execute_tx(&settlement_tx(&funder, 0, open_op_consistency("s", 2, 2 * REWARD, 50, 100, 2, 0)), &p, 1, 1000).unwrap();
    attest_digest(&executor, &p, &v1, "s", 5, 0, tuple);
    attest_digest(&executor, &p, &v2, "s", 5, 0, tuple);

    // Funder opens a dispute against v2 during the window (height 8).
    let od = executor
        .execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: v2.address(), evidence_commitment: [9u8; 32] })), &p, 8, 1000)
        .unwrap();
    assert!(od.status.is_success(), "open dispute: {:?}", od.status);

    // v1 claims at maturity (58): v2 excluded (open dispute) → group = {v1} = 1 < 2 → 362.
    assert!(matches!(claim_status(&executor, &p, &v1, "s", 1, 58), TxStatus::Failed(362)), "open-disputed peer excluded");
}

#[test]
fn consistency_gate_open_but_no_config_keeps_v1_behavior() {
    // Consistency gate OPEN, but a session that does NOT opt in behaves exactly
    // like v1: a single verifier claims after maturity with no plurality check.
    let (state, db, _dir, executor) = setup_with_params(params_consistency(None));
    let funder = KeyPair::generate();
    let v1 = KeyPair::generate();
    let proposer = KeyPair::generate();
    for kp in [&funder, &v1] { fund(&state, kp, 10_000_000); }
    let p = proposer.address();

    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 0, 1000)), &p, 1, 1000).unwrap();
    assert!(sexec(&db).get_session("s").unwrap().unwrap().consistency.is_none(), "no config stored");
    attest_digest(&executor, &p, &v1, "s", 5, 0, (1, 2, 3, 4));
    assert!(claim_status(&executor, &p, &v1, "s", 1, 8).is_success(), "v1 single-verifier claim unaffected");
}
