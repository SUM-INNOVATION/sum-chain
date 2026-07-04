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
fn params_enabled(resolver: Option<Address>) -> ChainParams {
    let mut p = params_omninode_enabled();
    p.inference_settlement_enabled_from_height = Some(0);
    p.inference_settlement_dispute_resolver = resolver;
    p
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
    })
}

fn sexec(db: &Arc<Database>) -> InferenceSettlementExecutor {
    InferenceSettlementExecutor::new(db.clone())
}

// ── Gate ─────────────────────────────────────────────────────────────────────

#[test]
fn defaults_leave_settlement_dormant() {
    let p = ChainParams::default();
    assert_eq!(p.inference_settlement_enabled_from_height, None);
    assert_eq!(p.inference_settlement_dispute_resolver, None);
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
    let (state, db, _dir, executor) = setup_with_params(params_enabled(Some(resolver.address())));
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

    // Resolver denies the claim (height 9).
    let rd = executor
        .execute_tx(&settlement_tx(&resolver, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: false })), &proposer.address(), 9, 1000)
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
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(Some(resolver.address())));
    let funder = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &funder, 10_000_000);
    fund(&state, &verifier, 10_000_000);
    fund(&state, &resolver, 10_000_000);
    executor.execute_tx(&settlement_tx(&funder, 0, open_op("s", 2, 2 * REWARD, 50, 1000)), &proposer.address(), 1, 1000).unwrap();
    attest(&executor, &proposer.address(), &verifier, "s", 5, 0); // maturity = 55

    executor.execute_tx(&settlement_tx(&funder, 1, InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), evidence_commitment: [9u8; 32] })), &proposer.address(), 8, 1000).unwrap();
    // resolver allows.
    executor.execute_tx(&settlement_tx(&resolver, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: true })), &proposer.address(), 9, 1000).unwrap();
    // claim proceeds after maturity.
    let vbal = state.get_balance(&verifier.address()).unwrap();
    let claim = executor
        .execute_tx(&settlement_tx(&verifier, 1, InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest { session_id: "s".into() })), &proposer.address(), 60, 1000)
        .unwrap();
    assert!(claim.status.is_success(), "got {:?}", claim.status);
    assert_eq!(state.get_balance(&verifier.address()).unwrap(), vbal - FEE + REWARD);
}

#[test]
fn only_configured_resolver_may_resolve_353() {
    let resolver = KeyPair::generate();
    let (state, _db, _dir, executor) = setup_with_params(params_enabled(Some(resolver.address())));
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
    // stranger tries to resolve → 353.
    let r = executor
        .execute_tx(&settlement_tx(&stranger, 0, InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest { session_id: "s".into(), verifier: verifier.address(), allow_claim: true })), &proposer.address(), 9, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(353)), "got {:?}", r.status);
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
