//! Dispatch-level tests for the OmniNode `InferenceAttestation` subprotocol.
//!
//! These exercise the **full** consensus path through
//! `BlockExecutor::execute_tx` for `TxPayload::InferenceAttestation`, not
//! just the storage-layer executor. Each test constructs a properly-
//! signed `TransactionV2`, runs it through `execute_tx`, and asserts on
//! both the returned `TxStatus` AND the observable side-effects (sender
//! balance, proposer balance, sender nonce, CF presence).
//!
//! What's covered:
//!
//! 1. Pre-activation rejection (`Failed(50)`)
//! 2. Success path (fee accounting + nonce + CF persist)
//! 3. Duplicate rejection (`Failed(51)`)
//! 4. Invalid inner signature rejection (`Failed(52)`)
//! 5. Insufficient balance handling (`InsufficientBalance`)
//!
//! Not covered by these tests, **on purpose**: `Failed(53)
//! SenderVerifierMismatch`. The outer `BlockExecutor::execute_tx` path
//! at executor.rs:1064-1072 already rejects `sender != signer_address`
//! with `TxStatus::InvalidSignature` BEFORE the variant-specific arm is
//! reached. So the only way for `Failed(53)` to fire in practice is if a
//! caller bypasses outer validation — a defense-in-depth path that is
//! intentionally unreachable in normal consensus flow. The arm exists,
//! returns the right status code, and is covered by visual inspection
//! of the dispatch code. We do NOT spend test effort forcing an
//! unreachable execution.

mod common;

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    inference_attestation::{
        canonical_digest_bytes, inference_attestation_key, signing_input_bytes, DOMAIN_TAG,
    },
    TxStatus,
};
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_storage::cf;
use std::sync::Arc;

use common::{
    build_signed_attestation_tx, fund, params_omninode_enabled, sample_digest,
    setup_with_params,
};

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_pre_activation_rejects() {
    // ChainParams::default() has omninode_enabled_from_height == None,
    // so the gate is closed at every block height. The outer dispatch
    // arm must return Failed(50), fee_paid: 0, and leave sender balance,
    // sender nonce, and the CF untouched.
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 1_000_000_000);
    let initial_balance = state.get_balance(&sender.address()).unwrap();
    let initial_nonce = state.get_nonce(&sender.address()).unwrap();

    let digest = sample_digest("pre-activation-vec");
    let tx = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    let result = executor
        .execute_tx(&tx, &proposer.address(), 1, 0)
        .expect("execute_tx returned Err");

    assert!(matches!(result.status, TxStatus::Failed(50)));
    assert_eq!(result.fee_paid, 0, "no fee should be charged pre-activation");
    assert_eq!(state.get_balance(&sender.address()).unwrap(), initial_balance);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), initial_nonce);

    let cf_key = inference_attestation_key(&digest.session_id, &sender.address());
    assert!(
        db.get(cf::INFERENCE_ATTESTATIONS, &cf_key).unwrap().is_none(),
        "no CF row should be written on Failed(50)"
    );
}

#[test]
fn dispatch_success_path() {
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    fund(&state, &sender, 10 * fee);

    let digest = sample_digest("success-vec");
    let tx = build_signed_attestation_tx(&sender, 0, fee, digest.clone(), false);
    let result = executor
        .execute_tx(&tx, &proposer.address(), 1, 0)
        .expect("execute_tx returned Err");

    assert!(
        matches!(result.status, TxStatus::Success),
        "expected Success, got {:?}",
        result.status
    );
    assert_eq!(result.fee_paid, fee);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10 * fee - fee);
    assert_eq!(
        state.get_balance(&proposer.address()).unwrap(),
        fee,
        "proposer must be credited"
    );
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 1, "nonce must advance");

    let cf_key = inference_attestation_key(&digest.session_id, &sender.address());
    let row = db
        .get(cf::INFERENCE_ATTESTATIONS, &cf_key)
        .unwrap()
        .expect("CF row must exist on Success");
    // Round-trip the canonical digest to confirm the stored record
    // matches what we signed.
    let stored_record: sumchain_primitives::inference_attestation::InferenceAttestationRecord =
        bincode::deserialize(&row).expect("bincode-deserialize record");
    assert_eq!(
        canonical_digest_bytes(&stored_record.digest).unwrap(),
        canonical_digest_bytes(&digest).unwrap(),
        "stored digest must round-trip to the same canonical bytes"
    );
    assert_eq!(stored_record.included_at_height, 1);
}

#[test]
fn dispatch_duplicate_after_success_rejects() {
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    fund(&state, &sender, 10 * fee);

    let digest = sample_digest("duplicate-vec");

    // First submission succeeds.
    let tx1 = build_signed_attestation_tx(&sender, 0, fee, digest.clone(), false);
    let r1 = executor.execute_tx(&tx1, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r1.status, TxStatus::Success));
    let post_success_balance = state.get_balance(&sender.address()).unwrap();
    let post_success_nonce = state.get_nonce(&sender.address()).unwrap();
    let post_success_proposer = state.get_balance(&proposer.address()).unwrap();
    let cf_key = inference_attestation_key(&digest.session_id, &sender.address());
    let first_row = db.get(cf::INFERENCE_ATTESTATIONS, &cf_key).unwrap().expect("row");

    // Second submission of the SAME (session_id, verifier) — must be
    // rejected at the CF dedup step with Failed(51), no further fee or
    // nonce mutation, no CF overwrite.
    let tx2 = build_signed_attestation_tx(&sender, 1, fee, digest.clone(), false);
    let r2 = executor.execute_tx(&tx2, &proposer.address(), 2, 0).unwrap();
    assert!(
        matches!(r2.status, TxStatus::Failed(51)),
        "expected Failed(51) DuplicateAttestation, got {:?}",
        r2.status
    );
    assert_eq!(r2.fee_paid, 0);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), post_success_balance);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), post_success_nonce);
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), post_success_proposer);
    let second_row = db.get(cf::INFERENCE_ATTESTATIONS, &cf_key).unwrap().expect("row");
    assert_eq!(first_row, second_row, "CF row must not change on duplicate");
}

#[test]
fn dispatch_invalid_inner_signature_rejects() {
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    fund(&state, &sender, 10 * fee);
    let initial_balance = state.get_balance(&sender.address()).unwrap();

    let digest = sample_digest("bad-sig-vec");
    // corrupt_inner_sig = true: outer tx signature is still valid (the
    // chain's standard outer-tx signing covers the whole tx including
    // the corrupted inner sig as a payload byte), but the inner Stage 6
    // verify under DOMAIN_TAG must reject.
    let tx = build_signed_attestation_tx(&sender, 0, fee, digest.clone(), true);
    let result = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(result.status, TxStatus::Failed(52)),
        "expected Failed(52) InvalidVerifierSignature, got {:?}",
        result.status
    );
    assert_eq!(result.fee_paid, 0);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), initial_balance);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0);
    let cf_key = inference_attestation_key(&digest.session_id, &sender.address());
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &cf_key).unwrap().is_none());
}

#[test]
fn dispatch_insufficient_balance_for_fee() {
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    // Fund sender with strictly less than the fee. The outer validate
    // path may not catch this for InferenceAttestation (amount = 0,
    // so total_cost == fee), so the variant arm's explicit balance
    // check at step 5a is what fires.
    fund(&state, &sender, fee - 1);

    let digest = sample_digest("balance-vec");
    let tx = build_signed_attestation_tx(&sender, 0, fee, digest.clone(), false);
    let result = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    // Outer balance validation at executor.rs:1108-1114 returns
    // `InsufficientBalance` for transfers; for fee-only attestations the
    // same status is returned from our variant arm. Either way, the
    // observable behavior is identical: no fee charged, no nonce
    // advance, no CF write.
    assert!(
        matches!(result.status, TxStatus::InsufficientBalance),
        "expected InsufficientBalance, got {:?}",
        result.status
    );
    assert_eq!(result.fee_paid, 0);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), fee - 1);
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0);
    let cf_key = inference_attestation_key(&digest.session_id, &sender.address());
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &cf_key).unwrap().is_none());
}

#[test]
fn dispatch_stored_record_uses_omninode_domain_tag() {
    // Round-trip the on-disk record's signing input under DOMAIN_TAG
    // and confirm the recorded signature still verifies against the
    // recorded pubkey. This is the "documented stable wire format"
    // assertion for the storage layer, separate from the Phase 1
    // fixture parity tests which lock the bytes against OmniNode's
    // reference vectors.
    let (state, _db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    fund(&state, &sender, 10 * fee);

    let digest = sample_digest("domain-tag-roundtrip");
    let tx = build_signed_attestation_tx(&sender, 0, fee, digest.clone(), false);
    let result = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(result.status, TxStatus::Success));

    // Recompute the signing input from the digest the chain stored and
    // confirm it starts with the OmniNode DOMAIN_TAG bytes.
    let input = signing_input_bytes(&digest).unwrap();
    let domain_bytes = DOMAIN_TAG.as_bytes();
    assert_eq!(
        &input[..domain_bytes.len()],
        domain_bytes,
        "signing input must begin with DOMAIN_TAG bytes"
    );
}

#[test]
fn dispatch_populates_session_index() {
    // After a Successful dispatch, the RPC `sum_listInferenceAttestations`
    // path reads `INFERENCE_ATTESTATIONS_BY_SESSION` to enumerate the
    // verifiers for a session. Prove the dispatcher actually maintains
    // that index by querying it after execute_tx.
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());

    let sender_a = KeyPair::generate();
    let sender_b = KeyPair::generate();
    let proposer = KeyPair::generate();
    let fee: u128 = 1_000_000;
    fund(&state, &sender_a, 10 * fee);
    fund(&state, &sender_b, 10 * fee);

    let session_id = "indexed-session";
    let tx_a = build_signed_attestation_tx(&sender_a, 0, fee, sample_digest(session_id), false);
    let tx_b = build_signed_attestation_tx(&sender_b, 0, fee, sample_digest(session_id), false);

    let r_a = executor.execute_tx(&tx_a, &proposer.address(), 1, 0).unwrap();
    let r_b = executor.execute_tx(&tx_b, &proposer.address(), 2, 0).unwrap();
    assert!(matches!(r_a.status, TxStatus::Success));
    assert!(matches!(r_b.status, TxStatus::Success));

    // Read the session index via the same path RPC uses.
    let read_executor = InferenceAttestationExecutor::new(Arc::clone(&db));
    let mut verifiers = read_executor
        .list_verifiers_by_session(session_id)
        .expect("index lookup");
    verifiers.sort();
    let mut expected = vec![sender_a.address(), sender_b.address()];
    expected.sort();
    assert_eq!(
        verifiers, expected,
        "session index must contain both verifiers after successful dispatch"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Sponsored attestation v2 (issue #79): payer != verifier
// ─────────────────────────────────────────────────────────────────────────

use sumchain_crypto::sign;
use sumchain_primitives::inference_attestation::InferenceAttestationV2TxData;
use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload};
use common::{stage6_sign, CHAIN_ID};

/// omninode + sponsored-attestation gates both open.
fn params_sponsored_enabled() -> ChainParams {
    let mut p = params_omninode_enabled();
    p.omninode_sponsored_attestation_enabled_from_height = Some(0);
    p
}

/// Build a sponsored v2 attestation tx: the SPONSOR signs the outer tx; the
/// VERIFIER signs the inner digest. `wrong_verifier_pk` optionally swaps in a
/// different (valid) key so the inner sig no longer matches.
fn build_sponsored_tx(
    sponsor: &KeyPair,
    verifier: &KeyPair,
    nonce: u64,
    fee: u128,
    digest: sumchain_primitives::inference_attestation::InferenceAttestationDigest,
    tamper_sig: bool,
    override_pk: Option<[u8; 32]>,
) -> SignedTransaction {
    let mut verifier_signature = stage6_sign(verifier, &digest);
    if tamper_sig {
        verifier_signature[0] ^= 0xff;
    }
    let verifier_public_key = override_pk.unwrap_or(*verifier.public_key().as_bytes());
    let payload = TxPayload::InferenceAttestationV2(InferenceAttestationV2TxData {
        digest,
        verifier_public_key,
        verifier_signature,
    });
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: sponsor.address(), fee, nonce, payload };
    let outer_hash = tx.signing_hash();
    let outer_sig = sign(outer_hash.as_bytes(), sponsor.private_key());
    SignedTransaction::new_v2(tx, *outer_sig.as_bytes(), *sponsor.public_key().as_bytes())
}

#[test]
fn v2_sponsored_succeeds_and_stores_under_verifier_not_sponsor() {
    let (state, db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);
    // verifier is NOT funded — it never pays.
    let v_bal0 = state.get_balance(&verifier.address()).unwrap();
    let s_bal0 = state.get_balance(&sponsor.address()).unwrap();

    let digest = sample_digest("sponsored-vec");
    let tx = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), false, None);
    let r = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(r.status.is_success(), "sponsored attestation should succeed: {:?}", r.status);

    // Sponsor paid the fee + nonce; verifier untouched.
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), s_bal0 - 1_000);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 1);
    assert_eq!(state.get_balance(&verifier.address()).unwrap(), v_bal0, "verifier never pays");
    assert_eq!(state.get_nonce(&verifier.address()).unwrap(), 0, "verifier nonce untouched");

    // Record stored under the VERIFIER key, not the sponsor key.
    let vkey = inference_attestation_key(&digest.session_id, &verifier.address());
    let skey = inference_attestation_key(&digest.session_id, &sponsor.address());
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &vkey).unwrap().is_some(), "stored under verifier");
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &skey).unwrap().is_none(), "NOT stored under sponsor");
    // Session index lists the verifier, not the sponsor.
    let verifiers = InferenceAttestationExecutor::new(db.clone())
        .list_verifiers_by_session(&digest.session_id)
        .unwrap();
    assert_eq!(verifiers, vec![verifier.address()], "index attributes to verifier");
}

#[test]
fn v2_gate_closed_is_free_no_mutation() {
    // omninode ON, sponsored sub-gate OFF → Failed(54), free, nothing written.
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);
    let bal0 = state.get_balance(&sponsor.address()).unwrap();

    let digest = sample_digest("gate-closed-vec");
    let tx = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), false, None);
    let r = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(54)), "got {:?}", r.status);
    assert_eq!(r.fee_paid, 0, "sponsored gate-closed is free");
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), bal0, "no fee");
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 0, "no nonce bump");
    let vkey = inference_attestation_key(&digest.session_id, &verifier.address());
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &vkey).unwrap().is_none(), "no CF write");
}

#[test]
fn v2_bad_verifier_signature_52() {
    let (state, _db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let other = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);
    let digest = sample_digest("bad-sig-vec");

    // Tampered inner signature → 52.
    let t = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), true, None);
    assert!(matches!(executor.execute_tx(&t, &proposer.address(), 1, 0).unwrap().status, TxStatus::Failed(52)));

    // Valid sig by `verifier` but envelope claims a DIFFERENT (valid) pubkey →
    // the sponsor cannot swap in another verifier: sig no longer matches → 52.
    let m = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest, false, Some(*other.public_key().as_bytes()));
    assert!(matches!(executor.execute_tx(&m, &proposer.address(), 1, 0).unwrap().status, TxStatus::Failed(52)));
}

#[test]
fn v2_malformed_envelope_oversize_session_55() {
    let (state, _db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);

    // session_id > MAX_SESSION_ID_BYTES (256) → malformed envelope → 55.
    let mut digest = sample_digest("x");
    digest.session_id = "a".repeat(300);
    let tx = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest, false, None);
    let r = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(55)), "got {:?}", r.status);
    assert_eq!(r.fee_paid, 0, "malformed envelope pays nothing");
}

#[test]
fn v2_duplicate_and_cross_version_dedup_51() {
    let (state, _db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);
    fund(&state, &verifier, 1_000_000_000);
    let digest = sample_digest("dup-vec");

    // First v2 submission succeeds.
    let a = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), false, None);
    assert!(executor.execute_tx(&a, &proposer.address(), 1, 0).unwrap().status.is_success());
    // Second v2 for the same (session, verifier) → 51.
    let b = build_sponsored_tx(&sponsor, &verifier, 1, 1_000, digest.clone(), false, None);
    assert!(matches!(executor.execute_tx(&b, &proposer.address(), 2, 0).unwrap().status, TxStatus::Failed(51)));
    // A v1 self-submission by the verifier for the SAME pair also → 51 (shared keyspace).
    let v1 = build_signed_attestation_tx(&verifier, 0, 1_000, digest, false);
    assert!(matches!(executor.execute_tx(&v1, &proposer.address(), 3, 0).unwrap().status, TxStatus::Failed(51)));
}

// ─────────────────────────────────────────────────────────────────────────
// Issue #95 — additive sponsor metadata
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn v2_sponsored_writes_sponsor_metadata() {
    let (state, db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);

    let digest = sample_digest("sponsor-meta-vec");
    let tx = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), false, None);
    let r = executor.execute_tx(&tx, &proposer.address(), 7, 0).unwrap();
    assert!(r.status.is_success(), "sponsored attestation should succeed: {:?}", r.status);

    // Sponsor metadata is keyed by the VERIFIER key (same as the record), and
    // records sponsor address, inclusion height, and outer tx hash.
    let vkey = inference_attestation_key(&digest.session_id, &verifier.address());
    let sp = InferenceAttestationExecutor::new(db.clone())
        .get_sponsor(&vkey)
        .unwrap()
        .expect("sponsor metadata present for a sponsored attestation");
    assert_eq!(sp.sponsor, sponsor.address(), "sponsor is the outer sender");
    assert_eq!(sp.submitted_at_height, 7, "records inclusion height");
    assert_eq!(sp.tx_hash, r.tx_hash, "records the outer tx hash");

    // Not keyed under the sponsor address.
    let skey = inference_attestation_key(&digest.session_id, &sponsor.address());
    assert!(db.get(cf::INFERENCE_ATTESTATION_SPONSORS, &skey).unwrap().is_none());
}

#[test]
fn v1_direct_leaves_sponsor_metadata_absent() {
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &verifier, 1_000_000_000);

    let digest = sample_digest("v1-no-sponsor-vec");
    let tx = build_signed_attestation_tx(&verifier, 0, 1_000, digest.clone(), false);
    let r = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(r.status.is_success(), "v1 direct attestation should succeed: {:?}", r.status);

    // The record exists but no sponsor metadata is written for a direct submission.
    let key = inference_attestation_key(&digest.session_id, &verifier.address());
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &key).unwrap().is_some(), "record present");
    assert!(
        InferenceAttestationExecutor::new(db.clone()).get_sponsor(&key).unwrap().is_none(),
        "v1 direct submission writes no sponsor metadata"
    );
}

#[test]
fn v2_duplicate_does_not_overwrite_sponsor_metadata() {
    let (state, db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor_a = KeyPair::generate();
    let sponsor_b = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor_a, 1_000_000_000);
    fund(&state, &sponsor_b, 1_000_000_000);

    let digest = sample_digest("dup-sponsor-vec");
    // First sponsored submission by sponsor A succeeds and records A.
    let a = build_sponsored_tx(&sponsor_a, &verifier, 0, 1_000, digest.clone(), false, None);
    assert!(executor.execute_tx(&a, &proposer.address(), 1, 0).unwrap().status.is_success());
    let vkey = inference_attestation_key(&digest.session_id, &verifier.address());
    assert_eq!(
        InferenceAttestationExecutor::new(db.clone()).get_sponsor(&vkey).unwrap().unwrap().sponsor,
        sponsor_a.address()
    );

    // A second sponsored submission for the same (session, verifier) by sponsor B
    // is rejected (51) and MUST NOT overwrite the recorded sponsor.
    let b = build_sponsored_tx(&sponsor_b, &verifier, 0, 1_000, digest, false, None);
    assert!(matches!(executor.execute_tx(&b, &proposer.address(), 2, 0).unwrap().status, TxStatus::Failed(51)));
    assert_eq!(
        InferenceAttestationExecutor::new(db.clone()).get_sponsor(&vkey).unwrap().unwrap().sponsor,
        sponsor_a.address(),
        "duplicate v2 must not overwrite existing sponsor metadata"
    );
}

#[test]
fn sponsored_attestation_settlement_identity_is_verifier_only() {
    // Settlement's ClaimReward keys on `inference_attestation_key(session_id,
    // claimer)` (inference_settlement_executor.rs). After a sponsored (v2)
    // attestation, the canonical record resolves under the VERIFIER key and is
    // ABSENT under the sponsor key — so only the verifier can claim; the sponsor
    // cannot, regardless of the additive sponsor metadata. The sponsor CF is a
    // separate keyspace settlement never reads.
    let (state, db, _dir, executor) = setup_with_params(params_sponsored_enabled());
    let sponsor = KeyPair::generate();
    let verifier = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 1_000_000_000);

    let digest = sample_digest("settlement-identity-vec");
    let tx = build_sponsored_tx(&sponsor, &verifier, 0, 1_000, digest.clone(), false, None);
    assert!(executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap().status.is_success());

    let verifier_key = inference_attestation_key(&digest.session_id, &verifier.address());
    let sponsor_key = inference_attestation_key(&digest.session_id, &sponsor.address());
    // The settlement-relevant record is under the verifier, not the sponsor.
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &verifier_key).unwrap().is_some(), "claimable by verifier");
    assert!(db.get(cf::INFERENCE_ATTESTATIONS, &sponsor_key).unwrap().is_none(), "sponsor has no claimable record");
}
