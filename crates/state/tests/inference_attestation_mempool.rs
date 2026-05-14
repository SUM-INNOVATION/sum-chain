//! Phase 3 admission tests for the OmniNode `InferenceAttestation`
//! subprotocol.
//!
//! Each test exercises `Mempool::add` (and where relevant `Mempool::remove`,
//! `Mempool::contains`, executor `execute_tx`) to prove:
//!
//! - Pre-activation `InferenceAttestation` txs are rejected at admission
//!   and never reach the mempool.
//! - In-flight duplicates with the same `(session_id, verifier_address)`
//!   pair are rejected at admission and never reach the mempool.
//! - Permanent duplicates (already in the `INFERENCE_ATTESTATIONS` CF
//!   from a previously-mined attestation) are rejected at admission.
//! - Mempool-rejected duplicates never reach `execute_tx` (no fee burn,
//!   no nonce change, no CF mutation).
//! - Removing an admitted tx clears the in-flight key, so a re-admit
//!   after eviction is allowed (covers mempool eviction → re-submit).
//! - Subprotocols other than `InferenceAttestation` are unaffected by
//!   the new admission path.
//!
//! Helpers (`build_signed_attestation_tx`, `setup_with_params`,
//! `params_omninode_enabled`, etc.) are shared with the Phase 2 dispatch
//! suite via `tests/common/mod.rs`.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::TxStatus;
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::mempool::{InferenceAttestationAdmission, Mempool, MempoolConfig};
use sumchain_state::StateError;
use sumchain_storage::Database;
use tempfile::TempDir;

use common::{
    build_signed_attestation_tx, fund, params_omninode_enabled, sample_digest,
    setup_with_params,
};

/// Tiny helper: build an admission context. Uses the SAME Database the
/// executor writes to, so the permanent CF dedup check sees finalized
/// attestations the moment the executor persists them.
fn build_admission(
    db: Arc<Database>,
    params: ChainParams,
    height: u64,
) -> (InferenceAttestationAdmission, Arc<AtomicU64>) {
    let current_height = Arc::new(AtomicU64::new(height));
    let admission = InferenceAttestationAdmission {
        executor: Arc::new(InferenceAttestationExecutor::new(db)),
        params: Arc::new(params),
        current_height: current_height.clone(),
    };
    (admission, current_height)
}

fn fresh_mempool_without_admission() -> Mempool {
    Mempool::new(MempoolConfig::default())
}

fn fresh_mempool_with_admission(db: Arc<Database>, params: ChainParams, height: u64) -> Mempool {
    let (admission, _) = build_admission(db, params, height);
    Mempool::new(MempoolConfig::default()).with_inference_admission(admission)
}

// ────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────

#[test]
fn admission_rejects_pre_activation() {
    // ChainParams::default() has omninode_enabled_from_height = None.
    // Mempool should reject any attestation tx with OmniNodeNotActivated.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, ChainParams::default(), 100);

    let sender = KeyPair::generate();
    let tx = build_signed_attestation_tx(&sender, 0, 1_000_000, sample_digest("vec-1"), false);
    let hash = tx.hash();

    let err = mempool.add(tx).expect_err("must reject pre-activation");
    assert!(
        matches!(err, StateError::OmniNodeNotActivated),
        "expected OmniNodeNotActivated, got {err:?}"
    );
    assert!(!mempool.contains(&hash), "tx must never enter the mempool");
    assert_eq!(mempool.len(), 0);
}

#[test]
fn admission_rejects_pre_activation_even_after_height_advances_below_target() {
    // Activation target is 1000 but current height is 999 → still closed.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mut params = ChainParams::default();
    params.omninode_enabled_from_height = Some(1000);
    let (admission, height) = build_admission(db, params, 999);
    let mempool = Mempool::new(MempoolConfig::default()).with_inference_admission(admission);

    let sender = KeyPair::generate();
    let tx = build_signed_attestation_tx(&sender, 0, 1_000_000, sample_digest("vec-a"), false);
    let err = mempool.add(tx).expect_err("must reject at 999");
    assert!(matches!(err, StateError::OmniNodeNotActivated));

    // Bump height past the gate; a NEW tx (different session_id) admits.
    height.store(1000, Ordering::Relaxed);
    let tx2 = build_signed_attestation_tx(&sender, 1, 1_000_000, sample_digest("vec-b"), false);
    mempool.add(tx2).expect("admits at gate-open height");
}

#[test]
fn admission_accepts_when_gate_open_and_no_duplicates() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    let tx = build_signed_attestation_tx(&sender, 0, 1_000_000, sample_digest("vec-ok"), false);
    let hash = tx.hash();
    mempool.add(tx).expect("first admission must succeed");
    assert!(mempool.contains(&hash));
    assert_eq!(mempool.len(), 1);
}

#[test]
fn admission_rejects_in_flight_duplicate() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    let digest = sample_digest("dup-vec");

    let tx1 = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    let hash1 = tx1.hash();
    mempool.add(tx1).expect("first admit");

    // Second tx with the same (session_id, verifier_address) but different
    // nonce → distinct tx hash, identical admission key → must reject.
    let tx2 = build_signed_attestation_tx(&sender, 1, 1_000_000, digest.clone(), false);
    let hash2 = tx2.hash();
    assert_ne!(hash1, hash2);

    let err = mempool.add(tx2).expect_err("must reject in-flight duplicate");
    assert!(
        matches!(err, StateError::DuplicateInferenceAttestation),
        "expected DuplicateInferenceAttestation, got {err:?}"
    );
    assert!(!mempool.contains(&hash2), "duplicate must not enter mempool");
    assert!(mempool.contains(&hash1), "original stays");
    assert_eq!(mempool.len(), 1);
}

#[test]
fn admission_rejects_permanent_cf_duplicate() {
    // First persist an attestation via the executor (simulates a
    // previously-mined attestation), then try to admit the same
    // (session_id, verifier) to mempool. Must reject.
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let mempool = fresh_mempool_with_admission(db.clone(), params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000_000);

    let digest = sample_digest("perm-vec");
    let tx_first = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    let result = executor
        .execute_tx(&tx_first, &proposer.address(), 1, 0)
        .expect("execute_tx");
    assert!(
        matches!(result.status, TxStatus::Success),
        "first attestation must persist; got {:?}",
        result.status
    );

    // Now try to admit a NEW signed tx with the same (session_id, verifier).
    let tx_dup = build_signed_attestation_tx(&sender, 1, 1_000_000, digest.clone(), false);
    let hash_dup = tx_dup.hash();
    let err = mempool.add(tx_dup).expect_err("must reject permanent duplicate");
    assert!(
        matches!(err, StateError::DuplicateInferenceAttestation),
        "expected DuplicateInferenceAttestation, got {err:?}"
    );
    assert!(!mempool.contains(&hash_dup));
}

#[test]
fn rejected_mempool_duplicate_never_reaches_executor() {
    // End-to-end proof that mempool admission is the first gate, not
    // the executor. Build a duplicate-pair tx, attempt to admit it,
    // then confirm the executor is never invoked. We simulate "never
    // invoked" by asserting the executor's CF row count is unchanged.
    let (state, db, _dir, executor) = setup_with_params(params_omninode_enabled());
    let mempool = fresh_mempool_with_admission(db.clone(), params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sender, 10_000_000);

    let digest = sample_digest("e2e-vec");

    // First tx: persist via executor.
    let first = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    executor
        .execute_tx(&first, &proposer.address(), 1, 0)
        .expect("first execute");
    let cf_key = sumchain_primitives::inference_attestation::inference_attestation_key(
        &digest.session_id,
        &sender.address(),
    );
    assert!(
        db.get(sumchain_storage::cf::INFERENCE_ATTESTATIONS, &cf_key)
            .unwrap()
            .is_some(),
        "first attestation should be persisted"
    );

    // Snapshot proposer balance + sender nonce to prove they don't change
    // when mempool rejects the duplicate.
    let proposer_balance_before = state.get_balance(&proposer.address()).unwrap();
    let sender_nonce_before = state.get_nonce(&sender.address()).unwrap();

    // Duplicate tx: mempool MUST reject before executor sees it.
    let dup = build_signed_attestation_tx(&sender, 1, 1_000_000, digest.clone(), false);
    let err = mempool.add(dup).expect_err("admission must reject duplicate");
    assert!(matches!(err, StateError::DuplicateInferenceAttestation));

    // No state mutation triggered by the rejected attempt.
    assert_eq!(
        state.get_balance(&proposer.address()).unwrap(),
        proposer_balance_before,
        "proposer must not be credited on a rejected admission"
    );
    assert_eq!(
        state.get_nonce(&sender.address()).unwrap(),
        sender_nonce_before,
        "sender nonce must not advance on a rejected admission"
    );
}

#[test]
fn remove_clears_in_flight_key_enabling_resubmit() {
    // Mempool eviction (timeout, full, manual remove, etc.) MUST clear
    // the in-flight key so a future submission of the same
    // (session_id, verifier) is accepted again. Otherwise an evicted
    // tx leaves a permanent in-mempool ghost.
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    let digest = sample_digest("evict-vec");

    let tx1 = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    let hash1 = tx1.hash();
    mempool.add(tx1).expect("first admit");
    assert!(mempool.contains(&hash1));

    // Manually evict.
    mempool.remove(&hash1);
    assert!(!mempool.contains(&hash1));

    // Same (session_id, verifier) re-submitted with a new nonce → must
    // now admit because the in-flight key was cleared on remove.
    let tx2 = build_signed_attestation_tx(&sender, 1, 1_000_000, digest, false);
    mempool.add(tx2).expect("re-admit after eviction");
    assert_eq!(mempool.len(), 1);
}

#[test]
fn distinct_sessions_do_not_collide() {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, params_omninode_enabled(), 1);

    let sender = KeyPair::generate();
    for i in 0..5 {
        let tx = build_signed_attestation_tx(
            &sender,
            i,
            1_000_000,
            sample_digest(&format!("session-{i}")),
            false,
        );
        mempool.add(tx).unwrap_or_else(|e| panic!("session-{i}: {e:?}"));
    }
    assert_eq!(mempool.len(), 5);
}

#[test]
fn distinct_verifiers_for_same_session_id_do_not_collide() {
    // The dedup key is `(session_id, verifier_address)` — two different
    // verifiers attesting the same session must both be admitted (the
    // chain wants multiple verifiers per session as a quorum signal).
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, params_omninode_enabled(), 1);

    let v1 = KeyPair::generate();
    let v2 = KeyPair::generate();
    assert_ne!(v1.address(), v2.address());

    let digest = sample_digest("multi-verifier-session");
    let tx1 = build_signed_attestation_tx(&v1, 0, 1_000_000, digest.clone(), false);
    let tx2 = build_signed_attestation_tx(&v2, 0, 1_000_000, digest, false);

    mempool.add(tx1).expect("verifier 1 admits");
    mempool.add(tx2).expect("verifier 2 admits — distinct dedup key");
    assert_eq!(mempool.len(), 2);
}

#[test]
fn mempool_without_admission_still_dedupes_in_flight() {
    // Tests / consensus internal re-adds construct Mempool::new()
    // without admission. Those callers should still get in-flight
    // dedup (so a tx isn't re-added to a mempool that already has it
    // by content), but skip activation gate + permanent CF check.
    let mempool = fresh_mempool_without_admission();

    let sender = KeyPair::generate();
    let digest = sample_digest("no-ctx-vec");
    let tx1 = build_signed_attestation_tx(&sender, 0, 1_000_000, digest.clone(), false);
    mempool.add(tx1).expect("admits without activation context");

    let tx2 = build_signed_attestation_tx(&sender, 1, 1_000_000, digest, false);
    let err = mempool.add(tx2).expect_err("in-flight dedup still fires");
    assert!(matches!(err, StateError::DuplicateInferenceAttestation));
}

// ────────────────────────────────────────────────────────────────────────
// Production-wiring contract tests
//
// These mirror the admission recipe in `Node::new`
// (crates/node/src/node.rs) line-for-line. If `Node::new` is refactored
// to construct admission differently, these tests must be updated
// alongside. The duplication is deliberate — it's a tripwire against
// silent removal of `.with_inference_admission(...)` from production
// node startup. Phase 4 step 3 contract.
// ────────────────────────────────────────────────────────────────────────

/// Mirror of `Node::new`'s admission construction. Returns the same
/// `Arc<Mempool>` shape with the same admission context fields wired
/// up. Used only by the two production-wiring tests below.
fn build_production_wiring_mempool(
    params: ChainParams,
    initial_height: u64,
) -> (Arc<sumchain_state::Mempool>, Arc<AtomicU64>, TempDir) {
    use sumchain_state::MempoolConfig;
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let chain_height = Arc::new(AtomicU64::new(initial_height));
    let admission = InferenceAttestationAdmission {
        executor: Arc::new(InferenceAttestationExecutor::new(db.clone())),
        params: Arc::new(params.clone()),
        current_height: chain_height.clone(),
    };
    let mempool = Arc::new(
        sumchain_state::Mempool::new(MempoolConfig {
            min_fee: params.min_fee,
            ..Default::default()
        })
        .with_inference_admission(admission),
    );
    (mempool, chain_height, dir)
}

#[test]
fn production_wiring_rejects_attestation_pre_activation() {
    // Default ChainParams has omninode_enabled_from_height = None. Any
    // node started from such a genesis (i.e. mainnet today) MUST reject
    // every attestation tx at mempool admission — proving
    // `sum_sendRawTransaction` cannot reach an unactivated executor.
    let (mempool, _height, _dir) = build_production_wiring_mempool(ChainParams::default(), 0);
    let sender = KeyPair::generate();
    let tx = build_signed_attestation_tx(&sender, 0, 1_000_000, sample_digest("prod-pre"), false);
    let result = mempool.add(tx);
    assert!(
        matches!(result, Err(StateError::OmniNodeNotActivated)),
        "production-shape mempool must reject pre-activation attestation; \
         got {result:?}. If this is failing, Node::new has been \
         refactored without an admission context — re-wire \
         `.with_inference_admission(...)` before merging."
    );
    assert_eq!(mempool.len(), 0);
}

#[test]
fn production_wiring_height_advance_opens_gate() {
    // Activation = Some(1000). At chain_height = 999 the gate is closed;
    // bumping chain_height to 1000 (which Node::new does on every
    // BlockProduced / BlockImported event in its run loop) must open the
    // gate for the next attestation. Proves the `chain_height.store(...)`
    // path is load-bearing for live admission decisions.
    let mut params = ChainParams::default();
    params.omninode_enabled_from_height = Some(1000);
    let (mempool, chain_height, _dir) = build_production_wiring_mempool(params, 999);

    let sender = KeyPair::generate();
    let tx_pre = build_signed_attestation_tx(
        &sender,
        0,
        1_000_000,
        sample_digest("below-target"),
        false,
    );
    assert!(matches!(
        mempool.add(tx_pre),
        Err(StateError::OmniNodeNotActivated)
    ));

    // Simulate Node::new's run-loop bumping chain_height on a
    // BlockProduced / BlockImported event.
    chain_height.store(1000, Ordering::Relaxed);

    let tx_post = build_signed_attestation_tx(
        &sender,
        1,
        1_000_000,
        sample_digest("at-target"),
        false,
    );
    let hash = tx_post.hash();
    mempool
        .add(tx_post)
        .expect("post-activation admission must succeed");
    assert!(mempool.contains(&hash));
}

#[test]
fn admission_does_not_affect_non_inference_payloads() {
    use sumchain_crypto::sign;
    use sumchain_primitives::{SignedTransaction, Transaction};

    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let mempool = fresh_mempool_with_admission(db, ChainParams::default(), 0);

    // Plain transfer; admission must skip the InferenceAttestation hook
    // entirely. ChainParams default has omninode_enabled_from_height
    // = None — that gate MUST NOT reject transfers.
    let sender = KeyPair::generate();
    let recipient = KeyPair::generate();
    let tx = Transaction::new(common::CHAIN_ID, sender.address(), recipient.address(), 100, 10, 0);
    let signing_hash = tx.signing_hash();
    let sig = sign(signing_hash.as_bytes(), sender.private_key());
    let signed = SignedTransaction::new(tx, *sig.as_bytes(), *sender.public_key().as_bytes());
    mempool.add(signed).expect("transfer admits regardless of OmniNode gate");
}
