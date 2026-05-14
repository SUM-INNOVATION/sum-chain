//! Shared helpers for OmniNode `InferenceAttestation` integration tests.
//!
//! Two callers (Phase 2 dispatch tests, Phase 3 mempool admission tests)
//! need identical fixtures: a deterministic test setup, signed
//! `TransactionV2` construction with an inner Stage 6 signature, and a
//! reusable sample digest. Centralizing them here prevents drift between
//! the dispatch and admission test suites and gives Phase 4 (RPC tests)
//! a stable scaffolding to build on.

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    inference_attestation::{
        signing_input_bytes, InferenceAttestationDigest, InferenceAttestationTxData,
    },
    SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::{executor::BlockExecutor, state::StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;

pub const CHAIN_ID: u64 = 1;

/// Standard test setup: temp RocksDB, fresh StateManager, BlockExecutor
/// wired with the supplied ChainParams.
#[allow(dead_code)]
pub fn setup_with_params(
    params: ChainParams,
) -> (Arc<StateManager>, Arc<Database>, TempDir, BlockExecutor) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let executor = BlockExecutor::new(state.clone(), db.clone(), params);
    (state, db, dir, executor)
}

/// ChainParams with OmniNode activated from genesis (height 0). Mirrors
/// `ChainParams::with_v2_enabled` semantics for the OmniNode gate.
#[allow(dead_code)]
pub fn params_omninode_enabled() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.omninode_enabled_from_height = Some(0);
    p
}

/// Fund a sender account so it has balance for fees.
#[allow(dead_code)]
pub fn fund(state: &StateManager, kp: &KeyPair, balance: u128) {
    state
        .put_account(
            &kp.address(),
            &sumchain_storage::schema::AccountState { balance, nonce: 0 },
        )
        .unwrap();
}

/// Sample digest. Each test passes a unique `session_id` to keep CF
/// keys disjoint when multiple tests share a setup.
#[allow(dead_code)]
pub fn sample_digest(session_id: &str) -> InferenceAttestationDigest {
    InferenceAttestationDigest {
        session_id: session_id.to_string(),
        model_hash: [1u8; 32],
        manifest_root: [2u8; 32],
        response_hash: [3u8; 32],
        proof_root: [4u8; 32],
    }
}

/// Sign the inner Stage 6 digest with the verifier's Ed25519 key.
#[allow(dead_code)]
pub fn stage6_sign(kp: &KeyPair, digest: &InferenceAttestationDigest) -> [u8; 64] {
    let input = signing_input_bytes(digest).expect("encode signing input");
    let sig = sign(&input, kp.private_key());
    *sig.as_bytes()
}

/// Construct a signed `TransactionV2` carrying an `InferenceAttestation`
/// payload. Same Ed25519 key signs both the inner digest and the outer
/// tx (sender == verifier in v1).
///
/// If `corrupt_inner_sig` is true, the inner verifier_signature has one
/// byte XOR'd. Ed25519 verification is strict — any single bit change
/// rejects. Used by tests that prove the dispatch's
/// `Failed(52)` / mempool admission's invalid-sig path.
#[allow(dead_code)]
pub fn build_signed_attestation_tx(
    sender: &KeyPair,
    nonce: u64,
    fee: u128,
    digest: InferenceAttestationDigest,
    corrupt_inner_sig: bool,
) -> SignedTransaction {
    let mut verifier_signature = stage6_sign(sender, &digest);
    if corrupt_inner_sig {
        verifier_signature[0] ^= 0xff;
    }
    let payload = TxPayload::InferenceAttestation(InferenceAttestationTxData {
        digest,
        verifier_signature,
    });
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: sender.address(),
        fee,
        nonce,
        payload,
    };
    let outer_hash = tx.signing_hash();
    let outer_sig = sign(outer_hash.as_bytes(), sender.private_key());
    SignedTransaction::new_v2(tx, *outer_sig.as_bytes(), *sender.public_key().as_bytes())
}
