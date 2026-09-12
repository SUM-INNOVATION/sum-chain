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

/// ChainParams with the SRC-817/818 Education suite activated from
/// genesis (height 0).
#[allow(dead_code)]
pub fn params_education_enabled() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.education_enabled_from_height = Some(0);
    p
}

/// ChainParams with the Education suite DISABLED (default `None`).
#[allow(dead_code)]
pub fn params_education_disabled() -> ChainParams {
    ChainParams::with_v2_enabled()
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

// ── Executing transactions against a candidate ───────────────────────────────
//
// `execute_tx` takes an `ExecutionView`, the handle onto one block's candidate.
// Nothing it writes reaches the database until that candidate is published, so
// a test that executes transactions has to decide which block they belong to.

/// The per-block write-set ceiling these tests run under.
///
/// Mirrors the executor's own scaffolding constant, which is private. Both are
/// stand-ins for the versioned consensus parameter that has to replace them
/// before any of this is proposed for publication; a test that wanted to
/// exercise the limit would set its own, not read this.
pub const TEST_CANDIDATE_LIMIT: u64 = 1 << 30;

/// One candidate for one block.
///
/// Every transaction in a same-block scenario must execute against the SAME
/// candidate. A fresh candidate per transaction is a fresh block per
/// transaction: the second transaction would not see what the first staged, so
/// read-your-own-writes would silently not hold and a test that depends on it
/// would pass for the wrong reason — or fail in a way that looks like a bug in
/// the code under test.
#[allow(dead_code)]
pub fn candidate(db: &Database) -> sumchain_storage::candidate::CandidateExecution<'_> {
    sumchain_storage::candidate::CandidateExecution::new(db, TEST_CANDIDATE_LIMIT)
}

/// The receipts one block's execution produced.
///
/// `execute_block` returns a `BlockExecution` whose candidate carries the
/// receipts already bound to the accumulator that produced them, rather than a
/// loose list a caller could substitute. This reads them back out; nothing is
/// published.
#[allow(dead_code)]
pub fn receipts_of(
    exec: sumchain_state::executor::BlockExecution<'_>,
) -> Vec<sumchain_primitives::Receipt> {
    let (executed, _state_diff, _contract_diff) = exec.into_parts();
    executed.receipts().to_vec()
}

/// Execute `txs` as one block at `height` and PUBLISH it, the way a proposer
/// does: `execute_block` -> fill in the computed root -> `accept_produced` ->
/// `publish`.
///
/// This is the real publication path, not a shortcut around it. There is no way
/// to turn a candidate into canonical state from outside `sumchain-storage`
/// except through `AcceptedCandidate::publish`, and that is the point — a test
/// fixture that could commit an overlay directly would be the escape hatch this
/// work removes.
///
/// Use it where the SUBJECT is canonical state: a later block reading what an
/// earlier one published, or mempool admission, which answers about the
/// published chain rather than about a candidate. A same-block scenario wants
/// [`candidate`] instead — publishing between transactions would make each one
/// its own block and hide exactly the read-your-own-writes behaviour under
/// test.
///
/// The root is written into the header AFTER execution and BEFORE acceptance,
/// which is the producer's own order (`poa.rs`): the header cannot carry a root
/// that has not been computed yet, and `accept_produced` refuses a block whose
/// header root disagrees with what its execution produced. Filling it in is
/// sound because `ExecutionSubject` binds height, parent, timestamp, tx root,
/// proposer and transactions — everything except the root, which is the one
/// field the producer is still allowed to set.
///
/// `accept_produced` is the honest acceptance here: a proposer writes the root
/// it computed into the header it is about to sign, so there is no independent
/// value to check it against.
#[allow(dead_code)]
pub fn publish_block(
    state: &Arc<sumchain_state::state::StateManager>,
    executor: &BlockExecutor,
    height: u64,
    proposer_pubkey: &[u8; 32],
    txs: Vec<SignedTransaction>,
    validators: &[[u8; 32]],
) -> Vec<sumchain_primitives::Receipt> {
    use sumchain_primitives::{Block, BlockHeader, Hash};

    let header = BlockHeader::new(
        Hash::ZERO,
        height,
        1000,
        Hash::ZERO,
        Hash::ZERO,
        *proposer_pubkey,
    );
    let mut block = Block::new(header, txs);

    let exec = executor
        .execute_block(&block, state.state_root(), validators)
        .expect("execute_block");
    block.header.state_root = exec.computed_root();

    let (executed, _state_diff, _contract_diff) = exec.into_parts();
    let receipts = executed.receipts().to_vec();
    let accepted = executed.accept_produced(&block).expect("accept_produced");
    let accumulator = accepted.accumulator();
    accepted.publish().expect("publish");

    // The in-memory accumulator advances only after the commit is durable,
    // which is what the producer does — and it must, or the next block chains
    // from a root that was never published.
    state.set_state_root(accumulator);
    receipts
}

/// Publish one EMPTY block at `height`, the way a proposer does.
///
/// The block-level effects that run regardless of transactions — the one-time
/// supply correction, the beacon boundary snapshot, expired-challenge slashing
/// — happen inside `execute_block`, so a test whose subject is one of those
/// drives it by publishing a block at the right height, not by calling the
/// function and committing what it staged.
#[allow(dead_code)]
pub fn publish_empty_block(
    state: &Arc<sumchain_state::state::StateManager>,
    executor: &BlockExecutor,
    height: u64,
    proposer_pubkey: &[u8; 32],
) {
    publish_block(state, executor, height, proposer_pubkey, Vec::new(), &[]);
}
