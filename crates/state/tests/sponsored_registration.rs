//! Consensus-path tests for `RegisterPublicKeySponsoredV1` (sum-chain #145).
//!
//! These exercise the FULL consensus path through `BlockExecutor::execute_tx`
//! for `TxPayload::Messaging` with the sponsored-registration operation, and
//! assert on both the returned `TxStatus` AND the observable side-effects
//! (sponsor balance, proposer balance, sponsor nonce, and the
//! `MESSAGING_PUBLIC_KEYS` CF for the *registrant*, never the sponsor).
//!
//! Coverage (§9): a valid sponsor + valid registrant signature registers the
//! REGISTRANT (not the sponsor); the sponsor pays per the established
//! fee/nonce rules; a wrong registrant signature / public-key substitution /
//! sponsor substitution / cross-chain replay all reject with NO registration
//! write and NO fee; the closed gate and pre-activation height reject free; the
//! activation-height boundary succeeds; duplicate registration follows the
//! existing `RegisterPublicKey` semantics; malformed payloads and invalid
//! public keys reject with distinct codes; two independent validators executing
//! the identical transaction produce byte-identical receipts and post-state;
//! and a regression reproduces the former node-local-write fork.

mod common;

use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    sponsored_register_v1_signing_preimage, Address, MessagingOperation, MessagingTxData,
    RegisterPublicKeySponsoredV1Data, RegisteredPublicKey, SignedTransaction, TransactionV2,
    TxStatus,
};
use sumchain_state::state::StateManager;
use sumchain_storage::{cf, Database, MessagingStore};

const FEE: u128 = 1_000_000;

/// ChainParams with the sponsored-registration gate open from height 0.
fn params_gate_open() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging_sponsored_registration_enabled_from_height = Some(0);
    p
}

/// ChainParams with the gate open only from `h`.
fn params_gate_from(h: u64) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging_sponsored_registration_enabled_from_height = Some(h);
    p
}

/// Build a signed sponsored-registration tx. `preimage_chain_id` /
/// `preimage_sponsor` let a test deliberately sign the WRONG binding (cross-
/// chain replay / sponsor substitution); pass `CHAIN_ID` and `sponsor.address()`
/// for the honest case. `mutate` gets the payload before it is serialized so a
/// test can corrupt the signature or swap the public key.
fn build_tx(
    sponsor: &KeyPair,
    registrant: &KeyPair,
    nonce: u64,
    preimage_chain_id: u64,
    preimage_sponsor: &Address,
    mutate: impl FnOnce(&mut RegisterPublicKeySponsoredV1Data),
) -> SignedTransaction {
    let registrant_public_key = *registrant.public_key().as_bytes();
    let preimage = sponsored_register_v1_signing_preimage(
        preimage_chain_id,
        preimage_sponsor,
        &registrant_public_key,
    );
    let registrant_signature = *sign(&preimage, registrant.private_key()).as_bytes();
    let mut reg = RegisterPublicKeySponsoredV1Data {
        registrant_public_key,
        registrant_signature,
    };
    mutate(&mut reg);
    let messaging_data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: reg.to_bytes(),
    };
    // Outer tx: sponsor is `from`, uses the real chain id.
    let tx = TransactionV2::messaging(CHAIN_ID, sponsor.address(), FEE, nonce, messaging_data);
    let outer_hash = tx.signing_hash();
    let outer_sig = sign(outer_hash.as_bytes(), sponsor.private_key());
    SignedTransaction::new_v2(tx, *outer_sig.as_bytes(), *sponsor.public_key().as_bytes())
}

/// Honest tx: registrant signs the correct (CHAIN_ID, sponsor) binding.
fn honest_tx(sponsor: &KeyPair, registrant: &KeyPair, nonce: u64) -> SignedTransaction {
    let sponsor_addr = sponsor.address();
    build_tx(sponsor, registrant, nonce, CHAIN_ID, &sponsor_addr, |_| {})
}

fn stored_key(db: &Database, addr: &Address) -> Option<RegisteredPublicKey> {
    MessagingStore::new(db).get_public_key(addr).unwrap()
}

fn has_key(db: &Database, addr: &Address) -> bool {
    MessagingStore::new(db).has_public_key(addr).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────

#[test]
fn valid_registers_registrant_not_sponsor_and_sponsor_pays() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let tx = honest_tx(&sponsor, &registrant, 0);
    let res = executor
        .execute_tx(&tx, &proposer.address(), 1, 123)
        .unwrap();

    assert!(
        matches!(res.status, TxStatus::Success),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, FEE);

    // The REGISTRANT is registered — never the sponsor.
    assert!(
        has_key(&db, &registrant.address()),
        "registrant must be registered"
    );
    assert!(
        !has_key(&db, &sponsor.address()),
        "sponsor must NOT be registered"
    );
    let record = stored_key(&db, &registrant.address()).unwrap();
    assert_eq!(record.public_key, *registrant.public_key().as_bytes());
    assert_eq!(record.address, registrant.address());
    assert_eq!(record.registered_at_block, 1);
    assert_eq!(record.registered_at, 123);
    assert_eq!(record.updated_at_block, 0);

    // Sponsor pays per established fee/nonce rules; registrant is untouched.
    assert_eq!(
        state.get_balance(&sponsor.address()).unwrap(),
        100 * FEE - FEE
    );
    assert_eq!(
        state.get_balance(&proposer.address()).unwrap(),
        FEE,
        "proposer credited"
    );
    assert_eq!(
        state.get_nonce(&sponsor.address()).unwrap(),
        1,
        "sponsor nonce advances"
    );
    assert_eq!(
        state.get_nonce(&registrant.address()).unwrap(),
        0,
        "registrant nonce untouched"
    );
    assert_eq!(
        state.get_balance(&registrant.address()).unwrap(),
        0,
        "registrant balance untouched"
    );
}

#[test]
fn wrong_registrant_signature_rejects_no_write_no_fee() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let sponsor_addr = sponsor.address();
    // Corrupt one byte of the registrant signature.
    let tx = build_tx(&sponsor, &registrant, 0, CHAIN_ID, &sponsor_addr, |d| {
        d.registrant_signature[0] ^= 0xff;
    });
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(res.status, TxStatus::Failed(391)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
    assert!(
        !has_key(&db, &registrant.address()),
        "no registration on bad sig"
    );
    assert_eq!(
        state.get_balance(&sponsor.address()).unwrap(),
        100 * FEE,
        "no fee charged"
    );
    assert_eq!(
        state.get_nonce(&sponsor.address()).unwrap(),
        0,
        "no nonce advance"
    );
}

#[test]
fn public_key_substitution_rejects() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let attacker = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let sponsor_addr = sponsor.address();
    // Registrant signs for its own key; attacker swaps in a different pubkey.
    let tx = build_tx(&sponsor, &registrant, 0, CHAIN_ID, &sponsor_addr, |d| {
        d.registrant_public_key = *attacker.public_key().as_bytes();
    });
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(res.status, TxStatus::Failed(391)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
    assert!(!has_key(&db, &attacker.address()));
    assert!(!has_key(&db, &registrant.address()));
}

#[test]
fn sponsor_substitution_rejects() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let other_sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    // Registrant signed a preimage bound to `other_sponsor`, but the tx is
    // submitted (and paid) by `sponsor` — the executor rebuilds the preimage
    // from tx.from = sponsor, so verification fails.
    let other_addr = other_sponsor.address();
    let tx = build_tx(&sponsor, &registrant, 0, CHAIN_ID, &other_addr, |_| {});
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(res.status, TxStatus::Failed(391)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
    assert!(!has_key(&db, &registrant.address()));
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 100 * FEE);
}

#[test]
fn cross_chain_replay_rejects() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    // Registrant signed a preimage bound to chain_id 999; this chain is CHAIN_ID.
    let sponsor_addr = sponsor.address();
    let tx = build_tx(&sponsor, &registrant, 0, 999, &sponsor_addr, |_| {});
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(res.status, TxStatus::Failed(391)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
    assert!(!has_key(&db, &registrant.address()));
}

#[test]
fn invalid_registrant_public_key_rejects_393() {
    let (state, _db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let sponsor_addr = sponsor.address();
    // `[0x02; 32]` is not a valid Ed25519 point → distinct malformed-key code.
    let tx = build_tx(&sponsor, &registrant, 0, CHAIN_ID, &sponsor_addr, |d| {
        d.registrant_public_key = [0x02; 32];
    });
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();
    assert!(
        matches!(res.status, TxStatus::Failed(393)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
}

#[test]
fn malformed_payload_rejects_392() {
    let (state, _db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    // Payload is not a valid RegisterPublicKeySponsoredV1Data (too short).
    let messaging_data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: vec![0u8; 10],
    };
    let tx = TransactionV2::messaging(CHAIN_ID, sponsor.address(), FEE, 0, messaging_data);
    let outer_hash = tx.signing_hash();
    let outer_sig = sign(outer_hash.as_bytes(), sponsor.private_key());
    let signed =
        SignedTransaction::new_v2(tx, *outer_sig.as_bytes(), *sponsor.public_key().as_bytes());

    let res = executor
        .execute_tx(&signed, &proposer.address(), 1, 0)
        .unwrap();
    assert!(
        matches!(res.status, TxStatus::Failed(392)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
}

#[test]
fn trailing_bytes_payload_rejects_392() {
    // The strict decoder rejects trailing bytes — a distinct malformed case.
    let (state, _db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let registrant_public_key = *registrant.public_key().as_bytes();
    let sponsor_addr = sponsor.address();
    let preimage =
        sponsored_register_v1_signing_preimage(CHAIN_ID, &sponsor_addr, &registrant_public_key);
    let reg = RegisterPublicKeySponsoredV1Data {
        registrant_public_key,
        registrant_signature: *sign(&preimage, registrant.private_key()).as_bytes(),
    };
    let mut data = reg.to_bytes();
    data.push(0x00); // trailing byte

    let messaging_data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data,
    };
    let tx = TransactionV2::messaging(CHAIN_ID, sponsor.address(), FEE, 0, messaging_data);
    let outer_hash = tx.signing_hash();
    let outer_sig = sign(outer_hash.as_bytes(), sponsor.private_key());
    let signed =
        SignedTransaction::new_v2(tx, *outer_sig.as_bytes(), *sponsor.public_key().as_bytes());

    let res = executor
        .execute_tx(&signed, &proposer.address(), 1, 0)
        .unwrap();
    assert!(
        matches!(res.status, TxStatus::Failed(392)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
}

#[test]
fn closed_gate_rejects_free_390() {
    // Default params: gate is None → closed at every height.
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let tx = honest_tx(&sponsor, &registrant, 0);
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 0).unwrap();

    assert!(
        matches!(res.status, TxStatus::Failed(390)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0, "closed gate is free");
    assert!(!has_key(&db, &registrant.address()));
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 100 * FEE);
    assert_eq!(state.get_nonce(&sponsor.address()).unwrap(), 0);
}

#[test]
fn pre_activation_height_rejects_free_390() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_from(100));
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let tx = honest_tx(&sponsor, &registrant, 0);
    // Height 50 < activation 100.
    let res = executor
        .execute_tx(&tx, &proposer.address(), 50, 0)
        .unwrap();
    assert!(
        matches!(res.status, TxStatus::Failed(390)),
        "got {:?}",
        res.status
    );
    assert_eq!(res.fee_paid, 0);
    assert!(!has_key(&db, &registrant.address()));
    assert_eq!(state.get_balance(&sponsor.address()).unwrap(), 100 * FEE);
}

#[test]
fn activation_height_boundary_succeeds() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_from(100));
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    let tx = honest_tx(&sponsor, &registrant, 0);
    // Height exactly at activation 100 → open.
    let res = executor
        .execute_tx(&tx, &proposer.address(), 100, 0)
        .unwrap();
    assert!(
        matches!(res.status, TxStatus::Success),
        "got {:?}",
        res.status
    );
    assert!(has_key(&db, &registrant.address()));
}

#[test]
fn duplicate_registration_rejects_394() {
    let (state, db, _dir, executor) = setup_with_params(params_gate_open());
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &sponsor, 100 * FEE);

    // First registration succeeds (nonce 0).
    let tx0 = honest_tx(&sponsor, &registrant, 0);
    assert!(matches!(
        executor
            .execute_tx(&tx0, &proposer.address(), 1, 0)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    let bal_after_first = state.get_balance(&sponsor.address()).unwrap();

    // Second registration of the SAME registrant (nonce 1) → duplicate, free.
    let tx1 = honest_tx(&sponsor, &registrant, 1);
    let res = executor
        .execute_tx(&tx1, &proposer.address(), 2, 0)
        .unwrap();
    assert!(
        matches!(res.status, TxStatus::Failed(394)),
        "got {:?}",
        res.status
    );
    assert_eq!(
        res.fee_paid, 0,
        "duplicate is a free rejection (existing RegisterPublicKey semantics)"
    );
    assert_eq!(
        state.get_balance(&sponsor.address()).unwrap(),
        bal_after_first,
        "no extra fee on duplicate"
    );
    // The stored record is unchanged from the first registration.
    assert!(has_key(&db, &registrant.address()));
}

#[test]
fn two_validators_identical_tx_produce_identical_receipts_and_poststate() {
    // Two INDEPENDENT validators (separate DBs) execute the byte-identical
    // signed transaction and must agree on the receipt AND the post-state.
    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let proposer = KeyPair::generate();
    let tx = honest_tx(&sponsor, &registrant, 0);

    let run = || {
        let (state, db, dir, executor) = setup_with_params(params_gate_open());
        fund(&state, &sponsor, 100 * FEE);
        let res = executor
            .execute_tx(&tx, &proposer.address(), 7, 999)
            .unwrap();
        // Raw on-disk CF bytes are the strongest post-state evidence.
        let record_bytes = db
            .get(cf::MESSAGING_PUBLIC_KEYS, registrant.address().as_bytes())
            .unwrap();
        let sponsor_bal = state.get_balance(&sponsor.address()).unwrap();
        let proposer_bal = state.get_balance(&proposer.address()).unwrap();
        let sponsor_nonce = state.get_nonce(&sponsor.address()).unwrap();
        drop(dir);
        (
            res.status,
            res.fee_paid,
            record_bytes,
            sponsor_bal,
            proposer_bal,
            sponsor_nonce,
        )
    };

    let a = run();
    let b = run();
    assert_eq!(a.0, b.0, "status must match");
    assert_eq!(a.1, b.1, "fee_paid must match");
    assert_eq!(a.2, b.2, "stored registrant record bytes must be identical");
    assert_eq!((a.3, a.4, a.5), (b.3, b.4, b.5), "post-state must match");
    assert!(matches!(a.0, TxStatus::Success));
    assert!(a.2.is_some(), "record must be present on both");
}

#[test]
fn regression_node_local_write_forks_but_consensus_path_converges() {
    // Reproduces WHY the former RPC direct-write forked: a node-local
    // `set_public_key` on ONE validator makes the `has_public_key(...)`
    // predicate — the exact branch a later sponsored SEND keys off
    // (messaging_executor.rs) — diverge between validators, so the SAME
    // subsequent tx would take different branches → different state roots.
    let registrant = KeyPair::generate();
    let record = RegisteredPublicKey {
        public_key: *registrant.public_key().as_bytes(),
        address: registrant.address(),
        registered_at_block: 1,
        registered_at: 0,
        updated_at_block: 0,
    };

    // Validator A: OLD bug — RPC wrote directly to the messaging CF (node-local,
    // not block-ordered). Validator B never saw that RPC call.
    let (_sa, db_a, _da, _ea) = setup_with_params(params_gate_open());
    let (_sb, db_b, _db_, _eb) = setup_with_params(params_gate_open());
    MessagingStore::new(&db_a)
        .set_public_key(&registrant.address(), &record)
        .unwrap();

    assert!(
        has_key(&db_a, &registrant.address()),
        "A has the node-local write"
    );
    assert!(
        !has_key(&db_b, &registrant.address()),
        "B does not — DIVERGENCE (fork seed)"
    );

    // THE FIX: registration flows through consensus execution of an identical
    // RegisterPublicKeySponsoredV1 tx on BOTH validators, so both converge on
    // byte-identical registrant state.
    let sponsor = KeyPair::generate();
    let proposer = KeyPair::generate();
    let tx = honest_tx(&sponsor, &registrant, 0);

    let converge = |db: &Arc<Database>,
                    state: &Arc<StateManager>,
                    executor: &sumchain_state::executor::BlockExecutor| {
        fund(state, &sponsor, 100 * FEE);
        let res = executor
            .execute_tx(&tx, &proposer.address(), 1, 42)
            .unwrap();
        assert!(matches!(res.status, TxStatus::Success));
        bincode::serialize(&stored_key(db, &registrant.address()).unwrap()).unwrap()
    };

    let (sc, db_c, _dc, ec) = setup_with_params(params_gate_open());
    let (sd, db_d, _dd, ed) = setup_with_params(params_gate_open());
    let rec_c = converge(&db_c, &sc, &ec);
    let rec_d = converge(&db_d, &sd, &ed);
    assert_eq!(
        rec_c, rec_d,
        "consensus execution converges on identical state across validators"
    );
}

#[test]
fn defensive_generic_executor_arm_fails_closed() {
    // The generic MessagingExecutor::execute() is never reached for this op in
    // production (dispatch intercepts it). If a caller bypasses the dispatch,
    // the arm must fail closed rather than execute an ungated registration.
    use sumchain_state::MessagingExecutor;
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let exec = MessagingExecutor::new(db.clone(), params_gate_open());

    let sponsor = KeyPair::generate();
    let registrant = KeyPair::generate();
    let sponsor_addr = sponsor.address();
    let registrant_public_key = *registrant.public_key().as_bytes();
    let preimage =
        sponsored_register_v1_signing_preimage(CHAIN_ID, &sponsor_addr, &registrant_public_key);
    let reg = RegisterPublicKeySponsoredV1Data {
        registrant_public_key,
        registrant_signature: *sign(&preimage, registrant.private_key()).as_bytes(),
    };
    let data = MessagingTxData {
        operation: MessagingOperation::RegisterPublicKeySponsoredV1,
        data: reg.to_bytes(),
    };
    let res = exec
        .execute(
            &sponsor.address(),
            &data,
            &state,
            &Address::ZERO,
            FEE,
            1,
            0,
            0,
            sumchain_primitives::Hash::hash(b"x"),
        )
        .unwrap();
    assert!(
        !res.success,
        "generic messaging executor must fail closed for the sponsored op"
    );
    assert!(
        !has_key(&db, &registrant.address()),
        "no write on the defensive path"
    );
}
