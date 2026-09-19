//! `subsystem_proof_presence_enabled_from_height`: six `VerifyProof` arms stop
//! reporting success for a proof the chain does not hold.
//!
//! ACTIVATION-AUDIT rows AU-6, AU-12, AU-17, AU-20, AU-26 and AU-29 — the same
//! six defects Class 5 files as PR-1 to PR-6.
//!
//! # What this gate does NOT do
//!
//! It does not verify a proof, and nothing here claims it does. No proof
//! verifier exists anywhere in this tree: nothing consumes `proof_data` against
//! `public_inputs`, in any subsystem. The audit's finding is "verifies
//! nothing", and above this gate that sentence is still true.
//!
//! What changes is the FALSE POSITIVE. Below the gate the six arms are
//! character-for-character identical — deduct, credit, increment, `success()`
//! — and the payload is never read, so `VerifyProof` returns a success receipt
//! for a proof id that was never submitted and for a payload that is not an id
//! at all. A relying party reading receipts cannot distinguish "this proof
//! exists and was checked" from "these four bytes are not a proof id". Above
//! the gate it can: the payload must be the 32 bytes of a proof id, and that
//! proof must be present in the subsystem's own proof family.
//!
//! # The disagreement each case shows
//!
//! Each subsystem gets one `#[test]` that runs the SAME three transactions
//! against the SAME seeded state twice, once with `proof_presence: false` — the
//! release configuration, and byte-for-byte the unremediated binary — and once
//! with it true, and asserts the two nodes DISAGREE:
//!
//!   1. `VerifyProof` naming a proof that was submitted: success on BOTH sides.
//!      The gate must not break the case that was always meant to work.
//!   2. `VerifyProof` naming an id no `SubmitProof` ever wrote: success below
//!      the gate, FAILURE at it.
//!   3. `VerifyProof` whose payload is not 32 bytes at all: success below the
//!      gate, FAILURE at it.
//!
//! The fee is part of the disagreement and is asserted: below the gate the
//! refusal does not exist, so the sender is charged and the nonce advances; at
//! the gate the refusal returns BEFORE the deduct, which is where the sibling
//! `SubmitProof` arm's duplicate-id refusal returns in every one of these six,
//! so a refused proof operation costs the same as the other refusals in its own
//! subsystem.
//!
//! Every pair is spelled `{ proof_presence: …, ..CLOSED }` rather than
//! `CLOSED`/`OPEN`: `OPEN` also opens the authorization and timestamp gates,
//! and a pair that differs in three ways cannot attribute a difference to one
//! of them.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementOperation, AgreementProofEnvelope, AgreementProofProfile, AgreementProofType,
    AgreementTxData,
};
use sumchain_primitives::employment::{
    EmploymentIssuerClass, EmploymentOperation, EmploymentProofEnvelope, EmploymentProofType,
    EmploymentTxData,
};
use sumchain_primitives::finance::{
    FinanceIssuerClass, FinanceOperation, FinanceProofEnvelope, FinanceProofType, FinanceTxData,
};
use sumchain_primitives::healthcare::{
    HealthcareOperation, HealthcareProofEnvelope, HealthcareProofProfile, HealthcareProofType,
    HealthcareTxData,
};
use sumchain_primitives::legal::{
    LegalOperation, LegalProofEnvelope, LegalProofProfile, LegalProofType, LegalTxData,
};
use sumchain_primitives::tax::{
    TaxIssuer, TaxIssuerClass, TaxIssuerStatus, TaxOperation, TaxProofEnvelope, TaxProofType,
    TaxTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, EmploymentExecutor, EmploymentGates, FinanceExecutor,
    FinanceGates, HealthcareExecutor, HealthcareGates, LegalExecutor, LegalGates, TaxExecutor,
    TaxGates, PROOF_ID_BYTES,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The id a `SubmitProof` writes in each case, and the id nothing ever writes.
const PRESENT: u8 = 0xA1;
const ABSENT: [u8; 32] = [0xB2; 32];

/// A payload that cannot be a proof id, because it is not 32 bytes.
///
/// Four bytes, which is what `verify_proof_succeeds_for_a_proof_that_does_not_exist`
/// in `healthcare_routing.rs` already submits and which that test still
/// accepts, because that test drives `execute_tx` and the release `ChainParams`
/// leaves this gate closed.
const NOT_AN_ID: &[u8] = b"\xff\xff\xff\xff";

/// `[CLOSED, this gate and only this gate]`, for every subsystem.
///
/// A macro rather than six hand-written pairs so that the isolation argument is
/// made once. `..CLOSED` is load-bearing: a gate added to any of these structs
/// later must leave the pair differing in exactly one decision, and listing the
/// fields makes that a compile error somebody then fixes by guessing.
macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                proof_presence: true,
                ..$g::CLOSED
            },
        ]
    };
}

/// The three assertions every subsystem makes, given a driver that returns
/// `(success, nonce_advanced)` for one `VerifyProof` payload.
///
/// Written once because the claim is that the six arms are ONE rule; six
/// copies of it would let five drift.
fn assert_the_pair_disagrees(
    subsystem: &str,
    gate_open: bool,
    present: (bool, bool),
    absent: (bool, bool),
    malformed: (bool, bool),
) {
    assert!(
        present.0,
        "{subsystem}: verifying a proof that WAS submitted must succeed on both \
         sides of the gate; it failed with proof_presence={gate_open}"
    );
    assert!(
        present.1,
        "{subsystem}: and must charge for it on both sides"
    );

    assert_eq!(
        absent.0, !gate_open,
        "{subsystem}: VerifyProof for an id no SubmitProof ever wrote reports \
         success below the gate and must refuse at it (proof_presence={gate_open})"
    );
    assert_eq!(
        absent.1, !gate_open,
        "{subsystem}: and the refusal returns before the deduct, where this \
         subsystem's other proof refusal returns (proof_presence={gate_open})"
    );

    assert_eq!(
        malformed.0, !gate_open,
        "{subsystem}: VerifyProof for a payload that is not a {PROOF_ID_BYTES}-byte \
         id reports success below the gate and must refuse at it \
         (proof_presence={gate_open})"
    );
    assert_eq!(
        malformed.1, !gate_open,
        "{subsystem}: and that refusal is free too (proof_presence={gate_open})"
    );
}

// ── Healthcare — AU-6 (= PR-6) ──────────────────────────────────────────────

#[test]
fn healthcare_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(HealthcareGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: HealthcareOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = HealthcareExecutor::execute_with_gates(
                &mut view,
                &sender,
                &HealthcareTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        let envelope = HealthcareProofEnvelope {
            proof_id: [PRESENT; 32],
            profile: HealthcareProofProfile::ConsentValid,
            profile_id: "healthcare.consent_valid.v1".to_string(),
            policy_ids: vec![[12u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: vec![4u8; 48],
            proof_type: HealthcareProofType::Mock,
            subject_nullifier: [0x55; 32],
            generated_at: 1000,
            expires_at: 9_000_000,
        };
        assert!(
            run(
                HealthcareOperation::SubmitProof,
                bincode::serialize(&envelope).unwrap()
            )
            .0,
            "the proof must be submittable on both sides -- this gate does not touch SubmitProof"
        );

        let present = run(HealthcareOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(HealthcareOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(HealthcareOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees(
            "healthcare",
            gates.proof_presence,
            present,
            absent,
            malformed,
        );
    }
}

// ── Agreement — AU-12 (= PR-5) ──────────────────────────────────────────────

#[test]
fn agreement_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(AgreementGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: AgreementOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = AgreementExecutor::execute_with_gates(
                &mut view,
                &sender,
                &AgreementTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        let envelope = AgreementProofEnvelope {
            proof_id: [PRESENT; 32],
            profile: AgreementProofProfile::SignedByRoles,
            profile_id: "agreement.signed_by_roles.v1".to_string(),
            policy_ids: vec![[12u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: vec![4u8; 48],
            proof_type: AgreementProofType::Mock,
            subject_nullifier: [0x55; 32],
            generated_at: 1000,
            expires_at: 9_000_000,
        };
        assert!(
            run(
                AgreementOperation::SubmitProof,
                bincode::serialize(&envelope).unwrap()
            )
            .0
        );

        let present = run(AgreementOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(AgreementOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(AgreementOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees("agreement", gates.proof_presence, present, absent, malformed);
    }
}

// ── Legal — AU-17 (= PR-3) ──────────────────────────────────────────────────

#[test]
fn legal_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(LegalGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: LegalOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = LegalExecutor::execute_with_gates(
                &mut view,
                &sender,
                &LegalTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        let envelope = LegalProofEnvelope {
            proof_id: [PRESENT; 32],
            profile: LegalProofProfile::BenefitApproved,
            profile_id: "legal.benefit_approved.v1".to_string(),
            policy_ids: vec![[0xF1; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: vec![4, 5, 6],
            proof_type: LegalProofType::Groth16,
            subject_nullifier: [0xF2; 32],
            generated_at: 1_000,
            expires_at: 9_000,
        };
        assert!(
            run(
                LegalOperation::SubmitProof,
                bincode::serialize(&envelope).unwrap()
            )
            .0
        );

        let present = run(LegalOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(LegalOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(LegalOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees("legal", gates.proof_presence, present, absent, malformed);
    }
}

// ── Tax — AU-20 (= PR-1) ────────────────────────────────────────────────────

#[test]
fn tax_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(TaxGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: TaxOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = TaxExecutor::execute_with_gates(
                &mut view,
                &sender,
                &TaxTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        // Tax writes its proof row from `IssueClaim`, which needs a registered
        // active issuer first.
        let issuer = TaxIssuer {
            address: sender,
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [0u8; 32],
            attributes_schema_hash: [0u8; 32],
            registered_at: 1_000,
            updated_at: 1_000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };
        assert!(
            run(
                TaxOperation::RegisterIssuer,
                bincode::serialize(&issuer).unwrap()
            )
            .0,
            "the issuer must register on both sides"
        );

        let envelope = TaxProofEnvelope {
            proof_id: [PRESENT; 32],
            profile_id: "p".to_string(),
            policy_ids: vec![],
            claim_ids: vec![],
            public_inputs: vec![],
            proof_data: vec![7],
            proof_type: TaxProofType::Groth16,
            subject_nullifier: [0x33; 32],
            generated_at: 1_000,
            expires_at: 2_000,
        };
        assert!(
            run(
                TaxOperation::IssueClaim,
                bincode::serialize(&envelope).unwrap()
            )
            .0,
            "IssueClaim is the Tax arm that writes a proof row"
        );

        let present = run(TaxOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(TaxOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(TaxOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees("tax", gates.proof_presence, present, absent, malformed);
    }
}

// ── Finance — AU-26 (= PR-4) ────────────────────────────────────────────────

#[test]
fn finance_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(FinanceGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: FinanceOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = FinanceExecutor::execute_with_gates(
                &mut view,
                &sender,
                &FinanceTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        let envelope = FinanceProofEnvelope {
            proof_id: [PRESENT; 32],
            profile_id: [24u8; 32],
            proof_type: FinanceProofType::KycLevelAchieved,
            subject_nullifier: [25u8; 32],
            proof_data: vec![9, 9, 9],
            public_inputs_commitment: [26u8; 32],
            credential_refs: vec![],
            source_issuer_class: FinanceIssuerClass::RegulatedBank,
            policy_id: [27u8; 32],
            valid_from: 1_000,
            expiry: 2_000,
            created_at: 1_000,
        };
        assert!(
            run(
                FinanceOperation::SubmitProof,
                bincode::serialize(&envelope).unwrap()
            )
            .0
        );

        let present = run(FinanceOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(FinanceOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(FinanceOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees("finance", gates.proof_presence, present, absent, malformed);
    }
}

// ── Employment — AU-29 (= PR-2) ─────────────────────────────────────────────

#[test]
fn employment_verify_proof_stops_succeeding_for_a_proof_that_does_not_exist() {
    for gates in pair!(EmploymentGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: EmploymentOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = EmploymentExecutor::execute_with_gates(
                &mut view,
                &sender,
                &EmploymentTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before)
        };

        let envelope = EmploymentProofEnvelope {
            proof_id: [PRESENT; 32],
            profile_id: [0xD1; 32],
            proof_type: EmploymentProofType::CurrentlyEmployed,
            subject_nullifier: [0xD2; 32],
            proof_data: vec![7, 7, 7],
            public_inputs_commitment: [0xD3; 32],
            credential_refs: vec![],
            source_issuer_class: EmploymentIssuerClass::PayrollProcessor,
            policy_id: [0xD4; 32],
            valid_from: 100,
            expiry: 1_000_000,
            created_at: 1_000,
        };
        assert!(
            run(
                EmploymentOperation::SubmitProof,
                bincode::serialize(&envelope).unwrap()
            )
            .0
        );

        let present = run(EmploymentOperation::VerifyProof, vec![PRESENT; 32]);
        let absent = run(EmploymentOperation::VerifyProof, ABSENT.to_vec());
        let malformed = run(EmploymentOperation::VerifyProof, NOT_AN_ID.to_vec());
        assert_the_pair_disagrees(
            "employment",
            gates.proof_presence,
            present,
            absent,
            malformed,
        );
    }
}
