//! `subsystem_proof_unsupported_enabled_from_height`: seven `VerifyProof` arms
//! stop reporting success for anything.
//!
//! ACTIVATION-AUDIT rows AU-6, AU-12, AU-17, AU-20, AU-26 and AU-29 — the same
//! six defects Class 5 files as PR-1 to PR-6 — plus the Property `VerifyProof`
//! arm that no audit row names and that PR-7 explicitly denies exists.
//!
//! # Why refusal, and not a verifier
//!
//! A verifier is not implementable from what this tree holds, and that was
//! established from source rather than inherited from the earlier pass:
//!
//!   * no proof system is in the workspace dependency graph — the risc0/sp1
//!     crates exist only under `tools/`, which the root `Cargo.toml` EXCLUDES
//!     from the workspace so it has no dependency edge into production;
//!   * no verifying key, circuit or trusted-setup artefact exists in source,
//!     `configs/`, `genesis.json` or `deploy/`. `b0::verifier_material` holds
//!     LABELS, LENGTHS and HASHES of material that lives somewhere else, and
//!     `ProductionProofEnvelopeV1` carries a `proof_artifact_digest` rather
//!     than any proof bytes — neither is reachable from `crates/state`;
//!   * `crates/sumchain-wire` declares no verification-REQUEST type, so a
//!     `VerifyProof` payload carries no expected public inputs to check a proof
//!     against;
//!   * the `Groth16` and `Plonk` discriminants on the per-subsystem
//!     `ProofType` enums are never matched on anywhere in the tree;
//!   * and `proof_data` / `public_inputs` are read in exactly four non-test
//!     places in the whole workspace, every one of which hashes them into an
//!     identifier and none of which checks one against the other.
//!
//! So there is no successful case in this file, and that is the point rather
//! than a gap: a SUCCESS assertion would require constructing a valid proof
//! independently of the code under test, and "valid" is not defined for any
//! proof this chain accepts.
//!
//! # What the gate replaces
//!
//! `subsystem_proof_presence_enabled_from_height` is RETIRED by this change.
//! It removed two of the three false positives and kept the third: above it, a
//! payload naming a proof the subsystem happened to hold still returned SUCCESS
//! from an operation called `VerifyProof`, and a success receipt from
//! `VerifyProof` is read downstream as "this proof verified". Presence is not
//! verification, so presence must not be REPORTED as verification. The field
//! and its accessor survive — deleting a declared `ChainParams` field would
//! change the activation digest's field set for a gate no chain has ever opened
//! — but nothing on an execution path reads them, which
//! `the_retired_presence_gate_decides_nothing` pins directly. There are not two
//! gates here that disagree about what `VerifyProof` returns; there is one.
//!
//! # The disagreement each case shows
//!
//! Each subsystem gets one `#[test]` that runs the SAME `VerifyProof`
//! transactions against the SAME seeded state twice — once with
//! `proof_unsupported: false`, the release configuration and byte-for-byte the
//! unremediated binary, and once with it true — and asserts the two nodes
//! DISAGREE on all four:
//!
//!   1. **missing proof** — a 32-byte id no submission ever wrote.
//!   2. **malformed payload** — four bytes, which cannot be a proof id.
//!   3. **unrelated proof** — an id the subsystem DOES hold, for a different
//!      subject nullifier and already expired at the block's timestamp.
//!   4. **present but invalid proof** — an id the subsystem DOES hold, whose
//!      envelope declares a proof type and carries an EMPTY `proof_data`. The
//!      invalidity is independent of the code under test: a Groth16 proof is
//!      three group elements and cannot be zero bytes, under any parameters and
//!      any verifying key. Below the gate this is the worst of the four — the
//!      chain reports "verified" for a proof that is not a proof — and the
//!      retired presence check could never have caught it, because the row is
//!      present.
//!
//! The fee is part of the disagreement and is asserted: below the gate there is
//! no refusal, so the sender is charged and the nonce advances; at the gate the
//! refusal returns BEFORE the deduct, which is where the sibling `SubmitProof`
//! arm's duplicate-id refusal returns in every one of these seven, so a refused
//! proof operation costs the same as the other refusals in its own subsystem.
//!
//! Every pair is spelled `{ proof_unsupported: …, ..CLOSED }` rather than
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
use sumchain_primitives::property::{
    PropertyOperation, PropertyProofEnvelope, PropertyProofProfile, PropertyProofType,
    PropertyTxData,
};
use sumchain_primitives::tax::{
    TaxIssuer, TaxIssuerClass, TaxIssuerStatus, TaxOperation, TaxProofEnvelope, TaxProofType,
    TaxTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, EmploymentExecutor, EmploymentGates, FinanceExecutor,
    FinanceGates, HealthcareExecutor, HealthcareGates, LegalExecutor, LegalGates, PropertyExecutor,
    PropertyGates, TaxExecutor, TaxGates, PROOF_ID_BYTES, VERIFY_PROOF_UNSUPPORTED,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The id of the proof each subsystem holds whose `proof_data` is EMPTY.
const INVALID: u8 = 0xA1;

/// The id of a second proof each subsystem holds, about a different subject
/// nullifier and already expired at the block timestamp these tests execute at.
const UNRELATED: u8 = 0xC3;

/// The id nothing ever writes.
const ABSENT: [u8; 32] = [0xB2; 32];

/// A payload that cannot be a proof id, because it is not 32 bytes.
const NOT_AN_ID: &[u8] = b"\xff\xff\xff\xff";

/// The block timestamp every case executes at. Past `UNRELATED`'s expiry and
/// inside `INVALID`'s, so "expired" and "present" are separable facts.
const NOW: u64 = 5_000;

/// `[CLOSED, this gate and only this gate]`, for every subsystem.
///
/// A macro rather than seven hand-written pairs so that the isolation argument
/// is made once. `..CLOSED` is load-bearing: a gate added to any of these
/// structs later must leave the pair differing in exactly one decision, and
/// listing the fields makes that a compile error somebody then fixes by
/// guessing.
macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                proof_unsupported: true,
                ..$g::CLOSED
            },
        ]
    };
}

/// The four `VerifyProof` payloads every subsystem is asked about, in order.
///
/// Written once because the claim is that the seven arms are ONE rule; seven
/// copies of the list would let six drift.
fn the_four_cases() -> [(&'static str, Vec<u8>); 4] {
    [
        ("missing proof", ABSENT.to_vec()),
        ("malformed payload", NOT_AN_ID.to_vec()),
        ("unrelated proof", vec![UNRELATED; PROOF_ID_BYTES]),
        ("present but invalid proof", vec![INVALID; PROOF_ID_BYTES]),
    ]
}

/// What the two nodes must say about one case.
///
/// `outcome` is `(success, nonce_advanced, error)`.
fn assert_the_pair_disagrees(
    subsystem: &str,
    case: &str,
    gate_open: bool,
    outcome: (bool, bool, Option<String>),
) {
    let (success, charged, error) = outcome;
    if gate_open {
        assert!(
            !success,
            "{subsystem}/{case}: at the gate `VerifyProof` must refuse. Nothing \
             in this tree can verify a proof, and an operation that cannot be \
             performed must not return success"
        );
        assert!(
            !charged,
            "{subsystem}/{case}: and the refusal returns before the deduct, \
             where this subsystem's other proof refusal returns"
        );
        assert_eq!(
            error.as_deref(),
            Some(VERIFY_PROOF_UNSUPPORTED),
            "{subsystem}/{case}: the reason must be the shared UNSUPPORTED \
             message. `Proof not found` would carry the implication that a \
             proof which WAS found would have been checked, and none is"
        );
    } else {
        assert!(
            success,
            "{subsystem}/{case}: below the gate this is the false positive \
             being removed — the unremediated binary reports success here, and \
             the two sides must differ"
        );
        assert!(
            charged,
            "{subsystem}/{case}: and below the gate the sender is charged for it"
        );
        assert_eq!(
            error, None,
            "{subsystem}/{case}: below the gate there is no refusal at all"
        );
    }
}

// ── Healthcare — AU-6 (= PR-6) ──────────────────────────────────────────────

#[test]
fn healthcare_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        let envelope = |id: u8, nullifier: u8, expires_at: u64| HealthcareProofEnvelope {
            proof_id: [id; 32],
            profile: HealthcareProofProfile::ConsentValid,
            profile_id: "healthcare.consent_valid.v1".to_string(),
            policy_ids: vec![[12u8; 32]],
            public_inputs: vec![1, 2, 3],
            // EMPTY. A Groth16 proof is three group elements; zero bytes is not
            // one under any parameters or verifying key.
            proof_data: Vec::new(),
            proof_type: HealthcareProofType::Groth16,
            subject_nullifier: [nullifier; 32],
            generated_at: 1_000,
            expires_at,
        };
        for (id, nullifier, expires_at) in [(INVALID, 0x55, 9_000_000), (UNRELATED, 0x66, 2_000)] {
            assert!(
                run(
                    HealthcareOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expires_at)).unwrap()
                )
                .0,
                "the proof must be submittable on both sides -- this gate does \
                 not touch SubmitProof, which checks nothing about the proof either"
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(HealthcareOperation::VerifyProof, payload);
            assert_the_pair_disagrees("healthcare", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Agreement — AU-12 (= PR-5) ──────────────────────────────────────────────

#[test]
fn agreement_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        let envelope = |id: u8, nullifier: u8, expires_at: u64| AgreementProofEnvelope {
            proof_id: [id; 32],
            profile: AgreementProofProfile::SignedByRoles,
            profile_id: "agreement.signed_by_roles.v1".to_string(),
            policy_ids: vec![[12u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: AgreementProofType::Groth16,
            subject_nullifier: [nullifier; 32],
            generated_at: 1_000,
            expires_at,
        };
        for (id, nullifier, expires_at) in [(INVALID, 0x55, 9_000_000), (UNRELATED, 0x66, 2_000)] {
            assert!(
                run(
                    AgreementOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expires_at)).unwrap()
                )
                .0
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(AgreementOperation::VerifyProof, payload);
            assert_the_pair_disagrees("agreement", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Legal — AU-17 (= PR-3) ──────────────────────────────────────────────────

#[test]
fn legal_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        let envelope = |id: u8, nullifier: u8, expires_at: u64| LegalProofEnvelope {
            proof_id: [id; 32],
            profile: LegalProofProfile::BenefitApproved,
            profile_id: "legal.benefit_approved.v1".to_string(),
            policy_ids: vec![[0xF1; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: LegalProofType::Groth16,
            subject_nullifier: [nullifier; 32],
            generated_at: 1_000,
            expires_at,
        };
        for (id, nullifier, expires_at) in [(INVALID, 0xF2, 9_000_000), (UNRELATED, 0xF3, 2_000)] {
            assert!(
                run(
                    LegalOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expires_at)).unwrap()
                )
                .0
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(LegalOperation::VerifyProof, payload);
            assert_the_pair_disagrees("legal", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Property — named by NO audit row, and denied by PR-7 ────────────────────

#[test]
fn property_verify_proof_refuses_as_unsupported() {
    for gates in pair!(PropertyGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |op: PropertyOperation, payload: Vec<u8>| {
            let before = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            let r = PropertyExecutor::execute_with_gates(
                &mut view,
                &sender,
                &PropertyTxData {
                    operation: op,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        let envelope = |id: u8, nullifier: u8, expires_at: u64| PropertyProofEnvelope {
            proof_id: [id; 32],
            profile: PropertyProofProfile::OwnershipProof,
            profile_id: "property.ownership.v1".to_string(),
            policy_ids: vec![[0xE1; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: PropertyProofType::Groth16,
            subject_nullifier: [nullifier; 32],
            generated_at: 1_000,
            expires_at,
        };
        for (id, nullifier, expires_at) in [(INVALID, 0xE2, 9_000_000), (UNRELATED, 0xE3, 2_000)] {
            assert!(
                run(
                    PropertyOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expires_at)).unwrap()
                )
                .0
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(PropertyOperation::VerifyProof, payload);
            assert_the_pair_disagrees("property", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Tax — AU-20 (= PR-1) ────────────────────────────────────────────────────

#[test]
fn tax_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
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

        let envelope = |id: u8, nullifier: u8, expires_at: u64| TaxProofEnvelope {
            proof_id: [id; 32],
            profile_id: "p".to_string(),
            policy_ids: vec![],
            claim_ids: vec![],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: TaxProofType::Groth16,
            subject_nullifier: [nullifier; 32],
            generated_at: 1_000,
            expires_at,
        };
        for (id, nullifier, expires_at) in [(INVALID, 0x33, 9_000_000), (UNRELATED, 0x34, 2_000)] {
            assert!(
                run(
                    TaxOperation::IssueClaim,
                    bincode::serialize(&envelope(id, nullifier, expires_at)).unwrap()
                )
                .0,
                "IssueClaim is the Tax arm that writes a proof row"
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(TaxOperation::VerifyProof, payload);
            assert_the_pair_disagrees("tax", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Finance — AU-26 (= PR-4) ────────────────────────────────────────────────

#[test]
fn finance_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        // Finance's `proof_type` is semantic rather than cryptographic, so the
        // independent invalidity here is the EMPTY `proof_data`: there is no
        // proof system whose proofs are zero bytes.
        let envelope = |id: u8, nullifier: u8, expiry: u64| FinanceProofEnvelope {
            proof_id: [id; 32],
            profile_id: [24u8; 32],
            proof_type: FinanceProofType::KycLevelAchieved,
            subject_nullifier: [nullifier; 32],
            proof_data: Vec::new(),
            public_inputs_commitment: [26u8; 32],
            credential_refs: vec![],
            source_issuer_class: FinanceIssuerClass::RegulatedBank,
            policy_id: [27u8; 32],
            valid_from: 1_000,
            expiry,
            created_at: 1_000,
        };
        for (id, nullifier, expiry) in [(INVALID, 25, 9_000_000), (UNRELATED, 28, 2_000)] {
            assert!(
                run(
                    FinanceOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expiry)).unwrap()
                )
                .0
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(FinanceOperation::VerifyProof, payload);
            assert_the_pair_disagrees("finance", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── Employment — AU-29 (= PR-2) ─────────────────────────────────────────────

#[test]
fn employment_verify_proof_refuses_as_unsupported() {
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
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap();
            let after = sumchain_state::StateManager::v_get_nonce(&view, &sender).unwrap();
            (r.success, after > before, r.error)
        };

        let envelope = |id: u8, nullifier: u8, expiry: u64| EmploymentProofEnvelope {
            proof_id: [id; 32],
            profile_id: [0xD1; 32],
            proof_type: EmploymentProofType::CurrentlyEmployed,
            subject_nullifier: [nullifier; 32],
            proof_data: Vec::new(),
            public_inputs_commitment: [0xD3; 32],
            credential_refs: vec![],
            source_issuer_class: EmploymentIssuerClass::PayrollProcessor,
            policy_id: [0xD4; 32],
            valid_from: 100,
            expiry,
            created_at: 1_000,
        };
        for (id, nullifier, expiry) in [(INVALID, 0xD2, 9_000_000), (UNRELATED, 0xD5, 2_000)] {
            assert!(
                run(
                    EmploymentOperation::SubmitProof,
                    bincode::serialize(&envelope(id, nullifier, expiry)).unwrap()
                )
                .0
            );
        }

        for (case, payload) in the_four_cases() {
            let outcome = run(EmploymentOperation::VerifyProof, payload);
            assert_the_pair_disagrees("employment", case, gates.proof_unsupported, outcome);
        }
    }
}

// ── The supersession ────────────────────────────────────────────────────────

/// One `VerifyProof` transaction under all four combinations of the retired
/// presence height and the live unsupported height.
///
/// Driven through `execute`, which derives the gates from `ChainParams`, so
/// this exercises the WIRING and not a hand-built `Gates` literal.
fn healthcare_verify_proof_under(
    presence: Option<u64>,
    unsupported: Option<u64>,
) -> (bool, Option<String>) {
    let mut p = params();
    p.subsystem_proof_presence_enabled_from_height = presence;
    p.subsystem_proof_unsupported_enabled_from_height = unsupported;

    let (_state, db, _dir, _executor) = setup_with_params(p.clone());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let sender = actor.address();
    let proposer = Address::new([9; 20]);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r = HealthcareExecutor::execute(
        &mut view,
        &p,
        &sender,
        &HealthcareTxData {
            operation: HealthcareOperation::VerifyProof,
            data: ABSENT.to_vec(),
            recipient: Address::ZERO,
        },
        &proposer,
        100,
        1,
        NOW,
        0,
        Hash::ZERO,
    )
    .unwrap();
    (r.success, r.error)
}

/// The retired presence gate decides nothing, at any height, on either side of
/// the gate that replaced it.
///
/// This is the claim that there are not TWO gates here disagreeing about what
/// `VerifyProof` returns. The presence field is still declared, still carried
/// in the activation digest and still pinned to its accessor by
/// `remediation_gates.rs` — deleting a declared field would change the digest's
/// field set for a gate no chain has ever opened — but no execution path reads
/// it, so an operator who sets it gets exactly what they had before.
///
/// It is asserted as an EQUALITY between configurations rather than as a
/// literal outcome on purpose: the value of the presence-open configuration is
/// not something this file endorses, it is something this file pins as
/// unchanged.
#[test]
fn the_retired_presence_gate_decides_nothing() {
    for unsupported in [None, Some(0)] {
        let without = healthcare_verify_proof_under(None, unsupported);
        let with = healthcare_verify_proof_under(Some(0), unsupported);
        assert_eq!(
            without, with,
            "setting subsystem_proof_presence_enabled_from_height must change \
             nothing (unsupported={unsupported:?}); it is retired, and two \
             gates that both decide what VerifyProof returns is the thing this \
             supersession exists to prevent"
        );
    }

    assert!(
        healthcare_verify_proof_under(None, None).0,
        "with the live gate closed the arm is the unremediated binary"
    );
    assert_eq!(
        healthcare_verify_proof_under(None, Some(0)).1.as_deref(),
        Some(VERIFY_PROOF_UNSUPPORTED),
        "and with it open the arm refuses as unsupported"
    );
}

/// A proof one subsystem holds is not a verification in another.
///
/// The strongest form of "unrelated": Healthcare submits a proof, and LEGAL is
/// asked to verify that id. Below the gate Legal reports success for a proof it
/// has never held, which is the false positive at its widest — the retired
/// presence check would have caught this one, and nothing else in this file's
/// four cases is caught by it.
#[test]
fn a_proof_another_subsystem_holds_is_not_a_verification() {
    for gates in [
        (HealthcareGates::CLOSED, LegalGates::CLOSED),
        (
            HealthcareGates::CLOSED,
            LegalGates {
                proof_unsupported: true,
                ..LegalGates::CLOSED
            },
        ),
    ] {
        let (hc_gates, legal_gates) = gates;
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let envelope = HealthcareProofEnvelope {
            proof_id: [INVALID; 32],
            profile: HealthcareProofProfile::ConsentValid,
            profile_id: "healthcare.consent_valid.v1".to_string(),
            policy_ids: vec![[12u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: Vec::new(),
            proof_type: HealthcareProofType::Groth16,
            subject_nullifier: [0x55; 32],
            generated_at: 1_000,
            expires_at: 9_000_000,
        };
        assert!(
            HealthcareExecutor::execute_with_gates(
                &mut view,
                &sender,
                &HealthcareTxData {
                    operation: HealthcareOperation::SubmitProof,
                    data: bincode::serialize(&envelope).unwrap(),
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                hc_gates,
            )
            .unwrap()
            .success
        );

        let r = LegalExecutor::execute_with_gates(
            &mut view,
            &sender,
            &LegalTxData {
                operation: LegalOperation::VerifyProof,
                data: vec![INVALID; PROOF_ID_BYTES],
                recipient: Address::ZERO,
            },
            &proposer,
            100,
            1,
            NOW,
            0,
            Hash::ZERO,
            legal_gates,
        )
        .unwrap();

        if legal_gates.proof_unsupported {
            assert!(!r.success, "Legal must refuse Healthcare's proof id");
            assert_eq!(r.error.as_deref(), Some(VERIFY_PROOF_UNSUPPORTED));
        } else {
            assert!(
                r.success,
                "below the gate Legal reports success for a proof it has never held"
            );
        }
    }
}

/// The refusal says UNSUPPORTED, and does not say `not found`.
///
/// The distinction is the whole remedy. "Not found" is a claim about the
/// chain's contents and carries the implication that a proof which WAS found
/// would have been checked. Nothing in this tree checks one, so the refusal has
/// to be about the OPERATION rather than about the argument.
#[test]
fn the_refusal_is_about_the_operation_and_not_about_the_argument() {
    let m = VERIFY_PROOF_UNSUPPORTED.to_ascii_lowercase();
    assert!(
        m.contains("unsupported"),
        "the reason must name the operation as unsupported: {VERIFY_PROOF_UNSUPPORTED}"
    );
    assert!(
        !m.contains("not found") && !m.contains("does not exist"),
        "the reason must not be about whether the named proof is present: \
         {VERIFY_PROOF_UNSUPPORTED}"
    );
    assert!(
        m.contains("verifier"),
        "and it must say what is missing -- a verifier -- rather than only that \
         the operation failed: {VERIFY_PROOF_UNSUPPORTED}"
    );
}
