//! `subsystem_no_op_receipt_enabled_from_height`: an operation that writes
//! nothing stops reporting success.
//!
//! ACTIVATION-AUDIT rows OV-6, OV-25 and OV-30.
//!
//! # Why one height for three subsystems
//!
//! On the `subsystem_block_timestamp_enabled_from_height` argument, not the
//! per-subsystem authorization one. It is a single rule about what a RECEIPT
//! means, the three bodies are the same shape — deduct, credit, increment,
//! `success()`, with no write of the row the operation names — and the blast
//! radius is identical on all three sides: a success receipt becomes a failed
//! one, and none of them can abort a block. An operator who activated one of
//! the three would be running a chain where a success receipt means "the
//! operation happened" in Legal and "the fee was taken" in Agreement, which is
//! a new inconsistency rather than a partial fix of an old one.
//!
//! # What this is NOT
//!
//! It is a failed receipt, not an implementation. `AddParty` still does not add
//! a party and `UpdateCredential` still does not update a credential: neither
//! subsystem defines what that would mean — `UpdateCredential`'s payload
//! carries nothing but a credential id, so there is no field for an update to
//! apply — and inventing a semantics inside an executor would be a rule nobody
//! set. What the gate removes is the receipt claiming an absent effect
//! happened.
//!
//! # What each pair shows
//!
//! Each case runs the SAME transaction against the SAME seeded state twice,
//! once with `no_op_receipt: false` — the release configuration, and
//! byte-for-byte the unremediated binary — and once with it true, and asserts
//! the two nodes disagree on the receipt AND on the fee. Below the gate the
//! no-op is paid for; at the gate the refusal returns before the deduct, which
//! is where each arm's own existence and authorization refusals already return.
//!
//! The Legal case additionally asserts the thing that makes OV-6 a no-op rather
//! than a redundant write: below the gate the repeated consolidation leaves the
//! PRIMARY case row byte-for-byte unchanged, because `v_add_related_case` skips
//! the append and the `updated_at` write together.
//!
//! Every pair is spelled `{ no_op_receipt: …, ..CLOSED }`: `OPEN` would also
//! move the authorization and timestamp decisions, and a pair differing in
//! several ways cannot attribute a difference to one of them.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{AgreementOperation, AgreementTxData};
use sumchain_primitives::docclass::{
    DocClassOperation, DocClassTxData, DocSubcode, EligibilityAttestation, EligibilityType,
    RevocationStatus,
};
use sumchain_primitives::legal::{
    CaseAnchor, CaseStatus, CaseType, LegalIssuerClass, LegalOperation, LegalTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, DocClassExecutor, DocClassGates, LegalExecutor, LegalGates,
    StateManager,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::DocClassStore;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                no_op_receipt: true,
                ..$g::CLOSED
            },
        ]
    };
}

// ── OV-6: Legal, a repeated consolidation ───────────────────────────────────

#[test]
fn a_repeated_consolidation_stops_being_a_paid_no_op() {
    #[derive(serde::Serialize)]
    struct Consolidate {
        case_id: [u8; 32],
        related_case_id: [u8; 32],
    }

    for gates in pair!(LegalGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        let sender = issuer.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let case = |id: u8| CaseAnchor {
            case_id: [id; 32],
            case_commitment: [0xC1; 32],
            jurisdiction_code: "US-NY".to_string(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [0xC2; 32],
            issuer_class: LegalIssuerClass::LawFirm,
            issuer_address: sender,
            status: CaseStatus::Filed,
            created_at: 1_000,
            updated_at: 1_000,
            anchored_at_height: 1,
            related_cases: vec![],
        };

        let run = |view: &mut ExecutionView<'_, '_>, op: LegalOperation, data: Vec<u8>| {
            let before = StateManager::v_get_nonce(view, &sender).unwrap();
            let ok = LegalExecutor::execute_with_gates(
                view,
                &sender,
                &LegalTxData {
                    operation: op,
                    data,
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
            .unwrap()
            .success;
            (
                ok,
                StateManager::v_get_nonce(view, &sender).unwrap() > before,
            )
        };

        for id in [0x41u8, 0x42] {
            assert!(
                run(
                    &mut view,
                    LegalOperation::AnchorCase,
                    bincode::serialize(&case(id)).unwrap()
                )
                .0
            );
        }

        let payload = bincode::serialize(&Consolidate {
            case_id: [0x41; 32],
            related_case_id: [0x42; 32],
        })
        .unwrap();

        let first = run(&mut view, LegalOperation::ConsolidateCase, payload.clone());
        assert!(
            first.0,
            "the FIRST consolidation does real work and is accepted on both sides \
             (no_op_receipt={})",
            gates.no_op_receipt
        );

        // What the primary row holds before the repeat.
        let before_repeat = LegalExecutor::v_get_case(&view, &[0x41; 32])
            .unwrap()
            .expect("the case is there");

        let repeat = run(&mut view, LegalOperation::ConsolidateCase, payload);
        assert_eq!(
            repeat.0, !gates.no_op_receipt,
            "OV-6: a repeated consolidation reports SUCCESS below the gate and is \
             refused at it (no_op_receipt={})",
            gates.no_op_receipt
        );
        assert_eq!(
            repeat.1, !gates.no_op_receipt,
            "OV-6: and it is PAID for below the gate; at the gate the refusal \
             returns before the deduct (no_op_receipt={})",
            gates.no_op_receipt
        );

        // The claim that makes it a no-op and not a redundant write: the
        // primary case row is identical either way, INCLUDING below the gate
        // where the transaction reported success and took the fee.
        let after_repeat = LegalExecutor::v_get_case(&view, &[0x41; 32])
            .unwrap()
            .expect("the case is still there");
        assert_eq!(
            after_repeat.related_cases, before_repeat.related_cases,
            "the repeat appends nothing"
        );
        assert_eq!(
            after_repeat.updated_at, before_repeat.updated_at,
            "and writes no updated_at, because that write lives inside the \
             branch the `contains` guard skips -- which is what makes the paid \
             success receipt a lie rather than a redundancy"
        );
    }
}

// ── OV-25: DocClass, UpdateCredential ───────────────────────────────────────

#[test]
fn update_credential_stops_reporting_success_for_a_write_it_does_not_do() {
    #[derive(serde::Serialize)]
    struct CredentialIdData {
        credential_id: [u8; 32],
    }

    for gates in pair!(DocClassGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let issuer = KeyPair::generate();
        fund(&db, &issuer, 100_000_000);
        let sender = issuer.address();
        let proposer = Address::new([9; 20]);

        DocClassStore::new(&db)
            .eligibility()
            .put(&EligibilityAttestation {
                credential_id: [0x87; 32],
                subject_address: Address::ZERO,
                subcode: DocSubcode::EligibilityAttestation,
                subject_commitment: [0xC7; 32],
                issuer: sender,
                jurisdiction: "US-NY".to_string(),
                eligibility_type: EligibilityType::Citizenship,
                schema_hash: [0x61; 32],
                content_commitment: [0x62; 32],
                issued_at: 1_000,
                valid_from: 1_000,
                expires_at: 0,
                payload_hash: None,
                payload_hint: None,
                encryption_meta: None,
                issuer_signature: [0u8; 64],
                issuer_key_id: "gov-1".to_string(),
                revocation_status: RevocationStatus::Active,
                superseded_by: None,
            })
            .unwrap();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let before = StateManager::v_get_nonce(&view, &sender).unwrap();
        let ok = DocClassExecutor::execute_with_gates(
            &mut view,
            &params(),
            &sender,
            &DocClassTxData {
                operation: DocClassOperation::UpdateCredential,
                subcode: DocSubcode::EligibilityAttestation,
                data: bincode::serialize(&CredentialIdData {
                    credential_id: [0x87; 32],
                })
                .unwrap(),
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
        .unwrap()
        .success;
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        assert_eq!(
            ok, !gates.no_op_receipt,
            "OV-25: UpdateCredential reports success for the credential's own \
             issuer while writing nothing, until the gate (no_op_receipt={})",
            gates.no_op_receipt
        );
        assert_eq!(
            charged, !gates.no_op_receipt,
            "OV-25: and charges for it below the gate (no_op_receipt={})",
            gates.no_op_receipt
        );
    }
}

// ── OV-30: Agreement, AddParty and RemoveParty ──────────────────────────────

#[test]
fn add_party_and_remove_party_stop_reporting_success_for_doing_nothing() {
    #[derive(serde::Serialize)]
    struct AnyPayload {
        agreement_id: [u8; 32],
    }

    for gates in pair!(AgreementGates) {
        for op in [
            AgreementOperation::AddParty,
            AgreementOperation::RemoveParty,
        ] {
            let (_state, db, _dir, _executor) = setup_with_params(params());
            let actor = KeyPair::generate();
            fund(&db, &actor, 100_000_000);
            let sender = actor.address();
            let proposer = Address::new([9; 20]);
            let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
            let mut view = ExecutionView::new(&mut overlay);

            let before = StateManager::v_get_nonce(&view, &sender).unwrap();
            let ok = AgreementExecutor::execute_with_gates(
                &mut view,
                &sender,
                &AgreementTxData {
                    operation: op,
                    data: bincode::serialize(&AnyPayload {
                        agreement_id: [0x51; 32],
                    })
                    .unwrap(),
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
            .unwrap()
            .success;
            let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

            assert_eq!(
                ok, !gates.no_op_receipt,
                "OV-30: {op:?} reports success for an agreement that does not even \
                 exist, until the gate (no_op_receipt={})",
                gates.no_op_receipt
            );
            assert_eq!(
                charged, !gates.no_op_receipt,
                "OV-30: and charges for it below the gate (no_op_receipt={})",
                gates.no_op_receipt
            );
        }
    }
}
