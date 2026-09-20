//! `subsystem_ambiguous_policy_id_refused_enabled_from_height`: an operation
//! that claims to be governed by a policy this chain cannot identify REFUSES.
//!
//! `docs/lane-a/ACTIVATION-AUDIT.md` row AU-8.
//!
//! # The ambiguity, which is the whole of the row
//!
//! Thirteen wire types across Healthcare, Property and Agreement carry a
//! `policy_id: [u8; 32]`, and every one of them is written from the payload and
//! consulted by no guard. What makes that unsafe rather than merely unused is
//! that nothing in this tree says WHICH NAMESPACE the value is in: a policy
//! ACCOUNT id, which `PolicyAccountExecutor::v_get_policy_account` could
//! resolve, or a COMMITMENT to an off-chain policy document, which it could
//! not. The two are typed identically, so the compiler cannot tell them apart;
//! no subsystem executor names `PolicyAccount` at all; and no `policy_id` in
//! any fixture is a policy-account key.
//!
//! Resolving that is a specification decision, and this gate does not make it.
//! It refuses instead: a NON-ZERO `policy_id` is a claim the chain cannot back,
//! so the operation fails, before the deduct, with a reason that names the
//! ambiguity rather than the value. `[0u8; 32]` is this tree's absent sentinel
//! -- the same null `Address::ZERO` and `Hash::ZERO` are -- and stays accepted,
//! which is what keeps the gate a refusal of the CLAIM rather than a shutdown
//! of three subsystems.
//!
//! # What this file asserts, and in which of the two available ways
//!
//! Behaviourally, one pair per subsystem, on the arm that creates the family's
//! root row: Property `AnchorAsset`, Healthcare `RegisterProvider`, Agreement
//! `CommitAgreement`. Each runs the SAME transaction twice, once with the gate
//! closed and once with it open, and asserts the two nodes DISAGREE; each also
//! drives the ZERO-`policy_id` form of the same transaction and requires both
//! sides to accept it.
//!
//! Structurally, for the other thirteen arms. Sixteen arms carry a `policy_id`
//! into state and they are the same three lines each; what a behavioural test
//! per arm would add over the three above is coverage of a COPY, and what could
//! actually go wrong is an arm that has no guard at all. So the last test reads
//! the three executors and requires every arm that deserializes a
//! `policy_id`-bearing payload to call `Self::ambiguous_policy_refusal`, with
//! the count pinned -- the same shape `remediation_gates.rs` uses for the
//! wiring claim, and for the same reason: the realistic failure in sixteen
//! near-identical guards is a missing one, not a wrong one.
//!
//! Every gates literal is spelled `{ policy_id_ambiguous_refused: …, ..CLOSED }`.
//! `OPEN` would open five or six gates at once in each subsystem, and a pair
//! differing in six ways cannot attribute a difference to one of them.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementRole, AgreementStatus, AgreementTxData,
    PartyBinding, PartyRef,
};
use sumchain_primitives::healthcare::{
    HealthcareIssuerClass, HealthcareOperation, HealthcareTxData, ProviderProfile, ProviderStatus,
    ProviderType,
};
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass, PropertyOperation, PropertyTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, HealthcareExecutor, HealthcareGates, PropertyExecutor,
    PropertyGates, StateManager, AMBIGUOUS_POLICY_ID_UNRESOLVABLE,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

const NOW: u64 = 5_000;
/// A well-formed thirty-two bytes that this chain cannot say anything about.
/// The refusal is not that the value is malformed -- it is that there is no
/// non-zero value the chain COULD resolve.
const SOME_POLICY: [u8; 32] = [12u8; 32];
const NO_POLICY: [u8; 32] = [0u8; 32];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

const PROPERTY: [PropertyGates; 2] = [
    PropertyGates::CLOSED,
    PropertyGates {
        policy_id_ambiguous_refused: true,
        ..PropertyGates::CLOSED
    },
];
const HEALTHCARE: [HealthcareGates; 2] = [
    HealthcareGates::CLOSED,
    HealthcareGates {
        policy_id_ambiguous_refused: true,
        ..HealthcareGates::CLOSED
    },
];
const AGREEMENT: [AgreementGates; 2] = [
    AgreementGates::CLOSED,
    AgreementGates {
        policy_id_ambiguous_refused: true,
        ..AgreementGates::CLOSED
    },
];

fn asset(id: u8, issuer: Address, policy_id: [u8; 32]) -> AssetAnchor {
    AssetAnchor {
        asset_id: [id; 32],
        asset_commitment: [id.wrapping_add(1); 32],
        asset_type: AssetType::SingleFamilyResidence,
        jurisdiction_code: "US-CA-LA".to_string(),
        public_reference: None,
        policy_id,
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: issuer,
        status: AssetStatus::Active,
        created_at: NOW,
        updated_at: NOW,
        anchored_at_height: 1,
        related_assets: vec![],
        attachments: vec![],
    }
}

fn provider(id: u8, issuer: Address, policy_id: [u8; 32]) -> ProviderProfile {
    ProviderProfile {
        provider_id: [id; 32],
        provider_commitment: [id.wrapping_add(1); 32],
        provider_type: ProviderType::Hospital,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: None,
        credentials_commitment: None,
        policy_id,
        issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
        issuer_address: issuer,
        status: ProviderStatus::Active,
        created_at: NOW,
        updated_at: NOW,
        registered_at_height: 1,
        network_affiliations: vec![],
        attachments: vec![],
    }
}

fn agreement(id: u8, policy_id: [u8; 32]) -> AgreementCommitment {
    AgreementCommitment {
        agreement_id: [id; 32],
        agreement_commitment: [id.wrapping_add(1); 32],
        parties: vec![PartyBinding {
            party_ref: PartyRef::Commitment([0xA1; 32]),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        }],
        jurisdiction_code: "US-DE".to_string(),
        effective_from: Some(NOW),
        expiry: Some(9_000_000),
        attachments: vec![],
        policy_id,
        status: AgreementStatus::PendingSignatures,
        created_at: NOW,
        updated_at: NOW,
        created_at_height: 1,
        supersedes: None,
    }
}

// ── Property — AnchorAsset ──────────────────────────────────────────────────

/// AU-8, Property. An asset claiming a policy the chain cannot identify is
/// anchored below the gate and refused above it.
#[test]
fn a_property_asset_claims_an_unresolvable_policy_below_the_gate_and_not_above_it() {
    for gates in PROPERTY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let run = |view: &mut ExecutionView<'_, '_>, a: &AssetAnchor| {
            PropertyExecutor::execute_with_gates(
                view,
                &sender,
                &PropertyTxData {
                    operation: PropertyOperation::AnchorAsset,
                    data: bincode::serialize(a).unwrap(),
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
        };

        let claimed = run(&mut view, &asset(0x51, sender, SOME_POLICY));
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.policy_id_ambiguous_refused {
            assert!(!claimed.success, "at the gate the claim is refused");
            assert_eq!(
                claimed.error.as_deref(),
                Some(AMBIGUOUS_POLICY_ID_UNRESOLVABLE),
                "and the reason names the AMBIGUITY, not the value -- there is \
                 no other non-zero policy_id this chain would have resolved"
            );
            assert!(!charged, "refused ahead of the deduct");
            assert!(
                PropertyExecutor::v_get_asset(&view, &[0x51; 32])
                    .unwrap()
                    .is_none(),
                "and no row was written"
            );
        } else {
            assert!(claimed.success, "below the gate the claim is recorded");
            assert_eq!(
                PropertyExecutor::v_get_asset(&view, &[0x51; 32])
                    .unwrap()
                    .unwrap()
                    .policy_id,
                SOME_POLICY,
                "and the unresolvable id is STORED, which is AU-8's sentence"
            );
        }

        // An asset naming NO policy is anchored on both sides.
        assert!(
            run(&mut view, &asset(0x52, sender, NO_POLICY)).success,
            "a zero policy_id names no policy and is accepted at every height"
        );
    }
}

// ── Healthcare — RegisterProvider ───────────────────────────────────────────

/// AU-8, Healthcare. Same rule, same height, different family.
#[test]
fn a_healthcare_provider_claims_an_unresolvable_policy_below_the_gate_and_not_above_it() {
    for gates in HEALTHCARE {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let run = |view: &mut ExecutionView<'_, '_>, p: &ProviderProfile| {
            HealthcareExecutor::execute_with_gates(
                view,
                &sender,
                &HealthcareTxData {
                    operation: HealthcareOperation::RegisterProvider,
                    data: bincode::serialize(p).unwrap(),
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
        };

        let claimed = run(&mut view, &provider(0x61, sender, SOME_POLICY));
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.policy_id_ambiguous_refused {
            assert!(!claimed.success);
            assert_eq!(
                claimed.error.as_deref(),
                Some(AMBIGUOUS_POLICY_ID_UNRESOLVABLE)
            );
            assert!(!charged, "refused ahead of the deduct");
            assert!(HealthcareExecutor::v_get_provider(&view, &[0x61; 32])
                .unwrap()
                .is_none());
        } else {
            assert!(claimed.success);
            assert_eq!(
                HealthcareExecutor::v_get_provider(&view, &[0x61; 32])
                    .unwrap()
                    .unwrap()
                    .policy_id,
                SOME_POLICY
            );
        }

        assert!(
            run(&mut view, &provider(0x62, sender, NO_POLICY)).success,
            "a zero policy_id names no policy and is accepted at every height"
        );
    }
}

// ── Agreement — CommitAgreement ─────────────────────────────────────────────

/// AU-8, Agreement. Same rule again, and the arm that
/// `agreement_party_authority_unsupported_enabled_from_height` deliberately
/// leaves reachable -- so this gate reaches something that one does not.
#[test]
fn an_agreement_claims_an_unresolvable_policy_below_the_gate_and_not_above_it() {
    for gates in AGREEMENT {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_nonce(&view, &sender).unwrap();

        let run = |view: &mut ExecutionView<'_, '_>, a: &AgreementCommitment| {
            AgreementExecutor::execute_with_gates(
                view,
                &sender,
                &AgreementTxData {
                    operation: AgreementOperation::CommitAgreement,
                    data: bincode::serialize(a).unwrap(),
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                100,
                1,
                NOW,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
        };

        let claimed = run(&mut view, &agreement(0x71, SOME_POLICY));
        let charged = StateManager::v_get_nonce(&view, &sender).unwrap() > before;

        if gates.policy_id_ambiguous_refused {
            assert!(!claimed.success);
            assert_eq!(
                claimed.error.as_deref(),
                Some(AMBIGUOUS_POLICY_ID_UNRESOLVABLE)
            );
            assert!(!charged, "refused ahead of the deduct");
            assert!(AgreementExecutor::v_get_agreement(&view, &[0x71; 32])
                .unwrap()
                .is_none());
        } else {
            assert!(claimed.success);
            assert_eq!(
                AgreementExecutor::v_get_agreement(&view, &[0x71; 32])
                    .unwrap()
                    .unwrap()
                    .policy_id,
                SOME_POLICY
            );
        }

        assert!(
            run(&mut view, &agreement(0x72, NO_POLICY)).success,
            "a zero policy_id names no policy and is accepted at every height"
        );
    }
}

// ── The other thirteen arms ─────────────────────────────────────────────────

/// Every arm that carries a `policy_id` into state calls the refusal, and there
/// are sixteen of them.
///
/// The three tests above prove the RULE. This proves its REACH, which is the
/// thing a behavioural test per arm would prove sixteen times over while
/// leaving the actual hazard -- an arm nobody added a guard to -- detectable
/// only by someone who counted. It is the shape `remediation_gates.rs` uses for
/// the accessor/field pairing, and for the same reason.
///
/// The list is the thirteen creation types AU-8 names plus the three
/// supersession arms that write a REPLACEMENT of the same type. Those three are
/// not in the row and are here anyway, for the reason the consent-grant
/// ordering exists: a gate that refused a claim on the creation arm and left
/// the supersession arm open would close nothing, because supersession mints
/// the same row.
///
/// The three proof envelopes -- `HealthcareProofEnvelope`,
/// `PropertyProofEnvelope`, `AgreementProofEnvelope`, each carrying
/// `policy_ids: Vec<PolicyId>` -- are deliberately absent, and named here so
/// their absence is a decision rather than an omission. Property `SubmitProof`
/// already refuses under
/// `property_proof_submission_unsupported_enabled_from_height` and every
/// `VerifyProof` under `subsystem_proof_unsupported_enabled_from_height`, so a
/// third refusal on an operation two gates already refuse would say nothing
/// new.
#[test]
fn every_arm_that_stores_a_policy_id_calls_the_refusal() {
    /// `(file, the payload binding whose policy_id must be guarded)`.
    const ARMS: &[(&str, &str)] = &[
        ("healthcare_executor.rs", "provider.policy_id"),
        ("healthcare_executor.rs", "membership.policy_id"),
        ("healthcare_executor.rs", "consent.policy_id"),
        ("healthcare_executor.rs", "d.new_consent.policy_id"),
        ("healthcare_executor.rs", "prescription.policy_id"),
        ("property_executor.rs", "asset.policy_id"),
        ("property_executor.rs", "event.policy_id"),
        ("property_executor.rs", "d.new_event.policy_id"),
        ("property_executor.rs", "encumbrance.policy_id"),
        ("property_executor.rs", "coverage.policy_id"),
        ("property_executor.rs", "claim.policy_id"),
        ("agreement_executor.rs", "agreement.policy_id"),
        ("agreement_executor.rs", "d.new_agreement.policy_id"),
        ("agreement_executor.rs", "attestation.policy_id"),
        ("agreement_executor.rs", "action.policy_id"),
        ("agreement_executor.rs", "link.activation_policy_id"),
    ];

    let source = |file: &str| {
        let path = format!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/{}"), file);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
    };

    let mut seen = 0usize;
    for (file, binding) in ARMS {
        let src = source(file);
        let call = format!("Self::ambiguous_policy_refusal(gates, &{binding})");
        assert!(
            src.contains(&call),
            "{file} must guard `{binding}` with `{call}`; an arm that writes a \
             policy_id without the guard leaves the claim this gate exists to \
             refuse reachable at every height"
        );
        seen += 1;
    }
    assert_eq!(seen, 16, "sixteen arms carry a policy_id into state");

    // And the guard is not named anywhere it is not accounted for: the total
    // number of call sites across the three files equals the list above, so an
    // arm added later shows up here as a mismatch rather than as silence.
    const FILES: [&str; 3] = [
        "healthcare_executor.rs",
        "property_executor.rs",
        "agreement_executor.rs",
    ];
    let needle = "Self::ambiguous_policy_refusal(gates, &";
    let total: usize = FILES
        .iter()
        .map(|f| source(f).matches(needle).count())
        .sum();
    assert_eq!(
        total, 16,
        "the call sites and the enumerated arms must be the same set; a \
         seventeenth call means a payload this list has not been updated for"
    );
}
