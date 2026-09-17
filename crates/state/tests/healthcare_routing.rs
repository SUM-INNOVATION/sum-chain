//! SRC-87X healthcare executes against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//!
//! ## Why this subsystem's reads had to move with its writes
//!
//! Healthcare is two interlocking state machines -- consent and prescription --
//! and twenty-four of the twenty-nine migrated occurrences are transitions that
//! read a row, change one field plus `updated_at`, and write it back.
//!
//! The sharpest case is not even same-BLOCK. `PartialFillPrescription` writes
//! the SAME row TWICE inside ONE transaction: it appends the fill commitment
//! and then re-reads that row to stamp `PartiallyFilled` on it. Had the writes
//! moved to the candidate without the reads, the second read would have found
//! the row without the fill and written it back -- the transaction whose whole
//! purpose is to record a partial fill would have erased it.
//!
//! `a_second_partial_fill_in_one_block_appends_rather_than_replacing` is that
//! case, and `one_partial_fill_records_exactly_one` is its control.
//!
//! The refill counter is the same argument one level up:
//! `two_fills_in_one_block_decrement_refills_twice`, against its control
//! `one_fill_leaves_two_refills`.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareIssuerClass, HealthcareOperation, HealthcareProofEnvelope, HealthcareProofProfile,
    HealthcareProofType, HealthcareTxData, MembershipRecord, MembershipStatus, MembershipType,
    Prescription, PrescriptionStatus, PrescriptionType, ProviderProfile, ProviderStatus,
    ProviderType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{HealthcareExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, HealthcareStore};

/// Every family this unit moved. Ten.
///
/// The ORDER matters: `families_changed` reports in this order, and the
/// corrupt-row cases below assert the changed-family list with `assert_eq!`
/// against a list written in it.
const HEALTHCARE_CFS: &[&str] = &[
    cf::HEALTHCARE_PROVIDERS,
    cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
    cf::HEALTHCARE_MEMBERSHIPS,
    cf::HEALTHCARE_MEMBER_INDEX,
    cf::HEALTHCARE_CONSENTS,
    cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
    cf::HEALTHCARE_PRESCRIPTIONS,
    cf::HEALTHCARE_PATIENT_RX_INDEX,
    cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
    cf::HEALTHCARE_PROOFS,
];

/// The healthcare arm's status code, on both dispatch surfaces.
const HEALTHCARE_FAILED: TxStatus = TxStatus::Failed(14);

const PLAN_A: [u8; 32] = [0xC1; 32];
const PLAN_B: [u8; 32] = [0xC2; 32];
const MEMBER_NULL: [u8; 32] = [0xD1; 32];
const SUBJECT_NULL: [u8; 32] = [0xE1; 32];
const PATIENT_NULL: [u8; 32] = [0xF1; 32];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    op: HealthcareOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    signed(kp, nonce, op, bincode::serialize(payload).unwrap())
}

fn signed(kp: &KeyPair, nonce: u64, op: HealthcareOperation, data: Vec<u8>) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Healthcare(HealthcareTxData {
            operation: op,
            data,
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn provider(id: u8, issuer: Address, plans: Vec<[u8; 32]>) -> ProviderProfile {
    ProviderProfile {
        provider_id: [id; 32],
        provider_commitment: [id.wrapping_add(1); 32],
        provider_type: ProviderType::Hospital,
        jurisdiction_code: "US-CA".to_string(),
        public_reference: None,
        specialties_commitment: None,
        credentials_commitment: None,
        policy_id: [12u8; 32],
        issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
        issuer_address: issuer,
        status: ProviderStatus::Active,
        created_at: 1000,
        updated_at: 1000,
        registered_at_height: 1,
        network_affiliations: plans,
        attachments: vec![],
    }
}

fn membership(id: u8, provider_id: u8, issuer: Address) -> MembershipRecord {
    MembershipRecord {
        membership_id: [id; 32],
        provider_id: [provider_id; 32],
        membership_type: MembershipType::IndividualHealth,
        membership_commitment: [id.wrapping_add(1); 32],
        member_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        member_address: Address::new([0x33; 20]),
        member_nullifier: MEMBER_NULL,
        coverage_tier: Some(CoverageTier::Individual),
        group_commitment: None,
        effective_from: 0,
        expiry: Some(9_000_000),
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: MembershipStatus::Active,
        created_at: 1000,
        updated_at: 1000,
        issued_at_height: 1,
        prior_membership_id: None,
        dependents: vec![],
        attachments: vec![],
    }
}

fn consent(id: u8, issuer: Address) -> ConsentEnvelope {
    ConsentEnvelope {
        consent_id: [id; 32],
        consent_type: ConsentType::HipaaAuthorization,
        consent_commitment: [id.wrapping_add(1); 32],
        subject_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        subject_address: Address::new([0x34; 20]),
        subject_nullifier: SUBJECT_NULL,
        recipient_ref: PartyRef::Commitment([id.wrapping_add(3); 32]),
        purpose_commitment: [id.wrapping_add(4); 32],
        scope: DisclosureScope::TreatmentOnly,
        scope_commitment: None,
        effective_from: 0,
        expiry: Some(9_000_000),
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ConsentStatus::Granted,
        created_at: 1000,
        updated_at: 1000,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

/// `effective_from` is `None` deliberately. Both dispatch arms pass a literal
/// `0` where the block timestamp belongs, so `is_valid` is evaluated at time
/// zero and any prescription with a non-zero effective date is unfillable
/// forever. That is pinned as its own inherited defect below; the fixtures that
/// need to reach a fill have to work around it.
fn prescription(id: u8, prescriber: u8, issuer: Address, refills: u8) -> Prescription {
    Prescription {
        prescription_id: [id; 32],
        prescription_type: PrescriptionType::StandardPrescription,
        prescription_commitment: [id.wrapping_add(1); 32],
        patient_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        patient_address: Address::new([0x35; 20]),
        patient_nullifier: PATIENT_NULL,
        prescriber_ref: PartyRef::Commitment([id.wrapping_add(3); 32]),
        prescriber_provider_id: [prescriber; 32],
        pharmacy_ref: None,
        medication_commitment: [id.wrapping_add(4); 32],
        quantity_commitment: [id.wrapping_add(5); 32],
        days_supply_commitment: None,
        refills_authorized: refills,
        refills_remaining: refills,
        is_controlled: false,
        date_written: 900,
        effective_from: None,
        expiry: 9_000_000,
        issuer_address: issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: PrescriptionStatus::Active,
        created_at: 900,
        updated_at: 900,
        recorded_at_height: 1,
        supersedes: None,
        fill_history: vec![],
        attachments: vec![],
    }
}

fn proof_envelope(id: u8) -> HealthcareProofEnvelope {
    HealthcareProofEnvelope {
        proof_id: [id; 32],
        profile: HealthcareProofProfile::ConsentValid,
        profile_id: "healthcare.consent_valid.v1".to_string(),
        policy_ids: vec![[12u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: HealthcareProofType::Mock,
        subject_nullifier: SUBJECT_NULL,
        generated_at: 1000,
        expires_at: 9_000_000,
    }
}

// ── Payload shapes the executor deserializes ────────────────────────────────

#[derive(serde::Serialize)]
struct ProviderId {
    provider_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct ProviderStatusUpdate {
    provider_id: [u8; 32],
    status: ProviderStatus,
}
#[derive(serde::Serialize)]
struct Affiliation {
    provider_id: [u8; 32],
    plan_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct MembershipId {
    membership_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct MembershipStatusUpdate {
    membership_id: [u8; 32],
    status: MembershipStatus,
}
#[derive(serde::Serialize)]
struct Renewal {
    membership_id: [u8; 32],
    new_expiry: u64,
}
#[derive(serde::Serialize)]
struct Dependent {
    membership_id: [u8; 32],
    dependent_commitment: [u8; 32],
}
#[derive(serde::Serialize)]
struct ConsentId {
    consent_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct ConsentStatusUpdate {
    consent_id: [u8; 32],
    status: ConsentStatus,
}
#[derive(serde::Serialize)]
struct Supersede {
    old_consent_id: [u8; 32],
    new_consent: ConsentEnvelope,
}
#[derive(serde::Serialize)]
struct PrescriptionId {
    prescription_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct PrescriptionStatusUpdate {
    prescription_id: [u8; 32],
    status: PrescriptionStatus,
}
#[derive(serde::Serialize)]
struct Fill {
    prescription_id: [u8; 32],
    fill_commitment: [u8; 32],
}

// ── Canonical / candidate comparison ────────────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in HEALTHCARE_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// A real per-CF diff, not a presence check: `prefix_iter` on a view is MERGED
/// with committed state, so presence proves nothing about what this block did.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in HEALTHCARE_CFS {
        let committed: Vec<(Vec<u8>, Vec<u8>)> = db
            .prefix_iter(f, &[])
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let staged: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iter(f, &[])
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();
        if committed != staged {
            out.push(*f);
        }
    }
    out
}

// ── The prescription lifecycle: the sharpest same-block cases ───────────────

/// A partial fill records the fill AND the status in ONE transaction.
///
/// `PartialFillPrescription` calls `v_add_fill_history` and then
/// `v_update_prescription_status` on the same row. The second reads what the
/// first staged; against committed state it would read the row without the
/// fill.
#[test]
fn one_partial_fill_records_exactly_one() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(10, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(20, 10, addr, 3),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::PartialFillPrescription,
            &Fill {
                prescription_id: [20; 32],
                fill_commitment: [0x91; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let rx = HealthcareExecutor::v_get_prescription(&view, &[20u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        rx.fill_history,
        vec![[0x91u8; 32]],
        "the fill this transaction recorded survived the status write it made \
         a moment later -- a committed read there would have erased it"
    );
    assert_eq!(rx.status, PrescriptionStatus::PartiallyFilled);
    assert_eq!(
        rx.refills_remaining, 3,
        "a partial fill does not touch the refill counter"
    );
}

/// The discriminator: a SECOND partial fill in the same block appends.
///
/// The test above would pass if the fill list simply always held the last
/// commitment. Two fills in one block can only produce a two-element list if
/// every read in the sequence saw the candidate.
#[test]
fn a_second_partial_fill_in_one_block_appends_rather_than_replacing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(11, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(21, 11, addr, 3),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::PartialFillPrescription,
            &Fill {
                prescription_id: [21; 32],
                fill_commitment: [0x92; 32],
            },
        ),
        tx(
            &issuer,
            3,
            HealthcareOperation::PartialFillPrescription,
            &Fill {
                prescription_id: [21; 32],
                fill_commitment: [0x93; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_prescription(&view, &[21u8; 32])
            .unwrap()
            .unwrap()
            .fill_history,
        vec![[0x92u8; 32], [0x93u8; 32]],
        "both fills, in order -- the second transaction must have seen the first"
    );
}

/// Two fills in one block decrement the refill counter twice.
#[test]
fn two_fills_in_one_block_decrement_refills_twice() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(12, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(22, 12, addr, 3),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::FillPrescription,
            &Fill {
                prescription_id: [22; 32],
                fill_commitment: [0x94; 32],
            },
        ),
        tx(
            &issuer,
            3,
            HealthcareOperation::FillPrescription,
            &Fill {
                prescription_id: [22; 32],
                fill_commitment: [0x95; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let rx = HealthcareExecutor::v_get_prescription(&view, &[22u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        rx.refills_remaining, 1,
        "three authorized, two filled in one block -- the second fill must have \
         read the counter the first one wrote"
    );
    assert_eq!(rx.fill_history, vec![[0x94u8; 32], [0x95u8; 32]]);
    assert_eq!(rx.status, PrescriptionStatus::PartiallyFilled);
}

/// The control: one fill leaves two.
#[test]
fn one_fill_leaves_two_refills() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(13, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(23, 13, addr, 3),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::FillPrescription,
            &Fill {
                prescription_id: [23; 32],
                fill_commitment: [0x96; 32],
            },
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }
    assert_eq!(
        HealthcareExecutor::v_get_prescription(&view, &[23u8; 32])
            .unwrap()
            .unwrap()
            .refills_remaining,
        2
    );
}

/// The last fill exhausts the refills and the status becomes `Filled`; a
/// further fill in the SAME block is then refused by a guard reading the
/// candidate.
#[test]
fn the_fill_that_exhausts_refills_closes_the_prescription_within_the_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(14, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(24, 14, addr, 1),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::FillPrescription,
            &Fill {
                prescription_id: [24; 32],
                fill_commitment: [0x97; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        HealthcareExecutor::v_get_prescription(&view, &[24u8; 32])
            .unwrap()
            .unwrap()
            .status,
        PrescriptionStatus::Filled
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                3,
                HealthcareOperation::FillPrescription,
                &Fill {
                    prescription_id: [24; 32],
                    fill_commitment: [0x98; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "the `is_valid` guard reads the Filled status this block staged"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &addr).unwrap(),
        3,
        "and the refusal does not advance the nonce"
    );
}

// ── Lifecycle transitions that read a status staged in the same block ───────

/// A provider suspended and reactivated within one block: the reactivation
/// guard requires `Suspended`, which is only in the candidate.
#[test]
fn a_provider_is_suspended_and_reactivated_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(30, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::SuspendProvider,
            &ProviderId {
                provider_id: [30; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        HealthcareExecutor::v_get_provider(&view, &[30u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ProviderStatus::Suspended
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                2,
                HealthcareOperation::ReactivateProvider,
                &ProviderId {
                    provider_id: [30; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "reactivation must read the Suspended status from the candidate: {:?}",
        r.status
    );
    assert_eq!(
        HealthcareExecutor::v_get_provider(&view, &[30u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ProviderStatus::Active
    );

    // The discriminator: a SECOND reactivation is refused, because the guard
    // reads the `Active` status the first one staged.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                3,
                HealthcareOperation::ReactivateProvider,
                &ProviderId {
                    provider_id: [30; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "only a suspended or inactive provider may be reactivated, and the \
         status is in the candidate"
    );
}

/// The same shape for memberships: suspend, reinstate, and a second reinstate
/// refused.
#[test]
fn a_membership_is_suspended_and_reinstated_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(31, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssueMembership,
            &membership(41, 31, addr),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::SuspendMembership,
            &MembershipId {
                membership_id: [41; 32],
            },
        ),
        tx(
            &issuer,
            3,
            HealthcareOperation::ReinstateMembership,
            &MembershipId {
                membership_id: [41; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        HealthcareExecutor::v_get_membership(&view, &[41u8; 32])
            .unwrap()
            .unwrap()
            .status,
        MembershipStatus::Active
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                4,
                HealthcareOperation::ReinstateMembership,
                &MembershipId {
                    membership_id: [41; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "only a suspended membership may be reinstated, and the status is in \
         the candidate"
    );
}

/// And for prescriptions: hold, release, and a second release refused.
#[test]
fn a_prescription_is_held_and_released_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(32, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(42, 32, addr, 2),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::HoldPrescription,
            &PrescriptionId {
                prescription_id: [42; 32],
            },
        ),
        tx(
            &issuer,
            3,
            HealthcareOperation::ReleaseHold,
            &PrescriptionId {
                prescription_id: [42; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        HealthcareExecutor::v_get_prescription(&view, &[42u8; 32])
            .unwrap()
            .unwrap()
            .status,
        PrescriptionStatus::Active
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                4,
                HealthcareOperation::ReleaseHold,
                &PrescriptionId {
                    prescription_id: [42; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "only a held prescription may be released, and the status is in the \
         candidate"
    );
}

/// The three generic `Update*` arms -- provider, membership and consent -- each
/// set an arbitrary status on a row created earlier in the SAME block, and each
/// refuses a sender who is not the recorded issuer.
///
/// These are the only arms that take a caller-supplied status rather than a
/// fixed one, so they are the ones that can put a row into a state no other
/// operation would produce. `Expired` is used deliberately: nothing in the
/// executor ever writes it.
#[test]
fn the_three_update_arms_set_an_arbitrary_status_on_a_row_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0x20, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssueMembership,
            &membership(0x21, 0x20, addr),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::GrantConsent,
            &consent(0x22, addr),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // A stranger may update none of the three.
    for (n, t) in [
        tx(
            &stranger,
            0,
            HealthcareOperation::UpdateProvider,
            &ProviderStatusUpdate {
                provider_id: [0x20; 32],
                status: ProviderStatus::Expired,
            },
        ),
        tx(
            &stranger,
            0,
            HealthcareOperation::UpdateMembership,
            &MembershipStatusUpdate {
                membership_id: [0x21; 32],
                status: MembershipStatus::Expired,
            },
        ),
        tx(
            &stranger,
            0,
            HealthcareOperation::UpdateConsent,
            &ConsentStatusUpdate {
                consent_id: [0x22; 32],
                status: ConsentStatus::Expired,
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status, HEALTHCARE_FAILED,
            "stranger update {n} must be refused by the issuer check, which \
             reads the row this block staged"
        );
    }
    assert_eq!(
        StateManager::v_get_nonce(&view, &stranger.address()).unwrap(),
        0,
        "and none of the three refusals charged the stranger a fee"
    );

    // The issuer may update all three, each reading the candidate.
    for (n, t) in [
        tx(
            &issuer,
            3,
            HealthcareOperation::UpdateProvider,
            &ProviderStatusUpdate {
                provider_id: [0x20; 32],
                status: ProviderStatus::Expired,
            },
        ),
        tx(
            &issuer,
            4,
            HealthcareOperation::UpdateMembership,
            &MembershipStatusUpdate {
                membership_id: [0x21; 32],
                status: MembershipStatus::Expired,
            },
        ),
        tx(
            &issuer,
            5,
            HealthcareOperation::UpdateConsent,
            &ConsentStatusUpdate {
                consent_id: [0x22; 32],
                status: ConsentStatus::Expired,
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "issuer update {n}: {:?}",
            r.status
        );
    }

    assert_eq!(
        HealthcareExecutor::v_get_provider(&view, &[0x20u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ProviderStatus::Expired
    );
    assert_eq!(
        HealthcareExecutor::v_get_membership(&view, &[0x21u8; 32])
            .unwrap()
            .unwrap()
            .status,
        MembershipStatus::Expired
    );
    assert_eq!(
        HealthcareExecutor::v_get_consent(&view, &[0x22u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::Expired
    );
}

// ── Existence guards that must see the same block's rows ────────────────────

/// A membership finds the provider registered earlier in the same block.
#[test]
fn a_membership_finds_a_provider_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(33, addr, vec![]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                1,
                HealthcareOperation::IssueMembership,
                &membership(43, 33, addr),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
}

/// Without the provider, the same membership is refused BY THE HEALTHCARE
/// GUARD -- `Failed(14)`, not an earlier rejection.
#[test]
fn without_the_provider_the_same_membership_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::IssueMembership,
                &membership(43, 33, addr),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "it must fail in the healthcare executor, not for an unrelated reason"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &addr).unwrap(),
        0,
        "a refused healthcare operation does not advance the account nonce"
    );
}

/// A prescription finds its prescriber registered earlier in the same block.
#[test]
fn a_prescription_finds_its_prescriber_registered_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(34, addr, vec![]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                1,
                HealthcareOperation::IssuePrescription,
                &prescription(44, 34, addr, 2),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
}

/// Without the prescriber provider, the same prescription is refused.
#[test]
fn without_the_prescriber_provider_the_same_prescription_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::IssuePrescription,
                &prescription(44, 34, addr, 2),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, HEALTHCARE_FAILED);
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(StateManager::v_get_nonce(&view, &addr).unwrap(), 0);
}

// ── Duplicate guards, each with a control ───────────────────────────────────

/// Every `exists` guard in the subsystem, driven through dispatch: a repeat in
/// one block is refused, a different id in the same block is not.
///
/// The control is what makes this about the candidate rather than about the
/// operation being refused generally.
#[test]
fn every_duplicate_id_guard_reads_the_candidate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 500_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // A provider first, so the membership and prescription guards are reached.
    let mut nonce = 0u64;
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                nonce,
                HealthcareOperation::RegisterProvider,
                &provider(50, addr, vec![]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success));
    nonce += 1;

    // (label, repeat-op-with-the-same-id, op-with-a-different-id)
    let cases: Vec<(&str, Vec<u8>, Vec<u8>, HealthcareOperation)> = vec![
        (
            "provider",
            bincode::serialize(&provider(50, addr, vec![])).unwrap(),
            bincode::serialize(&provider(51, addr, vec![])).unwrap(),
            HealthcareOperation::RegisterProvider,
        ),
        (
            "membership",
            bincode::serialize(&membership(60, 50, addr)).unwrap(),
            bincode::serialize(&membership(61, 50, addr)).unwrap(),
            HealthcareOperation::IssueMembership,
        ),
        (
            "consent",
            bincode::serialize(&consent(70, addr)).unwrap(),
            bincode::serialize(&consent(71, addr)).unwrap(),
            HealthcareOperation::GrantConsent,
        ),
        (
            "prescription",
            bincode::serialize(&prescription(80, 50, addr, 2)).unwrap(),
            bincode::serialize(&prescription(81, 50, addr, 2)).unwrap(),
            HealthcareOperation::IssuePrescription,
        ),
        (
            "proof",
            bincode::serialize(&proof_envelope(90)).unwrap(),
            bincode::serialize(&proof_envelope(91)).unwrap(),
            HealthcareOperation::SubmitProof,
        ),
    ];

    for (label, same, other, op) in cases {
        // First, the original.
        let r = executor
            .execute_tx(
                &mut view,
                &signed(&issuer, nonce, op, same.clone()),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if label != "provider" {
            assert!(
                matches!(r.status, TxStatus::Success),
                "{label}: {:?}",
                r.status
            );
            nonce += 1;
        } else {
            // The provider with this id was already registered above, so this
            // IS the duplicate.
            assert_eq!(r.status, HEALTHCARE_FAILED, "{label} duplicate");
        }

        // The repeat.
        let r = executor
            .execute_tx(
                &mut view,
                &signed(&issuer, nonce, op, same),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert_eq!(
            r.status, HEALTHCARE_FAILED,
            "{label}: the repeated id must be refused by a guard reading the \
             candidate"
        );

        // The control: a different id at the SAME nonce succeeds.
        let r = executor
            .execute_tx(
                &mut view,
                &signed(&issuer, nonce, op, other),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{label}: a different id must not be refused: {:?}",
            r.status
        );
        nonce += 1;
    }
}

// ── The five accumulating indexes, and the in-row dependent list ────────────

/// Two providers joining one plan in one block: the network index holds BOTH.
#[test]
fn two_providers_for_one_plan_accumulate_in_the_network_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, id) in [0x40u8, 0x41u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &issuer,
                    n as u64,
                    HealthcareOperation::RegisterProvider,
                    &provider(id, addr, vec![PLAN_A]),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_network_provider_ids(&view, &PLAN_A).unwrap(),
        vec![[0x40u8; 32], [0x41u8; 32]],
        "both provider ids, in registration order -- the second must have seen \
         the first"
    );
}

/// Two memberships for one member in one block: the member index holds BOTH.
#[test]
fn two_memberships_for_one_member_accumulate_in_the_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(0x42, addr, vec![]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    for (n, id) in [0x43u8, 0x44u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &issuer,
                    (n + 1) as u64,
                    HealthcareOperation::IssueMembership,
                    &membership(id, 0x42, addr),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_member_membership_ids(&view, &MEMBER_NULL).unwrap(),
        vec![[0x43u8; 32], [0x44u8; 32]]
    );
}

/// Two consents for one subject in one block: the subject index holds BOTH.
#[test]
fn two_consents_for_one_subject_accumulate_in_the_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, id) in [0x45u8, 0x46u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &issuer,
                    n as u64,
                    HealthcareOperation::GrantConsent,
                    &consent(id, addr),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_subject_consent_ids(&view, &SUBJECT_NULL).unwrap(),
        vec![[0x45u8; 32], [0x46u8; 32]]
    );
}

/// Two prescriptions in one block: BOTH indexes accumulate, in order.
#[test]
fn two_prescriptions_accumulate_in_both_indexes() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(0x47, addr, vec![]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    for (n, id) in [0x48u8, 0x49u8].into_iter().enumerate() {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &issuer,
                    (n + 1) as u64,
                    HealthcareOperation::IssuePrescription,
                    &prescription(id, 0x47, addr, 2),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_patient_rx_ids(&view, &PATIENT_NULL).unwrap(),
        vec![[0x48u8; 32], [0x49u8; 32]],
        "the patient index"
    );
    assert_eq!(
        HealthcareExecutor::v_get_prescriber_rx_ids(&view, &[0x47u8; 32]).unwrap(),
        vec![[0x48u8; 32], [0x49u8; 32]],
        "and the prescriber index, which is keyed by the provider id"
    );
}

/// Two dependents added in one block both land, and a repeat of the first is a
/// no-op -- the `contains` check reads the candidate.
#[test]
fn dependents_added_in_one_block_accumulate_and_deduplicate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0x4A, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssueMembership,
            &membership(0x4B, 0x4A, addr),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::AddDependent,
            &Dependent {
                membership_id: [0x4B; 32],
                dependent_commitment: [0xA1; 32],
            },
        ),
        tx(
            &issuer,
            3,
            HealthcareOperation::AddDependent,
            &Dependent {
                membership_id: [0x4B; 32],
                dependent_commitment: [0xA2; 32],
            },
        ),
        // A repeat of the first: accepted as a transaction, writes nothing.
        tx(
            &issuer,
            4,
            HealthcareOperation::AddDependent,
            &Dependent {
                membership_id: [0x4B; 32],
                dependent_commitment: [0xA1; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_membership(&view, &[0x4Bu8; 32])
            .unwrap()
            .unwrap()
            .dependents,
        vec![[0xA1u8; 32], [0xA2u8; 32]],
        "both dependents once each -- the second add saw the first, and the \
         repeat saw them both"
    );

    // And removing one leaves the other, from the candidate.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                5,
                HealthcareOperation::RemoveDependent,
                &Dependent {
                    membership_id: [0x4B; 32],
                    dependent_commitment: [0xA1; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert_eq!(
        HealthcareExecutor::v_get_membership(&view, &[0x4Bu8; 32])
            .unwrap()
            .unwrap()
            .dependents,
        vec![[0xA2u8; 32]]
    );
}

/// An affiliation added twice in one block is added ONCE.
///
/// `v_add_network_affiliation` checks the provider's own affiliation list. Read
/// from committed state the second add would see the parent row, find no
/// affiliation, and append a duplicate.
#[test]
fn an_affiliation_added_twice_in_one_block_lands_once() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0x4C, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::AddNetworkAffiliation,
            &Affiliation {
                provider_id: [0x4C; 32],
                plan_id: PLAN_B,
            },
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::AddNetworkAffiliation,
            &Affiliation {
                provider_id: [0x4C; 32],
                plan_id: PLAN_B,
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_provider(&view, &[0x4Cu8; 32])
            .unwrap()
            .unwrap()
            .network_affiliations,
        vec![PLAN_B],
        "one affiliation, not two -- the second add read the candidate"
    );
    assert_eq!(
        HealthcareExecutor::v_get_network_provider_ids(&view, &PLAN_B).unwrap(),
        vec![[0x4Cu8; 32]],
        "and one index entry"
    );

    // Removing it clears the provider row and writes an empty index list.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                3,
                HealthcareOperation::RemoveNetworkAffiliation,
                &Affiliation {
                    provider_id: [0x4C; 32],
                    plan_id: PLAN_B,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    assert!(HealthcareExecutor::v_get_provider(&view, &[0x4Cu8; 32])
        .unwrap()
        .unwrap()
        .network_affiliations
        .is_empty());
    assert_eq!(
        view.get(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &PLAN_B)
            .unwrap()
            .as_deref(),
        Some(&bincode::serialize(&Vec::<[u8; 32]>::new()).unwrap()[..]),
        "an EMPTY list, written rather than deleted"
    );
}

/// Removing an affiliation the provider never had still STAGES an empty index
/// row, through dispatch.
///
/// The committed twin's remove is unconditional -- it re-serializes whatever
/// survives the `retain` and writes it -- and the candidate surface reproduces
/// that. A conditional write would be a quieter and arguably better subsystem;
/// it would also be a different one, so it is pinned rather than fixed.
#[test]
fn removing_an_affiliation_that_was_never_there_still_stages_an_empty_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0x4D, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::RemoveNetworkAffiliation,
            &Affiliation {
                provider_id: [0x4D; 32],
                plan_id: PLAN_B,
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        view.get(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &PLAN_B)
            .unwrap()
            .as_deref(),
        Some(&bincode::serialize(&Vec::<[u8; 32]>::new()).unwrap()[..]),
        "an EMPTY list is staged at a plan the provider was never in"
    );
    assert!(
        families_changed(&db, &view).contains(&cf::HEALTHCARE_PROVIDER_NETWORK_INDEX),
        "and that family really is one the candidate changed"
    );
}

// ── Consent supersession within one block ───────────────────────────────────

/// A consent granted and superseded in the same block: the supersede reads the
/// consent the block staged, marks it `Superseded`, and stores the new one.
#[test]
fn a_consent_is_granted_and_superseded_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::GrantConsent,
            &consent(0x60, addr),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::SupersedeConsent,
            &Supersede {
                old_consent_id: [0x60; 32],
                new_consent: consent(0x61, addr),
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        HealthcareExecutor::v_get_consent(&view, &[0x60u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::Superseded
    );
    assert_eq!(
        HealthcareExecutor::v_get_consent(&view, &[0x61u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::Granted
    );
    assert_eq!(
        HealthcareExecutor::v_get_subject_consent_ids(&view, &SUBJECT_NULL).unwrap(),
        vec![[0x60u8; 32], [0x61u8; 32]],
        "and both are in the subject index"
    );
}

/// Without the old consent, the same supersession is refused.
#[test]
fn without_the_old_consent_the_same_supersession_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::SupersedeConsent,
                &Supersede {
                    old_consent_id: [0x60; 32],
                    new_consent: consent(0x61, addr),
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, HEALTHCARE_FAILED);
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(StateManager::v_get_nonce(&view, &addr).unwrap(), 0);
}

// ── Abandonment ─────────────────────────────────────────────────────────────

/// Five transactions that between them write all TEN healthcare families.
///
/// Used by the abandonment test, the restart test and the journal test, so all
/// three are talking about the same block. `id` keeps the fixtures distinct.
fn a_block_touching_every_family(signer: &KeyPair, id: u8) -> Vec<SignedTransaction> {
    let addr = signer.address();
    vec![
        // providers + the plan-network index
        tx(
            signer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(id, addr, vec![PLAN_A]),
        ),
        // memberships + the member index
        tx(
            signer,
            1,
            HealthcareOperation::IssueMembership,
            &membership(id.wrapping_add(1), id, addr),
        ),
        // consents + the subject index
        tx(
            signer,
            2,
            HealthcareOperation::GrantConsent,
            &consent(id.wrapping_add(2), addr),
        ),
        // prescriptions + the patient and prescriber indexes
        tx(
            signer,
            3,
            HealthcareOperation::IssuePrescription,
            &prescription(id.wrapping_add(3), id, addr, 2),
        ),
        // proofs
        tx(
            signer,
            4,
            HealthcareOperation::SubmitProof,
            &proof_envelope(id.wrapping_add(4)),
        ),
    ]
}

/// A block writing every healthcare family commits none of it.
///
/// All ten are asserted STAGED first, by per-CF diff, so the canonical
/// comparison afterwards is a statement about ten discarded families and not
/// about a block that quietly did nothing.
#[test]
fn an_abandoned_block_leaves_all_ten_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for t in a_block_touching_every_family(&actor, 0x70) {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let touched = families_changed(&db, &view);
        for f in HEALTHCARE_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so this block does not test it"
            );
        }
        // dropped without publication
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every healthcare row byte-identical"
    );
}

// ── Limit refusal ───────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and the sweep finds ceilings
/// that refuse at EACH of the two index boundaries.
///
/// `IssuePrescription` is the operation to calibrate against: it writes the
/// prescription row, then the patient index, then the prescriber index, so a
/// ceiling can land in either gap. Every ceiling below the measured cost is
/// tried, not a sample -- the intervals are a few bytes wide.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let addr = actor.address();

    // The prescriber provider is CANONICAL, so the prescription transaction is
    // the only thing the candidate holds.
    HealthcareStore::new(&db)
        .providers()
        .put(&provider(0x78, addr, vec![]))
        .unwrap();
    let before = canonical(&db);

    let signed_tx = tx(
        &actor,
        0,
        HealthcareOperation::IssuePrescription,
        &prescription(0x79, 0x78, addr, 2),
    );

    for f in [
        cf::HEALTHCARE_PRESCRIPTIONS,
        cf::HEALTHCARE_PATIENT_RX_INDEX,
        cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
    ] {
        assert!(
            db.prefix_iter(f, &[]).unwrap().next().is_none(),
            "{f} must start canonically empty for the merged reads below to \
             stand for staged"
        );
    }

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut v = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut v, &signed_tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "a prescription must cost something");

    let (mut after_primary, mut after_patient) = (0usize, 0usize);
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let rx = view
            .get(cf::HEALTHCARE_PRESCRIPTIONS, &[0x79u8; 32])
            .unwrap()
            .is_some();
        let patient = view
            .get(cf::HEALTHCARE_PATIENT_RX_INDEX, &PATIENT_NULL)
            .unwrap()
            .is_some();
        let prescriber = view
            .get(cf::HEALTHCARE_PRESCRIBER_RX_INDEX, &[0x78u8; 32])
            .unwrap()
            .is_some();

        if rx && !patient && !prescriber {
            after_primary += 1;
        }
        if rx && patient && !prescriber {
            after_patient += 1;
        }
        assert!(
            (!patient || rx) && (!prescriber || patient),
            "ceiling {ceiling} staged an index without its predecessor, which \
             the write order cannot produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must commit nothing"
        );
    }
    assert!(
        after_primary > 0,
        "no ceiling refused with the prescription staged and its patient index not"
    );
    assert!(
        after_patient > 0,
        "no ceiling refused with the patient index staged and the prescriber \
         index not"
    );
}

// ── Parity, including a restart ─────────────────────────────────────────────

/// Published rows satisfy the committed scans AND survive a restart.
///
/// Reading back through the same handle proves the write reached the database's
/// view of itself, not that it is durable. This closes the handle -- asserting
/// the strong count first, so the close is proved rather than hoped for -- and
/// reopens at the same path. Same block shape as the abandonment test: all ten
/// families.
#[test]
fn published_healthcare_rows_survive_a_database_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let actor = KeyPair::generate();

    let expected: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &actor, 500_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[3u8; 32],
            a_block_touching_every_family(&actor, 0x80),
            &[],
        );
        assert_eq!(receipts.len(), 5);
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all five must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        let rows = canonical(&db);
        for f in HEALTHCARE_CFS {
            assert!(
                rows.iter().any(|(fam, _, _)| fam == f),
                "{f} carries no committed row, so the restart proves nothing \
                 about it"
            );
        }

        // The committed scans the RPC uses, through this handle.
        assert_committed_readers_resolve(&db);

        drop(executor);
        drop(state);
        assert_eq!(
            std::sync::Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             actually close it and this test proves nothing about durability"
        );
        drop(db);
        rows
    };

    // Reopen at the same path.
    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    assert_eq!(
        canonical(&db),
        expected,
        "every healthcare row must survive the restart, byte for byte"
    );
    assert_committed_readers_resolve(&db);
}

/// The committed readers, driven against whichever handle is passed.
fn assert_committed_readers_resolve(db: &Database) {
    let store = HealthcareStore::new(db);
    assert!(store.providers().get(&[0x80u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .providers()
            .get_by_network(&PLAN_A)
            .unwrap()
            .iter()
            .map(|p| p.provider_id)
            .collect::<Vec<_>>(),
        vec![[0x80u8; 32]],
        "the network index resolves"
    );
    assert!(store.memberships().get(&[0x81u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .memberships()
            .get_by_member(&MEMBER_NULL)
            .unwrap()
            .iter()
            .map(|m| m.membership_id)
            .collect::<Vec<_>>(),
        vec![[0x81u8; 32]],
        "the member index resolves"
    );
    assert!(store.consents().get(&[0x82u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .consents()
            .get_by_subject(&SUBJECT_NULL)
            .unwrap()
            .iter()
            .map(|c| c.consent_id)
            .collect::<Vec<_>>(),
        vec![[0x82u8; 32]],
        "the subject index resolves"
    );
    assert!(store.prescriptions().get(&[0x83u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .prescriptions()
            .get_by_patient(&PATIENT_NULL)
            .unwrap()
            .iter()
            .map(|p| p.prescription_id)
            .collect::<Vec<_>>(),
        vec![[0x83u8; 32]],
        "the patient index resolves"
    );
    assert_eq!(
        store
            .prescriptions()
            .get_by_prescriber(&[0x80u8; 32])
            .unwrap()
            .iter()
            .map(|p| p.prescription_id)
            .collect::<Vec<_>>(),
        vec![[0x83u8; 32]],
        "the prescriber index resolves"
    );
    assert!(store.proofs().get(&[0x84u8; 32]).unwrap().is_some());
}

// ── The second dispatch surface ─────────────────────────────────────────────

/// `execute_tx_v2` routes healthcare through the candidate too.
#[test]
fn the_v2_dispatch_surface_also_stages_healthcare() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = actor.address();
    let before = canonical(&db);
    let key = *actor.public_key().as_bytes();

    let v2 = |nonce: u64, op: HealthcareOperation, data: Vec<u8>| {
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: addr,
            fee: 100,
            nonce,
            payload: TxPayload::Healthcare(HealthcareTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        (t, sig)
    };

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        let (t, sig) = v2(
            0,
            HealthcareOperation::RegisterProvider,
            bincode::serialize(&provider(0x90, addr, vec![PLAN_A])).unwrap(),
        );
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute a provider registration: {:?}",
            r.status
        );
        let changed = families_changed(&db, &view);
        assert!(changed.contains(&cf::HEALTHCARE_PROVIDERS));
        assert!(changed.contains(&cf::HEALTHCARE_PROVIDER_NETWORK_INDEX));

        // A second transaction through the SAME surface, which has to see the
        // first one's provider, and which carries this arm's own
        // `0, // block_timestamp placeholder` into the row it rewrites.
        let (t, sig) = v2(
            1,
            HealthcareOperation::SuspendProvider,
            bincode::serialize(&ProviderId {
                provider_id: [0x90; 32],
            })
            .unwrap(),
        );
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must see the provider it staged a moment ago: {:?}",
            r.status
        );
        let p = HealthcareExecutor::v_get_provider(&view, &[0x90u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(p.status, ProviderStatus::Suspended);
        assert_eq!(
            p.updated_at, 0,
            "and this arm passes 0 where the block timestamp belongs, exactly \
             like the live one"
        );

        // A prescription through this arm, which has to find that provider.
        let (t, sig) = v2(
            2,
            HealthcareOperation::IssuePrescription,
            bincode::serialize(&prescription(0x91, 0x90, addr, 2)).unwrap(),
        );
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        assert_eq!(
            HealthcareExecutor::v_get_prescriber_rx_ids(&view, &[0x90u8; 32]).unwrap(),
            vec![[0x91u8; 32]],
            "and the prescriber index it staged is visible on this arm too"
        );

        // And a refusal on this arm carries the healthcare status code, not a
        // neighbouring subsystem's.
        let (t, sig) = v2(
            3,
            HealthcareOperation::CancelPrescription,
            bincode::serialize(&PrescriptionId {
                prescription_id: [0x7F; 32],
            })
            .unwrap(),
        );
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status, HEALTHCARE_FAILED,
            "a missing prescription must fail IN the healthcare arm of this \
             surface"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &addr).unwrap(),
            3,
            "and the refusal does not advance the nonce"
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

// ── Corrupt rows: every family, with the staged state named ─────────────────

/// One corrupt-row case: which family is corrupted, the operation that has to
/// READ it, and the exact candidate state the failure is required to leave.
struct CorruptCase {
    family: &'static str,
    label: &'static str,
    /// Healthcare families whose candidate contents must differ from committed,
    /// and nothing else. Named exactly -- not an allowed set.
    staged: &'static [&'static str],
    /// The sender's nonce after the failure. `0` means the read failed before
    /// the fee was charged; `1` means execution got past the guards.
    nonce: u64,
}

/// A corrupt row makes the routed transaction ERROR; it is never read as
/// absence. What the candidate holds afterwards is asserted positively, family
/// by family, key by key.
///
/// This is the difference between "no such consent" and "that consent's row is
/// corrupt", and every guard here branches on exactly that. A candidate reader
/// that swallowed a decode failure into `None` would turn corruption into a
/// duplicate-id opportunity, or into a prescription recorded against a
/// prescriber whose profile could not be read.
///
/// Nine of the ten families are covered here: four corrupt PRIMARY rows and all
/// five corrupt INDEX rows. The tenth, `HEALTHCARE_PROOFS`, has no decoding
/// reader reachable from dispatch -- `SubmitProof` guards with `contains` --
/// and is pinned separately, as a preserved defect, by
/// `a_corrupt_proof_row_is_read_as_presence_not_as_corruption`.
///
/// The five index cases are the ones that leave state: the primary write
/// precedes every index append, so the row is staged and the fee has been
/// charged when the append fails. Each is asserted as exact bytes, and the
/// corrupt index row is asserted UNCHANGED.
#[test]
fn corrupt_rows_error_through_dispatch_with_exactly_this_staged() {
    const CORRUPT: &[u8] = b"not a valid row";

    let cases = [
        CorruptCase {
            family: cf::HEALTHCARE_PROVIDERS,
            label: "provider",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::HEALTHCARE_MEMBERSHIPS,
            label: "membership",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::HEALTHCARE_CONSENTS,
            label: "consent",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::HEALTHCARE_PRESCRIPTIONS,
            label: "prescription",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
            label: "network index",
            staged: &[cf::HEALTHCARE_PROVIDERS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::HEALTHCARE_MEMBER_INDEX,
            label: "member index",
            staged: &[cf::HEALTHCARE_MEMBERSHIPS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
            label: "subject consent index",
            staged: &[cf::HEALTHCARE_CONSENTS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::HEALTHCARE_PATIENT_RX_INDEX,
            label: "patient index",
            staged: &[cf::HEALTHCARE_PRESCRIPTIONS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
            label: "prescriber index",
            staged: &[
                cf::HEALTHCARE_PRESCRIPTIONS,
                cf::HEALTHCARE_PATIENT_RX_INDEX,
            ],
            nonce: 1,
        },
    ];

    for case in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);
        let addr = actor.address();

        // Keys written by hand, from the schema and not from the key builders,
        // so a change to a builder cannot silently move this test with it.
        let key: Vec<u8> = match case.family {
            f if f == cf::HEALTHCARE_PROVIDER_NETWORK_INDEX => PLAN_A.to_vec(),
            f if f == cf::HEALTHCARE_MEMBER_INDEX => MEMBER_NULL.to_vec(),
            f if f == cf::HEALTHCARE_SUBJECT_CONSENT_INDEX => SUBJECT_NULL.to_vec(),
            f if f == cf::HEALTHCARE_PATIENT_RX_INDEX => PATIENT_NULL.to_vec(),
            f if f == cf::HEALTHCARE_PRESCRIBER_RX_INDEX => vec![0xB0u8; 32],
            f if f == cf::HEALTHCARE_MEMBERSHIPS => vec![0xB1u8; 32],
            f if f == cf::HEALTHCARE_CONSENTS => vec![0xB2u8; 32],
            f if f == cf::HEALTHCARE_PRESCRIPTIONS => vec![0xB3u8; 32],
            _ => vec![0xB0u8; 32],
        };

        // What each guard needs in order to REACH the corrupt row. Anything
        // that has to be present and VALID is written canonically first.
        let store = HealthcareStore::new(&db);
        let (op, data): (HealthcareOperation, Vec<u8>) = match case.family {
            f if f == cf::HEALTHCARE_PROVIDERS => (
                HealthcareOperation::SuspendProvider,
                bincode::serialize(&ProviderId {
                    provider_id: [0xB0; 32],
                })
                .unwrap(),
            ),
            f if f == cf::HEALTHCARE_MEMBERSHIPS => (
                HealthcareOperation::SuspendMembership,
                bincode::serialize(&MembershipId {
                    membership_id: [0xB1; 32],
                })
                .unwrap(),
            ),
            f if f == cf::HEALTHCARE_CONSENTS => (
                HealthcareOperation::RevokeConsent,
                bincode::serialize(&ConsentId {
                    consent_id: [0xB2; 32],
                })
                .unwrap(),
            ),
            f if f == cf::HEALTHCARE_PRESCRIPTIONS => (
                HealthcareOperation::CancelPrescription,
                bincode::serialize(&PrescriptionId {
                    prescription_id: [0xB3; 32],
                })
                .unwrap(),
            ),
            f if f == cf::HEALTHCARE_PROVIDER_NETWORK_INDEX => (
                HealthcareOperation::RegisterProvider,
                bincode::serialize(&provider(0xB0, addr, vec![PLAN_A])).unwrap(),
            ),
            f if f == cf::HEALTHCARE_MEMBER_INDEX => {
                // IssueMembership reads the index only after it has found the
                // provider, so that has to be present and valid.
                store
                    .providers()
                    .put(&provider(0xB0, addr, vec![]))
                    .unwrap();
                (
                    HealthcareOperation::IssueMembership,
                    bincode::serialize(&membership(0xB1, 0xB0, addr)).unwrap(),
                )
            }
            f if f == cf::HEALTHCARE_SUBJECT_CONSENT_INDEX => (
                HealthcareOperation::GrantConsent,
                bincode::serialize(&consent(0xB2, addr)).unwrap(),
            ),
            _ => {
                // Both prescription-index cases. The prescriber provider has to
                // be present and valid; for the PRESCRIBER case the patient
                // index must also be present and valid, so it is written with a
                // real one-element list.
                store
                    .providers()
                    .put(&provider(0xB0, addr, vec![]))
                    .unwrap();
                if case.family == cf::HEALTHCARE_PRESCRIBER_RX_INDEX {
                    db.put(
                        cf::HEALTHCARE_PATIENT_RX_INDEX,
                        &PATIENT_NULL,
                        &bincode::serialize(&vec![[0xC0u8; 32]]).unwrap(),
                    )
                    .unwrap();
                }
                (
                    HealthcareOperation::IssuePrescription,
                    bincode::serialize(&prescription(0xB3, 0xB0, addr, 2)).unwrap(),
                )
            }
        };
        db.put(case.family, &key, CORRUPT).unwrap();

        let before = canonical(&db);
        let t = signed(&actor, 0, op, data);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &t, &proposer, 1, 1000);
            let err = outcome.err().unwrap_or_else(|| {
                panic!(
                    "a corrupt {} row must ERROR, not be read as absence",
                    case.label
                )
            });
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {} failure must name the decode, not something else: {text}",
                case.label
            );

            // Exactly these families changed. Not a subset, not an allowed set.
            assert_eq!(
                families_changed(&db, &view),
                case.staged.to_vec(),
                "{}: the candidate must hold exactly the families named for \
                 this case",
                case.label
            );

            // And exactly this content, where anything is staged at all.
            if case.family == cf::HEALTHCARE_PROVIDER_NETWORK_INDEX {
                assert_eq!(
                    view.get(cf::HEALTHCARE_PROVIDERS, &[0xB0u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&provider(0xB0, addr, vec![PLAN_A])).unwrap()[..]),
                    "the provider written before the failing append, byte for byte"
                );
            }
            if case.family == cf::HEALTHCARE_MEMBER_INDEX {
                assert_eq!(
                    view.get(cf::HEALTHCARE_MEMBERSHIPS, &[0xB1u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&membership(0xB1, 0xB0, addr)).unwrap()[..]),
                    "the membership written before the failing append, byte for byte"
                );
            }
            if case.family == cf::HEALTHCARE_SUBJECT_CONSENT_INDEX {
                assert_eq!(
                    view.get(cf::HEALTHCARE_CONSENTS, &[0xB2u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&consent(0xB2, addr)).unwrap()[..]),
                    "the consent written before the failing append, byte for byte"
                );
            }
            if case.family == cf::HEALTHCARE_PATIENT_RX_INDEX
                || case.family == cf::HEALTHCARE_PRESCRIBER_RX_INDEX
            {
                assert_eq!(
                    view.get(cf::HEALTHCARE_PRESCRIPTIONS, &[0xB3u8; 32])
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&prescription(0xB3, 0xB0, addr, 2)).unwrap()[..]),
                    "the prescription written before the failing append, byte for byte"
                );
            }
            if case.family == cf::HEALTHCARE_PRESCRIBER_RX_INDEX {
                assert_eq!(
                    view.get(cf::HEALTHCARE_PATIENT_RX_INDEX, &PATIENT_NULL)
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&vec![[0xC0u8; 32], [0xB3u8; 32]]).unwrap()[..]),
                    "and the patient index, appended before the prescriber \
                     index failed"
                );
            }

            // The corrupt row itself is never rewritten or repaired.
            assert_eq!(
                view.get(case.family, &key).unwrap().as_deref(),
                Some(CORRUPT),
                "{}: the corrupt bytes must be left exactly as they were",
                case.label
            );

            // The account side, positively: whether the fee was charged says
            // where in the arm the failure happened.
            assert_eq!(
                StateManager::v_get_nonce(&view, &addr).unwrap(),
                case.nonce,
                "{}: nonce after the failure",
                case.label
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {}",
            case.label
        );
    }
}

// ── Behaviours reproduced deliberately, not fixed ───────────────────────────

/// `SubmitProof` guards with `contains`, so a CORRUPT proof row is refused as a
/// duplicate rather than reported as corruption.
///
/// Preserved, not fixed: making it decode would change which transactions are
/// valid, which is a consensus change and belongs in separately activated work.
#[test]
fn a_corrupt_proof_row_is_read_as_presence_not_as_corruption() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    db.put(cf::HEALTHCARE_PROOFS, &[0x90u8; 32], b"not a valid row")
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                HealthcareOperation::SubmitProof,
                &proof_envelope(0x90),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "the corrupt row is treated as an existing proof -- a FAILURE, not the \
         error a decoding guard would raise"
    );
    assert_eq!(
        view.get(cf::HEALTHCARE_PROOFS, &[0x90u8; 32])
            .unwrap()
            .as_deref(),
        Some(&b"not a valid row"[..]),
        "and the corrupt bytes are left exactly as they were"
    );
    assert_eq!(
        families_changed(&db, &view),
        Vec::<&str>::new(),
        "with nothing staged in any healthcare family"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        0,
        "and no fee charged -- the guard refused before the deduct"
    );
}

/// `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
/// returns success for a proof id that was never submitted, without
/// deserializing its payload at all.
#[test]
fn verify_proof_succeeds_for_a_proof_that_does_not_exist() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            // Not a proof envelope at all. It is never deserialized.
            &signed(
                &actor,
                0,
                HealthcareOperation::VerifyProof,
                b"\xff\xff\xff\xff".to_vec(),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    assert!(
        matches!(r.status, TxStatus::Success),
        "verification of a non-existent proof succeeds: {:?}",
        r.status
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and writes nothing to any healthcare family"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "while still charging the fee and advancing the nonce"
    );
}

/// Nobody checks the SUBJECT of a consent.
///
/// `GrantConsent` requires the envelope's ISSUER to be the sender and compares
/// nothing to `subject_address` or `subject_ref`. So the subject's own
/// signature is neither required to grant a consent about them nor sufficient:
/// a subject attempting to grant their own consent is REFUSED because they are
/// not the issuer.
///
/// Preserved, not fixed: binding consent to its subject changes which
/// transactions are valid, which is a consensus change.
#[test]
fn the_subject_of_a_consent_can_neither_grant_nor_revoke_it() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let subject = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &subject, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer_addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // The consent names the SUBJECT's address, and the issuer grants it. The
    // subject is never consulted.
    let mut c = consent(0xA0, issuer_addr);
    c.subject_address = subject.address();
    let r = executor
        .execute_tx(
            &mut view,
            &tx(&issuer, 0, HealthcareOperation::GrantConsent, &c),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the issuer grants a consent about someone else without their \
         participation: {:?}",
        r.status
    );

    // The subject cannot revoke it.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &subject,
                0,
                HealthcareOperation::RevokeConsent,
                &ConsentId {
                    consent_id: [0xA0; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "and the subject of the consent may not revoke it -- only the issuer may"
    );
    assert_eq!(
        HealthcareExecutor::v_get_consent(&view, &[0xA0u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::Granted
    );

    // Nor grant one of their own, because they are not the issuer named in it.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &subject,
                0,
                HealthcareOperation::GrantConsent,
                &consent(0xA1, issuer_addr),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "the subject cannot grant a consent naming the issuer either"
    );
}

/// `SupersedeConsent` checks NOTHING about the sender.
///
/// Every other consent operation requires the sender to be the recorded issuer.
/// This one only checks that the old consent exists, and then marks it
/// `Superseded` and stores a replacement whose entire contents come from the
/// payload -- a different subject, a different recipient, a different scope, a
/// different issuer. It is a complete bypass of the consent lifecycle's
/// authorization.
///
/// Preserved, not fixed. This is the single most serious item in the healthcare
/// inventory.
#[test]
fn any_sender_can_supersede_any_consent_with_one_of_their_own() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    assert_ne!(issuer.address(), stranger.address());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::GrantConsent,
                &consent(0xA2, issuer.address()),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    // The stranger's replacement names ITSELF as issuer and widens the scope.
    let mut replacement = consent(0xA3, stranger.address());
    replacement.scope = DisclosureScope::AllRecords;
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                0,
                HealthcareOperation::SupersedeConsent,
                &Supersede {
                    old_consent_id: [0xA2; 32],
                    new_consent: replacement,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "a stranger superseded someone else's consent: {:?}",
        r.status
    );

    assert_eq!(
        HealthcareExecutor::v_get_consent(&view, &[0xA2u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::Superseded,
        "the original is retired"
    );
    let new = HealthcareExecutor::v_get_consent(&view, &[0xA3u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(new.issuer_address, stranger.address());
    assert_eq!(
        new.scope,
        DisclosureScope::AllRecords,
        "and the replacement the stranger wrote discloses ALL records rather than treatment only"
    );
    assert_eq!(
        HealthcareExecutor::v_get_subject_consent_ids(&view, &SUBJECT_NULL).unwrap(),
        vec![[0xA2u8; 32], [0xA3u8; 32]],
        "both are indexed under the same subject nullifier"
    );
}

/// Filling a prescription requires no authorization of any kind.
///
/// `FillPrescription` and `PartialFillPrescription` check validity and refills
/// and nothing about the sender: not the patient, not the prescriber, not the
/// pharmacy, not the issuer. Every other prescription operation checks the
/// issuer.
#[test]
fn any_sender_can_fill_any_prescription() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0xA4, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &prescription(0xA5, 0xA4, addr, 2),
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }

    for (nonce, op) in [
        (0u64, HealthcareOperation::FillPrescription),
        (1, HealthcareOperation::PartialFillPrescription),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &stranger,
                    nonce,
                    op,
                    &Fill {
                        prescription_id: [0xA5; 32],
                        fill_commitment: [0xA6u8.wrapping_add(nonce as u8); 32],
                    },
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} by a stranger: {:?}",
            r.status
        );
    }

    let rx = HealthcareExecutor::v_get_prescription(&view, &[0xA5u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(rx.fill_history.len(), 2, "a stranger filled it twice");
    assert_eq!(rx.refills_remaining, 1);

    // The contrast: cancelling the same prescription IS checked.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                2,
                HealthcareOperation::CancelPrescription,
                &PrescriptionId {
                    prescription_id: [0xA5; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "but only the issuer may cancel it -- the asymmetry is the defect"
    );
}

/// Network affiliations may be changed by anyone.
///
/// `AddNetworkAffiliation` and `RemoveNetworkAffiliation` are the only provider
/// operations with no issuer check: they verify the provider exists and write.
#[test]
fn any_sender_can_change_a_providers_network_affiliations() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(0xA7, addr, vec![PLAN_A]),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    for (nonce, op, plan) in [
        (0u64, HealthcareOperation::AddNetworkAffiliation, PLAN_B),
        (1, HealthcareOperation::RemoveNetworkAffiliation, PLAN_A),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &tx(
                    &stranger,
                    nonce,
                    op,
                    &Affiliation {
                        provider_id: [0xA7; 32],
                        plan_id: plan,
                    },
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} by a stranger: {:?}",
            r.status
        );
    }

    assert_eq!(
        HealthcareExecutor::v_get_provider(&view, &[0xA7u8; 32])
            .unwrap()
            .unwrap()
            .network_affiliations,
        vec![PLAN_B],
        "a stranger moved the provider from one plan's network to another"
    );

    // The contrast: suspending the same provider IS checked.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                2,
                HealthcareOperation::SuspendProvider,
                &ProviderId {
                    provider_id: [0xA7; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "but only the issuer may suspend"
    );
}

/// Renewing a TERMINATED membership resurrects it.
///
/// `RenewMembership` sets the status to `Active` unconditionally. There is no
/// transition check, so a membership that was terminated a transaction earlier
/// is active again by the end of the block.
#[test]
fn renewing_a_terminated_membership_makes_it_active_again() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0xA8, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssueMembership,
            &membership(0xA9, 0xA8, addr),
        ),
        tx(
            &issuer,
            2,
            HealthcareOperation::TerminateMembership,
            &MembershipId {
                membership_id: [0xA9; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    assert_eq!(
        HealthcareExecutor::v_get_membership(&view, &[0xA9u8; 32])
            .unwrap()
            .unwrap()
            .status,
        MembershipStatus::Terminated
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                3,
                HealthcareOperation::RenewMembership,
                &Renewal {
                    membership_id: [0xA9; 32],
                    new_expiry: 9_999_999,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let m = HealthcareExecutor::v_get_membership(&view, &[0xA9u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        m.status,
        MembershipStatus::Active,
        "a terminated membership is Active again after a renewal, with no \
         transition check anywhere"
    );
    assert_eq!(m.expiry, Some(9_999_999));
}

/// Both dispatch arms pass a literal `0` where the block timestamp belongs, so
/// every healthcare timestamp the executor writes is 0 regardless of the block
/// -- AND the prescription validity window is evaluated at time zero.
///
/// The second half is worse than the cosmetic one: a prescription with a
/// non-zero `effective_from` can never be filled, and an EXPIRED one can always
/// be filled, because `0 >= expiry` is false for every positive expiry.
#[test]
fn the_block_timestamp_reaching_healthcare_operations_is_always_zero() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // An expired prescription, and one whose effective date has not arrived.
    let mut expired = prescription(0xAA, 0xAB, addr, 2);
    expired.expiry = 1_000;
    let mut future = prescription(0xAC, 0xAB, addr, 2);
    future.effective_from = Some(1_000);

    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0xAB, addr, vec![]),
        ),
        tx(&issuer, 1, HealthcareOperation::IssuePrescription, &expired),
        tx(&issuer, 2, HealthcareOperation::IssuePrescription, &future),
    ] {
        let r = executor
            // A block timestamp that is emphatically not zero.
            .execute_tx(&mut view, &t, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // The EXPIRED one fills.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                3,
                HealthcareOperation::FillPrescription,
                &Fill {
                    prescription_id: [0xAA; 32],
                    fill_commitment: [0xAD; 32],
                },
            ),
            &proposer,
            1,
            1_700_000_000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "a prescription that expired at t=1000 fills at a block timestamp of \
         1_700_000_000, because the guard is evaluated at 0: {:?}",
        r.status
    );
    let rx = HealthcareExecutor::v_get_prescription(&view, &[0xAAu8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        rx.updated_at, 0,
        "and the row records the placeholder, not 1_700_000_000"
    );

    // The FUTURE-dated one does not.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                4,
                HealthcareOperation::FillPrescription,
                &Fill {
                    prescription_id: [0xAC; 32],
                    fill_commitment: [0xAE; 32],
                },
            ),
            &proposer,
            1,
            1_700_000_000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "while one effective from t=1000 can never be filled at all"
    );
}

/// A prescription with zero refills left but status `Active` can still be
/// filled once more.
///
/// The guard is `refills_remaining == 0 && status != Active`, so a row in that
/// combination passes, `record_fill` appends the fill, leaves the counter at
/// zero, and stamps `Filled`.
#[test]
fn a_prescription_with_no_refills_but_active_status_can_be_filled_once_more() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut zero = prescription(0xB4, 0xB5, addr, 0);
    zero.refills_authorized = 0;
    zero.refills_remaining = 0;
    zero.status = PrescriptionStatus::Active;

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0xB5, addr, vec![]),
        ),
        tx(&issuer, 1, HealthcareOperation::IssuePrescription, &zero),
        tx(
            &issuer,
            2,
            HealthcareOperation::FillPrescription,
            &Fill {
                prescription_id: [0xB4; 32],
                fill_commitment: [0xB6; 32],
            },
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    let rx = HealthcareExecutor::v_get_prescription(&view, &[0xB4u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        rx.fill_history,
        vec![[0xB6u8; 32]],
        "a prescription authorizing zero refills was filled anyway"
    );
    assert_eq!(rx.status, PrescriptionStatus::Filled);
}

/// The controlled-substance guard is the one place `is_controlled` is read, and
/// it only covers ONE status value.
///
/// `UpdatePrescription` refuses `TransferRequested` for a controlled substance.
/// Nothing else consults the flag: the same prescription can be filled, held,
/// released and cancelled exactly like any other, and any other status may be
/// set on it directly.
#[test]
fn the_controlled_substance_guard_covers_only_the_transfer_status() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let addr = issuer.address();

    let mut controlled = prescription(0xB7, 0xB8, addr, 2);
    controlled.is_controlled = true;

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &issuer,
            0,
            HealthcareOperation::RegisterProvider,
            &provider(0xB8, addr, vec![]),
        ),
        tx(
            &issuer,
            1,
            HealthcareOperation::IssuePrescription,
            &controlled,
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // The guard fires, reading the `is_controlled` flag from the candidate.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                2,
                HealthcareOperation::UpdatePrescription,
                &PrescriptionStatusUpdate {
                    prescription_id: [0xB7; 32],
                    status: PrescriptionStatus::TransferRequested,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, HEALTHCARE_FAILED,
        "a controlled substance may not be moved to TransferRequested"
    );

    // And nothing else is covered: `Superseded` is accepted on the same row.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &issuer,
                2,
                HealthcareOperation::UpdatePrescription,
                &PrescriptionStatusUpdate {
                    prescription_id: [0xB7; 32],
                    status: PrescriptionStatus::Superseded,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "every other status is accepted for a controlled substance: {:?}",
        r.status
    );
    assert_eq!(
        HealthcareExecutor::v_get_prescription(&view, &[0xB7u8; 32])
            .unwrap()
            .unwrap()
            .status,
        PrescriptionStatus::Superseded
    );
}

/// The eleventh healthcare column family, `healthcare_system_events`, is never
/// written by any operation, so the healthcare journal is empty on every chain.
#[test]
fn the_healthcare_event_journal_is_never_written() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let executor =
        sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[4u8; 32],
        a_block_touching_every_family(&actor, 0xC0),
        &[],
    );
    assert!(receipts
        .iter()
        .all(|r| matches!(r.status, TxStatus::Success)));

    assert_eq!(
        db.prefix_iter(cf::HEALTHCARE_SYSTEM_EVENTS, &[])
            .unwrap()
            .count(),
        0,
        "five successful operations across all ten written families leave the \
         eleventh, the journal, empty"
    );
    // And the three address-keyed index families the schema declares are never
    // written either -- `execution_closure` calls them dead, and this is that
    // claim driven through a real block.
    for f in [
        cf::HEALTHCARE_MEMBER_ADDRESS_INDEX,
        cf::HEALTHCARE_SUBJECT_ADDRESS_INDEX,
        cf::HEALTHCARE_PATIENT_ADDRESS_INDEX,
    ] {
        assert_eq!(
            db.prefix_iter(f, &[]).unwrap().count(),
            0,
            "{f} is declared and never written, even though every row carries \
             the address it would be keyed by"
        );
    }
}

/// The committed healthcare readers are unpaginated whole-family scans.
///
/// `list_active` walks every row in its column family and returns one `Vec`,
/// and `get_by_patient` / `get_by_network` resolve their whole index list.
/// There is no limit, offset or cursor to ask for fewer. Pinned rather than
/// fixed: these are the RPC's readers and changing their signatures is API
/// work, not part of moving writes onto the candidate.
#[test]
fn the_committed_healthcare_readers_return_two_thousand_rows_whole() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let store = HealthcareStore::new(&db);
    let issuer = Address::new([0xE0; 20]);

    for i in 0..2_000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());

        let mut p = provider(1, issuer, vec![PLAN_A]);
        p.provider_id = id;
        store.providers().put(&p).unwrap();

        let mut rx = prescription(1, 1, issuer, 2);
        rx.prescription_id = id;
        store.prescriptions().put(&rx).unwrap();
    }

    assert_eq!(
        store.providers().list_active().unwrap().len(),
        2_000,
        "every active provider, in one Vec, with no way to ask for fewer"
    );
    assert_eq!(
        store.providers().get_by_network(&PLAN_A).unwrap().len(),
        2_000,
        "and the whole network index list, resolved row by row"
    );
    assert_eq!(
        store
            .prescriptions()
            .get_by_patient(&PATIENT_NULL)
            .unwrap()
            .len(),
        2_000
    );
}

// ── The seven accumulating structures, measured ─────────────────────────────
//
// Five INDEX families whose values are `Vec` lists, and two lists that
// accumulate INSIDE a primary row: a membership's `dependents` and a
// prescription's `fill_history`. All seven are read-modify-write, none is
// capped, and every one of them re-serializes its entire contents on every
// append.
//
// Each case below measures ONE size: 20,000 entries. That does not and cannot
// establish that no input reaches an allocator abort; a cap would change which
// transactions are valid and belongs in separately activated work. The
// allocation figures themselves are in `healthcare_index_allocation.rs`, which
// installs a counting allocator and holds exactly one test.

/// Twenty thousand ids, spelled the same way for every accumulating structure.
fn twenty_thousand_ids() -> Vec<[u8; 32]> {
    (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

/// One accumulating structure, put through both halves of the same question.
///
/// * A 4,096-byte ceiling refuses, canonical storage is unchanged, and the
///   candidate still sees the OLD contents byte for byte.
/// * With room, exactly one entry is appended and all 20,000 existing ones
///   survive IN ORDER -- compared as a whole slice, not sampled.
///
/// `staged_primary`, where given, is the row the write order puts BEFORE the
/// failing append; asserting it is staged is what places the refusal at the
/// accumulator rather than somewhere earlier.
#[allow(clippy::too_many_arguments)]
fn assert_accumulator(
    label: &str,
    seed: impl Fn(&Database, Address),
    build: impl Fn(&KeyPair) -> SignedTransaction,
    family: &'static str,
    key: Vec<u8>,
    staged_primary: Option<(&'static str, Vec<u8>)>,
    read_back: impl Fn(&ExecutionView<'_, '_>) -> Vec<[u8; 32]>,
    appended: [u8; 32],
) {
    let existing = twenty_thousand_ids();
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());

    let committed_row = db
        .get(family, &key)
        .unwrap()
        .unwrap_or_else(|| panic!("{label}: the seed must have written {family}"));
    assert!(
        committed_row.len() > 640_000,
        "{label}: the fixture must actually be large: {} B",
        committed_row.len()
    );
    let before = canonical(&db);
    let t = build(&actor);

    // Tight ceiling.
    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .expect_err("a structure far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "{label}: refused by the ceiling, not by something else: {err}"
        );
        if let Some((pf, pk)) = &staged_primary {
            assert!(
                view.get(pf, pk).unwrap().is_some(),
                "{label}: {pf} must be staged, which is what puts the failure \
                 at the accumulating write"
            );
        }
        assert_eq!(
            view.get(family, &key).unwrap(),
            Some(committed_row.clone()),
            "{label}: the candidate must still see the committed contents, \
             byte for byte"
        );
    }
    assert_eq!(canonical(&db), before, "{label}: and nothing is committed");

    // With room.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{label}: {:?}",
            r.status
        );
        let ids = read_back(&view);
        assert_eq!(ids.len(), 20_001, "{label}: appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "{label}: every existing entry preserved, in order"
        );
        assert_eq!(ids[20_000], appended, "{label}: and the new one last");
    }
    assert_eq!(canonical(&db), before, "{label}: still nothing committed");
}

#[test]
fn a_640_kb_provider_network_index_is_refused_by_the_ceiling_without_canonical_change() {
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_eq!(fixture.len(), 640_008);
    assert_accumulator(
        "provider network index",
        move |db, _addr| {
            db.put(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &PLAN_A, &fixture)
                .unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::RegisterProvider,
                &provider(0xD0, actor.address(), vec![PLAN_A]),
            )
        },
        cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
        PLAN_A.to_vec(),
        Some((cf::HEALTHCARE_PROVIDERS, vec![0xD0u8; 32])),
        |view| HealthcareExecutor::v_get_network_provider_ids(view, &PLAN_A).unwrap(),
        [0xD0u8; 32],
    );
}

#[test]
fn a_640_kb_member_index_is_refused_by_the_ceiling_without_canonical_change() {
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_accumulator(
        "member index",
        move |db, addr| {
            HealthcareStore::new(db)
                .providers()
                .put(&provider(0xD0, addr, vec![]))
                .unwrap();
            db.put(cf::HEALTHCARE_MEMBER_INDEX, &MEMBER_NULL, &fixture)
                .unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::IssueMembership,
                &membership(0xD1, 0xD0, actor.address()),
            )
        },
        cf::HEALTHCARE_MEMBER_INDEX,
        MEMBER_NULL.to_vec(),
        Some((cf::HEALTHCARE_MEMBERSHIPS, vec![0xD1u8; 32])),
        |view| HealthcareExecutor::v_get_member_membership_ids(view, &MEMBER_NULL).unwrap(),
        [0xD1u8; 32],
    );
}

#[test]
fn a_640_kb_subject_consent_index_is_refused_by_the_ceiling_without_canonical_change() {
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_accumulator(
        "subject consent index",
        move |db, _addr| {
            db.put(
                cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
                &SUBJECT_NULL,
                &fixture,
            )
            .unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::GrantConsent,
                &consent(0xD2, actor.address()),
            )
        },
        cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
        SUBJECT_NULL.to_vec(),
        Some((cf::HEALTHCARE_CONSENTS, vec![0xD2u8; 32])),
        |view| HealthcareExecutor::v_get_subject_consent_ids(view, &SUBJECT_NULL).unwrap(),
        [0xD2u8; 32],
    );
}

#[test]
fn a_640_kb_patient_index_is_refused_by_the_ceiling_without_canonical_change() {
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_accumulator(
        "patient prescription index",
        move |db, addr| {
            HealthcareStore::new(db)
                .providers()
                .put(&provider(0xD0, addr, vec![]))
                .unwrap();
            db.put(cf::HEALTHCARE_PATIENT_RX_INDEX, &PATIENT_NULL, &fixture)
                .unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::IssuePrescription,
                &prescription(0xD3, 0xD0, actor.address(), 2),
            )
        },
        cf::HEALTHCARE_PATIENT_RX_INDEX,
        PATIENT_NULL.to_vec(),
        Some((cf::HEALTHCARE_PRESCRIPTIONS, vec![0xD3u8; 32])),
        |view| HealthcareExecutor::v_get_patient_rx_ids(view, &PATIENT_NULL).unwrap(),
        [0xD3u8; 32],
    );
}

#[test]
fn a_640_kb_prescriber_index_is_refused_by_the_ceiling_without_canonical_change() {
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_accumulator(
        "prescriber prescription index",
        move |db, addr| {
            HealthcareStore::new(db)
                .providers()
                .put(&provider(0xD0, addr, vec![]))
                .unwrap();
            db.put(cf::HEALTHCARE_PRESCRIBER_RX_INDEX, &[0xD0u8; 32], &fixture)
                .unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::IssuePrescription,
                &prescription(0xD4, 0xD0, actor.address(), 2),
            )
        },
        cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
        vec![0xD0u8; 32],
        Some((cf::HEALTHCARE_PRESCRIPTIONS, vec![0xD4u8; 32])),
        |view| HealthcareExecutor::v_get_prescriber_rx_ids(view, &[0xD0u8; 32]).unwrap(),
        [0xD4u8; 32],
    );
}

/// The `dependents` list lives INSIDE the membership row, so the whole record
/// -- not just a list -- is re-serialized on every append.
#[test]
fn a_640_kb_dependent_list_is_refused_by_the_ceiling_without_canonical_change() {
    assert_accumulator(
        "membership dependents",
        |db, addr| {
            let store = HealthcareStore::new(db);
            store
                .providers()
                .put(&provider(0xD0, addr, vec![]))
                .unwrap();
            let mut m = membership(0xD5, 0xD0, addr);
            m.dependents = twenty_thousand_ids();
            store.memberships().put(&m).unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::AddDependent,
                &Dependent {
                    membership_id: [0xD5; 32],
                    dependent_commitment: [0xD6; 32],
                },
            )
        },
        cf::HEALTHCARE_MEMBERSHIPS,
        vec![0xD5u8; 32],
        None,
        |view| {
            HealthcareExecutor::v_get_membership(view, &[0xD5u8; 32])
                .unwrap()
                .unwrap()
                .dependents
        },
        [0xD6u8; 32],
    );
}

/// The `fill_history` list lives INSIDE the prescription row, and a partial
/// fill re-serializes the whole record TWICE -- once to append the fill and
/// once to stamp the status.
#[test]
fn a_640_kb_fill_history_is_refused_by_the_ceiling_without_canonical_change() {
    assert_accumulator(
        "prescription fill history",
        |db, addr| {
            let store = HealthcareStore::new(db);
            store
                .providers()
                .put(&provider(0xD0, addr, vec![]))
                .unwrap();
            let mut rx = prescription(0xD7, 0xD0, addr, 2);
            rx.fill_history = twenty_thousand_ids();
            store.prescriptions().put(&rx).unwrap();
        },
        |actor| {
            tx(
                actor,
                0,
                HealthcareOperation::PartialFillPrescription,
                &Fill {
                    prescription_id: [0xD7; 32],
                    fill_commitment: [0xD8; 32],
                },
            )
        },
        cf::HEALTHCARE_PRESCRIPTIONS,
        vec![0xD7u8; 32],
        None,
        |view| {
            HealthcareExecutor::v_get_prescription(view, &[0xD7u8; 32])
                .unwrap()
                .unwrap()
                .fill_history
        },
        [0xD8u8; 32],
    );
}
