//! SRC-86X property, title, encumbrance and insurance execute against the
//! block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//!
//! ## Why this subsystem's reads had to move with its writes
//!
//! Property is a lifecycle registry: twenty-two of the thirty-one migrated
//! occurrences read a row, change its status plus a timestamp, and write it
//! back. Against committed state each would read the value the block STARTED
//! with, so a second transition in one block would overwrite the first.
//!
//! Three of those transitions BRANCH on the state they read, and those are the
//! cases with a discriminator here rather than only an assertion:
//!
//!   * `ReinstateCoverage` refuses unless the coverage is `Suspended`.
//!     -- suspend_then_reinstate_in_one_block_reactivates_the_coverage
//!     -- without_the_suspension_the_same_reinstatement_is_refused
//!   * `PayClaim` refuses unless the claim is `Approved` or
//!     `PartiallyApproved`.
//!     -- approve_then_pay_in_one_block_records_both_commitments
//!     -- without_the_approval_the_same_payment_is_refused
//!   * `ReopenClaim` refuses unless the claim is `Closed` or `Denied`.
//!     -- close_then_reopen_in_one_block_reopens_the_claim
//!     -- without_the_closure_the_same_reopen_is_refused
//!
//! The existence guards are the other half: a title event, an encumbrance and a
//! coverage each require their asset, and a claim requires its coverage. Each
//! pairs with a control that removes the earlier transaction and requires the
//! later one to fail.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, ClaimStatus, ClaimType, CoverageStatus, CoverageType,
    Encumbrance, EncumbranceStatus, EncumbranceType, InsuranceClaim, InsuranceCoverage,
    PriorityPosition, PropertyIssuerClass, PropertyOperation, PropertyProofEnvelope,
    PropertyProofProfile, PropertyProofType, PropertyTxData, TitleEvent, TitleEventStatus,
    TitleEventType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{PropertyExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, PropertyStore};

/// Every family this unit moved. Eleven.
///
/// `cf::PROPERTY_SYSTEM_EVENTS` is the twelfth property family and is NOT here:
/// no executor operation writes it, which is pinned by
/// `the_property_event_journal_is_never_written`.
const PROPERTY_CFS: &[&str] = &[
    cf::PROPERTY_ASSETS,
    cf::PROPERTY_JURISDICTION_INDEX,
    cf::PROPERTY_TITLE_EVENTS,
    cf::PROPERTY_ASSET_TITLE_INDEX,
    cf::PROPERTY_ENCUMBRANCES,
    cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
    cf::PROPERTY_COVERAGE,
    cf::PROPERTY_ASSET_COVERAGE_INDEX,
    cf::PROPERTY_CLAIMS,
    cf::PROPERTY_COVERAGE_CLAIM_INDEX,
    cf::PROPERTY_PROOFS,
];

const JURISDICTION: &str = "US-CA-LA";

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    op: PropertyOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Property(PropertyTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

// ── Payload shapes ──────────────────────────────────────────────────────────
//
// bincode is not self-describing: what matters is the FIELD ORDER, which is why
// each of these mirrors the `#[derive(Deserialize)]` struct in the operation it
// feeds rather than being one general-purpose bag.

#[derive(serde::Serialize)]
struct AssetId32 {
    asset_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct AssetStatusUpdate {
    asset_id: [u8; 32],
    status: AssetStatus,
}
#[derive(serde::Serialize)]
struct MergeData {
    primary_asset_id: [u8; 32],
    secondary_asset_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct EventId32 {
    event_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct TitleStatusUpdate {
    event_id: [u8; 32],
    status: TitleEventStatus,
}
#[derive(serde::Serialize)]
struct SupersedeData {
    old_event_id: [u8; 32],
    new_event: TitleEvent,
}
#[derive(serde::Serialize)]
struct EncumbranceId32 {
    encumbrance_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct EncumbranceStatusUpdate {
    encumbrance_id: [u8; 32],
    status: EncumbranceStatus,
}
#[derive(serde::Serialize)]
struct CoverageId32 {
    coverage_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct CoverageStatusUpdate {
    coverage_id: [u8; 32],
    status: CoverageStatus,
}
#[derive(serde::Serialize)]
struct RenewData {
    coverage_id: [u8; 32],
    new_expiry: u64,
}
#[derive(serde::Serialize)]
struct ClaimId32 {
    claim_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct ClaimStatusUpdate {
    claim_id: [u8; 32],
    status: ClaimStatus,
}
#[derive(serde::Serialize)]
struct ApproveData {
    claim_id: [u8; 32],
    approved_amount_commitment: [u8; 32],
}
#[derive(serde::Serialize)]
struct PayData {
    claim_id: [u8; 32],
    paid_amount_commitment: [u8; 32],
}

// ── Row fixtures ────────────────────────────────────────────────────────────

fn asset(id: u8, issuer: Address) -> AssetAnchor {
    AssetAnchor {
        asset_id: [id; 32],
        asset_commitment: [id.wrapping_add(1); 32],
        asset_type: AssetType::SingleFamilyResidence,
        jurisdiction_code: JURISDICTION.to_string(),
        public_reference: None,
        policy_id: [12u8; 32],
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: issuer,
        status: AssetStatus::Active,
        created_at: 1000,
        updated_at: 1000,
        anchored_at_height: 1,
        related_assets: vec![],
        attachments: vec![],
    }
}

fn title_event(id: u8, asset_id: u8, issuer: Address) -> TitleEvent {
    TitleEvent {
        event_id: [id; 32],
        asset_id: [asset_id; 32],
        event_type: TitleEventType::WarrantyDeed,
        event_commitment: [id.wrapping_add(1); 32],
        grantor_ref: Some(PartyRef::Commitment([0xA1; 32])),
        grantee_ref: Some(PartyRef::Commitment([0xB2; 32])),
        issuer_address: issuer,
        issuer_class: PropertyIssuerClass::TitleCompany,
        effective_date: 1000,
        recording_ref: None,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: TitleEventStatus::Recorded,
        created_at: 1000,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

fn encumbrance(id: u8, asset_id: u8, issuer: Address) -> Encumbrance {
    Encumbrance {
        encumbrance_id: [id; 32],
        asset_id: [asset_id; 32],
        encumbrance_type: EncumbranceType::FirstMortgage,
        encumbrance_commitment: [id.wrapping_add(1); 32],
        holder_ref: PartyRef::Commitment([0xC3; 32]),
        obligor_ref: None,
        priority: PriorityPosition::First,
        amount_commitment: None,
        effective_from: 1000,
        expiry: Some(9_000_000),
        issuer_address: issuer,
        issuer_class: PropertyIssuerClass::MortgageLender,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: EncumbranceStatus::Active,
        created_at: 1000,
        updated_at: 1000,
        recorded_at_height: 1,
        agreement_id: None,
        attachments: vec![],
    }
}

fn coverage(id: u8, asset_id: u8, issuer: Address) -> InsuranceCoverage {
    InsuranceCoverage {
        coverage_id: [id; 32],
        asset_id: [asset_id; 32],
        coverage_type: CoverageType::Homeowners,
        coverage_commitment: [id.wrapping_add(1); 32],
        insurer_ref: PartyRef::Commitment([0xE5; 32]),
        insured_ref: PartyRef::Commitment([0xF6; 32]),
        additional_insureds: vec![],
        limit_commitment: [id.wrapping_add(2); 32],
        deductible_commitment: None,
        premium_commitment: None,
        effective_from: 1000,
        expiry: 9_000_000,
        issuer_address: issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: CoverageStatus::Active,
        created_at: 1000,
        updated_at: 1000,
        recorded_at_height: 1,
        prior_coverage_id: None,
        attachments: vec![],
    }
}

fn claim(id: u8, coverage_id: u8, asset_id: u8, issuer: Address) -> InsuranceClaim {
    InsuranceClaim {
        claim_id: [id; 32],
        coverage_id: [coverage_id; 32],
        asset_id: [asset_id; 32],
        claim_type: ClaimType::WaterDamage,
        claim_commitment: [id.wrapping_add(1); 32],
        claimant_ref: PartyRef::Commitment([0xA7; 32]),
        date_of_loss: 900,
        date_filed: 1000,
        loss_amount_commitment: None,
        approved_amount_commitment: None,
        paid_amount_commitment: None,
        adjuster_ref: None,
        issuer_address: issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ClaimStatus::Filed,
        created_at: 1000,
        updated_at: 1000,
        recorded_at_height: 1,
        related_claims: vec![],
        attachments: vec![],
    }
}

fn proof_envelope(id: u8) -> PropertyProofEnvelope {
    PropertyProofEnvelope {
        proof_id: [id; 32],
        profile: PropertyProofProfile::CoverageInForce,
        profile_id: "property.coverage_in_force.v1".to_string(),
        policy_ids: vec![[12u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4u8; 48],
        proof_type: PropertyProofType::Groth16,
        subject_nullifier: [id.wrapping_add(1); 32],
        generated_at: 1000,
        expires_at: 2000,
    }
}

// ── Canonical / candidate comparison ────────────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in PROPERTY_CFS {
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
    for f in PROPERTY_CFS {
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

// ── Guarded transitions: property's sharpest same-block cases ───────────────

/// Suspend then reinstate in one block: the reinstatement's guard reads the
/// suspension this block staged a moment earlier.
#[test]
fn suspend_then_reinstate_in_one_block_reactivates_the_coverage() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (n, t) in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(10, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x30, 10, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::SuspendCoverage,
            &CoverageId32 {
                coverage_id: [0x30; 32],
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
            "tx {n}: {:?}",
            r.status
        );
    }

    assert_eq!(
        PropertyExecutor::v_get_coverage(&view, &[0x30u8; 32])
            .unwrap()
            .unwrap()
            .status,
        CoverageStatus::Suspended,
        "the suspension is in the candidate and nowhere else"
    );

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                3,
                PropertyOperation::ReinstateCoverage,
                &CoverageId32 {
                    coverage_id: [0x30; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the reinstatement must see the suspension -- a committed read here \
         would see `Active` and refuse: {:?}",
        r.status
    );
    assert_eq!(
        PropertyExecutor::v_get_coverage(&view, &[0x30u8; 32])
            .unwrap()
            .unwrap()
            .status,
        CoverageStatus::Active
    );
}

/// The discriminator: without the suspension, the identical reinstatement
/// fails. The test above would pass if reinstatement simply always succeeded.
#[test]
fn without_the_suspension_the_same_reinstatement_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(11, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x31, 11, issuer),
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                2,
                PropertyOperation::ReinstateCoverage,
                &CoverageId32 {
                    coverage_id: [0x31; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(13),
        "an active coverage cannot be reinstated"
    );
    assert_eq!(
        PropertyExecutor::v_get_coverage(&view, &[0x31u8; 32])
            .unwrap()
            .unwrap()
            .status,
        CoverageStatus::Active,
        "and the row is untouched"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        2,
        "a refused reinstatement does not advance the nonce past the two \
         transactions that succeeded"
    );
}

/// Approve then pay in one block: the payment's guard reads the approval, and
/// BOTH commitments end up on the row.
#[test]
fn approve_then_pay_in_one_block_records_both_commitments() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, t) in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(12, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x32, 12, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::FileClaim,
            &claim(0x40, 0x32, 12, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::ApproveClaim,
            &ApproveData {
                claim_id: [0x40; 32],
                approved_amount_commitment: [0xAA; 32],
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
            "tx {n}: {:?}",
            r.status
        );
    }

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                4,
                PropertyOperation::PayClaim,
                &PayData {
                    claim_id: [0x40; 32],
                    paid_amount_commitment: [0xBB; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the payment must see the approval: {:?}",
        r.status
    );

    let c = PropertyExecutor::v_get_claim(&view, &[0x40u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(c.status, ClaimStatus::Paid);
    assert_eq!(
        (c.approved_amount_commitment, c.paid_amount_commitment),
        (Some([0xAAu8; 32]), Some([0xBBu8; 32])),
        "paying does not clear the approval -- both commitments are on the row, \
         which only holds if the payment read the approved row rather than the \
         block's starting one"
    );
}

/// The discriminator: without the approval, the identical payment fails.
#[test]
fn without_the_approval_the_same_payment_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(13, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x33, 13, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::FileClaim,
            &claim(0x41, 0x33, 13, issuer),
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                3,
                PropertyOperation::PayClaim,
                &PayData {
                    claim_id: [0x41; 32],
                    paid_amount_commitment: [0xBB; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(13),
        "a filed claim cannot be paid"
    );
    let c = PropertyExecutor::v_get_claim(&view, &[0x41u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (c.status, c.paid_amount_commitment),
        (ClaimStatus::Filed, None),
        "and nothing about the claim moved"
    );
}

/// Close then reopen in one block: the reopen's guard reads the closure.
#[test]
fn close_then_reopen_in_one_block_reopens_the_claim() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, t) in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(14, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x34, 14, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::FileClaim,
            &claim(0x42, 0x34, 14, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::CloseClaim,
            &ClaimId32 {
                claim_id: [0x42; 32],
            },
        ),
        tx(
            &actor,
            4,
            PropertyOperation::ReopenClaim,
            &ClaimId32 {
                claim_id: [0x42; 32],
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
            "tx {n}: {:?}",
            r.status
        );
    }

    assert_eq!(
        PropertyExecutor::v_get_claim(&view, &[0x42u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ClaimStatus::Reopened
    );
}

/// The discriminator: without the closure, the identical reopen fails.
#[test]
fn without_the_closure_the_same_reopen_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(15, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::IssueCoverage,
            &coverage(0x35, 15, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::FileClaim,
            &claim(0x43, 0x35, 15, issuer),
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }

    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                3,
                PropertyOperation::ReopenClaim,
                &ClaimId32 {
                    claim_id: [0x43; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(13),
        "a filed claim cannot be reopened"
    );
    assert_eq!(
        PropertyExecutor::v_get_claim(&view, &[0x43u8; 32])
            .unwrap()
            .unwrap()
            .status,
        ClaimStatus::Filed
    );
}

// ── Existence guards across transactions in one block ───────────────────────

/// A title event, an encumbrance and a coverage each find the asset anchored
/// earlier in the SAME block, and a claim finds its coverage.
#[test]
fn every_dependent_row_finds_its_parent_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (n, t) in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(20, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::RecordTitleEvent,
            &title_event(0x20, 20, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(0x21, 20, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::IssueCoverage,
            &coverage(0x22, 20, issuer),
        ),
        tx(
            &actor,
            4,
            PropertyOperation::FileClaim,
            &claim(0x23, 0x22, 20, issuer),
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
            "tx {n} must see what the block staged before it: {:?}",
            r.status
        );
    }

    assert!(PropertyExecutor::v_title_event_exists(&view, &[0x20u8; 32]).unwrap());
    assert!(PropertyExecutor::v_encumbrance_exists(&view, &[0x21u8; 32]).unwrap());
    assert!(PropertyExecutor::v_coverage_exists(&view, &[0x22u8; 32]).unwrap());
    assert!(PropertyExecutor::v_claim_exists(&view, &[0x23u8; 32]).unwrap());
}

/// The discriminator, one parent at a time: without the earlier transaction the
/// identical later one is refused, by the PROPERTY arm -- `Failed(13)`, not an
/// earlier rejection -- and changes nothing.
#[test]
fn without_its_parent_each_dependent_row_is_refused() {
    let issuer_slot = Address::new([0x77; 20]);
    let cases: Vec<(&str, PropertyOperation, Vec<u8>)> = vec![
        (
            "title event",
            PropertyOperation::RecordTitleEvent,
            bincode::serialize(&title_event(0x24, 21, issuer_slot)).unwrap(),
        ),
        (
            "encumbrance",
            PropertyOperation::RecordEncumbrance,
            bincode::serialize(&encumbrance(0x25, 21, issuer_slot)).unwrap(),
        ),
        (
            "coverage",
            PropertyOperation::IssueCoverage,
            bincode::serialize(&coverage(0x26, 21, issuer_slot)).unwrap(),
        ),
        (
            "claim",
            PropertyOperation::FileClaim,
            bincode::serialize(&claim(0x27, 0x26, 21, issuer_slot)).unwrap(),
        ),
    ];

    for (label, op, data) in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        // The issuer-is-sender guard runs BEFORE the parent lookup, so the
        // sender has to be the issuer or this would fail for the wrong reason.
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);
        let data = data.clone();
        let mut fixed = data;
        // Rewrite the issuer slot to this run's sender: the fixtures are built
        // before the key exists.
        let from = actor.address();
        rewrite_issuer(&mut fixed, &issuer_slot, &from);

        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from,
            fee: 100,
            nonce: 0,
            payload: TxPayload::Property(PropertyTxData {
                operation: op,
                data: fixed,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            r.status,
            TxStatus::Failed(13),
            "{label}: it must fail in the property executor, not for an \
             unrelated reason"
        );
        assert!(
            families_changed(&db, &view).is_empty(),
            "{label}: and change nothing"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
            0,
            "{label}: a refused property operation does not advance the nonce"
        );
    }
}

/// Replace the 20-byte issuer placeholder inside an already-encoded payload.
///
/// The fixtures above are built once, before the per-case keypair exists. The
/// placeholder is a distinctive constant and appears exactly once in each
/// payload, which is asserted rather than assumed.
fn rewrite_issuer(bytes: &mut [u8], from: &Address, to: &Address) {
    let needle = from.as_ref();
    let hits: Vec<usize> = bytes
        .windows(20)
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "the issuer placeholder must be unique");
    bytes[hits[0]..hits[0] + 20].copy_from_slice(to.as_ref());
}

// ── The five accumulating indexes ───────────────────────────────────────────

/// Two rows sharing one index key in one block: the list holds BOTH.
///
/// Every index value is an accumulating `Vec<[u8; 32]>`. Read from committed
/// state the second write would see an empty list and replace the first entry
/// with a single-element one.
#[test]
fn all_five_indexes_accumulate_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let txs = vec![
        // Two assets, one jurisdiction.
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(30, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::AnchorAsset,
            &asset(31, issuer),
        ),
        // Two title events, one asset.
        tx(
            &actor,
            2,
            PropertyOperation::RecordTitleEvent,
            &title_event(0x50, 30, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::RecordTitleEvent,
            &title_event(0x51, 30, issuer),
        ),
        // Two encumbrances, one asset.
        tx(
            &actor,
            4,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(0x60, 30, issuer),
        ),
        tx(
            &actor,
            5,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(0x61, 30, issuer),
        ),
        // Two coverages, one asset.
        tx(
            &actor,
            6,
            PropertyOperation::IssueCoverage,
            &coverage(0x70, 30, issuer),
        ),
        tx(
            &actor,
            7,
            PropertyOperation::IssueCoverage,
            &coverage(0x71, 30, issuer),
        ),
        // Two claims, one coverage.
        tx(
            &actor,
            8,
            PropertyOperation::FileClaim,
            &claim(0x80, 0x70, 30, issuer),
        ),
        tx(
            &actor,
            9,
            PropertyOperation::FileClaim,
            &claim(0x81, 0x70, 30, issuer),
        ),
    ];
    for (n, t) in txs.into_iter().enumerate() {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "tx {n}: {:?}",
            r.status
        );
    }

    assert_eq!(
        PropertyExecutor::v_get_jurisdiction_asset_ids(&view, JURISDICTION).unwrap(),
        vec![[30u8; 32], [31u8; 32]],
        "both asset ids, in anchor order -- the second must have seen the first"
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_title_event_ids(&view, &[30u8; 32]).unwrap(),
        vec![[0x50u8; 32], [0x51u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_encumbrance_ids(&view, &[30u8; 32]).unwrap(),
        vec![[0x60u8; 32], [0x61u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_coverage_ids(&view, &[30u8; 32]).unwrap(),
        vec![[0x70u8; 32], [0x71u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_coverage_claim_ids(&view, &[0x70u8; 32]).unwrap(),
        vec![[0x80u8; 32], [0x81u8; 32]]
    );
    // The second asset is in the same jurisdiction but has no rows of its own,
    // so the three asset-keyed indexes must NOT have collected anything there.
    assert!(
        PropertyExecutor::v_get_asset_title_event_ids(&view, &[31u8; 32])
            .unwrap()
            .is_empty()
    );
    assert!(
        PropertyExecutor::v_get_coverage_claim_ids(&view, &[0x71u8; 32])
            .unwrap()
            .is_empty(),
        "and the second coverage's claim list is its own"
    );
}

// ── Duplicate guards, reading the candidate ─────────────────────────────────

/// A second row with an id already staged in the SAME block is refused by a
/// guard that reads the candidate. A different id is not.
///
/// The control is what makes each of these about the candidate rather than
/// about the operation being refused generally.
#[test]
fn a_duplicate_id_in_the_same_block_is_refused_for_every_guarded_family() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let mut nonce = 0u64;

    // Seed one of each.
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(40, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::RecordTitleEvent,
            &title_event(0x90, 40, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(0x91, 40, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::IssueCoverage,
            &coverage(0x92, 40, issuer),
        ),
        tx(
            &actor,
            4,
            PropertyOperation::FileClaim,
            &claim(0x93, 0x92, 40, issuer),
        ),
        tx(
            &actor,
            5,
            PropertyOperation::SubmitProof,
            &proof_envelope(0x94),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "seed: {:?}",
            r.status
        );
        nonce += 1;
    }

    // Each repeat is refused; each fresh id is not.
    let repeats: Vec<(&str, PropertyOperation, Vec<u8>, Vec<u8>)> = vec![
        (
            "asset",
            PropertyOperation::AnchorAsset,
            bincode::serialize(&asset(40, issuer)).unwrap(),
            bincode::serialize(&asset(41, issuer)).unwrap(),
        ),
        (
            "title event",
            PropertyOperation::RecordTitleEvent,
            bincode::serialize(&title_event(0x90, 40, issuer)).unwrap(),
            bincode::serialize(&title_event(0x95, 40, issuer)).unwrap(),
        ),
        (
            "encumbrance",
            PropertyOperation::RecordEncumbrance,
            bincode::serialize(&encumbrance(0x91, 40, issuer)).unwrap(),
            bincode::serialize(&encumbrance(0x96, 40, issuer)).unwrap(),
        ),
        (
            "coverage",
            PropertyOperation::IssueCoverage,
            bincode::serialize(&coverage(0x92, 40, issuer)).unwrap(),
            bincode::serialize(&coverage(0x97, 40, issuer)).unwrap(),
        ),
        (
            "claim",
            PropertyOperation::FileClaim,
            bincode::serialize(&claim(0x93, 0x92, 40, issuer)).unwrap(),
            bincode::serialize(&claim(0x98, 0x92, 40, issuer)).unwrap(),
        ),
        (
            "proof",
            PropertyOperation::SubmitProof,
            bincode::serialize(&proof_envelope(0x94)).unwrap(),
            bincode::serialize(&proof_envelope(0x99)).unwrap(),
        ),
    ];

    for (label, op, duplicate, fresh) in repeats {
        for (data, expected, note) in [
            (duplicate, TxStatus::Failed(13), "a repeat must be refused"),
            (fresh, TxStatus::Success, "a fresh id must not be"),
        ] {
            let t = TransactionV2 {
                chain_id: CHAIN_ID,
                from: actor.address(),
                fee: 100,
                nonce,
                payload: TxPayload::Property(PropertyTxData {
                    operation: op,
                    data,
                    recipient: Address::ZERO,
                }),
            };
            let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
            let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert_eq!(r.status, expected, "{label}: {note} ({:?})", r.status);
            if expected == TxStatus::Success {
                nonce += 1;
            }
        }
    }
}

// ── Abandonment ─────────────────────────────────────────────────────────────

/// Six transactions that between them write all ELEVEN property families.
///
/// Used by the abandonment test and by the restart test, so the two are talking
/// about the same block. `id` keeps the fixtures distinct between them.
fn a_block_touching_every_family(signer: &KeyPair, id: u8) -> Vec<SignedTransaction> {
    let issuer = signer.address();
    vec![
        // assets + jurisdiction index
        tx(
            signer,
            0,
            PropertyOperation::AnchorAsset,
            &asset(id, issuer),
        ),
        // title events + asset title index
        tx(
            signer,
            1,
            PropertyOperation::RecordTitleEvent,
            &title_event(id.wrapping_add(1), id, issuer),
        ),
        // encumbrances + asset encumbrance index
        tx(
            signer,
            2,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(id.wrapping_add(2), id, issuer),
        ),
        // coverage + asset coverage index
        tx(
            signer,
            3,
            PropertyOperation::IssueCoverage,
            &coverage(id.wrapping_add(3), id, issuer),
        ),
        // claims + coverage claim index
        tx(
            signer,
            4,
            PropertyOperation::FileClaim,
            &claim(id.wrapping_add(4), id.wrapping_add(3), id, issuer),
        ),
        // proofs
        tx(
            signer,
            5,
            PropertyOperation::SubmitProof,
            &proof_envelope(id.wrapping_add(5)),
        ),
    ]
}

/// A block writing every property family commits none of it.
///
/// All eleven are asserted STAGED first, by per-CF diff, so the canonical
/// comparison afterwards is a statement about eleven discarded families and not
/// about a block that quietly did nothing.
#[test]
fn an_abandoned_block_leaves_all_eleven_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for t in a_block_touching_every_family(&actor, 50) {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, 1000)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let touched = families_changed(&db, &view);
        for f in PROPERTY_CFS {
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
        "an abandoned block must leave every property row byte-identical"
    );
}

// ── Limit refusal ───────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the asset staged and its jurisdiction-index entry not.
///
/// `AnchorAsset` is the operation to calibrate against: it writes the asset row
/// and then the jurisdiction-index entry, so a ceiling can land between them.
/// Every ceiling below the measured cost is tried, not a sample -- the interval
/// is a few bytes wide.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let signed_tx = tx(
        &actor,
        0,
        PropertyOperation::AnchorAsset,
        &asset(60, actor.address()),
    );

    assert!(
        db.prefix_iter(cf::PROPERTY_ASSETS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::PROPERTY_JURISDICTION_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "both families must start canonically empty for the merged reads below \
         to stand for staged"
    );

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
    assert!(full > 1, "an anchor must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let asset_staged = view
            .get(cf::PROPERTY_ASSETS, &[60u8; 32])
            .unwrap()
            .is_some();
        let index_staged = view
            .get(cf::PROPERTY_JURISDICTION_INDEX, JURISDICTION.as_bytes())
            .unwrap()
            .is_some();
        if asset_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || asset_staged,
            "ceiling {ceiling} staged the index without the asset, which the \
             write order cannot produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must commit nothing"
        );
    }
    assert!(
        partials > 0,
        "no ceiling refused with the asset staged and its jurisdiction index not"
    );
}

// ── Parity, including a restart ─────────────────────────────────────────────

/// Published rows satisfy the committed scans AND survive a restart.
///
/// Reading back through the same handle proves the write reached the database's
/// view of itself, not that it is durable. This closes the handle -- asserting
/// the strong count first, so the close is proved rather than hoped for -- and
/// reopens at the same path. Same block shape as the abandonment test: all
/// eleven families.
#[test]
fn published_property_rows_survive_a_database_restart() {
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
            a_block_touching_every_family(&actor, 70),
            &[],
        );
        assert_eq!(receipts.len(), 6);
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all six must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        let rows = canonical(&db);
        for f in PROPERTY_CFS {
            assert!(
                rows.iter().any(|(fam, _, _)| fam == f),
                "{f} carries no committed row, so the restart proves nothing about it"
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
        "every property row must survive the restart, byte for byte"
    );
    assert_committed_readers_resolve(&db);
}

/// The committed readers, driven against whichever handle is passed.
fn assert_committed_readers_resolve(db: &Database) {
    let store = PropertyStore::new(db);
    assert!(store.assets().get(&[70u8; 32]).unwrap().is_some());
    assert_eq!(
        store
            .assets()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .iter()
            .map(|a| a.asset_id)
            .collect::<Vec<_>>(),
        vec![[70u8; 32]],
        "the jurisdiction index resolves"
    );
    assert_eq!(
        store
            .title_events()
            .get_by_asset(&[70u8; 32])
            .unwrap()
            .iter()
            .map(|e| e.event_id)
            .collect::<Vec<_>>(),
        vec![[71u8; 32]],
        "the asset title index resolves"
    );
    assert_eq!(
        store
            .encumbrances()
            .get_by_asset(&[70u8; 32])
            .unwrap()
            .iter()
            .map(|e| e.encumbrance_id)
            .collect::<Vec<_>>(),
        vec![[72u8; 32]],
        "the asset encumbrance index resolves"
    );
    assert_eq!(
        store
            .coverage()
            .get_by_asset(&[70u8; 32])
            .unwrap()
            .iter()
            .map(|c| c.coverage_id)
            .collect::<Vec<_>>(),
        vec![[73u8; 32]],
        "the asset coverage index resolves"
    );
    assert_eq!(
        store
            .claims()
            .get_by_coverage(&[73u8; 32])
            .unwrap()
            .iter()
            .map(|c| c.claim_id)
            .collect::<Vec<_>>(),
        vec![[74u8; 32]],
        "the coverage claim index resolves"
    );
    assert!(store.proofs().get(&[75u8; 32]).unwrap().is_some());
}

// ── The second dispatch surface ─────────────────────────────────────────────

/// `execute_tx_v2` routes property operations through the candidate too.
#[test]
fn the_v2_dispatch_surface_also_stages_property_rows() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();
    let before = canonical(&db);
    let key = *actor.public_key().as_bytes();

    let v2 = |nonce: u64, op: PropertyOperation, data: Vec<u8>| TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer,
        fee: 100,
        nonce,
        payload: TxPayload::Property(PropertyTxData {
            operation: op,
            data,
            recipient: Address::ZERO,
        }),
    };

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        let t = v2(
            0,
            PropertyOperation::AnchorAsset,
            bincode::serialize(&asset(80, issuer)).unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000, 0)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must anchor an asset: {:?}",
            r.status
        );
        let changed = families_changed(&db, &view);
        assert!(changed.contains(&cf::PROPERTY_ASSETS));
        assert!(changed.contains(&cf::PROPERTY_JURISDICTION_INDEX));

        // A second transaction through the SAME surface, which has to see the
        // first one's asset, and which carries this arm's own
        // `0, // block_timestamp placeholder` into the row it rewrites.
        let t = v2(
            1,
            PropertyOperation::UpdateAsset,
            bincode::serialize(&AssetStatusUpdate {
                asset_id: [80; 32],
                status: AssetStatus::Encumbered,
            })
            .unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1_700_000_000, 0)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must see the asset it staged a moment ago: {:?}",
            r.status
        );
        let a = PropertyExecutor::v_get_asset(&view, &[80u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(a.status, AssetStatus::Encumbered);
        assert_eq!(
            a.updated_at, 0,
            "and this arm passes 0 where the block timestamp belongs, exactly \
             like the live one"
        );

        // And a refusal on this arm carries the property status code, not a
        // neighbouring subsystem's.
        let t = v2(
            2,
            PropertyOperation::UpdateAsset,
            bincode::serialize(&AssetStatusUpdate {
                asset_id: [0x7F; 32],
                status: AssetStatus::Seized,
            })
            .unwrap(),
        );
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let r = executor
            .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, 1000, 0)
            .unwrap();
        assert_eq!(
            r.status,
            TxStatus::Failed(13),
            "a missing asset must fail IN the property arm of this surface"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &issuer).unwrap(),
            2,
            "and the refusal does not advance the nonce"
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

// ── Corrupt rows: every family, with the staged state named ────────────────

/// One corrupt-row case: which family is corrupted, the operation that has to
/// READ it, and the exact candidate state the failure is required to leave.
struct CorruptCase {
    family: &'static str,
    label: &'static str,
    /// Property families whose candidate contents must differ from committed,
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
/// This is the difference between "no such asset" and "that asset's row is
/// corrupt", and every guard here branches on exactly that. A candidate reader
/// that swallowed a decode failure into `None` would turn corruption into a
/// duplicate-id opportunity, or into a claim filed against a coverage whose
/// issuer could not be read.
///
/// Ten of the eleven families are covered here: five corrupt PRIMARY rows and
/// all five corrupt INDEX rows. The eleventh, `PROPERTY_PROOFS`, has no
/// decoding reader reachable from dispatch -- `SubmitProof` guards with
/// `contains` -- and is pinned separately, as a preserved defect, by
/// `a_corrupt_proof_row_is_read_as_presence_not_as_corruption`.
///
/// The five index cases are the ones that leave state: the primary write
/// precedes the index append, so the row is staged and the fee has been charged
/// when the append fails. Each is asserted as exact bytes, and the corrupt
/// index row is asserted UNCHANGED.
#[test]
fn corrupt_rows_error_through_dispatch_with_exactly_this_staged() {
    const CORRUPT: &[u8] = b"not a valid row";

    let cases = [
        CorruptCase {
            family: cf::PROPERTY_ASSETS,
            label: "asset",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::PROPERTY_TITLE_EVENTS,
            label: "title event",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::PROPERTY_ENCUMBRANCES,
            label: "encumbrance",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::PROPERTY_COVERAGE,
            label: "coverage",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::PROPERTY_CLAIMS,
            label: "claim",
            staged: &[],
            nonce: 0,
        },
        CorruptCase {
            family: cf::PROPERTY_JURISDICTION_INDEX,
            label: "jurisdiction index",
            staged: &[cf::PROPERTY_ASSETS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::PROPERTY_ASSET_TITLE_INDEX,
            label: "asset title index",
            staged: &[cf::PROPERTY_TITLE_EVENTS],
            nonce: 1,
        },
        CorruptCase {
            family: cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
            label: "asset encumbrance index",
            staged: &[cf::PROPERTY_ENCUMBRANCES],
            nonce: 1,
        },
        CorruptCase {
            family: cf::PROPERTY_ASSET_COVERAGE_INDEX,
            label: "asset coverage index",
            staged: &[cf::PROPERTY_COVERAGE],
            nonce: 1,
        },
        CorruptCase {
            family: cf::PROPERTY_COVERAGE_CLAIM_INDEX,
            label: "coverage claim index",
            staged: &[cf::PROPERTY_CLAIMS],
            nonce: 1,
        },
    ];

    for case in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);
        let issuer = actor.address();
        let store = PropertyStore::new(&db);

        // Keys written by hand, from the schema and not from the key builders,
        // so a change to a builder cannot silently move this test with it.
        let key: Vec<u8> = match case.family {
            f if f == cf::PROPERTY_JURISDICTION_INDEX => b"US-CA-LA".to_vec(),
            f if f == cf::PROPERTY_TITLE_EVENTS => vec![0xB1u8; 32],
            f if f == cf::PROPERTY_ENCUMBRANCES => vec![0xB2u8; 32],
            f if f == cf::PROPERTY_COVERAGE => vec![0xB3u8; 32],
            f if f == cf::PROPERTY_CLAIMS => vec![0xB4u8; 32],
            f if f == cf::PROPERTY_COVERAGE_CLAIM_INDEX => vec![0xB3u8; 32],
            // The three asset-keyed indexes and the assets family itself.
            _ => vec![0xB0u8; 32],
        };

        // What each guard needs in order to REACH the corrupt row. The index
        // cases need their parent row canonically present and VALID, because
        // the existence guard runs before the append.
        let (op, data): (PropertyOperation, Vec<u8>) = match case.family {
            f if f == cf::PROPERTY_ASSETS => (
                PropertyOperation::UpdateAsset,
                bincode::serialize(&AssetStatusUpdate {
                    asset_id: [0xB0; 32],
                    status: AssetStatus::Seized,
                })
                .unwrap(),
            ),
            f if f == cf::PROPERTY_TITLE_EVENTS => (
                PropertyOperation::UpdateTitleEvent,
                bincode::serialize(&TitleStatusUpdate {
                    event_id: [0xB1; 32],
                    status: TitleEventStatus::Corrected,
                })
                .unwrap(),
            ),
            f if f == cf::PROPERTY_ENCUMBRANCES => (
                PropertyOperation::UpdateEncumbrance,
                bincode::serialize(&EncumbranceStatusUpdate {
                    encumbrance_id: [0xB2; 32],
                    status: EncumbranceStatus::Disputed,
                })
                .unwrap(),
            ),
            f if f == cf::PROPERTY_COVERAGE => (
                PropertyOperation::UpdateCoverage,
                bincode::serialize(&CoverageStatusUpdate {
                    coverage_id: [0xB3; 32],
                    status: CoverageStatus::Lapsed,
                })
                .unwrap(),
            ),
            f if f == cf::PROPERTY_CLAIMS => (
                PropertyOperation::UpdateClaim,
                bincode::serialize(&ClaimStatusUpdate {
                    claim_id: [0xB4; 32],
                    status: ClaimStatus::InReview,
                })
                .unwrap(),
            ),
            f if f == cf::PROPERTY_JURISDICTION_INDEX => (
                PropertyOperation::AnchorAsset,
                bincode::serialize(&asset(0xB0, issuer)).unwrap(),
            ),
            f if f == cf::PROPERTY_ASSET_TITLE_INDEX => {
                store.assets().put(&asset(0xB0, issuer)).unwrap();
                (
                    PropertyOperation::RecordTitleEvent,
                    bincode::serialize(&title_event(0xB1, 0xB0, issuer)).unwrap(),
                )
            }
            f if f == cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX => {
                store.assets().put(&asset(0xB0, issuer)).unwrap();
                (
                    PropertyOperation::RecordEncumbrance,
                    bincode::serialize(&encumbrance(0xB2, 0xB0, issuer)).unwrap(),
                )
            }
            f if f == cf::PROPERTY_ASSET_COVERAGE_INDEX => {
                store.assets().put(&asset(0xB0, issuer)).unwrap();
                (
                    PropertyOperation::IssueCoverage,
                    bincode::serialize(&coverage(0xB3, 0xB0, issuer)).unwrap(),
                )
            }
            _ => {
                store.assets().put(&asset(0xB0, issuer)).unwrap();
                store.coverage().put(&coverage(0xB3, 0xB0, issuer)).unwrap();
                (
                    PropertyOperation::FileClaim,
                    bincode::serialize(&claim(0xB4, 0xB3, 0xB0, issuer)).unwrap(),
                )
            }
        };
        db.put(case.family, &key, CORRUPT).unwrap();

        let before = canonical(&db);
        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: issuer,
            fee: 100,
            nonce: 0,
            payload: TxPayload::Property(PropertyTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
        let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());

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
            let staged_row: Option<(&str, Vec<u8>, Vec<u8>)> = match case.family {
                f if f == cf::PROPERTY_JURISDICTION_INDEX => Some((
                    cf::PROPERTY_ASSETS,
                    vec![0xB0u8; 32],
                    bincode::serialize(&asset(0xB0, issuer)).unwrap(),
                )),
                f if f == cf::PROPERTY_ASSET_TITLE_INDEX => Some((
                    cf::PROPERTY_TITLE_EVENTS,
                    vec![0xB1u8; 32],
                    bincode::serialize(&title_event(0xB1, 0xB0, issuer)).unwrap(),
                )),
                f if f == cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX => Some((
                    cf::PROPERTY_ENCUMBRANCES,
                    vec![0xB2u8; 32],
                    bincode::serialize(&encumbrance(0xB2, 0xB0, issuer)).unwrap(),
                )),
                f if f == cf::PROPERTY_ASSET_COVERAGE_INDEX => Some((
                    cf::PROPERTY_COVERAGE,
                    vec![0xB3u8; 32],
                    bincode::serialize(&coverage(0xB3, 0xB0, issuer)).unwrap(),
                )),
                f if f == cf::PROPERTY_COVERAGE_CLAIM_INDEX => Some((
                    cf::PROPERTY_CLAIMS,
                    vec![0xB4u8; 32],
                    bincode::serialize(&claim(0xB4, 0xB3, 0xB0, issuer)).unwrap(),
                )),
                _ => None,
            };
            if let Some((family, k, bytes)) = staged_row {
                assert_eq!(
                    view.get(family, &k).unwrap().as_deref(),
                    Some(&bytes[..]),
                    "{}: the row written before the failing append, byte for byte",
                    case.label
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
                StateManager::v_get_nonce(&view, &issuer).unwrap(),
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

// ── Behaviours reproduced deliberately, not fixed ──────────────────────────

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
    db.put(cf::PROPERTY_PROOFS, &[0xC0u8; 32], b"not a valid row")
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &actor,
                0,
                PropertyOperation::SubmitProof,
                &proof_envelope(0xC0),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(13),
        "the corrupt row is treated as an existing proof -- a FAILURE, not the \
         error a decoding guard would raise"
    );
    assert_eq!(
        view.get(cf::PROPERTY_PROOFS, &[0xC0u8; 32])
            .unwrap()
            .as_deref(),
        Some(&b"not a valid row"[..]),
        "and the corrupt bytes are left exactly as they were"
    );
    assert_eq!(
        families_changed(&db, &view),
        Vec::<&str>::new(),
        "with nothing staged in any property family"
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
///
/// Preserved, not fixed. Pinned in both directions: success AND no write to any
/// property family.
#[test]
fn verify_proof_succeeds_for_a_proof_that_does_not_exist() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: actor.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Property(PropertyTxData {
            operation: PropertyOperation::VerifyProof,
            // Not a proof envelope at all. It is never deserialized.
            data: b"\xff\xff\xff\xff".to_vec(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
    let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();

    assert!(
        matches!(r.status, TxStatus::Success),
        "verification of a non-existent proof succeeds: {:?}",
        r.status
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and writes nothing to any property family"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "while still charging the fee and advancing the nonce"
    );
}

/// Both dispatch arms pass a literal `0` where the block timestamp belongs, so
/// every property timestamp the executor writes is 0 regardless of the block.
///
/// Preserved, not fixed: correcting it changes committed bytes and therefore
/// the state root.
#[test]
fn the_block_timestamp_reaching_property_operations_is_always_zero() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(90, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::UpdateAsset,
            &AssetStatusUpdate {
                asset_id: [90; 32],
                status: AssetStatus::Seized,
            },
        ),
        tx(
            &actor,
            2,
            PropertyOperation::RecordTitleEvent,
            &title_event(0x91, 90, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::VoidTitleEvent,
            &EventId32 {
                event_id: [0x91; 32],
            },
        ),
        tx(
            &actor,
            4,
            PropertyOperation::IssueCoverage,
            &coverage(0x92, 90, issuer),
        ),
        tx(
            &actor,
            5,
            PropertyOperation::RenewCoverage,
            &RenewData {
                coverage_id: [0x92; 32],
                new_expiry: 12_345_678,
            },
        ),
    ] {
        // A block timestamp far from zero, which the dispatch discards.
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1_700_000_000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        PropertyExecutor::v_get_asset(&view, &[90u8; 32])
            .unwrap()
            .unwrap()
            .updated_at,
        0,
        "the asset transition wrote 0, not 1_700_000_000"
    );
    let e = PropertyExecutor::v_get_title_event(&view, &[0x91u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (e.status, e.created_at),
        (TitleEventStatus::Voided, 0),
        "and voiding an event overwrites its CREATION timestamp with that zero"
    );
    let c = PropertyExecutor::v_get_coverage(&view, &[0x92u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (c.status, c.expiry, c.updated_at),
        (CoverageStatus::Renewed, 12_345_678, 0),
        "the renewal takes its new expiry from the PAYLOAD and its updated_at \
         from the dispatch's zero"
    );
}

/// `MergeAssets`, `SupersedeTitleEvent` and `SubmitProof` check no authority at
/// all: any sender may merge assets it does not issue, supersede any title
/// event, and submit any proof.
///
/// Preserved, not fixed: binding these to senders changes which transactions
/// are valid, which is a consensus change.
#[test]
fn three_operations_check_no_authority_at_all() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let owner = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &owner, 100_000_000);
    fund(&db, &stranger, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = owner.address();
    assert_ne!(issuer, stranger.address());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &owner,
            0,
            PropertyOperation::AnchorAsset,
            &asset(100, issuer),
        ),
        tx(
            &owner,
            1,
            PropertyOperation::AnchorAsset,
            &asset(101, issuer),
        ),
        tx(
            &owner,
            2,
            PropertyOperation::RecordTitleEvent,
            &title_event(0xA0, 100, issuer),
        ),
    ] {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // A stranger merges two assets issued by someone else.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                0,
                PropertyOperation::MergeAssets,
                &MergeData {
                    primary_asset_id: [100; 32],
                    secondary_asset_id: [101; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "MergeAssets checks nothing about the sender: {:?}",
        r.status
    );
    assert_eq!(
        PropertyExecutor::v_get_asset(&view, &[101u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AssetStatus::Merged
    );

    // A stranger supersedes someone else's title event.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                1,
                PropertyOperation::SupersedeTitleEvent,
                &SupersedeData {
                    old_event_id: [0xA0; 32],
                    new_event: title_event(0xA1, 100, stranger.address()),
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "SupersedeTitleEvent checks nothing about the sender: {:?}",
        r.status
    );
    assert_eq!(
        PropertyExecutor::v_get_title_event(&view, &[0xA0u8; 32])
            .unwrap()
            .unwrap()
            .status,
        TitleEventStatus::Superseded
    );
    assert!(PropertyExecutor::v_title_event_exists(&view, &[0xA1u8; 32]).unwrap());

    // And a stranger submits a proof naming a policy it has no relation to.
    let r = executor
        .execute_tx(
            &mut view,
            &tx(
                &stranger,
                2,
                PropertyOperation::SubmitProof,
                &proof_envelope(0xA2),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "SubmitProof checks nothing about the sender: {:?}",
        r.status
    );
}

/// Merging, subdividing and transferring all record a STATUS and nothing else.
///
/// `MergeAssets` never links the two assets: `related_assets` stays empty on
/// both, and the primary is not touched at all. `SubdivideAsset` creates no
/// child assets. `TransferAsset` moves no ownership and ignores
/// `PropertyTxData.recipient` entirely -- there is no owner field on an asset
/// for it to move.
///
/// Preserved, not fixed.
#[test]
fn merge_subdivide_and_transfer_record_a_status_and_nothing_else() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in [
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(110, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::AnchorAsset,
            &asset(111, issuer),
        ),
    ] {
        executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
    }

    // A transfer naming a recipient. The recipient is not read anywhere.
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer,
        fee: 100,
        nonce: 2,
        payload: TxPayload::Property(PropertyTxData {
            operation: PropertyOperation::TransferAsset,
            data: bincode::serialize(&AssetId32 {
                asset_id: [110; 32],
            })
            .unwrap(),
            recipient: Address::new([0xDD; 20]),
        }),
    };
    let sig = *sign(t.signing_hash().as_bytes(), actor.private_key()).as_bytes();
    let t = SignedTransaction::new_v2(t, sig, *actor.public_key().as_bytes());
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let a = PropertyExecutor::v_get_asset(&view, &[110u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(a.status, AssetStatus::PendingTransfer);
    assert_eq!(
        a.issuer_address, issuer,
        "the named recipient reaches nothing: the asset has no owner field, and \
         its issuer is unchanged"
    );

    for (n, t) in [
        tx(
            &actor,
            3,
            PropertyOperation::MergeAssets,
            &MergeData {
                primary_asset_id: [110; 32],
                secondary_asset_id: [111; 32],
            },
        ),
        tx(
            &actor,
            4,
            PropertyOperation::SubdivideAsset,
            &AssetId32 {
                asset_id: [110; 32],
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
            "tx {n}: {:?}",
            r.status
        );
    }

    let primary = PropertyExecutor::v_get_asset(&view, &[110u8; 32])
        .unwrap()
        .unwrap();
    let secondary = PropertyExecutor::v_get_asset(&view, &[111u8; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            primary.related_assets.as_slice(),
            secondary.related_assets.as_slice()
        ),
        (&[][..], &[][..]),
        "merging records no relationship in either direction"
    );
    assert_eq!(
        secondary.status,
        AssetStatus::Merged,
        "only the secondary's status moves"
    );
    assert_eq!(
        primary.status,
        AssetStatus::Subdivided,
        "and the primary carries only the later subdivision status -- the merge \
         never wrote to it at all"
    );
    assert_eq!(
        PropertyExecutor::v_get_jurisdiction_asset_ids(&view, JURISDICTION).unwrap(),
        vec![[110u8; 32], [111u8; 32]],
        "subdividing creates no child asset, so the index still holds exactly two"
    );
}

/// The twelfth property column family, `property_system_events`, is never
/// written by any operation, so the property journal is empty on every chain.
///
/// `PropertyEventStore` exists for it and no executor operation ever calls it.
/// There is no undo history and no audit trail: a deregistered asset retains no
/// record of who deregistered it.
#[test]
fn the_property_event_journal_is_never_written() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for t in a_block_touching_every_family(&actor, 120) {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }
    // Every other family moved, so this is a statement about the journal and
    // not about a block that did nothing.
    assert_eq!(families_changed(&db, &view).len(), PROPERTY_CFS.len());

    assert_eq!(
        view.prefix_iter(cf::PROPERTY_SYSTEM_EVENTS, &[])
            .unwrap()
            .count(),
        0,
        "a block that writes all eleven other families writes no event at all"
    );
}

/// The committed property readers are unpaginated whole-family scans.
///
/// `list_active` walks every row in its column family and returns one `Vec`,
/// and the four `get_by_*` readers resolve an index list and then point-read
/// every id in it. There is no limit, offset or cursor to ask for fewer.
/// Pinned rather than fixed: these are the RPC's readers and changing their
/// signatures is API work, not part of moving writes onto the candidate.
#[test]
fn the_committed_property_readers_return_two_thousand_rows_whole() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let store = PropertyStore::new(&db);
    let issuer = Address::new([0x44; 20]);

    for i in 0..2_000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());

        let mut a = asset(0, issuer);
        a.asset_id = id;
        store.assets().put(&a).unwrap();

        let mut e = title_event(0, 0, issuer);
        e.event_id = id;
        e.asset_id = [0xFEu8; 32];
        store.title_events().put(&e).unwrap();

        let mut enc = encumbrance(0, 0, issuer);
        enc.encumbrance_id = id;
        enc.asset_id = [0xFEu8; 32];
        store.encumbrances().put(&enc).unwrap();

        let mut c = coverage(0, 0, issuer);
        c.coverage_id = id;
        c.asset_id = [0xFEu8; 32];
        store.coverage().put(&c).unwrap();

        let mut cl = claim(0, 0, 0, issuer);
        cl.claim_id = id;
        cl.coverage_id = [0xFDu8; 32];
        store.claims().put(&cl).unwrap();
    }

    assert_eq!(
        store.assets().list_active().unwrap().len(),
        2_000,
        "every active asset, in one Vec, with no way to ask for fewer"
    );
    assert_eq!(
        store
            .assets()
            .get_by_jurisdiction(JURISDICTION)
            .unwrap()
            .len(),
        2_000,
        "and one index list of 2,000 ids, each point-read in turn"
    );
    assert_eq!(
        store
            .title_events()
            .get_by_asset(&[0xFEu8; 32])
            .unwrap()
            .len(),
        2_000
    );
    assert_eq!(
        store
            .encumbrances()
            .get_by_asset(&[0xFEu8; 32])
            .unwrap()
            .len(),
        2_000
    );
    assert_eq!(
        store.coverage().get_by_asset(&[0xFEu8; 32]).unwrap().len(),
        2_000
    );
    assert_eq!(
        store.claims().get_by_coverage(&[0xFDu8; 32]).unwrap().len(),
        2_000
    );
}

// ── The remaining transitions, chained in one block ────────────────────────

/// Every status transition not exercised above, in ONE block, each reading the
/// row the transition before it staged.
///
/// This is the long tail of the read-modify-write shape: eleven operations that
/// take no branch on what they read but still have to read the candidate, or
/// each would write back a row built from the block's starting state and
/// discard its predecessor. The chain is asserted step by step, so a stale read
/// anywhere in it shows up as the wrong status rather than as a passing test.
#[test]
fn every_remaining_status_transition_reads_the_row_the_one_before_it_staged() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 500_000_000);
    let proposer = Address::new([9; 20]);
    let issuer = actor.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let setup = vec![
        tx(
            &actor,
            0,
            PropertyOperation::AnchorAsset,
            &asset(130, issuer),
        ),
        tx(
            &actor,
            1,
            PropertyOperation::RecordTitleEvent,
            &title_event(0xD0, 130, issuer),
        ),
        tx(
            &actor,
            2,
            PropertyOperation::RecordEncumbrance,
            &encumbrance(0xD1, 130, issuer),
        ),
        tx(
            &actor,
            3,
            PropertyOperation::IssueCoverage,
            &coverage(0xD2, 130, issuer),
        ),
        tx(
            &actor,
            4,
            PropertyOperation::FileClaim,
            &claim(0xD3, 0xD2, 130, issuer),
        ),
    ];
    for (n, t) in setup.into_iter().enumerate() {
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "setup {n}: {:?}",
            r.status
        );
    }

    // The encumbrance chain: four transitions on one row, in order.
    for (n, (t, expected)) in [
        (
            tx(
                &actor,
                5,
                PropertyOperation::UpdateEncumbrance,
                &EncumbranceStatusUpdate {
                    encumbrance_id: [0xD1; 32],
                    status: EncumbranceStatus::Pending,
                },
            ),
            EncumbranceStatus::Pending,
        ),
        (
            tx(
                &actor,
                6,
                PropertyOperation::SubordinateEncumbrance,
                &EncumbranceId32 {
                    encumbrance_id: [0xD1; 32],
                },
            ),
            EncumbranceStatus::Subordinated,
        ),
        (
            tx(
                &actor,
                7,
                PropertyOperation::ForecloseEncumbrance,
                &EncumbranceId32 {
                    encumbrance_id: [0xD1; 32],
                },
            ),
            EncumbranceStatus::Foreclosed,
        ),
        (
            tx(
                &actor,
                8,
                PropertyOperation::ReleaseEncumbrance,
                &EncumbranceId32 {
                    encumbrance_id: [0xD1; 32],
                },
            ),
            EncumbranceStatus::Released,
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
            "encumbrance step {n}: {:?}",
            r.status
        );
        assert_eq!(
            PropertyExecutor::v_get_encumbrance(&view, &[0xD1u8; 32])
                .unwrap()
                .unwrap()
                .status,
            expected,
            "encumbrance step {n}"
        );
    }

    // The claim chain: three more transitions, each over the last.
    for (n, (t, expected)) in [
        (
            tx(
                &actor,
                9,
                PropertyOperation::UpdateClaim,
                &ClaimStatusUpdate {
                    claim_id: [0xD3; 32],
                    status: ClaimStatus::UnderInvestigation,
                },
            ),
            ClaimStatus::UnderInvestigation,
        ),
        (
            tx(
                &actor,
                10,
                PropertyOperation::DenyClaim,
                &ClaimId32 {
                    claim_id: [0xD3; 32],
                },
            ),
            ClaimStatus::Denied,
        ),
        (
            tx(
                &actor,
                11,
                PropertyOperation::WithdrawClaim,
                &ClaimId32 {
                    claim_id: [0xD3; 32],
                },
            ),
            ClaimStatus::Withdrawn,
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
            "claim step {n}: {:?}",
            r.status
        );
        assert_eq!(
            PropertyExecutor::v_get_claim(&view, &[0xD3u8; 32])
                .unwrap()
                .unwrap()
                .status,
            expected,
            "claim step {n}"
        );
    }

    // The coverage chain, the title-event update, and the asset deregistration.
    for (n, t) in [
        tx(
            &actor,
            12,
            PropertyOperation::UpdateCoverage,
            &CoverageStatusUpdate {
                coverage_id: [0xD2; 32],
                status: CoverageStatus::NonRenewed,
            },
        ),
        tx(
            &actor,
            13,
            PropertyOperation::CancelCoverage,
            &CoverageId32 {
                coverage_id: [0xD2; 32],
            },
        ),
        tx(
            &actor,
            14,
            PropertyOperation::UpdateTitleEvent,
            &TitleStatusUpdate {
                event_id: [0xD0; 32],
                status: TitleEventStatus::Corrected,
            },
        ),
        tx(
            &actor,
            15,
            PropertyOperation::DeregisterAsset,
            &AssetId32 {
                asset_id: [130; 32],
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
            "tail {n}: {:?}",
            r.status
        );
    }

    assert_eq!(
        PropertyExecutor::v_get_coverage(&view, &[0xD2u8; 32])
            .unwrap()
            .unwrap()
            .status,
        CoverageStatus::Cancelled,
        "the cancellation was applied over the non-renewal, not over `Active`"
    );
    assert_eq!(
        PropertyExecutor::v_get_title_event(&view, &[0xD0u8; 32])
            .unwrap()
            .unwrap()
            .status,
        TitleEventStatus::Corrected
    );
    assert_eq!(
        PropertyExecutor::v_get_asset(&view, &[130u8; 32])
            .unwrap()
            .unwrap()
            .status,
        AssetStatus::Deregistered
    );
    // None of the five indexes moved during any of it: a transition rewrites
    // the primary row only.
    assert_eq!(
        PropertyExecutor::v_get_jurisdiction_asset_ids(&view, JURISDICTION).unwrap(),
        vec![[130u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_title_event_ids(&view, &[130u8; 32]).unwrap(),
        vec![[0xD0u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_encumbrance_ids(&view, &[130u8; 32]).unwrap(),
        vec![[0xD1u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_asset_coverage_ids(&view, &[130u8; 32]).unwrap(),
        vec![[0xD2u8; 32]]
    );
    assert_eq!(
        PropertyExecutor::v_get_coverage_claim_ids(&view, &[0xD2u8; 32]).unwrap(),
        vec![[0xD3u8; 32]]
    );
}

/// The PUBLISHED bytes are the byte contract, and this pins them directly.
///
/// Every other test here either compares candidate bytes to independent
/// expectations, or compares published rows to themselves across a restart.
/// Neither pins what actually lands in canonical storage: the step from
/// candidate to committed goes through `ApplicationOverlay::into_batch`, which
/// this commit does not cover. If that step ever reordered a key, dropped a
/// prefix or re-encoded a value, every existing assertion would still pass.
///
/// So: publish a real block through the real publisher, then for all eleven
/// migrated families read the RAW committed bytes and compare them against a
/// key written out by hand and a value produced by `bincode::serialize` applied
/// here in the test. Nothing on the expected side calls a key builder or a
/// codec from the crate under test. Then close the database, reopen it at the
/// same path, and compare the same eleven expectations again.
#[test]
fn published_property_bytes_match_independently_built_keys_and_values() {
    let dir = tempfile::TempDir::new().unwrap();
    let actor = KeyPair::generate();
    let issuer = actor.address();
    const ID: u8 = 80;

    // Expectations built here, from the schema, with no help from the crate.
    let asset_v = asset(ID, issuer);
    let title_v = title_event(ID.wrapping_add(1), ID, issuer);
    let enc_v = encumbrance(ID.wrapping_add(2), ID, issuer);
    let cov_v = coverage(ID.wrapping_add(3), ID, issuer);
    let claim_v = claim(ID.wrapping_add(4), ID.wrapping_add(3), ID, issuer);
    let proof_v = proof_envelope(ID.wrapping_add(5));

    // Primary families: a bare 32-byte id key. Index families: the parent's
    // 32-byte id, except the jurisdiction index, which is the raw UTF-8 of the
    // jurisdiction string. Index VALUES are bincode `Vec<[u8; 32]>`, not
    // presence markers.
    let expected: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            cf::PROPERTY_ASSETS,
            vec![ID; 32],
            bincode::serialize(&asset_v).unwrap(),
        ),
        (
            cf::PROPERTY_JURISDICTION_INDEX,
            JURISDICTION.as_bytes().to_vec(),
            bincode::serialize(&vec![[ID; 32]]).unwrap(),
        ),
        (
            cf::PROPERTY_TITLE_EVENTS,
            vec![ID.wrapping_add(1); 32],
            bincode::serialize(&title_v).unwrap(),
        ),
        (
            cf::PROPERTY_ASSET_TITLE_INDEX,
            vec![ID; 32],
            bincode::serialize(&vec![[ID.wrapping_add(1); 32]]).unwrap(),
        ),
        (
            cf::PROPERTY_ENCUMBRANCES,
            vec![ID.wrapping_add(2); 32],
            bincode::serialize(&enc_v).unwrap(),
        ),
        (
            cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
            vec![ID; 32],
            bincode::serialize(&vec![[ID.wrapping_add(2); 32]]).unwrap(),
        ),
        (
            cf::PROPERTY_COVERAGE,
            vec![ID.wrapping_add(3); 32],
            bincode::serialize(&cov_v).unwrap(),
        ),
        (
            cf::PROPERTY_ASSET_COVERAGE_INDEX,
            vec![ID; 32],
            bincode::serialize(&vec![[ID.wrapping_add(3); 32]]).unwrap(),
        ),
        (
            cf::PROPERTY_CLAIMS,
            vec![ID.wrapping_add(4); 32],
            bincode::serialize(&claim_v).unwrap(),
        ),
        (
            cf::PROPERTY_COVERAGE_CLAIM_INDEX,
            vec![ID.wrapping_add(3); 32],
            bincode::serialize(&vec![[ID.wrapping_add(4); 32]]).unwrap(),
        ),
        (
            cf::PROPERTY_PROOFS,
            vec![ID.wrapping_add(5); 32],
            bincode::serialize(&proof_v).unwrap(),
        ),
    ];
    assert_eq!(
        expected.len(),
        PROPERTY_CFS.len(),
        "one expectation per migrated family, and the list must not drift"
    );

    {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &actor, 500_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[9u8; 32],
            a_block_touching_every_family(&actor, ID),
            &[],
        );
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all six must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        for (family, key, value) in &expected {
            assert_eq!(
                db.get(family, key).unwrap().as_deref(),
                Some(&value[..]),
                "{family}: the published row does not match the bytes built \
                 independently in this test"
            );
        }
        // And the family holds exactly that one row -- so a publisher that
        // wrote the right bytes at an extra key would still be caught.
        for family in PROPERTY_CFS {
            assert_eq!(
                db.prefix_iter(family, &[]).unwrap().count(),
                1,
                "{family} must hold exactly the one published row"
            );
        }

        drop(executor);
        drop(state);
        assert_eq!(
            std::sync::Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             close it and the reopen proves nothing"
        );
        drop(db);
    }

    let db = Database::open_default(dir.path()).unwrap();
    for (family, key, value) in &expected {
        assert_eq!(
            db.get(family, key).unwrap().as_deref(),
            Some(&value[..]),
            "{family}: the row changed across a close and reopen"
        );
    }
}

// ── Class 3: the Property authority checks, and their activation ─────────────
//
// `docs/lane-a/ACTIVATION-AUDIT.md` rows AU-30 and AU-31, two of the three the
// pinning test `three_operations_check_no_authority_at_all` records.
// `MergeAssets` checks nothing about the sender, so any account merges two
// assets it did not issue and marks the secondary `Merged`. `SupersedeTitleEvent`
// checks nothing either, so any account supersedes any title event and records
// a replacement naming ITSELF -- a stranger rewriting a title history in one
// transaction.
//
// Gated on `property_authorization_enabled_from_height`, a `ChainParams` field
// this track cannot add.
//
// The third operation that test names -- `SubmitProof` (AU-32) -- is NOT
// addressed here and is not claimed to be. `PropertyProofEnvelope` carries no
// issuer address and Property has no issuer registry to consult (there is no
// `v_get_issuer` anywhere in `property_executor.rs` or `property_view.rs`), so
// there is nothing on the row or in the subsystem to authorize against. That is
// a wire and registry change, not a guard, and it stays blocking.

use sumchain_state::PropertyGates;

/// Drive one Property operation through the gate seam.
fn property_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: PropertyOperation,
    payload: &impl serde::Serialize,
    gates: PropertyGates,
) -> sumchain_state::PropertyExecutionResult {
    let proposer = Address::new([9; 20]);
    PropertyExecutor::execute_with_gates(
        view,
        sender,
        &PropertyTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        },
        &proposer,
        100,
        1,
        1_000,
        0,
        sumchain_primitives::Hash::ZERO,
        gates,
    )
    .unwrap()
}

/// AU-30: a stranger merges two assets it did not issue.
#[test]
fn a_stranger_can_merge_assets_it_did_not_issue_only_below_the_gate() {
    #[derive(serde::Serialize)]
    struct Merge {
        primary_asset_id: [u8; 32],
        secondary_asset_id: [u8; 32],
    }

    for gates in [PropertyGates::CLOSED, PropertyGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        let stranger = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for id in [110u8, 111] {
            assert!(
                property_at(
                    &mut view,
                    &owner.address(),
                    PropertyOperation::AnchorAsset,
                    &asset(id, owner.address()),
                    gates
                )
                .success
            );
        }

        let r = property_at(
            &mut view,
            &stranger.address(),
            PropertyOperation::MergeAssets,
            &Merge {
                primary_asset_id: [110u8; 32],
                secondary_asset_id: [111u8; 32],
            },
            gates,
        );
        assert_eq!(r.success, !gates.authorization);
        assert_eq!(
            PropertyExecutor::v_get_asset(&view, &[111u8; 32])
                .unwrap()
                .unwrap()
                .status
                == AssetStatus::Merged,
            !gates.authorization,
            "the secondary asset is marked Merged by a stranger, until the gate"
        );

        // And the issuer of both keeps the operation.
        assert!(
            property_at(
                &mut view,
                &owner.address(),
                PropertyOperation::MergeAssets,
                &Merge {
                    primary_asset_id: [110u8; 32],
                    secondary_asset_id: [111u8; 32],
                },
                gates
            )
            .success
        );
    }
}

/// AU-31: a stranger supersedes a title event and names itself in the
/// replacement.
#[test]
fn a_stranger_cannot_rewrite_a_title_history_at_the_gate() {
    #[derive(serde::Serialize)]
    struct Supersede {
        old_event_id: [u8; 32],
        new_event: TitleEvent,
    }

    for gates in [PropertyGates::CLOSED, PropertyGates::OPEN] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        let stranger = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        fund(&db, &stranger, 100_000_000);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            property_at(
                &mut view,
                &owner.address(),
                PropertyOperation::AnchorAsset,
                &asset(112, owner.address()),
                gates
            )
            .success
        );
        let original = title_event(0xB0, 112, owner.address());
        assert!(
            property_at(
                &mut view,
                &owner.address(),
                PropertyOperation::RecordTitleEvent,
                &original,
                gates
            )
            .success
        );

        // The replacement names the STRANGER as issuer.
        let replacement = title_event(0xB1, 112, stranger.address());
        let r = property_at(
            &mut view,
            &stranger.address(),
            PropertyOperation::SupersedeTitleEvent,
            &Supersede {
                old_event_id: original.event_id,
                new_event: replacement.clone(),
            },
            gates,
        );
        assert_eq!(r.success, !gates.authorization);
        assert_eq!(
            PropertyExecutor::v_get_title_event(&view, &replacement.event_id)
                .unwrap()
                .is_some(),
            !gates.authorization,
            "a stranger's replacement enters the title history, until the gate"
        );
    }
}
