//! `property_state_precondition_enabled_from_height` and
//! `property_asset_relationship_enabled_from_height`: a row whose status is
//! FINAL accepts no further operation, and a merge records the relationship it
//! asserts on both rows.
//!
//! ACTIVATION-AUDIT rows OV-21 and OV-22 (the merge half). Row OV-16 is the
//! third row of this track and is NOT here: it was closed in an earlier pass by
//! DECIDING what `max_supply` means rather than by gating anything, and its pin
//! is `max_supply_bounds_live_tokens_and_not_lifetime_issuance` in
//! `nft_routing.rs`. Nothing about it lives in `property_executor.rs`.
//!
//! # The two rules, and why they are two heights
//!
//! OV-21 decides whether an operation APPLIES. OV-22 decides what an operation
//! that does apply RECORDS. They fail differently, they are argued from
//! different evidence, and either is coherent without the other -- so each has
//! its own field, and each is proved here with the other CLOSED.
//!
//! # What "final" means, and where the definition is tested
//!
//! Final is not a judgement the executor makes: it is the status a NAMED
//! operation writes and that no named operation leaves. `MergeAssets`,
//! `SubdivideAsset` and `DeregisterAsset` write `Merged`, `Subdivided` and
//! `Deregistered`, and no arm writes an asset back out of any of them.
//! `Suspended`, `Closed` and `Denied` are deliberately NOT final, because
//! `ReinstateCoverage` and `ReopenClaim` are exactly the named ways out -- the
//! same fact that gave those two arms the only state guards this subsystem
//! already had.
//!
//! The five `the_final_*_statuses_are_*` tests below ARE that definition: each
//! drives every variant of one status enum through that family's free-form
//! `Update*` arm with the gate open, and asserts refused-iff-final against an
//! expectation restated in this file by an EXHAUSTIVE match. A status added to
//! the wire type stops this file compiling until it is classified; a status
//! moved across the line in `property_executor.rs` and not here fails a test
//! rather than the build. Those five are the covering tests for the predicate.
//!
//! Each has a `below_the_gate_*` twin running the same table with every gate
//! closed, in which EVERY status is accepted. That twin is the discriminator --
//! without it every assertion here would also pass for a gate that refused
//! everything -- and being byte-for-byte the release configuration it is also
//! the proof that a node with no height set executes what it executed before.
//!
//! # Why the merge bound is here and not on the allocation height
//!
//! `related_assets` only becomes an accumulating list AT the relationship gate.
//! A bound that arrived separately would leave an operator who opened this gate
//! alone running the one accumulating row in the tree that nothing bounds, so
//! `PropertyGates::related_row_limit` reads `asset_relationship` and the
//! refusal below is proved with `allocation_bound` CLOSED.
//!
//! Every pair is spelled `{ <one field>: true, ..CLOSED }`, never field by
//! field, so a gate added to `PropertyGates` later leaves the pair differing in
//! exactly one decision.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, ClaimStatus, ClaimType, CoverageStatus, CoverageType,
    Encumbrance, EncumbranceStatus, EncumbranceType, InsuranceClaim, InsuranceCoverage,
    PriorityPosition, PropertyIssuerClass, PropertyOperation, PropertyTxData, TitleEvent,
    TitleEventStatus, TitleEventType,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{PropertyExecutor, PropertyGates, StateManager, MAX_ACCUMULATING_ROW_BYTES};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::PropertyStore;

const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const JURISDICTION: &str = "US-NY";
const SEEDED_TS: u64 = 1_000;
const BLOCK_TS: u64 = 2_000;

/// What `block_timestamp` becomes INSIDE the executor while
/// `real_block_timestamp` is closed: `effective_block_timestamp` replaces the
/// block's own value with `0`. That gate belongs to another audit row and is
/// closed in every pair here, so every row these tests write carries `0` rather
/// than [`BLOCK_TS`]. Named rather than written as a bare literal, so that a
/// test asserting "this row was written at all" is not misread as asserting a
/// timestamp rule.
const WRITTEN_TS: u64 = 0;

const PRIMARY: u8 = 0xA0;
const SECONDARY: u8 = 0xB0;
const EVENT: u8 = 0x15;
const ENCUMBRANCE: u8 = 0x25;
const COVERAGE: u8 = 0xF0;
const CLAIM: u8 = 0x45;

// ── Payloads ────────────────────────────────────────────────────────────────
//
// One mirror struct per `#[derive(Deserialize)]` in the arm it feeds, rather
// than one general-purpose bag: a payload that stops matching its arm should
// fail to deserialize in one test, not in all of them.

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
struct TitleStatusUpdate {
    event_id: [u8; 32],
    status: TitleEventStatus,
}
#[derive(serde::Serialize)]
struct EncumbranceStatusUpdate {
    encumbrance_id: [u8; 32],
    status: EncumbranceStatus,
}
#[derive(serde::Serialize)]
struct CoverageStatusUpdate {
    coverage_id: [u8; 32],
    status: CoverageStatus,
}
#[derive(serde::Serialize)]
struct ClaimStatusUpdate {
    claim_id: [u8; 32],
    status: ClaimStatus,
}
#[derive(serde::Serialize)]
struct ClaimId32 {
    claim_id: [u8; 32],
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
#[derive(serde::Serialize)]
struct AssetId32 {
    asset_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct EventId32 {
    event_id: [u8; 32],
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
struct CoverageId32 {
    coverage_id: [u8; 32],
}
#[derive(serde::Serialize)]
struct RenewData {
    coverage_id: [u8; 32],
    new_expiry: u64,
}

fn enc<T: serde::Serialize>(t: &T) -> Vec<u8> {
    bincode::serialize(t).expect("payload")
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn asset_of(issuer: &Address, id: u8) -> AssetAnchor {
    AssetAnchor {
        asset_id: [id; 32],
        asset_commitment: [id.wrapping_add(1); 32],
        asset_type: AssetType::SingleFamilyResidence,
        jurisdiction_code: JURISDICTION.to_string(),
        public_reference: None,
        policy_id: [12u8; 32],
        issuer_class: PropertyIssuerClass::LandRegistry,
        issuer_address: *issuer,
        status: AssetStatus::Active,
        created_at: SEEDED_TS,
        updated_at: SEEDED_TS,
        anchored_at_height: 1,
        related_assets: vec![],
        attachments: vec![],
    }
}

fn title_event_of(issuer: &Address, id: u8) -> TitleEvent {
    TitleEvent {
        event_id: [id; 32],
        asset_id: [PRIMARY; 32],
        event_type: TitleEventType::WarrantyDeed,
        event_commitment: [id.wrapping_add(1); 32],
        grantor_ref: None,
        grantee_ref: None,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::TitleCompany,
        effective_date: SEEDED_TS,
        recording_ref: None,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: TitleEventStatus::Recorded,
        created_at: SEEDED_TS,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

fn encumbrance_of(issuer: &Address, id: u8) -> Encumbrance {
    Encumbrance {
        encumbrance_id: [id; 32],
        asset_id: [PRIMARY; 32],
        encumbrance_type: EncumbranceType::FirstMortgage,
        encumbrance_commitment: [id.wrapping_add(1); 32],
        holder_ref: PartyRef::Commitment([0xC3; 32]),
        obligor_ref: None,
        priority: PriorityPosition::First,
        amount_commitment: None,
        effective_from: SEEDED_TS,
        expiry: Some(9_000_000),
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::MortgageLender,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: EncumbranceStatus::Active,
        created_at: SEEDED_TS,
        updated_at: SEEDED_TS,
        recorded_at_height: 1,
        agreement_id: None,
        attachments: vec![],
    }
}

fn coverage_of(issuer: &Address, id: u8) -> InsuranceCoverage {
    InsuranceCoverage {
        coverage_id: [id; 32],
        asset_id: [PRIMARY; 32],
        coverage_type: CoverageType::Homeowners,
        coverage_commitment: [id.wrapping_add(1); 32],
        insurer_ref: PartyRef::Commitment([0xE5; 32]),
        insured_ref: PartyRef::Commitment([0xF6; 32]),
        additional_insureds: vec![],
        limit_commitment: [id.wrapping_add(2); 32],
        deductible_commitment: None,
        premium_commitment: None,
        effective_from: SEEDED_TS,
        expiry: 9_000_000,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: CoverageStatus::Active,
        created_at: SEEDED_TS,
        updated_at: SEEDED_TS,
        recorded_at_height: 1,
        prior_coverage_id: None,
        attachments: vec![],
    }
}

fn claim_of(issuer: &Address, id: u8) -> InsuranceClaim {
    InsuranceClaim {
        claim_id: [id; 32],
        coverage_id: [COVERAGE; 32],
        asset_id: [PRIMARY; 32],
        claim_type: ClaimType::WaterDamage,
        claim_commitment: [id.wrapping_add(1); 32],
        claimant_ref: PartyRef::Commitment([0xA7; 32]),
        date_of_loss: 900,
        date_filed: SEEDED_TS,
        loss_amount_commitment: None,
        approved_amount_commitment: None,
        paid_amount_commitment: None,
        adjuster_ref: None,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ClaimStatus::Filed,
        created_at: SEEDED_TS,
        updated_at: SEEDED_TS,
        recorded_at_height: 1,
        related_claims: vec![],
        attachments: vec![],
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The gate under test open, and nothing else.
const PRECONDITION: PropertyGates = PropertyGates {
    state_precondition: true,
    ..PropertyGates::CLOSED
};

const RELATIONSHIP: PropertyGates = PropertyGates {
    asset_relationship: true,
    ..PropertyGates::CLOSED
};

/// One transaction against one candidate, and everything a test here asks about
/// the result.
struct Outcome<T> {
    success: bool,
    error: Option<String>,
    /// Whether the sender paid. A refusal that has already taken the fee is a
    /// different remedy from one that has not, and every guard added for these
    /// two rows sits AHEAD of `v_deduct` deliberately.
    fee_charged: bool,
    seen: T,
}

/// Run one transaction against `view` and report only whether it applied.
fn step(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    op: PropertyOperation,
    data: Vec<u8>,
    gates: PropertyGates,
) -> (bool, Option<String>) {
    let r = PropertyExecutor::execute_with_gates(
        view,
        sender,
        &PropertyTxData {
            operation: op,
            data,
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        BLOCK_TS,
        0,
        Hash::ZERO,
        gates,
    )
    .expect("neither side may make the block unexecutable");
    (r.success, r.error)
}

/// Seed, execute once, inspect the candidate.
///
/// The rows go in through the committed stores, so that the SEEDED status is
/// the only thing differing between two runs of one table; the read back is
/// through the candidate's own view rather than the database, because a refusal
/// that wrote nothing and a success that wrote something have to be
/// distinguished INSIDE the block.
fn exec<T>(
    seed: impl FnOnce(&Address, &PropertyStore<'_>),
    op: PropertyOperation,
    payload: impl FnOnce() -> Vec<u8>,
    gates: PropertyGates,
    inspect: impl FnOnce(&ExecutionView<'_, '_>) -> T,
) -> Outcome<T> {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let addr = actor.address();
    fund(&db, &actor, FUNDED);
    {
        let store = PropertyStore::new(&db);
        seed(&addr, &store);
    }

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before = StateManager::v_get_balance(&view, &addr).unwrap();
    let (success, error) = step(&mut view, &addr, op, payload(), gates);
    let after = StateManager::v_get_balance(&view, &addr).unwrap();
    Outcome {
        success,
        error,
        fee_charged: after != before,
        seen: inspect(&view),
    }
}

fn asset(view: &ExecutionView<'_, '_>, id: u8) -> AssetAnchor {
    PropertyExecutor::v_get_asset(view, &[id; 32])
        .unwrap()
        .expect("the row is seeded")
}

// ── The definition of final, one family at a time ───────────────────────────
//
// Each `expected_final_*` restates the rule INDEPENDENTLY of the executor, by
// an exhaustive match. That is what makes the tables below covering tests:
// moving a status across the line in `property_executor.rs` and not here fails
// a test, and adding a variant to the wire type and not here fails the build.

const ALL_ASSET_STATUSES: [AssetStatus; 8] = [
    AssetStatus::Active,
    AssetStatus::PendingTransfer,
    AssetStatus::Encumbered,
    AssetStatus::Seized,
    AssetStatus::Destroyed,
    AssetStatus::Merged,
    AssetStatus::Subdivided,
    AssetStatus::Deregistered,
];

/// `Merged`, `Subdivided` and `Deregistered` are written by `MergeAssets`,
/// `SubdivideAsset` and `DeregisterAsset`, and no arm writes an asset back out
/// of any of them.
///
/// `Destroyed` and `Seized` READ as endings and are deliberately not final:
/// nothing but the free-form `UpdateAsset` ever writes them, so calling them
/// final would be choosing a lifecycle inside an executor rather than enforcing
/// the one the named arms already describe.
fn expected_final_asset(status: AssetStatus) -> bool {
    match status {
        AssetStatus::Merged | AssetStatus::Subdivided | AssetStatus::Deregistered => true,
        AssetStatus::Active
        | AssetStatus::PendingTransfer
        | AssetStatus::Encumbered
        | AssetStatus::Seized
        | AssetStatus::Destroyed => false,
    }
}

const ALL_TITLE_EVENT_STATUSES: [TitleEventStatus; 5] = [
    TitleEventStatus::Recorded,
    TitleEventStatus::Pending,
    TitleEventStatus::Superseded,
    TitleEventStatus::Voided,
    TitleEventStatus::Corrected,
];

/// `SupersedeTitleEvent` writes `Superseded` and `VoidTitleEvent` writes
/// `Voided`; nothing writes a title event back out of either.
fn expected_final_title_event(status: TitleEventStatus) -> bool {
    match status {
        TitleEventStatus::Superseded | TitleEventStatus::Voided => true,
        TitleEventStatus::Recorded | TitleEventStatus::Pending | TitleEventStatus::Corrected => {
            false
        }
    }
}

const ALL_ENCUMBRANCE_STATUSES: [EncumbranceStatus; 8] = [
    EncumbranceStatus::Active,
    EncumbranceStatus::Pending,
    EncumbranceStatus::Subordinated,
    EncumbranceStatus::Released,
    EncumbranceStatus::Foreclosed,
    EncumbranceStatus::Expired,
    EncumbranceStatus::Disputed,
    EncumbranceStatus::Voided,
];

/// `ReleaseEncumbrance` writes `Released` and `ForecloseEncumbrance` writes
/// `Foreclosed`. `Expired` and `Voided` are reachable only through
/// `UpdateEncumbrance` and are not final, for the reason
/// [`expected_final_asset`] gives.
fn expected_final_encumbrance(status: EncumbranceStatus) -> bool {
    match status {
        EncumbranceStatus::Released | EncumbranceStatus::Foreclosed => true,
        EncumbranceStatus::Active
        | EncumbranceStatus::Pending
        | EncumbranceStatus::Subordinated
        | EncumbranceStatus::Expired
        | EncumbranceStatus::Disputed
        | EncumbranceStatus::Voided => false,
    }
}

const ALL_COVERAGE_STATUSES: [CoverageStatus; 8] = [
    CoverageStatus::Active,
    CoverageStatus::Pending,
    CoverageStatus::Suspended,
    CoverageStatus::Cancelled,
    CoverageStatus::Expired,
    CoverageStatus::Lapsed,
    CoverageStatus::Renewed,
    CoverageStatus::NonRenewed,
];

/// `CancelCoverage` writes `Cancelled` and nothing writes a coverage back out
/// of it. `Suspended` is NOT final: `ReinstateCoverage` is the named way out,
/// which is the same fact that gives that arm its own existing guard.
fn expected_final_coverage(status: CoverageStatus) -> bool {
    match status {
        CoverageStatus::Cancelled => true,
        CoverageStatus::Active
        | CoverageStatus::Pending
        | CoverageStatus::Suspended
        | CoverageStatus::Expired
        | CoverageStatus::Lapsed
        | CoverageStatus::Renewed
        | CoverageStatus::NonRenewed => false,
    }
}

const ALL_CLAIM_STATUSES: [ClaimStatus; 14] = [
    ClaimStatus::Filed,
    ClaimStatus::Acknowledged,
    ClaimStatus::UnderInvestigation,
    ClaimStatus::PendingDocumentation,
    ClaimStatus::InReview,
    ClaimStatus::Approved,
    ClaimStatus::PartiallyApproved,
    ClaimStatus::Denied,
    ClaimStatus::Paid,
    ClaimStatus::Closed,
    ClaimStatus::Reopened,
    ClaimStatus::InLitigation,
    ClaimStatus::SubrogationPending,
    ClaimStatus::Withdrawn,
];

/// `PayClaim` writes `Paid` and `WithdrawClaim` writes `Withdrawn`. `Closed`
/// and `Denied` are NOT final: `ReopenClaim` is the named way out of both, and
/// its existing guard names exactly those two.
fn expected_final_claim(status: ClaimStatus) -> bool {
    match status {
        ClaimStatus::Paid | ClaimStatus::Withdrawn => true,
        ClaimStatus::Filed
        | ClaimStatus::Acknowledged
        | ClaimStatus::UnderInvestigation
        | ClaimStatus::PendingDocumentation
        | ClaimStatus::InReview
        | ClaimStatus::Approved
        | ClaimStatus::PartiallyApproved
        | ClaimStatus::Denied
        | ClaimStatus::Closed
        | ClaimStatus::Reopened
        | ClaimStatus::InLitigation
        | ClaimStatus::SubrogationPending => false,
    }
}

// ── OV-21: the five tables ──────────────────────────────────────────────────

#[test]
fn the_final_asset_statuses_are_the_ones_a_named_operation_writes_and_none_leaves() {
    for seeded in ALL_ASSET_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = asset_of(a, PRIMARY);
                row.status = seeded;
                s.assets().put(&row).unwrap();
            },
            PropertyOperation::UpdateAsset,
            || {
                enc(&AssetStatusUpdate {
                    asset_id: [PRIMARY; 32],
                    status: AssetStatus::Active,
                })
            },
            PRECONDITION,
            |v| asset(v, PRIMARY),
        );

        if expected_final_asset(seeded) {
            assert!(
                !out.success,
                "{seeded:?} is final and `UpdateAsset` must not apply to it"
            );
            assert!(
                !out.fee_charged,
                "{seeded:?}: a refusal ahead of `v_deduct` charges nothing"
            );
            assert_eq!(
                out.seen.status, seeded,
                "{seeded:?}: the refused transaction wrote nothing"
            );
            assert_eq!(
                out.seen.updated_at, SEEDED_TS,
                "{seeded:?}: nor a timestamp"
            );
        } else {
            assert!(
                out.success,
                "{seeded:?} is not final and must still accept the operation, or \
                 the gate refuses the OPERATION rather than the dead row: {:?}",
                out.error
            );
            assert_eq!(out.seen.status, AssetStatus::Active);
        }
    }
}

#[test]
fn below_the_gate_every_asset_status_accepts_the_free_form_update() {
    for seeded in ALL_ASSET_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = asset_of(a, PRIMARY);
                row.status = seeded;
                s.assets().put(&row).unwrap();
            },
            PropertyOperation::UpdateAsset,
            || {
                enc(&AssetStatusUpdate {
                    asset_id: [PRIMARY; 32],
                    status: AssetStatus::Active,
                })
            },
            PropertyGates::CLOSED,
            |v| asset(v, PRIMARY),
        );

        assert!(
            out.success,
            "the release configuration accepts {seeded:?}: {:?}",
            out.error
        );
        assert_eq!(
            out.seen.status,
            AssetStatus::Active,
            "and that is the un-deregister, the un-merge and the un-subdivide \
             this subsystem has no named operation for"
        );
    }
}

#[test]
fn the_final_title_event_statuses_are_the_ones_a_named_operation_writes_and_none_leaves() {
    for seeded in ALL_TITLE_EVENT_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = title_event_of(a, EVENT);
                row.status = seeded;
                s.title_events().put(&row).unwrap();
            },
            PropertyOperation::UpdateTitleEvent,
            || {
                enc(&TitleStatusUpdate {
                    event_id: [EVENT; 32],
                    status: TitleEventStatus::Recorded,
                })
            },
            PRECONDITION,
            |v| {
                PropertyExecutor::v_get_title_event(v, &[EVENT; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        if expected_final_title_event(seeded) {
            assert!(!out.success, "{seeded:?} is final");
            assert!(!out.fee_charged, "{seeded:?}: refused ahead of the fee");
            assert_eq!(out.seen.status, seeded, "{seeded:?}: nothing was written");
        } else {
            assert!(out.success, "{seeded:?} is live: {:?}", out.error);
            assert_eq!(out.seen.status, TitleEventStatus::Recorded);
        }
    }
}

#[test]
fn below_the_gate_every_title_event_status_accepts_the_free_form_update() {
    for seeded in ALL_TITLE_EVENT_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = title_event_of(a, EVENT);
                row.status = seeded;
                s.title_events().put(&row).unwrap();
            },
            PropertyOperation::UpdateTitleEvent,
            || {
                enc(&TitleStatusUpdate {
                    event_id: [EVENT; 32],
                    status: TitleEventStatus::Recorded,
                })
            },
            PropertyGates::CLOSED,
            |v| {
                PropertyExecutor::v_get_title_event(v, &[EVENT; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        assert!(
            out.success,
            "the release configuration accepts {seeded:?}: {:?}",
            out.error
        );
        assert_eq!(
            out.seen.status,
            TitleEventStatus::Recorded,
            "and that is how a history is rewritten without `SupersedeTitleEvent` \
             ever being called"
        );
    }
}

#[test]
fn the_final_encumbrance_statuses_are_the_ones_a_named_operation_writes_and_none_leaves() {
    for seeded in ALL_ENCUMBRANCE_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = encumbrance_of(a, ENCUMBRANCE);
                row.status = seeded;
                s.encumbrances().put(&row).unwrap();
            },
            PropertyOperation::UpdateEncumbrance,
            || {
                enc(&EncumbranceStatusUpdate {
                    encumbrance_id: [ENCUMBRANCE; 32],
                    status: EncumbranceStatus::Active,
                })
            },
            PRECONDITION,
            |v| {
                PropertyExecutor::v_get_encumbrance(v, &[ENCUMBRANCE; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        if expected_final_encumbrance(seeded) {
            assert!(!out.success, "{seeded:?} is final");
            assert!(!out.fee_charged, "{seeded:?}: refused ahead of the fee");
            assert_eq!(out.seen.status, seeded, "{seeded:?}: nothing was written");
        } else {
            assert!(out.success, "{seeded:?} is live: {:?}", out.error);
            assert_eq!(out.seen.status, EncumbranceStatus::Active);
        }
    }
}

#[test]
fn below_the_gate_every_encumbrance_status_accepts_the_free_form_update() {
    for seeded in ALL_ENCUMBRANCE_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = encumbrance_of(a, ENCUMBRANCE);
                row.status = seeded;
                s.encumbrances().put(&row).unwrap();
            },
            PropertyOperation::UpdateEncumbrance,
            || {
                enc(&EncumbranceStatusUpdate {
                    encumbrance_id: [ENCUMBRANCE; 32],
                    status: EncumbranceStatus::Active,
                })
            },
            PropertyGates::CLOSED,
            |v| {
                PropertyExecutor::v_get_encumbrance(v, &[ENCUMBRANCE; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        assert!(
            out.success,
            "the release configuration accepts {seeded:?}: {:?}",
            out.error
        );
        assert_eq!(
            out.seen.status,
            EncumbranceStatus::Active,
            "and that is a released lien becoming live again"
        );
    }
}

#[test]
fn the_final_coverage_statuses_are_the_ones_a_named_operation_writes_and_none_leaves() {
    for seeded in ALL_COVERAGE_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = coverage_of(a, COVERAGE);
                row.status = seeded;
                s.coverage().put(&row).unwrap();
            },
            PropertyOperation::UpdateCoverage,
            || {
                enc(&CoverageStatusUpdate {
                    coverage_id: [COVERAGE; 32],
                    status: CoverageStatus::Active,
                })
            },
            PRECONDITION,
            |v| {
                PropertyExecutor::v_get_coverage(v, &[COVERAGE; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        if expected_final_coverage(seeded) {
            assert!(!out.success, "{seeded:?} is final");
            assert!(!out.fee_charged, "{seeded:?}: refused ahead of the fee");
            assert_eq!(out.seen.status, seeded, "{seeded:?}: nothing was written");
        } else {
            assert!(
                out.success,
                "{seeded:?} is live -- and `Suspended` being live is the whole \
                 reason `ReinstateCoverage` exists: {:?}",
                out.error
            );
            assert_eq!(out.seen.status, CoverageStatus::Active);
        }
    }
}

#[test]
fn below_the_gate_every_coverage_status_accepts_the_free_form_update() {
    for seeded in ALL_COVERAGE_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = coverage_of(a, COVERAGE);
                row.status = seeded;
                s.coverage().put(&row).unwrap();
            },
            PropertyOperation::UpdateCoverage,
            || {
                enc(&CoverageStatusUpdate {
                    coverage_id: [COVERAGE; 32],
                    status: CoverageStatus::Active,
                })
            },
            PropertyGates::CLOSED,
            |v| {
                PropertyExecutor::v_get_coverage(v, &[COVERAGE; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        assert!(
            out.success,
            "the release configuration accepts {seeded:?}: {:?}",
            out.error
        );
        assert_eq!(
            out.seen.status,
            CoverageStatus::Active,
            "and that is `UpdateCoverage` walking around `ReinstateCoverage`'s \
             `Suspended` requirement"
        );
    }
}

#[test]
fn the_final_claim_statuses_are_the_ones_a_named_operation_writes_and_none_leaves() {
    for seeded in ALL_CLAIM_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = claim_of(a, CLAIM);
                row.status = seeded;
                s.claims().put(&row).unwrap();
            },
            PropertyOperation::UpdateClaim,
            || {
                enc(&ClaimStatusUpdate {
                    claim_id: [CLAIM; 32],
                    status: ClaimStatus::Approved,
                })
            },
            PRECONDITION,
            |v| {
                PropertyExecutor::v_get_claim(v, &[CLAIM; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        if expected_final_claim(seeded) {
            assert!(!out.success, "{seeded:?} is final");
            assert!(!out.fee_charged, "{seeded:?}: refused ahead of the fee");
            assert_eq!(out.seen.status, seeded, "{seeded:?}: nothing was written");
        } else {
            assert!(
                out.success,
                "{seeded:?} is live -- and `Closed` and `Denied` being live is the \
                 whole reason `ReopenClaim` exists: {:?}",
                out.error
            );
            assert_eq!(out.seen.status, ClaimStatus::Approved);
        }
    }
}

#[test]
fn below_the_gate_every_claim_status_accepts_the_free_form_update() {
    for seeded in ALL_CLAIM_STATUSES {
        let out = exec(
            |a, s| {
                let mut row = claim_of(a, CLAIM);
                row.status = seeded;
                s.claims().put(&row).unwrap();
            },
            PropertyOperation::UpdateClaim,
            || {
                enc(&ClaimStatusUpdate {
                    claim_id: [CLAIM; 32],
                    status: ClaimStatus::Approved,
                })
            },
            PropertyGates::CLOSED,
            |v| {
                PropertyExecutor::v_get_claim(v, &[CLAIM; 32])
                    .unwrap()
                    .expect("the row is seeded")
            },
        );

        assert!(
            out.success,
            "the release configuration accepts {seeded:?}: {:?}",
            out.error
        );
        assert_eq!(
            out.seen.status,
            ClaimStatus::Approved,
            "and setting a PAID claim back to `Approved` is the first step of the \
             double payment"
        );
    }
}

// ── OV-21: the cycle that walks around both guards the subsystem has ────────

/// Close, reopen, approve, pay: the same claim paid twice.
///
/// The sharpest case in row OV-21, because every step but the first is one of
/// the two arms that DO guard on what they read, and the cycle satisfies both:
/// `ReopenClaim` demands `Closed` and `CloseClaim` supplies it; `PayClaim`
/// demands `Approved` and `ApproveClaim` supplies it. Below the gate the second
/// payment overwrites `paid_amount_commitment` with a second, different
/// commitment on a claim the row already recorded as settled.
///
/// Above the gate the cycle dies at its FIRST step, because `Paid` is final and
/// `Closed` is not -- which is the whole content of the rule.
#[test]
fn a_paid_claim_is_closed_reopened_approved_and_paid_again_only_below_the_gate() {
    const FIRST: [u8; 32] = [0x01; 32];
    const SECOND: [u8; 32] = [0x02; 32];

    for gates in [PropertyGates::CLOSED, PRECONDITION] {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        let addr = actor.address();
        fund(&db, &actor, FUNDED);
        {
            let store = PropertyStore::new(&db);
            let mut claim = claim_of(&addr, CLAIM);
            claim.status = ClaimStatus::Paid;
            claim.paid_amount_commitment = Some(FIRST);
            store.claims().put(&claim).unwrap();
        }

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let id = ClaimId32 {
            claim_id: [CLAIM; 32],
        };

        let (closed, why) = step(
            &mut view,
            &addr,
            PropertyOperation::CloseClaim,
            enc(&id),
            gates,
        );

        if gates.state_precondition {
            assert!(
                !closed,
                "`Paid` is final: the cycle has no first step above the gate"
            );
            let claim = PropertyExecutor::v_get_claim(&view, &[CLAIM; 32])
                .unwrap()
                .expect("the row is seeded");
            assert_eq!(claim.status, ClaimStatus::Paid, "the row did not move");
            assert_eq!(
                claim.paid_amount_commitment,
                Some(FIRST),
                "and was paid exactly once"
            );
            continue;
        }

        assert!(closed, "below the gate a paid claim closes: {why:?}");
        assert!(
            step(
                &mut view,
                &addr,
                PropertyOperation::ReopenClaim,
                enc(&id),
                gates
            )
            .0,
            "`ReopenClaim`'s guard demands `Closed`, and `CloseClaim` supplied it"
        );
        assert!(
            step(
                &mut view,
                &addr,
                PropertyOperation::ApproveClaim,
                enc(&ApproveData {
                    claim_id: [CLAIM; 32],
                    approved_amount_commitment: SECOND,
                }),
                gates
            )
            .0,
            "and `ApproveClaim` guards on nothing at all"
        );
        assert!(
            step(
                &mut view,
                &addr,
                PropertyOperation::PayClaim,
                enc(&PayData {
                    claim_id: [CLAIM; 32],
                    paid_amount_commitment: SECOND,
                }),
                gates
            )
            .0,
            "`PayClaim`'s guard demands `Approved`, and `ApproveClaim` supplied it"
        );

        let claim = PropertyExecutor::v_get_claim(&view, &[CLAIM; 32])
            .unwrap()
            .expect("the row is seeded");
        assert_eq!(claim.status, ClaimStatus::Paid);
        assert_eq!(
            claim.paid_amount_commitment,
            Some(SECOND),
            "the release configuration pays one claim a second time, and the row \
             keeps only the second commitment"
        );
    }
}

// ── OV-21: the merge checks BOTH rows ───────────────────────────────────────

/// A merge is a statement about both rows, so a dead row on either side stops
/// it. Two cases, because a gate that checked one side only would pass a test
/// that only ever seeded the other.
#[test]
fn a_merge_is_refused_above_the_gate_when_either_asset_is_already_final() {
    for (label, primary_status, secondary_status) in [
        ("primary", AssetStatus::Merged, AssetStatus::Active),
        ("secondary", AssetStatus::Active, AssetStatus::Merged),
    ] {
        for gates in [PropertyGates::CLOSED, PRECONDITION] {
            let out = exec(
                |a, s| {
                    let mut p = asset_of(a, PRIMARY);
                    p.status = primary_status;
                    s.assets().put(&p).unwrap();
                    let mut q = asset_of(a, SECONDARY);
                    q.status = secondary_status;
                    s.assets().put(&q).unwrap();
                },
                PropertyOperation::MergeAssets,
                || {
                    enc(&MergeData {
                        primary_asset_id: [PRIMARY; 32],
                        secondary_asset_id: [SECONDARY; 32],
                    })
                },
                gates,
                |v| asset(v, SECONDARY).status,
            );

            if gates.state_precondition {
                assert!(
                    !out.success,
                    "the {label} asset is `Merged` and the merge must be refused"
                );
                assert!(!out.fee_charged, "{label}: refused ahead of the fee");
                assert_eq!(
                    out.seen, secondary_status,
                    "{label}: the refused merge wrote nothing"
                );
            } else {
                assert!(
                    out.success,
                    "the release configuration merges an already-merged asset \
                     ({label}): {:?}",
                    out.error
                );
                assert_eq!(out.seen, AssetStatus::Merged);
            }
        }
    }
}

// ── OV-22: the merge records what it asserts ────────────────────────────────

/// Below the gate the whole of a merge is `AssetStatus::Merged` on the
/// secondary. The primary row is never written, and `related_assets` -- the
/// field `AssetAnchor` carries "for subdivisions, mergers" -- stays empty on
/// both sides, so the merge is unreadable from either row afterwards.
///
/// Above it each row names the other. BOTH directions are asserted, because the
/// audit row names both halves of the omission: "records no relationship" and
/// "never writes the primary asset".
#[test]
fn a_merge_links_both_rows_only_above_the_relationship_gate() {
    for gates in [PropertyGates::CLOSED, RELATIONSHIP] {
        let out = exec(
            |a, s| {
                s.assets().put(&asset_of(a, PRIMARY)).unwrap();
                s.assets().put(&asset_of(a, SECONDARY)).unwrap();
            },
            PropertyOperation::MergeAssets,
            || {
                enc(&MergeData {
                    primary_asset_id: [PRIMARY; 32],
                    secondary_asset_id: [SECONDARY; 32],
                })
            },
            gates,
            |v| (asset(v, PRIMARY), asset(v, SECONDARY)),
        );

        assert!(
            out.success,
            "the merge itself applies on both sides of this gate: {:?}",
            out.error
        );
        let (primary, secondary) = out.seen;
        assert_eq!(
            secondary.status,
            AssetStatus::Merged,
            "the status write is what a merge does on both sides"
        );

        if gates.asset_relationship {
            assert_eq!(
                primary.related_assets,
                vec![[SECONDARY; 32]],
                "the primary names what it absorbed"
            );
            assert_eq!(
                secondary.related_assets,
                vec![[PRIMARY; 32]],
                "and the absorbed row names what absorbed it, or a `Merged` row \
                 still points nowhere"
            );
            assert_eq!(
                primary.updated_at, WRITTEN_TS,
                "the primary row is written, which below the gate it never is"
            );
        } else {
            assert_eq!(
                primary,
                asset_of(&primary.issuer_address, PRIMARY),
                "below the gate the primary row is not touched AT ALL"
            );
            assert!(
                secondary.related_assets.is_empty(),
                "and the secondary records nothing but a status"
            );
        }
    }
}

/// The append is idempotent, exactly as the committed twin
/// `PropertyAssetStore::add_related_asset` writes it: `contains`, then push.
///
/// Two merges of the same pair in one candidate, with `state_precondition`
/// CLOSED so that the second is not refused for the secondary being `Merged` --
/// the thing under test is the list, not the precondition.
#[test]
fn merging_the_same_pair_twice_adds_no_second_entry() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let addr = actor.address();
    fund(&db, &actor, FUNDED);
    {
        let store = PropertyStore::new(&db);
        store.assets().put(&asset_of(&addr, PRIMARY)).unwrap();
        store.assets().put(&asset_of(&addr, SECONDARY)).unwrap();
    }

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for n in 0..2 {
        let (ok, why) = step(
            &mut view,
            &addr,
            PropertyOperation::MergeAssets,
            enc(&MergeData {
                primary_asset_id: [PRIMARY; 32],
                secondary_asset_id: [SECONDARY; 32],
            }),
            RELATIONSHIP,
        );
        assert!(ok, "merge {n} applies: {why:?}");
    }

    assert_eq!(
        asset(&view, PRIMARY).related_assets,
        vec![[SECONDARY; 32]],
        "a repeat is a no-op rather than a duplicate entry"
    );
    assert_eq!(
        asset(&view, SECONDARY).related_assets,
        vec![[PRIMARY; 32]],
        "on both rows"
    );
}

// ── OV-22 and AL-6: the write brings its own bound ──────────────────────────

/// An `AssetAnchor` whose STORED encoding is at least `target` bytes, and that
/// encoding's length.
///
/// The size is chosen rather than searched for -- a `Vec<[u8; 32]>` is an
/// 8-byte length prefix and 32 bytes an entry -- and asserted anyway, because a
/// codec change that altered the framing would otherwise seed a row on the
/// wrong side of the bound and leave every assertion below passing for the
/// wrong reason.
fn asset_of_at_least(issuer: &Address, id: u8, target: usize) -> (AssetAnchor, usize) {
    let mut row = asset_of(issuer, id);
    row.related_assets = (0..target.div_ceil(32) + 1)
        .map(|n| {
            let mut x = [0xEEu8; 32];
            x[..8].copy_from_slice(&(n as u64).to_le_bytes());
            x
        })
        .collect();
    let len = bincode::serialize(&row).unwrap().len();
    assert!(
        len >= target,
        "the fixture must actually be the size this test claims: {len} < {target}"
    );
    (row, len)
}

/// A merge whose relationship write would append to an over-long row is
/// refused; one at the bound is not.
///
/// The bound reads `asset_relationship`, NOT
/// `subsystem_allocation_bound_enabled_from_height` -- so `allocation_bound` is
/// closed on both sides of this pair. An operator who opened the relationship
/// gate alone would otherwise be running the one accumulating row in the tree
/// that nothing bounds.
///
/// Both sides are seeded in turn, because the write touches both rows and a
/// check on one only would pass a test that seeded the other. The AT-bound case
/// is the discriminator: what the gate refuses is the over-long row and not the
/// operation.
#[test]
fn a_merge_is_refused_when_either_stored_asset_row_is_already_over_the_bound() {
    for over_side in [PRIMARY, SECONDARY] {
        for (label, target) in [
            ("over", MAX_ACCUMULATING_ROW_BYTES + 1),
            ("at", MAX_ACCUMULATING_ROW_BYTES - 65_536),
        ] {
            for gates in [PropertyGates::CLOSED, RELATIONSHIP] {
                let small_side = if over_side == PRIMARY {
                    SECONDARY
                } else {
                    PRIMARY
                };
                let out = exec(
                    |a, s| {
                        let (big, len) = asset_of_at_least(a, over_side, target);
                        if label == "at" {
                            assert!(
                                len <= MAX_ACCUMULATING_ROW_BYTES,
                                "the AT fixture must be at or under the bound: {len}"
                            );
                        } else {
                            assert!(
                                len > MAX_ACCUMULATING_ROW_BYTES,
                                "the OVER fixture must be past it: {len}"
                            );
                        }
                        s.assets().put(&big).unwrap();
                        s.assets().put(&asset_of(a, small_side)).unwrap();
                    },
                    PropertyOperation::MergeAssets,
                    || {
                        enc(&MergeData {
                            primary_asset_id: [PRIMARY; 32],
                            secondary_asset_id: [SECONDARY; 32],
                        })
                    },
                    gates,
                    |v| asset(v, SECONDARY).status,
                );

                let refused = gates.asset_relationship && label == "over";
                assert_eq!(
                    out.success, !refused,
                    "over={over_side:#x} {label} relationship={}: {:?}",
                    gates.asset_relationship, out.error
                );
                if refused {
                    assert!(
                        out.error
                            .as_deref()
                            .is_some_and(|e| e.contains("too large to modify")),
                        "the refusal names the ROW, not the operation: {:?}",
                        out.error
                    );
                    assert!(!out.fee_charged, "and is taken before the fee");
                    assert_eq!(out.seen, AssetStatus::Active, "and writes no status either");
                } else {
                    assert_eq!(out.seen, AssetStatus::Merged);
                }
            }
        }
    }
}

// ── The two heights are two heights ─────────────────────────────────────────

/// Each field opens its own gate, at its own height, and neither opens the
/// other.
///
/// `PropertyGates::from_params` is the only place a height becomes a decision,
/// and the two new fields sit beside each other in `ChainParams` with names
/// sharing their first word. `remediation_gates.rs` proves each ACCESSOR reads
/// the field it names; this proves the two accessors reach the two struct
/// fields the executor actually branches on.
#[test]
fn each_new_height_opens_its_own_gate_and_neither_opens_the_other() {
    let precondition_only = ChainParams {
        property_state_precondition_enabled_from_height: Some(100),
        ..params()
    };
    let relationship_only = ChainParams {
        property_asset_relationship_enabled_from_height: Some(100),
        ..params()
    };

    for h in [0u64, 99] {
        let g = PropertyGates::from_params(&precondition_only, h);
        assert!(
            !g.state_precondition && !g.asset_relationship,
            "below its height the state-precondition gate is closed, at {h}"
        );
        let g = PropertyGates::from_params(&relationship_only, h);
        assert!(
            !g.state_precondition && !g.asset_relationship,
            "below its height the relationship gate is closed, at {h}"
        );
    }

    for h in [100u64, 10_000] {
        let g = PropertyGates::from_params(&precondition_only, h);
        assert!(
            g.state_precondition,
            "the state-precondition gate opens AT its height and stays open, at {h}"
        );
        assert!(
            !g.asset_relationship,
            "and opens nothing else: the relationship height is unset, at {h}"
        );
        let g = PropertyGates::from_params(&relationship_only, h);
        assert!(
            g.asset_relationship,
            "the relationship gate opens AT its height and stays open, at {h}"
        );
        assert!(!g.state_precondition, "and opens nothing else, at {h}");
    }

    let g = PropertyGates::from_params(&params(), u64::MAX);
    assert!(
        !g.state_precondition && !g.asset_relationship,
        "an unset field is dormant at EVERY height, which is what a genesis \
         written before these fields existed resolves to"
    );
}

// ── OV-21: every arm that gained the guard, not just the free-form one ──────
//
// The five tables prove the DEFINITION of final against one arm per family.
// These five prove the PLACEMENT: twenty-two guard sites were added to this
// executor, and a guard dropped from one arm in a merge would leave that one
// operation as the remaining way to move a dead row, with every table above
// still green. Each case is asserted on BOTH sides of the gate, so it is also
// the record of what the release configuration does today: all of it applies.

fn assert_arm(
    family: &str,
    op: PropertyOperation,
    data: Vec<u8>,
    seeded: impl Fn(&Address, &PropertyStore<'_>) + Copy,
) {
    for gates in [PropertyGates::CLOSED, PRECONDITION] {
        let out = exec(seeded, op, || data.clone(), gates, |_| ());
        if gates.state_precondition {
            assert!(
                !out.success,
                "{family}/{op:?} must refuse a final row above the gate"
            );
            assert!(
                !out.fee_charged,
                "{family}/{op:?}: refused ahead of `v_deduct`"
            );
            assert!(
                out.error
                    .as_deref()
                    .is_some_and(|e| e.contains("which is final")),
                "{family}/{op:?} must refuse for FINALITY and not for some other \
                 reason that would mask a missing guard: {:?}",
                out.error
            );
        } else {
            assert!(
                out.success,
                "the release configuration applies {family}/{op:?} to a final \
                 row: {:?}",
                out.error
            );
        }
    }
}

#[test]
fn every_guarded_asset_arm_refuses_a_final_asset() {
    let id = enc(&AssetId32 {
        asset_id: [PRIMARY; 32],
    });
    let seed = |a: &Address, s: &PropertyStore<'_>| {
        let mut row = asset_of(a, PRIMARY);
        row.status = AssetStatus::Deregistered;
        s.assets().put(&row).unwrap();
    };
    for op in [
        PropertyOperation::UpdateAsset,
        PropertyOperation::TransferAsset,
        PropertyOperation::SubdivideAsset,
        PropertyOperation::DeregisterAsset,
    ] {
        let data = if op == PropertyOperation::UpdateAsset {
            enc(&AssetStatusUpdate {
                asset_id: [PRIMARY; 32],
                status: AssetStatus::Active,
            })
        } else {
            id.clone()
        };
        assert_arm("asset", op, data, seed);
    }
}

#[test]
fn every_guarded_title_event_arm_refuses_a_final_event() {
    let seed = |a: &Address, s: &PropertyStore<'_>| {
        let mut row = title_event_of(a, EVENT);
        row.status = TitleEventStatus::Voided;
        s.title_events().put(&row).unwrap();
    };
    for (op, data) in [
        (
            PropertyOperation::UpdateTitleEvent,
            enc(&TitleStatusUpdate {
                event_id: [EVENT; 32],
                status: TitleEventStatus::Recorded,
            }),
        ),
        (
            PropertyOperation::SupersedeTitleEvent,
            enc(&SupersedeData {
                old_event_id: [EVENT; 32],
                new_event: title_event_of(&Address::ZERO, 0x16),
            }),
        ),
        (
            PropertyOperation::VoidTitleEvent,
            enc(&EventId32 {
                event_id: [EVENT; 32],
            }),
        ),
    ] {
        assert_arm("title event", op, data, seed);
    }
}

#[test]
fn every_guarded_encumbrance_arm_refuses_a_final_encumbrance() {
    let id = enc(&EncumbranceId32 {
        encumbrance_id: [ENCUMBRANCE; 32],
    });
    let seed = |a: &Address, s: &PropertyStore<'_>| {
        let mut row = encumbrance_of(a, ENCUMBRANCE);
        row.status = EncumbranceStatus::Released;
        s.encumbrances().put(&row).unwrap();
    };
    for op in [
        PropertyOperation::UpdateEncumbrance,
        PropertyOperation::SubordinateEncumbrance,
        PropertyOperation::ReleaseEncumbrance,
        PropertyOperation::ForecloseEncumbrance,
    ] {
        let data = if op == PropertyOperation::UpdateEncumbrance {
            enc(&EncumbranceStatusUpdate {
                encumbrance_id: [ENCUMBRANCE; 32],
                status: EncumbranceStatus::Active,
            })
        } else {
            id.clone()
        };
        assert_arm("encumbrance", op, data, seed);
    }
}

#[test]
fn every_guarded_coverage_arm_refuses_a_final_coverage() {
    let seed = |a: &Address, s: &PropertyStore<'_>| {
        let mut row = coverage_of(a, COVERAGE);
        row.status = CoverageStatus::Cancelled;
        s.coverage().put(&row).unwrap();
    };
    for (op, data) in [
        (
            PropertyOperation::UpdateCoverage,
            enc(&CoverageStatusUpdate {
                coverage_id: [COVERAGE; 32],
                status: CoverageStatus::Active,
            }),
        ),
        (
            PropertyOperation::RenewCoverage,
            enc(&RenewData {
                coverage_id: [COVERAGE; 32],
                new_expiry: 9_999_999,
            }),
        ),
        (
            PropertyOperation::CancelCoverage,
            enc(&CoverageId32 {
                coverage_id: [COVERAGE; 32],
            }),
        ),
        (
            PropertyOperation::SuspendCoverage,
            enc(&CoverageId32 {
                coverage_id: [COVERAGE; 32],
            }),
        ),
    ] {
        assert_arm("coverage", op, data, seed);
    }
}

#[test]
fn every_guarded_claim_arm_refuses_a_final_claim() {
    let id = enc(&ClaimId32 {
        claim_id: [CLAIM; 32],
    });
    let seed = |a: &Address, s: &PropertyStore<'_>| {
        let mut row = claim_of(a, CLAIM);
        row.status = ClaimStatus::Paid;
        s.claims().put(&row).unwrap();
    };
    for (op, data) in [
        (
            PropertyOperation::UpdateClaim,
            enc(&ClaimStatusUpdate {
                claim_id: [CLAIM; 32],
                status: ClaimStatus::Approved,
            }),
        ),
        (
            PropertyOperation::ApproveClaim,
            enc(&ApproveData {
                claim_id: [CLAIM; 32],
                approved_amount_commitment: [0x09; 32],
            }),
        ),
        (PropertyOperation::DenyClaim, id.clone()),
        (PropertyOperation::CloseClaim, id.clone()),
        (PropertyOperation::WithdrawClaim, id.clone()),
    ] {
        assert_arm("claim", op, data, seed);
    }
}
