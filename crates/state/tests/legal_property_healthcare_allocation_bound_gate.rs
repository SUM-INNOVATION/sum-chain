//! `subsystem_allocation_bound_enabled_from_height`, Legal, Property and
//! Healthcare halves: an accumulating row past the limit is refused BEFORE it
//! is decoded, appended to and re-encoded, and a payload past the limit is
//! refused before it is deserialized.
//!
//! ACTIVATION-AUDIT rows AL-3 (Legal, three index families), AL-6 (Property,
//! five), AL-8 (Healthcare, seven -- five index families plus two lists that
//! accumulate INSIDE a primary row) and AL-12 (the decode boundary, for the
//! three subsystems it names that did not already carry the payload bound).
//!
//! # Why this reads the field five other subsystems already read
//!
//! AL-3, AL-6 and AL-8 are AL-2/AL-4/AL-5/AL-10/AL-11 in three more
//! subsystems, word for word: every `v_add_to_*_index` reads an accumulating
//! row, decodes the whole of it, pushes one entry and re-encodes the whole of
//! it, and `view.put` only then charges the candidate's byte ceiling. The
//! ceiling therefore bounds what a block may COMMIT and bounds nothing about
//! what one transaction may ALLOCATE.
//!
//! The field's own doc comment gives the argument for one height rather than
//! eight -- one rule at one seam, and an attacker refused by one bound simply
//! uses the cheapest one still open. It applies here with a sharper edge than
//! usual: AL-1, AL-2, AL-4 and AL-5 are the SAME fixed-width accumulators as
//! AL-3 and AL-6 and were gated on exactly this argument, so leaving these two
//! ungated would have been the inconsistency, not the caution.
//!
//! This file does NOT claim a new gate, a new constant or a new rule. It claims
//! that three more subsystems now read the rule that already exists.
//!
//! # What AL-8's two IN-ROW cases turn out to be
//!
//! The audit's own Class 4 preamble separates this class by whether the
//! attacker controls the LENGTH of what is appended, and assigns AL-8 to the
//! fixed-32-bytes-per-transaction side. For AL-8's five INDEX families that is
//! right. For its two in-row accumulators it is not:
//! `HealthcareOperation::IssueMembership` deserializes a `MembershipRecord`
//! from the payload and stores it VERBATIM, `dependents` included, and
//! `IssuePrescription` does the same with `fill_history`. That is the
//! `CreateIdentityRoot` shape of AL-10 -- one transaction, bounded only by
//! `max_block_bytes`, seeds the row -- and
//! `a_membership_row_is_seeded_over_the_bound_by_one_transaction` below is the
//! demonstration rather than the assertion.
//!
//! # What each pair shows
//!
//! One `#[test]` per accumulating structure. Each seeds ONE committed row past
//! [`MAX_ACCUMULATING_ROW_BYTES`], then runs the SAME transaction against it
//! twice -- once with `allocation_bound: false` (the release configuration,
//! and byte-for-byte the unremediated binary) and once with it true -- and
//! asserts the two nodes DISAGREE: the ungated node admits the transaction and
//! grows the row further, the gated one refuses it with a failed receipt,
//! writes nothing, and charges nothing.
//!
//! A row AT the bound is accepted on both sides, so what the gate refuses is
//! the over-long row and not the operation. That is the discriminator: without
//! it every assertion here would also pass for a gate that refused everything.
//!
//! Every pair is spelled `{ allocation_bound: …, ..CLOSED }`, never field by
//! field, so a gate added to any of the three structs later leaves the pair
//! differing in exactly one decision.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementRole, AgreementStatus, AgreementTxData,
    PartyBinding, PartyRef,
};
use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareIssuerClass, HealthcareOperation, HealthcareTxData, MembershipRecord,
    MembershipStatus, MembershipType, Prescription, PrescriptionStatus, PrescriptionType,
    ProviderProfile, ProviderStatus, ProviderType,
};
use sumchain_primitives::legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType, CourtOrder,
    LegalIssuerClass, LegalOperation, LegalTxData, OrderStatus, OrderType, ProcessEvent,
    ProcessEventStatus, ProcessEventType,
};
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, ClaimStatus, ClaimType, CoverageStatus, CoverageType,
    Encumbrance, EncumbranceStatus, EncumbranceType, InsuranceClaim, InsuranceCoverage,
    PriorityPosition, PropertyIssuerClass, PropertyOperation, PropertyTxData, TitleEvent,
    TitleEventStatus, TitleEventType,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    AgreementExecutor, AgreementGates, HealthcareExecutor, HealthcareGates, LegalExecutor,
    LegalGates, PropertyExecutor, PropertyGates, StateManager, MAX_ACCUMULATING_ROW_BYTES,
    MAX_SUBSYSTEM_PAYLOAD_BYTES,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, HealthcareStore, LegalStore, PropertyStore};

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const JURISDICTION: &str = "US-NY";
const TS: u64 = 1_000;

const MEMBER_NULL: [u8; 32] = [0x71; 32];
const SUBJECT_NULL: [u8; 32] = [0x72; 32];
const PATIENT_NULL: [u8; 32] = [0x73; 32];
const PLAN_A: [u8; 32] = [0x74; 32];

macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                allocation_bound: true,
                ..$g::CLOSED
            },
        ]
    };
}

/// A bincode `Vec<[u8; 32]>` whose ENCODING is at least `target` bytes, plus
/// the exact encoding length.
///
/// The encoding is an 8-byte length prefix and 32 bytes an entry, so the size
/// is chosen rather than searched for; it is asserted anyway, because a codec
/// change that altered the framing would otherwise silently seed a row on the
/// wrong side of the bound and every assertion below would still pass.
fn id_list_of_at_least(target: usize) -> (Vec<u8>, usize) {
    let bytes = bincode::serialize(&ids_numbering(target.div_ceil(32) + 1)).unwrap();
    assert!(
        bytes.len() >= target,
        "the fixture must actually be the size this test claims: {} < {target}",
        bytes.len()
    );
    let len = bytes.len();
    (bytes, len)
}

fn ids_numbering(n: usize) -> Vec<[u8; 32]> {
    (0..n as u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

/// The one claim every index case makes.
///
/// `over` and `at` are "the creation transaction succeeded".
fn assert_the_pair_disagrees(family: &str, gate_open: bool, at: bool, over: bool) {
    assert!(
        at,
        "{family}: a row at the {MAX_ACCUMULATING_ROW_BYTES}-byte bound must be accepted \
         on both sides -- the gate refuses an over-long ROW, not the operation \
         (allocation_bound={gate_open})"
    );
    assert_eq!(
        over, !gate_open,
        "{family}: a row past the bound is ADMITTED below the gate and grown further; \
         at the gate it is a failed receipt (allocation_bound={gate_open})"
    );
}

// ── Legal ───────────────────────────────────────────────────────────────────

fn case_of(issuer: &Address, id: u8) -> CaseAnchor {
    CaseAnchor {
        case_id: [id; 32],
        case_commitment: [0xC1; 32],
        jurisdiction_code: JURISDICTION.to_string(),
        case_type: Some(CaseType::Civil),
        public_reference: None,
        policy_id: [0xC2; 32],
        issuer_class: LegalIssuerClass::LawFirm,
        issuer_address: *issuer,
        status: CaseStatus::Filed,
        created_at: TS,
        updated_at: TS,
        anchored_at_height: 1,
        related_cases: vec![],
    }
}

fn event_of(issuer: &Address, id: u8, case_id: u8) -> ProcessEvent {
    ProcessEvent {
        event_id: [id; 32],
        case_id: [case_id; 32],
        event_type: ProcessEventType::Filed,
        event_commitment: [0xE1; 32],
        issuer_address: *issuer,
        issuer_class: LegalIssuerClass::LawFirm,
        event_time_start: Some(TS),
        event_time_end: None,
        attachments: vec![],
        policy_id: [0xE2; 32],
        revocation_ref: None,
        status: ProcessEventStatus::Recorded,
        created_at: TS,
        recorded_at_height: 1,
        supersedes: None,
    }
}

fn order_of(issuer: &Address, id: u8, case_id: u8) -> CourtOrder {
    CourtOrder {
        order_id: [id; 32],
        case_id: [case_id; 32],
        order_type: OrderType::FinalJudgment,
        order_commitment: [0x01; 32],
        issuer_address: *issuer,
        issuer_class: LegalIssuerClass::CourtSystem,
        status: OrderStatus::Active,
        effective_from: TS,
        expiry: Some(9_000_000),
        policy_id: [0x02; 32],
        revocation_ref: None,
        created_at: TS,
        updated_at: TS,
        issued_at_height: 1,
        supersedes_order_id: None,
        attachments: vec![],
    }
}

fn benefit_of(issuer: &Address, id: u8) -> BenefitDetermination {
    BenefitDetermination {
        benefit_id: [id; 32],
        benefit_type: BenefitType::Medicare,
        jurisdiction_code: JURISDICTION.to_string(),
        status: BenefitStatus::Approved,
        determination_commitment: [0xB1; 32],
        subject_nullifier: [0xB2; 32],
        issuer_address: *issuer,
        issuer_class: LegalIssuerClass::GovernmentAgency,
        valid_from: TS,
        expiry: None,
        policy_id: [0xB3; 32],
        revocation_ref: None,
        created_at: TS,
        updated_at: TS,
        recorded_at_height: 1,
        supersedes: None,
    }
}

/// Everything one index case needs, so that the three subsystems' runners
/// differ only in which executor they call.
///
/// `make` takes the actor's address because every creation arm in all three
/// subsystems refuses a payload whose `issuer_address` is not the sender, and
/// the actor is generated per run.
struct Case<'a> {
    family: &'a str,
    index_cf: &'a str,
    key: Vec<u8>,
    seeded: Vec<u8>,
    /// The primary family the creation would have written, checked empty on a
    /// refusal so that "refused" means "wrote nothing", not "wrote half".
    primary_cf: &'a str,
    primary_key: Vec<u8>,
    make: &'a dyn Fn(&Address) -> Vec<u8>,
}

/// What the gated side must be true of, and what the ungated side must not be.
fn assert_outcome(
    c: &Case<'_>,
    view: &ExecutionView<'_, '_>,
    actor: &Address,
    before: u128,
    r: (bool, Option<String>),
) -> bool {
    let (success, error) = r;
    let family = c.family;
    if success {
        assert_ne!(
            view.get(c.index_cf, &c.key).unwrap().as_deref(),
            Some(c.seeded.as_slice()),
            "{family}: a transaction that succeeded must have grown the row"
        );
    } else {
        assert!(
            error.as_deref().unwrap_or_default().contains("too large"),
            "{family}: refused by the bound, not by something else: {error:?}"
        );
        assert_eq!(
            view.get(c.index_cf, &c.key).unwrap().as_deref(),
            Some(c.seeded.as_slice()),
            "{family}: the refusal must leave the row untouched"
        );
        assert!(
            view.get(c.primary_cf, &c.primary_key).unwrap().is_none(),
            "{family}: and must not stage the primary row either -- the bound is \
             checked before the write, not after it"
        );
        assert_eq!(
            StateManager::v_get_balance(view, actor).unwrap(),
            before,
            "{family}: the refusal writes nothing at all, and must not be the \
             exception that charges"
        );
    }
    success
}

// ── Legal runner ────────────────────────────────────────────────────────────

fn legal_case(c: Case<'_>, op: LegalOperation, gates: LegalGates) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let addr = actor.address();
    fund(&db, &actor, FUNDED);
    // The event and order arms both require the case they name to exist, and
    // anchoring it through the store rather than through a transaction keeps
    // the seeded index row the only thing that differs between the two runs.
    //
    // BEFORE the index row is seeded, not after: `CaseStore::put` appends to
    // the jurisdiction index itself, so seeding first would leave the row one
    // entry longer than `c.seeded` and every "the refusal left the row
    // untouched" assertion would compare against the wrong fixture.
    LegalStore::new(&db)
        .cases()
        .put(&case_of(&addr, 0xC0))
        .unwrap();
    db.put(c.index_cf, &c.key, &c.seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before = StateManager::v_get_balance(&view, &addr).unwrap();
    let r = LegalExecutor::execute_with_gates(
        &mut view,
        &addr,
        &LegalTxData {
            operation: op,
            data: (c.make)(&addr),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        TS,
        0,
        Hash::ZERO,
        gates,
    )
    .expect("neither side may make the block unexecutable");
    assert_outcome(&c, &view, &addr, before, (r.success, r.error))
}

#[test]
fn legal_jurisdiction_index_stops_growing_an_unbounded_accumulating_row() {
    let (over, over_len) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
    assert!(over_len > MAX_ACCUMULATING_ROW_BYTES);
    let (at, at_len) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
    assert!(at_len <= MAX_ACCUMULATING_ROW_BYTES);
    let make = |a: &Address| bincode::serialize(&case_of(a, 0xC5)).unwrap();
    let case = |seeded: &Vec<u8>| Case {
        family: "legal jurisdiction index",
        index_cf: cf::LEGAL_JURISDICTION_INDEX,
        key: format!("{JURISDICTION}:case").into_bytes(),
        seeded: seeded.clone(),
        primary_cf: cf::LEGAL_CASES,
        primary_key: vec![0xC5; 32],
        make: &make,
    };
    for gates in pair!(LegalGates) {
        assert_the_pair_disagrees(
            "legal jurisdiction index",
            gates.allocation_bound,
            legal_case(case(&at), LegalOperation::AnchorCase, gates),
            legal_case(case(&over), LegalOperation::AnchorCase, gates),
        );
    }
}

#[test]
fn legal_jurisdiction_index_is_the_same_row_for_benefits_and_is_bounded_there_too() {
    // The benefit half of the family, kept apart from the case half only by the
    // `":benefit"` suffix `v_put_benefit` appends. A second writer of one row
    // shape, and it needs the bound for the same reason.
    let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
    let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
    let make = |a: &Address| bincode::serialize(&benefit_of(a, 0xB5)).unwrap();
    let case = |seeded: &Vec<u8>| Case {
        family: "legal jurisdiction index (benefit)",
        index_cf: cf::LEGAL_JURISDICTION_INDEX,
        key: format!("{JURISDICTION}:benefit").into_bytes(),
        seeded: seeded.clone(),
        primary_cf: cf::LEGAL_BENEFITS,
        primary_key: vec![0xB5; 32],
        make: &make,
    };
    for gates in pair!(LegalGates) {
        assert_the_pair_disagrees(
            "legal jurisdiction index (benefit)",
            gates.allocation_bound,
            legal_case(case(&at), LegalOperation::DetermineBenefit, gates),
            legal_case(case(&over), LegalOperation::DetermineBenefit, gates),
        );
    }
}

#[test]
fn legal_case_event_index_stops_growing_an_unbounded_accumulating_row() {
    let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
    let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
    let make = |a: &Address| bincode::serialize(&event_of(a, 0xE5, 0xC0)).unwrap();
    let case = |seeded: &Vec<u8>| Case {
        family: "legal case event index",
        index_cf: cf::LEGAL_CASE_EVENT_INDEX,
        key: vec![0xC0; 32],
        seeded: seeded.clone(),
        primary_cf: cf::LEGAL_EVENTS,
        primary_key: vec![0xE5; 32],
        make: &make,
    };
    for gates in pair!(LegalGates) {
        assert_the_pair_disagrees(
            "legal case event index",
            gates.allocation_bound,
            legal_case(case(&at), LegalOperation::RecordEvent, gates),
            legal_case(case(&over), LegalOperation::RecordEvent, gates),
        );
    }
}

#[test]
fn legal_case_order_index_stops_growing_an_unbounded_accumulating_row() {
    let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
    let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
    let make = |a: &Address| bincode::serialize(&order_of(a, 0x05, 0xC0)).unwrap();
    let case = |seeded: &Vec<u8>| Case {
        family: "legal case order index",
        index_cf: cf::LEGAL_CASE_ORDER_INDEX,
        key: vec![0xC0; 32],
        seeded: seeded.clone(),
        primary_cf: cf::LEGAL_ORDERS,
        primary_key: vec![0x05; 32],
        make: &make,
    };
    for gates in pair!(LegalGates) {
        assert_the_pair_disagrees(
            "legal case order index",
            gates.allocation_bound,
            legal_case(case(&at), LegalOperation::IssueOrder, gates),
            legal_case(case(&over), LegalOperation::IssueOrder, gates),
        );
    }
}

// ── Property ────────────────────────────────────────────────────────────────

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
        created_at: TS,
        updated_at: TS,
        anchored_at_height: 1,
        related_assets: vec![],
        attachments: vec![],
    }
}

fn title_event_of(issuer: &Address, id: u8, asset_id: u8) -> TitleEvent {
    TitleEvent {
        event_id: [id; 32],
        asset_id: [asset_id; 32],
        event_type: TitleEventType::WarrantyDeed,
        event_commitment: [id.wrapping_add(1); 32],
        grantor_ref: None,
        grantee_ref: None,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::TitleCompany,
        effective_date: TS,
        recording_ref: None,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: TitleEventStatus::Recorded,
        created_at: TS,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

fn encumbrance_of(issuer: &Address, id: u8, asset_id: u8) -> Encumbrance {
    Encumbrance {
        encumbrance_id: [id; 32],
        asset_id: [asset_id; 32],
        encumbrance_type: EncumbranceType::FirstMortgage,
        encumbrance_commitment: [id.wrapping_add(1); 32],
        holder_ref: PartyRef::Commitment([0xC3; 32]),
        obligor_ref: None,
        priority: PriorityPosition::First,
        amount_commitment: None,
        effective_from: TS,
        expiry: Some(9_000_000),
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::MortgageLender,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: EncumbranceStatus::Active,
        created_at: TS,
        updated_at: TS,
        recorded_at_height: 1,
        agreement_id: None,
        attachments: vec![],
    }
}

fn coverage_of(issuer: &Address, id: u8, asset_id: u8) -> InsuranceCoverage {
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
        effective_from: TS,
        expiry: 9_000_000,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: CoverageStatus::Active,
        created_at: TS,
        updated_at: TS,
        recorded_at_height: 1,
        prior_coverage_id: None,
        attachments: vec![],
    }
}

fn claim_of(issuer: &Address, id: u8, coverage_id: u8, asset_id: u8) -> InsuranceClaim {
    InsuranceClaim {
        claim_id: [id; 32],
        coverage_id: [coverage_id; 32],
        asset_id: [asset_id; 32],
        claim_type: ClaimType::WaterDamage,
        claim_commitment: [id.wrapping_add(1); 32],
        claimant_ref: PartyRef::Commitment([0xA7; 32]),
        date_of_loss: 900,
        date_filed: TS,
        loss_amount_commitment: None,
        approved_amount_commitment: None,
        paid_amount_commitment: None,
        adjuster_ref: None,
        issuer_address: *issuer,
        issuer_class: PropertyIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ClaimStatus::Filed,
        created_at: TS,
        updated_at: TS,
        recorded_at_height: 1,
        related_claims: vec![],
        attachments: vec![],
    }
}

fn property_case(c: Case<'_>, op: PropertyOperation, gates: PropertyGates) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let addr = actor.address();
    fund(&db, &actor, FUNDED);
    // Every arm but `AnchorAsset` requires the asset it names, and `FileClaim`
    // the coverage. Seeded through the stores so that the index row under test
    // is the only thing that differs between the two runs -- and BEFORE the
    // index row is seeded, because `AssetStore::put` and `CoverageStore::put`
    // append to the jurisdiction and asset-coverage indexes themselves.
    let store = PropertyStore::new(&db);
    store.assets().put(&asset_of(&addr, 0xA0)).unwrap();
    store
        .coverage()
        .put(&coverage_of(&addr, 0xF0, 0xA0))
        .unwrap();
    db.put(c.index_cf, &c.key, &c.seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before = StateManager::v_get_balance(&view, &addr).unwrap();
    let r = PropertyExecutor::execute_with_gates(
        &mut view,
        &addr,
        &PropertyTxData {
            operation: op,
            data: (c.make)(&addr),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        TS,
        0,
        Hash::ZERO,
        gates,
    )
    .expect("neither side may make the block unexecutable");
    assert_outcome(&c, &view, &addr, before, (r.success, r.error))
}

macro_rules! property_index_test {
    ($name:ident, $family:literal, $index_cf:expr, $key:expr, $primary_cf:expr,
     $primary_key:expr, $op:expr, $make:expr) => {
        #[test]
        fn $name() {
            let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
            let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
            let make = $make;
            let case = |seeded: &Vec<u8>| Case {
                family: $family,
                index_cf: $index_cf,
                key: $key,
                seeded: seeded.clone(),
                primary_cf: $primary_cf,
                primary_key: $primary_key,
                make: &make,
            };
            for gates in pair!(PropertyGates) {
                assert_the_pair_disagrees(
                    $family,
                    gates.allocation_bound,
                    property_case(case(&at), $op, gates),
                    property_case(case(&over), $op, gates),
                );
            }
        }
    };
}

property_index_test!(
    property_jurisdiction_index_stops_growing_an_unbounded_accumulating_row,
    "property jurisdiction index",
    cf::PROPERTY_JURISDICTION_INDEX,
    JURISDICTION.as_bytes().to_vec(),
    cf::PROPERTY_ASSETS,
    vec![0xA5; 32],
    PropertyOperation::AnchorAsset,
    |a: &Address| bincode::serialize(&asset_of(a, 0xA5)).unwrap()
);

property_index_test!(
    property_asset_title_index_stops_growing_an_unbounded_accumulating_row,
    "property asset title index",
    cf::PROPERTY_ASSET_TITLE_INDEX,
    vec![0xA0; 32],
    cf::PROPERTY_TITLE_EVENTS,
    vec![0x15; 32],
    PropertyOperation::RecordTitleEvent,
    |a: &Address| bincode::serialize(&title_event_of(a, 0x15, 0xA0)).unwrap()
);

property_index_test!(
    property_asset_encumbrance_index_stops_growing_an_unbounded_accumulating_row,
    "property asset encumbrance index",
    cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX,
    vec![0xA0; 32],
    cf::PROPERTY_ENCUMBRANCES,
    vec![0x25; 32],
    PropertyOperation::RecordEncumbrance,
    |a: &Address| bincode::serialize(&encumbrance_of(a, 0x25, 0xA0)).unwrap()
);

property_index_test!(
    property_asset_coverage_index_stops_growing_an_unbounded_accumulating_row,
    "property asset coverage index",
    cf::PROPERTY_ASSET_COVERAGE_INDEX,
    vec![0xA0; 32],
    cf::PROPERTY_COVERAGE,
    vec![0x35; 32],
    PropertyOperation::IssueCoverage,
    |a: &Address| bincode::serialize(&coverage_of(a, 0x35, 0xA0)).unwrap()
);

property_index_test!(
    property_coverage_claim_index_stops_growing_an_unbounded_accumulating_row,
    "property coverage claim index",
    cf::PROPERTY_COVERAGE_CLAIM_INDEX,
    vec![0xF0; 32],
    cf::PROPERTY_CLAIMS,
    vec![0x45; 32],
    PropertyOperation::FileClaim,
    |a: &Address| bincode::serialize(&claim_of(a, 0x45, 0xF0, 0xA0)).unwrap()
);

// ── Healthcare ──────────────────────────────────────────────────────────────

fn provider_of(issuer: &Address, id: u8, plans: Vec<[u8; 32]>) -> ProviderProfile {
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
        issuer_address: *issuer,
        status: ProviderStatus::Active,
        created_at: TS,
        updated_at: TS,
        registered_at_height: 1,
        network_affiliations: plans,
        attachments: vec![],
    }
}

fn membership_of(issuer: &Address, id: u8, dependents: Vec<[u8; 32]>) -> MembershipRecord {
    MembershipRecord {
        membership_id: [id; 32],
        provider_id: [0xD0; 32],
        membership_type: MembershipType::IndividualHealth,
        membership_commitment: [id.wrapping_add(1); 32],
        member_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        member_address: Address::new([0x33; 20]),
        member_nullifier: MEMBER_NULL,
        coverage_tier: Some(CoverageTier::Individual),
        group_commitment: None,
        effective_from: 0,
        expiry: Some(9_000_000),
        issuer_address: *issuer,
        issuer_class: HealthcareIssuerClass::InsuranceCompany,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: MembershipStatus::Active,
        created_at: TS,
        updated_at: TS,
        issued_at_height: 1,
        prior_membership_id: None,
        dependents,
        attachments: vec![],
    }
}

fn consent_of(issuer: &Address, id: u8) -> ConsentEnvelope {
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
        issuer_address: *issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: ConsentStatus::Granted,
        created_at: TS,
        updated_at: TS,
        recorded_at_height: 1,
        supersedes: None,
        attachments: vec![],
    }
}

fn prescription_of(issuer: &Address, id: u8, fill_history: Vec<[u8; 32]>) -> Prescription {
    Prescription {
        prescription_id: [id; 32],
        prescription_type: PrescriptionType::StandardPrescription,
        prescription_commitment: [id.wrapping_add(1); 32],
        patient_ref: PartyRef::Commitment([id.wrapping_add(2); 32]),
        patient_address: Address::new([0x35; 20]),
        patient_nullifier: PATIENT_NULL,
        prescriber_ref: PartyRef::Commitment([id.wrapping_add(3); 32]),
        prescriber_provider_id: [0xD0; 32],
        pharmacy_ref: None,
        medication_commitment: [id.wrapping_add(4); 32],
        quantity_commitment: [id.wrapping_add(5); 32],
        days_supply_commitment: None,
        refills_authorized: 2,
        refills_remaining: 2,
        is_controlled: false,
        date_written: 900,
        effective_from: None,
        expiry: 9_000_000,
        issuer_address: *issuer,
        issuer_class: HealthcareIssuerClass::MedicalPractice,
        policy_id: [12u8; 32],
        revocation_ref: None,
        status: PrescriptionStatus::Active,
        created_at: 900,
        updated_at: 900,
        recorded_at_height: 1,
        supersedes: None,
        fill_history,
        attachments: vec![],
    }
}

fn healthcare_case(c: Case<'_>, op: HealthcareOperation, gates: HealthcareGates) -> bool {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let addr = actor.address();
    fund(&db, &actor, FUNDED);
    // `IssueMembership` and `IssuePrescription` both require the provider they
    // name, seeded through the store so that the index row under test is the
    // only thing that differs between the two runs -- and BEFORE the index row
    // is seeded, because `ProviderStore::put` appends to the network index
    // itself for every affiliation the profile declares.
    HealthcareStore::new(&db)
        .providers()
        .put(&provider_of(&addr, 0xD0, vec![]))
        .unwrap();
    db.put(c.index_cf, &c.key, &c.seeded).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before = StateManager::v_get_balance(&view, &addr).unwrap();
    let r = HealthcareExecutor::execute_with_gates(
        &mut view,
        &addr,
        &HealthcareTxData {
            operation: op,
            data: (c.make)(&addr),
            recipient: Address::ZERO,
        },
        &Address::new([9; 20]),
        FEE,
        1,
        TS,
        0,
        Hash::ZERO,
        gates,
    )
    .expect("neither side may make the block unexecutable");
    assert_outcome(&c, &view, &addr, before, (r.success, r.error))
}

macro_rules! healthcare_index_test {
    ($name:ident, $family:literal, $index_cf:expr, $key:expr, $primary_cf:expr,
     $primary_key:expr, $op:expr, $make:expr) => {
        #[test]
        fn $name() {
            let (over, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES + 1);
            let (at, _) = id_list_of_at_least(MAX_ACCUMULATING_ROW_BYTES - 64);
            let make = $make;
            let case = |seeded: &Vec<u8>| Case {
                family: $family,
                index_cf: $index_cf,
                key: $key,
                seeded: seeded.clone(),
                primary_cf: $primary_cf,
                primary_key: $primary_key,
                make: &make,
            };
            for gates in pair!(HealthcareGates) {
                assert_the_pair_disagrees(
                    $family,
                    gates.allocation_bound,
                    healthcare_case(case(&at), $op, gates),
                    healthcare_case(case(&over), $op, gates),
                );
            }
        }
    };
}

healthcare_index_test!(
    healthcare_provider_network_index_stops_growing_an_unbounded_accumulating_row,
    "healthcare provider network index",
    cf::HEALTHCARE_PROVIDER_NETWORK_INDEX,
    PLAN_A.to_vec(),
    cf::HEALTHCARE_PROVIDERS,
    vec![0xD5; 32],
    HealthcareOperation::RegisterProvider,
    |a: &Address| bincode::serialize(&provider_of(a, 0xD5, vec![PLAN_A])).unwrap()
);

healthcare_index_test!(
    healthcare_member_index_stops_growing_an_unbounded_accumulating_row,
    "healthcare member index",
    cf::HEALTHCARE_MEMBER_INDEX,
    MEMBER_NULL.to_vec(),
    cf::HEALTHCARE_MEMBERSHIPS,
    vec![0xD6; 32],
    HealthcareOperation::IssueMembership,
    |a: &Address| bincode::serialize(&membership_of(a, 0xD6, vec![])).unwrap()
);

healthcare_index_test!(
    healthcare_subject_consent_index_stops_growing_an_unbounded_accumulating_row,
    "healthcare subject consent index",
    cf::HEALTHCARE_SUBJECT_CONSENT_INDEX,
    SUBJECT_NULL.to_vec(),
    cf::HEALTHCARE_CONSENTS,
    vec![0xD7; 32],
    HealthcareOperation::GrantConsent,
    |a: &Address| bincode::serialize(&consent_of(a, 0xD7)).unwrap()
);

healthcare_index_test!(
    healthcare_patient_prescription_index_stops_growing_an_unbounded_accumulating_row,
    "healthcare patient prescription index",
    cf::HEALTHCARE_PATIENT_RX_INDEX,
    PATIENT_NULL.to_vec(),
    cf::HEALTHCARE_PRESCRIPTIONS,
    vec![0xD8; 32],
    HealthcareOperation::IssuePrescription,
    |a: &Address| bincode::serialize(&prescription_of(a, 0xD8, vec![])).unwrap()
);

healthcare_index_test!(
    healthcare_prescriber_prescription_index_stops_growing_an_unbounded_accumulating_row,
    "healthcare prescriber prescription index",
    cf::HEALTHCARE_PRESCRIBER_RX_INDEX,
    vec![0xD0; 32],
    cf::HEALTHCARE_PRESCRIPTIONS,
    vec![0xD9; 32],
    HealthcareOperation::IssuePrescription,
    |a: &Address| bincode::serialize(&prescription_of(a, 0xD9, vec![])).unwrap()
);

// ── AL-8's two IN-ROW cases ─────────────────────────────────────────────────
//
// These differ from every case above in what the oversized row IS. An index row
// is a `Vec` of ids under its own key; these two are the PRIMARY RECORD, with
// the accumulating list inside it. So the seed has to be a real, decodable
// `MembershipRecord` / `Prescription` -- a blob would make the ungated side an
// `Err`, not a receipt, and the pair would be comparing a refusal against a
// broken block instead of against today's behaviour.

/// Enough 32-byte dependents to put the ENCODED record past the bound.
fn dependents_past_the_bound() -> Vec<[u8; 32]> {
    ids_numbering(MAX_ACCUMULATING_ROW_BYTES / 32 + 64)
}

#[test]
fn healthcare_membership_row_is_refused_before_a_dependent_decodes_it() {
    for gates in pair!(HealthcareGates) {
        let open = gates.allocation_bound;
        for (label, deps) in [
            ("at the bound", ids_numbering(16)),
            ("past the bound", dependents_past_the_bound()),
        ] {
            let (_state, db, _dir, _executor) = setup_with_params(params());
            let actor = KeyPair::generate();
            let addr = actor.address();
            fund(&db, &actor, FUNDED);
            let store = HealthcareStore::new(&db);
            store
                .providers()
                .put(&provider_of(&addr, 0xD0, vec![]))
                .unwrap();
            let seeded = membership_of(&addr, 0xE6, deps);
            store.memberships().put(&seeded).unwrap();
            let seeded_len = db
                .get(cf::HEALTHCARE_MEMBERSHIPS, &[0xE6u8; 32])
                .unwrap()
                .unwrap()
                .len();
            let past = seeded_len > MAX_ACCUMULATING_ROW_BYTES;
            assert_eq!(
                past,
                label == "past the bound",
                "the fixture must land on the side it claims: {seeded_len} B"
            );

            #[derive(serde::Serialize)]
            struct Dependent {
                membership_id: [u8; 32],
                dependent_commitment: [u8; 32],
            }
            let payload = bincode::serialize(&Dependent {
                membership_id: [0xE6; 32],
                dependent_commitment: [0xEE; 32],
            })
            .unwrap();

            let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
            let mut view = ExecutionView::new(&mut overlay);
            let before = StateManager::v_get_balance(&view, &addr).unwrap();
            let r = HealthcareExecutor::execute_with_gates(
                &mut view,
                &addr,
                &HealthcareTxData {
                    operation: HealthcareOperation::AddDependent,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                FEE,
                1,
                TS,
                0,
                Hash::ZERO,
                gates,
            )
            .expect("neither side may make the block unexecutable");

            if past && open {
                assert!(
                    !r.success,
                    "membership row {label}: the gate must refuse it"
                );
                assert_eq!(
                    r.error.as_deref(),
                    Some(
                        format!(
                            "Healthcare membership row too large to modify: {seeded_len} \
                             bytes, limit {MAX_ACCUMULATING_ROW_BYTES}"
                        )
                        .as_str()
                    ),
                    "and name the row and the length, because the remedy is not retry"
                );
                assert_eq!(
                    view.get(cf::HEALTHCARE_MEMBERSHIPS, &[0xE6u8; 32])
                        .unwrap()
                        .map(|r| r.len()),
                    Some(seeded_len),
                    "the refused transaction leaves the record byte-for-byte as it found it"
                );
                assert_eq!(
                    StateManager::v_get_balance(&view, &addr).unwrap(),
                    before,
                    "and charges nothing"
                );
            } else {
                assert!(
                    r.success,
                    "membership row {label}, allocation_bound={open}: must be admitted \
                     -- below the gate this is today's behaviour, and at the gate a row \
                     inside the bound is untouched: {:?}",
                    r.error
                );
                assert!(
                    view.get(cf::HEALTHCARE_MEMBERSHIPS, &[0xE6u8; 32])
                        .unwrap()
                        .unwrap()
                        .len()
                        > seeded_len,
                    "and the whole record was rebuilt one dependent larger"
                );
            }
        }
    }
}

#[test]
fn healthcare_prescription_row_is_refused_before_a_fill_decodes_it() {
    for gates in pair!(HealthcareGates) {
        let open = gates.allocation_bound;
        for (label, fills) in [
            ("at the bound", ids_numbering(16)),
            ("past the bound", dependents_past_the_bound()),
        ] {
            let (_state, db, _dir, _executor) = setup_with_params(params());
            let actor = KeyPair::generate();
            let addr = actor.address();
            fund(&db, &actor, FUNDED);
            let store = HealthcareStore::new(&db);
            store
                .providers()
                .put(&provider_of(&addr, 0xD0, vec![]))
                .unwrap();
            store
                .prescriptions()
                .put(&prescription_of(&addr, 0xE7, fills))
                .unwrap();
            let seeded_len = db
                .get(cf::HEALTHCARE_PRESCRIPTIONS, &[0xE7u8; 32])
                .unwrap()
                .unwrap()
                .len();
            let past = seeded_len > MAX_ACCUMULATING_ROW_BYTES;
            assert_eq!(
                past,
                label == "past the bound",
                "the fixture must land on the side it claims: {seeded_len} B"
            );

            #[derive(serde::Serialize)]
            struct Fill {
                prescription_id: [u8; 32],
                fill_commitment: [u8; 32],
            }
            let payload = bincode::serialize(&Fill {
                prescription_id: [0xE7; 32],
                fill_commitment: [0xEF; 32],
            })
            .unwrap();

            let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
            let mut view = ExecutionView::new(&mut overlay);
            let before = StateManager::v_get_balance(&view, &addr).unwrap();
            let r = HealthcareExecutor::execute_with_gates(
                &mut view,
                &addr,
                &HealthcareTxData {
                    // The arm that rebuilds the record TWICE in one
                    // transaction, which is why AL-8 names it.
                    operation: HealthcareOperation::PartialFillPrescription,
                    data: payload,
                    recipient: Address::ZERO,
                },
                &Address::new([9; 20]),
                FEE,
                1,
                TS,
                0,
                Hash::ZERO,
                gates,
            )
            .expect("neither side may make the block unexecutable");

            if past && open {
                assert!(
                    !r.success,
                    "prescription row {label}: the gate must refuse it"
                );
                assert_eq!(
                    r.error.as_deref(),
                    Some(
                        format!(
                            "Healthcare prescription row too large to modify: {seeded_len} \
                             bytes, limit {MAX_ACCUMULATING_ROW_BYTES}"
                        )
                        .as_str()
                    ),
                    "and name the OTHER in-row case, so the two refusals cannot be confused"
                );
                assert_eq!(
                    view.get(cf::HEALTHCARE_PRESCRIPTIONS, &[0xE7u8; 32])
                        .unwrap()
                        .map(|r| r.len()),
                    Some(seeded_len),
                    "the refused transaction leaves the record byte-for-byte as it found it"
                );
                assert_eq!(
                    StateManager::v_get_balance(&view, &addr).unwrap(),
                    before,
                    "and charges nothing"
                );
            } else {
                assert!(
                    r.success,
                    "prescription row {label}, allocation_bound={open}: must be admitted: {:?}",
                    r.error
                );
                assert!(
                    view.get(cf::HEALTHCARE_PRESCRIPTIONS, &[0xE7u8; 32])
                        .unwrap()
                        .unwrap()
                        .len()
                        > seeded_len,
                    "and the whole record was rebuilt one fill larger"
                );
            }
        }
    }
}

// ── AL-12: the decode boundary, in the three subsystems that lacked it ───────

/// A payload past [`MAX_SUBSYSTEM_PAYLOAD_BYTES`] that still DECODES, so that
/// what the gate refuses is the size and not the shape.
///
/// A payload that failed to decode would make the ungated side an `Err` and the
/// whole block unexecutable, and the pair would then be comparing a refusal
/// against a broken block rather than against today's behaviour.
fn oversized_membership(issuer: &Address) -> Vec<u8> {
    let bytes = bincode::serialize(&membership_of(
        issuer,
        0xF5,
        ids_numbering(MAX_SUBSYSTEM_PAYLOAD_BYTES / 32 + 64),
    ))
    .unwrap();
    assert!(bytes.len() > MAX_SUBSYSTEM_PAYLOAD_BYTES);
    bytes
}

#[test]
fn a_membership_row_is_seeded_over_the_payload_bound_by_one_transaction() {
    // The AL-8 correction, demonstrated rather than asserted. The audit's Class
    // 4 preamble puts AL-8 on the fixed-32-bytes-per-transaction side of its
    // own separator. `IssueMembership` stores the deserialized `MembershipRecord`
    // VERBATIM, so ONE transaction decides how large the record every later
    // `AddDependent` decodes, rebuilds and re-encodes is -- which is AL-10's
    // shape, not AL-1's.
    for gates in pair!(HealthcareGates) {
        let open = gates.allocation_bound;
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        let addr = actor.address();
        fund(&db, &actor, FUNDED);
        HealthcareStore::new(&db)
            .providers()
            .put(&provider_of(&addr, 0xD0, vec![]))
            .unwrap();
        let payload = oversized_membership(&addr);
        let payload_len = payload.len();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let before = StateManager::v_get_balance(&view, &addr).unwrap();
        let r = HealthcareExecutor::execute_with_gates(
            &mut view,
            &addr,
            &HealthcareTxData {
                operation: HealthcareOperation::IssueMembership,
                data: payload,
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            FEE,
            1,
            TS,
            0,
            Hash::ZERO,
            gates,
        )
        .expect("neither side may make the block unexecutable");

        if open {
            assert!(!r.success, "the payload bound must refuse it");
            assert_eq!(
                r.error.as_deref(),
                Some(
                    format!(
                        "Healthcare payload too large: {payload_len} bytes, limit \
                         {MAX_SUBSYSTEM_PAYLOAD_BYTES}"
                    )
                    .as_str()
                ),
                "named as a payload, before the deserialize, not as a row"
            );
            assert!(
                view.get(cf::HEALTHCARE_MEMBERSHIPS, &[0xF5u8; 32])
                    .unwrap()
                    .is_none(),
                "and nothing is staged"
            );
            assert_eq!(
                StateManager::v_get_balance(&view, &addr).unwrap(),
                before,
                "and nothing is charged"
            );
        } else {
            assert!(
                r.success,
                "below the gate this is TODAY: one transaction commits a membership \
                 record of {payload_len} B for one fee: {:?}",
                r.error
            );
            let stored = view
                .get(cf::HEALTHCARE_MEMBERSHIPS, &[0xF5u8; 32])
                .unwrap()
                .expect("the record committed");
            assert!(
                stored.len() > MAX_SUBSYSTEM_PAYLOAD_BYTES,
                "and the row every later AddDependent must decode is {} B, chosen by \
                 the payload -- which is what puts AL-8's in-row half on AL-10's side \
                 of the class separator and not AL-1's",
                stored.len()
            );
        }
    }
}

#[test]
fn an_oversized_payload_is_refused_before_it_is_deserialized_in_all_three_subsystems() {
    // Legal already carried the KEY bound and Employment/Finance the ROW bound;
    // the three subsystems AL-12 names that carried NEITHER half of the decode
    // boundary are Agreement, Property and Healthcare. One case each.
    let filler = ids_numbering(MAX_SUBSYSTEM_PAYLOAD_BYTES / 32 + 64);

    // Agreement: `CommitAgreement`, padded through `parties`.
    for gates in pair!(AgreementGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, FUNDED);
        let agreement = AgreementCommitment {
            agreement_id: [0xF1; 32],
            agreement_commitment: [0xF2; 32],
            parties: filler
                .iter()
                .map(|c| PartyBinding {
                    party_ref: PartyRef::Commitment(*c),
                    role: AgreementRole::Buyer,
                    signed: false,
                    signed_at: None,
                })
                .collect(),
            jurisdiction_code: "US-DE".to_string(),
            effective_from: Some(TS),
            expiry: Some(9_000_000),
            attachments: vec![],
            policy_id: [12u8; 32],
            status: AgreementStatus::PendingSignatures,
            created_at: TS,
            updated_at: TS,
            created_at_height: 1,
            supersedes: None,
        };
        let payload = bincode::serialize(&agreement).unwrap();
        let payload_len = payload.len();
        assert!(payload_len > MAX_SUBSYSTEM_PAYLOAD_BYTES);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = AgreementExecutor::execute_with_gates(
            &mut view,
            &actor.address(),
            &AgreementTxData {
                operation: AgreementOperation::CommitAgreement,
                data: payload,
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            FEE,
            1,
            TS,
            0,
            Hash::ZERO,
            gates,
        )
        .expect("neither side may make the block unexecutable");
        assert_eq!(
            r.success, !gates.allocation_bound,
            "Agreement payload bound (allocation_bound={}): {:?}",
            gates.allocation_bound, r.error
        );
        if gates.allocation_bound {
            assert_eq!(
                r.error.as_deref(),
                Some(
                    format!(
                        "Agreement payload too large: {payload_len} bytes, limit \
                         {MAX_SUBSYSTEM_PAYLOAD_BYTES}"
                    )
                    .as_str()
                )
            );
        }
    }

    // Property: `AnchorAsset`, padded through `related_assets`.
    for gates in pair!(PropertyGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        let addr = actor.address();
        fund(&db, &actor, FUNDED);
        let mut asset = asset_of(&addr, 0xF3);
        asset.related_assets = filler.clone();
        let payload = bincode::serialize(&asset).unwrap();
        let payload_len = payload.len();
        assert!(payload_len > MAX_SUBSYSTEM_PAYLOAD_BYTES);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = PropertyExecutor::execute_with_gates(
            &mut view,
            &addr,
            &PropertyTxData {
                operation: PropertyOperation::AnchorAsset,
                data: payload,
                recipient: Address::ZERO,
            },
            &Address::new([9; 20]),
            FEE,
            1,
            TS,
            0,
            Hash::ZERO,
            gates,
        )
        .expect("neither side may make the block unexecutable");
        assert_eq!(
            r.success, !gates.allocation_bound,
            "Property payload bound (allocation_bound={}): {:?}",
            gates.allocation_bound, r.error
        );
        if gates.allocation_bound {
            assert_eq!(
                r.error.as_deref(),
                Some(
                    format!(
                        "Property payload too large: {payload_len} bytes, limit \
                         {MAX_SUBSYSTEM_PAYLOAD_BYTES}"
                    )
                    .as_str()
                )
            );
        }
    }

    // Healthcare is covered above, by the test that also demonstrates what the
    // unbounded payload SEEDS.
}

#[test]
fn a_lawful_payload_and_a_small_row_are_refused_by_nothing_in_any_of_the_three() {
    // The discriminator for the whole file: without it every assertion above is
    // also satisfied by a gate that refuses everything.
    let (small, small_len) = id_list_of_at_least(1_024);
    assert!(small_len < MAX_ACCUMULATING_ROW_BYTES);

    for gates in pair!(LegalGates) {
        let make = |a: &Address| bincode::serialize(&case_of(a, 0xC9)).unwrap();
        assert!(
            legal_case(
                Case {
                    family: "legal, lawful",
                    index_cf: cf::LEGAL_JURISDICTION_INDEX,
                    key: format!("{JURISDICTION}:case").into_bytes(),
                    seeded: small.clone(),
                    primary_cf: cf::LEGAL_CASES,
                    primary_key: vec![0xC9; 32],
                    make: &make,
                },
                LegalOperation::AnchorCase,
                gates,
            ),
            "a {small_len} B Legal index row is appended to on both sides \
             (allocation_bound={})",
            gates.allocation_bound
        );
    }

    for gates in pair!(PropertyGates) {
        let make = |a: &Address| bincode::serialize(&asset_of(a, 0xA9)).unwrap();
        assert!(
            property_case(
                Case {
                    family: "property, lawful",
                    index_cf: cf::PROPERTY_JURISDICTION_INDEX,
                    key: JURISDICTION.as_bytes().to_vec(),
                    seeded: small.clone(),
                    primary_cf: cf::PROPERTY_ASSETS,
                    primary_key: vec![0xA9; 32],
                    make: &make,
                },
                PropertyOperation::AnchorAsset,
                gates,
            ),
            "a {small_len} B Property index row is appended to on both sides \
             (allocation_bound={})",
            gates.allocation_bound
        );
    }

    for gates in pair!(HealthcareGates) {
        let make = |a: &Address| bincode::serialize(&membership_of(a, 0xD9, vec![])).unwrap();
        assert!(
            healthcare_case(
                Case {
                    family: "healthcare, lawful",
                    index_cf: cf::HEALTHCARE_MEMBER_INDEX,
                    key: MEMBER_NULL.to_vec(),
                    seeded: small.clone(),
                    primary_cf: cf::HEALTHCARE_MEMBERSHIPS,
                    primary_key: vec![0xD9; 32],
                    make: &make,
                },
                HealthcareOperation::IssueMembership,
                gates,
            ),
            "a {small_len} B Healthcare index row is appended to on both sides \
             (allocation_bound={})",
            gates.allocation_bound
        );
    }
}
