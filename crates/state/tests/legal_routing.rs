//! SRC-85X legal and benefits execute against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//! Legal is the status-transition subsystem: of its twenty-four operations,
//! sixteen are "read the row, check the issuer, write it back with a new
//! status". Every one of those reads was a COMMITTED read, correct only because
//! the matching writes committed as they went -- so a case anchored earlier in
//! the block was invisible to the transition that followed it, and two
//! transitions on one case in one block each recomputed from the parent's row.
//!
//! Two of the transitions have a PRECONDITION on the status they are replacing
//! (`UnsealCase` requires `Sealed`, `ReinstateBenefit` requires `Suspended`),
//! which is what makes a same-block chain of them a real discriminator rather
//! than a test that would pass either way. Both are driven here with their
//! controls.
//!
//! ## Defects this suite PINS rather than fixes
//!
//! * `ConsolidateCase` and `TransferCase` have NO authority check: any funded
//!   account can consolidate or transfer any case.
//! * `SupersedeOrder` and `SupersedeEvent` have no authority check AND no
//!   duplicate guard, so either can overwrite an existing row -- and
//!   `SupersedeEvent` does not verify that the new event's case exists, so it
//!   can create a case→event index entry under a case id that was never
//!   anchored.
//! * `VerifyProof` verifies nothing. It charges the fee, advances the nonce and
//!   returns success without reading a proof at all.
//! * Both dispatch arms pass `0` for `block_timestamp`, so every status
//!   transition stamps `updated_at = 0`.
//! * Nothing ever writes `cf::LEGAL_SYSTEM_EVENTS`, though `LegalEventStore`
//!   exists for it.
//!
//! All predate this commit and are reproduced exactly. They are pinned here so
//! that changing any of them is a deliberate act with a failing test attached,
//! not a silent correction inside a migration.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType, CourtOrder,
    LegalIssuerClass, LegalOperation, LegalProofEnvelope, LegalProofProfile, LegalProofType,
    LegalTxData, OrderStatus, OrderType, ProcessEvent, ProcessEventStatus, ProcessEventType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::{LegalExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, LegalStore};

/// Every family this unit moved. Eight.
///
/// `cf::LEGAL_SYSTEM_EVENTS` is the ninth legal family and is deliberately NOT
/// here: no executor operation writes it, before this commit or after.
const LEGAL_CFS: &[&str] = &[
    cf::LEGAL_CASES,
    cf::LEGAL_EVENTS,
    cf::LEGAL_ORDERS,
    cf::LEGAL_BENEFITS,
    cf::LEGAL_PROOFS,
    cf::LEGAL_CASE_EVENT_INDEX,
    cf::LEGAL_CASE_ORDER_INDEX,
    cf::LEGAL_JURISDICTION_INDEX,
];

/// The dispatch arm's own refusal code. Every negative control below pins this
/// exact value: accepting any non-success would let an invalid nonce, an
/// insufficient balance or a malformed payload stand in for the legal guard the
/// test is actually about.
const LEGAL_FAILED: TxStatus = TxStatus::Failed(12);

/// The bytes seeded wherever a test needs a row that cannot be decoded.
///
/// Named so that "is the corrupt row still exactly what we wrote" is a
/// comparison against one value rather than a repeated literal that could
/// drift between the seeding site and the assertion.
const CORRUPT: &[u8] = b"not a valid row";

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn legal_tx(kp: &KeyPair, nonce: u64, op: LegalOperation, data: Vec<u8>) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload: TxPayload::Legal(LegalTxData {
            operation: op,
            data,
            recipient: Address::ZERO,
        }),
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn signed(
    kp: &KeyPair,
    nonce: u64,
    op: LegalOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    legal_tx(kp, nonce, op, bincode::serialize(payload).unwrap())
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn case_of(issuer: &KeyPair, id: u8, jurisdiction: &str) -> CaseAnchor {
    CaseAnchor {
        case_id: [id; 32],
        case_commitment: [0xC1; 32],
        jurisdiction_code: jurisdiction.to_string(),
        case_type: Some(CaseType::Civil),
        public_reference: None,
        policy_id: [0xC2; 32],
        issuer_class: LegalIssuerClass::LawFirm,
        issuer_address: issuer.address(),
        status: CaseStatus::Filed,
        created_at: 1_000,
        updated_at: 1_000,
        anchored_at_height: 1,
        related_cases: vec![],
    }
}

fn event_of(issuer: &KeyPair, id: u8, case_id: u8) -> ProcessEvent {
    ProcessEvent {
        event_id: [id; 32],
        case_id: [case_id; 32],
        event_type: ProcessEventType::Filed,
        event_commitment: [0xE1; 32],
        issuer_address: issuer.address(),
        issuer_class: LegalIssuerClass::LawFirm,
        event_time_start: Some(1_000),
        event_time_end: None,
        attachments: vec![],
        policy_id: [0xE2; 32],
        revocation_ref: None,
        status: ProcessEventStatus::Recorded,
        created_at: 1_000,
        recorded_at_height: 1,
        supersedes: None,
    }
}

fn order_of(issuer: &KeyPair, id: u8, case_id: u8) -> CourtOrder {
    CourtOrder {
        order_id: [id; 32],
        case_id: [case_id; 32],
        order_type: OrderType::FinalJudgment,
        order_commitment: [0x01; 32],
        issuer_address: issuer.address(),
        issuer_class: LegalIssuerClass::CourtSystem,
        status: OrderStatus::Active,
        effective_from: 1_000,
        expiry: Some(9_000),
        policy_id: [0x02; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
        issued_at_height: 1,
        supersedes_order_id: None,
        attachments: vec![],
    }
}

fn benefit_of(
    issuer: &KeyPair,
    id: u8,
    jurisdiction: &str,
    status: BenefitStatus,
) -> BenefitDetermination {
    BenefitDetermination {
        benefit_id: [id; 32],
        benefit_type: BenefitType::Medicare,
        jurisdiction_code: jurisdiction.to_string(),
        status,
        determination_commitment: [0xB1; 32],
        subject_nullifier: [0xB2; 32],
        issuer_address: issuer.address(),
        issuer_class: LegalIssuerClass::GovernmentAgency,
        valid_from: 1_000,
        expiry: None,
        policy_id: [0xB3; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
        recorded_at_height: 1,
        supersedes: None,
    }
}

fn proof_of(id: u8) -> LegalProofEnvelope {
    LegalProofEnvelope {
        proof_id: [id; 32],
        profile: LegalProofProfile::BenefitApproved,
        profile_id: "legal.benefit_approved.v1".to_string(),
        policy_ids: vec![[0xF1; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4, 5, 6],
        proof_type: LegalProofType::Groth16,
        subject_nullifier: [0xF2; 32],
        generated_at: 1_000,
        expires_at: 9_000,
    }
}

// ── Payload shapes the executor deserializes ─────────────────────────────────

#[derive(serde::Serialize)]
struct CaseIdOnly {
    case_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct CaseStatusUpdate {
    case_id: [u8; 32],
    status: CaseStatus,
}

#[derive(serde::Serialize)]
struct Consolidate {
    case_id: [u8; 32],
    related_case_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct EventStatusUpdate {
    event_id: [u8; 32],
    status: ProcessEventStatus,
}

#[derive(serde::Serialize)]
struct EventIdOnly {
    event_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct SupersedeEvent {
    old_event_id: [u8; 32],
    new_event: ProcessEvent,
}

#[derive(serde::Serialize)]
struct OrderStatusUpdate {
    order_id: [u8; 32],
    status: OrderStatus,
}

#[derive(serde::Serialize)]
struct OrderIdOnly {
    order_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct SupersedeOrder {
    old_order_id: [u8; 32],
    new_order: CourtOrder,
}

#[derive(serde::Serialize)]
struct BenefitIdOnly {
    benefit_id: [u8; 32],
}

#[derive(serde::Serialize)]
struct BenefitStatusUpdate {
    benefit_id: [u8; 32],
    status: BenefitStatus,
}

// ── Canonical snapshots and per-family diffs ─────────────────────────────────

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in LEGAL_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// Not a presence check on the view: `prefix_iter` on an `ExecutionView` is
/// MERGED with committed state, so a family that already holds a committed row
/// reads as non-empty whether or not this block touched it. Several tests below
/// pre-seed canonical rows, and a presence check would report those families as
/// staged for every transaction, including the ones that staged nothing.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in LEGAL_CFS {
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

// ── Same-block visibility: cases ─────────────────────────────────────────────

/// A case update finds the anchor from earlier in the same block.
///
/// `UpdateCase` requires the case to exist AND its issuer to match. Both come
/// from one read, and against committed state that read answers from the parent
/// block -- so the update would be refused as "Case not found" for a case this
/// block had just anchored.
#[test]
fn a_case_update_finds_the_anchor_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                LegalOperation::UpdateCase,
                &CaseStatusUpdate {
                    case_id: [0x10; 32],
                    status: CaseStatus::Active,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r1.status, TxStatus::Success),
        "the update must find the case this block anchored: {:?}",
        r1.status
    );
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .status,
        CaseStatus::Active,
        "and the staged case must carry the new status"
    );
}

/// Without the anchor, the same update is refused.
#[test]
fn without_the_anchor_the_same_case_update_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::UpdateCase,
                &CaseStatusUpdate {
                    case_id: [0x10; 32],
                    status: CaseStatus::Active,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, LEGAL_FAILED,
        "an update against a case that does not exist must fail IN the legal \
         executor"
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "and change nothing at all"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0,
        "a refused legal operation does not advance the account nonce"
    );
}

/// Three transitions on one case in one block, the last of which has a
/// PRECONDITION on the second's result.
///
/// `UnsealCase` refuses unless the case is `Sealed`. Anchor → Seal → Unseal
/// therefore only works if the unseal reads the SEAL this block staged: against
/// committed state it would read `Filed` and refuse, and the seal itself would
/// have been refused for a case that did not exist yet.
#[test]
fn an_unseal_sees_the_seal_from_earlier_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let steps: Vec<(u64, LegalOperation, Vec<u8>)> = vec![
        (
            0,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::SealCase,
            bincode::serialize(&CaseIdOnly {
                case_id: [0x10; 32],
            })
            .unwrap(),
        ),
        (
            2,
            LegalOperation::UnsealCase,
            bincode::serialize(&CaseIdOnly {
                case_id: [0x10; 32],
            })
            .unwrap(),
        ),
    ];
    for (nonce, op, data) in steps {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} must succeed against the candidate: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .status,
        CaseStatus::Active,
        "the unseal must have found the block's own seal and moved it to Active"
    );
}

/// Without the seal, the same unseal is refused.
///
/// The discriminator: the test above would pass on any block in which unseals
/// happen to succeed regardless of the preceding status.
#[test]
fn without_the_seal_the_same_unseal_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                LegalOperation::UnsealCase,
                &CaseIdOnly {
                    case_id: [0x10; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, LEGAL_FAILED,
        "an unseal of a case that is not sealed must fail in the legal executor"
    );
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .status,
        CaseStatus::Filed,
        "and leave the anchored status alone"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one successful anchor, one refusal that charged no nonce"
    );
}

// ── Same-block visibility: benefits ──────────────────────────────────────────

/// `ReinstateBenefit` requires `Suspended`, so a determine → suspend →
/// reinstate chain in one block only works if each step reads the previous.
#[test]
fn a_reinstatement_sees_the_suspension_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let steps: Vec<(u64, LegalOperation, Vec<u8>)> = vec![
        (
            0,
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit_of(&issuer, 0x40, "US", BenefitStatus::Approved)).unwrap(),
        ),
        (
            1,
            LegalOperation::SuspendBenefit,
            bincode::serialize(&BenefitIdOnly {
                benefit_id: [0x40; 32],
            })
            .unwrap(),
        ),
        (
            2,
            LegalOperation::ReinstateBenefit,
            bincode::serialize(&BenefitIdOnly {
                benefit_id: [0x40; 32],
            })
            .unwrap(),
        ),
    ];
    for (nonce, op, data) in steps {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} must succeed against the candidate: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_benefit(&view, &[0x40; 32])
            .unwrap()
            .unwrap()
            .status,
        BenefitStatus::Approved,
        "suspended then reinstated, both seen inside the block"
    );
}

/// Without the suspension, the same reinstatement is refused.
#[test]
fn without_the_suspension_the_same_reinstatement_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::DetermineBenefit,
                &benefit_of(&issuer, 0x40, "US", BenefitStatus::Approved),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                LegalOperation::ReinstateBenefit,
                &BenefitIdOnly {
                    benefit_id: [0x40; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, LEGAL_FAILED,
        "reinstating a benefit that is not suspended must fail in the legal \
         executor"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one determination, one refusal that charged no nonce"
    );
}

// ── Same-block visibility: events and orders under a same-block case ─────────

/// `RecordEvent` and `IssueOrder` both verify the CASE exists before writing.
#[test]
fn an_event_and_an_order_find_the_case_anchored_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_case_event_ids(&view, &[0x10; 32]).unwrap(),
        vec![[0x20u8; 32]]
    );
    assert_eq!(
        LegalExecutor::v_get_case_order_ids(&view, &[0x10; 32]).unwrap(),
        vec![[0x30u8; 32]]
    );
}

/// Without the anchor, the same event is refused.
#[test]
fn without_the_anchor_the_same_event_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::RecordEvent,
                &event_of(&issuer, 0x20, 0x10),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r.status, LEGAL_FAILED,
        "an event on a case that does not exist must fail in the legal executor"
    );
    assert!(families_changed(&db, &view).is_empty(), "and stage nothing");
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

/// An order status update finds the order issued earlier in the same block.
#[test]
fn an_order_status_update_finds_the_issue_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::UpdateOrderStatus,
            bincode::serialize(&OrderStatusUpdate {
                order_id: [0x30; 32],
                status: OrderStatus::Satisfied,
            })
            .unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_order(&view, &[0x30; 32])
            .unwrap()
            .unwrap()
            .status,
        OrderStatus::Satisfied
    );
}

/// Without the issue, the same order status update is refused.
#[test]
fn without_the_issue_the_same_order_status_update_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::UpdateOrderStatus,
                &OrderStatusUpdate {
                    order_id: [0x30; 32],
                    status: OrderStatus::Satisfied,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(r.status, LEGAL_FAILED);
    assert!(families_changed(&db, &view).is_empty(), "and stage nothing");
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

/// An event status update finds the record from earlier in the same block.
#[test]
fn an_event_status_update_finds_the_record_from_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::UpdateEvent,
            bincode::serialize(&EventStatusUpdate {
                event_id: [0x20; 32],
                status: ProcessEventStatus::Corrected,
            })
            .unwrap(),
        ),
        (
            3,
            LegalOperation::RevokeEvent,
            bincode::serialize(&EventIdOnly {
                event_id: [0x20; 32],
            })
            .unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?}: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_process_event(&view, &[0x20; 32])
            .unwrap()
            .unwrap()
            .status,
        ProcessEventStatus::Revoked,
        "the revoke saw the correction, which saw the record"
    );
}

/// Every remaining status transition, chained in one block.
///
/// `StayOrder`, `VacateOrder` and `ModifyOrder` each rewrite the order they
/// read; `TerminateBenefit` and `UpdateBenefitStatus` do the same for benefits.
/// Run back to back they can only work if each reads the candidate: against
/// committed state the second would recompute from the parent row and drop the
/// first one's effect.
#[test]
fn the_remaining_order_and_benefit_transitions_chain_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let order_id = OrderIdOnly {
        order_id: [0x30; 32],
    };
    let benefit_id = BenefitIdOnly {
        benefit_id: [0x40; 32],
    };
    let steps: Vec<(u64, LegalOperation, Vec<u8>)> = vec![
        (
            0,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::StayOrder,
            bincode::serialize(&order_id).unwrap(),
        ),
        (
            3,
            LegalOperation::ModifyOrder,
            bincode::serialize(&order_id).unwrap(),
        ),
        (
            4,
            LegalOperation::VacateOrder,
            bincode::serialize(&order_id).unwrap(),
        ),
        (
            5,
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit_of(&issuer, 0x40, "US", BenefitStatus::Approved)).unwrap(),
        ),
        (
            6,
            LegalOperation::UpdateBenefitStatus,
            bincode::serialize(&BenefitStatusUpdate {
                benefit_id: [0x40; 32],
                status: BenefitStatus::UnderReview,
            })
            .unwrap(),
        ),
        (
            7,
            LegalOperation::TerminateBenefit,
            bincode::serialize(&benefit_id).unwrap(),
        ),
    ];
    for (nonce, op, data) in steps {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} must succeed against the candidate: {:?}",
            r.status
        );
    }

    assert_eq!(
        LegalExecutor::v_get_order(&view, &[0x30; 32])
            .unwrap()
            .unwrap()
            .status,
        OrderStatus::Vacated,
        "stayed, modified, then vacated -- each reading the previous"
    );
    assert_eq!(
        LegalExecutor::v_get_benefit(&view, &[0x40; 32])
            .unwrap()
            .unwrap()
            .status,
        BenefitStatus::Terminated,
        "reviewed then terminated"
    );
    // A transition rewrites the row; it does not add one.
    assert_eq!(
        view.prefix_iter(cf::LEGAL_ORDERS, &[]).unwrap().count(),
        1,
        "three transitions on one order leave one row"
    );
}

// ── Duplicate guards ─────────────────────────────────────────────────────────

/// Two anchors of one case id in one block: the second is refused by a guard
/// that reads the candidate.
#[test]
fn a_duplicate_case_anchor_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, expect) in [(0u64, true), (1u64, false)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    LegalOperation::AnchorCase,
                    &case_of(&issuer, 0x10, "US-NY"),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        if expect {
            assert!(
                matches!(r.status, TxStatus::Success),
                "the first anchor must succeed: {:?}",
                r.status
            );
        } else {
            assert_eq!(
                r.status, LEGAL_FAILED,
                "the duplicate must be refused BY THE LEGAL GUARD, not rejected \
                 earlier for some unrelated reason"
            );
        }
    }
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        1,
        "one successful anchor, one refusal"
    );

    let rows: Vec<_> = view
        .prefix_iter(cf::LEGAL_CASES, &[])
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(rows.len(), 1, "the duplicate must not leave a second row");
}

/// The same guard on proofs, which is `contains` rather than a decode.
#[test]
fn a_duplicate_proof_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let r0 = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, LegalOperation::SubmitProof, &proof_of(0x50)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r0.status, TxStatus::Success), "{:?}", r0.status);

    let r1 = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 1, LegalOperation::SubmitProof, &proof_of(0x50)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r1.status, LEGAL_FAILED,
        "the duplicate proof must be refused by the legal guard"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1
    );
}

/// The same guard on events, orders and benefits.
///
/// Each of the three reads its family with `contains` before writing. Against
/// committed state both halves of each pair would pass the guard and the second
/// would silently overwrite the first.
#[test]
fn a_duplicate_event_order_or_benefit_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // Seed the case both the event and the order hang off.
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let mut nonce = 1u64;
    for (op, data, label) in [
        (
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
            "event",
        ),
        (
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
            "order",
        ),
        (
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit_of(&issuer, 0x40, "US", BenefitStatus::Approved)).unwrap(),
            "benefit",
        ),
    ] {
        let first = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data.clone()),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(
            matches!(first.status, TxStatus::Success),
            "the first {label} must succeed: {:?}",
            first.status
        );
        nonce += 1;

        let second = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert_eq!(
            second.status, LEGAL_FAILED,
            "the duplicate {label} must be refused BY THE LEGAL GUARD, reading \
             what this block already staged"
        );
        assert_eq!(
            StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
            nonce,
            "and the refusal must charge no nonce for {label}"
        );
    }
}

/// A submitted proof is readable from the candidate.
///
/// `SubmitProof` is the one legal write whose row nothing in the executor reads
/// back -- the duplicate guard uses `contains`. `v_get_proof` is the candidate
/// reader for the family, and this drives it through real dispatch so that a
/// reader answering from the parent block shows up as a missing row rather than
/// as nothing at all.
#[test]
fn a_submitted_proof_is_readable_from_the_candidate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(
            &mut view,
            &signed(&actor, 0, LegalOperation::SubmitProof, &proof_of(0x50)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);

    let staged = LegalExecutor::v_get_proof(&view, &[0x50; 32])
        .unwrap()
        .expect("the proof this block submitted must be readable from the candidate");
    assert_eq!(staged.profile_id, "legal.benefit_approved.v1");
    assert!(
        db.get(cf::LEGAL_PROOFS, &[0x50u8; 32]).unwrap().is_none(),
        "and it must NOT be committed: the block was never published"
    );
}

/// A corrupt proof row makes the candidate reader ERROR, not report absence.
///
/// `v_get_proof` is the one legal decoder no dispatch path reaches -- the proof
/// guard is a `contains`. It is exercised directly here for exactly that reason:
/// a reader that swallowed the decode into `None` would otherwise be uncovered,
/// and a caller added later would silently treat corruption as a free id.
#[test]
fn a_corrupt_proof_row_makes_the_candidate_reader_error() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    db.put(cf::LEGAL_PROOFS, &[0x50u8; 32], b"not a valid row")
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let view = ExecutionView::new(&mut overlay);
    let err = LegalExecutor::v_get_proof(&view, &[0x50; 32])
        .expect_err("a corrupt proof row must ERROR, not be reported as absent");
    assert!(
        err.to_string().contains("Serialization") || err.to_string().contains("Storage"),
        "and the failure must name the decode: {err}"
    );
}

// ── The three accumulating index families, in one block ──────────────────────

/// Two events for one case in one block: the index holds BOTH ids.
///
/// The index value is an accumulating `Vec<ProcessEventId>`. Reading it from
/// committed state would give the second event an empty list, and it would
/// overwrite the first one's entry with a single-element one.
#[test]
fn two_events_for_one_case_accumulate_in_the_case_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x21, 0x10)).unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        LegalExecutor::v_get_case_event_ids(&view, &[0x10; 32]).unwrap(),
        vec![[0x20u8; 32], [0x21u8; 32]],
        "both event ids, in record order -- the second must have seen the first"
    );
}

/// The same, for orders, in their own family.
#[test]
fn two_orders_for_one_case_accumulate_in_the_case_order_index() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x31, 0x10)).unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        LegalExecutor::v_get_case_order_ids(&view, &[0x10; 32]).unwrap(),
        vec![[0x30u8; 32], [0x31u8; 32]]
    );
    assert!(
        LegalExecutor::v_get_case_event_ids(&view, &[0x10; 32])
            .unwrap()
            .is_empty(),
        "and orders do not leak into the event index, which has the same key \
         shape"
    );
}

/// Two cases and a benefit in one jurisdiction: cases accumulate under
/// `"{j}:case"`, the benefit lands under `"{j}:benefit"`, in the same family.
#[test]
fn the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x11, "US-NY")).unwrap(),
        ),
        (
            2,
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit_of(&issuer, 0x40, "US-NY", BenefitStatus::Approved))
                .unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    assert_eq!(
        LegalExecutor::v_get_jurisdiction_ids(&view, "US-NY", "case").unwrap(),
        vec![[0x10u8; 32], [0x11u8; 32]],
        "both cases, in anchor order -- the second must have seen the first"
    );
    assert_eq!(
        LegalExecutor::v_get_jurisdiction_ids(&view, "US-NY", "benefit").unwrap(),
        vec![[0x40u8; 32]],
        "and the benefit under its own suffix, not merged with the cases"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A block touching all eight families commits none of it.
#[test]
fn an_abandoned_block_leaves_all_eight_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let steps: Vec<(u64, LegalOperation, Vec<u8>)> = vec![
            (
                0,
                LegalOperation::AnchorCase,
                bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
            ),
            (
                1,
                LegalOperation::RecordEvent,
                bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
            ),
            (
                2,
                LegalOperation::IssueOrder,
                bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
            ),
            (
                3,
                LegalOperation::DetermineBenefit,
                bincode::serialize(&benefit_of(&issuer, 0x40, "US", BenefitStatus::Approved))
                    .unwrap(),
            ),
            (
                4,
                LegalOperation::SubmitProof,
                bincode::serialize(&proof_of(0x50)).unwrap(),
            ),
        ];
        for (nonce, op, data) in steps {
            let r = executor
                .execute_tx(
                    &mut view,
                    &legal_tx(&issuer, nonce, op, data),
                    &proposer,
                    1,
                    1000,
                )
                .unwrap();
            assert!(
                matches!(r.status, TxStatus::Success),
                "seeding {op:?} must succeed: {:?}",
                r.status
            );
        }

        // Per family, a real DIFF against committed state -- not a presence
        // check on the merged view.
        let touched = families_changed(&db, &view);
        for f in LEGAL_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so dropping the block proves nothing about it"
            );
        }
        // dropped
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every legal row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the case staged and its jurisdiction-index entry not.
///
/// The operation has to be `AnchorCase` for that to be reachable at all. Most
/// legal operations write ONE row and the fee and nonce writes come before it,
/// so a ceiling either refuses during the account writes -- nothing legal
/// staged -- or fits the whole transaction. `AnchorCase` writes two, the case
/// and its jurisdiction-index entry, so a ceiling can land between them.
///
/// The partial is asserted as EXACT state rather than "some family is
/// non-empty": the case readable through the view, the index row not, and the
/// canonical rows unchanged. Both families start canonically empty, so a row
/// readable through the merged view can only have come from the candidate --
/// which is what makes these two reads sound.
///
/// Every ceiling below the measured cost is tried, not a sample: the interval
/// between the two writes is a few hundred bytes wide and a stepped sweep can
/// step straight over it.
#[test]
fn a_refusal_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    assert!(
        db.prefix_iter(cf::LEGAL_CASES, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::LEGAL_JURISDICTION_INDEX, &[])
                .unwrap()
                .next()
                .is_none(),
        "cases and the jurisdiction index must start empty for this test to \
         read the candidate through the merged view"
    );

    let tx = signed(
        &issuer,
        0,
        LegalOperation::AnchorCase,
        &case_of(&issuer, 0x10, "US-NY"),
    );
    let index_key = b"US-NY:case";

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "an anchor must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let case_staged = view.get(cf::LEGAL_CASES, &[0x10u8; 32]).unwrap().is_some();
        let index_staged = view
            .get(cf::LEGAL_JURISDICTION_INDEX, index_key)
            .unwrap()
            .is_some();
        if case_staged && !index_staged {
            partials += 1;
        }
        assert!(
            !index_staged || case_staged,
            "ceiling {ceiling} staged the jurisdiction index without the case, \
             which no order of these two writes can produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must leave canonical storage as it was"
        );
    }

    assert!(
        partials > 0,
        "no ceiling refused with the case staged and its index entry not -- \
         either the two writes stopped being separate, or this sweep stopped \
         covering the interval between them"
    );
}

// ── Index parity ─────────────────────────────────────────────────────────────

/// Published rows satisfy every committed point lookup and scan the RPC uses.
#[test]
fn published_rows_satisfy_the_committed_scans() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            signed(
                &issuer,
                1,
                LegalOperation::RecordEvent,
                &event_of(&issuer, 0x20, 0x10),
            ),
            signed(
                &issuer,
                2,
                LegalOperation::IssueOrder,
                &order_of(&issuer, 0x30, 0x10),
            ),
            signed(
                &issuer,
                3,
                LegalOperation::DetermineBenefit,
                &benefit_of(&issuer, 0x40, "US-NY", BenefitStatus::Approved),
            ),
            signed(&issuer, 4, LegalOperation::SubmitProof, &proof_of(0x50)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all five must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let store = LegalStore::new(&db);

    // The three reads the RPC server actually makes (`legal_get_case`,
    // `legal_get_active_cases`, `legal_get_cases_by_jurisdiction`).
    assert_eq!(
        store.cases().get(&[0x10; 32]).unwrap().map(|c| c.case_id),
        Some([0x10u8; 32]),
        "the case point lookup"
    );
    assert_eq!(
        store.cases().list_active().unwrap().len(),
        1,
        "the active-case scan"
    );
    assert_eq!(
        store
            .cases()
            .get_by_jurisdiction("US-NY")
            .unwrap()
            .iter()
            .map(|c| c.case_id)
            .collect::<Vec<_>>(),
        vec![[0x10u8; 32]],
        "and the jurisdiction index, which the candidate wrote"
    );
    assert!(
        store.cases().exists(&[0x10; 32]).unwrap(),
        "the presence check the duplicate guard uses"
    );

    // Events: point lookup, and the case index the candidate wrote.
    assert_eq!(
        store
            .process_events()
            .get(&[0x20; 32])
            .unwrap()
            .map(|e| e.event_id),
        Some([0x20u8; 32])
    );
    assert_eq!(
        store
            .process_events()
            .get_by_case(&[0x10; 32])
            .unwrap()
            .iter()
            .map(|e| e.event_id)
            .collect::<Vec<_>>(),
        vec![[0x20u8; 32]]
    );
    assert_eq!(
        store
            .process_events()
            .get_active_by_case(&[0x10; 32])
            .unwrap()
            .len(),
        1
    );

    // Orders: point lookup, the case index, the effect filters.
    assert_eq!(
        store.orders().get(&[0x30; 32]).unwrap().map(|o| o.order_id),
        Some([0x30u8; 32])
    );
    assert_eq!(
        store
            .orders()
            .get_by_case(&[0x10; 32])
            .unwrap()
            .iter()
            .map(|o| o.order_id)
            .collect::<Vec<_>>(),
        vec![[0x30u8; 32]]
    );
    assert_eq!(
        store
            .orders()
            .get_active_by_case(&[0x10; 32], 5_000)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.orders().list_active(5_000).unwrap().len(), 1);
    assert_eq!(
        store
            .orders()
            .get_active_by_case(&[0x10; 32], 9_500)
            .unwrap()
            .len(),
        0,
        "and the expiry filter still applies to a published order"
    );

    // Benefits: point lookup, the subject scan, the jurisdiction index.
    assert_eq!(
        store
            .benefits()
            .get(&[0x40; 32])
            .unwrap()
            .map(|b| b.benefit_id),
        Some([0x40u8; 32])
    );
    assert_eq!(
        store.benefits().get_by_subject(&[0xB2; 32]).unwrap().len(),
        1
    );
    assert_eq!(
        store
            .benefits()
            .get_valid_for_subject(&[0xB2; 32], 5_000)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .benefits()
            .get_by_jurisdiction("US-NY")
            .unwrap()
            .iter()
            .map(|b| b.benefit_id)
            .collect::<Vec<_>>(),
        vec![[0x40u8; 32]],
        "the benefit half of the shared jurisdiction family"
    );
    assert_eq!(store.benefits().list_approved(5_000).unwrap().len(), 1);

    // Proofs: point lookup and both scans.
    assert_eq!(
        store.proofs().get(&[0x50; 32]).unwrap().map(|p| p.proof_id),
        Some([0x50u8; 32])
    );
    assert_eq!(
        store
            .proofs()
            .get_valid_for_subject(&[0xF2; 32], 5_000)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .proofs()
            .get_by_profile("legal.benefit_approved.v1")
            .unwrap()
            .len(),
        1
    );

    // The journal family stays empty: no operation writes it, and publishing a
    // block does not change that.
    assert_eq!(
        store.events().get_by_height_range(0, 10).unwrap().len(),
        0,
        "LEGAL_SYSTEM_EVENTS is written by nothing -- see the header"
    );
}

/// Published legal rows survive closing and reopening the database.
///
/// Every other parity assertion in this file reads back through the SAME
/// `Database` handle the block was published through. That proves the rows
/// reached the store; it does not prove they reached the disk, because a
/// handle can answer from its own memtables. This one drops every `Arc` on the
/// handle -- asserted, by strong count, to be the last one -- closes RocksDB,
/// reopens at the same path, and compares the bytes of all EIGHT families.
///
/// Both halves matter: the primary rows AND the index rows, because the index
/// rows are the ones the candidate built by read-modify-write and are the ones
/// a durability gap would most plausibly lose.
#[test]
fn published_legal_rows_survive_a_database_restart() {
    let (state, db, dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            signed(
                &issuer,
                1,
                LegalOperation::RecordEvent,
                &event_of(&issuer, 0x20, 0x10),
            ),
            signed(
                &issuer,
                2,
                LegalOperation::IssueOrder,
                &order_of(&issuer, 0x30, 0x10),
            ),
            signed(
                &issuer,
                3,
                LegalOperation::DetermineBenefit,
                &benefit_of(&issuer, 0x40, "US-NY", BenefitStatus::Approved),
            ),
            signed(&issuer, 4, LegalOperation::SubmitProof, &proof_of(0x50)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all five must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let before = canonical(&db);
    assert!(
        !before.is_empty(),
        "the fixture must have published something for the restart to be about"
    );

    // Close it for real. RocksDB holds a LOCK file, so a reopen that raced a
    // live handle would fail rather than quietly read the same instance -- and
    // the strong-count assertion makes the close explicit rather than hoped for.
    let path = dir.path().to_path_buf();
    drop(executor);
    drop(state);
    assert_eq!(
        std::sync::Arc::strong_count(&db),
        1,
        "the executor and the state manager must have released their handles, \
         or the reopen below is not a restart"
    );
    drop(db);

    let reopened = Database::open_default(&path).expect("reopen at the same path");

    assert_eq!(
        canonical(&reopened),
        before,
        "every legal row in all eight families must come back byte-identical"
    );

    // And spelled out per family, so a change that emptied `canonical` would
    // not turn this into a comparison of two empty vectors.
    let store = LegalStore::new(&reopened);
    assert_eq!(
        store.cases().get(&[0x10; 32]).unwrap().map(|c| c.case_id),
        Some([0x10u8; 32]),
        "LEGAL_CASES"
    );
    assert_eq!(
        store
            .process_events()
            .get(&[0x20; 32])
            .unwrap()
            .map(|e| e.event_id),
        Some([0x20u8; 32]),
        "LEGAL_EVENTS"
    );
    assert_eq!(
        store.orders().get(&[0x30; 32]).unwrap().map(|o| o.order_id),
        Some([0x30u8; 32]),
        "LEGAL_ORDERS"
    );
    assert_eq!(
        store
            .benefits()
            .get(&[0x40; 32])
            .unwrap()
            .map(|b| b.benefit_id),
        Some([0x40u8; 32]),
        "LEGAL_BENEFITS"
    );
    assert_eq!(
        store.proofs().get(&[0x50; 32]).unwrap().map(|p| p.proof_id),
        Some([0x50u8; 32]),
        "LEGAL_PROOFS"
    );

    // The three index families, by raw bytes: these are what the candidate
    // built by read-modify-write.
    assert_eq!(
        reopened
            .get(cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case")
            .unwrap(),
        Some(bincode::serialize(&vec![[0x10u8; 32]]).unwrap()),
        "LEGAL_JURISDICTION_INDEX, case half"
    );
    assert_eq!(
        reopened
            .get(cf::LEGAL_JURISDICTION_INDEX, b"US-NY:benefit")
            .unwrap(),
        Some(bincode::serialize(&vec![[0x40u8; 32]]).unwrap()),
        "LEGAL_JURISDICTION_INDEX, benefit half"
    );
    assert_eq!(
        reopened
            .get(cf::LEGAL_CASE_EVENT_INDEX, &[0x10u8; 32])
            .unwrap(),
        Some(bincode::serialize(&vec![[0x20u8; 32]]).unwrap()),
        "LEGAL_CASE_EVENT_INDEX"
    );
    assert_eq!(
        reopened
            .get(cf::LEGAL_CASE_ORDER_INDEX, &[0x10u8; 32])
            .unwrap(),
        Some(bincode::serialize(&vec![[0x30u8; 32]]).unwrap()),
        "LEGAL_CASE_ORDER_INDEX"
    );

    // And the scans that read through those indexes still answer.
    assert_eq!(
        store
            .cases()
            .get_by_jurisdiction("US-NY")
            .unwrap()
            .iter()
            .map(|c| c.case_id)
            .collect::<Vec<_>>(),
        vec![[0x10u8; 32]]
    );
    assert_eq!(
        store
            .process_events()
            .get_by_case(&[0x10; 32])
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.orders().get_by_case(&[0x10; 32]).unwrap().len(), 1);
    assert_eq!(
        store.benefits().get_by_jurisdiction("US-NY").unwrap().len(),
        1
    );
}

// ── The three accumulating indexes under load ────────────────────────────────
//
// Each of the three index families holds a bincode `Vec<[u8; 32]>` that the
// committed store has always decoded, linearly searched, appended to and
// reserialized on every write. Routing reproduces that exactly; it neither
// introduces the growth nor bounds it.
//
// SCOPE, precisely, and it applies to all three tests below: each measures ONE
// size. It shows that at ~20,000 ids (~640 KiB) the routed path returns a limit
// error after reaching the index replacement, leaves both the candidate-visible
// and the canonical index byte-identical, and -- given room -- preserves every
// existing id in order while appending exactly one. It does NOT show that
// arbitrarily large input can never reach an allocator abort: the replacement
// value is BUILT before the ceiling is charged, so no test here can. A bound
// would make transactions fail that succeed today, which is a consensus change
// and belongs to activation-gated hardening, not to a migration.
//
// The candidate holds both the pre-image and the staged replacement, so peak
// memory for one row is higher here than on the committed path. That is a
// property of the candidate model this lane adopted, not of legal.

/// 20,000 distinct ids, distinguishable by position.
fn many_ids(tag: u8) -> Vec<[u8; 32]> {
    (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[31] = tag;
            id
        })
        .collect()
}

/// Seed a 640 KiB index row and assert the fixture really is that size.
fn seed_large_index(db: &Database, family: &str, key: &[u8], ids: &[[u8; 32]]) -> Vec<u8> {
    let bytes = bincode::serialize(&ids.to_vec()).unwrap();
    assert!(
        bytes.len() > 600_000,
        "the fixture must actually be the size this test claims: {} bytes",
        bytes.len()
    );
    db.put(family, key, &bytes).unwrap();
    bytes
}

/// A 640 KiB JURISDICTION index is refused by the ceiling, then appended to.
///
/// See the scope note above this function's section.
#[test]
fn a_640_kib_jurisdiction_index_is_refused_by_the_ceiling_then_appended_to() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let existing = many_ids(0xA1);
    let seeded = seed_large_index(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case", &existing);
    let before = canonical(&db);

    let tx = signed(
        &issuer,
        0,
        LegalOperation::AnchorCase,
        &case_of(&issuer, 0xFE, "US-NY"),
    );

    // Under a ceiling far below the index's size the replacement is REFUSED --
    // an error, not an abort.
    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert!(
            view.get(cf::LEGAL_CASES, &[0xFEu8; 32]).unwrap().is_some(),
            "the case row must be staged, which is what puts the failure at the \
             jurisdiction-index write rather than before it"
        );
        assert_eq!(
            view.get(cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case")
                .unwrap(),
            Some(seeded.clone()),
            "the candidate must still see the seeded index, byte for byte"
        );
    }
    assert_eq!(
        db.get(cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case").unwrap(),
        Some(seeded.clone()),
        "and the canonical index is byte-identical too"
    );
    assert_eq!(canonical(&db), before, "and nothing is committed");

    // With room it succeeds and the list grows by exactly one, preserving every
    // existing id -- compared in full, not by sampling.
    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = LegalExecutor::v_get_jurisdiction_ids(&view, "US-NY", "case").unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xFEu8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

/// A 640 KiB CASE-EVENT index is refused by the ceiling, then appended to.
///
/// See the scope note above this function's section.
#[test]
fn a_640_kib_case_event_index_is_refused_by_the_ceiling_then_appended_to() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    // The case must be committed and decodable: `RecordEvent` reads it first.
    LegalStore::new(&db)
        .cases()
        .put(&case_of(&issuer, 0x10, "US-NY"))
        .unwrap();
    let existing = many_ids(0xE1);
    let seeded = seed_large_index(&db, cf::LEGAL_CASE_EVENT_INDEX, &[0x10u8; 32], &existing);
    let before = canonical(&db);

    let tx = signed(
        &issuer,
        0,
        LegalOperation::RecordEvent,
        &event_of(&issuer, 0xFE, 0x10),
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert!(
            view.get(cf::LEGAL_EVENTS, &[0xFEu8; 32]).unwrap().is_some(),
            "the event row must be staged, which is what puts the failure at the \
             case-event-index write rather than before it"
        );
        assert_eq!(
            view.get(cf::LEGAL_CASE_EVENT_INDEX, &[0x10u8; 32]).unwrap(),
            Some(seeded.clone()),
            "the candidate must still see the seeded index, byte for byte"
        );
    }
    assert_eq!(
        db.get(cf::LEGAL_CASE_EVENT_INDEX, &[0x10u8; 32]).unwrap(),
        Some(seeded.clone()),
        "and the canonical index is byte-identical too"
    );
    assert_eq!(canonical(&db), before, "and nothing is committed");

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = LegalExecutor::v_get_case_event_ids(&view, &[0x10; 32]).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xFEu8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

/// A 640 KiB CASE-ORDER index is refused by the ceiling, then appended to.
///
/// See the scope note above this function's section.
#[test]
fn a_640_kib_case_order_index_is_refused_by_the_ceiling_then_appended_to() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    LegalStore::new(&db)
        .cases()
        .put(&case_of(&issuer, 0x10, "US-NY"))
        .unwrap();
    let existing = many_ids(0x01);
    let seeded = seed_large_index(&db, cf::LEGAL_CASE_ORDER_INDEX, &[0x10u8; 32], &existing);
    let before = canonical(&db);

    let tx = signed(
        &issuer,
        0,
        LegalOperation::IssueOrder,
        &order_of(&issuer, 0xFE, 0x10),
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, 4_096);
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .expect_err("an index far larger than the ceiling must be refused");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        assert!(
            view.get(cf::LEGAL_ORDERS, &[0xFEu8; 32]).unwrap().is_some(),
            "the order row must be staged, which is what puts the failure at the \
             case-order-index write rather than before it"
        );
        assert_eq!(
            view.get(cf::LEGAL_CASE_ORDER_INDEX, &[0x10u8; 32]).unwrap(),
            Some(seeded.clone()),
            "the candidate must still see the seeded index, byte for byte"
        );
    }
    assert_eq!(
        db.get(cf::LEGAL_CASE_ORDER_INDEX, &[0x10u8; 32]).unwrap(),
        Some(seeded.clone()),
        "and the canonical index is byte-identical too"
    );
    assert_eq!(canonical(&db), before, "and nothing is committed");

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        let ids = LegalExecutor::v_get_case_order_ids(&view, &[0x10; 32]).unwrap();
        assert_eq!(ids.len(), 20_001, "appended, not replaced");
        assert_eq!(
            &ids[..20_000],
            &existing[..],
            "every existing id preserved, in order"
        );
        assert_eq!(ids[20_000], [0xFEu8; 32], "and the new one last");
    }
    assert_eq!(canonical(&db), before, "still nothing committed");
}

// ── Malformed committed rows ─────────────────────────────────────────────────

/// A malformed PRIMARY row makes the routed transaction ERROR and stage
/// nothing; it is never read as absence.
///
/// This is the difference between "no case anchored" and "the case row is
/// corrupt", and the guards branch on exactly that. A candidate reader that
/// swallowed a decode failure into `None` would turn corruption into a
/// duplicate-anchor opportunity, or into an order issued against a case whose
/// issuer could not be read. The `v_get_*` readers propagate, and these prove
/// it through real dispatch rather than by calling the accessor.
///
/// Each transaction here decodes its family BEFORE any write, so the correct
/// staged set is EMPTY -- asserted as such rather than as an allowed list. The
/// index families fail after a write and are covered separately below.
#[test]
fn malformed_primary_rows_error_through_dispatch_and_stage_nothing() {
    for (family, key, op, data_for, label) in [
        (
            cf::LEGAL_CASES,
            vec![0x10u8; 32],
            LegalOperation::UpdateCase,
            "case",
            "case",
        ),
        (
            cf::LEGAL_EVENTS,
            vec![0x20u8; 32],
            LegalOperation::UpdateEvent,
            "event",
            "process event",
        ),
        (
            cf::LEGAL_ORDERS,
            vec![0x30u8; 32],
            LegalOperation::UpdateOrderStatus,
            "order",
            "order",
        ),
        (
            cf::LEGAL_BENEFITS,
            vec![0x40u8; 32],
            LegalOperation::UpdateBenefitStatus,
            "benefit",
            "benefit",
        ),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 1_000_000_000);
        let proposer = Address::new([9; 20]);

        let data: Vec<u8> = match data_for {
            "case" => bincode::serialize(&CaseStatusUpdate {
                case_id: [0x10; 32],
                status: CaseStatus::Active,
            })
            .unwrap(),
            "event" => bincode::serialize(&EventStatusUpdate {
                event_id: [0x20; 32],
                status: ProcessEventStatus::Corrected,
            })
            .unwrap(),
            "order" => bincode::serialize(&OrderStatusUpdate {
                order_id: [0x30; 32],
                status: OrderStatus::Satisfied,
            })
            .unwrap(),
            _ => bincode::serialize(&BenefitStatusUpdate {
                benefit_id: [0x40; 32],
                status: BenefitStatus::Terminated,
            })
            .unwrap(),
        };

        db.put(family, &key, CORRUPT).unwrap();
        let before = canonical(&db);

        let tx = legal_tx(&actor, 0, op, data);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let err = executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .err()
                .unwrap_or_else(|| {
                    panic!("a malformed {label} row must ERROR, not be read as absence")
                });
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {label} failure must name the decode, not something else: {text}"
            );
            assert!(
                families_changed(&db, &view).is_empty(),
                "the {label} decode happens before any write, so nothing may be \
                 staged"
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {label}"
        );
    }
}

/// A malformed INDEX row fails AFTER its primary row has been staged, and
/// leaves the malformed row itself untouched.
///
/// All four index appends are read-modify-write on a bincode `Vec<[u8; 32]>`,
/// and every one of them runs after the entity row is written. Three separate
/// facts are asserted, because any one of them alone can hold for the wrong
/// reason:
///
///   1. the PRIMARY row is staged -- so the failure is really at the index
///      write and not somewhere earlier. A transaction that failed before
///      reaching the index would stage nothing and would satisfy a
///      "canonical is unchanged" assertion perfectly well.
///   2. the malformed index row the candidate can see is still BYTE-IDENTICAL
///      to what was seeded -- the refused read-modify-write left no partial
///      replacement behind.
///   3. canonical storage is unchanged.
#[test]
fn a_malformed_index_row_fails_after_its_primary_row_is_staged() {
    for (index_family, index_key, primary_family, primary_key, op, data_for, label) in [
        (
            cf::LEGAL_JURISDICTION_INDEX,
            b"US-NY:case".to_vec(),
            cf::LEGAL_CASES,
            vec![0x10u8; 32],
            LegalOperation::AnchorCase,
            "case",
            "jurisdiction index (cases)",
        ),
        (
            cf::LEGAL_JURISDICTION_INDEX,
            b"US-NY:benefit".to_vec(),
            cf::LEGAL_BENEFITS,
            vec![0x40u8; 32],
            LegalOperation::DetermineBenefit,
            "benefit",
            "jurisdiction index (benefits)",
        ),
        (
            cf::LEGAL_CASE_EVENT_INDEX,
            vec![0x10u8; 32],
            cf::LEGAL_EVENTS,
            vec![0x20u8; 32],
            LegalOperation::RecordEvent,
            "event",
            "case event index",
        ),
        (
            cf::LEGAL_CASE_ORDER_INDEX,
            vec![0x10u8; 32],
            cf::LEGAL_ORDERS,
            vec![0x30u8; 32],
            LegalOperation::IssueOrder,
            "order",
            "case order index",
        ),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 1_000_000_000);
        let proposer = Address::new([9; 20]);
        let store = LegalStore::new(&db);

        // Events and orders verify their case first, so it has to be there and
        // has to decode.
        let data: Vec<u8> = match data_for {
            "case" => bincode::serialize(&case_of(&actor, 0x10, "US-NY")).unwrap(),
            "benefit" => {
                bincode::serialize(&benefit_of(&actor, 0x40, "US-NY", BenefitStatus::Approved))
                    .unwrap()
            }
            "event" => {
                store.cases().put(&case_of(&actor, 0x10, "US-NY")).unwrap();
                bincode::serialize(&event_of(&actor, 0x20, 0x10)).unwrap()
            }
            _ => {
                store.cases().put(&case_of(&actor, 0x10, "US-NY")).unwrap();
                bincode::serialize(&order_of(&actor, 0x30, 0x10)).unwrap()
            }
        };

        // Seeding the case above writes the "US-NY:case" jurisdiction row, so
        // the corrupt row goes down AFTER that and wins.
        db.put(index_family, &index_key, CORRUPT).unwrap();
        let before = canonical(&db);

        let tx = legal_tx(&actor, 0, op, data);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let err = executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .err()
                .unwrap_or_else(|| panic!("a malformed {label} row must ERROR"));
            assert!(
                err.to_string().contains("Serialization") || err.to_string().contains("Storage"),
                "the {label} failure must name the decode: {err}"
            );

            // 1. The primary row IS staged: execution reached the index write.
            assert!(
                view.get(primary_family, &primary_key).unwrap().is_some(),
                "{label}: the primary row in {primary_family} must be staged \
                 before the index append runs -- without this the test would \
                 pass for a transaction that failed earlier and staged nothing"
            );

            // 2. The malformed index row is untouched, byte for byte.
            assert_eq!(
                view.get(index_family, &index_key).unwrap().as_deref(),
                Some(CORRUPT),
                "{label}: the refused read-modify-write must leave the seeded \
                 bytes exactly as they were"
            );

            // 3. Nothing else in this subsystem was staged.
            let mut changed = families_changed(&db, &view);
            changed.retain(|f| *f != primary_family);
            assert!(
                changed.is_empty(),
                "{label}: only the primary family may be staged, found {changed:?}"
            );
        }

        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {label}"
        );
        assert_eq!(
            db.get(index_family, &index_key).unwrap().as_deref(),
            Some(CORRUPT),
            "{label}: the committed malformed row is untouched too"
        );
    }
}

/// The families whose duplicate guard is `contains` read corruption as
/// PRESENCE, and refuse.
///
/// `AnchorCase`, `RecordEvent`, `IssueOrder`, `DetermineBenefit` and
/// `SubmitProof` all call `exists`, which never decodes. A corrupt row
/// therefore refuses the transaction as a duplicate rather than erroring --
/// and, crucially, never as ABSENCE, which would let a corrupt row be silently
/// overwritten by a transaction that believed the id was free. That is the
/// committed twin's behaviour, reproduced rather than upgraded: upgrading it
/// would turn today's refusals into block-level errors for rows that exist on
/// chains today.
///
/// All five families are exercised, not just the two whose guard is the first
/// thing the operation does: for events and orders the corrupt row is reached
/// only after the case decodes cleanly, which is itself part of the ordering
/// being pinned.
#[test]
fn a_presence_guard_reads_a_corrupt_row_as_present_not_absent() {
    for (family, key, op, data_for, label) in [
        (
            cf::LEGAL_CASES,
            vec![0x10u8; 32],
            LegalOperation::AnchorCase,
            "case",
            "case",
        ),
        (
            cf::LEGAL_PROOFS,
            vec![0x50u8; 32],
            LegalOperation::SubmitProof,
            "proof",
            "proof",
        ),
        (
            cf::LEGAL_EVENTS,
            vec![0x20u8; 32],
            LegalOperation::RecordEvent,
            "event",
            "process event",
        ),
        (
            cf::LEGAL_ORDERS,
            vec![0x30u8; 32],
            LegalOperation::IssueOrder,
            "order",
            "order",
        ),
        (
            cf::LEGAL_BENEFITS,
            vec![0x40u8; 32],
            LegalOperation::DetermineBenefit,
            "benefit",
            "benefit",
        ),
    ] {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 1_000_000_000);
        let proposer = Address::new([9; 20]);
        let store = LegalStore::new(&db);

        let payload: Vec<u8> = match data_for {
            "case" => bincode::serialize(&case_of(&actor, 0x10, "US-NY")).unwrap(),
            "proof" => bincode::serialize(&proof_of(0x50)).unwrap(),
            "benefit" => {
                bincode::serialize(&benefit_of(&actor, 0x40, "US", BenefitStatus::Approved))
                    .unwrap()
            }
            "event" => {
                store.cases().put(&case_of(&actor, 0x10, "US-NY")).unwrap();
                bincode::serialize(&event_of(&actor, 0x20, 0x10)).unwrap()
            }
            _ => {
                store.cases().put(&case_of(&actor, 0x10, "US-NY")).unwrap();
                bincode::serialize(&order_of(&actor, 0x30, 0x10)).unwrap()
            }
        };

        db.put(family, &key, CORRUPT).unwrap();
        let before = canonical(&db);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let r = executor
                .execute_tx(
                    &mut view,
                    &legal_tx(&actor, 0, op, payload),
                    &proposer,
                    1,
                    1000,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "a corrupt {label} row must REFUSE, not error: the guard \
                         is a bare `contains` that never decodes: {e}"
                    )
                });
            assert_eq!(
                r.status, LEGAL_FAILED,
                "a corrupt {label} row must REFUSE as a duplicate, never be \
                 read as absence and overwritten"
            );
            assert!(
                families_changed(&db, &view).is_empty(),
                "and stage nothing for {label}"
            );
            assert_eq!(
                StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
                0,
                "with the nonce unchanged for {label}"
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {label}"
        );
        assert_eq!(
            db.get(family, &key).unwrap().as_deref(),
            Some(CORRUPT),
            "{label}: the corrupt row is left exactly as it was, not overwritten"
        );
    }
}

// ── The second dispatch surface ──────────────────────────────────────────────

/// `execute_tx_v2` routes legal through the candidate too.
///
/// Two public transaction surfaces exist. `execute_tx` (wrapping
/// `execute_tx_with_validators`) is the live one every test above drives;
/// `execute_tx_v2` is `pub` with no production caller and has its own legal arm
/// at `executor.rs`. A migration that moved only the live arm would leave the
/// other writing committed rows.
#[test]
fn the_v2_dispatch_surface_also_stages_legal() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Legal(LegalTxData {
            operation: LegalOperation::AnchorCase,
            data: bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let r = executor
            .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "the v2 surface must execute a case anchor: {:?}",
            r.status
        );
        assert_eq!(
            families_changed(&db, &view),
            vec![cf::LEGAL_CASES, cf::LEGAL_JURISDICTION_INDEX],
            "and stage exactly the case and its jurisdiction-index entry"
        );
        assert_eq!(
            LegalExecutor::v_get_case(&view, &[0x10; 32])
                .unwrap()
                .map(|c| c.case_id),
            Some([0x10u8; 32]),
            "with the case readable from the candidate"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "and canonical storage still empty of legal rows"
    );
}

/// The v2 surface's refusal carries the same legal failure code, and stages
/// nothing.
#[test]
fn the_v2_dispatch_surface_refuses_with_the_legal_code() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 100_000_000);
    let proposer = Address::new([9; 20]);

    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: issuer.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Legal(LegalTxData {
            operation: LegalOperation::UpdateCase,
            data: bincode::serialize(&CaseStatusUpdate {
                case_id: [0x10; 32],
                status: CaseStatus::Active,
            })
            .unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = *sign(tx.signing_hash().as_bytes(), issuer.private_key()).as_bytes();
    let key = *issuer.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx_v2(&mut view, &tx, &sig, &key, &proposer, 1, 1000)
        .unwrap();
    assert_eq!(r.status, LEGAL_FAILED);
    assert!(families_changed(&db, &view).is_empty());
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        0
    );
}

// ── Deferred defects, pinned in both directions ──────────────────────────────

/// `ConsolidateCase` has NO authority check.
///
/// PRE-EXISTING. Every other case operation verifies `case.issuer_address ==
/// sender`; consolidation checks only that both cases exist. Any funded account
/// can therefore attach one stranger's case to another's and move the second to
/// `Consolidated`. Pinned in both directions -- the stranger succeeds AND the
/// issuer succeeds -- so that adding the check is a deliberate change with a
/// failing test attached rather than a silent correction inside a migration.
#[test]
fn consolidate_case_has_no_authority_check() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    fund(&db, &stranger, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, id) in [(0u64, 0x10u8), (1, 0x11)] {
        let r = executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    LegalOperation::AnchorCase,
                    &case_of(&issuer, id, "US-NY"),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // The STRANGER consolidates two cases that are not theirs, and succeeds.
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                LegalOperation::ConsolidateCase,
                &Consolidate {
                    case_id: [0x10; 32],
                    related_case_id: [0x11; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "consolidation by a stranger SUCCEEDS today -- a missing authority \
         check, pinned not fixed: {:?}",
        r.status
    );
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .related_cases,
        vec![[0x11u8; 32]],
        "the relation was written"
    );
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x11; 32])
            .unwrap()
            .unwrap()
            .status,
        CaseStatus::Consolidated,
        "and the related case was moved"
    );

    // The other direction: the real issuer can do it too, so the test above is
    // not passing because consolidation is simply broken for everyone.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                2,
                LegalOperation::ConsolidateCase,
                &Consolidate {
                    case_id: [0x11; 32],
                    related_case_id: [0x10; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r2.status, TxStatus::Success), "{:?}", r2.status);
}

/// `TransferCase` has NO authority check either.
#[test]
fn transfer_case_has_no_authority_check() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    fund(&db, &stranger, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();

    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                LegalOperation::TransferCase,
                &CaseIdOnly {
                    case_id: [0x10; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "transfer by a stranger SUCCEEDS today -- pinned, not fixed: {:?}",
        r.status
    );
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .status,
        CaseStatus::Transferred
    );

    // The other direction: `CloseCase`, which DOES check, refuses the stranger.
    // Without this the test above could pass simply because every case
    // operation ignores the sender.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                1,
                LegalOperation::CloseCase,
                &CaseIdOnly {
                    case_id: [0x10; 32],
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r2.status, LEGAL_FAILED,
        "CloseCase does check the issuer, so the transfer above really is the \
         odd one out"
    );
}

/// `SupersedeOrder` has no authority check AND no duplicate guard: it can
/// overwrite an order that already exists.
#[test]
fn supersede_order_overwrites_an_existing_order_without_a_guard() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    let stranger = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    fund(&db, &stranger, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x30, 0x10)).unwrap(),
        ),
        (
            2,
            LegalOperation::IssueOrder,
            bincode::serialize(&order_of(&issuer, 0x31, 0x10)).unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // A STRANGER supersedes order 0x30 with a payload whose "new" order reuses
    // the id of the EXISTING order 0x31, with a different type. No authority
    // check refuses them, and no duplicate guard refuses the reuse.
    let mut replacement = order_of(&stranger, 0x31, 0x10);
    replacement.order_type = OrderType::Tro;
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &stranger,
                0,
                LegalOperation::SupersedeOrder,
                &SupersedeOrder {
                    old_order_id: [0x30; 32],
                    new_order: replacement,
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "supersession by a stranger over an existing order id SUCCEEDS today \
         -- two missing guards, pinned not fixed: {:?}",
        r.status
    );
    assert_eq!(
        LegalExecutor::v_get_order(&view, &[0x30; 32])
            .unwrap()
            .unwrap()
            .status,
        OrderStatus::Superseded
    );
    assert_eq!(
        LegalExecutor::v_get_order(&view, &[0x31; 32])
            .unwrap()
            .unwrap()
            .order_type,
        OrderType::Tro,
        "and the existing order 0x31 was OVERWRITTEN by the replacement"
    );

    // The other direction: `IssueOrder` DOES have a duplicate guard, so the
    // overwrite above is specific to supersession.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                3,
                LegalOperation::IssueOrder,
                &order_of(&issuer, 0x31, 0x10),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r2.status, LEGAL_FAILED,
        "IssueOrder refuses a duplicate id, which SupersedeOrder does not"
    );
}

/// `SupersedeEvent` indexes the new event under a case that need not exist.
///
/// PRE-EXISTING. `RecordEvent` verifies the case first; supersession does not,
/// so the case→event index gains an entry keyed by a case id that was never
/// anchored. Pinned in both directions.
#[test]
fn supersede_event_indexes_under_a_case_that_need_not_exist() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, op, data) in [
        (
            0u64,
            LegalOperation::AnchorCase,
            bincode::serialize(&case_of(&issuer, 0x10, "US-NY")).unwrap(),
        ),
        (
            1,
            LegalOperation::RecordEvent,
            bincode::serialize(&event_of(&issuer, 0x20, 0x10)).unwrap(),
        ),
    ] {
        let r = executor
            .execute_tx(
                &mut view,
                &legal_tx(&issuer, nonce, op, data),
                &proposer,
                1,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    }

    // The replacement points at case 0xAA, which nothing ever anchored.
    let r = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                2,
                LegalOperation::SupersedeEvent,
                &SupersedeEvent {
                    old_event_id: [0x20; 32],
                    new_event: event_of(&issuer, 0x21, 0xAA),
                },
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "supersession onto a nonexistent case SUCCEEDS today: {:?}",
        r.status
    );
    assert!(
        LegalExecutor::v_get_case(&view, &[0xAA; 32])
            .unwrap()
            .is_none(),
        "case 0xAA does not exist"
    );
    assert_eq!(
        LegalExecutor::v_get_case_event_ids(&view, &[0xAA; 32]).unwrap(),
        vec![[0x21u8; 32]],
        "and yet the case→event index now points at it -- a dangling index \
         entry, pinned not fixed"
    );

    // The other direction: `RecordEvent` against the same nonexistent case is
    // refused, so the gap really is specific to supersession.
    let r2 = executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                3,
                LegalOperation::RecordEvent,
                &event_of(&issuer, 0x22, 0xAA),
            ),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert_eq!(
        r2.status, LEGAL_FAILED,
        "RecordEvent does verify the case, which SupersedeEvent does not"
    );
}

/// `VerifyProof` verifies nothing.
///
/// PRE-EXISTING. It takes the fee, advances the nonce, reads no proof and
/// returns success -- for a proof id that was never submitted, and indeed for a
/// payload that is not a proof id at all. Pinned in both directions: it succeeds
/// with no proof present, and it succeeds with one present, which is the same
/// answer either way.
#[test]
fn verify_proof_verifies_nothing_and_still_charges_the_fee() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let before_balance = StateManager::v_get_balance(&view, &actor.address()).unwrap();

    // Nothing submitted, and the payload is junk rather than a proof id.
    let r = executor
        .execute_tx(
            &mut view,
            &legal_tx(&actor, 0, LegalOperation::VerifyProof, b"junk".to_vec()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "verification of nothing SUCCEEDS today -- pinned, not fixed: {:?}",
        r.status
    );
    assert!(
        families_changed(&db, &view).is_empty(),
        "it writes no legal row"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "but it does advance the nonce"
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        before_balance - 100,
        "and it does charge the fee"
    );

    // With a real proof present the answer is identical, which is the point:
    // the operation never reads one.
    executor
        .execute_tx(
            &mut view,
            &signed(&actor, 1, LegalOperation::SubmitProof, &proof_of(0x50)),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    let r2 = executor
        .execute_tx(
            &mut view,
            &legal_tx(&actor, 2, LegalOperation::VerifyProof, b"junk".to_vec()),
            &proposer,
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(r2.status, TxStatus::Success), "{:?}", r2.status);
}

/// Every status transition stamps `updated_at = 0`.
///
/// PRE-EXISTING. Both dispatch arms pass a literal `0` where the executor
/// expects `block_timestamp`, so `v_update_case_status` writes a zero into a
/// field the anchor had filled. Pinned in both directions: the anchored row
/// keeps the payload's timestamp, the transition replaces it with zero.
#[test]
fn a_status_transition_stamps_a_zero_timestamp() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                0,
                LegalOperation::AnchorCase,
                &case_of(&issuer, 0x10, "US-NY"),
            ),
            &proposer,
            1,
            7_777,
        )
        .unwrap();
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .updated_at,
        1_000,
        "the anchor stores the payload's own timestamp"
    );

    executor
        .execute_tx(
            &mut view,
            &signed(
                &issuer,
                1,
                LegalOperation::CloseCase,
                &CaseIdOnly {
                    case_id: [0x10; 32],
                },
            ),
            &proposer,
            1,
            7_777,
        )
        .unwrap();
    assert_eq!(
        LegalExecutor::v_get_case(&view, &[0x10; 32])
            .unwrap()
            .unwrap()
            .updated_at,
        0,
        "and the transition overwrites it with ZERO, not with the block \
         timestamp 7777 -- the dispatch arms pass a placeholder. Pinned, not \
         fixed: changing it changes what every transition writes."
    );
}

/// A repeated consolidation is a paid no-op.
///
/// PRE-EXISTING. `v_add_related_case` skips the write when the relation is
/// already recorded, so the second consolidation leaves the case row exactly as
/// it was -- including `updated_at` -- while still charging the fee and the
/// nonce.
#[test]
fn a_repeated_consolidation_is_a_paid_no_op() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    for (nonce, id) in [(0u64, 0x10u8), (1, 0x11)] {
        executor
            .execute_tx(
                &mut view,
                &signed(
                    &issuer,
                    nonce,
                    LegalOperation::AnchorCase,
                    &case_of(&issuer, id, "US-NY"),
                ),
                &proposer,
                1,
                1000,
            )
            .unwrap();
    }

    let consolidate = |nonce: u64| {
        signed(
            &issuer,
            nonce,
            LegalOperation::ConsolidateCase,
            &Consolidate {
                case_id: [0x10; 32],
                related_case_id: [0x11; 32],
            },
        )
    };

    executor
        .execute_tx(&mut view, &consolidate(2), &proposer, 1, 1000)
        .unwrap();
    let after_first = LegalExecutor::v_get_case(&view, &[0x10; 32])
        .unwrap()
        .unwrap();

    let r = executor
        .execute_tx(&mut view, &consolidate(3), &proposer, 1, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
    let after_second = LegalExecutor::v_get_case(&view, &[0x10; 32])
        .unwrap()
        .unwrap();

    assert_eq!(
        after_second.related_cases, after_first.related_cases,
        "the relation list is unchanged"
    );
    assert_eq!(
        after_second.updated_at, after_first.updated_at,
        "and so is updated_at: the skip is inside the branch that writes it"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &issuer.address()).unwrap(),
        4,
        "yet both consolidations charged a nonce"
    );
}

// ── The publication byte contract ───────────────────────────────────────────

/// The PUBLISHED bytes are the byte contract, and this pins them directly.
///
/// `published_rows_satisfy_the_committed_scans` compares candidate bytes to
/// independent expectations; `published_legal_rows_survive_a_database_restart`
/// compares published rows to THEMSELVES across a close and reopen. Neither
/// pins the step between them: candidate to committed goes through
/// `ApplicationOverlay::into_batch`, and if that reordered a key, dropped a
/// prefix or re-encoded a value, both of those tests would still pass.
///
/// So: publish a real block through the real publisher, then for all EIGHT
/// families read the RAW committed bytes and compare them against a key written
/// out by hand and a value produced by `bincode::serialize` applied here in the
/// test. Nothing on the expected side calls a key builder or a codec from the
/// crate under test. The key shapes are transcribed from the schema: every
/// primary family and both case indexes take a bare 32-byte id, and the
/// jurisdiction index is the only STRING key in the subsystem --
/// `"{jurisdiction}:{id_type}"`, where cases and benefits share one family and
/// are kept apart by that suffix alone. That family is the reason this test
/// carries NINE expectations over eight families. Index VALUES are bincode
/// `Vec<[u8; 32]>`, not presence markers. Then close the database, reopen it at
/// the same path, and compare the same nine expectations again.
///
/// Test-only addition: no production source and no existing test body changed.
#[test]
fn published_legal_bytes_match_independently_built_keys_and_values() {
    let (state, db, dir, executor) = setup_with_params(params());
    let issuer = KeyPair::generate();
    fund(&db, &issuer, 1_000_000_000);

    // Expectations built here, from the schema, with no help from the crate.
    let case_v = case_of(&issuer, 0x10, "US-NY");
    let event_v = event_of(&issuer, 0x20, 0x10);
    let order_v = order_of(&issuer, 0x30, 0x10);
    let benefit_v = benefit_of(&issuer, 0x40, "US-NY", BenefitStatus::Approved);
    let proof_v = proof_of(0x50);

    let expected: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            cf::LEGAL_CASES,
            vec![0x10u8; 32],
            bincode::serialize(&case_v).unwrap(),
        ),
        (
            cf::LEGAL_JURISDICTION_INDEX,
            b"US-NY:case".to_vec(),
            bincode::serialize(&vec![[0x10u8; 32]]).unwrap(),
        ),
        (
            cf::LEGAL_EVENTS,
            vec![0x20u8; 32],
            bincode::serialize(&event_v).unwrap(),
        ),
        (
            cf::LEGAL_CASE_EVENT_INDEX,
            vec![0x10u8; 32],
            bincode::serialize(&vec![[0x20u8; 32]]).unwrap(),
        ),
        (
            cf::LEGAL_ORDERS,
            vec![0x30u8; 32],
            bincode::serialize(&order_v).unwrap(),
        ),
        (
            cf::LEGAL_CASE_ORDER_INDEX,
            vec![0x10u8; 32],
            bincode::serialize(&vec![[0x30u8; 32]]).unwrap(),
        ),
        (
            cf::LEGAL_BENEFITS,
            vec![0x40u8; 32],
            bincode::serialize(&benefit_v).unwrap(),
        ),
        (
            cf::LEGAL_JURISDICTION_INDEX,
            b"US-NY:benefit".to_vec(),
            bincode::serialize(&vec![[0x40u8; 32]]).unwrap(),
        ),
        (
            cf::LEGAL_PROOFS,
            vec![0x50u8; 32],
            bincode::serialize(&proof_v).unwrap(),
        ),
    ];
    // Eight families, nine rows: the jurisdiction index carries two, and every
    // family must be represented or a family could drop out unnoticed.
    for f in LEGAL_CFS {
        assert!(
            expected.iter().any(|(fam, _, _)| fam == f),
            "{f} has no expectation, so this test says nothing about it"
        );
    }

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(&issuer, 0, LegalOperation::AnchorCase, &case_v),
            signed(&issuer, 1, LegalOperation::RecordEvent, &event_v),
            signed(&issuer, 2, LegalOperation::IssueOrder, &order_v),
            signed(&issuer, 3, LegalOperation::DetermineBenefit, &benefit_v),
            signed(&issuer, 4, LegalOperation::SubmitProof, &proof_v),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, TxStatus::Success)),
        "all five must succeed: {:?}",
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
    // And each family holds exactly the rows expected of it -- so a publisher
    // that wrote the right bytes at an extra key would still be caught.
    for family in LEGAL_CFS {
        let want = expected.iter().filter(|(f, _, _)| f == family).count();
        assert_eq!(
            db.prefix_iter(family, &[]).unwrap().count(),
            want,
            "{family} must hold exactly {want} published row(s)"
        );
    }

    let path = dir.path().to_path_buf();
    drop(executor);
    drop(state);
    assert_eq!(
        std::sync::Arc::strong_count(&db),
        1,
        "nothing else may hold the database, or the drop below does not close \
         it and the reopen proves nothing"
    );
    drop(db);

    let reopened = Database::open_default(&path).unwrap();
    for (family, key, value) in &expected {
        assert_eq!(
            reopened.get(family, key).unwrap().as_deref(),
            Some(&value[..]),
            "{family}: the row changed across a close and reopen"
        );
    }
}
