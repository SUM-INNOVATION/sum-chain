//! The education subsystem reads through the block's own write set.
//!
//! Migrating a subsystem's *writes* into the overlay while leaving its *reads*
//! on the committed `Database` is not a partial improvement — it is a
//! correctness regression. Validation would then decide against the parent's
//! state while the block's earlier transactions sat unread in the candidate,
//! so two transactions in one block could both create the same record, and a
//! transaction could be rejected for referring to something its own block had
//! just created.
//!
//! These tests drive `validate` + `stage` directly against an
//! `ExecutionView`, without `execute_tx`, so they assert the property itself
//! rather than the dispatcher around it.

use std::sync::Arc;

use sumchain_primitives::education::{
    catalog_op, offering_op, AccessAudience, ContentAccessPolicy, CourseLevel,
    CreateCatalogEntryData, CreateOfferingData, EducationStandard, EducationTxData, ManagedSnipRef,
    PublishCatalogContentData, SnipRef,
};
use sumchain_primitives::Address;
use sumchain_state::education_executor::{
    parse_education, EducationExecutor, F_CATALOG_NOT_FOUND, F_DUPLICATE,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database};

const CATALOG: [u8; 32] = [7u8; 32];
const OFFERING: [u8; 32] = [9u8; 32];
const LIMIT: u64 = 1 << 20;

fn sponsor() -> Address {
    Address::from([3u8; 20])
}

fn catalog_tx() -> EducationTxData {
    EducationTxData {
        standard: EducationStandard::CourseCatalog,
        operation: catalog_op::CREATE_CATALOG_ENTRY,
        data: bincode::serialize(&CreateCatalogEntryData {
            catalog_id: CATALOG,
            institution_id: [1u8; 32],
            department: "CS".into(),
            course_code: "101".into(),
            course_title: Some("Intro".into()),
            title_commitment: None,
            course_level: CourseLevel::Undergraduate as u8,
            credit_hours: Some(3),
            credit_commitment: None,
            prerequisites_count: 0,
            prerequisites_root: None,
            version: 1,
            supersedes: None,
            nonce: 1,
        })
        .unwrap(),
        recipient: Address::ZERO,
    }
}

/// Activates the catalog entry. A new entry is Draft, and an offering may bind
/// only an Active one, so this is the transaction that must observe the record
/// the previous transaction created — and whose status change the next
/// transaction must in turn observe.
fn publish_catalog_tx() -> EducationTxData {
    let m = ManagedSnipRef {
        snip_ref: SnipRef {
            content_root: [9u8; 32],
            snip_file_id: None,
            size_bytes: 1,
            schema_version: 1,
        },
        access_policy: ContentAccessPolicy {
            opens_at: None,
            closes_at: None,
            grace_until: None,
            audience: AccessAudience::StaffOnly,
            revoke_on_course_archive: true,
        },
    };
    EducationTxData {
        standard: EducationStandard::CourseCatalog,
        operation: catalog_op::PUBLISH_CATALOG_CONTENT,
        data: bincode::serialize(&PublishCatalogContentData {
            catalog_id: CATALOG,
            description_ref: Some(m),
            learning_outcomes_ref: None,
            default_syllabus_ref: None,
            default_assessment_policy_ref: None,
            nonce: 2,
        })
        .unwrap(),
        recipient: Address::ZERO,
    }
}

fn offering_tx() -> EducationTxData {
    EducationTxData {
        standard: EducationStandard::CourseOffering,
        operation: offering_op::CREATE_OFFERING,
        data: bincode::serialize(&CreateOfferingData {
            offering_id: OFFERING,
            catalog_id: CATALOG,
            term: "2026FA".into(),
            section: "A".into(),
            instruction_start_at: 0,
            instruction_end_at: 1_000,
            final_grade_submission_deadline: 2_000,
            nonce: 1,
        })
        .unwrap(),
        recipient: Address::ZERO,
    }
}

/// Run one education transaction against `view`, staging it on success.
/// Returns the semantic reject code, if any.
fn run(view: &mut ExecutionView<'_, '_>, tx: &EducationTxData, height: u64) -> Option<u8> {
    let parsed = parse_education(tx).expect("parse");
    match EducationExecutor::validate(view, &parsed, &sponsor(), height, 1_000).unwrap() {
        Err(code) => Some(code),
        Ok(prepared) => {
            EducationExecutor::stage(view, prepared).unwrap();
            None
        }
    }
}

fn db() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

#[test]
fn an_offering_resolves_a_catalog_created_earlier_in_the_same_block() {
    let (_dir, db) = db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert_eq!(run(&mut view, &catalog_tx(), 1), None, "catalog creation");

    // The catalog is not in the committed database — only in the candidate.
    assert_eq!(
        db.get(cf::EDU_CATALOG_ENTRIES, &CATALOG).unwrap(),
        None,
        "the catalog must still be unpublished; if it is committed here the \
         write did not go through the overlay"
    );
    assert!(view
        .get(cf::EDU_CATALOG_ENTRIES, &CATALOG)
        .unwrap()
        .is_some());

    // Reading committed state, this would reject with F_CATALOG_NOT_FOUND.
    assert_eq!(
        run(&mut view, &publish_catalog_tx(), 1),
        None,
        "publishing must resolve the catalog its own block just created"
    );

    // Still nothing committed. `a_dropped_candidate_leaves_nothing_for_the_next_block`
    // runs this same offering against exactly this committed state and gets
    // `F_CATALOG_NOT_FOUND`, so a `None` here is the overlay read and nothing
    // else — the pair is what makes this test non-vacuous.
    assert_eq!(db.get(cf::EDU_CATALOG_ENTRIES, &CATALOG).unwrap(), None);

    // And this one must see the *latest* buffered value for that key — the
    // Active status the previous transaction wrote over the Draft record,
    // not the Draft one and not the parent's absence.
    assert_eq!(
        run(&mut view, &offering_tx(), 1),
        None,
        "the offering must bind the catalog its own block just activated"
    );
    assert!(view.get(cf::EDU_OFFERINGS, &OFFERING).unwrap().is_some());
}

#[test]
fn a_duplicate_within_one_block_is_rejected() {
    let (_dir, db) = db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert_eq!(run(&mut view, &catalog_tx(), 1), None);
    // Against committed state the second creation would see nothing and be
    // accepted, and the block would publish one record for two charged
    // transactions.
    assert_eq!(
        run(&mut view, &catalog_tx(), 1),
        Some(F_DUPLICATE),
        "the second creation of the same catalog id must be rejected"
    );
}

/// The view is the candidate, not the chain: dropping it publishes nothing,
/// and the next block sees the parent's state.
#[test]
fn a_dropped_candidate_leaves_nothing_for_the_next_block() {
    let (_dir, db) = db();
    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        assert_eq!(run(&mut view, &catalog_tx(), 1), None);
        assert_eq!(run(&mut view, &publish_catalog_tx(), 1), None);
        assert_eq!(run(&mut view, &offering_tx(), 1), None);
    }
    assert_eq!(db.get(cf::EDU_CATALOG_ENTRIES, &CATALOG).unwrap(), None);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert_eq!(
        run(&mut view, &offering_tx(), 2),
        Some(F_CATALOG_NOT_FOUND),
        "a rejected block's catalog must not be visible to the next one"
    );
}
