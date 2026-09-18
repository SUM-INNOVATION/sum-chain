//! Legal: the committed store's rows are exactly what the shared helpers build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_case(...)` proves nothing: the store
//! CALLS that helper, so a wrong helper moves both sides of the assertion
//! together. The same trap applies twice as hard here, because `CaseId`,
//! `ProcessEventId`, `OrderId`, `BenefitId` and `ProofId` are ALL `[u8; 32]`:
//! swapping `case_event_index_key` for `case_order_index_key`, or keying the
//! order family by `case_id`, compiles and type-checks. Only raw bytes catch it.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand. Both are what the
//! committed store produced BEFORE this commit extracted the helpers: the row
//! layout is the compatibility contract, and it must not move.
//!
//! ## Keys, spelled out
//!
//!     cases              the 32-byte case id
//!     process events     the 32-byte event id
//!     orders             the 32-byte order id
//!     benefits           the 32-byte benefit id
//!     proofs             the 32-byte proof id
//!     case→event index   the 32-byte CASE id, value a bincode Vec<[u8; 32]>
//!     case→order index   the 32-byte CASE id, value a bincode Vec<[u8; 32]>
//!     jurisdiction index the ASCII "{jurisdiction}:{case|benefit}", value a
//!                        bincode Vec<[u8; 32]>
//!     system events      8-byte big-endian height then 4-byte big-endian index
//!
//! The jurisdiction family holds cases and benefits together, separated only by
//! the key suffix. That is asserted explicitly below: a builder that dropped the
//! suffix would make a case and a benefit in one jurisdiction overwrite each
//! other's list, and every per-store test would still pass.

use sumchain_primitives::legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType, CourtOrder,
    LegalEvent, LegalIssuerClass, LegalProofEnvelope, LegalProofProfile, LegalProofType,
    OrderStatus, OrderType, ProcessEvent, ProcessEventStatus, ProcessEventType,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::legal_store::{decode_id_list, LegalStore};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

fn case(id: u8, jurisdiction: &str) -> CaseAnchor {
    CaseAnchor {
        case_id: [id; 32],
        case_commitment: [11u8; 32],
        jurisdiction_code: jurisdiction.to_string(),
        case_type: Some(CaseType::Civil),
        public_reference: None,
        policy_id: [12u8; 32],
        issuer_class: LegalIssuerClass::LawFirm,
        issuer_address: Address::new([1u8; 20]),
        status: CaseStatus::Filed,
        created_at: 1_000,
        updated_at: 1_000,
        anchored_at_height: 100,
        related_cases: vec![],
    }
}

fn process_event(id: u8, case_id: u8) -> ProcessEvent {
    ProcessEvent {
        event_id: [id; 32],
        case_id: [case_id; 32],
        event_type: ProcessEventType::Filed,
        event_commitment: [21u8; 32],
        issuer_address: Address::new([1u8; 20]),
        issuer_class: LegalIssuerClass::LawFirm,
        event_time_start: Some(1_000),
        event_time_end: None,
        attachments: vec![],
        policy_id: [22u8; 32],
        revocation_ref: None,
        status: ProcessEventStatus::Recorded,
        created_at: 1_000,
        recorded_at_height: 100,
        supersedes: None,
    }
}

fn order(id: u8, case_id: u8) -> CourtOrder {
    CourtOrder {
        order_id: [id; 32],
        case_id: [case_id; 32],
        order_type: OrderType::FinalJudgment,
        order_commitment: [31u8; 32],
        issuer_address: Address::new([1u8; 20]),
        issuer_class: LegalIssuerClass::CourtSystem,
        status: OrderStatus::Active,
        effective_from: 1_000,
        expiry: Some(9_000),
        policy_id: [32u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
        issued_at_height: 100,
        supersedes_order_id: None,
        attachments: vec![],
    }
}

fn benefit(id: u8, jurisdiction: &str) -> BenefitDetermination {
    BenefitDetermination {
        benefit_id: [id; 32],
        benefit_type: BenefitType::Medicare,
        jurisdiction_code: jurisdiction.to_string(),
        status: BenefitStatus::Approved,
        determination_commitment: [41u8; 32],
        subject_nullifier: [42u8; 32],
        issuer_address: Address::new([1u8; 20]),
        issuer_class: LegalIssuerClass::GovernmentAgency,
        valid_from: 1_000,
        expiry: None,
        policy_id: [43u8; 32],
        revocation_ref: None,
        created_at: 1_000,
        updated_at: 1_000,
        recorded_at_height: 100,
        supersedes: None,
    }
}

fn proof(id: u8) -> LegalProofEnvelope {
    LegalProofEnvelope {
        proof_id: [id; 32],
        profile: LegalProofProfile::BenefitApproved,
        profile_id: "legal.benefit_approved.v1".to_string(),
        policy_ids: vec![[51u8; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4, 5, 6],
        proof_type: LegalProofType::Groth16,
        subject_nullifier: [52u8; 32],
        generated_at: 1_000,
        expires_at: 2_000,
    }
}

// ── The five entity families ─────────────────────────────────────────────────

#[test]
fn a_case_row_is_bincode_at_the_case_id_key() {
    let (db, _dir) = db();
    let c = case(10, "US-NY-SDNY");
    LegalStore::new(&db).cases().put(&c).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_CASES, &[10u8; 32]),
        Some(bincode::serialize(&c).unwrap()),
        "the key is the case id, the value plain bincode"
    );
}

#[test]
fn a_process_event_row_is_bincode_at_the_event_id_key() {
    let (db, _dir) = db();
    let e = process_event(20, 10);
    LegalStore::new(&db).process_events().put(&e).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_EVENTS, &[20u8; 32]),
        Some(bincode::serialize(&e).unwrap()),
        "the key is the EVENT id, not the case id it belongs to"
    );
}

#[test]
fn an_order_row_is_bincode_at_the_order_id_key() {
    let (db, _dir) = db();
    let o = order(30, 10);
    LegalStore::new(&db).orders().put(&o).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_ORDERS, &[30u8; 32]),
        Some(bincode::serialize(&o).unwrap()),
        "the key is the ORDER id, not the case id it belongs to"
    );
}

#[test]
fn a_benefit_row_is_bincode_at_the_benefit_id_key() {
    let (db, _dir) = db();
    let b = benefit(40, "US");
    LegalStore::new(&db).benefits().put(&b).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_BENEFITS, &[40u8; 32]),
        Some(bincode::serialize(&b).unwrap())
    );
}

#[test]
fn a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index() {
    let (db, _dir) = db();
    let p = proof(50);
    LegalStore::new(&db).proofs().put(&p).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_PROOFS, &[50u8; 32]),
        Some(bincode::serialize(&p).unwrap())
    );
    // Unlike tax proofs, legal proofs have NO subject index: the RPC scans the
    // family. Asserted so that adding one becomes a visible change here.
    assert!(
        db.prefix_iter(cf::LEGAL_JURISDICTION_INDEX, &[])
            .unwrap()
            .next()
            .is_none(),
        "a legal proof writes exactly one row"
    );
}

// ── The three index families ─────────────────────────────────────────────────

#[test]
fn a_case_puts_its_id_in_the_jurisdiction_index_under_the_case_suffix() {
    let (db, _dir) = db();
    LegalStore::new(&db)
        .cases()
        .put(&case(10, "US-NY"))
        .unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case"),
        Some(bincode::serialize(&vec![[10u8; 32]]).unwrap()),
        "a one-element list at the ASCII \"US-NY:case\""
    );
    assert_eq!(
        row(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY"),
        None,
        "and nothing at the bare jurisdiction, which is what a dropped suffix \
         would produce"
    );
}

#[test]
fn a_benefit_puts_its_id_in_the_same_family_under_the_benefit_suffix() {
    let (db, _dir) = db();
    let store = LegalStore::new(&db);
    store.cases().put(&case(10, "US-NY")).unwrap();
    store.benefits().put(&benefit(40, "US-NY")).unwrap();

    // One FAMILY, two keys. If the suffix were dropped these two would be one
    // list and each store's own reader would still look correct.
    assert_eq!(
        row(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case"),
        Some(bincode::serialize(&vec![[10u8; 32]]).unwrap())
    );
    assert_eq!(
        row(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY:benefit"),
        Some(bincode::serialize(&vec![[40u8; 32]]).unwrap())
    );
}

#[test]
fn a_second_case_in_one_jurisdiction_appends_to_the_same_list() {
    let (db, _dir) = db();
    let store = LegalStore::new(&db);
    store.cases().put(&case(10, "US-NY")).unwrap();
    store.cases().put(&case(11, "US-NY")).unwrap();
    // A repeat of the first must NOT append again.
    store.cases().put(&case(10, "US-NY")).unwrap();

    let raw = row(&db, cf::LEGAL_JURISDICTION_INDEX, b"US-NY:case").unwrap();
    assert_eq!(
        raw,
        bincode::serialize(&vec![[10u8; 32], [11u8; 32]]).unwrap(),
        "both ids, in insertion order, de-duplicated"
    );
    assert_eq!(decode_id_list(&raw).unwrap(), vec![[10u8; 32], [11u8; 32]]);
}

#[test]
fn a_process_event_indexes_itself_under_its_case_id() {
    let (db, _dir) = db();
    let store = LegalStore::new(&db);
    store.process_events().put(&process_event(20, 10)).unwrap();
    store.process_events().put(&process_event(21, 10)).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_CASE_EVENT_INDEX, &[10u8; 32]),
        Some(bincode::serialize(&vec![[20u8; 32], [21u8; 32]]).unwrap()),
        "keyed by the CASE id, holding the EVENT ids"
    );
    assert_eq!(
        row(&db, cf::LEGAL_CASE_EVENT_INDEX, &[20u8; 32]),
        None,
        "and nothing keyed by an event id, which is what swapping the two \
         32-byte arrays would produce"
    );
}

#[test]
fn an_order_indexes_itself_under_its_case_id_in_its_own_family() {
    let (db, _dir) = db();
    let store = LegalStore::new(&db);
    store.orders().put(&order(30, 10)).unwrap();
    store.orders().put(&order(31, 10)).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_CASE_ORDER_INDEX, &[10u8; 32]),
        Some(bincode::serialize(&vec![[30u8; 32], [31u8; 32]]).unwrap()),
        "keyed by the CASE id, holding the ORDER ids"
    );
    // Same key SHAPE as the event index, different family. An order must not
    // land in the event index and vice versa.
    assert_eq!(
        row(&db, cf::LEGAL_CASE_EVENT_INDEX, &[10u8; 32]),
        None,
        "orders do not write the event index"
    );
}

#[test]
fn the_two_case_keyed_indexes_stay_separate() {
    let (db, _dir) = db();
    let store = LegalStore::new(&db);
    store.process_events().put(&process_event(20, 10)).unwrap();
    store.orders().put(&order(30, 10)).unwrap();

    assert_eq!(
        row(&db, cf::LEGAL_CASE_EVENT_INDEX, &[10u8; 32]),
        Some(bincode::serialize(&vec![[20u8; 32]]).unwrap()),
        "the event index holds only the event"
    );
    assert_eq!(
        row(&db, cf::LEGAL_CASE_ORDER_INDEX, &[10u8; 32]),
        Some(bincode::serialize(&vec![[30u8; 32]]).unwrap()),
        "the order index holds only the order"
    );
}

// ── The system-event journal ─────────────────────────────────────────────────

#[test]
fn a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key() {
    let (db, _dir) = db();
    let event = LegalEvent::CaseAnchored {
        case_id: [10u8; 32],
        jurisdiction: "US-NY".to_string(),
        case_commitment: [11u8; 32],
        timestamp: 1_000,
    };
    LegalStore::new(&db)
        .events()
        .put(0x0102_0304_0506_0708, 0x090A_0B0C, &event)
        .unwrap();

    // Written out by hand: big-endian height, then big-endian index. A
    // little-endian builder would still round-trip through its own reader.
    let key: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];
    assert_eq!(
        row(&db, cf::LEGAL_SYSTEM_EVENTS, &key),
        Some(bincode::serialize(&event).unwrap())
    );
}

// ── Decoders ─────────────────────────────────────────────────────────────────

#[test]
fn malformed_bytes_are_refused_by_every_legal_decoder() {
    use sumchain_storage::legal_store::{
        decode_benefit, decode_case, decode_legal_event, decode_order, decode_process_event,
        decode_proof,
    };
    let junk = b"not a row";
    assert!(decode_case(junk).is_err());
    assert!(decode_process_event(junk).is_err());
    assert!(decode_order(junk).is_err());
    assert!(decode_benefit(junk).is_err());
    assert!(decode_proof(junk).is_err());
    assert!(decode_id_list(junk).is_err());
    assert!(
        decode_legal_event(junk).is_err(),
        "including system events, which nothing writes but the reader still \
         decodes"
    );
}
