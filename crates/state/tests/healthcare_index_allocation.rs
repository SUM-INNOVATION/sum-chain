//! All seven healthcare accumulators allocate their whole value BEFORE the
//! overlay accounts for it -- measured, not argued.
//!
//! Healthcare has five accumulating INDEX families and two lists that
//! accumulate inside a primary row:
//!
//!     provider network index          Vec<ProviderId>      keyed by PLAN id
//!     member index                    Vec<MembershipId>    keyed by member nullifier
//!     subject consent index           Vec<ConsentId>       keyed by subject nullifier
//!     patient prescription index      Vec<PrescriptionId>  keyed by patient nullifier
//!     prescriber prescription index   Vec<PrescriptionId>  keyed by provider id
//!     membership.dependents           Vec<[u8; 32]>        inside the membership row
//!     prescription.fill_history       Vec<[u8; 32]>        inside the prescription row
//!
//! Every one is read-modify-write: read the existing contents, push one entry,
//! and serialize the whole thing into a fresh `Vec<u8>`. Only then does
//! `view.put` charge the candidate's byte ceiling. So the ceiling bounds what a
//! block may COMMIT; it does not bound what a single transaction may ALLOCATE
//! on the way to being refused.
//!
//! The two in-row lists are the worse shape of the two: the buffer that gets
//! built is the ENTIRE record, and a partial fill builds it twice -- once to
//! append the fill and once to stamp the status onto the row it just wrote.
//!
//! This file exists separately from `healthcare_routing` because it installs a
//! counting global allocator, and a counting allocator is only meaningful if
//! nothing else in the binary is allocating at the same time. One test, run
//! alone, measuring seven accumulators in sequence.
//!
//! What this measures and what it does not: it measures ONE fixture size,
//! 20,000 entries, and reports the bytes actually allocated while the ceiling
//! was 4,096. It does not establish a bound for arbitrary input, and it is not
//! a fix. Capping any of these lists would change which transactions are valid,
//! which is a consensus change and belongs in separately activated work.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::healthcare::{
    ConsentEnvelope, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareIssuerClass, HealthcareOperation, HealthcareTxData, MembershipRecord,
    MembershipStatus, MembershipType, Prescription, PrescriptionStatus, PrescriptionType,
    ProviderProfile, ProviderStatus, ProviderType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, HealthcareStore};

static BYTES: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
static RECORDING: AtomicBool = AtomicBool::new(false);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RECORDING.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f` with allocation counting on. Returns (total bytes, largest single).
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    BYTES.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    RECORDING.store(true, Ordering::Relaxed);
    let out = f();
    RECORDING.store(false, Ordering::Relaxed);
    (
        out,
        BYTES.load(Ordering::Relaxed),
        LARGEST.load(Ordering::Relaxed),
    )
}

const CEILING: u64 = 4_096;
const PLAN_A: [u8; 32] = [0xC1; 32];
const MEMBER_NULL: [u8; 32] = [0xD1; 32];
const SUBJECT_NULL: [u8; 32] = [0xE1; 32];
const PATIENT_NULL: [u8; 32] = [0xF1; 32];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn twenty_thousand_ids() -> Vec<[u8; 32]> {
    (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

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

fn prescription(id: u8, prescriber: u8, issuer: Address) -> Prescription {
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
        refills_authorized: 2,
        refills_remaining: 2,
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

#[derive(serde::Serialize)]
struct Dependent {
    membership_id: [u8; 32],
    dependent_commitment: [u8; 32],
}
#[derive(serde::Serialize)]
struct Fill {
    prescription_id: [u8; 32],
    fill_commitment: [u8; 32],
}

fn tx(kp: &KeyPair, op: HealthcareOperation, payload: &impl serde::Serialize) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Healthcare(HealthcareTxData {
            operation: op,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// The counting allocator actually counts.
///
/// Called at the top of the measurement below rather than standing as its own
/// `#[test]`: two tests in this binary would run on two threads, and a counting
/// allocator that sees another thread's allocations measures nothing. One test
/// in the binary is what makes the numbers mean anything.
fn assert_the_allocator_measures_what_it_claims_to() {
    let ((), bytes, largest) = measure(|| {
        let v: Vec<u8> = Vec::with_capacity(1_000_000);
        std::hint::black_box(&v);
    });
    assert!(
        bytes >= 1_000_000 && largest >= 1_000_000,
        "a deliberate 1 MB allocation must be seen: total {bytes} B, largest {largest} B"
    );
    let ((), quiet, _) = measure(|| {});
    assert_eq!(quiet, 0, "and an empty window must measure zero");
    println!("allocator self-check: 1 MB seen, empty window measured 0 B");
}

/// One measurement: seed the accumulator, then run `build_tx` under a
/// 4,096-byte ceiling and report what was allocated.
///
/// Each measurement is its own function because the seeding writes to the
/// database and the measuring constructs a candidate. Two of them in one body
/// puts the second seed after the first candidate, which is indistinguishable --
/// to `no_test_publishes_a_candidate_by_hand`, and to a reader -- from a fixture
/// committing what it found in an overlay. One seed, then one candidate, per
/// function.
fn measure_refusal(
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> (usize, usize, u64) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, CEILING);
    // The view borrows the overlay, and the overlay has to be readable after
    // the measurement. A scope ends the borrow; `drop` would not -- an
    // `ExecutionView` is not `Drop`, so dropping it by name does nothing the
    // scope does not already do.
    let (outcome, bytes, largest) = {
        let mut view = ExecutionView::new(&mut overlay);
        measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, 1000))
    };

    let err = outcome.expect_err("the ceiling must refuse the replacement");
    assert!(
        err.to_string().contains("limit"),
        "refused by the ceiling, not by something else: {err}"
    );
    (bytes, largest, overlay.logical_bytes())
}

/// The ceiling is 4,096 bytes. Each accumulator still allocates its entire
/// value, and more, on the way to being refused.
#[test]
fn every_healthcare_accumulator_allocates_its_whole_value_before_the_ceiling_refuses() {
    assert_the_allocator_measures_what_it_claims_to();

    let ids = twenty_thousand_ids();
    let list = bincode::serialize(&ids).unwrap();
    assert_eq!(
        list.len(),
        640_008,
        "the index fixture must be exactly the size this test reports"
    );

    // The in-row fixtures are the whole record, so they are larger than the
    // bare list. Measured, not assumed.
    let fat_membership = {
        let mut m = membership(0xD5, 0xD0, Address::ZERO);
        m.dependents = ids.clone();
        bincode::serialize(&m).unwrap().len()
    };
    let fat_prescription = {
        let mut rx = prescription(0xD7, 0xD0, Address::ZERO);
        rx.fill_history = ids.clone();
        bincode::serialize(&rx).unwrap().len()
    };
    assert!(fat_membership > list.len() && fat_prescription > list.len());

    let cases: Vec<(&str, usize, (usize, usize, u64))> = vec![
        ("provider network index", list.len(), {
            let f = list.clone();
            measure_refusal(
                move |db, _addr| {
                    db.put(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, &PLAN_A, &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::RegisterProvider,
                        &provider(0xD0, actor.address(), vec![PLAN_A]),
                    )
                },
            )
        }),
        ("member index", list.len(), {
            let f = list.clone();
            measure_refusal(
                move |db, addr| {
                    HealthcareStore::new(db)
                        .providers()
                        .put(&provider(0xD0, addr, vec![]))
                        .unwrap();
                    db.put(cf::HEALTHCARE_MEMBER_INDEX, &MEMBER_NULL, &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::IssueMembership,
                        &membership(0xD1, 0xD0, actor.address()),
                    )
                },
            )
        }),
        ("subject consent index", list.len(), {
            let f = list.clone();
            measure_refusal(
                move |db, _addr| {
                    db.put(cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, &SUBJECT_NULL, &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::GrantConsent,
                        &consent(0xD2, actor.address()),
                    )
                },
            )
        }),
        ("patient prescription index", list.len(), {
            let f = list.clone();
            measure_refusal(
                move |db, addr| {
                    HealthcareStore::new(db)
                        .providers()
                        .put(&provider(0xD0, addr, vec![]))
                        .unwrap();
                    db.put(cf::HEALTHCARE_PATIENT_RX_INDEX, &PATIENT_NULL, &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::IssuePrescription,
                        &prescription(0xD3, 0xD0, actor.address()),
                    )
                },
            )
        }),
        ("prescriber prescription index", list.len(), {
            let f = list.clone();
            measure_refusal(
                move |db, addr| {
                    HealthcareStore::new(db)
                        .providers()
                        .put(&provider(0xD0, addr, vec![]))
                        .unwrap();
                    db.put(cf::HEALTHCARE_PRESCRIBER_RX_INDEX, &[0xD0u8; 32], &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::IssuePrescription,
                        &prescription(0xD4, 0xD0, actor.address()),
                    )
                },
            )
        }),
        ("membership dependents (in row)", fat_membership, {
            let seeded = ids.clone();
            measure_refusal(
                move |db, addr| {
                    let store = HealthcareStore::new(db);
                    store
                        .providers()
                        .put(&provider(0xD0, addr, vec![]))
                        .unwrap();
                    let mut m = membership(0xD5, 0xD0, addr);
                    m.dependents = seeded;
                    store.memberships().put(&m).unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::AddDependent,
                        &Dependent {
                            membership_id: [0xD5; 32],
                            dependent_commitment: [0xD6; 32],
                        },
                    )
                },
            )
        }),
        ("prescription fill history (in row)", fat_prescription, {
            let seeded = ids.clone();
            measure_refusal(
                move |db, addr| {
                    let store = HealthcareStore::new(db);
                    store
                        .providers()
                        .put(&provider(0xD0, addr, vec![]))
                        .unwrap();
                    let mut rx = prescription(0xD7, 0xD0, addr);
                    rx.fill_history = seeded;
                    store.prescriptions().put(&rx).unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        HealthcareOperation::PartialFillPrescription,
                        &Fill {
                            prescription_id: [0xD7; 32],
                            fill_commitment: [0xD8; 32],
                        },
                    )
                },
            )
        }),
    ];

    for (label, fixture_len, (bytes, largest, accounted)) in cases {
        println!(
            "{label}: ceiling {CEILING} B, existing value {fixture_len} B, \
             allocated {bytes} B during the refused transaction, largest single \
             allocation {largest} B, overlay accounted {accounted} B"
        );
        assert!(
            bytes >= fixture_len,
            "{label}: the whole {fixture_len}-byte value is built before the \
             ceiling is consulted; measured {bytes} B"
        );
        assert!(
            largest >= fixture_len,
            "{label}: and it is built as one buffer, not incrementally: \
             largest single allocation {largest} B"
        );
        assert!(
            bytes as u64 > CEILING * 100,
            "{label}: the allocation is not within two orders of magnitude of \
             the ceiling: {bytes} B against {CEILING} B"
        );
        assert!(
            accounted <= CEILING,
            "{label}: the overlay's accounted size stays under its own ceiling, \
             which is the point -- it bounds what may be COMMITTED, not what may \
             be allocated: {accounted} B"
        );
    }
}
