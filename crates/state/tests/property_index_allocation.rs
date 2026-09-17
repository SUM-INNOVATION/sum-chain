//! All five property indexes allocate their whole value BEFORE the overlay
//! accounts for it -- measured, not argued -- and an admitted append preserves
//! every existing entry in order.
//!
//! `v_add_to_jurisdiction_index`, `v_add_to_asset_title_index`,
//! `v_add_to_asset_encumbrance_index`, `v_add_to_asset_coverage_index` and
//! `v_add_to_coverage_claim_index` are read-modify-write: each reads the
//! existing list, pushes one id, and calls its `encode_*_ids`, which serializes
//! the whole list into a fresh `Vec<u8>`. Only then does `view.put` charge the
//! candidate's byte ceiling. So the ceiling bounds what a block may COMMIT; it
//! does not bound what a single transaction may ALLOCATE on the way to being
//! refused.
//!
//! This file exists separately from `property_routing` because it installs a
//! counting global allocator, and a counting allocator is only meaningful if
//! nothing else in the binary is allocating at the same time. ONE test, run
//! alone, measuring five indexes in sequence.
//!
//! ## What this measures and what it does not
//!
//! It measures ONE fixture size, 20,000 ids, and reports the bytes actually
//! allocated while the ceiling was 4,096. It does not establish a bound for
//! arbitrary input: a larger index allocates proportionally more, and nothing
//! in the subsystem caps the length of any of these lists. One measured size
//! does not prove that arbitrary input is OOM-safe, and this file does not
//! claim it does. Capping a list would change which transactions are valid,
//! which is a consensus change and belongs in separately activated work, so no
//! cap is added here.
//!
//! The variable-sized rows that are NOT accumulated across transactions --
//! `AssetAnchor.related_assets`, `attachments`, the free-form
//! `jurisdiction_code` that forms the jurisdiction index KEY -- come from a
//! single payload and are not read-modify-written by any execution path, so
//! they are bounded by whatever bounds transaction size and are not measured
//! here. `AssetStore::add_related_asset` is the one accumulating row writer in
//! the subsystem that no dispatch arm reaches.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::PartyRef;
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, ClaimStatus, ClaimType, CoverageStatus, CoverageType,
    Encumbrance, EncumbranceStatus, EncumbranceType, InsuranceClaim, InsuranceCoverage,
    PriorityPosition, PropertyIssuerClass, PropertyOperation, PropertyTxData, TitleEvent,
    TitleEventStatus, TitleEventType,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::PropertyExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, PropertyStore};

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

/// Run `f` with allocation counting on. Returns (value, total bytes, largest).
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

/// One family's numbers: label, column family, bytes allocated during the
/// refused transaction, largest single allocation, bytes the overlay accounted
/// for, and the list an admitted append produced.
type Measurement = (&'static str, &'static str, usize, usize, u64, Vec<[u8; 32]>);

const CEILING: u64 = 4_096;
const JURISDICTION: &str = "US-CA-LA";
const PARENT_ASSET: u8 = 0xE0;
const PARENT_COVERAGE: u8 = 0xE3;

/// Every family this unit moved. Eleven.
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

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

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

fn twenty_thousand_ids() -> Vec<[u8; 32]> {
    (0..20_000u32)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect()
}

// ── Fixtures ────────────────────────────────────────────────────────────────

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
        grantor_ref: None,
        grantee_ref: None,
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

fn tx(kp: &KeyPair, op: PropertyOperation, payload: &impl serde::Serialize) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Property(PropertyTxData {
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

/// One refusal measurement: seed the parents and the fat index row, run the
/// transaction under a 4,096-byte ceiling, and report what was allocated.
///
/// Each measurement is its own function because the seeding writes to the
/// database and the measuring constructs a candidate. Two of them in one body
/// puts the second seed after the first candidate, which is indistinguishable
/// -- to `no_test_publishes_a_candidate_by_hand`, and to a reader -- from a
/// fixture committing what it found in an overlay. One seed, then one
/// candidate, per function.
fn measure_refusal(
    family: &'static str,
    key: Vec<u8>,
    fixture: Vec<u8>,
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> (usize, usize, u64) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    db.put(family, &key, &fixture).unwrap();
    let before = canonical(&db);
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, CEILING);
    // The view borrows the overlay, and the overlay has to be readable after
    // the measurement. A scope ends the borrow; `drop` would not -- an
    // `ExecutionView` is not `Drop`, so dropping it by name does nothing the
    // scope does not already do.
    let (bytes, largest) = {
        let mut view = ExecutionView::new(&mut overlay);
        let (outcome, bytes, largest) =
            measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, 1000));

        let err = outcome.expect_err("the ceiling must refuse the replacement");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // The candidate-visible old index is still exactly what was seeded.
        assert_eq!(
            view.get(family, &key).unwrap().as_deref(),
            Some(&fixture[..]),
            "{family}: the refused append must leave the old list byte-identical \
             in the candidate, not a truncated or partial one"
        );
        (bytes, largest)
    };

    assert_eq!(
        canonical(&db),
        before,
        "{family}: a refused append must commit nothing"
    );
    (bytes, largest, overlay.logical_bytes())
}

/// The same shape, admitted: a generous ceiling, and the resulting list read
/// back from the candidate.
fn admitted_append(
    family: &'static str,
    key: Vec<u8>,
    fixture: Vec<u8>,
    seed: impl FnOnce(&Database, Address),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
    read_back: impl FnOnce(&ExecutionView<'_, '_>) -> Vec<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db, actor.address());
    db.put(family, &key, &fixture).unwrap();
    let t = build_tx(&actor);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, 1000)
        .unwrap();
    assert!(
        matches!(r.status, sumchain_primitives::TxStatus::Success),
        "{family}: the append must be admitted under a generous ceiling: {:?}",
        r.status
    );
    read_back(&view)
}

/// The ceiling is 4,096 bytes. Each of the five indexes still allocates its
/// entire 640,008-byte value, and more, on the way to being refused -- and an
/// admitted append preserves every one of the 20,000 existing entries, in
/// order, with the new id last.
#[test]
fn all_five_indexes_allocate_their_whole_value_before_the_ceiling_refuses() {
    assert_the_allocator_measures_what_it_claims_to();

    let ids = twenty_thousand_ids();
    let fixture = bincode::serialize(&ids).unwrap();
    assert_eq!(
        fixture.len(),
        640_008,
        "the fixture must be exactly the size this test reports"
    );

    let seed_asset = |db: &Database, issuer: Address| {
        PropertyStore::new(db)
            .assets()
            .put(&asset(PARENT_ASSET, issuer))
            .unwrap();
    };
    let seed_asset_and_coverage = |db: &Database, issuer: Address| {
        let store = PropertyStore::new(db);
        store.assets().put(&asset(PARENT_ASSET, issuer)).unwrap();
        store
            .coverage()
            .put(&coverage(PARENT_COVERAGE, PARENT_ASSET, issuer))
            .unwrap();
    };

    let mut results: Vec<Measurement> = Vec::new();

    // 1. Jurisdiction index -- the one keyed by a STRING.
    {
        let f = cf::PROPERTY_JURISDICTION_INDEX;
        let key = JURISDICTION.as_bytes().to_vec();
        let (b, l, a) = measure_refusal(
            f,
            key.clone(),
            fixture.clone(),
            |_db, _issuer| {},
            |actor| {
                tx(
                    actor,
                    PropertyOperation::AnchorAsset,
                    &asset(0xF0, actor.address()),
                )
            },
        );
        let admitted = admitted_append(
            f,
            key,
            fixture.clone(),
            |_db, _issuer| {},
            |actor| {
                tx(
                    actor,
                    PropertyOperation::AnchorAsset,
                    &asset(0xF0, actor.address()),
                )
            },
            |view| PropertyExecutor::v_get_jurisdiction_asset_ids(view, JURISDICTION).unwrap(),
        );
        results.push(("jurisdiction index", f, b, l, a, admitted));
    }

    // 2. Asset -> title event index.
    {
        let f = cf::PROPERTY_ASSET_TITLE_INDEX;
        let key = vec![PARENT_ASSET; 32];
        let (b, l, a) = measure_refusal(f, key.clone(), fixture.clone(), seed_asset, |actor| {
            tx(
                actor,
                PropertyOperation::RecordTitleEvent,
                &title_event(0xF1, PARENT_ASSET, actor.address()),
            )
        });
        let admitted = admitted_append(
            f,
            key,
            fixture.clone(),
            seed_asset,
            |actor| {
                tx(
                    actor,
                    PropertyOperation::RecordTitleEvent,
                    &title_event(0xF1, PARENT_ASSET, actor.address()),
                )
            },
            |view| {
                PropertyExecutor::v_get_asset_title_event_ids(view, &[PARENT_ASSET; 32]).unwrap()
            },
        );
        results.push(("asset title index", f, b, l, a, admitted));
    }

    // 3. Asset -> encumbrance index.
    {
        let f = cf::PROPERTY_ASSET_ENCUMBRANCE_INDEX;
        let key = vec![PARENT_ASSET; 32];
        let (b, l, a) = measure_refusal(f, key.clone(), fixture.clone(), seed_asset, |actor| {
            tx(
                actor,
                PropertyOperation::RecordEncumbrance,
                &encumbrance(0xF2, PARENT_ASSET, actor.address()),
            )
        });
        let admitted = admitted_append(
            f,
            key,
            fixture.clone(),
            seed_asset,
            |actor| {
                tx(
                    actor,
                    PropertyOperation::RecordEncumbrance,
                    &encumbrance(0xF2, PARENT_ASSET, actor.address()),
                )
            },
            |view| {
                PropertyExecutor::v_get_asset_encumbrance_ids(view, &[PARENT_ASSET; 32]).unwrap()
            },
        );
        results.push(("asset encumbrance index", f, b, l, a, admitted));
    }

    // 4. Asset -> coverage index.
    {
        let f = cf::PROPERTY_ASSET_COVERAGE_INDEX;
        let key = vec![PARENT_ASSET; 32];
        let (b, l, a) = measure_refusal(f, key.clone(), fixture.clone(), seed_asset, |actor| {
            tx(
                actor,
                PropertyOperation::IssueCoverage,
                &coverage(0xF3, PARENT_ASSET, actor.address()),
            )
        });
        let admitted = admitted_append(
            f,
            key,
            fixture.clone(),
            seed_asset,
            |actor| {
                tx(
                    actor,
                    PropertyOperation::IssueCoverage,
                    &coverage(0xF3, PARENT_ASSET, actor.address()),
                )
            },
            |view| PropertyExecutor::v_get_asset_coverage_ids(view, &[PARENT_ASSET; 32]).unwrap(),
        );
        results.push(("asset coverage index", f, b, l, a, admitted));
    }

    // 5. Coverage -> claim index.
    {
        let f = cf::PROPERTY_COVERAGE_CLAIM_INDEX;
        let key = vec![PARENT_COVERAGE; 32];
        let (b, l, a) = measure_refusal(
            f,
            key.clone(),
            fixture.clone(),
            seed_asset_and_coverage,
            |actor| {
                tx(
                    actor,
                    PropertyOperation::FileClaim,
                    &claim(0xF4, PARENT_COVERAGE, PARENT_ASSET, actor.address()),
                )
            },
        );
        let admitted = admitted_append(
            f,
            key,
            fixture.clone(),
            seed_asset_and_coverage,
            |actor| {
                tx(
                    actor,
                    PropertyOperation::FileClaim,
                    &claim(0xF4, PARENT_COVERAGE, PARENT_ASSET, actor.address()),
                )
            },
            |view| {
                PropertyExecutor::v_get_coverage_claim_ids(view, &[PARENT_COVERAGE; 32]).unwrap()
            },
        );
        results.push(("coverage claim index", f, b, l, a, admitted));
    }

    let new_ids = [
        [0xF0u8; 32], // the anchored asset
        [0xF1u8; 32], // the title event
        [0xF2u8; 32], // the encumbrance
        [0xF3u8; 32], // the coverage
        [0xF4u8; 32], // the claim
    ];

    for (n, (label, family, bytes, largest, accounted, admitted)) in results.into_iter().enumerate()
    {
        println!(
            "{label} ({family}): ceiling {CEILING} B, allocated {bytes} B during \
             the refused transaction, largest single allocation {largest} B, \
             overlay accounted {accounted} B"
        );
        assert!(
            bytes >= fixture.len(),
            "{label}: the whole 640,008-byte value is built before the ceiling \
             is consulted; measured {bytes} B"
        );
        assert!(
            largest >= fixture.len(),
            "{label}: and it is built as one buffer, not incrementally: largest \
             single allocation {largest} B"
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

        // The admitted append: the WHOLE slice, not a sample. Every one of the
        // 20,000 existing entries, in its original position, with the new id
        // appended last.
        let mut expected = ids.clone();
        expected.push(new_ids[n]);
        assert_eq!(
            admitted.len(),
            20_001,
            "{label}: one entry added, none dropped"
        );
        assert_eq!(
            admitted, expected,
            "{label}: an admitted append must preserve every existing entry in \
             order and add the new id at the end"
        );
    }
}
