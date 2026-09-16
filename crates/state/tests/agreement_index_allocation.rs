//! Both agreement indexes allocate their whole value BEFORE the overlay
//! accounts for it -- measured, not argued.
//!
//! `v_add_to_party_index` and `v_add_to_executor_index` are read-modify-write:
//! they read the existing list, push one id, and call `encode_*_ids`, which
//! serializes the whole list into a fresh `Vec<u8>`. Only then does `view.put`
//! charge the candidate's byte ceiling. So the ceiling bounds what a block may
//! COMMIT; it does not bound what a single transaction may ALLOCATE on the way
//! to being refused.
//!
//! This file exists separately from `agreement_routing` because it installs a
//! counting global allocator, and a counting allocator is only meaningful if
//! nothing else in the binary is allocating at the same time. One test, run
//! alone, measuring two indexes in sequence.
//!
//! What this measures and what it does not: it measures ONE fixture size,
//! 20,000 ids, and reports the bytes actually allocated while the ceiling was
//! 4,096. It does not establish a bound for arbitrary input, and it is not a
//! fix. Capping either list would change which transactions are valid, which is
//! a consensus change and belongs in separately activated work.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementRole, AgreementStatus, AgreementTxData,
    ExecutorLink, ExecutorState, PartyBinding, PartyRef,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, AgreementStore, Database};

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

fn agreement(id: u8) -> AgreementCommitment {
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
        effective_from: Some(1000),
        expiry: Some(9_000_000),
        attachments: vec![],
        policy_id: [12u8; 32],
        status: AgreementStatus::PendingSignatures,
        created_at: 1000,
        updated_at: 1000,
        created_at_height: 1,
        supersedes: None,
    }
}

fn link(id: u8, agreement_id: u8, contract: Address) -> ExecutorLink {
    ExecutorLink {
        link_id: [id; 32],
        agreement_id: [agreement_id; 32],
        executor_contract: contract,
        executor_interface_id: [id.wrapping_add(1); 32],
        terms_commitment: [id.wrapping_add(2); 32],
        activation_policy_id: [12u8; 32],
        state: ExecutorState::Draft,
        created_at: 1000,
        updated_at: 1000,
        created_at_height: 1,
        activation_proof_id: None,
    }
}

fn tx(kp: &KeyPair, op: AgreementOperation, payload: &impl serde::Serialize) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Agreement(AgreementTxData {
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

/// One measurement: seed `family`/`key` with `fixture`, then run `t` under a
/// 4,096-byte ceiling and report what was allocated.
///
/// Each measurement is its own function because the seeding writes to the
/// database and the measuring constructs a candidate. Two of them in one body
/// puts the second seed after the first candidate, which is indistinguishable —
/// to `no_test_publishes_a_candidate_by_hand`, and to a reader — from a fixture
/// committing what it found in an overlay. One seed, then one candidate, per
/// function.
fn measure_refusal(
    seed: impl FnOnce(&Database),
    build_tx: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> (usize, usize, u64) {
    const CEILING: u64 = 4_096;
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db);
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

/// The ceiling is 4,096 bytes. Each index still allocates its entire
/// 640,008-byte value, and more, on the way to being refused.
#[test]
fn both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses() {
    assert_the_allocator_measures_what_it_claims_to();

    const CEILING: u64 = 4_096;
    let fixture = bincode::serialize(&twenty_thousand_ids()).unwrap();
    assert_eq!(
        fixture.len(),
        640_008,
        "the fixture must be exactly the size this test reports"
    );
    let contract = Address::new([0xCC; 20]);

    let cases: Vec<(&str, (usize, usize, u64))> = vec![
        ("party index", {
            let f = fixture.clone();
            measure_refusal(
                move |db| {
                    db.put(cf::AGREEMENT_PARTY_INDEX, &[0xA1u8; 32], &f)
                        .unwrap();
                },
                |actor| tx(actor, AgreementOperation::CommitAgreement, &agreement(90)),
            )
        }),
        ("executor index", {
            let f = fixture.clone();
            measure_refusal(
                move |db| {
                    AgreementStore::new(db)
                        .agreements()
                        .put(&agreement(91))
                        .unwrap();
                    db.put(cf::AGREEMENT_EXECUTOR_INDEX, contract.as_ref(), &f)
                        .unwrap();
                },
                |actor| {
                    tx(
                        actor,
                        AgreementOperation::LinkExecutor,
                        &link(0xF1, 91, contract),
                    )
                },
            )
        }),
    ];

    for (label, (bytes, largest, accounted)) in cases {
        println!(
            "{label}: ceiling {CEILING} B, allocated {bytes} B during the \
             refused transaction, largest single allocation {largest} B, \
             overlay accounted {accounted} B"
        );
        assert!(
            bytes >= fixture.len(),
            "{label}: the whole 640,008-byte value is built before the ceiling \
             is consulted; measured {bytes} B"
        );
        assert!(
            largest >= fixture.len(),
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
