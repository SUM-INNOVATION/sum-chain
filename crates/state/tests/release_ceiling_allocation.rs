//! What ONE transaction can make a validator allocate under the RELEASE
//! configuration -- the derived `MAX_BLOCK_WRITE_SET_BYTES` candidate ceiling,
//! 2,000,000-byte blocks, 1000 transactions per block.
//!
//! # Why this file exists
//!
//! `crates/state/tests/*_index_allocation.rs` measure the same read-modify-write
//! accumulators under a 4,096- or 8,192-byte candidate ceiling. Those ceilings
//! are five to six orders of magnitude below the one a release node runs:
//! `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES` is `1 << 28`, and
//! `crates/state/src/executor.rs`'s only production construction site uses
//! it. So those files prove the refusal MECHANISM works and describe no
//! behaviour a release node exhibits. Under the release ceiling the very
//! transactions they show being refused are ADMITTED, and that is what is
//! measured here.
//!
//! The release sizing inputs are taken from the repository's own `genesis.json`:
//! `max_block_bytes: 2000000`, `max_txs_per_block: 1000`, `min_fee: 1000`.
//! `BlockExecutor::validate_block` enforces both limits, and
//! `PoaEngine::do_import_block` calls it BEFORE `execute_block`, so a payload is
//! bounded by the block limit before any executor decodes it. That bound, and
//! nothing else, is what caps a single transaction's sizing inputs today.
//!
//! # What is measured
//!
//! Three quantities per window, from a counting global allocator:
//!
//!   * `cumulative` -- every byte passed to `alloc`, summed. This is the number
//!     the existing `*_index_allocation.rs` files report. It is allocator
//!     CHURN, not footprint: a `Vec` that doubles five times contributes all six
//!     buffers.
//!   * `peak live` -- the high-water mark of (allocated - deallocated). This is
//!     the number that decides whether a validator survives, and no existing
//!     file in this tree reports it. Reporting only `cumulative` overstates
//!     footprint; reporting only `peak` understates cost. Both are here.
//!   * `largest single` -- the biggest one allocation, which is what an
//!     allocator refuses first.
//!
//! and one quantity from the overlay: `logical_bytes`, what the ceiling actually
//! charged.
//!
//! # What this file does NOT claim
//!
//! It does not measure a row at the ceiling. Materialising one needs twice the
//! ceiling in resident memory and would make this suite unrunnable on a
//! developer machine. What it does instead is measure the SLOPE at four row
//! sizes spanning six doublings and report it, so the extrapolation to the
//! ceiling is arithmetic on measured points rather than assertion. Every
//! extrapolated number in the printed report is labelled `EXTRAPOLATED`.
//!
//! ONE `#[test]` in this binary, deliberately: two tests run on two threads and
//! a counting global allocator that sees another thread's allocations measures
//! nothing.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, DocClassOperation, DocClassTxData, DocSubcode, IdentityKey, IdentityRoot,
    IdentityStatus, KeyPurpose, KeyType, ServiceEndpoint, SignedTransaction, TransactionV2,
    TxPayload, TxStatus,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore};

// ── The counting allocator ──────────────────────────────────────────────────

static CUMULATIVE: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static RECORDING: AtomicBool = AtomicBool::new(false);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RECORDING.load(Ordering::Relaxed) {
            CUMULATIVE.fetch_add(layout.size(), Ordering::Relaxed);
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
            let now =
                LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed) + layout.size() as isize;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if RECORDING.load(Ordering::Relaxed) {
            LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One measurement window.
#[derive(Clone, Copy, Debug, Default)]
struct Alloc {
    cumulative: usize,
    peak: usize,
    largest: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Alloc) {
    CUMULATIVE.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    RECORDING.store(true, Ordering::Relaxed);
    let out = f();
    RECORDING.store(false, Ordering::Relaxed);
    (
        out,
        Alloc {
            cumulative: CUMULATIVE.load(Ordering::Relaxed),
            peak: PEAK.load(Ordering::Relaxed).max(0) as usize,
            largest: LARGEST.load(Ordering::Relaxed),
        },
    )
}

// ── The release configuration, named once ───────────────────────────────────

/// `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES`. The ceiling a release node
/// actually runs, and the number `common::TEST_CANDIDATE_LIMIT` also carries.
/// Read from the constant, never restated: this file's whole claim is that it
/// measures the RELEASE configuration, and a local copy of the number would be
/// the way that claim quietly stops being true.
const RELEASE_CEILING: u64 = sumchain_state::MAX_BLOCK_WRITE_SET_BYTES;

/// `params.max_block_bytes` in this repository's `genesis.json`. A transaction's
/// serialized payload cannot exceed this, because `validate_block` refuses the
/// block that carries it before `execute_block` decodes anything.
const RELEASE_MAX_BLOCK_BYTES: usize = 2_000_000;

/// Room for the block header, the signature, the envelope and the other
/// `TransactionV2` fields. The payload budget, not the block budget.
const PAYLOAD_BUDGET: usize = 1_900_000;

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const IDENT: u8 = 0xE0;

fn key_with_id(id: String) -> IdentityKey {
    IdentityKey {
        key_id: id,
        key_type: KeyType::Ed25519,
        public_key: [7u8; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: 1_000,
        expires_at: 0,
        active: true,
    }
}

fn empty_service(n: usize) -> ServiceEndpoint {
    // Every string empty: 8 + 8 + 8 bytes of bincode length prefix plus one byte
    // for the `None`. 25 bytes on the wire, and a 96-byte struct in memory --
    // the shape with the largest payload-to-footprint amplification this row
    // admits, which is why it is the one measured.
    let _ = n;
    ServiceEndpoint {
        service_id: String::new(),
        service_type: String::new(),
        endpoint: String::new(),
        description: None,
    }
}

fn identity(controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id: [IDENT; 32],
        subject_commitment: [IDENT.wrapping_add(0x40); 32],
        controller,
        additional_controllers: vec![],
        keys: vec![],
        services: vec![],
        created_at: 1_000,
        updated_at: 1_000,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

fn tx(
    kp: &KeyPair,
    nonce: u64,
    operation: DocClassOperation,
    payload: &impl serde::Serialize,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// Commit a row of approximately `bytes` encoded length: one identity with a
/// single key whose `key_id` carries the weight.
///
/// One long string rather than many short ones on purpose. It isolates the
/// re-encode factor from the `Vec`-growth factor, so the slope this file reports
/// is the slope of "row size", not of "entry count".
fn seed_row_of(db: &Database, controller: Address, bytes: usize) -> usize {
    let mut root = identity(controller);
    root.keys = vec![key_with_id("x".repeat(bytes))];
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    db.get(cf::DOCCLASS_IDENTITY_ROOTS, &[IDENT; 32])
        .unwrap()
        .expect("the seeded row must be there")
        .len()
}

/// The allocator measures what it says it measures, and its peak tracking
/// distinguishes churn from footprint.
///
/// Not its own `#[test]`: see the module header.
fn assert_the_allocator_measures_what_it_claims_to() {
    // Churn without footprint: ten one-megabyte buffers, one at a time.
    let ((), churn) = measure(|| {
        for _ in 0..10 {
            let v: Vec<u8> = Vec::with_capacity(1_000_000);
            std::hint::black_box(&v);
        }
    });
    assert!(
        churn.cumulative >= 10_000_000,
        "ten sequential 1 MB buffers must sum to at least 10 MB: {churn:?}"
    );
    assert!(
        churn.peak < 3_000_000,
        "and, freed one at a time, must never be more than a couple live at \
         once -- this is the distinction the existing allocation files do not \
         draw: {churn:?}"
    );

    // Footprint: ten one-megabyte buffers, all live.
    let ((), held) = measure(|| {
        let all: Vec<Vec<u8>> = (0..10).map(|_| Vec::with_capacity(1_000_000)).collect();
        std::hint::black_box(&all);
    });
    assert!(
        held.peak >= 10_000_000,
        "ten SIMULTANEOUS 1 MB buffers must peak at 10 MB: {held:?}"
    );

    let ((), quiet) = measure(|| {});
    assert_eq!(quiet.cumulative, 0, "an empty window must measure zero");
    println!(
        "allocator self-check: churn {} B cumulative / {} B peak; held {} B \
         cumulative / {} B peak; empty window 0 B",
        churn.cumulative, churn.peak, held.cumulative, held.peak
    );
}

/// One transaction's outcome under the release ceiling.
struct Run {
    /// Encoded length of the identity row the seed committed, if any.
    seeded: usize,
    alloc: Alloc,
    /// `logical_bytes` the overlay charged -- what the ceiling actually bounds.
    accounted: u64,
    status: TxStatus,
    /// Encoded length of the identity row as the candidate holds it AFTER the
    /// transaction. Read from the view, not inferred from the accounting: the
    /// accounting also carries the event row, the account rows and the subject
    /// index, and attributing all of that to row growth would overstate it.
    row_after: usize,
}

/// Run one transaction against a seeded database under the RELEASE ceiling and
/// report what it allocated and what the ceiling charged.
fn run_one_tx(
    seed: impl FnOnce(&Database, Address) -> usize,
    build: impl FnOnce(&KeyPair) -> SignedTransaction,
) -> Run {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000_000);
    let proposer = Address::new([9; 20]);
    let seeded = seed(&db, actor.address());
    let t = build(&actor);

    let mut overlay = ApplicationOverlay::new(&db, RELEASE_CEILING);
    let (alloc, status, row_after) = {
        let mut view = ExecutionView::new(&mut overlay);
        let (outcome, alloc) = measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, 1_000));
        let receipt = outcome.expect(
            "under the RELEASE ceiling this transaction is not refused -- that \
             is the whole finding; an Err here would mean the ceiling bit, and \
             at the release ceiling it does not",
        );
        let row_after = view
            .get(cf::DOCCLASS_IDENTITY_ROOTS, &[IDENT; 32])
            .unwrap()
            .map_or(0, |v| v.len());
        (alloc, receipt.status, row_after)
    };
    Run {
        seeded,
        alloc,
        accounted: overlay.logical_bytes(),
        status,
        row_after,
    }
}

/// The measurement.
#[test]
fn one_transaction_at_the_release_ceiling_allocates_what_the_release_ceiling_does_not_bound() {
    assert_the_allocator_measures_what_it_claims_to();

    println!(
        "\n=== RELEASE configuration: ceiling {RELEASE_CEILING} B \
         ({} MiB), max_block_bytes {RELEASE_MAX_BLOCK_BYTES}, \
         max_txs_per_block 1000, min_fee 1000 ===\n",
        RELEASE_CEILING / (1 << 20)
    );

    // ── 1. The decode boundary, at the block-size limit ─────────────────────
    //
    // ONE `CreateIdentityRoot` whose payload is as large as a block may carry.
    // Nothing is seeded: this is the cost of the FIRST transaction an attacker
    // sends, from an empty chain, for one min_fee.
    let services = PAYLOAD_BUDGET / 25;
    let m1 = run_one_tx(
        |_db, _c| 0,
        |actor| {
            let mut root = identity(actor.address());
            root.services = (0..services).map(empty_service).collect();
            tx(actor, 0, DocClassOperation::CreateIdentityRoot, &root)
        },
    );
    let (first, first_accounted, first_status) = (m1.alloc, m1.accounted, m1.status);
    let wire = {
        let mut root = identity(Address::ZERO);
        root.services = (0..services).map(empty_service).collect();
        bincode::serialize(&root).unwrap().len()
    };
    println!(
        "M1  CreateIdentityRoot, {services} empty ServiceEndpoints, \
         {wire} B payload (block limit {RELEASE_MAX_BLOCK_BYTES} B)\n\
         \x20   status {first_status:?}; cumulative {} B, PEAK LIVE {} B, \
         largest single {} B; ceiling charged {first_accounted} B\n\
         \x20   amplification: {:.1}x cumulative, {:.1}x peak, per payload byte",
        first.cumulative,
        first.peak,
        first.largest,
        first.cumulative as f64 / wire as f64,
        first.peak as f64 / wire as f64,
    );
    assert!(
        wire <= RELEASE_MAX_BLOCK_BYTES,
        "the fixture must fit a release block: {wire} B"
    );
    assert!(
        matches!(first_status, TxStatus::Success),
        "at the RELEASE ceiling this is ADMITTED, not refused -- the 4,096-byte \
         measurements describe no release behaviour: {first_status:?}"
    );
    assert!(
        first.peak > wire,
        "the decoded value outweighs its own encoding: peak {} B against a \
         {wire} B payload",
        first.peak
    );

    // ── 2. The read-modify-write slope ──────────────────────────────────────
    //
    // ONE `AddKey` against a committed row, at four sizes spanning six
    // doublings. `AddKey` reads the row, decodes the WHOLE of it, pushes one
    // entry and re-encodes the WHOLE of it -- all before `view.put` charges a
    // byte. The slope in `row bytes` is what the ceiling does not bound.
    let mut slope: Vec<(usize, Alloc, u64)> = Vec::new();
    for mib in [1usize, 4, 16, 64] {
        let target = mib << 20;
        let m2 = run_one_tx(
            |db, c| seed_row_of(db, c, target),
            |actor| {
                tx(
                    actor,
                    0,
                    DocClassOperation::AddKey,
                    &AddKeyData {
                        identity_id: [IDENT; 32],
                        key: key_with_id("k".to_string()),
                    },
                )
            },
        );
        let (row, alloc, accounted, status) = (m2.seeded, m2.alloc, m2.accounted, m2.status);
        assert!(
            matches!(status, TxStatus::Success),
            "a {mib} MiB row is well under the release ceiling, so the append is \
             ADMITTED and commits: {status:?}"
        );
        println!(
            "M2  AddKey against a {row} B row: cumulative {} B ({:.2}x row), \
             PEAK LIVE {} B ({:.2}x row), largest single {} B; \
             ceiling charged {} B ({:.2}x row)",
            alloc.cumulative,
            alloc.cumulative as f64 / row as f64,
            alloc.peak,
            alloc.peak as f64 / row as f64,
            alloc.largest,
            accounted,
            accounted as f64 / row as f64,
        );
        slope.push((row, alloc, accounted));
    }

    // The slope is linear: doubling the row doubles the allocation. Checked
    // rather than eyeballed, because the extrapolation below rests on it.
    for w in slope.windows(2) {
        let (r0, a0, _) = w[0];
        let (r1, a1, _) = w[1];
        let row_ratio = r1 as f64 / r0 as f64;
        let peak_ratio = a1.peak as f64 / a0.peak as f64;
        assert!(
            (peak_ratio / row_ratio - 1.0).abs() < 0.35,
            "peak allocation must track row size linearly: row x{row_ratio:.2} \
             gave peak x{peak_ratio:.2}"
        );
    }

    let (biggest_row, biggest, biggest_accounted) = *slope.last().unwrap();
    let peak_factor = biggest.peak as f64 / biggest_row as f64;
    let cum_factor = biggest.cumulative as f64 / biggest_row as f64;
    assert!(
        biggest_accounted < RELEASE_CEILING,
        "and the ceiling charged {biggest_accounted} B, under its own \
         {RELEASE_CEILING} B limit, so nothing was refused"
    );

    // ── 3. How fast a row reaches the ceiling ───────────────────────────────
    //
    // The entry `AddKey` appends is `IdentityKey`, whose `key_id` is a `String`
    // with no length check anywhere in `docclass_executor.rs`. So ONE
    // transaction grows the row by as much as a block may carry, and the row
    // reaches the ceiling in a number of blocks the ceiling itself sets.
    let grown_from = 1 << 20;
    let long = PAYLOAD_BUDGET - 200;
    let m3 = run_one_tx(
        |db, c| seed_row_of(db, c, grown_from),
        |actor| {
            tx(
                actor,
                0,
                DocClassOperation::AddKey,
                &AddKeyData {
                    identity_id: [IDENT; 32],
                    key: key_with_id("g".repeat(long)),
                },
            )
        },
    );
    let (row_before, growth, growth_accounted, growth_status) =
        (m3.seeded, m3.alloc, m3.accounted, m3.status);
    assert!(
        matches!(growth_status, TxStatus::Success),
        "the oversized key_id is ADMITTED: nothing in the subsystem bounds a \
         key_id's length: {growth_status:?}"
    );
    // MEASURED, from the candidate, not inferred from the accounting. The
    // charge is larger than this because the `KeyAdded` event row carries a
    // COPY of the same `key_id`, which is a second unbounded write this
    // transaction makes and not part of the row's growth.
    let grew_by = m3.row_after as i64 - row_before as i64;
    println!(
        "M3  AddKey with a {long} B key_id against a {row_before} B row: \
         ADMITTED. Row is {} B after, so it grew by {grew_by} B in ONE \
         transaction, for one min_fee of 1000. Ceiling charged \
         {growth_accounted} B in total -- more than 2*row + growth, because the \
         `KeyAdded` event row carries a second copy of the same key_id.\n\
         \x20   cumulative {} B, PEAK LIVE {} B",
        m3.row_after, growth.cumulative, growth.peak
    );
    assert!(
        grew_by > 1_800_000,
        "one transaction must be shown to add nearly two megabytes to a single \
         row: {grew_by} B"
    );

    // ── 4. The extrapolation, labelled ──────────────────────────────────────
    //
    // Arithmetic on the measured points above. Not a measurement.
    // The largest row a single `put` can still commit: `put` charges the new
    // value AND the captured pre-image, so a row of R costs about 2R.
    let ceiling_row = RELEASE_CEILING / 2;
    let blocks_to_ceiling = ceiling_row / grew_by.max(1) as u64;
    println!(
        "\nEXTRAPOLATED (arithmetic on M2 and M3, not measured):\n\
         \x20 * the largest row a single put can still commit is about \
         {ceiling_row} B, because `put` charges the new value AND the captured \
         pre-image against the {RELEASE_CEILING} B ceiling.\n\
         \x20 * growing a row at the M3 rate of {grew_by} B per transaction, one \
         such transaction per block, it reaches that size in about \
         {blocks_to_ceiling} blocks -- at a 3,000 ms block time that is about \
         {} minutes, for about {} units of fee in total.\n\
         \x20 * at the M2 peak factor of {peak_factor:.2}x, ONE further AddKey \
         against a row that size peaks at about {} B live -- about {:.1} GiB -- \
         and at the cumulative factor of {cum_factor:.2}x churns about {} B.\n\
         \x20 * that transaction is REFUSED by the ceiling, and the refusal \
         happens AFTER the allocation. That is the class: the ceiling bounds \
         what a block may COMMIT, not what a refused transaction may ALLOCATE.",
        blocks_to_ceiling * 3 / 60,
        blocks_to_ceiling * 1000,
        (ceiling_row as f64 * peak_factor) as u64,
        ceiling_row as f64 * peak_factor / (1u64 << 30) as f64,
        (ceiling_row as f64 * cum_factor) as u64,
    );
}
