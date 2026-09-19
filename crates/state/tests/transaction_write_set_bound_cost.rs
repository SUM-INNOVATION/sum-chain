//! What the per-transaction write-set bound COSTS to enforce.
//!
//! A bound on memory that is itself expensive in memory has moved the problem
//! rather than solved it, and a bound that adds milliseconds per transaction to
//! a 3,000 ms block time is a different kind of defect from the one it fixes.
//! So both are measured here rather than argued.
//!
//! # Method
//!
//! The SAME block, executed through the SAME production entry point
//! (`BlockExecutor::execute_block`) twice: once with
//! `subsystem_tx_write_set_bound_enabled_from_height` closed — which is the
//! binary that existed before this rule — and once with it open. The difference
//! between the two is the whole cost of the checking, because nothing else
//! differs between the runs.
//!
//! Three quantities per run, from a counting global allocator, reported
//! separately for the reason `release_ceiling_allocation.rs` gives:
//!
//!   * `cumulative` — every byte passed to `alloc`. Allocator CHURN, not
//!     footprint.
//!   * `peak live` — the high-water mark of (allocated - deallocated). This is
//!     the number that decides whether a validator survives.
//!   * `largest single` — the biggest one allocation.
//!
//! and wall time, which is reported and NOT asserted on tightly: a wall clock
//! on a developer machine under a debug build is a rough instrument, and an
//! assertion tight enough to be interesting would be an assertion that fails on
//! a loaded CI box. What IS asserted is the shape — that the overhead is a
//! small multiple of nothing, not a multiple of the block.
//!
//! ONE `#[test]` in this binary, deliberately: two tests run on two threads and
//! a counting global allocator that sees another thread's allocations measures
//! nothing.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::time::Instant;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Block, BlockHeader, DocClassOperation, DocClassTxData, DocSubcode, Hash, IdentityKey,
    IdentityRoot, IdentityStatus, KeyPurpose, KeyType, SignedTransaction, TransactionV2, TxPayload,
    TxStatus,
};
use sumchain_state::{MAX_TX_WRITE_SET_BYTES, TX_WRITE_SET_BOUND_RECEIPT_CODE};
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

#[derive(Clone, Copy, Debug, Default)]
struct Alloc {
    cumulative: usize,
    peak: usize,
    largest: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Alloc, f64) {
    CUMULATIVE.store(0, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    RECORDING.store(true, Ordering::Relaxed);
    let started = Instant::now();
    let out = f();
    let elapsed = started.elapsed().as_secs_f64();
    RECORDING.store(false, Ordering::Relaxed);
    (
        out,
        Alloc {
            cumulative: CUMULATIVE.load(Ordering::Relaxed),
            peak: PEAK.load(Ordering::Relaxed).max(0) as usize,
            largest: LARGEST.load(Ordering::Relaxed),
        },
        elapsed,
    )
}

// ── Fixtures ────────────────────────────────────────────────────────────────

/// `max_txs_per_block` in this repository's `genesis.json`. The transaction
/// count a block may carry, which is the count the per-transaction overhead is
/// paid once for.
const RELEASE_MAX_TXS_PER_BLOCK: usize = 1_000;

/// The row each transaction rewrites in the measured block.
///
/// Small enough that a thousand of them fit inside the block ceiling, and large
/// enough that the transaction does real read-modify-write work — so the
/// overhead being measured is compared against a transaction that costs
/// something, not against an empty one.
const MEASURED_ROW: usize = 8 << 10;

/// The row size used for the refusal measurement: its rewrite crosses
/// [`MAX_TX_WRITE_SET_BYTES`], so the ROLLBACK path is what gets timed.
const OVERSIZED_ROW: usize = 9 << 20;

fn params_at(activation: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    if let Some(ref mut d) = p.docclass {
        d.min_issuer_stake = 0;
    }
    p.subsystem_tx_write_set_bound_enabled_from_height = activation;
    p
}

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

fn identity(identity_id: [u8; 32], controller: Address) -> IdentityRoot {
    IdentityRoot {
        identity_id,
        subject_commitment: [0x40; 32],
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

fn ident(n: usize) -> [u8; 32] {
    let mut id = [0xE0u8; 32];
    id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

fn seed_row(db: &Database, n: usize, controller: Address, bytes: usize) -> usize {
    let mut root = identity(ident(n), controller);
    root.keys = vec![key_with_id("x".repeat(bytes))];
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    db.get(cf::DOCCLASS_IDENTITY_ROOTS, &ident(n))
        .unwrap()
        .expect("the seeded row must be there")
        .len()
}

fn add_key_tx(kp: &KeyPair, nonce: u64, n: usize) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload: TxPayload::DocClass(DocClassTxData {
            operation: DocClassOperation::AddKey,
            subcode: DocSubcode::IdentityRoot,
            data: bincode::serialize(&AddKeyData {
                identity_id: ident(n),
                key: key_with_id(format!("k{n}")),
            })
            .unwrap(),
            recipient: Address::ZERO,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn block_of(txs: Vec<SignedTransaction>) -> Block {
    Block::new(
        BlockHeader::new(Hash::ZERO, 1, 1000, Hash::ZERO, Hash::ZERO, [9u8; 32]),
        txs,
    )
}

/// Execute one full block under `activation` and report what it cost.
///
/// Seeding happens OUTSIDE the measurement window: the fixture's own
/// allocations are not what is being measured, and including them would drown
/// the difference this file exists to report.
fn measure_block(activation: Option<u64>, rows: usize, row_bytes: usize) -> (Alloc, f64, Vec<TxStatus>) {
    let (state, db, _dir, executor) = setup_with_params(params_at(activation));
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000_000_000);
    for n in 0..rows {
        seed_row(&db, n, actor.address(), row_bytes);
    }
    let txs: Vec<SignedTransaction> = (0..rows).map(|n| add_key_tx(&actor, n as u64, n)).collect();
    let block = block_of(txs);
    let root = state.state_root();

    let (outcome, alloc, secs) = measure(|| executor.execute_block(&block, root, &[]));
    let statuses = outcome
        .expect("the measured block must execute")
        .into_parts()
        .0
        .receipts()
        .iter()
        .map(|r| r.status)
        .collect();
    (alloc, secs, statuses)
}

/// The allocator measures what it claims to. Not its own `#[test]`: see the
/// module header.
fn assert_the_allocator_measures_what_it_claims_to() {
    let ((), churn, _) = measure(|| {
        for _ in 0..10 {
            let v: Vec<u8> = Vec::with_capacity(1_000_000);
            std::hint::black_box(&v);
        }
    });
    assert!(churn.cumulative >= 10_000_000, "{churn:?}");
    assert!(churn.peak < 3_000_000, "churn is not footprint: {churn:?}");
    let ((), held, _) = measure(|| {
        let all: Vec<Vec<u8>> = (0..10).map(|_| Vec::with_capacity(1_000_000)).collect();
        std::hint::black_box(&all);
    });
    assert!(held.peak >= 10_000_000, "{held:?}");
    println!(
        "allocator self-check: churn {} B cumulative / {} B peak; held {} B peak",
        churn.cumulative, churn.peak, held.peak
    );
}

// ── The measurement ─────────────────────────────────────────────────────────

#[test]
fn the_per_transaction_bound_costs_less_than_the_transactions_it_checks() {
    assert_the_allocator_measures_what_it_claims_to();

    // ── 1. The happy path: a full block, every transaction inside its bound ──
    //
    // This is what the rule costs in the case that is every block: nothing is
    // refused, and the overhead is one scope opened and closed per transaction
    // plus one reversal record per staged write, held for one transaction and
    // dropped.
    let (closed, closed_secs, closed_status) =
        measure_block(None, RELEASE_MAX_TXS_PER_BLOCK, MEASURED_ROW);
    let (open, open_secs, open_status) =
        measure_block(Some(0), RELEASE_MAX_TXS_PER_BLOCK, MEASURED_ROW);

    assert!(
        closed_status.iter().all(|s| matches!(s, TxStatus::Success)),
        "the measured block must be one where NOTHING is refused, or the two \
         runs are not executing the same work"
    );
    assert_eq!(
        closed_status, open_status,
        "and the two runs must produce identical receipts, or the difference \
         between them is not the cost of the checking"
    );

    let peak_overhead = open.peak as i64 - closed.peak as i64;
    let churn_overhead = open.cumulative as i64 - closed.cumulative as i64;
    println!(
        "\n=== COST, {RELEASE_MAX_TXS_PER_BLOCK} transactions, {MEASURED_ROW} B rows, \
         nothing refused ===\n\
         \x20 gate CLOSED: {} B cumulative, PEAK LIVE {} B, largest single {} B, {:.3} s\n\
         \x20 gate OPEN:   {} B cumulative, PEAK LIVE {} B, largest single {} B, {:.3} s\n\
         \x20 overhead:    {churn_overhead} B cumulative ({:+.2}%), \
         PEAK LIVE {peak_overhead} B ({:+.2}%), wall {:+.1}% \
         = {:.0} us per transaction, against a 3,000 ms block time\n\
         \x20 NOTE: a debug build with a counting global allocator. Every extra \
         allocation the scope makes pays four atomics it would not pay in \
         release, so the wall figure is an UPPER bound on the real one and the \
         allocation figures are exact.",
        closed.cumulative,
        closed.peak,
        closed.largest,
        closed_secs,
        open.cumulative,
        open.peak,
        open.largest,
        open_secs,
        100.0 * churn_overhead as f64 / closed.cumulative as f64,
        100.0 * peak_overhead as f64 / closed.peak as f64,
        100.0 * (open_secs - closed_secs) / closed_secs,
        1e6 * (open_secs - closed_secs) / RELEASE_MAX_TXS_PER_BLOCK as f64,
    );

    // The claim: the checking is not itself the cost. Peak live is the number
    // that decides whether a validator survives, and the reversal log holds ONE
    // transaction's records at a time — never the block's — so the overhead is
    // a fraction of the block's own footprint rather than a multiple of it.
    //
    // A quarter, not a percent: this is a debug build with a counting allocator
    // on a developer machine, and a threshold tight enough to be interesting is
    // a threshold that fails for reasons that have nothing to do with the rule.
    // What it rules out is the failure that matters — an overhead that SCALES
    // with the block, which is what holding every transaction's reversal log
    // for the life of the block would produce.
    assert!(
        peak_overhead < closed.peak as i64 / 4,
        "the per-transaction bound must not cost a quarter of the peak live \
         memory of the block it is checking: {peak_overhead} B on top of {} B. \
         The likeliest cause is a reversal log that is no longer dropped per \
         transaction",
        closed.peak
    );

    // ── 2. The refusal path ─────────────────────────────────────────────────
    //
    // What a rollback costs. The whole design claim is that a rollback MOVES
    // the values it restores rather than copying them, so refusing a
    // transaction that rewrote a nine-megabyte row must not need a second
    // nine megabytes to undo.
    let (refused, refused_secs, refused_status) = measure_block(Some(0), 1, OVERSIZED_ROW);
    assert_eq!(
        refused_status,
        vec![TxStatus::Failed(TX_WRITE_SET_BOUND_RECEIPT_CODE)],
        "the oversized rewrite must be the refusal this measures"
    );
    let row_charge = 2 * OVERSIZED_ROW;
    println!(
        "\n=== COST, the REFUSAL path: one AddKey against a {OVERSIZED_ROW} B row, \
         bound {MAX_TX_WRITE_SET_BYTES} B ===\n\
         \x20 {} B cumulative, PEAK LIVE {} B, largest single {} B, {:.3} s\n\
         \x20 the refused transaction would have charged about {row_charge} B; \
         peak live is {:.2}x that, and a rollback that COPIED what it restores \
         would be at least one row higher",
        refused.cumulative,
        refused.peak,
        refused.largest,
        refused_secs,
        refused.peak as f64 / row_charge as f64,
    );
    assert!(
        refused.peak < 4 * row_charge,
        "rolling a refused transaction back must not cost a multiple of the \
         charge it was refused for. Peak live {} B against a {row_charge} B \
         charge means the reversal log is copying the values it displaces \
         instead of moving them",
        refused.peak
    );
}
