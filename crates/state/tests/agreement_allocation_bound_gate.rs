//! `subsystem_allocation_bound_enabled_from_height`, Agreement half: an
//! accumulating index row past the limit is refused BEFORE it is decoded,
//! appended to and re-encoded.
//!
//! ACTIVATION-AUDIT row AL-5.
//!
//! # Why this reads the field DocClass and NFT read
//!
//! AL-5 is AL-10/AL-11 in a third subsystem, word for word: `v_add_to_party_index`
//! and `v_add_to_executor_index` read an accumulating row, decode the whole of
//! it, push one 32-byte id and re-encode the whole of it, and `view.put` only
//! then charges the candidate's byte ceiling. The ceiling therefore bounds what
//! a block may COMMIT and bounds nothing about what one transaction may
//! ALLOCATE.
//!
//! The field's own doc comment gives the argument for one height rather than
//! three -- one rule at one seam, and an attacker refused by the DocClass bound
//! simply uses the NFT one -- and it applies to Agreement unchanged: a party
//! index row is reachable by anyone who can commit an agreement naming that
//! party, for one `min_fee` a transaction. A partial activation would leave the
//! cheapest of the three open, and there is no configuration in which an
//! operator wants two of the three.
//!
//! # What this file shows, and what `agreement_index_allocation.rs` shows
//!
//! That file is the MEASUREMENT: it reports that the whole 640,008-byte value
//! is built before a 4,096-byte ceiling refuses the write. This file is the
//! REMEDY, run at the release ceiling (`1 << 30`) where nothing refuses the
//! write at all -- so below the gate the allocation happens on the way to a
//! transaction that SUCCEEDS, and the ceiling is not a bound an attacker has to
//! work around.
//!
//! Every case runs the SAME transaction against the SAME seeded database twice,
//! once with the gate closed -- the release configuration, and byte-for-byte
//! the unremediated binary -- and once with it open, and asserts the two nodes
//! disagree. The open side must refuse having allocated far less: a refusal
//! that costs what the work it refused costs bounds nothing, which is the
//! defect itself wearing a gate.
//!
//! ONE `#[test]`, for the reason `agreement_index_allocation.rs` gives: a
//! counting global allocator that sees another thread's allocations measures
//! nothing.
//!
//! Spelled `{ allocation_bound: true, ..CLOSED }`, never field by field, so a
//! gate added to `AgreementGates` later leaves this fixture isolating exactly
//! what it says it isolates.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::agreement::{
    AgreementCommitment, AgreementOperation, AgreementRole, AgreementStatus, AgreementTxData,
    ExecutorLink, ExecutorState, PartyBinding, PartyRef,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{AgreementExecutor, AgreementGates, MAX_ACCUMULATING_ROW_BYTES};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, AgreementStore, Database};

// ── Counting allocator ──────────────────────────────────────────────────────

static CUMULATIVE: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static RECORDING: AtomicBool = AtomicBool::new(false);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RECORDING.load(Ordering::Relaxed) {
            CUMULATIVE.fetch_add(layout.size(), Ordering::Relaxed);
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
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Alloc) {
    CUMULATIVE.store(0, Ordering::Relaxed);
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
        },
    )
}

/// `CANDIDATE_LIMIT_SCAFFOLD`, `crates/state/src/executor.rs`.
const RELEASE_CEILING: u64 = 1 << 30;

const TS: u64 = 1_000;
const PARTY: [u8; 32] = [0xA1; 32];
/// The executor contract the links name. A function, not a `const`:
/// `Address::new` is not `const fn`.
fn contract() -> Address {
    Address::new([0xCC; 20])
}

/// The unremediated binary: every Agreement gate closed.
const CLOSED: AgreementGates = AgreementGates::CLOSED;

/// The unremediated binary with THIS gate and no other open.
///
/// Not `AgreementGates::OPEN`: that also opens the real-block-timestamp rule
/// (which changes the bytes a lawful row carries), the signature-integrity
/// rules and the no-op receipt rule, and a pair that differs in four ways
/// cannot attribute a difference to one of them.
const BOUND: AgreementGates = AgreementGates {
    allocation_bound: true,
    ..AgreementGates::CLOSED
};

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The actor. Deterministic, not `KeyPair::generate()`: two runs meant to be
/// compared have to be the same account.
fn actor() -> KeyPair {
    KeyPair::from_bytes([0x5A; 32])
}

fn agreement(id: u8) -> AgreementCommitment {
    AgreementCommitment {
        agreement_id: [id; 32],
        agreement_commitment: [id.wrapping_add(1); 32],
        parties: vec![PartyBinding {
            party_ref: PartyRef::Commitment(PARTY),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        }],
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
    }
}

fn link(id: u8, agreement_id: u8) -> ExecutorLink {
    ExecutorLink {
        link_id: [id; 32],
        agreement_id: [agreement_id; 32],
        executor_contract: contract(),
        executor_interface_id: [id.wrapping_add(1); 32],
        terms_commitment: [id.wrapping_add(2); 32],
        activation_policy_id: [12u8; 32],
        state: ExecutorState::Draft,
        created_at: TS,
        updated_at: TS,
        created_at_height: 1,
        activation_proof_id: None,
    }
}

/// `n` thirty-two-byte ids, bincode-encoded: the shape both index rows hold.
fn ids(n: usize) -> Vec<u8> {
    let list: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            id
        })
        .collect();
    bincode::serialize(&list).unwrap()
}

/// What one Agreement transaction did, under one set of gates.
struct Run {
    /// Stored length of the index row the seed committed.
    seeded: usize,
    ok: bool,
    error: Option<String>,
    alloc: Alloc,
    /// The index row as the candidate holds it afterwards.
    row_after: Option<Vec<u8>>,
}

fn run(
    family: &'static str,
    key: Vec<u8>,
    seed: impl FnOnce(&Database),
    op: AgreementOperation,
    data: Vec<u8>,
    gates: AgreementGates,
) -> Run {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = actor();
    fund(&db, &actor, 100_000_000_000);
    let proposer = Address::new([9; 20]);
    seed(&db);
    let seeded = db.get(family, &key).unwrap().map_or(0, |r| r.len());

    let mut overlay = ApplicationOverlay::new(&db, RELEASE_CEILING);
    let mut view = ExecutionView::new(&mut overlay);
    let (result, alloc) = measure(|| {
        AgreementExecutor::execute_with_gates(
            &mut view,
            &actor.address(),
            &AgreementTxData {
                operation: op,
                data,
                recipient: Address::ZERO,
            },
            &proposer,
            1_000,
            1,
            TS,
            0,
            Hash::ZERO,
            gates,
        )
    });
    let result = result.expect("neither side may make the block unexecutable");
    let row_after = view.get(family, &key).unwrap();
    Run {
        seeded,
        ok: result.success,
        error: result.error,
        alloc,
        row_after,
    }
}

fn assert_the_allocator_measures_what_it_claims_to() {
    let ((), a) = measure(|| {
        let v: Vec<u8> = Vec::with_capacity(4_000_000);
        std::hint::black_box(&v);
    });
    assert!(
        a.cumulative >= 4_000_000 && a.peak >= 4_000_000,
        "a deliberate 4 MB allocation must be seen: {a:?}"
    );
    let ((), quiet) = measure(|| {});
    assert_eq!(quiet.cumulative, 0, "an empty window must measure zero");
}

// ── The test ────────────────────────────────────────────────────────────────

#[test]
fn the_allocation_bound_gate_refuses_an_oversized_agreement_index_row() {
    assert_the_allocator_measures_what_it_claims_to();
    println!("\nlimit: accumulating row {MAX_ACCUMULATING_ROW_BYTES} B; candidate ceiling {RELEASE_CEILING} B\n");

    // A row already twice the limit, and a perfectly ordinary commitment. This
    // is the case the payload bound cannot reach: the row was grown one lawful
    // payload at a time, by anyone willing to name this party.
    let fat = ids(70_000);
    assert!(
        fat.len() > 2 * MAX_ACCUMULATING_ROW_BYTES,
        "the fixture must be comfortably over the limit, so that the gate is \
         what refuses it and not a rounding error: {} B against {} B",
        fat.len(),
        MAX_ACCUMULATING_ROW_BYTES
    );

    // ── The party index ─────────────────────────────────────────────────────

    let party_key = PARTY.to_vec();
    let commit = bincode::serialize(&agreement(0x10)).unwrap();
    let seed_party = |bytes: Vec<u8>| {
        move |db: &Database| {
            db.put(cf::AGREEMENT_PARTY_INDEX, &PARTY, &bytes).unwrap();
        }
    };

    let closed = run(
        cf::AGREEMENT_PARTY_INDEX,
        party_key.clone(),
        seed_party(fat.clone()),
        AgreementOperation::CommitAgreement,
        commit.clone(),
        CLOSED,
    );
    let open = run(
        cf::AGREEMENT_PARTY_INDEX,
        party_key.clone(),
        seed_party(fat.clone()),
        AgreementOperation::CommitAgreement,
        commit.clone(),
        BOUND,
    );
    println!(
        "AL-5 party index: a {} B row, one CommitAgreement naming that party\n\
         \x20  gate CLOSED: success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  gate OPEN:   success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  error: {:?}",
        closed.seeded,
        closed.ok,
        closed.alloc.peak,
        closed.alloc.cumulative,
        closed.row_after.as_ref().map_or(0, |r| r.len()),
        open.ok,
        open.alloc.peak,
        open.alloc.cumulative,
        open.row_after.as_ref().map_or(0, |r| r.len()),
        open.error,
    );
    assert!(
        closed.ok,
        "closed gate reproduces today: a two-megabyte index row is read, \
         decoded, appended to and re-encoded, and the 1 GiB ceiling does not \
         object"
    );
    assert!(
        closed.row_after.as_ref().unwrap().len() > closed.seeded,
        "and the row grew"
    );
    assert!(!open.ok, "open gate refuses it");
    assert_eq!(
        open.error.as_deref(),
        Some(
            format!(
                "Agreement party index too large to modify: {} bytes, limit \
                 {MAX_ACCUMULATING_ROW_BYTES}",
                open.seeded
            )
            .as_str()
        ),
        "and names the family and the length, because the remedy is not retry"
    );
    assert_eq!(
        open.row_after.as_deref().map(<[u8]>::len),
        Some(open.seeded),
        "the refused transaction leaves the row byte-for-byte as it found it"
    );
    assert!(
        open.alloc.peak * 2 < closed.alloc.peak,
        "the open gate must refuse having allocated far less: open peaked at {} \
         B against the closed side's {} B",
        open.alloc.peak,
        closed.alloc.peak
    );

    // ── The executor index ──────────────────────────────────────────────────

    let exec_key = contract().as_ref().to_vec();
    let link_payload = bincode::serialize(&link(0xF1, 0x11)).unwrap();
    let seed_exec = |bytes: Vec<u8>| {
        move |db: &Database| {
            AgreementStore::new(db)
                .agreements()
                .put(&agreement(0x11))
                .unwrap();
            db.put(cf::AGREEMENT_EXECUTOR_INDEX, contract().as_ref(), &bytes)
                .unwrap();
        }
    };

    let closed_x = run(
        cf::AGREEMENT_EXECUTOR_INDEX,
        exec_key.clone(),
        seed_exec(fat.clone()),
        AgreementOperation::LinkExecutor,
        link_payload.clone(),
        CLOSED,
    );
    let open_x = run(
        cf::AGREEMENT_EXECUTOR_INDEX,
        exec_key.clone(),
        seed_exec(fat.clone()),
        AgreementOperation::LinkExecutor,
        link_payload.clone(),
        BOUND,
    );
    println!(
        "AL-5 executor index: a {} B row, one LinkExecutor naming that contract\n\
         \x20  gate CLOSED: success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  gate OPEN:   success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  error: {:?}",
        closed_x.seeded,
        closed_x.ok,
        closed_x.alloc.peak,
        closed_x.alloc.cumulative,
        closed_x.row_after.as_ref().map_or(0, |r| r.len()),
        open_x.ok,
        open_x.alloc.peak,
        open_x.alloc.cumulative,
        open_x.row_after.as_ref().map_or(0, |r| r.len()),
        open_x.error,
    );
    assert!(closed_x.ok, "closed gate reproduces today");
    assert!(
        closed_x.row_after.as_ref().unwrap().len() > closed_x.seeded,
        "and the row grew"
    );
    assert!(!open_x.ok, "open gate refuses it");
    assert_eq!(
        open_x.error.as_deref(),
        Some(
            format!(
                "Agreement executor index too large to modify: {} bytes, limit \
                 {MAX_ACCUMULATING_ROW_BYTES}",
                open_x.seeded
            )
            .as_str()
        ),
        "and names the OTHER family, so the two refusals cannot be confused"
    );
    assert_eq!(
        open_x.row_after.as_deref().map(<[u8]>::len),
        Some(open_x.seeded),
        "the refused transaction leaves the row byte-for-byte as it found it"
    );
    assert!(
        open_x.alloc.peak * 2 < closed_x.alloc.peak,
        "open peaked at {} B against the closed side's {} B",
        open_x.alloc.peak,
        closed_x.alloc.peak
    );

    // ── A row INSIDE the bound is untouched by the gate ──────────────────────
    //
    // The gate refuses an oversized row, not the operation. Without this the
    // whole pair above is satisfied by an "open" side that refuses everything.
    let small = ids(10);
    assert!(small.len() < MAX_ACCUMULATING_ROW_BYTES);
    for (label, gates) in [("CLOSED", CLOSED), ("OPEN", BOUND)] {
        let lawful = run(
            cf::AGREEMENT_PARTY_INDEX,
            party_key.clone(),
            seed_party(small.clone()),
            AgreementOperation::CommitAgreement,
            commit.clone(),
            gates,
        );
        assert!(
            lawful.ok,
            "a {} B party-index row is appended to on both sides ({label}): {:?}",
            lawful.seeded, lawful.error
        );
        assert!(
            lawful.row_after.unwrap().len() > lawful.seeded,
            "and the append actually happened ({label})"
        );
    }
}
