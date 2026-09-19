//! `subsystem_allocation_bound_enabled_from_height`: the oversized input is
//! refused BEFORE the allocation, and with the gate closed today's behaviour is
//! reproduced exactly.
//!
//! ACTIVATION-AUDIT rows AL-9, AL-10 and AL-11.
//!
//! # The ceiling this runs at
//!
//! `RELEASE_CEILING` here is `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES`, the
//! derived ceiling a release node runs -- read from the constant rather than
//! restated, so this file cannot drift from it -- and not the 4,096 or 8,192
//! bytes the `*_index_allocation` files used. That matters for what the
//! closed-gate half of each pair MEANS: at 8,192 bytes every one of these
//! transactions is refused by the ceiling and the measurement shows the
//! allocation happening on the way to a refusal. At the release ceiling none of
//! them is refused -- they are ADMITTED and they COMMIT -- so the allocation
//! happens on the way to a successful transaction, and the ceiling is not a
//! bound on anything an attacker has to work around.
//! `crates/state/tests/release_ceiling_allocation.rs` is the measurement; this
//! file is the remedy.
//!
//! # What each pair shows
//!
//! Every case runs the SAME transaction against the SAME seeded database twice,
//! once with the gate closed and once with it open, and reports what each
//! allocated. The closed side is the unremediated binary. The open side must
//! refuse, and must refuse having allocated ORDERS OF MAGNITUDE less -- refusing
//! after the decode would be a refusal that bounds nothing, which is the defect
//! itself wearing a gate.
//!
//! ONE `#[test]`, for the reason the other allocation files give: a counting
//! global allocator that sees another thread's allocations measures nothing.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_nft::ops::{NftBatchMintData, NftBatchMintRequest};
use sumchain_primitives::{
    Address, DocClassOperation, DocClassTxData, DocSubcode, Hash, IdentityKey, IdentityRoot,
    IdentityStatus, KeyPurpose, KeyType, NftOperation, NftTxData,
};
use sumchain_state::{
    DocClassExecutor, DocClassGates, NftExecutor, NftGates, MAX_ACCUMULATING_ROW_BYTES,
    MAX_NFT_BATCH_MINT_REQUESTS, MAX_SUBSYSTEM_PAYLOAD_BYTES,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, DocClassStore, NftCollectionData, NftStore};

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

/// The ceiling a release node runs, read from the constant the production
/// `execute_block` path reads.
const RELEASE_CEILING: u64 = sumchain_state::MAX_BLOCK_WRITE_SET_BYTES;

const IDENT: u8 = 0xE0;
const COLLECTION: [u8; 32] = [0xC0; 32];
const TS: u64 = 1_000;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// The unremediated binary: every DocClass gate closed.
const DOC_CLOSED: DocClassGates = DocClassGates::CLOSED;

/// The unremediated binary with THIS gate and no other open.
///
/// Not `DocClassGates::OPEN`: that opens four gates at once, three of which
/// change the bytes a lawful transaction writes, and a pair that differs in four
/// ways cannot attribute a difference to one of them.
const DOC_BOUND: DocClassGates = DocClassGates {
    allocation_bound: true,
    ..DocClassGates::CLOSED
};

/// The same isolation on the NFT side: `NftGates::OPEN` would also open the
/// receipt-failure rule, which changes an `Err` into a `Failed` receipt, and
/// the token-authority rules, which decide who may rewrite a token.
///
/// Spelled with `..CLOSED` rather than field by field, so that a gate added to
/// `NftGates` later leaves this fixture isolating exactly what it says it
/// isolates instead of failing to compile and inviting whoever fixes it to
/// guess. That is how it broke when the token-authority gate arrived.
const NFT_CLOSED: NftGates = NftGates::CLOSED;
const NFT_BOUND: NftGates = NftGates {
    allocation_bound: true,
    ..NftGates::CLOSED
};

// ── DocClass fixtures ───────────────────────────────────────────────────────

fn key_with_id(id: String) -> IdentityKey {
    IdentityKey {
        key_id: id,
        key_type: KeyType::Ed25519,
        public_key: [7u8; 32],
        purposes: vec![KeyPurpose::Authentication],
        added_at: TS,
        expires_at: 0,
        active: true,
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
        created_at: TS,
        updated_at: TS,
        status: IdentityStatus::Active,
        schema_hash: [0u8; 32],
    }
}

#[derive(serde::Serialize)]
struct AddKeyData {
    identity_id: [u8; 32],
    key: IdentityKey,
}

fn add_key_payload(key_id_len: usize) -> DocClassTxData {
    DocClassTxData {
        operation: DocClassOperation::AddKey,
        subcode: DocSubcode::IdentityRoot,
        data: bincode::serialize(&AddKeyData {
            identity_id: [IDENT; 32],
            key: key_with_id("k".repeat(key_id_len)),
        })
        .unwrap(),
        recipient: Address::ZERO,
    }
}

/// Commit an identity row of roughly `bytes` encoded length.
fn seed_row_of(db: &Database, controller: Address, bytes: usize) -> usize {
    let mut root = identity(controller);
    root.keys = vec![key_with_id("x".repeat(bytes))];
    DocClassStore::new(db).identity_roots().put(&root).unwrap();
    db.get(cf::DOCCLASS_IDENTITY_ROOTS, &[IDENT; 32])
        .unwrap()
        .expect("seeded")
        .len()
}

/// What one DocClass transaction did, under one set of gates.
struct DocRun {
    /// Encoded length of the row the seed committed.
    seeded: usize,
    ok: bool,
    error: Option<String>,
    alloc: Alloc,
    /// The identity row as the candidate holds it afterwards.
    row_after: Option<Vec<u8>>,
}

/// The actor. Deterministic, not `KeyPair::generate()`: the controller address
/// is part of the row, so two runs meant to be compared byte-for-byte have to be
/// the same account.
fn actor() -> KeyPair {
    KeyPair::from_bytes([0x5A; 32])
}

fn run_docclass(seed_bytes: usize, data: &DocClassTxData, gates: DocClassGates) -> DocRun {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = actor();
    fund(&db, &actor, 100_000_000_000);
    let proposer = Address::new([9; 20]);
    let seeded = seed_row_of(&db, actor.address(), seed_bytes);

    let mut overlay = ApplicationOverlay::new(&db, RELEASE_CEILING);
    let mut view = ExecutionView::new(&mut overlay);
    let (result, alloc) = measure(|| {
        DocClassExecutor::execute_with_gates(
            &mut view,
            &params(),
            &actor.address(),
            data,
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
    let row_after = view.get(cf::DOCCLASS_IDENTITY_ROOTS, &[IDENT; 32]).unwrap();
    DocRun {
        seeded,
        ok: result.success,
        error: result.error,
        alloc,
        row_after,
    }
}

// ── NFT fixtures ────────────────────────────────────────────────────────────

fn seed_collection(db: &Database, owner: &Address) {
    NftStore::new(db)
        .put_collection(
            &COLLECTION,
            &NftCollectionData {
                name: "Seeded".to_string(),
                symbol: "SEED".to_string(),
                description: "d".to_string(),
                owner: *owner,
                max_supply: 0,
                total_supply: 0,
                next_token_id: 1,
                transferable: true,
                burnable: true,
                metadata_updatable: false,
                owner_only_minting: true,
                royalty_bps: 0,
                royalty_recipient: Address::ZERO,
                base_uri: None,
                created_at: TS,
            },
        )
        .unwrap();
}

fn batch_payload(to: Address, count: usize) -> NftTxData {
    NftTxData {
        collection_id: COLLECTION,
        token_id: 0,
        operation: NftOperation::BatchMint,
        data: bincode::serialize(&NftBatchMintData {
            requests: (0..count)
                .map(|_| NftBatchMintRequest {
                    to,
                    metadata: Vec::new(),
                })
                .collect(),
        })
        .unwrap(),
    }
}

struct NftRun {
    ok: bool,
    error: Option<String>,
    alloc: Alloc,
    tokens_written: usize,
}

fn run_nft(count: usize, gates: NftGates) -> (NftRun, usize) {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = actor();
    fund(&db, &actor, 100_000_000_000);
    let proposer = Address::new([9; 20]);
    seed_collection(&db, &actor.address());
    let nft_data = batch_payload(actor.address(), count);
    let payload_len = nft_data.data.len();

    let mut overlay = ApplicationOverlay::new(&db, RELEASE_CEILING);
    let mut view = ExecutionView::new(&mut overlay);
    let (result, alloc) = measure(|| {
        NftExecutor::execute_with_gates(
            &mut view,
            &params(),
            &actor.address(),
            &nft_data,
            &proposer,
            1_000,
            TS,
            gates,
        )
    });
    let result = result.expect("neither side may make the block unexecutable");
    // How many token rows the candidate actually holds.
    let mut tokens_written = 0usize;
    for id in 1..=count as u64 {
        let mut key = COLLECTION.to_vec();
        key.extend_from_slice(&id.to_be_bytes());
        if view.get(cf::NFT_TOKENS, &key).unwrap().is_some() {
            tokens_written += 1;
        }
    }
    (
        NftRun {
            ok: result.success,
            error: result.error,
            alloc,
            tokens_written,
        },
        payload_len,
    )
}

// ── The self-check ──────────────────────────────────────────────────────────

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
fn the_allocation_bound_gate_refuses_oversized_input_before_it_is_built() {
    assert_the_allocator_measures_what_it_claims_to();
    println!(
        "\nlimits: payload {MAX_SUBSYSTEM_PAYLOAD_BYTES} B, accumulating row \
         {MAX_ACCUMULATING_ROW_BYTES} B, BatchMint {MAX_NFT_BATCH_MINT_REQUESTS} \
         requests; candidate ceiling {RELEASE_CEILING} B\n"
    );

    // ── AL-10, the payload half ─────────────────────────────────────────────
    //
    // One `AddKey` whose `key_id` is nearly a whole block long. Nothing in
    // `docclass_executor.rs` checks the length of a `key_id`, so below the gate
    // it is admitted and the row grows by its whole length in one transaction
    // for one `min_fee`.
    let seed = 1 << 20;
    let fat = add_key_payload(1_899_800);
    let closed = run_docclass(seed, &fat, DOC_CLOSED);
    let open = run_docclass(seed, &fat, DOC_BOUND);
    let seeded_len = closed.seeded;
    println!(
        "AL-10 payload: {} B payload against a ~{seeded_len} B row\n\
         \x20  gate CLOSED: success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  gate OPEN:   success={} peak {} B cumulative {} B, row is {} B after\n\
         \x20  error: {:?}",
        fat.data.len(),
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
        "closed gate reproduces today: the oversized key_id is ADMITTED"
    );
    assert!(
        closed.row_after.as_ref().unwrap().len() > 2_900_000,
        "and the row grew by the whole key_id"
    );
    assert!(!open.ok, "open gate refuses it");
    assert!(
        open.error.as_deref().unwrap().contains("payload too large"),
        "and names the payload, not something downstream: {:?}",
        open.error
    );
    assert_eq!(
        open.row_after.as_deref().map(<[u8]>::len),
        Some(open.seeded),
        "the refused transaction leaves the row byte-for-byte as it found it"
    );
    // The refusal is CHEAP. The closed side has to decode a megabyte row and
    // rebuild it around a two-megabyte string; the open side compares a length.
    assert!(
        open.alloc.peak * 4 < closed.alloc.peak,
        "the open gate must refuse having allocated far less: open peaked at {} \
         B against the closed side's {} B -- a refusal that costs as much as the \
         work it refused bounds nothing",
        open.alloc.peak,
        closed.alloc.peak
    );

    // ── AL-10 and AL-11, the row half ───────────────────────────────────────
    //
    // A row ALREADY over the limit, and a perfectly ordinary small payload. This
    // is the case the payload bound cannot reach: a row grown below the gate, or
    // grown one lawful payload at a time. The bound that catches it is the one
    // on the STORED row, checked against the bytes the view returned before they
    // reach `decode_identity_root`.
    //
    // It is also what bounds AL-11: the linear `contains`/`find` scans are
    // bounded because the list they scan is bounded, because the row is.
    let over = MAX_ACCUMULATING_ROW_BYTES * 2;
    let small = add_key_payload(4);
    let closed_row = run_docclass(over, &small, DOC_CLOSED);
    let open_row = run_docclass(over, &small, DOC_BOUND);
    println!(
        "AL-10/AL-11 row: a ~{over} B row, {} B payload\n\
         \x20  gate CLOSED: success={} peak {} B cumulative {} B\n\
         \x20  gate OPEN:   success={} peak {} B cumulative {} B\n\
         \x20  error: {:?}",
        small.data.len(),
        closed_row.ok,
        closed_row.alloc.peak,
        closed_row.alloc.cumulative,
        open_row.ok,
        open_row.alloc.peak,
        open_row.alloc.cumulative,
        open_row.error,
    );
    assert!(
        closed_row.ok,
        "closed gate reproduces today: a two-megabyte row is read, decoded, \
         appended to and re-encoded, and the release ceiling does not object"
    );
    assert!(
        closed_row.alloc.peak > 3 * over,
        "and that costs more than three times the row: {} B",
        closed_row.alloc.peak
    );
    assert!(!open_row.ok, "open gate refuses it");
    assert!(
        open_row
            .error
            .as_deref()
            .unwrap()
            .contains("too large to modify"),
        "{:?}",
        open_row.error
    );
    assert_eq!(
        open_row.row_after.as_deref().map(<[u8]>::len),
        Some(open_row.seeded),
        "the refused transaction leaves the row byte-for-byte as it found it"
    );
    // The decode never happened. The view read still copies the row out once --
    // that is one buffer of the row's own size and is not what this bounds --
    // so the ceiling for "refused before the decode" is a small multiple of the
    // row, not the four-times-plus the closed side pays.
    assert!(
        open_row.alloc.peak < 2 * over,
        "refused BEFORE the decode: peak {} B against a {over} B row. Anything \
         at or above the closed side's factor would mean the decode ran and the \
         refusal came afterwards, which is the defect with a gate on it",
        open_row.alloc.peak
    );
    assert!(
        open_row.alloc.peak * 2 < closed_row.alloc.peak,
        "open {} B, closed {} B",
        open_row.alloc.peak,
        closed_row.alloc.peak
    );

    // ── AL-9 ────────────────────────────────────────────────────────────────
    //
    // `BatchMint` rebuilds the owner index and the collection index once per
    // request, so its cost is QUADRATIC in a count the payload declares. 2,000
    // requests fit inside the payload bound, so the payload check does not reach
    // them and the count check is what has to.
    let n = 2_000;
    let (nft_closed, payload_len) = run_nft(n, NFT_CLOSED);
    let (nft_open, _) = run_nft(n, NFT_BOUND);
    println!(
        "AL-9: BatchMint of {n} requests, {payload_len} B payload (inside the \
         {MAX_SUBSYSTEM_PAYLOAD_BYTES} B payload bound)\n\
         \x20  gate CLOSED: success={} peak {} B CUMULATIVE {} B, {} token rows\n\
         \x20  gate OPEN:   success={} peak {} B CUMULATIVE {} B, {} token rows\n\
         \x20  error: {:?}",
        nft_closed.ok,
        nft_closed.alloc.peak,
        nft_closed.alloc.cumulative,
        nft_closed.tokens_written,
        nft_open.ok,
        nft_open.alloc.peak,
        nft_open.alloc.cumulative,
        nft_open.tokens_written,
        nft_open.error,
    );
    assert!(
        payload_len < MAX_SUBSYSTEM_PAYLOAD_BYTES,
        "the fixture must be inside the payload bound, or it proves the wrong \
         check: {payload_len} B"
    );
    assert!(
        nft_closed.ok,
        "closed gate reproduces today: it is admitted"
    );
    assert_eq!(nft_closed.tokens_written, n, "and every token is written");
    // Quadratic: the cumulative figure, not the peak, is where it shows. Each
    // of 2,000 requests rebuilds an index that averages 1,000 entries.
    assert!(
        nft_closed.alloc.cumulative > 50 * payload_len,
        "the work is quadratic in the declared count, so the churn dwarfs the \
         payload: {} B against a {payload_len} B payload",
        nft_closed.alloc.cumulative
    );
    assert!(!nft_open.ok, "open gate refuses it");
    assert!(
        nft_open
            .error
            .as_deref()
            .unwrap()
            .contains("exceeds the limit"),
        "{:?}",
        nft_open.error
    );
    assert_eq!(
        nft_open.tokens_written, 0,
        "and refuses BEFORE the loop, so not one token row was written"
    );
    assert!(
        nft_open.alloc.cumulative * 10 < nft_closed.alloc.cumulative,
        "open {} B, closed {} B",
        nft_open.alloc.cumulative,
        nft_closed.alloc.cumulative
    );

    // Exactly at the limit is admitted: the bound is `>`, not `>=`, and a test
    // that only checks the refusal cannot tell an off-by-one from a bound.
    let (at_limit, _) = run_nft(MAX_NFT_BATCH_MINT_REQUESTS, NFT_BOUND);
    assert!(
        at_limit.ok,
        "a batch of exactly {MAX_NFT_BATCH_MINT_REQUESTS} is admitted with the \
         gate open: {:?}",
        at_limit.error
    );
    assert_eq!(at_limit.tokens_written, MAX_NFT_BATCH_MINT_REQUESTS);

    // ── Dormant, and inert for lawful input ─────────────────────────────────
    //
    // The gate is closed in every shipped configuration...
    for h in [0u64, 1, 1_000, u64::MAX] {
        assert!(
            !DocClassGates::from_params(&ChainParams::default(), h).allocation_bound,
            "dormant at height {h} under ChainParams::default()"
        );
        assert!(
            !DocClassGates::from_params(&ChainParams::with_v2_enabled(), h).allocation_bound,
            "dormant at height {h} under ChainParams::with_v2_enabled()"
        );
    }
    // ...and opening it changes nothing for a transaction inside the limits.
    let lawful = add_key_payload(16);
    let l_closed = run_docclass(4_096, &lawful, DOC_CLOSED);
    let l_open = run_docclass(4_096, &lawful, DOC_BOUND);
    assert!(l_closed.ok && l_open.ok);
    assert_eq!(
        l_closed.row_after, l_open.row_after,
        "an in-limit transaction writes the identical row on both sides of the \
         activation -- the gate refuses oversized input and touches nothing else"
    );
    println!(
        "dormant by default; and an in-limit AddKey writes the identical {} B \
         row on both sides",
        l_open.row_after.as_ref().unwrap().len()
    );
}
