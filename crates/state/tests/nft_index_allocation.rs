//! Both nft indexes allocate their whole value BEFORE the overlay accounts for
//! it -- measured, not argued.
//!
//! `v_add_to_owner_index` and `v_add_to_collection_index` are read-modify-write:
//! they read the existing list, push one entry, and call `encode_*`, which
//! serializes the whole list into a fresh `Vec<u8>`. Only then does `view.put`
//! charge the candidate's byte ceiling. So the ceiling bounds what a block may
//! COMMIT; it does not bound what a single transaction may ALLOCATE on the way
//! to being refused.
//!
//! Both are unbounded and both grow with use: the owner index accumulates one
//! `(collection id, token id)` pair per token an address holds, and the
//! collection index accumulates one `u64` per token ever minted into a
//! collection. Neither is ever compacted -- the collection index is not even
//! shortened by a burn, which rewrites it one element shorter and leaves it a
//! list.
//!
//! This file exists separately from `nft_routing` because it installs a
//! counting global allocator, and a counting allocator is only meaningful if
//! nothing else in the binary is allocating at the same time. ONE test, run
//! alone, measuring two indexes in sequence.
//!
//! What this measures and what it does not: it measures ONE fixture size,
//! 20,000 entries, and reports the bytes actually allocated while the ceiling
//! was 4,096. It does not establish a bound for arbitrary input, and it is not
//! a fix. Capping either list would change which transactions are valid, which
//! is a consensus change and belongs in separately activated work.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_nft::ops::NftMintData;
use sumchain_primitives::{
    Address, NftOperation, NftTxData, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::NftExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, NftCollectionData, NftStore};

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
const TS: u64 = 1000;
const COLLECTION: [u8; 32] = [7u8; 32];
const ENTRIES: usize = 20_000;

const NFT_CFS: &[&str] = &[
    cf::NFT_COLLECTIONS,
    cf::NFT_TOKENS,
    cf::NFT_OWNER_INDEX,
    cf::NFT_COLLECTION_INDEX,
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in NFT_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// 20,000 owner-index entries: one per token the address already holds.
fn owner_fixture() -> Vec<(Vec<u8>, u64)> {
    (0..ENTRIES as u64)
        .map(|i| (COLLECTION.to_vec(), i + 1_000))
        .collect()
}

/// 20,000 collection-index entries: one per token ever minted here.
fn collection_fixture() -> Vec<u64> {
    (0..ENTRIES as u64).map(|i| i + 1_000).collect()
}

fn seed_collection(db: &Database, owner: &Address, next_token_id: u64) {
    NftStore::new(db)
        .put_collection(
            &COLLECTION,
            &NftCollectionData {
                name: "Seeded".to_string(),
                symbol: "SEED".to_string(),
                description: "d".to_string(),
                owner: *owner,
                max_supply: 0,
                total_supply: next_token_id - 1,
                next_token_id,
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

fn mint_tx(kp: &KeyPair) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: 0,
        payload: TxPayload::Nft(NftTxData {
            collection_id: COLLECTION,
            token_id: 0,
            operation: NftOperation::Mint,
            data: bincode::serialize(&NftMintData {
                to: kp.address(),
                metadata: Vec::new(),
                uri_type: "onchain".to_string(),
                uri_value: None,
            })
            .unwrap(),
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

/// One refusal measurement: seed `family`/`key` with `fixture`, run a mint
/// under a 4,096-byte ceiling, and report what it allocated.
///
/// Also asserts the two things a refusal has to be: canonical storage
/// byte-identical, and the candidate-visible OLD index byte-identical -- the
/// refused `put` must leave nothing behind for the merged read to find.
///
/// Each measurement is its own function because the seeding writes to the
/// database and the measuring constructs a candidate. Two of them in one body
/// puts the second seed after the first candidate, which is indistinguishable
/// -- to `no_test_publishes_a_candidate_by_hand`, and to a reader -- from a
/// fixture committing what it found in an overlay.
fn measure_refusal(family: &str, fixture: &[u8]) -> (usize, usize, u64) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    seed_collection(&db, &actor.address(), 1_000 + ENTRIES as u64);
    let key: Vec<u8> = if family == cf::NFT_OWNER_INDEX {
        actor.address().as_bytes().to_vec()
    } else {
        COLLECTION.to_vec()
    };
    db.put(family, &key, fixture).unwrap();
    let before = canonical(&db);

    let t = mint_tx(&actor);
    let mut overlay = ApplicationOverlay::new(&db, CEILING);
    // The view borrows the overlay, and the overlay has to be readable after
    // the measurement. A scope ends the borrow; `drop` would not -- an
    // `ExecutionView` is not `Drop`, so dropping it by name does nothing the
    // scope does not already do.
    let (outcome, bytes, largest) = {
        let mut view = ExecutionView::new(&mut overlay);
        let measured = measure(|| executor.execute_tx(&mut view, &t, &proposer, 1, TS));

        let err = measured.0.as_ref().err().expect("the ceiling must refuse");
        assert!(
            err.to_string().contains("limit"),
            "refused by the ceiling, not by something else: {err}"
        );
        // The candidate-visible old index is byte-identical: the refused write
        // staged nothing, so the merged read still returns the committed row.
        assert_eq!(
            view.get(family, &key).unwrap().as_deref(),
            Some(fixture),
            "{family}: the old index must be untouched in the candidate too"
        );
        measured
    };
    drop(outcome);

    assert_eq!(
        canonical(&db),
        before,
        "{family}: a refused transaction must commit nothing"
    );
    (bytes, largest, overlay.logical_bytes())
}

/// The same mint, ADMITTED, must preserve every existing entry in order.
///
/// The whole slice is compared, not a sample: an append that dropped or
/// reordered the middle of a 20,000-entry list would pass any spot check.
fn assert_an_admitted_append_preserves_every_entry(family: &str, fixture: &[u8]) {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let next_token_id = 1_000 + ENTRIES as u64;
    seed_collection(&db, &actor.address(), next_token_id);
    let key: Vec<u8> = if family == cf::NFT_OWNER_INDEX {
        actor.address().as_bytes().to_vec()
    } else {
        COLLECTION.to_vec()
    };
    db.put(family, &key, fixture).unwrap();

    let t = mint_tx(&actor);
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    if family == cf::NFT_OWNER_INDEX {
        let mut expected = owner_fixture();
        expected.push((COLLECTION.to_vec(), next_token_id));
        assert_eq!(
            NftExecutor::v_get_owner_tokens(&view, &actor.address()).unwrap(),
            expected,
            "every one of the {ENTRIES} existing entries, in order, then the new one"
        );
    } else {
        let mut expected = collection_fixture();
        expected.push(next_token_id);
        assert_eq!(
            NftExecutor::v_get_collection_tokens(&view, &COLLECTION).unwrap(),
            expected,
            "every one of the {ENTRIES} existing entries, in order, then the new one"
        );
    }
}

/// The ceiling is 4,096 bytes. Each index still allocates its entire value, and
/// more, on the way to being refused.
#[test]
fn both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses() {
    assert_the_allocator_measures_what_it_claims_to();

    let owner_bytes = bincode::serialize(&owner_fixture()).unwrap();
    let collection_bytes = bincode::serialize(&collection_fixture()).unwrap();
    assert_eq!(
        (owner_bytes.len(), collection_bytes.len()),
        (960_008, 160_008),
        "the fixtures must be exactly the sizes this test reports"
    );

    let cases = [
        ("owner index", cf::NFT_OWNER_INDEX, owner_bytes.clone()),
        (
            "collection index",
            cf::NFT_COLLECTION_INDEX,
            collection_bytes.clone(),
        ),
    ];

    for (label, family, fixture) in cases {
        let (bytes, largest, accounted) = measure_refusal(family, &fixture);
        println!(
            "{label}: {ENTRIES} entries, row {} B, ceiling {CEILING} B, \
             allocated {bytes} B during the refused transaction, largest single \
             allocation {largest} B, overlay accounted {accounted} B",
            fixture.len()
        );
        assert!(
            bytes >= fixture.len(),
            "{label}: the whole {} B value is built before the ceiling is \
             consulted; measured {bytes} B",
            fixture.len()
        );
        assert!(
            largest >= fixture.len(),
            "{label}: and it is built as one buffer, not incrementally: largest \
             single allocation {largest} B"
        );
        assert!(
            bytes as u64 > CEILING * 10,
            "{label}: the allocation is not within an order of magnitude of the \
             ceiling: {bytes} B against {CEILING} B"
        );
        assert!(
            accounted <= CEILING,
            "{label}: the overlay's accounted size stays under its own ceiling, \
             which is the point -- it bounds what may be COMMITTED, not what may \
             be allocated: {accounted} B"
        );

        assert_an_admitted_append_preserves_every_entry(family, &fixture);
    }

    println!(
        "one measured size does not prove arbitrary input is OOM-safe: neither \
         index is bounded, and nothing here establishes a bound"
    );
}
