//! SUM-721 NFTs execute against the block's candidate.
//!
//! Real signed transactions through `BlockExecutor`, in sequence, in one block.
//!
//! ## Why this subsystem's reads had to move with its writes
//!
//! NFTs are ownership state, and every guard is a read of the row it is about
//! to write. `execute_transfer` reads the token, checks `token.owner ==
//! sender`, and writes a new owner. Against committed state that check answers
//! about the row the BLOCK started with, and two things follow, in opposite
//! directions:
//!
//!   * A chain cannot form. `mint -> A`, `A -> B`, `B -> C` in one block: the
//!     third transaction would find `A` still recorded as owner and refuse `B`.
//!     -- `a_chain_of_transfers_in_one_block_reaches_the_last_owner`
//!   * The same token could be moved TWICE. `A -> B` and then `A -> C` in one
//!     block would both pass the ownership guard, because the second read would
//!     still show `A`.
//!     -- `the_same_token_cannot_be_transferred_twice_in_one_block`
//!
//! Every claim of that shape here has a DISCRIMINATOR: the same later
//! transaction without the earlier one, which must fail or observe parent
//! state. A same-block test that passes whether or not the candidate is
//! consulted proves nothing.
//!
//! The counters have the same shape. `execute_mint` reads `next_token_id` and
//! `total_supply` off the collection and writes both back, so two mints in one
//! block mint the same token id unless the second sees the first. Both indexes
//! are accumulating lists appended by read-modify-write, so a second token for
//! one owner overwrites the first one's list with a single-element one.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::{CollectionConfig, CollectionId};
use sumchain_nft::ops::{
    CreateCollectionData, NftApproveData, NftBatchMintData, NftBatchMintRequest, NftMintData,
    NftTransferCollectionOwnershipData, NftTransferData, NftUpdateCollectionConfigData,
};
use sumchain_primitives::{
    Address, NftOperation, NftTxData, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{NftExecutor, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, IssuerData, IssuerStore, NftCollectionData, NftStore};

/// Every family this unit moved. Four.
///
/// `ISSUER_REGISTRY` is NOT here: execution only reads it, and
/// `no_block_writes_the_issuer_registry` is what says so.
const NFT_CFS: &[&str] = &[
    cf::NFT_COLLECTIONS,
    cf::NFT_TOKENS,
    cf::NFT_OWNER_INDEX,
    cf::NFT_COLLECTION_INDEX,
];

/// The block timestamp every test here executes under.
///
/// It is also the collection-id nonce, which is why it is a named constant --
/// see `the_block_timestamp_is_the_only_nonce_in_a_collection_id`.
const TS: u64 = 1000;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn nft_tx(
    kp: &KeyPair,
    nonce: u64,
    fee: u128,
    collection_id: [u8; 32],
    token_id: u64,
    operation: NftOperation,
    data: Vec<u8>,
) -> SignedTransaction {
    let t = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::Nft(NftTxData {
            collection_id,
            token_id,
            operation,
            data,
        }),
    };
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn create_payload(name: &str, config: CollectionConfig) -> Vec<u8> {
    bincode::serialize(&CreateCollectionData {
        name: name.to_string(),
        symbol: "SYM".to_string(),
        description: "d".to_string(),
        config,
        base_uri: None,
    })
    .unwrap()
}

fn mint_payload(to: Address) -> Vec<u8> {
    bincode::serialize(&NftMintData {
        to,
        metadata: Vec::new(),
        uri_type: "onchain".to_string(),
        uri_value: None,
    })
    .unwrap()
}

fn transfer_payload(to: Address) -> Vec<u8> {
    bincode::serialize(&NftTransferData { to }).unwrap()
}

fn approve_payload(approved: Option<Address>) -> Vec<u8> {
    bincode::serialize(&NftApproveData { approved }).unwrap()
}

/// The collection id a `CreateCollection` at `TS` will produce.
fn collection_id_of(creator: &Address, name: &str) -> [u8; 32] {
    *CollectionId::new(creator, name, TS).as_bytes()
}

/// The 40-byte token key, written by hand rather than through the builder.
fn token_key(collection_id: &[u8; 32], token_id: u64) -> Vec<u8> {
    let mut k = collection_id.to_vec();
    k.extend_from_slice(&token_id.to_be_bytes());
    k
}

fn transferable() -> CollectionConfig {
    CollectionConfig {
        owner_only_minting: true,
        transferable: true,
        burnable: true,
        ..Default::default()
    }
}

/// A committed collection, the parent state a block starts from.
fn seed_collection(db: &Database, owner: &Address, id: &[u8; 32], config: &CollectionConfig) {
    NftStore::new(db)
        .put_collection(
            id,
            &NftCollectionData {
                name: "Seeded".to_string(),
                symbol: "SEED".to_string(),
                description: "d".to_string(),
                owner: *owner,
                max_supply: config.max_supply,
                total_supply: 0,
                next_token_id: 1,
                transferable: config.transferable,
                burnable: config.burnable,
                metadata_updatable: config.metadata_updatable,
                owner_only_minting: config.owner_only_minting,
                royalty_bps: config.royalty_bps,
                royalty_recipient: config.royalty_recipient,
                base_uri: None,
                created_at: TS,
            },
        )
        .unwrap();
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

/// Families whose CANDIDATE contents differ from the committed ones.
///
/// A real per-CF diff, not a presence check: `prefix_iter` on a view is MERGED
/// with committed state, so presence proves nothing about what this block did.
fn families_changed(db: &Database, view: &ExecutionView<'_, '_>) -> Vec<&'static str> {
    let mut out = Vec::new();
    for f in NFT_CFS {
        let committed: Vec<(Vec<u8>, Vec<u8>)> = db
            .prefix_iter(f, &[])
            .unwrap()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let staged: Vec<(Vec<u8>, Vec<u8>)> = view
            .prefix_iter(f, &[])
            .unwrap()
            .map(|r| {
                let (k, v) = r.unwrap();
                (k.to_vec(), v.to_vec())
            })
            .collect();
        if committed != staged {
            out.push(*f);
        }
    }
    out
}

fn owner_ids(view: &ExecutionView<'_, '_>, who: &Address) -> Vec<(Vec<u8>, u64)> {
    NftExecutor::v_get_owner_tokens(view, who).unwrap()
}

// ── Ownership chains: the sharpest same-block case ───────────────────────────

/// `mint -> A`, `A -> B`, `B -> C`, all in one block.
///
/// The third transaction's ownership guard reads the SECOND one's write. It can
/// only see it in the candidate.
#[test]
fn a_chain_of_transfers_in_one_block_reaches_the_last_owner() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let c = Address::new([0xCC; 20]);
    for kp in [&creator, &a, &b] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Chain");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (kp, nonce, op, token, data) in [
        (
            &creator,
            0u64,
            NftOperation::CreateCollection,
            0u64,
            create_payload("Chain", transferable()),
        ),
        (
            &creator,
            1,
            NftOperation::Mint,
            0,
            mint_payload(a.address()),
        ),
        (
            &a,
            0,
            NftOperation::Transfer,
            1,
            transfer_payload(b.address()),
        ),
        (&b, 0, NftOperation::Transfer, 1, transfer_payload(c)),
    ] {
        let t = nft_tx(kp, nonce, 100, cid, token, op, data);
        let r = executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap();
        assert!(
            matches!(r.status, TxStatus::Success),
            "{op:?} from nonce {nonce}: {:?}",
            r.status
        );
    }

    let token = NftExecutor::v_get_token(&view, &cid, 1).unwrap().unwrap();
    assert_eq!(
        token.owner, c,
        "the token must end on the third owner -- a committed read would have \
         refused the second transfer"
    );
    assert_eq!(token.transfer_count, 2, "both transfers counted");
    assert_eq!(token.approved, None);

    // Every owner list agrees with the row, in the same candidate.
    assert_eq!(owner_ids(&view, &a.address()), Vec::new());
    assert_eq!(owner_ids(&view, &b.address()), Vec::new());
    assert_eq!(owner_ids(&view, &c), vec![(cid.to_vec(), 1u64)]);
}

/// Without the first transfer, the second is refused.
///
/// The discriminator for the test above: it would pass if transfers simply
/// never checked ownership.
#[test]
fn without_the_first_transfer_the_second_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let c = Address::new([0xCC; 20]);
    for kp in [&creator, &a, &b] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Chain");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (kp, nonce, op, data) in [
        (
            &creator,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Chain", transferable()),
        ),
        (&creator, 1, NftOperation::Mint, mint_payload(a.address())),
    ] {
        let t = nft_tx(kp, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    // `A -> B` is NOT executed. `B -> C` must now fail.
    let t = nft_tx(
        &b,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(c),
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, TS)
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(2),
        "without the transfer that made B the owner, B may not move the token"
    );
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        a.address(),
        "and the token stays with A"
    );
    assert_eq!(owner_ids(&view, &c), Vec::new());
}

/// One token cannot be transferred twice in a block by the same owner.
///
/// This is the direction that matters for consensus: against committed state
/// BOTH transactions would pass the ownership guard, the token would land on
/// the last recipient, and every earlier recipient would hold a receipt saying
/// the transfer succeeded.
#[test]
fn the_same_token_cannot_be_transferred_twice_in_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let a = KeyPair::generate();
    let b = Address::new([0xB0; 20]);
    let c = Address::new([0xC0; 20]);
    for kp in [&creator, &a] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Double");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (kp, nonce, op, data) in [
        (
            &creator,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Double", transferable()),
        ),
        (&creator, 1, NftOperation::Mint, mint_payload(a.address())),
    ] {
        let t = nft_tx(kp, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let first = nft_tx(
        &a,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(b),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &first, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    let second = nft_tx(
        &a,
        1,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(c),
    );
    let r = executor
        .execute_tx(&mut view, &second, &proposer, 1, TS)
        .unwrap();
    assert_eq!(
        r.status,
        TxStatus::Failed(2),
        "A no longer owns the token in this block's candidate"
    );

    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        b,
        "the token is where the first transfer put it"
    );
    assert_eq!(owner_ids(&view, &b), vec![(cid.to_vec(), 1u64)]);
    assert_eq!(owner_ids(&view, &c), Vec::new());
}

/// The discriminator: the SECOND transfer, without the first, succeeds.
///
/// So the refusal above is about the candidate and not about the transaction.
#[test]
fn without_the_first_transfer_the_second_one_succeeds() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let a = KeyPair::generate();
    let c = Address::new([0xC0; 20]);
    for kp in [&creator, &a] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Double");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (kp, nonce, op, data) in [
        (
            &creator,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Double", transferable()),
        ),
        (&creator, 1, NftOperation::Mint, mint_payload(a.address())),
    ] {
        let t = nft_tx(kp, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    // Nonce 0, because the transfer that would have used it never ran.
    let second = nft_tx(
        &a,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(c),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &second, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        c
    );
}

// ── The mint counters, and both indexes ──────────────────────────────────────

/// Two mints in one block get 1 and 2, and the owner list holds both.
#[test]
fn two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let owner = Address::new([0xA0; 20]);
    let cid = collection_id_of(&creator.address(), "Counter");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let t = nft_tx(
        &creator,
        0,
        100,
        cid,
        0,
        NftOperation::CreateCollection,
        create_payload("Counter", transferable()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    for nonce in 1..=2u64 {
        let t = nft_tx(
            &creator,
            nonce,
            100,
            cid,
            0,
            NftOperation::Mint,
            mint_payload(owner),
        );
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert!(
        NftExecutor::v_get_token(&view, &cid, 1).unwrap().is_some(),
        "token 1"
    );
    assert!(
        NftExecutor::v_get_token(&view, &cid, 2).unwrap().is_some(),
        "token 2 -- the second mint read the next_token_id the first wrote"
    );
    let collection = NftExecutor::v_get_collection(&view, &cid).unwrap().unwrap();
    assert_eq!((collection.total_supply, collection.next_token_id), (2, 3));

    // Both indexes accumulate rather than being overwritten with a
    // single-element list.
    assert_eq!(
        owner_ids(&view, &owner),
        vec![(cid.to_vec(), 1u64), (cid.to_vec(), 2u64)],
        "the owner list holds BOTH tokens, in mint order"
    );
    assert_eq!(
        NftExecutor::v_get_collection_tokens(&view, &cid).unwrap(),
        vec![1, 2],
        "and so does the collection list"
    );
}

/// Without the first mint, the second mint is token ONE.
///
/// The discriminator: the test above would pass if ids were allocated from
/// anything other than the collection row.
#[test]
fn without_the_first_mint_the_second_is_token_one() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let owner = Address::new([0xA0; 20]);
    let cid = collection_id_of(&creator.address(), "Counter");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            NftOperation::CreateCollection,
            create_payload("Counter", transferable()),
        ),
        (1, NftOperation::Mint, mint_payload(owner)),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert!(NftExecutor::v_get_token(&view, &cid, 2).unwrap().is_none());
    let collection = NftExecutor::v_get_collection(&view, &cid).unwrap().unwrap();
    assert_eq!((collection.total_supply, collection.next_token_id), (1, 2));
    assert_eq!(owner_ids(&view, &owner), vec![(cid.to_vec(), 1u64)]);
    assert_eq!(
        NftExecutor::v_get_collection_tokens(&view, &cid).unwrap(),
        vec![1]
    );
}

/// `max_supply` is counted against the candidate.
#[test]
fn max_supply_is_reached_within_one_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let owner = Address::new([0xA0; 20]);
    let config = CollectionConfig {
        max_supply: 2,
        ..transferable()
    };
    let cid = collection_id_of(&creator.address(), "Limited");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let t = nft_tx(
        &creator,
        0,
        100,
        cid,
        0,
        NftOperation::CreateCollection,
        create_payload("Limited", config),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    let statuses: Vec<TxStatus> = (1..=3u64)
        .map(|nonce| {
            let t = nft_tx(
                &creator,
                nonce,
                100,
                cid,
                0,
                NftOperation::Mint,
                mint_payload(owner),
            );
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status
        })
        .collect();
    assert_eq!(
        statuses,
        vec![TxStatus::Success, TxStatus::Success, TxStatus::Failed(2)],
        "the third mint is refused by a supply counter that only moves in the \
         candidate -- against committed state all three would see supply 0"
    );
    assert_eq!(
        NftExecutor::v_get_collection(&view, &cid)
            .unwrap()
            .unwrap()
            .total_supply,
        2
    );
}

// ── Duplicate guards ─────────────────────────────────────────────────────────

/// A second collection with the same creator, name and block timestamp is
/// refused by a guard that reads the candidate.
#[test]
fn a_duplicate_collection_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Dup");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let first = nft_tx(
        &creator,
        0,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload("Dup", transferable()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &first, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    let second = nft_tx(
        &creator,
        1,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload("Dup", transferable()),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &second, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2),
        "the second creation collides with the first, which is only visible in \
         the candidate"
    );

    // A DIFFERENT name is a different id and is not refused: the guard is about
    // the id, not about the operation.
    let other = nft_tx(
        &creator,
        2,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload("Other", transferable()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &other, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert!(NftExecutor::v_collection_exists(&view, &cid).unwrap());
    assert!(NftExecutor::v_collection_exists(
        &view,
        &collection_id_of(&creator.address(), "Other")
    )
    .unwrap());
}

/// The discriminator: alone, that second transaction creates the collection.
#[test]
fn without_the_first_creation_the_same_collection_is_created() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Dup");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let only = nft_tx(
        &creator,
        0,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload("Dup", transferable()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &only, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert!(NftExecutor::v_collection_exists(&view, &cid).unwrap());
}

// ── Approvals ────────────────────────────────────────────────────────────────

/// An approval granted earlier in the block lets the approved address transfer.
#[test]
fn an_approval_in_one_block_lets_the_approved_address_transfer_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let spender = KeyPair::generate();
    let dest = Address::new([0xDE; 20]);
    for kp in [&creator, &spender] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Approve");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            NftOperation::CreateCollection,
            create_payload("Approve", transferable()),
        ),
        (1, NftOperation::Mint, mint_payload(creator.address())),
        (
            2,
            NftOperation::Approve,
            approve_payload(Some(spender.address())),
        ),
    ] {
        let t = nft_tx(
            &creator,
            nonce,
            100,
            cid,
            if nonce == 2 { 1 } else { 0 },
            op,
            data,
        );
        assert!(
            matches!(
                executor
                    .execute_tx(&mut view, &t, &proposer, 1, TS)
                    .unwrap()
                    .status,
                TxStatus::Success
            ),
            "{op:?}"
        );
    }

    let t = nft_tx(
        &spender,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(dest),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    let token = NftExecutor::v_get_token(&view, &cid, 1).unwrap().unwrap();
    assert_eq!(token.owner, dest);
    assert_eq!(
        token.approved, None,
        "and the transfer clears the approval it used"
    );
}

/// Without the approval, the same transfer is refused.
#[test]
fn without_the_approval_the_same_transfer_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let spender = KeyPair::generate();
    let dest = Address::new([0xDE; 20]);
    for kp in [&creator, &spender] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Approve");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            NftOperation::CreateCollection,
            create_payload("Approve", transferable()),
        ),
        (1, NftOperation::Mint, mint_payload(creator.address())),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let t = nft_tx(
        &spender,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(dest),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2),
        "an unapproved address may not move the token"
    );
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        creator.address()
    );
}

/// A lock staged earlier in the block stops a transfer later in it.
#[test]
fn a_lock_in_one_block_stops_a_transfer_in_the_same_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let dest = Address::new([0xDE; 20]);
    let cid = collection_id_of(&creator.address(), "Lock");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Lock", transferable()),
        ),
        (1, 0, NftOperation::Mint, mint_payload(creator.address())),
        (2, 1, NftOperation::LockToken, Vec::new()),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let t = nft_tx(
        &creator,
        3,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(dest),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2),
        "the lock is only visible in the candidate"
    );

    // And unlocking in the same block lets it move again.
    let t = nft_tx(
        &creator,
        4,
        100,
        cid,
        1,
        NftOperation::UnlockToken,
        Vec::new(),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    let t = nft_tx(
        &creator,
        5,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(dest),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        dest
    );
}

/// Without the lock, that transfer succeeds.
#[test]
fn without_the_lock_the_same_transfer_succeeds() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let dest = Address::new([0xDE; 20]);
    let cid = collection_id_of(&creator.address(), "Lock");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (
            0u64,
            NftOperation::CreateCollection,
            create_payload("Lock", transferable()),
        ),
        (1, NftOperation::Mint, mint_payload(creator.address())),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let t = nft_tx(
        &creator,
        2,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(dest),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
}

// ── The mirror pairs, burned ─────────────────────────────────────────────────

/// A mint and a burn in one block leave the row, both indexes and the supply
/// agreeing with each other.
#[test]
fn a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Burn");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Burn", transferable()),
        ),
        (1, 0, NftOperation::Mint, mint_payload(creator.address())),
        (2, 0, NftOperation::Mint, mint_payload(creator.address())),
        (3, 1, NftOperation::Burn, Vec::new()),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(
            matches!(
                executor
                    .execute_tx(&mut view, &t, &proposer, 1, TS)
                    .unwrap()
                    .status,
                TxStatus::Success
            ),
            "{op:?} at nonce {nonce}"
        );
    }

    assert!(
        NftExecutor::v_get_token(&view, &cid, 1).unwrap().is_none(),
        "the burned token row is gone"
    );
    assert!(NftExecutor::v_get_token(&view, &cid, 2).unwrap().is_some());
    assert_eq!(
        owner_ids(&view, &creator.address()),
        vec![(cid.to_vec(), 2u64)],
        "the owner list loses exactly the burned entry and keeps the other"
    );
    assert_eq!(
        NftExecutor::v_get_collection_tokens(&view, &cid).unwrap(),
        vec![2],
        "and so does the collection list"
    );
    let collection = NftExecutor::v_get_collection(&view, &cid).unwrap().unwrap();
    assert_eq!(
        (collection.total_supply, collection.next_token_id),
        (1, 3),
        "the burn decrements the supply the mints wrote; next_token_id never \
         goes back"
    );
}

/// Burning the last token empties the owner list -- which DELETES its row --
/// and empties the collection list, which WRITES an empty one.
#[test]
fn burning_the_last_token_deletes_one_index_row_and_writes_the_other_empty() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Last");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::CreateCollection,
            create_payload("Last", transferable()),
        ),
        (1, 0, NftOperation::Mint, mint_payload(creator.address())),
        (2, 1, NftOperation::Burn, Vec::new()),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert_eq!(
        view.get(cf::NFT_OWNER_INDEX, creator.address().as_bytes())
            .unwrap(),
        None,
        "the owner row is DELETED, not written empty"
    );
    let empty: Vec<u64> = Vec::new();
    assert_eq!(
        view.get(cf::NFT_COLLECTION_INDEX, &cid).unwrap().as_deref(),
        Some(&bincode::serialize(&empty).unwrap()[..]),
        "and the collection row is written as an EMPTY list -- the asymmetry is \
         inherited and reproduced"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// Transactions that between them write all FOUR nft families.
fn a_block_touching_every_family(creator: &KeyPair, name: &str) -> Vec<SignedTransaction> {
    let cid = collection_id_of(&creator.address(), name);
    vec![
        // collections
        nft_tx(
            creator,
            0,
            100,
            [0u8; 32],
            0,
            NftOperation::CreateCollection,
            create_payload(name, transferable()),
        ),
        // tokens + owner index + collection index, and the collection again
        nft_tx(
            creator,
            1,
            100,
            cid,
            0,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        nft_tx(
            creator,
            2,
            100,
            cid,
            0,
            NftOperation::BatchMint,
            bincode::serialize(&NftBatchMintData {
                requests: vec![NftBatchMintRequest {
                    to: Address::new([0xB1; 20]),
                    metadata: vec![1, 2, 3],
                }],
            })
            .unwrap(),
        ),
        nft_tx(
            creator,
            3,
            100,
            cid,
            1,
            NftOperation::Approve,
            approve_payload(Some(Address::new([0xAB; 20]))),
        ),
        nft_tx(
            creator,
            4,
            100,
            cid,
            1,
            NftOperation::Transfer,
            transfer_payload(Address::new([0xB1; 20])),
        ),
    ]
}

/// A block writing every nft family commits none of it.
#[test]
fn an_abandoned_block_leaves_all_four_families_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 500_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for t in a_block_touching_every_family(&creator, "Abandon") {
            let r = executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "{:?}", r.status);
        }

        let touched = families_changed(&db, &view);
        for f in NFT_CFS {
            assert!(
                touched.contains(f),
                "{f} was not staged, so this block does not test it"
            );
        }
        // dropped without publication
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every nft row byte-identical"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A refusal leaves canonical storage untouched, and at least one ceiling
/// refuses with the token staged and its owner-index entry not.
///
/// `Mint` is the operation to calibrate against: it writes the token row, then
/// the owner index, then the collection index, then the collection. Every
/// ceiling below the measured cost is tried, not a sample, and the whole write
/// ORDER is asserted as a chain of implications -- each row may be staged only
/// if the one before it is.
///
/// Staging is read from `ExecutionView::preimage`, which answers "did THIS
/// block write this key". A merged point read cannot: the collection row is
/// canonically present, and a mint that rewrote it with the bytes it already
/// held would be invisible to a content comparison. It is not invisible here.
#[test]
fn a_refusal_part_way_leaves_canonical_storage_untouched() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 500_000_000);
    let proposer = Address::new([9; 20]);
    let owner = Address::new([0xA0; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &transferable());
    let before = canonical(&db);

    let signed_tx = nft_tx(
        &creator,
        0,
        100,
        cid,
        0,
        NftOperation::Mint,
        mint_payload(owner),
    );

    assert!(
        db.prefix_iter(cf::NFT_TOKENS, &[])
            .unwrap()
            .next()
            .is_none()
            && db
                .prefix_iter(cf::NFT_OWNER_INDEX, &[])
                .unwrap()
                .next()
                .is_none()
            && db
                .prefix_iter(cf::NFT_COLLECTION_INDEX, &[])
                .unwrap()
                .next()
                .is_none()
            && db.prefix_iter(cf::NFT_COLLECTIONS, &[]).unwrap().count() == 1,
        "the fixture is one seeded collection and nothing else"
    );

    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut v = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut v, &signed_tx, &proposer, 1, TS)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "a mint must cost something");

    let mut partials = 0usize;
    for ceiling in 1..full {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &signed_tx, &proposer, 1, TS);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        assert!(
            outcome.unwrap_err().to_string().contains("limit"),
            "ceiling {ceiling} must fail because a WRITE was refused"
        );

        let token_staged = view.preimage(cf::NFT_TOKENS, &token_key(&cid, 1)).is_some();
        let owner_staged = view
            .preimage(cf::NFT_OWNER_INDEX, owner.as_bytes())
            .is_some();
        let collection_index_staged = view.preimage(cf::NFT_COLLECTION_INDEX, &cid).is_some();
        let collection_staged = view.preimage(cf::NFT_COLLECTIONS, &cid).is_some();

        if token_staged && !owner_staged {
            partials += 1;
        }
        assert!(
            !owner_staged || token_staged,
            "ceiling {ceiling} staged the owner index without the token, which \
             the write order cannot produce"
        );
        assert!(
            !collection_index_staged || owner_staged,
            "ceiling {ceiling} staged the collection index without the owner \
             index, which the write order cannot produce"
        );
        assert!(
            !collection_staged || collection_index_staged,
            "ceiling {ceiling} staged the collection row before the collection \
             index, which the write order cannot produce"
        );
        assert_eq!(
            canonical(&db),
            before,
            "ceiling {ceiling} must commit nothing"
        );
    }
    assert!(
        partials > 0,
        "no ceiling refused with the token staged and its owner index not"
    );
}

// ── Parity, including a restart ──────────────────────────────────────────────

/// Published rows satisfy the committed readers AND survive a restart.
#[test]
fn published_nft_rows_survive_a_database_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let creator = KeyPair::generate();
    let cid = collection_id_of(&creator.address(), "Restart");

    let expected: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let state = std::sync::Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let executor =
            sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params());
        fund(&db, &creator, 500_000_000);

        let receipts = common::publish_block(
            &state,
            &executor,
            1,
            &[3u8; 32],
            a_block_touching_every_family(&creator, "Restart"),
            &[],
        );
        assert_eq!(receipts.len(), 5);
        assert!(
            receipts
                .iter()
                .all(|r| matches!(r.status, TxStatus::Success)),
            "all five must succeed: {:?}",
            receipts.iter().map(|r| r.status).collect::<Vec<_>>()
        );

        let rows = canonical(&db);
        for f in NFT_CFS {
            assert!(
                rows.iter().any(|(fam, _, _)| fam == f),
                "{f} carries no committed row, so the restart proves nothing about it"
            );
        }

        assert_committed_readers_resolve(&db, cid, creator.address());

        drop(executor);
        drop(state);
        assert_eq!(
            std::sync::Arc::strong_count(&db),
            1,
            "nothing else may hold the database, or the drop below does not \
             actually close it and this test proves nothing about durability"
        );
        drop(db);
        rows
    };

    let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
    assert_eq!(
        canonical(&db),
        expected,
        "every nft row must survive the restart, byte for byte"
    );
    assert_committed_readers_resolve(&db, cid, creator.address());
}

/// The committed readers, driven against whichever handle is passed.
fn assert_committed_readers_resolve(db: &Database, cid: [u8; 32], creator: Address) {
    let store = NftStore::new(db);
    let collection = store.get_collection(&cid).unwrap().expect("collection");
    assert_eq!(collection.owner, creator);
    assert_eq!((collection.total_supply, collection.next_token_id), (2, 3));

    let one = store.get_token(&cid, 1).unwrap().expect("token 1");
    assert_eq!(one.owner, Address::new([0xB1; 20]), "transferred");
    assert_eq!(one.transfer_count, 1);
    assert_eq!(one.approved, None, "the transfer cleared the approval");
    let two = store.get_token(&cid, 2).unwrap().expect("token 2");
    assert_eq!(two.owner, Address::new([0xB1; 20]));
    assert_eq!(two.metadata, vec![1, 2, 3]);

    assert_eq!(
        store.get_owner_tokens(&creator).unwrap(),
        Vec::new(),
        "the creator's list emptied, so its row is gone"
    );
    assert_eq!(
        store.get_owner_tokens(&Address::new([0xB1; 20])).unwrap(),
        vec![(cid.to_vec(), 2u64), (cid.to_vec(), 1u64)],
        "the recipient holds both, batch-minted one first"
    );
    assert_eq!(store.get_collection_tokens(&cid).unwrap(), vec![1, 2]);
}

// ── The second dispatch surface ──────────────────────────────────────────────

/// `execute_tx_v2` routes nfts through the candidate too, and chains within it.
#[test]
fn the_v2_dispatch_surface_also_stages_nfts() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let cid = collection_id_of(&creator.address(), "V2");
    let key = *creator.public_key().as_bytes();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        let mut run = |nonce: u64, token_id: u64, op: NftOperation, data: Vec<u8>| {
            let t = TransactionV2 {
                chain_id: CHAIN_ID,
                from: creator.address(),
                fee: 100,
                nonce,
                payload: TxPayload::Nft(NftTxData {
                    collection_id: cid,
                    token_id,
                    operation: op,
                    data,
                }),
            };
            let sig = *sign(t.signing_hash().as_bytes(), creator.private_key()).as_bytes();
            executor
                .execute_tx_v2(&mut view, &t, &sig, &key, &proposer, 1, TS, 0)
                .unwrap()
        };

        assert!(matches!(
            run(
                0,
                0,
                NftOperation::CreateCollection,
                create_payload("V2", transferable())
            )
            .status,
            TxStatus::Success
        ));
        assert!(
            matches!(
                run(1, 0, NftOperation::Mint, mint_payload(creator.address())).status,
                TxStatus::Success
            ),
            "the v2 surface must see the collection it staged a moment ago"
        );
        assert!(
            matches!(
                run(
                    2,
                    1,
                    NftOperation::Transfer,
                    transfer_payload(Address::new([0xB1; 20]))
                )
                .status,
                TxStatus::Success
            ),
            "and the token it staged a moment ago"
        );

        // A refusal on this arm carries the nft status code, not a
        // neighbouring subsystem's.
        let refused = run(
            3,
            1,
            NftOperation::Transfer,
            transfer_payload(Address::new([0xB2; 20])),
        );
        assert_eq!(
            refused.status,
            TxStatus::Failed(2),
            "the creator no longer owns it IN the nft arm of this surface"
        );

        let changed = families_changed(&db, &view);
        assert_eq!(
            changed,
            vec![
                cf::NFT_COLLECTIONS,
                cf::NFT_TOKENS,
                cf::NFT_OWNER_INDEX,
                cf::NFT_COLLECTION_INDEX
            ],
            "all four families staged through this surface"
        );
        assert_eq!(
            NftExecutor::v_get_token(&view, &cid, 1)
                .unwrap()
                .unwrap()
                .owner,
            Address::new([0xB1; 20])
        );
    }
    assert_eq!(canonical(&db), before, "and commit nothing");
}

// ── Corrupt rows: every family, with the staged state named ─────────────────

/// One corrupt-row case: which family is corrupted, the operation that has to
/// READ it, and the exact candidate state the failure is required to leave.
struct CorruptCase {
    family: &'static str,
    label: &'static str,
    /// Nft families whose candidate contents must differ from committed, and
    /// nothing else. Named exactly -- not an allowed set.
    staged: &'static [&'static str],
}

/// A corrupt row makes the routed transaction ERROR; it is never read as
/// absence.
///
/// Five families are covered: two corrupt PRIMARY rows, both corrupt INDEX
/// rows, and the read-only issuer registry. The candidate is asserted
/// positively, family by family, and the corrupt row is asserted UNCHANGED.
///
/// The sender's nonce is 1 in EVERY case, and that is itself a finding: unlike
/// agreement, the nft arm charges the fee and advances the nonce BEFORE any
/// guard runs, so a transaction that fails on a corrupt row has still paid. It
/// is pinned separately by
/// `a_refused_nft_operation_has_already_charged_the_fee`.
#[test]
fn corrupt_rows_error_through_dispatch_with_exactly_this_staged() {
    const CORRUPT: &[u8] = b"not a valid row";
    let cid = [7u8; 32];

    let cases = [
        CorruptCase {
            family: cf::NFT_COLLECTIONS,
            label: "collection",
            staged: &[],
        },
        CorruptCase {
            family: cf::NFT_TOKENS,
            label: "token",
            staged: &[],
        },
        CorruptCase {
            family: cf::NFT_OWNER_INDEX,
            label: "owner index",
            staged: &[cf::NFT_TOKENS],
        },
        CorruptCase {
            family: cf::NFT_COLLECTION_INDEX,
            label: "collection index",
            staged: &[cf::NFT_TOKENS, cf::NFT_OWNER_INDEX],
        },
        CorruptCase {
            family: cf::ISSUER_REGISTRY,
            label: "issuer",
            staged: &[],
        },
    ];

    for case in cases {
        let (_state, db, _dir, executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let proposer = Address::new([9; 20]);

        // Every case except the corrupt collection needs a readable collection
        // to get as far as the row under test.
        if case.family != cf::NFT_COLLECTIONS {
            seed_collection(&db, &actor.address(), &cid, &transferable());
        }

        // Keys written by hand, from the schema and not from the key builders,
        // so a change to a builder cannot silently move this test with it.
        let key: Vec<u8> = match case.family {
            f if f == cf::NFT_TOKENS => token_key(&cid, 1),
            f if f == cf::NFT_OWNER_INDEX || f == cf::ISSUER_REGISTRY => {
                actor.address().as_bytes().to_vec()
            }
            _ => cid.to_vec(),
        };

        // What each guard needs in order to REACH the corrupt row.
        let (op, token_id, data): (NftOperation, u64, Vec<u8>) = match case.family {
            f if f == cf::NFT_TOKENS => {
                // The token row has to exist for `Transfer` to decode it.
                (
                    NftOperation::Transfer,
                    1,
                    transfer_payload(Address::new([0xB1; 20])),
                )
            }
            f if f == cf::ISSUER_REGISTRY => {
                (NftOperation::MintDocument, 0, mint_payload(actor.address()))
            }
            // Mint reads the owner index after writing the token, and the
            // collection index after writing the owner index.
            _ => (NftOperation::Mint, 0, mint_payload(actor.address())),
        };
        db.put(case.family, &key, CORRUPT).unwrap();

        let before = canonical(&db);
        let t = nft_tx(&actor, 0, 100, cid, token_id, op, data);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut overlay);
            let outcome = executor.execute_tx(&mut view, &t, &proposer, 1, TS);
            let err = outcome.err().unwrap_or_else(|| {
                panic!(
                    "a corrupt {} row must ERROR, not be read as absence",
                    case.label
                )
            });
            let text = err.to_string();
            assert!(
                text.contains("Serialization") || text.contains("Storage"),
                "the {} failure must name the decode, not something else: {text}",
                case.label
            );

            // Exactly these families changed. Not a subset, not an allowed set.
            assert_eq!(
                families_changed(&db, &view),
                case.staged.to_vec(),
                "{}: the candidate must hold exactly the families named for \
                 this case",
                case.label
            );

            // And exactly this content, where anything is staged at all.
            if case.family == cf::NFT_OWNER_INDEX || case.family == cf::NFT_COLLECTION_INDEX {
                let staged_token = view
                    .get(cf::NFT_TOKENS, &token_key(&cid, 1))
                    .unwrap()
                    .expect("the token written before the failing append");
                let decoded: sumchain_storage::NftTokenData =
                    bincode::deserialize(&staged_token).unwrap();
                assert_eq!(
                    bincode::serialize(&decoded).unwrap(),
                    staged_token,
                    "the staged token row is exactly bincode of what it decodes to"
                );
                assert_eq!((decoded.token_id, decoded.owner), (1, actor.address()));
            }
            if case.family == cf::NFT_COLLECTION_INDEX {
                let expected: Vec<(Vec<u8>, u64)> = vec![(cid.to_vec(), 1u64)];
                assert_eq!(
                    view.get(cf::NFT_OWNER_INDEX, actor.address().as_bytes())
                        .unwrap()
                        .as_deref(),
                    Some(&bincode::serialize(&expected).unwrap()[..]),
                    "the owner index written before the failing append, byte for byte"
                );
            }

            // The corrupt row itself is never rewritten or repaired.
            assert_eq!(
                view.get(case.family, &key).unwrap().as_deref(),
                Some(CORRUPT),
                "{}: the corrupt bytes must be left exactly as they were",
                case.label
            );

            assert_eq!(
                StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
                1,
                "{}: the fee is charged before any guard runs, so the nonce \
                 advanced even though the operation failed",
                case.label
            );
        }
        assert_eq!(
            canonical(&db),
            before,
            "and nothing may be committed for {}",
            case.label
        );
    }
}

/// Execution only READS the issuer registry.
///
/// A block that mints a document against a registered issuer writes the three
/// nft families and leaves `ISSUER_REGISTRY` byte-identical, which is what
/// keeps it out of `NFT_CFS` and out of the closure manifest.
#[test]
fn no_block_writes_the_issuer_registry() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &actor.address(), &cid, &transferable());
    IssuerStore::new(&db)
        .put_issuer(
            &actor.address(),
            &IssuerData {
                address: actor.address(),
                name: "Test University".to_string(),
                domain: "test.edu".to_string(),
                org_type: 0,
                country_code: "US".to_string(),
                status: 0,
                allowed_doc_types: vec![],
                registered_at: 1,
                updated_at: 1,
                expires_at: 0,
                metadata: None,
            },
        )
        .unwrap();
    let issuer_before: Vec<(Vec<u8>, Vec<u8>)> = db
        .prefix_iter(cf::ISSUER_REGISTRY, &[])
        .unwrap()
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &actor,
        0,
        100,
        cid,
        0,
        NftOperation::MintDocument,
        mint_payload(actor.address()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .is_document
    );

    let issuer_after: Vec<(Vec<u8>, Vec<u8>)> = view
        .prefix_iter(cf::ISSUER_REGISTRY, &[])
        .unwrap()
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect();
    assert_eq!(
        issuer_after, issuer_before,
        "block execution reads the issuer registry and never writes it"
    );
}

/// An unregistered issuer is refused, through dispatch, reading the candidate.
#[test]
fn an_unregistered_issuer_cannot_mint_a_document() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &actor.address(), &cid, &transferable());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &actor,
        0,
        100,
        cid,
        0,
        NftOperation::MintDocument,
        mint_payload(actor.address()),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2)
    );
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

// ── Behaviours reproduced deliberately, not fixed ────────────────────────────
//
// Everything below is inherited. Each one is pinned here so that a future fix
// has to change a test on purpose, and each is listed in
// `docs/lane-a/DEPLOYMENT-BLOCKERS.md`. None of it is repaired by this commit:
// every item changes which transactions are valid or what bytes reach the
// state root, which is consensus work requiring separate activation.

/// A transaction naming a collection that does not exist ERRORS instead of
/// failing, and the error propagates out of `execute_block` — so one such
/// transaction makes the WHOLE BLOCK unexecutable.
///
/// `execute_mint` and its siblings use `ok_or_else(|| StateError::
/// BlockValidation("Collection not found"))?` where every other guard in the
/// file returns `NftExecutionResult::failure`. Anyone may submit one.
#[test]
fn a_transaction_naming_an_absent_collection_aborts_the_whole_block() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let t = nft_tx(
        &actor,
        0,
        100,
        [0x55u8; 32],
        0,
        NftOperation::Mint,
        mint_payload(actor.address()),
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        let err = executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .expect_err("an absent collection is an ERROR, not a failed receipt");
        assert!(err.to_string().contains("Collection not found"), "{err}");
    }

    // And through the real block path: `execute_block` propagates it, so no
    // block containing this transaction can be produced or imported.
    let header = sumchain_primitives::BlockHeader::new(
        sumchain_primitives::Hash::ZERO,
        1,
        TS,
        sumchain_primitives::Hash::ZERO,
        sumchain_primitives::Hash::ZERO,
        [3u8; 32],
    );
    let block = sumchain_primitives::Block::new(header, vec![t]);
    assert!(
        executor
            .execute_block(&block, state.state_root(), &[])
            .is_err(),
        "a single such transaction makes the whole block unexecutable"
    );
}

/// The same shape for an absent TOKEN, reached in one block by burning it
/// first.
///
/// A burn followed by any operation on the same token aborts the block. It is
/// the same inherited `ok_or_else(..)?`, and the candidate is what makes the
/// burn visible to the second transaction — which is correct, and which is
/// exactly why this path now aborts where it previously succeeded against a
/// stale row.
#[test]
fn burning_a_token_and_then_using_it_in_one_block_aborts_the_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "BurnUse");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::CreateCollection,
            create_payload("BurnUse", transferable()),
        ),
        (1, 0, NftOperation::Mint, mint_payload(creator.address())),
        (2, 1, NftOperation::Burn, Vec::new()),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let t = nft_tx(
        &creator,
        3,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(Address::new([0xB1; 20])),
    );
    let err = executor
        .execute_tx(&mut view, &t, &proposer, 1, TS)
        .expect_err("an absent token is an ERROR, not a failed receipt");
    assert!(err.to_string().contains("Token not found"), "{err}");
}

/// An invalid `CollectionConfig` in the payload aborts the block too.
///
/// `config.validate()` is mapped to `StateError::BlockValidation` with `?`, so
/// a royalty above 2500bps is not a failed receipt either.
#[test]
fn an_invalid_collection_config_aborts_the_whole_block() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let config = CollectionConfig {
        royalty_bps: 2501,
        royalty_recipient: Address::new([0xAA; 20]),
        ..transferable()
    };
    let t = nft_tx(
        &actor,
        0,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload("Greedy", config),
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let err = executor
        .execute_tx(&mut view, &t, &proposer, 1, TS)
        .expect_err("an invalid config is an ERROR, not a failed receipt");
    assert!(err.to_string().contains("Invalid config"), "{err}");
}

/// A refused nft operation has ALREADY paid.
///
/// `deduct_fee` runs before the dispatch match, so every guard below it refuses
/// a transaction whose fee is spent and whose nonce has advanced — while the
/// receipt reports `fee_paid: 0`. The receipt and the state disagree.
#[test]
fn a_refused_nft_operation_has_already_charged_the_fee() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    // Owned by somebody else, so `owner_only_minting` refuses the mint.
    seed_collection(&db, &Address::new([0xEE; 20]), &cid, &transferable());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &actor,
        0,
        100,
        cid,
        0,
        NftOperation::Mint,
        mint_payload(actor.address()),
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, 1, TS)
        .unwrap();

    assert_eq!(r.status, TxStatus::Failed(2));
    assert_eq!(r.fee_paid, 0, "the receipt says nothing was paid");
    assert_eq!(
        StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        100_000_000 - 100,
        "and the fee was taken anyway"
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1,
        "and the nonce advanced, so the transaction cannot be retried as-is"
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &proposer).unwrap(),
        100,
        "the proposer keeps it"
    );
    assert_eq!(
        families_changed(&db, &view),
        Vec::<&str>::new(),
        "no nft row moved"
    );
}

/// `SetApprovalForAll` charges a fee, advances the nonce and does nothing.
///
/// Operator approvals are unimplemented, and the fee is taken before the arm
/// that says so.
#[test]
fn set_approval_for_all_charges_a_fee_and_does_nothing() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &actor,
        0,
        100,
        [7u8; 32],
        0,
        NftOperation::SetApprovalForAll,
        approve_payload(Some(Address::new([0xAB; 20]))),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2)
    );
    assert_eq!(
        StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        1
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        100_000_000 - 100
    );
    assert_eq!(families_changed(&db, &view), Vec::<&str>::new());
}

/// `UpdateMetadata` takes the payload VERBATIM, with no size limit and no
/// per-byte storage fee.
///
/// Minting enforces `max_metadata_bytes` and `calculate_nft_storage_fee`.
/// Updating enforces neither: the transaction data becomes the metadata as-is,
/// for the flat minimum fee. A 32 KB row costs 100 base units here and would be
/// refused outright at mint.
#[test]
fn update_metadata_accepts_any_size_and_charges_no_storage_fee() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let config = CollectionConfig {
        metadata_updatable: true,
        ..transferable()
    };
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &config);

    let oversized = vec![0xABu8; 32_768];
    assert!(
        !params().validate_metadata_size(oversized.len()),
        "this payload is over the mint-time limit, which is the point"
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let t = nft_tx(
        &creator,
        0,
        100,
        cid,
        0,
        NftOperation::Mint,
        mint_payload(creator.address()),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));

    let t = nft_tx(
        &creator,
        1,
        100,
        cid,
        1,
        NftOperation::UpdateMetadata,
        oversized.clone(),
    );
    assert!(
        matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ),
        "32 KB of metadata, for a flat fee of 100"
    );
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .metadata,
        oversized,
        "the payload bytes are the metadata, verbatim and undecoded"
    );
}

/// The CREATOR may rewrite the metadata of a token it no longer owns.
///
/// `execute_update_metadata` accepts `token.owner == sender || token.creator ==
/// sender`, and the creator field never changes.
#[test]
fn the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let holder = Address::new([0xB1; 20]);
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let config = CollectionConfig {
        metadata_updatable: true,
        ..transferable()
    };
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &config);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        (1, 1, NftOperation::Transfer, transfer_payload(holder)),
        (2, 1, NftOperation::UpdateMetadata, b"rewritten".to_vec()),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(
            matches!(
                executor
                    .execute_tx(&mut view, &t, &proposer, 1, TS)
                    .unwrap()
                    .status,
                TxStatus::Success
            ),
            "{op:?}"
        );
    }

    let token = NftExecutor::v_get_token(&view, &cid, 1).unwrap().unwrap();
    assert_eq!(token.owner, holder, "the holder owns it");
    assert_eq!(
        token.metadata,
        b"rewritten".to_vec(),
        "and the creator rewrote its metadata anyway"
    );
}

/// A LOCKED token can still be approved and have its metadata rewritten.
///
/// The lock is consulted by `execute_transfer` and `execute_burn` only.
#[test]
fn a_locked_token_can_still_be_approved_and_rewritten() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let config = CollectionConfig {
        metadata_updatable: true,
        ..transferable()
    };
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &config);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        (1, 1, NftOperation::LockToken, Vec::new()),
        (
            2,
            1,
            NftOperation::Approve,
            approve_payload(Some(Address::new([0xAB; 20]))),
        ),
        (
            3,
            1,
            NftOperation::UpdateMetadata,
            b"still writable".to_vec(),
        ),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(
            matches!(
                executor
                    .execute_tx(&mut view, &t, &proposer, 1, TS)
                    .unwrap()
                    .status,
                TxStatus::Success
            ),
            "{op:?} on a locked token"
        );
    }

    let token = NftExecutor::v_get_token(&view, &cid, 1).unwrap().unwrap();
    assert!(token.locked);
    assert_eq!(token.approved, Some(Address::new([0xAB; 20])));
    assert_eq!(token.metadata, b"still writable".to_vec());
}

/// `BatchMint` enforces neither the metadata size limit nor the storage fee.
///
/// `execute_mint` checks both. `execute_batch_mint` checks neither, so the
/// cheapest way to write oversized metadata is to batch it.
#[test]
fn batch_mint_ignores_the_metadata_size_limit_and_the_storage_fee() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &transferable());

    let oversized = vec![0xCDu8; 32_768];
    assert!(!params().validate_metadata_size(oversized.len()));
    assert!(
        params().calculate_nft_storage_fee(oversized.len()) > 100,
        "a single mint of this size would need far more than the fee below"
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &creator,
        0,
        100,
        cid,
        0,
        NftOperation::BatchMint,
        bincode::serialize(&NftBatchMintData {
            requests: vec![NftBatchMintRequest {
                to: creator.address(),
                metadata: oversized.clone(),
            }],
        })
        .unwrap(),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .metadata,
        oversized,
        "32 KB written for a fee of 100, through the batch arm"
    );
}

/// The block timestamp is the ONLY nonce in a collection id.
///
/// `CollectionId::new(sender, name, block_timestamp)`. Two blocks with the same
/// timestamp — which nothing forbids — give the same sender the same id for the
/// same name, so the later creation is refused as a duplicate. The id is not
/// unique per creation; it is unique per (sender, name, timestamp).
#[test]
fn the_block_timestamp_is_the_only_nonce_in_a_collection_id() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let cid = collection_id_of(&creator.address(), "Same");

    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![nft_tx(
            &creator,
            0,
            100,
            [0u8; 32],
            0,
            NftOperation::CreateCollection,
            create_payload("Same", transferable()),
        )],
        &[],
    );
    assert!(matches!(receipts[0].status, TxStatus::Success));
    assert!(NftStore::new(&db).collection_exists(&cid).unwrap());

    // A LATER block, same timestamp (`publish_block` uses 1000 throughout, as
    // any chain with a fixed or repeated block time would).
    let receipts = common::publish_block(
        &state,
        &executor,
        2,
        &[3u8; 32],
        vec![nft_tx(
            &creator,
            1,
            100,
            [0u8; 32],
            0,
            NftOperation::CreateCollection,
            create_payload("Same", transferable()),
        )],
        &[],
    );
    assert_eq!(
        receipts[0].status,
        TxStatus::Failed(2),
        "the same creator can never make two collections of one name in two \
         blocks that share a timestamp"
    );
}

/// `UpdateCollectionConfig` can set a royalty recipient on a collection whose
/// royalty is zero, and can never change the royalty itself.
///
/// Creation zeroes `royalty_recipient` when `royalty_bps == 0`; the update path
/// has no such rule, and has no field for `royalty_bps` at all.
#[test]
fn a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Royalty");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let t = nft_tx(
        &creator,
        0,
        100,
        [0u8; 32],
        0,
        NftOperation::CreateCollection,
        create_payload(
            "Royalty",
            CollectionConfig {
                royalty_bps: 0,
                royalty_recipient: Address::new([0xAA; 20]),
                ..transferable()
            },
        ),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    assert_eq!(
        NftExecutor::v_get_collection(&view, &cid)
            .unwrap()
            .unwrap()
            .royalty_recipient,
        Address::ZERO,
        "creation zeroes the recipient when the royalty is zero"
    );

    let t = nft_tx(
        &creator,
        1,
        100,
        cid,
        0,
        NftOperation::UpdateCollectionConfig,
        bincode::serialize(&NftUpdateCollectionConfigData {
            new_royalty_recipient: Some(Address::new([0xAA; 20])),
            new_base_uri: Some("ipfs://after".to_string()),
        })
        .unwrap(),
    );
    assert!(matches!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Success
    ));
    let collection = NftExecutor::v_get_collection(&view, &cid).unwrap().unwrap();
    assert_eq!(
        (collection.royalty_bps, collection.royalty_recipient),
        (0, Address::new([0xAA; 20])),
        "the update sets a recipient the creation refused to keep, and cannot \
         touch the basis points at all"
    );
    assert_eq!(collection.base_uri, Some("ipfs://after".to_string()));
}

/// Transferring a collection moves no token and touches no index.
///
/// The new owner gains minting rights over every existing token's collection
/// without any token changing hands — recorded because the collection row is
/// the only authority `owner_only_minting` consults.
#[test]
fn transferring_a_collection_moves_no_token() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let new_owner = Address::new([0xF0; 20]);
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &transferable());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, op, data) in [
        (0u64, NftOperation::Mint, mint_payload(creator.address())),
        (
            1,
            NftOperation::TransferCollectionOwnership,
            bincode::serialize(&NftTransferCollectionOwnershipData { new_owner }).unwrap(),
        ),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert_eq!(
        NftExecutor::v_get_collection(&view, &cid)
            .unwrap()
            .unwrap()
            .owner,
        new_owner
    );
    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .owner,
        creator.address(),
        "the token did not move"
    );
    assert_eq!(owner_ids(&view, &new_owner), Vec::new());
    assert_eq!(
        owner_ids(&view, &creator.address()),
        vec![(cid.to_vec(), 1u64)]
    );
}

/// A transfer to SELF still bumps the transfer count and clears the approval.
///
/// `remove_from_owner_index` then `add_to_owner_index` on the same address is a
/// delete followed by a write, so the row survives — but the token row has been
/// rewritten, and any approval on it is gone.
#[test]
fn a_transfer_to_self_clears_the_approval_and_keeps_the_index_entry() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(&db, &creator.address(), &cid, &transferable());

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        (
            1,
            1,
            NftOperation::Approve,
            approve_payload(Some(Address::new([0xAB; 20]))),
        ),
        (
            2,
            1,
            NftOperation::Transfer,
            transfer_payload(creator.address()),
        ),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    let token = NftExecutor::v_get_token(&view, &cid, 1).unwrap().unwrap();
    assert_eq!(token.owner, creator.address());
    assert_eq!(token.transfer_count, 1);
    assert_eq!(token.approved, None);
    assert_eq!(
        owner_ids(&view, &creator.address()),
        vec![(cid.to_vec(), 1u64)],
        "the entry survives the delete-then-write"
    );
}

/// Both existence guards answer from the candidate.
///
/// `v_collection_exists` is the duplicate guard `execute_create_collection`
/// uses; `v_token_exists` has no production caller and is here for the same
/// reason the rest of the accessor set is — so that nothing has to reach for
/// the committed twin to ask the question.
#[test]
fn the_existence_guards_read_the_candidate() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = collection_id_of(&creator.address(), "Exists");

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert!(!NftExecutor::v_collection_exists(&view, &cid).unwrap());
    assert!(!NftExecutor::v_token_exists(&view, &cid, 1).unwrap());

    for (nonce, op, data) in [
        (
            0u64,
            NftOperation::CreateCollection,
            create_payload("Exists", transferable()),
        ),
        (1, NftOperation::Mint, mint_payload(creator.address())),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, 0, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert!(
        NftExecutor::v_collection_exists(&view, &cid).unwrap(),
        "the collection exists in the candidate"
    );
    assert!(
        NftExecutor::v_token_exists(&view, &cid, 1).unwrap(),
        "and so does the token"
    );
    assert!(
        !NftExecutor::v_token_exists(&view, &cid, 2).unwrap(),
        "and a token this block did not mint does not"
    );
    assert!(
        !NftExecutor::v_collection_exists(&view, &[0x11u8; 32]).unwrap(),
        "nor a collection nobody created"
    );
    // Nothing reached the database.
    assert!(!NftStore::new(&db).collection_exists(&cid).unwrap());
}

/// `Approve` never reads the collection at all.
///
/// So a token in a non-transferable collection can still be given an approved
/// address — an approval that can never be exercised, recorded on a soulbound
/// token.
#[test]
fn approve_never_reads_the_collection() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let spender = KeyPair::generate();
    for kp in [&creator, &spender] {
        fund(&db, kp, 100_000_000);
    }
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(
        &db,
        &creator.address(),
        &cid,
        &CollectionConfig {
            transferable: false,
            ..transferable()
        },
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        (
            1,
            1,
            NftOperation::Approve,
            approve_payload(Some(spender.address())),
        ),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(
            matches!(
                executor
                    .execute_tx(&mut view, &t, &proposer, 1, TS)
                    .unwrap()
                    .status,
                TxStatus::Success
            ),
            "{op:?} on a soulbound collection"
        );
    }

    assert_eq!(
        NftExecutor::v_get_token(&view, &cid, 1)
            .unwrap()
            .unwrap()
            .approved,
        Some(spender.address()),
        "the approval is recorded on a token that can never be transferred"
    );

    let t = nft_tx(
        &spender,
        0,
        100,
        cid,
        1,
        NftOperation::Transfer,
        transfer_payload(Address::new([0xDE; 20])),
    );
    assert_eq!(
        executor
            .execute_tx(&mut view, &t, &proposer, 1, TS)
            .unwrap()
            .status,
        TxStatus::Failed(2),
        "and the transfer arm, which does read the collection, refuses it"
    );
}

/// Royalties are recorded and never paid.
///
/// `royalty_bps` and `royalty_recipient` are stored on the collection, returned
/// by the RPC readers, and consulted by no execution path: a transfer moves the
/// token and pays the recipient nothing.
#[test]
fn royalties_are_recorded_and_never_paid() {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    let royalty_recipient = Address::new([0xAA; 20]);
    fund(&db, &creator, 100_000_000);
    let proposer = Address::new([9; 20]);
    let cid = [7u8; 32];
    seed_collection(
        &db,
        &creator.address(),
        &cid,
        &CollectionConfig {
            royalty_bps: 2500,
            royalty_recipient,
            ..transferable()
        },
    );

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, token, op, data) in [
        (
            0u64,
            0u64,
            NftOperation::Mint,
            mint_payload(creator.address()),
        ),
        (
            1,
            1,
            NftOperation::Transfer,
            transfer_payload(Address::new([0xDE; 20])),
        ),
    ] {
        let t = nft_tx(&creator, nonce, 100, cid, token, op, data);
        assert!(matches!(
            executor
                .execute_tx(&mut view, &t, &proposer, 1, TS)
                .unwrap()
                .status,
            TxStatus::Success
        ));
    }

    assert_eq!(
        NftExecutor::v_get_collection(&view, &cid)
            .unwrap()
            .unwrap()
            .royalty_bps,
        2500,
        "the collection records a 25% royalty"
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &royalty_recipient).unwrap(),
        0,
        "and the transfer paid the recipient nothing"
    );
}

// ── BD-1..BD-5: the block-denial rule, and the activation that governs it ────
//
// `docs/lane-a/ACTIVATION-AUDIT.md` rows BD-1 to BD-5. The four pinning tests
// above record the inherited behaviour: a `StateError::BlockValidation` out of
// `NftExecutor::execute`, propagated by `?` at `crates/state/src/executor.rs`
// and again inside `execute_block`'s transaction loop, so one minimum-fee
// transaction from anyone makes a whole block unexecutable.
//
// Changing that is a CONSENSUS CHANGE — a block that one node refuses to
// execute at all is a block another node executes and roots — so it is gated
// rather than fixed outright. The gate is
// `NftExecutor::receipt_failure_gate_open`, whose activation height wants a
// `nft_receipt_failure_enabled_from_height` field in `ChainParams` that this
// track cannot add; until it lands the activation reads `None`, the gate is
// closed, and the four tests above still pass unchanged. That is the point: the
// production path did not move.
//
// What the tests below establish is the other half — that the gated side is
// real, that it is reachable through one entry point, and that an ungated node
// and a gated node disagree DETECTABLY. The disagreement is not two different
// state roots over the same block. It is stronger: the ungated node produces NO
// BLOCK AT ALL (`execute_block` returns `Err` before `receipts.push`) where the
// gated node produces a block carrying a `Failed` receipt. A node that cannot
// execute a block its peers executed halts against them rather than forking
// silently behind them.

/// The gate seam, driven both ways over the same transaction and the same view.
///
/// Below the gate: `Err(BlockValidation("Collection not found"))`, which is
/// what `execute_block` propagates. At or above it: a `Failed` result and a
/// block that still executes.
#[test]
fn an_absent_collection_aborts_the_block_below_the_gate_and_is_a_receipt_above_it() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let nft_data = NftTxData {
        collection_id: [0x55u8; 32],
        token_id: 0,
        operation: NftOperation::Mint,
        data: mint_payload(actor.address()),
    };

    // Ungated node: the error that ends the block.
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let err = NftExecutor::execute_with_gate(
        &mut view,
        &params(),
        &actor.address(),
        &nft_data,
        &proposer,
        100,
        TS,
        false,
    )
    .expect_err("below the gate an absent collection is still an Err");
    assert!(err.to_string().contains("Collection not found"), "{err}");

    // Gated node: a refusal the block survives.
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let result = NftExecutor::execute_with_gate(
        &mut view,
        &params(),
        &actor.address(),
        &nft_data,
        &proposer,
        100,
        TS,
        true,
    )
    .expect("at the gate the same transaction is a receipt, not a block abort");
    assert!(!result.success, "it is still a refusal");
    assert_eq!(
        result.error.as_deref(),
        Some("Collection not found"),
        "and it carries the same reason the error carried"
    );

    // The refusal is paid for. `deduct_fee` runs before the dispatch match, so
    // the sender is charged and the proposer credited exactly as for every
    // other refused NFT operation — the gate changes the block's fate, not the
    // fee rule.
    assert_eq!(
        StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        100_000_000 - 100
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &proposer).unwrap(),
        100,
        "the proposer keeps the fee for the work it did"
    );
    assert_eq!(
        StateManager::v_get_account(&view, &actor.address())
            .unwrap()
            .nonce,
        1,
        "and the nonce advanced, so the refusal is not replayable"
    );
}

/// All four block-denial shapes flip together, and only at the gate.
///
/// BD-1 absent collection, BD-2 absent token, BD-3 out-of-range royalty,
/// BD-4 undecodable payload. One table, both gate values, so a fix that
/// converts one shape and forgets another fails here.
#[test]
fn every_block_denial_shape_becomes_a_receipt_at_the_gate_and_only_at_the_gate() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    // A collection that exists, so the absent-TOKEN case reaches its own guard
    // rather than the absent-collection one.
    let live = [0x77u8; 32];
    seed_collection(&db, &actor.address(), &live, &transferable());

    let greedy = CollectionConfig {
        royalty_bps: 2501,
        royalty_recipient: Address::new([0xAA; 20]),
        ..transferable()
    };

    let cases: Vec<(&str, NftTxData, &str)> = vec![
        (
            "BD-1 absent collection",
            NftTxData {
                collection_id: [0x55u8; 32],
                token_id: 0,
                operation: NftOperation::Mint,
                data: mint_payload(actor.address()),
            },
            "Collection not found",
        ),
        (
            "BD-2 absent token",
            NftTxData {
                collection_id: live,
                token_id: 4242,
                operation: NftOperation::Transfer,
                data: transfer_payload(Address::new([0xB1; 20])),
            },
            "Token not found",
        ),
        (
            "BD-3 royalty above 2500bps",
            NftTxData {
                collection_id: [0u8; 32],
                token_id: 0,
                operation: NftOperation::CreateCollection,
                data: create_payload("Greedy", greedy),
            },
            "Invalid config",
        ),
        (
            "BD-4 undecodable payload",
            NftTxData {
                collection_id: [0u8; 32],
                token_id: 0,
                operation: NftOperation::CreateCollection,
                data: vec![0xFF; 3],
            },
            "Invalid collection data",
        ),
    ];

    for (label, nft_data, needle) in cases {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let err = NftExecutor::execute_with_gate(
            &mut view,
            &params(),
            &actor.address(),
            &nft_data,
            &proposer,
            100,
            TS,
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "{label}: below the gate this must still abort the block, got {err}"
        );

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        let result = NftExecutor::execute_with_gate(
            &mut view,
            &params(),
            &actor.address(),
            &nft_data,
            &proposer,
            100,
            TS,
            true,
        )
        .unwrap_or_else(|e| panic!("{label}: at the gate this must be a receipt, got {e}"));
        assert!(!result.success, "{label}: still a refusal");
        assert!(
            result.error.as_deref().unwrap_or_default().contains(needle),
            "{label}: the receipt must carry the reason, got {:?}",
            result.error
        );
    }
}

/// BD-5: the fee deduction's own insufficient-balance error is the same shape.
///
/// It is reachable inside a block even though `validate_tx` checked the balance
/// against the parent state — a sender that spends down inside the block meets
/// it on a later transaction. Below the gate it ends the block; at the gate it
/// is a receipt, and the nonce advances even though no fee could be charged, so
/// the refused transaction is not replayable at the same nonce.
#[test]
fn an_in_block_insufficient_balance_aborts_below_the_gate_and_advances_the_nonce_above_it() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 150);
    let proposer = Address::new([9; 20]);
    let live = [0x88u8; 32];
    seed_collection(&db, &actor.address(), &live, &transferable());

    let nft_data = NftTxData {
        collection_id: live,
        token_id: 0,
        operation: NftOperation::Mint,
        data: mint_payload(actor.address()),
    };

    for gate_open in [false, true] {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        // First mint spends 100 of 150.
        NftExecutor::execute_with_gate(
            &mut view,
            &params(),
            &actor.address(),
            &nft_data,
            &proposer,
            100,
            TS,
            gate_open,
        )
        .expect("the first mint is affordable under either gate");

        // Second mint cannot afford its fee out of the 50 that remain.
        let outcome = NftExecutor::execute_with_gate(
            &mut view,
            &params(),
            &actor.address(),
            &nft_data,
            &proposer,
            100,
            TS,
            gate_open,
        );

        if gate_open {
            let result = outcome.expect("at the gate this is a receipt");
            assert!(!result.success);
            assert!(
                result
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("Insufficient balance"),
                "{:?}",
                result.error
            );
            assert_eq!(
                StateManager::v_get_balance(&view, &actor.address()).unwrap(),
                50,
                "nothing was charged, because nothing could be"
            );
            assert_eq!(
                StateManager::v_get_account(&view, &actor.address())
                    .unwrap()
                    .nonce,
                2,
                "but the nonce advanced, so the refusal is consumed"
            );
        } else {
            let err = outcome.expect_err("below the gate this ends the block");
            assert!(
                err.to_string().contains("Insufficient balance")
                    || err.to_string().contains("insufficient"),
                "{err}"
            );
        }
    }
}

/// The mixed-version disagreement, stated as a block outcome rather than as a
/// receipt field.
///
/// One block, one transaction, two nodes. The node below the activation height
/// cannot execute the block at all; the node at or above it executes it and
/// records a refusal. That is not a silent fork — the ungated node has no root
/// to offer, so it stalls against a chain that moved on, which is the loud
/// failure a consensus change is supposed to have.
///
/// The ungated half runs through the real `execute_block`. The gated half runs
/// through the executor seam, because opening the gate from `ChainParams`
/// requires `nft_receipt_failure_enabled_from_height`, which is in
/// `crates/genesis` and not in this track's files. When that field lands, the
/// gated half of this test becomes an `execute_block` call with the height set
/// and the assertion below stays as it is.
#[test]
fn an_ungated_node_cannot_execute_the_block_a_gated_node_roots() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    let proposer = Address::new([9; 20]);

    let nft_data = NftTxData {
        collection_id: [0x55u8; 32],
        token_id: 0,
        operation: NftOperation::Mint,
        data: mint_payload(actor.address()),
    };
    let t = nft_tx(
        &actor,
        0,
        100,
        nft_data.collection_id,
        0,
        NftOperation::Mint,
        nft_data.data.clone(),
    );

    // Ungated node, real block path: no block.
    let header = sumchain_primitives::BlockHeader::new(
        sumchain_primitives::Hash::ZERO,
        1,
        TS,
        sumchain_primitives::Hash::ZERO,
        sumchain_primitives::Hash::ZERO,
        [3u8; 32],
    );
    let block = sumchain_primitives::Block::new(header, vec![t]);
    assert!(
        executor
            .execute_block(&block, state.state_root(), &[])
            .is_err(),
        "the ungated node produces no block, which is what the gate is for"
    );

    // Gated node, same transaction: a refusal the block carries.
    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let result = NftExecutor::execute_with_gate(
        &mut view,
        &params(),
        &actor.address(),
        &nft_data,
        &proposer,
        100,
        TS,
        true,
    )
    .expect("the gated node executes the transaction");
    assert!(!result.success);

    // The receipt the gated node produces is the one `compute_block_state_root`
    // folds in (tx hash, success bit, `fee_paid`). The ungated node has no
    // receipt to fold, and therefore no root: the divergence is a halt, not a
    // quiet difference in a digest.
}
