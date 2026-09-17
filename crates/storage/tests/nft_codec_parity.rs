//! NFTs: the committed store's rows are exactly what the shared helpers build.
//!
//! ## Why the expectations are built independently
//!
//! Comparing a stored row against `encode_token(...)` proves nothing: the store
//! CALLS that helper, so a wrong helper moves both sides of the assertion
//! together. The same hole applies to keys — asserting `token_key(..)` against
//! itself would let a little-endian token id through.
//!
//! So the expected VALUE here is `bincode::serialize` applied directly in the
//! test, and the expected KEY is written out by hand as a literal. Both are
//! what the committed store produced BEFORE this commit extracted the helpers:
//! the row layout is the compatibility contract, and it must not move.
//!
//! ## Keys, spelled out
//!
//!     collections        the 32-byte collection id
//!     tokens             32-byte collection id ++ token id, BIG-endian: 40 bytes
//!     owner index        the 20-byte owner ADDRESS, value a bincode
//!                        Vec<(Vec<u8>, u64)>
//!     collection index   the 32-byte collection id, value a bincode Vec<u64>
//!     issuer registry    the 20-byte issuer ADDRESS
//!
//! Three of these are worth reading twice. The token key is the only composite
//! one and its byte order is load-bearing. The two index values are lists of
//! DIFFERENT shapes — the owner index's collection id is a length-prefixed
//! `Vec<u8>`, not a fixed array, so bincode writes eight extra length bytes per
//! entry that a `[u8; 32]` would not. And removal is asymmetric: emptying an
//! owner's list DELETES the row, emptying a collection's list WRITES an empty
//! one.

use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::nft_store::{decode_collection_tokens, decode_owner_tokens, OwnerTokenEntry};
use sumchain_storage::{IssuerData, IssuerStore, NftCollectionData, NftStore, NftTokenData};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn row(db: &Database, family: &str, key: &[u8]) -> Option<Vec<u8>> {
    db.get(family, key).unwrap()
}

const COLLECTION: [u8; 32] = [1u8; 32];
const OWNER: [u8; 20] = [0xA1u8; 20];
const CREATOR: [u8; 20] = [0xB2u8; 20];

/// The 40-byte token key, written out by hand rather than by the builder.
fn token_key_literal(collection: [u8; 32], token_id: u64) -> Vec<u8> {
    let mut key = collection.to_vec();
    key.extend_from_slice(&token_id.to_be_bytes());
    assert_eq!(key.len(), 40, "the token key is forty bytes");
    key
}

fn collection() -> NftCollectionData {
    NftCollectionData {
        name: "Test Collection".to_string(),
        symbol: "TEST".to_string(),
        description: "A collection".to_string(),
        owner: Address::new(OWNER),
        max_supply: 100,
        total_supply: 2,
        next_token_id: 3,
        transferable: true,
        burnable: true,
        metadata_updatable: false,
        owner_only_minting: true,
        royalty_bps: 250,
        royalty_recipient: Address::new(CREATOR),
        base_uri: Some("ipfs://base".to_string()),
        created_at: 1_000,
    }
}

fn token(token_id: u64) -> NftTokenData {
    NftTokenData {
        collection_id: COLLECTION,
        token_id,
        owner: Address::new(OWNER),
        creator: Address::new(CREATOR),
        metadata: vec![7u8; 9],
        is_document: true,
        uri_type: "ipfs".to_string(),
        uri_value: Some("ipfs://token".to_string()),
        approved: Some(Address::new([0xCC; 20])),
        locked: false,
        transfer_count: 4,
        minted_at: 1_000,
    }
}

fn issuer() -> IssuerData {
    IssuerData {
        address: Address::new(OWNER),
        name: "Test University".to_string(),
        domain: "test.edu".to_string(),
        org_type: 0,
        country_code: "US".to_string(),
        status: 0,
        allowed_doc_types: vec!["degree".to_string()],
        registered_at: 1_000,
        updated_at: 2_000,
        expires_at: 0,
        metadata: None,
    }
}

#[test]
fn a_collection_row_is_bincode_at_the_collection_id_key() {
    let (db, _dir) = db();
    let c = collection();
    NftStore::new(&db).put_collection(&COLLECTION, &c).unwrap();

    assert_eq!(
        row(&db, cf::NFT_COLLECTIONS, &[1u8; 32]),
        Some(bincode::serialize(&c).unwrap()),
        "the collection, at its id"
    );
    // Putting a collection writes nothing else: the collection index is
    // populated by minting, not by creation.
    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        None,
        "creating a collection writes no index row"
    );
}

#[test]
fn a_token_row_is_bincode_at_the_forty_byte_big_endian_key() {
    let (db, _dir) = db();
    let t = token(7);
    NftStore::new(&db).put_token(&COLLECTION, 7, &t).unwrap();

    // The key, spelled out: 32 bytes of collection id then 00 00 00 00 00 00 00 07.
    let expected_key: Vec<u8> = {
        let mut k = vec![1u8; 32];
        k.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        k
    };
    assert_eq!(
        row(&db, cf::NFT_TOKENS, &expected_key),
        Some(bincode::serialize(&t).unwrap()),
        "the token, at the big-endian composite key"
    );

    // Little-endian would put the 7 first among the eight suffix bytes.
    let little: Vec<u8> = {
        let mut k = vec![1u8; 32];
        k.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
        k
    };
    assert_eq!(
        row(&db, cf::NFT_TOKENS, &little),
        None,
        "nothing is written at the little-endian spelling of the same token"
    );
    assert_eq!(
        row(&db, cf::NFT_TOKENS, &[1u8; 32]),
        None,
        "and nothing at the bare collection id"
    );
}

#[test]
fn token_keys_sort_in_token_id_order() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    for id in [2u64, 300, 1] {
        store.put_token(&COLLECTION, id, &token(id)).unwrap();
    }

    let keys: Vec<Vec<u8>> = db
        .prefix_iter(cf::NFT_TOKENS, &[])
        .unwrap()
        .map(|(k, _)| k.to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![
            token_key_literal(COLLECTION, 1),
            token_key_literal(COLLECTION, 2),
            token_key_literal(COLLECTION, 300),
        ],
        "big-endian is what makes a scan come back in token-id order"
    );
}

#[test]
fn the_owner_index_is_a_list_of_length_prefixed_collection_ids() {
    let (db, _dir) = db();
    NftStore::new(&db)
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();

    // The entry type is `(Vec<u8>, u64)`, so bincode writes an eight-byte
    // length before the collection id. A `[u8; 32]` would not, and the row
    // would be eight bytes shorter.
    let expected: Vec<OwnerTokenEntry> = vec![(vec![1u8; 32], 7u64)];
    let bytes = row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]).unwrap();
    assert_eq!(
        bytes,
        bincode::serialize(&expected).unwrap(),
        "a one-element list at the 20-byte owner address"
    );
    assert_eq!(
        bytes.len(),
        8 + 8 + 32 + 8,
        "list length, id length, id, token id"
    );
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 32]),
        None,
        "nothing is written at a 32-byte spelling of the same address"
    );
    assert_eq!(decode_owner_tokens(&bytes).unwrap(), expected);
}

#[test]
fn the_collection_index_is_a_bare_list_of_token_ids() {
    let (db, _dir) = db();
    NftStore::new(&db)
        .add_to_collection_index(&COLLECTION, 7)
        .unwrap();

    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![7u64]).unwrap()),
        "a one-element list at the collection id"
    );
}

#[test]
fn both_indexes_append_in_insertion_order() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    let other: [u8; 32] = [2u8; 32];

    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &other, 1)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();
    store.add_to_collection_index(&COLLECTION, 3).unwrap();

    let owner_bytes = row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]).unwrap();
    let expected: Vec<OwnerTokenEntry> = vec![(vec![1u8; 32], 7u64), (vec![2u8; 32], 1u64)];
    assert_eq!(
        owner_bytes,
        bincode::serialize(&expected).unwrap(),
        "both entries, in insertion order -- not sorted"
    );
    assert_eq!(decode_owner_tokens(&owner_bytes).unwrap(), expected);

    let collection_bytes = row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]).unwrap();
    assert_eq!(
        collection_bytes,
        bincode::serialize(&vec![7u64, 3u64]).unwrap(),
        "insertion order, so 3 follows 7"
    );
    assert_eq!(
        decode_collection_tokens(&collection_bytes).unwrap(),
        vec![7, 3]
    );
}

#[test]
fn re_adding_an_entry_rewrites_an_identical_list_rather_than_duplicating_it() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();

    let expected: Vec<OwnerTokenEntry> = vec![(vec![1u8; 32], 7u64)];
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]),
        Some(bincode::serialize(&expected).unwrap()),
        "still one element"
    );
    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![7u64]).unwrap()),
        "still one element"
    );
}

/// Emptying an owner's list DELETES the row; emptying a collection's list
/// WRITES an empty one. Inherited, and reproduced on both sides.
#[test]
fn removal_is_asymmetric_between_the_two_indexes() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();

    store
        .remove_from_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.remove_from_collection_index(&COLLECTION, 7).unwrap();

    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]),
        None,
        "the owner row is deleted when its list empties"
    );
    let empty: Vec<u64> = Vec::new();
    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&empty).unwrap()),
        "the collection row is written as an EMPTY list, not deleted"
    );
    assert_eq!(
        bincode::serialize(&empty).unwrap(),
        vec![0u8; 8],
        "an empty bincode list is eight zero bytes, so the row is present and empty"
    );
}

#[test]
fn removing_one_of_two_leaves_the_other_in_place_on_both_indexes() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    let other: [u8; 32] = [2u8; 32];
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &other, 1)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();
    store.add_to_collection_index(&COLLECTION, 3).unwrap();

    store
        .remove_from_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.remove_from_collection_index(&COLLECTION, 7).unwrap();

    let expected: Vec<OwnerTokenEntry> = vec![(vec![2u8; 32], 1u64)];
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]),
        Some(bincode::serialize(&expected).unwrap())
    );
    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&vec![3u64]).unwrap())
    );
}

/// The owner index keys on the WHOLE pair. Same token id in another
/// collection is a different entry.
#[test]
fn the_owner_index_distinguishes_the_same_token_id_in_two_collections() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    let other: [u8; 32] = [2u8; 32];
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &other, 7)
        .unwrap();
    store
        .remove_from_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();

    let expected: Vec<OwnerTokenEntry> = vec![(vec![2u8; 32], 7u64)];
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]),
        Some(bincode::serialize(&expected).unwrap()),
        "only the entry for the named collection is removed"
    );
}

#[test]
fn an_issuer_row_is_bincode_at_the_issuer_address_key() {
    let (db, _dir) = db();
    let i = issuer();
    IssuerStore::new(&db)
        .put_issuer(&Address::new(OWNER), &i)
        .unwrap();

    assert_eq!(
        row(&db, cf::ISSUER_REGISTRY, &[0xA1u8; 20]),
        Some(bincode::serialize(&i).unwrap())
    );
    assert_eq!(
        row(&db, cf::ISSUER_REGISTRY, &[0xA1u8; 32]),
        None,
        "nothing at a 32-byte spelling of the same address"
    );
}

/// `transfer_token` writes the token row, then `from`'s list, then `to`'s.
#[test]
fn a_transfer_writes_the_token_and_both_owner_lists() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    let to = Address::new([0xDD; 20]);
    store.put_token(&COLLECTION, 7, &token(7)).unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();

    store
        .transfer_token(&COLLECTION, 7, &Address::new(OWNER), &to)
        .unwrap();

    let mut expected_token = token(7);
    expected_token.owner = to;
    expected_token.approved = None;
    expected_token.transfer_count = 5;
    assert_eq!(
        row(&db, cf::NFT_TOKENS, &token_key_literal(COLLECTION, 7)),
        Some(bincode::serialize(&expected_token).unwrap()),
        "owner rewritten, approval cleared, transfer count bumped"
    );
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]),
        None,
        "the sender's list emptied, so its row is deleted"
    );
    let expected: Vec<OwnerTokenEntry> = vec![(vec![1u8; 32], 7u64)];
    assert_eq!(
        row(&db, cf::NFT_OWNER_INDEX, &[0xDDu8; 20]),
        Some(bincode::serialize(&expected).unwrap()),
        "and the recipient's list holds it"
    );
}

/// `burn_token` deletes the token, drops it from both indexes, and decrements
/// the collection's supply.
#[test]
fn a_burn_deletes_the_token_and_decrements_the_supply() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    store.put_collection(&COLLECTION, &collection()).unwrap();
    store.put_token(&COLLECTION, 7, &token(7)).unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();

    store
        .burn_token(&COLLECTION, 7, &Address::new(OWNER))
        .unwrap();

    assert_eq!(
        row(&db, cf::NFT_TOKENS, &token_key_literal(COLLECTION, 7)),
        None
    );
    assert_eq!(row(&db, cf::NFT_OWNER_INDEX, &[0xA1u8; 20]), None);
    let empty: Vec<u64> = Vec::new();
    assert_eq!(
        row(&db, cf::NFT_COLLECTION_INDEX, &[1u8; 32]),
        Some(bincode::serialize(&empty).unwrap())
    );
    let mut expected = collection();
    expected.total_supply = 1;
    assert_eq!(
        row(&db, cf::NFT_COLLECTIONS, &[1u8; 32]),
        Some(bincode::serialize(&expected).unwrap()),
        "total_supply decremented; next_token_id untouched"
    );
}

#[test]
fn every_round_trip_returns_the_value_that_was_written() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    let (c, t, i) = (collection(), token(7), issuer());
    store.put_collection(&COLLECTION, &c).unwrap();
    store.put_token(&COLLECTION, 7, &t).unwrap();
    store
        .add_to_owner_index(&Address::new(OWNER), &COLLECTION, 7)
        .unwrap();
    store.add_to_collection_index(&COLLECTION, 7).unwrap();
    IssuerStore::new(&db)
        .put_issuer(&Address::new(OWNER), &i)
        .unwrap();

    let got = store.get_collection(&COLLECTION).unwrap().unwrap();
    assert_eq!(
        bincode::serialize(&got).unwrap(),
        bincode::serialize(&c).unwrap()
    );
    let got = store.get_token(&COLLECTION, 7).unwrap().unwrap();
    assert_eq!(
        bincode::serialize(&got).unwrap(),
        bincode::serialize(&t).unwrap()
    );
    assert_eq!(
        store.get_owner_tokens(&Address::new(OWNER)).unwrap(),
        vec![(vec![1u8; 32], 7u64)]
    );
    assert_eq!(store.get_collection_tokens(&COLLECTION).unwrap(), vec![7]);
    let got = IssuerStore::new(&db)
        .get_issuer(&Address::new(OWNER))
        .unwrap()
        .unwrap();
    assert_eq!(
        bincode::serialize(&got).unwrap(),
        bincode::serialize(&i).unwrap()
    );
}

#[test]
fn a_malformed_row_is_an_error_from_every_decoding_reader() {
    let (db, _dir) = db();
    let store = NftStore::new(&db);
    db.put(cf::NFT_COLLECTIONS, &[1u8; 32], b"not a valid row")
        .unwrap();
    db.put(
        cf::NFT_TOKENS,
        &token_key_literal(COLLECTION, 7),
        b"not a valid row",
    )
    .unwrap();
    db.put(cf::NFT_OWNER_INDEX, &[0xA1u8; 20], b"not a valid row")
        .unwrap();
    db.put(cf::NFT_COLLECTION_INDEX, &[1u8; 32], b"not a valid row")
        .unwrap();
    db.put(cf::ISSUER_REGISTRY, &[0xA1u8; 20], b"not a valid row")
        .unwrap();

    assert!(store.get_collection(&COLLECTION).is_err());
    assert!(store.get_token(&COLLECTION, 7).is_err());
    assert!(store.get_owner_tokens(&Address::new(OWNER)).is_err());
    assert!(store.get_owner_token_count(&Address::new(OWNER)).is_err());
    assert!(store.get_collection_tokens(&COLLECTION).is_err());
    assert!(IssuerStore::new(&db)
        .get_issuer(&Address::new(OWNER))
        .is_err());
    assert!(IssuerStore::new(&db)
        .can_mint_documents(&Address::new(OWNER), None, 1_000)
        .is_err());

    // The `exists` guards do NOT decode, so corruption reads as presence.
    // Preserved deliberately; pinned here and, through dispatch, in
    // `nft_routing`.
    assert!(store.collection_exists(&COLLECTION).unwrap());
    assert!(store.token_exists(&COLLECTION, 7).unwrap());
    assert!(IssuerStore::new(&db)
        .is_registered(&Address::new(OWNER))
        .unwrap());
}
