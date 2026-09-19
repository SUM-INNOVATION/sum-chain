//! `nft_update_path_parity_enabled_from_height`: the NFT arms that write
//! metadata or a collection config apply the rules the CREATION arms apply.
//!
//! ACTIVATION-AUDIT rows OV-10, the first half of RY-2, and the zero-owner
//! hazard recorded under RY-3.
//!
//! # Why one height for the three
//!
//! All three are the same asymmetry: a rule the creation arm enforces and a
//! later-write arm does not.
//!
//!   * `execute_mint` checks `max_metadata_bytes` and requires the fee to cover
//!     `storage_fee_per_byte`. `UpdateMetadata` writes `data.to_vec()` straight
//!     into the token with neither check, and `BatchMint` clones per-request
//!     metadata with neither, for any number of requests. **Both of those
//!     values are set in the release `genesis.json`** — `max_metadata_bytes:
//!     16384` and `storage_fee_per_byte: 100` — which is why this file
//!     configures them rather than taking `ChainParams::default()`, whose
//!     `min_fee` is 1 and not the release's 1000.
//!   * collection creation zeroes `royalty_recipient` when `royalty_bps` is
//!     zero. `UpdateCollectionConfig` sets one anyway.
//!   * collection creation writes `owner: *sender`, an address that signed the
//!     transaction, so no collection is ever created ownerless.
//!     `TransferCollectionOwnership` accepts `Address::ZERO` from the payload.
//!
//! Activating any one alone leaves the others open at the same price, and all
//! three turn a success receipt into a failed one — none can abort a block — so
//! there is nothing to sequence between them.
//!
//! # What this does NOT do
//!
//! RY-1 is untouched: a royalty is still recorded and never paid, because a
//! transfer carries no consideration for one to be a fraction of. The SECOND
//! half of RY-2 is untouched too: `NftUpdateCollectionConfigData` has no
//! `new_royalty_bps` field, so a royalty still cannot be changed after
//! creation, and adding one is a wire change rather than an executor change.
//!
//! # What each pair shows
//!
//! Every case runs the SAME transaction against the SAME seeded database twice,
//! once with `update_path_parity: false` — the release configuration, and
//! byte-for-byte the unremediated binary — and once with it true, and asserts
//! the two nodes disagree. Each case also drives the LAWFUL form of the same
//! transaction and asserts both sides accept it, so what the gate refuses is
//! the rule-breaking transaction and not the operation.
//!
//! Spelled `{ update_path_parity: …, ..CLOSED }`, never field by field: the
//! pair must differ in exactly one decision, and `NftGates::OPEN` would also
//! open the receipt-failure rule (which changes whether a block exists at all)
//! and the token-authority rules (which decide who may rewrite a token).

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionConfig;
use sumchain_nft::ops::{
    NftBatchMintData, NftBatchMintRequest, NftMintData, NftTransferCollectionOwnershipData,
    NftUpdateCollectionConfigData,
};
use sumchain_primitives::{Address, NftOperation, NftTxData};
use sumchain_state::{NftExecutor, NftGates};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{Database, NftCollectionData, NftStore};

const TS: u64 = 1_000;

/// The release `genesis.json`'s three relevant values, not the crate defaults.
///
/// `ChainParams::default()` has `min_fee: 1`; the committed runtime
/// `genesis.json` has `min_fee: 1000`, `storage_fee_per_byte: 100` and
/// `max_metadata_bytes: 16384`. The whole point of OV-10 is that the release
/// SETS these and two of three metadata arms ignore them, so measuring against
/// the defaults would measure the wrong chain.
fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.min_fee = 1_000;
    p.storage_fee_per_byte = 100;
    p.max_metadata_bytes = 16_384;
    p
}

const PARITY: [NftGates; 2] = [
    NftGates::CLOSED,
    NftGates {
        update_path_parity: true,
        ..NftGates::CLOSED
    },
];

#[allow(clippy::too_many_arguments)]
fn nft_at(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    cid: [u8; 32],
    token_id: u64,
    op: NftOperation,
    data: Vec<u8>,
    fee: u128,
    gates: NftGates,
) -> bool {
    let proposer = Address::new([9; 20]);
    NftExecutor::execute_with_gates(
        view,
        &params(),
        sender,
        &NftTxData {
            collection_id: cid,
            token_id,
            operation: op,
            data,
        },
        &proposer,
        fee,
        TS,
        gates,
    )
    .unwrap()
    .success
}

fn seed_collection(db: &Database, owner: &Address, id: &[u8; 32], royalty_bps: u16) {
    NftStore::new(db)
        .put_collection(
            id,
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
                metadata_updatable: true,
                owner_only_minting: true,
                royalty_bps,
                royalty_recipient: Address::ZERO,
                base_uri: None,
                created_at: TS,
            },
        )
        .unwrap();
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

/// `min_fee` + `storage_fee_per_byte` * n, which is `calculate_nft_storage_fee`.
fn storage_fee(n: usize) -> u128 {
    1_000 + 100 * n as u128
}

// ── OV-10: UpdateMetadata ───────────────────────────────────────────────────

#[test]
fn update_metadata_starts_applying_the_mints_size_limit_and_storage_fee() {
    for gates in PARITY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000_000);
        let sender = owner.address();
        let cid = [7u8; 32];
        seed_collection(&db, &sender, &cid, 0);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            nft_at(
                &mut view,
                &sender,
                cid,
                0,
                NftOperation::Mint,
                mint_payload(sender),
                storage_fee(0),
                gates,
            ),
            "the mint itself is lawful on both sides"
        );

        // A rewrite that respects both rules: accepted either way.
        let lawful = nft_at(
            &mut view,
            &sender,
            cid,
            1,
            NftOperation::UpdateMetadata,
            vec![0xAA; 100],
            storage_fee(100),
            gates,
        );
        assert!(
            lawful,
            "a rewrite inside the limit that pays the per-byte fee is accepted on \
             both sides -- the gate refuses a rule-breaking transaction, not the \
             operation (update_path_parity={})",
            gates.update_path_parity
        );

        // One byte over `max_metadata_bytes`, fee no object.
        let oversized = nft_at(
            &mut view,
            &sender,
            cid,
            1,
            NftOperation::UpdateMetadata,
            vec![0xBB; 16_385],
            storage_fee(16_385),
            gates,
        );
        assert_eq!(
            oversized, !gates.update_path_parity,
            "OV-10: a rewrite one byte past max_metadata_bytes is ADMITTED below \
             the gate, although the mint arm refuses the same bytes \
             (update_path_parity={})",
            gates.update_path_parity
        );

        // Inside the limit, but paying only `min_fee` for 100 stored bytes.
        let underpaid = nft_at(
            &mut view,
            &sender,
            cid,
            1,
            NftOperation::UpdateMetadata,
            vec![0xCC; 100],
            1_000,
            gates,
        );
        assert_eq!(
            underpaid, !gates.update_path_parity,
            "OV-10: 100 bytes of storage for min_fee alone is ADMITTED below the \
             gate, although the mint arm charges storage_fee_per_byte for the \
             same bytes (update_path_parity={})",
            gates.update_path_parity
        );
    }
}

// ── OV-10: BatchMint ────────────────────────────────────────────────────────

#[test]
fn batch_mint_starts_applying_the_mints_size_limit_and_storage_fee() {
    for gates in PARITY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000_000);
        let sender = owner.address();
        let cid = [8u8; 32];
        seed_collection(&db, &sender, &cid, 0);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let batch = |sizes: &[usize]| {
            bincode::serialize(&NftBatchMintData {
                requests: sizes
                    .iter()
                    .map(|n| NftBatchMintRequest {
                        to: sender,
                        metadata: vec![0xDD; *n],
                    })
                    .collect(),
            })
            .unwrap()
        };

        let lawful = nft_at(
            &mut view,
            &sender,
            cid,
            0,
            NftOperation::BatchMint,
            batch(&[10, 20]),
            storage_fee(30),
            gates,
        );
        assert!(
            lawful,
            "a batch inside the limit that pays for its total bytes is accepted on \
             both sides (update_path_parity={})",
            gates.update_path_parity
        );

        let oversized = nft_at(
            &mut view,
            &sender,
            cid,
            0,
            NftOperation::BatchMint,
            batch(&[10, 16_385]),
            storage_fee(16_395),
            gates,
        );
        assert_eq!(
            oversized, !gates.update_path_parity,
            "OV-10: one request past max_metadata_bytes carries the whole batch \
             below the gate (update_path_parity={})",
            gates.update_path_parity
        );

        let underpaid = nft_at(
            &mut view,
            &sender,
            cid,
            0,
            NftOperation::BatchMint,
            batch(&[100, 100]),
            1_000,
            gates,
        );
        assert_eq!(
            underpaid, !gates.update_path_parity,
            "OV-10: 200 bytes of storage across a batch for min_fee alone is \
             ADMITTED below the gate (update_path_parity={})",
            gates.update_path_parity
        );
    }
}

// ── RY-2, first half: UpdateCollectionConfig ────────────────────────────────

#[test]
fn a_royalty_recipient_stops_being_settable_on_a_collection_that_pays_none() {
    for gates in PARITY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000_000);
        let sender = owner.address();
        let free = [0x21u8; 32];
        let paying = [0x22u8; 32];
        seed_collection(&db, &sender, &free, 0);
        seed_collection(&db, &sender, &paying, 250);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let set_recipient = bincode::serialize(&NftUpdateCollectionConfigData {
            new_royalty_recipient: Some(Address::new([0x77; 20])),
            new_base_uri: None,
        })
        .unwrap();

        let on_paying = nft_at(
            &mut view,
            &sender,
            paying,
            0,
            NftOperation::UpdateCollectionConfig,
            set_recipient.clone(),
            storage_fee(0),
            gates,
        );
        assert!(
            on_paying,
            "a recipient on a collection that DOES pay a royalty is accepted on \
             both sides (update_path_parity={})",
            gates.update_path_parity
        );

        let on_free = nft_at(
            &mut view,
            &sender,
            free,
            0,
            NftOperation::UpdateCollectionConfig,
            set_recipient,
            storage_fee(0),
            gates,
        );
        assert_eq!(
            on_free, !gates.update_path_parity,
            "RY-2: creation zeroes the recipient when royalty_bps is zero and the \
             update arm sets one anyway, until the gate (update_path_parity={})",
            gates.update_path_parity
        );

        // And the ROW, not only the receipt.
        let stored = NftExecutor::v_get_collection(&view, &free)
            .unwrap()
            .expect("the collection is there either way");
        assert_eq!(
            stored.royalty_recipient != Address::ZERO,
            !gates.update_path_parity,
            "RY-2: the recipient is IN the row below the gate and absent at it"
        );
    }
}

// ── RY-3, the zero-owner hazard: TransferCollectionOwnership ────────────────

/// The third instance of the same asymmetry, and the reason it is the same
/// height rather than a ninth field.
///
/// `execute_create_collection` writes `owner: *sender` — an address that
/// signed the transaction, so no collection is ever CREATED ownerless.
/// `TransferCollectionOwnership` takes `new_owner` from the payload and checks
/// nothing about it, so it accepts `Address::ZERO`: the value the very same
/// creation arm writes into `royalty_recipient` to mean "no recipient". The
/// result is a collection that can never be reconfigured — `UpdateCollectionConfig`
/// requires `collection.owner == sender` and nobody signs for the zero address —
/// and, while `owner_only_minting` is set, can never be minted in again, by
/// anybody, at any height. No operation in the subsystem undoes it.
///
/// RY-3's own sentence is NOT what this closes: transferring a collection
/// still moves no token and still hands the new owner minting rights, which is
/// ordinary Ownable semantics and not a rule this tree states differently.
/// What is closed is the one destination creation cannot produce.
#[test]
fn a_collection_stops_being_transferable_to_the_zero_address() {
    for gates in PARITY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000_000);
        let sender = owner.address();
        let burned = [0x31u8; 32];
        let handed_on = [0x32u8; 32];
        seed_collection(&db, &sender, &burned, 0);
        seed_collection(&db, &sender, &handed_on, 0);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let to = |a: Address| {
            bincode::serialize(&NftTransferCollectionOwnershipData { new_owner: a }).unwrap()
        };

        // A transfer to a real address: the OPERATION is untouched on both sides.
        let successor = Address::new([0x55; 20]);
        let lawful = nft_at(
            &mut view,
            &sender,
            handed_on,
            0,
            NftOperation::TransferCollectionOwnership,
            to(successor),
            storage_fee(0),
            gates,
        );
        assert!(
            lawful,
            "handing a collection to another address is accepted on both sides -- \
             the gate refuses one destination, not the operation \
             (update_path_parity={})",
            gates.update_path_parity
        );
        assert_eq!(
            NftExecutor::v_get_collection(&view, &handed_on)
                .unwrap()
                .expect("the collection is there either way")
                .owner,
            successor,
            "and the row moves, on both sides"
        );

        // The same transaction to the null sentinel.
        let to_zero = nft_at(
            &mut view,
            &sender,
            burned,
            0,
            NftOperation::TransferCollectionOwnership,
            to(Address::ZERO),
            storage_fee(0),
            gates,
        );
        assert_eq!(
            to_zero, !gates.update_path_parity,
            "RY-3: creation binds `owner` to the signing sender and the transfer \
             arm accepts the zero address anyway, until the gate \
             (update_path_parity={})",
            gates.update_path_parity
        );

        // And the ROW, not only the receipt: below the gate the collection is
        // left unreconfigurable, above it the original owner still holds it.
        let stored = NftExecutor::v_get_collection(&view, &burned)
            .unwrap()
            .expect("the collection survives either way");
        assert_eq!(
            stored.owner == Address::ZERO,
            !gates.update_path_parity,
            "RY-3: the ownerless row EXISTS below the gate and is not written at it"
        );
        assert_eq!(
            stored.owner == sender,
            gates.update_path_parity,
            "RY-3: above the gate the refusal leaves the collection where it was"
        );
    }
}
