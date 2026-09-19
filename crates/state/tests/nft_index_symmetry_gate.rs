//! `nft_index_symmetry_enabled_from_height`: the two NFT token indexes empty
//! the same way.
//!
//! ACTIVATION-AUDIT row OV-15.
//!
//! # The defect
//!
//! `v_remove_from_owner_index` DELETES its row when the last entry goes.
//! `v_remove_from_collection_index` WRITES an empty list instead. Two families
//! holding the same kind of value -- a list of token ids -- disagree about what
//! "no entries" looks like, and a burn of a collection's last token stages both
//! spellings in one transaction.
//!
//! Three consequences, in increasing order of how hard they are to notice:
//!
//!   * Anything that decides by row PRESENCE gets a different answer from each
//!     index. Both readers decode an absent row as an empty list, so the RPC
//!     surface hides it -- which is why this survived.
//!   * The empty rows accumulate, one per collection ever emptied, and nothing
//!     collects them. The owner index has no such rows at all.
//!   * The state ROOT differs between the two spellings, so this is a consensus
//!     change and not a tidy-up, which is why it is behind a height rather than
//!     simply fixed.
//!
//! # Why this is its OWN height
//!
//! It is the only one of the NFT remediation gates that changes which ROWS
//! exist rather than what a receipt says: a burn under this gate produces the
//! same receipt and a different state root. `nft_charged_receipt` moves the
//! receipts root and leaves the state root alone; this is the mirror image, and
//! an operator sequencing an upgrade needs them apart.
//!
//! # What each pair shows
//!
//! The SAME burn against the SAME seeded database twice, once with
//! `index_symmetry: false` -- the release configuration, and byte-for-byte the
//! unremediated binary -- and once with it true. The receipt is identical and
//! the rows are not.
//!
//! Spelled `{ index_symmetry: …, ..CLOSED }`, never field by field, so a gate
//! added to `NftGates` later leaves this fixture isolating exactly what it says
//! it isolates.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionConfig;
use sumchain_nft::ops::NftMintData;
use sumchain_primitives::{
    Address, NftOperation, NftTxData, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{NftExecutor, NftGates};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, NftCollectionData, NftStore};

const TS: u64 = 1_000;
const FEE: u128 = 100;
const CID: [u8; 32] = [7u8; 32];
const GATE_HEIGHT: u64 = 500;

const SYMMETRY: [NftGates; 2] = [
    NftGates::CLOSED,
    NftGates {
        index_symmetry: true,
        ..NftGates::CLOSED
    },
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn seed_collection(db: &Database, owner: &Address) {
    let config = CollectionConfig {
        owner_only_minting: true,
        transferable: true,
        burnable: true,
        ..Default::default()
    };
    NftStore::new(db)
        .put_collection(
            &CID,
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

fn mint_payload(to: Address) -> Vec<u8> {
    bincode::serialize(&NftMintData {
        to,
        metadata: Vec::new(),
        uri_type: "onchain".to_string(),
        uri_value: None,
    })
    .unwrap()
}

fn run(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    token_id: u64,
    op: NftOperation,
    data: Vec<u8>,
    gates: NftGates,
) -> bool {
    NftExecutor::execute_with_gates(
        view,
        &params(),
        sender,
        &NftTxData {
            collection_id: CID,
            token_id,
            operation: op,
            data,
        },
        &Address::new([9; 20]),
        FEE,
        TS,
        gates,
    )
    .expect("neither side may make the block unexecutable")
    .success
}

/// The two index rows as the candidate holds them: `None` for an absent row,
/// `Some(bytes)` for one that is there, whatever it encodes.
fn index_rows(view: &ExecutionView<'_, '_>, owner: &Address) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    (
        view.get(cf::NFT_OWNER_INDEX, owner.as_bytes()).unwrap(),
        view.get(cf::NFT_COLLECTION_INDEX, &CID).unwrap(),
    )
}

/// Burning the last token stops leaving an empty collection-index row behind.
#[test]
fn emptying_the_collection_index_starts_deleting_its_row() {
    for gates in SYMMETRY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        let sender = owner.address();
        seed_collection(&db, &sender);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        assert!(
            run(
                &mut view,
                &sender,
                0,
                NftOperation::Mint,
                mint_payload(sender),
                gates
            ),
            "the mint is lawful on both sides"
        );
        let (owner_row, collection_row) = index_rows(&view, &sender);
        assert!(
            owner_row.is_some() && collection_row.is_some(),
            "both indexes carry the token before the burn \
             (index_symmetry={})",
            gates.index_symmetry
        );

        assert!(
            run(&mut view, &sender, 1, NftOperation::Burn, Vec::new(), gates),
            "the burn is lawful on both sides -- this gate changes the rows a \
             burn leaves, not whether it is allowed"
        );

        let (owner_row, collection_row) = index_rows(&view, &sender);
        assert_eq!(
            owner_row, None,
            "the owner index deletes its row on both sides; that half was \
             never the defect (index_symmetry={})",
            gates.index_symmetry
        );
        assert_eq!(
            collection_row.is_some(),
            !gates.index_symmetry,
            "OV-15: below the gate the emptied collection list is WRITTEN as an \
             empty row and the owner list is DELETED; at the gate both are \
             deleted (index_symmetry={}, row={collection_row:?})",
            gates.index_symmetry
        );

        // Below the gate, say exactly what the leftover row is: an ENCODED
        // EMPTY LIST, not a stray byte. If it ever became something else this
        // assertion is what would say so.
        if !gates.index_symmetry {
            assert_eq!(
                collection_row.as_deref(),
                Some(&bincode::serialize(&Vec::<u64>::new()).unwrap()[..]),
                "and it is the encoding of an empty list"
            );
        }

        // Both readers answer the same way whichever spelling is on disk, which
        // is precisely why nothing above the storage layer noticed.
        assert_eq!(
            NftExecutor::v_get_collection_tokens(&view, &CID).unwrap(),
            Vec::<u64>::new(),
            "the READER cannot tell the two spellings apart (index_symmetry={})",
            gates.index_symmetry
        );
    }
}

/// Emptying a collection's list while the OWNER still holds other tokens is
/// untouched: only the empty case differs.
///
/// Without this the gate could be "delete the collection row on every burn",
/// which would lose the surviving entries.
#[test]
fn a_burn_that_leaves_entries_writes_the_same_row_on_both_sides() {
    let mut rows: Vec<Option<Vec<u8>>> = Vec::new();
    for gates in SYMMETRY {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        let sender = owner.address();
        seed_collection(&db, &sender);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for _ in 0..2 {
            assert!(run(
                &mut view,
                &sender,
                0,
                NftOperation::Mint,
                mint_payload(sender),
                gates
            ));
        }
        assert!(run(
            &mut view,
            &sender,
            1,
            NftOperation::Burn,
            Vec::new(),
            gates
        ));

        assert_eq!(
            NftExecutor::v_get_collection_tokens(&view, &CID).unwrap(),
            vec![2u64],
            "the surviving token is still listed (index_symmetry={})",
            gates.index_symmetry
        );
        rows.push(index_rows(&view, &sender).1);
    }
    assert_eq!(
        rows[0], rows[1],
        "a burn that leaves entries writes the SAME bytes on both sides"
    );
    assert!(rows[0].is_some(), "and that row is there");
}

/// The height, not only the flag: `NftGates::from_params` reads the field.
///
/// The flag tests above drive `execute_with_gates`, which cannot tell whether
/// the wiring from `ChainParams` exists. This runs the same burn through
/// `BlockExecutor` at two heights around one configured activation.
#[test]
fn the_configured_height_is_what_switches_the_collection_index_row() {
    for (height, open) in [(GATE_HEIGHT - 1, false), (GATE_HEIGHT, true)] {
        let mut p = ChainParams::with_v2_enabled();
        p.nft_index_symmetry_enabled_from_height = Some(GATE_HEIGHT);

        let (_state, db, _dir, executor) = setup_with_params(p);
        let owner = KeyPair::generate();
        fund(&db, &owner, 100_000_000);
        let sender = owner.address();
        let proposer = Address::new([9; 20]);
        seed_collection(&db, &sender);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        for (nonce, token, op, data) in [
            (0u64, 0u64, NftOperation::Mint, mint_payload(sender)),
            (1, 1, NftOperation::Burn, Vec::new()),
        ] {
            let t = TransactionV2 {
                chain_id: CHAIN_ID,
                from: sender,
                fee: FEE,
                nonce,
                payload: TxPayload::Nft(NftTxData {
                    collection_id: CID,
                    token_id: token,
                    operation: op,
                    data,
                }),
            };
            let sig = sign(t.signing_hash().as_bytes(), owner.private_key());
            let t = SignedTransaction::new_v2(t, *sig.as_bytes(), *owner.public_key().as_bytes());
            assert_eq!(
                executor
                    .execute_tx(&mut view, &t, &proposer, height, TS)
                    .unwrap()
                    .status,
                TxStatus::Success,
                "{op:?} at height {height}"
            );
        }

        assert_eq!(
            index_rows(&view, &sender).1.is_some(),
            !open,
            "at height {height} against an activation of {GATE_HEIGHT}, the \
             emptied collection-index row must be {}",
            if open { "gone" } else { "an empty list" }
        );
    }
}
