//! `nft_collection_id_nonce_enabled_from_height`: a collection id stops being
//! a function of the block clock alone.
//!
//! ACTIVATION-AUDIT row CI-1.
//!
//! # The defect
//!
//! `CollectionId::new(creator, name, nonce)` takes the BLOCK TIMESTAMP as its
//! whole nonce, and the NFT arm forwards the real one. So the id is
//! `hash(creator || name || timestamp)` and nothing else. Two blocks that carry
//! the same timestamp therefore hand one creator ONE id for one name, and the
//! second creation is refused by the duplicate check -- with
//! `Collection already exists`, naming a collection that creator does not own
//! and cannot obtain, at any later height, under that name.
//!
//! What makes it reachable rather than theoretical: the proposer CHOOSES the
//! timestamp. Nothing in this executor requires it to advance, nothing compares
//! it to the parent block's, and a node with a coarse or stopped clock produces
//! a run of blocks sharing one value. It is also the one subsystem where the
//! real timestamp reaching the executor is itself the problem, which is why NFT
//! is absent from the block-timestamp class in the audit.
//!
//! Note the SHAPE of the failure. It is not that two different collections
//! collide on one id -- the duplicate check catches that. It is that a creator
//! is permanently refused a NAME whose id another of its own transactions
//! already took, and the refusal message describes a state of affairs that is
//! not true from the creator's point of view.
//!
//! # The remedy, and why the account nonce
//!
//! At and above the gate the preimage gains the creator's ACCOUNT NONCE. It is
//! consensus state, read from the same view the transaction executes against,
//! so every node computes the same id; `deduct_fee` has already incremented it
//! by the time the creation arm runs, so two creations in ONE block see two
//! values; and it only ever goes up, so the clock no longer has to move for the
//! id to.
//!
//! The nonce is APPENDED, so the two rules hash preimages that differ in length
//! by exactly eight bytes with a shared prefix. Ids minted under the two rules
//! live in disjoint spaces: activating this is a change of address space for
//! collections created after the height, not a rule that could collide with
//! what the chain already holds.
//!
//! # What this does NOT do
//!
//! It does not renumber anything. No existing collection's id is recomputed,
//! and nothing migrates -- `nft_getCollection` answers about the same 32 bytes
//! it always did. Every test below drives a CREATION; none touches a
//! collection that exists.
//!
//! Spelled `{ collection_id_nonce: …, ..CLOSED }`, never field by field.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::{CollectionConfig, CollectionId};
use sumchain_nft::ops::CreateCollectionData;
use sumchain_primitives::{
    Address, NftOperation, NftTxData, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{NftExecutor, NftGates, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

/// One timestamp for every block in this file. That is the point: two blocks
/// SHARING a timestamp is the condition CI-1 is about, and a fixture that let
/// the clock advance would not reach the defect at all.
const TS: u64 = 1_000;
const FEE: u128 = 100;
const NAME: &str = "Deeds";
const GATE_HEIGHT: u64 = 500;

const NONCE_GATE: [NftGates; 2] = [
    NftGates::CLOSED,
    NftGates {
        collection_id_nonce: true,
        ..NftGates::CLOSED
    },
];

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn create_payload(name: &str) -> Vec<u8> {
    bincode::serialize(&CreateCollectionData {
        name: name.to_string(),
        symbol: "SYM".to_string(),
        description: "d".to_string(),
        config: CollectionConfig {
            owner_only_minting: true,
            transferable: true,
            burnable: true,
            ..Default::default()
        },
        base_uri: None,
    })
    .unwrap()
}

/// One `CreateCollection`, through the gated seam.
fn create(
    view: &mut ExecutionView<'_, '_>,
    sender: &Address,
    name: &str,
    gates: NftGates,
) -> (bool, Option<[u8; 32]>, Option<String>) {
    let r = NftExecutor::execute_with_gates(
        view,
        &params(),
        sender,
        &NftTxData {
            collection_id: [0u8; 32],
            token_id: 0,
            operation: NftOperation::CreateCollection,
            data: create_payload(name),
        },
        &Address::new([9; 20]),
        FEE,
        TS,
        gates,
    )
    .expect("a duplicate name is a failed receipt, not an unexecutable block");
    (r.success, r.collection_id, r.error)
}

/// Two creations of the same name by the same sender, both at `TS`.
///
/// Below the gate the second is refused as a duplicate. At the gate both
/// succeed with different ids.
#[test]
fn the_same_creator_can_take_the_same_name_twice_under_one_timestamp() {
    for gates in NONCE_GATE {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let creator = KeyPair::generate();
        fund(&db, &creator, 100_000_000);
        let sender = creator.address();

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let (first_ok, first_id, _) = create(&mut view, &sender, NAME, gates);
        assert!(
            first_ok,
            "the first creation succeeds on both sides (collection_id_nonce={})",
            gates.collection_id_nonce
        );

        let (second_ok, second_id, err) = create(&mut view, &sender, NAME, gates);
        assert_eq!(
            second_ok, gates.collection_id_nonce,
            "CI-1: under one timestamp the second creation of the same name is \
             refused below the gate and accepted at it \
             (collection_id_nonce={}, error={err:?})",
            gates.collection_id_nonce
        );

        if gates.collection_id_nonce {
            assert_ne!(
                first_id, second_id,
                "and the two collections are two different ids"
            );
        } else {
            assert_eq!(
                err.as_deref(),
                Some("Collection already exists"),
                "and the refusal names a collection the creator does not own"
            );
        }
    }
}

/// The id at the gate is exactly `new_with_account_nonce`, computed from the
/// nonce AFTER `deduct_fee` advanced it.
///
/// Recomputed here from the public constructor rather than compared to a
/// hard-coded 32 bytes: the claim is that the executor derives the id the
/// documented way, not that it derives some particular value.
#[test]
fn the_id_at_the_gate_is_the_account_nonce_preimage() {
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let creator = KeyPair::generate();
    fund(&db, &creator, 100_000_000);
    let sender = creator.address();

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let before = StateManager::v_get_nonce(&view, &sender).unwrap();
    assert_eq!(before, 0, "a fresh account starts at nonce zero");

    let gates = NftGates {
        collection_id_nonce: true,
        ..NftGates::CLOSED
    };
    let (ok, id, _) = create(&mut view, &sender, NAME, gates);
    assert!(ok);

    let after = StateManager::v_get_nonce(&view, &sender).unwrap();
    assert_eq!(
        after,
        before + 1,
        "deduct_fee advanced the nonce before the creation arm ran, which is \
         what makes two creations in one block see two values"
    );
    assert_eq!(
        id.map(CollectionId),
        Some(CollectionId::new_with_account_nonce(
            &sender, NAME, TS, after
        )),
        "the id is hash(creator || name || timestamp || account_nonce), with \
         the POST-deduction nonce"
    );
    assert_ne!(
        id.map(CollectionId),
        Some(CollectionId::new(&sender, NAME, TS)),
        "and it is NOT the id the same transaction produces below the gate"
    );
}

/// Two DIFFERENT creators are unaffected: the creator address was always in
/// the preimage, and still is.
///
/// Without this the gate could be "make ids unique per transaction" in a way
/// that lost the creator binding.
#[test]
fn two_creators_still_get_two_ids_for_one_name_on_both_sides() {
    for gates in NONCE_GATE {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        fund(&db, &a, 100_000_000);
        fund(&db, &b, 100_000_000);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let (ok_a, id_a, _) = create(&mut view, &a.address(), NAME, gates);
        let (ok_b, id_b, err_b) = create(&mut view, &b.address(), NAME, gates);
        assert!(
            ok_a && ok_b,
            "one name, two creators, both accepted (collection_id_nonce={}, \
             error={err_b:?})",
            gates.collection_id_nonce
        );
        assert_ne!(
            id_a, id_b,
            "and two ids (collection_id_nonce={})",
            gates.collection_id_nonce
        );
    }
}

/// The height, not only the flag: `NftGates::from_params` reads the field.
#[test]
fn the_configured_height_is_what_switches_the_collection_id() {
    for (height, open) in [(GATE_HEIGHT - 1, false), (GATE_HEIGHT, true)] {
        let mut p = ChainParams::with_v2_enabled();
        p.nft_collection_id_nonce_enabled_from_height = Some(GATE_HEIGHT);

        let (_state, db, _dir, executor) = setup_with_params(p);
        let creator = KeyPair::generate();
        fund(&db, &creator, 100_000_000);
        let sender = creator.address();
        let proposer = Address::new([9; 20]);

        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let t = TransactionV2 {
            chain_id: CHAIN_ID,
            from: sender,
            fee: FEE,
            nonce: 0,
            payload: TxPayload::Nft(NftTxData {
                collection_id: [0u8; 32],
                token_id: 0,
                operation: NftOperation::CreateCollection,
                data: create_payload(NAME),
            }),
        };
        let sig = sign(t.signing_hash().as_bytes(), creator.private_key());
        let t = SignedTransaction::new_v2(t, *sig.as_bytes(), *creator.public_key().as_bytes());
        assert_eq!(
            executor
                .execute_tx(&mut view, &t, &proposer, height, TS)
                .unwrap()
                .status,
            TxStatus::Success
        );

        // Which id the row landed under is the whole observable.
        let legacy = *CollectionId::new(&sender, NAME, TS).as_bytes();
        let gated = *CollectionId::new_with_account_nonce(&sender, NAME, TS, 1).as_bytes();
        assert_ne!(legacy, gated, "the two rules name two different rows");

        assert_eq!(
            NftExecutor::v_collection_exists(&view, &gated).unwrap(),
            open,
            "at height {height} against an activation of {GATE_HEIGHT}, the \
             account-nonce id must{} be the one written",
            if open { "" } else { " not" }
        );
        assert_eq!(
            NftExecutor::v_collection_exists(&view, &legacy).unwrap(),
            !open,
            "and the clock-only id must{} be",
            if open { " not" } else { "" }
        );
    }
}
