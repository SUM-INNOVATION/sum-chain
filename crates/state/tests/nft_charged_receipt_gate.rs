//! `nft_charged_receipt_enabled_from_height`: a failed NFT receipt reports the
//! fee the executor actually took.
//!
//! ACTIVATION-AUDIT row OV-9.
//!
//! # The defect
//!
//! `NftExecutor::execute_ungated` deducts the fee BEFORE the dispatch match, so
//! every guard below it -- an absent collection, a collection somebody else
//! owns, a locked token, a payload that will not decode -- refuses a
//! transaction whose fee is already debited, whose proposer is already
//! credited, and whose nonce has already advanced. The receipt the block
//! executor writes for that refusal says `fee_paid: 0`.
//!
//! So the receipt and the state disagree on every failed NFT transaction, and
//! they disagree in the direction that matters: anyone reconciling balances
//! from receipts -- an explorer, an exchange, a fee-revenue accounting job --
//! reads zero and finds the balance short. The receipts root is in the block
//! header, so the lie is committed to rather than merely printed.
//!
//! # Why this is its OWN height
//!
//! `nft_receipt_failure_enabled_from_height` decides whether a block EXISTS at
//! all: below it certain NFT refusals return `Err` and the whole block is
//! unexecutable. This one changes a NUMBER in a receipt of a block that exists
//! under either setting. Both move the receipts root, so both are consensus
//! changes, but the blast radii are nowhere near each other and an operator
//! must be able to sequence them -- which is the same argument the
//! receipt-failure and token-authority gates were split on.
//!
//! # What is NOT changed
//!
//! The fee itself. Nothing here makes a refused transaction cheaper, refunds
//! it, or moves the deduction: `deduct_fee` still runs first, deliberately,
//! because an unpaid refusal is the cheaper transaction to spam. What changes
//! is only what the receipt SAYS about a payment that already happened. The
//! sibling assertions below check the balance, the proposer credit and the
//! nonce on both sides of the gate and require them IDENTICAL.
//!
//! # The one refusal whose zero is true
//!
//! An insufficient balance never reaches `deduct_fee`'s writes, so nothing was
//! taken and `0` is the honest number. The gate is therefore a rule about what
//! was PAID rather than a blanket "report the fee", which would replace one
//! false receipt with another. Two tests cover it, at two different seams,
//! because the refusal can arrive from either:
//!
//!   * `BlockExecutor::validate_tx` refuses a sender who cannot pay BEFORE the
//!     NFT arm runs at all, and writes `fee_paid: 0` from its own arm. That
//!     path never touches this gate and must stay untouched.
//!   * `NftExecutor::deduct_fee` has its own balance check, and it is the one
//!     the receipt-failure gate converts into a `Failed` receipt. That one goes
//!     through the gated code and has to come back carrying zero.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionConfig;
use sumchain_nft::ops::NftMintData;
use sumchain_primitives::{
    Address, NftOperation, NftTxData, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{NftExecutor, NftGates, StateManager};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{Database, NftCollectionData, NftStore};

const TS: u64 = 1_000;
const FEE: u128 = 100;
const FUNDED: u128 = 100_000_000;
const GATE_HEIGHT: u64 = 500;
const CID: [u8; 32] = [7u8; 32];

/// The two nodes this file compares: one below the activation height and one
/// at it, differing in that and nothing else.
///
/// The height is carried in `ChainParams` rather than handed to
/// `execute_with_gates`, because the thing under test is a field of the
/// RECEIPT, and only `BlockExecutor` writes one.
fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.nft_charged_receipt_enabled_from_height = Some(GATE_HEIGHT);
    p
}

/// Below the gate and at it. The whole test matrix.
const HEIGHTS: [(u64, &str); 2] = [
    (GATE_HEIGHT - 1, "below"),
    (GATE_HEIGHT, "at the activation height"),
];

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

fn mint_payload(to: Address) -> Vec<u8> {
    bincode::serialize(&NftMintData {
        to,
        metadata: Vec::new(),
        uri_type: "onchain".to_string(),
        uri_value: None,
    })
    .unwrap()
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

/// What one refused transaction left behind, receipt and state together.
struct Refusal {
    status: TxStatus,
    fee_paid: u128,
    sender_balance: u128,
    sender_nonce: u64,
    proposer_balance: u128,
}

/// A mint into a collection owned by somebody else: refused by
/// `owner_only_minting`, below the deduction it has already paid.
fn refused_mint(height: u64, funded: u128, fee: u128) -> Refusal {
    let (_state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, funded);
    let proposer = Address::new([9; 20]);
    seed_collection(&db, &Address::new([0xEE; 20]));

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let t = nft_tx(
        &actor,
        0,
        fee,
        CID,
        0,
        NftOperation::Mint,
        mint_payload(actor.address()),
    );
    let r = executor
        .execute_tx(&mut view, &t, &proposer, height, TS)
        .expect("a refused mint is a receipt, not an unexecutable block");
    Refusal {
        status: r.status,
        fee_paid: r.fee_paid,
        sender_balance: StateManager::v_get_balance(&view, &actor.address()).unwrap(),
        sender_nonce: StateManager::v_get_nonce(&view, &actor.address()).unwrap(),
        proposer_balance: StateManager::v_get_balance(&view, &proposer).unwrap(),
    }
}

/// The receipt starts reporting the fee, and NOTHING else about the
/// transaction changes.
#[test]
fn a_refused_nft_receipt_starts_reporting_the_fee_it_charged() {
    for (height, label) in HEIGHTS {
        let r = refused_mint(height, FUNDED, FEE);
        let open = height >= GATE_HEIGHT;

        assert_eq!(
            r.status,
            TxStatus::Failed(2),
            "{label}: the transaction is refused either way -- this gate is \
             about the receipt's fee, not about which transactions succeed"
        );
        assert_eq!(
            r.fee_paid,
            if open { FEE } else { 0 },
            "OV-9 ({label}): the receipt reports {} for a fee of {FEE} that was \
             actually taken",
            r.fee_paid
        );

        // The three state facts, identical on both sides. If any of these moved
        // with the gate, this would be a fee change wearing a receipt gate.
        assert_eq!(
            r.sender_balance,
            FUNDED - FEE,
            "{label}: the fee was taken, below the gate and at it"
        );
        assert_eq!(
            r.sender_nonce, 1,
            "{label}: the nonce advanced, below the gate and at it"
        );
        assert_eq!(
            r.proposer_balance, FEE,
            "{label}: the proposer keeps it, below the gate and at it"
        );
    }
}

/// The receipt and the state agree at the gate, and disagree below it.
///
/// The same two runs read as one sentence rather than two numbers: below the
/// gate `fee_paid` and the balance delta are different numbers for the same
/// movement of the same coins.
#[test]
fn below_the_gate_the_nft_receipt_and_the_balance_disagree() {
    let below = refused_mint(GATE_HEIGHT - 1, FUNDED, FEE);
    let at = refused_mint(GATE_HEIGHT, FUNDED, FEE);

    let spent_below = FUNDED - below.sender_balance;
    let spent_at = FUNDED - at.sender_balance;
    println!(
        "OV-9: below the gate the sender spent {spent_below} and the receipt \
         says {}; at the gate the sender spent {spent_at} and the receipt says \
         {}",
        below.fee_paid, at.fee_paid
    );

    assert_eq!(spent_below, spent_at, "the same coins moved either way");
    assert_ne!(
        below.fee_paid, spent_below,
        "below the gate the receipt contradicts the balance"
    );
    assert_eq!(
        at.fee_paid, spent_at,
        "at the gate the receipt is the balance delta"
    );
}

/// A sender who cannot pay is refused ahead of the NFT arm, and the gate does
/// not touch that.
///
/// `BlockExecutor::validate_tx` runs first and answers
/// `TxStatus::InsufficientBalance` with `fee_paid: 0` from its own arm, so the
/// NFT executor is never entered. Asserted rather than assumed: if that
/// pre-check ever stopped catching this, the number below would move and the
/// claim in this file's header about WHICH seam refuses would be wrong.
#[test]
fn a_sender_who_cannot_pay_is_refused_before_the_nft_arm_on_both_sides() {
    for (height, label) in HEIGHTS {
        let r = refused_mint(height, FEE - 1, FEE);
        assert_eq!(
            r.status,
            TxStatus::InsufficientBalance,
            "{label}: refused by validate_tx, not by an NFT guard"
        );
        assert_eq!(
            r.sender_balance,
            FEE - 1,
            "{label}: nothing was taken from a sender who could not pay"
        );
        assert_eq!(
            r.proposer_balance, 0,
            "{label}: and nothing reached the proposer"
        );
        assert_eq!(
            r.fee_paid, 0,
            "{label}: so the receipt's zero is TRUE here, and the gate leaves \
             it alone"
        );
    }
}

/// `deduct_fee`'s OWN balance refusal reports zero even with both gates open.
///
/// This is the seam the block executor's pre-check hides: the receipt-failure
/// gate converts `deduct_fee`'s `InsufficientBalance` into a `Failed` receipt,
/// and that receipt runs through the charged-receipt gate on its way out. The
/// fee was not taken there -- the check fires before the debit -- so the number
/// it carries must be zero, while a refusal from any arm BELOW the deduction
/// carries the fee.
///
/// Driven through `execute_with_gates` rather than `execute_tx`, because
/// `validate_tx` refuses this sender before the NFT arm ever runs and there is
/// no way to reach `deduct_fee`'s check from outside.
///
/// Spelled `{ .., ..CLOSED }`, never field by field.
#[test]
fn deduct_fees_own_balance_refusal_carries_zero_while_a_later_one_carries_the_fee() {
    const BOTH: NftGates = NftGates {
        receipt_failure: true,
        charged_receipt: true,
        ..NftGates::CLOSED
    };

    // (a) The sender cannot pay. `deduct_fee` refuses before its debit.
    let (_state, db, _dir, _executor) = setup_with_params(params());
    let poor = KeyPair::generate();
    fund(&db, &poor, FEE - 1);
    seed_collection(&db, &Address::new([0xEE; 20]));
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    let unpaid = NftExecutor::execute_with_gates(
        &mut view,
        &params(),
        &poor.address(),
        &NftTxData {
            collection_id: CID,
            token_id: 0,
            operation: NftOperation::Mint,
            data: mint_payload(poor.address()),
        },
        &proposer,
        FEE,
        TS,
        BOTH,
    )
    .expect("the receipt-failure gate turns this into a receipt");
    assert!(!unpaid.success);
    assert_eq!(
        unpaid.fee_charged, 0,
        "OV-9: nothing was debited, so the receipt's zero is the true number"
    );
    assert_eq!(
        StateManager::v_get_balance(&view, &poor.address()).unwrap(),
        FEE - 1,
        "and the balance confirms it"
    );

    // (b) The sender CAN pay, and the mint is refused by `owner_only_minting`
    // -- an arm below the deduction. Same gates, same fee, different number.
    let (_state2, db2, _dir2, _executor2) = setup_with_params(params());
    let rich = KeyPair::generate();
    fund(&db2, &rich, FUNDED);
    seed_collection(&db2, &Address::new([0xEE; 20]));

    let mut overlay2 = ApplicationOverlay::new(&db2, common::TEST_CANDIDATE_LIMIT);
    let mut view2 = ExecutionView::new(&mut overlay2);
    let paid = NftExecutor::execute_with_gates(
        &mut view2,
        &params(),
        &rich.address(),
        &NftTxData {
            collection_id: CID,
            token_id: 0,
            operation: NftOperation::Mint,
            data: mint_payload(rich.address()),
        },
        &proposer,
        FEE,
        TS,
        BOTH,
    )
    .unwrap();
    assert!(!paid.success);
    assert_eq!(
        paid.fee_charged, FEE,
        "OV-9: a refusal from below the deduction carries the fee it spent"
    );
    assert_eq!(
        StateManager::v_get_balance(&view2, &rich.address()).unwrap(),
        FUNDED - FEE,
        "and the balance confirms that too"
    );
}
