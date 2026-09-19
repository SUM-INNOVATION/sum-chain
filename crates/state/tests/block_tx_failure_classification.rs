//! What `execute_block` tells a proposer about a transaction it could not
//! execute, and why the answer is two facts rather than one.
//!
//! The loop's last arm used to be `Err(e) => return Err(e)`. That names nothing
//! a proposer can act on, and a proposer MUST act: `Mempool::select_for_block`
//! is non-destructive and fee-ordered, so the transaction that made the block
//! unexecutable is selected FIRST on the next tick, and the tick after that.
//! One `min_fee`, payable by anyone, stopped that validator producing blocks
//! for good.
//!
//! So the loop reports two things, and the second one is the one this file
//! exists to pin:
//!
//!   * the INDEX, because that is the only thing a proposer can decline to
//!     include;
//!   * the CLASS, because declining is not the same decision as DESTROYING.
//!
//! # Why the class cannot be read off the error variant
//!
//! The obvious rule — `StateError::InvalidOperation` means the transaction is
//! nonsense, evict it — is wrong, and the counterexample is in this repository
//! rather than in principle. `StakingView::v_claim_rewards` raises
//! `InvalidOperation("Validator not found")` for a `ClaimRewards` against a
//! validator that has not registered YET. Evicting that destroys a transaction
//! the next block makes valid.
//!
//! So `Permanent` hangs off `StateError::UnsubmittableOperation`, which a
//! dispatch arm raises only when the operation CODE names something that is not
//! a submission at all — decided before any state is read. Everything else is
//! `Transient`, and this file drives three shapes through the real
//! `execute_block` to show which is which.

#![cfg(test)]

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, NftOperation, NftTxData, PolicyAccountOperation,
    PolicyAccountTxData, SignedTransaction, StakingOperation, StakingTxData, TransactionV2,
    TxPayload, TxStatus,
};
use sumchain_state::{
    classify_block_tx_failure, policy_account_operation_is_submittable, StateError, TxFailureClass,
};

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

fn block_of(height: u64, txs: Vec<SignedTransaction>) -> Block {
    Block::new(
        BlockHeader::new(Hash::ZERO, height, 1_000, Hash::ZERO, Hash::ZERO, [9u8; 32]),
        txs,
    )
}

fn sign_v2(kp: &KeyPair, t: TransactionV2) -> SignedTransaction {
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn modify_membership_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::PolicyAccount(PolicyAccountTxData {
                operation: PolicyAccountOperation::ModifyMembership,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        },
    )
}

fn mint_absent_collection_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    #[derive(serde::Serialize)]
    struct MintData {
        to: Address,
        metadata: Vec<u8>,
        uri_type: String,
        uri_value: Option<String>,
    }
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::Nft(NftTxData {
                collection_id: [0x55u8; 32],
                token_id: 0,
                operation: NftOperation::Mint,
                data: bincode::serialize(&MintData {
                    to: kp.address(),
                    metadata: Vec::new(),
                    uri_type: "onchain".to_string(),
                    uri_value: None,
                })
                .unwrap(),
            }),
        },
    )
}

fn claim_from_absent_validator_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::Staking(StakingTxData {
                operation: StakingOperation::ClaimRewards,
                data: bincode::serialize(&[0x33u8; 32]).unwrap(),
            }),
        },
    )
}

fn transfer_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::Transfer {
                to: Address::new([0xAB; 20]),
                amount: 1,
            },
        },
    )
}

// ── Permanent ───────────────────────────────────────────────────────────────

/// A `ModifyMembership` submission is refused PERMANENTLY, and the refusal says
/// which transaction it was.
#[test]
fn an_unsubmittable_operation_is_reported_as_permanent_with_its_index() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    // Two ordinary transfers, then the poison, then another transfer: the index
    // has to be the poison's and not zero or the block length.
    let txs = vec![
        transfer_tx(&actor, 0),
        transfer_tx(&actor, 1),
        modify_membership_tx(&actor, 2),
        transfer_tx(&actor, 3),
    ];
    let block = block_of(1, txs);
    match executor.execute_block(&block, state.state_root(), &[]) {
        Err(StateError::BlockTransactionAborted {
            tx_index,
            class,
            detail,
        }) => {
            println!("PERMANENT: index {tx_index}, class {class}, detail: {detail}");
            assert_eq!(
                tx_index, 2,
                "the index must name the transaction that refused, not the \
                 first or the last: it is the only thing a proposer can \
                 decline to include"
            );
            assert_eq!(
                class,
                TxFailureClass::Permanent,
                "and it must be permanent — no state and no height makes a \
                 directly submitted ModifyMembership succeed, so a proposer \
                 that only SKIPS it selects it first again on the next tick"
            );
            assert!(
                detail.contains("ExecuteProposal"),
                "and the original message survives verbatim, so nothing a node \
                 used to log is lost: {detail}"
            );
        }
        Err(other) => panic!("expected a permanent refusal, got {other:?}"),
        Ok(_) => panic!("the block must be refused"),
    }
}

/// The classifier itself, on the variant that carries the licence to evict.
#[test]
fn only_an_unsubmittable_operation_classifies_as_permanent() {
    assert_eq!(
        classify_block_tx_failure(&StateError::UnsubmittableOperation {
            operation: "PolicyAccount::ModifyMembership".to_string(),
            reason: "effect only".to_string(),
        }),
        TxFailureClass::Permanent
    );

    // The near misses, each one a transaction a later block could carry.
    for e in [
        // The counterexample that disqualified `InvalidOperation` wholesale.
        StateError::InvalidOperation("Validator not found".to_string()),
        // What the NFT executors raise for an absent collection.
        StateError::BlockValidation("Collection not found".to_string()),
        StateError::SerializationError("short write".to_string()),
        StateError::DeserializationError("bad row".to_string()),
        StateError::EducationNotActivated,
        StateError::BeaconNotActivated,
        StateError::InsufficientBalance {
            required: 2,
            available: 1,
        },
        StateError::InvalidNonce {
            expected: 4,
            got: 9,
        },
    ] {
        assert_eq!(
            classify_block_tx_failure(&e),
            TxFailureClass::Transient,
            "`{e}` must be transient. The classification is fail-safe by \
             design: holding a dead transaction one more tick costs a \
             selection slot, and evicting a live one costs a user their \
             transaction"
        );
    }
    println!("CLASSIFIER: one permanent variant, eight transient near misses");
}

/// The mempool's list of unsubmittable operations is the executor's list.
///
/// Two hand-maintained lists of the same operations are one edit away from
/// disagreeing, and the disagreement that matters is a mempool admitting a
/// transaction that makes every block it is selected into unexecutable. So the
/// predicate is read by both, and this drives it against the executor's actual
/// behaviour for every operation the enum has.
#[test]
fn the_submittability_predicate_agrees_with_the_executor_on_every_operation() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 1_000_000_000);

    let ops = [
        PolicyAccountOperation::Create,
        PolicyAccountOperation::SubmitProposal,
        PolicyAccountOperation::ExecuteProposal,
        PolicyAccountOperation::CancelProposal,
        PolicyAccountOperation::ModifyMembership,
        PolicyAccountOperation::ModifyPolicy,
        PolicyAccountOperation::Freeze,
        PolicyAccountOperation::Unfreeze,
    ];
    // Nonce ZERO every time, against a fresh block over the same unspent
    // account: `validate_tx` runs before the dispatch, so a nonce that has
    // advanced would turn every probe after the first into an `InvalidNonce`
    // receipt and this test into a test of nothing.
    for op in ops.into_iter() {
        let tx = sign_v2(
            &actor,
            TransactionV2 {
                chain_id: CHAIN_ID,
                from: actor.address(),
                fee: 1_000,
                nonce: 0,
                payload: TxPayload::PolicyAccount(PolicyAccountTxData {
                    operation: op,
                    data: Vec::new(),
                    recipient: Address::ZERO,
                }),
            },
        );
        let outcome = executor.execute_block(&block_of(1, vec![tx]), state.state_root(), &[]);
        let aborted_permanently = matches!(
            outcome,
            Err(StateError::BlockTransactionAborted {
                class: TxFailureClass::Permanent,
                ..
            })
        );
        println!(
            "PREDICATE: {op:?} submittable={} executor aborts permanently={}",
            policy_account_operation_is_submittable(op),
            aborted_permanently
        );
        assert_eq!(
            policy_account_operation_is_submittable(op),
            !aborted_permanently,
            "the predicate and the executor must agree about {op:?}. They \
             disagree only in one direction that matters: a mempool that \
             admits what the executor will refuse re-creates the halt"
        );
    }
}

// ── Transient ───────────────────────────────────────────────────────────────

/// An NFT mint naming a collection that does not exist YET is TRANSIENT.
///
/// This is the shape the owner's second condition is about. It aborts the block
/// exactly as the permanently invalid transaction does, so a proposer that
/// reads only "the block failed" cannot tell them apart — and a proposer that
/// evicts on that reading destroys a transaction whose `CreateCollection` may
/// be in the very next block.
#[test]
fn an_absent_collection_is_reported_as_transient() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);

    let block = block_of(1, vec![mint_absent_collection_tx(&actor, 0)]);
    match executor.execute_block(&block, state.state_root(), &[]) {
        Err(StateError::BlockTransactionAborted {
            tx_index,
            class,
            detail,
        }) => {
            println!("TRANSIENT: index {tx_index}, class {class}, detail: {detail}");
            assert_eq!(tx_index, 0);
            assert_eq!(
                class,
                TxFailureClass::Transient,
                "the collection is missing from the STATE, not from the \
                 transaction. Evicting it is destroying honest traffic"
            );
            assert!(detail.contains("Collection not found"), "{detail}");
        }
        Err(other) => panic!("expected a transient refusal, got {other:?}"),
        Ok(_) => panic!("the block must be refused"),
    }
}

/// Rewards claimed against a validator that has not registered yet is
/// TRANSIENT, and the error it raises is `InvalidOperation`.
///
/// This is the counterexample in the flesh. Anything that treated
/// `InvalidOperation` as evidence of permanence would evict this transaction,
/// and a `RegisterValidator` in the next block makes it valid.
#[test]
fn an_unregistered_validator_is_reported_as_transient_despite_invalid_operation() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    fund(&db, &actor, 100_000_000);

    let block = block_of(1, vec![claim_from_absent_validator_tx(&actor, 0)]);
    match executor.execute_block(&block, state.state_root(), &[]) {
        Err(StateError::BlockTransactionAborted { class, detail, .. }) => {
            println!("TRANSIENT (InvalidOperation): class {class}, detail: {detail}");
            assert_eq!(
                class,
                TxFailureClass::Transient,
                "a validator that has not registered YET is a fact about the \
                 state. The error is InvalidOperation, which is exactly why \
                 the permanence marker cannot be that variant"
            );
        }
        // If a future change turns this into a receipt, that is an improvement
        // and not a regression — but it must not become PERMANENT.
        Ok(exec) => {
            let (executed, _, _) = exec.into_parts();
            println!(
                "TRANSIENT (InvalidOperation): now a receipt rather than a \
                 refusal, {} bytes charged",
                executed.logical_bytes()
            );
        }
        Err(other) => panic!("must not be a permanent refusal: {other:?}"),
    }
}

// ── The many failures that are neither ──────────────────────────────────────

/// The ordinary failures stay receipts, and the block is still produced.
///
/// The whole classification only applies to the handful of paths that abort a
/// block. A bad nonce and an empty balance must not be routed into it: they
/// already have receipts, and turning them into block refusals would make every
/// one of them a halt.
#[test]
fn ordinary_failures_are_still_receipts_and_the_block_is_still_executed() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let actor = KeyPair::generate();
    let pauper = KeyPair::generate();
    fund(&db, &actor, 100_000_000);
    fund(&db, &pauper, 0);

    let txs = vec![
        transfer_tx(&actor, 0),
        // A nonce far ahead of the sender's.
        transfer_tx(&actor, 99),
        // A sender with nothing.
        transfer_tx(&pauper, 0),
    ];
    let block = block_of(1, txs.clone());
    let execution = executor
        .execute_block(&block, state.state_root(), &[])
        .expect("none of these may abort the block");
    let (executed, _, _) = execution.into_parts();
    let statuses: Vec<TxStatus> = executed.receipts().iter().map(|r| r.status).collect();
    println!("RECEIPTS: {statuses:?}");
    assert_eq!(statuses.len(), 3, "every transaction got a receipt");
    assert_eq!(statuses[0], TxStatus::Success);
    assert_eq!(
        statuses[1],
        TxStatus::InvalidNonce,
        "a nonce ahead of the sender is a receipt, not a halt"
    );
    assert_eq!(
        statuses[2],
        TxStatus::InsufficientBalance,
        "and so is an empty balance"
    );
}
