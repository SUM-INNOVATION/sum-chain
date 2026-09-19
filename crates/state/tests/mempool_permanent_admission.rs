//! What a mempool may refuse at the door, and — much more importantly — what it
//! may not.
//!
//! # The two it may
//!
//! A proposer now survives a transaction that cannot execute: it identifies the
//! offender, drops it, and produces a block out of what is left. Surviving is
//! not free. Each refusal costs a whole speculative block execution, and the
//! transaction is still in every peer's mempool, still gossiped, still at the
//! front of every fee-ordered selection until the next proposer pays to
//! discover it again.
//!
//! Two shapes are decidable from the transaction's own bytes, with no state
//! read and nothing executed, so they are decided here instead:
//!
//!   * PERMANENTLY OVERSIZED. `BlockExecutor::validate_block` refuses any block
//!     whose serialized bytes exceed `max_block_bytes`, and a block carrying
//!     this transaction is at least as large as the transaction. There is no
//!     valid block, at any height, in any order, behind any other transaction,
//!     that could include it.
//!   * PERMANENTLY UNEXECUTABLE. `PolicyAccount::ModifyMembership` and
//!     `ModifyPolicy` are reachable only as the EFFECT of an `ExecuteProposal`.
//!     `PolicyAccountExecutor::execute` refuses a directly submitted one on the
//!     operation code alone, before reading any state — and that refusal
//!     propagates out of `execute_block` and makes the whole block
//!     unexecutable, which is how one of them, at one `min_fee`, halted a
//!     validator permanently.
//!
//! # The many it may not
//!
//! Everything a height or a state could change its mind about. A mempool that
//! refuses those is destroying transactions on a guess, and the guess is wrong
//! often enough to matter: a gate that is closed today opens at a height, a row
//! that is missing today is created by the next block, a balance that is short
//! today is topped up. Half this file is that negative.

#![cfg(test)]

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, NftOperation, NftTxData, PolicyAccountOperation, PolicyAccountTxData,
    SignedTransaction, StakingOperation, StakingTxData, TransactionV2, TxPayload,
};
use sumchain_state::{Mempool, MempoolConfig, StateError};

const CHAIN_ID: u64 = 1;

/// The block limit the fixtures are sized against. Read from `ChainParams`
/// rather than written as a literal, so a change to the parameter moves the
/// boundary these tests probe instead of silently making them probe nothing.
fn block_limit() -> u64 {
    ChainParams::default().max_block_bytes
}

fn pool() -> Mempool {
    Mempool::new(MempoolConfig {
        max_per_sender: 10_000,
        max_tx_bytes: block_limit(),
        ..MempoolConfig::default()
    })
}

fn sign_v2(kp: &KeyPair, t: TransactionV2) -> SignedTransaction {
    let sig = sign(t.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(t, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn policy_tx(kp: &KeyPair, nonce: u64, operation: PolicyAccountOperation) -> SignedTransaction {
    sign_v2(
        kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce,
            payload: TxPayload::PolicyAccount(PolicyAccountTxData {
                operation,
                data: Vec::new(),
                recipient: Address::ZERO,
            }),
        },
    )
}

/// An NFT mint carrying `padding` bytes of metadata, so the ENCODED size of the
/// transaction can be steered to the byte.
fn padded_nft_tx(kp: &KeyPair, nonce: u64, padding: usize) -> SignedTransaction {
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
                    metadata: vec![0u8; padding],
                    uri_type: "onchain".to_string(),
                    uri_value: None,
                })
                .unwrap(),
            }),
        },
    )
}

/// The padding that makes `padded_nft_tx` encode to exactly `target` bytes.
///
/// Solved rather than guessed: the encoding is length-prefixed and otherwise
/// fixed-width, so one measurement of the overhead gives the padding for any
/// target, and an assertion below proves the solution landed on the byte. That
/// is what makes the boundary tests boundary tests.
fn padding_for_encoded_size(kp: &KeyPair, target: u64) -> usize {
    let base = padded_nft_tx(kp, 0, 0).to_bytes().len() as u64;
    (target - base) as usize
}

// ── The two it may refuse ───────────────────────────────────────────────────

/// A `ModifyMembership` submission never enters the mempool.
///
/// This is the transaction that halted a validator permanently, and this is the
/// cheapest of the three places it is now stopped.
#[test]
fn an_unsubmittable_policy_operation_is_refused_at_admission() {
    let pool = pool();
    let kp = KeyPair::generate();

    for (nonce, op) in [
        PolicyAccountOperation::ModifyMembership,
        PolicyAccountOperation::ModifyPolicy,
    ]
    .into_iter()
    .enumerate()
    {
        let tx = policy_tx(&kp, nonce as u64, op);
        let err = pool
            .add(tx.clone())
            .expect_err("an unsubmittable operation must not be admitted");
        println!("ADMISSION: {op:?} -> {err}");
        assert!(
            matches!(err, StateError::TransactionPermanentlyUnincludable(_)),
            "and must say WHY in the one variant reserved for what no block can \
             ever carry, so nothing downstream mistakes it for a full mempool \
             or a low fee: got {err:?}"
        );
        assert!(!pool.contains(&tx.hash()), "and it is not held");
    }
    assert!(pool.is_empty(), "nothing was admitted");
}

/// The operations that ARE submittable still are.
///
/// The refusal is a list of two, not a refusal of the payload variant. A
/// `PolicyAccount` mempool that admitted nothing would pass the test above and
/// break the subsystem.
#[test]
fn the_submittable_policy_operations_are_still_admitted() {
    let pool = pool();
    let kp = KeyPair::generate();
    let ops = [
        PolicyAccountOperation::Create,
        PolicyAccountOperation::SubmitProposal,
        PolicyAccountOperation::ExecuteProposal,
        PolicyAccountOperation::CancelProposal,
        PolicyAccountOperation::Freeze,
        PolicyAccountOperation::Unfreeze,
    ];
    for (nonce, op) in ops.into_iter().enumerate() {
        let tx = policy_tx(&kp, nonce as u64, op);
        pool.add(tx.clone())
            .unwrap_or_else(|e| panic!("{op:?} must still be admitted: {e}"));
        assert!(pool.contains(&tx.hash()));
    }
    println!("ADMISSION: {} submittable policy operations admitted", ops.len());
    assert_eq!(pool.len(), ops.len());
}

/// A transaction larger than any block is refused, and the boundary is EXACT.
///
/// Three probes, one byte apart around `max_block_bytes`: at the limit it is
/// admitted, one byte over it is refused. A bound that is off by one in the
/// permissive direction leaves a transaction in the mempool that no block can
/// carry; off by one in the strict direction it destroys a transaction that
/// fits.
#[test]
fn the_oversized_boundary_is_exact() {
    let kp = KeyPair::generate();
    let limit = block_limit();

    for (target, admitted) in [(limit - 1, true), (limit, true), (limit + 1, false)] {
        let pool = pool();
        let tx = padded_nft_tx(&kp, 0, padding_for_encoded_size(&kp, target));
        let encoded = tx.to_bytes().len() as u64;
        assert_eq!(
            encoded, target,
            "the fixture must land on the byte, or this is not a boundary test"
        );
        let outcome = pool.add(tx.clone());
        println!(
            "BOUNDARY: {encoded} bytes against a {limit}-byte block limit -> {}",
            if outcome.is_ok() { "admitted" } else { "refused" }
        );
        if admitted {
            outcome.unwrap_or_else(|e| {
                panic!("{encoded} bytes fits in a {limit}-byte block and must be admitted: {e}")
            });
            assert!(pool.contains(&tx.hash()));
        } else {
            let err = outcome.expect_err("one byte over the block limit fits in no block");
            assert!(
                matches!(err, StateError::TransactionPermanentlyUnincludable(_)),
                "got {err:?}"
            );
            assert!(pool.is_empty());
        }
    }
}

/// A zero `max_tx_bytes` is no bound at all.
///
/// The default `MempoolConfig` carries the parameter's own figure, and a node
/// sets its genesis one. Zero is the escape hatch for a caller that has no
/// chain parameters to hand — a test, or the consensus-internal re-adds — and
/// it must mean "do not check", not "reject everything".
#[test]
fn a_zero_size_bound_disables_the_size_check() {
    let pool = Mempool::new(MempoolConfig {
        max_tx_bytes: 0,
        ..MempoolConfig::default()
    });
    let kp = KeyPair::generate();
    let tx = padded_nft_tx(&kp, 0, padding_for_encoded_size(&kp, block_limit() + 4_096));
    pool.add(tx.clone())
        .expect("with the bound disabled, size is not a reason to refuse");
    assert!(pool.contains(&tx.hash()));
    println!(
        "UNBOUNDED: {} bytes admitted with max_tx_bytes = 0",
        tx.to_bytes().len()
    );
}

// ── The many it may not ─────────────────────────────────────────────────────

/// Nothing state-dependent is refused here.
///
/// Each of these is a transaction that fails today and succeeds later, and each
/// is a shape the proposer classifies as TRANSIENT for exactly that reason. A
/// mempool that refused any of them would be destroying a user's transaction on
/// the strength of a guess about a state it did not read.
#[test]
fn nothing_a_later_block_could_make_valid_is_refused_at_admission() {
    let pool = pool();
    let kp = KeyPair::generate();

    // An NFT mint naming a collection that does not exist YET. The executor
    // answers `BlockValidation("Collection not found")`, and the next block may
    // contain the `CreateCollection`.
    let early_mint = padded_nft_tx(&kp, 0, 0);
    pool.add(early_mint.clone())
        .expect("an absent collection is a fact about the state, not the tx");

    // Rewards claimed against a validator that has not registered YET. The
    // executor answers `InvalidOperation("Validator not found")` — the very
    // message that made `InvalidOperation` unusable as a permanence marker.
    let claim = sign_v2(
        &kp,
        TransactionV2 {
            chain_id: CHAIN_ID,
            from: kp.address(),
            fee: 1_000,
            nonce: 1,
            payload: TxPayload::Staking(StakingTxData {
                operation: StakingOperation::ClaimRewards,
                data: bincode::serialize(&[0x33u8; 32]).unwrap(),
            }),
        },
    );
    pool.add(claim.clone())
        .expect("an unregistered validator is a fact about the state too");

    // A nonce far ahead of anything the sender has spent. It becomes valid the
    // moment the transactions before it confirm.
    let ahead = padded_nft_tx(&kp, 500, 0);
    pool.add(ahead.clone())
        .expect("a nonce ahead of the chain is the ordinary case, not an error");

    println!(
        "NOT REFUSED: absent collection, unregistered validator, nonce 500 — \
         all three held, {} in the pool",
        pool.len()
    );
    assert_eq!(pool.len(), 3);
    for tx in [&early_mint, &claim, &ahead] {
        assert!(pool.contains(&tx.hash()));
    }
}

/// Admission does not rewrite what it admits.
///
/// The fee decides selection order and the nonce decides executability, so a
/// transaction that comes back out of the mempool differing in either is a
/// transaction the node quietly replaced. Checked over every shape this file
/// touches, including the ones that only just fit.
#[test]
fn admission_returns_transactions_byte_for_byte() {
    let pool = pool();
    let kp = KeyPair::generate();
    let txs = vec![
        policy_tx(&kp, 0, PolicyAccountOperation::Create),
        padded_nft_tx(&kp, 1, 0),
        padded_nft_tx(&kp, 2, padding_for_encoded_size(&kp, block_limit())),
    ];
    for tx in &txs {
        pool.add(tx.clone()).expect("admitted");
    }
    for tx in &txs {
        let held = pool.get(&tx.hash()).expect("held");
        assert_eq!(held.hash(), tx.hash(), "byte for byte");
        assert_eq!(held.fee(), tx.fee(), "the fee was not rewritten");
        assert_eq!(held.nonce(), tx.nonce(), "nor the nonce");
        assert_eq!(held.to_bytes(), tx.to_bytes(), "nor anything else");
    }
    println!("UNCHANGED: {} transactions returned byte for byte", txs.len());
}
