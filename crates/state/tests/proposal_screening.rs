//! One execution that names EVERY transaction a proposal cannot execute.
//!
//! # The cost this file measures
//!
//! `BlockExecutor::execute_block` abandons the whole block at the FIRST
//! transaction it cannot execute — it has to, because below the
//! per-transaction gate there is no scope to undo what that transaction staged
//! before it failed. So a proposer learns about exactly ONE offender per
//! execution, and a proposal carrying `n` of them costs `n + 1` executions.
//! `PoAEngine::MAX_REFUSED_TX_DROPS` used to bound that at sixty-four, which
//! bounded the work and left the door open: sixty-four full block executions,
//! bought for sixty-four `min_fee`s.
//!
//! `BlockExecutor::screen_proposal` executes the same candidate for its
//! VERDICTS instead. It opens a per-transaction scope for every transaction
//! whatever the gate says, rolls each refusal back, and carries on. One pass,
//! every offender, with its class.
//!
//! The central assertion is the pair: the same block, handed to `execute_block`
//! and to `screen_proposal`, yields ONE named offender and ALL of them.
//!
//! # What it must not do
//!
//! Screening is PROPOSER-LOCAL. It produces no block, writes nothing, and no
//! importing node ever consults it — so it needs no activation gate, and this
//! file pins all three: the pass returns no block, the state root is the same
//! byte for byte afterwards, and a block executed after a screening pass
//! computes the same root as one executed without.

#![cfg(test)]

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, NftOperation, NftTxData, PolicyAccountOperation,
    PolicyAccountTxData, SignedTransaction, StakingOperation, StakingTxData, TransactionV2,
    TxPayload,
};
use sumchain_state::{StateError, TxFailureClass};

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// A budget no test proposal can reach, so a test that is not about the charge
/// is not accidentally about the charge.
const UNBOUNDED: u64 = u64::MAX;

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

/// PERMANENTLY INVALID. `PolicyAccountExecutor::execute` refuses
/// `ModifyMembership` on the operation code alone, before reading any state:
/// the operation is reachable only as the effect of an `ExecuteProposal`, so a
/// directly submitted one fails at every height against every state.
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

/// TEMPORARILY INELIGIBLE. A mint against a collection nothing has created yet.
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

/// The counterexample that disqualified `StateError::InvalidOperation` as a
/// permanence marker: `StakingView::v_claim_rewards` raises it for a validator
/// that has not registered YET, and the next block may register it.
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

/// `n` funded senders, one per transaction, because a refusal is ROLLED BACK
/// and therefore does not advance its sender's nonce: a second transaction from
/// the same sender at nonce 1 would take an `InvalidNonce` RECEIPT rather than
/// refusing, and a test of the refusal count would be counting something else.
fn senders(db: &sumchain_storage::Database, n: usize) -> Vec<KeyPair> {
    (0..n)
        .map(|_| {
            let kp = KeyPair::generate();
            fund(db, &kp, 100_000_000);
            kp
        })
        .collect()
}

// ── 1. One pass, every offender ─────────────────────────────────────────────

/// The defect and the repair, on the same block.
///
/// Twenty-four transactions that cannot execute, from twenty-four senders, with
/// four ordinary transfers behind them. `execute_block` names ONE of the
/// twenty-four and abandons the block; `screen_proposal` names all twenty-four
/// in a single call, each with its class.
///
/// That ratio IS the defect: under `execute_block` alone a proposer needs
/// twenty-five executions to learn what one pass now tells it.
#[test]
fn one_screening_pass_names_every_refusal_where_execute_block_names_one() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let poisoners = senders(&db, 24);
    let clean = senders(&db, 4);

    // Alternating classes, so the verdict cannot be right by naming one kind.
    let mut txs: Vec<SignedTransaction> = poisoners
        .iter()
        .enumerate()
        .map(|(i, kp)| {
            if i % 2 == 0 {
                modify_membership_tx(kp, 0)
            } else {
                mint_absent_collection_tx(kp, 0)
            }
        })
        .collect();
    txs.extend(clean.iter().map(|kp| transfer_tx(kp, 0)));
    let block = block_of(1, txs);

    // The defect, stated as a measurement rather than as a claim.
    match executor.execute_block(&block, state.state_root(), &[]) {
        Err(StateError::BlockTransactionAborted { tx_index, .. }) => {
            println!("EXECUTE_BLOCK: abandoned the block at index {tx_index}, naming 1 of 24");
            assert_eq!(
                tx_index, 0,
                "the producing execution stops at the FIRST refusal; everything \
                 behind it is unexamined, which is why 24 offenders used to cost \
                 25 executions"
            );
        }
        Err(other) => panic!("expected an aborted transaction, got {other:?}"),
        Ok(_) => panic!(
            "the producing execution must refuse this block: that refusal is the \
             defect this pass exists to make cheap"
        ),
    }

    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], UNBOUNDED)
        .expect("a screening pass must not fail on a proposal it can screen");
    println!(
        "SCREEN_PROPOSAL: one pass, {} refusals named, {} transactions reached, {} bytes charged",
        screening.refused().len(),
        screening.screened(),
        screening.refusal_bytes()
    );

    assert_eq!(
        screening.refused().len(),
        24,
        "ONE pass must name every offender. Naming fewer is the defect with a \
         smaller number on it: the proposer goes back for another execution per \
         offender it was not told about"
    );
    assert_eq!(
        screening.screened(),
        28,
        "and it must have reached the whole proposal, not stopped early"
    );
    assert_eq!(
        screening.ceiling_cut(),
        None,
        "nothing here goes near the block write-set ceiling"
    );
    assert_eq!(
        screening.charge_cut(),
        None,
        "nor near the refusal budget, which is unbounded in this test"
    );

    // The indices are the poison's positions, in order, with the right class on
    // each — a verdict a proposer acts on by EVICTING or by QUARANTINING, and
    // the two are not the same decision.
    let expected: Vec<(usize, TxFailureClass)> = (0..24)
        .map(|i| {
            (
                i,
                if i % 2 == 0 {
                    TxFailureClass::Permanent
                } else {
                    TxFailureClass::Transient
                },
            )
        })
        .collect();
    assert_eq!(
        screening.refused(),
        expected.as_slice(),
        "in ascending index order, each with the class that decides whether the \
         proposer may destroy it"
    );
}

/// The first offender is not the only one a pass survives — the LAST
/// transaction refusing must be reported too.
///
/// A pass that stopped one short of the end would look correct on a proposal
/// whose poison is in the middle, and would send the proposer back for one more
/// execution on every proposal whose poison is last.
#[test]
fn a_refusal_in_the_final_position_is_reported() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let clean = senders(&db, 3);
    let last = senders(&db, 1);
    let mut txs: Vec<SignedTransaction> = clean.iter().map(|kp| transfer_tx(kp, 0)).collect();
    txs.push(modify_membership_tx(&last[0], 0));
    let block = block_of(1, txs);

    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], UNBOUNDED)
        .expect("screened");
    println!("LAST: refused {:?}", screening.refused());
    assert_eq!(
        screening.refused(),
        &[(3, TxFailureClass::Permanent)],
        "the refusal in the final position is named"
    );
    assert_eq!(screening.screened(), 4);
}

/// A proposal nothing is wrong with is reported CLEAN, and a clean verdict is
/// what lets the proposer offer its selection untouched.
#[test]
fn a_proposal_that_executes_is_reported_clean() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let clean = senders(&db, 6);
    let block = block_of(1, clean.iter().map(|kp| transfer_tx(kp, 0)).collect());

    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], UNBOUNDED)
        .expect("screened");
    println!(
        "CLEAN: {} refusals, clean = {}",
        screening.refused().len(),
        screening.is_clean()
    );
    assert!(
        screening.is_clean(),
        "a proposal with nothing wrong with it must be reported clean; a false \
         accusation here removes honest traffic from a block that would have \
         carried it"
    );
    assert_eq!(screening.refusal_bytes(), 0, "and charges nothing");
}

// ── 2. The classifier's four populations survive the pass ───────────────────

/// `StateError::InvalidOperation` is NOT permanent, and a screening pass must
/// not turn it into one.
///
/// `StakingView::v_claim_rewards` raises `InvalidOperation("Validator not
/// found")` for a validator that has not registered yet. Screening reports it
/// `Transient`, so the proposer quarantines it rather than destroying it — the
/// whole difference between a repair and a second defect.
#[test]
fn a_claim_against_an_unregistered_validator_is_screened_transient() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let s = senders(&db, 1);
    let block = block_of(1, vec![claim_from_absent_validator_tx(&s[0], 0)]);

    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], UNBOUNDED)
        .expect("screened");
    println!("INVALID_OPERATION: {:?}", screening.refused());
    // In this tree the path ends in a RECEIPT rather than a refusal, so there
    // is nothing for screening to report — which is the better outcome and not
    // a regression. What must never happen is the other one.
    assert!(
        screening
            .refused()
            .iter()
            .all(|(_, class)| *class != TxFailureClass::Permanent),
        "a ClaimRewards against a validator that has not registered YET is \
         TEMPORARILY ineligible. Screening it permanent would have the proposer \
         evict a transaction the very next block makes valid"
    );

    // And the marker it would have to travel through, pinned from this side
    // too: `StakingView::v_claim_rewards` raises `InvalidOperation` for exactly
    // this case, so a screening pass that treated that variant as permanent
    // would destroy it whichever way the dispatch arm above goes.
    assert_eq!(
        sumchain_state::classify_block_tx_failure(&StateError::InvalidOperation(
            "Validator not found".to_string()
        )),
        TxFailureClass::Transient,
        "`InvalidOperation` is not a permanence marker, and a screening pass \
         reports whatever this function says"
    );
}

// ── 3. Screening decides nothing about validity ─────────────────────────────

/// The pass produces no block and leaves no state.
///
/// Everything a screened transaction staged is rolled back, and everything an
/// EXECUTED one staged is dropped with the candidate. So the committed state
/// root is the same byte for byte afterwards and every balance is untouched —
/// including the balances of the transactions that executed perfectly well.
#[test]
fn a_screening_pass_produces_no_block_and_commits_no_state() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let clean = senders(&db, 3);
    let poisoned = senders(&db, 2);

    let root_before = state.state_root();
    let balances_before: Vec<u128> = clean
        .iter()
        .chain(poisoned.iter())
        .map(|kp| state.get_balance(&kp.address()).expect("balance"))
        .collect();

    let mut txs: Vec<SignedTransaction> = clean.iter().map(|kp| transfer_tx(kp, 0)).collect();
    txs.extend(poisoned.iter().map(|kp| modify_membership_tx(kp, 0)));
    let block = block_of(1, txs);

    let screening = executor
        .screen_proposal(&block, root_before, &[], UNBOUNDED)
        .expect("screened");
    assert_eq!(screening.refused().len(), 2);

    assert_eq!(
        state.state_root(),
        root_before,
        "a screening pass commits nothing, so the state root it was handed is \
         the state root afterwards. If this moves, the pass is a block \
         production path wearing a different name and every claim about it \
         being proposer-local is false"
    );
    let balances_after: Vec<u128> = clean
        .iter()
        .chain(poisoned.iter())
        .map(|kp| state.get_balance(&kp.address()).expect("balance"))
        .collect();
    println!("NO STATE: balances {balances_before:?} -> {balances_after:?}");
    assert_eq!(
        balances_after, balances_before,
        "and nobody paid a fee for it — not the refused senders, and not the \
         three whose transfers executed cleanly inside the candidate"
    );
}

/// A block executed AFTER a screening pass computes the same state root as the
/// same block executed without one.
///
/// This is the property that makes screening proposer-local policy rather than
/// a consensus rule. If a screening pass could move the root, then whether a
/// proposer screened would be visible in the block it produced, and an
/// importing node would have to know — which is what an activation gate is for,
/// and what this repair is claiming it does not need.
#[test]
fn screening_first_does_not_change_the_root_the_block_computes() {
    let key = [7u8; 32];
    let seed = |db: &sumchain_storage::Database| -> Vec<KeyPair> {
        (0..4)
            .map(|i| {
                let mut bytes = key;
                bytes[0] = i as u8;
                let kp = KeyPair::from_bytes(bytes);
                fund(db, &kp, 100_000_000);
                kp
            })
            .collect()
    };

    // Two identical chains from identical genesis state. The only difference is
    // that one is screened first.
    let (state_a, db_a, _dir_a, exec_a) = setup_with_params(params());
    let a = seed(&db_a);
    let (state_b, db_b, _dir_b, exec_b) = setup_with_params(params());
    let b = seed(&db_b);

    let build = |kps: &[KeyPair]| -> Vec<SignedTransaction> {
        let mut txs = vec![transfer_tx(&kps[0], 0), transfer_tx(&kps[1], 0)];
        // A refusal in the middle, so the screened run really does roll
        // something back rather than screening a block with nothing in it.
        txs.push(modify_membership_tx(&kps[2], 0));
        txs.push(transfer_tx(&kps[3], 0));
        txs
    };
    let block_a = block_of(1, build(&a));
    let block_b = block_of(1, build(&b));
    assert_eq!(
        block_a
            .transactions
            .iter()
            .map(|t| t.hash())
            .collect::<Vec<_>>(),
        block_b
            .transactions
            .iter()
            .map(|t| t.hash())
            .collect::<Vec<_>>(),
        "the two runs must be handed the same transactions"
    );

    // A: screen, apply the verdict, execute what survives.
    let screening = exec_a
        .screen_proposal(&block_a, state_a.state_root(), &[], UNBOUNDED)
        .expect("screened");
    assert_eq!(screening.refused(), &[(2, TxFailureClass::Permanent)]);
    let survivors_a: Vec<SignedTransaction> = block_a
        .transactions
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, t)| t.clone())
        .collect();
    let root_a = exec_a
        .execute_block(&block_of(1, survivors_a), state_a.state_root(), &[])
        .expect("the survivors execute")
        .computed_root();

    // B: no screening pass at all; the same survivors, executed directly.
    let survivors_b: Vec<SignedTransaction> = block_b
        .transactions
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, t)| t.clone())
        .collect();
    let root_b = exec_b
        .execute_block(&block_of(1, survivors_b), state_b.state_root(), &[])
        .expect("the survivors execute")
        .computed_root();

    println!("ROOTS: screened {root_a}, unscreened {root_b}");
    assert_eq!(
        root_a, root_b,
        "a screening pass must leave no trace in the block that follows it. If \
         these differ, screening changes what a block contains for an importer \
         and cannot be proposer-local policy"
    );
}

// ── 4. What bounds the pass ─────────────────────────────────────────────────

/// A refusal that stages nothing still costs something, and the charge is what
/// stops an unbounded pass.
///
/// `ProposalScreening::REFUSAL_FLOOR_BYTES` is 4 KiB, so a budget of exactly
/// two floors admits two refusals and is crossed by the third. The pass stops
/// there and reports the prefix it actually screened — it does not carry on
/// judging transactions it has no budget to judge.
#[test]
fn the_refusal_charge_stops_the_pass_and_reports_the_prefix_it_screened() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let poisoners = senders(&db, 6);
    let block = block_of(
        1,
        poisoners
            .iter()
            .map(|kp| modify_membership_tx(kp, 0))
            .collect(),
    );

    // Two floors. `ModifyMembership` is refused on the operation code before a
    // byte is staged, so without the floor these six refusals would charge zero
    // and no budget would ever bind.
    let budget = 2 * 4_096u64;
    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], budget)
        .expect("screened");
    println!(
        "CHARGE: budget {budget}, charged {}, cut {:?}, refused {}, screened {}",
        screening.refusal_bytes(),
        screening.charge_cut(),
        screening.refused().len(),
        screening.screened()
    );

    assert_eq!(
        screening.charge_cut(),
        Some(3),
        "the third refusal crosses two floors' worth of budget, so the pass \
         stops with a prefix of three. A charge that never binds is a pass an \
         attacker can make arbitrarily expensive; a cut that lands anywhere \
         else is an off-by-one in the only thing bounding it"
    );
    assert_eq!(
        screening.refused().len(),
        3,
        "and it reports the three it judged, not the six it was handed"
    );
    assert_eq!(
        screening.screened(),
        3,
        "reaching three of six is the fact the proposer acts on: it offers the \
         prefix it screened and leaves the rest for a later tick"
    );
    assert_eq!(
        screening.refusal_bytes(),
        3 * 4_096,
        "three refusals, each charged the floor, because each staged less than \
         it"
    );
}

/// Exactly at the budget is NOT a cut.
///
/// The charge is crossed when it goes OVER, not when it reaches. Two refusals
/// charging exactly the whole budget must still be screened and reported, with
/// no cut — otherwise every budget silently admits one refusal fewer than it
/// says, and the constant means something other than what it is documented to
/// mean.
#[test]
fn a_charge_that_exactly_reaches_the_budget_is_not_a_cut() {
    let (state, db, _dir, executor) = setup_with_params(params());
    let poisoners = senders(&db, 2);
    let block = block_of(
        1,
        poisoners
            .iter()
            .map(|kp| modify_membership_tx(kp, 0))
            .collect(),
    );

    let budget = 2 * 4_096u64;
    let screening = executor
        .screen_proposal(&block, state.state_root(), &[], budget)
        .expect("screened");
    println!(
        "EXACT: budget {budget}, charged {}, cut {:?}",
        screening.refusal_bytes(),
        screening.charge_cut()
    );
    assert_eq!(
        screening.refusal_bytes(),
        budget,
        "two refusals charge exactly the budget"
    );
    assert_eq!(
        screening.charge_cut(),
        None,
        "and exactly the budget is not over it"
    );
    assert_eq!(
        screening.refused().len(),
        2,
        "so both are judged and reported"
    );
}
