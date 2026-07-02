//! On-chain governance v1 executor (issue #50, P3 — RecordOnly lifecycle).
//!
//! Registry (`RegisterAsset`), proposal creation with an atomic `TOKEN_BALANCES`
//! snapshot, voting, lazy tally, RecordOnly execution, and cancellation — all
//! behind the P1 activation gate and requiring `ChainParams::governance`.
//!
//! Governance failure-code namespace (`crates/primitives/src/receipt.rs`):
//! - `300` gate closed              · `301` params absent
//! - `302` undecodable/unsupported  · `303` registry/eligibility
//! - `304` create threshold not met · `305` snapshot holder bound exceeded
//! - `306` proposal not found/wrong status · `307` voting closed/expired
//! - `308` no snapshot weight        · `309` duplicate vote
//! - `310` on-chain execution not supported for this proposal (non-treasury,
//!   or treasury not configured / beneficiary+amount absent)
//! - `311` insufficient balance to post the proposal bond
//! - `312` insufficient governance treasury balance for the payout
//!
//! Treasury execution (P6b): a passed `TreasurySpend` + `OnChain` proposal pays
//! a single native-Koppa amount from `GovernanceParams::treasury` to the
//! proposal's beneficiary and moves to `Executed`. It is the only auto-exec
//! path; every other `OnChain` class still fails `310`, and no chain-param /
//! validator / consensus state is ever mutated.
//!
//! Deposit bond (P6a): when `GovernanceParams::proposal_bond > 0`, creating a
//! proposal escrows the bond to the keyless [`gov_escrow_address`] (the proposer
//! must cover `fee + bond`). On a terminal transition the bond is returned to
//! the proposer (Passed/Recorded, Rejected, proposer cancel) or burned to
//! `Address::ZERO` (QuorumNotMet, Expired, council cancel).
//!
//! Fee/nonce (Policy-B): gate/params/undecodable are pre-semantic (no fee, no
//! nonce, no state). A decoded op that fails semantically charges the fee and
//! advances the nonce (when the sender can cover it). Success charges the fee
//! and advances the nonce exactly once, then persists.

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{
    generate_proposal_id, gov_escrow_address, BondState, CancelProposalRequest, CastVoteRequest,
    CreateProposalRequest, ExecuteProposalRequest, ExecutionKind, GovAsset, GovAssetKind,
    GovAssetStatus, GovProposal, GovProposalClass, GovProposalStatus, GovVote, GovernanceOperation,
    GovernanceParams, GovernanceTxData, RegisterAssetRequest, VoteChoice, WeightRule,
};
use sumchain_primitives::{Address, Balance, Hash, TxStatus};
use sumchain_storage::{Database, GovStore, TokenStore};

use crate::executor::TxExecutionResult;
use crate::{Result, StateManager};

/// Whether the governance activation gate is open at `block_height`.
#[inline]
pub fn gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(params.governance_enabled_from_height, Some(h) if block_height >= h)
}

fn decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> std::result::Result<T, ()> {
    bincode::deserialize(data).map_err(|_| ())
}

fn result(tx_hash: Hash, status: TxStatus, fee_paid: Balance) -> TxExecutionResult {
    TxExecutionResult { tx_hash, status, fee_paid }
}

/// Bond settlement staged alongside a terminal proposal update.
enum BondSettlement {
    /// No bond movement (bond disabled, or non-terminal update).
    None,
    /// Return the escrowed bond to the proposal's proposer.
    Return(u128),
    /// Burn the escrowed bond (credit `Address::ZERO`).
    Burn(u128),
}

/// A single native-Koppa treasury payout staged by a passed `TreasurySpend` +
/// `OnChain` proposal (P6b). Deducted from the configured governance treasury
/// and credited to the beneficiary; nothing else is touched.
struct TreasuryPayout {
    from_treasury: Address,
    to: Address,
    amount: u128,
}

/// Writes staged by a successful validation, applied only after the fee is charged.
enum Prepared {
    RegisterAsset(GovAsset),
    CreateProposal { proposal: GovProposal, snapshot: Vec<(Address, u128)> },
    CastVote(GovVote),
    ProposalUpdate {
        proposal: GovProposal,
        settlement: BondSettlement,
        /// Treasury payout for a passed `TreasurySpend` + `OnChain` proposal.
        payout: Option<TreasuryPayout>,
    },
}

/// Execute a `TxPayload::Governance` transaction. `nonce` is the tx nonce
/// (mixed into proposal-id derivation); `from` pays the fee, `proposer` is
/// credited.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    state: &Arc<StateManager>,
    db: &Arc<Database>,
    params: &ChainParams,
    gov: &GovernanceTxData,
    from: &Address,
    nonce: u64,
    fee: Balance,
    proposer: &Address,
    block_height: u64,
    block_timestamp: u64,
    tx_hash: Hash,
) -> Result<TxExecutionResult> {
    // ── Pre-semantic: gate / params / decode (no fee, no nonce, no state) ────
    if !gate_open(params, block_height) {
        return Ok(result(tx_hash, TxStatus::Failed(300), 0));
    }
    let Some(gp) = params.governance.as_ref() else {
        return Ok(result(tx_hash, TxStatus::Failed(301), 0));
    };

    let validated: std::result::Result<Prepared, u32> = match gov.operation {
        GovernanceOperation::RegisterAsset => match decode::<RegisterAssetRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_register(db, gp, from, &req),
        },
        GovernanceOperation::CreateProposal => match decode::<CreateProposalRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_create(db, gp, from, nonce, block_height, block_timestamp, &req),
        },
        GovernanceOperation::CastVote => match decode::<CastVoteRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_vote(db, gp, from, block_height, &req),
        },
        GovernanceOperation::ExecuteProposal => match decode::<ExecuteProposalRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_execute(db, gp, block_height, &req),
        },
        GovernanceOperation::CancelProposal => match decode::<CancelProposalRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_cancel(db, gp, from, &req),
        },
    };

    // ── Semantic: apply Policy-B fee/nonce ───────────────────────────────────
    let balance = state.get_balance(from)?;
    let fee_affordable = balance >= fee;
    match validated {
        Err(code) => {
            if fee_affordable {
                charge(state, from, proposer, fee)?;
                Ok(result(tx_hash, TxStatus::Failed(code), fee))
            } else {
                // Semantic failure but the sender cannot cover the fee: no charge.
                Ok(result(tx_hash, TxStatus::Failed(code), 0))
            }
        }
        Ok(prepared) => {
            // Creating a proposal also escrows the deposit bond; the sender must
            // cover `fee + bond`. Other ops post no bond.
            let bond = match &prepared {
                Prepared::CreateProposal { proposal, .. } => proposal.bond,
                _ => 0,
            };
            if balance < fee.saturating_add(bond) {
                if fee_affordable && bond > 0 {
                    // Valid proposal, can pay the fee but not the bond: charge the
                    // fee + advance nonce (Policy-B) and fail with a bond code.
                    charge(state, from, proposer, fee)?;
                    return Ok(result(tx_hash, TxStatus::Failed(311), fee));
                }
                // Cannot even cover the fee: reject free.
                return Ok(result(tx_hash, TxStatus::Failed(302), 0));
            }
            // Treasury payout affordability (312): checked before any state
            // mutation, so an underfunded treasury leaves the proposal live
            // (Voting) with its bond escrowed. Semantic failure ⇒ charge the fee.
            if let Prepared::ProposalUpdate { payout: Some(p), .. } = &prepared {
                if state.get_balance(&p.from_treasury)? < p.amount {
                    charge(state, from, proposer, fee)?;
                    return Ok(result(tx_hash, TxStatus::Failed(312), fee));
                }
            }
            charge(state, from, proposer, fee)?;
            apply_bond(state, &prepared)?;
            apply_treasury(state, &prepared)?;
            apply(db, prepared)?;
            Ok(result(tx_hash, TxStatus::Success, fee))
        }
    }
}

/// Apply the bond escrow (proposal create) or settlement (terminal update) to
/// native balances. Runs after the fee is charged, so `fee + bond` affordability
/// has already been checked for the create path.
fn apply_bond(state: &Arc<StateManager>, prepared: &Prepared) -> Result<()> {
    let escrow = gov_escrow_address();
    match prepared {
        // Escrow: proposer (== `from` at creation) funds the escrow.
        Prepared::CreateProposal { proposal, .. } if proposal.bond > 0 => {
            state.deduct(&proposal.proposer, proposal.bond)?;
            state.credit(&escrow, proposal.bond)?;
        }
        Prepared::ProposalUpdate { proposal, settlement, .. } => match settlement {
            BondSettlement::Return(amount) if *amount > 0 => {
                state.deduct(&escrow, *amount)?;
                state.credit(&proposal.proposer, *amount)?;
            }
            BondSettlement::Burn(amount) if *amount > 0 => {
                state.deduct(&escrow, *amount)?;
                state.credit(&Address::ZERO, *amount)?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

/// Apply a staged treasury payout: deduct from the governance treasury and
/// credit the beneficiary. Runs after the treasury-balance (312) check, so the
/// deduct cannot underflow. No other account or chain state is touched.
fn apply_treasury(state: &Arc<StateManager>, prepared: &Prepared) -> Result<()> {
    if let Prepared::ProposalUpdate { payout: Some(p), .. } = prepared {
        state.deduct(&p.from_treasury, p.amount)?;
        state.credit(&p.to, p.amount)?;
    }
    Ok(())
}

fn charge(state: &Arc<StateManager>, from: &Address, proposer: &Address, fee: Balance) -> Result<()> {
    state.deduct(from, fee)?;
    state.credit(proposer, fee)?;
    state.increment_nonce(from)?;
    Ok(())
}

fn apply(db: &Arc<Database>, prepared: Prepared) -> Result<()> {
    let store = GovStore::new(db);
    match prepared {
        Prepared::RegisterAsset(asset) => store.put_asset(&asset)?,
        Prepared::CreateProposal { proposal, snapshot } => {
            store.create_proposal_atomic(&proposal, &snapshot)?
        }
        Prepared::CastVote(vote) => store.put_vote(&vote)?,
        Prepared::ProposalUpdate { proposal, .. } => store.put_proposal(&proposal)?,
    }
    Ok(())
}

// ── Per-operation validation (returns Err(code) for semantic failures) ───────

fn validate_register(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    req: &RegisterAssetRequest,
) -> std::result::Result<Prepared, u32> {
    // Council authority.
    if *from != gp.council {
        return Err(303);
    }
    // Token must exist and be fixed-supply / non-mintable.
    let tokens = TokenStore::new(db);
    match tokens.get_token(&req.token_id).map_err(|_| 303u32)? {
        Some(t) if !t.mintable => {}
        _ => return Err(303),
    }
    Ok(Prepared::RegisterAsset(GovAsset {
        asset: GovAssetKind::Src20Token(req.token_id),
        create_threshold: req.create_threshold,
        vote_weight_rule: WeightRule::Linear,
        status: GovAssetStatus::Enabled,
        effective_height: req.effective_height,
    }))
}

fn validate_create(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    nonce: u64,
    height: u64,
    timestamp: u64,
    req: &CreateProposalRequest,
) -> std::result::Result<Prepared, u32> {
    let GovAssetKind::Src20Token(token_id) = req.asset;
    let store = GovStore::new(db);

    // Asset must be registered, enabled, and effective at this height.
    let asset = match store.get_asset(&req.asset).map_err(|_| 303u32)? {
        Some(a) if a.status == GovAssetStatus::Enabled && a.effective_height <= height => a,
        _ => return Err(303),
    };

    // Proposer must meet the per-asset create threshold (eligible balance now).
    let tokens = TokenStore::new(db);
    let bal = tokens.get_balance(&token_id, from).map_err(|_| 304u32)?;
    if bal < asset.create_threshold {
        return Err(304);
    }

    // Freeze the snapshot from TOKEN_BALANCES; enforce the holder bound before
    // any write (scan collects at most cap+1, so len > cap ⇒ over-bound).
    let cap = gp.max_snapshot_holders as usize;
    let snapshot = store.scan_token_holders(&token_id, cap).map_err(|_| 305u32)?;
    if snapshot.len() > cap {
        return Err(305);
    }

    let id = generate_proposal_id(from, &req.asset, &req.external_ref.content_hash, height, nonce);
    let proposal = GovProposal {
        id,
        proposer: *from,
        class: req.class,
        execution_kind: req.execution_kind,
        external_ref: req.external_ref.clone(),
        asset: req.asset,
        voting_start_height: height,
        status: GovProposalStatus::Voting,
        created_at: timestamp,
        created_at_height: height,
        expires_at: timestamp, // informational; the height-based window is authoritative
        bond: gp.proposal_bond,
        bond_state: BondState::Escrowed,
        // Treasury payout target (pass-through; enforced at execution for a
        // TreasurySpend + OnChain proposal, ignored otherwise).
        treasury_beneficiary: req.treasury_beneficiary,
        treasury_amount: req.treasury_amount,
    };
    Ok(Prepared::CreateProposal { proposal, snapshot })
}

fn validate_vote(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    height: u64,
    req: &CastVoteRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) if p.status == GovProposalStatus::Voting => p,
        _ => return Err(306),
    };
    // Voting window (height-based).
    if height > proposal.voting_start_height + gp.voting_period_blocks {
        return Err(307);
    }
    // Weight comes only from the frozen snapshot, never live balance.
    let weight = match store.get_snapshot(&req.proposal_id, from).map_err(|_| 308u32)? {
        Some(w) if w > 0 => w,
        _ => return Err(308),
    };
    // One vote per (proposal, voter).
    if store.get_vote(&req.proposal_id, from).map_err(|_| 309u32)?.is_some() {
        return Err(309);
    }
    Ok(Prepared::CastVote(GovVote {
        proposal_id: req.proposal_id,
        voter: *from,
        weight,
        choice: req.choice,
        cast_at_height: height,
    }))
}

fn validate_execute(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    height: u64,
    req: &ExecuteProposalRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let mut proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) if p.status == GovProposalStatus::Voting => p,
        _ => return Err(306),
    };
    // Voting must be closed.
    if height <= proposal.voting_start_height + gp.voting_period_blocks {
        return Err(307);
    }

    // Tally over the frozen snapshot + cast votes.
    let snapshot_total: u128 = store
        .list_snapshot(&req.proposal_id)
        .map_err(|_| 306u32)?
        .iter()
        .map(|(_, w)| *w)
        .sum();
    let (mut yes, mut no, mut abstain): (u128, u128, u128) = (0, 0, 0);
    for v in store.list_votes(&req.proposal_id).map_err(|_| 306u32)? {
        match v.choice {
            VoteChoice::Yes => yes += v.weight,
            VoteChoice::No => no += v.weight,
            VoteChoice::Abstain => abstain += v.weight,
        }
    }
    let participation = yes + no + abstain;

    let new_status = if participation == 0 {
        GovProposalStatus::Expired
    } else if participation.saturating_mul(10_000)
        < (gp.quorum_bps as u128).saturating_mul(snapshot_total)
    {
        GovProposalStatus::QuorumNotMet
    } else if yes.saturating_mul(10_000) >= (gp.pass_threshold_bps as u128).saturating_mul(yes + no) {
        GovProposalStatus::Passed
    } else {
        GovProposalStatus::Rejected
    };

    let mut payout = None;
    if new_status == GovProposalStatus::Passed {
        match proposal.execution_kind {
            ExecutionKind::RecordOnly => proposal.status = GovProposalStatus::Recorded,
            ExecutionKind::OnChain => {
                // On-chain execution is limited to a single native-Koppa
                // treasury payout; every other class is unsupported (310).
                if proposal.class != GovProposalClass::TreasurySpend {
                    return Err(310);
                }
                match (gp.treasury, proposal.treasury_beneficiary, proposal.treasury_amount) {
                    (Some(treasury), Some(to), Some(amount)) if amount > 0 => {
                        proposal.status = GovProposalStatus::Executed;
                        payout = Some(TreasuryPayout { from_treasury: treasury, to, amount });
                    }
                    // Treasury not configured, or beneficiary/amount missing/zero:
                    // no funds move; the proposal stays live for a later cancel.
                    _ => return Err(310),
                }
            }
        }
    } else {
        proposal.status = new_status;
    }

    // Settle the bond on this terminal transition: return on a good-faith
    // outcome (Recorded / Executed / Rejected), burn on spam / low turnout
    // (QuorumNotMet / Expired).
    let settlement = settle_bond(&mut proposal, |status| {
        matches!(
            status,
            GovProposalStatus::Recorded | GovProposalStatus::Executed | GovProposalStatus::Rejected
        )
    });
    Ok(Prepared::ProposalUpdate { proposal, settlement, payout })
}

/// Resolve a proposal's bond as it reaches a terminal state. `is_return`
/// decides, from the (already-set) terminal `status`, whether the bond is
/// returned; otherwise it is burned. Records the `bond_state` transition and
/// returns the matching balance-settlement instruction. A no-op when the bond
/// is `0` or already settled.
fn settle_bond(
    proposal: &mut GovProposal,
    is_return: impl Fn(GovProposalStatus) -> bool,
) -> BondSettlement {
    if proposal.bond == 0 || proposal.bond_state != BondState::Escrowed {
        return BondSettlement::None;
    }
    if is_return(proposal.status) {
        proposal.bond_state = BondState::Returned;
        BondSettlement::Return(proposal.bond)
    } else {
        proposal.bond_state = BondState::Burned;
        BondSettlement::Burn(proposal.bond)
    }
}

fn validate_cancel(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    req: &CancelProposalRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let mut proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) => p,
        None => return Err(306),
    };
    // The proposer or the council may cancel, and only while Created/Voting.
    let is_proposer = proposal.proposer == *from;
    let is_council = *from == gp.council;
    if (!is_proposer && !is_council)
        || !matches!(proposal.status, GovProposalStatus::Created | GovProposalStatus::Voting)
    {
        return Err(306);
    }
    proposal.status = GovProposalStatus::Cancelled;
    // Proposer cancel returns the bond (clean withdrawal); council cancel burns
    // it (anti-spam force). If the canceller is both, the proposer path wins.
    let settlement = settle_bond(&mut proposal, |_| is_proposer);
    Ok(Prepared::ProposalUpdate { proposal, settlement, payout: None })
}
