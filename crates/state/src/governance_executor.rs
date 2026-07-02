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
//! - `310` on-chain execution not supported in v1
//!
//! Fee/nonce (Policy-B): gate/params/undecodable are pre-semantic (no fee, no
//! nonce, no state). A decoded op that fails semantically charges the fee and
//! advances the nonce (when the sender can cover it). Success charges the fee
//! and advances the nonce exactly once, then persists.

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{
    generate_proposal_id, CancelProposalRequest, CastVoteRequest, CreateProposalRequest,
    ExecuteProposalRequest, ExecutionKind, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
    GovProposalStatus, GovVote, GovernanceOperation, GovernanceParams, GovernanceTxData,
    RegisterAssetRequest, VoteChoice, WeightRule,
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

/// Writes staged by a successful validation, applied only after the fee is charged.
enum Prepared {
    RegisterAsset(GovAsset),
    CreateProposal { proposal: GovProposal, snapshot: Vec<(Address, u128)> },
    CastVote(GovVote),
    ProposalUpdate(GovProposal),
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
            Ok(req) => validate_cancel(db, from, &req),
        },
    };

    // ── Semantic: apply Policy-B fee/nonce ───────────────────────────────────
    let affordable = state.get_balance(from)? >= fee;
    match validated {
        Err(code) => {
            if affordable {
                charge(state, from, proposer, fee)?;
                Ok(result(tx_hash, TxStatus::Failed(code), fee))
            } else {
                // Semantic failure but the sender cannot cover the fee: no charge.
                Ok(result(tx_hash, TxStatus::Failed(code), 0))
            }
        }
        Ok(prepared) => {
            if !affordable {
                // Would succeed but the sender cannot cover the fee: reject free.
                return Ok(result(tx_hash, TxStatus::Failed(302), 0));
            }
            charge(state, from, proposer, fee)?;
            apply(db, prepared)?;
            Ok(result(tx_hash, TxStatus::Success, fee))
        }
    }
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
        Prepared::ProposalUpdate(proposal) => store.put_proposal(&proposal)?,
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

    if new_status == GovProposalStatus::Passed {
        match proposal.execution_kind {
            // On-chain / treasury execution is not supported in v1.
            ExecutionKind::OnChain => return Err(310),
            ExecutionKind::RecordOnly => proposal.status = GovProposalStatus::Recorded,
        }
    } else {
        proposal.status = new_status;
    }
    Ok(Prepared::ProposalUpdate(proposal))
}

fn validate_cancel(
    db: &Arc<Database>,
    from: &Address,
    req: &CancelProposalRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let mut proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) => p,
        None => return Err(306),
    };
    // Only the proposer may cancel, and only while Created/Voting.
    if proposal.proposer != *from
        || !matches!(proposal.status, GovProposalStatus::Created | GovProposalStatus::Voting)
    {
        return Err(306);
    }
    proposal.status = GovProposalStatus::Cancelled;
    Ok(Prepared::ProposalUpdate(proposal))
}
