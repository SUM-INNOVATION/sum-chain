//! Governance rows, as this block's candidate sees them.
//!
//! Unused on purpose — preparation, like [`crate::token_view`] and
//! [`crate::equity_view`]. These three route together in the next commit
//! because their reads cross each other inside a single block: governance takes
//! a create-threshold from a live token balance, freezes a vote snapshot by
//! scanning `cf::TOKEN_BALANCES`, and weighs an equity vote from a class's
//! holders. Route one and the others answer from the parent.
//!
//! Governance's executor is free functions rather than a type, so these are
//! free functions too.
//!
//! ## The two "atomic" writers stop needing a batch
//!
//! `GovStore::create_proposal_atomic` and `record_equity_vote_atomic` exist
//! because a proposal and its index and snapshot rows, or a vote and its dedup
//! row, must not land apart. They get that today from a `WriteBatch` — which is
//! also, precisely, a second publisher: a commit path that does not go through
//! the candidate.
//!
//! Staged into the candidate they need no batch, and the guarantee gets wider
//! rather than narrower. A `WriteBatch` is atomic across its own rows; the
//! candidate is atomic across the whole block. The rows a batch protected can
//! no longer land apart from each other OR from the block that produced them.

use sumchain_primitives::governance::{GovAsset, GovAssetKind, GovProposal, GovProposalId, GovVote};
use sumchain_primitives::Address;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::governance_store::{
    addr_from_suffix, asset_key, composite_key, de, decode_snapshot_weight,
    encode_snapshot_weight, equity_commitment_key, proposer_index_key, ser, EquityClassRoot,
    QualifyingAsset,
};
use sumchain_storage::schema::{decode_token_amount, TokenStore};

use crate::{Result, StateError};

// ── Registry ────────────────────────────────────────────────────────────────

pub fn v_put_asset(view: &mut ExecutionView<'_, '_>, asset: &GovAsset) -> Result<()> {
    view.put(cf::GOV_REGISTRY, &asset_key(&asset.asset), &ser(asset)?)
        .map_err(StateError::Storage)
}

pub fn v_get_asset(
    view: &ExecutionView<'_, '_>,
    kind: &GovAssetKind,
) -> Result<Option<GovAsset>> {
    match view
        .get(cf::GOV_REGISTRY, &asset_key(kind))
        .map_err(StateError::Storage)?
    {
        Some(b) => Ok(Some(de(&b)?)),
        None => Ok(None),
    }
}

// ── Proposals ───────────────────────────────────────────────────────────────

pub fn v_get_proposal(
    view: &ExecutionView<'_, '_>,
    id: &GovProposalId,
) -> Result<Option<GovProposal>> {
    match view.get(cf::GOV_PROPOSALS, id).map_err(StateError::Storage)? {
        Some(b) => Ok(Some(de(&b)?)),
        None => Ok(None),
    }
}

/// Stage a proposal and its proposer-index entry.
pub fn v_put_proposal(view: &mut ExecutionView<'_, '_>, proposal: &GovProposal) -> Result<()> {
    view.put(cf::GOV_PROPOSALS, &proposal.id, &ser(proposal)?)
        .map_err(StateError::Storage)?;
    view.put(
        cf::GOV_PROPOSAL_INDEX,
        &proposer_index_key(&proposal.proposer, &proposal.id),
        &[],
    )
    .map_err(StateError::Storage)
}

/// Stage a proposal, its index entry and every frozen snapshot row.
///
/// The committed twin is `create_proposal_atomic` and uses a `WriteBatch` so a
/// failure part-way leaves no partial rows. Here the candidate is the atom: if
/// any of these writes fails the block fails, and a block that fails publishes
/// nothing. The batch is not replaced by something weaker — it is replaced by
/// something that also covers the rest of the block.
pub fn v_create_proposal(
    view: &mut ExecutionView<'_, '_>,
    proposal: &GovProposal,
    snapshot: &[(Address, u128)],
) -> Result<()> {
    v_put_proposal(view, proposal)?;
    for (holder, weight) in snapshot {
        view.put(
            cf::GOV_SNAPSHOTS,
            &composite_key(&proposal.id, holder),
            &encode_snapshot_weight(*weight),
        )
        .map_err(StateError::Storage)?;
    }
    Ok(())
}

// ── Votes ───────────────────────────────────────────────────────────────────

pub fn v_put_vote(view: &mut ExecutionView<'_, '_>, vote: &GovVote) -> Result<()> {
    view.put(
        cf::GOV_VOTES,
        &composite_key(&vote.proposal_id, &vote.voter),
        &ser(vote)?,
    )
    .map_err(StateError::Storage)
}

pub fn v_get_vote(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
    voter: &Address,
) -> Result<Option<GovVote>> {
    match view
        .get(cf::GOV_VOTES, &composite_key(proposal_id, voter))
        .map_err(StateError::Storage)?
    {
        Some(b) => Ok(Some(de(&b)?)),
        None => Ok(None),
    }
}

pub fn v_list_votes(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
) -> Result<Vec<GovVote>> {
    let mut out = Vec::new();
    for item in view
        .prefix_iter(cf::GOV_VOTES, proposal_id)
        .map_err(StateError::Storage)?
    {
        // A read error ends the scan: a tally short of one vote is a different
        // outcome, not a smaller one.
        let (k, v) = item.map_err(StateError::Storage)?;
        if !k.starts_with(proposal_id) {
            continue;
        }
        out.push(de::<GovVote>(&v)?);
    }
    Ok(out)
}

/// Stage a vote and the dedup row that stops it being cast twice.
///
/// The committed twin batches these two. See [`v_create_proposal`] for why the
/// candidate does not need to.
pub fn v_record_equity_vote(
    view: &mut ExecutionView<'_, '_>,
    vote: &GovVote,
    holder_commitment: &[u8; 32],
) -> Result<()> {
    v_put_vote(view, vote)?;
    view.put(
        cf::GOV_EQUITY_USED_COMMITMENTS,
        &equity_commitment_key(&vote.proposal_id, holder_commitment),
        &[],
    )
    .map_err(StateError::Storage)
}

pub fn v_is_equity_commitment_used(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
    holder_commitment: &[u8; 32],
) -> Result<bool> {
    view.contains(
        cf::GOV_EQUITY_USED_COMMITMENTS,
        &equity_commitment_key(proposal_id, holder_commitment),
    )
    .map_err(StateError::Storage)
}

// ── Snapshots ───────────────────────────────────────────────────────────────

pub fn v_get_snapshot(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
    holder: &Address,
) -> Result<Option<u128>> {
    match view
        .get(cf::GOV_SNAPSHOTS, &composite_key(proposal_id, holder))
        .map_err(StateError::Storage)?
    {
        Some(b) => Ok(Some(decode_snapshot_weight(&b)?)),
        None => Ok(None),
    }
}

/// Every frozen snapshot row for a proposal, from the candidate.
///
/// The tally divides by this total, so a row short of the real set is a
/// different outcome, not a smaller one — which is why a read error ends the
/// scan rather than truncating it.
pub fn v_list_snapshot(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
) -> Result<Vec<(Address, u128)>> {
    let mut out = Vec::new();
    for item in view
        .prefix_iter(cf::GOV_SNAPSHOTS, proposal_id)
        .map_err(StateError::Storage)?
    {
        let (k, v) = item.map_err(StateError::Storage)?;
        if !k.starts_with(proposal_id) {
            continue;
        }
        out.push((addr_from_suffix(&k), decode_snapshot_weight(&v)?));
    }
    Ok(out)
}

// ── Qualifying assets and equity-class roots ────────────────────────────────

pub fn v_put_qualifying_asset(
    view: &mut ExecutionView<'_, '_>,
    asset: &QualifyingAsset,
) -> Result<()> {
    view.put(cf::GOV_QUALIFYING_ASSETS, &asset.token_id, &ser(asset)?)
        .map_err(StateError::Storage)
}

pub fn v_list_effective_qualifying_assets(
    view: &ExecutionView<'_, '_>,
    height: u64,
) -> Result<Vec<QualifyingAsset>> {
    let mut out = Vec::new();
    for item in view
        .prefix_iter(cf::GOV_QUALIFYING_ASSETS, &[])
        .map_err(StateError::Storage)?
    {
        let (_, v) = item.map_err(StateError::Storage)?;
        let a: QualifyingAsset = de(&v)?;
        if a.effective_height <= height {
            out.push(a);
        }
    }
    Ok(out)
}

pub fn v_put_equity_class_root(
    view: &mut ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
    root: &EquityClassRoot,
) -> Result<()> {
    view.put(cf::GOV_EQUITY_CLASS_ROOTS, proposal_id, &ser(root)?)
        .map_err(StateError::Storage)
}

pub fn v_get_equity_class_root(
    view: &ExecutionView<'_, '_>,
    proposal_id: &GovProposalId,
) -> Result<Option<EquityClassRoot>> {
    match view
        .get(cf::GOV_EQUITY_CLASS_ROOTS, proposal_id)
        .map_err(StateError::Storage)?
    {
        Some(b) => Ok(Some(de(&b)?)),
        None => Ok(None),
    }
}

// ── The cross-subsystem read ────────────────────────────────────────────────

/// Holders of a SRC-20 token, from the CANDIDATE, for freezing a vote snapshot.
///
/// This is the read that forces governance and token to migrate together. A
/// snapshot frozen from committed balances, in a block that had already staged
/// a mint or a transfer, binds a proposal to voting power the chain no longer
/// has — and the proposal keeps that snapshot for its whole life.
///
/// Zero balances are skipped and the scan stops at `cap + 1`, so the caller can
/// still detect an over-bound holder set without unbounded work, exactly as the
/// committed twin does.
pub fn v_scan_token_holders(
    view: &ExecutionView<'_, '_>,
    token_id: &[u8; 32],
    cap: usize,
) -> Result<Vec<(Address, u128)>> {
    let mut out = Vec::new();
    for item in view
        .prefix_iter(cf::TOKEN_BALANCES, token_id)
        .map_err(StateError::Storage)?
    {
        let (k, v) = item.map_err(StateError::Storage)?;
        if !k.starts_with(token_id) || k.len() < 52 {
            continue;
        }
        let bal = decode_token_amount(&v)?;
        if bal == 0 {
            continue;
        }
        out.push((addr_from_suffix(&k), bal));
        if out.len() > cap {
            break;
        }
    }
    Ok(out)
}

/// A token balance from the candidate, for a create-threshold check.
pub fn v_token_balance(
    view: &ExecutionView<'_, '_>,
    token_id: &[u8; 32],
    owner: &Address,
) -> Result<u128> {
    match view
        .get(cf::TOKEN_BALANCES, &TokenStore::balance_key(token_id, owner))
        .map_err(StateError::Storage)?
    {
        Some(b) => Ok(decode_token_amount(&b)?),
        None => Ok(0),
    }
}
