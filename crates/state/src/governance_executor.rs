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
//! Governance-v2 codes (native-Koppa eligibility #91, SRC-833 equity vote #92):
//! - `313` native mode not enabled/configured (no qualifying registry / params)
//! - `314` native create found an insufficient (0) eligible set
//! - `315` no qualifying-asset holders (empty electorate before Koppa filter)
//! - `316` qualifying asset not allowlisted / registry empty at register/create
//! - `317` equity mode not enabled, or the class is non-voting (votes_per_share=0)
//! - `318` invalid equity vote (bad merkle proof / bad/mismatched controller
//!   signature / root not frozen for this proposal)
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
    equity_vote_signing_bytes, generate_proposal_id, gov_escrow_address, BondState,
    CancelProposalRequest, CastEquityVoteRequest, CastVoteRequest, CreateProposalRequest,
    ExecuteProposalRequest, ExecutionKind, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
    GovProposalClass, GovProposalStatus, GovVote, GovernanceOperation, GovernanceParams,
    GovernanceTxData, RegisterAssetRequest, RegisterEquityClassRequest,
    RegisterQualifyingAssetRequest, VoteChoice, WeightRule,
};
use sumchain_primitives::{Address, Balance, Hash, TxStatus};
use sumchain_storage::{
    equity_balances_root, equity_merkle_verify, Database, EquityClassRoot, EquityStore, GovStore,
    QualifyingAsset, TokenStore,
};

/// Fixed pass threshold (bps) for `NativeEligibility` 1-address-1-vote proposals
/// when no explicit config is present (#91). 6667 bps ≈ two-thirds of yes+no.
const NATIVE_PASS_THRESHOLD_BPS: u128 = 6667;

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
    CreateProposal {
        proposal: GovProposal,
        snapshot: Vec<(Address, u128)>,
        /// Equity-class root frozen for this proposal (#92, EquityClass only).
        equity_root: Option<EquityClassRoot>,
    },
    CastVote(GovVote),
    /// Register a native-eligibility qualifying SRC-20 (#91).
    RegisterQualifyingAsset(QualifyingAsset),
    /// Register an SRC-833 equity share class as a governance asset (#92).
    RegisterEquityClass(GovAsset),
    /// A controller-attested equity vote + its commitment dedup mark (#92).
    CastEquityVote { vote: GovVote, holder_commitment: [u8; 32] },
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
    // Active PoA validator set for the block being executed (threaded from
    // consensus). Validator-gated actions authorize against exactly this set —
    // never StakingStore/ValidatorSetStore.
    active_validator_pubkeys: &[[u8; 32]],
) -> Result<TxExecutionResult> {
    // ── Pre-semantic: gate / params / decode (no fee, no nonce, no state) ────
    if !gate_open(params, block_height) {
        return Ok(result(tx_hash, TxStatus::Failed(300), 0));
    }
    let Some(gp) = params.governance.as_ref() else {
        return Ok(result(tx_hash, TxStatus::Failed(301), 0));
    };
    let chain_id = state.chain_id();

    let validated: std::result::Result<Prepared, u32> = match gov.operation {
        GovernanceOperation::RegisterAsset => match decode::<RegisterAssetRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_register(db, gp, &req, chain_id, active_validator_pubkeys),
        },
        GovernanceOperation::CreateProposal => match decode::<CreateProposalRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => {
                validate_create(state, db, gp, from, nonce, block_height, block_timestamp, &req)
            }
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
            Ok(req) => validate_cancel(db, gp, from, &req, chain_id, active_validator_pubkeys),
        },
        GovernanceOperation::RegisterQualifyingAsset => {
            match decode::<RegisterQualifyingAssetRequest>(&gov.data) {
                Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
                Ok(req) => validate_register_qualifying(
                    db,
                    gp,
                    &req,
                    chain_id,
                    active_validator_pubkeys,
                ),
            }
        }
        GovernanceOperation::RegisterEquityClass => {
            match decode::<RegisterEquityClassRequest>(&gov.data) {
                Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
                Ok(req) => validate_register_equity_class(
                    db,
                    gp,
                    &req,
                    chain_id,
                    active_validator_pubkeys,
                ),
            }
        }
        GovernanceOperation::CastEquityVote => match decode::<CastEquityVoteRequest>(&gov.data) {
            Err(()) => return Ok(result(tx_hash, TxStatus::Failed(302), 0)),
            Ok(req) => validate_equity_vote(db, gp, from, chain_id, block_height, &req),
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
        Prepared::CreateProposal { proposal, snapshot, equity_root } => {
            store.create_proposal_atomic(&proposal, &snapshot)?;
            // Freeze the equity-class root for this proposal (#92), if any.
            if let Some(root) = equity_root {
                store.put_equity_class_root(&proposal.id, &root)?;
            }
        }
        Prepared::CastVote(vote) => store.put_vote(&vote)?,
        Prepared::RegisterQualifyingAsset(asset) => store.put_qualifying_asset(&asset)?,
        Prepared::RegisterEquityClass(asset) => store.put_asset(&asset)?,
        Prepared::CastEquityVote { vote, holder_commitment } => {
            store.record_equity_vote_atomic(&vote, &holder_commitment)?
        }
        Prepared::ProposalUpdate { proposal, .. } => store.put_proposal(&proposal)?,
    }
    Ok(())
}

// ── Per-operation validation (returns Err(code) for semantic failures) ───────

fn validate_register(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    req: &RegisterAssetRequest,
    chain_id: sumchain_primitives::ChainId,
    active_validator_pubkeys: &[[u8; 32]],
) -> std::result::Result<Prepared, u32> {
    // Validator-quorum authority (replaces the former single council address).
    // `tx.from` is only the fee payer; authority comes from the approvals.
    let signing = sumchain_primitives::validator_authority::register_asset_signing_bytes(
        chain_id,
        &req.token_id,
        req.create_threshold,
        req.effective_height,
    );
    if crate::validator_quorum::verify_validator_quorum(
        &req.approvals,
        &signing,
        active_validator_pubkeys,
        gp.validator_authority_threshold_bps,
    )
    .is_err()
    {
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

/// Register a native-eligibility qualifying SRC-20 (#91). Validator-quorum
/// authorized (reuses the RegisterAsset signing bytes with
/// `create_threshold = min_balance`). The token must exist. Also ensures the
/// `NativeEligibility` governance asset is registered (idempotent-on-put via the
/// caller) so native proposals can be created. Code 316 on authority/token
/// failure.
fn validate_register_qualifying(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    req: &RegisterQualifyingAssetRequest,
    chain_id: sumchain_primitives::ChainId,
    active_validator_pubkeys: &[[u8; 32]],
) -> std::result::Result<Prepared, u32> {
    let signing = sumchain_primitives::validator_authority::register_asset_signing_bytes(
        chain_id,
        &req.token_id,
        req.min_balance,
        req.effective_height,
    );
    if crate::validator_quorum::verify_validator_quorum(
        &req.approvals,
        &signing,
        active_validator_pubkeys,
        gp.validator_authority_threshold_bps,
    )
    .is_err()
    {
        return Err(316);
    }
    // The SRC-20 token must exist (any supply model — a qualifying asset is an
    // eligibility gate, not a vote-weight token).
    let tokens = TokenStore::new(db);
    if tokens.get_token(&req.token_id).map_err(|_| 316u32)?.is_none() {
        return Err(316);
    }
    // Ensure the NativeEligibility governance asset exists so native proposals
    // can be created. Registering the first qualifying asset enables the mode.
    let store = GovStore::new(db);
    if store.get_asset(&GovAssetKind::NativeEligibility).map_err(|_| 316u32)?.is_none() {
        store
            .put_asset(&GovAsset {
                asset: GovAssetKind::NativeEligibility,
                create_threshold: 0,
                vote_weight_rule: WeightRule::OneAddressOneVote,
                status: GovAssetStatus::Enabled,
                effective_height: req.effective_height,
            })
            .map_err(|_| 316u32)?;
    }
    Ok(Prepared::RegisterQualifyingAsset(QualifyingAsset {
        token_id: req.token_id,
        min_balance: req.min_balance,
        effective_height: req.effective_height,
    }))
}

/// Register an SRC-833 equity share class as a governance asset (#92).
/// Validator-quorum authorized. The class must exist and be voting
/// (`votes_per_share > 0`). Registers a `GovAsset::EquityClass` with
/// `SharesTimesVotesPerShare`. Code 317 for a non-voting/missing class, 303 for
/// an authority failure (matches the RegisterAsset convention).
fn validate_register_equity_class(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    req: &RegisterEquityClassRequest,
    chain_id: sumchain_primitives::ChainId,
    active_validator_pubkeys: &[[u8; 32]],
) -> std::result::Result<Prepared, u32> {
    let signing = sumchain_primitives::validator_authority::register_equity_class_signing_bytes(
        chain_id,
        &req.class_id,
        req.create_threshold,
        req.effective_height,
    );
    if crate::validator_quorum::verify_validator_quorum(
        &req.approvals,
        &signing,
        active_validator_pubkeys,
        gp.validator_authority_threshold_bps,
    )
    .is_err()
    {
        return Err(303);
    }
    let equity = EquityStore::new(db);
    let token = equity.tokens().get(&req.class_id).map_err(|_| 317u32)?.ok_or(317u32)?;
    if token.votes_per_share == 0 {
        return Err(317);
    }
    Ok(Prepared::RegisterEquityClass(GovAsset {
        asset: GovAssetKind::EquityClass(req.class_id),
        create_threshold: req.create_threshold,
        vote_weight_rule: WeightRule::SharesTimesVotesPerShare,
        status: GovAssetStatus::Enabled,
        effective_height: req.effective_height,
    }))
}

/// Cast an SRC-833 controller-attested equity vote (#92). Verifies, in order:
///   1. the class exists and is voting (votes_per_share > 0)  → 317
///   2. a balances root is frozen for this proposal          → 318
///   3. the Merkle proof proves (holder_commitment, shares) under that root → 318
///   4. `Address::from_public_key(controller_pubkey) == class.controller` AND
///      Ed25519(controller_sig) over `equity_vote_signing_bytes(...)` verifies → 318
///   5. `(proposal_id, holder_commitment)` not already used  → 309
///   6. weight = shares * votes_per_share; records a `GovVote` + marks used.
/// The proposal must be in `Voting` and inside the voting window (306 / 307).
fn validate_equity_vote(
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    chain_id: sumchain_primitives::ChainId,
    height: u64,
    req: &CastEquityVoteRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) if p.status == GovProposalStatus::Voting => p,
        _ => return Err(306),
    };
    // Must be an EquityClass proposal.
    let class_id = match proposal.asset {
        GovAssetKind::EquityClass(cid) => cid,
        _ => return Err(306),
    };
    // Voting window (height-based).
    if height > proposal.voting_start_height + gp.voting_period_blocks {
        return Err(307);
    }

    // (1) class voting.
    let equity = EquityStore::new(db);
    let token = equity.tokens().get(&class_id).map_err(|_| 317u32)?.ok_or(317u32)?;
    if token.votes_per_share == 0 {
        return Err(317);
    }

    // (2) root frozen for this proposal.
    let frozen = match store.get_equity_class_root(&req.proposal_id).map_err(|_| 318u32)? {
        Some(r) if r.class_id == class_id => r,
        _ => return Err(318),
    };

    // (3) Merkle proof of (holder_commitment, shares) under the frozen root.
    // The leaf index is recovered from the class's current sorted holder set;
    // because a proposal freezes the root at creation and equity balances are
    // static within the vote window in these flows, the on-chain holder ordering
    // matches the frozen root. Recompute the proof deterministically and require
    // it to reproduce the frozen root with the submitted path.
    if !equity_vote_merkle_ok(db, &class_id, &frozen.balances_root, req) {
        return Err(318);
    }

    // (4) controller identity + signature.
    if Address::from_public_key(&req.controller_pubkey) != token.controller {
        return Err(318);
    }
    let signing = equity_vote_signing_bytes(
        chain_id,
        &req.proposal_id,
        &class_id,
        &frozen.balances_root,
        &req.holder_commitment,
        req.shares,
        from,
    );
    if sumchain_crypto::verify_bytes(&signing, &req.controller_sig, &req.controller_pubkey).is_err() {
        return Err(318);
    }

    // (5) dedup on (proposal, holder_commitment).
    if store
        .is_equity_commitment_used(&req.proposal_id, &req.holder_commitment)
        .map_err(|_| 309u32)?
    {
        return Err(309);
    }

    // (6) weight = shares * votes_per_share.
    let weight = (req.shares as u128).saturating_mul(frozen.votes_per_share as u128);
    let vote = GovVote {
        proposal_id: req.proposal_id,
        voter: *from,
        weight,
        choice: req.choice,
        cast_at_height: height,
    };
    Ok(Prepared::CastEquityVote { vote, holder_commitment: req.holder_commitment })
}

/// Verify the submitted Merkle path proves `(holder_commitment, shares)` under
/// `balances_root` (#92). The leaf index is derived from the class's sorted
/// holder set (commitments unique per class); the submitted `merkle_path` must
/// then fold to the frozen root under the same rules the chain used to build it.
fn equity_vote_merkle_ok(
    db: &Arc<Database>,
    class_id: &[u8; 32],
    balances_root: &[u8; 32],
    req: &CastEquityVoteRequest,
) -> bool {
    let equity = EquityStore::new(db);
    let mut holders = match equity.balances().get_holders(class_id) {
        Ok(h) => h,
        Err(_) => return false,
    };
    holders.sort_by(|a, b| a.0.cmp(&b.0));
    let idx = match holders.iter().position(|(hc, _)| hc == &req.holder_commitment) {
        Some(i) => i as u64,
        None => return false,
    };
    equity_merkle_verify(
        balances_root,
        &req.holder_commitment,
        req.shares,
        idx,
        &req.merkle_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_create(
    state: &Arc<StateManager>,
    db: &Arc<Database>,
    gp: &GovernanceParams,
    from: &Address,
    nonce: u64,
    height: u64,
    timestamp: u64,
    req: &CreateProposalRequest,
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);

    // Asset must be registered, enabled, and effective at this height. A missing
    // registration maps to a mode-specific "not enabled" code for the v2 kinds
    // (313 native, 317 equity), and to the generic 303 for SRC-20.
    let not_enabled_code = match req.asset {
        GovAssetKind::NativeEligibility => 313u32,
        GovAssetKind::EquityClass(_) => 317u32,
        GovAssetKind::Src20Token(_) => 303u32,
    };
    let asset = match store.get_asset(&req.asset).map_err(|_| not_enabled_code)? {
        Some(a) if a.status == GovAssetStatus::Enabled && a.effective_height <= height => a,
        _ => return Err(not_enabled_code),
    };

    // Build the frozen snapshot per asset kind. `equity_root` is set only for an
    // EquityClass proposal (frozen root binding).
    let (snapshot, equity_root): (Vec<(Address, u128)>, Option<EquityClassRoot>) = match req.asset {
        GovAssetKind::Src20Token(token_id) => {
            // Proposer must meet the per-asset create threshold (live balance).
            let tokens = TokenStore::new(db);
            let bal = tokens.get_balance(&token_id, from).map_err(|_| 304u32)?;
            if bal < asset.create_threshold {
                return Err(304);
            }
            let cap = gp.max_snapshot_holders as usize;
            let snap = store.scan_token_holders(&token_id, cap).map_err(|_| 305u32)?;
            if snap.len() > cap {
                return Err(305);
            }
            (snap, None)
        }
        GovAssetKind::NativeEligibility => {
            (build_native_eligibility_snapshot(state, db, gp, height)?, None)
        }
        GovAssetKind::EquityClass(class_id) => {
            let (snap, root) =
                build_equity_class_snapshot(state, db, gp, from, height, &class_id, &asset)?;
            (snap, Some(root))
        }
    };

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
    Ok(Prepared::CreateProposal { proposal, snapshot, equity_root })
}

/// Build the native-Koppa 1-address-1-vote eligibility snapshot at creation
/// height (#91). Electorate = holders of an allowlisted, effective qualifying
/// SRC-20 (balance >= that asset's `min_balance`) whose native Koppa balance is
/// >= `gp.min_koppa_for_eligibility`. Deduped; each eligible address weight = 1.
/// Bounded by `gp.max_snapshot_holders` (305). Codes: 316 empty registry, 315 no
/// qualifying holders, 314 empty eligible set after the Koppa filter.
fn build_native_eligibility_snapshot(
    state: &Arc<StateManager>,
    db: &Arc<Database>,
    gp: &GovernanceParams,
    height: u64,
) -> std::result::Result<Vec<(Address, u128)>, u32> {
    let store = GovStore::new(db);
    let qualifying = store.list_effective_qualifying_assets(height).map_err(|_| 316u32)?;
    if qualifying.is_empty() {
        return Err(316);
    }
    let tokens = TokenStore::new(db);
    let cap = gp.max_snapshot_holders as usize;

    // Collect the union of qualifying-asset holders (balance >= min_balance),
    // deduped. Scan each qualifying token's holders; bound total work.
    let mut eligible: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
    let mut any_holder = false;
    for qa in &qualifying {
        // scan_token_holders returns up to cap+1 holders with non-zero balance.
        let holders = store.scan_token_holders(&qa.token_id, cap).map_err(|_| 305u32)?;
        for (addr, bal) in holders {
            if bal < qa.min_balance {
                continue;
            }
            any_holder = true;
            // Native Koppa floor at creation height (current state == creation
            // height, executed in-block).
            let koppa = state.get_balance(&addr).map_err(|_| 315u32)?;
            if (koppa as u128) < gp.min_koppa_for_eligibility {
                continue;
            }
            eligible.insert(addr);
            if eligible.len() > cap {
                return Err(305);
            }
        }
    }
    if !any_holder {
        return Err(315);
    }
    if eligible.is_empty() {
        return Err(314);
    }
    Ok(eligible.into_iter().map(|a| (a, 1u128)).collect())
}

/// Build the frozen equity-class snapshot for an EquityClass proposal (#92).
/// Computes the chain-derived `EQUITY_BALANCES` Merkle root now and freezes it to
/// the proposal. The proposer must meet the class create threshold (measured as
/// total voting weight `sum(shares) * votes_per_share`). The GOV_SNAPSHOTS rows
/// store `snapshot_total` as a single synthetic entry keyed by the escrow-style
/// zero address so tally quorum can divide against it without a holder table.
/// Code 317 if the class is non-voting (votes_per_share == 0) or missing.
#[allow(clippy::too_many_arguments)]
fn build_equity_class_snapshot(
    _state: &Arc<StateManager>,
    db: &Arc<Database>,
    gp: &GovernanceParams,
    _from: &Address,
    _height: u64,
    class_id: &[u8; 32],
    asset: &GovAsset,
) -> std::result::Result<(Vec<(Address, u128)>, EquityClassRoot), u32> {
    let equity = EquityStore::new(db);
    let token = equity.tokens().get(class_id).map_err(|_| 317u32)?.ok_or(317u32)?;
    if token.votes_per_share == 0 {
        return Err(317);
    }
    // Chain-derived root over the class's EQUITY_BALANCES (never client-supplied).
    let balances_root = equity_balances_root(db, class_id).map_err(|_| 317u32)?;

    // Total voting weight across the class = sum(shares) * votes_per_share.
    let holders = equity.balances().get_holders(class_id).map_err(|_| 317u32)?;
    let total_shares: u128 = holders.iter().map(|(_, s)| *s as u128).sum();
    let snapshot_total = total_shares.saturating_mul(token.votes_per_share as u128);

    // Bound: number of holder leaves must respect the snapshot-holder cap.
    if holders.len() > gp.max_snapshot_holders as usize {
        return Err(305);
    }
    // Create threshold is measured against the class's total voting weight.
    if snapshot_total < asset.create_threshold {
        return Err(304);
    }

    let root = EquityClassRoot {
        class_id: *class_id,
        balances_root,
        votes_per_share: token.votes_per_share,
        frozen_height: _height,
    };
    // Store snapshot_total as one synthetic row so tally quorum has a denominator
    // without exposing any holder→balance mapping. Keyed by Address::ZERO.
    let snapshot = vec![(Address::ZERO, snapshot_total)];
    Ok((snapshot, root))
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

    // Native-eligibility proposals pass at a fixed 6667 bps of (yes+no) (#91);
    // SRC-20 and equity proposals use the configured `pass_threshold_bps`.
    let pass_bps: u128 = match proposal.asset {
        GovAssetKind::NativeEligibility => NATIVE_PASS_THRESHOLD_BPS,
        _ => gp.pass_threshold_bps as u128,
    };

    let new_status = if participation == 0 {
        GovProposalStatus::Expired
    } else if participation.saturating_mul(10_000)
        < (gp.quorum_bps as u128).saturating_mul(snapshot_total)
    {
        GovProposalStatus::QuorumNotMet
    } else if yes.saturating_mul(10_000) >= pass_bps.saturating_mul(yes + no) {
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
    chain_id: sumchain_primitives::ChainId,
    active_validator_pubkeys: &[[u8; 32]],
) -> std::result::Result<Prepared, u32> {
    let store = GovStore::new(db);
    let mut proposal = match store.get_proposal(&req.proposal_id).map_err(|_| 306u32)? {
        Some(p) => p,
        None => return Err(306),
    };
    // Only cancellable while Created/Voting.
    if !matches!(proposal.status, GovProposalStatus::Created | GovProposalStatus::Voting) {
        return Err(306);
    }
    // Authority: the proposer may cancel with no approvals; anyone else needs a
    // validator quorum (replaces the former single council address).
    let is_proposer = proposal.proposer == *from;
    if !is_proposer {
        let signing = sumchain_primitives::validator_authority::cancel_proposal_signing_bytes(
            chain_id,
            &req.proposal_id,
        );
        if crate::validator_quorum::verify_validator_quorum(
            &req.approvals,
            &signing,
            active_validator_pubkeys,
            gp.validator_authority_threshold_bps,
        )
        .is_err()
        {
            return Err(306);
        }
    }
    proposal.status = GovProposalStatus::Cancelled;
    // Proposer cancel returns the bond (clean withdrawal); validator-quorum cancel
    // burns it (anti-spam force).
    let settlement = settle_bond(&mut proposal, |_| is_proposer);
    Ok(Prepared::ProposalUpdate { proposal, settlement, payout: None })
}
