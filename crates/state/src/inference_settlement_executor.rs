//! OmniNode Inference Settlement executor (issue #61) — v1.
//!
//! Escrow-funded reward settlement keyed by existing immutable
//! `InferenceAttestation` records. This executor **only reads** attestations
//! (via [`InferenceAttestationExecutor`]) and moves escrowed Koppa; it never
//! writes the attestation CFs.
//!
//! **v1 has no bond slashing** — there is no on-chain verifier bond. The economic
//! levers are reward denial, claim withholding, escrow refund, and dispute
//! records. Nothing here mints Koppa: a funder is debited on open/fund, verifiers
//! are credited on claim, and the funder is refunded any remainder on close, so
//! total supply is conserved.

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::inference_attestation::inference_attestation_key;
use sumchain_primitives::inference_attestation::InferenceAttestationDigest;
use sumchain_primitives::inference_attestation::InferenceAttestationRecord;
use sumchain_primitives::inference_settlement::{
    session_key, session_prefix, settlement_entry_key, verifier_key, InferenceClaim,
    InferenceClaimStatus, InferenceConsistencyConfig, InferenceDispute, InferenceDisputeStatus,
    InferenceSession, InferenceSessionStatus, InferenceSettlementOperation, InferenceVerifierRecord,
    InferenceVerifierStatus, OpenInferenceDisputeRequest, OpenInferenceSessionRequest,
    ResolveInferenceDisputeRequest,
};
use sumchain_primitives::{Address, Balance};
use sumchain_storage::db::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;
use tracing::info;

use crate::inference_attestation_executor::InferenceAttestationExecutor;
use crate::{Result, StateError, StateManager};

/// Result of a settlement operation. `failure_code`, when `Some(c)`, is the
/// `TxStatus::Failed(c)` the dispatch surfaces.
#[derive(Debug)]
pub struct InferenceSettlementExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub failure_code: Option<u32>,
}

impl InferenceSettlementExecutionResult {
    fn ok() -> Self {
        Self { success: true, error: None, failure_code: None }
    }
    fn fail(code: u32, msg: impl Into<String>) -> Self {
        Self { success: false, error: Some(msg.into()), failure_code: Some(code) }
    }
}

/// Height at/after which a verifier's claim is mature: the attestation must be
/// finalized (`+ finality_depth`) AND the dispute window must have elapsed
/// (`+ dispute_window_blocks`). No reward is payable before this.
fn claim_maturity_height(
    included_at_height: u64,
    finality_depth: u64,
    dispute_window_blocks: u64,
) -> u64 {
    included_at_height
        .saturating_add(finality_depth)
        .saturating_add(dispute_window_blocks)
}

/// Deterministic consistency predicate (issue #77). `matching` is the size of the
/// claimant's exact-tuple group (claimant included). The `min_matching_verifiers`
/// constraint is always active; the `threshold_bps` constraint is active only when
/// `> 0` and is measured against the fixed, funder-declared `max_verifiers` — never
/// a live attestation count. Both active constraints must hold.
fn consistency_satisfied(cfg: InferenceConsistencyConfig, matching: u32, max_verifiers: u32) -> bool {
    if matching < cfg.min_matching_verifiers {
        return false;
    }
    if cfg.threshold_bps > 0 {
        // matching / max_verifiers >= threshold_bps / 10_000, in integer math.
        // u64 widening avoids overflow (u32 * 10_000 fits in u64 comfortably).
        let lhs = matching as u64 * 10_000;
        let rhs = max_verifiers as u64 * cfg.threshold_bps as u64;
        if lhs < rhs {
            return false;
        }
    }
    true
}

pub struct InferenceSettlementExecutor {
    db: Arc<Database>,
}

/// Whether one attestation lends consistency weight to `target`.
///
/// The rule, shared by the candidate and committed counts so they cannot
/// disagree — a group size decides a payout, and two copies that drift would
/// decide it differently depending on who asked.
fn counts_toward_group(
    att: &InferenceAttestationRecord,
    target: &InferenceAttestationDigest,
    claim_height: u64,
    finality_depth: u64,
    dispute: Option<InferenceDisputeStatus>,
) -> bool {
    // Full-tuple equality — the four digest commitments, not response_hash
    // alone. (session_id is constant across the group, so it is excluded.)
    if att.digest.model_hash != target.model_hash
        || att.digest.manifest_root != target.manifest_root
        || att.digest.response_hash != target.response_hash
        || att.digest.proof_root != target.proof_root
    {
        return false;
    }
    // Only finalized attestations count — prevents a flash of not-yet-final
    // attestations from manufacturing a plurality in the same block.
    if att.included_at_height.saturating_add(finality_depth) > claim_height {
        return false;
    }
    // A disputed (open) or denied attestation lends no consistency weight.
    !matches!(
        dispute,
        Some(InferenceDisputeStatus::Open) | Some(InferenceDisputeStatus::ResolvedDenyClaim)
    )
}

/// Σ `remaining_escrow` over a session-row stream.
///
/// Shared by the committed and candidate totals so the two cannot decode or
/// accumulate differently — this feeds the supply correction's reserve delta,
/// and a divergence between the value a block mints against and the value a
/// diagnostic reports is precisely the kind that goes unnoticed.
///
/// The stream is fallible because the candidate's merged scan is: a read error
/// ends the sum loudly rather than producing a short total that would mint too
/// large a delta.
fn sum_escrow<I>(rows: I) -> Result<u128>
where
    I: Iterator<Item = Result<(Vec<u8>, Vec<u8>)>>,
{
    let mut sum: u128 = 0;
    for row in rows {
        let (key, value) = row?;
        if key.len() != 32 {
            continue;
        }
        let s: InferenceSession = bincode::deserialize(&value)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        sum = sum.checked_add(s.remaining_escrow).ok_or_else(|| {
            StateError::BlockValidation("inference escrow sum overflow".to_string())
        })?;
    }
    Ok(sum)
}

/// Σ verifier `bond` over a verifier-row stream. Shared for the same reason as
/// [`sum_escrow`].
fn sum_bonds<I>(rows: I) -> Result<u128>
where
    I: Iterator<Item = Result<(Vec<u8>, Vec<u8>)>>,
{
    let mut sum: u128 = 0;
    for row in rows {
        let (key, value) = row?;
        if key.len() != 32 {
            continue;
        }
        let r: InferenceVerifierRecord = bincode::deserialize(&value)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        sum = sum.checked_add(r.bond).ok_or_else(|| {
            StateError::BlockValidation("inference verifier bond sum overflow".to_string())
        })?;
    }
    Ok(sum)
}

impl InferenceSettlementExecutor {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Deduct the tx fee from the sender, credit the proposer, bump the nonce.
    /// Charged up-front so gate-open semantic failures still pay the fee (matches
    /// the other subprotocol executors). The gate-closed (`350`) path is handled
    /// in dispatch before this runs, so it pays nothing.
    fn deduct_fee(
        &self,
        state: &StateManager,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }
        if state.get_balance(sender)? < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: state.get_balance(sender)?,
            });
        }
        state.deduct(sender, fee)?;
        if !proposer.is_zero() {
            state.credit(proposer, fee)?;
        }
        state.increment_nonce(sender)?;
        Ok(())
    }

    /// Dispatch a settlement operation. The activation gate is enforced by the
    /// caller (dispatch) before this is invoked.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        operation: &InferenceSettlementOperation,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        chain_params: &ChainParams,
        // Active PoA validator set for the block being executed (threaded from
        // consensus). `ResolveDispute` authorizes against exactly this set —
        // never StakingStore/ValidatorSetStore.
        active_validator_pubkeys: &[[u8; 32]],
    ) -> Result<InferenceSettlementExecutionResult> {
        self.deduct_fee(state, sender, fee, proposer)?;

        match operation {
            InferenceSettlementOperation::OpenSession(req) => {
                self.open_session(view, sender, req, state, block_height, chain_params)
            }
            InferenceSettlementOperation::FundSession(req) => {
                self.fund_session(view, sender, &req.session_id, req.amount, state)
            }
            InferenceSettlementOperation::ClaimReward(req) => {
                self.claim_reward(view, sender, &req.session_id, state, block_height, chain_params)
            }
            InferenceSettlementOperation::OpenDispute(req) => {
                self.open_dispute(view, sender, req, block_height, chain_params)
            }
            InferenceSettlementOperation::ResolveDispute(req) => {
                self.resolve_dispute(
                    view,
                    req,
                    state,
                    block_height,
                    chain_params,
                    state.chain_id(),
                    active_validator_pubkeys,
                )
            }
            InferenceSettlementOperation::RefundSession(req) => {
                self.refund_session(view, sender, &req.session_id, state, block_height, chain_params)
            }
            // ── Verifier bonding (issue #78) ──
            InferenceSettlementOperation::RegisterVerifier(req) => {
                self.register_verifier(view, sender, req.bond, state, block_height, chain_params)
            }
            InferenceSettlementOperation::AddVerifierBond(req) => {
                self.add_verifier_bond(view, sender, req.amount, state, block_height, chain_params)
            }
            InferenceSettlementOperation::BeginVerifierUnbond => {
                self.begin_verifier_unbond(view, sender, block_height, chain_params)
            }
            InferenceSettlementOperation::WithdrawVerifierBond => {
                self.withdraw_verifier_bond(view, sender, state, block_height, chain_params)
            }
        }
    }

    /// `true` iff the verifier-bonding gate (issue #78) is open at `block_height`.
    fn bonding_gate_open(chain_params: &ChainParams, block_height: u64) -> bool {
        matches!(
            chain_params.inference_verifier_bonding_enabled_from_height,
            Some(h) if block_height >= h
        )
    }

    // ── Operations ───────────────────────────────────────────────────────────

    fn open_session(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        req: &OpenInferenceSessionRequest,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if Self::v_get_session(view, &req.session_id)?.is_some() {
            return Ok(InferenceSettlementExecutionResult::fail(
                352,
                "inference session already exists",
            ));
        }
        // Term validity.
        if req.reward_per_verifier == 0 || req.max_verifiers == 0 {
            return Ok(InferenceSettlementExecutionResult::fail(
                354,
                "reward_per_verifier and max_verifiers must be > 0",
            ));
        }
        if req.dispute_window_blocks > chain_params.inference_settlement_max_dispute_window_blocks {
            return Ok(InferenceSettlementExecutionResult::fail(
                354,
                "dispute_window_blocks exceeds chain maximum",
            ));
        }
        // Expiry must be at or after the minimum claim-maturity window, so a
        // session can never expire (and be refunded) before an attestation
        // submitted at open time could finalize + clear its dispute window.
        let min_expiry =
            claim_maturity_height(block_height, chain_params.finality_depth, req.dispute_window_blocks);
        if req.expires_at_height <= block_height || req.expires_at_height < min_expiry {
            return Ok(InferenceSettlementExecutionResult::fail(
                354,
                "expires_at_height must be >= created_at_height + finality_depth + dispute_window_blocks",
            ));
        }
        if req.expires_at_height - block_height
            > chain_params.inference_settlement_max_session_duration_blocks
        {
            return Ok(InferenceSettlementExecutionResult::fail(
                354,
                "session duration exceeds chain maximum",
            ));
        }
        // Deposit must at least cover one reward and not exceed the full cap.
        let full_cap = req.reward_per_verifier.saturating_mul(req.max_verifiers as u128);
        if req.deposit < req.reward_per_verifier || req.deposit > full_cap {
            return Ok(InferenceSettlementExecutionResult::fail(
                355,
                "deposit must be between reward_per_verifier and reward_per_verifier*max_verifiers",
            ));
        }
        // Consistency/plurality mode (issue #77) is an opt-in, gated claim rule.
        // Only a session that requests it is affected: the consistency gate is a
        // semantic OpenSession check (fee already paid), NOT the free 350
        // settlement gate. A session with no consistency config is unaffected by
        // the consistency gate entirely.
        if let Some(cfg) = &req.consistency {
            if !matches!(
                chain_params.inference_settlement_consistency_enabled_from_height,
                Some(h) if block_height >= h
            ) {
                return Ok(InferenceSettlementExecutionResult::fail(
                    361,
                    "inference consistency mode not enabled at this block height",
                ));
            }
            // Deterministic bounds. Denominator for any bps rule is the fixed,
            // funder-declared `max_verifiers` — never a live attestation count.
            if cfg.min_matching_verifiers < 1
                || cfg.min_matching_verifiers > req.max_verifiers
                || cfg.threshold_bps > 10_000
            {
                return Ok(InferenceSettlementExecutionResult::fail(
                    363,
                    "invalid inference consistency configuration",
                ));
            }
        }
        // Verifier-bond requirement (issue #78) is opt-in and gated. A session that
        // requests it needs the bonding gate open (semantic failure 364, fee paid);
        // a session without it is unaffected by the bonding gate.
        if let Some(req_bond) = &req.bond_requirement {
            if !Self::bonding_gate_open(chain_params, block_height) {
                return Ok(InferenceSettlementExecutionResult::fail(
                    364,
                    "inference verifier bonding not enabled at this block height",
                ));
            }
            if req_bond.min_bond == 0 || req_bond.slash_bps_on_denied_dispute > 10_000 {
                return Ok(InferenceSettlementExecutionResult::fail(
                    365,
                    "invalid verifier bond requirement config",
                ));
            }
        }
        if state.get_balance(sender)? < req.deposit {
            return Ok(InferenceSettlementExecutionResult::fail(
                355,
                "insufficient balance for session deposit",
            ));
        }

        state.deduct(sender, req.deposit)?;
        let session = InferenceSession {
            session_id: req.session_id.clone(),
            funder: *sender,
            reward_per_verifier: req.reward_per_verifier,
            max_verifiers: req.max_verifiers,
            remaining_escrow: req.deposit,
            claims_count: 0,
            dispute_window_blocks: req.dispute_window_blocks,
            status: InferenceSessionStatus::Open,
            created_at_height: block_height,
            expires_at_height: req.expires_at_height,
            consistency: req.consistency,
            bond_requirement: req.bond_requirement,
        };
        Self::v_put_session(view, &session)?;
        info!(
            "InferenceSettlement OpenSession {} funder={} deposit={}",
            req.session_id, sender, req.deposit
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn fund_session(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        session_id: &str,
        amount: u128,
        state: &StateManager,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match Self::v_get_session(view, session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        if session.status != InferenceSessionStatus::Open {
            return Ok(InferenceSettlementExecutionResult::fail(352, "session not open"));
        }
        if session.funder != *sender {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "only the funder may fund the session",
            ));
        }
        if amount == 0 {
            return Ok(InferenceSettlementExecutionResult::fail(354, "amount must be > 0"));
        }
        if state.get_balance(sender)? < amount {
            return Ok(InferenceSettlementExecutionResult::fail(
                355,
                "insufficient balance to fund",
            ));
        }
        state.deduct(sender, amount)?;
        session.remaining_escrow = session.remaining_escrow.saturating_add(amount);
        Self::v_put_session(view, &session)?;
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn claim_reward(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        session_id: &str,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match Self::v_get_session(view, session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        if session.status != InferenceSessionStatus::Open {
            return Ok(InferenceSettlementExecutionResult::fail(352, "session not open"));
        }
        // The signer must be the verifier of an existing attestation for this session.
        let att_key = inference_attestation_key(session_id, sender);
        let att = match InferenceAttestationExecutor::v_get(view, &att_key)? {
            Some(a) => a,
            None => {
                return Ok(InferenceSettlementExecutionResult::fail(
                    356,
                    "no attestation for (session_id, signer)",
                ));
            }
        };
        // Claim only after the attestation is finalized AND the dispute window
        // has elapsed.
        let maturity = claim_maturity_height(
            att.included_at_height,
            chain_params.finality_depth,
            session.dispute_window_blocks,
        );
        if block_height < maturity {
            return Ok(InferenceSettlementExecutionResult::fail(
                357,
                "claim not yet mature (needs finality_depth + dispute_window)",
            ));
        }
        // A dispute against this verifier blocks the claim (open = pending,
        // denied = withheld). Only an allow-claim resolution or no dispute passes.
        if let Some(d) = Self::v_get_dispute(view, session_id, sender)? {
            match d.status {
                InferenceDisputeStatus::Open | InferenceDisputeStatus::ResolvedDenyClaim => {
                    return Ok(InferenceSettlementExecutionResult::fail(
                        359,
                        "an unresolved or denied dispute blocks this claim",
                    ));
                }
                InferenceDisputeStatus::ResolvedAllowClaim => {}
            }
        }
        if Self::v_get_claim(view, session_id, sender)?.is_some() {
            return Ok(InferenceSettlementExecutionResult::fail(358, "reward already claimed"));
        }
        // Consistency/plurality rule (issue #77). Only when the session opted in.
        // The group is computed against the CLAIMANT'S OWN full digest tuple, so a
        // qualifying claimant is by construction a member of the winning group — a
        // divergent-digest verifier can never ride another group's plurality.
        if let Some(cfg) = session.consistency {
            let matching = Self::v_consistency_group_size(
                view,
                session_id,
                &att.digest,
                block_height,
                chain_params.finality_depth,
            )?;
            if !consistency_satisfied(cfg, matching, session.max_verifiers) {
                return Ok(InferenceSettlementExecutionResult::fail(
                    362,
                    "insufficient verifier consistency for claim",
                ));
            }
        }
        // Verifier-bond gating (issue #78). Only for bond-required sessions.
        // Deterministic order: missing record (367) → not Active (368) → too low (370).
        if let Some(bond_req) = session.bond_requirement {
            let record = Self::v_get_verifier(view, sender)?;
            match record {
                None => {
                    return Ok(InferenceSettlementExecutionResult::fail(
                        367,
                        "verifier not registered",
                    ));
                }
                Some(r) if r.status != InferenceVerifierStatus::Active => {
                    return Ok(InferenceSettlementExecutionResult::fail(
                        368,
                        "verifier not active (unbonding or withdrawn)",
                    ));
                }
                Some(r) if r.bond < bond_req.min_bond => {
                    return Ok(InferenceSettlementExecutionResult::fail(
                        370,
                        "insufficient verifier bond for claim",
                    ));
                }
                Some(_) => {}
            }
        }
        if session.claims_count >= session.max_verifiers {
            return Ok(InferenceSettlementExecutionResult::fail(
                355,
                "max_verifiers reached; no reward available",
            ));
        }
        if session.remaining_escrow < session.reward_per_verifier {
            return Ok(InferenceSettlementExecutionResult::fail(
                355,
                "insufficient remaining escrow for reward",
            ));
        }

        state.credit(sender, session.reward_per_verifier)?;
        // 800B correction: a valid settlement claim is REAL compute service —
        // accrue protocol-earned credit (the reward) for 1:1 grant unlock and
        // advance the verifier milestone counter. No-ops until the supply
        // correction is applied.
        {
            use crate::supply::SupplyStore;
            SupplyStore::accrue_earned_credit(
                view,
                sender,
                sumchain_primitives::supply::ServiceKind::Compute,
                session.reward_per_verifier,
            )?;
            SupplyStore::record_settlement_claim(view, sender)?;
        }
        session.remaining_escrow -= session.reward_per_verifier;
        session.claims_count += 1;
        Self::v_put_session(view, &session)?;
        Self::v_put_claim(view, &InferenceClaim {
            session_id: session_id.to_string(),
            verifier: *sender,
            amount: session.reward_per_verifier,
            claimed_at_height: block_height,
            status: InferenceClaimStatus::Paid,
        })?;
        info!(
            "InferenceSettlement ClaimReward {} verifier={} amount={}",
            session_id, sender, session.reward_per_verifier
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn open_dispute(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        req: &OpenInferenceDisputeRequest,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        // Disputes require the dispute mode to be enabled (a configured
        // validator-quorum threshold) — otherwise a dispute could block a claim
        // with no path to resolution.
        if chain_params.inference_settlement_dispute_threshold_bps.is_none() {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "disputes disabled: no dispute threshold configured",
            ));
        }
        let session = match Self::v_get_session(view, &req.session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        // Only the funder may raise a dispute in v1.
        if session.funder != *sender {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "only the funder may open a dispute",
            ));
        }
        // Target must have an attestation, and the dispute must be raised BEFORE
        // the claim matures (during the dispute window).
        let att_key = inference_attestation_key(&req.session_id, &req.verifier);
        let att = match InferenceAttestationExecutor::v_get(view, &att_key)? {
            Some(a) => a,
            None => {
                return Ok(InferenceSettlementExecutionResult::fail(
                    356,
                    "no attestation for the disputed verifier",
                ));
            }
        };
        let maturity = claim_maturity_height(
            att.included_at_height,
            chain_params.finality_depth,
            session.dispute_window_blocks,
        );
        if block_height >= maturity {
            return Ok(InferenceSettlementExecutionResult::fail(
                357,
                "claim already mature; cannot open dispute",
            ));
        }
        if Self::v_get_dispute(view, &req.session_id, &req.verifier)?.is_some() {
            return Ok(InferenceSettlementExecutionResult::fail(358, "dispute already exists"));
        }
        Self::v_put_dispute(view, &InferenceDispute {
            session_id: req.session_id.clone(),
            verifier: req.verifier,
            opener: *sender,
            evidence_commitment: req.evidence_commitment,
            status: InferenceDisputeStatus::Open,
            opened_at_height: block_height,
            resolved_at_height: None,
            allow_claim: false,
        })?;
        Ok(InferenceSettlementExecutionResult::ok())
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_dispute(
        &self,
        view: &mut ExecutionView<'_, '_>,
        req: &ResolveInferenceDisputeRequest,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
        chain_id: sumchain_primitives::ChainId,
        active_validator_pubkeys: &[[u8; 32]],
    ) -> Result<InferenceSettlementExecutionResult> {
        // Validator-quorum authority (replaces the former single resolver
        // address). `tx.from` is only the fee payer; authority comes from the
        // approvals over the active PoA validator set for this block.
        let threshold_bps = match chain_params.inference_settlement_dispute_threshold_bps {
            Some(bps) => bps,
            None => {
                return Ok(InferenceSettlementExecutionResult::fail(
                    353,
                    "disputes disabled: no dispute threshold configured",
                ));
            }
        };
        let signing = sumchain_primitives::validator_authority::resolve_dispute_signing_bytes(
            chain_id,
            &req.session_id,
            &req.verifier,
            req.allow_claim,
        );
        if crate::validator_quorum::verify_validator_quorum(
            &req.approvals,
            &signing,
            active_validator_pubkeys,
            threshold_bps,
        )
        .is_err()
        {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "resolve dispute: validator quorum not met",
            ));
        }
        let session = match Self::v_get_session(view, &req.session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        let mut dispute = match Self::v_get_dispute(view, &req.session_id, &req.verifier)? {
            Some(d) => d,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "dispute not found")),
        };
        if dispute.status != InferenceDisputeStatus::Open {
            return Ok(InferenceSettlementExecutionResult::fail(
                359,
                "dispute already resolved",
            ));
        }
        dispute.status = if req.allow_claim {
            InferenceDisputeStatus::ResolvedAllowClaim
        } else {
            InferenceDisputeStatus::ResolvedDenyClaim
        };
        dispute.allow_claim = req.allow_claim;
        dispute.resolved_at_height = Some(block_height);
        Self::v_put_dispute(view, &dispute)?;

        // Slashing (issue #78) happens ONLY here, on a validator-quorum DENIED
        // dispute, and ONLY when the session carries a bond requirement with a
        // positive slash rate. Consistency failures never reach this path. A
        // missing/zero bond slashes zero — reward denial still stands; no mint,
        // no underflow. Slashed bond is burned to `Address::ZERO` (auditable),
        // matching the governance bond-burn precedent. Slashing does NOT require
        // the verifier to be Active — an Unbonding verifier's remaining bond is
        // still slashable, reducing what it can later withdraw.
        let mut slashed: u128 = 0;
        if !req.allow_claim {
            if let Some(bond_req) = session.bond_requirement {
                if bond_req.slash_bps_on_denied_dispute > 0 {
                    if let Some(mut record) = Self::v_get_verifier(view, &req.verifier)? {
                        let slash = record
                            .bond
                            .saturating_mul(bond_req.slash_bps_on_denied_dispute as u128)
                            / 10_000;
                        let slash = slash.min(record.bond); // cap at current bond
                        if slash > 0 {
                            record.bond -= slash;
                            Self::v_put_verifier(view, &record)?;
                            state.credit(&Address::ZERO, slash)?; // auditable burn
                            slashed = slash;
                        }
                    }
                }
            }
            // 800B correction: a DENIED dispute is recorded against the verifier
            // (blocks further compute milestone claims) and forfeits any
            // remaining grant-derived locked stake back to the ProtocolReserve.
            // No-ops until the supply correction is applied. Note: consistency
            // failure alone never reaches this branch — only an explicit denied
            // dispute does.
            {
                use crate::supply::SupplyStore;
                SupplyStore::record_denied_dispute(view, &req.verifier)?;
                SupplyStore::forfeit_locked_grant(
                    view,
                    &req.verifier,
                    sumchain_primitives::supply::ServiceKind::Compute,
                )?;
            }
        }
        info!(
            "InferenceSettlement ResolveDispute {} verifier={} allow_claim={} slashed={}",
            req.session_id, req.verifier, req.allow_claim, slashed
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn refund_session(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        session_id: &str,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match Self::v_get_session(view, session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        if session.status != InferenceSessionStatus::Open {
            return Ok(InferenceSettlementExecutionResult::fail(352, "session not open"));
        }
        if session.funder != *sender {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "only the funder may refund",
            ));
        }
        // Refund only once the session is closable: expired or fully claimed.
        let closable = block_height >= session.expires_at_height
            || session.claims_count >= session.max_verifiers;
        if !closable {
            return Ok(InferenceSettlementExecutionResult::fail(
                360,
                "refund not available: session not expired and not fully claimed",
            ));
        }
        // No unresolved disputes may remain (they must be resolved first).
        for d in Self::v_list_disputes(view, session_id)? {
            if d.status == InferenceDisputeStatus::Open {
                return Ok(InferenceSettlementExecutionResult::fail(
                    359,
                    "unresolved dispute blocks refund",
                ));
            }
        }
        // Defensive: refund must not bypass a still-maturing, unclaimed,
        // un-denied claim. Enumerate every verifier that attested for this
        // session and block the refund while any of them could still validly
        // claim (maturity not yet elapsed, not already claimed, not denied).
        // This guards against parameter/record edge cases where a late
        // attestation matures after `expires_at_height`.
                for verifier in InferenceAttestationExecutor::v_list_verifiers_by_session(view, session_id)? {
            let att = match InferenceAttestationExecutor::v_get(
                view,
                &inference_attestation_key(session_id, &verifier),
            )? {
                Some(a) => a,
                None => continue,
            };
            let maturity = claim_maturity_height(
                att.included_at_height,
                chain_params.finality_depth,
                session.dispute_window_blocks,
            );
            if block_height >= maturity {
                continue; // matured — the claim window has closed for this verifier
            }
            let already_claimed = Self::v_get_claim(view, session_id, &verifier)?.is_some();
            let denied = matches!(
                Self::v_get_dispute(view, session_id, &verifier)?.map(|d| d.status),
                Some(InferenceDisputeStatus::ResolvedDenyClaim)
            );
            if !already_claimed && !denied {
                return Ok(InferenceSettlementExecutionResult::fail(
                    360,
                    "refund blocked: a verifier's claim is still within its maturity window",
                ));
            }
        }

        let refund = session.remaining_escrow;
        if refund > 0 {
            state.credit(sender, refund)?;
        }
        session.remaining_escrow = 0;
        session.status = InferenceSessionStatus::Refunded;
        Self::v_put_session(view, &session)?;
        info!(
            "InferenceSettlement RefundSession {} funder={} refunded={}",
            session_id, sender, refund
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    // ── Verifier bonding (issue #78) ──────────────────────────────────────────

    /// Register (or re-register a `Withdrawn` verifier with) a bond. Locks `bond`
    /// native Koppa as accounting-in-record. Rejects an existing `Active`/`Unbonding`
    /// record (366). Gate-closed → 364 (fee already paid; the free 350 gate is the
    /// outer settlement gate).
    fn register_verifier(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        bond: u128,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if !Self::bonding_gate_open(chain_params, block_height) {
            return Ok(InferenceSettlementExecutionResult::fail(
                364,
                "inference verifier bonding not enabled at this block height",
            ));
        }
        if bond == 0 {
            return Ok(InferenceSettlementExecutionResult::fail(365, "bond must be > 0"));
        }
        // An Active/Unbonding record blocks re-registration; a Withdrawn record is
        // cleanly reinitialized.
        if let Some(existing) = Self::v_get_verifier(view, sender)? {
            if existing.status != InferenceVerifierStatus::Withdrawn {
                return Ok(InferenceSettlementExecutionResult::fail(
                    366,
                    "verifier already registered",
                ));
            }
        }
        if state.get_balance(sender)? < bond {
            return Ok(InferenceSettlementExecutionResult::fail(
                365,
                "insufficient balance for verifier bond",
            ));
        }
        state.deduct(sender, bond)?;
        Self::v_put_verifier(view, &InferenceVerifierRecord {
            verifier: *sender,
            bond,
            status: InferenceVerifierStatus::Active,
            registered_at_height: block_height,
            unbonding_started_height: None,
            unlock_height: None,
        })?;
        info!("InferenceSettlement RegisterVerifier {} bond={}", sender, bond);
        Ok(InferenceSettlementExecutionResult::ok())
    }

    /// Top up an `Active` verifier's bond.
    fn add_verifier_bond(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        amount: u128,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if !Self::bonding_gate_open(chain_params, block_height) {
            return Ok(InferenceSettlementExecutionResult::fail(
                364,
                "inference verifier bonding not enabled at this block height",
            ));
        }
        if amount == 0 {
            return Ok(InferenceSettlementExecutionResult::fail(365, "amount must be > 0"));
        }
        let mut record = match Self::v_get_verifier(view, sender)? {
            Some(r) => r,
            None => return Ok(InferenceSettlementExecutionResult::fail(367, "verifier not registered")),
        };
        if record.status != InferenceVerifierStatus::Active {
            return Ok(InferenceSettlementExecutionResult::fail(
                368,
                "verifier not active (unbonding or withdrawn)",
            ));
        }
        if state.get_balance(sender)? < amount {
            return Ok(InferenceSettlementExecutionResult::fail(
                365,
                "insufficient balance to add bond",
            ));
        }
        state.deduct(sender, amount)?;
        record.bond = record.bond.saturating_add(amount);
        Self::v_put_verifier(view, &record)?;
        Ok(InferenceSettlementExecutionResult::ok())
    }

    /// Begin the unbonding delay for an `Active` verifier. Rejects a verifier with
    /// no withdrawable bond (365) rather than creating a pointless unbonding state.
    fn begin_verifier_unbond(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if !Self::bonding_gate_open(chain_params, block_height) {
            return Ok(InferenceSettlementExecutionResult::fail(
                364,
                "inference verifier bonding not enabled at this block height",
            ));
        }
        let mut record = match Self::v_get_verifier(view, sender)? {
            Some(r) => r,
            None => return Ok(InferenceSettlementExecutionResult::fail(367, "verifier not registered")),
        };
        if record.status != InferenceVerifierStatus::Active {
            return Ok(InferenceSettlementExecutionResult::fail(
                368,
                "verifier not active (unbonding or withdrawn)",
            ));
        }
        if record.bond == 0 {
            return Ok(InferenceSettlementExecutionResult::fail(
                365,
                "no withdrawable bond to unbond",
            ));
        }
        let unlock = block_height.saturating_add(chain_params.inference_verifier_unbonding_period_blocks);
        record.status = InferenceVerifierStatus::Unbonding;
        record.unbonding_started_height = Some(block_height);
        record.unlock_height = Some(unlock);
        Self::v_put_verifier(view, &record)?;
        info!("InferenceSettlement BeginVerifierUnbond {} unlock={}", sender, unlock);
        Ok(InferenceSettlementExecutionResult::ok())
    }

    /// Withdraw a matured unbonding verifier's remaining bond (possibly reduced by
    /// slashes during unbonding). Credits the sender and marks the record
    /// `Withdrawn` with zero bond.
    fn withdraw_verifier_bond(
        &self,
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if !Self::bonding_gate_open(chain_params, block_height) {
            return Ok(InferenceSettlementExecutionResult::fail(
                364,
                "inference verifier bonding not enabled at this block height",
            ));
        }
        let mut record = match Self::v_get_verifier(view, sender)? {
            Some(r) => r,
            None => return Ok(InferenceSettlementExecutionResult::fail(367, "verifier not registered")),
        };
        if record.status != InferenceVerifierStatus::Unbonding {
            return Ok(InferenceSettlementExecutionResult::fail(
                368,
                "verifier not unbonding",
            ));
        }
        let unlock = record.unlock_height.unwrap_or(u64::MAX);
        if block_height < unlock {
            return Ok(InferenceSettlementExecutionResult::fail(
                369,
                "verifier unbonding not yet mature",
            ));
        }
        let refund = record.bond; // already reduced by any slashes during unbonding
        if refund > 0 {
            state.credit(sender, refund)?;
        }
        record.bond = 0;
        record.status = InferenceVerifierStatus::Withdrawn;
        Self::v_put_verifier(view, &record)?;
        info!("InferenceSettlement WithdrawVerifierBond {} refund={}", sender, refund);
        Ok(InferenceSettlementExecutionResult::ok())
    }

    // ── Consistency grouping (issue #77) ──────────────────────────────────────

    /// Count the verifiers in `session_id` whose **full digest tuple**
    /// `(model_hash, manifest_root, response_hash, proof_root)` exactly equals
    /// `target` and who are eligible to count toward a plurality: their
    /// attestation is **finalized** at `claim_height` (`included + finality_depth
    /// <= claim_height`) and is **not** blocked by an `Open`/`ResolvedDenyClaim`
    /// dispute. `response_hash` alone is never sufficient — all four fields must
    /// match. The claimant is naturally included when its own tuple is `target`.
    ///
    /// Reads only attestation + dispute records; never mutates attestation storage.
    /// The consistency group for `target`, as this block sees it.
    ///
    /// Execution counts through the candidate: an attestation staged earlier in
    /// the same block belongs in the group, and a dispute opened earlier in it
    /// must remove one. Counting the parent would let a block reach a verdict
    /// the state it publishes does not support.
    pub fn v_consistency_group_size(
        view: &ExecutionView<'_, '_>,
        session_id: &str,
        target: &InferenceAttestationDigest,
        claim_height: u64,
        finality_depth: u64,
    ) -> Result<u32> {
        let verifiers =
            InferenceAttestationExecutor::v_list_verifiers_by_session(view, session_id)?;
        let mut count: u32 = 0;
        for verifier in verifiers {
            let att = match InferenceAttestationExecutor::v_get(
                view,
                &inference_attestation_key(session_id, &verifier),
            )? {
                Some(a) => a,
                None => continue,
            };
            let dispute = Self::v_get_dispute(view, session_id, &verifier)?.map(|d| d.status);
            if counts_toward_group(&att, target, claim_height, finality_depth, dispute) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    /// The same count over COMMITTED state, for RPC.
    ///
    /// RPC answers about the published chain, so it reads it. Both paths share
    /// [`counts_toward_group`], which is the rule; only the source of the rows
    /// differs.
    pub fn consistency_group_size(
        &self,
        session_id: &str,
        target: &InferenceAttestationDigest,
        claim_height: u64,
        finality_depth: u64,
    ) -> Result<u32> {
        let aexec = InferenceAttestationExecutor::new(self.db.clone());
        let mut count: u32 = 0;
        for verifier in aexec.list_verifiers_by_session(session_id)? {
            let att = match aexec.get(&inference_attestation_key(session_id, &verifier))? {
                Some(a) => a,
                None => continue,
            };
            let dispute = self.get_dispute(session_id, &verifier)?.map(|d| d.status);
            if counts_toward_group(&att, target, claim_height, finality_depth, dispute) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    // ── Storage ──────────────────────────────────────────────────────────────

    pub fn get_session(&self, session_id: &str) -> Result<Option<InferenceSession>> {
        match self.db.get(cf::INFERENCE_SESSIONS, &session_key(session_id))? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    // ── Execution-path reads (candidate-scoped) ─────────────────────────────
    //
    // The `&self` readers stay for RPC, which answers about the published
    // chain. These read the candidate, because a block settles what it has just
    // recorded: an escrow drawn down by an earlier claim, a dispute opened
    // earlier in the block, an attestation from the same block. Reading the
    // parent would let one block pay the same escrow twice.

    pub fn v_get_session(
        view: &ExecutionView<'_, '_>,
        session_id: &str,
    ) -> Result<Option<InferenceSession>> {
        match view.get(cf::INFERENCE_SESSIONS, &session_key(session_id))? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_get_verifier(
        view: &ExecutionView<'_, '_>,
        verifier: &Address,
    ) -> Result<Option<InferenceVerifierRecord>> {
        match view.get(cf::INFERENCE_VERIFIERS, &verifier_key(verifier))? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_get_claim(
        view: &ExecutionView<'_, '_>,
        session_id: &str,
        verifier: &Address,
    ) -> Result<Option<InferenceClaim>> {
        match view.get(
            cf::INFERENCE_CLAIMS,
            &settlement_entry_key(session_id, verifier),
        )? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_get_dispute(
        view: &ExecutionView<'_, '_>,
        session_id: &str,
        verifier: &Address,
    ) -> Result<Option<InferenceDispute>> {
        match view.get(
            cf::INFERENCE_DISPUTES,
            &settlement_entry_key(session_id, verifier),
        )? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_list_disputes(
        view: &ExecutionView<'_, '_>,
        session_id: &str,
    ) -> Result<Vec<InferenceDispute>> {
        Self::v_list_by_prefix(view, cf::INFERENCE_DISPUTES, session_id)
    }

    fn v_list_by_prefix<T: serde::de::DeserializeOwned>(
        view: &ExecutionView<'_, '_>,
        cf_name: &str,
        session_id: &str,
    ) -> Result<Vec<T>> {
        let prefix = session_prefix(session_id);
        let mut out = Vec::new();
        let iter = match view.prefix_iter(cf_name, &prefix) {
            Ok(it) => it,
            Err(sumchain_storage::StorageError::NotFound(_)) => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        // The merged scan is fallible: a read error must end it rather than
        // return a short list a payout decision would then trust.
        for entry in iter {
            let (key, value) = entry?;
            if key.len() != 36 || key[..prefix.len()] != prefix[..] {
                continue;
            }
            out.push(
                bincode::deserialize(&value)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            );
        }
        Ok(out)
    }

    pub fn v_put_session(view: &mut ExecutionView<'_, '_>, s: &InferenceSession) -> Result<()> {
        let bytes =
            bincode::serialize(s).map_err(|e| StateError::SerializationError(e.to_string()))?;
        Ok(view.put(cf::INFERENCE_SESSIONS, &session_key(&s.session_id), &bytes)?)
    }

    /// Fetch a verifier bond record (issue #78) by verifier address.
    pub fn get_verifier(&self, verifier: &Address) -> Result<Option<InferenceVerifierRecord>> {
        match self.db.get(cf::INFERENCE_VERIFIERS, &verifier_key(verifier))? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_put_verifier(view: &mut ExecutionView<'_, '_>, r: &InferenceVerifierRecord) -> Result<()> {
        let bytes =
            bincode::serialize(r).map_err(|e| StateError::SerializationError(e.to_string()))?;
        Ok(view.put(cf::INFERENCE_VERIFIERS, &verifier_key(&r.verifier), &bytes)?)
    }

    /// Σ `remaining_escrow` across all inference sessions, with checked u128
    /// addition. This is the live native-Koppa escrow still held by open
    /// sessions: as a session pays out rewards or refunds, `remaining_escrow`
    /// drops (the funds re-enter account balances), so closed sessions
    /// contribute 0. `cf::INFERENCE_SESSIONS` is single-key-family (32-byte
    /// blake3 session keys → `InferenceSession` rows only); rows of any other
    /// length are skipped defensively. Deterministic full scan, tolerates an
    /// empty CF. One-time supply census + `chain_getSupplyInfo` only.
    pub fn total_session_remaining_escrow(&self) -> Result<u128> {
        sum_escrow(
            self.db
                .iter(cf::INFERENCE_SESSIONS)
                .map_err(StateError::Storage)?
                .map(|(k, v)| Ok((k.to_vec(), v.to_vec()))),
        )
    }

    /// Σ `remaining_escrow` as THIS BLOCK sees it.
    ///
    /// The supply census folds this into the correction's reserve delta, and a
    /// block can open, fund, claim from or refund a session before the
    /// correction runs. Reading committed state would measure an escrow the
    /// block has already changed and mint a delta that does not reconcile with
    /// what it publishes.
    pub fn v_total_session_remaining_escrow(view: &ExecutionView<'_, '_>) -> Result<u128> {
        match view.prefix_iter(cf::INFERENCE_SESSIONS, &[]) {
            Ok(it) => sum_escrow(it.map(|e| e.map_err(Into::into))),
            Err(sumchain_storage::StorageError::NotFound(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Σ `bond` across all inference-verifier records, with checked u128
    /// addition. This is the live native-Koppa verifier bond still held:
    /// withdrawing a bond or slashing it reduces `bond` (the value re-enters
    /// account balances or the burn sink), so fully-withdrawn verifiers
    /// contribute 0. `cf::INFERENCE_VERIFIERS` is single-key-family (32-byte
    /// blake3 verifier keys → `InferenceVerifierRecord` rows only); other lengths
    /// are skipped defensively. Deterministic full scan, tolerates an empty CF.
    /// One-time supply census + `chain_getSupplyInfo` only.
    pub fn total_verifier_bonds(&self) -> Result<u128> {
        sum_bonds(
            self.db
                .iter(cf::INFERENCE_VERIFIERS)
                .map_err(StateError::Storage)?
                .map(|(k, v)| Ok((k.to_vec(), v.to_vec()))),
        )
    }

    /// Σ verifier `bond` as THIS BLOCK sees it. See
    /// [`v_total_session_remaining_escrow`](Self::v_total_session_remaining_escrow):
    /// a registration, top-up, unbond or slash earlier in the block moves this,
    /// and the census has to measure what the block will publish.
    pub fn v_total_verifier_bonds(view: &ExecutionView<'_, '_>) -> Result<u128> {
        match view.prefix_iter(cf::INFERENCE_VERIFIERS, &[]) {
            Ok(it) => sum_bonds(it.map(|e| e.map_err(Into::into))),
            Err(sumchain_storage::StorageError::NotFound(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_claim(&self, session_id: &str, verifier: &Address) -> Result<Option<InferenceClaim>> {
        match self
            .db
            .get(cf::INFERENCE_CLAIMS, &settlement_entry_key(session_id, verifier))?
        {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_put_claim(view: &mut ExecutionView<'_, '_>, c: &InferenceClaim) -> Result<()> {
        let bytes =
            bincode::serialize(c).map_err(|e| StateError::SerializationError(e.to_string()))?;
        Ok(view.put(
            cf::INFERENCE_CLAIMS,
            &settlement_entry_key(&c.session_id, &c.verifier),
            &bytes,
        )?)
    }

    pub fn get_dispute(
        &self,
        session_id: &str,
        verifier: &Address,
    ) -> Result<Option<InferenceDispute>> {
        match self
            .db
            .get(cf::INFERENCE_DISPUTES, &settlement_entry_key(session_id, verifier))?
        {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_put_dispute(view: &mut ExecutionView<'_, '_>, d: &InferenceDispute) -> Result<()> {
        let bytes =
            bincode::serialize(d).map_err(|e| StateError::SerializationError(e.to_string()))?;
        Ok(view.put(
            cf::INFERENCE_DISPUTES,
            &settlement_entry_key(&d.session_id, &d.verifier),
            &bytes,
        )?)
    }

    /// All paid claims for a session (prefix scan).
    pub fn list_claims(&self, session_id: &str) -> Result<Vec<InferenceClaim>> {
        self.list_by_prefix(cf::INFERENCE_CLAIMS, session_id)
    }

    /// All disputes for a session (prefix scan).
    pub fn list_disputes(&self, session_id: &str) -> Result<Vec<InferenceDispute>> {
        self.list_by_prefix(cf::INFERENCE_DISPUTES, session_id)
    }

    fn list_by_prefix<T: serde::de::DeserializeOwned>(
        &self,
        cf_name: &str,
        session_id: &str,
    ) -> Result<Vec<T>> {
        let prefix = session_prefix(session_id);
        let mut out = Vec::new();
        let iter = match self.db.prefix_iter(cf_name, &prefix) {
            Ok(it) => it,
            Err(sumchain_storage::StorageError::NotFound(_)) => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for (key, value) in iter {
            if key.len() != 36 || key[..prefix.len()] != prefix[..] {
                continue;
            }
            out.push(
                bincode::deserialize(&value)
                    .map_err(|e| StateError::SerializationError(e.to_string()))?,
            );
        }
        Ok(out)
    }
}
