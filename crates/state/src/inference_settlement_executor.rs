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
use sumchain_primitives::inference_settlement::{
    session_key, session_prefix, settlement_entry_key, InferenceClaim, InferenceClaimStatus,
    InferenceDispute, InferenceDisputeStatus, InferenceSession, InferenceSessionStatus,
    InferenceSettlementOperation, OpenInferenceDisputeRequest, OpenInferenceSessionRequest,
    ResolveInferenceDisputeRequest,
};
use sumchain_primitives::{Address, Balance};
use sumchain_storage::db::cf;
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

pub struct InferenceSettlementExecutor {
    db: Arc<Database>,
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
    pub fn execute(
        &self,
        sender: &Address,
        operation: &InferenceSettlementOperation,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        self.deduct_fee(state, sender, fee, proposer)?;

        match operation {
            InferenceSettlementOperation::OpenSession(req) => {
                self.open_session(sender, req, state, block_height, chain_params)
            }
            InferenceSettlementOperation::FundSession(req) => {
                self.fund_session(sender, &req.session_id, req.amount, state)
            }
            InferenceSettlementOperation::ClaimReward(req) => {
                self.claim_reward(sender, &req.session_id, state, block_height, chain_params)
            }
            InferenceSettlementOperation::OpenDispute(req) => {
                self.open_dispute(sender, req, block_height, chain_params)
            }
            InferenceSettlementOperation::ResolveDispute(req) => {
                self.resolve_dispute(sender, req, block_height, chain_params)
            }
            InferenceSettlementOperation::RefundSession(req) => {
                self.refund_session(sender, &req.session_id, state, block_height, chain_params)
            }
        }
    }

    // ── Operations ───────────────────────────────────────────────────────────

    fn open_session(
        &self,
        sender: &Address,
        req: &OpenInferenceSessionRequest,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        if self.get_session(&req.session_id)?.is_some() {
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
        };
        self.put_session(&session)?;
        info!(
            "InferenceSettlement OpenSession {} funder={} deposit={}",
            req.session_id, sender, req.deposit
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn fund_session(
        &self,
        sender: &Address,
        session_id: &str,
        amount: u128,
        state: &StateManager,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match self.get_session(session_id)? {
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
        self.put_session(&session)?;
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn claim_reward(
        &self,
        sender: &Address,
        session_id: &str,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match self.get_session(session_id)? {
            Some(s) => s,
            None => return Ok(InferenceSettlementExecutionResult::fail(352, "session not found")),
        };
        if session.status != InferenceSessionStatus::Open {
            return Ok(InferenceSettlementExecutionResult::fail(352, "session not open"));
        }
        // The signer must be the verifier of an existing attestation for this session.
        let att_key = inference_attestation_key(session_id, sender);
        let att = match InferenceAttestationExecutor::new(self.db.clone()).get(&att_key)? {
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
        if let Some(d) = self.get_dispute(session_id, sender)? {
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
        if self.get_claim(session_id, sender)?.is_some() {
            return Ok(InferenceSettlementExecutionResult::fail(358, "reward already claimed"));
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
        session.remaining_escrow -= session.reward_per_verifier;
        session.claims_count += 1;
        self.put_session(&session)?;
        self.put_claim(&InferenceClaim {
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
        sender: &Address,
        req: &OpenInferenceDisputeRequest,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        // Disputes require a configured neutral resolver — otherwise a dispute
        // could block a claim with no path to resolution.
        if chain_params.inference_settlement_dispute_resolver.is_none() {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "disputes disabled: no dispute resolver configured",
            ));
        }
        let session = match self.get_session(&req.session_id)? {
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
        let att = match InferenceAttestationExecutor::new(self.db.clone()).get(&att_key)? {
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
        if self.get_dispute(&req.session_id, &req.verifier)?.is_some() {
            return Ok(InferenceSettlementExecutionResult::fail(358, "dispute already exists"));
        }
        self.put_dispute(&InferenceDispute {
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

    fn resolve_dispute(
        &self,
        sender: &Address,
        req: &ResolveInferenceDisputeRequest,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        let resolver = match chain_params.inference_settlement_dispute_resolver {
            Some(r) => r,
            None => {
                return Ok(InferenceSettlementExecutionResult::fail(
                    353,
                    "disputes disabled: no dispute resolver configured",
                ));
            }
        };
        if *sender != resolver {
            return Ok(InferenceSettlementExecutionResult::fail(
                353,
                "only the configured dispute resolver may resolve",
            ));
        }
        if self.get_session(&req.session_id)?.is_none() {
            return Ok(InferenceSettlementExecutionResult::fail(352, "session not found"));
        }
        let mut dispute = match self.get_dispute(&req.session_id, &req.verifier)? {
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
        self.put_dispute(&dispute)?;
        info!(
            "InferenceSettlement ResolveDispute {} verifier={} allow_claim={}",
            req.session_id, req.verifier, req.allow_claim
        );
        Ok(InferenceSettlementExecutionResult::ok())
    }

    fn refund_session(
        &self,
        sender: &Address,
        session_id: &str,
        state: &StateManager,
        block_height: u64,
        chain_params: &ChainParams,
    ) -> Result<InferenceSettlementExecutionResult> {
        let mut session = match self.get_session(session_id)? {
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
        for d in self.list_disputes(session_id)? {
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
        let aexec = InferenceAttestationExecutor::new(self.db.clone());
        for verifier in aexec.list_verifiers_by_session(session_id)? {
            let att = match aexec
                .get(&inference_attestation_key(session_id, &verifier))?
            {
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
            let already_claimed = self.get_claim(session_id, &verifier)?.is_some();
            let denied = matches!(
                self.get_dispute(session_id, &verifier)?.map(|d| d.status),
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
        self.put_session(&session)?;
        info!(
            "InferenceSettlement RefundSession {} funder={} refunded={}",
            session_id, sender, refund
        );
        Ok(InferenceSettlementExecutionResult::ok())
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

    fn put_session(&self, s: &InferenceSession) -> Result<()> {
        let bytes =
            bincode::serialize(s).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db.put(cf::INFERENCE_SESSIONS, &session_key(&s.session_id), &bytes)?;
        Ok(())
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

    fn put_claim(&self, c: &InferenceClaim) -> Result<()> {
        let bytes =
            bincode::serialize(c).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db
            .put(cf::INFERENCE_CLAIMS, &settlement_entry_key(&c.session_id, &c.verifier), &bytes)?;
        Ok(())
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

    fn put_dispute(&self, d: &InferenceDispute) -> Result<()> {
        let bytes =
            bincode::serialize(d).map_err(|e| StateError::SerializationError(e.to_string()))?;
        self.db
            .put(cf::INFERENCE_DISPUTES, &settlement_entry_key(&d.session_id, &d.verifier), &bytes)?;
        Ok(())
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
