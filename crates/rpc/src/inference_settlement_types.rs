//! RPC DTOs for OmniNode Inference Settlement (issue #61).
//!
//! Read views + unsigned-transaction builder requests/response. Builders take no
//! private keys — they return a bincode-encoded unsigned `TransactionV2` (hex)
//! plus the signing hash for the client to sign and broadcast.

use serde::{Deserialize, Serialize};

// ── Read DTOs ────────────────────────────────────────────────────────────────

/// Consistency/plurality rule attached to a session (issue #77). Present only
/// when the session opted in at open time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConsistencyInfo {
    /// Minimum matching (finalized, undisputed) verifiers, claimant included.
    pub min_matching_verifiers: u32,
    /// Basis points of the fixed `max_verifiers`; `0` = no percentage threshold.
    pub threshold_bps: u16,
}

/// Per-session settlement state (`omninode_getInferenceSession`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceSessionInfo {
    pub session_id: String,
    /// Funder address (base58).
    pub funder: String,
    pub reward_per_verifier: u128,
    pub max_verifiers: u32,
    pub remaining_escrow: u128,
    pub claims_count: u32,
    pub dispute_window_blocks: u64,
    /// `"Open"` | `"Refunded"`.
    pub status: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    /// Consistency/plurality rule (issue #77), or `null` for a v1 session.
    #[serde(default)]
    pub consistency: Option<InferenceConsistencyInfo>,
}

/// One full-digest-tuple group within a session (`omninode_getInferenceConsistency`).
/// Attestations are grouped by the complete tuple `(model_hash, manifest_root,
/// response_hash, proof_root)` — never `response_hash` alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConsistencyGroupInfo {
    /// `0x` + 64 hex — the four commitments that define the group.
    pub model_hash: String,
    pub manifest_root: String,
    pub response_hash: String,
    pub proof_root: String,
    /// All verifiers (base58) whose attestation carries this exact tuple.
    pub verifiers: Vec<String>,
    /// Total attesters in this group (== `verifiers.len()`).
    pub verifier_count: u32,
    /// Subset that is finalized at the current height (`included + finality_depth
    /// <= height`) and not blocked by an open/denied dispute — i.e. the count
    /// that would currently satisfy a consistency claim for this tuple.
    pub eligible_count: u32,
}

/// Consistency landscape for a session (`omninode_getInferenceConsistency`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConsistencyReport {
    pub session_id: String,
    /// The session's configured rule, or `null` if it did not opt in.
    pub consistency: Option<InferenceConsistencyInfo>,
    pub max_verifiers: u32,
    /// Groups, sorted by `eligible_count` then `verifier_count` (descending).
    pub groups: Vec<InferenceConsistencyGroupInfo>,
}

/// A paid reward claim (`omninode_getInferenceClaims`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceClaimInfo {
    pub session_id: String,
    pub verifier: String,
    pub amount: u128,
    pub claimed_at_height: u64,
    /// `"Paid"`.
    pub status: String,
}

/// A dispute record (`omninode_getInferenceDisputes`). Record-only; never slashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceDisputeInfo {
    pub session_id: String,
    pub verifier: String,
    pub opener: String,
    /// `0x` + 64 hex chars of the opaque evidence commitment.
    pub evidence_commitment: String,
    /// `"Open"` | `"ResolvedAllowClaim"` | `"ResolvedDenyClaim"`.
    pub status: String,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub allow_claim: bool,
}

/// Whether a verifier can currently claim (`omninode_getClaimableReward`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimableRewardInfo {
    pub session_id: String,
    pub verifier: String,
    pub eligible: bool,
    /// Reward amount if eligible.
    pub amount: Option<u128>,
    /// Height at/after which the claim matures (finality + dispute window).
    pub unlock_height: Option<u64>,
    /// Human-readable reason (e.g. "no attestation", "not mature", "already
    /// claimed", "blocked by dispute", "insufficient consistency", "eligible").
    pub reason: String,
    /// Consistency evaluation (issue #77) — present only when the session opted
    /// into a consistency rule. `null` for a v1 session.
    #[serde(default)]
    pub consistency: Option<ClaimConsistencyEval>,
}

/// Consistency evaluation for a specific claimant (issue #77).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimConsistencyEval {
    pub required_min: u32,
    /// `0` = no percentage threshold.
    pub threshold_bps: u16,
    /// Fixed denominator for the bps rule.
    pub max_verifiers: u32,
    /// Size of the claimant's exact-tuple group (finalized, undisputed).
    pub matching_count: u32,
    /// Whether `matching_count` satisfies both active constraints.
    pub satisfied: bool,
}

// ── Builder requests ─────────────────────────────────────────────────────────

/// Optional consistency/plurality config on the open-session builder (issue #77).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInferenceConsistency {
    pub min_matching_verifiers: u32,
    /// Basis points of `max_verifiers`; omit or `0` to disable the % threshold.
    #[serde(default)]
    pub threshold_bps: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildOpenSessionRequest {
    pub from: String,
    pub session_id: String,
    pub reward_per_verifier: u128,
    pub max_verifiers: u32,
    pub dispute_window_blocks: u64,
    pub expires_at_height: u64,
    pub deposit: u128,
    pub fee: Option<u128>,
    /// Optional consistency/plurality rule (issue #77). Omit for a v1 session.
    #[serde(default)]
    pub consistency: Option<BuildInferenceConsistency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildFundSessionRequest {
    pub from: String,
    pub session_id: String,
    pub amount: u128,
    pub fee: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildClaimRewardRequest {
    pub from: String,
    pub session_id: String,
    pub fee: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildOpenDisputeRequest {
    pub from: String,
    pub session_id: String,
    /// Disputed verifier (base58).
    pub verifier: String,
    /// `0x` + 64 hex chars of the evidence commitment.
    pub evidence_commitment: String,
    pub fee: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildResolveDisputeRequest {
    pub from: String,
    pub session_id: String,
    pub verifier: String,
    pub allow_claim: bool,
    pub fee: Option<u128>,
    /// Validator approvals reaching the configured dispute threshold (collected
    /// off-chain over the resolve-dispute signing bytes). Required for the tx to
    /// pass authority.
    #[serde(default)]
    pub approvals: Vec<crate::types::ValidatorApprovalInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniBuildRefundSessionRequest {
    pub from: String,
    pub session_id: String,
    pub fee: Option<u128>,
}

// ── Builder response ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniSettlementBuildResponse {
    /// Bincode-encoded unsigned `TransactionV2` (hex, `0x`-prefixed).
    pub unsigned_tx: String,
    /// Hash the client signs (hex, `0x`-prefixed).
    pub signing_hash: String,
    pub from: String,
    pub nonce: u64,
    pub fee: u128,
    pub chain_id: u64,
}
