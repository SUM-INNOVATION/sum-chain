//! RPC DTOs for OmniNode Inference Settlement (issue #61).
//!
//! Read views + unsigned-transaction builder requests/response. Builders take no
//! private keys — they return a bincode-encoded unsigned `TransactionV2` (hex)
//! plus the signing hash for the client to sign and broadcast.

use serde::{Deserialize, Serialize};

// ── Read DTOs ────────────────────────────────────────────────────────────────

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
    /// claimed", "blocked by dispute", "eligible").
    pub reason: String,
}

// ── Builder requests ─────────────────────────────────────────────────────────

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
