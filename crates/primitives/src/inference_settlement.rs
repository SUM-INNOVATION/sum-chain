//! OmniNode Inference Settlement (issue #61) — v1.
//!
//! Escrow-funded reward settlement **keyed by** the existing, immutable
//! [`crate::inference_attestation`] records — by `(session_id, verifier_address)`.
//! This subprotocol does **not** change attestation v1 in any way: it only reads
//! attestations and moves escrowed Koppa. It is a separate, activation-gated
//! subprotocol (`ChainParams::inference_settlement_enabled_from_height`).
//!
//! **v1 has no bond slashing** — no on-chain verifier bond exists yet. v1 supports
//! **reward denial**, **claim withholding**, **escrow refund**, and **dispute
//! records** only. Bond slashing is a v2 feature that requires a verifier-bond
//! registry. Nothing here mints Koppa: payouts are supply-conserving (deducted
//! from a funder's balance on funding, credited to verifiers on claim, or
//! refunded to the funder), mirroring the storage `fee_pool` pattern.

use serde::{Deserialize, Serialize};

use crate::Address;

// ─── Key domains ─────────────────────────────────────────────────────────────

/// Domain for the per-session record key (32-byte point lookup). Distinct from
/// the attestation key domains so the keyspaces never collide.
const SESSION_KEY_DOMAIN: &[u8] = b"InferenceSettlementSessionV1";
/// Domain for the 16-byte session prefix used by the per-(session, verifier)
/// claim and dispute CFs, so all claims/disputes for a session are prefix-scannable.
const SESSION_INDEX_DOMAIN: &[u8] = b"InferenceSettlementSessionIndexV1";

/// Bytes of the session prefix embedded in claim/dispute keys.
pub const SESSION_PREFIX_BYTES: usize = 16;

/// Per-session record key for `INFERENCE_SESSIONS`:
/// `BLAKE3(SESSION_KEY_DOMAIN || session_id)` (32 bytes, fixed regardless of
/// session_id length — bounded RocksDB point-lookup cost).
pub fn session_key(session_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_KEY_DOMAIN);
    hasher.update(session_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// 16-byte session prefix: `BLAKE3(SESSION_INDEX_DOMAIN || session_id)[..16]`.
pub fn session_prefix(session_id: &str) -> [u8; SESSION_PREFIX_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_INDEX_DOMAIN);
    hasher.update(session_id.as_bytes());
    let mut out = [0u8; SESSION_PREFIX_BYTES];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..SESSION_PREFIX_BYTES]);
    out
}

/// Per-(session, verifier) entry key for `INFERENCE_CLAIMS` and
/// `INFERENCE_DISPUTES`: `session_prefix_16 || verifier_address_20` (36 bytes).
/// Prefix-iterate with `session_prefix(session_id)` to enumerate all entries.
pub fn settlement_entry_key(session_id: &str, verifier: &Address) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..SESSION_PREFIX_BYTES].copy_from_slice(&session_prefix(session_id));
    out[SESSION_PREFIX_BYTES..].copy_from_slice(verifier.as_bytes());
    out
}

// ─── Status enums ────────────────────────────────────────────────────────────

/// Lifecycle of a settlement session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InferenceSessionStatus {
    /// Accepting claims / funding.
    Open = 0,
    /// Closed after refund (terminal).
    Refunded = 1,
}

impl InferenceSessionStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Open),
            1 => Some(Self::Refunded),
            _ => None,
        }
    }
}

/// State of a paid claim. In v1 a claim record only exists once paid; blocking is
/// tracked on the dispute record, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InferenceClaimStatus {
    /// Reward paid out to the verifier.
    Paid = 0,
}

impl InferenceClaimStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Paid),
            _ => None,
        }
    }
}

/// State of a dispute record. **No slashing** — a dispute only withholds/denies a
/// verifier's reward claim; escrow stays available for refund on deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InferenceDisputeStatus {
    /// Open — blocks the target verifier's claim until resolved.
    Open = 0,
    /// Resolved: the verifier may proceed to claim.
    ResolvedAllowClaim = 1,
    /// Resolved: the verifier's claim is denied (withheld); escrow refundable.
    ResolvedDenyClaim = 2,
}

impl InferenceDisputeStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Open),
            1 => Some(Self::ResolvedAllowClaim),
            2 => Some(Self::ResolvedDenyClaim),
            _ => None,
        }
    }
}

// ─── Request payloads ────────────────────────────────────────────────────────

/// Open (and fund with `deposit`) a settlement session. `reward_per_verifier` is
/// the fixed amount each qualifying verifier can claim; `max_verifiers` caps the
/// number of claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenInferenceSessionRequest {
    pub session_id: String,
    pub reward_per_verifier: u128,
    pub max_verifiers: u32,
    pub dispute_window_blocks: u64,
    pub expires_at_height: u64,
    pub deposit: u128,
}

/// Top up an open session's escrow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundInferenceSessionRequest {
    pub session_id: String,
    pub amount: u128,
}

/// Verifier self-claim of the fixed per-verifier reward. The signer must be the
/// verifier of an existing, matured attestation for `session_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimInferenceRewardRequest {
    pub session_id: String,
}

/// Open a dispute against a verifier's attestation (record-only). `evidence_commitment`
/// is an opaque 32-byte commitment (hash) — no plaintext evidence on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenInferenceDisputeRequest {
    pub session_id: String,
    pub verifier: Address,
    pub evidence_commitment: [u8; 32],
}

/// Resolve a dispute. Only the configured dispute resolver may submit this.
/// `allow_claim = true` lets the verifier proceed; `false` denies the claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveInferenceDisputeRequest {
    pub session_id: String,
    pub verifier: Address,
    pub allow_claim: bool,
}

/// Refund the funder's remaining escrow once the session is closable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundInferenceSessionRequest {
    pub session_id: String,
}

// ─── Operation + tx wrapper ──────────────────────────────────────────────────

/// The v1 InferenceSettlement operations. Append-only if extended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InferenceSettlementOperation {
    OpenSession(OpenInferenceSessionRequest),
    FundSession(FundInferenceSessionRequest),
    ClaimReward(ClaimInferenceRewardRequest),
    OpenDispute(OpenInferenceDisputeRequest),
    ResolveDispute(ResolveInferenceDisputeRequest),
    RefundSession(RefundInferenceSessionRequest),
}

/// Transaction data wrapper carried by `TxPayload::InferenceSettlement`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceSettlementTxData {
    pub operation: InferenceSettlementOperation,
}

// ─── Stored records ──────────────────────────────────────────────────────────

/// Per-session settlement record (`INFERENCE_SESSIONS`). Chain-internal; field
/// order frozen for stored-data forward compatibility (a change requires a CF
/// migration / key-domain rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceSession {
    pub session_id: String,
    pub funder: Address,
    pub reward_per_verifier: u128,
    pub max_verifiers: u32,
    pub remaining_escrow: u128,
    pub claims_count: u32,
    pub dispute_window_blocks: u64,
    pub status: InferenceSessionStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

/// A paid reward claim (`INFERENCE_CLAIMS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceClaim {
    pub session_id: String,
    pub verifier: Address,
    pub amount: u128,
    pub claimed_at_height: u64,
    pub status: InferenceClaimStatus,
}

/// A dispute record (`INFERENCE_DISPUTES`). Record-only; never slashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceDispute {
    pub session_id: String,
    pub verifier: Address,
    pub opener: Address,
    pub evidence_commitment: [u8; 32],
    pub status: InferenceDisputeStatus,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub allow_claim: bool,
}
