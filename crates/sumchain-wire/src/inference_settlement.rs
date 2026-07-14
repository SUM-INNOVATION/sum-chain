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

/// Domain for the per-verifier bond record key (issue #78). Distinct from the
/// session/claim/dispute domains so the keyspaces never collide.
const VERIFIER_KEY_DOMAIN: &[u8] = b"InferenceVerifierV1";

/// Per-verifier bond record key for `INFERENCE_VERIFIERS`:
/// `BLAKE3(VERIFIER_KEY_DOMAIN || verifier_address)` (32 bytes).
pub fn verifier_key(verifier: &Address) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(VERIFIER_KEY_DOMAIN);
    hasher.update(verifier.as_bytes());
    *hasher.finalize().as_bytes()
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

/// Lifecycle of a verifier bond record (issue #78). Mirrors the archive-node
/// unbonding lifecycle: bonds are locked while `Active`, enter a delay on
/// `Unbonding`, and are returned (minus any slashes) at `Withdrawn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum InferenceVerifierStatus {
    /// Bond locked and usable to satisfy a session's bond requirement.
    Active = 0,
    /// Unbonding delay running; still slashable, not usable for new claims.
    Unbonding = 1,
    /// Bond withdrawn; zero bond. May re-register with a fresh bond.
    Withdrawn = 2,
}

impl InferenceVerifierStatus {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Active),
            1 => Some(Self::Unbonding),
            2 => Some(Self::Withdrawn),
            _ => None,
        }
    }
}

// ─── Consistency / plurality mode (issue #77) ────────────────────────────────

/// Optional consistency/plurality reward rule for a session (issue #77, v1.1).
///
/// When present, a `ClaimReward` qualifies only if the claimant's **full
/// attestation digest tuple** `(model_hash, manifest_root, response_hash,
/// proof_root)` is shared by a large enough group of other verifiers who
/// attested the same `session_id`. This is **deterministic agreement over the
/// on-chain commitments** — it is NOT a claim about the semantic correctness of
/// the AI output and involves NO zkML / on-chain re-execution.
///
/// Absent (`InferenceSession::consistency == None`) → v1 single-attestation claim
/// behavior is unchanged. Gated behind
/// `ChainParams::inference_settlement_consistency_enabled_from_height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceConsistencyConfig {
    /// Absolute minimum number of finalized, undisputed verifiers (the claimant
    /// included) whose full digest tuple matches, for a claim to qualify. `>= 1`,
    /// and `<= max_verifiers`. Primary, always-active constraint.
    pub min_matching_verifiers: u32,
    /// Optional proportional constraint, in basis points of the **fixed,
    /// funder-declared `max_verifiers`** (never the live attestation count, which
    /// would be gameable). `0` disables it. When `> 0`, the matching group must
    /// also satisfy `matching_count * 10_000 >= max_verifiers * threshold_bps`.
    /// Must be `<= 10_000`.
    pub threshold_bps: u16,
}

// ─── Verifier bonding / slashing (issue #78) ─────────────────────────────────

/// Optional per-session verifier-bond requirement (issue #78). When present, a
/// verifier must hold an `Active` bond record of at least `min_bond` to claim,
/// and an upheld (denied) dispute may slash `slash_bps_on_denied_dispute` of the
/// target's bond. Absent → v1/#77 behavior: no bond required, no slashing.
///
/// **consistency decides eligibility; dispute resolution decides punishment** —
/// slashing is only ever triggered by a validator-quorum denied dispute, never
/// by a consistency-plurality failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceVerifierBondRequirement {
    /// Minimum `Active` bond a verifier must hold to claim this session. `> 0`.
    pub min_bond: u128,
    /// Basis points of the target's current bond slashed on a denied dispute.
    /// `0` disables slashing (denial still withholds the reward). `<= 10_000`.
    pub slash_bps_on_denied_dispute: u16,
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
    /// Optional consistency/plurality rule (issue #77). Appended field; `None`
    /// (the `serde` default for absent input) preserves v1 claim behavior.
    /// Requesting it while the consistency gate is closed fails `Failed(361)`.
    #[serde(default)]
    pub consistency: Option<InferenceConsistencyConfig>,
    /// Optional verifier-bond requirement (issue #78). Appended field; `None`
    /// preserves v1/#77 behavior (no bond, no slashing). Requesting it while the
    /// bonding gate is closed fails `Failed(364)`.
    #[serde(default)]
    pub bond_requirement: Option<InferenceVerifierBondRequirement>,
}

/// Register a verifier bond (issue #78). Sender = verifier. Locks `bond` native
/// Koppa as accounting-in-record. Re-registering a `Withdrawn` record reinitializes
/// it; an `Active`/`Unbonding` record is rejected `Failed(366)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterVerifierRequest {
    pub bond: u128,
}

/// Top up an existing `Active` verifier bond (issue #78). Sender = verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddVerifierBondRequest {
    pub amount: u128,
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

/// Resolve a dispute. Authorized by a **validator quorum** —
/// `approvals` must reach `ChainParams.inference_settlement_dispute_threshold_bps`
/// of the active PoA validator set. `tx.from` is only the fee payer.
/// `allow_claim = true` lets the verifier proceed; `false` denies the claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveInferenceDisputeRequest {
    pub session_id: String,
    pub verifier: Address,
    pub allow_claim: bool,
    /// Validator approvals over [`crate::validator_authority::resolve_dispute_signing_bytes`].
    #[serde(default)]
    pub approvals: Vec<crate::validator_authority::ValidatorApproval>,
}

/// Refund the funder's remaining escrow once the session is closable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundInferenceSessionRequest {
    pub session_id: String,
}

// ─── Operation + tx wrapper ──────────────────────────────────────────────────

/// The InferenceSettlement operations. **Append-only** — new variants are added
/// at the end so existing bincode variant indices never shift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InferenceSettlementOperation {
    OpenSession(OpenInferenceSessionRequest),
    FundSession(FundInferenceSessionRequest),
    ClaimReward(ClaimInferenceRewardRequest),
    OpenDispute(OpenInferenceDisputeRequest),
    ResolveDispute(ResolveInferenceDisputeRequest),
    RefundSession(RefundInferenceSessionRequest),
    // ── Verifier bonding (issue #78), appended ──
    RegisterVerifier(RegisterVerifierRequest),
    AddVerifierBond(AddVerifierBondRequest),
    BeginVerifierUnbond,
    WithdrawVerifierBond,
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
    /// Optional consistency/plurality rule (issue #77), fixed at open time.
    /// **Appended** field — safe because settlement is dormant (activation gate
    /// unreached on every live chain, so there are no persisted `InferenceSession`
    /// records to break). `#[serde(default)]` decodes any pre-#77 record as `None`
    /// = v1 behavior. New records always carry an explicit value.
    #[serde(default)]
    pub consistency: Option<InferenceConsistencyConfig>,
    /// Optional verifier-bond requirement (issue #78), fixed at open time.
    /// **Appended** field — same dormant-safety rationale as `consistency`.
    /// `None` = no bond required, no slashing.
    #[serde(default)]
    pub bond_requirement: Option<InferenceVerifierBondRequirement>,
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

/// A dispute record (`INFERENCE_DISPUTES`). Record-only; the dispute itself never
/// slashes — slashing (issue #78) happens at `ResolveDispute(deny)` time when the
/// session carries a bond requirement, and reduces the verifier's bond record.
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

/// Per-verifier bond record (`INFERENCE_VERIFIERS`, issue #78). Keyed by
/// [`verifier_key`]. Bond is accounting-in-record (native Koppa debited on
/// register/add, credited back on withdraw); a denied dispute slashes it to
/// `Address::ZERO`. No minting; supply is conserved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceVerifierRecord {
    pub verifier: Address,
    /// Currently locked bond (withdrawable amount while `Unbonding`).
    pub bond: u128,
    pub status: InferenceVerifierStatus,
    pub registered_at_height: u64,
    /// Set when `BeginVerifierUnbond` runs; `None` while `Active`.
    pub unbonding_started_height: Option<u64>,
    /// `unbonding_started_height + inference_verifier_unbonding_period_blocks`.
    pub unlock_height: Option<u64>,
}
