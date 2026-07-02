//! Governance v1 RPC DTOs (issue #50, Phase 4).
//!
//! Builder requests/response follow the unsigned-tx pattern (no private keys):
//! the client supplies `from` + params, the server fills `chain_id`/`nonce` and
//! returns unsigned tx bytes + a signing hash. Read DTOs expose only governance
//! data — SRC-20 token ids, addresses, weights, statuses, external refs.

use serde::{Deserialize, Serialize};

use sumchain_primitives::governance::{
    ExecutionKind, GovAsset, GovAssetKind, GovProposal, GovProposalClass, GovVote, VoteChoice,
};

// ── Builder requests ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovBuildCreateProposalRequest {
    pub from: String,
    /// SRC-20 governance token id (hex).
    pub token_id: String,
    /// Proposal class (enum name, e.g. "RoutineProcess").
    pub class: String,
    /// Execution kind ("RecordOnly" or "OnChain").
    pub execution_kind: String,
    pub external_ref_url: String,
    /// Content hash binding the referenced artifact (hex).
    pub external_ref_content_hash: String,
    pub fee: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovBuildCastVoteRequest {
    pub from: String,
    pub proposal_id: String,
    /// "Yes" | "No" | "Abstain".
    pub choice: String,
    pub fee: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovBuildExecuteProposalRequest {
    pub from: String,
    pub proposal_id: String,
    pub fee: Option<u128>,
}

// ── Builder response ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovBuildResponse {
    /// Bincode-encoded unsigned `TransactionV2` (hex).
    pub unsigned_tx: String,
    /// Hash the client signs (hex).
    pub signing_hash: String,
    pub from: String,
    pub nonce: u64,
    pub fee: u128,
    pub chain_id: u64,
    /// Derived proposal id, when known at build time. `None` in v1 (the id
    /// depends on the execution block height); discover via `gov_listProposals`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
}

// ── Read DTOs ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovProposalInfo {
    pub proposal_id: String,
    pub proposer: String,
    pub class: String,
    pub execution_kind: String,
    pub external_ref_url: String,
    pub external_ref_content_hash: String,
    pub asset_token_id: String,
    pub voting_start_height: u64,
    pub status: String,
    pub created_at: u64,
    pub created_at_height: u64,
    pub expires_at: u64,
}

impl From<&GovProposal> for GovProposalInfo {
    fn from(p: &GovProposal) -> Self {
        let GovAssetKind::Src20Token(token_id) = p.asset;
        Self {
            proposal_id: format!("0x{}", hex::encode(p.id)),
            proposer: p.proposer.to_base58(),
            class: format!("{:?}", p.class),
            execution_kind: format!("{:?}", p.execution_kind),
            external_ref_url: p.external_ref.url.clone(),
            external_ref_content_hash: format!("0x{}", hex::encode(p.external_ref.content_hash)),
            asset_token_id: format!("0x{}", hex::encode(token_id)),
            voting_start_height: p.voting_start_height,
            status: format!("{:?}", p.status),
            created_at: p.created_at,
            created_at_height: p.created_at_height,
            expires_at: p.expires_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovAssetInfo {
    pub token_id: String,
    pub create_threshold: String,
    pub weight_rule: String,
    pub status: String,
    pub effective_height: u64,
}

impl From<&GovAsset> for GovAssetInfo {
    fn from(a: &GovAsset) -> Self {
        let GovAssetKind::Src20Token(token_id) = a.asset;
        Self {
            token_id: format!("0x{}", hex::encode(token_id)),
            create_threshold: a.create_threshold.to_string(),
            weight_rule: format!("{:?}", a.vote_weight_rule),
            status: format!("{:?}", a.status),
            effective_height: a.effective_height,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovVoteInfo {
    pub proposal_id: String,
    pub voter: String,
    pub weight: String,
    pub choice: String,
    pub cast_at_height: u64,
}

impl From<&GovVote> for GovVoteInfo {
    fn from(v: &GovVote) -> Self {
        Self {
            proposal_id: format!("0x{}", hex::encode(v.proposal_id)),
            voter: v.voter.to_base58(),
            weight: v.weight.to_string(),
            choice: format!("{:?}", v.choice),
            cast_at_height: v.cast_at_height,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovTallyInfo {
    pub proposal_id: String,
    pub snapshot_total: String,
    pub yes: String,
    pub no: String,
    pub abstain: String,
    pub participation: String,
    /// `None` when `chain_params.governance` is absent (params unknown).
    pub quorum_met: Option<bool>,
    pub passed: Option<bool>,
    /// Tally status derived from votes/snapshot (+ params when present).
    pub projected_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovVotingPowerInfo {
    pub proposal_id: String,
    pub holder: String,
    /// Frozen snapshot voting weight for this proposal (never live balance).
    pub weight: String,
}

// ── String → enum parsers for builder inputs ─────────────────────────────────

pub fn parse_gov_class(s: &str) -> Option<GovProposalClass> {
    use GovProposalClass::*;
    Some(match s {
        "RoutineProcess" => RoutineProcess,
        "PublicRpcSurface" => PublicRpcSurface,
        "TokenEconomic" => TokenEconomic,
        "GenesisConfigValidator" => GenesisConfigValidator,
        "ActivationHeight" => ActivationHeight,
        "ConsensusWireStorageMigration" => ConsensusWireStorageMigration,
        "PackagePublishing" => PackagePublishing,
        "EmergencySecurity" => EmergencySecurity,
        "TreasurySpend" => TreasurySpend,
        _ => return None,
    })
}

pub fn parse_execution_kind(s: &str) -> Option<ExecutionKind> {
    match s {
        "RecordOnly" => Some(ExecutionKind::RecordOnly),
        "OnChain" => Some(ExecutionKind::OnChain),
        _ => None,
    }
}

pub fn parse_vote_choice(s: &str) -> Option<VoteChoice> {
    match s {
        "Yes" => Some(VoteChoice::Yes),
        "No" => Some(VoteChoice::No),
        "Abstain" => Some(VoteChoice::Abstain),
        _ => None,
    }
}
