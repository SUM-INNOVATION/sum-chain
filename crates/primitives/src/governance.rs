//! SRC governance v1 — on-chain token-holder governance (Phase 1: wire/gate
//! scaffolding only).
//!
//! Phase 1 introduces only the transaction wire type and the activation gate.
//! The governance asset registry, snapshot voting, proposal lifecycle, and RPC
//! are implemented in later phases (issue #50). Governance is dormant by
//! default behind `ChainParams::governance_enabled_from_height` and is enabled
//! only by a coordinated validator upgrade.
//!
//! Design source: `docs/specs/GOVERNANCE-V1.md`.

use serde::{Deserialize, Serialize};

use crate::Address;

/// SRC governance operation codes (v1).
///
/// Phase 1 defines the operation surface for wire stability; the executor does
/// not yet dispatch any of these (governance is gated dormant). Discriminants
/// are stable and append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum GovernanceOperation {
    /// Register / enable a governance-eligible asset (council-gated).
    RegisterAsset = 0,
    /// Create a proposal.
    CreateProposal = 1,
    /// Cast a vote on a proposal.
    CastVote = 2,
    /// Execute a passed proposal (record-only in v1, or council treasury path).
    ExecuteProposal = 3,
    /// Cancel a pending proposal.
    CancelProposal = 4,
}

impl GovernanceOperation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(GovernanceOperation::RegisterAsset),
            1 => Some(GovernanceOperation::CreateProposal),
            2 => Some(GovernanceOperation::CastVote),
            3 => Some(GovernanceOperation::ExecuteProposal),
            4 => Some(GovernanceOperation::CancelProposal),
            _ => None,
        }
    }
}

/// Transaction data for `TxPayload::Governance` (SRC governance v1).
///
/// Phase 1 carries the operation code plus an opaque, operation-specific
/// `data` payload (decoded by the executor in a later phase). The shape mirrors
/// other domain `*TxData` structs for consistency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceTxData {
    pub operation: GovernanceOperation,
    pub data: Vec<u8>,
}

// =============================================================================
// v1 data model (Phase 2 — passive data types only; no executor/lifecycle).
// See docs/specs/GOVERNANCE-V1.md.
// =============================================================================

/// Opaque proposal identifier.
pub type GovProposalId = [u8; 32];
/// SRC-20 token identifier (as `[u8; 32]`; avoids a primitives→token crate cycle).
pub type TokenId = [u8; 32];
/// Block height alias for governance records.
pub type GovBlockHeight = u64;
/// Timestamp alias for governance records.
pub type GovTimestamp = u64;

/// Governance-eligible asset kind. v1 supports a single allowlisted SRC-20
/// governance token; `StakedKoppa` and other classes are reserved for a future,
/// separately-approved revision (not constructed or accepted in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GovAssetKind {
    /// An allowlisted SRC-20 governance token.
    Src20Token(TokenId),
}

/// How a holder's balance maps to voting weight. v1 is linear
/// (`weight = snapshot balance`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeightRule {
    /// weight = snapshot balance.
    Linear,
}

/// Registry status of a governance asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovAssetStatus {
    Enabled,
    Disabled,
}

/// A governance-eligible asset entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovAsset {
    pub asset: GovAssetKind,
    /// Minimum snapshot voting power required to CREATE a proposal.
    pub create_threshold: u128,
    pub vote_weight_rule: WeightRule,
    pub status: GovAssetStatus,
    /// Height from which this eligibility takes effect.
    pub effective_height: GovBlockHeight,
}

/// Proposal classification (drives the execution model). See spec §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum GovProposalClass {
    RoutineProcess = 0,
    PublicRpcSurface = 1,
    TokenEconomic = 2,
    GenesisConfigValidator = 3,
    ActivationHeight = 4,
    ConsensusWireStorageMigration = 5,
    PackagePublishing = 6,
    EmergencySecurity = 7,
    TreasurySpend = 8,
}

impl GovProposalClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::RoutineProcess),
            1 => Some(Self::PublicRpcSurface),
            2 => Some(Self::TokenEconomic),
            3 => Some(Self::GenesisConfigValidator),
            4 => Some(Self::ActivationHeight),
            5 => Some(Self::ConsensusWireStorageMigration),
            6 => Some(Self::PackagePublishing),
            7 => Some(Self::EmergencySecurity),
            8 => Some(Self::TreasurySpend),
            _ => None,
        }
    }
}

/// How an approved proposal is carried out. v1 is RecordOnly-only; `OnChain` is
/// named for the treasury path but is not executed in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionKind {
    /// Approval is an authoritative record; execution happens off-chain.
    RecordOnly,
    /// On-chain execution (treasury via council). Not executed in v1.
    OnChain,
}

/// Proposal lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum GovProposalStatus {
    Created = 0,
    Voting = 1,
    Passed = 2,
    Rejected = 3,
    QuorumNotMet = 4,
    Executed = 5,
    Recorded = 6,
    Expired = 7,
    Cancelled = 8,
}

impl GovProposalStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Created),
            1 => Some(Self::Voting),
            2 => Some(Self::Passed),
            3 => Some(Self::Rejected),
            4 => Some(Self::QuorumNotMet),
            5 => Some(Self::Executed),
            6 => Some(Self::Recorded),
            7 => Some(Self::Expired),
            8 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Lifecycle of a proposal's deposit bond (issue #50, P6a). The bond is
/// escrowed to the canonical governance escrow address at creation, then either
/// returned to the proposer or burned (credited to `Address::ZERO`) when the
/// proposal reaches a terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondState {
    /// Held in escrow while the proposal is live.
    Escrowed,
    /// Returned to the proposer (good-faith terminal state / proposer cancel).
    Returned,
    /// Burned to `Address::ZERO` (spam / quorum failure / council cancel).
    Burned,
}

/// Reference to the off-chain artifact a proposal authorizes (GitHub PR /
/// release / doc): a URL plus a content hash binding the referenced content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRef {
    pub url: String,
    pub content_hash: [u8; 32],
}

/// A governance proposal record (passive data in Phase 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovProposal {
    pub id: GovProposalId,
    pub proposer: Address,
    pub class: GovProposalClass,
    pub execution_kind: ExecutionKind,
    pub external_ref: ExternalRef,
    /// The governance asset whose snapshot decides this proposal.
    pub asset: GovAssetKind,
    /// Voting-start height. v1: equals `created_at_height` (snapshot at creation).
    pub voting_start_height: GovBlockHeight,
    pub status: GovProposalStatus,
    pub created_at: GovTimestamp,
    pub created_at_height: GovBlockHeight,
    pub expires_at: GovTimestamp,
    /// Deposit bond escrowed at creation (`0` when bonds are disabled).
    pub bond: u128,
    /// Escrow lifecycle of the bond.
    pub bond_state: BondState,
    /// Beneficiary for a `TreasurySpend` + `OnChain` payout (P6b). `None` for
    /// every other class / `RecordOnly` proposal.
    pub treasury_beneficiary: Option<Address>,
    /// Native-Koppa amount for a `TreasurySpend` + `OnChain` payout (P6b).
    pub treasury_amount: Option<u128>,
}

/// A cast vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteChoice {
    Yes = 0,
    No = 1,
    Abstain = 2,
}

impl VoteChoice {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Yes),
            1 => Some(Self::No),
            2 => Some(Self::Abstain),
            _ => None,
        }
    }
}

/// A vote record. One vote per (proposal, voter); the store key enforces this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovVote {
    pub proposal_id: GovProposalId,
    pub voter: Address,
    /// Frozen snapshot weight applied to this vote.
    pub weight: u128,
    pub choice: VoteChoice,
    pub cast_at_height: GovBlockHeight,
}

// =============================================================================
// Network governance parameters (chain-configured; dormant by default).
// =============================================================================

/// Network-level governance configuration. Held on `ChainParams` as
/// `governance: Option<GovernanceParams>` (default `None` = not configured).
/// Per-asset proposal thresholds live on `GovAsset::create_threshold`; these are
/// the network-wide tally/authorization parameters. No mainnet defaults exist —
/// values are set only for a coordinated activation or in tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Authority allowed to register/enable governance assets (`RegisterAsset`
    /// requires `tx.from == council`). Single configured address in v1.
    pub council: Address,
    /// Quorum, in basis points of total snapshot voting power.
    pub quorum_bps: u16,
    /// Pass threshold, in basis points of (yes + no) weight.
    pub pass_threshold_bps: u16,
    /// Voting window length in blocks (from `voting_start_height`).
    pub voting_period_blocks: u64,
    /// Maximum holders a proposal snapshot may capture; creation fails cleanly
    /// if a governance token's holder set exceeds this bound.
    pub max_snapshot_holders: u32,
    /// Deposit bond (native Koppa) escrowed when a proposal is created,
    /// returned on good-faith terminal states and burned on spam / quorum
    /// failure / council cancel. `0` (default) disables bonds. No mainnet
    /// default exists — set only for a coordinated activation or in tests.
    #[serde(default)]
    pub proposal_bond: u128,
    /// Dedicated governance treasury address (P6b). A passed `TreasurySpend` +
    /// `OnChain` proposal pays out from here to its beneficiary. `None`
    /// (default) means on-chain treasury execution is unavailable — such
    /// proposals fail rather than move funds. This is a governance-owned
    /// address funded deliberately to be governed; it is **not** the council
    /// Policy Account.
    #[serde(default)]
    pub treasury: Option<Address>,
}

/// Domain separator for the canonical, keyless governance bond-escrow address.
pub const GOV_ESCROW_DOMAIN: &[u8] = b"SRC-GOV-ESCROW:v1:";

/// Canonical governance bond-escrow address (issue #50, P6a). Deposit bonds are
/// held here between proposal creation and terminal settlement. Deterministically
/// derived from [`GOV_ESCROW_DOMAIN`] (not from any public key), so it is
/// keyless and spendable only by the governance executor. Anyone can recompute
/// it to audit the escrowed balance.
pub fn gov_escrow_address() -> Address {
    let hash = blake3::hash(GOV_ESCROW_DOMAIN);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash.as_bytes()[12..32]);
    Address::new(bytes)
}

// =============================================================================
// Operation request payloads (bincode-encoded into `GovernanceTxData::data`).
// Defined in P3a for the lifecycle phases; not yet decoded by the executor.
// =============================================================================

/// `RegisterAsset` request (council-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAssetRequest {
    pub token_id: TokenId,
    pub create_threshold: u128,
    pub effective_height: GovBlockHeight,
}

/// `CreateProposal` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateProposalRequest {
    pub asset: GovAssetKind,
    pub class: GovProposalClass,
    pub execution_kind: ExecutionKind,
    pub external_ref: ExternalRef,
    /// Beneficiary for a `TreasurySpend` + `OnChain` proposal (P6b). Ignored
    /// (and should be `None`) for every other class / `RecordOnly` proposal.
    #[serde(default)]
    pub treasury_beneficiary: Option<Address>,
    /// Native-Koppa payout amount for a `TreasurySpend` + `OnChain` proposal.
    #[serde(default)]
    pub treasury_amount: Option<u128>,
}

/// `CastVote` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastVoteRequest {
    pub proposal_id: GovProposalId,
    pub choice: VoteChoice,
}

/// `ExecuteProposal` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteProposalRequest {
    pub proposal_id: GovProposalId,
}

/// `CancelProposal` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelProposalRequest {
    pub proposal_id: GovProposalId,
}

/// Domain separator for deterministic proposal-id derivation.
pub const GOV_PROPOSAL_DOMAIN: &[u8] = b"SRC-GOV-PROPOSAL:v1:";

/// Deterministically derive a proposal id. Replay-safe: the outer tx `nonce`
/// (already replay-protected at the tx layer) is mixed in, along with the
/// proposer, asset, external-ref content hash, and creation height.
pub fn generate_proposal_id(
    proposer: &Address,
    asset: &GovAssetKind,
    content_hash: &[u8; 32],
    created_at_height: GovBlockHeight,
    nonce: u64,
) -> GovProposalId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GOV_PROPOSAL_DOMAIN);
    hasher.update(proposer.as_ref());
    match asset {
        GovAssetKind::Src20Token(token_id) => hasher.update(token_id),
    };
    hasher.update(content_hash);
    hasher.update(&created_at_height.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}
