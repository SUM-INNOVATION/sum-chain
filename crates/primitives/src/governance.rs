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
