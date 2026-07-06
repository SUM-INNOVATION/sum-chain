//! Validator-quorum authority primitives, shared by on-chain governance (issue
//! #50) and OmniNode inference settlement (issue #61).
//!
//! Certain privileged actions — governance `RegisterAsset` / validator-cancel and
//! settlement `ResolveDispute` — are authorized not by a single configured
//! address but by a **quorum of the active PoA validator set**. Approvals are
//! Ed25519 signatures collected off-chain and submitted together in one
//! transaction; the submitter (`tx.from`) is only the fee payer.
//!
//! This module holds the pure, dependency-light pieces: the [`ValidatorApproval`]
//! type and the domain-separated **signing bytes** each action commits to. The
//! Ed25519 verification and quorum evaluation live in the `state` crate
//! (`sumchain-primitives` intentionally has no dependency on `sumchain-crypto`).
//!
//! Each action uses a distinct domain separator and binds `chain_id`, so an
//! approval for one action (or chain) can never be replayed into another.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{Address, ChainId};

/// A single validator's Ed25519 approval of one specific privileged action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorApproval {
    /// Approving validator's Ed25519 public key. Must be a member of the active
    /// PoA validator set at the execution height, or the approval does not count.
    pub pubkey: [u8; 32],
    /// Ed25519 signature over the action's domain-separated signing bytes.
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Domain separator: governance `RegisterAsset` validator approval.
pub const GOV_REGISTER_ASSET_DOMAIN: &[u8] = b"SRC-GOV-VALQUORUM:register_asset:v1:";
/// Domain separator: governance validator-authority `CancelProposal` approval.
pub const GOV_CANCEL_PROPOSAL_DOMAIN: &[u8] = b"SRC-GOV-VALQUORUM:cancel_proposal:v1:";
/// Domain separator: inference-settlement `ResolveDispute` validator approval.
pub const INFERENCE_RESOLVE_DISPUTE_DOMAIN: &[u8] =
    b"OMNINODE-SETTLE-VALQUORUM:resolve_dispute:v1:";

/// Canonical bytes a validator signs to approve a governance `RegisterAsset`.
/// Binds `chain_id` + every action-critical field so the approval authorizes
/// exactly this registration and nothing else.
pub fn register_asset_signing_bytes(
    chain_id: ChainId,
    token_id: &[u8; 32],
    create_threshold: u128,
    effective_height: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(GOV_REGISTER_ASSET_DOMAIN.len() + 8 + 32 + 16 + 8);
    m.extend_from_slice(GOV_REGISTER_ASSET_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(token_id);
    m.extend_from_slice(&create_threshold.to_le_bytes());
    m.extend_from_slice(&effective_height.to_le_bytes());
    m
}

/// Canonical bytes a validator signs to approve a governance validator-cancel of
/// a specific proposal.
pub fn cancel_proposal_signing_bytes(chain_id: ChainId, proposal_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(GOV_CANCEL_PROPOSAL_DOMAIN.len() + 8 + 32);
    m.extend_from_slice(GOV_CANCEL_PROPOSAL_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(proposal_id);
    m
}

/// Canonical bytes a validator signs to approve an inference-settlement
/// `ResolveDispute` for a specific `(session_id, verifier)` and outcome.
pub fn resolve_dispute_signing_bytes(
    chain_id: ChainId,
    session_id: &str,
    verifier: &Address,
    allow_claim: bool,
) -> Vec<u8> {
    let sid = session_id.as_bytes();
    let mut m = Vec::with_capacity(INFERENCE_RESOLVE_DISPUTE_DOMAIN.len() + 8 + 8 + sid.len() + 20 + 1);
    m.extend_from_slice(INFERENCE_RESOLVE_DISPUTE_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    // Length-prefix the variable-length session id so the field boundary is
    // unambiguous (prevents cross-field ambiguity attacks).
    m.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    m.extend_from_slice(sid);
    m.extend_from_slice(verifier.as_bytes());
    m.push(if allow_claim { 1 } else { 0 });
    m
}

/// Required number of distinct valid validator approvals for a quorum, given the
/// active validator count and a threshold in basis points:
/// `ceil(active_count * threshold_bps / 10000)`.
///
/// Non-signing validators remain in the denominator (they abstain): the required
/// count is derived from the full active set, not from who happened to sign. A
/// `threshold_bps` of `10000` requires every active validator; `5000` requires a
/// strict majority-by-ceiling (e.g. 1 of 2, 2 of 3).
pub fn required_approvals(active_count: u32, threshold_bps: u16) -> u32 {
    let num = (active_count as u64) * (threshold_bps as u64);
    // ceil(num / 10000)
    ((num + 9999) / 10000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_approvals_ceiling() {
        // 2-validator network
        assert_eq!(required_approvals(2, 5000), 1); // 1.0 -> 1
        assert_eq!(required_approvals(2, 5001), 2); // 1.0002 -> 2
        assert_eq!(required_approvals(2, 6667), 2); // 1.33 -> 2
        assert_eq!(required_approvals(2, 10000), 2); // 2.0 -> 2
        // 3-validator network
        assert_eq!(required_approvals(3, 5000), 2); // 1.5 -> 2
        assert_eq!(required_approvals(3, 6667), 3); // 2.0001 -> 3
        assert_eq!(required_approvals(3, 3334), 2); // 1.0002 -> 2
        // never zero for any positive threshold on a non-empty set
        assert_eq!(required_approvals(1, 1), 1);
    }

    #[test]
    fn domains_are_distinct() {
        assert_ne!(GOV_REGISTER_ASSET_DOMAIN, GOV_CANCEL_PROPOSAL_DOMAIN);
        assert_ne!(GOV_REGISTER_ASSET_DOMAIN, INFERENCE_RESOLVE_DISPUTE_DOMAIN);
        assert_ne!(GOV_CANCEL_PROPOSAL_DOMAIN, INFERENCE_RESOLVE_DISPUTE_DOMAIN);
    }

    #[test]
    fn signing_bytes_bind_fields() {
        let a = register_asset_signing_bytes(1, &[1u8; 32], 100, 5);
        let b = register_asset_signing_bytes(1, &[1u8; 32], 100, 6); // different height
        assert_ne!(a, b);
        let c = register_asset_signing_bytes(2, &[1u8; 32], 100, 5); // different chain
        assert_ne!(a, c);
    }
}
