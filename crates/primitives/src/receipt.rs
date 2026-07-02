//! Transaction receipts for SUM Chain.
//!
//! Receipts record the outcome of transaction execution,
//! including success/failure status and any fees paid.

use serde::{Deserialize, Serialize};

use crate::{Balance, BlockHeight, Hash};

/// Status of a transaction after execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction executed successfully
    Success,
    /// Transaction failed - invalid signature
    InvalidSignature,
    /// Transaction failed - wrong nonce
    InvalidNonce,
    /// Transaction failed - insufficient balance
    InsufficientBalance,
    /// Transaction failed - invalid chain ID
    InvalidChainId,
    /// Transaction failed - other reason
    Failed(u32),
}

impl TxStatus {
    /// Check if transaction succeeded
    pub fn is_success(&self) -> bool {
        matches!(self, TxStatus::Success)
    }

    /// Get a human-readable description.
    ///
    /// `Failed(u32)` codes are mapped here so `chain_getTransactionStatus`
    /// (and any other receipt-surfacing path) emits the specific reason.
    /// Allocated codes:
    ///
    /// * `22` — V2 `RegisterEncryptionKey`: rejected a low/small-order
    ///   X25519 public key. Validation lives in
    ///   `sumchain_crypto::is_low_order_x25519_public_key` (separate crate;
    ///   `sumchain-primitives` does not depend on `sumchain-crypto`, so this
    ///   is a plain reference rather than an intra-doc link).
    ///
    /// Allocated codes (kept in sync with executor dispatch):
    ///
    /// * `20` — V2 NodeRegistry dispatch failed (generic) — falls through to
    ///   `"failed"` until per-op reasons are added.
    /// * `21` — V2 StorageMetadata dispatch failed (generic) — falls through.
    /// * `22` — `RegisterEncryptionKey` rejected a low/small-order X25519
    ///   public key. See `sumchain_crypto::is_low_order_x25519_public_key`.
    /// * `30` — `RegisterFilePendingV2` validity failure (size/chunk caps,
    ///   visibility/bundle/owner rules, recipient X25519 missing, collision).
    /// * `31` — `AbandonFileV2` validity failure (state/owner/grace).
    /// * `32` — V2 storage op accepted by the dispatcher but not yet
    ///   implemented in the current checkpoint (placeholder for 1c stubs).
    /// * `33` — `AcceptAssignmentV2` validity failure (file state, snapshot
    ///   membership, per-tx cap, index range, index-not-assigned).
    /// * `34` — `ActivateFileV2` validity failure (state/owner/incomplete
    ///   chunk coverage).
    /// * `35` — `AddAccessV2` / `RemoveAccessV2` / `UpdateAccessV2` validity
    ///   failure (file state/owner/visibility-bundle/X25519/duplicate/missing/
    ///   byte-cap).
    /// * `40` — V2 storage protocol not enabled at this block height. Set
    ///   `v2_enabled_from_height` in the chain's genesis to opt in.
    ///   Distinct from validity codes 30–35: this is a chain-level gate
    ///   rejection, no fee consumed; safe to retry after activation.
    pub fn description(&self) -> &'static str {
        match self {
            TxStatus::Success => "success",
            TxStatus::InvalidSignature => "invalid signature",
            TxStatus::InvalidNonce => "invalid nonce",
            TxStatus::InsufficientBalance => "insufficient balance",
            TxStatus::InvalidChainId => "invalid chain id",
            TxStatus::Failed(22) => "low-order x25519 public key rejected",
            TxStatus::Failed(30) => "RegisterFilePendingV2 validity check failed",
            TxStatus::Failed(31) => "AbandonFileV2 validity check failed",
            TxStatus::Failed(32) => "V2 storage op not yet implemented",
            TxStatus::Failed(33) => "AcceptAssignmentV2 validity check failed",
            TxStatus::Failed(34) => "ActivateFileV2 validity check failed",
            TxStatus::Failed(35) => "V2 access op validity check failed",
            TxStatus::Failed(40) => "V2 storage protocol not enabled at this height",
            // Policy account governance failures.
            TxStatus::Failed(17) => "policy account operation failed (invalid approval, threshold not met, or unsupported wrapped action)",
            // Smart-contract subprotocol gate.
            TxStatus::Failed(60) => "contract subprotocol not enabled at this block height",
            // OmniNode `InferenceAttestation` subprotocol failures.
            TxStatus::Failed(50) => "OmniNode subprotocol not enabled at this block height",
            TxStatus::Failed(51) => "duplicate InferenceAttestation for (session_id, verifier)",
            TxStatus::Failed(52) => "invalid OmniNode Stage 6 verifier signature",
            TxStatus::Failed(53) => "tx sender does not match verifier address (Ed25519 pubkey hash)",
            // SRC-817/818 Education-LMS suite failures (Phase 2).
            TxStatus::Failed(70) => "education subprotocol not enabled at this block height",
            TxStatus::Failed(71) => "malformed education payload",
            TxStatus::Failed(72) => "unsupported education operation",
            TxStatus::Failed(73) => "catalog entry not found",
            TxStatus::Failed(74) => "catalog entry in wrong state for operation",
            TxStatus::Failed(75) => "offering not found",
            TxStatus::Failed(76) => "offering in wrong state for operation",
            TxStatus::Failed(77) => "assessment not found or wrong kind",
            TxStatus::Failed(78) => "assessment submission window closed",
            TxStatus::Failed(79) => "student commitment not enrolled in offering",
            TxStatus::Failed(80) => "submission attempts exhausted",
            TxStatus::Failed(81) => "duplicate education record",
            TxStatus::Failed(82) => "invalid reference (enrollment/employment/catalog)",
            TxStatus::Failed(83) => "not authorized for education operation",
            TxStatus::Failed(84) => "insufficient balance for education fee",
            // On-chain governance v1 failures (issue #50). Isolated 300-block so
            // codes never collide with the education (70–84) or other ranges.
            TxStatus::Failed(300) => "governance subprotocol not enabled at this block height",
            TxStatus::Failed(301) => "governance not configured (no governance params)",
            TxStatus::Failed(302) => "undecodable or unsupported governance operation",
            TxStatus::Failed(303) => "governance registry / asset eligibility failure",
            TxStatus::Failed(304) => "governance proposal create threshold not met",
            TxStatus::Failed(305) => "governance snapshot holder bound exceeded",
            TxStatus::Failed(306) => "governance proposal not found or in wrong status",
            TxStatus::Failed(307) => "governance voting window closed or proposal expired",
            TxStatus::Failed(308) => "no governance snapshot weight for voter",
            TxStatus::Failed(309) => "duplicate governance vote",
            TxStatus::Failed(310) => "on-chain governance execution not supported in v1",
            TxStatus::Failed(_) => "failed",
        }
    }
}

/// Receipt for an executed transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction
    pub tx_hash: Hash,
    /// Block height where tx was included
    pub block_height: BlockHeight,
    /// Index of tx within the block
    pub tx_index: u32,
    /// Execution status
    pub status: TxStatus,
    /// Fee actually paid (may differ if tx failed early)
    pub fee_paid: Balance,
}

impl Receipt {
    /// Create a new receipt
    pub fn new(
        tx_hash: Hash,
        block_height: BlockHeight,
        tx_index: u32,
        status: TxStatus,
        fee_paid: Balance,
    ) -> Self {
        Self {
            tx_hash,
            block_height,
            tx_index,
            status,
            fee_paid,
        }
    }

    /// Create a success receipt
    pub fn success(
        tx_hash: Hash,
        block_height: BlockHeight,
        tx_index: u32,
        fee_paid: Balance,
    ) -> Self {
        Self::new(tx_hash, block_height, tx_index, TxStatus::Success, fee_paid)
    }

    /// Check if the transaction succeeded
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Receipt serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_is_success() {
        assert!(TxStatus::Success.is_success());
        assert!(!TxStatus::InvalidNonce.is_success());
        assert!(!TxStatus::InsufficientBalance.is_success());
    }

    #[test]
    fn test_receipt_serialization() {
        let receipt = Receipt::success(Hash::hash(b"tx"), 100, 0, 10);
        let bytes = receipt.to_bytes();
        let receipt2 = Receipt::from_bytes(&bytes).unwrap();
        assert_eq!(receipt, receipt2);
    }
}
