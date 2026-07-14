//! `InferenceAttestation` — semantic verification and status classification for
//! the OmniNode v1 subprotocol (Stage 6 handoff).
//!
//! The **wire types** (digest, tx-data, sponsored-v2 envelope, storage records,
//! key derivations, signing bytes, error type, and all constants) live in the
//! `sumchain-wire` leaf crate and are re-exported below verbatim, so every
//! existing `sumchain_primitives::inference_attestation::…` path keeps
//! resolving unchanged.
//!
//! This module keeps the pieces that must stay ABOVE the leaf:
//!
//! * **Ed25519 verification** ([`verify_attestation_signature`],
//!   [`verify_attestation_v2_signature`]) — the leaf is deliberately
//!   ed25519-free; encoding is separated from cryptographic verification.
//! * **Receipt-bound status classification**
//!   ([`classify_inference_attestation_status`] /
//!   [`InferenceAttestationStatusInfo`]) — binds `Receipt`/`TxStatus`, which
//!   also live above the leaf.

use serde::{Deserialize, Serialize};

// Re-export the full wire surface (digest, tx-data, records, key-derivations,
// signing-byte helpers, `AttestationError`, and every constant) so callers see
// an unchanged module API.
pub use sumchain_wire::inference_attestation::*;

/// Verify a sponsored (v2) attestation's inner verifier signature over the same
/// v1 signing bytes, against the envelope's `verifier_public_key`. Distinguishes
/// an invalid public key ([`AttestationError::InvalidPublicKey`]) from a bad
/// signature ([`AttestationError::InvalidSignature`]) so the dispatch can surface
/// the right receipt code. The sponsor (outer sender) is never consulted here.
pub fn verify_attestation_v2_signature(
    tx_data: &InferenceAttestationV2TxData,
) -> Result<(), AttestationError> {
    if tx_data.digest.session_id.len() > MAX_SESSION_ID_BYTES {
        return Err(AttestationError::SessionIdTooLong(
            tx_data.digest.session_id.len(),
        ));
    }
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&tx_data.verifier_public_key)
        .map_err(|_| AttestationError::InvalidPublicKey)?;
    let signing_input = signing_input_bytes(&tx_data.digest)?;
    let signature = ed25519_dalek::Signature::from_bytes(&tx_data.verifier_signature);
    verifying_key
        .verify_strict(&signing_input, &signature)
        .map_err(|_| AttestationError::InvalidSignature)
}

/// Verify the inner `verifier_signature` over `signing_input_bytes(digest)`
/// against the supplied raw 32-byte Ed25519 public key.
///
/// Cap-check on `session_id` length is performed first so an oversize
/// payload is rejected before any crypto work.
pub fn verify_attestation_signature(
    tx_data: &InferenceAttestationTxData,
    verifier_public_key: &[u8; 32],
) -> Result<(), AttestationError> {
    if tx_data.digest.session_id.len() > MAX_SESSION_ID_BYTES {
        return Err(AttestationError::SessionIdTooLong(
            tx_data.digest.session_id.len(),
        ));
    }
    let signing_input = signing_input_bytes(&tx_data.digest)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(verifier_public_key)
        .map_err(|_| AttestationError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&tx_data.verifier_signature);
    verifying_key
        .verify_strict(&signing_input, &signature)
        .map_err(|_| AttestationError::InvalidSignature)
}

/// Status of a specific `InferenceAttestation` tx, returned by the
/// `sum_getInferenceAttestationStatus` RPC. Lives in primitives (not
/// `sumchain-rpc::types`) so the classification logic can be exercised
/// without the storage / rocksdb transitive dependency chain.
///
/// Four-state v1 model: `submitted` (mempool), `included` (in a block
/// but < finality_depth deep), `finalized` (>= finality_depth deep),
/// `failed` (in a block, executor rejected). `Dropped` is intentionally
/// NOT represented in v1 — mempool eviction is not tracked; clients
/// should resubmit after a client-side timeout. `unknown` is returned
/// for any tx hash that isn't a recognized `InferenceAttestation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationStatusInfo {
    /// One of: `"submitted"`, `"included"`, `"finalized"`, `"failed"`,
    /// `"unknown"`.
    pub status: String,
    /// Block height the tx was included at, or `None` if still
    /// submitted / unknown.
    pub included_at_height: Option<u64>,
    /// Human-readable failure reason from `TxStatus::description()` when
    /// `status == "failed"`. `None` otherwise.
    pub reason: Option<String>,
}

/// Pure classifier for `sum_getInferenceAttestationStatus`. Receipt-first
/// precedence with a payload-type guard:
///
/// 1. **Payload-type guard.** If neither the stored tx nor the mempool
///    tx is an `InferenceAttestation`, return `"unknown"` regardless of
///    receipt state. A foreign tx hash MUST NOT be reported as
///    `included` or `finalized` through this method — clients would
///    misinterpret it as an attestation otherwise.
/// 2. **Receipt → `included`/`finalized`/`failed`.** Receipt is the
///    authoritative source; a stale mempool entry can coexist with a
///    receipt during the prune window. Mirrors the existing
///    `classify_tx_status` helper in `sumchain-rpc::server`.
/// 3. **Mempool → `submitted`.** Only consulted when no receipt exists.
/// 4. **Otherwise → `"unknown"`.**
///
/// All inputs are owned by the RPC layer; this function performs zero
/// I/O. It lives in primitives so the seven exhaustive branch tests
/// can run without the rpc crate's storage transitive deps. The RPC
/// server hands its four inputs through and returns the result.
pub fn classify_inference_attestation_status(
    stored_tx: Option<&crate::SignedTransaction>,
    mempool_tx: Option<&crate::SignedTransaction>,
    receipt: Option<&crate::Receipt>,
    current_height: u64,
    finality_depth: u64,
) -> InferenceAttestationStatusInfo {
    use crate::{TxInner, TxPayload, TxStatus};

    let is_attestation = |signed: &crate::SignedTransaction| -> bool {
        matches!(&signed.inner, TxInner::V2(v2)
            if matches!(&v2.payload, TxPayload::InferenceAttestation(_)))
    };
    let confirmed = stored_tx.map(is_attestation).unwrap_or(false)
        || mempool_tx.map(is_attestation).unwrap_or(false);
    if !confirmed {
        return InferenceAttestationStatusInfo {
            status: "unknown".to_string(),
            included_at_height: None,
            reason: None,
        };
    }

    if let Some(r) = receipt {
        let is_success = matches!(r.status, TxStatus::Success);
        let status_str = if !is_success {
            "failed"
        } else if current_height >= r.block_height.saturating_add(finality_depth) {
            "finalized"
        } else {
            "included"
        };
        let reason = if !is_success {
            Some(r.status.description().to_string())
        } else {
            None
        };
        return InferenceAttestationStatusInfo {
            status: status_str.to_string(),
            included_at_height: Some(r.block_height),
            reason,
        };
    }

    if mempool_tx.is_some() {
        InferenceAttestationStatusInfo {
            status: "submitted".to_string(),
            included_at_height: None,
            reason: None,
        }
    } else {
        InferenceAttestationStatusInfo {
            status: "unknown".to_string(),
            included_at_height: None,
            reason: None,
        }
    }
}
