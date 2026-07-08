//! `InferenceAttestation` — chain-side wire types for the OmniNode v1
//! subprotocol (Stage 6 handoff).
//!
//! The on-chain tx variant `TxType::InferenceAttestation = 21` carries an
//! [`InferenceAttestationTxData`] payload inside the existing
//! `SignedTransaction` envelope. The verifier (off-chain OmniNode node)
//! signs an inner [`InferenceAttestationDigest`] under
//! `DOMAIN_TAG || bincode(digest)`; the chain verifies that signature
//! against the outer `SignedTransaction.public_key` (which, by executor
//! rule, equals `tx.sender`'s pubkey — `sender == verifier` is enforced).
//!
//! Wire-format frozen for v1, locked by the test vectors in
//! `crates/primitives/tests/inference_attestation_fixtures.rs`:
//!
//! - `bincode` 1.3 default config (u64-LE length prefix for `String`).
//! - Field order of `InferenceAttestationDigest` is significant:
//!   `session_id, model_hash, manifest_root, response_hash, proof_root`.
//! - `DOMAIN_TAG` is the OmniNode-defined separator
//!   `omninode.inference_attestation.v1`.
//!
//! See `docs/SUBPROTOCOLS/INFERENCE-ATTESTATION.md` for full protocol notes.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::Address;

/// Domain separator prepended to `bincode(digest)` before Ed25519 signing.
/// Frozen by OmniNode Stage 6; bumping requires a new TxPayload variant
/// (e.g. `InferenceAttestationV2`).
pub const DOMAIN_TAG: &str = "omninode.inference_attestation.v1";

/// Maximum byte length (UTF-8) of `InferenceAttestationDigest::session_id`.
/// Executor rejects payloads exceeding this.
pub const MAX_SESSION_ID_BYTES: usize = 256;

/// Inner digest signed by the verifier. Field order is the on-wire bincode
/// order and is **frozen** for v1 — changing it silently invalidates every
/// historical attestation. New fields require a new variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationDigest {
    pub session_id: String,
    pub model_hash: [u8; 32],
    pub manifest_root: [u8; 32],
    pub response_hash: [u8; 32],
    pub proof_root: [u8; 32],
}

/// On-chain tx payload. Wrapped by `SignedTransaction`; the outer signature
/// (verifier signing the full `SignedTransaction.inner`) and the inner
/// `verifier_signature` (verifier signing `DOMAIN_TAG || bincode(digest)`)
/// are produced by the same Ed25519 key but under different inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationTxData {
    pub digest: InferenceAttestationDigest,
    #[serde(with = "BigArray")]
    pub verifier_signature: [u8; 64],
}

/// Errors surfaced when validating an `InferenceAttestationTxData` against
/// chain rules or its inner signature.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("session_id is {0} bytes; max is {MAX_SESSION_ID_BYTES}")]
    SessionIdTooLong(usize),
    #[error("inner verifier signature is invalid for the supplied public key")]
    InvalidSignature,
    #[error("verifier public key is not a valid Ed25519 point")]
    InvalidPublicKey,
    #[error("bincode-serializing digest failed: {0}")]
    Serialization(String),
}

/// Sponsored attestation v2 envelope (issue #79). **Append-only** — this does
/// NOT change v1: it wraps the *same* [`InferenceAttestationDigest`] and the same
/// verifier signing bytes (`DOMAIN_TAG || bincode(digest)`), so a v2 attestation
/// is an identical commitment to the v1 form.
///
/// The difference is *who submits it*: the outer `SignedTransaction` is signed by
/// a **sponsor/payer** (the fee payer), while the **verifier** is identified by
/// `verifier_public_key` and authenticated by `verifier_signature`. Sponsored
/// attestation changes who pays to submit the attestation, not who made it — the
/// verifier remains the attestation identity for deduplication, storage, and
/// settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationV2TxData {
    pub digest: InferenceAttestationDigest,
    /// The verifier's raw Ed25519 public key — the attestation identity. The
    /// verifier address is `Address::from_public_key(verifier_public_key)`.
    pub verifier_public_key: [u8; 32],
    /// The verifier's signature over `DOMAIN_TAG || bincode(digest)` (identical
    /// bytes to v1). Must verify against `verifier_public_key`.
    #[serde(with = "BigArray")]
    pub verifier_signature: [u8; 64],
}

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

/// Canonical bytes of the digest under bincode 1.3 default config.
/// Matches OmniNode Stage 6 fixture's `canonical_digest_bytes`.
pub fn canonical_digest_bytes(
    digest: &InferenceAttestationDigest,
) -> Result<Vec<u8>, AttestationError> {
    bincode::serialize(digest).map_err(|e| AttestationError::Serialization(e.to_string()))
}

/// `DOMAIN_TAG.as_bytes() || canonical_digest_bytes(digest)` — the exact
/// byte sequence Ed25519 signs over. Matches OmniNode Stage 6 fixture's
/// `signing_input_bytes`.
pub fn signing_input_bytes(
    digest: &InferenceAttestationDigest,
) -> Result<Vec<u8>, AttestationError> {
    let canonical = canonical_digest_bytes(digest)?;
    let domain = DOMAIN_TAG.as_bytes();
    let mut out = Vec::with_capacity(domain.len() + canonical.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&canonical);
    Ok(out)
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

/// Derive the verifier address from the raw Ed25519 public key using the
/// chain's canonical address rule. Re-exported for clarity at the
/// subprotocol surface; equivalent to [`Address::from_public_key`].
pub fn verifier_address(public_key: &[u8; 32]) -> Address {
    Address::from_public_key(public_key)
}

/// Domain string for the inference-attestation CF key derivation.
/// Bumping this string (e.g. to `…V2`) is the path to a CF-schema
/// migration without breaking lookups against historical entries.
pub const INFERENCE_ATTESTATION_KEY_DOMAIN: &[u8] = b"InferenceAttestationKeyV1";

/// Stable 32-byte CF key for the `inference_attestations` column family.
///
/// `BLAKE3(INFERENCE_ATTESTATION_KEY_DOMAIN || bincode((session_id, verifier_address)))`
///
/// Properties:
/// - **Domain-separated**: the `V1` suffix in the domain string lets a
///   future schema rotation use a `V2` keyspace without colliding with
///   historical entries.
/// - **Length-safe**: bincode 1.3 default config length-prefixes `String`
///   with a u64 LE before the bytes, so a `session_id` containing `0x00`
///   cannot be confused with a different `(session_id, verifier)` split.
/// - **Fixed-size**: 32 bytes regardless of `session_id` length, keeping
///   point-lookup cost bounded on RocksDB.
/// - **Fixture-locked**: the wire-fixture test asserts the exact key bytes
///   for OmniNode's three reference vectors. Drift = red CI.
pub fn inference_attestation_key(
    session_id: &str,
    verifier_address: &Address,
) -> [u8; 32] {
    let inner = bincode::serialize(&(session_id, verifier_address))
        .expect("bincode of (String, Address) cannot fail");
    let mut hasher = blake3::Hasher::new();
    hasher.update(INFERENCE_ATTESTATION_KEY_DOMAIN);
    hasher.update(&inner);
    *hasher.finalize().as_bytes()
}

/// Domain string for the session-id-keyed index CF (`INFERENCE_ATTESTATIONS_BY_SESSION`).
/// Versioned so future index-key rotations can use a `V2` namespace
/// without colliding with historical entries.
pub const INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN: &[u8] =
    b"InferenceAttestationSessionIndexV1";

/// Number of bytes of the session-id BLAKE3 hash used as the prefix
/// portion of the session-index key. 16 bytes = 128 bits of session-id
/// distinguishability, sufficient for any practical attestation rate.
pub const SESSION_ID_HASH_BYTES: usize = 16;

/// 36-byte index key for the `INFERENCE_ATTESTATIONS_BY_SESSION` CF:
/// `session_id_hash_16 || verifier_address_20`.
///
/// Property: the first 16 bytes are a deterministic function of
/// `session_id` alone — prefix-iterating with that 16-byte prefix
/// returns every `(session_id, verifier)` pair for the given session.
/// The trailing 20 bytes are the verifier's chain Address, so the
/// caller can recover the verifier without a second lookup.
pub fn session_index_key(
    session_id: &str,
    verifier_address: &Address,
) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..SESSION_ID_HASH_BYTES].copy_from_slice(&session_index_prefix(session_id));
    out[SESSION_ID_HASH_BYTES..].copy_from_slice(verifier_address.as_bytes());
    out
}

/// 16-byte prefix portion of [`session_index_key`]. Used by the RPC
/// `list_by_session` path to bound a prefix scan to one session's
/// attestations.
pub fn session_index_prefix(session_id: &str) -> [u8; SESSION_ID_HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN);
    hasher.update(session_id.as_bytes());
    let hash = hasher.finalize();
    let mut prefix = [0u8; SESSION_ID_HASH_BYTES];
    prefix.copy_from_slice(&hash.as_bytes()[..SESSION_ID_HASH_BYTES]);
    prefix
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

/// Value stored in the `INFERENCE_ATTESTATIONS` CF. Bincode-serialized.
///
/// Records the verifier-signed digest, the signature, and the inclusion
/// metadata the chain stamps at executor time. Both the executor (during
/// dedup check + persist) and future RPC read paths (Phase 4) consume
/// this record.
///
/// Wire shape is **not** part of the OmniNode handoff — it's a chain-side
/// internal storage record. Field order is still frozen for forward
/// compatibility with stored data: changing it would require a CF schema
/// migration (rotate to `InferenceAttestationKeyV2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationRecord {
    pub digest: InferenceAttestationDigest,
    #[serde(with = "BigArray")]
    pub verifier_signature: [u8; 64],
    pub included_at_height: u64,
    pub tx_hash: crate::Hash,
}

/// Additive sponsor metadata for a **sponsored (v2)** inference attestation
/// (issue #95). Stored in the dedicated `INFERENCE_ATTESTATION_SPONSORS` CF under
/// the SAME `inference_attestation_key(session_id, verifier_address)` as the
/// canonical [`InferenceAttestationRecord`], and written **only** by the
/// sponsored v2 path, in the same atomic batch as the record. v1 direct
/// submissions (`sender == verifier`) write no sponsor entry, so absence means
/// "not sponsored". This is observability-only: the sponsor never becomes the
/// attestation identity and settlement never reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationSponsor {
    /// The outer transaction sender that paid to submit the attestation.
    pub sponsor: Address,
    /// Block height at which the sponsored attestation was included.
    pub submitted_at_height: u64,
    /// Hash of the outer (sponsor-signed) transaction that carried the v2 envelope.
    pub tx_hash: crate::Hash,
}
