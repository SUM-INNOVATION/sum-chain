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
    #[error("bincode-serializing digest failed: {0}")]
    Serialization(String),
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
