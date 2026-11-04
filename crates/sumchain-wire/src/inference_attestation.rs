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
//!
//! ## Without `std`
//!
//! With `default-features = false` (sum-chain #312) this module keeps
//! [`DOMAIN_TAG`], [`MAX_SESSION_ID_BYTES`], [`InferenceAttestationDigest`],
//! [`AttestationError`], [`canonical_digest_bytes`], [`signing_input_bytes`]
//! and [`verifier_address`]; everything else here needs `std`. `bincode` is
//! not available without `std`, so there [`canonical_digest_bytes`] writes
//! the same bytes with an encoder written by hand in this module. This
//! module's tests pin that encoder to golden bytes taken from `bincode` and to
//! `bincode` itself. A default build still calls `bincode`.

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
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
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationTxData {
    pub digest: InferenceAttestationDigest,
    #[serde(with = "BigArray")]
    pub verifier_signature: [u8; 64],
}

/// Errors surfaced when validating an `InferenceAttestationTxData` against
/// chain rules or its inner signature.
///
/// With `std` it implements `Display` and `std::error::Error` (through
/// `thiserror`); without `std` it implements `Debug` only.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AttestationError {
    #[cfg_attr(
        feature = "std",
        error("session_id is {0} bytes; max is {MAX_SESSION_ID_BYTES}")
    )]
    SessionIdTooLong(usize),
    #[cfg_attr(
        feature = "std",
        error("inner verifier signature is invalid for the supplied public key")
    )]
    InvalidSignature,
    #[cfg_attr(
        feature = "std",
        error("verifier public key is not a valid Ed25519 point")
    )]
    InvalidPublicKey,
    #[cfg_attr(feature = "std", error("bincode-serializing digest failed: {0}"))]
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
#[cfg(feature = "std")]
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

/// Canonical bytes of the digest under bincode 1.3 default config.
/// Matches OmniNode Stage 6 fixture's `canonical_digest_bytes`.
///
/// With `std` this calls `bincode`. Without `std` it writes the same bytes by
/// hand (see the [module docs](self)) and never returns `Err`.
pub fn canonical_digest_bytes(
    digest: &InferenceAttestationDigest,
) -> Result<Vec<u8>, AttestationError> {
    #[cfg(feature = "std")]
    {
        bincode::serialize(digest).map_err(|e| AttestationError::Serialization(e.to_string()))
    }
    #[cfg(not(feature = "std"))]
    {
        Ok(digest_bytes_by_hand(digest))
    }
}

/// The bytes `bincode` 1.3 writes for `digest` under its default
/// configuration, written by hand for builds without `std`:
///
/// - `session_id`: its length in bytes as a `u64`, little-endian, then its
///   UTF-8 bytes;
/// - then `model_hash`, `manifest_root`, `response_hash` and `proof_root`, in
///   that order: each array's 32 bytes as they are, with no length prefix.
///
/// It is compiled without `std`, where [`canonical_digest_bytes`] calls it,
/// and in tests, which pin it to `bincode`. A default build does not contain
/// it.
#[cfg(any(not(feature = "std"), test))]
fn digest_bytes_by_hand(digest: &InferenceAttestationDigest) -> Vec<u8> {
    // Destructured without `..`: a field added to the digest stops this
    // compiling until the encoder writes it.
    let InferenceAttestationDigest {
        session_id,
        model_hash,
        manifest_root,
        response_hash,
        proof_root,
    } = digest;
    let mut out = Vec::with_capacity(8 + session_id.len() + 4 * 32);
    out.extend_from_slice(&(session_id.len() as u64).to_le_bytes());
    out.extend_from_slice(session_id.as_bytes());
    for array in [model_hash, manifest_root, response_hash, proof_root] {
        out.extend_from_slice(array);
    }
    out
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

/// Derive the verifier address from the raw Ed25519 public key using the
/// chain's canonical address rule. Re-exported for clarity at the
/// subprotocol surface; equivalent to [`Address::from_public_key`].
pub fn verifier_address(public_key: &[u8; 32]) -> Address {
    Address::from_public_key(public_key)
}

/// Domain string for the inference-attestation CF key derivation.
/// Bumping this string (e.g. to `…V2`) is the path to a CF-schema
/// migration without breaking lookups against historical entries.
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
pub const INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN: &[u8] =
    b"InferenceAttestationSessionIndexV1";

/// Number of bytes of the session-id BLAKE3 hash used as the prefix
/// portion of the session-index key. 16 bytes = 128 bits of session-id
/// distinguishability, sufficient for any practical attestation rate.
#[cfg(feature = "std")]
pub const SESSION_ID_HASH_BYTES: usize = 16;

/// 36-byte index key for the `INFERENCE_ATTESTATIONS_BY_SESSION` CF:
/// `session_id_hash_16 || verifier_address_20`.
///
/// Property: the first 16 bytes are a deterministic function of
/// `session_id` alone — prefix-iterating with that 16-byte prefix
/// returns every `(session_id, verifier)` pair for the given session.
/// The trailing 20 bytes are the verifier's chain Address, so the
/// caller can recover the verifier without a second lookup.
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
pub fn session_index_prefix(session_id: &str) -> [u8; SESSION_ID_HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INFERENCE_ATTESTATION_SESSION_INDEX_DOMAIN);
    hasher.update(session_id.as_bytes());
    let hash = hasher.finalize();
    let mut prefix = [0u8; SESSION_ID_HASH_BYTES];
    prefix.copy_from_slice(&hash.as_bytes()[..SESSION_ID_HASH_BYTES]);
    prefix
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
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttestationSponsor {
    /// The outer transaction sender that paid to submit the attestation.
    pub sponsor: Address,
    /// Block height at which the sponsored attestation was included.
    pub submitted_at_height: u64,
    /// Hash of the outer (sponsor-signed) transaction that carried the v2 envelope.
    pub tx_hash: crate::Hash,
}

#[cfg(test)]
mod tests {
    //! The hand-written digest encoder against `bincode` 1.3 (sum-chain #312).
    //!
    //! The golden bytes come from `bincode`, from two places:
    //!
    //! - the three OmniNode Stage 6 vectors, copied verbatim from
    //!   `crates/primitives/tests/fixtures/chain_attestation_vectors.json`;
    //! - vectors printed by `bincode::serialize` at 182d74b6, before the encoder
    //!   existed, one for each shape a field can take.
    //!
    //! Each is checked against the encoder, against `bincode` and against
    //! `canonical_digest_bytes`, which calls `bincode` in a `std` build and the
    //! encoder without `std`. Without `std` the `bincode` comparisons are left
    //! out, so those builds check the encoder and `canonical_digest_bytes`
    //! against the same golden bytes.
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    fn bytes32(f: impl Fn(u8) -> u8) -> [u8; 32] {
        core::array::from_fn(|i| f(i as u8))
    }

    fn digest(session_id: &str, arrays: [[u8; 32]; 4]) -> InferenceAttestationDigest {
        let [model_hash, manifest_root, response_hash, proof_root] = arrays;
        InferenceAttestationDigest {
            session_id: session_id.to_string(),
            model_hash,
            manifest_root,
            response_hash,
            proof_root,
        }
    }

    /// The encoder, `bincode` and `canonical_digest_bytes` all write `expected`.
    fn assert_all_write(d: &InferenceAttestationDigest, expected: &[u8], name: &str) {
        assert_eq!(digest_bytes_by_hand(d), expected, "{name}: hand encoder");
        #[cfg(feature = "std")]
        assert_eq!(bincode::serialize(d).unwrap(), expected, "{name}: bincode");
        assert_eq!(
            canonical_digest_bytes(d).unwrap(),
            expected,
            "{name}: canonical"
        );
    }

    #[test]
    fn omninode_stage6_vectors() {
        let vectors = [
            (
                "omninode-stage6-vec-1",
                [0x00, 0x11, 0x22, 0x33],
                "15000000000000006f6d6e696e6f64652d7374616765362d7665632d310000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333",
                "6f6d6e696e6f64652e696e666572656e63655f6174746573746174696f6e2e763115000000000000006f6d6e696e6f64652d7374616765362d7665632d310000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333",
            ),
            (
                "omninode-stage6-vec-2",
                [0x44, 0x55, 0x66, 0x77],
                "15000000000000006f6d6e696e6f64652d7374616765362d7665632d324444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555566666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777",
                "6f6d6e696e6f64652e696e666572656e63655f6174746573746174696f6e2e763115000000000000006f6d6e696e6f64652d7374616765362d7665632d324444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555566666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777",
            ),
            (
                "omninode-stage6-vec-3-abcdef-0123456789",
                [0x88, 0x99, 0xaa, 0xbb],
                "27000000000000006f6d6e696e6f64652d7374616765362d7665632d332d6162636465662d3031323334353637383988888888888888888888888888888888888888888888888888888888888888889999999999999999999999999999999999999999999999999999999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "6f6d6e696e6f64652e696e666572656e63655f6174746573746174696f6e2e763127000000000000006f6d6e696e6f64652d7374616765362d7665632d332d6162636465662d3031323334353637383988888888888888888888888888888888888888888888888888888888888888889999999999999999999999999999999999999999999999999999999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ];
        for (session_id, fills, canonical, signing_input) in vectors {
            let d = digest(session_id, fills.map(|b| [b; 32]));
            let canonical = hex::decode(canonical).unwrap();
            let signing_input = hex::decode(signing_input).unwrap();
            assert_all_write(&d, &canonical, session_id);
            assert_eq!(
                signing_input_bytes(&d).unwrap(),
                signing_input,
                "{session_id}"
            );
            // What `signing_input_bytes` computes without `std`.
            let by_hand = [DOMAIN_TAG.as_bytes(), &digest_bytes_by_hand(&d)].concat();
            assert_eq!(by_hand, signing_input, "{session_id}: hand signing input");
        }
    }

    #[test]
    fn field_shape_goldens() {
        let vectors = [
            (
                "empty session_id, zero arrays",
                digest("", [[0; 32]; 4]),
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "one-byte session_id, 0xff arrays",
                digest("a", [[0xff; 32]; 4]),
                "010000000000000061ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "a different fill per array: field order",
                digest("s", [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]]),
                "0100000000000000731111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                "every array byte distinct: byte positions",
                digest(
                    "session-0001",
                    [
                        bytes32(|i| i),
                        bytes32(|i| 32 + i),
                        bytes32(|i| 64 + i),
                        bytes32(|i| 96 + i),
                    ],
                ),
                "0c0000000000000073657373696f6e2d30303031000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            ),
            (
                "multi-byte UTF-8: the prefix counts bytes (12), not chars (4)",
                digest(
                    "\u{e9}\u{65e5}\u{672c}\u{1f980}",
                    [
                        bytes32(|i| 255 - i),
                        bytes32(|i| i.wrapping_mul(7)),
                        [0xa5; 32],
                        [0x5a; 32],
                    ],
                ),
                "0c00000000000000c3a9e697a5e69cacf09fa680fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e000070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            ),
            (
                "NUL and control characters in session_id",
                digest(
                    "\u{0}a\u{0}\n\t\u{7f}",
                    [
                        bytes32(|i| i ^ 0x55),
                        bytes32(|i| i ^ 0xaa),
                        bytes32(|i| i.wrapping_mul(13)),
                        bytes32(|i| 0x80 | i),
                    ],
                ),
                "06000000000000000061000a097f55545756515053525d5c5f5e59585b5a45444746414043424d4c4f4e49484b4aaaaba8a9aeafacada2a3a0a1a6a7a4a5babbb8b9bebfbcbdb2b3b0b1b6b7b4b5000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            ),
        ];
        for (name, d, expected) in vectors {
            let expected = hex::decode(expected).unwrap();
            assert_eq!(expected.len(), 8 + d.session_id.len() + 128, "{name}");
            assert_all_write(&d, &expected, name);
        }
    }

    /// Lengths whose `u64` prefix uses a second and a third byte, either side of
    /// `MAX_SESSION_ID_BYTES` (which the encoder, like `bincode`, does not
    /// enforce). Pinned by length, prefix and the BLAKE3 of the whole encoding.
    #[test]
    fn length_prefix_goldens() {
        let vectors = [
            (
                'x',
                255,
                [0x01, 0x02, 0x03, 0x04],
                "ff00000000000000",
                "4ea8aba801b0744aee6dbe9b3751547b3b688ef393822f944ceeb9f037949ea2",
            ),
            (
                'y',
                256,
                [0x05, 0x06, 0x07, 0x08],
                "0001000000000000",
                "0885f0de2c3cd7ccc7f943b08a5c01ca7ad3f39fe65c02a5a94da9484877eeec",
            ),
            (
                'z',
                257,
                [0x09, 0x0a, 0x0b, 0x0c],
                "0101000000000000",
                "c78d543d03d25ea7efbe360aee9ab7eec42997a0d80684ae4a159617821371cc",
            ),
            (
                'q',
                65537,
                [0x0d, 0x0e, 0x0f, 0x10],
                "0100010000000000",
                "8643bb6b0b6bdad2843562deace19d027b87f1800bd08be4e7cfda7ce82d735b",
            ),
        ];
        assert_eq!(MAX_SESSION_ID_BYTES, 256);
        for (c, n, fills, prefix, blake3_hex) in vectors {
            let d = digest(&c.to_string().repeat(n), fills.map(|b| [b; 32]));
            let by_hand = digest_bytes_by_hand(&d);
            assert_eq!(by_hand.len(), 8 + n + 128, "{n}");
            assert_eq!(hex::encode(&by_hand[..8]), prefix, "{n}");
            assert_eq!(blake3::hash(&by_hand).to_hex().as_str(), blake3_hex, "{n}");
            assert_all_write(&d, &by_hand, &format!("{n} bytes"));
        }
    }

    /// Every `session_id` length from 0 to 1024 bytes, over all of ASCII
    /// (NUL and controls included), and runs of 2-, 3- and 4-byte characters,
    /// each with arrays that change with the length: the encoder and `bincode`
    /// agree on all of them.
    #[cfg(feature = "std")]
    #[test]
    fn agrees_with_bincode_across_lengths_and_characters() {
        for n in 0..=1024usize {
            let session_id: String = (0..n).map(|i| char::from((i % 128) as u8)).collect();
            let k = n as u8;
            let d = digest(
                &session_id,
                [
                    bytes32(|i| i.wrapping_add(k)),
                    bytes32(|i| i.wrapping_mul(k)),
                    bytes32(|i| i ^ k),
                    bytes32(|i| k.wrapping_sub(i)),
                ],
            );
            let by_hand = digest_bytes_by_hand(&d);
            assert_eq!(by_hand.len(), 8 + n + 128, "{n}");
            assert_eq!(by_hand, bincode::serialize(&d).unwrap(), "{n} ASCII bytes");
        }
        for c in ['\u{e9}', '\u{65e5}', '\u{1f980}'] {
            for count in 0..=300usize {
                let d = digest(&c.to_string().repeat(count), [[c as u8; 32]; 4]);
                assert_eq!(
                    digest_bytes_by_hand(&d),
                    bincode::serialize(&d).unwrap(),
                    "{count} x {c:?}"
                );
            }
        }
    }
}
