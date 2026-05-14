//! Wire-fixture parity tests for the OmniNode Stage 6 `InferenceAttestation`
//! handoff.
//!
//! Loads the three reference vectors from the **vendored** fixture at
//! `crates/primitives/tests/fixtures/chain_attestation_vectors.json` and
//! asserts that this crate produces bit-for-bit identical
//! `canonical_digest_bytes`, `signing_input_bytes`, and
//! `signer_address_base58` for each vector. Also verifies the recorded
//! signature against the recorded signer pubkey using the chain's
//! verification path.
//!
//! The fixture is a verbatim copy of OmniNode's Stage 6 deliverable at
//! `OmniNode-Protocol/crates/omni-zkml/tests/fixtures/chain_attestation_vectors.json`.
//! When OmniNode regenerates their vectors with a wire-format change,
//! re-vendor this file and the tests will fail loudly until the chain side
//! is updated to match — that's the design; the OmniNode fixture file is
//! the contract.

use serde::Deserialize;

use sumchain_primitives::address::Address;
use sumchain_primitives::inference_attestation::{
    canonical_digest_bytes, inference_attestation_key, signing_input_bytes,
    verify_attestation_signature, InferenceAttestationDigest,
    InferenceAttestationTxData, DOMAIN_TAG, MAX_SESSION_ID_BYTES,
};

/// Path is resolved at compile time relative to the crate manifest dir, so
/// it works on every machine and in CI without hardcoded absolute paths.
const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/chain_attestation_vectors.json"
);

#[derive(Debug, Deserialize)]
struct Vector {
    session_id: String,
    model_hash: String,
    manifest_root: String,
    response_hash: String,
    proof_root: String,
    verifier_ed25519_seed: String,
    canonical_digest_bytes: String,
    signing_input_bytes: String,
    signature_bytes: String,
    signer_address_base58: String,
    signer_pubkey_hex: String,
}

fn load_vectors() -> Vec<Vector> {
    let raw = std::fs::read_to_string(FIXTURE_PATH).unwrap_or_else(|e| {
        panic!(
            "failed to read vendored Stage 6 fixture at {FIXTURE_PATH}: {e}\n\
             This fixture is tracked in the chain repo at \
             `crates/primitives/tests/fixtures/`. If it's missing, the \
             working tree has been corrupted; restore from git."
        )
    });
    serde_json::from_str(&raw).expect("fixture JSON parses")
}

fn hex32(field: &str, s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap_or_else(|e| panic!("hex decode {field}: {e}"));
    assert_eq!(v.len(), 32, "{field} must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex64(field: &str, s: &str) -> [u8; 64] {
    let v = hex::decode(s).unwrap_or_else(|e| panic!("hex decode {field}: {e}"));
    assert_eq!(v.len(), 64, "{field} must be 64 bytes");
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

fn build_digest(v: &Vector) -> InferenceAttestationDigest {
    InferenceAttestationDigest {
        session_id: v.session_id.clone(),
        model_hash: hex32("model_hash", &v.model_hash),
        manifest_root: hex32("manifest_root", &v.manifest_root),
        response_hash: hex32("response_hash", &v.response_hash),
        proof_root: hex32("proof_root", &v.proof_root),
    }
}

#[test]
fn domain_tag_value_locked() {
    assert_eq!(DOMAIN_TAG, "omninode.inference_attestation.v1");
}

#[test]
fn max_session_id_bytes_locked() {
    assert_eq!(MAX_SESSION_ID_BYTES, 256);
}

#[test]
fn fixture_canonical_digest_bytes_match() {
    for v in load_vectors() {
        let digest = build_digest(&v);
        let actual = canonical_digest_bytes(&digest).expect("encode digest");
        let expected = hex::decode(&v.canonical_digest_bytes)
            .expect("expected canonical_digest_bytes is hex");
        assert_eq!(
            actual, expected,
            "canonical_digest_bytes mismatch for session_id={:?}",
            v.session_id
        );
    }
}

#[test]
fn fixture_signing_input_bytes_match() {
    for v in load_vectors() {
        let digest = build_digest(&v);
        let actual = signing_input_bytes(&digest).expect("compute signing input");
        let expected = hex::decode(&v.signing_input_bytes)
            .expect("expected signing_input_bytes is hex");
        assert_eq!(
            actual, expected,
            "signing_input_bytes mismatch for session_id={:?}",
            v.session_id
        );
    }
}

#[test]
fn fixture_signer_address_derives_from_pubkey() {
    for v in load_vectors() {
        let pubkey = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
        let addr = Address::from_public_key(&pubkey).to_base58();
        assert_eq!(
            addr, v.signer_address_base58,
            "signer_address_base58 mismatch for session_id={:?}",
            v.session_id
        );
    }
}

#[test]
fn fixture_signature_verifies_against_chain_path() {
    for v in load_vectors() {
        let digest = build_digest(&v);
        let signature = hex64("signature_bytes", &v.signature_bytes);
        let pubkey = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
        let tx_data = InferenceAttestationTxData {
            digest,
            verifier_signature: signature,
        };
        verify_attestation_signature(&tx_data, &pubkey).unwrap_or_else(|e| {
            panic!(
                "chain-side signature verification rejected vector \
                 session_id={:?}: {e}",
                v.session_id
            )
        });
    }
}

#[test]
fn signature_verification_rejects_tampered_digest() {
    let v = load_vectors().into_iter().next().expect("at least one vector");
    let mut digest = build_digest(&v);
    digest.model_hash[0] ^= 0xff;
    let signature = hex64("signature_bytes", &v.signature_bytes);
    let pubkey = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
    let tx_data = InferenceAttestationTxData {
        digest,
        verifier_signature: signature,
    };
    let result = verify_attestation_signature(&tx_data, &pubkey);
    assert!(
        result.is_err(),
        "tampered digest must NOT verify against the original signature"
    );
}

#[test]
fn signature_verification_rejects_oversize_session_id() {
    let v = load_vectors().into_iter().next().expect("at least one vector");
    let mut digest = build_digest(&v);
    digest.session_id = "a".repeat(MAX_SESSION_ID_BYTES + 1);
    let signature = hex64("signature_bytes", &v.signature_bytes);
    let pubkey = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
    let tx_data = InferenceAttestationTxData {
        digest,
        verifier_signature: signature,
    };
    let result = verify_attestation_signature(&tx_data, &pubkey);
    assert!(
        matches!(
            result,
            Err(sumchain_primitives::inference_attestation::AttestationError::SessionIdTooLong(_))
        ),
        "oversize session_id must error with SessionIdTooLong, got {result:?}"
    );
}

#[test]
fn tx_type_inference_attestation_ordinal_locked() {
    // Variant index in `TxType` must be 21. If anyone reorders, this fails.
    use sumchain_primitives::transaction::TxType;
    assert_eq!(TxType::InferenceAttestation as u8, 21);
    assert_eq!(TxType::from_byte(21), Some(TxType::InferenceAttestation));
}

/// Locked CF keys for the three reference vectors. Computed once via
/// `inference_attestation_key(session_id, &Address::from_public_key(pubkey))`
/// and pinned here. Any drift in the BLAKE3 domain string, the bincode
/// config, the field order, or `Address::from_public_key` flips one or
/// more of these bytes → red CI → on-disk historical attestations
/// become unreachable. Don't regenerate without a CF schema migration.
const EXPECTED_CF_KEY_HEX: &[(&str, &str)] = &[
    (
        "omninode-stage6-vec-1",
        "26961a74c1476a7e53d3a1d2f92210961b358f27aec7007dbe76bd49d231a6cf",
    ),
    (
        "omninode-stage6-vec-2",
        "ad134f4cb86856b1bc8f1122f3b383854a3eb7cf35d80cdd340ea3731749242e",
    ),
    (
        "omninode-stage6-vec-3-abcdef-0123456789",
        "71b9b2d05abe723e28daf207700479d20892ca358d891f870d73bf814167b312",
    ),
];

#[test]
fn fixture_inference_attestation_storage_key() {
    for v in load_vectors() {
        let pubkey = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
        let verifier_addr = Address::from_public_key(&pubkey);
        let key = inference_attestation_key(&v.session_id, &verifier_addr);
        let actual_hex = hex::encode(key);
        let expected_hex = EXPECTED_CF_KEY_HEX
            .iter()
            .find(|(sid, _)| *sid == v.session_id.as_str())
            .map(|(_, h)| *h)
            .unwrap_or_else(|| panic!("no expected key for session_id={:?}", v.session_id));
        assert_eq!(
            actual_hex, expected_hex,
            "INFERENCE_ATTESTATIONS CF key drift for session_id={:?}. \
             Drift here invalidates every persisted attestation. If this is \
             a deliberate schema change, rotate the keying scheme to a new \
             `InferenceAttestationKeyV2` and add a migration plan.",
            v.session_id
        );
    }
}

#[test]
fn tx_payload_inference_attestation_variant_index_locked() {
    // Bincode tags enum variants by their declaration ordinal. The
    // InferenceAttestation variant must be appended at index 22 (0-based:
    // Transfer=0, Nft=1, …, StorageMetadataV2=21, InferenceAttestation=22).
    // Locking this byte protects every serialized tx already on chain — any
    // reorder of variants ABOVE InferenceAttestation silently re-numbers
    // existing variants and turns historical txs into garbage.
    use sumchain_primitives::transaction::TxPayload;

    let v = load_vectors().into_iter().next().expect("at least one vector");
    let digest = build_digest(&v);
    let signature = hex64("signature_bytes", &v.signature_bytes);
    let payload = TxPayload::InferenceAttestation(InferenceAttestationTxData {
        digest,
        verifier_signature: signature,
    });
    let bytes = bincode::serialize(&payload).expect("payload encodes");
    // bincode default: enum variant tag is u32 little-endian.
    // TxPayload bincode tags (0-based, declaration order):
    //   StorageMetadataV2 = 20, InferenceAttestation = 21.
    // The TxType enum's #[repr(u8)] discriminant also assigns the value 21
    // to InferenceAttestation, but that's a separate enum; the assertion
    // here is purely about TxPayload's bincode wire shape.
    let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(
        tag, 21,
        "TxPayload::InferenceAttestation bincode variant tag must be 21 \
         (declaration ordinal, immediately after StorageMetadataV2 at 20); \
         got {tag}. If this is failing, someone reordered variants above \
         InferenceAttestation — every existing serialized tx would \
         re-decode as the wrong operation."
    );
}
