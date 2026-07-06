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
    canonical_digest_bytes, classify_inference_attestation_status,
    inference_attestation_key, signing_input_bytes, verify_attestation_signature,
    verify_attestation_v2_signature, AttestationError, InferenceAttestationDigest,
    InferenceAttestationTxData, InferenceAttestationV2TxData, DOMAIN_TAG,
    MAX_SESSION_ID_BYTES,
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
    // InferenceAttestation variant is appended at declaration index 21
    // (0-based: Transfer=0, Nft=1, …, StorageMetadataV2=20,
    // InferenceAttestation=21). Locking this byte protects every
    // serialized tx already on chain — any reorder of variants ABOVE
    // InferenceAttestation silently re-numbers existing variants and
    // turns historical txs into garbage.
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

// ─────────────────────────────────────────────────────────────────────────
// Sponsored attestation v2 (issue #79) — append-only ordinals + verification
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn tx_type_inference_attestation_v2_ordinal_locked() {
    use sumchain_primitives::transaction::TxType;
    // v2 appended at 25; v1 unchanged at 21.
    assert_eq!(TxType::InferenceAttestationV2 as u8, 25);
    assert_eq!(TxType::from_byte(25), Some(TxType::InferenceAttestationV2));
    assert_eq!(TxType::InferenceAttestation as u8, 21);
}

#[test]
fn tx_payload_inference_attestation_v2_variant_index_locked() {
    // v2 is appended as the 26th TxPayload variant (declaration ordinal 25),
    // AFTER InferenceSettlement (24). v1 InferenceAttestation stays at 21.
    use sumchain_primitives::transaction::TxPayload;
    let v = load_vectors().into_iter().next().expect("at least one vector");
    let digest = build_digest(&v);
    let payload = TxPayload::InferenceAttestationV2(InferenceAttestationV2TxData {
        digest,
        verifier_public_key: hex32("signer_pubkey_hex", &v.signer_pubkey_hex),
        verifier_signature: hex64("signature_bytes", &v.signature_bytes),
    });
    let bytes = bincode::serialize(&payload).expect("payload encodes");
    let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(
        tag, 25,
        "TxPayload::InferenceAttestationV2 bincode tag must be 25 (appended after \
         InferenceSettlement=24); got {tag}"
    );
}

#[test]
fn v2_signature_verifies_over_same_v1_signing_bytes() {
    // A v2 envelope reuses the exact v1 signing bytes, so every recorded v1
    // vector's (digest, pubkey, signature) validates unchanged as v2 — proving
    // the attestation is an identical commitment regardless of who submits it.
    for v in load_vectors() {
        let tx = InferenceAttestationV2TxData {
            digest: build_digest(&v),
            verifier_public_key: hex32("signer_pubkey_hex", &v.signer_pubkey_hex),
            verifier_signature: hex64("signature_bytes", &v.signature_bytes),
        };
        verify_attestation_v2_signature(&tx)
            .unwrap_or_else(|e| panic!("v2 verify rejected vector {:?}: {e}", v.session_id));
    }
}

#[test]
fn v2_signature_rejects_tampered_and_oversize() {
    let v = load_vectors().into_iter().next().expect("at least one vector");
    let pk = hex32("signer_pubkey_hex", &v.signer_pubkey_hex);
    let sig = hex64("signature_bytes", &v.signature_bytes);

    // Tampered signature → InvalidSignature.
    let mut bad_sig = sig;
    bad_sig[0] ^= 0xff;
    let tampered = InferenceAttestationV2TxData {
        digest: build_digest(&v),
        verifier_public_key: pk,
        verifier_signature: bad_sig,
    };
    assert_eq!(verify_attestation_v2_signature(&tampered), Err(AttestationError::InvalidSignature));

    // Oversize session_id → SessionIdTooLong (dispatch maps this to Failed(55)).
    let mut big = build_digest(&v);
    big.session_id = "a".repeat(MAX_SESSION_ID_BYTES + 1);
    let oversize = InferenceAttestationV2TxData {
        digest: big,
        verifier_public_key: pk,
        verifier_signature: sig,
    };
    assert!(matches!(
        verify_attestation_v2_signature(&oversize),
        Err(AttestationError::SessionIdTooLong(_))
    ));
}

// ─────────────────────────────────────────────────────────────────────────
// classify_inference_attestation_status — pure-function status RPC tests
//
// The classifier lives in `sumchain-primitives` (not in `sumchain-rpc`)
// specifically so these tests can run locally without the rocksdb /
// system-library link chain that `sumchain-rpc`'s test binary requires.
// The `sum_getInferenceAttestationStatus` RPC handler in
// `crates/rpc/src/server.rs` is a thin plumber: it fetches stored tx +
// mempool tx + receipt + current_height + finality_depth from the chain
// and passes them straight through to this function.
// ─────────────────────────────────────────────────────────────────────────

use sumchain_primitives::{Hash, Receipt, SignedTransaction, Transaction, TransactionV2, TxPayload, TxStatus};

/// Build an Ed25519 keypair via `ed25519_dalek` — we keep test crypto
/// dependencies inside the test file so the primitives crate itself
/// doesn't acquire a transitive sign/verify dep for production code.
fn ed25519_keypair_from_seed(seed: [u8; 32]) -> (ed25519_dalek::SigningKey, [u8; 32]) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();
    (sk, pk_bytes)
}

fn ed25519_sign(sk: &ed25519_dalek::SigningKey, message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    sk.sign(message).to_bytes()
}

fn mk_attestation_signed_tx(seed: [u8; 32]) -> SignedTransaction {
    let (sk, pk_bytes) = ed25519_keypair_from_seed(seed);
    let sender_addr = Address::from_public_key(&pk_bytes);
    let digest = InferenceAttestationDigest {
        session_id: "classifier-test-session".to_string(),
        model_hash: [1u8; 32],
        manifest_root: [2u8; 32],
        response_hash: [3u8; 32],
        proof_root: [4u8; 32],
    };
    let signing_input = signing_input_bytes(&digest).unwrap();
    let inner_sig = ed25519_sign(&sk, &signing_input);
    let payload = TxPayload::InferenceAttestation(InferenceAttestationTxData {
        digest,
        verifier_signature: inner_sig,
    });
    let tx = TransactionV2 {
        chain_id: 1,
        from: sender_addr,
        fee: 1_000_000,
        nonce: 0,
        payload,
    };
    let outer_hash = tx.signing_hash();
    let outer_sig = ed25519_sign(&sk, outer_hash.as_bytes());
    SignedTransaction::new_v2(tx, outer_sig, pk_bytes)
}

fn mk_transfer_signed_tx(seed: [u8; 32]) -> SignedTransaction {
    let (sk, pk_bytes) = ed25519_keypair_from_seed(seed);
    let sender_addr = Address::from_public_key(&pk_bytes);
    let recipient_addr = Address::from_public_key(&[7u8; 32]);
    let tx = Transaction::new(1, sender_addr, recipient_addr, 100, 10, 0);
    let h = tx.signing_hash();
    let sig = ed25519_sign(&sk, h.as_bytes());
    SignedTransaction::new(tx, sig, pk_bytes)
}

fn mk_receipt(status: TxStatus, block_height: u64) -> Receipt {
    Receipt::new(Hash::hash(b"tx"), block_height, 0, status, 10)
}

#[test]
fn classifier_unknown_when_no_tx_and_no_mempool() {
    let s = classify_inference_attestation_status(None, None, None, 100, 3);
    assert_eq!(s.status, "unknown");
    assert_eq!(s.included_at_height, None);
    assert_eq!(s.reason, None);
}

#[test]
fn classifier_unknown_when_foreign_tx_payload_type() {
    // Transfer tx in store + Success receipt — but the payload-type guard
    // MUST keep this from leaking as a finalized attestation through the
    // InferenceAttestation-specific status RPC. This is the
    // reviewer-flagged regression in Phase 4 (suggestion 3).
    let foreign = mk_transfer_signed_tx([42u8; 32]);
    let r = mk_receipt(TxStatus::Success, 50);
    let s = classify_inference_attestation_status(Some(&foreign), None, Some(&r), 100, 3);
    assert_eq!(
        s.status, "unknown",
        "foreign tx hash must not surface as included/finalized through the InferenceAttestation status RPC"
    );
    assert_eq!(s.included_at_height, None, "no height leak through the guard");
}

#[test]
fn classifier_submitted_when_only_in_mempool() {
    let att = mk_attestation_signed_tx([1u8; 32]);
    let s = classify_inference_attestation_status(None, Some(&att), None, 100, 3);
    assert_eq!(s.status, "submitted");
}

#[test]
fn classifier_included_when_success_receipt_under_finality_depth() {
    let att = mk_attestation_signed_tx([2u8; 32]);
    let r = mk_receipt(TxStatus::Success, 50);
    // current=51, finality_depth=3 → 51 < 50+3 → included.
    let s = classify_inference_attestation_status(Some(&att), None, Some(&r), 51, 3);
    assert_eq!(s.status, "included");
    assert_eq!(s.included_at_height, Some(50));
}

#[test]
fn classifier_finalized_when_success_receipt_past_finality_depth() {
    let att = mk_attestation_signed_tx([3u8; 32]);
    let r = mk_receipt(TxStatus::Success, 50);
    // current=53, finality_depth=3 → 53 >= 50+3 → finalized.
    let s = classify_inference_attestation_status(Some(&att), None, Some(&r), 53, 3);
    assert_eq!(s.status, "finalized");
    assert_eq!(s.included_at_height, Some(50));
}

#[test]
fn classifier_failed_carries_description() {
    let att = mk_attestation_signed_tx([4u8; 32]);
    let r = mk_receipt(TxStatus::Failed(51), 50);
    let s = classify_inference_attestation_status(Some(&att), None, Some(&r), 100, 3);
    assert_eq!(s.status, "failed");
    assert_eq!(s.included_at_height, Some(50));
    // reason carries TxStatus::description() — must reference the
    // failure code's meaning (`Failed(51)` = duplicate attestation).
    assert!(s.reason.unwrap().contains("duplicate"));
}

#[test]
fn classifier_receipt_takes_precedence_over_mempool() {
    // A receipt-bearing attestation that's ALSO still in the mempool
    // (the prune-lag window) must classify by receipt, not mempool.
    // Otherwise `included`/`finalized` would regress to `submitted`.
    // This is the reviewer-flagged regression in Phase 4 (issue 2).
    let att = mk_attestation_signed_tx([5u8; 32]);
    let r = mk_receipt(TxStatus::Success, 50);
    let s = classify_inference_attestation_status(Some(&att), Some(&att), Some(&r), 100, 3);
    assert_eq!(
        s.status, "finalized",
        "receipt-first precedence: mempool presence must not downgrade a finalized status"
    );
}
