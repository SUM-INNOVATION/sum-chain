//! SP1 verifier-material extractor (venue-only).
//!
//! NOT_YET_REPRODUCED off-venue: this binary compiles and runs only where
//! `sp1-verifier = 6.3.1` is present (the pinned container). It emits a
//! `VerifierMaterialManifestV1` for the SP1 candidate by READING the immutable
//! Groth16 verifying key bytes directly from the pinned crate — no bytes are
//! hardcoded, inferred, or fabricated.
//!
//! The single immutable non-code artifact the SP1 Groth16 terminal verifier
//! consumes is `sp1_verifier::GROTH16_VK_BYTES` (role `groth16_vk`, label
//! `GROTH16_VK_BYTES`). `tests/contract.rs` proves, executably, that
//! `Groth16Verifier::verify` consumes exactly that material and that no other
//! omitted immutable blob is required.

// Frozen B0-PRE domain for the verifier-material manifest identity. Must equal
// b0-pre-validator `tags::VERIFIER_MATERIAL_TAG` ("SUMCHAIN/B0PRE/VMAT/v1"); the
// venue independently re-derives and cross-checks this.
const VMAT_TAG_ASCII: &str = "SUMCHAIN/B0PRE/VMAT/v1";

fn vmat_tag32() -> [u8; 32] {
    let mut t = [0u8; 32];
    let b = VMAT_TAG_ASCII.as_bytes();
    t[..b.len()].copy_from_slice(b);
    t
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn main() {
    // READ the immutable Groth16 vk bytes from the pinned crate.
    let vk: &[u8] = sp1_verifier::GROTH16_VK_BYTES.as_ref();
    let entry_digest = blake3::hash(vk);

    // Manifest identity = single-self-domain BLAKE3(VMAT_TAG ‖ canonical body).
    // Body binds candidate/role/label/length/digest deterministically.
    let mut body = Vec::new();
    body.extend_from_slice(b"Sp1\0");
    body.extend_from_slice(b"groth16_vk\0");
    body.extend_from_slice(b"GROTH16_VK_BYTES\0");
    body.extend_from_slice(&(vk.len() as u64).to_le_bytes());
    body.extend_from_slice(entry_digest.as_bytes());
    let mut h = blake3::Hasher::new();
    h.update(&vmat_tag32());
    h.update(&body);
    let identity = h.finalize();

    let manifest = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0"],
        "candidate_id": "Sp1",
        "manifest_schema": "VerifierMaterialManifestV1",
        "entries": [{
            "role": "groth16_vk",
            "label": "GROTH16_VK_BYTES",
            "byte_length": vk.len(),
            "blake3": hex(entry_digest.as_bytes()),
        }],
        "total_bytes": vk.len(),
        "manifest_identity_blake3": hex(identity.as_bytes()),
        "domain": VMAT_TAG_ASCII,
        "note": "bytes read from sp1_verifier::GROTH16_VK_BYTES; not fabricated",
    });
    println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
}
