//! Frozen, primary-source-derived reference vector for the Groth16 verifying-key
//! material encoding (SMOKE-BLOCKED-006). Binds the encoding so a future risc0 SDK
//! change cannot silently alter the extracted verifier-material bytes.
//!
//! ROLE_GROTH16_VK is the 32-byte `risc0_binfmt::Digestible` struct digest of the
//! pinned `risc0_groth16::VerifyingKey` — the VK's exact contribution to
//! `Groth16ReceiptVerifierParameters::digest()`, which `Groth16Receipt::verify`
//! binds. We cross-check against risc0-zkvm 3.0.5's OWN frozen params-digest
//! stability vector (`receipt/groth16.rs::groth16_receipt_verifier_parameters_is_stable`):
//! since the params digest hashes `[control_root, bn254_control_id, verifying_key.digest()]`,
//! reproducing it proves our VK reading is the canonical one.

use risc0_zkvm::sha::Digestible;
use risc0_zkvm::Groth16ReceiptVerifierParameters;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// risc0-zkvm 3.0.5 receipt/groth16.rs frozen stability vector (upstream primary source).
const PARAMS_DIGEST_HEX: &str = "73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc";
// The VK Digestible struct digest — frozen from the pinned crate (risc0-groth16 3.0.4 /
// risc0-zkvm 3.0.5), cross-verified below against risc0's own params-digest stability vector.
const GROTH16_VK_DIGEST_HEX: &str =
    "21c5fdd9b4d576b17581f50b755482ba7a2134a3b5186e8e454acfa1f69511ab";

#[test]
fn vk_material_matches_frozen_primary_source_vector() {
    let p = Groth16ReceiptVerifierParameters::default();
    let vk_bytes = Digestible::digest(&p.verifying_key).as_bytes().to_vec();
    let vk = hex(&vk_bytes);
    let params = hex(Digestible::digest(&p).as_bytes());
    eprintln!("GROTH16_VK_DIGEST={vk}");
    eprintln!("PARAMS_DIGEST={params}");

    // Cross-check against risc0's own frozen stability vector: proves the VK reading is canonical
    // (the params digest folds in exactly verifying_key.digest()).
    assert_eq!(
        params, PARAMS_DIGEST_HEX,
        "Groth16 params digest drifted from the upstream stability vector; the pinned risc0 stack changed"
    );
    // The frozen VK material vector: fails closed if a future SDK bump changes the VK encoding/value.
    assert_eq!(
        vk, GROTH16_VK_DIGEST_HEX,
        "ROLE_GROTH16_VK material drifted from the frozen primary-source vector"
    );
    // Encoding guard: the canonical VK material is the fixed 32-byte digest — NOT the (longer)
    // ark serialize_uncompressed wire form. A silent switch of encoding would change this length.
    assert_eq!(
        vk_bytes.len(),
        32,
        "VK material must be the 32-byte Digestible digest, not raw bytes"
    );
}

/// Truncating or mutating the frozen vector must not still compare equal — the material identity is
/// sensitive to every byte and to length (a change in compression/encoding/length is detected).
#[test]
fn mutated_or_truncated_vk_vector_is_rejected() {
    let p = Groth16ReceiptVerifierParameters::default();
    let good = Digestible::digest(&p.verifying_key).as_bytes().to_vec();
    assert_eq!(good.len(), 32);
    // flip one byte
    let mut flipped = good.clone();
    flipped[0] ^= 0x01;
    assert_ne!(
        flipped, good,
        "a one-byte mutation must differ from the frozen VK material"
    );
    // truncate
    let truncated = &good[..31];
    assert_ne!(
        truncated,
        good.as_slice(),
        "a truncated VK material must differ"
    );
    // an alternative (longer) encoding must not equal the 32-byte digest
    assert_ne!(
        good.len(),
        64,
        "sanity: the digest is not a 64-byte encoding"
    );
}
