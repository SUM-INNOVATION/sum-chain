//! Executable contract proof (venue-only) that the pinned SP1 Groth16 terminal
//! verifier consumes exactly `GROTH16_VK_BYTES` and no omitted immutable blob.
//!
//! The proof fixture is a genuine minimal SP1 Groth16 proof produced in the
//! venue and pointed to by `SP1_G16_FIXTURE` (path to a JSON bundle with
//! proof/public-values/vkey-hash). It is TEST_ONLY / NON_SELECTION /
//! INVALID_FOR_R0 / NOT_AN_OFFICIAL_GUEST — its guest identity must never enter
//! the normative artifact. Without the fixture the test is skipped, never faked.

use std::path::PathBuf;

fn fixture() -> Option<PathBuf> {
    std::env::var_os("SP1_G16_FIXTURE").map(PathBuf::from)
}

#[test]
fn groth16_verify_consumes_the_extracted_vk_and_rejects_mutation() {
    let Some(path) = fixture() else {
        eprintln!("SKIP: set SP1_G16_FIXTURE to a genuine venue-produced TEST_ONLY bundle");
        return;
    };
    let raw = std::fs::read(&path).expect("read fixture");
    let f: serde_json::Value = serde_json::from_slice(&raw).expect("parse fixture");
    // Fixture must be self-labeled non-selection so it can never be mistaken for
    // official evidence.
    let stamp = f["stamp"].as_array().expect("stamp");
    for s in [
        "TEST_ONLY",
        "NON_SELECTION",
        "INVALID_FOR_R0",
        "NOT_AN_OFFICIAL_GUEST",
    ] {
        assert!(stamp.iter().any(|v| v == s), "fixture missing stamp {s}");
    }

    let proof = hexbytes(&f["proof_hex"]);
    let public_values = hexbytes(&f["public_values_hex"]);
    let vkey_hash = f["vkey_hash"].as_str().expect("vkey_hash").to_string();
    let vk: &[u8] = sp1_verifier::GROTH16_VK_BYTES.as_ref();

    // 1. genuine verification succeeds with the extracted vk
    sp1_verifier::Groth16Verifier::verify(&proof, &public_values, &vkey_hash, vk)
        .expect("valid Groth16 proof must verify against GROTH16_VK_BYTES");

    // 2. mutating the immutable vk material breaks verification -> the material
    //    is genuinely consumed (nothing omitted stands in for it).
    let mut vk_mut = vk.to_vec();
    vk_mut[0] ^= 0x01;
    assert!(
        sp1_verifier::Groth16Verifier::verify(&proof, &public_values, &vkey_hash, &vk_mut).is_err(),
        "mutated vk must fail; proves GROTH16_VK_BYTES is the consumed material"
    );

    // 3. mutating the proof/public values also fails (sanity)
    let mut proof_mut = proof.clone();
    proof_mut[proof_mut.len() / 2] ^= 0x01;
    assert!(
        sp1_verifier::Groth16Verifier::verify(&proof_mut, &public_values, &vkey_hash, vk).is_err(),
        "mutated proof must fail"
    );
}

fn hexbytes(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
