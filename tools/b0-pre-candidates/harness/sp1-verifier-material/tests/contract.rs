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

/// The required-stamp policy is the SHARED one (`b0_pre_vmat::REQUIRED_STAMPS`),
/// the same gate the validator's real fixture-acceptance path applies — no local
/// copy. A fixture missing any one stamp (in particular `NOT_AN_OFFICIAL_GUEST`)
/// is rejected.
fn stamp_strings(stamp: &[serde_json::Value]) -> Vec<String> {
    stamp
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

fn all_required_stamps_present(stamp: &[serde_json::Value]) -> bool {
    b0_pre_vmat::all_required_stamps_present(&stamp_strings(stamp))
}

#[test]
fn three_stamp_fixture_is_rejected_four_stamp_accepted() {
    // A three-stamp fixture (missing NOT_AN_OFFICIAL_GUEST) must fail the shared
    // stamp gate; only the full four-stamp set is accepted.
    let three = serde_json::json!(["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0"]);
    assert!(!all_required_stamps_present(three.as_array().unwrap()));

    let four = serde_json::json!(b0_pre_vmat::REQUIRED_STAMPS);
    assert!(all_required_stamps_present(four.as_array().unwrap()));
}

#[test]
fn each_single_stamp_omission_is_rejected() {
    // Dropping ANY one of the four stamps must fail the shared gate.
    for omit in b0_pre_vmat::REQUIRED_STAMPS {
        let kept: Vec<&str> = b0_pre_vmat::REQUIRED_STAMPS
            .iter()
            .copied()
            .filter(|s| *s != omit)
            .collect();
        let arr = serde_json::json!(kept);
        assert!(
            !all_required_stamps_present(arr.as_array().unwrap()),
            "omitting {omit} must be rejected"
        );
    }
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
    // official evidence: all four stamps required, three-stamp fixtures rejected.
    let stamp = f["stamp"].as_array().expect("stamp");
    assert!(
        all_required_stamps_present(stamp),
        "fixture missing a required stamp (all four, incl. NOT_AN_OFFICIAL_GUEST, are mandatory)"
    );

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
