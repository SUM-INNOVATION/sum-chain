use b0_pre_validator::venue::canonical_sp1_guest_artifact::CanonicalSp1GuestArtifactV1;
const REAL_ADDR: &str = "8b063fdb061177f814ad33a21ac596b1b51b874ec871bb8d9de188721397312c";
const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
#[test]
fn real_canonical_artifact_recomputes_and_verifies() {
    let bytes = include_bytes!("fixtures/real_canonical_sp1_guest.json");
    let a = CanonicalSp1GuestArtifactV1::from_json(bytes).expect("parse real canonical artifact");
    assert_eq!(a.address, REAL_ADDR, "fixture drifted");
    assert_eq!(
        a.recompute_address(),
        REAL_ADDR,
        "Rust preimage != producer python preimage"
    );
    a.verify(MEASURED).expect("verify real canonical artifact");
}

use b0_pre_validator::guest_set::{verify_canonical_sp1_guest_artifact, GuestIdentityRecord};

fn rec(cand: &str, arch: &str, canon: &str, pid: &str, gih: &str) -> GuestIdentityRecord {
    serde_json::from_value(serde_json::json!({
        "candidate": cand, "arch": arch,
        "source_commit": "507281e21e95a6a98e3480e25e12d1baab586e07",
        "clean_tree": true,
        "guest_source_tree_hash": "1".repeat(64), "candidate_dep_lock_hash": "2".repeat(64),
        "guest_image_hash": gih, "program_id": pid,
        "builder_container_digest": "3".repeat(64), "toolchain_identity": "4".repeat(64),
        "verifier_material_manifest_hash": "5".repeat(64), "build_command_hash": "6".repeat(64),
        "production_binary_blake3": "7".repeat(64), "real_backend": true, "real_guest_embedded": true,
        "b0_pre_spec_hash": "8".repeat(64), "tooling_commit": "a".repeat(40),
        "tooling_pathset_blake3": "f".repeat(64),
        "canonical_sp1_guest_artifact_address": canon,
    }))
    .unwrap()
}

// v8: measure-produce / sealed-import re-decode the ONE canonical artifact from its retained bytes and
// require every SP1 record to reference EXACTLY it; the negative controls each refuse.
#[test]
fn canonical_mapping_reverify_and_negative_controls() {
    let man = include_bytes!("fixtures/real_canonical_sp1_guest.json").to_vec();
    let elf = include_bytes!("fixtures/real_canonical_sp1_guest.elf").to_vec();
    let art: serde_json::Value = serde_json::from_slice(&man).unwrap();
    let addr = art["address"].as_str().unwrap();
    let pid = art["program_id"].as_str().unwrap();
    let gih = art["guest_image_hash"].as_str().unwrap();
    let x86 = rec("Sp1", "x86_64", addr, pid, gih);
    let arm = rec("Sp1", "aarch64", addr, pid, gih);

    // valid: both SP1 arches reference exactly the retained artifact.
    assert_eq!(
        verify_canonical_sp1_guest_artifact(&[x86.clone(), arm.clone()], &man, &elf).unwrap(),
        addr
    );
    // changed ELF (single bit) -> refused.
    let mut bad = elf.clone();
    bad[0] ^= 1;
    assert!(verify_canonical_sp1_guest_artifact(&[x86.clone(), arm.clone()], &man, &bad).is_err());
    // a record with a wrong/copied address -> refused.
    let wrong_addr = rec("Sp1", "aarch64", &"0".repeat(64), pid, gih);
    assert!(verify_canonical_sp1_guest_artifact(&[x86.clone(), wrong_addr], &man, &elf).is_err());
    // a record with a changed program_id (ELF unchanged) -> refused (mutual edit / substitution).
    let wrong_pid = rec("Sp1", "aarch64", addr, &"0".repeat(64), gih);
    assert!(verify_canonical_sp1_guest_artifact(&[x86.clone(), wrong_pid], &man, &elf).is_err());
    // a RISC0 record carrying the SP1 artifact address -> refused (cross-candidate).
    let risc0_bad = rec("Risc0", "x86_64", addr, pid, gih);
    assert!(verify_canonical_sp1_guest_artifact(
        &[x86.clone(), arm.clone(), risc0_bad],
        &man,
        &elf
    )
    .is_err());
    // tampered manifest (address rewritten) -> refused (recompute mismatch).
    let mut m2 = art.clone();
    m2["address"] = serde_json::json!("0".repeat(64));
    let man2 = serde_json::to_vec(&m2).unwrap();
    assert!(verify_canonical_sp1_guest_artifact(&[x86, arm], &man2, &elf).is_err());
}
