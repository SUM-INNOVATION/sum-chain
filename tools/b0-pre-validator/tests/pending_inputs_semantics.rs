//! Stage-1 `pending_inputs` coverage semantics (decisions #1/#2/#6): the TEST_ONLY
//! finalizable fixture must satisfy exact 8-entry container coverage, 2 per-candidate
//! locks, 2 per-candidate manifests with per-candidate totals; and every
//! adversarial deviation (empty / incomplete / duplicate / extra / unknown /
//! wrong-domain) must be rejected by `semantic_violations()` so the preimage
//! refuses it.

use b0_pre_validator::enums::{Candidate, VerifierMaterialRole};
use b0_pre_validator::protocol::{
    self, B0PreProtocolV1, ContainerDigest, LockHash, VerifierMaterialManifestRef,
};
use b0_pre_validator::schema::verifier_material::VerifierMaterialManifestV1;
use b0_pre_validator::{protocol_hash, ProtocolHashError};

/// TEST_ONLY synthetic RISC Zero material total these fixtures carry (256+32+32+32).
/// NOT a protocol constant, requirement, limit, preregistered result, or venue
/// acceptance condition — a manifest is only ever checked against its own Σ.
const TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL: u64 = 256 + 32 + 32 + 32;

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn test_only_fixture_has_exact_coverage_and_is_consistent() {
    let p = protocol::test_only_finalizable_artifact();
    assert!(
        p.semantic_violations().is_empty(),
        "{:?}",
        p.semantic_violations()
    );
    assert!(p.is_finalizable());

    let pi = &p.pending_inputs;
    // exactly 8 containers = 2 candidates x 2 roles x 2 arches, each tuple once
    let containers = pi.candidate_container_digests.as_ref().unwrap();
    assert_eq!(containers.len(), 8);
    let mut tuples: Vec<(String, String, String)> = containers
        .iter()
        .map(|c| (c.candidate.clone(), c.role.clone(), c.arch.clone()))
        .collect();
    tuples.sort();
    tuples.dedup();
    assert_eq!(tuples.len(), 8, "all 8 tuples must be distinct");
    // base AND builder are both present for both arches of both candidates
    for cand in ["Sp1", "Risc0"] {
        for role in ["base", "builder"] {
            for arch in ["X86_64", "Aarch64"] {
                assert!(
                    containers
                        .iter()
                        .any(|c| c.candidate == cand && c.role == role && c.arch == arch),
                    "missing ({cand}, {role}, {arch})"
                );
            }
        }
    }

    // 2 locks, one per candidate
    let locks = pi.cargo_lock_hashes.as_ref().unwrap();
    assert_eq!(locks.len(), 2);
    let mut lnames: Vec<&str> = locks.iter().map(|l| l.name.as_str()).collect();
    lnames.sort();
    assert_eq!(lnames, ["Risc0", "Sp1"]);

    // 2 manifests, per-candidate totals: SP1 = 292, RISC0 != 292 (its own Sum)
    let manifests = pi.verifier_material_manifests.as_ref().unwrap();
    assert_eq!(manifests.len(), 2);
    let sp1 = manifests.iter().find(|m| m.candidate == "Sp1").unwrap();
    let risc0 = manifests.iter().find(|m| m.candidate == "Risc0").unwrap();
    assert_eq!(sp1.total_bytes, 292);
    assert_ne!(risc0.total_bytes, 292, "RISC0 must not carry SP1's 292");
    assert_eq!(risc0.total_bytes, TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL);
}

#[test]
fn manifest_hash_hex_is_the_canonical_identity_never_ad_hoc() {
    // The fixture's SP1 manifest_hash_hex must equal the canonical
    // BLAKE3(VerifierMaterialManifestV1::encode()) of the reconstructed manifest,
    // proving no ad-hoc extractor hash was inserted.
    let p = protocol::test_only_finalizable_artifact();
    let sp1_ref = p
        .pending_inputs
        .verifier_material_manifests
        .as_ref()
        .unwrap()
        .iter()
        .find(|m| m.candidate == "Sp1")
        .unwrap();
    // reconstruct the same canonical SP1 manifest the fixture builds
    let sp1 = VerifierMaterialManifestV1::from_canonical(
        Candidate::Sp1,
        [(VerifierMaterialRole::Groth16Vk, 292, [0x71; 32])],
    );
    assert_eq!(sp1_ref.manifest_hash_hex, hex(&sp1.identity().unwrap()));
    // and it is NOT the double-prefixed / body-hash form
    assert_ne!(
        sp1_ref.manifest_hash_hex,
        hex(b0_pre_validator::hashing::prefixed(
            &b0_pre_validator::tags::VERIFIER_MATERIAL_TAG,
            &sp1.encode().unwrap()
        )
        .as_ref())
    );
}

fn tag_ascii(tag: &[u8; 32]) -> String {
    let n = b0_pre_validator::tags::ascii_len(tag);
    String::from_utf8_lossy(&tag[..n]).into_owned()
}

fn with_pending(mutate: impl FnOnce(&mut B0PreProtocolV1)) -> B0PreProtocolV1 {
    let mut p = protocol::test_only_finalizable_artifact();
    mutate(&mut p);
    p
}

#[test]
fn adversarial_coverage_deviations_are_all_rejected() {
    let container = |candidate: &str, role: &str, arch: &str, b: u8| ContainerDigest {
        candidate: candidate.into(),
        role: role.into(),
        arch: arch.into(),
        image_digest: format!("sha256:{}", hex(&[b; 32])),
        domain_ascii: tag_ascii(&b0_pre_validator::tags::CONTAINER_TAG),
    };

    // empty container array
    let a = with_pending(|p| {
        p.pending_inputs.candidate_container_digests = Some(vec![]);
    });
    // empty lock array
    let b = with_pending(|p| {
        p.pending_inputs.cargo_lock_hashes = Some(vec![]);
    });
    // empty manifest array
    let c = with_pending(|p| {
        p.pending_inputs.verifier_material_manifests = Some(vec![]);
    });
    // incomplete: drop one container tuple (7)
    let d = with_pending(|p| {
        p.pending_inputs
            .candidate_container_digests
            .as_mut()
            .unwrap()
            .pop();
    });
    // duplicate: overwrite the last with a copy of the first (still 8, dup tuple)
    let e = with_pending(|p| {
        let v = p
            .pending_inputs
            .candidate_container_digests
            .as_mut()
            .unwrap();
        v[7] = v[0].clone();
    });
    // extra: a 9th container tuple
    let f = with_pending(|p| {
        p.pending_inputs
            .candidate_container_digests
            .as_mut()
            .unwrap()
            .push(container("Sp1", "base", "X86_64", 0x99));
    });
    // unknown arch
    let g = with_pending(|p| {
        p.pending_inputs
            .candidate_container_digests
            .as_mut()
            .unwrap()[0]
            .arch = "riscv".into();
    });
    // wrong domain tag on a container
    let h = with_pending(|p| {
        p.pending_inputs
            .candidate_container_digests
            .as_mut()
            .unwrap()[0]
            .domain_ascii = "WRONG".into();
    });
    // duplicate candidate lock (both Sp1)
    let i = with_pending(|p| {
        p.pending_inputs.cargo_lock_hashes.as_mut().unwrap()[1] = LockHash {
            name: "Sp1".into(),
            blake3_hex: hex(&[0x44; 32]),
            domain_ascii: tag_ascii(&b0_pre_validator::tags::CARGO_LOCK_TAG),
        };
    });
    // extra manifest (3, duplicate candidate)
    let j = with_pending(|p| {
        let v = p
            .pending_inputs
            .verifier_material_manifests
            .as_mut()
            .unwrap();
        v.push(VerifierMaterialManifestRef {
            candidate: "Sp1".into(),
            manifest_hash_hex: hex(&[0x55; 32]),
            total_bytes: 292,
            domain_ascii: tag_ascii(&b0_pre_validator::tags::VERIFIER_MATERIAL_TAG),
        });
    });

    for (name, p) in [
        ("empty_containers", a),
        ("empty_locks", b),
        ("empty_manifests", c),
        ("incomplete_containers", d),
        ("duplicate_container", e),
        ("extra_container", f),
        ("unknown_arch", g),
        ("wrong_domain", h),
        ("duplicate_lock_candidate", i),
        ("extra_manifest", j),
    ] {
        assert!(
            !p.semantic_violations().is_empty(),
            "case `{name}` must produce a semantic violation"
        );
        assert!(
            matches!(
                protocol_hash(&p),
                Err(ProtocolHashError::SemanticViolations(_))
            ),
            "case `{name}` must make the spec-hash preimage refuse"
        );
    }
}

#[test]
fn artifact_and_schema_regenerate_idempotently_and_stay_not_finalizable() {
    // Regenerating from the deterministic frozen model twice is byte-identical,
    // and the artifact stays not_finalizable (no accidental finalization).
    let a = serde_json::to_string_pretty(&B0PreProtocolV1::frozen()).unwrap();
    let b = serde_json::to_string_pretty(&B0PreProtocolV1::frozen()).unwrap();
    assert_eq!(a, b, "frozen artifact serialization must be deterministic");
    let p = B0PreProtocolV1::frozen();
    assert!(!p.is_finalizable());
    assert_eq!(p.finalization.state, "not_finalizable");
    assert!(protocol_hash(&p).is_err());

    let s1 = serde_json::to_string_pretty(&schemars::schema_for!(B0PreProtocolV1)).unwrap();
    let s2 = serde_json::to_string_pretty(&schemars::schema_for!(B0PreProtocolV1)).unwrap();
    assert_eq!(s1, s2, "schema generation must be deterministic");
}

// ---- Item 6: semantic (candidate, role, arch) container coverage ----

/// Index of the container tuple `(candidate, role, arch)` in the fixture, so
/// mutations target a specific tuple regardless of array order.
fn container_index(p: &B0PreProtocolV1, candidate: &str, role: &str, arch: &str) -> usize {
    p.pending_inputs
        .candidate_container_digests
        .as_ref()
        .unwrap()
        .iter()
        .position(|c| c.candidate == candidate && c.role == role && c.arch == arch)
        .unwrap_or_else(|| panic!("fixture missing ({candidate}, {role}, {arch})"))
}

#[test]
fn semantic_tuple_coverage_is_checked_not_array_length() {
    // The validator compares the semantic (candidate, role, arch) set, not merely
    // that the array has eight elements. Every deviation below keeps exactly eight
    // OR fewer/more entries yet must be rejected on coverage grounds.
    let cont = |candidate: &str, role: &str, arch: &str, b: u8| ContainerDigest {
        candidate: candidate.into(),
        role: role.into(),
        arch: arch.into(),
        image_digest: format!("sha256:{}", hex(&[b; 32])),
        domain_ascii: tag_ascii(&b0_pre_validator::tags::CONTAINER_TAG),
    };

    // Each case mutates a fresh finalizable fixture; all must fail coverage.
    type Mut = Box<dyn Fn(&mut B0PreProtocolV1)>;
    let remove = |cand: &'static str, role: &'static str, arch: &'static str| -> Mut {
        Box::new(move |p: &mut B0PreProtocolV1| {
            let i = container_index(p, cand, role, arch);
            p.pending_inputs
                .candidate_container_digests
                .as_mut()
                .unwrap()
                .remove(i);
        })
    };
    let set_field = |cand: &'static str,
                     role: &'static str,
                     arch: &'static str,
                     field: &'static str,
                     val: &'static str|
     -> Mut {
        Box::new(move |p: &mut B0PreProtocolV1| {
            let i = container_index(p, cand, role, arch);
            let v = p
                .pending_inputs
                .candidate_container_digests
                .as_mut()
                .unwrap();
            match field {
                "candidate" => v[i].candidate = val.into(),
                "role" => v[i].role = val.into(),
                "arch" => v[i].arch = val.into(),
                _ => unreachable!(),
            }
        })
    };

    let cases: Vec<(&str, Mut)> = vec![
        // one required tuple absent (array shrinks to 7)
        ("missing_sp1_arm64_base", remove("Sp1", "base", "Aarch64")),
        (
            "missing_risc0_arm64_base",
            remove("Risc0", "base", "Aarch64"),
        ),
        ("missing_sp1_x86_base", remove("Sp1", "base", "X86_64")),
        ("missing_risc0_x86_base", remove("Risc0", "base", "X86_64")),
        ("missing_sp1_builder", remove("Sp1", "builder", "X86_64")),
        // still eight entries, but the coverage set is wrong: a substitution both
        // introduces a duplicate tuple and drops the substituted-away one
        (
            "candidate_substitution",
            set_field("Sp1", "base", "X86_64", "candidate", "Risc0"),
        ),
        (
            "base_builder_substitution",
            set_field("Sp1", "base", "X86_64", "role", "builder"),
        ),
        (
            "architecture_substitution",
            set_field("Sp1", "base", "X86_64", "arch", "Aarch64"),
        ),
        // unknown enum members are rejected outright
        (
            "wrong_candidate",
            set_field("Sp1", "base", "X86_64", "candidate", "Plonky"),
        ),
        (
            "wrong_role",
            set_field("Sp1", "base", "X86_64", "role", "runtime"),
        ),
        (
            "wrong_architecture",
            set_field("Sp1", "base", "X86_64", "arch", "riscv"),
        ),
        // a duplicated tuple that reuses another tuple's digest to try to "hide" a
        // now-missing tuple; the semantic set catches dup + missing regardless
        (
            "reused_digest_hides_missing_tuple",
            Box::new(|p: &mut B0PreProtocolV1| {
                let src = container_index(p, "Sp1", "base", "X86_64");
                let dst = container_index(p, "Sp1", "base", "Aarch64");
                let v = p
                    .pending_inputs
                    .candidate_container_digests
                    .as_mut()
                    .unwrap();
                v[dst] = v[src].clone(); // exact copy, same digest -> dup + missing
            }),
        ),
        // an extra ninth tuple (duplicate of an existing one)
        (
            "extra_ninth_tuple",
            Box::new(move |p: &mut B0PreProtocolV1| {
                p.pending_inputs
                    .candidate_container_digests
                    .as_mut()
                    .unwrap()
                    .push(cont("Sp1", "base", "X86_64", 0x99));
            }),
        ),
    ];

    for (name, mutate) in cases {
        let mut p = protocol::test_only_finalizable_artifact();
        mutate(&mut p);
        assert!(
            !p.semantic_violations().is_empty(),
            "case `{name}` must produce a semantic violation"
        );
        assert!(
            matches!(
                protocol_hash(&p),
                Err(ProtocolHashError::SemanticViolations(_))
            ),
            "case `{name}` must make the spec-hash preimage refuse"
        );
    }
}

#[test]
fn arbitrary_input_order_of_the_complete_set_is_accepted() {
    // The frozen coverage rule is order-independent: reversing the eight correct
    // tuples still satisfies the (candidate, role, arch) set, so the fixture stays
    // finalizable with no semantic violation.
    let mut p = protocol::test_only_finalizable_artifact();
    p.pending_inputs
        .candidate_container_digests
        .as_mut()
        .unwrap()
        .reverse();
    assert!(
        p.semantic_violations().is_empty(),
        "reordering the complete set must remain valid: {:?}",
        p.semantic_violations()
    );
    assert!(p.is_finalizable());
    assert!(protocol_hash(&p).is_ok());
}
