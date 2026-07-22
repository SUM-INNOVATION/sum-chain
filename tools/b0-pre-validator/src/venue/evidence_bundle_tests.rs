// Adversarial + structural tests for the sealed, hashed, immutable per-arch
// evidence bundle (Blocker 1 + 7 + the Blocker 8 platform binding).
use super::*;
use crate::venue::lock_provenance::{recompute_lock_hash, IN_CONTAINER_ORIGIN};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmpdir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-evbundle-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bh(label: &str) -> String {
    crate::venue::to_hex(blake3::hash(label.as_bytes()).as_bytes())
}
fn oci(label: &str) -> String {
    format!("sha256:{}", bh(label))
}

const COMMIT: &str = "abcdef0123456789abcdef0123456789abcdef01"; // 40-hex, not all-zero

fn oci_arch_of(arch: &str) -> &'static str {
    if arch == "X86_64" {
        "amd64"
    } else {
        "arm64"
    }
}

/// The tool names each candidate declares (mirrors the frozen pins).
fn candidate_tools(candidate: &str) -> Vec<(&'static str, &'static str)> {
    match candidate {
        "Sp1" => vec![("sp1-verifier", "6.3.1")],
        _ => vec![("risc0-zkvm", "3.0.5"), ("risc0-groth16", "3.0.4")],
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
}

/// Write a COMPLETE, internally-consistent per-arch bundle directory (unsealed).
fn write_bundle_files(dir: &Path, arch: &str) {
    let material = crate::schema::stage6::test_only_venue_outputs();
    for c in ["Sp1", "Risc0"] {
        let lc = c.to_lowercase();
        let builder_digest = oci(&format!("builder-{lc}-{arch}"));
        let base_digest = oci(&format!("base-{lc}-{arch}"));

        // container: base + builder OciBuild (builder carries platform + media type).
        let builds = serde_json::json!([
            {
                "candidate": c, "role": "base", "arch": arch,
                "build1_digest": base_digest, "build2_digest": base_digest,
                "base_image_ref": format!("registry.test/{lc}/base:pinned"),
                "base_image_digest": base_digest,
                "builder_oci_ref": format!("oci:local/b0pre-{lc}-{arch}"),
                "builder_oci_digest": builder_digest,
                "source_commit": COMMIT,
                "command_log_blake3": bh(&format!("base-cmd-{lc}-{arch}")),
                "raw_output_blake3": bh(&format!("base-out-{lc}-{arch}")),
            },
            {
                "candidate": c, "role": "builder", "arch": arch,
                "build1_digest": builder_digest, "build2_digest": builder_digest,
                "base_image_ref": format!("registry.test/{lc}/base:pinned"),
                "base_image_digest": base_digest,
                "builder_oci_ref": format!("oci:local/b0pre-{lc}-{arch}"),
                "builder_oci_digest": builder_digest,
                "source_commit": COMMIT,
                "command_log_blake3": bh(&format!("builder-cmd-{lc}-{arch}")),
                "raw_output_blake3": bh(&format!("builder-out-{lc}-{arch}")),
                "platform_architecture": oci_arch_of(arch),
                "platform_os": "linux",
                "media_type": "application/vnd.oci.image.manifest.v1+json",
            },
        ]);
        write(dir, &container_file(c), serde_json::to_vec(&builds).unwrap().as_slice());

        // native
        let native = serde_json::json!([{ "candidate": c, "arch": arch, "host_arch": arch }]);
        write(dir, &native_file(c), serde_json::to_vec(&native).unwrap().as_slice());

        // lock + provenance
        let lock_bytes = format!("# {c} in-container Cargo.lock ({arch})\nversion = 3\n").into_bytes();
        write(dir, &lock_file(c), &lock_bytes);
        let lock_hash = recompute_lock_hash(&lock_bytes);
        let prov = serde_json::json!({
            "candidate": c, "arch": arch, "origin": IN_CONTAINER_ORIGIN,
            "container_digest": builder_digest,
            "source_commit": COMMIT,
            "command_log_blake3_hex": bh(&format!("lockcmd-{lc}-{arch}")),
            "lock_blake3_hex": lock_hash,
        });
        write(dir, &lock_prov_file(c), serde_json::to_vec_pretty(&prov).unwrap().as_slice());

        // stage2 audit (clean graph with the required pinned crates)
        let nodes: Vec<serde_json::Value> = if c == "Sp1" {
            vec![
                serde_json::json!({"name":"sp1","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"p3-field","version":"0.1.0-alpha.1","source":"registry","license":"MIT"}),
            ]
        } else {
            vec![
                serde_json::json!({"name":"risc0-zkvm","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-build","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-groth16","version":"3.0.4","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-zkvm-platform","version":"2.2.2","source":"registry","license":"Apache-2.0"}),
            ]
        };
        let stage2 = serde_json::json!({
            "candidate": c, "arch": arch,
            "lock_blake3_hex": lock_hash,
            "container_digest": builder_digest,
            "source_commit": COMMIT,
            "audit_tool_identity": "cargo-metadata 1.0 + cargo-audit 0.21",
            "advisory_db_snapshot": "rustsec-db@2026-07-01",
            "allowed_licenses": ["MIT","Apache-2.0","MIT OR Apache-2.0"],
            "nodes": nodes,
            "advisories": [],
        });
        write(dir, &stage2_file(c), serde_json::to_vec_pretty(&stage2).unwrap().as_slice());

        // tool bindings (verified == declared; bound to builder + source commit)
        let mut bindings = Vec::new();
        let mut first_installed = String::new();
        for (i, (name, ver)) in candidate_tools(c).into_iter().enumerate() {
            let declared = bh(&format!("artifact-{name}-{ver}"));
            let installed = bh(&format!("installed-{name}-{ver}"));
            if i == 0 {
                first_installed = installed.clone();
            }
            bindings.push(serde_json::json!({
                "candidate": c, "name": name, "version": ver,
                "artifact_identity": format!("https://fixtures.invalid/{name}-{ver}.tar"),
                "checksum_algorithm": "sha256",
                "declared_checksum_hex": declared,
                "verified_artifact_hex": declared,
                "installed_binary_sha256_hex": installed,
                "install_entrypoint": format!("cargo:{name}@{ver}"),
                "container_digest": builder_digest,
                "source_commit": COMMIT,
                "test_only": false,
            }));
        }
        write(dir, &tool_binding_file(c), serde_json::to_vec_pretty(&bindings).unwrap().as_slice());

        // Stage-5 result (SP1 on both arches; RISC0 x86_64 only)
        let want_stage5 = c == "Sp1" || arch == "X86_64";
        if want_stage5 {
            let cases: Vec<serde_json::Value> = crate::venue::stage5::REQUIRED_MUTATION_CASES
                .iter()
                .map(|n| serde_json::json!({"name": n, "expected_rejected": true, "actual_rejected": true}))
                .collect();
            let s5 = serde_json::json!({
                "candidate": c, "arch": arch,
                "fixture_hashes": [{"label":"terminal-proof","blake3_hex": bh(&format!("fx-{lc}-{arch}")),"byte_len": 512}],
                "verifier_identity": format!("pinned-{lc}-verifier@1"),
                "mutation_cases": cases,
                "tool_identity_hex": first_installed,
                "container_digest": builder_digest,
                "source_commit": COMMIT,
                "overall_pass": true,
            });
            write(dir, &stage5_file(c), serde_json::to_vec_pretty(&s5).unwrap().as_slice());
        }
    }

    // verifier material (SP1 both arches, RISC0 x86_64 only) — identical SP1 bytes
    // across arches so cross-arch aggregation agrees.
    write(dir, SP1_MATERIAL, material.sp1_extractor_json.as_bytes());
    if arch == "X86_64" {
        write(dir, RISC0_MATERIAL, material.risc0_extractor_json.as_bytes());
    }
}

/// Write + seal a valid per-arch bundle, returning its dir.
fn sealed_bundle(tag: &str, arch: &str) -> PathBuf {
    let dir = tmpdir(tag);
    write_bundle_files(&dir, arch);
    seal(&dir, arch, COMMIT).expect("seal a complete bundle");
    dir
}

fn rewrite_json<F: FnOnce(&mut serde_json::Value)>(dir: &Path, name: &str, f: F) {
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(dir.join(name), serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

/// Re-seal after mutating a file so the manifest hashes match the new bytes (used to
/// prove a mutation is caught by the RECORD validation, not merely the file hash).
fn reseal(dir: &Path, arch: &str) {
    std::fs::remove_file(dir.join(MANIFEST_FILE)).ok();
    seal(dir, arch, COMMIT).expect("reseal");
}

// ---- Structural: a complete bundle imports and aggregates -------------------

#[test]
fn a_complete_x86_and_arm_bundle_import_and_aggregate() {
    let x86 = sealed_bundle("x86", "X86_64");
    let arm = sealed_bundle("arm", "Aarch64");
    let ix = import_verify(&x86).expect("x86 import");
    let ia = import_verify(&arm).expect("arm import");
    assert_eq!(ix.arch, "X86_64");
    assert_eq!(ia.arch, "Aarch64");
    assert!(ix.risc0_extractor_json.is_some());
    assert!(ia.risc0_extractor_json.is_none());
    assert_eq!(ix.lock_bindings.len(), 2);
    assert_eq!(ix.stage2_reports.len(), 2);
    assert_eq!(ix.stage5_results.len(), 2); // Sp1 + Risc0 on x86
    assert_eq!(ia.stage5_results.len(), 1); // Sp1 only on arm

    let agg = aggregate_imported(&[ix, ia]).expect("typed cross-arch aggregate");
    // the aggregate feeds the existing Stage-6 assembler.
    let v = crate::schema::stage6::test_only_venue_outputs();
    let bundle = crate::schema::stage6::assemble_bundle(
        crate::schema::stage6::AssembleMode::TestOnly,
        &agg.venue.oci_digests_json,
        &agg.venue.sp1_extractor_json,
        &agg.venue.risc0_extractor_json,
        &agg.venue.native_json,
        None,
        &v.sp1_cargo_lock,
        &v.risc0_cargo_lock,
    )
    .expect("assemble from typed aggregate");
    bundle.validate().expect("aggregated bundle validates");
    std::fs::remove_dir_all(&x86).ok();
    std::fs::remove_dir_all(&arm).ok();
}

// ---- Adversarial: unmanifested file rejected --------------------------------

#[test]
fn an_unmanifested_extra_file_is_rejected() {
    let dir = sealed_bundle("unman", "Aarch64");
    // inject an extra file NOT in the sealed manifest.
    write(&dir, "sneaky-extra.json", b"{}");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::UnmanifestedFile { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: tampered file-hash rejected -------------------------------

#[test]
fn a_tampered_file_after_sealing_is_rejected() {
    let dir = sealed_bundle("tamper", "Aarch64");
    // change a file's bytes WITHOUT re-sealing -> the manifest hash no longer matches.
    let lock = lock_file("Sp1");
    let mut bytes = std::fs::read(dir.join(&lock)).unwrap();
    bytes.extend_from_slice(b"# swapped\n");
    std::fs::write(dir.join(&lock), &bytes).unwrap();
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::FileHashMismatch { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: missing stage result rejected -----------------------------

#[test]
fn a_missing_stage5_result_is_rejected() {
    let dir = tmpdir("missing5");
    write_bundle_files(&dir, "X86_64");
    // remove the RISC Zero Stage-5 result before sealing -> seal refuses (missing).
    std::fs::remove_file(dir.join(stage5_file("Risc0"))).unwrap();
    let err = seal(&dir, "X86_64", COMMIT).unwrap_err();
    assert!(matches!(err, EvidenceError::MissingFile { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: cross-arch binding mismatch rejected ----------------------

#[test]
fn a_record_bound_to_the_wrong_arch_is_rejected() {
    let dir = sealed_bundle("archmix", "X86_64");
    // flip a Stage-2 record's arch to aarch64 and reseal so file hashes still match.
    rewrite_json(&dir, &stage2_file("Sp1"), |v| {
        v["arch"] = serde_json::json!("Aarch64");
    });
    reseal(&dir, "X86_64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::ArchBinding { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_record_bound_to_the_wrong_source_commit_is_rejected() {
    let dir = sealed_bundle("commitmix", "Aarch64");
    rewrite_json(&dir, &lock_prov_file("Risc0"), |v| {
        // a different (still valid-shaped) commit than the bundle's.
        v["source_commit"] = serde_json::json!("1234567890123456789012345678901234567890");
    });
    // the lock hash still matches the lock bytes, so re-seal so the FILE hash matches
    // and the SOURCE-COMMIT binding is what fails.
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    // provenance recomputes over the (still-valid) lock; the mismatch is the commit.
    assert!(
        matches!(err, EvidenceError::SourceCommitBinding { .. } | EvidenceError::Lock { .. }),
        "got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: mismatched tool binding rejected --------------------------

#[test]
fn a_tool_binding_whose_verified_hash_lies_is_rejected() {
    let dir = sealed_bundle("toolmix", "Aarch64");
    rewrite_json(&dir, &tool_binding_file("Sp1"), |v| {
        // claim a verified hash that differs from the declared checksum.
        v[0]["verified_artifact_hex"] = serde_json::json!(bh("a-different-artifact"));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Tool { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_tool_binding_bound_to_the_wrong_container_is_rejected() {
    let dir = sealed_bundle("toolcont", "Aarch64");
    rewrite_json(&dir, &tool_binding_file("Risc0"), |v| {
        v[0]["container_digest"] = serde_json::json!(oci("some-other-image"));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::ContainerBinding { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: mutable-file-swap defeated --------------------------------

#[test]
fn a_file_swapped_after_import_cannot_change_aggregation() {
    // import returns an in-memory typed bundle; a later on-disk swap has no effect
    // on the typed aggregation (which never re-reads the directory).
    let x86 = sealed_bundle("swapx86", "X86_64");
    let arm = sealed_bundle("swaparm", "Aarch64");
    let ix = import_verify(&x86).expect("x86 import");
    let ia = import_verify(&arm).expect("arm import");
    // an attacker swaps the SP1 material on disk AFTER import.
    write(&arm, SP1_MATERIAL, b"TAMPERED");
    // the typed aggregate is computed from the imported objects, unaffected.
    let agg = aggregate_imported(&[ix, ia]).expect("aggregate from typed objects");
    assert!(agg.venue.sp1_extractor_json.contains("VerifierMaterialManifestV1"));
    // Item 6: the typed aggregate carries the verified lock BYTES (per candidate) and
    // the authoritative tool identities, so Stage 6 needs no directory copy.
    assert_eq!(agg.locks.len(), 2, "verified lock bytes carried for both candidates");
    // The emitted tool-identities MUST deserialize into the exact struct stage6-assemble
    // consumes ({candidate, rust_version, proof_tools}), grouped per candidate in
    // first-appearance order — otherwise Stage-6 assembly fails on the aggregate output.
    let tools: crate::schema::stage6::ToolIdentitiesFile =
        serde_json::from_str(&agg.tool_identities_json)
            .expect("tool-identities must parse as the stage6 ToolIdentitiesFile input");
    assert_eq!(
        tools.tool_identities.iter().map(|t| t.candidate.as_str()).collect::<Vec<_>>(),
        vec!["Sp1", "Risc0"],
        "tool identities grouped per candidate in first-appearance order"
    );
    assert!(
        tools
            .tool_identities
            .iter()
            .all(|t| t.rust_version == crate::protocol::CANDIDATE_CONTAINER_RUST),
        "each candidate carries the frozen protocol toolchain version"
    );
    assert_eq!(
        tools.tool_identities[1].proof_tools.len(),
        2,
        "Risc0 carries both verified proof tools sourced from its bindings"
    );
    // and re-importing the now-swapped directory fails closed.
    assert!(import_verify(&arm).is_err(), "swapped dir must fail re-import");
    std::fs::remove_dir_all(&x86).ok();
    std::fs::remove_dir_all(&arm).ok();
}

// ---- Adversarial: an incomplete Stage-2 graph is rejected -------------------

#[test]
fn an_incomplete_stage2_graph_is_rejected() {
    let dir = sealed_bundle("graphmix", "Aarch64");
    rewrite_json(&dir, &stage2_file("Risc0"), |v| {
        // drop a required pinned crate -> incomplete graph.
        let nodes = v["nodes"].as_array().unwrap().clone();
        v["nodes"] = serde_json::json!(nodes
            .into_iter()
            .filter(|n| n["name"] != "risc0-groth16")
            .collect::<Vec<_>>());
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Stage2 { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: a Stage-5 result not bound to a verified tool is rejected --

#[test]
fn a_stage5_result_unbound_from_the_tool_is_rejected() {
    let dir = sealed_bundle("s5unbound", "Aarch64");
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        v["tool_identity_hex"] = serde_json::json!(bh("not-the-installed-binary"));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Stage5ToolUnbound { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: a builder build missing its platform proof is rejected -----

#[test]
fn a_builder_build_missing_platform_proof_is_rejected() {
    let dir = sealed_bundle("noplat", "Aarch64");
    rewrite_json(&dir, &container_file("Sp1"), |v| {
        // remove the builder entry's platform_architecture.
        for entry in v.as_array_mut().unwrap() {
            if entry["role"] == "builder" {
                entry.as_object_mut().unwrap().remove("platform_architecture");
            }
        }
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::PlatformBinding { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: a Stage-5 lying overall_pass is rejected ------------------

#[test]
fn a_stage5_lying_overall_pass_is_rejected() {
    let dir = sealed_bundle("s5lie", "X86_64");
    rewrite_json(&dir, &stage5_file("Risc0"), |v| {
        // a mutation the verifier did NOT reject, but overall_pass still claims true.
        v["mutation_cases"][0]["actual_rejected"] = serde_json::json!(false);
    });
    reseal(&dir, "X86_64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Stage5 { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: aarch64 carrying RISC Zero material is refused ------------

#[test]
fn an_aarch64_bundle_carrying_risc0_material_is_refused() {
    let dir = tmpdir("armrisc0");
    write_bundle_files(&dir, "Aarch64");
    // wrongly add RISC Zero material to an aarch64 bundle.
    let material = crate::schema::stage6::test_only_venue_outputs();
    write(&dir, RISC0_MATERIAL, material.risc0_extractor_json.as_bytes());
    // seal refuses the unmanifested extra (RISC0 material is not required on arm).
    let err = seal(&dir, "Aarch64", COMMIT).unwrap_err();
    assert!(matches!(err, EvidenceError::UnmanifestedFile { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: a lock swapped before sealing is caught by provenance ------

#[test]
fn a_swapped_lock_is_caught_by_recomputed_provenance() {
    let dir = tmpdir("lockswap");
    write_bundle_files(&dir, "Aarch64");
    // swap the lock bytes but keep the provenance hash (over the ORIGINAL bytes).
    write(&dir, &lock_file("Sp1"), b"# a different lock\nversion = 3\n");
    seal(&dir, "Aarch64", COMMIT).expect("seals (hashes the new bytes)");
    let err = import_verify(&dir).unwrap_err();
    // the provenance hash no longer matches the (swapped) exported bytes.
    assert!(matches!(err, EvidenceError::Lock { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}
