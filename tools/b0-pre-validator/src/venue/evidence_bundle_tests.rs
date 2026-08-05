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
                serde_json::json!({"name":"sp1-sdk","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"sp1-verifier","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"sp1-build","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"sp1-zkvm","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"p3-field","version":"0.1.0-alpha.1","source":"registry","license":"MIT"}),
            ]
        } else {
            vec![
                serde_json::json!({"name":"risc0-zkvm","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-build","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-groth16","version":"3.0.4","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-zkvm-platform","version":"2.2.3","source":"registry","license":"Apache-2.0"}),
            ]
        };
        let stage2 = serde_json::json!({
            "schema_version": crate::venue::audit::STAGE2_SCHEMA_VERSION,
            "candidate": c, "arch": arch,
            "lock_blake3_hex": lock_hash,
            "container_digest": builder_digest,
            "source_commit": COMMIT,
            "command_log_blake3_hex": bh(&format!("stage2cmd-{c}-{arch}")),
            "audit_tool_identity": "cargo-metadata 1.0 + cargo-audit 0.22.2",
            "cargo_audit_version": "0.22.2",
            "cargo_audit_executable_sha256": bh(&format!("ca-{c}-{arch}")),
            "advisory_db": {"commit": "a".repeat(40), "git_tree": "b".repeat(40), "content_blake3": bh("advdb")},
            "audit_policy": {"database_update_allowed": false, "stale_snapshot_permitted": true, "output_format": "json", "database_source": "runtime-read-only-mount"},
            "allowed_licenses": ["MIT","Apache-2.0","MIT OR Apache-2.0"],
            "nodes": nodes,
            "advisories": [],
        });
        write(dir, &stage2_file(c), serde_json::to_vec_pretty(&stage2).unwrap().as_slice());

        // third-party notices + sealed target-closure from this candidate's (empty-graph) lock.
        let closure = crate::venue::third_party_notices::TargetClosure {
            schema_version: crate::venue::third_party_notices::TARGET_CLOSURE_SCHEMA_VERSION,
            candidate: c.to_string(),
            arch: arch.to_string(),
            venue_targets: vec!["x86_64-unknown-linux-gnu".to_string()],
            features: vec![],
            lock_blake3_hex: lock_hash.clone(),
            stage2_graph_blake3_hex: lock_hash.clone(),
            roots: vec!["synthetic-root\u{1f}0.0.0\u{1f}".to_string()],
            nodes: vec![crate::venue::third_party_notices::ClosureNode {
                name: "synthetic-root".to_string(),
                version: "0.0.0".to_string(),
                source: String::new(),
                checksum: None,
                normal_deps: vec![],
            }],
        };
        let notices = crate::venue::third_party_notices::generate(
            c,
            arch,
            &lock_hash,
            std::str::from_utf8(&lock_bytes).unwrap(),
            std::path::Path::new("/nonexistent-vendor-root-empty-graph"),
            None,
            Some(&closure),
        )
        .unwrap();
        write(dir, &notices_file(c), serde_json::to_vec_pretty(&notices).unwrap().as_slice());
        write(dir, &notices_closure_file(c), serde_json::to_vec_pretty(&closure).unwrap().as_slice());

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
        // Tool binding: SP1 on both arches; RISC Zero x86_64 ONLY (VENUE.md §2 — there is
        // no aarch64 RISC Zero toolchain to install and bind).
        if c == "Sp1" || arch == "X86_64" {
            write(dir, &tool_binding_file(c), serde_json::to_vec_pretty(&bindings).unwrap().as_slice());
        }

        // Stage-5 result (SP1 on both arches; RISC0 x86_64 only)
        let want_stage5 = c == "Sp1" || arch == "X86_64";
        if want_stage5 {
            let cases: Vec<serde_json::Value> = crate::venue::stage5::REQUIRED_MUTATION_CASES
                .iter()
                .map(|n| serde_json::json!({"name": n, "expected_rejected": true, "actual_rejected": true}))
                .collect();
            let (sdk_name, sdk_ver) = if c == "Sp1" {
                ("sp1-verifier", "6.3.1")
            } else {
                ("risc0-zkvm", "3.0.5")
            };
            let runner_lock = crate::venue::cargo_lock::synthetic_runner_lock(sdk_name, sdk_ver);
            let runner_lock_hash =
                crate::venue::lock_provenance::recompute_lock_hash(runner_lock.as_bytes());
            write(dir, &stage5_runner_lock_file(c), runner_lock.as_bytes());
            let s5 = serde_json::json!({
                "schema_version": crate::venue::stage5::STAGE5_SCHEMA_VERSION,
                "candidate": c, "arch": arch,
                "fixture_hashes": [{"label":"terminal-proof","blake3_hex": bh(&format!("fx-{lc}-{arch}")),"byte_len": 512}],
                "verifier_identity": format!("{sdk_name} {sdk_ver} terminal (descriptive)"),
                "mutation_cases": cases,
                "verifier_executed_binary_sha256": bh(&format!("runbin-{lc}-{arch}")),
                "verifier_sdk_lock_blake3": runner_lock_hash,
                "verifier_sdk_name": sdk_name,
                "verifier_sdk_version": sdk_ver,
                "container_digest": builder_digest,
                "source_commit": COMMIT,
                "command_log_blake3_hex": bh(&format!("stage5cmd-{lc}-{arch}")),
                "overall_pass": true,
            });
            let _ = &first_installed;
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
    // SP1 is the candidate that carries a tool binding on aarch64; RISC Zero does not
    // (VENUE.md §2). The equivalent RISC Zero case is covered on x86_64 below.
    let dir = sealed_bundle("toolcont", "Aarch64");
    rewrite_json(&dir, &tool_binding_file("Sp1"), |v| {
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

#[test]
fn a_bundle_missing_third_party_notices_is_rejected_at_seal() {
    // A bundle that cannot produce a candidate's third-party notice manifest is refused at seal
    // (exact required-file set), so it can never import and therefore never finalize.
    let dir = sealed_bundle("notices_missing", "Aarch64");
    std::fs::remove_file(dir.join(notices_file("Risc0"))).unwrap();
    std::fs::remove_file(dir.join(MANIFEST_FILE)).ok();
    let err = seal(&dir, "Aarch64", COMMIT).unwrap_err();
    assert!(
        matches!(err, EvidenceError::MissingFile { .. }),
        "a bundle missing third-party notices must be refused at seal; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_notice_manifest_bound_to_the_wrong_lock_is_rejected() {
    // Re-binding the notice manifest to a different lock hash (a notice set generated for another
    // graph) is refused: notices are useless unless bound to THIS candidate's resolved lock.
    let dir = sealed_bundle("notices_wrong_lock", "Aarch64");
    rewrite_json(&dir, &notices_file("Sp1"), |v| {
        v["lock_blake3_hex"] = serde_json::json!("f".repeat(64));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Notices { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_notice_manifest_with_a_crate_not_in_the_lock_is_rejected() {
    // An extra notice entry not present in the sealed lock is refused (fail closed both ways: the
    // covered set must EQUAL the lock's third-party set, no phantom coverage).
    let dir = sealed_bundle("notices_extra", "Aarch64");
    rewrite_json(&dir, &notices_file("Sp1"), |v| {
        let entries = v["entries"].as_array_mut().unwrap();
        entries.push(serde_json::json!({
            "name": "phantom-crate",
            "version": "9.9.9",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "spdx": "MIT",
            "notice_source": "crate-file",
            "notices": [{"path": "LICENSE", "sha256": crate::venue::sha256::hex_digest(b"x"), "text": "x"}],
        }));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Notices { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_bundle_missing_target_closure_is_rejected_at_seal() {
    // A bundle that cannot produce a candidate's target-closure record is refused at seal, so the
    // not-redistributed classification can never go unverified.
    let dir = sealed_bundle("closure_missing", "Aarch64");
    std::fs::remove_file(dir.join(notices_closure_file("Risc0"))).unwrap();
    std::fs::remove_file(dir.join(MANIFEST_FILE)).ok();
    let err = seal(&dir, "Aarch64", COMMIT).unwrap_err();
    assert!(
        matches!(err, EvidenceError::MissingFile { .. }),
        "a bundle missing the target closure must be refused at seal; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_target_closure_unbound_from_lock_or_stage2_is_rejected() {
    // Re-binding the closure to a different lock is refused (the closure could otherwise be swapped).
    let dir = sealed_bundle("closure_lock", "Aarch64");
    rewrite_json(&dir, &notices_closure_file("Sp1"), |v| {
        v["lock_blake3_hex"] = serde_json::json!("f".repeat(64));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Notices { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();

    // Re-binding to a different Stage-2 graph identity is refused.
    let dir2 = sealed_bundle("closure_s2", "Aarch64");
    rewrite_json(&dir2, &notices_closure_file("Sp1"), |v| {
        v["stage2_graph_blake3_hex"] = serde_json::json!("e".repeat(64));
    });
    reseal(&dir2, "Aarch64");
    let err2 = import_verify(&dir2).unwrap_err();
    assert!(matches!(err2, EvidenceError::Notices { .. }), "got {err2}");
    std::fs::remove_dir_all(&dir2).ok();
}

// ---- Adversarial: an unbound OPTIONAL proof-producer identity is rejected ----
// (v2: the verifier identity is self-contained/causal; only the optional upstream
// proof_producer_tool_identity, when present, must reference a verified tool binding.)

#[test]
fn a_stage5_optional_proof_producer_unbound_from_a_tool_is_rejected() {
    let dir = sealed_bundle("s5unbound", "Aarch64");
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        v["proof_producer_tool_identity"] =
            serde_json::json!(bh("not-the-installed-binary"));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(matches!(err, EvidenceError::Stage5ToolUnbound { .. }), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: an inadequate v1 (unversioned) Stage-5 record is refused for
// authoritative import (its non-causal installed-CLI attribution is insufficient). ----

#[test]
fn a_v1_unversioned_stage5_record_is_rejected_as_inadequate() {
    let dir = sealed_bundle("s5v1", "Aarch64");
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        // Downgrade to a v1-shaped record: drop the schema_version + the causal verifier
        // bindings, reintroduce the old installed-CLI tool_identity_hex.
        let obj = v.as_object_mut().unwrap();
        obj.remove("schema_version");
        obj.remove("verifier_executed_binary_sha256");
        obj.remove("verifier_sdk_lock_blake3");
        obj.remove("verifier_sdk_name");
        obj.remove("verifier_sdk_version");
        obj.insert("tool_identity_hex".into(), serde_json::json!(bh("installed-cli")));
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(
        matches!(err, EvidenceError::Stage5 { .. }),
        "a v1 Stage-5 record must be refused as inadequate for authoritative import; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Adversarial: sealed verifier-runner-lock binding negatives (S1 v2) ------
// The Stage-5 record's verifier_sdk_lock_blake3 must equal the domain-separated hash of
// the SEALED runner lock, which must structurally pin the declared SDK from a registry
// source with a checksum. Each mutation below is content-addressed and re-sealed, so the
// manifest is internally consistent and the RECORD/lock cross-check is what rejects it.

#[test]
fn an_altered_runner_lock_is_rejected_by_hash_recompute() {
    let dir = sealed_bundle("rl_altered", "Aarch64");
    // Replace the sealed runner lock with a DIFFERENT (still valid-shaped) lock; the
    // record's verifier_sdk_lock_blake3 now no longer matches the recomputed hash.
    let other = crate::venue::cargo_lock::synthetic_runner_lock("sp1-verifier", "6.3.1")
        + "\n# tampered trailer changes the bytes + hash\n";
    write(&dir, &stage5_runner_lock_file("Sp1"), other.as_bytes());
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(
        matches!(&err, EvidenceError::Stage5 { error, .. } if error.contains("runner lock hash mismatch")),
        "altered runner lock must fail the domain-separated hash recompute; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_wrong_sdk_version_in_the_record_is_rejected() {
    let dir = sealed_bundle("rl_ver", "Aarch64");
    // Lock still pins 6.3.1; the record claims a different version -> structural mismatch.
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        v["verifier_sdk_version"] = serde_json::json!("6.3.0");
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(
        matches!(&err, EvidenceError::Stage5 { error, .. } if error.contains("SDK binding invalid")),
        "a record SDK version that disagrees with the sealed lock must be rejected; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_wrong_sdk_name_in_the_record_is_rejected() {
    let dir = sealed_bundle("rl_name", "Aarch64");
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        v["verifier_sdk_name"] = serde_json::json!("not-the-verifier-crate");
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(
        matches!(&err, EvidenceError::Stage5 { error, .. } if error.contains("SDK binding invalid")),
        "a record SDK name absent from the sealed lock must be rejected; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_runner_lock_with_a_non_registry_sdk_source_is_rejected() {
    let dir = sealed_bundle("rl_src", "Aarch64");
    // A path-sourced SDK cannot pin the published bytes; content-address it + update the
    // record hash so the hash check passes and the SOURCE check is what rejects it.
    let path_lock =
        "# path-sourced SDK (unpinnable)\nversion = 3\n\n[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\n"
            .to_string();
    let h = crate::venue::lock_provenance::recompute_lock_hash(path_lock.as_bytes());
    write(&dir, &stage5_runner_lock_file("Sp1"), path_lock.as_bytes());
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        v["verifier_sdk_lock_blake3"] = serde_json::json!(h);
    });
    reseal(&dir, "Aarch64");
    let err = import_verify(&dir).unwrap_err();
    assert!(
        matches!(&err, EvidenceError::Stage5 { error, .. } if error.contains("SDK binding invalid")),
        "a runner lock whose SDK has no registry source must be rejected; got {err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_missing_runner_lock_is_rejected_as_missing_required_file() {
    let dir = sealed_bundle("rl_missing", "Aarch64");
    std::fs::remove_file(dir.join(stage5_runner_lock_file("Sp1"))).unwrap();
    // Re-seal would refuse (exact-set: missing file); prove seal itself catches it.
    std::fs::remove_file(dir.join(MANIFEST_FILE)).ok();
    let err = seal(&dir, "Aarch64", COMMIT).unwrap_err();
    assert!(
        matches!(err, EvidenceError::MissingFile { .. }),
        "a bundle missing the sealed runner lock must be refused at seal; got {err}"
    );
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

// ---- Architecture acceptance contract (VENUE.md §2) --------------------------
//
// x86_64 carries SP1 **and** the RISC Zero material (verifier material, Stage-5 result,
// tool binding). aarch64 carries SP1 only: Groth16 / `stark2snark` / verifier-material
// extraction are native-x86_64-only, and upstream publishes no aarch64-linux RISC Zero
// artifact, so there is no aarch64 RISC Zero tool identity to install, verify, or bind.
// The bundle file set is compared exactly in both directions, so a missing RISC Zero
// file on x86_64 and an extra one on aarch64 are both refused.

/// The three files that constitute "RISC Zero material" for the arch contract.
fn risc0_material_names() -> Vec<String> {
    risc0_material_files()
}

#[test]
fn x86_bundle_missing_risc0_material_is_rejected() {
    for name in risc0_material_names() {
        let dir = tmpdir("x86-missing-r0");
        write_bundle_files(&dir, "X86_64");
        std::fs::remove_file(dir.join(&name)).expect("remove a required RISC Zero file");
        let err = seal(&dir, "X86_64", COMMIT)
            .expect_err("an x86_64 bundle without RISC Zero material must be refused");
        assert!(
            matches!(&err, EvidenceError::MissingFile { name: n } if *n == name),
            "removing {name} should be MissingFile, got {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn x86_bundle_with_risc0_material_is_accepted() {
    let dir = sealed_bundle("x86-with-r0", "X86_64");
    let imported = import_verify(&dir).expect("a complete x86_64 bundle must import");
    assert_eq!(imported.arch, "X86_64");
    assert!(
        imported.risc0_extractor_json.is_some(),
        "x86_64 must carry RISC Zero verifier material"
    );
    // Both candidates bound a verified tool on x86_64.
    let bound: Vec<&str> = imported
        .tool_bindings
        .iter()
        .map(|b| b.candidate.as_str())
        .collect();
    assert!(bound.contains(&"Sp1"), "x86_64 must bind SP1: {bound:?}");
    assert!(bound.contains(&"Risc0"), "x86_64 must bind RISC Zero: {bound:?}");
    for name in risc0_material_names() {
        assert!(dir.join(&name).exists(), "x86_64 bundle must carry {name}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arm_bundle_without_risc0_material_is_accepted() {
    let dir = sealed_bundle("arm-no-r0", "Aarch64");
    let imported = import_verify(&dir).expect("an aarch64 SP1-only bundle must import");
    assert_eq!(imported.arch, "Aarch64");
    assert!(
        imported.risc0_extractor_json.is_none(),
        "aarch64 must not carry RISC Zero verifier material"
    );
    let bound: Vec<&str> = imported
        .tool_bindings
        .iter()
        .map(|b| b.candidate.as_str())
        .collect();
    assert_eq!(bound, vec!["Sp1"], "aarch64 binds SP1 only, got {bound:?}");
    for name in risc0_material_names() {
        assert!(
            !dir.join(&name).exists(),
            "aarch64 bundle must not carry {name}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn arm_bundle_carrying_risc0_material_is_rejected() {
    // Each RISC Zero file, introduced on its own into an otherwise valid aarch64
    // bundle, must be refused as unexpected/ineligible — never silently accepted.
    for name in risc0_material_names() {
        let dir = tmpdir("arm-with-r0");
        write_bundle_files(&dir, "Aarch64");
        // Borrow the genuine x86_64 bytes: the point is that the FILE is ineligible on
        // aarch64, not that its contents happen to be malformed.
        let src = tmpdir("arm-with-r0-src");
        write_bundle_files(&src, "X86_64");
        std::fs::copy(src.join(&name), dir.join(&name)).expect("plant RISC Zero material");

        let err = seal(&dir, "Aarch64", COMMIT)
            .expect_err("aarch64 carrying RISC Zero material must be refused");
        assert!(
            matches!(&err, EvidenceError::UnmanifestedFile { name: n } if *n == name),
            "planting {name} on aarch64 should be UnmanifestedFile, got {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&src).ok();
    }
}

#[test]
fn aggregation_sources_risc0_material_only_from_x86() {
    let x86 = sealed_bundle("agg-x86", "X86_64");
    let arm = sealed_bundle("agg-arm", "Aarch64");
    let ix = import_verify(&x86).expect("x86 import");
    let ia = import_verify(&arm).expect("arm import");

    let x86_r0 = ix
        .risc0_extractor_json
        .clone()
        .expect("x86_64 supplies the RISC Zero material");
    assert!(
        ia.risc0_extractor_json.is_none(),
        "aarch64 supplies no RISC Zero material at all"
    );

    let agg = aggregate_imported(&[ix, ia]).expect("typed cross-arch aggregate");
    assert_eq!(
        agg.venue.risc0_extractor_json, x86_r0,
        "aggregate RISC Zero material must be exactly the x86_64 bundle's bytes"
    );

    // An aarch64-only aggregate cannot produce RISC Zero material at all.
    let arm_only = sealed_bundle("agg-arm-only", "Aarch64");
    let ia2 = import_verify(&arm_only).expect("arm import");
    assert!(
        aggregate_imported(&[ia2]).is_err(),
        "aggregation from aarch64 alone must fail: it has no RISC Zero material"
    );

    std::fs::remove_dir_all(&x86).ok();
    std::fs::remove_dir_all(&arm).ok();
    std::fs::remove_dir_all(&arm_only).ok();
}

// ============================================================================
// Strengthened Option A: the TEST_ONLY smoke bundle trust-path (crafted, complete,
// locally sealed + imported — no x86 venue needed to validate the quarantine logic).
//
// A smoke bundle = every REAL producer record (as written by `write_bundle_files`) with the
// ONE synthetic substitution being the Stage-5b tool binding, PLUS the smoke-only files:
// `smoke-source-binding.json`, `<Cand>.smoke-attestation.json`, `<Cand>.substitution-log.json`.
// It is sealed under `ImportMode::TestOnly` (kind `SMOKE_BUNDLE_KIND`).
//   * `import_verify_test_only` ACCEPTS it under the strict smoke rules.
//   * `import_verify` (Authoritative) REJECTS the IDENTICAL bytes (bundle_kind).
// ============================================================================
use crate::venue::smoke::{
    SmokeClass, SmokeExecutable, SmokeExecutionAttestation, SmokeSourceBinding, SubstitutionLog,
};

fn host_arch(arch: &str) -> &'static str {
    if arch == "X86_64" {
        "x86_64"
    } else {
        "aarch64"
    }
}
fn synthetic_stage5b_id(c: &str) -> String {
    format!("TEST_ONLY_SYNTHETIC://{}-stage5b-verifier", c.to_lowercase())
}
fn runbin(c: &str, arch: &str) -> String {
    // MUST equal the Stage-5 result's verifier_executed_binary_sha256 in write_bundle_files.
    bh(&format!("runbin-{}-{arch}", c.to_lowercase()))
}

fn write_synthetic_tool_binding(dir: &Path, c: &str, arch: &str) {
    let builder = oci(&format!("builder-{}-{arch}", c.to_lowercase()));
    let bindings = serde_json::json!([{
        "candidate": c, "name": "stage5b-verifier", "version": "0.0.0",
        "artifact_identity": synthetic_stage5b_id(c), "checksum_algorithm": "sha256",
        "declared_checksum_hex": bh("syn-decl"), "verified_artifact_hex": bh("syn-decl"),
        "installed_binary_sha256_hex": bh("syn-inst"),
        "install_entrypoint": format!("TEST_ONLY_SYNTHETIC:cargo:{}-stage5b", c.to_lowercase()),
        "container_digest": builder, "source_commit": COMMIT, "test_only": true,
    }]);
    write(dir, &tool_binding_file(c), serde_json::to_vec_pretty(&bindings).unwrap().as_slice());
}
fn write_real_tool_binding(dir: &Path, c: &str, arch: &str) {
    let builder = oci(&format!("builder-{}-{arch}", c.to_lowercase()));
    let declared = bh("artifact-real");
    let bindings = serde_json::json!([{
        "candidate": c, "name": "sp1-verifier", "version": "6.3.1",
        "artifact_identity": "https://fixtures.invalid/sp1-verifier-6.3.1.tar",
        "checksum_algorithm": "sha256", "declared_checksum_hex": declared,
        "verified_artifact_hex": declared, "installed_binary_sha256_hex": bh("installed-real"),
        "install_entrypoint": "cargo:sp1-verifier@6.3.1",
        "container_digest": builder, "source_commit": COMMIT, "test_only": false,
    }]);
    write(dir, &tool_binding_file(c), serde_json::to_vec_pretty(&bindings).unwrap().as_slice());
}

fn smoke_attestation(c: &str, arch: &str) -> SmokeExecutionAttestation {
    SmokeExecutionAttestation {
        schema_version: 1,
        classification: SmokeClass::TestOnly,
        candidate: c.to_string(),
        arch: host_arch(arch).to_string(),
        container_digest: oci(&format!("builder-{}-{arch}", c.to_lowercase())),
        source_pr_head: COMMIT.to_string(),
        executables: vec![SmokeExecutable {
            executable_name: "stage5-runner".into(),
            version_output: "sp1-verifier 6.3.1".into(),
            checksum_verified_hex: bh("dl"),
            point_of_use_sha256: runbin(c, arch), // == the Stage-5 executed binary
            produced_output_blake3: bh("out"),
        }],
    }
}

fn write_smoke_bundle_files(dir: &Path, arch: &str) {
    write_bundle_files(dir, arch);
    let src = SmokeSourceBinding {
        schema_version: 1,
        classification: SmokeClass::TestOnly,
        source_pr_head: COMMIT.to_string(),
        note: "crafted smoke bundle".into(),
    };
    write(dir, SMOKE_SOURCE_BINDING_FILE, serde_json::to_vec_pretty(&src).unwrap().as_slice());
    for c in tool_binding_candidates(arch).iter().copied() {
        write_synthetic_tool_binding(dir, c, arch);
        let att = smoke_attestation(c, arch);
        write(dir, &smoke_attestation_file(c), serde_json::to_vec_pretty(&att).unwrap().as_slice());
        let sub = SubstitutionLog {
            reason: "crafted".into(),
            real_executables: vec![("stage5-runner".into(), runbin(c, arch))],
            synthetic_sentinel: synthetic_stage5b_id(c),
            attestation_hash: att.attestation_hash(),
        };
        write(dir, &substitution_log_file(c), serde_json::to_vec_pretty(&sub).unwrap().as_slice());
    }
}
fn sealed_smoke_bundle(tag: &str, arch: &str) -> PathBuf {
    let dir = tmpdir(tag);
    write_smoke_bundle_files(&dir, arch);
    seal_mode(&dir, arch, COMMIT, ImportMode::TestOnly).expect("seal a complete smoke bundle");
    dir
}
fn reseal_smoke(dir: &Path, arch: &str) {
    std::fs::remove_file(dir.join(MANIFEST_FILE)).ok();
    seal_mode(dir, arch, COMMIT, ImportMode::TestOnly).expect("reseal smoke");
}

// ---- ACCEPTANCE + the one-way quarantine ------------------------------------
#[test]
fn smoke_testonly_accepts_and_authoritative_rejects_the_identical_bundle() {
    for arch in ["X86_64", "Aarch64"] {
        let dir = sealed_smoke_bundle("smoke-ok", arch);
        import_verify_test_only(&dir).expect("TestOnly import must accept a valid smoke bundle");
        // The IDENTICAL sealed bytes: Authoritative import rejects on bundle_kind (quarantine).
        assert!(
            matches!(import_verify(&dir), Err(EvidenceError::BundleKind { .. })),
            "Authoritative import must reject the smoke bundle"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn testonly_cannot_import_an_authoritative_bundle() {
    let dir = sealed_bundle("auth-for-testonly", "X86_64");
    assert!(
        matches!(import_verify_test_only(&dir), Err(EvidenceError::BundleKind { .. })),
        "TestOnly import must reject an authoritative bundle"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn authoritative_import_refuses_a_synthetic_stage5b_binding() {
    // Authoritative-KIND bundle whose Stage-5b tool binding is synthetic -> rejected.
    let dir = tmpdir("auth-synthetic-tb");
    write_bundle_files(&dir, "X86_64");
    write_synthetic_tool_binding(&dir, "Sp1", "X86_64");
    write_synthetic_tool_binding(&dir, "Risc0", "X86_64");
    seal(&dir, "X86_64", COMMIT).expect("seal authoritative");
    assert!(
        matches!(import_verify(&dir), Err(EvidenceError::Tool { .. })),
        "Authoritative import must refuse a synthetic tool binding"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---- TestOnly is STRICTER: each smoke rule, mutated, must fail ---------------
#[test]
fn testonly_refuses_a_real_stage5b_binding() {
    let dir = tmpdir("smoke-real-tb");
    write_smoke_bundle_files(&dir, "X86_64");
    write_real_tool_binding(&dir, "Sp1", "X86_64"); // non-synthetic -> TestOnly must refuse
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::Tool { .. })));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn testonly_refuses_missing_attestation_or_substitution() {
    // Missing attestation -> the exact required-file set rejects it at seal time.
    let dir = tmpdir("smoke-no-att");
    write_smoke_bundle_files(&dir, "X86_64");
    std::fs::remove_file(dir.join(smoke_attestation_file("Sp1"))).unwrap();
    assert!(matches!(
        seal_mode(&dir, "X86_64", COMMIT, ImportMode::TestOnly),
        Err(EvidenceError::MissingFile { .. })
    ));
    std::fs::remove_dir_all(&dir).ok();
    // Missing substitution log -> likewise.
    let dir = tmpdir("smoke-no-sub");
    write_smoke_bundle_files(&dir, "X86_64");
    std::fs::remove_file(dir.join(substitution_log_file("Sp1"))).unwrap();
    assert!(matches!(
        seal_mode(&dir, "X86_64", COMMIT, ImportMode::TestOnly),
        Err(EvidenceError::MissingFile { .. })
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn testonly_refuses_attestation_that_disagrees_with_stage5_execution() {
    let dir = tmpdir("smoke-att-disagree");
    write_smoke_bundle_files(&dir, "X86_64");
    // Break the causal binding: attestation point-of-use != the Stage-5 executed binary.
    let mut att = smoke_attestation("Sp1", "X86_64");
    att.executables[0].point_of_use_sha256 = bh("a-different-binary");
    write(&dir, &smoke_attestation_file("Sp1"), serde_json::to_vec_pretty(&att).unwrap().as_slice());
    // keep the substitution log consistent with THIS attestation so we isolate the causal check.
    let sub = SubstitutionLog {
        reason: "x".into(),
        real_executables: vec![("stage5-runner".into(), att.executables[0].point_of_use_sha256.clone())],
        synthetic_sentinel: synthetic_stage5b_id("Sp1"),
        attestation_hash: att.attestation_hash(),
    };
    write(&dir, &substitution_log_file("Sp1"), serde_json::to_vec_pretty(&sub).unwrap().as_slice());
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::Smoke { .. })));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn testonly_refuses_substitution_not_bound_to_attestation_or_sealed_identity() {
    // (a) substitution attestation_hash mismatch.
    let dir = tmpdir("smoke-sub-hash");
    write_smoke_bundle_files(&dir, "X86_64");
    rewrite_json(&dir, &substitution_log_file("Sp1"), |v| {
        v["attestation_hash"] = serde_json::json!(bh("wrong-hash"));
    });
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::Smoke { .. })));
    std::fs::remove_dir_all(&dir).ok();
    // (b) substitution sentinel != the sealed synthetic tool-binding identity.
    let dir = tmpdir("smoke-sub-sentinel");
    write_smoke_bundle_files(&dir, "X86_64");
    rewrite_json(&dir, &substitution_log_file("Sp1"), |v| {
        v["synthetic_sentinel"] = serde_json::json!("TEST_ONLY_SYNTHETIC://something-else");
    });
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::Smoke { .. })));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn testonly_refuses_source_binding_not_bound_to_sealed_commit() {
    let dir = tmpdir("smoke-src-commit");
    write_smoke_bundle_files(&dir, "X86_64");
    rewrite_json(&dir, SMOKE_SOURCE_BINDING_FILE, |v| {
        v["source_pr_head"] = serde_json::json!("f".repeat(40));
    });
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::Smoke { .. })));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn smoke_v1_stage5result_is_refused() {
    let dir = tmpdir("smoke-v1-stage5");
    write_smoke_bundle_files(&dir, "X86_64");
    rewrite_json(&dir, &stage5_file("Sp1"), |v| {
        let o = v.as_object_mut().unwrap();
        o.remove("schema_version");
        o.remove("verifier_executed_binary_sha256");
        o.remove("verifier_sdk_lock_blake3");
        o.insert("tool_identity_hex".into(), serde_json::json!("a".repeat(64)));
    });
    reseal_smoke(&dir, "X86_64");
    assert!(matches!(
        import_verify_test_only(&dir),
        Err(EvidenceError::Stage5 { .. } | EvidenceError::Parse { .. })
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn smoke_altered_sealed_runner_lock_is_refused() {
    let dir = tmpdir("smoke-alter-lock");
    write_smoke_bundle_files(&dir, "X86_64");
    seal_mode(&dir, "X86_64", COMMIT, ImportMode::TestOnly).expect("seal");
    // tamper the sealed runner lock AFTER sealing -> recomputed hash != manifest.
    let lf = stage5_runner_lock_file("Sp1");
    let mut bytes = std::fs::read(dir.join(&lf)).unwrap();
    bytes.extend_from_slice(b"\n# tampered\n");
    std::fs::write(dir.join(&lf), &bytes).unwrap();
    assert!(matches!(import_verify_test_only(&dir), Err(EvidenceError::FileHashMismatch { .. })));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn smoke_post_seal_source_or_classification_mutation_is_refused() {
    // (a) mutate the sealed manifest source_commit -> content hash / commit check fails.
    let dir = sealed_smoke_bundle("smoke-mutate-src", "X86_64");
    rewrite_json(&dir, MANIFEST_FILE, |v| {
        v["source_commit"] = serde_json::json!("b".repeat(40));
    });
    assert!(import_verify_test_only(&dir).is_err(), "post-seal source mutation must be refused");
    std::fs::remove_dir_all(&dir).ok();
    // (b) mutate the sealed source-binding classification -> file hash mismatch.
    let dir = sealed_smoke_bundle("smoke-mutate-cls", "X86_64");
    rewrite_json(&dir, SMOKE_SOURCE_BINDING_FILE, |v| {
        v["classification"] = serde_json::json!("NON_SELECTION");
    });
    assert!(
        matches!(import_verify_test_only(&dir), Err(EvidenceError::FileHashMismatch { .. })),
        "post-seal classification mutation must break the seal"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---- LINEAGE: every sealed file is the real producer output; ONLY Stage-5b is synthetic -----
#[test]
fn smoke_bundle_lineage_only_stage5b_synthetic_every_file_is_producer_output() {
    for arch in ["X86_64", "Aarch64"] {
        let dir = tmpdir("smoke-lineage");
        write_smoke_bundle_files(&dir, arch);
        // Capture the producer output bytes per file BEFORE sealing.
        let mut producer: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
        for name in required_files_mode(arch, ImportMode::TestOnly) {
            producer.insert(name.clone(), std::fs::read(dir.join(&name)).unwrap());
        }
        let manifest = seal_mode(&dir, arch, COMMIT, ImportMode::TestOnly).expect("seal smoke");
        // (a) byte/hash equality: every sealed file == its producer output (seal added nothing).
        assert_eq!(manifest.files.len(), producer.len());
        for mf in &manifest.files {
            let bytes = producer.get(&mf.name).expect("sealed file was a producer output");
            assert_eq!(
                mf.blake3_hex,
                crate::venue::to_hex(blake3::hash(bytes).as_bytes()),
                "sealed {} != its producer output",
                mf.name
            );
            assert_eq!(mf.byte_len, bytes.len() as u64);
        }
        // (b) ONLY the Stage-5b tool binding is synthetic. Every REAL substantive record (container,
        //     native, lock, provenance, stage2 audit, stage5 result, runner lock, material) MUST
        //     be free of the synthetic sentinel — proving nothing but the tool identity was
        //     substituted. (The smoke-only files legitimately reference the sentinel.)
        for (name, bytes) in &producer {
            let smoke_only = name.ends_with(".tool-binding.json")
                || name == SMOKE_SOURCE_BINDING_FILE
                || name.ends_with(".smoke-attestation.json")
                || name.ends_with(".substitution-log.json");
            let has_sentinel = String::from_utf8_lossy(bytes).contains("TEST_ONLY_SYNTHETIC");
            if name.ends_with(".tool-binding.json") {
                assert!(has_sentinel, "{name} must carry the synthetic Stage-5b sentinel");
            }
            if !smoke_only {
                assert!(
                    !has_sentinel,
                    "REAL producer record {name} must NOT carry the synthetic sentinel (lineage)"
                );
            }
        }
        import_verify_test_only(&dir).expect("the lineage smoke bundle imports TestOnly");
        std::fs::remove_dir_all(&dir).ok();
    }
}
