//! Typed fragment merge (reviewer correction #6): combine the per-(candidate,arch)
//! measurement fragments into ONE canonical `RawFacts` — an authoritative producer step, not
//! an operator instruction. Fail-closed: it requires EXACTLY the eligible fragment set
//! (Sp1 x86_64 + aarch64, Risc0 x86_64), rejects duplicates / missing / extra / a
//! RISC-Zero-aarch64 fragment, verifies the SP1 fragments agree on guest identity + candidate
//! hashes + verifier material + source commit + spec, combines SP1 x86+ARM (cells, provenance,
//! builder records), preserves RISC0 x86-only, and re-runs the full `validate_raw_facts`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::producer::{validate_raw_facts, RawFacts, MERGED_SPEC_HASH_HEX};

/// The arch a fragment describes (all its cells must share it).
fn fragment_arch(f: &Value) -> Result<String, String> {
    let cells = f
        .get("cells")
        .and_then(|c| c.as_array())
        .ok_or("fragment has no cells[]")?;
    if cells.is_empty() {
        return Err("fragment has zero cells".into());
    }
    let mut arch: Option<&str> = None;
    for c in cells {
        let a = c
            .get("arch")
            .and_then(|x| x.as_str())
            .ok_or("cell missing arch")?;
        match arch {
            None => arch = Some(a),
            Some(prev) if prev != a => {
                return Err(format!("fragment mixes cell arches: {prev} vs {a}"))
            }
            _ => {}
        }
    }
    Ok(arch.unwrap().to_string())
}

fn fragment_candidate(f: &Value) -> Result<String, String> {
    f.get("candidate")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| "fragment missing candidate".into())
}

/// The set of source commits a fragment's provenance records reference (must be a single one).
fn fragment_commits(f: &Value) -> Result<Vec<String>, String> {
    let prov = f
        .get("provenance")
        .and_then(|p| p.as_array())
        .ok_or("fragment has no provenance[]")?;
    Ok(prov
        .iter()
        .filter_map(|p| {
            p.get("source_commit")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .collect())
}

fn agree(a: &Value, b: &Value, ptr: &str) -> Result<(), String> {
    if a.pointer(ptr) != b.pointer(ptr) {
        return Err(format!("SP1 x86_64/aarch64 fragments disagree on {ptr}"));
    }
    Ok(())
}

/// Merge the fragments into canonical `RawFacts` JSON (validated). `fragments` are the
/// per-(candidate,arch) `CandidateFacts` emitted by `measure_fragment.sh`.
pub fn merge_fragments(spec_hex: &str, fragments: &[Value]) -> Result<Value, String> {
    if spec_hex != MERGED_SPEC_HASH_HEX {
        return Err(format!(
            "spec {spec_hex} != merged finalized {MERGED_SPEC_HASH_HEX}"
        ));
    }
    let mut by_key: BTreeMap<(String, String), &Value> = BTreeMap::new();
    let mut all_commits: Vec<String> = Vec::new();
    for f in fragments {
        let cand = fragment_candidate(f)?;
        let arch = fragment_arch(f)?;
        if cand == "Risc0" && arch == "aarch64" {
            return Err("a RISC-Zero-aarch64 fragment is native-ineligible; rejected".into());
        }
        if by_key.insert((cand.clone(), arch.clone()), f).is_some() {
            return Err(format!("duplicate fragment for {cand}/{arch}"));
        }
        all_commits.extend(fragment_commits(f)?);
    }
    // Exactly the eligible set.
    let want = [("Sp1", "x86_64"), ("Sp1", "aarch64"), ("Risc0", "x86_64")];
    if by_key.len() != want.len() {
        return Err(format!(
            "expected exactly {} fragments (Sp1 x86_64/aarch64, Risc0 x86_64), got {}",
            want.len(),
            by_key.len()
        ));
    }
    let get = |c: &str, a: &str| -> Result<&Value, String> {
        by_key
            .get(&(c.to_string(), a.to_string()))
            .copied()
            .ok_or_else(|| format!("missing eligible fragment {c}/{a}"))
    };
    let sp1x = get("Sp1", "x86_64")?;
    let sp1a = get("Sp1", "aarch64")?;
    let risc0 = get("Risc0", "x86_64")?;

    // EXACT source authority: every fragment must be from the ratified commit — not merely a
    // commit they agree on.
    for c in &all_commits {
        if c != crate::guest_set::RATIFIED_SOURCE_COMMIT {
            return Err(format!(
                "fragment source commit {c} != ratified {}",
                crate::guest_set::RATIFIED_SOURCE_COMMIT
            ));
        }
    }

    // SP1 x86/aarch64 must agree on the genuinely ARCH-NEUTRAL fields only. `container_image_digest`
    // is per-arch (each native builder image) and is preserved per-arch in the builder + provenance
    // records — it is NOT compared here (comparing it would repeat the cross-arch reconciliation bug).
    for ptr in [
        "/candidate",
        "/statement_hash_tlg",
        "/statement_hash_st",
        "/rss_context_hash",
        "/malformed_corpus_result_hash",
        "/guest/program_id",
        "/guest/guest_image_hash",
        "/guest/guest_source_tree_hash",
        "/guest/candidate_dep_lock_hash",
        "/guest/build_command_hash",
        "/verifier_material",
    ] {
        agree(sp1x, sp1a, ptr)?;
    }

    // Merge SP1: concat cells + provenance + builder records (x86 then aarch64).
    let mut sp1 = sp1x.clone();
    let concat = |field: &str| -> Result<Value, String> {
        let mut v = sp1x
            .get(field)
            .and_then(|x| x.as_array())
            .cloned()
            .ok_or_else(|| format!("sp1 x86 fragment missing {field}"))?;
        v.extend(
            sp1a.get(field)
                .and_then(|x| x.as_array())
                .cloned()
                .ok_or_else(|| format!("sp1 aarch64 fragment missing {field}"))?,
        );
        Ok(Value::Array(v))
    };
    sp1["cells"] = concat("cells")?;
    sp1["provenance"] = concat("provenance")?;
    // Runner continuity survives the merge: concat the per-arch Phase-1 identity records (x86 + arm).
    sp1["identity_records"] = concat("identity_records")?;
    let mut builders = sp1x
        .pointer("/guest/builder")
        .and_then(|x| x.as_array())
        .cloned()
        .ok_or("sp1 x86 guest.builder missing")?;
    builders.extend(
        sp1a.pointer("/guest/builder")
            .and_then(|x| x.as_array())
            .cloned()
            .ok_or("sp1 aarch64 guest.builder missing")?,
    );
    sp1["guest"]["builder"] = Value::Array(builders);

    let raw = json!({
        "lifecycle_mode": "measurement",
        "b0_pre_spec_hash": spec_hex,
        "candidates": [sp1, risc0.clone()],
    });

    // Fail-closed: the merged RawFacts must pass the full structural validation.
    let typed: RawFacts =
        serde_json::from_value(raw.clone()).map_err(|e| format!("merged RawFacts invalid: {e}"))?;
    validate_raw_facts(&typed)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(x: &str) -> String {
        x.repeat(32)
    }
    fn cpuset_obs() -> Value {
        json!({"state": "readable-nonempty", "raw": "0-7", "file_type": "regular", "is_symlink": false, "dev": 1u64, "inode": 2u64, "size": 3u64, "mtime_secs": 0i64, "mtime_nanos": 0i64})
    }
    fn runner_attestation(arch: &str) -> Value {
        json!({
            "build_target_arch": arch,
            "execution_tooling_checkout_head": "1234567890abcdef1234567890abcdef12345678",
            "ratified_tooling_commit": "1234567890abcdef1234567890abcdef12345678",
            "ratified_pathset_blake3": h("70"), "recomputed_pathset_blake3": h("70"),
            "measured_source_commit": crate::guest_set::RATIFIED_SOURCE_COMMIT,
            "build_git_sha": crate::guest_set::RATIFIED_SOURCE_COMMIT,
            "measured_source_context_blake3": h("c7"), "runner_sha256": h("52"), "runner_blake3": h("53"),
            "immutable_builder_identity": h("b0"), "protobuf_authority_sha256": h("5b"), "protobuf_authority_blake3": h("5c"),
            "native_protoc_sha256": h("60"), "native_protoc_blake3": h("61"), "native_protoc_version": "libprotoc 3.21.12",
            "docker_argv_blake3": h("d0"), "reproducibility_pair_blake3": h("2a")
        })
    }
    fn runner_recipe(arch: &str) -> Value {
        let enc_hex = |t: &str| -> String {
            use std::fmt::Write as _;
            let s = format!("--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo\u{1f}--remap-path-prefix=/b0-input/{t}/target=/b0/target");
            s.bytes().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
        };
        let rec_addr = |t: &str| -> String {
            let body = format!("b0-final-rustc-invocation/v2\nkind=compile\nremap_arg=--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo\nremap_arg=--remap-path-prefix=/b0-input/{t}/target=/b0/target");
            blake3::hash(body.as_bytes()).to_hex().to_string()
        };
        let side = |t: &str, s: u64, e: u64| {
            json!({
                "original_root": format!("/b0-input/{t}/tooling"),
                "cargo_from": format!("/b0-input/{t}/cargo"),
                "target_from": format!("/b0-input/{t}/target"),
                "encoded_rustflags_hex": enc_hex(t),
                "runner_sha256": h("52"), "runner_blake3": h("53"),
                "guest_image_id": h("e4"), "guest_methods_blake3": h("e5"),
                "origin_manifest_blake3": h("77"), "materialized_manifest_blake3": h("77"),
                "start_unix": s, "end_unix": e,
                "invocations": [{"kind": "compile", "remap_args": [
                    format!("--remap-path-prefix=/b0-input/{t}/cargo=/b0/cargo"),
                    format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target")],
                    "record_address": rec_addr(t)}]
            })
        };
        json!({
            "candidate": "sp1", "arch": arch,
            "manifest_path": "tools/b0-pre-measure-sp1/Cargo.toml",
            "artifact_path": "release/b0-pre-measure-sp1", "cargo_ident": "cargo", "b0_venue_embed": "0",
            "canonical_build_path": "/b0/tooling",
            "per_arch_toolchain_identity": h("e2"), "wrapper_blake3": h("e3"),
            "build_argv": ["cargo","build","--release","--locked","--features","real-backend","--manifest-path","tools/b0-pre-measure-sp1/Cargo.toml"],
            "build_env": [["BUILD_GIT_SHA", crate::guest_set::RATIFIED_SOURCE_COMMIT], ["SOURCE_DATE_EPOCH","0"], ["B0_VENUE_EMBED","0"]],
            "build_a": side("a", 100, 200), "build_b": side("b", 200, 300), "byte_equal": true,
            "leakage_refused_prefixes": ["/b0-input/a/tooling","/b0-input/a/cargo","/b0-input/a/target","/b0-input/b/tooling","/b0-input/b/cargo","/b0-input/b/target","/tmp/b0-evid"],
            "leakage_permitted_prefixes": ["/b0/cargo", "/b0/target", "/b0/tooling"],
            "leakage_clean": true, "evidence_root": "/tmp/b0-evid"
        })
    }
    fn prov(arch: &str, role: &str) -> Value {
        let chain = json!([{"cgroup_path": "/b0.slice", "order": 0, "first": cpuset_obs(), "second": cpuset_obs()}]);
        json!({
            "arch": arch, "role": role, "source_commit": crate::guest_set::RATIFIED_SOURCE_COMMIT,
            "dirty_tree_flag": false,
            "builder_container_digest": h("b0"), "host_os": "Linux", "kernel": "6.1.0",
            "cpu_vendor": "GenuineIntel", "cpu_model": "Xeon", "physical_core_count": 8,
            "logical_cpu_count": 8, "total_ram_bytes": 34359738368u64,
            "configured_cpuset_core_limit": 8, "configured_memory_limit_bytes": 34359738368u64,
            "dvfs": {"kind": "observable", "turbo_enabled": false, "governor": "performance"}, "clock_source": "tsc",
            "cgroup_version": 2, "cgroup_scope_label": "/b0.slice", "benchmark_harness_source_hash": h("d1"),
            "raw_environment_capture_hash": h("d2"),
            "cpuset_source_cgroup_path": "/b0.slice", "cpuset_raw": "0-7", "cpuset_inherited": false,
            "cpuset_probe_chain": chain,
            "runner_attestation": runner_attestation(arch),
            "runner_recipe": runner_recipe(arch)
        })
    }
    fn cells(arch: &str) -> Vec<Value> {
        let mut v = Vec::new();
        for stmt in ["Tlg", "SelectToken"] {
            for it in 0..10u32 {
                v.push(json!({
                    "arch": arch, "statement": stmt, "iteration": it, "proof_hash": h("cf"),
                    "artifact_hashes": [["proof", h("cf")]], "prove_ns": 1u64, "setup_ns": 1u64,
                    "proof_bytes": 32u64, "verify_ns": vec![1u64; 100],
                    "proving_run_rss_bytes": 1u64, "verify_batch_rss_bytes": 1u64
                }));
            }
        }
        v
    }
    fn frag(cand: &str, arch: &str) -> Value {
        let (img, prog, vk) = if cand == "Sp1" {
            (h("11"), h("aa"), h("dd"))
        } else {
            (h("22"), h("bb"), h("ee"))
        };
        let builder = if arch == "x86_64" { h("b0") } else { h("b1") };
        json!({
            "candidate": cand, "container_image_digest": h("f0"),
            "statement_hash_tlg": h("f1"), "statement_hash_st": h("f2"),
            "rss_context_hash": h("f3"), "malformed_corpus_result_hash": h("f4"),
            "guest": {
                "guest_source_tree_hash": h("a2"), "candidate_dep_lock_hash": h("a3"),
                "guest_image_hash": img, "program_id": prog, "build_command_hash": h("a4"),
                "reproducible": true,
                "builder": [{"arch": arch, "builder_container_digest": builder}]
            },
            "verifier_material": [{"role": "Groth16Vk", "byte_len": 292u64, "hash": vk}],
            "provenance": [prov(arch, "Proving"), prov(arch, "Verification")],
            "cells": cells(arch),
            // Phase-1 identity record (runner continuity): production_binary_blake3 == the provenance
            // runner attestation's runner_blake3 (h("53")); same measured-source/tooling/spec.
            "identity_records": [{
                "arch": arch,
                "source_commit": crate::guest_set::RATIFIED_SOURCE_COMMIT,
                "tooling_commit": "1234567890abcdef1234567890abcdef12345678",
                "tooling_pathset_blake3": h("70"),
                "b0_pre_spec_hash": SPEC,
                "production_binary_blake3": h("53")
            }]
        })
    }
    const SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

    #[test]
    fn eligible_fragments_merge_and_validate() {
        let raw = merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Sp1", "aarch64"),
                frag("Risc0", "x86_64"),
            ],
        )
        .unwrap();
        let cands = raw["candidates"].as_array().unwrap();
        let sp1 = &cands[0];
        assert_eq!(sp1["cells"].as_array().unwrap().len(), 40); // x86 20 + arm 20
        assert_eq!(sp1["provenance"].as_array().unwrap().len(), 4);
        assert_eq!(
            sp1.pointer("/guest/builder")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    // DIRECT merge → produce → verify: the retained cpuset + runner artifacts AND Phase-1 runner
    // continuity survive the fragment merge (previously only transitively covered).
    #[test]
    fn merge_produce_verify_preserves_retention_and_continuity() {
        use crate::measurement::parse_vector;
        use crate::producer::{produce, RawFacts};
        use crate::schema::runner_attestation::RunnerAttestationV1;

        let merged = merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Sp1", "aarch64"),
                frag("Risc0", "x86_64"),
            ],
        )
        .unwrap();
        let raw: RawFacts = serde_json::from_value(merged).expect("merged -> RawFacts");
        // produce() enforces runner continuity + artifact retention during assembly (the merge fixture
        // uses a non-reference verify cpuset, so the qualification verdict itself is not the point).
        let pkg = produce(&raw).expect("merged facts produce");
        let (_al, bundles) = parse_vector(&pkg.vector).unwrap();
        for (_c, ev) in &bundles {
            assert_eq!(ev.cpuset_chains.len(), ev.provenances.len());
            assert_eq!(ev.runner_attestations.len(), ev.provenances.len());
            // The retained Phase-1 identity artifact survives the merge and is independently decoded +
            // bound to its attestation at final import.
            assert_eq!(ev.identity_records.len(), ev.provenances.len());
            for (ab, rb) in ev.runner_attestations.iter().zip(&ev.identity_records) {
                let att = RunnerAttestationV1::decode_exact(ab).unwrap();
                att.check_runner_continuity()
                    .expect("runner continuity survives the merge");
                let rec = crate::schema::identity_record::Phase1IdentityRecordV1::decode_exact(rb)
                    .unwrap();
                att.check_bound_identity_record(&rec)
                    .expect("retained identity record binds after merge");
            }
        }

        // Negative THROUGH the merge: a substituted Phase-1 runner binary in a fragment → produce
        // refuses (tooling authority unchanged).
        let mut bad = frag("Sp1", "x86_64");
        bad["identity_records"][0]["production_binary_blake3"] = json!(h("99"));
        let merged2 = merge_fragments(
            SPEC,
            &[bad, frag("Sp1", "aarch64"), frag("Risc0", "x86_64")],
        )
        .unwrap();
        let raw2: RawFacts = serde_json::from_value(merged2).unwrap();
        assert!(produce(&raw2)
            .unwrap_err()
            .contains("production_binary_blake3 != measurement runner_blake3"));
    }

    #[test]
    fn missing_extra_and_duplicate_are_refused() {
        // missing SP1 aarch64
        assert!(merge_fragments(SPEC, &[frag("Sp1", "x86_64"), frag("Risc0", "x86_64")]).is_err());
        // duplicate SP1 x86
        assert!(merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Sp1", "x86_64"),
                frag("Risc0", "x86_64")
            ]
        )
        .unwrap_err()
        .contains("duplicate"));
        // extra RISC0 aarch64
        assert!(merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Sp1", "aarch64"),
                frag("Risc0", "x86_64"),
                frag("Risc0", "aarch64")
            ]
        )
        .is_err());
    }

    #[test]
    fn sp1_cross_arch_identity_skew_is_refused() {
        let mut arm = frag("Sp1", "aarch64");
        arm["guest"]["program_id"] = json!(h("99")); // != x86 program id
        let e = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), arm, frag("Risc0", "x86_64")])
            .unwrap_err();
        assert!(e.contains("disagree on /guest/program_id"), "{e}");
    }

    #[test]
    fn non_ratified_commit_is_refused() {
        // All fragments consistently bound to a DIFFERENT clean commit — still refused.
        let (mut x, mut a, mut r) = (
            frag("Sp1", "x86_64"),
            frag("Sp1", "aarch64"),
            frag("Risc0", "x86_64"),
        );
        for f in [&mut x, &mut a, &mut r] {
            for p in f["provenance"].as_array_mut().unwrap() {
                p["source_commit"] = json!("c".repeat(40));
            }
        }
        assert!(merge_fragments(SPEC, &[x, a, r])
            .unwrap_err()
            .contains("ratified"));
    }

    #[test]
    fn differing_sp1_container_identities_accepted_but_guest_substitution_refused() {
        // Legitimate per-arch native builder images differ — MUST be accepted.
        let mut x = frag("Sp1", "x86_64");
        let mut a = frag("Sp1", "aarch64");
        x["container_image_digest"] = json!(h("c0"));
        a["container_image_digest"] = json!(h("c1"));
        assert!(merge_fragments(SPEC, &[x, a, frag("Risc0", "x86_64")]).is_ok());
        // But substituting the guest identity across arches is refused.
        let mut a2 = frag("Sp1", "aarch64");
        a2["guest"]["program_id"] = json!(h("99"));
        assert!(
            merge_fragments(SPEC, &[frag("Sp1", "x86_64"), a2, frag("Risc0", "x86_64")])
                .unwrap_err()
                .contains("program_id")
        );
    }
}
