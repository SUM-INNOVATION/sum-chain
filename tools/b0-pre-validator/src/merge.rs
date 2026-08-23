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

/// A measurement-wide field EVERY fragment must carry byte-identically (the retained authority / report
/// / inventory). Refuses absence, an empty value, or ANY disagreement across the fragment set — so a
/// valid old authority package can never be mixed with fragments produced under a different one.
fn fragment_field_agree<'a>(fragments: &'a [Value], key: &str) -> Result<&'a Value, String> {
    let first = fragments
        .first()
        .and_then(|f| f.get(key))
        .filter(|v| v.as_str().map(|s| !s.is_empty()).unwrap_or(false))
        .ok_or_else(|| format!("fragment missing/empty {key}"))?;
    for f in fragments {
        match f.get(key) {
            Some(v) if v == first => {}
            Some(_) => {
                return Err(format!(
                    "fragments disagree on {key} (byte/address mismatch across the fragment set)"
                ))
            }
            None => return Err(format!("fragment missing {key}")),
        }
    }
    Ok(first)
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
        // No fragment may carry a legacy caller-supplied measurement-input hash (all three were
        // removed by the measurement-input-authority correction; the report/inventory/RSS values are
        // derived from retained artifacts). Refuse, never silently ignore.
        crate::producer::refuse_legacy_operator_hashes(f)?;
        let cand = fragment_candidate(f)?;
        let arch = fragment_arch(f)?;
        if cand == "Risc0" && arch == "aarch64" {
            return Err("a RISC-Zero-aarch64 fragment is native-ineligible; rejected".into());
        }
        if by_key.insert((cand.clone(), arch.clone()), f).is_some() {
            return Err(format!("duplicate fragment for {cand}/{arch}"));
        }
        all_commits.extend(fragment_commits(f)?);
        // Cargo dependency-SEED: every fragment must carry a NON-EMPTY, well-formed, candidate-MATCHING
        // DependencySeedV1 (defense-in-depth before produce; the sealed-import anchor re-authenticates it).
        // `verify(candidate)` refuses a mutated (recompute!=address) or swapped/cross-candidate seed here.
        let dep = f
            .get("dependency_seed_json")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("fragment {cand}/{arch} missing/empty dependency_seed_json"))?;
        let cand_lc = match cand.as_str() {
            "Sp1" => "sp1",
            "Risc0" => "risc0",
            other => return Err(format!("fragment has unknown candidate {other}")),
        };
        crate::venue::dependency_seed::DependencySeedV1::from_json(dep.as_bytes())
            .map_err(|e| format!("fragment {cand}/{arch} dependency_seed_json parse: {e}"))?
            .verify(cand_lc)
            .map_err(|e| format!("fragment {cand}/{arch} dependency-seed authenticity: {e}"))?;
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
        "/guest/program_id",
        "/guest/guest_image_hash",
        "/guest/guest_source_tree_hash",
        "/guest/candidate_dep_lock_hash",
        "/guest/build_command_hash",
        "/verifier_material",
        // The cargo dependency seed is per-CANDIDATE (arch-independent): the two SP1 fragments MUST carry
        // byte-identical dependency_seed_json (candidate correspondence + byte identity through merge).
        "/dependency_seed_json",
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

    // Every fragment MUST carry byte-identical measurement-input authority + malformed-corpus report +
    // harness-source inventory; disagreement is refused. The single agreed set flows to the merged
    // RawFacts (top-level), where `produce` decodes + verifies it and derives the report/MIA addresses.
    let mia = fragment_field_agree(fragments, "measurement_input_authority")?.clone();
    let report = fragment_field_agree(fragments, "malformed_corpus_report")?.clone();
    let inv = fragment_field_agree(fragments, "harness_source_inventory")?.clone();

    let raw = json!({
        "lifecycle_mode": "measurement",
        "b0_pre_spec_hash": spec_hex,
        "candidates": [sp1, risc0.clone()],
        "measurement_input_authority": mia,
        "malformed_corpus_report": report,
        "harness_source_inventory": inv,
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
    fn runner_recipe(cand: &str, arch: &str) -> Value {
        // Anchor-consistent synthetic dependency-seed values: the recipe's dependency_seed.address is the
        // synthetic record address for THIS candidate, and cargo_seed == the fixed synthetic host content.
        let dep_candidate = if cand == "Sp1" {
            crate::enums::Candidate::Sp1
        } else {
            crate::enums::Candidate::Risc0
        };
        let hexb = |bytes: &[u8]| -> String {
            use std::fmt::Write as _;
            bytes.iter().fold(String::new(), |mut a, b| {
                let _ = write!(a, "{b:02x}");
                a
            })
        };
        let dep_addr_hex: String =
            hexb(&crate::measurement::synth_dependency_seed(dep_candidate).1);
        let cargo_seed_hex: String = hexb(&crate::measurement::synth_cargo_seed_content());
        let enc_hex = |t: &str| -> String {
            use std::fmt::Write as _;
            let s = format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target");
            s.bytes().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
        };
        let rec_addr = |t: &str| -> String {
            let body = format!("b0-final-rustc-invocation/v2\nkind=compile\nremap_arg=--remap-path-prefix=/b0-input/{t}/target=/b0/target");
            blake3::hash(body.as_bytes()).to_hex().to_string()
        };
        let side = |t: &str, s: u64, e: u64| {
            json!({
                "original_root": format!("/b0-input/{t}/tooling"),
                "target_from": format!("/b0-input/{t}/target"),
                "encoded_rustflags_hex": enc_hex(t),
                "runner_sha256": h("52"), "runner_blake3": h("53"),
                "guest_image_id": h("e4"), "guest_methods_blake3": h("e5"),
                "origin_manifest_blake3": h("77"), "materialized_manifest_blake3": h("77"),
                "start_unix": s, "end_unix": e,
                "invocations": [{"kind": "compile", "remap_args": [
                    format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target")],
                    "record_address": rec_addr(t)}]
            })
        };
        json!({
            "candidate": "sp1", "arch": arch,
            "manifest_path": "tools/b0-pre-measure-sp1/Cargo.toml",
            "artifact_path": "release/b0-pre-measure-sp1", "cargo_ident": "cargo", "b0_venue_embed": "0",
            "canonical_build_path": "/b0/tooling", "canonical_cargo_home": "/b0/cargo",
            "per_arch_toolchain_identity": h("e2"), "wrapper_blake3": h("e3"),
            "build_argv": ["cargo","build","--release","--locked","--features","real-backend","--manifest-path","tools/b0-pre-measure-sp1/Cargo.toml"],
            "build_env": [["BUILD_GIT_SHA", crate::guest_set::RATIFIED_SOURCE_COMMIT], ["SOURCE_DATE_EPOCH","0"], ["B0_VENUE_EMBED","0"]],
            "build_a": side("a", 100, 200), "build_b": side("b", 200, 300), "byte_equal": true,
            "dependency_seed": {"address": dep_addr_hex, "json_sha256": h("ds")},
            "cargo_seed": {"origin_address": cargo_seed_hex.clone(), "materialized_a": cargo_seed_hex.clone(), "materialized_b": cargo_seed_hex},
            "leakage_refused_prefixes": ["/b0-input/a/tooling","/b0-input/a/target","/b0-input/b/tooling","/b0-input/b/target","/tmp/b0-evid"],
            "leakage_permitted_prefixes": ["/b0/cargo", "/b0/target", "/b0/tooling"],
            "leakage_clean": true, "evidence_root": "/tmp/b0-evid"
        })
    }
    fn prov(cand: &str, arch: &str, role: &str) -> Value {
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
            "runner_recipe": runner_recipe(cand, arch)
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
            "guest": {
                "guest_source_tree_hash": h("a2"), "candidate_dep_lock_hash": h("a3"),
                "guest_image_hash": img, "program_id": prog, "build_command_hash": h("a4"),
                "reproducible": true,
                "builder": [{"arch": arch, "builder_container_digest": builder}]
            },
            "verifier_material": [{"role": "Groth16Vk", "byte_len": 292u64, "hash": vk}],
            "provenance": [prov(cand, arch, "Proving"), prov(cand, arch, "Verification")],
            "cells": cells(arch),
            "dependency_seed_json": String::from_utf8(
                crate::measurement::synth_dependency_seed(if cand == "Sp1" {
                    crate::enums::Candidate::Sp1
                } else {
                    crate::enums::Candidate::Risc0
                })
                .0,
            )
            .expect("synthetic dependency-seed JSON is UTF-8"),
            // Phase-1 identity record (runner continuity): production_binary_blake3 == the provenance
            // runner attestation's runner_blake3 (h("53")); same measured-source/tooling/spec.
            "identity_records": [{
                "arch": arch,
                "source_commit": crate::guest_set::RATIFIED_SOURCE_COMMIT,
                "tooling_commit": "1234567890abcdef1234567890abcdef12345678",
                "tooling_pathset_blake3": h("70"),
                "b0_pre_spec_hash": SPEC,
                "production_binary_blake3": h("53")
            }],
            // Every fragment carries byte-identical measurement-input authority + report + inventory.
            "measurement_input_authority": include_str!(
                "../../../docs/b0-pre/fixtures/measurement-input-authority/measurement-input-authority.v1.json"
            ),
            "malformed_corpus_report": include_str!(
                "../../../docs/b0-pre/fixtures/measurement-input-authority/malformed-corpus-report.v1.json"
            ),
            "harness_source_inventory": include_str!(
                "../../../docs/b0-pre/fixtures/measurement-input-authority/harness-source-inventory.txt"
            ),
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
        let (_al, _mia, _report, _inv, bundles) = parse_vector(&pkg.vector).unwrap();
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
    fn dependency_seed_missing_mutated_swapped_and_skew_refused() {
        use crate::venue::dependency_seed::DependencySeedV1;
        // MISSING/empty dependency_seed_json in a fragment -> refused.
        let mut nf = frag("Sp1", "x86_64");
        nf.as_object_mut().unwrap().remove("dependency_seed_json");
        let e = merge_fragments(SPEC, &[nf, frag("Sp1", "aarch64"), frag("Risc0", "x86_64")])
            .unwrap_err()
            .to_lowercase();
        assert!(e.contains("dependency_seed_json"), "{e}");

        // MUTATED seed (corrupt a graph hash inside the JSON, leave `address` stale) -> authenticity fail.
        let mut mf = frag("Sp1", "x86_64");
        {
            let mut dep: Value =
                serde_json::from_str(mf["dependency_seed_json"].as_str().unwrap()).unwrap();
            dep["graphs"][0]["lock_sha256"] = json!("0".repeat(64));
            mf["dependency_seed_json"] = json!(serde_json::to_string(&dep).unwrap());
        }
        let e = merge_fragments(SPEC, &[mf, frag("Sp1", "aarch64"), frag("Risc0", "x86_64")])
            .unwrap_err()
            .to_lowercase();
        assert!(
            e.contains("authenticity") || e.contains("dependency-seed"),
            "{e}"
        );

        // SWAPPED/cross-candidate: RISC0's seed on an SP1 fragment -> verify(candidate) refuses.
        let mut sf = frag("Sp1", "x86_64");
        sf["dependency_seed_json"] = frag("Risc0", "x86_64")["dependency_seed_json"].clone();
        assert!(
            merge_fragments(SPEC, &[sf, frag("Sp1", "aarch64"), frag("Risc0", "x86_64")]).is_err()
        );

        // BYTE-IDENTITY skew: the two SP1 fragments carry DIFFERENT (but individually valid) sp1 seeds.
        let (other_sp1_json, _addr, _c) = DependencySeedV1::synthetic_json("sp1", [7u8; 32]);
        let mut arm = frag("Sp1", "aarch64");
        arm["dependency_seed_json"] = json!(String::from_utf8(other_sp1_json).unwrap());
        let e = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), arm, frag("Risc0", "x86_64")])
            .unwrap_err();
        assert!(e.contains("disagree on /dependency_seed_json"), "{e}");
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
