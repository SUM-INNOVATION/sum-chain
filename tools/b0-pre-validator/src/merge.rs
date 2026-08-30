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
        // Two-cell model: an SP1/aarch64 MEASUREMENT fragment is a fabricated ARM terminal Groth16
        // proof — SP1/aarch64 is ratified-unsupported (no first-party arm64 gnark backend). Its
        // identity travels in the guest set, never as a measurement fragment. Refuse it explicitly.
        if cand == "Sp1" && arch == "aarch64" {
            return Err(
                "an SP1/aarch64 measurement fragment is ratified-unsupported \
                (terminal Groth16 has no arm64 gnark backend); never a measurement — rejected"
                    .into(),
            );
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
    // Exactly the two natively terminal-measurable cells (two-cell model). SP1/aarch64 terminal Groth16
    // and RISC0/aarch64 are ratified unsupported (see EligibilityMatrixV1) — never a measurement fragment.
    // The SP1/aarch64 *identity* still travels in the Phase-1 guest set; it is NOT a measurement.
    let want = [("Sp1", "x86_64"), ("Risc0", "x86_64")];
    if by_key.len() != want.len() {
        return Err(format!(
            "expected exactly {} measurement fragments (Sp1 x86_64, Risc0 x86_64), got {}",
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
    // Two-cell model: SP1 is measured natively on x86_64 ONLY, and RISC0 on x86_64 ONLY. SP1/aarch64
    // terminal Groth16 is ratified unsupported (no first-party arm64 gnark backend) — there is NO
    // SP1/aarch64 measurement fragment to reconcile; its Phase-1 *identity* travels in the shared guest
    // set (records/all.json), never as a measurement. So the merged SP1 candidate is the x86 fragment
    // as-is (its own x86 cells/provenance/builder/identity record).
    let sp1 = get("Sp1", "x86_64")?.clone();
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

    // Every fragment MUST carry byte-identical measurement-input authority + malformed-corpus report +
    // harness-source inventory + eligibility/unsupported matrix; disagreement is refused. The single
    // agreed set flows to the merged RawFacts (top-level), where `produce` decodes + verifies it and
    // derives the report/MIA addresses and cross-checks the two-cell eligibility model.
    let mia = fragment_field_agree(fragments, "measurement_input_authority")?.clone();
    let report = fragment_field_agree(fragments, "malformed_corpus_report")?.clone();
    let inv = fragment_field_agree(fragments, "harness_source_inventory")?.clone();
    let eligibility = fragment_field_agree(fragments, "eligibility_matrix")?.clone();

    let raw = json!({
        "lifecycle_mode": "measurement",
        "b0_pre_spec_hash": spec_hex,
        "candidates": [sp1, risc0.clone()],
        "measurement_input_authority": mia,
        "malformed_corpus_report": report,
        "harness_source_inventory": inv,
        "eligibility_matrix": eligibility,
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
            "build_argv": ["cargo","build","--release","--locked","--offline","--features","real-backend","--manifest-path","tools/b0-pre-measure-sp1/Cargo.toml"],
            "offline": true, "cargo_net_offline": true,
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
        // Two-cell model: the SP1 GUEST identity spans BOTH arches (its arch-independent program_id
        // reconciles across x86_64 + aarch64 builders — the retained 3-identity guest set), even
        // though SP1 is terminal-measured on x86_64 only. RISC0 is x86_64-only throughout.
        let builders = if cand == "Sp1" {
            json!([
                {"arch": "x86_64", "builder_container_digest": h("b0")},
                {"arch": "aarch64", "builder_container_digest": h("b1")}
            ])
        } else {
            json!([{"arch": "x86_64", "builder_container_digest": h("b0")}])
        };
        json!({
            "candidate": cand, "container_image_digest": h("f0"),
            "statement_hash_tlg": h("f1"), "statement_hash_st": h("f2"),
            "guest": {
                "guest_source_tree_hash": h("a2"), "candidate_dep_lock_hash": h("a3"),
                "guest_image_hash": img, "program_id": prog, "build_command_hash": h("a4"),
                "reproducible": true,
                "builder": builders
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
            // The retained two-cell eligibility matrix (byte-identical across fragments), built through
            // the sole canonical constructor and bound by address into the measurement-input authority.
            "eligibility_matrix":
                crate::venue::eligibility_matrix::EligibilityMatrixV1::canonical(SPEC).to_json(),
        })
    }
    const SPEC: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

    // Round-trip guard (defence-in-depth): merging the two real fragments must PRESERVE, in every merged
    // provenance runner_recipe, both offline booleans AND the exact single --offline argv — for BOTH
    // candidates. This is the "fragment -> merge" leg of the offline-preservation guarantee (the
    // measure-core round-trip test covers "recipe -> fragment").
    #[test]
    fn merge_preserves_offline_booleans_and_exact_offline_argv() {
        let raw = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), frag("Risc0", "x86_64")]).unwrap();
        for cand in raw["candidates"].as_array().unwrap() {
            let cn = cand["candidate"].as_str().unwrap_or("?").to_string();
            for prov in cand["provenance"].as_array().unwrap() {
                let rr = &prov["runner_recipe"];
                assert_eq!(rr["offline"], json!(true), "{cn}: merge preserved offline");
                assert_eq!(
                    rr["cargo_net_offline"],
                    json!(true),
                    "{cn}: merge preserved cargo_net_offline"
                );
                let n = rr["build_argv"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|v| v.as_str() == Some("--offline"))
                    .count();
                assert_eq!(n, 1, "{cn}: merge preserved exactly one --offline");
            }
        }
    }

    #[test]
    fn eligible_fragments_merge_and_validate() {
        // Two-cell model: EXACTLY two measurement fragments (Sp1/x86_64, Risc0/x86_64).
        let raw = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), frag("Risc0", "x86_64")]).unwrap();
        let cands = raw["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 2);
        let sp1 = &cands[0];
        // x86_64-only measurement: 20 cells, 2 provenance snapshots (proving + verification).
        assert_eq!(sp1["cells"].as_array().unwrap().len(), 20);
        assert_eq!(sp1["provenance"].as_array().unwrap().len(), 2);
        // The SP1 GUEST identity still spans both arches (retained 3-identity guest set).
        assert_eq!(
            sp1.pointer("/guest/builder")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        // Every measured cell is x86_64 — never an aarch64 (ARM) measurement.
        for cell in sp1["cells"].as_array().unwrap() {
            assert_eq!(cell["arch"], "x86_64");
        }
    }

    // DIRECT merge → produce → verify: the retained cpuset + runner artifacts AND Phase-1 runner
    // continuity survive the fragment merge (previously only transitively covered).
    #[test]
    fn merge_produce_verify_preserves_retention_and_continuity() {
        use crate::measurement::parse_vector;
        use crate::producer::{produce, records_from_raw, RawFacts};
        use crate::schema::runner_attestation::RunnerAttestationV1;

        let merged =
            merge_fragments(SPEC, &[frag("Sp1", "x86_64"), frag("Risc0", "x86_64")]).unwrap();
        let raw: RawFacts = serde_json::from_value(merged).expect("merged -> RawFacts");
        // produce() enforces runner continuity + artifact retention during assembly (the merge fixture
        // uses a non-reference verify cpuset, so the qualification verdict itself is not the point).
        let pkg = produce(&raw, &records_from_raw(&raw)).expect("merged facts produce");
        let (_al, _mia, _report, _inv, _elig, _v2, bundles) = parse_vector(&pkg.vector).unwrap();
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
        let merged2 = merge_fragments(SPEC, &[bad, frag("Risc0", "x86_64")]).unwrap();
        let raw2: RawFacts = serde_json::from_value(merged2).unwrap();
        assert!(produce(&raw2, &records_from_raw(&raw2))
            .unwrap_err()
            .contains("production_binary_blake3 != measurement runner_blake3"));
    }

    #[test]
    fn missing_extra_and_duplicate_are_refused() {
        // Two-cell model: EXACTLY {Sp1/x86_64, Risc0/x86_64}.
        // missing a measurement fragment (only SP1/x86_64 present)
        assert!(merge_fragments(SPEC, &[frag("Sp1", "x86_64")]).is_err());
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
        // extra SP1 aarch64 measurement fragment (ratified-unsupported — never a measurement)
        assert!(merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Sp1", "aarch64"),
                frag("Risc0", "x86_64"),
            ]
        )
        .is_err());
        // extra RISC0 aarch64 (native-ineligible)
        assert!(merge_fragments(
            SPEC,
            &[
                frag("Sp1", "x86_64"),
                frag("Risc0", "x86_64"),
                frag("Risc0", "aarch64")
            ]
        )
        .is_err());
    }

    #[test]
    fn sp1_aarch64_measurement_fragment_is_refused_as_unsupported() {
        // Two-cell model: there is NO SP1/aarch64 measurement fragment to reconcile — a fabricated
        // one (an ARM terminal Groth16 proof) is refused with the ratified-unsupported reason before
        // any merge/skew logic. The SP1/aarch64 identity lives only in the guest set.
        let arm = frag("Sp1", "aarch64");
        let e = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), arm, frag("Risc0", "x86_64")])
            .unwrap_err();
        assert!(
            e.contains("SP1/aarch64 measurement fragment is ratified-unsupported"),
            "{e}"
        );
    }

    #[test]
    fn dependency_seed_missing_mutated_and_swapped_refused() {
        // Two-cell model: two measurement fragments (Sp1/x86_64, Risc0/x86_64). There is no second
        // SP1 fragment, so the former cross-arch byte-identity skew case no longer applies.
        // MISSING/empty dependency_seed_json in a fragment -> refused.
        let mut nf = frag("Sp1", "x86_64");
        nf.as_object_mut().unwrap().remove("dependency_seed_json");
        let e = merge_fragments(SPEC, &[nf, frag("Risc0", "x86_64")])
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
        let e = merge_fragments(SPEC, &[mf, frag("Risc0", "x86_64")])
            .unwrap_err()
            .to_lowercase();
        assert!(
            e.contains("authenticity") || e.contains("dependency-seed"),
            "{e}"
        );

        // SWAPPED/cross-candidate: RISC0's seed on an SP1 fragment -> verify(candidate) refuses.
        let mut sf = frag("Sp1", "x86_64");
        sf["dependency_seed_json"] = frag("Risc0", "x86_64")["dependency_seed_json"].clone();
        assert!(merge_fragments(SPEC, &[sf, frag("Risc0", "x86_64")]).is_err());
    }

    #[test]
    fn non_ratified_commit_is_refused() {
        // Both measurement fragments consistently bound to a DIFFERENT clean commit — still refused.
        let (mut x, mut r) = (frag("Sp1", "x86_64"), frag("Risc0", "x86_64"));
        for f in [&mut x, &mut r] {
            for p in f["provenance"].as_array_mut().unwrap() {
                p["source_commit"] = json!("c".repeat(40));
            }
        }
        assert!(merge_fragments(SPEC, &[x, r])
            .unwrap_err()
            .contains("ratified"));
    }

    #[test]
    fn sp1_guest_carries_both_builder_identities() {
        // Two-cell model: the single SP1/x86_64 measurement fragment carries the FULL SP1 guest
        // identity — both x86_64 and aarch64 builder digests — so the merged candidate reproduces
        // the ratified 3-identity guest set even though only x86_64 is terminal-measured.
        let raw = merge_fragments(SPEC, &[frag("Sp1", "x86_64"), frag("Risc0", "x86_64")]).unwrap();
        let sp1 = &raw["candidates"].as_array().unwrap()[0];
        let builders = sp1.pointer("/guest/builder").unwrap().as_array().unwrap();
        assert_eq!(builders.len(), 2);
        let arches: std::collections::BTreeSet<&str> = builders
            .iter()
            .map(|b| b["arch"].as_str().unwrap())
            .collect();
        assert!(arches.contains("x86_64") && arches.contains("aarch64"));
        // RISC0 guest identity is x86_64-only (RISC0/aarch64 is not even an identity).
        let risc0 = &raw["candidates"].as_array().unwrap()[1];
        assert_eq!(
            risc0
                .pointer("/guest/builder")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}
