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
    fn prov(arch: &str, role: &str) -> Value {
        json!({
            "arch": arch, "role": role, "source_commit": crate::guest_set::RATIFIED_SOURCE_COMMIT,
            "dirty_tree_flag": false,
            "builder_container_digest": h("b0"), "host_os": "Linux", "kernel": "6.1.0",
            "cpu_vendor": "GenuineIntel", "cpu_model": "Xeon", "physical_core_count": 8,
            "logical_cpu_count": 8, "total_ram_bytes": 34359738368u64,
            "configured_cpuset_core_limit": 8, "configured_memory_limit_bytes": 34359738368u64,
            "governor": "performance", "turbo_enabled": false, "clock_source": "tsc",
            "cgroup_version": 2, "cgroup_scope_label": "/b0.slice", "benchmark_harness_source_hash": h("d1"),
            "raw_environment_capture_hash": h("d2")
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
            "cells": cells(arch)
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
