//! Frozen, content-addressed Stage-2 fixtures for the two AUTHENTIC resolved graphs collected by
//! the native-x86 TEST_ONLY smoke at head cb365a4a (SMOKE-BLOCKED-004), and the offline proofs the
//! owner ruling requires: with only the two newly-approved atoms (`Unicode-3.0`,
//! `CDLA-Permissive-2.0`) both graphs produce ZERO license findings and pass required-crate
//! coverage, while missing/wrong/duplicate/cross-candidate required crates still fail closed.
//!
//! The fixture is a LOSSLESS POLICY PROJECTION: `parse_cargo_metadata(original)` -> the CrateNode
//! set `{name, version, source, license}` — which is the COMPLETE set of fields Stage-2 policy
//! (license + pins + source + duplicate + coverage) consumes; nothing else in the 2.5 MB / 1.7 MB
//! cargo metadata affects the verdict. Provenance binds each fixture to the exact source head,
//! candidate, arch, Stage-1 lock hash, builder digest, original metadata sha256, and the canonical
//! projection sha256. Regenerate (from the preserved authentic metadata) with:
//!   B0PRE_METADATA_DIR=/path/to/authentic cargo test --test authentic_stage2_graphs -- --ignored regenerate

use b0_pre_validator::venue::audit::{
    audit_graph, parse_cargo_metadata, require_candidate_pins, CrateNode, FatalKind,
    GraphCoverageError,
};
use b0_pre_validator::venue::license_policy::STAGE2_ALLOWED_LICENSES;

const SP1_FIXTURE: &str = include_str!("fixtures/sp1-stage2-graph.authentic.json");
const RISC0_FIXTURE: &str = include_str!("fixtures/risc0-stage2-graph.authentic.json");

// The allow-list as it stood BEFORE the SMOKE-BLOCKED-004 ruling (no Unicode-3.0 / CDLA-Permissive-2.0)
// — used only to prove the findings are resolved solely by the two approved atoms.
const ALLOW_PRE_RULING: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "MIT OR Apache-2.0",
    "Apache-2.0 OR MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "Apache-2.0 WITH LLVM-exception",
    "MPL-2.0",
    "Zlib",
    "CC0-1.0",
    "Unlicense",
];

fn sha256_hex(b: &[u8]) -> String {
    b0_pre_validator::venue::sha256::hex_digest(b)
}

/// Canonical serialization of the projected node set (stable key order + sorted) for content
/// addressing — order-independent so two runs of the same graph hash identically.
fn canonical_nodes(nodes: &[CrateNode]) -> Vec<u8> {
    let mut v: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| serde_json::to_value(n).unwrap())
        .collect();
    v.sort_by_key(|x| x.to_string());
    serde_json::to_vec(&v).unwrap()
}

struct Fixture {
    provenance: serde_json::Value,
    nodes: Vec<CrateNode>,
}
fn load(raw: &str) -> Fixture {
    let v: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
    let nodes: Vec<CrateNode> = serde_json::from_value(v["nodes"].clone()).expect("nodes decode");
    Fixture {
        provenance: v["provenance"].clone(),
        nodes,
    }
}

fn license_findings(nodes: &[CrateNode], allow: &[&str]) -> Vec<String> {
    audit_graph(nodes, &[], allow)
        .fatal_findings()
        .filter_map(|k| match k {
            FatalKind::DisallowedLicense {
                crate_name,
                license,
            } => Some(format!("{crate_name}: {license}")),
            FatalKind::UnlicensedCrate { crate_name } => Some(format!("{crate_name}: <none>")),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Provenance + losslessness

fn check_provenance(fx: &Fixture, candidate: &str, expected_count: usize) {
    let p = &fx.provenance;
    assert_eq!(p["source_head"], "cb365a4ac73b13116941409614bef1ceeba66925");
    assert_eq!(p["candidate"], candidate);
    assert_eq!(p["arch"], "X86_64");
    assert_eq!(
        p["package_count"].as_u64().unwrap() as usize,
        expected_count
    );
    assert_eq!(
        fx.nodes.len(),
        expected_count,
        "node count == package count"
    );
    // the projection re-hashes to its recorded content address (frozen, tamper-evident).
    assert_eq!(
        p["canonical_nodes_sha256"].as_str().unwrap(),
        sha256_hex(&canonical_nodes(&fx.nodes)),
        "canonical projection hash matches the recorded content address"
    );
    // lossless: EVERY policy-consumed field is present for every package (name+version+source; the
    // real graphs carry 0 license-file-only packages, asserted here).
    for n in &fx.nodes {
        assert!(!n.name.is_empty() && !n.version.is_empty());
        assert!(n.license.is_some(), "{} has no license expression", n.name);
    }
}

#[test]
fn sp1_fixture_provenance_and_losslessness() {
    let fx = load(SP1_FIXTURE);
    check_provenance(&fx, "Sp1", 529);
    assert_eq!(
        fx.provenance["original_metadata_sha256"],
        "48453e70be6d6f0f2eb657e88b7c5b620e99f6a09a5bd957f527b5d86c6fe076"
    );
    assert_eq!(
        fx.provenance["lock_blake3_hex"],
        "41931aed51b6ba79272f20db74130ada464d89c76a059dcf71e6cd1a85467d8a"
    );
}

#[test]
fn risc0_fixture_provenance_and_losslessness() {
    let fx = load(RISC0_FIXTURE);
    check_provenance(&fx, "Risc0", 359);
    assert_eq!(
        fx.provenance["original_metadata_sha256"],
        "d202606b4930756e914a7a6a1fe1fd5e3bd1ac45a72b90d384100539d0eff026"
    );
    assert_eq!(
        fx.provenance["lock_blake3_hex"],
        "a50526063463c1aefc776f1001e7d32605e208cb26885aceeec9a06cb58f4ff4"
    );
}

// ---------------------------------------------------------------------------------------------
// The ruling's offline proofs

#[test]
fn both_authentic_graphs_have_zero_license_findings_with_the_approved_policy() {
    for (raw, cand) in [(SP1_FIXTURE, "Sp1"), (RISC0_FIXTURE, "Risc0")] {
        let fx = load(raw);
        let findings = license_findings(&fx.nodes, STAGE2_ALLOWED_LICENSES);
        assert!(
            findings.is_empty(),
            "{cand}: expected 0 license findings under the approved policy, got {findings:?}"
        );
    }
}

/// The findings are resolved SOLELY by the two approved atoms: under the pre-ruling allow-list the
/// same graphs have exactly the 20 findings the audit reported; the ONLY licenses they add are
/// `Unicode-3.0` and `CDLA-Permissive-2.0`.
#[test]
fn the_findings_are_resolved_only_by_the_two_approved_atoms() {
    for (raw, cand) in [(SP1_FIXTURE, "Sp1"), (RISC0_FIXTURE, "Risc0")] {
        let fx = load(raw);
        let pre = license_findings(&fx.nodes, ALLOW_PRE_RULING);
        assert_eq!(pre.len(), 20, "{cand}: pre-ruling findings");
        // every pre-ruling finding is a license the two approved atoms cover.
        for f in &pre {
            let lic = f.split_once(": ").unwrap().1;
            assert!(
                lic.contains("Unicode-3.0") || lic.contains("CDLA-Permissive-2.0"),
                "{cand}: pre-ruling finding not covered by the two atoms: {f}"
            );
        }
    }
}

#[test]
fn both_authentic_graphs_pass_required_crate_coverage() {
    assert_eq!(
        require_candidate_pins(&load(SP1_FIXTURE).nodes, "Sp1"),
        Ok(())
    );
    // RISC Zero coverage passes ONLY because risc0-zkvm-platform is now required at 2.2.3.
    assert_eq!(
        require_candidate_pins(&load(RISC0_FIXTURE).nodes, "Risc0"),
        Ok(())
    );
}

/// The whole real graphs are otherwise clean: NO fatal finding at all under the approved policy
/// (no wrong-pin, source, duplicate, or advisory issues) — only the expected recorded prereleases.
#[test]
fn both_authentic_graphs_have_no_fatal_findings_end_to_end() {
    for (raw, cand) in [(SP1_FIXTURE, "Sp1"), (RISC0_FIXTURE, "Risc0")] {
        let fx = load(raw);
        let r = audit_graph(&fx.nodes, &[], STAGE2_ALLOWED_LICENSES);
        assert!(
            !r.is_fatal(),
            "{cand}: authentic graph must have no fatal finding, got {:?}",
            r.fatal_findings().collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Negatives on the authentic graphs

#[test]
fn missing_required_crate_fails_closed() {
    let mut n = load(SP1_FIXTURE).nodes;
    n.retain(|c| c.name != "sp1-verifier");
    assert!(matches!(
        require_candidate_pins(&n, "Sp1"),
        Err(GraphCoverageError::RequiredCrateAbsent { crate_name, .. }) if crate_name == "sp1-verifier"
    ));
}

#[test]
fn wrong_version_required_crate_fails_closed() {
    let mut n = load(RISC0_FIXTURE).nodes;
    // regress risc0-zkvm-platform back to 2.2.2 (the stale pin) -> coverage fails.
    for c in n.iter_mut() {
        if c.name == "risc0-zkvm-platform" {
            c.version = "2.2.2".into();
        }
    }
    assert!(matches!(
        require_candidate_pins(&n, "Risc0"),
        Err(GraphCoverageError::RequiredCrateAbsent { crate_name, version })
            if crate_name == "risc0-zkvm-platform" && version == "2.2.3"
    ));
}

#[test]
fn duplicated_required_crate_fails_closed() {
    let mut n = load(SP1_FIXTURE).nodes;
    let dup = n.iter().find(|c| c.name == "sp1-sdk").unwrap().clone();
    n.push(dup);
    assert!(matches!(
        require_candidate_pins(&n, "Sp1"),
        Err(GraphCoverageError::RequiredCrateDuplicated { crate_name, .. }) if crate_name == "sp1-sdk"
    ));
}

#[test]
fn cross_candidate_graph_fails_closed() {
    assert!(matches!(
        require_candidate_pins(&load(SP1_FIXTURE).nodes, "Risc0"),
        Err(GraphCoverageError::RequiredCrateAbsent { .. })
    ));
    assert!(matches!(
        require_candidate_pins(&load(RISC0_FIXTURE).nodes, "Sp1"),
        Err(GraphCoverageError::RequiredCrateAbsent { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// Regenerator (ignored by default; run explicitly against the preserved authentic metadata).

#[test]
#[ignore = "run explicitly with B0PRE_METADATA_DIR set to the preserved authentic metadata"]
fn regenerate() {
    let dir = std::env::var("B0PRE_METADATA_DIR").expect("set B0PRE_METADATA_DIR");
    // (candidate, arch, metadata sha256, lock blake3, builder digest)
    let jobs = [
        (
            "Sp1",
            "Sp1.cargo-metadata.json",
            "48453e70be6d6f0f2eb657e88b7c5b620e99f6a09a5bd957f527b5d86c6fe076",
            "41931aed51b6ba79272f20db74130ada464d89c76a059dcf71e6cd1a85467d8a",
            "sha256:2b38036628803ca2613b717b9b015cede28c41aa57034749992d310a3b5fd152",
            "sp1-stage2-graph.authentic.json",
        ),
        (
            "Risc0",
            "Risc0.cargo-metadata.json",
            "d202606b4930756e914a7a6a1fe1fd5e3bd1ac45a72b90d384100539d0eff026",
            "a50526063463c1aefc776f1001e7d32605e208cb26885aceeec9a06cb58f4ff4",
            "sha256:5112a049554885e10f89e0dc63f6e7a7bc8561fe64c92299b8549bda55d87ea5",
            "risc0-stage2-graph.authentic.json",
        ),
    ];
    for (cand, meta, meta_sha, lock, builder, out) in jobs {
        let raw = std::fs::read_to_string(format!("{dir}/{meta}")).unwrap();
        assert_eq!(
            sha256_hex(raw.as_bytes()),
            meta_sha,
            "authentic metadata hash"
        );
        let nodes = parse_cargo_metadata(&raw).expect("parse authentic metadata");
        let provenance = serde_json::json!({
            "source_head": "cb365a4ac73b13116941409614bef1ceeba66925",
            "candidate": cand,
            "arch": "X86_64",
            "lock_blake3_hex": lock,
            "builder_container_digest": builder,
            "original_metadata_sha256": meta_sha,
            "package_count": nodes.len(),
            "projection": "LOSSLESS policy projection: parse_cargo_metadata(original) -> CrateNode{name,version,source,license} — the complete set of fields Stage-2 policy consumes",
            "canonical_nodes_sha256": sha256_hex(&canonical_nodes(&nodes)),
        });
        let doc = serde_json::json!({ "provenance": provenance, "nodes": nodes });
        std::fs::write(
            format!("{}/tests/fixtures/{out}", env!("CARGO_MANIFEST_DIR")),
            serde_json::to_vec_pretty(&doc).unwrap(),
        )
        .unwrap();
        eprintln!("wrote {out}: {} nodes", nodes.len());
    }
}
