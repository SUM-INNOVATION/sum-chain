//! Blocker 1 demonstration (structural, off-venue): drive the REAL venue commands
//! (`venue-verify import-arch` / `aggregate-arches`, then `stage6-assemble` /
//! `stage1-ingest`) over two per-architecture producer bundles.
//!
//! The container builds / extractions can't run here, so the per-arch bundle files
//! are the real-shaped synthetic outputs from the SHARED canonical primitive (the
//! same shapes the venue producers emit). This proves the import + cross-arch
//! aggregation commands work end-to-end, that a per-arch bundle carrying the wrong
//! RISC Zero coverage is refused, and — retained — that the resulting TEST_ONLY
//! bundle is REFUSED by authoritative ingest (no finalizable artifact). The genuine
//! AUTHORITATIVE accept path (finalizable artifact) is proven in-code by
//! `venue::arch_bundle::tests::genuine_two_arch_flow_reaches_a_finalizable_artifact_authoritatively`.

use std::path::{Path, PathBuf};
use std::process::Command;

const VENUE_VERIFY: &str = env!("CARGO_BIN_EXE_venue-verify");
const ASSEMBLE: &str = env!("CARGO_BIN_EXE_stage6-assemble");
const INGEST: &str = env!("CARGO_BIN_EXE_stage1-ingest");

fn workdir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-2arch-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Split the whole-run synthetic venue outputs into a per-arch producer bundle dir.
/// `with_risc0` controls whether the RISC Zero verifier material is present (true
/// for x86_64 only).
fn write_per_arch_bundle(dir: &Path, arch: &str, with_risc0: bool) {
    let v = b0_pre_validator::schema::stage6::test_only_venue_outputs();
    let oci: serde_json::Value = serde_json::from_str(&v.oci_digests_json).unwrap();
    let native: serde_json::Value = serde_json::from_str(&v.native_json).unwrap();

    for cand in ["Sp1", "Risc0"] {
        // this candidate+arch's 2 container builds (base + builder)
        let builds: Vec<serde_json::Value> = oci["builds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["candidate"] == cand && b["arch"] == arch)
            .cloned()
            .collect();
        assert_eq!(builds.len(), 2, "base + builder for {cand}/{arch}");
        let lc = cand.to_lowercase();
        std::fs::write(
            dir.join(format!("{lc}.{arch}.container.json")),
            serde_json::to_vec(&builds).unwrap(),
        )
        .unwrap();

        // this candidate+arch's native build
        let nb: Vec<serde_json::Value> = native["native_builds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["candidate"] == cand && n["arch"] == arch)
            .cloned()
            .collect();
        assert_eq!(nb.len(), 1);
        std::fs::write(
            dir.join(format!("{lc}.{arch}.native.json")),
            serde_json::to_vec(&nb).unwrap(),
        )
        .unwrap();

        // per-candidate synthetic tool identity + lock (for the aggregate step)
        std::fs::write(
            dir.join(format!("{cand}.tool.json")),
            per_candidate_tool_json(cand),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("sp1-verifier-material.json"),
        &v.sp1_extractor_json,
    )
    .unwrap();
    if with_risc0 {
        std::fs::write(
            dir.join("risc0-verifier-material.json"),
            &v.risc0_extractor_json,
        )
        .unwrap();
    }
    std::fs::write(dir.join("Sp1.Cargo.lock"), &v.sp1_cargo_lock).unwrap();
    std::fs::write(dir.join("Risc0.Cargo.lock"), &v.risc0_cargo_lock).unwrap();
}

fn per_candidate_tool_json(cand: &str) -> String {
    let outputs = b0_pre_validator::schema::stage6::test_only_venue_outputs();
    let all: serde_json::Value = serde_json::from_str(&outputs.tool_identities_json).unwrap();
    let entry = all["tool_identities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["candidate"] == cand)
        .unwrap()
        .clone();
    serde_json::to_string(&entry).unwrap()
}

fn vv(args: &[&str]) -> bool {
    Command::new(VENUE_VERIFY)
        .args(args)
        .status()
        .unwrap()
        .success()
}

#[test]
fn two_arch_import_aggregate_and_test_only_refusal() {
    let x86 = workdir("x86");
    let arm = workdir("arm");
    let out = workdir("agg");
    // the aggregate out dir must be empty (the bin refuses to overwrite)
    std::fs::remove_dir_all(&out).ok();

    write_per_arch_bundle(&x86, "X86_64", true);
    write_per_arch_bundle(&arm, "Aarch64", false);

    // (b) each per-arch bundle independently import-verifies
    assert!(
        vv(&["import-arch", x86.to_str().unwrap()]),
        "x86_64 bundle must import-verify"
    );
    assert!(
        vv(&["import-arch", arm.to_str().unwrap()]),
        "aarch64 bundle must import-verify"
    );

    // (c) cross-arch aggregation succeeds and writes the aggregate inputs
    assert!(
        vv(&[
            "aggregate-arches",
            x86.to_str().unwrap(),
            arm.to_str().unwrap(),
            out.to_str().unwrap(),
        ]),
        "cross-arch aggregation must succeed"
    );
    for f in [
        "digests.json",
        "native-provenance.json",
        "sp1-verifier-material.json",
        "risc0-verifier-material.json",
    ] {
        assert!(out.join(f).is_file(), "aggregate must write {f}");
    }

    // tool identities + locks for the assemble step
    let tools = out.join("tool-identities.json");
    std::fs::write(
        &tools,
        format!(
            r#"{{"tool_identities":[{},{}]}}"#,
            per_candidate_tool_json("Sp1"),
            per_candidate_tool_json("Risc0")
        ),
    )
    .unwrap();
    std::fs::copy(x86.join("Sp1.Cargo.lock"), out.join("Sp1.Cargo.lock")).unwrap();
    std::fs::copy(x86.join("Risc0.Cargo.lock"), out.join("Risc0.Cargo.lock")).unwrap();

    // assemble the (TEST_ONLY, synthetic) bundle from the aggregated inputs
    let bundle = out.join("stage1-result-bundle.json");
    let ok = Command::new(ASSEMBLE)
        .arg("--test-only-from-files")
        .arg(out.join("digests.json"))
        .arg(out.join("sp1-verifier-material.json"))
        .arg(out.join("risc0-verifier-material.json"))
        .arg(out.join("native-provenance.json"))
        .arg(&tools)
        .arg(out.join("Sp1.Cargo.lock"))
        .arg(out.join("Risc0.Cargo.lock"))
        .arg(&bundle)
        .status()
        .unwrap()
        .success();
    assert!(ok, "aggregated per-arch inputs must assemble a bundle");

    // RETAINED: authoritative ingest REFUSES the TEST_ONLY bundle -> no artifact.
    let artifact = out.join("artifact.json");
    let refused = !Command::new(INGEST)
        .arg(&bundle)
        .arg(&artifact)
        .status()
        .unwrap()
        .success();
    assert!(
        refused,
        "a TEST_ONLY bundle must be refused by authoritative ingest"
    );
    assert!(!artifact.exists(), "no finalizable artifact may be written");

    for d in [x86, arm, out] {
        std::fs::remove_dir_all(&d).ok();
    }
}

#[test]
fn aarch64_bundle_carrying_risc0_material_is_refused_on_import() {
    // arm64 must NOT attempt RISC Zero (VENUE.md §2): a per-arch bundle that wrongly
    // carries RISC Zero material fails import verification.
    let arm = workdir("arm-bad");
    write_per_arch_bundle(&arm, "Aarch64", true); // RISC Zero present on arm64 = wrong
    assert!(
        !vv(&["import-arch", arm.to_str().unwrap()]),
        "an aarch64 bundle carrying RISC Zero material must be refused"
    );
    std::fs::remove_dir_all(&arm).ok();
}
