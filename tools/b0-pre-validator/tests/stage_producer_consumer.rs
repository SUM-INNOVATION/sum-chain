//! Blocker 1: producer→consumer compatibility. Proves EVERY file emitted by the
//! Stage 1-5 producers (in their off-venue dry mode) + the real aggregation decodes
//! DIRECTLY in the Stage-6 assembler with NO manual reshaping, and drives the two
//! distinct outcomes:
//!   (1) real-shaped producer outputs -> assembler -> bundle -> validation;
//!   (2) the resulting TEST_ONLY bundle is REFUSED by authoritative `stage1-ingest`.
//!
//! The venue steps (Docker / toolchains / verifier-material extractors) can't run
//! here, so the container/native/lock/tool producers run in dry mode and the
//! verifier-material JSON comes from the SHARED canonical primitive (exactly what
//! the real extractor emits). The aggregation logic itself runs for real.

use std::path::{Path, PathBuf};
use std::process::Command;

const ASSEMBLE: &str = env!("CARGO_BIN_EXE_stage6-assemble");
const INGEST: &str = env!("CARGO_BIN_EXE_stage1-ingest");

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../b0-pre-candidates/scripts")
}

fn workdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-prodcons-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run a producer script in dry mode; assert success.
fn dry(script: &str, args: &[&str]) {
    let status = Command::new("bash")
        .arg(scripts_dir().join(script))
        .args(args)
        .env("SUMCHAIN_B0PRE_DRYRUN", "1")
        .status()
        .unwrap_or_else(|e| panic!("spawn {script}: {e}"));
    assert!(
        status.success(),
        "producer {script} must succeed in dry mode"
    );
}

fn run(script: &str, args: &[&str]) {
    let status = Command::new("bash")
        .arg(scripts_dir().join(script))
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {script}: {e}"));
    assert!(status.success(), "{script} must succeed");
}

/// Drive the Stage 1-5 producers (dry) + real aggregation into `work`, and write the
/// verifier-material extractor JSON from the shared canonical primitive.
fn generate_stage6_inputs(work: &Path) {
    let w = work.to_str().unwrap();
    for (cand, arch) in [
        ("sp1", "x86_64"),
        ("sp1", "aarch64"),
        ("risc0", "x86_64"),
        ("risc0", "aarch64"),
    ] {
        dry("build_container.sh", &[cand, arch, w]);
    }
    dry("resolve_lock.sh", &["sp1", w]);
    dry("resolve_lock.sh", &["risc0", w]);
    dry("tool_identities.sh", &[w]);
    // the real aggregation logic runs for real (no dry env needed).
    run("aggregate_stage6_inputs.sh", &[w]);

    // verifier-material JSON from the SHARED canonical primitive (the real extractor's
    // identity path), written to the files Stage 6 consumes.
    let v = b0_pre_validator::schema::stage6::test_only_venue_outputs();
    std::fs::write(
        work.join("sp1-verifier-material.json"),
        &v.sp1_extractor_json,
    )
    .unwrap();
    std::fs::write(
        work.join("risc0-verifier-material.json"),
        &v.risc0_extractor_json,
    )
    .unwrap();
}

/// The seven Stage-6 input paths, in assembler argument order.
fn stage6_inputs(work: &Path) -> [PathBuf; 7] {
    [
        work.join("digests.json"),
        work.join("sp1-verifier-material.json"),
        work.join("risc0-verifier-material.json"),
        work.join("native-provenance.json"),
        work.join("tool-identities.json"),
        work.join("Sp1.Cargo.lock"),
        work.join("Risc0.Cargo.lock"),
    ]
}

#[test]
fn producer_outputs_decode_directly_in_stage6_and_test_only_is_refused() {
    let work = workdir();
    generate_stage6_inputs(&work);
    let inputs = stage6_inputs(&work);
    for p in &inputs {
        assert!(p.is_file(), "producer output {} must exist", p.display());
    }
    let bundle = work.join("stage1-result-bundle.json");

    // (compatibility) EVERY producer file decodes directly in Stage 6 with no
    // reshaping: the assembler consumes them verbatim into a TEST_ONLY bundle.
    let mut cmd = Command::new(ASSEMBLE);
    cmd.arg("--test-only-from-files");
    for p in &inputs {
        cmd.arg(p);
    }
    cmd.arg(&bundle);
    let status = cmd.status().unwrap();
    assert!(
        status.success(),
        "aggregated producer files must decode directly in the Stage-6 assembler"
    );

    // (1) the produced TEST_ONLY bundle passes full test-only validation...
    let vstatus = Command::new(ASSEMBLE)
        .arg("--validate-test-only")
        .arg(&bundle)
        .status()
        .unwrap();
    assert!(vstatus.success(), "test-only validation must succeed");

    // (2) ...but authoritative ingest REFUSES it, producing NO finalizable artifact.
    let out = work.join("out.json");
    let istatus = Command::new(INGEST)
        .arg(&bundle)
        .arg(&out)
        .status()
        .unwrap();
    assert!(
        !istatus.success(),
        "a TEST_ONLY bundle must be refused by authoritative ingest"
    );
    assert!(!out.exists(), "no finalizable artifact may be written");

    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn aggregation_produces_exactly_the_stage6_aggregate_shapes() {
    // The aggregation concatenates without reshaping: 8 container builds (2x2x2),
    // 4 native builds, 2 tool identities.
    let work = workdir();
    generate_stage6_inputs(&work);
    let digests: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("digests.json")).unwrap()).unwrap();
    assert_eq!(digests["builds"].as_array().unwrap().len(), 8);
    let native: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("native-provenance.json")).unwrap())
            .unwrap();
    assert_eq!(native["native_builds"].as_array().unwrap().len(), 4);
    let tools: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("tool-identities.json")).unwrap()).unwrap();
    assert_eq!(tools["tool_identities"].as_array().unwrap().len(), 2);
    // every synthetic tool identity is unmistakably sentinel-marked.
    for t in tools["tool_identities"].as_array().unwrap() {
        for pt in t["proof_tools"].as_array().unwrap() {
            assert!(pt["artifact_identity"]
                .as_str()
                .unwrap()
                .contains("TEST_ONLY_SYNTHETIC"));
        }
    }
    std::fs::remove_dir_all(&work).ok();
}
