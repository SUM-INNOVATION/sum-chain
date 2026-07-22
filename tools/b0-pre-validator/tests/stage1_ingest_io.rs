//! Fail-closed `stage1-ingest` I/O, driven through the ACTUAL compiled binaries.
//! Covers the AUTHORITATIVE accept-path (assemble -> ingest -> durable finalizable
//! temp), the Blocker-4 TEST_ONLY REFUSAL, existing-output refusal, the
//! committed-artifact target guard, and malformed input. Stale-temp / write-failure
//! cleanup is unit-tested in `b0_pre_validator::durable`.

use std::path::PathBuf;
use std::process::Command;

const INGEST: &str = env!("CARGO_BIN_EXE_stage1-ingest");
const ASSEMBLE: &str = env!("CARGO_BIN_EXE_stage6-assemble");

fn workdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-ingest-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn committed_artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/b0-pre/protocol/b0-pre-protocol-v1.json")
}

/// Write the six real-shaped venue outputs (from the shared TEST_ONLY producer) to
/// `dir` and return their paths. The seventh input — tool identities — is written
/// by the caller so the classification (authoritative vs test-only) can differ.
fn write_venue_outputs(dir: &std::path::Path) -> [PathBuf; 6] {
    let v = b0_pre_validator::schema::stage6::test_only_venue_outputs();
    let oci = dir.join("digests.json");
    let sp1_ext = dir.join("sp1-verifier-material.json");
    let risc0_ext = dir.join("risc0-verifier-material.json");
    let native = dir.join("native-provenance.json");
    let sp1_lock = dir.join("sp1.Cargo.lock");
    let risc0_lock = dir.join("risc0.Cargo.lock");
    std::fs::write(&oci, &v.oci_digests_json).unwrap();
    std::fs::write(&sp1_ext, &v.sp1_extractor_json).unwrap();
    std::fs::write(&risc0_ext, &v.risc0_extractor_json).unwrap();
    std::fs::write(&native, &v.native_json).unwrap();
    std::fs::write(&sp1_lock, &v.sp1_cargo_lock).unwrap();
    std::fs::write(&risc0_lock, &v.risc0_cargo_lock).unwrap();
    [oci, sp1_ext, risc0_ext, native, sp1_lock, risc0_lock]
}

/// A complete AUTHORITATIVE tool-identity file with well-formed, NON-synthetic
/// fields (a test fixture, not real installer metadata).
fn authoritative_tools_json() -> String {
    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }
    let tool = |name: &str, version: &str| {
        // a deterministic well-formed 64-hex checksum that is not a placeholder.
        let cs = hex(&b0_pre_validator::hashing::plain(
            format!("auth-{name}-{version}").as_bytes(),
        ));
        format!(
            r#"{{"name":"{name}","version":"{version}","artifact_identity":"https://fixtures.invalid/{name}-{version}.tar","checksum_algorithm":"sha256","checksum_hex":"{cs}","install_entrypoint":"cargo:{name}@{version}"}}"#
        )
    };
    format!(
        r#"{{"tool_identities":[
            {{"candidate":"Sp1","rust_version":"1.88.0","proof_tools":[{}]}},
            {{"candidate":"Risc0","rust_version":"1.88.0","proof_tools":[{},{}]}}
        ]}}"#,
        tool("sp1-verifier", "6.3.1"),
        tool("risc0-zkvm", "3.0.5"),
        tool("risc0-groth16", "3.0.4"),
    )
}

/// Assemble an AUTHORITATIVE_STAGE1 bundle via the real `stage6-assemble` binary.
fn make_authoritative_bundle(dir: &std::path::Path) -> PathBuf {
    let [oci, sp1_ext, risc0_ext, native, sp1_lock, risc0_lock] = write_venue_outputs(dir);
    let tools = dir.join("tool-identities.json");
    std::fs::write(&tools, authoritative_tools_json()).unwrap();
    let bundle = dir.join("stage1-result-bundle.json");
    let status = Command::new(ASSEMBLE)
        .args([
            &oci,
            &sp1_ext,
            &risc0_ext,
            &native,
            &tools,
            &sp1_lock,
            &risc0_lock,
            &bundle,
        ])
        .status()
        .unwrap();
    assert!(status.success(), "authoritative assembly must succeed");
    bundle
}

/// Assemble a TEST_ONLY bundle via `stage6-assemble --test-only`.
fn make_test_only_bundle(dir: &std::path::Path) -> PathBuf {
    let bundle = dir.join("test-only-bundle.json");
    let status = Command::new(ASSEMBLE)
        .arg("--test-only")
        .arg(&bundle)
        .status()
        .unwrap();
    assert!(status.success(), "test-only assembly must succeed");
    bundle
}

#[test]
fn happy_path_authoritative_bundle_writes_a_finalizable_temp_artifact() {
    // Demonstration (1): real-shaped AUTHORITATIVE producer outputs -> assembler ->
    // AUTHORITATIVE_STAGE1 bundle -> stage1-ingest -> finalizable TEMP artifact.
    let dir = workdir();
    let bundle = make_authoritative_bundle(&dir);
    let out = dir.join("b0-pre-protocol-v1.finalizable.json");

    let status = Command::new(INGEST)
        .arg(&bundle)
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "authoritative bundle must be accepted");
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(written.contains("\"finalizable\""));
    // it is NOT the committed artifact
    assert!(!committed_artifact_path()
        .to_string_lossy()
        .eq(&out.to_string_lossy()));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_only_bundle_is_refused_by_authoritative_ingest() {
    // Demonstration (2): TEST_ONLY producer outputs -> assembler/test path ->
    // stage1-ingest REFUSES -> NO finalizable artifact.
    let dir = workdir();
    let bundle = make_test_only_bundle(&dir);
    let out = dir.join("out.json");

    // the explicit test-only validation succeeds on the same bundle...
    let vstatus = Command::new(ASSEMBLE)
        .arg("--validate-test-only")
        .arg(&bundle)
        .status()
        .unwrap();
    assert!(
        vstatus.success(),
        "test-only validation of a TEST_ONLY bundle must succeed"
    );
    // ...but authoritative ingest refuses it and writes nothing.
    let status = Command::new(INGEST)
        .arg(&bundle)
        .arg(&out)
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "a TEST_ONLY bundle must be refused by authoritative ingest"
    );
    assert!(!out.exists(), "no finalizable artifact may be written");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn existing_output_is_refused_never_silently_replaced() {
    let dir = workdir();
    let bundle = make_authoritative_bundle(&dir);
    let out = dir.join("out.json");
    std::fs::write(&out, b"PRIOR VENUE RESULT").unwrap();

    let status = Command::new(INGEST)
        .arg(&bundle)
        .arg(&out)
        .status()
        .unwrap();
    assert!(!status.success(), "a pre-existing output must be refused");
    assert_eq!(std::fs::read(&out).unwrap(), b"PRIOR VENUE RESULT");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn committed_artifact_target_is_refused() {
    let dir = workdir();
    let bundle = make_authoritative_bundle(&dir);
    let committed = committed_artifact_path();
    let before = std::fs::read(&committed).ok();

    let status = Command::new(INGEST)
        .arg(&bundle)
        .arg(&committed)
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "writing the committed normative artifact must be refused"
    );
    let after = std::fs::read(&committed).ok();
    assert_eq!(before, after, "committed artifact must be untouched");
    let text = String::from_utf8(after.unwrap()).unwrap();
    assert!(text.contains("\"not_finalizable\""));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn malformed_bundle_writes_nothing() {
    let dir = workdir();
    let bundle = dir.join("bundle.json");
    let out = dir.join("out.json");
    std::fs::write(&bundle, b"not json at all").unwrap();

    let status = Command::new(INGEST)
        .arg(&bundle)
        .arg(&out)
        .status()
        .unwrap();
    assert!(!status.success(), "malformed bundle must be refused");
    assert!(!out.exists(), "no artifact may be written for a bad bundle");
    std::fs::remove_dir_all(&dir).ok();
}
