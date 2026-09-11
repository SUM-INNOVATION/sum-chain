//! Bypassing verification must be a COMPILE error, not a runtime one.
//!
//! These are the expressions a caller would reach for to publish without
//! verifying. Each is compiled on its own and must fail. A runtime assertion
//! could not express this: the point is that the mistake has no representation.

/// Compile one snippet against this workspace; return true if it FAILED to
/// compile, which is the desired outcome.
fn rejected(body: &str) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("probe.rs");
    let program = format!(
        "fn main() {{}}\n\
         #[allow(unused, dead_code)]\n\
         fn probe(db: &sumchain_storage::db::Database) {{\n{body}\n}}\n"
    );
    std::fs::write(&src, program).expect("write probe");

    let deps = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/deps");
    let out = std::process::Command::new(env!("CARGO"))
        .args(["--version"])
        .output();
    assert!(out.is_ok(), "cargo must be available");

    let compile = std::process::Command::new("rustc")
        .args(["--edition", "2021", "--crate-type", "bin", "-o"])
        .arg(dir.path().join("probe_bin"))
        .arg(&src)
        .arg("-L")
        .arg(&deps)
        .arg("--extern")
        .arg(format!("sumchain_storage={}", find_rlib(&deps)))
        .output()
        .expect("run rustc");

    (
        !compile.status.success(),
        String::from_utf8_lossy(&compile.stderr).to_string(),
    )
}

fn find_rlib(deps: &std::path::Path) -> String {
    let mut best: Option<(std::time::SystemTime, String)> = None;
    for e in std::fs::read_dir(deps).expect("read deps dir") {
        let p = e.expect("entry").path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("libsumchain_storage-") && name.ends_with(".rlib") {
            let m = p.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| m > *t) {
                best = Some((m, p.to_string_lossy().to_string()));
            }
        }
    }
    best.expect("sumchain_storage rlib must exist; run `cargo build -p sumchain-storage` first")
        .1
}

#[test]
fn the_probe_harness_accepts_valid_code() {
    // Guard the guard: if everything failed to compile for an unrelated reason,
    // the rejection tests below would pass vacuously.
    let (failed, stderr) = rejected(
        "let mut c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let mut v = c.view();\n\
         let _ = v.put(sumchain_storage::db::cf::STATE, b\"k\", b\"v\");",
    );
    assert!(
        !failed,
        "the harness cannot compile valid code, so its rejections prove nothing:\n{stderr}"
    );
}

#[test]
fn publishing_without_verifying_does_not_compile() {
    let (failed, stderr) = rejected(
        "let c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let _b = c.into_batch();",
    );
    assert!(
        failed,
        "CandidateExecution must NOT expose into_batch — publication has to go \
         through verification"
    );
    assert!(
        stderr.contains("into_batch"),
        "expected the failure to name into_batch:\n{stderr}"
    );
}

#[test]
fn the_overlay_cannot_be_published_directly_from_outside_the_crate() {
    let (failed, stderr) = rejected(
        "let o = sumchain_storage::overlay::ApplicationOverlay::new(db, 1024);\n\
         let _b = o.into_batch();",
    );
    assert!(
        failed,
        "ApplicationOverlay::into_batch must be crate-private, or the typestate \
         is bypassable by constructing an overlay directly"
    );
    assert!(
        stderr.contains("private") || stderr.contains("into_batch"),
        "expected a privacy error naming into_batch:\n{stderr}"
    );
}

#[test]
fn an_execution_view_cannot_publish() {
    let (failed, _stderr) = rejected(
        "let mut c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let v = c.view();\n\
         let _b = v.publish();",
    );
    assert!(
        failed,
        "ExecutionView must not expose publication; execution helpers receive \
         only the view and must not be able to commit"
    );
}

#[test]
fn the_two_operand_comparison_does_not_exist() {
    // `verify(h, h)` was the forgeable shape: it proved a comparison occurred
    // and nothing about where either side came from. It is DELETED, not merely
    // hidden — a crate-private version would still be reachable from every
    // future caller inside the crate. The only verification path is
    // `verify_for_block`, which reads the expected root from the block.
    let (failed, stderr) = rejected(
        "let c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let h = sumchain_primitives::Hash::ZERO;\n\
         let _ = c.verify_computed_root(h, h);",
    );
    assert!(
        failed,
        "a two-operand root comparison must not exist; verification must read \
         the expected root from the block itself"
    );
    assert!(
        stderr.contains("private") || stderr.contains("verify_computed_root"),
        "expected a privacy error:\n{stderr}"
    );
}

#[test]
fn a_transition_cannot_be_built_with_fields_missing() {
    // Every field is private and there is one constructor taking all of them.
    let (failed, _stderr) = rejected(
        "let _t = sumchain_storage::candidate::CanonicalTransition { \n\
             block_hash: sumchain_primitives::Hash::ZERO,\n\
         };",
    );
    assert!(
        failed,
        "CanonicalTransition fields must be private, so a partially-specified \
         transition cannot be constructed"
    );
}
