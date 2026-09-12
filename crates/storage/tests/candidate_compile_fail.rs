//! Bypassing verification must be a COMPILE error, not a runtime one.
//!
//! These are the expressions a caller would reach for to publish without
//! verifying. Each is compiled on its own and must fail. A runtime assertion
//! could not express this: the point is that the mistake has no representation.

/// A known-good program: if this does not compile, the harness is broken and
/// every rejection below would pass for the wrong reason.
const CONTROL: &str = "let mut c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
     let mut v = c.view();\n\
     let _ = v.put(sumchain_storage::db::cf::STATE, b\"k\", b\"v\");";

/// The rlib to compile probes against.
///
/// Chosen by trying candidates until one compiles [`CONTROL`], newest first —
/// NOT simply by taking the newest. `target/debug/deps` accumulates rlibs, and a
/// stale one built by a different rustc than the current toolchain produces
/// `E0514: found crate compiled by an incompatible version of rustc`. Picking
/// blind made every negative test fail for a reason that had nothing to do with
/// the API under test, which is exactly the failure mode a positive control
/// exists to catch.
fn working_rlib() -> String {
    let deps = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/deps");
    let mut candidates: Vec<(std::time::SystemTime, String)> = Vec::new();
    for e in std::fs::read_dir(&deps).expect("read deps dir") {
        let path = e.expect("entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("libsumchain_storage-") && name.ends_with(".rlib") {
            let m = path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            candidates.push((m, path.to_string_lossy().to_string()));
        }
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    assert!(
        !candidates.is_empty(),
        "no sumchain_storage rlib; run `cargo build -p sumchain-storage` first"
    );

    for (_, rlib) in &candidates {
        if compile_with(CONTROL, rlib).0 {
            return rlib.clone();
        }
    }
    panic!(
        "no rlib in {} could compile the control program; the probe harness \
         cannot distinguish an API rejection from a toolchain mismatch",
        deps.display()
    );
}

/// Compile `body` against `rlib`. Returns (succeeded, stderr).
fn compile_with(body: &str, rlib: &str) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("probe.rs");
    let program = format!(
        "fn main() {{}}\n\
         #[allow(unused, dead_code)]\n\
         fn probe(db: &sumchain_storage::db::Database) {{\n{body}\n}}\n"
    );
    std::fs::write(&src, program).expect("write probe");
    let deps = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/deps");

    let out = std::process::Command::new("rustc")
        .args(["--edition", "2021", "--crate-type", "bin", "-o"])
        .arg(dir.path().join("probe_bin"))
        .arg(&src)
        .arg("-L")
        .arg(&deps)
        .arg("--extern")
        .arg(format!("sumchain_storage={rlib}"))
        .output()
        .expect("run rustc");

    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Compile a snippet; return true if it FAILED to compile, which is the desired
/// outcome for a negative test.
fn rejected(body: &str) -> (bool, String) {
    let rlib = working_rlib();
    let (ok, stderr) = compile_with(body, &rlib);
    assert!(
        !stderr.contains("E0514"),
        "toolchain mismatch reached a negative test; working_rlib should have \
         filtered it:\n{stderr}"
    );
    (!ok, stderr)
}

#[test]
fn the_probe_harness_accepts_valid_code() {
    // Guard the guard: if everything failed to compile for an unrelated reason,
    // the rejection tests below would pass vacuously.
    let rlib = working_rlib();
    let (ok, stderr) = compile_with(CONTROL, &rlib);
    assert!(
        ok,
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
fn acceptance_cannot_be_handed_a_root() {
    // The forgeable calls. Both manufactured acceptance from the header's own
    // root without using execution's result; neither compiles now, because
    // acceptance takes no Hash.
    for call in [
        "let c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let b: sumchain_primitives::Block = unimplemented!();\n\
         let _ = c.accept_imported(&b, b.header.state_root);",
        "let c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let b: sumchain_primitives::Block = unimplemented!();\n\
         let _ = c.accept_produced(&b, b.header.state_root);",
    ] {
        let (failed, stderr) = rejected(call);
        assert!(
            failed,
            "acceptance must not take a root from its caller; this compiled:\n{call}\n{stderr}"
        );
    }
}

#[test]
fn a_block_execution_cannot_be_built_or_destructured_externally() {
    // Private fields and no public constructor, so a caller cannot assemble a
    // BlockExecution around a candidate whose root it chose.
    let (failed, _e) = rejected(
        "let _x = sumchain_state::executor::BlockExecution { receipts: vec![] };",
    );
    assert!(failed, "BlockExecution must not be constructible externally");

    let (failed2, _e2) = rejected(
        "fn f(x: sumchain_state::executor::BlockExecution<'_>) {\n\
             let _r = x.receipts;\n\
         }",
    );
    assert!(failed2, "BlockExecution fields must be private");
}

#[test]
fn the_two_operand_comparison_does_not_exist() {
    // `verify(h, h)` was the forgeable shape: it proved a comparison occurred
    // and nothing about where either side came from. It is DELETED, not merely
    // hidden — a crate-private version would still be reachable from every
    // future caller inside the crate. The only verification path is
    // acceptance, which reads the expected root from the block and takes the
    // computed root from the binding made at execution completion.
    let (failed, stderr) = rejected(
        "let c = sumchain_storage::candidate::CandidateExecution::new(db, 1024);\n\
         let h = sumchain_primitives::Hash::ZERO;\n\
         let _ = c.verify(h, h);",
    );
    assert!(
        failed,
        "a two-operand root comparison must not exist; verification must read \
         the expected root from the block itself"
    );
    assert!(
        stderr.contains("verify") || stderr.contains("no method"),
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

#[test]
fn publication_takes_no_artifacts() {
    // `publish` derives every record from artifacts bound at execution
    // completion. If it took a transition — or receipts, or journals — a caller
    // could supply a set that merely pairs by hash while carrying different
    // outcomes or undo records.
    let (failed, _e) = rejected(
        "let t: sumchain_storage::candidate::CanonicalTransition = unimplemented!();\n\
         let a: sumchain_storage::candidate::AcceptedCandidate<'_, '_> = unimplemented!();\n\
         let _ = a.publish(t);",
    );
    assert!(
        failed,
        "publish must take no artifacts; a transition parameter reintroduces \
         substitution"
    );
}

#[test]
fn a_canonical_transition_cannot_be_constructed_from_independent_artifacts() {
    // The public transition type is gone: artifacts travel with the candidate.
    let (failed, _e) = rejected(
        "let _ = sumchain_storage::candidate::CanonicalTransition::new();",
    );
    assert!(
        failed,
        "no public constructor may assemble a transition from independently \
         supplied artifacts"
    );
}

#[test]
fn bound_artifacts_cannot_be_replaced_on_an_executed_candidate() {
    // Receipts are exposed read-only for the not-yet-migrated PoA paths; there
    // must be no mutable accessor or setter through which they could change.
    for call in [
        "let e: sumchain_storage::candidate::ExecutedCandidate<'_> = unimplemented!();\n\
         let _ = e.receipts_mut();",
        "let mut e: sumchain_storage::candidate::ExecutedCandidate<'_> = unimplemented!();\n\
         e.set_receipts(Vec::new());",
    ] {
        let (failed, _e) = rejected(call);
        assert!(failed, "no mutable path to bound artifacts may exist:\n{call}");
    }
}
