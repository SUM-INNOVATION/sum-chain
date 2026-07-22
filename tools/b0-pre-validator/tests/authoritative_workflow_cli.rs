//! CLI regression for the authoritative Stage-1 orchestration
//! (`run_authoritative.sh`). It drives the ACTUAL script end-to-end in its off-venue
//! dry mode and proves the deterministic properties the fifth-pass correction requires:
//!
//!   * produce-arch / import-verify / aggregate drive ONLY the SEALED workflow —
//!     `seal-bundle`, `import-bundle`, `aggregate-bundles` — and NEVER the obsolete
//!     mutable-directory `import-arch` / `aggregate-arches` path;
//!   * each produced per-arch evidence directory contains EXACTLY the sealed
//!     `required_files()` shapes (schema-cased, arch-free names — never the old
//!     `sp1.<arch>.container.json` / single `stage2-audit.json` / `Sp1.tool.json`);
//!   * the cross-arch `aggregate` sources every Stage-6 input from `aggregate-bundles`
//!     and performs NO post-verification `cp` out of the per-arch directories;
//!   * the dry (synthetic) run NEVER finalizes — Stage-6 assembly + Stage-1 ingest are
//!     not run, and a genuinely TEST_ONLY-classified bundle is REFUSED by ingest.
//!
//! The venue steps (Docker / toolchains / extractors) cannot run here, so produce-arch
//! runs in dry mode via the tested-valid `emit-test-only-bundle` constructor. The
//! sealed control flow itself runs for real against the built `venue-verify` binary.

use std::path::{Path, PathBuf};
use std::process::Command;

const VENUE_VERIFY: &str = env!("CARGO_BIN_EXE_venue-verify");
const ASSEMBLE: &str = env!("CARGO_BIN_EXE_stage6-assemble");
const INGEST: &str = env!("CARGO_BIN_EXE_stage1-ingest");

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../b0-pre-candidates/scripts")
}

fn run_authoritative() -> PathBuf {
    scripts_dir().join("run_authoritative.sh")
}

fn workdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-authcli-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `run_authoritative.sh <args>` in dry mode, appending venue-verify subcommands to
/// `trace`, driving the prebuilt binary (no nested cargo). Returns whether it succeeded.
fn dry_script(args: &[&str], trace: &Path) -> bool {
    Command::new("bash")
        .arg(run_authoritative())
        .args(args)
        .env("SUMCHAIN_B0PRE_DRYRUN", "1")
        .env("SUMCHAIN_B0PRE_VV_TRACE", trace)
        .env("VENUE_VERIFY_BIN", VENUE_VERIFY)
        .status()
        .unwrap_or_else(|e| panic!("spawn run_authoritative.sh: {e}"))
        .success()
}

#[test]
fn authoritative_dry_run_drives_only_the_sealed_workflow_and_never_finalizes() {
    let work = workdir();
    let trace = work.join("vv-trace.txt");
    std::fs::write(&trace, b"").unwrap();
    let ev_x86 = work.join("ev-x86");
    let ev_arm = work.join("ev-arm");
    let agg_work = work.join("agg-work");

    assert!(
        dry_script(
            &["produce-arch", "x86_64", ev_x86.to_str().unwrap()],
            &trace
        ),
        "produce-arch x86_64 must succeed (seal + typed import)"
    );
    assert!(
        dry_script(
            &["produce-arch", "aarch64", ev_arm.to_str().unwrap()],
            &trace
        ),
        "produce-arch aarch64 must succeed (seal + typed import)"
    );
    assert!(
        dry_script(&["import-verify", ev_x86.to_str().unwrap()], &trace),
        "import-verify must re-run the typed import"
    );
    assert!(
        dry_script(
            &[
                "aggregate",
                ev_x86.to_str().unwrap(),
                ev_arm.to_str().unwrap(),
                agg_work.to_str().unwrap(),
            ],
            &trace,
        ),
        "aggregate must succeed through cross-arch aggregation"
    );

    // (a) the command trace drives the SEALED workflow and never the obsolete path.
    let trace_txt = std::fs::read_to_string(&trace).unwrap();
    let cmds: Vec<&str> = trace_txt.lines().map(str::trim).collect();
    for required in [
        "emit-test-only-bundle",
        "seal-bundle",
        "import-bundle",
        "aggregate-bundles",
    ] {
        assert!(
            cmds.contains(&required),
            "the sealed workflow must invoke {required}; trace was {cmds:?}"
        );
    }
    for obsolete in ["import-arch", "aggregate-arches"] {
        assert!(
            !cmds.contains(&obsolete),
            "the obsolete mutable-directory subcommand {obsolete} must never be invoked; \
             trace was {cmds:?}"
        );
    }

    // (b) each per-arch evidence dir carries EXACTLY the sealed required_files() shapes:
    //     schema-cased, arch-free names — and NONE of the obsolete producer names.
    for f in [
        "Sp1.container.json",
        "Sp1.native.json",
        "Sp1.Cargo.lock",
        "Sp1.lock-provenance.json",
        "Sp1.stage2-audit.json",
        "Sp1.tool-binding.json",
        "Sp1.stage5-result.json",
        "Risc0.stage2-audit.json",
        "sp1-verifier-material.json",
        "risc0-verifier-material.json",
    ] {
        assert!(ev_x86.join(f).is_file(), "x86 evidence must contain {f}");
    }
    for obsolete in [
        "sp1.x86_64.container.json",
        "stage2-audit.json",
        "Sp1.tool.json",
    ] {
        assert!(
            !ev_x86.join(obsolete).exists(),
            "obsolete producer file {obsolete} must not be in the sealed evidence dir"
        );
    }
    // aarch64 must NOT carry RISC Zero material or a RISC Zero Stage-5 result.
    assert!(
        !ev_arm.join("risc0-verifier-material.json").exists(),
        "aarch64 bundle must not carry RISC Zero material"
    );
    assert!(
        !ev_arm.join("Risc0.stage5-result.json").exists(),
        "aarch64 bundle must not carry a RISC Zero Stage-5 result"
    );

    // (c) the dry (synthetic) run NEVER finalizes: no Stage-6 bundle / finalizable
    //     artifact is produced.
    assert!(
        !agg_work.join("stage1-result-bundle.json").exists(),
        "the dry run must not assemble a Stage-1 result bundle"
    );
    assert!(
        !agg_work
            .join("b0-pre-protocol-v1.finalizable.json")
            .exists(),
        "the dry run must not produce a finalizable artifact"
    );

    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn aggregate_does_no_post_verification_copy_out_of_the_arch_directories() {
    // Structural guard on the shipped script: the `aggregate` function sources every
    // Stage-6 input from `aggregate-bundles` and must contain no `cp` — nothing is
    // copied out of the per-arch evidence directories after import verification.
    let src = std::fs::read_to_string(run_authoritative()).unwrap();
    let after = src
        .split_once("\naggregate() {")
        .expect("aggregate() function must exist")
        .1;
    let body = after
        .split_once("\ncmd=")
        .expect("dispatch must follow aggregate()")
        .0;
    assert!(
        !body.contains("cp "),
        "aggregate() must not `cp` out of the per-arch evidence directories"
    );
    // and it must invoke the sealed aggregation, not the obsolete one.
    assert!(
        body.contains("aggregate-bundles"),
        "aggregate() must call aggregate-bundles"
    );
    assert!(
        !body.contains("aggregate-arches"),
        "aggregate() must not call the obsolete aggregate-arches"
    );
}

#[test]
fn a_test_only_classified_bundle_is_refused_by_authoritative_ingest() {
    // Criterion #7, positively: a genuinely TEST_ONLY-classified bundle can never build
    // a finalizable artifact.
    let work = workdir();
    let bundle = work.join("testonly-bundle.json");
    assert!(
        Command::new(ASSEMBLE)
            .arg("--test-only")
            .arg(&bundle)
            .status()
            .unwrap()
            .success(),
        "minting a TEST_ONLY bundle must succeed"
    );
    let out = work.join("out.json");
    assert!(
        !Command::new(INGEST)
            .arg(&bundle)
            .arg(&out)
            .status()
            .unwrap()
            .success(),
        "a TEST_ONLY bundle must be refused by authoritative ingest"
    );
    assert!(
        !out.exists(),
        "no finalizable artifact may be written for TEST_ONLY"
    );
    std::fs::remove_dir_all(&work).ok();
}
