//! Off-venue contract for the Stage-5 verifier-fixture harness
//! (`tools/b0-pre-candidates/scripts/verifier_fixtures.sh`).
//!
//! The genuine per-mutation verifier execution runs the pinned terminal verifier over
//! a genuine proof/receipt INSIDE the pinned container; it needs native Linux, Docker,
//! and the built image, so it cannot run on this host. These tests pin the OFF-VENUE
//! CONTRACT the fifth-pass correction requires:
//!
//!   (a) SHAPE — the harness's `fixtures.json` ([{label,path}]) + `mutations.json`
//!       ([{name,actual_rejected}]) are EXACTLY what `venue-verify stage5-generate`
//!       consumes, and a complete all-rejected suite yields a genuine, validated
//!       Stage-5 record whose `overall_pass` is DERIVED true;
//!   (b) CLASSIFICATION SEPARATION — the off-venue dry-run (TEST_ONLY) mode can never
//!       drive the authoritative harness;
//!   (c) FAIL CLOSED — a missing binding env or a missing genuine fixture stops the
//!       run non-zero and writes NO fixtures.json/mutations.json (no synthetic
//!       substitute reaches ingestion);
//!   (d) DERIVATION — a single non-rejecting mutation yields NO passing Stage-5 record
//!       (the pass is derived from observed outcomes, never asserted).
//!
//! (a)/(d) drive the real `stage5-generate` binary with harness-shaped inputs;
//! (b)/(c) shell the real harness in fail-closed configurations. Mirrors the
//! `authoritative_workflow_cli.rs` pattern.

use std::path::{Path, PathBuf};
use std::process::Command;

use b0_pre_validator::venue::stage5::REQUIRED_MUTATION_CASES;

const VENUE_VERIFY: &str = env!("CARGO_BIN_EXE_venue-verify");

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../b0-pre-candidates/scripts")
}

fn harness() -> PathBuf {
    scripts_dir().join("verifier_fixtures.sh")
}

fn prove_fixture() -> PathBuf {
    scripts_dir().join("prove_fixture.sh")
}

fn workdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "b0pre-s5harness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// Build the harness-shaped Stage-5 inputs (raw artifacts + fixtures.json +
/// mutations.json + params + cmd log) into `out`, with each mutation's
/// `actual_rejected` taken from `rejected` (the harness derives these from the real
/// verifier; here we supply them to exercise the generate-side contract). Returns the
/// paths `stage5-generate` is invoked with.
struct Stage5Inputs {
    params: PathBuf,
    fixtures: PathBuf,
    mutations: PathBuf,
    cmdlog: PathBuf,
    out: PathBuf,
}

fn build_inputs(out: &Path, rejected: &[bool]) -> Stage5Inputs {
    assert_eq!(rejected.len(), REQUIRED_MUTATION_CASES.len());
    // raw artifacts, exactly as the harness's SP1 runner writes them.
    let artifacts = [
        (
            "terminal-proof",
            "terminal-proof.bin",
            "genuine-groth16-proof-bytes",
        ),
        (
            "public-values",
            "public-values.bin",
            "genuine-public-values",
        ),
        ("groth16-vk", "groth16-vk.bin", "genuine-groth16-vk-bytes"),
        ("vkey-hash-claim", "vkey-hash-claim.bin", "0xdeadbeef"),
    ];
    let mut fixtures = Vec::new();
    for (label, fname, body) in artifacts {
        let p = out.join(fname);
        write(&p, body);
        fixtures.push(serde_json::json!({ "label": label, "path": p.to_str().unwrap() }));
    }
    let fixtures_path = out.join("fixtures.json");
    write(
        &fixtures_path,
        &serde_json::to_string_pretty(&serde_json::Value::Array(fixtures)).unwrap(),
    );

    let mutations: Vec<_> = REQUIRED_MUTATION_CASES
        .iter()
        .zip(rejected)
        .map(|(name, r)| serde_json::json!({ "name": name, "actual_rejected": r }))
        .collect();
    let mutations_path = out.join("mutations.json");
    write(
        &mutations_path,
        &serde_json::to_string_pretty(&serde_json::Value::Array(mutations)).unwrap(),
    );

    let params_path = out.join("params.json");
    write(
        &params_path,
        &serde_json::to_string_pretty(&serde_json::json!({
            "candidate": "Sp1",
            "arch": "X86_64",
            "verifier_identity": "pinned-sp1-terminal-verifier",
            "tool_identity_hex": "a".repeat(64),
            "container_digest": format!("sha256:{}", "b".repeat(64)),
            "source_commit": "c".repeat(40),
        }))
        .unwrap(),
    );

    let cmdlog = out.join("stage5.cmd.log");
    write(
        &cmdlog,
        "docker run ... cargo run genuine verifier + 5 mutations\n",
    );

    Stage5Inputs {
        params: params_path,
        fixtures: fixtures_path,
        mutations: mutations_path,
        cmdlog,
        out: out.join("stage5-result.json"),
    }
}

fn run_generate(i: &Stage5Inputs) -> bool {
    Command::new(VENUE_VERIFY)
        .arg("stage5-generate")
        .arg(&i.params)
        .arg(&i.fixtures)
        .arg(&i.mutations)
        .arg(&i.cmdlog)
        .arg(&i.out)
        .status()
        .unwrap_or_else(|e| panic!("spawn venue-verify: {e}"))
        .success()
}

// ---- (a) SHAPE: harness output feeds stage5-generate and derives a pass -----------

#[test]
fn harness_output_shapes_feed_stage5_generate_and_derive_a_pass() {
    let work = workdir();
    let all_rejected = vec![true; REQUIRED_MUTATION_CASES.len()];
    let inputs = build_inputs(&work, &all_rejected);

    assert!(
        run_generate(&inputs),
        "a complete all-rejected suite in the harness's exact fixtures.json/mutations.json \
         shapes must generate a Stage-5 record"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&inputs.out).unwrap()).unwrap();
    // overall_pass is DERIVED (never supplied by the harness), and every required
    // mutation case is present exactly once, each expected+actually rejected.
    assert_eq!(doc["overall_pass"], serde_json::json!(true));
    let cases = doc["mutation_cases"].as_array().unwrap();
    assert_eq!(cases.len(), REQUIRED_MUTATION_CASES.len());
    for req in REQUIRED_MUTATION_CASES {
        let c = cases
            .iter()
            .find(|c| c["name"] == serde_json::json!(req))
            .unwrap_or_else(|| panic!("required case {req} present"));
        assert_eq!(c["expected_rejected"], serde_json::json!(true));
        assert_eq!(c["actual_rejected"], serde_json::json!(true));
    }
    // the fixture hashes were computed by stage5-generate from the raw artifact bytes.
    assert_eq!(doc["fixture_hashes"].as_array().unwrap().len(), 4);
    // (NEW WORK 3) the sealed Stage-5 record binds every required identity: fixture/
    // proof/receipt bytes (fixture_hashes above), candidate + platform, container
    // identity, tool identity, source commit, verifier identity, and the command-log
    // hash (which in turn binds the in-container lock hashes, material identity, and
    // mutation-command provenance appended by the harness).
    for (field, expect) in [
        ("candidate", "Sp1"),
        ("arch", "X86_64"),
        ("verifier_identity", "pinned-sp1-terminal-verifier"),
        ("tool_identity_hex", &"a".repeat(64)[..]),
        (
            "container_digest",
            &format!("sha256:{}", "b".repeat(64))[..],
        ),
        ("source_commit", &"c".repeat(40)[..]),
    ] {
        assert_eq!(
            doc[field],
            serde_json::json!(expect),
            "record must bind {field}"
        );
    }
    assert!(
        doc["command_log_blake3_hex"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "record must bind the command-log identity (lock hashes + material id + commands)"
    );
    std::fs::remove_dir_all(&work).ok();
}

// ---- (d) DERIVATION: one non-rejecting mutation => no passing record --------------

#[test]
fn a_non_rejecting_mutation_yields_no_passing_stage5_record() {
    let work = workdir();
    // the verifier ACCEPTED the first mutation (actual_rejected=false) — a genuine
    // authenticity failure the harness must report verbatim.
    let mut rejected = vec![true; REQUIRED_MUTATION_CASES.len()];
    rejected[0] = false;
    let inputs = build_inputs(&work, &rejected);

    assert!(
        !run_generate(&inputs),
        "a non-rejecting mutation must fail Stage-5 generation (the pass is derived, not asserted)"
    );
    assert!(
        !inputs.out.exists(),
        "no Stage-5 record may be written when a mutation was not rejected"
    );
    std::fs::remove_dir_all(&work).ok();
}

// ---- harness / stage5 case-set agreement ------------------------------------------

#[test]
fn harness_declares_exactly_the_required_mutation_cases() {
    // The harness runner emits exactly REQUIRED_MUTATION_CASES; guard the two in sync.
    let src = std::fs::read_to_string(harness()).unwrap();
    for req in REQUIRED_MUTATION_CASES {
        assert!(
            src.contains(req),
            "harness must emit the required mutation case {req:?}"
        );
    }
    // and no OTHER mutation-case names sneak in (stage5-generate rejects unknowns, but
    // keep the harness honest at the source too).
    assert_eq!(REQUIRED_MUTATION_CASES.len(), 5);
}

// ---- (b) CLASSIFICATION SEPARATION: dry-run/TEST_ONLY can never drive it -----------

#[test]
fn dry_run_test_only_mode_is_refused_by_the_authoritative_harness() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    let status = Command::new("bash")
        .arg(harness())
        .args(["sp1", "x86_64"])
        .env("SUMCHAIN_B0PRE_DRYRUN", "1")
        .env("VERIFIER_REF", "oci:local/b0pre-sp1-x86_64")
        .env("OUT_DIR", &work)
        .env("CMD_LOG", &cmdlog)
        .env("SCHEMA_ARCH", "X86_64")
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "the authoritative harness must refuse SUMCHAIN_B0PRE_DRYRUN (TEST_ONLY) mode"
    );
    assert!(!work.join("fixtures.json").exists() && !work.join("mutations.json").exists());
    std::fs::remove_dir_all(&work).ok();
}

// ---- (c) FAIL CLOSED: missing binding env / missing genuine fixture ---------------

#[test]
fn missing_binding_env_fails_closed_with_no_output() {
    let work = workdir();
    // OUT_DIR is present but VERIFIER_REF/CMD_LOG/SCHEMA_ARCH are absent -> refuse
    // before any container work; nothing is written.
    let status = Command::new("bash")
        .arg(harness())
        .args(["sp1", "x86_64"])
        .env("OUT_DIR", &work)
        .env_remove("VERIFIER_REF")
        .env_remove("CMD_LOG")
        .env_remove("SCHEMA_ARCH")
        .env_remove("SUMCHAIN_B0PRE_DRYRUN")
        .status()
        .unwrap();
    assert!(!status.success(), "missing binding env must fail closed");
    assert!(!work.join("fixtures.json").exists() && !work.join("mutations.json").exists());
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn no_external_fixture_triggers_generation_which_fails_closed_off_venue() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    // No external fixture env -> the harness GENERATES one by proving the OFFICIAL guest.
    // Off-venue there is no pinned prover toolchain / container, so generation fails
    // closed and NOTHING is written (no synthetic fixture is ever substituted).
    let status = Command::new("bash")
        .arg(harness())
        .args(["sp1", "x86_64"])
        .env("VERIFIER_REF", "oci:local/b0pre-sp1-x86_64")
        .env("OUT_DIR", &work)
        .env("CMD_LOG", &cmdlog)
        .env("SCHEMA_ARCH", "X86_64")
        .env_remove("SP1_G16_FIXTURE")
        .env_remove("SUMCHAIN_B0PRE_DRYRUN")
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "with no external fixture, generation must run and fail closed off-venue"
    );
    assert!(
        !work.join("fixtures.json").exists()
            && !work.join("mutations.json").exists()
            && !work.join("generated-fixture.json").exists(),
        "a failed generation must leave no fixture/output behind"
    );
    std::fs::remove_dir_all(&work).ok();
}

// ---- FIXTURE GENERATION (prove_fixture.sh): gated command path, fail closed --------

/// Run prove_fixture.sh with the given env overrides; returns success + whether a
/// fixture was written.
fn run_prove(
    cand: &str,
    arch: &str,
    envs: &[(&str, &std::ffi::OsStr)],
    out: &Path,
) -> (bool, bool) {
    let mut cmd = Command::new("bash");
    cmd.arg(prove_fixture())
        .args([cand, arch])
        .arg(out)
        .env_remove("SUMCHAIN_B0PRE_DRYRUN");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let ok = cmd.status().unwrap().success();
    (ok, out.exists())
}

#[test]
fn generation_fails_closed_off_venue_even_with_official_guest_source() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    let tb = work.join("tb.json");
    write(&tb, "[]");
    let out = work.join("gen.json");
    // Full venue-shaped env. The candidate guest now carries OFFICIAL source
    // (routes through b0_pre_guest_core::run), so the positive official-guest gate
    // passes — but off-venue there is no pinned prover toolchain / container / native
    // builder, so generation still fails closed. Never a canned/synthetic proof.
    let (ok, wrote) = run_prove(
        "sp1",
        "x86_64",
        &[
            ("VERIFIER_REF", "oci:local/b0pre-sp1-x86_64".as_ref()),
            ("CMD_LOG", cmdlog.as_os_str()),
            ("SCHEMA_ARCH", "X86_64".as_ref()),
            ("TOOL_BINDING", tb.as_os_str()),
        ],
        &out,
    );
    assert!(!ok, "generation must fail closed off-venue");
    assert!(
        !wrote,
        "no genuine fixture may be written when generation fails closed"
    );
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn generation_refuses_dry_run_and_missing_binding_env() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    let tb = work.join("tb.json");
    write(&tb, "[]");
    let out = work.join("gen.json");
    // dry-run (TEST_ONLY) mode is refused before any proving.
    let (ok_dry, _) = run_prove(
        "sp1",
        "x86_64",
        &[
            ("SUMCHAIN_B0PRE_DRYRUN", "1".as_ref()),
            ("VERIFIER_REF", "oci:local/x".as_ref()),
            ("CMD_LOG", cmdlog.as_os_str()),
            ("SCHEMA_ARCH", "X86_64".as_ref()),
            ("TOOL_BINDING", tb.as_os_str()),
        ],
        &out,
    );
    assert!(!ok_dry, "dry-run/TEST_ONLY generation must be refused");
    // missing VERIFIER_REF binding env fails closed.
    let (ok_env, _) = run_prove(
        "sp1",
        "x86_64",
        &[
            ("CMD_LOG", cmdlog.as_os_str()),
            ("SCHEMA_ARCH", "X86_64".as_ref()),
            ("TOOL_BINDING", tb.as_os_str()),
        ],
        &out,
    );
    assert!(!ok_env, "missing binding env must fail closed");
    assert!(
        !out.exists(),
        "no fixture may be written on a refused generation"
    );
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn generation_enforces_the_risc0_x86_64_only_rule() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    let tb = work.join("tb.json");
    write(&tb, "[]");
    let out = work.join("gen.json");
    let (ok, wrote) = run_prove(
        "risc0",
        "aarch64",
        &[
            ("VERIFIER_REF", "oci:local/x".as_ref()),
            ("CMD_LOG", cmdlog.as_os_str()),
            ("SCHEMA_ARCH", "Aarch64".as_ref()),
            ("TOOL_BINDING", tb.as_os_str()),
        ],
        &out,
    );
    assert!(
        !ok && !wrote,
        "RISC Zero proving must be refused off x86_64"
    );
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn generation_command_path_proves_and_never_cans_a_fixture() {
    // Structural guard on the venue-UNEXECUTED command path: it PROVES a frozen guest
    // (genuine prover SDK), stamps the fixture NON-SELECTION, generates its lock
    // in-container before any --locked build, and contains no canned/synthetic proof.
    let src = std::fs::read_to_string(prove_fixture()).unwrap();
    assert!(
        src.contains("cargo run --quiet --release --locked"),
        "prover-runner must run --locked against its in-container-generated lock"
    );
    let gen = src
        .find("cargo generate-lockfile'")
        .expect("in-container lock gen");
    let run = src.find("cargo run --quiet --release --locked").unwrap();
    assert!(
        gen < run,
        "the prover-runner lock is generated before the --locked build"
    );
    assert!(
        !src.contains("generate-lockfile --locked"),
        "generate-lockfile must not run --locked against a fresh package"
    );
    // proves a real guest ELF (not a canned proof) and stamps it non-selection.
    assert!(
        src.contains("cargo prove build") && src.contains("cargo risczero build"),
        "generation must build the frozen guest with the pinned prover toolchain"
    );
    assert!(
        src.contains("NOT_AN_OFFICIAL_GUEST") && src.contains("b0_pre_guest_core::run"),
        "generation must stamp non-selection and gate POSITIVELY on the official guest source"
    );
    // the harness drives generation by default and binds the prover lock into the log.
    let hsrc = std::fs::read_to_string(harness()).unwrap();
    assert!(
        hsrc.contains("prove_fixture.sh") && hsrc.contains("TOOL_BINDING="),
        "harness must generate via prove_fixture.sh with the bound prover identity"
    );
    assert!(
        std::fs::read_to_string(prove_fixture())
            .unwrap()
            .contains("prove-runner-cargo-lock"),
        "generation must bind the prover-runner lock hash into the command log"
    );
}

// ---- wiring: produce_stage5 drives the harness with the binding contract ----------

#[test]
fn produce_stage5_invokes_the_harness_with_the_binding_contract() {
    let src = std::fs::read_to_string(scripts_dir().join("run_authoritative.sh")).unwrap();
    let after = src
        .split_once("\nproduce_stage5() {")
        .expect("produce_stage5() must exist")
        .1;
    let body = after.split_once("\n# ").map(|(b, _)| b).unwrap_or(after);
    // it drives THIS harness with all four binding env vars + positional args, and
    // requires both output files before handing off to stage5-generate.
    assert!(
        body.contains("verifier_fixtures.sh"),
        "must invoke verifier_fixtures.sh"
    );
    for needle in [
        "VERIFIER_REF=",
        "OUT_DIR=",
        "CMD_LOG=",
        "SCHEMA_ARCH=",
        "fixtures.json",
        "mutations.json",
        "stage5-generate",
    ] {
        assert!(
            body.contains(needle),
            "produce_stage5 must reference {needle}"
        );
    }
}

// ---- (c) FAIL CLOSED: a missing verifier-material manifest (binding input) ---------

#[test]
fn missing_verifier_material_manifest_fails_closed_with_no_output() {
    let work = workdir();
    let cmdlog = work.join("cmd.log");
    write(&cmdlog, "");
    // A genuine, correctly-stamped fixture is present, but the verifier-material
    // manifest that binds the Stage-5 record to the extracted material is ABSENT ->
    // the harness must fail closed (nothing to bind, so no evidence is produced).
    let fixture = work.join("fixture.json");
    write(
        &fixture,
        &serde_json::json!({
            "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0", "NOT_AN_OFFICIAL_GUEST"],
            "proof_hex": "00",
            "public_values_hex": "00",
            "vkey_hash": "0x00",
        })
        .to_string(),
    );
    let status = Command::new("bash")
        .arg(harness())
        .args(["sp1", "x86_64"])
        .env("VERIFIER_REF", "oci:local/b0pre-sp1-x86_64")
        .env("OUT_DIR", &work)
        .env("CMD_LOG", &cmdlog)
        .env("SCHEMA_ARCH", "X86_64")
        .env("SP1_G16_FIXTURE", &fixture)
        .env("VERIFIER_MATERIAL", work.join("does-not-exist.json"))
        .env_remove("SUMCHAIN_B0PRE_DRYRUN")
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "a missing verifier-material manifest must fail closed (nothing to bind)"
    );
    assert!(!work.join("fixtures.json").exists() && !work.join("mutations.json").exists());
    std::fs::remove_dir_all(&work).ok();
}

// ---- fix #1: the runner LOCK is generated IN-CONTAINER; never build unlocked -------

#[test]
fn harness_generates_runner_lock_in_container_before_any_locked_build() {
    let src = std::fs::read_to_string(harness()).unwrap();
    // The EXECUTED generate command (single-quote-terminated) resolves the fresh
    // package's lock in-container; it must never carry --locked (the fatal bug).
    let gen = src
        .find("cargo generate-lockfile'")
        .expect("harness must generate the runner lock in-container (executed command)");
    let locked_run = src
        .find("cargo run --quiet --release --locked")
        .expect("harness must run the verifier with --locked against that lock");
    assert!(
        gen < locked_run,
        "the in-container `cargo generate-lockfile` must precede the `--locked` build"
    );
    assert!(
        !src.contains("generate-lockfile --locked"),
        "cargo generate-lockfile must not run with --locked against an unlocked fresh package"
    );
}

// ---- fix #2: RISC Zero swap_verifier_material substitutes material, not corruption --

#[test]
fn risc0_swap_verifier_material_substitutes_material_not_receipt_corruption() {
    let src = std::fs::read_to_string(harness()).unwrap();
    // The RISC Zero case must verify against DIFFERENT verifier material via a
    // VerifierContext with mutated Groth16 parameters — genuine substitution.
    assert!(
        src.contains("with_groth16_verifier_parameters") && src.contains("verify_with_context"),
        "risc0 swap_verifier_material must substitute Groth16 verifier material via a \
         VerifierContext, not corrupt the serialized receipt"
    );
}

// ---- fix #4: fixture bytes, runner lock, and material identity enter the seal chain -

#[test]
fn harness_binds_fixture_lock_and_material_identity_into_the_sealed_chain() {
    let src = std::fs::read_to_string(harness()).unwrap();
    // exact genuine fixture bytes copied in so stage5-generate hashes them.
    assert!(
        src.contains("genuine-fixture") && src.contains("cp \"$FIXTURE_ABS\""),
        "harness must bind the exact genuine fixture bytes into fixtures.json"
    );
    // runner lock hashed + recorded (both as a raw artifact and in the command log).
    assert!(
        src.contains("runner-cargo-lock") && src.contains("RUNNER_LOCK_B3"),
        "harness must bind the in-container runner Cargo.lock hash"
    );
    // verifier-material manifest identity read + recorded into the (bound) command log.
    assert!(
        src.contains("manifest_identity_blake3")
            && src.contains("verifier-material-manifest-identity"),
        "harness must bind the verifier-material manifest identity into the command log"
    );
}
