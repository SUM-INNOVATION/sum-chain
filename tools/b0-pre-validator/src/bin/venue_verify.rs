//! `venue-verify` — the real venue verification commands the shell orchestration
//! calls, so each Stage's decision is the SAME code that is unit-tested off-venue
//! (never a shell approximation). Every subcommand fails closed on absent /
//! malformed inputs; off-venue (no Docker / toolchains / installer metadata) the
//! inputs do not exist, so the authoritative path stops here — it never fabricates.
//!
//!   venue-verify oci-manifest <layout_dir> <oci_arch>
//!       Parse an exported OCI image layout and print its TRUE manifest identity
//!       (content-addressed digest + platform), re-verifying the manifest blob's
//!       content address. NOT sha256(exported tar). (Blocker 5)
//!
//!   venue-verify verify-lock <provenance.json> <exported_Cargo.lock>
//!       Accept a candidate lock ONLY with generated-in-container provenance and a
//!       hash recomputed from the exported bytes; reject any host-originated lock.
//!       (Blocker 2)
//!
//!   venue-verify verify-tool <authoritative|test-only> <declared.json> \
//!                            <artifact_bytes> <installed_binary>
//!       Verify a proof tool's declared checksum over the downloaded artifact and
//!       bind the verified artifact hash + installed-binary hash. Authoritative mode
//!       refuses synthetic metadata (fails closed off-venue). (Blocker 3)
//!
//!   venue-verify stage2-audit <graph.json> <advisories.json> <allowed_licenses.json> <out.json>
//!       Audit the container-resolved graph (dependency/source/advisory/license),
//!       emit the machine-readable fatal-vs-recorded report, and EXIT NON-ZERO on
//!       any fatal finding — the artifact Stage 6 requires. (Blocker 4, Stage 2)
//!
//!   venue-verify verify-runtime-image <recorded_manifest_digest> <runtime_digest>
//!       Prove the runtime-loaded image resolves to the recorded OCI manifest
//!       digest before anything runs inside it — no invented local reference.
//!       (fifth-pass Blocker 2)
//!
//!   venue-verify seal-bundle <dir> <arch> <source_commit>
//!       Seal a curated per-arch bundle directory into an immutable, hashed
//!       `PerArchEvidenceBundleV1` manifest (hash of EVERY required file + one
//!       content hash). (fifth-pass Blocker 1 + 7)
//!
//!   venue-verify import-bundle <dir>
//!       Fully import-verify a sealed per-arch bundle: recompute every file hash,
//!       reject unmanifested/missing files, and validate + bind every TYPED stage
//!       record (lock provenance, Stage-2 audit, tool bindings, Stage-5 result,
//!       container/native/material) to ONE arch + source commit. (Blocker 1)
//!
//!   venue-verify aggregate-bundles <x86_dir> <arm_dir> <out_dir>
//!       Import-verify BOTH sealed bundles and aggregate from the TYPED objects
//!       (never a directory copy), writing the Stage-6 inputs. (Blocker 1 + 7)

use std::process::ExitCode;

use std::path::Path;

use b0_pre_validator::schema::stage6::{NativeBuild, OciBuild};
use b0_pre_validator::venue::arch_bundle::{aggregate, import_verify, PerArchBundle};
use b0_pre_validator::venue::audit::{self, Advisory, CrateNode, Stage2AuditRecord};
use b0_pre_validator::venue::evidence_bundle;
use b0_pre_validator::venue::lock_provenance::{
    recompute_lock_hash, verify_in_container_provenance, LockProvenance,
};
use b0_pre_validator::venue::oci_layout::{
    extract_manifest_identity, verify_runtime_image_identity,
};
use b0_pre_validator::venue::stage4::{enforce_stage4_arch, Extractor};
use b0_pre_validator::venue::stage5::Stage5Result;
use b0_pre_validator::venue::tool_install::{install_and_bind, DeclaredArtifact, InstallMode};

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn read_str(path: &str) -> Result<String, String> {
    String::from_utf8(read(path)?).map_err(|e| format!("{path} is not utf-8: {e}"))
}

fn oci_manifest(layout_dir: &str, oci_arch: &str) -> Result<String, String> {
    let id = extract_manifest_identity(std::path::Path::new(layout_dir), oci_arch)
        .map_err(|e| e.to_string())?;
    let platform = id.platform.map(
        |p| serde_json::json!({ "architecture": p.architecture, "os": p.os, "variant": p.variant }),
    );
    Ok(serde_json::json!({
        "manifest_digest": id.digest,
        "media_type": id.media_type,
        "platform": platform,
        "note": "OCI manifest content address parsed from index.json + blob re-hash; \
                 NOT sha256(exported tar)",
    })
    .to_string())
}

fn lock_hash(lock_path: &str) -> Result<String, String> {
    // The domain-separated candidate-lock hash, recomputed from the exported bytes:
    // BLAKE3(CARGO_LOCK_TAG ‖ bytes). Used to seed lock provenance; `verify-lock`
    // then independently recomputes and rejects any mismatch.
    Ok(recompute_lock_hash(&read(lock_path)?))
}

fn verify_lock(prov_path: &str, lock_path: &str) -> Result<String, String> {
    let prov: LockProvenance =
        serde_json::from_str(&read_str(prov_path)?).map_err(|e| format!("bad provenance: {e}"))?;
    let exported = read(lock_path)?;
    let binding = verify_in_container_provenance(&prov, &exported).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "accepted": true,
        "candidate": binding.candidate,
        "arch": binding.arch,
        "container_digest": binding.container_digest,
        "source_commit": binding.source_commit,
        "lock_blake3_hex": binding.lock_blake3_hex,
    })
    .to_string())
}

fn verify_tool(
    mode_arg: &str,
    declared_path: &str,
    artifact_path: &str,
    installed_path: &str,
) -> Result<String, String> {
    let mode = match mode_arg {
        "authoritative" => InstallMode::Authoritative,
        "test-only" => InstallMode::TestOnly,
        other => {
            return Err(format!(
                "mode must be authoritative|test-only, got {other:?}"
            ))
        }
    };
    let declared: DeclaredArtifact = serde_json::from_str(&read_str(declared_path)?)
        .map_err(|e| format!("bad declared: {e}"))?;
    let artifact = read(artifact_path)?;
    let installed = read(installed_path)?;
    let binding =
        install_and_bind(mode, &declared, &artifact, &installed).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "name": binding.name,
        "version": binding.version,
        "verified_artifact_hex": binding.verified_artifact_hex,
        "installed_binary_sha256_hex": binding.installed_binary_sha256_hex,
        "test_only": binding.test_only,
    })
    .to_string())
}

/// Load a per-architecture producer bundle directory into a `PerArchBundle`:
///   *.container.json  -> OciBuild arrays (concatenated)
///   *.native.json     -> NativeBuild arrays (concatenated)
///   sp1-verifier-material.json   -> SP1 extractor JSON (required)
///   risc0-verifier-material.json -> RISC Zero extractor JSON (x86_64 only)
fn load_per_arch_bundle(dir: &str) -> Result<PerArchBundle, String> {
    let mut builds: Vec<OciBuild> = Vec::new();
    let mut native: Vec<NativeBuild> = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read_dir {dir}: {e}"))?;
    let mut names: Vec<String> = Vec::new();
    for e in entries {
        let e = e.map_err(|e| e.to_string())?;
        if let Some(name) = e.file_name().to_str() {
            names.push(name.to_string());
        }
    }
    names.sort(); // deterministic concatenation order
    for name in &names {
        let path = Path::new(dir).join(name);
        if name.ends_with(".container.json") {
            let v: Vec<OciBuild> = serde_json::from_str(&read_str(path.to_str().unwrap())?)
                .map_err(|e| format!("{name}: {e}"))?;
            builds.extend(v);
        } else if name.ends_with(".native.json") {
            let v: Vec<NativeBuild> = serde_json::from_str(&read_str(path.to_str().unwrap())?)
                .map_err(|e| format!("{name}: {e}"))?;
            native.extend(v);
        }
    }
    if builds.is_empty() {
        return Err(format!("no *.container.json in {dir}"));
    }
    let arch = builds[0].arch.clone();
    let sp1_path = Path::new(dir).join("sp1-verifier-material.json");
    let sp1_extractor_json = read_str(sp1_path.to_str().unwrap())
        .map_err(|_| format!("{dir}: sp1-verifier-material.json is required"))?;
    let risc0_path = Path::new(dir).join("risc0-verifier-material.json");
    let risc0_extractor_json = if risc0_path.exists() {
        Some(read_str(risc0_path.to_str().unwrap())?)
    } else {
        None
    };
    Ok(PerArchBundle {
        arch,
        builds,
        native,
        sp1_extractor_json,
        risc0_extractor_json,
    })
}

fn import_arch(dir: &str) -> Result<String, String> {
    let bundle = load_per_arch_bundle(dir)?;
    import_verify(&bundle).map_err(|e| e.to_string())?;
    Ok(format!(
        "per-arch bundle {dir} import-verified: arch={} builds={} native={} risc0={}",
        bundle.arch,
        bundle.builds.len(),
        bundle.native.len(),
        bundle.risc0_extractor_json.is_some()
    ))
}

fn aggregate_arches(x86_dir: &str, arm_dir: &str, out_dir: &str) -> Result<String, String> {
    let x86 = load_per_arch_bundle(x86_dir)?;
    let arm = load_per_arch_bundle(arm_dir)?;
    let agg = aggregate(&[x86, arm]).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {out_dir}: {e}"))?;
    let write = |name: &str, body: &str| -> Result<(), String> {
        let p = Path::new(out_dir).join(name);
        if p.exists() {
            return Err(format!("refusing to overwrite existing {}", p.display()));
        }
        std::fs::write(&p, format!("{body}\n")).map_err(|e| format!("write {}: {e}", p.display()))
    };
    write("digests.json", &agg.oci_digests_json)?;
    write("native-provenance.json", &agg.native_json)?;
    write("sp1-verifier-material.json", &agg.sp1_extractor_json)?;
    write("risc0-verifier-material.json", &agg.risc0_extractor_json)?;
    Ok(format!(
        "cross-architecture aggregate written to {out_dir} (RISC Zero material sourced from x86_64)"
    ))
}

fn stage2_audit(
    graph_path: &str,
    advisories_path: &str,
    licenses_path: &str,
    out_path: &str,
) -> Result<String, String> {
    let nodes: Vec<CrateNode> =
        serde_json::from_str(&read_str(graph_path)?).map_err(|e| format!("bad graph: {e}"))?;
    let advisories: Vec<Advisory> = serde_json::from_str(&read_str(advisories_path)?)
        .map_err(|e| format!("bad advisories: {e}"))?;
    let licenses: Vec<String> = serde_json::from_str(&read_str(licenses_path)?)
        .map_err(|e| format!("bad licenses: {e}"))?;
    let allowed: Vec<&str> = licenses.iter().map(String::as_str).collect();
    let report = audit::audit_graph(&nodes, &advisories, &allowed);
    if std::path::Path::new(out_path).exists() {
        return Err(format!("refusing to overwrite existing {out_path}"));
    }
    std::fs::write(out_path, format!("{}\n", report.to_json()))
        .map_err(|e| format!("write {out_path}: {e}"))?;
    if report.is_fatal() {
        return Err(format!(
            "Stage-2 graph audit is FATAL ({} finding(s)); candidate ineligible",
            report.fatal_findings().count()
        ));
    }
    Ok(format!(
        "Stage-2 graph audit passed: no fatal findings ({} prerelease(s) recorded) -> {out_path}",
        report.recorded_findings().count()
    ))
}

/// Normalize an arch argument (`x86_64`/`amd64`/`X86_64` -> `X86_64`, etc.).
fn schema_arch(arg: &str) -> Result<&'static str, String> {
    match arg {
        "x86_64" | "amd64" | "X86_64" => Ok("X86_64"),
        "aarch64" | "arm64" | "Aarch64" => Ok("Aarch64"),
        other => Err(format!("arch must be x86_64|aarch64, got {other:?}")),
    }
}

/// Blocker 2: prove the runtime-loaded image resolves to the recorded manifest
/// digest before anything runs inside it.
fn verify_runtime_image(recorded: &str, runtime: &str) -> Result<String, String> {
    let d = verify_runtime_image_identity(recorded, runtime).map_err(|e| e.to_string())?;
    Ok(format!(
        "runtime image identity resolves to the recorded manifest digest {d}"
    ))
}

/// Blocker 3: enforce the Stage-4 extractor arch boundaries (RISC Zero is
/// x86_64-only at BOTH the host and container boundaries) — the SAME decision the
/// unit tests exercise, called by `run_authoritative.sh` before an extractor runs.
fn stage4_guard(
    extractor_arg: &str,
    target: &str,
    host: &str,
    container: &str,
) -> Result<String, String> {
    let extractor = match extractor_arg {
        "sp1" | "Sp1" => Extractor::Sp1,
        "risc0" | "Risc0" => Extractor::Risc0,
        other => return Err(format!("extractor must be sp1|risc0, got {other:?}")),
    };
    let arch =
        enforce_stage4_arch(extractor, target, host, container).map_err(|e| e.to_string())?;
    Ok(format!(
        "Stage-4 {extractor_arg} extraction arch boundary OK (target={arch}, host={host}, container={container})"
    ))
}

/// Blocker 5: validate a bound Stage-2 audit record — the in-container-DERIVED
/// resolved graph must have every candidate-pinned crate exactly once, no fatal
/// finding, and complete bindings. Rejects an empty/incomplete graph.
fn stage2_record(record_path: &str) -> Result<String, String> {
    let rec: Stage2AuditRecord = serde_json::from_str(&read_str(record_path)?)
        .map_err(|e| format!("bad Stage-2 record: {e}"))?;
    let report = rec.validate().map_err(|e| e.to_string())?;
    Ok(format!(
        "Stage-2 record for {} ({}) OK: no fatal findings, {} prerelease(s) recorded, required \
         crates present",
        rec.candidate,
        rec.arch,
        report.recorded_findings().count()
    ))
}

/// Blocker 4: validate a Stage-5 fixture+mutation result — every required mutation
/// case present, each rejected, and a derived (not asserted) overall pass.
fn verify_stage5(result_path: &str) -> Result<String, String> {
    let res: Stage5Result = serde_json::from_str(&read_str(result_path)?)
        .map_err(|e| format!("bad Stage-5 result: {e}"))?;
    res.validate().map_err(|e| e.to_string())?;
    Ok(format!(
        "Stage-5 result for {} ({}) OK: {} mutation cases all rejected; overall_pass derived=true",
        res.candidate,
        res.arch,
        res.mutation_cases.len()
    ))
}

/// Blocker 1 + 7: seal a curated per-arch bundle directory into an immutable,
/// hashed manifest.
fn seal_bundle(dir: &str, arch_arg: &str, source_commit: &str) -> Result<String, String> {
    let arch = schema_arch(arch_arg)?;
    let manifest = evidence_bundle::seal(std::path::Path::new(dir), arch, source_commit)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "sealed per-arch evidence bundle {dir} (arch={arch}, {} files, content={})",
        manifest.files.len(),
        manifest.bundle_content_hash
    ))
}

/// Blocker 1: full typed import verification of a sealed per-arch bundle.
fn import_bundle(dir: &str) -> Result<String, String> {
    let imported =
        evidence_bundle::import_verify(std::path::Path::new(dir)).map_err(|e| e.to_string())?;
    Ok(format!(
        "per-arch evidence bundle {dir} import-verified: arch={} builds={} native={} locks={} \
         stage2={} tools={} stage5={} risc0_material={} content={}",
        imported.arch,
        imported.builds.len(),
        imported.native.len(),
        imported.lock_bindings.len(),
        imported.stage2_reports.len(),
        imported.tool_bindings.len(),
        imported.stage5_results.len(),
        imported.risc0_extractor_json.is_some(),
        imported.content_hash,
    ))
}

/// Blocker 1 + 7: cross-arch aggregation from TWO import-verified TYPED bundles
/// (never a directory copy). Import-verifies both sealed bundles in this ONE
/// operation, then aggregates from the typed objects and writes the Stage-6 inputs.
fn aggregate_bundles(x86_dir: &str, arm_dir: &str, out_dir: &str) -> Result<String, String> {
    let x86 =
        evidence_bundle::import_verify(std::path::Path::new(x86_dir)).map_err(|e| e.to_string())?;
    let arm =
        evidence_bundle::import_verify(std::path::Path::new(arm_dir)).map_err(|e| e.to_string())?;
    let agg = evidence_bundle::aggregate_imported(&[x86, arm]).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {out_dir}: {e}"))?;
    let write = |name: &str, body: &str| -> Result<(), String> {
        let p = Path::new(out_dir).join(name);
        if p.exists() {
            return Err(format!("refusing to overwrite existing {}", p.display()));
        }
        std::fs::write(&p, format!("{body}\n")).map_err(|e| format!("write {}: {e}", p.display()))
    };
    write("digests.json", &agg.venue.oci_digests_json)?;
    write("native-provenance.json", &agg.venue.native_json)?;
    write("sp1-verifier-material.json", &agg.venue.sp1_extractor_json)?;
    write(
        "risc0-verifier-material.json",
        &agg.venue.risc0_extractor_json,
    )?;
    // Item 6: the candidate lock BYTES + authoritative tool identities come from the
    // TYPED aggregate (verified at import), so Stage 6 needs no `cp` from a directory.
    write("tool-identities.json", &agg.tool_identities_json)?;
    for (candidate, bytes) in &agg.locks {
        let p = Path::new(out_dir).join(format!("{candidate}.Cargo.lock"));
        if p.exists() {
            return Err(format!("refusing to overwrite existing {}", p.display()));
        }
        std::fs::write(&p, bytes).map_err(|e| format!("write {}: {e}", p.display()))?;
    }
    Ok(format!(
        "cross-architecture aggregate written to {out_dir} from TWO import-verified typed bundles \
         (RISC Zero material + candidate locks + tool identities sourced from x86_64)"
    ))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, layout, arch] if cmd == "oci-manifest" => oci_manifest(layout, arch),
        [cmd, recorded, runtime] if cmd == "verify-runtime-image" => {
            verify_runtime_image(recorded, runtime)
        }
        [cmd, lock] if cmd == "lock-hash" => lock_hash(lock),
        [cmd, prov, lock] if cmd == "verify-lock" => verify_lock(prov, lock),
        [cmd, mode, declared, artifact, installed] if cmd == "verify-tool" => {
            verify_tool(mode, declared, artifact, installed)
        }
        [cmd, graph, adv, lic, out] if cmd == "stage2-audit" => stage2_audit(graph, adv, lic, out),
        [cmd, dir] if cmd == "import-arch" => import_arch(dir),
        [cmd, x86, arm, out] if cmd == "aggregate-arches" => aggregate_arches(x86, arm, out),
        [cmd, dir, arch, commit] if cmd == "seal-bundle" => seal_bundle(dir, arch, commit),
        [cmd, dir] if cmd == "import-bundle" => import_bundle(dir),
        [cmd, x86, arm, out] if cmd == "aggregate-bundles" => aggregate_bundles(x86, arm, out),
        [cmd, extractor, target, host, container] if cmd == "stage4-guard" => {
            stage4_guard(extractor, target, host, container)
        }
        [cmd, record] if cmd == "stage2-record" => stage2_record(record),
        [cmd, result] if cmd == "verify-stage5" => verify_stage5(result),
        [cmd, dir, arch] if cmd == "emit-test-only-bundle" => {
            let sa = schema_arch(arch)?;
            evidence_bundle::write_test_only_bundle_dir(Path::new(dir), sa)
                .map(|()| format!("wrote TEST_ONLY per-arch evidence bundle to {dir} (arch={sa})"))
        }
        _ => Err(
            "usage: venue-verify <oci-manifest|verify-runtime-image|lock-hash|verify-lock|\
             verify-tool|stage2-audit|stage2-record|stage4-guard|verify-stage5|import-arch|\
             aggregate-arches|seal-bundle|import-bundle|aggregate-bundles|\
             emit-test-only-bundle> ..."
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REFUSED: {e}");
            ExitCode::FAILURE
        }
    }
}
