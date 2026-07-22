//! `stage6-assemble` — the production Stage-6 bundle producer.
//!
//! It consumes the ACTUAL venue outputs and emits the strict
//! `b0-pre-stage1-result-bundle-v1` JSON that `stage1-ingest` then re-validates.
//! It is the ONLY accepted way to produce that bundle; nothing hand-composes it.
//!
//! Authoritative usage (real venue) — emits an `AUTHORITATIVE_STAGE1` bundle only
//! from complete real inputs (fails closed on absent / synthetic tool identities):
//! ```text
//! stage6-assemble <oci_digests.json> <sp1_extractor.json> <risc0_extractor.json> \
//!                 <native.json> <tool_identities.json> \
//!                 <sp1_Cargo.lock> <risc0_Cargo.lock> <out_bundle.json>
//! ```
//!
//! Local TEST_ONLY paths (Blocker 4): these emit ONLY a `TEST_ONLY`-classified
//! bundle, which authoritative ingest REFUSES — there is NO shippable command that
//! mints an `AUTHORITATIVE_STAGE1` bundle from synthetic data.
//! ```text
//! stage6-assemble --test-only <out_bundle.json>              # in-code synthetic inputs
//! stage6-assemble --test-only-from-files <oci> <sp1_ext> <risc0_ext> \
//!                 <native> <tools> <sp1_lock> <risc0_lock> <out>   # real-shaped files
//! stage6-assemble --validate-test-only <bundle.json>         # full validation, no output
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use b0_pre_validator::durable::write_durably;
use b0_pre_validator::schema::stage1_bundle::validate_test_only_bundle;
use b0_pre_validator::schema::stage6::{assemble_bundle, test_only_bundle, AssembleMode};

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn read_str(path: &str) -> Result<String, String> {
    let bytes = read(path)?;
    String::from_utf8(bytes).map_err(|e| format!("{path} is not utf-8: {e}"))
}

/// Durably write the bundle to `out`, refusing to overwrite an existing target.
/// Routed through the SHARED [`write_durably`] create-new temp path so a
/// write/sync failure can never leave a partial final bundle (file-safety fix).
fn write_bundle(out: &str, bundle: &impl serde::Serialize) -> Result<String, String> {
    let json =
        serde_json::to_string_pretty(bundle).map_err(|e| format!("serialize bundle: {e}"))?;
    let body = format!("{json}\n");
    let out_path = PathBuf::from(out);
    // Fail-closed: never silently replace a prior bundle; the venue points this at a
    // fresh workdir target.
    if out_path.exists() {
        return Err(format!(
            "refusing to overwrite existing bundle {out}; point <out> at a fresh target"
        ));
    }
    let tmp = out_path.with_extension(format!("tmp.{}", std::process::id()));
    write_durably(&tmp, &out_path, body.as_bytes())?;
    Ok(format!("wrote Stage-1 result bundle to {out}"))
}

/// Assemble from the seven file inputs in the given mode.
#[allow(clippy::too_many_arguments)]
fn assemble_from_files(
    mode: AssembleMode,
    oci: &str,
    sp1_ext: &str,
    risc0_ext: &str,
    native: &str,
    tools: &str,
    sp1_lock: &str,
    risc0_lock: &str,
) -> Result<impl serde::Serialize, String> {
    assemble_bundle(
        mode,
        &read_str(oci)?,
        &read_str(sp1_ext)?,
        &read_str(risc0_ext)?,
        &read_str(native)?,
        Some(&read_str(tools)?),
        &read(sp1_lock)?,
        &read(risc0_lock)?,
    )
    .map_err(|e| e.to_string())
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, out] if flag == "--test-only" => {
            let bundle = test_only_bundle();
            write_bundle(out, &bundle)
        }
        [flag, bundle_path] if flag == "--validate-test-only" => {
            // Full semantic validation of a NON-authoritative bundle, with NO output
            // and NO route to a finalizable artifact.
            let raw = std::fs::read(Path::new(bundle_path))
                .map_err(|e| format!("cannot read bundle {bundle_path}: {e}"))?;
            let class = validate_test_only_bundle(&raw).map_err(|e| e.to_string())?;
            Ok(format!(
                "validated {bundle_path}: {class:?} bundle is well-formed (no finalizable \
                 artifact was or can be produced)"
            ))
        }
        [flag, oci, sp1_ext, risc0_ext, native, tools, sp1_lock, risc0_lock, out]
            if flag == "--test-only-from-files" =>
        {
            let bundle = assemble_from_files(
                AssembleMode::TestOnly,
                oci,
                sp1_ext,
                risc0_ext,
                native,
                tools,
                sp1_lock,
                risc0_lock,
            )?;
            write_bundle(out, &bundle)
        }
        [oci, sp1_ext, risc0_ext, native, tools, sp1_lock, risc0_lock, out] => {
            let bundle = assemble_from_files(
                AssembleMode::Authoritative,
                oci,
                sp1_ext,
                risc0_ext,
                native,
                tools,
                sp1_lock,
                risc0_lock,
            )?;
            write_bundle(out, &bundle)
        }
        _ => Err(
            "usage: stage6-assemble <oci_digests.json> <sp1_extractor.json> \
                  <risc0_extractor.json> <native.json> <tool_identities.json> \
                  <sp1_Cargo.lock> <risc0_Cargo.lock> <out_bundle.json>\n   or: \
                  stage6-assemble --test-only <out_bundle.json>\n   or: \
                  stage6-assemble --test-only-from-files <oci> <sp1_ext> <risc0_ext> \
                  <native> <tools> <sp1_lock> <risc0_lock> <out>\n   or: \
                  stage6-assemble --validate-test-only <bundle.json>"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(msg) => {
            eprintln!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REFUSED: {e}");
            ExitCode::FAILURE
        }
    }
}
