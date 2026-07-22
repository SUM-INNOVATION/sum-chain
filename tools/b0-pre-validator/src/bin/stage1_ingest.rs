//! `stage1-ingest` — the authoritative Stage-1 insertion gate.
//!
//! Usage: `stage1-ingest <bundle.json> <out-artifact.json>`
//!
//! Runs the full in-memory pipeline in
//! [`b0_pre_validator::schema::stage1_bundle::build_finalizable_artifact`]:
//! strict decode + forbidden-field scan, exact coverage / provenance /
//! reproducibility validation, canonical verifier-material reconstruction +
//! identity + total + the four-stamp fixture gate, the complete `pending_inputs`
//! replacement, and a whole-artifact semantic re-validation. It writes the
//! regenerated `finalizable` artifact to `<out>` DURABLY (create-new temp → write
//! → flush → fsync → rename → parent-dir fsync), and ONLY after every check passes
//! — a malformed bundle exits non-zero and writes nothing.
//!
//! Fail-closed output: it REFUSES an already-existing `<out>` (never silently
//! replaces a prior venue result), creates the temp with `create_new(true)` (a
//! stale temp is refused, not clobbered), propagates every write/flush/sync error
//! (removing the temp on failure), and `sync_all`s both the file and the parent
//! directory so a write reported as complete is actually durable — never an
//! fsync-free rename described as durable.
//!
//! This binary NEVER computes or writes the real `b0_pre_spec_hash`, and it
//! REFUSES to write over the committed normative artifact: `<out>` must be a temp
//! target (the venue points it at the workdir). It replaces the former loose,
//! host-side Python key-check in `run_authoritative.sh`; there is no alternate
//! acceptance path.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use b0_pre_validator::durable::write_durably;
use b0_pre_validator::schema::stage1_bundle::build_finalizable_artifact;

/// The committed normative artifact, resolved at compile time. `<out>` must never
/// resolve to this path — the pipeline emits a finalizable artifact and the
/// committed one must stay `not_finalizable`.
const COMMITTED_ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/b0-pre-protocol-v1.json"
);

fn resolve(p: &Path) -> PathBuf {
    // Canonicalize what exists; for a not-yet-created output, resolve its parent
    // and re-attach the file name so the guard still compares real paths.
    if let Ok(c) = p.canonicalize() {
        return c;
    }
    match (p.parent(), p.file_name()) {
        (Some(dir), Some(name)) => dir
            .canonicalize()
            .map(|d| d.join(name))
            .unwrap_or_else(|_| p.to_path_buf()),
        _ => p.to_path_buf(),
    }
}

fn run() -> Result<String, String> {
    let mut args = std::env::args_os().skip(1);
    let bundle_path = args
        .next()
        .ok_or("usage: stage1-ingest <bundle.json> <out-artifact.json>")?;
    let out_path = args
        .next()
        .ok_or("usage: stage1-ingest <bundle.json> <out-artifact.json>")?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let bundle_path = PathBuf::from(bundle_path);
    let out_path = PathBuf::from(out_path);

    // Guard: never write the committed normative artifact to a finalizable state.
    if resolve(&out_path) == resolve(Path::new(COMMITTED_ARTIFACT)) {
        return Err(
            "refusing to write the committed normative artifact; <out> must be a temp target"
                .into(),
        );
    }

    // Fail-closed: never silently replace a prior venue result. A pre-existing
    // <out> is refused rather than overwritten.
    if out_path.exists() {
        return Err(format!(
            "refusing to overwrite existing output {}; remove it or point <out> at a fresh target",
            out_path.display()
        ));
    }

    let raw = std::fs::read(&bundle_path)
        .map_err(|e| format!("cannot read bundle {}: {e}", bundle_path.display()))?;

    // The entire acceptance decision. Any failure -> Err, and nothing is written.
    let artifact = build_finalizable_artifact(&raw).map_err(|e| e.to_string())?;

    let json =
        serde_json::to_string_pretty(&artifact).map_err(|e| format!("serialize artifact: {e}"))?;
    let body = format!("{json}\n");

    // Durable create-new write into a fresh sibling temp, fsync, then rename +
    // parent-dir fsync. The artifact only appears at <out> once fully durable.
    let tmp = out_path.with_extension(format!("tmp.{}", std::process::id()));
    write_durably(&tmp, &out_path, body.as_bytes())?;

    Ok(format!(
        "accepted: wrote finalizable Stage-1 artifact to {} (real b0_pre_spec_hash NOT computed)",
        out_path.display()
    ))
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
