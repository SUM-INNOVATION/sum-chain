//! Official B0-FINAL measurement PRODUCER entry point.
//!
//! Converts raw venue facts (JSON) into a deterministic, content-addressed
//! measurement package through the ONE canonical assembler. Fail-closed: it
//! requires lifecycle mode `measurement` and the exact merged `b0_pre_spec_hash`,
//! refuses a turbo-enabled host, and never fabricates a RISC-Zero-aarch64 cell.
//!
//! Usage:
//!   measure-produce --facts <raw-facts.json> <out_dir>   # real venue facts
//!   measure-produce --dry-run <out_dir>                   # deterministic self-test
//!
//! Writes <out_dir>/real-orchestrator-vector.bin (the vector both verifiers accept),
//! <out_dir>/inventory.json, and <out_dir>/package-id.txt. Never writes over the
//! committed fixtures.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use b0_pre_validator::guest_set::{
    authenticate_manifest, derive_guest_set, GuestIdentityRecord, MERGED_SPEC_HASH_HEX,
};
use b0_pre_validator::merge::merge_fragments;
use b0_pre_validator::producer::{dry_run_raw_facts, produce, validate_raw_facts, RawFacts};

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn write_package(
    out_dir: &Path,
    pkg: &b0_pre_validator::producer::MeasurementPackage,
) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
    std::fs::write(out_dir.join("real-orchestrator-vector.bin"), &pkg.vector)
        .map_err(|e| format!("write vector: {e}"))?;
    let inv = serde_json::to_string_pretty(&pkg.inventory()).map_err(|e| e.to_string())?;
    std::fs::write(out_dir.join("inventory.json"), format!("{inv}\n"))
        .map_err(|e| format!("write inventory: {e}"))?;
    std::fs::write(
        out_dir.join("package-id.txt"),
        format!("{}\n", hx(&pkg.package_id)),
    )
    .map_err(|e| format!("write package-id: {e}"))?;
    Ok(())
}

fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or(
        "usage: measure-produce <--facts <raw-facts.json> <out_dir> | --dry-run <out_dir> | --validate <raw-facts.json>>",
    )?;
    // Cheap pre-proving structural validation: the venue runs this on the RawFacts it
    // has assembled BEFORE it spends hours proving, so a malformed grid fails fast.
    if mode == "--validate" {
        let facts = args.next().ok_or("missing <raw-facts.json>")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let text = std::fs::read_to_string(&facts).map_err(|e| format!("read {facts}: {e}"))?;
        let raw: RawFacts =
            serde_json::from_str(&text).map_err(|e| format!("parse raw facts: {e}"))?;
        validate_raw_facts(&raw)?;
        return Ok(format!(
            "RawFacts at {facts} are structurally valid for measurement"
        ));
    }
    // Phase-1 guest-closure: derive the canonical r0_guest_set_hash from the typed, verified
    // guest identity records (fail-closed) and emit the content-addressed coordination manifest.
    if mode == "--guest-set" {
        let records_path = args.next().ok_or("missing <identity-records.json>")?;
        let out = args.next().ok_or("missing <out_dir>")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let text = std::fs::read_to_string(&records_path)
            .map_err(|e| format!("read {records_path}: {e}"))?;
        let records: Vec<GuestIdentityRecord> =
            serde_json::from_str(&text).map_err(|e| format!("parse identity records: {e}"))?;
        let gs = derive_guest_set(&records, MERGED_SPEC_HASH_HEX)?;
        let out_dir = PathBuf::from(out);
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
        std::fs::write(out_dir.join("guest-allowlist.bin"), gs.allowlist.encode())
            .map_err(|e| format!("write allowlist: {e}"))?;
        std::fs::write(
            out_dir.join("r0_guest_set_hash.txt"),
            format!("{}\n", hx(&gs.r0_guest_set_hash)),
        )
        .map_err(|e| format!("write guest-set hash: {e}"))?;
        std::fs::write(
            out_dir.join("coordination-manifest.json"),
            format!("{}\n", gs.manifest_json),
        )
        .map_err(|e| format!("write coordination manifest: {e}"))?;
        return Ok(format!(
            "guest set derived: r0_guest_set_hash {} (coordination manifest {})",
            hx(&gs.r0_guest_set_hash),
            hx(&gs.manifest_hash)
        ));
    }
    // Typed fragment merge (#6): combine per-(candidate,arch) fragments into canonical RawFacts.
    if mode == "--merge-fragments" {
        let out = args.next().ok_or("missing <out_dir>")?;
        let frag_paths: Vec<String> = args.collect();
        if frag_paths.is_empty() {
            return Err("no fragment paths given".into());
        }
        let mut frags = Vec::new();
        for p in &frag_paths {
            let t = std::fs::read_to_string(p).map_err(|e| format!("read {p}: {e}"))?;
            frags.push(serde_json::from_str(&t).map_err(|e| format!("parse {p}: {e}"))?);
        }
        let raw = merge_fragments(MERGED_SPEC_HASH_HEX, &frags)?;
        let out_dir = PathBuf::from(out);
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
        std::fs::write(
            out_dir.join("merged-raw-facts.json"),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&raw).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| format!("write merged raw facts: {e}"))?;
        return Ok(format!(
            "merged {} fragments into canonical RawFacts ({}/merged-raw-facts.json)",
            frags.len(),
            out_dir.display()
        ));
    }
    // Final package production from real facts (#5/#1): the phase-1 identity records are a
    // REQUIRED input. The guest set is INDEPENDENTLY RE-DERIVED here from those records (never
    // trusting an r0_guest_set_hash field from arbitrary JSON), and the produced package's
    // r0_guest_set_hash MUST equal the re-derivation. When a coordination manifest is also
    // supplied, its content hash must equal the re-derived manifest hash (manifest authenticated
    // against the records). A forged manifest cannot pass.
    if mode == "--facts" {
        let facts = args.next().ok_or("missing <raw-facts.json>")?;
        let out = args.next().ok_or("missing <out_dir>")?;
        let records_path = args.next().ok_or(
            "missing <identity-records.json> (phase-1 records required to re-derive the guest set)",
        )?;
        let manifest = args.next(); // optional: cross-checked against the re-derivation if given
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let text = std::fs::read_to_string(&facts).map_err(|e| format!("read {facts}: {e}"))?;
        let raw: RawFacts =
            serde_json::from_str(&text).map_err(|e| format!("parse raw facts: {e}"))?;
        let rtext = std::fs::read_to_string(&records_path)
            .map_err(|e| format!("read {records_path}: {e}"))?;
        let records: Vec<GuestIdentityRecord> =
            serde_json::from_str(&rtext).map_err(|e| format!("parse identity records: {e}"))?;
        // INDEPENDENT re-derivation from the typed, verified records (fail-closed).
        let gs = derive_guest_set(&records, MERGED_SPEC_HASH_HEX)?;
        // If a coordination manifest was handed over, authenticate its FULL canonical bytes
        // against the re-derivation (not merely the self-declared manifest_hash field).
        if let Some(m) = &manifest {
            let mtext = std::fs::read_to_string(m).map_err(|e| format!("read {m}: {e}"))?;
            authenticate_manifest(&mtext, &gs)?;
        }
        let out_dir = PathBuf::from(out);
        let pkg = produce(&raw)?;
        if pkg.r0_guest_set_hash != gs.r0_guest_set_hash {
            return Err(format!(
                "package r0_guest_set_hash {} != re-derived phase-1 guest set {}; refusing",
                hx(&pkg.r0_guest_set_hash),
                hx(&gs.r0_guest_set_hash)
            ));
        }
        write_package(&out_dir, &pkg)?;
        return Ok(format!(
            "measurement package written to {} bound to re-derived phase-1 guest set {} (package_id {})",
            out_dir.display(),
            hx(&gs.r0_guest_set_hash),
            hx(&pkg.package_id)
        ));
    }
    let (raw, out_dir): (RawFacts, PathBuf) = match mode.as_str() {
        "--dry-run" => {
            let out = args.next().ok_or("missing <out_dir>")?;
            (dry_run_raw_facts(), PathBuf::from(out))
        }
        other => return Err(format!("unknown mode `{other}`")),
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let pkg = produce(&raw)?;
    write_package(&out_dir, &pkg)?;

    let verdicts: Vec<String> = pkg
        .verdicts
        .iter()
        .map(|(c, v)| format!("{c:?}={v:?}"))
        .collect();
    Ok(format!(
        "measurement package written to {} (package_id {}, {} bytes); verdicts: {}",
        out_dir.display(),
        hx(&pkg.package_id),
        pkg.vector.len(),
        verdicts.join(", ")
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

// Silence unused-import lints on Path in some cfgs.
#[allow(dead_code)]
fn _p(_: &Path) {}
