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
    authenticate_manifest, derive_guest_set, verify_canonical_sp1_guest_artifact,
    GuestIdentityRecord, MERGED_SPEC_HASH_HEX,
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
        let jv: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("parse raw facts: {e}"))?;
        b0_pre_validator::producer::refuse_legacy_operator_hashes(&jv)?;
        let raw: RawFacts =
            serde_json::from_str(&text).map_err(|e| format!("parse raw facts: {e}"))?;
        validate_raw_facts(&raw)?;
        return Ok(format!(
            "RawFacts at {facts} are structurally valid for measurement"
        ));
    }
    // TYPED runner-attestation generator: build the per-arch `provenance.json` runner_attestation from
    // the retained recipe + Phase-1 identity record + authenticated scalar inputs, run the sealed-import
    // self-consistency + continuity checks, emit canonical JSON, and re-decode + re-check before writing.
    // The security-critical construction is typed here; `measure_fragment.sh` only splices the bytes.
    if mode == "--gen-runner-attestation" {
        let inputs_p = args.next().ok_or("missing <inputs.json>")?;
        let recipe_p = args.next().ok_or("missing <recipe.json>")?;
        let records_p = args.next().ok_or("missing <identity-records.json>")?;
        let out_p = args.next().ok_or("missing <out.json>")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let inputs: b0_pre_validator::producer::RunnerAttestationGenInputs = serde_json::from_str(
            &std::fs::read_to_string(&inputs_p).map_err(|e| format!("read {inputs_p}: {e}"))?,
        )
        .map_err(|e| format!("parse inputs {inputs_p}: {e}"))?;
        let recipe: b0_pre_validator::producer::RunnerRecipeJson = serde_json::from_str(
            &std::fs::read_to_string(&recipe_p).map_err(|e| format!("read {recipe_p}: {e}"))?,
        )
        .map_err(|e| format!("parse recipe {recipe_p}: {e}"))?;
        let records: Vec<GuestIdentityRecord> = serde_json::from_str(
            &std::fs::read_to_string(&records_p).map_err(|e| format!("read {records_p}: {e}"))?,
        )
        .map_err(|e| format!("parse identity records {records_p}: {e}"))?;
        let bytes =
            b0_pre_validator::producer::generate_runner_attestation(&inputs, &recipe, &records)?;
        std::fs::write(&out_p, &bytes).map_err(|e| format!("write {out_p}: {e}"))?;
        return Ok(format!(
            "runner_attestation generated + self-verified for {}/{} -> {out_p}",
            recipe.candidate, inputs.arch
        ));
    }
    // PRE-PROVING provenance gate: run the SAME per-record binder + Phase-1 continuity the sealed importer
    // runs over the COMPLETE assembled provenance.json, so no proof launches on an unacceptable record.
    if mode == "--validate-provenance" {
        let prov_p = args.next().ok_or("missing <provenance.json>")?;
        let records_p = args.next().ok_or("missing <identity-records.json>")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let prov = std::fs::read_to_string(&prov_p).map_err(|e| format!("read {prov_p}: {e}"))?;
        let records: Vec<GuestIdentityRecord> = serde_json::from_str(
            &std::fs::read_to_string(&records_p).map_err(|e| format!("read {records_p}: {e}"))?,
        )
        .map_err(|e| format!("parse identity records {records_p}: {e}"))?;
        let n = b0_pre_validator::producer::validate_provenance(&prov, &records)?;
        return Ok(format!(
            "provenance at {prov_p} accepted: {n} role(s) bound (self-consistency + recipe artifacts + Phase-1 continuity)"
        ));
    }
    // FAIL-FAST PRE-GRID authority gate: the venue runs this on the retained MeasurementInputAuthorityV1
    // + its malformed-corpus report + harness-source inventory BEFORE any proving cell. It decodes +
    // cross-binds all three (report + inventory addresses independently recomputed from the retained
    // bytes) AND ties the authority to the RATIFIED measurement-tooling authority (commit + path-set) —
    // so a valid OLD authority package (bound to superseded tooling) can never be reused after source
    // edits change the tooling.
    if mode == "--verify-authority" {
        let mia_p = args
            .next()
            .ok_or("missing <measurement-input-authority.v1.json>")?;
        let report_p = args
            .next()
            .ok_or("missing <malformed-corpus-report.v1.json>")?;
        let inv_p = args
            .next()
            .ok_or("missing <harness-source-inventory.txt>")?;
        let elig_p = args.next().ok_or("missing <eligibility-matrix.v1.json>")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let mia_b = std::fs::read(&mia_p).map_err(|e| format!("read {mia_p}: {e}"))?;
        let report_b = std::fs::read(&report_p).map_err(|e| format!("read {report_p}: {e}"))?;
        let inv_b = std::fs::read(&inv_p).map_err(|e| format!("read {inv_p}: {e}"))?;
        let elig_b = std::fs::read(&elig_p).map_err(|e| format!("read {elig_p}: {e}"))?;
        let mia = b0_pre_validator::venue::measurement_input_authority::MeasurementInputAuthorityV1::from_json(
            &mia_b,
        )?;
        mia.verify(
            b0_pre_validator::guest_set::RATIFIED_SOURCE_COMMIT,
            MERGED_SPEC_HASH_HEX,
        )?;
        mia.verify_binds(
            &inv_b,
            &report_b,
            &elig_b,
            b0_pre_validator::guest_set::RATIFIED_SOURCE_COMMIT,
            MERGED_SPEC_HASH_HEX,
        )?;
        mia.verify_tooling_ratified(
            b0_pre_validator::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT,
            b0_pre_validator::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
        )?;
        return Ok(format!(
            "measurement-input authority verified + tooling-bound: address {}",
            mia.address
        ));
    }
    // Phase-1 guest-closure: derive the canonical r0_guest_set_hash from the typed, verified
    // guest identity records (fail-closed) and emit the content-addressed coordination manifest.
    if mode == "--guest-set" {
        let records_path = args.next().ok_or("missing <identity-records.json>")?;
        let out = args.next().ok_or("missing <out_dir>")?;
        let canon_pkg = args
            .next()
            .ok_or("missing <canonical-sp1-guest-package-dir> (v8: the ONE shared SP1 guest)")?;
        if args.next().is_some() {
            return Err("too many arguments".into());
        }
        let text = std::fs::read_to_string(&records_path)
            .map_err(|e| format!("read {records_path}: {e}"))?;
        let records: Vec<GuestIdentityRecord> =
            serde_json::from_str(&text).map_err(|e| format!("parse identity records: {e}"))?;
        // v8: re-decode the canonical SP1 guest artifact from its RETAINED package bytes and require
        // every SP1 record to reference exactly it (address + program_id + guest_image_hash). Never a
        // copied hash — the manifest is parsed and the ELF re-hashed here.
        let canon_dir = PathBuf::from(&canon_pkg);
        let canon_manifest = std::fs::read(canon_dir.join("canonical-sp1-guest-artifact.v1.json"))
            .map_err(|e| format!("read canonical artifact manifest: {e}"))?;
        let canon_elf = std::fs::read(canon_dir.join("guest.elf"))
            .map_err(|e| format!("read canonical artifact ELF: {e}"))?;
        let canon_addr =
            verify_canonical_sp1_guest_artifact(&records, &canon_manifest, &canon_elf)?;
        let gs = derive_guest_set(&records, MERGED_SPEC_HASH_HEX)?;
        let out_dir = PathBuf::from(out);
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
        // v8: retain the canonical artifact BYTES as mandatory, uniquely-addressed members of the
        // sealed guest set — downstream re-decodes them from scratch, never a copied hash.
        let mem = out_dir.join("canonical-sp1-guest");
        std::fs::create_dir_all(&mem).map_err(|e| format!("mkdir canonical member: {e}"))?;
        std::fs::write(
            mem.join("canonical-sp1-guest-artifact.v1.json"),
            &canon_manifest,
        )
        .map_err(|e| format!("write canonical manifest member: {e}"))?;
        std::fs::write(mem.join("guest.elf"), &canon_elf)
            .map_err(|e| format!("write canonical ELF member: {e}"))?;
        std::fs::write(mem.join("address.txt"), format!("{canon_addr}\n"))
            .map_err(|e| format!("write canonical address member: {e}"))?;
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
        let jv: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("parse raw facts: {e}"))?;
        b0_pre_validator::producer::refuse_legacy_operator_hashes(&jv)?;
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
        // produce() now binds the package to the AUTHORITATIVE guest set derived from these Phase-1
        // records (reconciling the multi-arch SP1 guest) and verifies every measured fragment is
        // consistent with its matching x86_64 record. The equality below is therefore an invariant belt.
        let pkg = produce(&raw, &records)?;
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

    // DRY-RUN / TEST_ONLY: no external records file — reconstruct the Phase-1 records the synthetic
    // fragments correspond to (reproduces the same guest set) so produce() binds records-authoritatively.
    let pkg = produce(&raw, &b0_pre_validator::producer::records_from_raw(&raw))?;
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
