//! End-to-end cargo dependency-SEED anchor smoke path (validator legs):
//!   raw facts -> produce VEC7 -> validator import (verify_evidence, which runs the sealed-import anchor)
//! plus the decisive negatives at the produce boundary: a MISSING seed and a SWAPPED (cross-candidate)
//! seed are both refused. (The independent-import leg of the same chain is covered in
//! `tools/b0-pre-independent/tests/`, which re-verifies the produced VEC7 bytes + its own negatives.)

use b0_pre_validator::harness::verify_evidence;
use b0_pre_validator::measurement::parse_vector;
use b0_pre_validator::producer::{dry_run_raw_facts, produce, records_from_raw};
use b0_pre_validator::schema::allowlist::GuestProgramAllowlistV1;
use b0_pre_validator::schema::result_set::R0ResultSetV1;

/// Positive chain: raw facts -> produce VEC7 -> validator import. verify_evidence re-runs the sealed-import
/// cargo dependency-seed anchor per provenance; SP1 qualifies, RISC0 (x86-only) is completeness-disqualified
/// AFTER the anchor passes (so a green SP1 proves the anchor accepted the sealed dependency seed).
#[test]
fn e2e_raw_facts_produce_import_positive() {
    let pkg = produce(
        &dry_run_raw_facts(),
        &records_from_raw(&dry_run_raw_facts()),
    )
    .expect("dry-run facts produce a VEC7 package");
    let (allowlist_bytes, _mia, _report, _inv, _elig, _v2, bundles) =
        parse_vector(&pkg.vector).expect("VEC7 vector parses");
    let gs = GuestProgramAllowlistV1::decode_exact(&allowlist_bytes)
        .expect("allowlist decodes")
        .guest_set_hash();
    assert_eq!(bundles.len(), 2);
    for (candidate, ev) in &bundles {
        assert!(
            !ev.dependency_seed_json.is_empty(),
            "every bundle seals a dependency-seed record (VEC7)"
        );
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(rs.r0_guest_set_hash, gs);
        // Two-cell model: BOTH candidates carry their complete x86_64-only native matrix and verify +
        // qualify through the sealed-import dependency-seed anchor.
        let _ = candidate;
        assert!(
            verify_evidence(ev).unwrap().qualification,
            "each x86-only measurement cell verifies + qualifies through the anchor"
        );
    }
}

/// Negative: a MISSING (empty) dependency seed is refused at produce — the anchor decodes the sealed
/// record from scratch, so an unsealed origin cannot be produced.
#[test]
fn e2e_produce_refuses_missing_dependency_seed() {
    let mut raw = dry_run_raw_facts();
    let sp1 = raw
        .candidates
        .iter_mut()
        .find(|c| c.candidate == "Sp1")
        .expect("sp1 candidate");
    sp1.dependency_seed_json = String::new();
    let err = produce(&raw, &records_from_raw(&raw))
        .expect_err("missing dependency seed must be refused");
    let e = err.to_lowercase();
    assert!(
        e.contains("dependency") || e.contains("eof") || e.contains("parse"),
        "unexpected error for missing seed: {err}"
    );
}

/// Negative: a SWAPPED cross-candidate seed (RISC0's dependency seed placed on the SP1 candidate) is
/// refused at produce — the anchor's `verify(candidate)` rejects the cross-candidate record.
#[test]
fn e2e_produce_refuses_swapped_cross_candidate_seed() {
    let mut raw = dry_run_raw_facts();
    let r0_seed = raw
        .candidates
        .iter()
        .find(|c| c.candidate == "Risc0")
        .expect("risc0 candidate")
        .dependency_seed_json
        .clone();
    raw.candidates
        .iter_mut()
        .find(|c| c.candidate == "Sp1")
        .expect("sp1 candidate")
        .dependency_seed_json = r0_seed;
    let err = produce(&raw, &records_from_raw(&raw))
        .expect_err("swapped cross-candidate dependency seed must be refused");
    let e = err.to_lowercase();
    assert!(
        e.contains("candidate") || e.contains("dependency"),
        "unexpected error for swapped seed: {err}"
    );
}
