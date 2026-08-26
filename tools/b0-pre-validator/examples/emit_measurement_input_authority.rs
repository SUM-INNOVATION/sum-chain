//! Regenerate the committed TEST_ONLY measurement-input-authority fixture triple for the CURRENT
//! `MERGED_SPEC_HASH_HEX` (the reviewed two-cell spec `e933e732…`):
//!   * `eligibility-matrix.v1.json`      — the canonical two-cell eligibility/unsupported record;
//!   * `malformed-corpus-report.v1.json` — re-spec'd + re-addressed (report BODY unchanged);
//!   * `measurement-input-authority.v1.json` — re-spec'd, binding the new report + eligibility addresses.
//!
//! The harness-source inventory manifest is spec-independent (its address is BLAKE3 over the manifest
//! bytes only), so it is NOT rewritten. These are MECHANICS-ONLY vectors bound to the non-authoritative
//! sentinel tooling commit — the production `--verify-authority` gate refuses the sentinel. All three
//! addresses are recomputed through the reference crate's own preimages (never hand-authored).

use std::fs;
use std::path::Path;

use b0_pre_validator::guest_set::RATIFIED_SOURCE_COMMIT;
use b0_pre_validator::producer::MERGED_SPEC_HASH_HEX;
use b0_pre_validator::venue::eligibility_matrix::EligibilityMatrixV1;
use b0_pre_validator::venue::malformed_corpus_report::MalformedCorpusReportV1;
use b0_pre_validator::venue::measurement_input_authority::{
    MeasurementInputAuthorityV1, MEASUREMENT_INPUT_AUTHORITY_SCHEMA, RSS_STATEMENT_BINDING_POLICY,
};

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/b0-pre/fixtures/measurement-input-authority");
    let spec = MERGED_SPEC_HASH_HEX;

    // 1) Canonical two-cell eligibility record (address self-computed over the frozen preimage).
    let elig = EligibilityMatrixV1::canonical(spec);
    elig.verify(spec)
        .expect("canonical eligibility record verifies");
    fs::write(
        dir.join("eligibility-matrix.v1.json"),
        format!("{}\n", elig.to_json()),
    )
    .expect("write eligibility-matrix.v1.json");

    // 2) Malformed-corpus report: re-spec + re-address (the report body/members are spec-independent).
    let mut report = MalformedCorpusReportV1::from_json(
        &fs::read(dir.join("malformed-corpus-report.v1.json")).expect("read old report"),
    )
    .expect("old report parses");
    report.b0_pre_spec_hash = spec.to_string();
    report.address = report.recompute_address();
    let report_json = serde_json::to_string_pretty(&report).expect("serialize report");
    fs::write(
        dir.join("malformed-corpus-report.v1.json"),
        format!("{report_json}\n"),
    )
    .expect("write report");
    report
        .verify(RATIFIED_SOURCE_COMMIT, spec)
        .expect("re-addressed report verifies");

    // 3) MIA: rebuild with the new spec, binding the new report + eligibility addresses. Spec-independent
    //    fields (measured commit, sentinel tooling, inventory address) are carried from the old fixture.
    let old_mia: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("measurement-input-authority.v1.json")).unwrap())
            .expect("old MIA parses as JSON");
    let carry = |k: &str| old_mia[k].as_str().expect("string field").to_string();
    let mut mia = MeasurementInputAuthorityV1 {
        schema: MEASUREMENT_INPUT_AUTHORITY_SCHEMA.to_string(),
        b0_pre_spec_hash: spec.to_string(),
        measured_source_commit: carry("measured_source_commit"),
        tooling_commit: carry("tooling_commit"),
        tooling_pathset_blake3: carry("tooling_pathset_blake3"),
        harness_source_inventory_address: carry("harness_source_inventory_address"),
        malformed_corpus_report_address: report.address.clone(),
        rss_statement_binding_policy: RSS_STATEMENT_BINDING_POLICY.to_string(),
        eligibility_matrix_address: elig.address.clone(),
        address: String::new(),
    };
    mia.address = mia.recompute_address();
    let mia_json = serde_json::to_string_pretty(&mia).expect("serialize MIA");
    fs::write(
        dir.join("measurement-input-authority.v1.json"),
        format!("{mia_json}\n"),
    )
    .expect("write MIA");

    // Full sanity: shape + self-consistency + it binds the three retained sub-artifacts.
    let inv = fs::read(dir.join("harness-source-inventory.txt")).expect("read inventory");
    mia.verify(RATIFIED_SOURCE_COMMIT, spec)
        .expect("MIA shape/self-consistency");
    mia.verify_binds(
        &inv,
        format!("{report_json}\n").as_bytes(),
        format!("{}\n", elig.to_json()).as_bytes(),
        RATIFIED_SOURCE_COMMIT,
        spec,
    )
    .expect("MIA binds inventory + report + eligibility");

    eprintln!(
        "wrote eligibility-matrix.v1.json ({} bytes), malformed-corpus-report.v1.json, \
         measurement-input-authority.v1.json for spec {spec}\n  eligibility_addr={}\n  report_addr={}\n  mia_addr={}",
        elig.to_json().len(),
        elig.address,
        report.address,
        mia.address
    );
}
