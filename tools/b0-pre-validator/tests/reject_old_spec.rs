//! Migration guard: after the reviewed two-cell correction, EVERY production path must refuse the
//! superseded `201cfcb8…` spec — no mixed old MIA / records / identities / fragments / packages. The
//! finalized spec is now `e933e732…`; anything bound to the old spec is a stale artifact and refused.

use b0_pre_validator::producer::{
    dry_run_raw_facts, produce, records_from_raw, MERGED_SPEC_HASH_HEX,
};

const OLD_SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

#[test]
fn merged_spec_is_the_new_two_cell_hash() {
    assert_eq!(
        MERGED_SPEC_HASH_HEX,
        "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2"
    );
    assert_ne!(MERGED_SPEC_HASH_HEX, OLD_SPEC);
}

#[test]
fn produce_refuses_the_old_spec() {
    let mut raw = dry_run_raw_facts();
    raw.b0_pre_spec_hash = OLD_SPEC.to_string();
    let e = produce(&raw, &records_from_raw(&raw)).expect_err("old-spec facts must be refused");
    assert!(e.contains("!= merged finalized"), "{e}");
}

#[test]
fn merge_fragments_refuses_the_old_spec() {
    // The spec-hex gate is the very first check; any fragment list under the old spec is refused.
    let e = b0_pre_validator::merge::merge_fragments(OLD_SPEC, &[])
        .expect_err("old-spec merge must be refused");
    assert!(e.contains("!= merged finalized"), "{e}");
}

#[test]
fn measurement_input_authority_fixture_refuses_the_old_spec() {
    // The committed MIA fixture binds the NEW spec; verifying it against the OLD spec is refused.
    const MIA: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/measurement-input-authority.v1.json"
    );
    let mia =
        b0_pre_validator::venue::measurement_input_authority::MeasurementInputAuthorityV1::from_json(
            MIA.as_bytes(),
        )
        .expect("MIA parses");
    const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
    let e = mia
        .verify(MEASURED, OLD_SPEC)
        .expect_err("MIA must refuse the old spec");
    assert!(e.contains("spec hash mismatch"), "{e}");
    // sanity: it DOES verify against the new spec.
    mia.verify(MEASURED, MERGED_SPEC_HASH_HEX)
        .expect("MIA verifies against the new spec");
}

#[test]
fn eligibility_matrix_fixture_refuses_the_old_spec() {
    const ELIG: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/eligibility-matrix.v1.json"
    );
    let elig = b0_pre_validator::venue::eligibility_matrix::EligibilityMatrixV1::from_json(
        ELIG.as_bytes(),
    )
    .expect("eligibility record parses");
    let e = elig
        .verify(OLD_SPEC)
        .expect_err("eligibility record must refuse the old spec");
    assert!(e.contains("spec hash mismatch"), "{e}");
    elig.verify(MERGED_SPEC_HASH_HEX)
        .expect("eligibility record verifies against the new spec");
}
